#!/bin/bash
# Smoke-test the image before it is sealed.
#
# dnsd is started against the loopback interface, not the builder's real NIC:
# attaching XDP to the NIC Packer is connected over risks losing the SSH
# session mid-build. Loopback still exercises everything that usually breaks —
# BPF object load, XDP attach, clsact qdisc creation, the :53 bind and the
# :9090 metrics listener.

set -uo pipefail

fail=0
ok()   { printf '    ok   %s\n' "$*"; }
bad()  { printf '    FAIL %s\n' "$*"; fail=1; }

echo "==> Static checks"

[[ -x /opt/dashdns/dnsd ]] && ok "/opt/dashdns/dnsd is executable" \
                           || bad "/opt/dashdns/dnsd missing"

for f in /etc/default/dnsd \
         /etc/sysctl.d/90-dnsd-network.conf \
         /etc/modprobe.d/dnsd-blacklist.conf \
         /etc/modules-load.d/dnsd.conf \
         /etc/udev/rules.d/70-dnsd-nic-tune.rules \
         /usr/local/sbin/dnsd-tune-nic \
         /usr/local/sbin/dnsd-tune-memory; do
    [[ -e "$f" ]] && ok "$f" || bad "$f missing"
done

# The token lives in this file; it must not be world-readable.
mode=$(stat -c '%a' /etc/default/dnsd)
[[ "${mode}" == "600" ]] && ok "/etc/default/dnsd mode 0600" \
                         || bad "/etc/default/dnsd mode ${mode}, expected 600"

echo "==> Unit files"
systemd-analyze verify /etc/systemd/system/dnsd.service 2>&1 | grep -v '^$' || true
for u in dnsd.service dnsd-tune-memory.service; do
    if systemctl is-enabled "$u" >/dev/null 2>&1; then ok "$u enabled"; else bad "$u not enabled"; fi
done

# ---------------------------------------------------------------------------
# SSH must survive first boot.
#
# 99-cleanup.sh deletes the host keys so each instance gets its own identity.
# If nothing regenerates them, sshd dies with "no hostkeys available" and the
# instance is unreachable — which is only discoverable by launching it. Prove
# the regeneration path works here instead.
# ---------------------------------------------------------------------------
echo "==> SSH first-boot path"

if systemctl is-enabled dnsd-sshd-keygen.service >/dev/null 2>&1; then
    ok "dnsd-sshd-keygen.service enabled"
else
    bad "dnsd-sshd-keygen.service is not enabled"
fi

# Exactly the situation the image boots into.
mkdir -p /tmp/hostkeys-backup
mv /etc/ssh/ssh_host_* /tmp/hostkeys-backup/ 2>/dev/null || true

if /usr/bin/ssh-keygen -A >/dev/null 2>&1 && ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
    ok "ssh-keygen -A regenerates host keys ($(ls /etc/ssh/ssh_host_*_key | wc -l) keys)"
else
    bad "ssh-keygen -A did not produce host keys"
fi

if /usr/sbin/sshd -t 2>/tmp/sshd-t.log; then
    ok "sshd -t accepts the configuration"
else
    bad "sshd -t rejected the configuration:"
    sed 's/^/      /' /tmp/sshd-t.log
fi
rm -f /tmp/sshd-t.log

# Whichever unit the base image uses, one of them must be enabled. Debian 13
# defaults to socket activation; 99-cleanup.sh no longer forces ssh.service.
sock=$(systemctl is-enabled ssh.socket  2>/dev/null || true)
svc=$(systemctl  is-enabled ssh.service 2>/dev/null || true)
if [[ "${sock}" == "enabled" || "${svc}" == "enabled" || "${svc}" == "enabled-runtime" ]]; then
    ok "ssh reachable at boot (ssh.socket=${sock:-n/a}, ssh.service=${svc:-n/a})"
else
    bad "neither ssh.socket nor ssh.service is enabled (socket=${sock:-n/a}, service=${svc:-n/a})"
fi

# ---------------------------------------------------------------------------
# cloud-init config must parse.
#
# A single malformed file in /etc/cloud/cloud.cfg.d aborts the config stage.
# That means no authorized_keys, no host keys, and user-data silently ignored —
# an instance that boots to a login prompt and answers nothing.
# ---------------------------------------------------------------------------
echo "==> cloud-init configuration"
for f in /etc/cloud/cloud.cfg /etc/cloud/cloud.cfg.d/*.cfg; do
    [[ -e "$f" ]] || continue
    if python3 -c "import sys,yaml; yaml.safe_load(open(sys.argv[1]))" "$f" 2>/tmp/yaml.log; then
        ok "parses: $f"
    else
        bad "malformed YAML: $f"
        sed 's/^/      /' /tmp/yaml.log
    fi
done
rm -f /tmp/yaml.log

if command -v cloud-init >/dev/null 2>&1; then
    if cloud-init schema --system >/tmp/ci-schema.log 2>&1; then
        ok "cloud-init schema --system clean"
    else
        # Schema warnings are common and not fatal; surface them, do not fail.
        echo "    note cloud-init schema reported:"
        sed 's/^/      /' /tmp/ci-schema.log | head -20
    fi
    rm -f /tmp/ci-schema.log
fi

echo "==> Port 53 is free"
if ss -lunp 2>/dev/null | grep -q ':53 '; then
    bad "something is already listening on UDP/53:"
    ss -lunp | grep ':53 ' | sed 's/^/      /'
    # Almost always the systemd-resolved stub on 127.0.0.53 coming back.
    # 30-install-dnsd.sh masks it; report the state so the cause is obvious.
    echo "      systemd-resolved: $(systemctl is-enabled systemd-resolved.service 2>&1) / $(systemctl is-active systemd-resolved.service 2>&1)"
else
    ok "UDP/53 unclaimed"
fi

echo "==> systemd-resolved is masked"
state=$(systemctl is-enabled systemd-resolved.service 2>&1 || true)
case "${state}" in
    masked)     ok "systemd-resolved masked" ;;
    *not-found*) ok "systemd-resolved not installed" ;;
    *)          bad "systemd-resolved is '${state}', expected masked" ;;
esac

# ---------------------------------------------------------------------------
# Runtime smoke test on loopback
# ---------------------------------------------------------------------------
echo "==> Starting dnsd on lo (generic XDP)"

/opt/dashdns/dnsd \
    -iface=lo \
    -link-mode=generic \
    -ipam=onpremise \
    -upstream=169.254.169.253:53 \
    > /tmp/dnsd-smoke.log 2>&1 &
pid=$!

for _ in $(seq 1 20); do
    sleep 1
    kill -0 "${pid}" 2>/dev/null || break
    ss -lun 2>/dev/null | grep -q ':53 ' && break
done

if ! kill -0 "${pid}" 2>/dev/null; then
    bad "dnsd exited during startup"
    sed -n '1,60p' /tmp/dnsd-smoke.log
else
    ok "dnsd is running (pid ${pid})"

    ss -lun  2>/dev/null | grep -q ':53 '   && ok "listening on UDP/53"   || bad "no UDP/53 listener"
    ss -ltn  2>/dev/null | grep -q ':9090 ' && ok "listening on TCP/9090" || bad "no TCP/9090 listener"

    if ip link show lo 2>/dev/null | grep -q xdp; then
        ok "XDP program attached to lo"
    else
        bad "no XDP program on lo"
    fi

    if tc qdisc show dev lo 2>/dev/null | grep -q clsact; then
        ok "clsact qdisc created on lo"
    else
        bad "no clsact qdisc on lo"
    fi

    if command -v bpftool >/dev/null 2>&1; then
        echo "    loaded BPF programs:"
        bpftool prog show 2>/dev/null | grep -E 'xdp|sched_cls' | sed 's/^/      /' || true
        echo "    BPF maps:"
        bpftool map show 2>/dev/null | grep -E 'blocked|ip_blocklist' | sed 's/^/      /' || true
    fi

    if curl -fsS --max-time 5 http://127.0.0.1:9090/metrics 2>/dev/null | grep -q '^dnsd_'; then
        ok "/metrics exposes dnsd_* series"
    else
        bad "/metrics did not return dnsd_* series"
    fi

    echo "==> Stopping dnsd"
    kill -TERM "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
fi

# dnsd's cleanup removes these, but make sure nothing is left pinned to lo.
tc qdisc del dev lo clsact 2>/dev/null || true
ip link set dev lo xdpgeneric off 2>/dev/null || true

echo "==> dnsd log:"
sed -n '1,40p' /tmp/dnsd-smoke.log | sed 's/^/    /'
rm -f /tmp/dnsd-smoke.log

if (( fail )); then
    echo "image verification FAILED" >&2
    exit 1
fi
echo "==> Image verification passed"
