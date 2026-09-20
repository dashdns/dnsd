#!/bin/bash
# Apply and verify the network sysctls.
#
# Applying them at build time is not what makes them persist — /etc/sysctl.d
# does that. The point of applying here is to fail the build now if a key is
# rejected, rather than discovering it silently missing on a production boot.

set -euo pipefail

echo "==> Loading modules required by the sysctl set"
modprobe sch_fq   2>/dev/null || echo "    WARNING: sch_fq unavailable; default_qdisc=fq will not apply"
modprobe tcp_bbr  2>/dev/null || echo "    WARNING: tcp_bbr unavailable; congestion_control=bbr will not apply"
# sch_ingress, not sch_clsact — the clsact qdisc lives in sch_ingress.ko.
modprobe sch_ingress 2>/dev/null || true
modprobe cls_bpf     2>/dev/null || true

echo "==> Applying /etc/sysctl.d/90-dnsd-network.conf"
sysctl -p /etc/sysctl.d/90-dnsd-network.conf

echo "==> Applying memory-proportional sysctls"
/usr/local/sbin/dnsd-tune-memory

# ---------------------------------------------------------------------------
# Verify the keys that actually matter for the DNS hot path. A typo in the
# conf file would otherwise only surface as a quiet performance regression.
# ---------------------------------------------------------------------------
echo "==> Verifying"
fail=0
check() {
    local key="$1" want="$2" got
    got=$(sysctl -n "${key}" 2>/dev/null || echo "<missing>")
    if [[ "${got}" == "${want}" ]]; then
        printf '    ok   %-42s = %s\n' "${key}" "${got}"
    else
        printf '    FAIL %-42s = %s (expected %s)\n' "${key}" "${got}" "${want}"
        fail=1
    fi
}

check net.core.rmem_max            16777216
check net.core.wmem_max            16777216
check net.core.netdev_max_backlog  65536
check net.core.netdev_budget       1200
check net.core.somaxconn           4096
check net.ipv4.udp_rmem_min        262144
check net.ipv4.udp_wmem_min        262144
check net.core.bpf_jit_enable      1
check net.ipv4.conf.all.rp_filter  2

# These two depend on a module being present; warn rather than fail so the
# build still works on a kernel flavour that lacks them.
for pair in "net.core.default_qdisc fq" "net.ipv4.tcp_congestion_control bbr"; do
    set -- ${pair}
    got=$(sysctl -n "$1" 2>/dev/null || echo "<missing>")
    if [[ "${got}" == "$2" ]]; then
        printf '    ok   %-42s = %s\n' "$1" "${got}"
    else
        printf '    WARN %-42s = %s (wanted %s)\n' "$1" "${got}" "$2"
    fi
done

if (( fail )); then
    echo "sysctl verification failed" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Re-enable IPv6 for the remainder of the build.
#
# The conf file disables it, and that is what the finished image boots with.
# But 60-purge-packages.sh still has apt work to do, and a build running in an
# IPv6-only or IPv6-preferring VPC would lose its mirror the moment the sysctl
# above took effect.
# ---------------------------------------------------------------------------
echo "==> Re-enabling IPv6 for the rest of the build (disabled again on boot)"
sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 || true
