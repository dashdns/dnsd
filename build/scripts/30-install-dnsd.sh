#!/bin/bash
# Install the binary, the systemd units and the tuning configuration, then
# clear anything else off UDP/53.

set -euo pipefail

STAGE=/tmp/dnsd-files

echo "==> Installing /opt/dashdns/dnsd"
install -d -m 0755 /opt/dashdns
install -m 0755 -o root -g root /tmp/dnsd /opt/dashdns/dnsd

echo "==> Installing tuning helpers"
install -m 0755 -o root -g root "${STAGE}/usr/local/sbin/dnsd-tune-nic"    /usr/local/sbin/dnsd-tune-nic
install -m 0755 -o root -g root "${STAGE}/usr/local/sbin/dnsd-tune-memory" /usr/local/sbin/dnsd-tune-memory

echo "==> Installing system configuration"
install -m 0644 -o root -g root "${STAGE}/etc/sysctl.d/90-dnsd-network.conf"    /etc/sysctl.d/90-dnsd-network.conf
install -m 0644 -o root -g root "${STAGE}/etc/modules-load.d/dnsd.conf"         /etc/modules-load.d/dnsd.conf
install -m 0644 -o root -g root "${STAGE}/etc/modprobe.d/dnsd-blacklist.conf"   /etc/modprobe.d/dnsd-blacklist.conf
install -m 0644 -o root -g root "${STAGE}/etc/security/limits.d/90-dnsd.conf"   /etc/security/limits.d/90-dnsd.conf
install -m 0644 -o root -g root "${STAGE}/etc/udev/rules.d/70-dnsd-nic-tune.rules" /etc/udev/rules.d/70-dnsd-nic-tune.rules

install -m 0644 -o root -g root "${STAGE}/etc/systemd/system/dnsd-sshd-keygen.service" /etc/systemd/system/dnsd-sshd-keygen.service
install -m 0644 -o root -g root "${STAGE}/etc/systemd/system/dnsd.service"              /etc/systemd/system/dnsd.service
install -m 0644 -o root -g root "${STAGE}/etc/systemd/system/dnsd-tune-nic@.service"    /etc/systemd/system/dnsd-tune-nic@.service
install -m 0644 -o root -g root "${STAGE}/etc/systemd/system/dnsd-tune-memory.service"  /etc/systemd/system/dnsd-tune-memory.service

# ---------------------------------------------------------------------------
# /etc/default/dnsd
#
# Mode 0600: DNSD_IP_BLOCKLIST_TOKEN is a bearer credential.
# ---------------------------------------------------------------------------
echo "==> Writing /etc/default/dnsd"
install -m 0600 -o root -g root "${STAGE}/etc/default/dnsd" /etc/default/dnsd

sed -i \
    -e "s|@DNSD_IFACE@|${DNSD_IFACE:-ens5}|" \
    -e "s|@DNSD_UPSTREAM@|${DNSD_UPSTREAM:-169.254.169.253:53}|" \
    -e "s|@DNSD_LINK_MODE@|${DNSD_LINK_MODE:-driver}|" \
    -e "s|@DNSD_IPAM@|${DNSD_IPAM:-onpremise}|" \
    /etc/default/dnsd

if grep -q '@DNSD_' /etc/default/dnsd; then
    echo "unsubstituted placeholders left in /etc/default/dnsd:" >&2
    grep -n '@DNSD_' /etc/default/dnsd >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Free up UDP/53
#
# dnsd binds 0.0.0.0:53, and a wildcard bind collides with systemd-resolved's
# stub listener on 127.0.0.53:53 (EADDRINUSE). resolved is stopped, disabled
# and masked rather than merely reconfigured: on an appliance whose entire job
# is owning port 53, the stub coming back after a package upgrade is a silent
# outage.
#
# The host still needs to resolve names of its own — the policy controller
# hostname, apt mirrors during the rest of this build — so /etc/resolv.conf is
# replaced with a static file first. It must NOT point at dnsd itself: dnsd
# needs DNS to reach the policy controller before it has finished starting.
# ---------------------------------------------------------------------------

# Strip the :port from the configured upstream to get a usable nameserver.
upstream_host="${DNSD_UPSTREAM:-169.254.169.253:53}"
upstream_host="${upstream_host%:*}"

echo "==> Writing a static /etc/resolv.conf (nameserver ${upstream_host})"
rm -f /etc/resolv.conf          # usually a symlink into /run/systemd/resolve
{
    echo "# Static resolv.conf for the dnsd appliance."
    echo "#"
    echo "# systemd-resolved is masked here because dnsd owns 0.0.0.0:53. These"
    echo "# entries are for the host's own lookups only; client DNS goes to dnsd."
    echo "nameserver ${upstream_host}"
    # 169.254.169.253 is the AWS VPC resolver and works in every VPC regardless
    # of CIDR. Skip it when it is already the primary.
    if [[ "${upstream_host}" != "169.254.169.253" ]]; then
        echo "nameserver 169.254.169.253"
    fi
    echo "options timeout:2 attempts:2"
} > /etc/resolv.conf
chmod 0644 /etc/resolv.conf

# dhclient's resolvconf hook would overwrite the file above on every lease.
install -d -m 0755 /etc/dhcp/dhclient-enter-hooks.d
cat > /etc/dhcp/dhclient-enter-hooks.d/nodnsupdate <<'EOF'
# Keep the static /etc/resolv.conf written by the dnsd image build.
make_resolv_conf() { : ; }
EOF
chmod 0755 /etc/dhcp/dhclient-enter-hooks.d/nodnsupdate

# cloud-init would do the same on first boot.
install -d -m 0755 /etc/cloud/cloud.cfg.d
cat > /etc/cloud/cloud.cfg.d/99-dnsd-resolv.cfg <<'EOF'
# The dnsd image ships its own /etc/resolv.conf; do not manage it.
manage_resolv_conf: false
EOF

# Leave the drop-in behind too, so the intent survives an operator unmasking
# resolved for troubleshooting.
install -d -m 0755 /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/10-dnsd.conf <<'EOF'
# dnsd binds 0.0.0.0:53; the 127.0.0.53 stub would take the port first.
# Relevant only if systemd-resolved is unmasked again.
[Resolve]
DNSStubListener=no
EOF

echo "==> Stopping and masking anything that wants port 53"
for svc in systemd-resolved.service dnsmasq.service named.service \
           bind9.service unbound.service; do
    if systemctl list-unit-files --no-legend "${svc}" 2>/dev/null | grep -q .; then
        echo "    ${svc}"
        systemctl disable --now "${svc}" >/dev/null 2>&1 || true
        systemctl mask "${svc}"          >/dev/null 2>&1 || true
    fi
done

# Confirm the port is actually free before the build continues; 80-verify.sh
# depends on it, and so does every instance booted from this image.
if ss -lunp 2>/dev/null | grep -q ':53 '; then
    echo "something still holds UDP/53 after masking:" >&2
    ss -lunp | grep ':53 ' >&2
    exit 1
fi
echo "    UDP/53 is free"

# With resolved masked, nss-resolve returns UNAVAIL on every lookup and glibc
# falls through to the classic `dns` module, so resolution still works — but it
# costs a failed socket connect per query. Drop it from the hosts line.
if grep -q '^hosts:.*resolve' /etc/nsswitch.conf 2>/dev/null; then
    echo "==> Removing nss-resolve from /etc/nsswitch.conf"
    sed -i -E '/^hosts:/ s/resolve +\[!UNAVAIL=return\] *//; /^hosts:/ s/ +resolve\b//' \
        /etc/nsswitch.conf
    grep '^hosts:' /etc/nsswitch.conf | sed 's/^/    /'
fi

# The rest of the build does apt work; prove name resolution survived.
if getent hosts deb.debian.org >/dev/null 2>&1; then
    echo "    name resolution OK via ${upstream_host}"
else
    echo "WARNING: cannot resolve deb.debian.org via ${upstream_host};" >&2
    echo "         later apt steps may fail" >&2
fi

# ---------------------------------------------------------------------------
# Enable units
#
# dnsd-tune-nic@ is instantiated by udev, not enabled directly.
# ---------------------------------------------------------------------------
echo "==> Enabling units"
systemctl daemon-reload
systemctl enable dnsd-sshd-keygen.service
systemctl enable dnsd-tune-memory.service
systemctl enable dnsd.service

# ---------------------------------------------------------------------------
# Emergency console access
#
# The EC2 serial console is the only way into an instance whose sshd is down,
# but it needs a password — and Debian AMIs ship the admin user locked. Without
# this, a boot-time failure means the image can only be debugged by detaching
# the root volume and mounting it elsewhere.
#
# Off unless -var 'debug_password=...' was passed. Never enable it for an image
# that goes anywhere near production.
# ---------------------------------------------------------------------------
if [[ -n "${DEBUG_PASSWORD:-}" ]]; then
    echo "==> WARNING: setting a console password for '${SSH_USERNAME:-admin}'"
    echo "             This image is for DEBUGGING ONLY. Do not ship it."
    echo "${SSH_USERNAME:-admin}:${DEBUG_PASSWORD}" | chpasswd
    # A locked account cannot log in even with a password set.
    passwd -u "${SSH_USERNAME:-admin}" >/dev/null 2>&1 || true
    touch /etc/dnsd-DEBUG-IMAGE
else
    echo "==> No debug_password set; serial console login stays disabled"
fi

# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------
cat > /etc/dnsd-release <<EOF
DNSD_VERSION="${DNSD_VERSION:-dev}"
DNSD_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DNSD_BUILD_KERNEL="$(uname -r)"
DNSD_BUILD_ARCH="$(dpkg --print-architecture)"
DNSD_BASE_OS="$(. /etc/os-release && echo "${ID}-${VERSION_ID}")"
DNSD_GO_VERSION="${GO_VERSION:-unknown}"
DNSD_LLVM_VERSION="${LLVM_VERSION:-unknown}"
EOF
chmod 0644 /etc/dnsd-release

echo "==> /etc/dnsd-release:"
cat /etc/dnsd-release
