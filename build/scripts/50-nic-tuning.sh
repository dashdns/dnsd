#!/bin/bash
# Exercise the NIC tuning path against the builder's own interface.
#
# The udev rule is what applies this at runtime; running it here proves the
# script parses `ethtool -g` output correctly on this driver before the image
# is sealed.

set -euo pipefail

echo "==> Reloading udev rules"
udevadm control --reload-rules || true

# Primary interface = the one carrying the default route.
IFACE=$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')
if [[ -z "${IFACE}" ]]; then
    IFACE=$(ls /sys/class/net | grep -v '^lo$' | head -1)
fi

echo "==> Primary interface: ${IFACE:-<none>}"

if [[ -z "${IFACE}" ]]; then
    echo "    no interface found, skipping smoke test"
    exit 0
fi

echo "==> Ring parameters before tuning"
ethtool -g "${IFACE}" 2>/dev/null || echo "    driver reports no ring parameters"

# Dry run, deliberately. Every ethtool write in dnsd-tune-nic bounces the link
# (ena_close/ena_open), and Packer's SSH session runs over this very interface.
# What we need from the build is proof that the parsing and the ENA cap compute
# correctly on a real driver — not the side effect.
echo "==> Running dnsd-tune-nic (dry run)"
DNSD_TUNE_DRY_RUN=1 /usr/local/sbin/dnsd-tune-nic "${IFACE}"

echo "==> Channel configuration"
ethtool -l "${IFACE}" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Confirm native XDP is actually available on this driver, because the image
# defaults to -link-mode=driver. A generic-mode fallback would silently halve
# throughput, so surface it at build time.
# ---------------------------------------------------------------------------
driver=$(ethtool -i "${IFACE}" 2>/dev/null | awk '/^driver:/ {print $2}')
echo "==> Driver: ${driver:-unknown}"
case "${driver}" in
    ena|ixgbe|i40e|ice|mlx5_core|virtio_net)
        echo "    native (driver-mode) XDP is supported"
        ;;
    *)
        echo "    WARNING: native XDP support unverified for '${driver}'."
        echo "             Set dnsd_link_mode=generic if attachment fails at boot."
        ;;
esac
