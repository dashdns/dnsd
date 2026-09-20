#!/bin/bash
# Shrink the kernel module surface.
#
# Two layers, doing different jobs:
#
#   1. /etc/modprobe.d/dnsd-blacklist.conf (installed in 30-install-dnsd.sh)
#      is the authoritative control. It survives kernel upgrades, because a new
#      linux-image package cannot un-blacklist anything.
#
#   2. Deleting the .ko trees below shrinks the image and the initramfs. This
#      does NOT survive a kernel upgrade — a new linux-image restores the files
#      — which is fine for an immutable AMI that gets rebaked, and is exactly
#      why layer 1 exists as well.
#
# Storage, networking, crypto and virtio/Xen/Nitro drivers are never touched.

set -euo pipefail

KVER=$(uname -r)
MODDIR="/lib/modules/${KVER}/kernel"

echo "==> Kernel ${KVER}"

if [[ ! -d "${MODDIR}" ]]; then
    echo "    ${MODDIR} not found, nothing to strip"
    exit 0
fi

echo "==> Module tree before: $(du -sh "/lib/modules/${KVER}" | cut -f1)"

if [[ "${STRIP_KERNEL_MODULES:-true}" != "true" ]]; then
    echo "==> STRIP_KERNEL_MODULES=false; blacklist-only mode"
else
    # Subtrees with no possible consumer on a headless cloud DNS appliance.
    STRIP_DIRS=(
        # Audio, video, graphics, input peripherals
        sound
        drivers/media
        drivers/gpu
        drivers/staging

        # Radio
        drivers/bluetooth
        drivers/net/wireless
        net/bluetooth
        net/wireless
        net/mac80211

        # Buses and peripherals with no virtual counterpart
        drivers/firewire
        drivers/isdn
        drivers/parport
        drivers/pcmcia
        drivers/usb/serial
        drivers/usb/gadget
        drivers/usb/atm
        drivers/auxdisplay
        drivers/memstick
        drivers/mmc
        # drivers/tty/serial is NOT stripped: the EC2 serial console is the
        # only way in when an instance will not boot.

        # Filesystems that will never be mounted (ext4/xfs/btrfs/vfat kept)
        fs/ocfs2
        fs/gfs2
        fs/cifs
        fs/smb
        fs/nfs
        fs/nfsd
        fs/nfs_common
        fs/hfs
        fs/hfsplus
        fs/jfs
        fs/reiserfs
        fs/befs
        fs/ntfs
        fs/ntfs3
        fs/affs
        fs/adfs
        fs/qnx4
        fs/qnx6
        fs/minix
        fs/ufs
        fs/freevxfs
        fs/jffs2
        fs/cramfs

        # Exotic network protocols (also blacklisted in modprobe.d)
        net/dccp
        net/sctp
        net/rds
        net/tipc
        net/ax25
        net/netrom
        net/rose
        net/x25
        net/decnet
        net/appletalk
        net/atm
        net/can
        net/irda
        net/9p
    )

    removed=0
    for d in "${STRIP_DIRS[@]}"; do
        target="${MODDIR}/${d}"
        if [[ -e "${target}" ]]; then
            rm -rf "${target}"
            echo "    removed kernel/${d}"
            removed=$(( removed + 1 ))
        fi
    done
    echo "==> Removed ${removed} module subtrees"
fi

# ---------------------------------------------------------------------------
# Sanity check: everything dnsd depends on must still resolve.
#
# A module can be present as a .ko, already loaded, or compiled into the
# kernel — all three are fine, so check for all three.
# ---------------------------------------------------------------------------
have_mod() {
    modinfo "$1" >/dev/null 2>&1 && return 0
    grep -qw "^$1" /proc/modules 2>/dev/null && return 0
    [[ -f "/lib/modules/${KVER}/modules.builtin" ]] \
        && grep -q "/$1\.ko" "/lib/modules/${KVER}/modules.builtin" && return 0
    return 1
}

echo "==> Verifying required modules survived"

# The clsact qdisc is NOT a module called sch_clsact — it is registered by
# net/sched/sch_ingress.c (sch_ingress.ko, MODULE_ALIAS_NET_SCH("clsact")).
# Testing the module name would give a false negative, so create the qdisc for
# real: that is precisely the netlink call dnsd makes in attachTC().
if tc qdisc add dev lo clsact 2>/dev/null; then
    echo "    ok   clsact qdisc can be created"
    tc qdisc del dev lo clsact 2>/dev/null || true
else
    echo "cannot create a clsact qdisc on lo" >&2
    echo "dnsd's TC egress hook will fail; check CONFIG_NET_SCH_INGRESS" >&2
    exit 1
fi

# dnsd attaches with DirectAction: true, so cls_bpf is the only classifier
# needed; act_bpf is not involved.
if have_mod cls_bpf; then
    echo "    ok   cls_bpf"
else
    echo "cls_bpf is unavailable; dnsd cannot attach its TC filter" >&2
    exit 1
fi

# Nice to have, but not fatal: the sysctl set degrades gracefully without them
# and 40-sysctl-tuning.sh already warned.
for m in sch_fq tcp_bbr ena nvme; do
    if have_mod "$m"; then
        printf '    ok   %s\n' "$m"
    else
        printf '    note %s not present (built in, or not applicable here)\n' "$m"
    fi
done

# ---------------------------------------------------------------------------
# Rebuild module dependency data and the initramfs so neither references a
# module that no longer exists.
#
# MODULES= in /etc/initramfs-tools/initramfs.conf is intentionally left at the
# Debian default. Narrowing it to 'dep' would bake in the *build* instance's
# hardware, and the AMI must stay bootable across instance families.
# ---------------------------------------------------------------------------
echo "==> depmod"
depmod -a "${KVER}"

echo "==> Rebuilding initramfs"
update-initramfs -u -k "${KVER}"

echo "==> Module tree after: $(du -sh "/lib/modules/${KVER}" | cut -f1)"
