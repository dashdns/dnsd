#!/bin/bash
# Remove packages and services a DNS appliance has no use for.
#
# Deliberately kept: openssh-server, cloud-init, ifupdown/dhcp client,
# systemd-timesyncd, pciutils and an editor. Removing any of those turns a
# recoverable misconfiguration into an unbootable or unreachable instance.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if [[ "${PURGE_PACKAGES:-true}" != "true" ]]; then
    echo "==> PURGE_PACKAGES=false, skipping"
    exit 0
fi

before=$(df --output=used -k / | tail -1)

installed() {
    dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null | grep -q '^installed$'
}

purge_list=()
add() { installed "$1" && purge_list+=("$1") || true; }

# --- Mail transport: the appliance logs to journald, it does not send mail ---
for p in exim4 exim4-base exim4-config exim4-daemon-light bsd-mailx mailutils; do add "$p"; done

# --- Documentation ----------------------------------------------------------
# Also takes man-db.timer with it, which otherwise wakes daily to reindex.
for p in man-db manpages manpages-dev info install-info doc-debian; do add "$p"; done

# --- Radio hardware that does not exist on a cloud instance -----------------
for p in wireless-tools wpasupplicant iw crda bluez bluez-firmware; do add "$p"; done

# --- Interactive/desktop leftovers ------------------------------------------
for p in tasksel tasksel-data reportbug python3-reportbug apt-listchanges \
         popularity-contest installation-report laptop-detect eject os-prober \
         telnet ftp usbutils mlocate plocate debconf-i18n; do add "$p"; done

# --- Network services that would compete for ports or widen the surface -----
for p in nfs-common rpcbind avahi-daemon avahi-utils rsync; do add "$p"; done

if [[ "${DISABLE_UNATTENDED_UPGRADES:-true}" == "true" ]]; then
    for p in unattended-upgrades; do add "$p"; done
fi

if (( ${#purge_list[@]} )); then
    echo "==> Purging ${#purge_list[@]} packages:"
    printf '    %s\n' "${purge_list[@]}"
    apt-get purge -y -qq "${purge_list[@]}"
else
    echo "==> Nothing to purge"
fi

echo "==> Autoremoving orphans"
apt-get autoremove --purge -y -qq

# ---------------------------------------------------------------------------
# Firmware blobs
#
# ENA, NVMe and the Xen/Nitro block drivers need no firmware files. Anything
# under /lib/firmware is dead weight on this image.
# ---------------------------------------------------------------------------
fw_list=()
while IFS= read -r p; do
    [[ -n "$p" ]] && fw_list+=("$p")
done < <(dpkg-query -W -f='${binary:Package}\n' 'firmware-*' 2>/dev/null || true)

if (( ${#fw_list[@]} )); then
    echo "==> Purging firmware packages: ${fw_list[*]}"
    apt-get purge -y -qq "${fw_list[@]}" || true
fi
rm -rf /lib/firmware/* 2>/dev/null || true

# ---------------------------------------------------------------------------
# Timers and services that only generate wake-ups and log noise
#
# fstrim.timer is kept on purpose: it matters for gp3 volume performance.
# ---------------------------------------------------------------------------
echo "==> Masking unnecessary units"
for unit in \
    apt-daily.timer apt-daily.service \
    apt-daily-upgrade.timer apt-daily-upgrade.service \
    man-db.timer man-db.service \
    e2scrub_all.timer e2scrub_all.service \
    dpkg-db-backup.timer dpkg-db-backup.service \
    ModemManager.service \
    wpa_supplicant.service \
    bluetooth.service \
    rpcbind.service rpcbind.socket
do
    if systemctl list-unit-files --no-legend "${unit}" 2>/dev/null | grep -q .; then
        systemctl disable --now "${unit}" >/dev/null 2>&1 || true
        systemctl mask "${unit}" >/dev/null 2>&1 || true
        echo "    masked ${unit}"
    fi
done

# ---------------------------------------------------------------------------
# Stop dpkg from unpacking docs and translations in the future, and drop the
# ones already on disk.
# ---------------------------------------------------------------------------
echo "==> Excluding documentation from future installs"
cat > /etc/dpkg/dpkg.cfg.d/01-dnsd-nodoc <<'EOF'
path-exclude=/usr/share/doc/*
path-exclude=/usr/share/man/*
path-exclude=/usr/share/groff/*
path-exclude=/usr/share/info/*
path-exclude=/usr/share/lintian/*
path-exclude=/usr/share/linda/*
# Keep copyright files: Debian policy and license compliance rely on them.
path-include=/usr/share/doc/*/copyright
EOF

find /usr/share/doc -depth -type f ! -name copyright -delete 2>/dev/null || true
find /usr/share/doc -empty -type d -delete 2>/dev/null || true
rm -rf /usr/share/man/* /usr/share/info/* /usr/share/groff/* \
       /usr/share/lintian/* /usr/share/linda/* 2>/dev/null || true

# ---------------------------------------------------------------------------
# Locales: keep C.UTF-8 and en_US only.
# ---------------------------------------------------------------------------
echo "==> Trimming locales"
cat > /etc/dpkg/dpkg.cfg.d/02-dnsd-nolocales <<'EOF'
path-exclude=/usr/share/locale/*
path-include=/usr/share/locale/en*
path-include=/usr/share/locale/locale.alias
EOF
find /usr/share/locale -mindepth 1 -maxdepth 1 -type d ! -name 'en*' -exec rm -rf {} + 2>/dev/null || true

after=$(df --output=used -k / | tail -1)
echo "==> Reclaimed $(( (before - after) / 1024 )) MiB"
