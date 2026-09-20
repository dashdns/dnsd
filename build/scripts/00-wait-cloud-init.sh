#!/bin/bash
# Wait for the base image's own first-boot work to finish before Packer starts
# mutating the system. Without this, apt races cloud-init's package hooks and
# the build fails intermittently on a dpkg frontend lock.

set -euo pipefail

echo "==> Waiting for cloud-init"
if command -v cloud-init >/dev/null 2>&1; then
    cloud-init status --wait || true
fi

echo "==> Waiting for apt/dpkg locks"
for _ in $(seq 1 120); do
    if ! fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock \
                /var/cache/apt/archives/lock >/dev/null 2>&1; then
        break
    fi
    sleep 5
done

# Debian cloud images ship these timers enabled; they will grab the dpkg lock
# mid-build. Stop them now and purge the packages later in 60-purge-packages.sh.
systemctl stop apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
systemctl stop apt-daily.service apt-daily-upgrade.service >/dev/null 2>&1 || true
systemctl stop unattended-upgrades.service >/dev/null 2>&1 || true

echo "==> Base system:"
. /etc/os-release && echo "    ${PRETTY_NAME} / kernel $(uname -r) / $(dpkg --print-architecture)"
