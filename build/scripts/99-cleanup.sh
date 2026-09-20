#!/bin/bash
# Remove the build toolchain and every trace of this build from the image.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

LLVM_VERSION="${LLVM_VERSION:-19}"
before=$(df --output=used -k / | tail -1)

# ---------------------------------------------------------------------------
# Build toolchain
#
# dnsd was linked with CGO_ENABLED=0, so nothing here is needed at runtime.
# ---------------------------------------------------------------------------
echo "==> Removing the build toolchain"
apt-get purge -y -qq \
    "clang-${LLVM_VERSION}" \
    "llvm-${LLVM_VERSION}" \
    libbpf-dev \
    libelf-dev \
    linux-libc-dev \
    make \
    gcc \
    git \
    curl \
    xz-utils \
    pkg-config \
    2>/dev/null || true

apt-get autoremove --purge -y -qq

rm -f /usr/bin/clang /usr/bin/llvm-strip

# Remove only the include symlinks 10-base-packages.sh actually created.
# /usr/include/asm-generic is a real directory from linux-libc-dev on Debian,
# so a blind `rm -f` on it fails with "Is a directory" and kills this script.
if [[ -f /var/lib/dnsd-build-symlinks ]]; then
    # An `A && B` one-liner would be fatal here: under `set -e` a failing
    # AND-list as the last command of the loop body exits the script.
    while IFS= read -r link; do
        if [[ -L "${link}" ]]; then
            rm -f "${link}"
            echo "    removed ${link}"
        fi
    done < /var/lib/dnsd-build-symlinks
    rm -f /var/lib/dnsd-build-symlinks
fi

echo "==> Removing Go and the build tree"
rm -rf /usr/local/go
rm -rf /root/go /root/.cache
rm -rf /usr/local/src/dnsd
rm -f  /tmp/dnsd /tmp/dnsd-src.tar.gz
rm -rf /tmp/dnsd-files

# ---------------------------------------------------------------------------
# apt state
# ---------------------------------------------------------------------------
echo "==> Cleaning apt"
apt-get clean
rm -rf /var/lib/apt/lists/*
rm -rf /var/cache/apt/archives/*.deb
rm -rf /var/cache/debconf/*-old

# ---------------------------------------------------------------------------
# Logs and transient state
# ---------------------------------------------------------------------------
echo "==> Clearing logs"
journalctl --rotate  >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
find /var/log -type f -exec truncate -s 0 {} \; 2>/dev/null || true
rm -rf /var/log/journal/* /var/tmp/* 2>/dev/null || true

# Cap journal growth on the running appliance so logs cannot fill the root vol.
install -d -m 0755 /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/10-dnsd.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=512M
SystemMaxFileSize=64M
MaxRetentionSec=1week
EOF

# ---------------------------------------------------------------------------
# Per-instance identity
#
# These must be regenerated on first boot, or every instance launched from this
# AMI shares a machine-id and SSH host key.
# ---------------------------------------------------------------------------
echo "==> Resetting instance identity"
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -sf /etc/machine-id /var/lib/dbus/machine-id

rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub

# Do NOT `systemctl enable ssh.service` here. Debian 13 runs sshd through
# socket activation (ssh.socket); force-enabling ssh.service alongside it makes
# both contend for :22 and Conflicts= takes one of them down. Whatever the base
# image had enabled is already correct — leave it alone.
#
# Regeneration of the host keys deleted above is handled by
# dnsd-sshd-keygen.service, which is ordered before both ssh units.
systemctl is-enabled ssh.socket  2>/dev/null | sed 's/^/    ssh.socket: /'  || true
systemctl is-enabled ssh.service 2>/dev/null | sed 's/^/    ssh.service: /' || true

echo "==> cloud-init clean"
cloud-init clean --logs --seed >/dev/null 2>&1 || cloud-init clean --logs >/dev/null 2>&1 || true
rm -rf /var/lib/cloud/instances/* /var/lib/cloud/data/* 2>/dev/null || true

# ---------------------------------------------------------------------------
# Credentials and shell history
# ---------------------------------------------------------------------------
echo "==> Removing build credentials"
rm -f /root/.bash_history /home/*/.bash_history
rm -rf /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys
rm -rf /root/.aws /home/*/.aws
find / -xdev -name 'authorized_keys' -path '*/.ssh/*' -delete 2>/dev/null || true

# ---------------------------------------------------------------------------
# Zero the free space so the EBS snapshot compresses well.
# ---------------------------------------------------------------------------
echo "==> Zeroing free space"
dd if=/dev/zero of=/EMPTY bs=4M status=none 2>/dev/null || true
rm -f /EMPTY
sync

after=$(df --output=used -k / | tail -1)
echo "==> Cleanup reclaimed $(( (before - after) / 1024 )) MiB"
echo "==> Final root usage:"
df -h / | sed 's/^/    /'
