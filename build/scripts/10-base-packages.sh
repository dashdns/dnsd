#!/bin/bash
# Install the eBPF build toolchain plus the handful of packages the appliance
# actually needs at runtime. The toolchain is removed again in 99-cleanup.sh.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
LLVM_VERSION="${LLVM_VERSION:-19}"

echo "==> apt-get update"
apt-get update -qq

echo "==> Upgrading base packages"
apt-get upgrade -y -qq -o Dpkg::Options::=--force-confold

# ---------------------------------------------------------------------------
# Runtime dependencies — these stay in the image.
#
#   ethtool          RX/TX ring and queue sizing (dnsd-tune-nic)
#   iproute2         clsact/qdisc inspection, `ip link`
#   ca-certificates  TLS to the policy controller
#   bpftool          the only practical way to inspect live BPF maps in prod
#   bind9-dnsutils   dig, for verifying the resolver from the box itself
# ---------------------------------------------------------------------------
echo "==> Installing runtime dependencies"
apt-get install -y -qq --no-install-recommends \
    ethtool \
    iproute2 \
    ca-certificates \
    bpftool \
    bind9-dnsutils

# ---------------------------------------------------------------------------
# Build dependencies — removed in 99-cleanup.sh.
# ---------------------------------------------------------------------------
echo "==> Installing build toolchain (clang/LLVM ${LLVM_VERSION})"
apt-get install -y -qq --no-install-recommends \
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
    pkg-config

# bpf2go invokes plain `clang` and `llvm-strip`.
ln -sf "/usr/bin/clang-${LLVM_VERSION}" /usr/bin/clang
ln -sf "/usr/bin/llvm-strip-${LLVM_VERSION}" /usr/bin/llvm-strip

# ---------------------------------------------------------------------------
# The BPF source includes <asm/types.h> via libbpf headers, but Debian installs
# the arch headers under a triplet directory that clang's default include path
# does not cover when targeting bpf.
#
# Only /usr/include/asm is actually missing. /usr/include/asm-generic is a real
# directory shipped by linux-libc-dev — pointing `ln` at it does not replace it,
# it creates a nested asm-generic/asm-generic symlink inside. So link only what
# does not already exist, and record which links we made so 99-cleanup.sh can
# remove exactly those and nothing else.
# ---------------------------------------------------------------------------
case "$(uname -m)" in
    x86_64)  TRIPLET=x86_64-linux-gnu  ;;
    aarch64) TRIPLET=aarch64-linux-gnu ;;
    *)
        echo "unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

: > /var/lib/dnsd-build-symlinks
for name in asm asm-generic; do
    if [[ -e "/usr/include/${name}" ]]; then
        echo "    /usr/include/${name} already present, leaving it alone"
        continue
    fi
    if [[ ! -d "/usr/include/${TRIPLET}/${name}" ]]; then
        echo "    /usr/include/${TRIPLET}/${name} does not exist, skipping"
        continue
    fi
    ln -s "/usr/include/${TRIPLET}/${name}" "/usr/include/${name}"
    echo "/usr/include/${name}" >> /var/lib/dnsd-build-symlinks
    echo "    /usr/include/${name} -> /usr/include/${TRIPLET}/${name}"
done

clang --version | head -1
