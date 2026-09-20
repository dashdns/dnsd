#!/bin/bash
# Compile dnsd (and its eBPF objects) inside the image.
#
# Mirrors the steps in the repository Dockerfile so the AMI and the container
# image are produced from the same recipe.

set -euo pipefail

GO_VERSION="${GO_VERSION:-1.25.6}"
BPF2GO_VERSION="${BPF2GO_VERSION:-v0.17.1}"
SRC_DIR=/usr/local/src/dnsd

# ---------------------------------------------------------------------------
# Go toolchain
#
# Debian 13 ships golang-1.24, which is older than the `go` directive in
# go.mod, so pull a release tarball from go.dev instead. GOTOOLCHAIN=auto lets
# the downloaded toolchain fetch a newer one if go.mod ever requires it.
# ---------------------------------------------------------------------------
GOARCH_DEB="$(dpkg --print-architecture)"   # amd64 | arm64 — matches go.dev naming
GO_TARBALL="go${GO_VERSION}.linux-${GOARCH_DEB}.tar.gz"

echo "==> Installing Go ${GO_VERSION} (${GOARCH_DEB})"
curl -fsSL --retry 3 --retry-delay 2 \
    -o "/tmp/${GO_TARBALL}" \
    "https://go.dev/dl/${GO_TARBALL}"

rm -rf /usr/local/go
tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
rm -f "/tmp/${GO_TARBALL}"

export GOPATH=/root/go
export GOCACHE=/root/.cache/go-build
export PATH="/usr/local/go/bin:${GOPATH}/bin:${PATH}"
export GOTOOLCHAIN=auto
export GOFLAGS=-mod=mod

go version

# ---------------------------------------------------------------------------
# Source
# ---------------------------------------------------------------------------
echo "==> Unpacking source"
rm -rf "${SRC_DIR}"
mkdir -p "${SRC_DIR}"
tar -xzf /tmp/dnsd-src.tar.gz -C "${SRC_DIR}"
cd "${SRC_DIR}"

# ---------------------------------------------------------------------------
# eBPF objects
#
# The //go:generate directive in main.go runs bpf2go via `go run`, resolving it
# from the module graph. Installing the pinned binary first warms the module
# cache and keeps the AMI build byte-compatible with the Dockerfile.
# ---------------------------------------------------------------------------
echo "==> Fetching modules"
go mod tidy
go mod download

echo "==> Installing bpf2go ${BPF2GO_VERSION}"
go install "github.com/cilium/ebpf/cmd/bpf2go@${BPF2GO_VERSION}"

echo "==> go generate (compiling bpf/xdp_tc.c)"
go generate ./...

ls -la bpf_bpf*.o bpf_bpf*.go 2>/dev/null || {
    echo "bpf2go produced no objects — eBPF compilation failed" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Binary
#
# CGO off: cilium/ebpf, netlink and miekg/dns are all pure Go, and a static
# binary survives the library purge in 99-cleanup.sh.
# ---------------------------------------------------------------------------
echo "==> Building dnsd"
CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags '-s -w' \
    -o /tmp/dnsd \
    .

file /tmp/dnsd 2>/dev/null || true
/tmp/dnsd -h 2>&1 | head -5 || true   # -h exits non-zero by design in Go's flag pkg

echo "==> Build complete: $(stat -c %s /tmp/dnsd) bytes"
