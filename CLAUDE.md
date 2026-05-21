# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

The project requires generating eBPF bytecode before building:

```bash
go generate          # compiles bpf/xdp_tc.c → Go-embedded objects via bpf2go
go build -o dnsd     # builds the final binary
```

Docker handles the full toolchain:

```bash
docker build -t dnsd:latest .
```

Build dependencies (must be installed for local `go generate`): `clang-19`, `llvm-19`, `libbpf-dev`, `libelf-dev`, `linux-libc-dev`, and `bpf2go` (`go install github.com/cilium/ebpf/cmd/bpf2go@v0.17.1`).

## Tests

No unit tests — integration testing is done via Docker Compose or Kubernetes:

```bash
docker-compose -f tests/docker-compose.yaml up
kubectl apply -f tests/kubernetes.yaml
```

`tests/payload.json` is a sample payload for testing the remote blocklist JSON endpoint.

## Running

The binary requires root or `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_RESOURCE`. Key flags:

| Flag | Purpose |
|------|---------|
| `-iface` | Network interface to attach XDP/TC (default: `lo`) |
| `-upstream` | Upstream DNS server (default: `8.8.8.8:53`) |
| `-upstream-rules` | Conditional routing: `glob=host:port;glob2=host2:port2` |
| `-blocklist` | Comma-separated global domain blocklist |
| `-blockips` | Block specific IPs appearing in DNS responses |
| `-blocked-dns` | Block specific DNS server IPs (blacklist) |
| `-allowed-dns` | Comma-separated list of approved DNS server IPs; enables **leak guard** — all other outgoing DNS traffic is dropped at the TC layer |
| `-ip-blocklist` | Per-IP rules: `IP:domain1,domain2;IP2:domain3` |
| `-ip-blocklist-url` | Remote JSON endpoint for dynamic per-IP blocklist |
| `-ip-blocklist-interval` | Remote blocklist refresh interval (default: `5m`) |
| `-link-mode` | XDP mode: `generic`, `driver`, or `offload` (default: `generic`) |
| `-ipam` | `onpremise` (default) or `aws-vpc-cni` for EKS ENI auto-attach |

## Architecture

DNSD is a kernel-assisted DNS proxy. It installs two eBPF programs on a given interface and runs a userspace DNS server for queries that pass the kernel filters.

### Kernel layer (`bpf/xdp_tc.c`)

- **XDP program** (ingress): Runs at the NIC driver level before the kernel network stack. Hashes queried domain names and checks them against two BPF hash maps — a global blocklist (`blocked_domains`) and a per-client-IP blocklist (`ip_blocklist`). Drops matching packets and records counts per source IP.
- **TC program** (egress): Hooks into the traffic control clsact qdisc. Drops traffic to blocked DNS server IPs (`blocked_dns_servers`). When leak guard is enabled, drops all outgoing DNS queries whose destination is not in `allowed_dns_servers`, preventing pods from bypassing the injected nameserver.
- Both programs emit events to a BPF ring buffer (`rb`) consumed by userspace for logging.

### Userspace layer (`main.go`)

- **eBPF loader** (`loadBPF`): Loads the bpf2go-generated objects, attaches XDP to the interface, and installs the clsact qdisc + BPF classifier for TC egress. Also handles AWS EKS ENI mode, which watches for new ENI interfaces and attaches dynamically.
- **DNS server**: `miekg/dns` server on `0.0.0.0:53`. Only processes packets that the XDP program allows through. Implements conditional upstream routing via glob pattern matching (`selectUpstream`).
- **Policy manager** (`fetchAndUpdateIPBlocklist`): Fetches per-IP block rules from a remote JSON endpoint, diffs against current map state, and applies incremental updates to the `ip_blocklist` BPF map.
- **Metrics**: Prometheus endpoint at `:9090/metrics`. `reportStats` polls BPF stat maps every few seconds and updates Prometheus gauges and counters.

### BPF maps (shared between kernel and userspace)

| Map | Key | Value | Purpose |
|-----|-----|-------|---------|
| `blocked_domains` | `u32` domain hash | `u8` flag | Global domain blocklist |
| `ip_blocklist` | `{client_ip, domain_hash}` | `u8` flag | Per-source-IP domain rules |
| `blocked_ips` | `u32` IP | `u8` flag | Block IPs found in DNS answers |
| `blocked_dns_servers` | `u32` IP | `u8` flag | Unauthorized DNS server IPs (blacklist) |
| `allowed_dns_servers` | `u32` IP | `u8` flag | Approved DNS server IPs (leak guard allowlist) |
| `dns_leak_guard` | `u32` index 0 | `u8` flag | 1 = leak guard active, drop DNS not in `allowed_dns_servers` |
| `stats` | `u32` index | `u64` counter | XDP/TC packet counters |
| `blocked_src_stats` | `u32` source IP | `u64` counter | Per-source block counts |
| `rb` | — | ring buffer events | Kernel→userspace event stream |

### CI/CD

`.github/workflows/build.yaml` triggers on git tags, builds and pushes a multi-arch (`linux/amd64`, `linux/arm64`) Docker image to `emirozbir/dnsd:{TAG}` on Docker Hub.

### Grafana

`grafana/dashboard.json` is a pre-built dashboard for all `dnsd_*` Prometheus metrics.
