# DNSD - eBPF-Based DNS Proxy

DNSD is a high-performance DNS proxy that leverages eBPF (Extended Berkeley Packet Filter) technology using XDP (eXpress Data Path) and TC (Traffic Control) programs for efficient packet-level DNS filtering. It provides fine-grained control over DNS queries with support for both global and per-IP domain blocking policies.

## Features

- **eBPF-Powered Filtering**: Uses XDP for ingress filtering and TC for egress filtering at the kernel level for maximum performance
- **Global Domain Blocking**: Block domains for all clients
- **Per-IP Domain Blocking**: Apply different blocking rules per client IP address
- **Dynamic Policy Management**: Fetch and auto-refresh blocking policies from a remote API endpoint
- **DNS Server Blocking**: Prevent clients from using unauthorized DNS servers
- **IP Response Blocking**: Block specific IPs from appearing in DNS responses
- **Real-time Statistics**: Monitor packet counts, blocked queries, and allowed queries
- **Kubernetes Ready**: Works as both a standalone service and within Kubernetes clusters
- **Multi-Architecture**: Supports both `linux/amd64` and `linux/arm64` platforms

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │              DNSD                       │
                    │  ┌─────────────────────────────────────┐│
   DNS Query        │  │         Userspace (Go)              ││
  ────────────►     │  │  ┌─────────┐  ┌──────────────────┐  ││
                    │  │  │  DNS    │  │  Policy Manager  │  ││
                    │  │  │ Server  │  │  (Remote Fetch)  │  ││
                    │  │  └────┬────┘  └────────┬─────────┘  ││
                    │  └───────┼────────────────┼────────────┘│
                    │          │                │             │
                    │  ┌───────▼────────────────▼────────────┐│
                    │  │         eBPF Maps                   ││
                    │  │  blocked_domains | ip_blocklist     ││
                    │  │  blocked_ips | blocked_dns_servers  ││
                    │  └───────┬────────────────┬────────────┘│
                    │          │                │             │
                    │  ┌───────▼──────┐  ┌──────▼───────┐     │
                    │  │  XDP Program │  │  TC Program  │     │
                    │  │  (Ingress)   │  │  (Egress)    │     │
                    │  └──────────────┘  └──────────────┘     │
                    └─────────────────────────────────────────┘
```

## Requirements

- Linux kernel 5.4+ with eBPF support
- Root privileges (CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_RESOURCE)
- Go 1.21+ (for building from source)
- Clang/LLVM 11+ (for compiling eBPF programs)

## Installation

### Using Docker

```bash
docker pull emirozbir/dnsd:latest
```

### Building from Source

```bash
# Install dependencies (Debian/Ubuntu)
apt-get install -y clang llvm libbpf-dev libelf-dev linux-libc-dev

# Install bpf2go
go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Build
go generate
go build -o dnsd
```

### Using Docker Build

```bash
docker build -t dnsd:latest .
```

## Usage

### Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-iface` | `lo` | Network interface to attach XDP/TC programs |
| `-upstream` | `8.8.8.8:53` | Upstream DNS server address |
| `-blocklist` | - | Comma-separated list of domains to block globally |
| `-blockips` | - | Comma-separated list of IPs to block in DNS responses |
| `-blocked-dns` | - | Comma-separated list of blocked DNS server IPs |
| `-ip-blocklist` | - | Per-IP blocklist in format: `IP1:domain1,domain2;IP2:domain3` |
| `-ip-blocklist-url` | - | URL to fetch per-IP blocklist from (JSON format) |
| `-ip-blocklist-interval` | `5m` | Interval to refresh the remote IP blocklist |

### Standalone Mode

```bash
# Basic usage - block facebook.com and google.com for all clients
sudo ./dnsd -iface eth0 -upstream 1.1.1.1:53 -blocklist "facebook.com,google.com"

# Per-IP blocking - block youtube.com only for specific IPs
sudo ./dnsd -iface eth0 -upstream 1.1.1.1:53 \
  -ip-blocklist "192.168.1.100:youtube.com,netflix.com;192.168.1.101:tiktok.com"

# Block unauthorized DNS servers
sudo ./dnsd -iface eth0 -upstream 1.1.1.1:53 -blocked-dns "8.8.8.8,8.8.4.4"

# Dynamic policy fetching from a remote API
sudo ./dnsd -iface eth0 -upstream 1.1.1.1:53 \
  -ip-blocklist-url "http://policy-server:8080/api/policies" \
  -ip-blocklist-interval 1m
```

### Kubernetes Deployment

Deploy DNSD as a DaemonSet or Deployment in your Kubernetes cluster:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dashdns
  labels:
    app: dashdns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: dashdns
  template:
    metadata:
      labels:
        app: dashdns
    spec:
      containers:
        - name: dashdns
          image: emirozbir/dnsd:v1
          command: ["/opt/dashdns/dnsd"]
          args:
            - "-iface=eth0"
            - "-upstream=1.1.1.1:53"
            - "-ip-blocklist-url=http://policy-controller:5959/api/policies"
          ports:
            - containerPort: 53
              protocol: UDP
          securityContext:
            privileged: true
            capabilities:
              add:
                - SYS_ADMIN
                - NET_ADMIN
                - SYS_RESOURCE
          volumeMounts:
            - name: bpf
              mountPath: /sys/fs/bpf
            - name: debug
              mountPath: /sys/kernel/debug
              readOnly: true
      volumes:
        - name: bpf
          hostPath:
            path: /sys/fs/bpf
            type: Directory
        - name: debug
          hostPath:
            path: /sys/kernel/debug
            type: Directory
---
apiVersion: v1
kind: Service
metadata:
  name: dashdns
spec:
  type: NodePort
  selector:
    app: dashdns
  ports:
    - port: 53
      targetPort: 53
      nodePort: 30053
      protocol: UDP
```

## Remote Policy API Format

When using `-ip-blocklist-url`, the remote endpoint should return JSON in the following format:

```json
{
  "blocklist": [
    {
      "ip": "192.168.1.100",
      "domains": ["facebook.com", "instagram.com"]
    },
    {
      "ip": "192.168.1.101",
      "domains": ["youtube.com", "tiktok.com"]
    }
  ]
}
```

DNSD will automatically:
- Fetch the blocklist on startup
- Periodically refresh based on `-ip-blocklist-interval`
- Diff changes to add new rules and remove stale ones

## How It Works

1. **XDP Program (Ingress)**: Attached to the network interface, inspects incoming DNS queries at the earliest possible point in the network stack. Blocked queries are dropped before reaching userspace.

2. **TC Program (Egress)**: Monitors outgoing traffic to detect and block DNS queries to unauthorized DNS servers.

3. **Userspace DNS Server**: Handles DNS queries that pass through eBPF filters, performs additional policy checks, and forwards allowed queries to the upstream DNS server.

4. **eBPF Maps**: Shared data structures between kernel and userspace for storing:
   - `blocked_domains`: Global domain blocklist (domain hash -> blocked)
   - `ip_blocklist`: Per-IP domain blocklist (client_ip + domain_hash -> blocked)
   - `blocked_ips`: IPs to block in DNS responses
   - `blocked_dns_servers`: Unauthorized DNS servers to block

## Statistics

DNSD reports statistics every 10 seconds:

```
Stats - Total: 1523, DNS: 342, Blocked: 45, Allowed: 297
```

- **Total**: Total packets processed
- **DNS**: DNS packets identified
- **Blocked**: Queries blocked by eBPF
- **Allowed**: Queries passed through

## Roadmap

- [ ] Support for XDP driver mode (qlink, skb, and generic mode selection)
- [ ] IPv6 support
- [ ] DNS over HTTPS (DoH) upstream support
- [ ] Web-based management UI
- [ ] Prometheus metrics endpoint

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
