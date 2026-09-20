# dnsd VM image build

Packer configuration that turns this repository into a bootable **Debian 13
(trixie) AMI** running dnsd as a systemd service, with the network stack tuned
for a DNS workload and the base image stripped down to what an eBPF appliance
actually needs.

```
build/
├── dnsd.pkr.hcl                     # sources (amd64 + arm64) and the build block
├── variables.pkr.hcl                # all inputs, with defaults
├── dnsd.auto.pkrvars.hcl.example    # copy to *.auto.pkrvars.hcl and edit
├── Makefile                         # build commands
├── scripts/                         # provisioners, run in filename order
└── files/                           # configuration baked into the image
```

## Requirements

| | |
|---|---|
| Packer | ≥ 1.9 (`brew install packer`) |
| AWS credentials | EC2 permissions to run an instance, create an AMI and snapshot |
| Network | The build instance needs egress to `deb.debian.org`, `go.dev` and `proxy.golang.org` |

The build compiles the eBPF objects and the Go binary **inside the guest**, so
no local Go or LLVM toolchain is required.

## Build commands

```bash
cd build

# One-time: fetch the amazon plugin
make init

# Syntax and variable check — creates nothing in AWS
make validate

# Build both architectures
make build

# Or one at a time
make build-amd64
make build-arm64
```

Override the defaults inline:

```bash
make build VERSION=v1.4.0 REGION=eu-west-1
```

Or with a variables file, which is the better option for anything permanent:

```bash
cp dnsd.auto.pkrvars.hcl.example dnsd.auto.pkrvars.hcl
$EDITOR dnsd.auto.pkrvars.hcl
make build
```

Raw Packer, if you would rather skip the Makefile. The tarball step is **not**
optional: the `file` provisioner stats its source during Prepare, which runs
before any provisioner, so it cannot be produced from inside the build block.

```bash
mkdir -p .artifacts
COPYFILE_DISABLE=1 tar -czf .artifacts/dnsd-src.tar.gz -C .. \
    --exclude='.git' --exclude='build/.artifacts' --exclude='./dnsd' .

packer init .
packer build -var 'dnsd_version=v1.4.0' -only='dnsd.amazon-ebs.amd64' .
```

When a provisioner fails, keep the builder alive and go look:

```bash
make debug          # packer build -on-error=ask, with PACKER_LOG=1
```

The resulting AMI IDs land in `.artifacts/manifest.json` (`make manifest`).

## What the build does

Provisioners run in filename order:

| Script | |
|---|---|
| `00-wait-cloud-init.sh` | Waits out cloud-init and the dpkg lock before touching apt |
| `10-base-packages.sh` | Installs clang/LLVM, and the runtime set (`ethtool`, `iproute2`, `bpftool`, `bind9-dnsutils`) |
| `20-build-dnsd.sh` | Installs Go, runs `go generate` (bpf2go → `bpf/xdp_tc.c`) and `go build` |
| `30-install-dnsd.sh` | Installs the binary, units and tuning config; frees UDP/53 |
| `40-sysctl-tuning.sh` | Applies the sysctls and **fails the build** if a key is rejected |
| `50-nic-tuning.sh` | Runs the ethtool tuning against the builder's NIC as a smoke test |
| `60-purge-packages.sh` | Purges redundant packages, masks noisy timers, strips docs/locales |
| `70-kernel-modules.sh` | Deletes unused module trees, `depmod`, rebuilds the initramfs |
| `80-verify.sh` | Starts dnsd on `lo` and asserts XDP + clsact + `:53` + `/metrics` |
| `99-cleanup.sh` | Removes the toolchain, logs, host keys, machine-id, credentials |

## Network tuning

### sysctl — `/etc/sysctl.d/90-dnsd-network.conf`

Persisted through `sysctl.d`, so it survives reboots and is re-applied by
`systemd-sysctl.service` on every boot. The highlights:

| Key | Value | Why |
|---|---|---|
| `net.core.rmem_max` / `wmem_max` | 16 MiB | Ceiling for the UDP sockets dnsd opens per upstream query |
| `net.ipv4.udp_rmem_min` / `udp_wmem_min` | 256 KiB | Per-socket floor that survives global memory pressure |
| `net.core.netdev_max_backlog` | 65536 | The default 1000 overflows on a query burst *before* userspace sees it |
| `net.core.netdev_budget` / `_usecs` | 1200 / 8000 | Defaults (300/2000) cause drops at high pps on multi-queue ENA |
| `net.ipv4.ip_local_port_range` | 10240–65000 | Each forwarded query consumes a source port |
| `net.core.default_qdisc` | `fq` | Coexists with the `clsact` qdisc dnsd attaches for its TC egress program |
| `net.ipv4.conf.all.rp_filter` | `2` (loose) | Strict mode breaks the asymmetric return paths of a multi-ENI node |
| `net.core.bpf_jit_enable` | `1` | Large win on the per-packet XDP hot path |
| `net.ipv6.conf.all.disable_ipv6` | `1` | The BPF maps are keyed on IPv4; leaving v6 up creates an unfiltered path around dnsd |

`udp_mem` and `tcp_mem` are **not** in that file. They are page counts that only
make sense relative to installed RAM, and the build instance rarely matches the
runtime instance. `dnsd-tune-memory.service` computes them at boot
(`udp_mem` at 6/12/24 % of RAM, `tcp_mem` at 3/6/12 %).

### RX/TX ring buffers — `/usr/local/sbin/dnsd-tune-nic`

Ring buffers are **not** a sysctl. They are driver ring descriptors, set with
`ethtool -G`, and they reset on every boot and every NIC hot-plug — so they
need a unit, not a config file.

`dnsd-tune-nic` reads the *Pre-set maximums* block out of `ethtool -g`, raises
RX and TX to the hardware maximum the driver reports (16384/1024 on ENA,
4096/4096 on virtio-net), sizes the combined queues (see the ENA caveat below),
turns **LRO off** (it coalesces frames in the NIC and destroys the 1:1 packet
view XDP depends on — GRO stays on, since it runs after XDP) and enables
adaptive RX coalescing.

#### ENA caps channels at half the maximum for native XDP

The obvious thing — one queue per CPU — is wrong on ENA. The driver reserves a
TX queue per RX queue for `XDP_TX`/`XDP_REDIRECT`, so it refuses to attach a
native XDP program unless the channel count is **at most half** the hardware
maximum:

```
ena 0000:00:05.0 ens5: Failed to set xdp program, the Rx/Tx channel count
should be at most half of the maximum allowed channel count.
The current queue count (4), the maximal queue count (4)
```

On a `c6i.xlarge` (4 vCPU, ENA max 4 channels) `min(nproc, max)` gives 4 — the
whole maximum — and `-link-mode=driver` then fails outright, dnsd exits, and
`Restart=always` turns it into a crash loop. So when the driver is `ena` *and*
`DNSD_LINK_MODE=driver`, the script caps at `max/2`. In generic mode XDP runs
in the stack and reserves nothing, so the cap is skipped and all channels are
used.

The practical consequence: on a 4-vCPU instance you get 2 XDP queues. If you
need more parallelism in the data path, pick an instance type with more ENA
channels rather than raising the count.

#### ENA also caps the MTU at 3498 for native XDP

The second, independent constraint. ENA has to fit a frame plus headroom and
`skb_shared_info` into a single page, so `ENA_XDP_MAX_MTU` is 3498:

```
ena 0000:00:05.0 ens5: Failed to set xdp program, the current MTU (9001) is
larger than the maximum allowed MTU (3498) while xdp is on
```

EC2 hands out jumbo frames (9001) inside a VPC by default, so `-link-mode=driver`
is impossible until the MTU comes down. `dnsd-tune-nic` lowers it to 3498 before
dnsd attaches, and from then on the driver itself refuses to raise it past the
limit — so this does not need to survive DHCP renewals on its own.

Jumbo frames buy a DNS resolver nothing: queries and answers sit far below 1500
bytes. Override with `DNSD_MTU` in `/etc/default/dnsd` — set `1500` if you run
into path-MTU trouble, since 3498 relies on PMTU discovery working for anything
that sends you larger datagrams.

Both caps are skipped in generic mode, where XDP runs in the stack and the
driver constrains nothing.

Both `ethtool -G` and `ethtool -L` bounce the link (`ena_close`/`ena_open`), so
the script skips any call that would be a no-op, and the unit is ordered after
`network-online.target` — resizing while DHCP is still settling can leave the
instance with no address at all. The build runs the script with
`DNSD_TUNE_DRY_RUN=1` for the same reason: Packer's SSH session rides on the
interface being tuned.

It is driven by udev rather than a static unit:

```
/etc/udev/rules.d/70-dnsd-nic-tune.rules  →  dnsd-tune-nic@<iface>.service
```

so hot-plugged ENIs get tuned the moment they appear — which is the case that
matters in `-ipam aws-vpc-cni` mode, where dnsd watches netlink and attaches
XDP to new ENIs as they arrive. Virtual devices are filtered out by driver
presence, so veth/bridge/tunnel interfaces are skipped without a name list.

Check it on a running instance:

```bash
ethtool -g ens5                 # current vs. maximum rings
ethtool -S ens5 | grep -Ei 'drop|full|no_buf'   # should stay flat under load
systemctl status 'dnsd-tune-nic@ens5.service'
```

## Image slimming

**Packages.** Mail transport, documentation, wireless/bluetooth tooling,
desktop leftovers and `nfs-common`/`rpcbind`/`avahi` are purged; `apt-daily`,
`man-db` and `e2scrub` timers are masked; `/usr/share/{doc,man,info,locale}` is
stripped and excluded from future installs via `dpkg.cfg.d`. `fstrim.timer`
stays — it matters for gp3 performance.

Deliberately **kept**: `openssh-server`, `cloud-init`, the DHCP client,
`systemd-timesyncd` and an editor. Removing any of those turns a recoverable
misconfiguration into an unreachable instance.

**Kernel modules.** Two layers doing different jobs:

1. `/etc/modprobe.d/dnsd-blacklist.conf` — the authoritative control. Every
   entry gets both `blacklist X` (stops udev autoload) *and*
   `install X /bin/false` (stops an explicit `modprobe`), because `blacklist`
   alone does not prevent a direct load. This survives kernel upgrades.
2. `70-kernel-modules.sh` deletes the `.ko` trees outright (sound, media, gpu,
   wireless, bluetooth, firewire, exotic filesystems and network protocols),
   then reruns `depmod` and rebuilds the initramfs. This does **not** survive a
   kernel upgrade — a new `linux-image` restores the files — which is fine for
   an immutable AMI and exactly why layer 1 exists too.

Stripping `drivers/gpu` is the single biggest saving, but it also means the
**EC2 instance screenshot** will show nothing. `drivers/tty/serial` is kept, so
the EC2 serial console still works — that is the better recovery path anyway.
Set `strip_kernel_modules = false` if you depend on screenshots.

Never touched: `ena`, `nvme`, virtio/Xen, `ext4`/`xfs`, `crypto/`, and
`sch_ingress` / `cls_bpf` — dnsd cannot create its TC egress hook without them.

There is **no `sch_clsact` module**: the `clsact` qdisc is registered by
`net/sched/sch_ingress.c`, which builds as `sch_ingress.ko` and carries
`MODULE_ALIAS_NET_SCH("clsact")`. `act_bpf` is not needed either — dnsd
attaches with `DirectAction: true`, which bypasses the action subsystem. So
rather than checking module names, `70-kernel-modules.sh` creates a real
`clsact` qdisc on `lo` and tears it down again: the same netlink call dnsd
makes in `attachTC()`, and the only check that cannot give a false answer.

`initramfs.conf`'s `MODULES=` is left at the Debian default on purpose;
narrowing it to `dep` would bake in the build instance's hardware and could
make the AMI unbootable on another instance family.

## Runtime layout

| Path | |
|---|---|
| `/opt/dashdns/dnsd` | The binary (static, `CGO_ENABLED=0`) |
| `/etc/default/dnsd` | Runtime configuration, **mode 0600** |
| `/etc/systemd/system/dnsd.service` | The service |
| `/etc/dnsd-release` | Version, base OS, build kernel, toolchain versions |
| `/usr/local/sbin/dnsd-tune-nic` | Per-interface ethtool tuning |
| `/usr/local/sbin/dnsd-tune-memory` | RAM-proportional `udp_mem`/`tcp_mem` |

Two details in `dnsd.service` worth knowing about:

- **`LimitMEMLOCK=infinity`** is load-bearing. `main.go` never calls
  `rlimit.RemoveMemlock()`, so without it the BPF maps fail to load with
  `EPERM` on kernels that still account maps against `RLIMIT_MEMLOCK`.
- **The policy token is never passed as a flag.** dnsd reads
  `DNSD_IP_BLOCKLIST_URL` and `DNSD_IP_BLOCKLIST_TOKEN` from the environment,
  so `ExecStart` omits `-ip-blocklist-url`/`-ip-blocklist-token` and the bearer
  token stays out of `/proc/<pid>/cmdline` and `ps`.

`StartLimitIntervalSec=0` with `Restart=always` means the service retries
forever. dnsd calls `log.Fatalf` when its interface is not up yet, which is
normal on a cold boot with a hot-plugged ENI.

### SSH survives first boot

`99-cleanup.sh` deletes `/etc/ssh/ssh_host_*` so every instance gets its own
identity — a host key shared across a fleet makes `known_hosts` meaningless.
Debian, unlike Fedora, has **no unit that regenerates them**. cloud-init's
`cc_ssh` module does, but it is not ordered before `ssh.service`, so sshd can
lose the race and exit with `no hostkeys available`; and if cloud-init fails
for any other reason, SSH never comes up at all.

`dnsd-sshd-keygen.service` (`ExecStart=/usr/bin/ssh-keygen -A`, ordered
`Before=ssh.service ssh.socket`) removes that dependency. `80-verify.sh` proves
it at build time: it moves the host keys aside, runs the same command, and
asserts keys appear and `sshd -t` still passes.

The build also does **not** run `systemctl enable ssh.service`. Debian 13 runs
sshd through socket activation (`ssh.socket`); force-enabling `ssh.service`
alongside it makes both contend for `:22` and `Conflicts=` takes one down.
Whatever the base image had enabled is already correct.

`80-verify.sh` additionally parses every file in `/etc/cloud/cloud.cfg.d/` as
YAML. One malformed file there aborts cloud-init's config stage, which means no
`authorized_keys`, no host keys, and user-data silently ignored — an instance
that boots to a login prompt and answers nothing.

### Getting in when sshd is down

The EC2 serial console needs a password, and Debian AMIs ship the `admin`
account locked, so a boot-time SSH failure normally leaves only one option:
detach the root volume and mount it elsewhere. To avoid that during
development:

```bash
make build-amd64 REGION=eu-central-1 \
    PACKER_EXTRA="-var 'debug_password=<something-long>'"
```

The image is then marked with `/etc/dnsd-DEBUG-IMAGE`. **Never promote a debug
image to production** — it has a password-authenticatable local account.

### systemd-resolved

dnsd binds `0.0.0.0:53`, and a wildcard bind collides with the resolved stub on
`127.0.0.53:53`. Setting `DNSStubListener=no` alone is not enough — on an
appliance whose whole job is owning port 53, the stub returning after a package
upgrade is a silent outage. So `30-install-dnsd.sh` **stops, disables and
masks** `systemd-resolved` (along with `dnsmasq`, `named`, `bind9` and
`unbound` if present), then asserts UDP/53 is actually free before the build
continues.

The host still needs lookups of its own — the policy controller hostname, and
apt for the rest of the build — so `/etc/resolv.conf` is replaced with a static
file *before* resolved goes away:

```
nameserver <DNSD_UPSTREAM host>      # 169.254.169.253 by default
nameserver 169.254.169.253           # AWS VPC resolver, works in any VPC
options timeout:2 attempts:2
```

It deliberately does **not** point at dnsd itself: dnsd has to resolve the
policy controller before it has finished starting, so pointing the host at
`127.0.0.1` would be a startup deadlock.

Three things would otherwise overwrite that file, and all three are pinned:

| | |
|---|---|
| `/etc/dhcp/dhclient-enter-hooks.d/nodnsupdate` | Stubs out `make_resolv_conf` so a DHCP lease renewal leaves it alone |
| `/etc/cloud/cloud.cfg.d/99-dnsd-resolv.cfg` | `manage_resolv_conf: false` |
| `/etc/systemd/resolved.conf.d/10-dnsd.conf` | `DNSStubListener=no`, kept so the intent survives an operator unmasking resolved |

`nss-resolve` is also removed from the `hosts:` line in `/etc/nsswitch.conf`.
Resolution works without this (glibc falls through to the `dns` module when
resolved is unavailable), but it saves a failed socket connect per lookup.

To resolve through dnsd itself after boot, point `/etc/resolv.conf` at
`127.0.0.1` in user-data *after* `systemctl start dnsd` — not before.

## Configuring an instance

Defaults are baked in at build time (`dnsd_iface`, `dnsd_upstream`,
`dnsd_link_mode`, `dnsd_ipam`). Override per instance with user-data:

```yaml
#cloud-config
runcmd:
  - |
    install -m 0600 /dev/stdin /etc/default/dnsd <<'EOF'
    DNSD_IFACE="ens5"
    DNSD_IPAM="aws-vpc-cni"
    DNSD_LINK_MODE="driver"
    DNSD_UPSTREAM="169.254.169.253:53"
    DNSD_UPSTREAM_RULES="*.privatelink.*.amazonaws.com=10.0.0.2:53"
    DNSD_BLOCKLIST=""
    DNSD_BLOCKIPS=""
    DNSD_BLOCKED_DNS="8.8.8.8,1.1.1.1"
    DNSD_IP_BLOCKLIST=""
    DNSD_IP_BLOCKLIST_URL="http://policy-controller.internal:8080"
    DNSD_IP_BLOCKLIST_TOKEN="dnsdap_..."
    DNSD_IP_BLOCKLIST_INTERVAL="1m"
    DNSD_IP_BLOCKLIST_TIMEOUT="30s"
    EOF
  - systemctl restart dnsd
```

Pull the token from Secrets Manager or SSM Parameter Store rather than
embedding it in user-data — user-data is readable by anything on the instance
that can reach IMDS.

### Security group

| Port | Proto | |
|---|---|---|
| 53 | UDP | DNS from clients |
| 9090 | TCP | Prometheus scrape — restrict to the monitoring subnet |
| 22 | TCP | SSH, or drop it entirely and use SSM |

## Verifying a running instance

```bash
systemctl status dnsd
journalctl -u dnsd -f

cat /etc/dnsd-release

ip link show ens5 | grep -o 'xdp[a-z]*'     # XDP attached
tc qdisc show dev ens5 | grep clsact        # TC egress hook
bpftool prog show | grep -E 'xdp|sched_cls'
bpftool map show  | grep -E 'blocked|ip_blocklist'

dig @127.0.0.1 example.com +short
curl -s localhost:9090/metrics | grep '^dnsd_'

sysctl net.core.netdev_max_backlog net.core.rmem_max net.ipv4.udp_mem
ethtool -g ens5
```

## Troubleshooting

**`attaching XDP program: operation not supported`** — the driver has no native
XDP. Set `DNSD_LINK_MODE="generic"` in `/etc/default/dnsd` and restart. Native
mode needs ENA (or ixgbe/i40e/ice/mlx5/virtio-net); `50-nic-tuning.sh` warns at
build time when it cannot confirm it.

**`Failed to set xdp program ... channel count should be at most half`** or
**`... MTU (9001) is larger than the maximum allowed MTU (3498)`** — ENA's two
native-XDP constraints. `dnsd-tune-nic` handles both, so this means it did not
run before dnsd: check `journalctl -u 'dnsd-tune-nic@*'` and confirm the udev
rule fired. Verify by hand with `ethtool -l ens5` (combined must be ≤ max/2) and
`ip link show ens5` (mtu must be ≤ 3498). The quick escape hatch is
`DNSD_LINK_MODE="generic"`, which lifts both constraints at a throughput cost.

**`adding clsact qdisc: no such file or directory`** — `sch_ingress` did not
load (not `sch_clsact`; that module does not exist). Check
`/etc/modules-load.d/dnsd.conf`, `systemctl status systemd-modules-load`, and
confirm by hand with `tc qdisc add dev lo clsact && tc qdisc del dev lo clsact`.

**`loading eBPF objects: permission denied`** — the memlock limit. Confirm
`systemctl show dnsd -p LimitMEMLOCK` reports `infinity`.

**`listen udp 0.0.0.0:53: address already in use`** — something else took the
port: `ss -lunp | grep :53`. Usually the resolved stub came back; confirm with
`systemctl is-enabled systemd-resolved` (should print `masked`) and re-mask it
with `systemctl disable --now systemd-resolved && systemctl mask
systemd-resolved`.

**Packets dropped before dnsd sees them** — `ethtool -S ens5 | grep -Ei
'drop|full|no_buf'`. If those counters climb while `dnsd_*` metrics stay flat,
the loss is at the NIC: confirm `dnsd-tune-nic` ran
(`journalctl -u 'dnsd-tune-nic@*'`) and that `ethtool -g` shows the maximum.

**Build fails in `20-build-dnsd.sh`** — usually `go_version` no longer
satisfies the `go` directive in `go.mod`, or the guest cannot reach
`proxy.golang.org`. Run `make debug` and inspect `/usr/local/src/dnsd`.
