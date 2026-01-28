package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf/xdp_tc.c -- -I/usr/include/bpf -Wall

type DNSProxy struct {
	iface          string
	upstreamDNS    string
	xdpLink        link.Link
	tcLink         link.Link
	objs           *bpfObjects
	blockedDomains map[string]bool
	ipAllowlist    map[string][]string // clientIP -> allowed domains
	dnsClient      *dns.Client
}

// IPDomainKey matches the BPF ip_domain_key struct
type IPDomainKey struct {
	ClientIP   uint32
	DomainHash uint32
}

func main() {
	iface := flag.String("iface", "lo", "Network interface to attach XDP/TC programs")
	upstream := flag.String("upstream", "8.8.8.8:53", "Upstream DNS server")
	blocklist := flag.String("blocklist", "www.google.com", "Comma-separated list of domains to block")
	blockips := flag.String("blockips", "", "Comma-separated list of IPs to block in DNS responses")
	allowedDNS := flag.String("allowed-dns", "", "Comma-separated list of allowed DNS server IPs (whitelist). All other DNS servers will be blocked!")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root")
	}

	proxy := &DNSProxy{
		iface:          *iface,
		upstreamDNS:    *upstream,
		blockedDomains: make(map[string]bool),
		ipAllowlist:    make(map[string][]string),
		dnsClient:      &dns.Client{Net: "udp", Timeout: 5 * time.Second},
	}

	// Example: Configure per-IP allowlist (will be loaded after BPF init)
	// TODO: Load from config file
	proxy.ipAllowlist["192.168.1.10"] = []string{"www.google.com", "google.com"}
	proxy.ipAllowlist["192.168.1.20"] = []string{"www.youtube.com", "youtube.com"}

	if *blocklist != "" {
		for _, domain := range strings.Split(*blocklist, ",") {
			domain = strings.TrimSpace(domain)
			if domain != "" {
				proxy.blockedDomains[strings.ToLower(domain)] = true
				log.Printf("Blocking domain: %s", domain)
			}
		}
	}

	if err := proxy.loadBPF(); err != nil {
		log.Fatalf("Failed to load eBPF programs: %v", err)
	}
	defer proxy.cleanup()

	if err := proxy.updateBlocklist(); err != nil {
		log.Fatalf("Failed to update blocklist: %v", err)
	}

	// Load per-IP allowlist into BPF map
	if err := proxy.LoadIPAllowlist(); err != nil {
		log.Fatalf("Failed to load IP allowlist: %v", err)
	}
	log.Printf("Loaded %d IP allowlist rules", len(proxy.ipAllowlist))

	if *blockips != "" {
		for _, ip := range strings.Split(*blockips, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				if err := proxy.BlockIP(ip); err != nil {
					log.Printf("Warning: %v", err)
				}
			}
		}
	}

	allowedCount := 0
	if *allowedDNS != "" {
		for _, ip := range strings.Split(*allowedDNS, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				if err := proxy.AllowDNSServer(ip); err != nil {
					log.Printf("Warning: %v", err)
				} else {
					allowedCount++
				}
			}
		}
	}

	if allowedCount > 0 {
		log.Printf("DNS whitelist active: only %d DNS server(s) allowed, all others will be BLOCKED", allowedCount)
	} else {
		log.Printf("WARNING: No allowed DNS servers specified! ALL DNS queries will be BLOCKED!")
	}

	log.Printf("DNS Proxy started on interface %s", *iface)
	log.Printf("Upstream DNS: %s", *upstream)
	log.Printf("Blocking %d domains", len(proxy.blockedDomains))

	go proxy.reportStats()

	go proxy.startDNSServer()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
}

func (p *DNSProxy) loadBPF() error {
	objs := &bpfObjects{}
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	}
	if err := loadBpfObjects(objs, opts); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	p.objs = objs

	iface, err := net.InterfaceByName(p.iface)
	if err != nil {
		return fmt.Errorf("getting interface %s: %w", p.iface, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDnsFilter,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP program: %w", err)
	}
	p.xdpLink = xdpLink
	log.Printf("XDP program attached to %s (generic/SKB mode) - blocking queries for blocked domains", p.iface)

	if err := p.attachTC(iface.Index); err != nil {
		return fmt.Errorf("attaching TC program: %w", err)
	}

	return nil
}

func (p *DNSProxy) attachTC(ifaceIndex int) error {
	link, err := netlink.LinkByIndex(ifaceIndex)
	if err != nil {
		return fmt.Errorf("getting link by index: %w", err)
	}

	// Create qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifaceIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	netlink.QdiscDel(qdisc)

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("adding clsact qdisc: %w", err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifaceIndex,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  syscall.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           p.objs.TcDnsFilter.FD(),
		Name:         "tc_dns_filter",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("adding TC filter: %w", err)
	}

	log.Printf("TC program attached to %s (egress) - blocking unauthorized DNS servers", link.Attrs().Name)
	return nil
}

func (p *DNSProxy) updateBlocklist() error {
	for domain := range p.blockedDomains {
		hash := hashDomain(domain)
		value := uint8(1)
		if err := p.objs.BlockedDomains.Put(&hash, &value); err != nil {
			return fmt.Errorf("updating blocklist for %s: %w", domain, err)
		}
	}
	return nil
}

// AllowDomain adds a domain to the allowlist for a specific client IP
func (p *DNSProxy) AllowDomain(clientIP, domain string) error {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", clientIP)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 supported: %s", clientIP)
	}

	// Convert to same format as BPF (network byte order in little-endian uint32)
	ipKey := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
	domainHash := hashDomain(domain)

	key := IPDomainKey{
		ClientIP:   ipKey,
		DomainHash: domainHash,
	}
	value := uint8(1)

	if err := p.objs.IpAllowlist.Put(&key, &value); err != nil {
		return fmt.Errorf("allowing domain %s for IP %s: %w", domain, clientIP, err)
	}

	log.Printf("Allowed domain '%s' for IP %s", domain, clientIP)
	return nil
}

// RevokeDomain removes a domain from the allowlist for a specific client IP
func (p *DNSProxy) RevokeDomain(clientIP, domain string) error {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", clientIP)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 supported: %s", clientIP)
	}

	ipKey := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
	domainHash := hashDomain(domain)

	key := IPDomainKey{
		ClientIP:   ipKey,
		DomainHash: domainHash,
	}

	if err := p.objs.IpAllowlist.Delete(&key); err != nil {
		return fmt.Errorf("revoking domain %s for IP %s: %w", domain, clientIP, err)
	}

	log.Printf("Revoked domain '%s' for IP %s", domain, clientIP)
	return nil
}

// LoadIPAllowlist loads per-IP allowlist rules into BPF map
func (p *DNSProxy) LoadIPAllowlist() error {
	for clientIP, domains := range p.ipAllowlist {
		for _, domain := range domains {
			if err := p.AllowDomain(clientIP, domain); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *DNSProxy) BlockIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 supported: %s", ipStr)
	}

	ipKey := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
	value := uint8(1)

	if err := p.objs.BlockedIps.Put(&ipKey, &value); err != nil {
		return fmt.Errorf("blocking IP %s: %w", ipStr, err)
	}

	log.Printf("Blocked IP: %s", ipStr)
	return nil
}

func (p *DNSProxy) AllowDNSServer(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 supported: %s", ipStr)
	}

	// Network byte order - BPF'teki ip->daddr ile aynı format
	// Little-endian makinede bellekte: ip4[0] ip4[1] ip4[2] ip4[3] sırasıyla saklanır
	ipKey := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
	value := uint8(1)

	if err := p.objs.AllowedDnsServers.Put(&ipKey, &value); err != nil {
		return fmt.Errorf("allowing DNS server %s: %w", ipStr, err)
	}

	log.Printf("Allowed DNS server: %s", ipStr)
	return nil
}

func hashDomain(domain string) uint32 { // for bpf side
	hash := uint32(5381)
	for _, c := range "." + strings.ToLower(domain) {
		hash = ((hash << 5) + hash) + uint32(c)
	}
	return hash
}

func (p *DNSProxy) reportStats() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var total, dnsPackets, blocked, allowed uint64

		key := uint32(0)
		p.objs.Stats.Lookup(&key, &total)

		key = uint32(1)
		p.objs.Stats.Lookup(&key, &dnsPackets)

		key = uint32(2)
		p.objs.Stats.Lookup(&key, &blocked)

		key = uint32(3)
		p.objs.Stats.Lookup(&key, &allowed)

		log.Printf("Stats - Total: %d, DNS: %d, Blocked: %d, Allowed: %d",
			total, dnsPackets, blocked, allowed)
	}
}

func (p *DNSProxy) startDNSServer() {
	server := &dns.Server{
		Addr: "127.0.0.1:5353",
		Net:  "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			p.handleDNSRequest(w, r)
		}),
	}

	log.Printf("DNS server listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
}

func (p *DNSProxy) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) > 0 {
		domain := strings.ToLower(r.Question[0].Name)
		domain = strings.TrimSuffix(domain, ".")

		if p.isBlocked(domain) {
			// Return NXDOMAIN for blocked domains
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			log.Printf("Blocked (userspace): %s", domain)
			return
		}
	}

	resp, _, err := p.dnsClient.Exchange(r, p.upstreamDNS)
	if err != nil {
		log.Printf("Error forwarding DNS query: %v", err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	w.WriteMsg(resp)
}

func (p *DNSProxy) isBlocked(domain string) bool {
	domain = strings.ToLower(domain)

	// Check exact match
	if p.blockedDomains[domain] {
		return true
	}

	// Check subdomains
	parts := strings.Split(domain, ".")
	for i := range parts {
		subdomain := strings.Join(parts[i:], ".")
		if p.blockedDomains[subdomain] {
			return true
		}
	}

	return false
}

func (p *DNSProxy) cleanup() {
	if p.xdpLink != nil {
		p.xdpLink.Close()
	}

	if p.objs != nil {
		p.objs.Close()
	}

	// Remove TC qdisc
	if link, err := net.InterfaceByName(p.iface); err == nil {
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Index,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
			QdiscType: "clsact",
		}
		netlink.QdiscDel(qdisc)
	}

	log.Println("Cleanup completed")
}
