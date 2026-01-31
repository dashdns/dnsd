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
	blocklist := flag.String("blocklist", "", "Comma-separated list of domains to block globally")
	blockips := flag.String("blockips", "", "Comma-separated list of IPs to block in DNS responses")
	blockedDNS := flag.String("blocked-dns", "", "Comma-separated list of blocked DNS server IPs")
	ipBlocklist := flag.String("ip-blocklist", "", "Per-IP blocklist. Format: 'IP1:domain1,domain2;IP2:domain3' (e.g., '5.23.44.53:www.google.com,facebook.com;192.168.1.10:youtube.com')")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root")
	}

	proxy := &DNSProxy{
		iface:          *iface,
		upstreamDNS:    *upstream,
		blockedDomains: make(map[string]bool),
		dnsClient:      &dns.Client{Net: "udp", Timeout: 5 * time.Second},
	}

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

	blockedDNSCount := 0
	if *blockedDNS != "" {
		for _, ip := range strings.Split(*blockedDNS, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				if err := proxy.BlockDNSServer(ip); err != nil {
					log.Printf("Warning: %v", err)
				} else {
					blockedDNSCount++
				}
			}
		}
	}

	// Parse and load per-IP blocklist
	// Format: "IP1:domain1,domain2;IP2:domain3,domain4"
	ipBlocklistCount := 0
	if *ipBlocklist != "" {
		for _, entry := range strings.Split(*ipBlocklist, ";") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			parts := strings.SplitN(entry, ":", 2)
			if len(parts) != 2 {
				log.Printf("Warning: invalid ip-blocklist entry format: %s (expected IP:domain1,domain2)", entry)
				continue
			}
			clientIP := strings.TrimSpace(parts[0])
			domains := strings.Split(parts[1], ",")
			for _, domain := range domains {
				domain = strings.TrimSpace(domain)
				if domain != "" {
					if err := proxy.BlockDomainForIP(clientIP, domain); err != nil {
						log.Printf("Warning: %v", err)
					} else {
						ipBlocklistCount++
					}
				}
			}
		}
	}
	if ipBlocklistCount > 0 {
		log.Printf("Loaded %d per-IP blocklist rules", ipBlocklistCount)
	}

	if blockedDNSCount > 0 {
		log.Printf("DNS server blocklist active: %d DNS server(s) blocked", blockedDNSCount)
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

// BlockDomainForIP adds a domain to the blocklist for a specific client IP
func (p *DNSProxy) BlockDomainForIP(clientIP, domain string) error {
	ip := net.ParseIP(clientIP)
	fmt.Println("The client IP address is ", ip)
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

	if err := p.objs.IpBlocklist.Put(&key, &value); err != nil {
		return fmt.Errorf("blocking domain %s for IP %s: %w", domain, clientIP, err)
	}

	log.Printf("Blocked domain '%s' for IP %s (ipKey=0x%x, hash=0x%x)", domain, clientIP, ipKey, domainHash)
	return nil
}

// UnblockDomainForIP removes a domain from the blocklist for a specific client IP
func (p *DNSProxy) UnblockDomainForIP(clientIP, domain string) error {
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

	if err := p.objs.IpBlocklist.Delete(&key); err != nil {
		return fmt.Errorf("unblocking domain %s for IP %s: %w", domain, clientIP, err)
	}

	log.Printf("Unblocked domain '%s' for IP %s", domain, clientIP)
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

func (p *DNSProxy) BlockDNSServer(ipStr string) error {
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

	if err := p.objs.BlockedDnsServers.Put(&ipKey, &value); err != nil {
		return fmt.Errorf("blocking DNS server %s: %w", ipStr, err)
	}

	log.Printf("Blocked DNS server: %s", ipStr)
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
		Addr: "0.0.0.0:53",
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
	// Get client IP from the request
	clientAddr := w.RemoteAddr().String()
	clientIP, _, err := net.SplitHostPort(clientAddr)
	if err != nil {
		clientIP = clientAddr // fallback if no port
	}
	fmt.Println("Client IP: ", clientIP)

	if len(r.Question) > 0 {
		domain := strings.ToLower(r.Question[0].Name)
		domain = strings.TrimSuffix(domain, ".")
		fmt.Println("The domain address is ", domain)

		// Check per-IP blocklist first
		if p.isBlockedForIP(clientIP, domain) {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			log.Printf("Blocked (userspace per-IP): %s for client %s", domain, clientIP)
			return
		}

		// Check global blocklist
		if p.isBlocked(domain) {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			log.Printf("Blocked (userspace global): %s", domain)
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

// isBlockedForIP checks if a domain is blocked for a specific client IP using BPF map
func (p *DNSProxy) isBlockedForIP(clientIP, domain string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return false // IPv6 not supported
	}

	// Convert to same format as BPF
	ipKey := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
	domainHash := hashDomain(domain)

	key := IPDomainKey{
		ClientIP:   ipKey,
		DomainHash: domainHash,
	}

	var value uint8
	err := p.objs.IpBlocklist.Lookup(&key, &value)
	if err == nil && value == 1 {
		log.Printf("Per-IP blocklist hit: IP=%s domain=%s hash=0x%x", clientIP, domain, domainHash)
		return true
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