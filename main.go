package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
)

const (
	AWS_VPC_CNI = "aws-vpc-cni"
	DEFAULT     = "onpremise"
	LINK_MODE   = ""
)

var (
	// XDP packet counters
	metricXDPTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_xdp_packets_total",
		Help: "Total packets seen by XDP program",
	})
	metricXDPDNSQueries = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_xdp_dns_queries_total",
		Help: "DNS query packets seen by XDP program",
	})
	metricXDPBlocked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_xdp_blocked_total",
		Help: "DNS queries blocked by XDP program",
	})
	metricXDPAllowed = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_xdp_allowed_total",
		Help: "DNS queries allowed by XDP program",
	})

	// TC response counters
	metricTCDNSResponses = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_tc_dns_responses_total",
		Help: "DNS responses seen by TC program",
	})
	metricTCBlockedResponses = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_tc_blocked_responses_total",
		Help: "DNS responses blocked by TC program",
	})
	metricTCAllowedResponses = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_tc_allowed_responses_total",
		Help: "DNS responses allowed by TC program",
	})
	metricTCIPBlockedResponses = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_tc_ip_blocked_responses_total",
		Help: "DNS responses blocked by TC per-IP rules",
	})

	// BPF map entry counts
	metricBlockedDomainsCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_blocked_domains_count",
		Help: "Number of entries in blocked_domains BPF map",
	})
	metricBlockedIPsCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_blocked_ips_count",
		Help: "Number of entries in blocked_ips BPF map",
	})
	metricBlockedDNSServersCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_blocked_dns_servers_count",
		Help: "Number of entries in blocked_dns_servers BPF map",
	})
	metricIPBlocklistRulesCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_ip_blocklist_rules_count",
		Help: "Number of entries in ip_blocklist BPF map",
	})

	// Per-source-IP blocked query counter
	metricSourceBlocked = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dnsd_source_blocked_total",
		Help: "Total blocked queries per source IP",
	}, []string{"source_ip"})

	// Policy controller (GET /api/policies) client metrics
	metricPolicyRevision = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_policy_revision",
		Help: "Policy revision reported by the controller via X-Policy-Revision",
	})
	metricPolicyFetchTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dnsd_policy_fetch_total",
		Help: "Policy fetch attempts by result (updated, not_modified, error)",
	}, []string{"result"})
	metricPolicyLastSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsd_policy_last_success_timestamp_seconds",
		Help: "Unix timestamp of the last successful policy fetch (200 or 304)",
	})
)

func init() {
	prometheus.MustRegister(
		metricXDPTotal,
		metricXDPDNSQueries,
		metricXDPBlocked,
		metricXDPAllowed,
		metricTCDNSResponses,
		metricTCBlockedResponses,
		metricTCAllowedResponses,
		metricTCIPBlockedResponses,
		metricBlockedDomainsCount,
		metricBlockedIPsCount,
		metricBlockedDNSServersCount,
		metricIPBlocklistRulesCount,
		metricSourceBlocked,
		metricPolicyRevision,
		metricPolicyFetchTotal,
		metricPolicyLastSuccess,
	)
}

// IPBlocklistEntry is one entry of the frozen GET /api/policies payload
// (pkg/dnsdcontract): an IPv4 client address plus the domains blocked for it.
type IPBlocklistEntry struct {
	IP      string   `json:"ip"`
	Domains []string `json:"domains"`
}

// APIError is the single error shape used by every policy-controller endpoint.
type APIError struct {
	Status    int               `json:"-"`
	RequestID string            `json:"-"`
	Code      string            `json:"error"`
	Message   string            `json:"message"`
	Details   map[string]string `json:"details,omitempty"`
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "policy api: %d", e.Status)
	if e.Code != "" {
		fmt.Fprintf(&b, " %s", e.Code)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, ": %s", e.Message)
	}
	for field, reason := range e.Details {
		fmt.Fprintf(&b, " (%s: %s)", field, reason)
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, " [request-id=%s]", e.RequestID)
	}
	return b.String()
}

// UpstreamRule maps a glob domain pattern to a specific upstream DNS server.
// A single "*" matches exactly one label; "default" is the catch-all fallback.
type UpstreamRule struct {
	Pattern  string // e.g. "*.privatelink.*.windows.net"
	Upstream string // e.g. "168.63.129.16:53"
}

// IPBlocklistResponse is the body of GET /api/policies. With no policies the
// controller sends {"blocklist":[]} — never null.
type IPBlocklistResponse struct {
	Blocklist []IPBlocklistEntry `json:"blocklist"`
}

// policyEndpointPath is the appliance-plane endpoint of the policy controller.
const policyEndpointPath = "/api/policies"

// maxPolicyBodyBytes caps how much of a response body we are willing to read.
const maxPolicyBodyBytes = 8 << 20

// policyClient talks to the appliance plane of the policy controller
// (GET /api/policies). It keeps the validators of the last response so
// subsequent polls are conditional requests.
type policyClient struct {
	url        string
	token      string
	httpClient *http.Client

	etag         string
	lastModified string
	revision     string
}

func newPolicyClient(rawURL, token string, timeout time.Duration) *policyClient {
	return &policyClient{
		url:        rawURL,
		token:      token,
		httpClient: &http.Client{Timeout: timeout},
	}
}

// resolvePolicyURL accepts either the controller base URL
// ("http://policy-controller:8080") or the full endpoint URL
// ("http://policy-controller:8080/api/policies") and returns the latter.
func resolvePolicyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid policy url %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid policy url %q: missing host", raw)
	}
	if path := strings.TrimSuffix(u.Path, "/"); path == "" {
		u.Path = policyEndpointPath
	}
	return u.String(), nil
}

// fetch performs a conditional GET against /api/policies. A 304 response
// returns (nil, false, nil): the cached policies are still current.
func (c *policyClient) fetch() (*IPBlocklistResponse, bool, error) {
	req, err := http.NewRequest(http.MethodGet, c.url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("building policy request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	// If-Modified-Since is only considered when If-None-Match is absent
	// (RFC 9110 13.1.3), so send at most one of them.
	switch {
	case c.etag != "":
		req.Header.Set("If-None-Match", c.etag)
	case c.lastModified != "":
		req.Header.Set("If-Modified-Since", c.lastModified)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("fetching policies: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// The validators are re-sent on 304 as well; keep tracking them.
		c.rememberValidators(resp)
		return nil, false, nil
	case http.StatusOK:
	default:
		return nil, false, parseAPIError(resp)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyBodyBytes))
	if err != nil {
		return nil, false, fmt.Errorf("reading policy response: %w", err)
	}

	var policies IPBlocklistResponse
	if err := json.Unmarshal(body, &policies); err != nil {
		return nil, false, fmt.Errorf("parsing policy response: %w", err)
	}

	c.rememberValidators(resp)
	return &policies, true, nil
}

// rememberValidators stores the cache validators and revision of a response so
// the next poll can be conditional.
func (c *policyClient) rememberValidators(resp *http.Response) {
	if etag := resp.Header.Get("ETag"); etag != "" {
		c.etag = etag
	}
	if lastModified := resp.Header.Get("Last-Modified"); lastModified != "" {
		c.lastModified = lastModified
	}
	if revision := resp.Header.Get("X-Policy-Revision"); revision != "" {
		c.revision = revision
		if parsed, err := strconv.ParseFloat(revision, 64); err == nil {
			metricPolicyRevision.Set(parsed)
		}
	}
}

// parseAPIError turns a non-2xx response into an *APIError, falling back to the
// raw body when it is not the documented JSON error shape.
func parseAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	apiErr := &APIError{
		Status:    resp.StatusCode,
		RequestID: resp.Header.Get("X-Request-ID"),
	}
	if err := json.Unmarshal(body, apiErr); err != nil || apiErr.Message == "" {
		apiErr.Message = strings.TrimSpace(string(body))
		if apiErr.Message == "" {
			apiErr.Message = http.StatusText(resp.StatusCode)
		}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		if challenge := resp.Header.Get("WWW-Authenticate"); challenge != "" {
			apiErr.Message += fmt.Sprintf(" (WWW-Authenticate: %s)", challenge)
		}
	}
	return apiErr
}

// normalizeDomain mirrors the controller-side normalization so a domain hashes
// to the same BPF key regardless of the casing or trailing dot we were sent.
func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf/xdp_tc.c -- -I/usr/include/bpf -Wall

type DNSProxy struct {
	iface            string
	upstreamDNS      string
	upstreamRules    []UpstreamRule
	xdpLink          link.Link
	tcLink           link.Link
	objs             *bpfObjects
	blockedDomains   map[string]bool
	dnsClient        *dns.Client
	policyAPI        *policyClient
	ipBlocklistMu    sync.RWMutex
	currentBlocklist []IPBlocklistEntry
	ipam             string
	linkTypeMap      map[string]link.XDPAttachFlags
	ringReader       *ringbuf.Reader
}

// IPDomainKey matches the BPF ip_domain_key struct
type IPDomainKey struct {
	ClientIP   uint32
	DomainHash uint32
}

// LogEvent matches the BPF log_event struct (28 bytes)
type LogEvent struct {
	TimestampNs uint64
	SrcIP       uint32
	DstIP       uint32
	DomainHash  uint32
	SrcPort     uint16
	DstPort     uint16
	Action      uint8
	Pad         [3]byte
}

const (
	logActionAllowed = uint8(0)
	logActionBlocked = uint8(1)
)

func main() {
	iface := flag.String("iface", "lo", "Network interface to attach XDP/TC programs")
	upstream := flag.String("upstream", "8.8.8.8:53", "Upstream DNS server (default fallback)")
	upstreamRulesFlag := flag.String("upstream-rules", "", "Conditional upstream rules. Format: 'pattern=host:port;pattern2=host2:port2' (e.g., '*.privatelink.*.windows.net=168.63.129.16:53')")
	blocklist := flag.String("blocklist", "", "Comma-separated list of domains to block globally")
	blockips := flag.String("blockips", "", "Comma-separated list of IPs to block in DNS responses")
	blockedDNS := flag.String("blocked-dns", "", "Comma-separated list of blocked DNS server IPs")
	ipBlocklist := flag.String("ip-blocklist", "", "Per-IP blocklist. Format: 'IP1:domain1,domain2;IP2:domain3' (e.g., '5.23.44.53:www.google.com,facebook.com;192.168.1.10:youtube.com')")
	ipBlocklistURL := flag.String("ip-blocklist-url", os.Getenv("DNSD_IP_BLOCKLIST_URL"), "Policy controller URL. Either the base URL (http://host:8080) or the full endpoint (http://host:8080/api/policies). Env: DNSD_IP_BLOCKLIST_URL")
	ipBlocklistToken := flag.String("ip-blocklist-token", os.Getenv("DNSD_IP_BLOCKLIST_TOKEN"), "Appliance token (dnsdap_...) sent as 'Authorization: Bearer'. Env: DNSD_IP_BLOCKLIST_TOKEN")
	ipBlocklistInterval := flag.Duration("ip-blocklist-interval", 5*time.Minute, "Interval to refresh the remote IP blocklist")
	ipBlocklistTimeout := flag.Duration("ip-blocklist-timeout", 30*time.Second, "HTTP timeout for a policy controller request")
	linkMode := flag.String("link-mode", "generic", "The type of links while attaching XDP programs")
	ipam := flag.String("ipam", "onpremise", "The identifer which gives details for CNI ipam usage.")

	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root")
	}
	linkTypeMap := make(map[string]link.XDPAttachFlags)
	linkTypeMap["generic"] = link.XDPGenericMode
	linkTypeMap["driver"] = link.XDPDriverMode
	linkTypeMap["offload"] = link.XDPOffloadMode

	policyURL, err := resolvePolicyURL(*ipBlocklistURL)
	if err != nil {
		log.Fatalf("Invalid -ip-blocklist-url: %v", err)
	}

	proxy := &DNSProxy{
		iface:            *iface,
		upstreamDNS:      *upstream,
		blockedDomains:   make(map[string]bool),
		dnsClient:        &dns.Client{Net: "udp", Timeout: 5 * time.Second},
		currentBlocklist: []IPBlocklistEntry{},
		linkTypeMap:      linkTypeMap,
		ipam:             *ipam,
	}

	if policyURL != "" {
		token := strings.TrimSpace(*ipBlocklistToken)
		switch {
		case token == "":
			log.Printf("Warning: no -ip-blocklist-token given; the controller will answer 401 unless it runs with -require-appliance-auth=false")
		case strings.HasPrefix(token, "dnsdsn_"):
			log.Fatalf("-ip-blocklist-token looks like an admin session token (dnsdsn_); dnsd needs an appliance token (dnsdap_) from POST /api/admin/appliances")
		case !strings.HasPrefix(token, "dnsdap_"):
			log.Printf("Warning: -ip-blocklist-token does not have the expected dnsdap_ prefix")
		}
		proxy.policyAPI = newPolicyClient(policyURL, token, *ipBlocklistTimeout)
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

	switch *ipam {
	case AWS_VPC_CNI:
		interfaces, err := net.Interfaces()
		if err != nil {
			log.Fatalf("Error while fetching interfaces: %v", err)
		}
		fmt.Println("The list of interfaces", interfaces)
		loaded := 0
		for _, intf := range interfaces {
			if strings.Contains(intf.Name, "ens") {
				if err := proxy.loadBPF(intf.Name, linkMode); err != nil {
					log.Printf("Failed to load eBPF on existing interface %s: %v", intf.Name, err)
				} else {
					loaded++
				}
			}
		}

		if loaded == 0 {
			log.Printf("No ENI interfaces found on startup, watching for new ones...")
		}

		go proxy.watchENIInterfaces(linkMode)
	default:
		if err := proxy.loadBPF("eth0", linkMode); err != nil {
			log.Fatalf("Failed to load eBPF programs: %v iface name: %s", err, "eth0")
		}
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

	// Parse conditional upstream rules
	if *upstreamRulesFlag != "" {
		for _, entry := range strings.Split(*upstreamRulesFlag, ";") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			parts := strings.SplitN(entry, "=", 2)
			if len(parts) != 2 {
				log.Printf("Warning: invalid upstream rule format: %s (expected pattern=host:port)", entry)
				continue
			}
			pattern := strings.TrimSpace(parts[0])
			upstreamAddr := strings.TrimSpace(parts[1])
			proxy.upstreamRules = append(proxy.upstreamRules, UpstreamRule{
				Pattern:  pattern,
				Upstream: upstreamAddr,
			})
			log.Printf("Upstream rule: %s -> %s", pattern, upstreamAddr)
		}
	}

	// Start the policy controller poller if a URL is configured
	if proxy.policyAPI != nil {
		log.Printf("Policy controller: %s", proxy.policyAPI.url)
		// Fetch immediately on startup
		if err := proxy.fetchAndUpdateIPBlocklist(); err != nil {
			log.Printf("Warning: initial policy fetch failed: %v", err)
		}
		// Start periodic refresh
		go proxy.startIPBlocklistRefresher(*ipBlocklistInterval)
	}

	log.Printf("DNS Proxy started on interface %s", *iface)
	log.Printf("Upstream DNS: %s", *upstream)
	log.Printf("Blocking %d domains", len(proxy.blockedDomains))

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		log.Printf("Prometheus metrics server listening on :9090/metrics")
		if err := http.ListenAndServe(":9090", mux); err != nil {
			log.Fatalf("Failed to start metrics server: %v", err)
		}
	}()

	go proxy.reportStats()

	go proxy.startDNSServer()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
}

func (p *DNSProxy) loadBPF(eth string, linkMode *string) error {
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

	iface, err := net.InterfaceByName(eth)
	if err != nil {
		return fmt.Errorf("getting interface %s: %w", p.iface, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDnsFilter,
		Interface: iface.Index,
		Flags:     p.linkTypeMap[*linkMode],
	})
	if err != nil {
		return fmt.Errorf("attaching XDP program: %w", err)
	}
	p.xdpLink = xdpLink
	log.Printf("XDP program attached to %s (generic/SKB mode) - blocking queries for blocked domains", p.iface)

	if err := p.attachTC(iface.Index); err != nil {
		return fmt.Errorf("attaching TC program: %w", err)
	}

	p.startRingBufReader()

	return nil
}

func (p *DNSProxy) watchENIInterfaces(linkMode *string) {
	updates := make(chan netlink.LinkUpdate)
	done := make(chan struct{})

	if err := netlink.LinkSubscribe(updates, done); err != nil {
		log.Printf("Failed to subscribe to network interface changes: %v", err)
		return
	}
	defer close(done)

	log.Printf("Watching for new ENI interfaces...")
	for update := range updates {
		if update.Header.Type == syscall.RTM_NEWLINK && strings.Contains(update.Link.Attrs().Name, "eni") {
			name := update.Link.Attrs().Name
			log.Printf("New ENI interface detected: %s, attaching eBPF programs", name)
			if err := p.loadBPF(name, linkMode); err != nil {
				log.Printf("Failed to load eBPF on new interface %s: %v", name, err)
			}
		}
	}
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
		// The rule is already gone; nothing left to do.
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
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

func uint32ToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF)
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
		var dnsResponses, blockedResponses, allowedResponses, ipBlockedResponses uint64

		key := uint32(0)
		p.objs.Stats.Lookup(&key, &total)

		key = uint32(1)
		p.objs.Stats.Lookup(&key, &dnsPackets)

		key = uint32(2)
		p.objs.Stats.Lookup(&key, &blocked)

		key = uint32(3)
		p.objs.Stats.Lookup(&key, &allowed)

		key = uint32(4)
		p.objs.Stats.Lookup(&key, &dnsResponses)

		key = uint32(5)
		p.objs.Stats.Lookup(&key, &blockedResponses)

		key = uint32(6)
		p.objs.Stats.Lookup(&key, &allowedResponses)

		key = uint32(7)
		p.objs.Stats.Lookup(&key, &ipBlockedResponses)

		// Count BPF map entries
		var blockedDomainsCount, blockedIPsCount, blockedDNSCount, ipBlocklistCount int
		var domainKey uint32
		var ipKey uint32
		var ipDomainKey IPDomainKey
		var val uint8

		iter := p.objs.BlockedDomains.Iterate()
		for iter.Next(&domainKey, &val) {
			blockedDomainsCount++
		}

		var blockedIPsList []string
		iter = p.objs.BlockedIps.Iterate()
		for iter.Next(&ipKey, &val) {
			blockedIPsCount++
			blockedIPsList = append(blockedIPsList, uint32ToIP(ipKey))
		}

		var blockedDNSList []string
		iter = p.objs.BlockedDnsServers.Iterate()
		for iter.Next(&ipKey, &val) {
			blockedDNSCount++
			blockedDNSList = append(blockedDNSList, uint32ToIP(ipKey))
		}

		// Collect per-IP blocklist entries grouped by client IP
		perIPEntries := make(map[string]int)
		ipBlocklistIter := p.objs.IpBlocklist.Iterate()
		for ipBlocklistIter.Next(&ipDomainKey, &val) {
			ipBlocklistCount++
			clientIP := uint32ToIP(ipDomainKey.ClientIP)
			perIPEntries[clientIP]++
		}

		// Update Prometheus metrics
		metricXDPTotal.Set(float64(total))
		metricXDPDNSQueries.Set(float64(dnsPackets))
		metricXDPBlocked.Set(float64(blocked))
		metricXDPAllowed.Set(float64(allowed))
		metricTCDNSResponses.Set(float64(dnsResponses))
		metricTCBlockedResponses.Set(float64(blockedResponses))
		metricTCAllowedResponses.Set(float64(allowedResponses))
		metricTCIPBlockedResponses.Set(float64(ipBlockedResponses))
		metricBlockedDomainsCount.Set(float64(blockedDomainsCount))
		metricBlockedIPsCount.Set(float64(blockedIPsCount))
		metricBlockedDNSServersCount.Set(float64(blockedDNSCount))
		metricIPBlocklistRulesCount.Set(float64(ipBlocklistCount))

		log.Printf("Stats [XDP] Total: %d | DNS queries: %d | Blocked: %d | Allowed: %d",
			total, dnsPackets, blocked, allowed)
		log.Printf("Stats [TC]  DNS responses: %d | Blocked: %d | Allowed: %d | Per-IP blocked: %d",
			dnsResponses, blockedResponses, allowedResponses, ipBlockedResponses)
		log.Printf("Stats [Maps] Blocked domains: %d | Blocked IPs: %d | Blocked DNS servers: %d | Per-IP rules: %d",
			blockedDomainsCount, blockedIPsCount, blockedDNSCount, ipBlocklistCount)
		if len(blockedIPsList) > 0 {
			log.Printf("Stats [Blocked IPs] %s", strings.Join(blockedIPsList, ", "))
		}
		if len(blockedDNSList) > 0 {
			log.Printf("Stats [Blocked DNS Servers] %s", strings.Join(blockedDNSList, ", "))
		}
		for clientIP, ruleCount := range perIPEntries {
			log.Printf("Stats [Per-IP Blocklist] Client %s: %d domain rules", clientIP, ruleCount)
		}

		// Per-source-IP blocked query counts
		metricSourceBlocked.Reset()
		var srcIP uint32
		var srcCount uint64
		srcIter := p.objs.BlockedSrcStats.Iterate()
		for srcIter.Next(&srcIP, &srcCount) {
			srcIPStr := uint32ToIP(srcIP)
			metricSourceBlocked.WithLabelValues(srcIPStr).Set(float64(srcCount))
			log.Printf("Stats [Blocked Source] %s: %d queries blocked", srcIPStr, srcCount)
		}
	}
}

func (p *DNSProxy) startRingBufReader() {
	rd, err := ringbuf.NewReader(p.objs.Rb)
	if err != nil {
		log.Printf("Failed to open ring buffer reader: %v", err)
		return
	}
	p.ringReader = rd

	go func() {
		var event LogEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("Ring buffer read error: %v", err)
				continue
			}
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Failed to decode ring buffer event: %v", err)
				continue
			}

			srcIP := uint32ToIP(event.SrcIP)
			action := "ALLOWED"
			if event.Action == logActionBlocked {
				action = "BLOCKED"
			}
			log.Printf("[BPF] %s src=%s:%d domain_hash=0x%x",
				action, srcIP, event.SrcPort, event.DomainHash)
		}
	}()
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

	qname := ""
	if len(r.Question) > 0 {
		qname = r.Question[0].Name
	}
	upstream := p.selectUpstream(qname)
	resp, _, err := p.dnsClient.Exchange(r, upstream)
	if err != nil {
		log.Printf("Error forwarding DNS query: %v", err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	w.WriteMsg(resp)
}

// selectUpstream returns the upstream DNS server for the given domain.
// Rules are evaluated in order; the first match wins. Falls back to p.upstreamDNS.
func (p *DNSProxy) selectUpstream(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, rule := range p.upstreamRules {
		if matchGlobDomain(rule.Pattern, domain) {
			log.Printf("Upstream routing: %s -> %s (rule: %s)", domain, rule.Upstream, rule.Pattern)
			return rule.Upstream
		}
	}
	return p.upstreamDNS
}

// matchGlobDomain matches a domain against a pattern where "*" matches exactly one label.
// Example: "*.privatelink.*.windows.net" matches "foo.privatelink.bar.windows.net".
func matchGlobDomain(pattern, domain string) bool {
	patternParts := strings.Split(strings.ToLower(pattern), ".")
	domainParts := strings.Split(domain, ".")
	if len(patternParts) != len(domainParts) {
		return false
	}
	for i, p := range patternParts {
		if p == "*" {
			continue
		}
		if p != domainParts[i] {
			return false
		}
	}
	return true
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
	if p.ringReader != nil {
		p.ringReader.Close()
	}

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

// fetchAndUpdateIPBlocklist polls GET /api/policies on the policy controller and
// reconciles the per-IP BPF map with the response. A 304 leaves the maps alone.
func (p *DNSProxy) fetchAndUpdateIPBlocklist() error {
	if p.policyAPI == nil {
		return nil
	}

	policies, changed, err := p.policyAPI.fetch()
	if err != nil {
		metricPolicyFetchTotal.WithLabelValues("error").Inc()
		return err
	}

	metricPolicyLastSuccess.SetToCurrentTime()

	if !changed {
		metricPolicyFetchTotal.WithLabelValues("not_modified").Inc()
		log.Printf("Policies unchanged (revision %s)", p.policyAPI.revisionLabel())
		return nil
	}

	metricPolicyFetchTotal.WithLabelValues("updated").Inc()
	p.applyPolicies(policies.Blocklist)
	return nil
}

// applyPolicies diffs the freshly fetched policies against the ones currently in
// the BPF map and applies only the difference.
func (p *DNSProxy) applyPolicies(entries []IPBlocklistEntry) {
	p.ipBlocklistMu.Lock()
	defer p.ipBlocklistMu.Unlock()

	currentSet := indexPolicies(p.currentBlocklist)
	newSet := indexPolicies(entries)

	// inMap is what the BPF map holds once this reconciliation is done. It is
	// what the next refresh diffs against, so a rule we failed to remove stays
	// listed (to be retried) and a rule we failed to add does not.
	inMap := make(map[string]map[string]bool, len(newSet))
	keep := func(ip, domain string) {
		if inMap[ip] == nil {
			inMap[ip] = make(map[string]bool)
		}
		inMap[ip][domain] = true
	}

	// Remove entries that are no longer in the new blocklist
	removedCount := 0
	for ip, domains := range currentSet {
		for domain := range domains {
			if newSet[ip][domain] {
				continue
			}
			if err := p.UnblockDomainForIP(ip, domain); err != nil {
				log.Printf("Warning: failed to unblock domain %s for IP %s: %v", domain, ip, err)
				keep(ip, domain)
				continue
			}
			removedCount++
		}
	}

	// Add entries that are not in the map yet
	addedCount := 0
	for ip, domains := range newSet {
		for domain := range domains {
			if currentSet[ip][domain] {
				keep(ip, domain)
				continue
			}
			if err := p.BlockDomainForIP(ip, domain); err != nil {
				log.Printf("Warning: failed to block domain %s for IP %s: %v", domain, ip, err)
				continue
			}
			keep(ip, domain)
			addedCount++
		}
	}

	p.currentBlocklist = flattenPolicies(inMap)

	log.Printf("Policies applied (revision %s): %d client(s), %d rule(s) added, %d removed",
		p.policyAPI.revisionLabel(), len(entries), addedCount, removedCount)
}

// indexPolicies groups normalized domains per client IP, dropping entries whose
// IP is not a usable IPv4 address (the BPF map is keyed on IPv4).
func indexPolicies(entries []IPBlocklistEntry) map[string]map[string]bool {
	index := make(map[string]map[string]bool, len(entries))
	for _, entry := range entries {
		ip := net.ParseIP(strings.TrimSpace(entry.IP))
		if ip == nil || ip.To4() == nil {
			log.Printf("Warning: skipping policy for %q: not an IPv4 address", entry.IP)
			continue
		}
		key := ip.To4().String()
		if index[key] == nil {
			index[key] = make(map[string]bool, len(entry.Domains))
		}
		for _, domain := range entry.Domains {
			if domain = normalizeDomain(domain); domain != "" {
				index[key][domain] = true
			}
		}
	}
	return index
}

// flattenPolicies turns the per-IP index back into the entry list kept on the proxy.
func flattenPolicies(index map[string]map[string]bool) []IPBlocklistEntry {
	entries := make([]IPBlocklistEntry, 0, len(index))
	for ip, domains := range index {
		list := make([]string, 0, len(domains))
		for domain := range domains {
			list = append(list, domain)
		}
		entries = append(entries, IPBlocklistEntry{IP: ip, Domains: list})
	}
	return entries
}

func (c *policyClient) revisionLabel() string {
	if c == nil || c.revision == "" {
		return "unknown"
	}
	return c.revision
}

// startIPBlocklistRefresher periodically fetches and updates the IP blocklist
func (p *DNSProxy) startIPBlocklistRefresher(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("Policy refresher started (interval: %v)", interval)

	for range ticker.C {
		if err := p.fetchAndUpdateIPBlocklist(); err != nil {
			log.Printf("Error refreshing policies: %v", err)
		}
	}
}
