package main

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testCache builds a cache whose clock the test drives by hand.
func testCache(t *testing.T, cfg CacheConfig) (*DNSCache, func(time.Duration)) {
	t.Helper()
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = 100
	}
	c := NewDNSCache(cfg)
	if c == nil {
		t.Fatalf("NewDNSCache(%+v) = nil, want a cache", cfg)
	}
	now := time.Unix(1700000000, 0)
	c.now = func() time.Time { return now }
	return c, func(d time.Duration) { now = now.Add(d) }
}

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

func answer(req *dns.Msg, ttl uint32, ip string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   mustIP(ip),
	}}
	return m
}

func mustIP(s string) []byte {
	rr, err := dns.NewRR("x. 0 IN A " + s)
	if err != nil {
		panic(err)
	}
	return rr.(*dns.A).A
}

func nxdomain(req *dns.Msg, soaTTL, minTTL uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNameError)
	m.Ns = []dns.RR{&dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaTTL},
		Ns:     "ns1.example.com.",
		Mbox:   "hostmaster.example.com.",
		Minttl: minTTL,
	}}
	return m
}

func TestCacheHitReturnsAnswerWithAgedTTL(t *testing.T) {
	c, advance := testCache(t, CacheConfig{})

	req := query("example.com", dns.TypeA)
	c.Put(req, answer(req, 300, "93.184.216.34"))

	advance(30 * time.Second)

	next := query("example.com", dns.TypeA)
	next.Id = 4242
	got, ok := c.Get(next)
	if !ok {
		t.Fatal("Get() missed a fresh entry")
	}
	if got.Id != 4242 {
		t.Errorf("Id = %d, want the requester's 4242", got.Id)
	}
	if !got.Response {
		t.Error("Response = false, want a reply")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(got.Answer))
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 270 {
		t.Errorf("Ttl = %d, want 270 (300 minus 30s in cache)", ttl)
	}
}

func TestCacheHitDoesNotMutateStoredEntry(t *testing.T) {
	c, advance := testCache(t, CacheConfig{})

	req := query("example.com", dns.TypeA)
	c.Put(req, answer(req, 300, "93.184.216.34"))

	advance(10 * time.Second)
	if _, ok := c.Get(query("example.com", dns.TypeA)); !ok {
		t.Fatal("first Get() missed")
	}

	advance(10 * time.Second)
	got, ok := c.Get(query("example.com", dns.TypeA))
	if !ok {
		t.Fatal("second Get() missed")
	}
	// Both hits count down from the stored TTL, not from the previous copy.
	if ttl := got.Answer[0].Header().Ttl; ttl != 280 {
		t.Errorf("Ttl = %d, want 280 (300 minus 20s in cache)", ttl)
	}
}

func TestCacheExpiresAfterTTL(t *testing.T) {
	c, advance := testCache(t, CacheConfig{})

	req := query("example.com", dns.TypeA)
	c.Put(req, answer(req, 60, "93.184.216.34"))

	advance(61 * time.Second)

	if _, ok := c.Get(query("example.com", dns.TypeA)); ok {
		t.Error("Get() hit an entry whose TTL ran out")
	}
	if s := c.Stats(); s.Expired != 1 || s.Entries != 0 {
		t.Errorf("Stats() = %+v, want 1 expired and 0 entries", s)
	}
}

func TestCacheClampsTTL(t *testing.T) {
	tests := []struct {
		name string
		cfg  CacheConfig
		ttl  uint32
		want time.Duration
	}{
		{"min raises short ttl", CacheConfig{MinTTL: 30 * time.Second, MaxTTL: time.Hour}, 5, 30 * time.Second},
		{"max caps long ttl", CacheConfig{MaxTTL: 10 * time.Minute}, 86400, 10 * time.Minute},
		{"upstream ttl respected", CacheConfig{MaxTTL: time.Hour}, 300, 300 * time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, advance := testCache(t, tc.cfg)

			req := query("example.com", dns.TypeA)
			c.Put(req, answer(req, tc.ttl, "93.184.216.34"))

			advance(tc.want - time.Second)
			if _, ok := c.Get(query("example.com", dns.TypeA)); !ok {
				t.Errorf("entry gone before %v", tc.want)
			}
			advance(2 * time.Second)
			if _, ok := c.Get(query("example.com", dns.TypeA)); ok {
				t.Errorf("entry still cached after %v", tc.want)
			}
		})
	}
}

func TestCacheNegativeAnswerUsesSOA(t *testing.T) {
	c, advance := testCache(t, CacheConfig{NegativeTTL: time.Hour})

	req := query("nope.example.com", dns.TypeA)
	// RFC 2308: the smaller of the SOA TTL and its MINIMUM field wins.
	c.Put(req, nxdomain(req, 900, 120))

	got, ok := c.Get(query("nope.example.com", dns.TypeA))
	if !ok {
		t.Fatal("Get() missed a cached NXDOMAIN")
	}
	if got.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %s, want NXDOMAIN", dns.RcodeToString[got.Rcode])
	}

	advance(121 * time.Second)
	if _, ok := c.Get(query("nope.example.com", dns.TypeA)); ok {
		t.Error("NXDOMAIN outlived the SOA minimum")
	}
}

func TestCacheNegativeAnswerCappedByConfig(t *testing.T) {
	c, advance := testCache(t, CacheConfig{NegativeTTL: 30 * time.Second})

	req := query("nope.example.com", dns.TypeA)
	c.Put(req, nxdomain(req, 3600, 3600))

	advance(31 * time.Second)
	if _, ok := c.Get(query("nope.example.com", dns.TypeA)); ok {
		t.Error("NXDOMAIN outlived -cache-negative-ttl")
	}
}

func TestCacheNoDataAnswer(t *testing.T) {
	c, _ := testCache(t, CacheConfig{NegativeTTL: time.Hour})

	req := query("example.com", dns.TypeAAAA)
	// NOERROR with an empty answer section is a NODATA reply.
	resp := nxdomain(req, 300, 300)
	resp.Rcode = dns.RcodeSuccess
	c.Put(req, resp)

	got, ok := c.Get(query("example.com", dns.TypeAAAA))
	if !ok {
		t.Fatal("Get() missed a cached NODATA answer")
	}
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 0 {
		t.Errorf("got rcode=%s answers=%d, want NOERROR with no answers", dns.RcodeToString[got.Rcode], len(got.Answer))
	}
}

func TestCacheSkipsUncacheableResponses(t *testing.T) {
	req := query("example.com", dns.TypeA)

	truncated := answer(req, 300, "93.184.216.34")
	truncated.Truncated = true

	servfail := answer(req, 300, "93.184.216.34")
	servfail.Rcode = dns.RcodeServerFailure

	wrongQuestion := answer(req, 300, "93.184.216.34")
	wrongQuestion.Question = []dns.Question{{Name: "other.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}

	tests := []struct {
		name string
		resp *dns.Msg
	}{
		{"truncated", truncated},
		{"servfail", servfail},
		{"zero ttl", answer(req, 0, "93.184.216.34")},
		{"question mismatch", wrongQuestion},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testCache(t, CacheConfig{})
			c.Put(req, tc.resp)
			if _, ok := c.Get(query("example.com", dns.TypeA)); ok {
				t.Errorf("a %s response was cached", tc.name)
			}
		})
	}
}

func TestCacheSkipsANYAndTransferQueries(t *testing.T) {
	c, _ := testCache(t, CacheConfig{})

	for _, qtype := range []uint16{dns.TypeANY, dns.TypeAXFR, dns.TypeIXFR} {
		req := query("example.com", qtype)
		c.Put(req, answer(req, 300, "93.184.216.34"))
		if _, ok := c.Get(query("example.com", qtype)); ok {
			t.Errorf("qtype %s was cached", dns.TypeToString[qtype])
		}
	}
}

func TestCacheKeySeparatesQuestions(t *testing.T) {
	c, _ := testCache(t, CacheConfig{})

	req := query("example.com", dns.TypeA)
	c.Put(req, answer(req, 300, "93.184.216.34"))

	if _, ok := c.Get(query("example.com", dns.TypeMX)); ok {
		t.Error("an A answer was served for an MX question")
	}
	if _, ok := c.Get(query("other.com", dns.TypeA)); ok {
		t.Error("an answer was served for a different name")
	}
	// DNS names are case-insensitive, so this must still hit.
	if _, ok := c.Get(query("ExAmPlE.CoM", dns.TypeA)); !ok {
		t.Error("Get() missed on a differently cased name")
	}
}

func TestCacheKeySeparatesDNSSECRequests(t *testing.T) {
	c, _ := testCache(t, CacheConfig{})

	plain := query("example.com", dns.TypeA)
	c.Put(plain, answer(plain, 300, "93.184.216.34"))

	dnssec := query("example.com", dns.TypeA)
	dnssec.SetEdns0(4096, true)
	if _, ok := c.Get(dnssec); ok {
		t.Error("a non-DNSSEC answer was served to a DO=1 client")
	}
}

func TestCacheRebuildsEDNSPerClient(t *testing.T) {
	c, _ := testCache(t, CacheConfig{})

	req := query("example.com", dns.TypeA)
	req.SetEdns0(4096, false)
	resp := answer(req, 300, "93.184.216.34")
	resp.SetEdns0(1232, false)
	c.Put(req, resp)

	// A client that asks without EDNS0 must not be handed an OPT record.
	plain := query("example.com", dns.TypeA)
	got, ok := c.Get(plain)
	if !ok {
		t.Fatal("Get() missed")
	}
	if got.IsEdns0() != nil {
		t.Error("an OPT record was served to a client that did not use EDNS0")
	}

	// A client that does use EDNS0 gets an OPT sized to its own buffer.
	ednsClient := query("example.com", dns.TypeA)
	ednsClient.SetEdns0(1400, false)
	got, ok = c.Get(ednsClient)
	if !ok {
		t.Fatal("Get() missed for the EDNS0 client")
	}
	opt := got.IsEdns0()
	if opt == nil {
		t.Fatal("no OPT record served to an EDNS0 client")
	}
	if opt.UDPSize() != 1400 {
		t.Errorf("OPT UDP size = %d, want the client's 1400", opt.UDPSize())
	}
}

func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	c, _ := testCache(t, CacheConfig{MaxEntries: 2})

	for _, name := range []string{"a.com", "b.com"} {
		req := query(name, dns.TypeA)
		c.Put(req, answer(req, 300, "93.184.216.34"))
	}

	// Touch a.com so b.com becomes the least recently used entry.
	if _, ok := c.Get(query("a.com", dns.TypeA)); !ok {
		t.Fatal("a.com was not cached")
	}

	req := query("c.com", dns.TypeA)
	c.Put(req, answer(req, 300, "93.184.216.34"))

	if _, ok := c.Get(query("b.com", dns.TypeA)); ok {
		t.Error("b.com survived eviction, want the least recently used entry dropped")
	}
	if _, ok := c.Get(query("a.com", dns.TypeA)); !ok {
		t.Error("a.com was evicted, want the recently used entry kept")
	}
	if s := c.Stats(); s.Entries != 2 || s.Evictions != 1 {
		t.Errorf("Stats() = %+v, want 2 entries and 1 eviction", s)
	}
}

func TestCacheRefreshReplacesEntry(t *testing.T) {
	c, advance := testCache(t, CacheConfig{})

	req := query("example.com", dns.TypeA)
	c.Put(req, answer(req, 300, "93.184.216.34"))
	advance(200 * time.Second)
	c.Put(req, answer(req, 300, "1.2.3.4"))

	got, ok := c.Get(query("example.com", dns.TypeA))
	if !ok {
		t.Fatal("Get() missed after a refresh")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 300 {
		t.Errorf("Ttl = %d, want the refreshed 300", ttl)
	}
	if s := c.Stats(); s.Entries != 1 {
		t.Errorf("Entries = %d, want the entry replaced in place", s.Entries)
	}
}

func TestCachePurgeExpired(t *testing.T) {
	c, advance := testCache(t, CacheConfig{})

	short := query("short.com", dns.TypeA)
	c.Put(short, answer(short, 10, "93.184.216.34"))
	long := query("long.com", dns.TypeA)
	c.Put(long, answer(long, 600, "93.184.216.34"))

	advance(60 * time.Second)

	if purged := c.PurgeExpired(); purged != 1 {
		t.Errorf("PurgeExpired() = %d, want 1", purged)
	}
	if s := c.Stats(); s.Entries != 1 {
		t.Errorf("Entries = %d, want only the long-lived entry left", s.Entries)
	}
}

func TestCacheStatsCountLookups(t *testing.T) {
	c, _ := testCache(t, CacheConfig{})

	req := query("example.com", dns.TypeA)
	c.Get(req) // miss
	c.Put(req, answer(req, 300, "93.184.216.34"))
	c.Get(req) // hit
	c.Get(req) // hit

	s := c.Stats()
	if s.Hits != 2 || s.Misses != 1 || s.Inserts != 1 {
		t.Errorf("Stats() = %+v, want 2 hits, 1 miss, 1 insert", s)
	}
	if rate := cacheHitRate(s); rate < 66.6 || rate > 66.7 {
		t.Errorf("cacheHitRate() = %.2f, want ~66.67", rate)
	}
}

func TestNilCacheIsANoOp(t *testing.T) {
	var c *DNSCache // what a disabled cache looks like on the proxy

	req := query("example.com", dns.TypeA)
	c.Put(req, answer(req, 300, "93.184.216.34"))
	if _, ok := c.Get(req); ok {
		t.Error("a disabled cache returned a hit")
	}
	if n := c.PurgeExpired(); n != 0 {
		t.Errorf("PurgeExpired() = %d, want 0", n)
	}
	if s := c.Stats(); s != (CacheStats{}) {
		t.Errorf("Stats() = %+v, want the zero value", s)
	}
	if NewDNSCache(CacheConfig{MaxEntries: 0}) != nil {
		t.Error("NewDNSCache() with no capacity should disable the cache")
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	c := NewDNSCache(CacheConfig{MaxEntries: 32, MaxTTL: time.Hour})

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				req := query(string(rune('a'+j%26))+".com", dns.TypeA)
				c.Put(req, answer(req, 300, "93.184.216.34"))
				c.Get(req)
				if j%50 == 0 {
					c.PurgeExpired()
					c.Stats()
				}
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}

	if s := c.Stats(); s.Entries > 32 {
		t.Errorf("Entries = %d, want at most the configured 32", s.Entries)
	}
}
