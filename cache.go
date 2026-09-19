package main

import (
	"container/list"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// CacheConfig holds the tunables of the userspace answer cache.
type CacheConfig struct {
	// MaxEntries bounds how many answers are kept; the least recently used
	// entry is dropped once the cache is full.
	MaxEntries int
	// MinTTL raises answers with a very short TTL so a single hot name cannot
	// force an upstream query per client request. 0 respects the upstream TTL.
	MinTTL time.Duration
	// MaxTTL caps how long a positive answer is kept, whatever the upstream says.
	MaxTTL time.Duration
	// NegativeTTL caps NXDOMAIN/NODATA answers (RFC 2308). It is also the TTL
	// used when the upstream sends no SOA to derive one from.
	NegativeTTL time.Duration
}

// CacheStats is a snapshot of the cache counters, published by reportStats.
type CacheStats struct {
	Entries   int
	Capacity  int
	Hits      uint64
	Misses    uint64
	Inserts   uint64
	Evictions uint64
	Expired   uint64
}

// cacheEntry is one cached upstream answer. msg keeps the TTLs exactly as the
// upstream sent them; the values handed to clients are derived from storedAt.
type cacheEntry struct {
	key       string
	msg       *dns.Msg
	storedAt  time.Time
	expiresAt time.Time
}

// DNSCache is a TTL-aware, LRU-bounded cache of upstream DNS answers. It sits
// behind every blocklist check in handleDNSRequest, so a cached answer can only
// ever be served to a client that is allowed to resolve the name anyway.
//
// All methods tolerate a nil receiver, which is what a disabled cache is.
type DNSCache struct {
	cfg CacheConfig

	mu      sync.Mutex
	entries map[string]*list.Element // cache key -> element holding *cacheEntry
	lru     *list.List               // front = most recently used

	hits      atomic.Uint64
	misses    atomic.Uint64
	inserts   atomic.Uint64
	evictions atomic.Uint64
	expired   atomic.Uint64

	// now is swapped out by the tests; production always uses time.Now.
	now func() time.Time
}

// NewDNSCache builds a cache with the given configuration. A MaxEntries of 0 or
// less is treated as "no cache" and yields a nil *DNSCache.
func NewDNSCache(cfg CacheConfig) *DNSCache {
	if cfg.MaxEntries <= 0 {
		return nil
	}
	if cfg.MinTTL < 0 {
		cfg.MinTTL = 0
	}
	return &DNSCache{
		cfg:     cfg,
		entries: make(map[string]*list.Element),
		lru:     list.New(),
		now:     time.Now,
	}
}

// Get returns a reply for req built from a cached upstream answer. The returned
// message is a private copy: its TTLs are counted down by the time the entry
// spent in the cache, its ID and question come from req, and its OPT record is
// rebuilt from the EDNS0 options req advertised.
func (c *DNSCache) Get(req *dns.Msg) (*dns.Msg, bool) {
	if c == nil || !cacheableQuestion(req) {
		return nil, false
	}
	key := cacheKey(req)
	now := c.now()

	c.mu.Lock()
	elem, ok := c.entries[key]
	if !ok {
		c.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}
	entry := elem.Value.(*cacheEntry)
	if !now.Before(entry.expiresAt) {
		c.removeElement(elem)
		c.mu.Unlock()
		c.expired.Add(1)
		c.misses.Add(1)
		return nil, false
	}
	c.lru.MoveToFront(elem)
	msg := entry.msg.Copy()
	elapsed := now.Sub(entry.storedAt)
	c.mu.Unlock()

	c.hits.Add(1)
	ageTTLs(msg, elapsed)

	// Rebuild the per-client parts of the reply. SetReply is not usable here
	// because it would force the Rcode back to NOERROR and drop NXDOMAIN.
	msg.Id = req.Id
	msg.Response = true
	msg.Opcode = req.Opcode
	msg.RecursionDesired = req.RecursionDesired
	msg.CheckingDisabled = req.CheckingDisabled
	msg.Question = []dns.Question{req.Question[0]}

	udpSize := dns.MinMsgSize
	if opt := req.IsEdns0(); opt != nil {
		msg.SetEdns0(opt.UDPSize(), opt.Do())
		if size := int(opt.UDPSize()); size > udpSize {
			udpSize = size
		}
	}
	// The stored answer was sized for whoever asked first; this client may have
	// advertised a smaller buffer. dnsd only serves UDP.
	msg.Truncate(udpSize)

	return msg, true
}

// Put stores resp as the answer to req when it is safely cacheable. Responses
// that are truncated, signed, non-query, or carry a zero TTL are skipped.
func (c *DNSCache) Put(req, resp *dns.Msg) {
	if c == nil || resp == nil || !cacheableQuestion(req) {
		return
	}
	ttl, ok := c.answerTTL(req, resp)
	if !ok {
		return
	}

	stored := resp.Copy()
	// The OPT record belongs to the hop, not to the answer: it is rebuilt per
	// client in Get from whatever that client advertised.
	stripOPT(stored)
	stored.Id = 0

	now := c.now()
	entry := &cacheEntry{
		key:       cacheKey(req),
		msg:       stored,
		storedAt:  now,
		expiresAt: now.Add(ttl),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.entries[entry.key]; ok {
		elem.Value = entry
		c.lru.MoveToFront(elem)
		c.inserts.Add(1)
		return
	}
	c.entries[entry.key] = c.lru.PushFront(entry)
	c.inserts.Add(1)

	for c.lru.Len() > c.cfg.MaxEntries {
		if oldest := c.lru.Back(); oldest != nil {
			c.removeElement(oldest)
			c.evictions.Add(1)
		}
	}
}

// PurgeExpired drops every entry whose TTL has run out. It is called from the
// stats ticker so names that are never asked for again do not pin memory until
// they are evicted by the LRU.
func (c *DNSCache) PurgeExpired() int {
	if c == nil {
		return 0
	}
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	purged := 0
	for elem := c.lru.Back(); elem != nil; {
		prev := elem.Prev()
		if !now.Before(elem.Value.(*cacheEntry).expiresAt) {
			c.removeElement(elem)
			purged++
		}
		elem = prev
	}
	c.expired.Add(uint64(purged))
	return purged
}

// Stats returns a snapshot of the cache counters.
func (c *DNSCache) Stats() CacheStats {
	if c == nil {
		return CacheStats{}
	}
	c.mu.Lock()
	entries := c.lru.Len()
	c.mu.Unlock()

	return CacheStats{
		Entries:   entries,
		Capacity:  c.cfg.MaxEntries,
		Hits:      c.hits.Load(),
		Misses:    c.misses.Load(),
		Inserts:   c.inserts.Load(),
		Evictions: c.evictions.Load(),
		Expired:   c.expired.Load(),
	}
}

// cacheHitRate is the share of lookups served from the cache, as a percentage.
func cacheHitRate(s CacheStats) float64 {
	lookups := s.Hits + s.Misses
	if lookups == 0 {
		return 0
	}
	return float64(s.Hits) / float64(lookups) * 100
}

// removeElement drops an element from both the map and the LRU list.
// The caller holds c.mu.
func (c *DNSCache) removeElement(elem *list.Element) {
	entry := elem.Value.(*cacheEntry)
	c.lru.Remove(elem)
	delete(c.entries, entry.key)
}

// answerTTL decides whether resp may be cached and for how long. Positive
// answers follow the smallest record TTL, negative ones the SOA of the
// authority section (RFC 2308), both clamped by the configured bounds.
func (c *DNSCache) answerTTL(req, resp *dns.Msg) (time.Duration, bool) {
	if resp.Truncated || resp.Opcode != dns.OpcodeQuery || resp.IsTsig() != nil {
		return 0, false
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return 0, false
	}
	// A reply for another question tells us nothing about this one.
	if len(resp.Question) != 1 || !sameQuestion(req.Question[0], resp.Question[0]) {
		return 0, false
	}

	if resp.Rcode == dns.RcodeNameError || len(resp.Answer) == 0 {
		ttl, ok := soaNegativeTTL(resp)
		if !ok {
			// Without a SOA there is nothing authoritative to base a negative
			// TTL on, so fall back to the configured cap.
			ttl = uint32(c.cfg.NegativeTTL / time.Second)
		}
		if ttl == 0 {
			return 0, false
		}
		return clampTTL(time.Duration(ttl)*time.Second, c.cfg.MinTTL, c.cfg.NegativeTTL), true
	}

	ttl, ok := minRecordTTL(resp)
	if !ok || ttl == 0 {
		// A zero TTL means "use once, do not cache".
		return 0, false
	}
	return clampTTL(time.Duration(ttl)*time.Second, c.cfg.MinTTL, c.cfg.MaxTTL), true
}

// cacheableQuestion reports whether a message is a plain single-question query
// of a type worth caching. ANY and the zone transfer types are never cached:
// their answers are partial by nature.
func cacheableQuestion(msg *dns.Msg) bool {
	if msg == nil || msg.Opcode != dns.OpcodeQuery || len(msg.Question) != 1 {
		return false
	}
	switch msg.Question[0].Qtype {
	case dns.TypeANY, dns.TypeAXFR, dns.TypeIXFR, dns.TypeOPT:
		return false
	}
	return true
}

// cacheKey identifies an answer. Names are case-folded because DNS name
// comparison is case-insensitive, and the DO bit is part of the key because a
// DNSSEC-aware client gets a different answer than a plain one.
func cacheKey(req *dns.Msg) string {
	q := req.Question[0]

	var b strings.Builder
	b.WriteString(strings.ToLower(q.Name))
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(q.Qtype), 10))
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(q.Qclass), 10))
	if opt := req.IsEdns0(); opt != nil && opt.Do() {
		b.WriteString("|do")
	}
	return b.String()
}

func sameQuestion(a, b dns.Question) bool {
	return a.Qtype == b.Qtype && a.Qclass == b.Qclass && strings.EqualFold(a.Name, b.Name)
}

// minRecordTTL is the smallest TTL of every record in the message, which is how
// long the answer as a whole stays valid.
func minRecordTTL(msg *dns.Msg) (uint32, bool) {
	var min uint32
	found := false
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if ttl := rr.Header().Ttl; !found || ttl < min {
				min, found = ttl, true
			}
		}
	}
	return min, found
}

// soaNegativeTTL returns the negative caching TTL of a response: the smaller of
// the authority SOA's own TTL and its MINIMUM field (RFC 2308 section 4).
func soaNegativeTTL(msg *dns.Msg) (uint32, bool) {
	for _, rr := range msg.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		ttl := soa.Hdr.Ttl
		if soa.Minttl < ttl {
			ttl = soa.Minttl
		}
		return ttl, true
	}
	return 0, false
}

// ageTTLs counts every TTL down by the time the answer spent in the cache,
// never below 1 so a client is not told the record is already stale.
func ageTTLs(msg *dns.Msg, elapsed time.Duration) {
	seconds := uint32(elapsed / time.Second)
	if seconds == 0 {
		return
	}
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue
			}
			if hdr.Ttl > seconds {
				hdr.Ttl -= seconds
			} else {
				hdr.Ttl = 1
			}
		}
	}
}

// stripOPT removes the EDNS0 pseudo-record from a message we own.
func stripOPT(msg *dns.Msg) {
	if len(msg.Extra) == 0 {
		return
	}
	kept := msg.Extra[:0]
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		kept = append(kept, rr)
	}
	msg.Extra = kept
}

// clampTTL keeps d inside [lo, hi]. A hi of 0 means "no upper bound"; when the
// bounds cross, the upper bound wins.
func clampTTL(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		d = lo
	}
	if hi > 0 && d > hi {
		d = hi
	}
	return d
}
