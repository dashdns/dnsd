//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DNS_PORT 53
#define MAX_DNS_NAME 255

// Per-IP allowlist key structure
struct ip_domain_key {
    __u32 client_ip;      // Source IP (network byte order)
    __u32 domain_hash;    // Domain hash (DJB2)
} __attribute__((packed));

// Per-IP domain allowlist (default: block all)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct ip_domain_key);
    __type(value, __u8);
} ip_allowlist SEC(".maps");

// Legacy blocked_domains - kept for backward compatibility
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u8);
} blocked_domains SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);  
    __type(value, __u8);     
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, __u8);
} allowed_dns_servers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

enum {
    STAT_TOTAL_PACKETS = 0,
    STAT_DNS_PACKETS = 1,
    STAT_BLOCKED_PACKETS = 2,
    STAT_ALLOWED_PACKETS = 3,
    STAT_DNS_RESPONSES = 4,
    STAT_BLOCKED_RESPONSES = 5,
    STAT_ALLOWED_RESPONSES = 6,
    STAT_IP_BLOCKED_RESPONSES = 7,
};

static __always_inline void update_stat(__u32 key) {
    __u64 *value = bpf_map_lookup_elem(&stats, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

struct dns_header {
    __u16 id;
    __u16 flags;
    __u16 qdcount;  // Number of questions
    __u16 ancount;  // Number of answers
    __u16 nscount;  // Number of authority records
    __u16 arcount;
};

// Check if domain is allowed for the given client IP
// Returns: 1 = should block (not in allowlist), 0 = allowed
static __always_inline int check_dns_query_allowed_xdp(void *data, void *data_end, __u32 dns_offset, __u32 client_ip) {
    __u32 pos = dns_offset + sizeof(struct dns_header);

    if (data + pos + 32 > data_end) {
        return 1;  // Block on parse error (default block all)
    }

    unsigned char *qname = data + pos;

    __u32 hash = 5381;

    #define HASH_BYTE(i) do { \
        unsigned char c = qname[i]; \
        if (c == 0) goto done; \
        if (c >= 'A' && c <= 'Z') c += 32; \
        if (c >= 1 && c <= 63) c = '.'; \
        hash = ((hash << 5) + hash) + c; \
    } while(0)

    HASH_BYTE(0);  HASH_BYTE(1);  HASH_BYTE(2);  HASH_BYTE(3);
    HASH_BYTE(4);  HASH_BYTE(5);  HASH_BYTE(6);  HASH_BYTE(7);
    HASH_BYTE(8);  HASH_BYTE(9);  HASH_BYTE(10); HASH_BYTE(11);
    HASH_BYTE(12); HASH_BYTE(13); HASH_BYTE(14); HASH_BYTE(15);
    HASH_BYTE(16); HASH_BYTE(17); HASH_BYTE(18); HASH_BYTE(19);
    HASH_BYTE(20); HASH_BYTE(21); HASH_BYTE(22); HASH_BYTE(23);
    HASH_BYTE(24); HASH_BYTE(25); HASH_BYTE(26); HASH_BYTE(27);
    HASH_BYTE(28); HASH_BYTE(29); HASH_BYTE(30); HASH_BYTE(31);

done:
    ;  // Empty statement after label for C compliance

    // Build composite key for per-IP allowlist lookup
    struct ip_domain_key key = {
        .client_ip = client_ip,
        .domain_hash = hash
    };

    bpf_printk("XDP: client_ip=0x%x domain_hash=0x%x", client_ip, hash);

    __u8 *allowed = bpf_map_lookup_elem(&ip_allowlist, &key);
    if (allowed && *allowed == 1) {
        bpf_printk("XDP: ALLOWED - IP+domain in allowlist");
        return 0;  // Allowed
    }

    bpf_printk("XDP: BLOCKED - IP+domain NOT in allowlist (default block all)");
    return 1;  // Block (not in allowlist)

    #undef HASH_BYTE
}

static __always_inline int check_dns_response_blocked_tc(struct __sk_buff *skb, __u32 dns_offset) {
    struct dns_header dns_hdr;

    if (bpf_skb_load_bytes(skb, dns_offset, &dns_hdr, sizeof(dns_hdr)) < 0) {
        return 0;
    }

    __u16 ancount = bpf_ntohs(dns_hdr.ancount);
    __u16 qdcount = bpf_ntohs(dns_hdr.qdcount);

    if (ancount == 0 || ancount > 4 || qdcount > 1) {
        return 0;
    }

    __u32 pos = dns_offset + sizeof(struct dns_header);

    #pragma unroll
    for (int i = 0; i < 16; i++) {
        unsigned char label_len;
        if (bpf_skb_load_bytes(skb, pos, &label_len, 1) < 0) {
            return 0;
        }

        if (label_len == 0) {
            pos++;
            break;
        }

        if ((label_len & 0xC0) == 0xC0) {
            pos += 2;
            break;
        }

        pos += 1 + label_len;
    }

    pos += 4;
    #pragma unroll
    for (int a = 0; a < 4; a++) {
        unsigned char first_byte;
        if (bpf_skb_load_bytes(skb, pos, &first_byte, 1) < 0) {
            return 0;
        }

        if ((first_byte & 0xC0) == 0xC0) {
            pos += 2;
        } else {
            #pragma unroll
            for (int i = 0; i < 16; i++) {
                unsigned char label_len;
                if (bpf_skb_load_bytes(skb, pos, &label_len, 1) < 0) {
                    return 0;
                }

                if (label_len == 0) {
                    pos++;
                    break;
                }

                if ((label_len & 0xC0) == 0xC0) {
                    pos += 2;
                    break;
                }

                pos += 1 + label_len;
            }
        }

        unsigned char rr_fixed[10];
        if (bpf_skb_load_bytes(skb, pos, rr_fixed, 10) < 0) {
            return 0;
        }

        __u16 type = (rr_fixed[0] << 8) | rr_fixed[1];
        __u16 rdlength = (rr_fixed[8] << 8) | rr_fixed[9];
        pos += 10;

        if (type == 1 && rdlength == 4) {
            __u32 ip;
            if (bpf_skb_load_bytes(skb, pos, &ip, 4) < 0) {
                return 0;
            }

            __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &ip);
            if (blocked && *blocked == 1) {
                bpf_printk("TC: Blocked IP in DNS response!");
                return 1;
            }
        }

        pos += rdlength;
    }

    return 0;
}

SEC("xdp")
int xdp_dns_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    update_stat(STAT_TOTAL_PACKETS);

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) > data_end) {
        return XDP_PASS;
    }

    // Ethernet header
    struct ethhdr *eth = data;

    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    struct iphdr *ip = data + sizeof(struct ethhdr);

    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    if (ip->ihl != 5) {
        return XDP_PASS;
    }

    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (udp->dest != bpf_htons(DNS_PORT)) {
        return XDP_PASS;
    }

    bpf_printk("XDP: Incoming DNS query detected");

    update_stat(STAT_DNS_PACKETS);

    __u32 dns_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    __u32 client_ip = ip->saddr;  // Source IP of the DNS query

    // Per-IP allowlist check (default: block all)
    if (check_dns_query_allowed_xdp(data, data_end, dns_offset, client_ip)) {
        bpf_printk("XDP: >>> DROPPING DNS QUERY - NOT IN ALLOWLIST <<<");
        update_stat(STAT_BLOCKED_PACKETS);
        return XDP_DROP;
    }

    bpf_printk("XDP: DNS query PASSED (in allowlist)");
    update_stat(STAT_ALLOWED_PACKETS);
    return XDP_PASS;
}

SEC("tc")
int tc_dns_filter(struct __sk_buff *skb) {
    void *data_end;
    void *data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    if (bpf_skb_pull_data(skb, 0) < 0) {
        return TC_ACT_OK;
    }

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
        return TC_ACT_OK;
    }

    eth = data;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    ip = data + sizeof(struct ethhdr);

    if (ip->protocol != IPPROTO_UDP) {
        return TC_ACT_OK;
    }

    if (ip->ihl != 5) {
        return TC_ACT_OK;
    }

    udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (udp->dest != bpf_htons(DNS_PORT)) {
        return TC_ACT_OK;
    }

    __u32 dest_ip = ip->daddr;

    bpf_printk("TC: DNS query catched, dest_ip=0x%x", bpf_ntohl(dest_ip));

    update_stat(STAT_DNS_PACKETS);

    __u8 *allowed = bpf_map_lookup_elem(&allowed_dns_servers, &dest_ip);

    if (allowed && *allowed == 1) {
        bpf_printk("TC: DNS query ALLOWED (whitelisted DNS server)");
        update_stat(STAT_ALLOWED_PACKETS);
        return TC_ACT_OK;
    }
    bpf_printk("TC: DNS query BLOCKED (unauthorized DNS server)");
    update_stat(STAT_BLOCKED_PACKETS);
    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
