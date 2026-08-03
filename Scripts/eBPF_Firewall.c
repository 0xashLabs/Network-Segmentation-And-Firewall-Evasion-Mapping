#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// BPF Mapping
struct {
__ uint(type, BPF_MAP_TYPE_HASH);
uint(max_entries, 100);
__ type(key, __ u32);
__ type(value, __ u32);
} allowed_ips SEC(".maps");

SEC("xdp")
int xdp_l7_filter(struct xdp_md *ctx) {
    // Define pointers to the start and end of the packet data
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only inspect IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Check if source IP is in allowed_ips map
__ u32 src_ip = ip->saddr;
__ u32 *allowed = bpf_map_lookup_elem(&allowed_ips, &src_ip);

if (allowed) {
return XDP_PASS; // Allow if in map

if (allowed) {
return XDP_PASS; // Whitelist bypass

    // 2. Parse IP Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Only inspect TCP packets
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // 3. Parse TCP Header (ihl = IP header length in 32-bit words)
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // 4. Calculate TCP Payload Offset
    // doff = TCP data offset in 32-bit words
    unsigned char *payload = (unsigned char *)tcp + (tcp->doff * 4);

    // Bounds check: ensure at least 14 bytes of payload exist
    // ("GET /attack-tar" = 14 characters)
    if ((void *)(payload + 14) > data_end)
        return XDP_PASS;

    // 5. Inspect the HTTP Payload for malicious signature
    // Target: "GET /attack" prefix
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' &&
        payload[3] == ' ' && payload[4] == '/' && payload[5] == 'a' &&
        payload[6] == 't' && payload[7] == 't' && payload[8] == 'a' &&
        payload[9] == 'c' && payload[10] == 'k') {

        // Malicious signature detected — drop at the NIC, zero CPU cost
        return XDP_DROP;
    }
    // BPF Mapping
    struct {
       __uint(type, BPF_MAP_TYPE_HASH);
       __uint(max_entries, 100);
   } allowed_ips SEC(".maps");

    // Allow all other traffic
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";