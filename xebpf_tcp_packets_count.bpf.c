//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xebpf_map.bpf.h"

char LICENSE[] SEC("license") = "GPL";


struct xebpf_tcp_packets_bytes
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct xebpf_map_key_t);
    __type(value, __u64);
    __uint(max_entries, 1024);
} xebpf_tcp_packets_bytes SEC(".maps");

struct xebpf_tcp_packets_total
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct xebpf_map_key_t);
    __type(value, __u64);
    __uint(max_entries, 1024);
} xebpf_tcp_packets_total SEC(".maps");

// xebpf_packets_count_fn atomically increases a packet counter on every invocation.
SEC("tc")
int xebpf_tcp_packets_count_fn(struct __sk_buff* skb) {
    // if (bpf_skb_pull_data(skb, 0) < 0) {
    //     return 0;
    // }

    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;

    if (skb->protocol != bpf_htons(ETH_P_IP)) {
        return 0;
    }

    /*
    为了保证安全，BPF 需要我们先确保没有到达数据包的线性部分，然后才访问数据包数据。
    因此，大多数数据包数据访问之前都必须进行边界检查。
    */
    if (data + TOTSZ > data_end) {
        return 0;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (true) {
        struct xebpf_map_key_t pk;
        __u64 *pv;
        __u64 *pbv;

        pk.src_ip = ip->saddr;
        // pk.src_port = tcph->source;
        pk.dst_ip = ip->daddr;
        pk.dst_port = tcph->dest;
        // pk.protocol = ip->protocol;

        pv = bpf_map_lookup_elem(&xebpf_tcp_packets_total, &pk);
        if (pv) {
            __sync_fetch_and_add(pv, 1);
        } else {
            __u64 pv_new = 1;
            bpf_map_update_elem(&xebpf_tcp_packets_total, &pk, &pv_new, BPF_ANY);
        }

        pbv = bpf_map_lookup_elem(&xebpf_tcp_packets_bytes, &pk);
        if (pbv) {
            __sync_fetch_and_add(pbv, skb->len);
        } else {
            __u64 pbv_new = skb->len;
            bpf_map_update_elem(&xebpf_tcp_packets_bytes, &pk, &pbv_new, BPF_ANY);
        }
    }
    return 0;
}
