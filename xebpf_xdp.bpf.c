//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xebpf_map.bpf.h"
// #include "xebpf_config.bpf.c"

#define UPPER_PORT_BOUND 32768

char LICENSE[] SEC("license") = "GPL";


struct xebpf_xdp_incoming_packets_total
{
    /* data */
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct xebpf_map_key_t);
    __type(value, __u64);
    __uint(max_entries, 1024);
} xebpf_xdp_incoming_packets_total SEC(".maps");

// 检查数据包是否为 TCP 的辅助函数
static bool is_tcp(struct ethhdr *eth, void *data_end)
{
    // 确保以太网头在边界内
    if ((void *)(eth + 1) > data_end)
        return false;

    // 仅处理 IPv4 数据包
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // 确保 IP 头在边界内
    if ((void *)(ip + 1) > data_end)
        return false;

    // 检查协议是否为 TCP
    if (ip->protocol != IPPROTO_TCP)
        return false;

    return true;
}


// count_packets atomically increases a packet counter on every invocation.
SEC("xdp/ens160")
int count_packets_fn(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (!is_tcp(eth, data_end)) {
        return XDP_PASS;
    }
    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);


    /*
    为了保证安全，BPF 需要我们先确保没有到达数据包的线性部分，然后才访问数据包数据。
    因此，大多数数据包数据访问之前都必须进行边界检查。
    https://www.kernel.org/doc/html/latest/bpf/verifier.html#direct-packet-access
    */
    if (data + TOTSZ > data_end) {
        return XDP_PASS;
    }

    // if (bpf_ntohs(tcph->dest) > UPPER_PORT_BOUND) {
    //     return XDP_PASS;
    // }

    if (bpf_ntohs(tcph->dest) != 22) {
        bpf_printk("tcp packet: %d, %d\n", tcph->dest, bpf_ntohs(tcph->dest));
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct xebpf_map_key_t pk;
        __u64 *pv;

        pk.src_ip = ip->saddr;
        pk.dst_ip = ip->daddr;
        pk.dst_port = tcph->dest;

        pv = bpf_map_lookup_elem(&xebpf_xdp_incoming_packets_total, &pk);
        if (pv) {
            __sync_fetch_and_add(pv, 1);
        } else {
            __u64 value = 1;
            bpf_map_update_elem(&xebpf_xdp_incoming_packets_total, &pk, &value, BPF_ANY);
        }
    }
    return XDP_PASS;
}
     