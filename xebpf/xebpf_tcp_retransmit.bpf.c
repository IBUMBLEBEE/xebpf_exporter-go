#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"
#include "xebpf_map.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct xebpf_tcp_retransmit_total {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct xebpf_map_key_t);
    __type(value, __u64);
} xebpf_tcp_retransmit_total SEC(".maps");

// https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp_output.c#L3254
SEC("fentry/tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit_skb_fn, struct sock *sk) {
    if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}
    const struct inet_sock *inet = (struct inet_sock *)(sk);
    __u32 src_ip = BPF_CORE_READ(inet, inet_saddr);
    __u32 dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u32 dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);

    if (src_ip == dst_ip) {
        return 0;
    }

    if (check_ports(bpf_ntohs(dst_port))) {
        struct xebpf_map_key_t key;
        __u64 *tr_val;

        key.src_ip = src_ip;
        key.dst_ip = dst_ip;
        key.dst_port = bpf_ntohs(dst_port);
        key.service_name = bpf_ntohs(dst_port);

        tr_val = bpf_map_lookup_elem(&xebpf_tcp_retransmit_total, &key);
        if (tr_val) {
            __sync_fetch_and_add(tr_val, 1);
        } else {
            __u64 val_new = 1;
            bpf_map_update_elem(&xebpf_tcp_retransmit_total, &key, &val_new, BPF_ANY);
        }
    }
    return 0;
}