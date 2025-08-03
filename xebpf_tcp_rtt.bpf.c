#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"
#include "xebpf_map.bpf.h"

char LICENSE[] SEC("license") = "GPL";


struct xebpf_tcp_rtt_latency_us_sum {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct xebpf_map_key_t);
    __type(value, u64);
} xebpf_tcp_rtt_latency_us_sum SEC(".maps");

struct xebpf_tcp_rtt_latency_total {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct xebpf_map_key_t);
    __type(value, u64);
} xebpf_tcp_rtt_latency_total SEC(".maps");


// https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp_input.c#L5731
SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv_established_fn, struct sock *sk) {
    if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}

    const struct inet_sock *inet = (struct inet_sock *)(sk);
    // const struct inet_sock *inet = (struct inet_sock *)sk;

    __u32 src_ip = BPF_CORE_READ(inet, inet_saddr);
    __u32 dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u32 dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    // __u32 src_port = BPF_CORE_READ(inet, inet_sport);

    if (src_ip == dst_ip) {
        return 0;
    }

    if (true) {
        struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
        if (!ts) {
            return 0;
        }
        __u32 srtt;
        srtt = ts->srtt_us >> 3;

        struct xebpf_map_key_t key;
        __u64 *latency_sum_val;
        __u64 *latency_total_val;

        key.src_ip = src_ip;
        key.dst_ip = dst_ip;
        // key.src_port = src_port;
        key.dst_port = dst_port;

        latency_sum_val = bpf_map_lookup_elem(&xebpf_tcp_rtt_latency_us_sum, &key);
        if (latency_sum_val) {
            __sync_fetch_and_add(latency_sum_val, srtt);
        } else {
            __u64 lus_val = srtt;
            bpf_map_update_elem(&xebpf_tcp_rtt_latency_us_sum, &key, &lus_val, BPF_ANY);
        }

        latency_total_val = bpf_map_lookup_elem(&xebpf_tcp_rtt_latency_total, &key);
        if (latency_total_val) {
            __sync_fetch_and_add(latency_total_val, 1);
        } else {
            __u64 lt_val = 1;
            bpf_map_update_elem(&xebpf_tcp_rtt_latency_total, &key, &lt_val, BPF_ANY);
        }
    }
    return 0;
}
