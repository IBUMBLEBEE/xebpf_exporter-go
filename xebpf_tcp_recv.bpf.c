//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "xebpf_map.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct xebpf_tcp_recv_bytes_map
{
    /* data */
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct xebpf_map_key_t);
    __type(value, __u64);
    __uint(max_entries, 1024);
} xebpf_tcp_recv_bytes_map SEC(".maps");

// https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp.c#L2537
SEC("fentry/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_fn, struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len) {
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

    if (true) {
        struct xebpf_map_key_t key;
        __u64 *val;

        key.src_ip = src_ip;
        key.dst_ip = dst_ip;
        key.dst_port = dst_port;

        val = bpf_map_lookup_elem(&xebpf_tcp_recv_bytes_map, &key);
        if (val) {
            __sync_fetch_and_add(val, len);
        } else {
            __u64 val_new = len;
            bpf_map_update_elem(&xebpf_tcp_recv_bytes_map, &key, &val_new, BPF_ANY);
        }
    }
    return 0;
}