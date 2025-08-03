#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "xebpf_map.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct kfree_skb_args {
  unsigned long pad;

  void * skbaddr;
  void * location;
  unsigned short protocol;
  enum skb_drop_reason reason;
};

struct xebpf_tcp_drop_ipv4_packets_total {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct xebpf_map_key_t);
    __type(value, __u64);
} xebpf_tcp_drop_ipv4_packets_total SEC(".maps");


// Only works on v5.17+
// /sys/kernel/tracing/events/skb/kfree_skb/format
SEC("tracepoint/skb/kfree_skb")
int tcp_drop_fn(struct kfree_skb_args *args) {
    struct sk_buff *skb = args->skbaddr;
    if (skb == NULL) {
        return 0;
    }
    struct sock *sk = BPF_CORE_READ(skb, sk);
    if (sk == NULL) {
        return 0;
    }
    if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET) {
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

        val = bpf_map_lookup_elem(&xebpf_tcp_drop_ipv4_packets_total, &key);;
        if (val) {
            __sync_fetch_and_add(val, 1);
        } else {
            __u64 val_new = 1;
            bpf_map_update_elem(&xebpf_tcp_drop_ipv4_packets_total, &key, &val_new, BPF_ANY);
        }
    }

    return 0;
}
