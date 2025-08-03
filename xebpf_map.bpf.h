//go:build ignore

#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800 // https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h#L52
#define TOTSZ (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))
#define MAX_ENTRIES	1024
#define AF_INET 2

int DST_PORT_LIST[] = {16379, 25672, 6379, 3306, 2379, 80, 443};

static __always_inline bool check_ports(__u32 port)
{
    int len = sizeof(DST_PORT_LIST) / sizeof(DST_PORT_LIST[0]);
    for (int i = 0; i < len; ++i) {
        if (port == bpf_htons(DST_PORT_LIST[i])) {
            return true;
        }
    };
    return false;
}

struct xebpf_map_key_t
{
    /* data */
    __u32 src_ip;
    // __u16 src_port;
    __u16 dst_port;
    __u32 dst_ip;
    // __u8 protocol;
};

#endif /* __MAPS_BPF_H */