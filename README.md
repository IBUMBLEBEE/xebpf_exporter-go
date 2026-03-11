# xebpf exporter

This is an example demonstrating the use of ebpf_exporter to collect kernel-level TCP metrics for Redis, RabbitMQ, and HTTP ports, and export them as Prometheus metrics. You can also modify the DST_PORT_LIST list to support collecting metrics for other services.

***Please note that this repository is only an example of using ebpf_exporter; please review the code before using it in a production environment.***

## Demo

![redis cluster status](./docs/redis_metrics.png)
![rabbitmq cluster status](./docs/rabbitmq_metrics.png)

## check your server BTF config

```shell
cat /boot/config-`uname -r` | grep CONFIG_DEBUG_INFO_BTF

CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
```

## BPF Environment Setup

### Dependencies

```shell
sudo dnf install clang llvm
sudo dnf install elfutils-libelf-devel libpcap-devel perf glibc-devel libbpf-devel.x86_64 libbpf
sudo dnf install kernel-headers
sudo dnf install bpftool
```

## Build

```shell
git clone <repo>
cd xebpf_exporter-go/xebpf
make -C examples clean build
# Download ebpf_exporter from https://github.com/cloudflare/ebpf_exporter/releases
ebpf_exporter --config.dir=/etc/xebpf_exporter/bpf \
    --config.names=xebpf_tcp_recv,xebpf_tcp_drop,xebpf_tcp_rtt,xebpf_xdp,xebpf_tcp_retransmit \
    --web.listen-address=":9527"
```

## Development

### tracing available_events

`/sys/kernel/debug/tracing/available_events`

`cat /sys/kernel/tracing/events/skb/kfree_skb/format`

```shell
name: kfree_skb
ID: 1763
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:void * skbaddr;   offset:8;       size:8; signed:0;
        field:void * location;  offset:16;      size:8; signed:0;
        field:unsigned short protocol;  offset:24;      size:2; signed:0;
        field:enum skb_drop_reason reason;      offset:28;      size:4; signed:0;

print fmt: "skbaddr=%p protocol=%u location=%pS reason: %s", REC->skbaddr, REC->protocol, REC->location, __print_symbolic(REC->reason, { 2, "NOT_SPECIFIED" }, { 3, "NO_SOCKET" }, { 4, "PKT_TOO_SMALL" }, { 5, "TCP_CSUM" }, { 6, "SOCKET_FILTER" }, { 7, "UDP_CSUM" }, { 8, "NETFILTER_DROP" }, { 9, "OTHERHOST" }, { 10, "IP_CSUM" }, { 11, "IP_INHDR" }, { 12, "IP_RPFILTER" }, { 13, "UNICAST_IN_L2_MULTICAST" }, { 14, "XFRM_POLICY" }, { 15, "IP_NOPROTO" }, { 16, "SOCKET_RCVBUFF" }, { 17, "PROTO_MEM" }, { 18, "TCP_AUTH_HDR" }, { 19, "TCP_MD5NOTFOUND" }, { 20, "TCP_MD5UNEXPECTED" }, { 21, "TCP_MD5FAILURE" }, { 22, "TCP_AONOTFOUND" }, { 23, "TCP_AOUNEXPECTED" }, { 24, "TCP_AOKEYNOTFOUND" }, { 25, "TCP_AOFAILURE" }, { 26, "SOCKET_BACKLOG" }, { 27, "TCP_FLAGS" }, { 28, "TCP_ZEROWINDOW" }, { 29, "TCP_OLD_DATA" }, { 30, "TCP_OVERWINDOW" }, { 31, "TCP_OFOMERGE" }, { 32, "TCP_RFC7323_PAWS" }, { 33, "TCP_OLD_SEQUENCE" }, { 34, "TCP_INVALID_SEQUENCE" }, { 35, "TCP_RESET" }, { 36, "TCP_INVALID_SYN" }, { 37, "TCP_CLOSE" }, { 38, "TCP_FASTOPEN" }, { 39, "TCP_OLD_ACK" }, { 40, "TCP_TOO_OLD_ACK" }, { 41, "TCP_ACK_UNSENT_DATA" }, { 42, "TCP_OFO_QUEUE_PRUNE" }, { 43, "TCP_OFO_DROP" }, { 44, "IP_OUTNOROUTES" }, { 45, "BPF_CGROUP_EGRESS" }, { 46, "IPV6DISABLED" }, { 47, "NEIGH_CREATEFAIL" }, { 48, "NEIGH_FAILED" }, { 49, "NEIGH_QUEUEFULL" }, { 50, "NEIGH_DEAD" }, { 51, "TC_EGRESS" }, { 52, "QDISC_DROP" }, { 53, "CPU_BACKLOG" }, { 54, "XDP" }, { 55, "TC_INGRESS" }, { 56, "UNHANDLED_PROTO" }, { 57, "SKB_CSUM" }, { 58, "SKB_GSO_SEG" }, { 59, "SKB_UCOPY_FAULT" }, { 60, "DEV_HDR" }, { 61, "DEV_READY" }, { 62, "FULL_RING" }, { 63, "NOMEM" }, { 64, "HDR_TRUNC" }, { 65, "TAP_FILTER" }, { 66, "TAP_TXFILTER" }, { 67, "ICMP_CSUM" }, { 68, "INVALID_PROTO" }, { 69, "IP_INADDRERRORS" }, { 70, "IP_INNOROUTES" }, { 71, "PKT_TOO_BIG" }, { 72, "DUP_FRAG" }, { 73, "FRAG_REASM_TIMEOUT" }, { 74, "FRAG_TOO_FAR" }, { 75, "TCP_MINTTL" }, { 76, "IPV6_BAD_EXTHDR" }, { 77, "IPV6_NDISC_FRAG" }, { 78, "IPV6_NDISC_HOP_LIMIT" }, { 79, "IPV6_NDISC_BAD_CODE" }, { 80, "IPV6_NDISC_BAD_OPTIONS" }, { 81, "IPV6_NDISC_NS_OTHERHOST" }, { 82, "QUEUE_PURGE" }, { 83, "TC_COOKIE_ERROR" }, { 84, "PACKET_SOCK_ERROR" }, { 85, "TC_CHAIN_NOTFOUND" }, { 86, "TC_RECLASSIFY_LOOP" }, { 87, "MAX" })
```

## Defined Metrics

(done) `tcp_packets_counter` counter: Number of TCP packets passing through the specified port
(done) `tcp_packets_receive_bytes` counter: Number of TCP bytes received through the specified port
(todo) `tcp_packets_send_bytes` counter: Number of TCP bytes sent through the specified port
(done) `tcp_packets_retransmits` counter: Number of TCP retransmissions through the specified port
(done) `tcp_packet_rtt_µs` gauge: TCP RTT time through the specified port

### metrics label

1. `src_ip` Source IP
2. `dst_ip` Destination IP
3. `src_port` Source port
4. `dst_port` Destination port

## Simulated TCP Retransmission Test

iptables Blocking Packets from a Node

```shell
iptables -I INPUT -s 192.168.59.113 -p TCP --dport 16379 -j DROP
```

iptables Clearing

```shell
iptables -F
```

### TC Command Simulation Test

Rocky8/9 tc

```shell
dnf install -y kernel-modules-extra iproute-tc
# restart server
# reboot
# find sch_netem.ko.xz
find / -type f -name *sch_netem*
# /usr/lib/modules/5.14.0-427.28.1.el9_4.x86_64/kernel/net/sched/sch_netem.ko.xz
# load module
insmod  /usr/lib/modules/5.14.0-427.28.1.el9_4.x86_64/kernel/net/sched/sch_netem.ko.xz
```

Add network failure simulation test

```shell
tc qdisc show
# Limit speed to 5Gbit and network interface delay to 10ms
tc qdisc add dev eth0 root netem rate 5000mbit latency 1s loss 50%
# Set the packet loss rate to 50%
tc qdisc add dev eth0 root netem loss 50%
```

Remove test

```shell
tc qdisc del dev eth0 root
```

## Recommended kernel version

1. `5.14.0-362.8.1.el9_3.x86_64` (Rocky9)
2. `4.18.0-553.el8_10.x86_64` (Rocky8)

## OS init

```shell
sudo dnf install -y socat logrotate
sudo dnf install -y kernel-modules-extra iproute-tc
```

## Benchmark

Rabbimq

https://perftest.rabbitmq.com/

```shell
java -jar perf-test-2.21.0.jar --uri amqp://admin:123456@cv1xna-r9sandbox000:5672 -x 1 -y 2 -u "throughput-test-1" -a --id "test 1"
```

Redis

```shell
redis-benchmark -h cv1xna-r9sandbox000 -p 6379 -c 4 -n 100000000
```

## Debug

bpf_printk("fmt", args)

```shell
cat /sys/kernel/debug/tracing/trace_pipe
```

## Reference

1. https://ebpf-go.dev/guides/getting-started/#ebpf-c-program
2. https://docs.cilium.io/en/latest/bpf/
3. https://eunomia.dev/zh/tutorials/14-tcpstates/
4. https://github.com/iovisor/bcc
5. https://github.com/xdp-project/xdp-tutorial
6. https://github.com/cloudflare/ebpf_exporter
7. https://www.brendangregg.com/blog/2018-03-22/tcp-tracepoints.html
8. https://github.com/cilium/ebpf
9. https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf
10. https://skywalking.incubator.apache.org/zh/2024-03-18-monitor-kubernetes-network-by-ebpf/