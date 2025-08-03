#!/bin/bash

export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"

./ebpf_exporter_2.5.x86_64 --config.dir=examples \
    --config.names=xebpf_xdp,xebpf_tcp_rtt,xebpf_tcp_recv,xebpf_tcp_drop,xebpf_tcp_packets_count \
    --debug \