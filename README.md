# xebpf exporter

This is an example demonstrating the use of ebpf_exporter to collect kernel-level TCP metrics for Redis, RabbitMQ, and HTTP ports, and export them as Prometheus metrics. You can also modify the DST_PORT_LIST list to support collecting metrics for other services.


***Please note that this repository is only an example of using ebpf_exporter; please review the code before using it in a production environment.***


## build

https://github.com/cloudflare/ebpf_exporter?tab=readme-ov-file#building-examples

## run

```shell
sudo ./start.sh
```