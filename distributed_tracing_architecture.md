# 跨机器 eBPF 分布式追踪系统架构

## 1. 整体架构设计

### 1.1 多机器部署模式
```
[机器A] --网络--> [机器B] --网络--> [机器C]
   |                |                |
eBPF Agent      eBPF Agent      eBPF Agent
   |                |                |
[Collector]     [Collector]     [Collector]
   |                |                |
   +----------------+----------------+
                    |
              [Central Tracing System]
```

### 1.2 追踪数据流
1. **用户空间注入**：在每台机器上注入 trace_id
2. **内核空间追踪**：eBPF 程序捕获网络事件
3. **数据收集**：每台机器的 Collector 收集 span 数据
4. **关联分析**：Central System 关联跨机器的 trace_id

## 2. 技术实现方案

### 2.1 网络包标记方案
```c
// 在 IP 包中嵌入 trace_id
struct ip_trace_header {
    u32 trace_id_hi;
    u32 trace_id_lo;
    u32 span_id;
    u32 flags;
};
```

### 2.2 跨机器追踪 eBPF 程序
```c
// 追踪网络包的发送和接收
SEC("xdp/ingress")
int trace_network_packet(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if (eth + 1 > data_end) return XDP_PASS;
    
    // 检查是否包含追踪信息
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if (iph + 1 > data_end) return XDP_PASS;
        
        // 提取或注入 trace_id
        extract_or_inject_trace_id(iph);
    }
    
    return XDP_PASS;
}
```

### 2.3 分布式追踪协调
```c
// 追踪信息传播
struct distributed_trace_info {
    u64 trace_id_hi;
    u64 trace_id_lo;
    u64 span_id;
    u64 source_machine_id;
    u64 timestamp;
    u32 ttl;  // 防止无限传播
};
```

## 3. 实现步骤

### 3.1 修改现有 eBPF 程序
```c
// 在现有的 sock-trace.bpf.c 基础上扩展
SEC("fentry/tcp_v4_do_rcv")
int BPF_PROG(tcp_v4_do_rcv_distributed, struct sock *sk, struct sk_buff *skb)
{
    u64 socket_cookie = bpf_get_socket_cookie(sk);
    
    // 检查是否是跨机器连接
    if (is_cross_machine_connection(sk)) {
        // 提取或传播 trace_id
        propagate_trace_id(sk, skb);
    }
    
    return handle_sk((struct pt_regs *) ctx, socket_cookie);
}
```

### 3.2 网络包标记机制
```c
// 使用 IP 选项或自定义协议头
static inline void inject_trace_id(struct sk_buff *skb, u64 trace_id)
{
    // 在 IP 包中注入追踪信息
    // 可以使用 IP 选项、自定义协议头或现有字段
}
```

### 3.3 机器间通信协议
```c
// 定义机器间追踪信息交换协议
struct machine_trace_message {
    u64 trace_id_hi;
    u64 trace_id_lo;
    u64 span_id;
    u64 source_machine_id;
    u64 target_machine_id;
    u64 timestamp;
    u32 message_type;  // TRACE_START, TRACE_CONTINUE, TRACE_END
};
```

## 4. 部署和配置

### 4.1 机器标识配置
```yaml
# 每台机器的配置
machine_id: "machine-001"
network_interfaces:
  - name: "eth0"
    enable_tracing: true
    cross_machine_tracing: true
```

### 4.2 追踪路由配置
```yaml
# 定义追踪路径
trace_routes:
  - source: "machine-001"
    target: "machine-002"
    protocols: ["tcp", "udp"]
    ports: [80, 443, 8080]
```

## 5. 数据收集和分析

### 5.1 分布式 Collector
```go
type DistributedCollector struct {
    machineID    string
    localSpans   chan Span
    remoteSpans  chan Span
    centralAPI   string
}

func (dc *DistributedCollector) CollectSpans() {
    // 收集本地 eBPF 生成的 spans
    // 接收其他机器发送的 spans
    // 发送到中央追踪系统
}
```

### 5.2 中央追踪系统
```go
type CentralTracingSystem struct {
    traceStore map[string]*DistributedTrace
    machines   map[string]*MachineInfo
}

func (cts *CentralTracingSystem) CorrelateSpans() {
    // 关联来自不同机器的 spans
    // 构建完整的分布式追踪链路
}
```

## 6. 性能考虑

### 6.1 网络开销
- 最小化追踪数据的网络传输
- 使用压缩和批处理
- 实现智能采样策略

### 6.2 存储优化
- 分布式存储追踪数据
- 实现数据分片和复制
- 支持数据生命周期管理

## 7. 安全考虑

### 7.1 数据隐私
- 加密追踪数据
- 实现数据脱敏
- 控制数据访问权限

### 7.2 网络安全
- 使用 TLS 加密机器间通信
- 实现身份认证和授权
- 防止追踪数据泄露 