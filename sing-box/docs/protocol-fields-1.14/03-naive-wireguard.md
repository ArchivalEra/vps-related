# sing-box 1.14.0-beta.14 outbound 配置字典：naive / wireguard

> 核实来源：v1.14.0-beta.14 官方文档 + GitHub 源码 + 发布资产实测（222 行）

## 1. Naive outbound（1.14 仍存在，1.13.0 引入）

### 字段清单

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `server` / `server_port` | string / uint16 | 必填 | |
| `username` / `password` | string | 必填 | 明文 |
| `insecure_concurrency` | int | 可选 | 官方警告会破坏抗分析特性 |
| `extra_headers` | map | 可选 | |
| `udp_over_tcp` | bool | 可选 | |
| `quic` / `quic_congestion_control` | — | 可选 | bbr/bbr2/cubic/reno |
| `tls` | object | 必填 | **无 insecure 选项** |
| Dial Fields | — | 可选 | |

### TLS 硬约束（源码 protocol/naive/outbound.go）

- **`tls.insecure:true` 直接报错**（无 insecure 选项）
- 只支持 `server_name` / `certificate` / `certificate_path` / `ech`，其余（utls/reality/alpn/fragment/kernel TLS）全部拒绝
- **真证书是设计前提**；自签只能走 certificate_path 固定，文档明说不推荐生产

### 依赖（libcronet.so）

- **无后缀 linux-amd64 包自带 libcronet.so**，需与二进制同目录或系统库路径
- glibc/musl 变体为 CGO 构建
- `with_naive_outbound` 默认构建标签仅主流平台有

### 已知性能 bug

- issue #3837（150Mbps→1Mbps）**closed 未修复**（缺最小复现被关），1.13.1 仍复现，1.14 changelog 无修复条目

### 1.14 变化

- naiveproxy 升级到 v150.0.7871.63-1（1.14.0-beta.5），配置字段与 1.13.0 逐字无差异

## 2. WireGuard（1.14 的 outbound 已删除 — 重大变化）

- `outbounds` 里写 `type: wireguard` 在 1.14 启动报错：**"deprecated in 1.11.0, removed in 1.13.0, use WireGuard endpoint"**
- 必须改用 `endpoints` 数组的 wireguard endpoint

### endpoint 字段

`system` / `name` / `mtu` / `address`（必填）/ `private_key`（必填）/ `listen_port` / `peers`（必填，含 `public_key` 与 `allowed_ips` 必填）/ `reserved` / `workers` + 1.14 新增 `udp_mapping`/`udp_filtering`/`udp_nat_max`

### 系统 wireguard

- `system:true` 需 root，但不是内核模块，是 userspace wireguard-go 跑在 sing-tun 的系统 TUN 上
- `system:false`（默认）纯用户态 gVisor 栈无需 root
- 单机客户端场景 = endpoint 被 selector/route 当 outbound 引用
- 已知 issue #4334：1.14 alpha `system:true` 启动崩溃

## 3. 客户端生成时依赖/警告清单

| 协议 | 依赖/警告 |
|---|---|
| naive | 必须真证书（无 insecure）、需要 libcronet.so 与二进制同目录、outbound 性能 bug 未修 |
| wireguard | 必须用 endpoints 形态（outbound 形态已删）、system:true 需 root、1.14 alpha 有崩溃 issue |

## 关键来源

- 官方文档 testing 分支：docs/configuration/{outbound/naive.md, endpoint/wireguard.md}
- 源码：option/naive.go、protocol/naive/outbound.go、endpoint/wireguard/*、include/registry.go
- 发布资产实测：linux-amd64 无后缀包含 libcronet.so
- 本仓库之前的子代理查证（性能 bug #3837 状态）
