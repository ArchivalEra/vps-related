> ⚠️ research 原始产出（含来源 URL，供复核）；**维护以 `docs/protocol-maintenance.md` §2 字段审计为准**（协议集已演进，本字典可能有已移除协议）。

# sing-box 1.14.0-beta.14 outbound 配置字典：hysteria2 / shadowtls / tuic / anytls

> 核实来源：官方文档（v1.14.0-beta.14 分支 docs/configuration/outbound/）+ GitHub 源码 v1.14.0-beta.14（option/、protocol/、test/shadowtls_test.go）

通用结构：每个 outbound 都含 `type`（必填）、`tag`（可选）、`server`/`server_port`（一般必填）、`tls` 段（多数协议必填且 `enabled` 必须为 true，否则源码直接报 `ErrTLSRequired`）、Dial Fields（含 `detour`、`bind_interface`、`connect_timeout`、`tcp_fast_open`、`tcp_multi_path`、`domain_resolver`、`network_strategy` 等）。

---

## 一、hysteria2

### 字段清单

| 字段 | 类型 | 必填 | 默认/说明 |
|---|---|---|---|
| `server` | string | 必填 | 服务器地址。与 `realm` 冲突 |
| `server_port` | number | 必填 | 服务器端口。设置了 `server_ports` 时被忽略 |
| `server_ports` | string[] | 可选 | 1.11+ 端口范围列表 |
| `hop_interval` | duration | 可选 | 端口跳跃间隔，默认 `30s` |
| `hop_interval_max` | duration | 可选 | 1.14+ 最大跳跃间隔（随机化） |
| `up_mbps` / `down_mbps` | number | 可选 | 最大带宽（Mbps）。**注意字段名不是 up/down**。留空则退回 BBR |
| `obfs` | object | 可选 | `type` 为空即禁用 |
| `obfs.type` | string | 条件必填 | `salamander` 或 `gecko`（gecko 1.14+） |
| `obfs.password` | string | 条件必填 | 设了 `obfs` 则必填，空报 `missing obfs password` |
| `obfs.min_packet_size` | number | 可选 | 1.14+，仅 gecko，默认 `512` |
| `obfs.max_packet_size` | number | 可选 | 1.14+，仅 gecko，默认 `1200` |
| `password` | string | 见坑 | 认证密码 |
| `network` | string | 可选 | `tcp`/`udp`，默认两者 |
| `tls` | object | 必填 | enabled/server_name/insecure/utls 等 |
| `bbr_profile` | string | 可选 | 1.14+，`conservative`/`standard`/`aggressive`，默认 `standard` |
| `brutal_debug` | boolean | 可选 | 调试日志 |
| `disable_chrome_parrot` | boolean | 可选 | 1.14+，默认 `false`（默认模仿 Chrome QUIC 指纹） |
| `realm` | object | 可选 | 1.14+ 打洞连接 |
| QUIC Fields | — | 可选 | `initial_packet_size`、`disable_path_mtu_discovery` + HTTP2 Fields |

### 最小 outbound JSON

```json
{
  "type": "hysteria2",
  "tag": "hy2-out",
  "server": "example.com",
  "server_port": 443,
  "password": "auth_password",
  "tls": { "enabled": true, "server_name": "example.com", "insecure": false }
}
```

### 坑

1. 官方 userpass 认证本质是 `<username>:<password>` 作为实际密码；sing-box 没有该别名，直接把组合串填进 `password`。
2. `disable_chrome_parrot` 默认 false（默认开 Chrome 指纹模仿）。开启时 Chrome 参数覆盖 `idle_timeout`(固定30s)、`max_concurrent_streams`、`initial_packet_size` 等；**Chrome 不支持 Ed25519，服务端 Ed25519 证书会握手失败**。
3. `obfs` 一旦设置，password 不能空，type 只能是 salamander/gecko。
4. 带宽字段是 `up_mbps`/`down_mbps`，留空退回 BBR 拥塞控制。
5. 1.14 新增：`hop_interval_max`、`bbr_profile`、`disable_chrome_parrot`、`realm`、obfs `gecko`。

---

## 二、shadowtls

### 字段清单

| 字段 | 类型 | 必填 | 默认/说明 |
|---|---|---|---|
| `server` | string | 必填 | 服务器地址 |
| `server_port` | number | 必填 | 服务器端口 |
| `version` | number | 可选 | `1`（默认）/`2`/`3` |
| `password` | string | v2/v3 必填 | 仅 v2/v3 可用 |
| `tls` | object | 必填 | 共享 TLS（outbound 侧） |

### 最小 outbound JSON（v3）

```json
{
  "type": "shadowtls",
  "tag": "st-out",
  "server": "example.com",
  "server_port": 443,
  "version": 3,
  "password": "shadowtls_password",
  "tls": { "enabled": true, "server_name": "example.com" }
}
```

### 坑

1. **version 默认 1**（源码 Version==0 强制置 1）。
2. v1 强制 TLS 1.2（源码固定 Min/MaxVersion）。
3. password 仅 v2/v3 有意义。
4. **v3 客户端写法与 v2 相同**：`version: 3` + `password` + `tls`。v3 握手优先用 uTLS session ID 协商，否则回退默认 handshake func。
5. **仅支持 TCP**（源码 network 固定 `["tcp"]`，UDP 走不了）。
6. 链式：ss outbound 的 `detour` 指向 shadowtls outbound 的 `tag`。

---

## 三、tuic

### 字段清单

| 字段 | 类型 | 必填 | 默认/说明 |
|---|---|---|---|
| `server` | string | 必填 | |
| `server_port` | number | 必填 | |
| `uuid` | string | 必填 | 非法 UUID 直接报错 |
| `password` | string | 服务端需要 | |
| `congestion_control` | string | 可选 | `cubic`/`new_reno`/`bbr`，**默认 `cubic`** |
| `udp_relay_mode` | string | 可选 | `native`/`quic`，默认 `native`；与 `udp_over_stream` 冲突 |
| `udp_over_stream` | boolean | 可选 | 与 `udp_relay_mode` 冲突 |
| `zero_rtt_handshake` | boolean | 可选 | 默认 `false` |
| `heartbeat` | duration | 可选 | 文档示例 `"10s"` |
| `tls` | object | 必填 | |

### 最小 outbound JSON

```json
{
  "type": "tuic",
  "tag": "tuic-out",
  "server": "example.com",
  "server_port": 443,
  "uuid": "2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365",
  "password": "hello",
  "congestion_control": "bbr",
  "zero_rtt_handshake": false,
  "udp_relay_mode": "native",
  "tls": { "enabled": true, "server_name": "example.com" }
}
```

### 坑

1. `uuid` 必须合法 UUID，否则 `invalid uuid`。
2. **congestion_control 默认 cubic 不是 bbr**——要 BBR 显式写 `"bbr"`。
3. `udp_relay_mode` 与 `udp_over_stream` 互斥。
4. `zero_rtt_handshake` 需客户端+服务端同时开启。
5. hysteria2/tuic 都强制 `UDPFragmentDefault = true`。

---

## 四、anytls

### 字段清单

| 字段 | 类型 | 必填 | 默认/说明 |
|---|---|---|---|
| `server` | string | 必填 | |
| `server_port` | number | 必填 | |
| `password` | string | 必填 | |
| `idle_session_check_interval` | duration | 可选 | 默认 `30s` |
| `idle_session_timeout` | duration | 可选 | 默认 `30s` |
| `min_idle_session` | number | 可选 | 默认 `0` |
| `client_metadata` | string | 可选 | **1.14 默认空字符串 `""`**（1.13.16 起） |
| `tls` | object | 必填 | |

### 最小 outbound JSON

```json
{
  "type": "anytls",
  "tag": "anytls-out",
  "server": "example.com",
  "server_port": 443,
  "password": "8JCsPssfgS8tiRwiMlhARg==",
  "idle_session_check_interval": "30s",
  "idle_session_timeout": "30s",
  "min_idle_session": 5,
  "client_metadata": "",
  "tls": { "enabled": true, "server_name": "example.com" }
}
```

### 坑

1. **tcp_fast_open 禁用**：true 直接报 `tcp_fast_open is not supported with anytls outbound`（lazy 连接握手空指针崩溃）。
2. **padding_scheme 是服务端（inbound）字段**，outbound 没有也不能配。
3. **client_metadata 1.14 默认空**（不再发软件指纹，防厂商识别封锁）。
4. TLS 必须 `enabled: true`。
5. 支持 TCP+UDP（UDP 走 UoT），内置 multiplex。

---

## 五、链式组合（ss ↔ shadowtls）客户端写法示例

官方测试 `test/shadowtls_test.go`（TestShadowTLSOutbound，version=3）：

```json
{
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-out",
      "method": "2022-blake3-aes-128-gcm",
      "password": "ss_password_base64",
      "detour": "st-out"
    },
    {
      "type": "shadowtls",
      "tag": "st-out",
      "server": "your-vps.example.com",
      "server_port": 443,
      "version": 3,
      "password": "shadowtls_password",
      "tls": { "enabled": true, "server_name": "www.example.com" }
    }
  ]
}
```

要点：
- `detour` 在 DialerOptions 顶层，值填 shadowtls 的 `tag`。
- 官方测试中 ss 的 server/server_port 可留空（远端地址由 shadowtls 服务端本地转发）。
- shadowtls 仅 TCP，ss 的 UDP 此链不支持。
- 服务端拓扑：shadowtls 监听公网端口 → detour/forward 到本地 ss（如 127.0.0.1:10001）。
