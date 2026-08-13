> ⚠️ research 原始产出（含来源 URL，供复核）；**维护以 `docs/protocol-maintenance.md` §2 字段审计为准**（协议集已演进，本字典可能有已移除协议）。

# sing-box 1.14.0-beta.14 客户端 outbound 字段字典（vless / vmess / trojan）

> 依据：官方文档（testing 分支 markdown）+ GitHub 源码 v1.14.0-beta.14（option/、protocol/、common/tls/）+ 本地二进制 check 实测。标注「已实测」=用 v1.14.0-beta.14 二进制验证过。

## 1. VLESS

源码 `option/vless.go`：`VLESSOutboundOptions` = DialerOptions + ServerOptions + 以下。

| 字段 | 类型/取值 | 必填 | 说明 |
|---|---|---|---|
| `type` | `"vless"` | 是 | |
| `tag` | string | 否 | |
| `server` / `server_port` | string / uint16 | 是 | |
| `uuid` | string | 是 | 缺失直接报错 |
| `flow` | `xtls-rprx-vision` | 否 | 仅此一个合法值；服务端需同款 |
| `network` | `tcp`/`udp` | 否 | 默认两者 |
| `packet_encoding` | 空/`packetaddr`/`xudp` | 否 | **默认 `xudp`**；显式空串=禁用 |
| `tls` | 对象 | 否 | 见下 |
| `multiplex` | 对象 | 否 | enabled/protocol(h2mux,smux,yamux)/max_connections/padding/brutal |
| `transport` | 对象 | 否 | 见下 |

### tls 段（出站，option/tls.go）

`enabled`、`server_name`、`insecure`、`alpn`、`min_version`/`max_version`、`cipher_suites`、`curve_preferences`、`disable_sni`、`handshake_timeout`（1.14 新增，默认 15s）、`engine`（1.14 新增，go/apple/windows）。

`utls` 子段：`enabled`（否，默认 false）、`fingerprint`（1.14 enum：chrome_psk,chrome_psk_shuffle,chrome_padding_psk_shuffle,chrome_pq,chrome_pq_psk,chrome,firefox,edge,safari,360,qq,ios,android,random,randomized；1.10 起前 5 个 legacy 已移除回退 chrome）。

`reality` 子段（客户端）：`enabled`、`public_key`（**必填**，URL-safe raw base64 无 `=`，解码 32 字节）、`short_id`（**必填**，0–8 位 hex 字符串，客户端是**单个字符串**，服务端才是数组；空串合法）。Reality 段不支持 `spoof`。

### transport 段（V2Ray Transport）

`type` 取值（1.14.0-beta.14 源码 enum）：`http`、`ws`、`quic`、`grpc`、`httpupgrade`。**1.14 没有 `xhttp`**（已实测：unknown transport type: xhttp，xhttp 是 1.15 才引入）。

- `ws`：`path`（默认空）、`headers`（默认 `{}`，常用 `{"Host": ...}`）、`max_early_data`（默认 0=关）、`early_data_header_name`（默认空=走 path）
- `grpc`：`service_name`（文档默认 TunService）、`idle_timeout`、`ping_timeout`、`permit_without_stream`
- `http`：`host`（列表）、`path`、`method`、`headers`、`idle_timeout`、`ping_timeout`
- `httpupgrade`：`host`、`path`、`headers`
- `quic`：无额外字段

### 最小 outbound JSON（已实测通过 check）

```json
{
  "type": "vless",
  "tag": "vless-out",
  "server": "1.2.3.4",
  "server_port": 443,
  "uuid": "c6df3583-7a6f-4019-af30-b53b55e19366",
  "flow": "xtls-rprx-vision",
  "packet_encoding": "xudp",
  "tls": {
    "enabled": true,
    "server_name": "www.microsoft.com",
    "utls": { "enabled": true, "fingerprint": "chrome" },
    "reality": {
      "enabled": true,
      "public_key": "<reality-public-key>",
      "short_id": "653a7b14"
    }
  }
}
```

### 坑

1. **Reality 客户端必须显式 `utls.enabled: true`**，否则 FATAL `uTLS is required by reality client`（已实测，1.14 不自动补）。
2. `public_key` 必须 URL-safe raw base64。
3. `short_id` 客户端是字符串非数组；超过 8 位 hex 报 `invalid short_id`。
4. `flow` 只有 `xtls-rprx-vision`；非法值初始化即报 `unsupported flow`。
5. `packet_encoding` 缺省=xudp；禁用要显式 `""`。
6. 服务端 reality `handshake.port` 已改名 `server_port`（本仓库实测 breaking）。
7. 无 plain TCP transport（v2ray 的 TCP 并入 `http` transport）。

## 2. VMess

源码 `option/vmess.go`。

| 字段 | 类型/取值 | 必填 | 说明 |
|---|---|---|---|
| `type` | `"vmess"` | 是 | |
| `server` / `server_port` | string / uint16 | 是 | |
| `uuid` | string | 是 | |
| `security` | auto/none/zero/aes-128-cfb/aes-128-gcm/chacha20-poly1305 | 否 | 缺省 auto；auto+TLS → 自动 zero |
| `alter_id` | int | 否 | **默认 0**（AEAD 现状）；1=legacy。**字段名 `alter_id`，与服务端 `alterId` 不同** |
| `global_padding` / `authenticated_length` | bool | 否 | 协议参数 |
| `network` | tcp/udp | 否 | 默认两者 |
| `tls` | 对象 | 否 | 同 VLESS tls 段，**不支持 reality** |
| `packet_encoding` | 空/`packetaddr`/`xudp` | 否 | **无默认，缺省=禁用**（与 VLESS 默认 xudp 不同） |
| `transport` | 对象 | 否 | 同前 |

### 最小 outbound JSON（已实测）

```json
{
  "type": "vmess",
  "tag": "vmess-out",
  "server": "1.2.3.4",
  "server_port": 10086,
  "uuid": "c6df3583-7a6f-4019-af30-b53b55e19366",
  "security": "auto",
  "alter_id": 0
}
```

TLS+WS 示例：`"tls":{"enabled":true,"server_name":"example.com"}` + `"transport":{"type":"ws","path":"/ws","headers":{"Host":"example.com"}}`（已实测）。

### 坑

1. `alter_id` 现状就是 0；不要写 >1。
2. `packet_encoding` 缺省禁用，要 UDP-over-TLS 显式 `"xudp"`。
3. `security` 源码 enum 是 `aes-128-cfb`，官方文档写的 `aes-128-ctr` 与源码不一致，以源码为准。
4. vmess 出站不带 reality。

## 3. Trojan

源码 `option/trojan.go`。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `type` | `"trojan"` | 是 | |
| `server` / `server_port` | string / uint16 | 是 | |
| `password` | string | 是 | 无 omitempty |
| `network` | tcp/udp | 否 | 默认两者 |
| `tls` | 对象 | 否（实际几乎必须） | 同 VLESS tls 段，**不支持 reality** |
| `transport` | 对象 | 否 | ws/grpc/httpupgrade/http/quic |

### 最小 outbound JSON（已实测）

```json
{
  "type": "trojan",
  "tag": "trojan-out",
  "server": "1.2.3.4",
  "server_port": 443,
  "password": "<trojan-password>",
  "tls": { "enabled": true, "server_name": "example.com" }
}
```

### 坑

1. Trojan 本身是 TLS 协议，必须 `tls.enabled: true`（可 insecure/自签 CA）。
2. `password` 必填。
3. 无 `packet_encoding` 字段。

## 4. 通用 Dial Fields（所有 outbound 共有）

`option/outbound.go` `AbstractDialerOptions`：

| 字段 | 说明 |
|---|---|
| `detour` | 上游 outbound tag；设了则其余字段全忽略 |
| `bind_interface`/`inet4_bind_address`/`inet6_bind_address`/`bind_address_no_port`(1.13+) | 绑定 |
| `routing_mark`/`reuse_addr`/`protect_path`/`netns` | 路由标记等 |
| `connect_timeout` | **默认 5s** |
| `tcp_fast_open` / `tcp_multi_path` | |
| `disable_tcp_keep_alive`/`tcp_keep_alive`/`tcp_keep_alive_interval` | 1.13+，默认 5m/75s |
| `udp_fragment` | |
| `domain_resolver` | 1.12+；**1.14 起域名型 server 地址必须配**或 route.default_domain_resolver |
| `network_strategy`/`network_type`/`fallback_*` | 1.11+，仅图形客户端 |

## 5. 1.14 特定注意（outbound 相关）

1. Reality + uTLS：必须显式 `utls.enabled: true`（已实测）。
2. **没有 xhttp transport**（1.15 才有，已实测 unknown）。
3. TLS 段 1.14 新增：`engine`（go/apple/windows）、`handshake_timeout`（默认 15s）、`spoof`+`spoof_method`（需特权）。
4. `domain_resolver` 1.14 变为必需（server 用域名时）。
5. uTLS legacy 指纹（chrome_psk*）已移除回退 chrome，文档不推荐 uTLS。
6. 1.14.0-beta.2 起内置 `$schema`/check 校验支持。
7. vless/vmess `packet_encoding` 默认值不同（xudp vs 禁用）。
8. reality `public_key` URL-safe raw base64；`short_id` 客户端字符串/服务端数组。

## 关键来源

- 源码：`option/{vless,vmess,trojan,tls,v2ray_transport,outbound,multiplex}.go`、`constant/v2ray.go`、`protocol/{vless,vmess}/outbound.go`、`common/tls/reality_client.go`
- 文档：`docs/configuration/{outbound/vless.md,vmess.md,trojan.md,shared/tls.md,shared/v2ray-transport.md,shared/dial.md,migration.md}`
- 本地二进制 `/tmp/sing-box-1.14.0-beta.14-linux-amd64/sing-box` 实测
