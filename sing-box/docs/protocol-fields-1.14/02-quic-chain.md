> ⚠️ Raw research output (includes source URLs for re-verification); **for maintenance, defer to the `docs/protocol-maintenance.md` §2 field audits** (the protocol set has evolved — this dictionary may include removed protocols).

# sing-box 1.14.0-beta.14 outbound config dictionary: hysteria2 / shadowtls / tuic / anytls

> Sources verified against: official docs (v1.14.0-beta.14 branch docs/configuration/outbound/) + GitHub source v1.14.0-beta.14 (option/, protocol/, test/shadowtls_test.go)

Common structure: every outbound has `type` (required), `tag` (optional), `server`/`server_port` (usually required), a `tls` section (required for most protocols, and `enabled` must be true or the source errors out with `ErrTLSRequired`), and Dial Fields (including `detour`, `bind_interface`, `connect_timeout`, `tcp_fast_open`, `tcp_multi_path`, `domain_resolver`, `network_strategy`, etc.).

---

## 1. hysteria2

### Field list

| Field | Type | Required | Default/Notes |
|---|---|---|---|
| `server` | string | required | server address. Conflicts with `realm` |
| `server_port` | number | required | server port. Ignored when `server_ports` is set |
| `server_ports` | string[] | optional | 1.11+ port range list |
| `hop_interval` | duration | optional | port-hopping interval, default `30s` |
| `hop_interval_max` | duration | optional | 1.14+ max hop interval (randomized) |
| `up_mbps` / `down_mbps` | number | optional | max bandwidth (Mbps). **Note the field names are not up/down**. Left empty falls back to BBR |
| `obfs` | object | optional | empty `type` = disabled |
| `obfs.type` | string | conditionally required | `salamander` or `gecko` (gecko 1.14+) |
| `obfs.password` | string | conditionally required | required once `obfs` is set; empty reports `missing obfs password` |
| `obfs.min_packet_size` | number | optional | 1.14+, gecko only, default `512` |
| `obfs.max_packet_size` | number | optional | 1.14+, gecko only, default `1200` |
| `password` | string | see pitfalls | auth password |
| `network` | string | optional | `tcp`/`udp`, default both |
| `tls` | object | required | enabled/server_name/insecure/utls, etc. |
| `bbr_profile` | string | optional | 1.14+, `conservative`/`standard`/`aggressive`, default `standard` |
| `brutal_debug` | boolean | optional | debug logging |
| `disable_chrome_parrot` | boolean | optional | 1.14+, default `false` (mimics the Chrome QUIC fingerprint by default) |
| `realm` | object | optional | 1.14+ hole punching |
| QUIC Fields | — | optional | `initial_packet_size`, `disable_path_mtu_discovery` + HTTP2 Fields |

### Minimal outbound JSON

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

### Pitfalls

1. The official userpass auth is really `<username>:<password>` used as the actual password; sing-box has no such alias — put the whole composite string into `password`.
2. `disable_chrome_parrot` defaults to false (Chrome fingerprint mimicry on by default). When enabled, Chrome params override `idle_timeout` (fixed 30s), `max_concurrent_streams`, `initial_packet_size`, etc.; **Chrome doesn't support Ed25519, so a server Ed25519 cert fails the handshake**.
3. Once `obfs` is set, password can't be empty and type can only be salamander/gecko.
4. Bandwidth fields are `up_mbps`/`down_mbps`; left empty falls back to BBR congestion control.
5. New in 1.14: `hop_interval_max`, `bbr_profile`, `disable_chrome_parrot`, `realm`, obfs `gecko`.

---

## 2. shadowtls

### Field list

| Field | Type | Required | Default/Notes |
|---|---|---|---|
| `server` | string | required | server address |
| `server_port` | number | required | server port |
| `version` | number | optional | `1` (default)/`2`/`3` |
| `password` | string | required for v2/v3 | only usable with v2/v3 |
| `tls` | object | required | shared TLS (outbound side) |

### Minimal outbound JSON (v3)

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

### Pitfalls

1. **version defaults to 1** (source forces 1 when Version==0).
2. v1 forces TLS 1.2 (source fixes Min/MaxVersion).
3. password is only meaningful for v2/v3.
4. **The v3 client config is the same as v2**: `version: 3` + `password` + `tls`. The v3 handshake prefers uTLS session-ID negotiation, otherwise falls back to the default handshake func.
5. **TCP only** (source fixes network to `["tcp"]`; UDP can't go through).
6. Chained: the ss outbound's `detour` points to the shadowtls outbound's `tag`.

---

## 3. tuic

### Field list

| Field | Type | Required | Default/Notes |
|---|---|---|---|
| `server` | string | required | |
| `server_port` | number | required | |
| `uuid` | string | required | invalid UUID errors directly |
| `password` | string | needed by server | |
| `congestion_control` | string | optional | `cubic`/`new_reno`/`bbr`, **default `cubic`** |
| `udp_relay_mode` | string | optional | `native`/`quic`, default `native`; conflicts with `udp_over_stream` |
| `udp_over_stream` | boolean | optional | conflicts with `udp_relay_mode` |
| `zero_rtt_handshake` | boolean | optional | default `false` |
| `heartbeat` | duration | optional | docs example `"10s"` |
| `tls` | object | required | |

### Minimal outbound JSON

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

### Pitfalls

1. `uuid` must be a valid UUID, otherwise `invalid uuid`.
2. **congestion_control defaults to cubic, not bbr** — for BBR write `"bbr"` explicitly.
3. `udp_relay_mode` and `udp_over_stream` are mutually exclusive.
4. `zero_rtt_handshake` must be enabled on both client and server.
5. Both hysteria2 and tuic force `UDPFragmentDefault = true`.

---

## 4. anytls

### Field list

| Field | Type | Required | Default/Notes |
|---|---|---|---|
| `server` | string | required | |
| `server_port` | number | required | |
| `password` | string | required | |
| `idle_session_check_interval` | duration | optional | default `30s` |
| `idle_session_timeout` | duration | optional | default `30s` |
| `min_idle_session` | number | optional | default `0` |
| `client_metadata` | string | optional | **1.14 defaults to empty string `""`** (since 1.13.16) |
| `tls` | object | required | |

### Minimal outbound JSON

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

### Pitfalls

1. **tcp_fast_open is disabled**: true errors directly with `tcp_fast_open is not supported with anytls outbound` (lazy-connect handshake nil-pointer crash).
2. **padding_scheme is a server-side (inbound) field**; the outbound doesn't have it and can't configure it.
3. **client_metadata defaults to empty in 1.14** (no software fingerprint sent, to resist vendor-identification blocking).
4. TLS must be `enabled: true`.
5. Supports TCP+UDP (UDP over UoT), with built-in multiplex.

---

## 5. Chained combo (ss ↔ shadowtls) client config example

Official test `test/shadowtls_test.go` (TestShadowTLSOutbound, version=3):

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

Key points:
- `detour` sits at the top of DialerOptions; its value is the shadowtls `tag`.
- In the official test, ss's server/server_port can be left empty (the remote address is forwarded locally by the shadowtls server).
- shadowtls is TCP only; ss UDP is not supported through this chain.
- Server topology: shadowtls listens on a public port → detour/forwards to a local ss (e.g. 127.0.0.1:10001).
