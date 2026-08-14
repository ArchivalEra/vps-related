> ⚠️ Raw research output (includes source URLs for re-verification); **for maintenance, defer to the `docs/protocol-maintenance.md` §2 field audits** (the protocol set has evolved — this dictionary may include removed protocols).

# sing-box 1.14.0-beta.14 client outbound field dictionary (vless / vmess / trojan)

> Sources: official docs (testing branch markdown) + GitHub source v1.14.0-beta.14 (option/, protocol/, common/tls/) + local binary check. Marked "verified" = validated against the v1.14.0-beta.14 binary.

## 1. VLESS

Source `option/vless.go`: `VLESSOutboundOptions` = DialerOptions + ServerOptions + the following.

| Field | Type/values | Required | Notes |
|---|---|---|---|
| `type` | `"vless"` | yes | |
| `tag` | string | no | |
| `server` / `server_port` | string / uint16 | yes | |
| `uuid` | string | yes | missing errors out |
| `flow` | `xtls-rprx-vision` | no | only legal value; server must use the same |
| `network` | `tcp`/`udp` | no | default both |
| `packet_encoding` | empty/`packetaddr`/`xudp` | no | **default `xudp`**; explicit empty string = disabled |
| `tls` | object | no | see below |
| `multiplex` | object | no | enabled/protocol(h2mux,smux,yamux)/max_connections/padding/brutal |
| `transport` | object | no | see below |

### tls section (outbound, option/tls.go)

`enabled`, `server_name`, `insecure`, `alpn`, `min_version`/`max_version`, `cipher_suites`, `curve_preferences`, `disable_sni`, `handshake_timeout` (new in 1.14, default 15s), `engine` (new in 1.14, go/apple/windows).

`utls` sub-section: `enabled` (no, default false), `fingerprint` (1.14 enum: chrome_psk,chrome_psk_shuffle,chrome_padding_psk_shuffle,chrome_pq,chrome_pq_psk,chrome,firefox,edge,safari,360,qq,ios,android,random,randomized; the first 5 legacy ones were removed in 1.10, falling back to chrome).

`reality` sub-section (client): `enabled`, `public_key` (**required**, URL-safe raw base64 without `=`, decodes to 32 bytes), `short_id` (**required**, 0–8 hex-digit string; on the client it is a **single string**, only the server uses an array; empty string is legal). The reality section doesn't support `spoof`.

### transport section (V2Ray Transport)

`type` values (1.14.0-beta.14 source enum): `http`, `ws`, `quic`, `grpc`, `httpupgrade`. **1.14 has no `xhttp`** (verified: unknown transport type: xhttp; xhttp is only introduced in 1.15).

- `ws`: `path` (default empty), `headers` (default `{}`, commonly `{"Host": ...}`), `max_early_data` (default 0 = off), `early_data_header_name` (default empty = via path)
- `grpc`: `service_name` (docs default TunService), `idle_timeout`, `ping_timeout`, `permit_without_stream`
- `http`: `host` (list), `path`, `method`, `headers`, `idle_timeout`, `ping_timeout`
- `httpupgrade`: `host`, `path`, `headers`
- `quic`: no extra fields

### Minimal outbound JSON (verified passing check)

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

### Pitfalls

1. **Reality clients must set `utls.enabled: true` explicitly**, otherwise FATAL `uTLS is required by reality client` (verified; 1.14 doesn't fill it in automatically).
2. `public_key` must be URL-safe raw base64.
3. On the client `short_id` is a string, not an array; more than 8 hex digits reports `invalid short_id`.
4. `flow` only accepts `xtls-rprx-vision`; an invalid value errors at init with `unsupported flow`.
5. `packet_encoding` defaults to xudp; to disable, write `""` explicitly.
6. Server-side reality `handshake.port` was renamed to `server_port` (breaking change verified in this repo).
7. There's no plain TCP transport (v2ray's TCP is folded into the `http` transport).

## 2. VMess

Source `option/vmess.go`.

| Field | Type/values | Required | Notes |
|---|---|---|---|
| `type` | `"vmess"` | yes | |
| `server` / `server_port` | string / uint16 | yes | |
| `uuid` | string | yes | |
| `security` | auto/none/zero/aes-128-cfb/aes-128-gcm/chacha20-poly1305 | no | default auto; auto+TLS → auto zero |
| `alter_id` | int | no | **default 0** (current AEAD state); 1=legacy. **Field name is `alter_id`, unlike the server's `alterId`** |
| `global_padding` / `authenticated_length` | bool | no | protocol params |
| `network` | tcp/udp | no | default both |
| `tls` | object | no | same as the VLESS tls section, **no reality support** |
| `packet_encoding` | empty/`packetaddr`/`xudp` | no | **no default, absent = disabled** (unlike VLESS which defaults to xudp) |
| `transport` | object | no | same as before |

### Minimal outbound JSON (verified)

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

TLS+WS example: `"tls":{"enabled":true,"server_name":"example.com"}` + `"transport":{"type":"ws","path":"/ws","headers":{"Host":"example.com"}}` (verified).

### Pitfalls

1. `alter_id` is 0 in the current state; don't write >1.
2. `packet_encoding` is disabled by default; for UDP-over-TLS write `"xudp"` explicitly.
3. The source enum for `security` is `aes-128-cfb`; the official docs say `aes-128-ctr`, which disagrees with the source — trust the source.
4. vmess outbound doesn't support reality.

## 3. Trojan

Source `option/trojan.go`.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | `"trojan"` | yes | |
| `server` / `server_port` | string / uint16 | yes | |
| `password` | string | yes | no omitempty |
| `network` | tcp/udp | no | default both |
| `tls` | object | no (practically always required) | same as the VLESS tls section, **no reality support** |
| `transport` | object | no | ws/grpc/httpupgrade/http/quic |

### Minimal outbound JSON (verified)

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

### Pitfalls

1. Trojan is itself a TLS protocol — `tls.enabled: true` is required (insecure/self-signed CA allowed).
2. `password` is required.
3. No `packet_encoding` field.

## 4. Common Dial Fields (shared by all outbounds)

`option/outbound.go` `AbstractDialerOptions`:

| Field | Notes |
|---|---|
| `detour` | upstream outbound tag; when set, all other fields are ignored |
| `bind_interface`/`inet4_bind_address`/`inet6_bind_address`/`bind_address_no_port`(1.13+) | binding |
| `routing_mark`/`reuse_addr`/`protect_path`/`netns` | routing mark, etc. |
| `connect_timeout` | **default 5s** |
| `tcp_fast_open` / `tcp_multi_path` | |
| `disable_tcp_keep_alive`/`tcp_keep_alive`/`tcp_keep_alive_interval` | 1.13+, default 5m/75s |
| `udp_fragment` | |
| `domain_resolver` | 1.12+; **since 1.14, a domain-type server address requires this** or route.default_domain_resolver |
| `network_strategy`/`network_type`/`fallback_*` | 1.11+, graphical clients only |

## 5. 1.14-specific notes (outbound-related)

1. Reality + uTLS: must set `utls.enabled: true` explicitly (verified).
2. **No xhttp transport** (1.15 only; verified unknown in 1.14).
3. New in the tls section for 1.14: `engine` (go/apple/windows), `handshake_timeout` (default 15s), `spoof`+`spoof_method` (requires privileges).
4. `domain_resolver` became required in 1.14 (when server uses a domain).
5. uTLS legacy fingerprints (chrome_psk*) were removed and fall back to chrome; the docs don't recommend uTLS.
6. Built-in `$schema`/check validation support since 1.14.0-beta.2.
7. vless/vmess `packet_encoding` defaults differ (xudp vs disabled).
8. reality `public_key` is URL-safe raw base64; `short_id` is a string on the client / an array on the server.

## Key sources

- Source: `option/{vless,vmess,trojan,tls,v2ray_transport,outbound,multiplex}.go`, `constant/v2ray.go`, `protocol/{vless,vmess}/outbound.go`, `common/tls/reality_client.go`
- Docs: `docs/configuration/{outbound/vless.md,vmess.md,trojan.md,shared/tls.md,shared/v2ray-transport.md,shared/dial.md,migration.md}`
- Tested against the local binary `/tmp/sing-box-1.14.0-beta.14-linux-amd64/sing-box`
