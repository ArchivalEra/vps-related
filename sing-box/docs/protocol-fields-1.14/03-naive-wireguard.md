> ⚠️ Raw research output (includes source URLs for re-verification); **for maintenance, defer to the `docs/protocol-maintenance.md` §2 field audits** (the protocol set has evolved — this dictionary may include removed protocols).

# sing-box 1.14.0-beta.14 outbound config dictionary: naive / wireguard

> Sources verified against: v1.14.0-beta.14 official docs + GitHub source + release artifacts (222 lines)

## 1. Naive outbound (still present in 1.14; introduced in 1.13.0)

### Field list

| Field | Type | Required | Notes |
|---|---|---|---|
| `server` / `server_port` | string / uint16 | required | |
| `username` / `password` | string | required | plaintext |
| `insecure_concurrency` | int | optional | officially warned to break anti-analysis features |
| `extra_headers` | map | optional | |
| `udp_over_tcp` | bool | optional | |
| `quic` / `quic_congestion_control` | — | optional | bbr/bbr2/cubic/reno |
| `tls` | object | required | **no insecure option** |
| Dial Fields | — | optional | |

### TLS hard constraints (source protocol/naive/outbound.go)

- **`tls.insecure:true` errors directly** (no insecure option)
- Only `server_name` / `certificate` / `certificate_path` / `ech` are supported; everything else (utls/reality/alpn/fragment/kernel TLS) is rejected
- **A real certificate is the design premise**; self-signed only works via a pinned certificate_path, and the docs explicitly say it's not recommended for production

### Dependencies (libcronet.so)

- **The suffix-less linux-amd64 package ships libcronet.so**, which must be in the same dir as the binary or on the system library path
- The glibc/musl variants are CGO builds
- The `with_naive_outbound` default build tag exists only for mainstream platforms

### Known performance bug

- issue #3837 (150Mbps→1Mbps) **closed unfixed** (closed for lack of a minimal repro), still reproducible in 1.13.1, no fix entry in the 1.14 changelog

### 1.14 changes

- naiveproxy upgraded to v150.0.7871.63-1 (1.14.0-beta.5); config fields are word-for-word identical to 1.13.0

## 2. WireGuard (the 1.14 outbound has been removed — breaking change)

- Writing `type: wireguard` in `outbounds` fails at 1.14 startup: **"deprecated in 1.11.0, removed in 1.13.0, use WireGuard endpoint"**
- Must use the wireguard endpoint form in the `endpoints` array instead

### endpoint fields

`system` / `name` / `mtu` / `address` (required) / `private_key` (required) / `listen_port` / `peers` (required; includes `public_key` and `allowed_ips`, both required) / `reserved` / `workers` + new in 1.14 `udp_mapping`/`udp_filtering`/`udp_nat_max`

### System wireguard

- `system:true` needs root, but it's not a kernel module — it's userspace wireguard-go running on the sing-tun system TUN
- `system:false` (default) is a pure userspace gVisor stack, no root needed
- Single-machine client scenario = the endpoint is referenced by the selector/route as an outbound
- Known issue #4334: 1.14 alpha crashes at startup with `system:true`

## 3. Client-generation dependencies/warning list

| Protocol | Dependency/warning |
|---|---|
| naive | real cert required (no insecure), needs libcronet.so in the same dir as the binary, outbound performance bug unfixed |
| wireguard | must use the endpoints form (outbound form removed), system:true needs root, 1.14 alpha has a crash issue |

## Key sources

- Official docs testing branch: docs/configuration/{outbound/naive.md, endpoint/wireguard.md}
- Source: option/naive.go, protocol/naive/outbound.go, endpoint/wireguard/*, include/registry.go
- Release artifact test: linux-amd64 suffix-less package includes libcronet.so
- Earlier sub-agent verification in this repo (performance bug #3837 status)
