# sing-box Client Protocol Maintenance Guide (MAINTENANCE)

> **Scope**: sing-box 1.13+ **client** outbound config (server side is out of scope here).
> **Current baseline**: `1.14.0-beta.14` (version constants `SINGBOX_VERSION`/`SINGBOX_MAJOR_MINOR` live in `scripts/protocols.lib.sh`).
> **Usage**: when upgrading the sing-box binary, walk through this guide item by item; issues actually hit in this repo are marked `[verified]`.

---

## 0. Upgrade SOP (run in order for every version bump)

```bash
# 1. 下载新版本二进制到脚本实际查找的位置（gen-client.sh 依次找：PATH 的 sing-box → /opt/sing-box/sing-box → test-env/bin/sing-box）
# 2. 改 scripts/gen-client.sh 头部的 SINGBOX_VERSION / SINGBOX_MAJOR_MINOR
# 3. 用 test-env 配置跑 gen-client.sh，看 sing-box check 是否报 unknown field
#    → 报错字段去下方【字段审计】对应协议找，改 scripts/protocols.lib.sh 对应 convert_* 模板
# 4. 跑全场景回归（--test 自检 + 六线链路 + 新协议）
# 5. 把新版本再变的字段记进本清单【变更史】，标注版本
```

**Binary discovery** (`find_sb_bin` in `scripts/protocols.lib.sh`, the single source of truth shared by gen-client.sh / assert_gen / e2e-all.sh): `SB_BIN` env (must be executable) → `sing-box` in `PATH` → `test-env/bin/sing-box`.

**Version consistency defense**: gen-client.sh probes the binary version itself — if the detected major.minor ≠ `SINGBOX_MAJOR_MINOR`, it warns. **But `check` is the final arbiter**: a renamed field always makes `check` report `unknown field`, so "bump version → run check → read errors" is the three-step loop that can never miss.

---

## 1. Breaking-change history (hit + known)

| Version | Change | Impact | Evidence |
|---|---|---|---|
| 1.14 | reality `handshake.port` → `server_port` | server template | [verified] FATAL `unknown field "port"` |
| 1.14 | DNS server `address` shorthand **removed** | client DNS section | [verified]: must use the new `type:https`/`type:local` format |
| 1.14 | `dns.strategy: ipv4_first` → `prefer_ipv4` | client DNS | [verified] FATAL `unknown domain strategy` |
| 1.14 | missing domain_resolver is enforced | client route | [verified]: requires `route.default_domain_resolver` |
| 1.14 | **wireguard outbound removed** → endpoint form | client wg | [verified] FATAL `outbounds[].server unknown field`; schema confirms endpoint |
| 1.14 | reality client must set `utls.enabled:true` explicitly | client vless | [verified] FATAL `uTLS is required by reality client` |
| 1.14 | `tls.acme` inline → `certificate_providers` | server (no client impact) | verified by sub-agent |
| 1.14 | hy2 adds `disable_chrome_parrot` (default false = Chrome fingerprint) | client hy2 | verified by sub-agent |
| 1.14 | naiveproxy → v150 (fields unchanged) | client naive | verified by sub-agent |
| 1.13 | tls cert field churn (certpath → certificate_path-type renames, user experience) | various tls sections | user experience (not tested in this repo); **1.14 state per schema: `certificate_path`/`certificate`** |
| 1.12 | DNS legacy server format begins deprecation | client DNS | official deprecation announcement |
| 1.13 | wireguard outbound deprecated (removed in 1.14) | client wg | official error text |
| 1.15 (upcoming) | **xhttp transport** introduced | client vless transport | verified: no xhttp in 1.14, only in 1.15 |

---

## 2. Protocol field audit tables

> Each table has three columns: template field / 1.14 state (required, default) / upgrade check point (what happens if the field changes).

### VLESS + Reality (`convert_vless`)

| Field | 1.14 state | Upgrade check point |
|---|---|---|
| `flow: xtls-rprx-vision` | only legal value; server must use the same | invalid value fails at init with `unsupported flow` |
| `packet_encoding: xudp` | xudp by default (explicit empty string = disabled) | a default-behavior change affects UDP |
| `tls.utls.enabled` | **must be explicitly true** (reality client) | not auto-filled since 1.14; removing it is a FATAL |
| `tls.reality.public_key` | URL-safe raw base64 (no `=`, may contain `-_`) | encoding-rule change = all keys must be regenerated |
| `tls.reality.short_id` | client uses a **single string** (server uses an array) | writing an array on the client errors out |
| `tls.handshake_timeout` | new in 1.14, default 15s | optional; safe to remove |

### Hysteria2 (`convert_hy2`)

| Field | 1.14 state | Upgrade check point |
|---|---|---|
| `obfs.type: salamander` | only salamander/gecko (gecko added in 1.14) | any other value fails `check` |
| `obfs.password` | required once obfs is set | empty reports `missing obfs password` |
| `password` | auth password | the userpass composite string goes entirely into password |
| `tls` (disable_chrome_parrot) | default false = Chrome QUIC fingerprint | **server must use an ECDSA cert** (Chrome doesn't support Ed25519) |
| `up_mbps`/`down_mbps` | field names are not up/down | left empty falls back to BBR congestion control |
| `server_ports`/`hop_interval` | 1.11+ port hopping | optional if unused |

### ShadowTLS (`convert_shadowtls`)

| Field | 1.14 state | Upgrade check point |
|---|---|---|
| `version: 3` | default 1; password only used by v2/v3 | client v3 config is structurally identical to v2 |
| `password` | only meaningful for v2/v3 | v1 has no password field |
| `tls` | server_name + utls chrome | TCP only (UDP not supported) |

### Shadowsocks (`convert_ss` direct; the chain form lives in `convert_shadowtls`)

| Field | 1.14 state | Upgrade check point |
|---|---|---|
| `method: 2022-blake3-aes-256-gcm` | 2022 series (base64 password) | a misspelled method fails `check` |
| `detour` (chained) | ss → shadowtls tag | a missing target tag fails at runtime |
| `server_port` (chained) | set to the shadowtls port | in a chain the ss layer is port-transparent |

### TUIC (`convert_tuic`)

| Field | 1.14 state | Upgrade check point |
|---|---|---|
| `uuid` | required; invalid UUID errors | format must be a standard UUID |
| `congestion_control: bbr` | **defaults to cubic**; write BBR explicitly | removing the field = back to cubic |
| `udp_relay_mode`/`udp_over_stream` | mutually exclusive | configuring both errors |
| `zero_rtt_handshake` | default false; must be enabled on both ends | enabled on one end only has no effect |

### AnyTLS (`convert_anytls`)

| Field | 1.14 state | Upgrade check point |
|---|---|---|
| `password` | required | |
| `padding_scheme` | **server-side field; not configurable on the client** | don't write it into the template (check errors) |
| `tcp_fast_open` | **disabled** (lazy-connect nil-pointer crash) | the template must never add tfo |
| `client_metadata` | default empty string in 1.14 | not adding it = no fingerprint sent (correct default) |
| `idle_session_*` | default 30s/30s/0 | optional |

### VLESS + WS / GRPC (`convert_vless` — ws/grpc branches)

> Note: the converter has a single `convert_vless` covering the reality / ws / grpc branches. There is no separate `convert_vless_ws`/`convert_vmess_ws`, and **VMess is not implemented**.

| Field | 1.14 state | Upgrade check point |
|---|---|---|
| `transport.type: ws` | no plain TCP; transport is only http/ws/quic/grpc/httpupgrade | **xhttp is 1.15 only**; writing xhttp on 1.14 = unknown |
| `transport.type: grpc` | `service_name` required; `transport.headers` has no effect on grpc | if 1.15 changes the `proto` form, sync the convert_vless grpc branch |
| `ws.path`/`ws.headers.Host` | default path empty | |

### Trojan (not implemented — no `convert_trojan` in the code)

> Reference only: the converter has no trojan branch (`convert_trojan` does not exist). If trojan is ever added back, the field facts below apply.

| Field | 1.14 state | Upgrade check point |
|---|---|---|
| `tls.enabled` | **must be true** (Trojan itself is TLS) | removing it makes the line unusable |
| `password` | required | |

### Naive (`convert_naive`)

| Field | 1.14 state | Upgrade check point |
|---|---|---|
| `tls` | **no insecure option** (hard validation) | real cert required; insecure=true errors out |
| dependency | libcronet.so in the same dir as the binary | included in the 1.14 suffix-less linux-amd64 package |
| performance | outbound bug #3837 (150→1Mbps) **unfixed** | don't use as a primary line |

### ~~WireGuard~~ (removed from this project, 2026-08-13)

> Removed by user decision (local dual-process tunnel orchestration wasn't mature + low value in a single-machine proxy scenario).
> In 1.14 it's a top-level `endpoints` form (the outbound was removed). This converter does not support it; refer to this table if it's ever added back.

| Field | 1.14 state | Upgrade check point |
|---|---|---|
| form | **outbound removed**; must use the top-level `endpoints` array | writing it back into outbounds reports `unknown field "server"` |
| `endpoints[].address` | required (e.g. 10.0.0.2/32) | |
| `peers[].public_key`/`allowed_ips` | required | |
| `system` | true needs root; 1.14 alpha has crash issue #4334 | default false (gVisor) is most stable |

---

## 3. Mapping between templates and binary

```
scripts/protocols.lib.sh   ← 协议转换库唯一真源（convert_* + render_from_server 遍历表 + assert_gen 自检）
scripts/gen-client.sh      ← 编排（--from-server 解析/版本探测/渲染/check）+ 版本速查注释
docs/protocol-fields-1.14/ ← 字段字典（子代理 research 落盘，含来源 URL，升级时可复核）
```

**Linked points when editing a template** (miss one and it breaks):
1. add `convert_xxx()` in `protocols.lib.sh` + register it in `render_from_server()`
2. add a field-audit row in `docs/protocol-maintenance.md`
3. add the protocol's line test in `test-env/` (e2e-all.sh picks lines from the generated output automatically; no script change needed)
4. update the field dictionary in `docs/protocol-fields-1.14/` (when sources need re-checking)

---

## 4. Verification layers (four, all required)

| Layer | Means | Blocks |
|---|---|---|
| 0 | **`gen-client.sh --test` self-check assertions** (assert_gen, merged into protocols.lib.sh) | 7 behavior regressions: exit-code contract / empty inbounds / 9-line conversion structure (incl. public-key derivation, ref sets) / idempotency |
| 1 | gen-client.sh version-probe warning | reminder that the binary version doesn't match the template |
| 2 | `sing-box check` (always run after generation) | field-name / required / format errors (**final arbiter**) |
| 3 | `$schema` (built-in since 1.14.0-beta.2+) | IDE edit-time validation (optional) |

**Must run after upgrade**: `bash scripts/gen-client.sh --test` (self-check) + `bash test-env/e2e-all.sh` (per-line live test of the converted output) — only release when both are green.

**For troubleshooting**: `bash scripts/gen-client.sh --from-server ... --debug` prints full diagnostics (config parse / unknown keys / binary probe / temp dir); fully silent by default (zero diagnostic output without `--debug`).

> Lesson: for the 1.13→1.14 field changes, the official changelog only said "Fixes and improvements" — **everything was caught by check errors** (6 places verified in this repo). So "upgrade → run check → read errors → update the list" is the only reliable loop.
