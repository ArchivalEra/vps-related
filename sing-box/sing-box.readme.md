# sing-box deployment suite — full-featured end-to-end walkthrough

This is the operator's single entry point to the whole sing-box folder. It runs
**every feature the suite ships** in one production-shaped flow, from an empty
VPS to a handoff link, and each step points at the readme that covers the detail.

What lives where:

```
sing-box/
├─ scripts/
│  ├─ gen-server.sh       # server config generator (flags or interactive)
│  ├─ secrets.lib.sh      # credentials + protocol registry + renderers (sourced by gen-server)
│  ├─ gen-client.sh       # server config → client config converter
│  └─ protocols.lib.sh    # conversion lib (sourced by gen-client)
├─ docs/
│  ├─ runbook.md              # manual two-node deploy (step-by-step VPS)
│  ├─ protocol-maintenance.md # 1.14 field audit + upgrade SOP
│  └─ cf-prefer-guide.md      # Cloudflare tunnel topology for ws/grpc/ss
└─ test-env/
   ├─ setup.sh          # mock VPS: secrets + 9-inbound server config + self-signed cert
   ├─ assert_gen.sh     # gen-client.sh --test target (structural assertions)
   ├─ e2e-all.sh        # live dual-process per-line 204 probe
   └─ bin/sing-box      # 1.14.0-beta.14 binary (gitignored)
```

Sibling tools outside `sing-box/` that complete the delivery story:

- `boiledegg/boiledegg.sh` — CF quick-tunnel manager for the ws/grpc lines (argo-only).
- `config-delivery/config-delivery.sh` + `.py` — one-time or persistent file delivery
  (multi-file directory, independent `?k=` link key).

---

## 0. The whole flow at a glance

```
gen-server.sh (all 9 protocols + ECH, real cert)
   │  └─ writes ONE server config.json (fresh creds, sing-box check)
   ▼
test-env/e2e-all.sh            # per-line live 204 verification (all protocols)
   │
gen-client.sh (--inbound socks, --insecure)
   │  └─ reads that server config → client config (single input/output)
   ▼
boiledegg.sh (ws/grpc → argo quick tunnels)
   │  └─ reuses gen-client, repoints ws/grpc lines at trycloudflare hosts
   ▼
config-delivery.sh/.py (multi-file, ?k=)
   └─ serves client configs (direct + argo) behind a persistent link
```

---

## 1. Prerequisites

```bash
# sing-box binary (the suite self-checks with it)
curl -fL -o /tmp/sb.tar.gz https://github.com/SagerNet/sing-box/releases/download/v1.14.0-beta.14/sing-box-1.14.0-beta.14-linux-amd64.tar.gz
tar -xzf /tmp/sb.tar.gz -C /usr/local/bin --strip-components=1
sing-box version   # → v1.14.0-beta.14

# TLS cert (wildcard design: ONE cert/key shared by all TLS inbounds)
#   - real VPS: your domain cert (+ key), e.g. /etc/ssl/dib.l.cd/apple/{cert,key}.pem
#   - test env: bash test-env/setup.sh mints one (self-signed ECDSA, CN=your.domain.example)

# tools: openssl (creds + self-signed), cloudflared (argo), python3 (converter/delivery)
```

---

## 2. Server config — every protocol + every hardening

Generate a server config that uses **all 9 protocols**, multi-instance repeats,
the shadowtls→ss chain, and ECH:

```bash
cd sing-box/scripts
bash gen-server.sh \
  --domain your.domain \
  --certpath /etc/ssl/your/cert.pem \
  --keypath  /etc/ssl/your/key.pem \
  --protocols reality,hysteria2,vless-ws,vless-grpc,anytls,shadowtls,shadowtls,shadowsocks,tuic,naive \
  --ports 443,443,8443,8444,8445,8446,8447,8388,8389,8448 \
  --chain-ss-port 8390 \
  --ss-methods 2022-blake3-aes-256-gcm,2022-blake3-aes-256-gcm \
  --ech \
  --outputname config-server.json --outputpath /etc/sing-box
```

What that config ships (all auto-embedded, no flags needed):

| Inbound | Tag | Hardening rendered by `secrets.lib.sh` |
|---|---|---|
| `reality` | `reality` | X25519 keypair, `short_id`, `utls.enabled` (1.14 requires it) |
| `hysteria2` | `hy2` | `obfs: {type: salamander, password: <fresh>}` — QUIC DPI padding |
| `vless-ws` | `vless-ws` | `transport.ws path /ws` + shared TLS cert |
| `vless-grpc` | `vless-grpc` | `transport.grpc service_name grpc` + shared TLS cert |
| `anytls` | `anytls` | 12-hex password, shared TLS cert |
| `shadowtls` (1st) | `shadowtls` | v3, `strict_mode`, `detour: ss-chain-in` → chain ss on `8390` |
| `shadowtls` (2nd) | `shadowtls-2` | second instance, no chain (multi-instance unique tags) |
| `shadowsocks` | `ss2022` | `multiplex {enabled, padding}` — H2-style multiplexing |
| `tuic` | `tuic` | `congestion_control bbr` + `heartbeat "10s"` (QUIC NAT keep-alive) |
| `naive` | `naive` | `sb`/password, shared TLS cert |

`--ech` additionally appends the ECH CONFIGS block as `//` comments at the end of
the file (publish it as your HTTPS/SVCB record so clients auto-load via DNS).

Self-check: `gen-server.sh --test` regenerates to temp, runs `sing-box check`, exits 0.
The real run above already ran `sing-box check` on the output.

---

## 3. Verify every line lives (local, dual-process)

The suite's own live test proves each protocol converts and dials:

```bash
cd sing-box/test-env
bash setup.sh      # mock VPS: 9 inbounds on 127.0.0.1:10001-10009 + self-signed cert
bash e2e-all.sh    # per-line: convert → run server+client → curl 204
```

- Covers: vless-reality, vless-ws, hy2, shadowtls+ss-chain, tuic, anytls,
  ss-direct, naive (naive is skipped — it needs a real cert, no `insecure`).
- Skips `auto/manual/direct/block` selectors and the shadowtls shell line.

Structural contract (no binary needed) is `gen-client.sh --test` →
`test-env/assert_gen.sh`: arg-error exit 1, empty-inbounds exit 2, 9-line
conversion structure + idempotency (identical md5 on re-run).

---

## 4. Client config — single input, single output

```bash
cd sing-box/scripts
bash gen-client.sh \
  --from-server /etc/sing-box/config-server.json \
  --addr your.domain \
  --sni your.domain \
  --insecure \
  --inbound socks:1080 \
  --outputname config-client.json --outputpath /etc/sing-box
```

- `--addr` is the client connect address (never auto-probed).
- `--sni` overrides SNI for real-TLS lines; reality/shadowtls keep config SNI.
- `--insecure` adds `insecure:true` for the self-signed test cert; **omit it with a
  real cert** (this is the step the e2e uses with `--inbound socks`).
- Output: one `config-client.json`, validated by `sing-box check` (exit 2 on fail).
- `--inbound tun` (default) or `socks:PORT`; `--test` runs the assert_gen self-check.

The conversion carries the server's hardening through: `convert_hy2` keeps
`salamander`, `convert_tuic` keeps `heartbeat`, `convert_ss` keeps `multiplex`,
`convert_vless[ws/grpc]` keeps the ECH-enabled TLS block.

---

## 5. Argo-boost the CDN-capable lines (ws/grpc)

`boiledegg.sh` is argo-only: proper CDNs (CF SaaS / CloudFront) terminate their own
certs and need zero sing-box changes, so this tool only manages the ephemeral
quick-tunnel variant.

```bash
cd boiledegg
bash boiledegg.sh /etc/sing-box/config-server.json \
  --addr your.domain --lines 1,2 --logs /var/log/boiledegg
```

> Proxy note: the production VPS has no GFW, so no proxy is needed. Only on a
> **test box behind the GFW** prepend `https_proxy=http://127.0.0.1:2080
> HTTP_PROXY=http://127.0.0.1:2080` (cloudflared honors it for the quick-tunnel
> registration).

- Lists only `vless-ws` / `vless-grpc` listeners, multi-select by number.
- Starts one detached `cloudflared tunnel --url <http|https>://127.0.0.1:<port>`
  per line (`--protocol http2`, `--no-tls-verify` for TLS origins).
- Reuses `gen-client.sh --from-server --addr` internally, then repoints the
  selected lines' `server`/`tls.server_name` at their `*.trycloudflare.com` hosts.
- Output: exactly one `cdn-client.json` (overwrite by design); PIDs printed in red
  are the handle — `kill <pids>` stops, re-run renews URLs.

---

## 6. Deliver the configs (multi-file, ?k=)

`config-delivery` serves the client configs — direct and argo — behind one
persistent link, with an independent `?k=` key:

```bash
# Put both client configs in one directory
mkdir -p /srv/cdn && cp /etc/sing-box/config-client.json /srv/cdn/direct.json
cp /srv/cdn/../cdn-client.json /srv/cdn/argo.json

# Multi-file directory (any file types, streamed; link has ?k=<64hex>)
python3 config-delivery/config-delivery.py /srv/cdn --host your.domain --ttl 86400
#   → one-time download link: http://your.domain:443/<key>/?k=<64hex>
#   GET /<key>/            → ["direct.json","argo.json"]
#   GET /<key>/argo.json?k=… → streamed file

# Or the bash twin (dufs backend)
bash config-delivery/config-delivery.sh /srv/cdn --host your.domain --ttl 86400
```

- `?k=<64hex>` is independent of the path `<key>` (`CD_ENC_KEY` env or
  `openssl rand -hex 32` fallback).
- TTL has no upper bound — a big value is the honest way to keep a subscription
  link up without systemd. `--hold` is the foreground countdown variant.
- `--argo` (delivery itself behind a quick tunnel) is orthogonal and works with
  the same directory.

---

## 7. Production checklist

- [ ] `sing-box check` passed on the generated server config (automatic).
- [ ] `gen-server.sh --test` green (6-protocol default set).
- [ ] `gen-client.sh --test` green (6/6 assert_gen).
- [ ] `test-env/e2e-all.sh` green on the machine that will run the server.
- [ ] Cert is real (not self-signed) when the client omits `--insecure`.
- [ ] ECH CONFIGS published as the HTTPS/SVCB record when `--ech` is used.
- [ ] `boiledegg` quick tunnels registered (no proxy on the production VPS; only
      GFW test boxes prepend `https_proxy=…2080`).
- [ ] Delivery link verified with the printed `?k=` (strip `?k=` to verify path).

## 8. Where each readme goes deeper

| Topic | Read |
|---|---|
| Manual two-node VPS deploy (ports, install) | `docs/runbook.md` |
| sing-box 1.14 field audit + upgrade SOP | `docs/protocol-maintenance.md` |
| Cloudflare topology (ws/grpc/ss preference) | `docs/cf-prefer-guide.md` |
| gen-server flags & hardening | `scripts/gen-server.sh.readme.md` |
| gen-client flags & conversion | `scripts/gen-client.sh.readme.md` |
| Argo quick-tunnel manager | `boiledegg/boiledegg.sh` (header) |
| File delivery (multi-file, `?k=`) | `config-delivery/config-delivery.py.readme.md` |
