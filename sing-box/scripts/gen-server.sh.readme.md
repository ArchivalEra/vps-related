# gen-server.sh — server config.json quick generator (pairs with secrets.lib.sh)

This program and secrets.lib.sh exist only to quickly generate a server config.json:
9 supported protocols, any protocol repeatable for multiple instances (unique tags `<proto>-N`).
Two hidden hardenings are embedded and not exposed as flags: hysteria2
`salamander` obfs password (fresh per-run, QUIC padding vs DPI) and tuic
`"heartbeat": "10s"` (keeps QUIC alive through NAT/NAT64).

## Usage

Flags (identical to the top-of-file usage block):

| Flag | Meaning |
|---|---|
| `--domain D` | SNI for ws/grpc/naive + client connect address (default: interactive prompt) |
| `--reality-sni S` | reality handshake server SNI (default `www.microsoft.com`) |
| `--certpath P` | TLS cert path shared by all TLS inbounds (default is a placeholder — must be set) |
| `--keypath P` | TLS key path (default is a placeholder — must be set) |
| `--protocols L` | comma list, repeats allowed (multi-instance) |
| `--ports P,P,...` | comma list, positionally aligned with `--protocols` (tcp/udp may share a port) |
| `--ss-methods M` | comma method list for ss instances (positional) |
| `--chain-ss-port N` | shadowtls chained-ss port (default 8389; `0` = no chain) |
| `--cdn` | CDN/argo fronting for ws/grpc: their inbounds render WITHOUT an origin tls block (the tunnel edge terminates TLS); cert is then only required if another protocol still needs it. Pair clients with `--addr <edge-host>`. |
| `--ech` | add ECH (Encrypted Client Hello) to TLS-terminating inbounds |
| `--outputname N` | output filename (default `config-server.json`; filename only, no path) |
| `--outputpath D` | output directory (default: the script's own dir) |
| `--debug` | diagnostic output (fully silent by default) |
| `--test` | self-check: 6-inbound set → temp, sing-box check, exit |

Minimal command — generate a 6-protocol config (reality / hy2 / ws / grpc / tuic / shadowtls):

```bash
bash gen-server.sh --domain your.domain \
  --certpath /path/cert.pem --keypath /path/key.pem \
  --protocols reality,hysteria2,vless-ws,vless-grpc,tuic,shadowtls \
  --ports 443,443,8443,8444,8447,8446 \
  --ech --outputname config-server.json
```

## Requirements

- `sing-box` binary (generate uuid / reality-keypair / ech-keypair + `sing-box check`)
- `openssl`

## Notes

- Zero persistence: fresh keys every run, re-run rotates everything; the output file is the only artifact.
- Overwrite protection: refuses to overwrite an existing output file.
- Hardening: every hysteria2 inbound ships `obfs: { type: salamander, password: <fresh> }`; every tuic inbound ships `heartbeat: 10s` — both verified against `sing-box check` (1.14.0-beta.14, SINGBOX_TAG). `server → client` carries them through (`convert_hy2` already had obfs passthrough; `convert_tuic` now carries heartbeat).
- Shadowsocks in 1.14 has no `plugin` field (v2ray-plugin is outbound-only); the server's ss uses `multiplex: { enabled: true, padding: true }` for H2-style multiplexing instead, and the client carries it through. Outbound-side v2ray-plugin is out of scope for this suite.
- CDN/argo (`--cdn`): ws/grpc origins go plain (edge terminates TLS), so one cert-less config fronts Cloudflare/CloudFront/EdgeOne. ss joins the tunnel via the client's `--ss-argo` chained line. Verified live: both quick-tunnel lines plus the ss-argo chain returned HTTP 204 end-to-end through a real CF edge.
- ECH: with `--ech`, the CONFIGS are appended as `//` comments at the end of the output (sing-box accepts them) — publish them as the HTTPS/SVCB record so clients auto-load via DNS.
- Default ports: reality 443/tcp, hy2 443/udp, ws 8443, grpc 8444, anytls 8445, shadowtls 8446, tuic 8447.
- Interactive mode: no flags and stdin is a TTY → interactive (pick protocols/ports); non-TTY stdin → hints `try --help`.
