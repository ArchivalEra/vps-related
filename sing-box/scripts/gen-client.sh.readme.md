# gen-client.sh — client config.json quick generator (pairs with protocols.lib.sh)

This program and protocols.lib.sh exist only to quickly generate a client config.json
(server config → client config, single input → single output).

## Usage

Flags (identical to the top-of-file usage block):

| Flag | Meaning |
|---|---|
| `--from-server PATH` | server config.json path (required unless `--test`) |
| `--addr host` | client connect address — domain / IPv4 / IPv6 (default: interactive prompt; never probes) |
| `--sni name` | TLS SNI for real-TLS lines (default: the connect address; reality/shadowtls keep config-filtered SNI) |
| `--outputname NAME` | output filename (default `config-client.json`; filename only, no path) |
| `--outputpath DIR` | output directory (default: the script's own dir) |
| `--insecure` | add when the cert is self-signed; omit with a real cert |
| `--mux-padding on\|off` | override ss multiplex padding (default: follow server config; `off` strips multiplex, `on` forces enabled+padding) |
| `--ss-argo` | add an ss clone (`<sstag>-argo`) chained through the first vless-ws line (detour) so shadowsocks traffic rides the CDN/argo tunnel; pick it from the manual selector |
| `--inbound tun\|socks[:port]` | `tun` = global TUN (default); `socks:1080` = local socks5 listener |
| `--debug` | diagnostic output (fully silent by default) |
| `--test` | run self-check assertions, then exit |

Example:

```bash
bash gen-client.sh --from-server /path/config-server.json \
  --addr your.domain --outputname config-client.json
```

## Requirements

- `python3` (parses the server config.json)
- `sing-box` binary (self-check is bound to `sing-box check`; auto-detected via
  `SB_BIN` / PATH / test-env fallback — deca intercept is the binary's own validation)
- `protocols.lib.sh` MUST be the same-version sibling — the entry script checks after
  sourcing that the output layer (ok/warn/err/die1/die2/debug) exists, and fails with
  a re-fetch command if the lib is an outdated pre-output-layer version.

## Notes

- Single input: reads only the server config.json; no intermediate files.
- Never probes for IPs: `--addr` is user-specified (domain / IPv4 / IPv6); if omitted, prompts interactively.
- Hardening passthrough: hysteria2 `obfs.salamander` and tuic `heartbeat: 10s` are carried from server → client; shadowsocks `multiplex: { enabled, padding }` is carried as `enabled+padding` (1.14 inbound has no `protocol` field). All verified against `sing-box check` (1.14.0-beta.14, SINGBOX_TAG).
- `--insecure`: add for self-signed certs, not for real certs.
- ECH: when the server config carries `tls.ech.key`, the client auto-adds `ech.enabled`; the CONFIGS comment block is carried over to the output.
- `--test` self-check: internal assertions (conversion structure / idempotency / unique multi-instance tags).
- Interactive mode: no flags and stdin is a TTY → prompts for `--addr`; non-TTY stdin → hints `try --help`.
