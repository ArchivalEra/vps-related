# gen-client.sh — client config.json quick generator (pairs with protocols.lib.sh)

This program and protocols.lib.sh exist only to quickly generate a client config.json
(server config → client config, single input → single output).

## Usage

Flags (identical to the top-of-file usage block):

| Flag | Meaning |
|---|---|
| `--from-server PATH` | server config.json path (required unless `--test`) |
| `--server host` | client connect address — domain / IPv4 / IPv6 (default: interactive prompt; never probes) |
| `--outputname NAME` | output filename (default `config-client.json`; filename only, no path) |
| `--outputpath DIR` | output directory (default: the script's own dir) |
| `--insecure` | add when the cert is self-signed; omit with a real cert |
| `--inbound tun\|socks[:port]` | `tun` = global TUN (default); `socks:1080` = local socks5 listener |
| `--debug` | diagnostic output (fully silent by default) |
| `--test` | run self-check assertions, then exit |

Example:

```bash
bash gen-client.sh --from-server /path/config-server.json \
  --server your.domain --outputname config-client.json
```

## Requirements

- `sing-box` binary (version detection + `sing-box check`)
- `python3` (parses the server config.json)

## Notes

- Single input: reads only the server config.json; no intermediate files.
- Never probes for IPs: `--server` is user-specified (domain / IPv4 / IPv6); if omitted, prompts interactively.
- `--insecure`: add for self-signed certs, not for real certs.
- ECH: when the server config carries `tls.ech.key`, the client auto-adds `ech.enabled`; the CONFIGS comment block is carried over to the output.
- `--test` self-check: internal assertions (conversion structure / idempotency / unique multi-instance tags).
- Interactive mode: no flags and stdin is a TTY → prompts for `--server`; non-TTY stdin → hints `try --help`.
