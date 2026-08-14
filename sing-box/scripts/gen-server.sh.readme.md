# gen-server.sh — server config.json quick generator (pairs with secrets.lib.sh)

This program and secrets.lib.sh exist only to quickly generate a server config.json:
9 supported protocols, any protocol repeatable for multiple instances (unique tags `<proto>-N`).

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
- ECH: with `--ech`, the CONFIGS are appended as `//` comments at the end of the output (sing-box accepts them) — publish them as the HTTPS/SVCB record so clients auto-load via DNS.
- Default ports: reality 443/tcp, hy2 443/udp, ws 8443, grpc 8444, anytls 8445, shadowtls 8446, tuic 8447.
- Interactive mode: no flags and stdin is a TTY → interactive (pick protocols/ports); non-TTY stdin → hints `try --help`.
