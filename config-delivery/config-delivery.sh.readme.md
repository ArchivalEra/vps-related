# config-delivery.sh — one-time file delivery over dufs

**config-delivery.sh + dufs exists for one thing only: one-time file delivery via a
random-key HTTPS URL that self-destructs after a TTL.**

## Usage

```
config-delivery.sh serve ./config-client.json --port 443 --ttl 600 --host your.domain
```

| flag | meaning |
|------|---------|
| `--port N` | listen port (default 443, 1-65535; < 1024 needs root) |
| `--ttl SEC` | auto-delete the file after N seconds (default 600, >= 1) |
| `--host NAME` | host in the link — an IP literal (v6 bracketed automatically), or a domain kept as-is (dual-stack: each client resolves it with its own DNS); never auto-probed |
| `--v4` | with `--host DOMAIN`: force-resolve to an IPv4 for an IP link (errors if no IPv4); mutually exclusive with `--v6` |
| `--v6` | with `--host DOMAIN`: force-resolve to an IPv6 for an IP link (errors if no IPv6); mutually exclusive with `--v4` |
| `--cert FILE` | PEM certificate; must be given with `--key` (default: fresh self-signed ECDSA) |
| `--key FILE` | PEM private key; must be given with `--cert` |
| `FILE` | the file to deliver (positional) |

Simplest form (defaults, self-signed cert):

```
config-delivery.sh serve ./config-client.json
```

Client side — open the link in a browser, or:

```
curl -kOJ https://localhost:443/<8-char-key>
```

Run `config-delivery.sh --help` for the same flag summary at the terminal.

## Requirements

- **dufs** — the script resolves the binary from `$DUFS_BIN` (env), falling back to
  `dufs` on PATH. When it is missing, the script prints a complete install wizard:
  architecture detection (`uname -m` → `x86_64-unknown-linux-musl` or
  `aarch64-unknown-linux-musl`), a curl download URL (pinned to v0.46.0; the message
  notes the version number can be replaced with the latest from the dufs releases
  page), `tar` extraction into `/usr/local/bin`, a `dufs --version` check, and a
  "re-run this script" prompt. Prebuilt binaries are published for Linux x86_64 and
  aarch64 (musl) only; other architectures need a from-source build.
- **openssl** — used to mint the self-signed cert when no `--cert`/`--key` is given,
  and to generate the random key.
- **bash** — for the `/dev/tcp` port pre-check. Nothing else.

## Notes

- **Why dufs + a thin wrapper?** dufs already ships the hard parts — static file
  serving, native TLS, streaming, a single static musl binary — and is mature and
  active. Writing our own server would only rebuild that. What dufs lacks is the
  one-time semantics, which is the ~30 lines this wrapper adds.
- **Why a random key URL?** The 8-char key (`a-zA-Z0-9_-`) is the secret: without it
  the path is a 404 and the directory listing is hidden, so the link is effectively
  private and one-time without any auth setup.
- **Why TTL self-destruct?** After N seconds the server process is killed and the
  temp dir is removed, so the delivered file does not linger on the machine after
  delivery. Nothing is persisted beyond the temp dir.
- **Why never auto-probe the IP?** The script cannot know which host/IP the client
  can actually reach (public IP, NAT, DNS, multiple interfaces). The operator knows;
  the script prints whatever `--host` is given (default localhost).
- **Why keep `--host DOMAIN` as a domain?** The link is dual-stack by default — each
  client resolves the domain with its own DNS, so a v4-only device gets the A record
  and a v6-only device the AAAA. `--v4`/`--v6` only force-resolve to an IP link when
  the caller explicitly needs one (a no-DNS client, or avoiding a sniffable SNI).
  This is user-supplied too: the script resolves what the caller names, never itself.
  The three host pickers (`--host`/`--v4`/`--v6`) — `--v4` and `--v6` are mutually
  exclusive; `--host` is the input they modify.
- **Port pre-check**: done with pure-bash `/dev/tcp` on loopback only — no `nc`
  dependency, and it checks availability without probing anything external.
- **Startup self-check**: the link is printed only after the key URL actually
  returns 200 — the script downloads it over loopback (curl -k, up to 1.5s) before
  announcing it. A dead bind surfaces as `dufs failed to serve the link` instead of
  a link nobody can open.
