# config-delivery.sh — one-time file delivery over dufs

**config-delivery.sh + dufs exists for one thing only: one-time file delivery via a
random-key URL that self-destructs after a TTL.**

## Usage

```
config-delivery.sh serve ./config-client.json --port 443 --ttl 600 --host your.domain
```

| flag | meaning |
|------|---------|
| `--port N` | listen port (default 443, 1-65535; < 1024 needs root). Ignored in `--argo` mode, where the backend binds a random loopback port. |
| `--ttl SEC` | auto-delete the file after N seconds (default 600, >= 1) |
| `--host NAME` | host in the link — an IP literal (v6 bracketed automatically), or a domain kept as-is (dual-stack: each client resolves it with its own DNS); never auto-probed. Disabled in `--argo` mode. |
| `--v4` | with `--host DOMAIN`: force-resolve to an IPv4 for an IP link (errors if no IPv4); mutually exclusive with `--v6`. Disabled in `--argo` mode. |
| `--v6` | with `--host DOMAIN`: force-resolve to an IPv6 for an IP link (errors if no IPv6); mutually exclusive with `--v4`. Disabled in `--argo` mode. |
| `--cert FILE` | PEM certificate. Three-state TLS: readable `--cert` + readable `--key` → real-cert HTTPS; only one given (or either unreadable) → warning + fresh self-signed HTTPS fallback (clients `curl -k`); neither given → plain HTTP with a secrets-in-clear warning. Disabled in `--argo` mode. |
| `--key FILE` | PEM private key; pairs with `--cert` (three states, see above). Disabled in `--argo` mode. |
| `--argo` | deliver via a cloudflared quick tunnel: public `https://<random>.trycloudflare.com` URL with a public-CA cert (Google Trust Services — browsers trust it, zero warnings), no domain or open inbound port needed. dufs runs plain HTTP on a random loopback port. Disables `--host`/`--v4`/`--v6`/`--cert`/`--key`. |
| `FILE` | the file to deliver (positional) |

Simplest form (defaults — plain HTTP on localhost):

```
config-delivery.sh serve ./config-client.json
```

With a real cert:

```
config-delivery.sh serve ./config-client.json --cert server.crt --key server.key
```

With a cloudflared quick tunnel (public URL, browser-trusted, no inbound port):

```
config-delivery.sh serve ./config-client.json --argo
```

Client side — open the link in a browser, or:

```
# plain HTTP / quick tunnel:
curl -OJ http://localhost:443/<8-char-key>

# HTTPS with a real cert:
curl -OJ https://your.domain:443/<8-char-key>

# HTTPS with the self-signed fallback:
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
- **cloudflared** — required only for `--argo` mode (the quick tunnel client). When
  it is missing, `--argo` prints a blue `no cf, argo link generation disabled`
  notice and exits 1 — there is deliberately no install wizard for it, since quick
  tunnels are a feature toggle, not a delivery requirement.
- **openssl** — used to mint the self-signed fallback cert (when a half
  `--cert`/`--key` pair is given or unreadable) and to generate the random key.
- **bash** — for the `/dev/tcp` port pre-check. Nothing else.

## Notes

- **Why dufs + a thin wrapper?** dufs already ships the hard parts — static file
  serving, native TLS, streaming, a single static musl binary — and is mature and
  active. Writing our own server would only rebuild that. What dufs lacks is the
  one-time semantics, which is the ~30 lines this wrapper adds.
- **Why a random key URL?** The 8-char key (`a-zA-Z0-9_-`) is the secret: without it
  the path is a 404 and the directory listing is hidden, so the link is effectively
  private and one-time without any auth setup.
- **Why TTL self-destruct?** After N seconds the served processes (dufs, plus
  cloudflared in `--argo` mode) are killed and the temp dir is removed, so the
  delivered file does not linger on the machine after delivery. Nothing is persisted
  beyond the temp dir.
- **Why an `--argo` quick-tunnel mode?** A direct link needs a reachable host/IP and
  an open inbound port (often 443 — root — for the cert to match). A cloudflared
  quick tunnel removes both: `cloudflared tunnel --url http://127.0.0.1:PORT` gives
  you a public `https://<random>.trycloudflare.com` URL whose cert is issued by
  Google Trust Services (a public CA), so browsers connect with **zero warnings**
  and no `-k` — no domain, no DNS, no open port, no private key to manage. The local
  dufs backend stays plain HTTP on a random loopback port (bound to 127.0.0.1 only),
  reachable solely through the tunnel. Because the tunnel owns the public URL and
  cert, `--host`/`--v4`/`--v6`/`--cert`/`--key` are refused with an error in
  `--argo` mode. The trycloudflare URL is polled from the cloudflared log (up to
  ~20s); if it never appears, the log tail is printed and everything is cleaned up.
- **TLS three states.** `--cert`/`--key` are optional, and there are three outcomes:
  1. **Real cert** — both paths are given and readable: dufs serves HTTPS with them
     end to end. Clients trust the cert directly (no `-k`).
  2. **Self-signed fallback** — only one is given, or either path is missing or
     unreadable: the script prints a warning and mints a fresh throwaway ECDSA
     cert instead of dying. Clients must `curl -k`; a browser shows one click-through
     warning.
  3. **Plain HTTP** — neither is given: dufs runs with no TLS flags at all. This is
     zero-config but carries a real security cost, so the printed link is prefixed
     with a warning: **the config file contains secrets, and plain HTTP means anyone
     on the network path (LAN, NAT, ISP, CDN) can read the payload.** Use it only on
     a trusted network, or pair it with `--argo` (which keeps the public path
     encrypted) or real certs.
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
  returns 200 — the script downloads it over loopback (curl -k for HTTPS states,
  plain curl for HTTP, up to 1.5s) before announcing it. A dead bind surfaces as
  `dufs failed to serve the link` instead of a link nobody can open.
