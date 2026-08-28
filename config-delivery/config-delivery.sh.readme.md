# config-delivery.sh — one-time file delivery over dufs

**config-delivery.sh + dufs exists for one thing only: one-time file delivery via a
random-key URL that self-destructs after a TTL (default 60s, or `--ttl N`). `--hold`
does not make the share longer — it is a terminal mode: the script stays in the
foreground with a live single-line countdown, `^C` stops the share right away, and
the TTL elapsing ends it by itself.**

## Usage

```
config-delivery.sh serve ./config-client.json --port 443 --ttl 600 --host your.domain   # 600s self-destruct
config-delivery.sh serve ./config-client.json --port 443 --hold --host your.domain      # foreground countdown, ^C to stop
config-delivery.sh serve ./config-client.json --port 443 --host your.domain             # default: 60s TTL self-destruct
config-delivery.sh serve ./config-client.json --port 443 --ttl 3600 --hold --host your.domain   # 1h, foreground countdown
```

| flag | meaning |
|------|---------|
| `--port N` | listen port (default 443, 1-65535; < 1024 needs root). Ignored in `--argo` mode, where the backend binds a random loopback port. |
| `--ttl SEC` | auto-delete: the file is served for N seconds (>= 1, no upper bound) and then self-destructs. Default **60**. Combines freely with `--hold`. |
| `--hold` | **foreground mode** — the script stays in the terminal and prints an acme-style single-line countdown (`\r` in-place update). `^C` stops the share immediately (with cleanup); when the countdown hits zero the share ends by itself and the terminal is released. Not a longer lease — the TTL still decides when the link dies. Not exclusive with `--ttl`. |
| `--host NAME` | host in the link — an IP literal (v6 bracketed automatically), or a domain kept as-is (dual-stack: each client resolves it with its own DNS); never auto-probed. Disabled in `--argo` mode. |
| `--v4` | with `--host DOMAIN`: force-resolve to an IPv4 for an IP link (errors if no IPv4); mutually exclusive with `--v6`. Disabled in `--argo` mode. |
| `--v6` | with `--host DOMAIN`: force-resolve to an IPv6 for an IP link (errors if no IPv6); mutually exclusive with `--v4`. Disabled in `--argo` mode. |
| `--cert FILE` | PEM certificate. Three-state TLS: readable `--cert` + readable `--key` → real-cert HTTPS; only one given (or either unreadable) → warning + fresh self-signed HTTPS fallback (clients `wget --no-check-certificate`); neither given → plain HTTP with a secrets-in-clear warning. Disabled in `--argo` mode. |
| `--key FILE` | PEM private key; pairs with `--cert` (three states, see above). Disabled in `--argo` mode. |
| `--argo` | deliver via a cloudflared quick tunnel: public `https://<random>.trycloudflare.com` URL with a public-CA cert (Google Trust Services — browsers trust it, zero warnings), no domain or open inbound port needed. dufs runs plain HTTP on a random loopback port. Disables `--host`/`--v4`/`--v6`/`--cert`/`--key`. |
| `FILE` | the file or directory to deliver (positional) — single file or multi-file (any types, streamed via dufs/py) |

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
wget -O config-client.json http://localhost:443/<8-char-key>

# HTTPS with a real cert:
wget -O config-client.json https://your.domain:443/<8-char-key>

# HTTPS with the self-signed fallback:
wget --no-check-certificate -O config-client.json https://localhost:443/<8-char-key>
```

Run `config-delivery.sh --help` for the same flag summary at the terminal.

## Python version (config-delivery.py)

`config-delivery.py` is a 1:1 flag-compatible port of this script with **zero
external dependencies**: no dufs, no wget — the HTTP server is Python stdlib
(`http.server` + `ssl`, HTTP/1.1 only) and link verification uses `urllib`.
Requires only python3 (3.8+) and `openssl` for the self-signed fallback cert.
Every flag (`--port/--ttl/--hold/--host/--v4/--v6/--cert/--key/--argo`) behaves
identically; see `config-delivery.py --help`.

## Requirements

- **dufs** — the script resolves the binary from `$DUFS_BIN` (env), falling back to
  `dufs` on PATH. When it is missing, the script prints a complete install wizard:
  architecture detection (`uname -m` → `x86_64-unknown-linux-musl` or
  `aarch64-unknown-linux-musl`), a wget download URL (pinned to v0.46.0; the message
  notes the version number can be replaced with the latest from the dufs releases
  page), `tar` extraction into `/usr/local/bin`, a `dufs --version` check, and a
  "re-run this script" prompt. Prebuilt binaries are published for Linux x86_64 and
  aarch64 (musl) only; other architectures need a from-source build.
- **wget** — the link self-check tool. One command works for both flavors — GNU wget
  and busybox wget accept the same flags the script uses (`-q -Y off -T 2
  --no-check-certificate -O /dev/null`), so there is no flavor detection. `-Y off`
  is deliberate: the probe targets loopback, so a server-side `http(s)_proxy` env
  must never intercept it. It is a hard dependency because the script promises a
  verified link; a missing wget exits with an error before anything is served. On
  machines too old for curl but with a static dufs binary, wget is the option that
  is actually there.
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
- **TTL self-destruct, and what `--hold` actually does.** The file is served for a TTL
  window (default 60s, or `--ttl N`, N >= 1 with **no upper bound** — a truly
  permanent share needs systemd, which this tool does not pretend to be, so a big TTL
  — a day, a week — is the honest way to keep a link up for a while). After the TTL
  elapses, a detached steward kills only the dufs this script started and removes the
  temp dir, so the delivered file does not linger on the machine; the script returns
  to the shell immediately. `--hold` is orthogonal: it keeps the script in the
  foreground and prints an acme.sh-style single-line countdown (in-place `\r`
  updates, so the terminal is not spammed) ticking down the same TTL. `^C` runs the
  same cleanup (kill dufs + remove the temp dir + exit 130) and stops right away;
  when the countdown reaches zero the share ends by itself and the terminal is
  released. Both flags combine freely — `--ttl 3600 --hold` is a one-hour share with
  a foreground countdown. Nothing is persisted beyond the temp dir either way.
- **Emergency stop in detached (background) mode.** The script prints its link and
  returns to the shell; the share keeps running via a detached steward. To end it
  before the TTL, the script prints a red
  `important: if you wanna end sharing before ttl, try kill <dufs-pid>` line with
  the exact PID of the dufs it started — killing it drops the link and frees the
  port immediately (the temp dir is cleaned by the steward at TTL end, or with the
  next dufs/server restart). The PID is the whole handle: there is deliberately no
  pidfile or `stop` subcommand, since restarting dufs or the server clears any
  strays anyway.
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
  ~20s); if it never appears, the log tail is printed and the failure path cleans up
  (dufs + temp dir, with the tunnel reminder).
- **This script never kills cloudflared.** The quick tunnel is launched detached
  (`setsid`) on purpose — it is allowed to outlive config-delivery.sh, because the
  tunnel may keep serving other things. Cleanup (the TTL steward, `^C`, or a failure
  path) kills only the dufs this script started. In `--argo` mode every cleanup ends
  with a blue reminder: `argo quick tunnel may still be running — remove manually, or
  try: sudo systemctl restart cloudflared`.
- **TLS three states.** `--cert`/`--key` are optional, and there are three outcomes:
  1. **Real cert** — both paths are given and readable: dufs serves HTTPS with them
     end to end. Clients trust the cert directly (no `-k`).
  2. **Self-signed fallback** — only one is given, or either path is missing or
     unreadable: the script prints a warning and mints a fresh throwaway ECDSA
     cert instead of dying. Clients must use `wget --no-check-certificate`; a browser
     shows one click-through
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
- **Unified link verification**: before the link is printed, the **final URL** (the
  one the client will actually hit — http/https direct or the trycloudflare tunnel)
  is verified with a live `checking link in 3... 2... 1...` countdown, then up to 3
  wget probes for a successful download (wget is always `--no-check-certificate`
  because we verify the link answers, not that its cert is trusted; `-T 2` keeps
  each probe from hanging; ~2s between retries). The countdown also doubles as the
  argo edge warm-up window — a fresh trycloudflare URL is typically unreachable for
  its first ~1-2s (530, then 200), so the 3s countdown plus the 3 retries covers
  that. All 3 attempts failed → the error is reported and everything is cleaned up
  with exit 1, and no link is printed. This replaces the old loopback self-check: it
  probes the exact URL the client will use, so the check is as real as the delivery.
