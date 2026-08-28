# config-delivery.py — stdlib file delivery (single-file | multi-file)

Python 1:1 port of `config-delivery.sh`.

## Why a Python port?

- **Zero deps** — stdlib only (`http.server` + `ssl`, HTTP/1.1). No dufs, no wget, no compiled binaries to ship. Works on any box with a Python 3.8+ interpreter.
- **Smaller footprint** — single `config-delivery.py` file, no per-arch musl binaries.
- **Behavioral twin** — every flag (`--port/--ttl/--hold/--host/--v4/--v6/--cert/--key/--argo`) has **identical meaning to the bash version**; only the implementation differs.

> TLS states intentionally differ: the bash version has a three-state TLS path
> (real cert / self-signed fallback / plain HTTP); the Python version has only two
> states — readable `--cert` + `--key` → HTTPS, everything else → plain HTTP with a
> warning. The link check is `urllib.request.urlopen` (system CA only), so
> self-signed fallback is not attempted here.

## Requirements

- `python3` (3.8+, `import ssl` available)
- `openssl` — only for the integer check and for `?k=` generation (`CD_ENC_KEY`
  env or `openssl rand -hex 32` fallback); not otherwise required.

## Usage

Flags mirror `config-delivery.sh` one-for-one; `FILE` may be a single file **or
a directory** (any file types, streamed):

```bash
# Single file
python3 config-delivery.py serve ./config-client.json --host your.domain
python3 config-delivery.py serve ./config-client.json --argo
python3 config-delivery.py serve ./config-client.json --host your.domain --v4
python3 config-delivery.py serve ./config-client.json --cert server.crt --key server.key

# Multi-file directory (any types)
python3 config-delivery.py serve ./out/ --host your.domain --ttl 360
```

| Flag | Meaning |
|---|---|
| `--port N` | Listen port (default 443, 1–65535, <1024 needs root). Ignored in `--argo` mode, where the backend binds a random loopback port. |
| `--ttl SEC` | Auto-delete after `SEC` seconds (default 60, no upper bound). Combines freely with `--hold`. |
| `--hold` | Foreground mode — single-line countdown (`\r` in-place). `Ctrl+C` exits immediately, TTL expiry exits by itself. |
| `--host NAME` | Host in the link (IP bracketed, domain dual-stack); never auto-probed. Disabled in `--argo`. |
| `--v4` | With `--host DOMAIN`, force-resolve to IPv4. Mutually exclusive with `--v6`. Disabled in `--argo`. |
| `--v6` | With `--host DOMAIN`, force-resolve to IPv6. Mutually exclusive with `--v4`. Disabled in `--argo`. |
| `--cert/--key FILE` | PEM pair → HTTPS when both readable; otherwise plain HTTP with a warning. Disabled in `--argo`. |
| `--argo` | Cloudflared quick tunnel (`https://<rand>.trycloudflare.com/<key>?k=<64hex>`), backend loopback HTTP. Disables `--host/--v4/--v6/--cert/--key`. |
| `FILE` | File or directory to deliver — single file or multi-file (any types). |

`FILE` is any file **or directory**; the link carries an independent `?k=<64hex>` (`openssl rand -hex 32` via `CD_ENC_KEY` env or fallback), decoupled from the path key.

When `FILE` is a directory:

```
GET /<key>/            → JSON array of filenames, e.g. ["a.json","b.out"]
GET /<key>/<filename>  → application/octet-stream, streamed in 64 KiB chunks
GET /<key>              → 404 (directory requires trailing slash)
```

All traffic under `GET /<key>/` is gated by the 8-char path key; `?k=` is informational and stripped before routing.

## Security model

- `?k=<64hex>` in the printed link is **not** enforced on GET — it is the documented client-side hint for decrypting payloads encrypted outside this server (e.g. `openssl enc -aes-256-ctr`); leaking the link still requires the path key, but treat `?k=` as public.
- Probes use `urllib.request` with `ProxyHandler({})` (direct loopback, equivalent to `wget -Y off`) and `_probe_allowed` hardens SSRF (only `http/https`, allowlist `localhost/*.trycloudflare.com`, otherwise `getaddrinfo` + `ipaddress` blocks `link_local`/metadata).
- Credentials only via `CD_ENC_KEY` env or local `openssl`; source, examples, and tests never contain usable credential literals.

## Rhythm

1. `--host` + `--port` & loopback port check
2. Payload: file → memory (`f.read()`); directory → disk-backed (`serve_dir`), pre-flight empty-dir warning
3. TLS material (real cert only when both readable)
4. Argo: quick-tunnel poll up to ~20s (regex anchored on `≥2` hyphen-words to skip `api.trycloudflare.com`)
5. Print `one-time download link:` + 3-step `checking link in 3..1` countdown (doubles as edge warm-up) → up to 3 probes with `timeout 2` and `sleep 2`
6. `--hold` foreground single-line countdown `\r` or detached: `file auto-deletes after <TTL>s` + red `kill <pid>` handle; `SIGINT→130` via `signal.signal`

## Deliverables

- Exactly one artifact to update: `config-delivery.py` (plus this doc and `config-delivery.sh` for 1:1 parity).

## Direct vs. argo verification

- Direct (`--host`): loopback probe via `ProxyHandler({})` (no proxy) — `wget -Y off` parity; multi-file `GET /<key>/ → ["a.json"]` + per-file `GET /<key>/a.json` — all `200`, including with `?k=` stripped.
- Argo (`--argo`): same shape behind `https://<rand>.trycloudflare.com/<key>/`; verification via the printed public URL shows `530` during the first ~1–2s edge warm-up (the 3s countdown covers it), then `200` over `http://127.0.0.1:2080` proxy. Probe via `https_proxy=http://127.0.0.1:2080 curl`.
