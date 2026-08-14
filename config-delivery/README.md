# config-delivery — one-time file delivery over dufs

Thin wrapper that turns [dufs](https://github.com/sigoden/dufs) (static file server
with native TLS + streaming) into a **one-time** delivery tool: a random 8-char key
URL that auto-destructs after a TTL. Single shell script + one dufs binary — zero
other dependencies, no runtime on the target.

## Why dufs + wrapper (not a full custom tool)

- dufs is a mature, active (MIT, no known CVEs) wheel for the heavy lifting: TLS,
  streaming, directory serving, and prebuilt **musl static binaries** for both
  `x86_64` and `arm64` (no cross-compile, no runtime).
- The one-time semantics dufs lacks — random key URL + TTL auto-expiry — are a
  ~30-line wrapper. Vetted 9 candidates (rustypaste/miniserve/microbin/etc.):
  none ships one-time + N-download + 410 semantics AND the above; dufs is the
  closest fit, so we wrap the gap instead of building the wheel.

## Usage

```bash
# deploy (any Linux, x86_64 or arm64): dufs musl binary + this script
#   https://github.com/sigoden/dufs/releases → dufs-linux-{x86_64,aarch64}
#   put binary on PATH or set DUFS_BIN=/path/to/dufs

./config-delivery.sh serve ./config-client.json --port 443 --ttl 600 --host your.domain
#   → one-time download link: https://your.domain:443/<8-char-key>
#   --port  default 443 (1-65535; <1024 needs root; checked for availability first)
#   --ttl   auto-delete the file after N seconds (default 600; >= 1)
#   --host  host/IP shown in the link (default localhost; NEVER auto-probed)
#   --cert/--key  real PEM cert+key, must be given together; default fresh self-signed ECDSA
# client side — open the link in a browser (downloads with the given name), or:
curl -kOJ https://your.domain:443/<8-char-key>     # self-signed → -k
```

## Semantics

- **One-time**: the key URL is random (8 chars, `a-zA-Z0-9_-`); the file and the
  server process both disappear when the TTL expires (or when the process exits).
  Nothing is persisted beyond the served file in a temp dir.
- **Random key = the secret**: without it the URL is a 404; directory listing is
  hidden (`--hidden '*'`).
- **Guardrails** (all fail loud, exit 1): file must exist/readable (empty → warn),
  `--ttl` integer >= 1, `--port` integer 1-65535 and **pre-checked for availability**
  via `bash /dev/tcp` before dufs starts, `--cert`/`--key` must be given together,
  dufs binary present, dufs startup failure surfaced with its log.

## Env

- `DUFS_BIN` — path to the dufs binary (default: `dufs` on PATH)

## Architecture notes

- `--host` is user-supplied only — the script **never probes the local IP**
  (matches gen-client.sh's `--server` policy). Default link host is `localhost`.
- Port pre-check uses pure-bash `/dev/tcp` (no nc dependency) and only touches
  loopback — it checks availability, it does not probe anything external.

## History

- `archived/otd/otd.py` — original Python version (python + aioquic deps), superseded.
- `archived/config-delivery-go/` — Go prototype (pure stdlib single binary), superseded
  when the wheel audit showed dufs + a thin wrapper is smaller to maintain.

## Maintenance checklist (before touching)

1. Bump/verify dufs version (release page; check CVEs before adopting newer).
2. `bash -n config-delivery.sh && shellcheck config-delivery.sh` — zero errors.
3. Manual test matrix: download 200 + md5 match, wrong key 404, dir listing hidden,
   TTL expiry kills the server, occupied port caught, `--cert` without `--key` refused.
