#!/usr/bin/env bash
# config-delivery.sh — one-time file delivery over dufs (thin wrapper, zero deps)
#
# dufs (https://github.com/sigoden/dufs) does the heavy lifting — static file
# serving, native TLS, streaming — as a single static musl binary (x86_64 + arm64).
# We wrap it instead of writing our own server because dufs already owns all the
# hard parts; the wrapper only adds the one-time semantics dufs lacks: a random
# key URL that auto-destructs after a TTL.
#
# Key decisions, and why:
#   - Random 8-char key URL: the key IS the secret. A path without it is a 404 and
#     the directory listing is hidden, so the link is effectively private and
#     one-time without any auth setup.
#   - TTL auto-expiry: after N seconds the server process is killed and the temp
#     dir removed, so the delivered file does not linger on the machine.
#   - Port pre-check via bash /dev/tcp: pure-bash (no nc dependency) and loopback
#     only — it checks availability, it never probes anything external.
#   - --host is user-supplied only, never auto-probed: the script cannot know which
#     host/IP the client can actually reach (public IP, NAT, DNS, interfaces). The
#     operator knows; we just print the link with the host they give.
#
# Usage: config-delivery.sh [serve] <file> [--port N] [--ttl SEC] [--host HOST]
#                           [--cert FILE] [--key FILE]   (details: --help)
# Env: DUFS_BIN (path to dufs binary; default: dufs on PATH)

set -uo pipefail

# No arguments at all → point at --help instead of failing later with a mystery.
if [[ $# -eq 0 ]]; then
  echo "try config-delivery.sh --help"
  exit 1
fi

PORT=443
TTL=600
HOST=""
RESOLVE=""
CERT=""
KEY=""
FILE=""

print_help() {
  cat <<'HELP'
##help##
  --port N        listen port (default 443, 1-65535, <1024 needs root)
  --ttl SEC       auto-delete the file after N seconds (default 600, >= 1)
  --host HOST     host/IP shown in the link (default localhost, never auto-probed)
  --resolve NAME  resolve NAME to an IP and build the link with that IP — the link
                  then carries no domain SNI to sniff (mutually exclusive with --host)
  --cert FILE     PEM certificate; must be paired with --key (default: self-signed ECDSA)
  --key FILE      PEM private key; must be paired with --cert
  FILE            file to deliver (positional, e.g. serve ./config-client.json)
##help##
HELP
}

args=("$@")
i=0
while [[ $i -lt ${#args[@]} ]]; do
  a="${args[$i]}"
  case "$a" in
    --help) print_help; exit 0 ;;
    --port) PORT="${args[$((i+1))]}"; i=$((i+2)) ;;
    --ttl)  TTL="${args[$((i+1))]}";  i=$((i+2)) ;;
    --host) HOST="${args[$((i+1))]}"; i=$((i+2)) ;;
    --resolve) RESOLVE="${args[$((i+1))]}"; i=$((i+2)) ;;
    --cert) CERT="${args[$((i+1))]}"; i=$((i+2)) ;;
    --key)  KEY="${args[$((i+1))]}";  i=$((i+2)) ;;
    *)      FILE="$a"; i=$((i+1)) ;;
  esac
done

# dufs is the only runtime this script needs; if it is missing, print the full
# install guide instead of a one-line dead end. Version note: v0.46.0 below is the
# pinned default — swap in the latest release number from the dufs releases page.
DUFS_BIN="${DUFS_BIN:-dufs}"
if ! command -v "$DUFS_BIN" >/dev/null 2>&1; then
  echo "error: dufs binary not found (looked for: $DUFS_BIN)"
  case "$(uname -m)" in
    x86_64)  DUF_TARGET="x86_64-unknown-linux-musl" ;;
    aarch64) DUF_TARGET="aarch64-unknown-linux-musl" ;;
    *)
      echo "error: unsupported architecture: $(uname -m)"
      echo "dufs publishes prebuilt musl binaries for x86_64 and aarch64 only;"
      echo "build from source (cargo install dufs) or run this on a supported machine."
      exit 1
      ;;
  esac
  echo "install dufs for your arch: $(uname -m) -> $DUF_TARGET"
  echo
  echo "  1. Download (v0.46.0 — replace with the latest from"
  echo "     https://github.com/sigoden/dufs/releases if you prefer):"
  echo "     curl -fL -o /tmp/dufs.tar.gz https://github.com/sigoden/dufs/releases/download/v0.46.0/dufs-v0.46.0-$DUF_TARGET.tar.gz"
  echo "  2. Extract the dufs binary into /usr/local/bin:"
  echo "     tar -xzf /tmp/dufs.tar.gz -C /usr/local/bin"
  echo "  3. Verify:"
  echo "     dufs --version"
  echo "  4. Re-run this script."
  exit 1
fi

# ---------- Input guards ----------
[[ -n "$FILE" && -f "$FILE" && -r "$FILE" ]] || { echo "error: file not readable: ${FILE:-<none>}"; exit 1; }
[[ -s "$FILE" ]] || echo "warning: file is empty: $FILE"
[[ "$TTL" =~ ^[0-9]+$ && "$TTL" -ge 1 ]] || { echo "error: --ttl must be an integer >= 1 (got: ${TTL:-<none>})"; exit 1; }
[[ "$TTL" -gt 3600 ]] && echo "warning: TTL ${TTL}s is long — the link stays live until then"
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 1 && "$PORT" -le 65535 ]] || { echo "error: --port must be an integer 1-65535 (got: ${PORT:-<none>})"; exit 1; }
[[ "$PORT" -lt 1024 ]] && echo "note: port $PORT < 1024 — dufs may need root to bind"
if [[ -n "$CERT" || -n "$KEY" ]]; then
  [[ -n "$CERT" && -n "$KEY" ]] || { echo "error: --cert and --key must be given together (or neither)"; exit 1; }
  [[ -r "$CERT" && -r "$KEY" ]] || { echo "error: cert/key not readable"; exit 1; }
fi
# --resolve and --host are two ways to pick the link host — refusing both at once
# keeps the tool unambiguous (never guess which one the caller meant).
if [[ -n "$RESOLVE" && -n "$HOST" ]]; then
  echo "error: --resolve and --host are mutually exclusive — pick one"
  exit 1
fi
# --resolve: turn the user's domain into an IP (getent is glibc, no new deps) so the
# link carries an IP instead of a sniffable domain SNI. v6 links need [brackets].
# Prefer IPv4, fall back to IPv6: a v4-less host still gets a working link, and a
# v6-only client can still use the v6 result if that is all the host has.
if [[ -n "$RESOLVE" ]]; then
  RESOLVED_IP="$(getent ahosts "$RESOLVE" 2>/dev/null | awk '!seen[$1]++ { if ($1 !~ /:/) print $1 }' | head -1)"
  [[ -z "$RESOLVED_IP" ]] && RESOLVED_IP="$(getent ahosts "$RESOLVE" 2>/dev/null | awk '!seen[$1]++ { print $1 }' | head -1)"
  [[ -n "$RESOLVED_IP" ]] || { echo "error: cannot resolve $RESOLVE (getent ahosts)"; exit 1; }
  HOST="$RESOLVED_IP"
  [[ "$HOST" == *:* ]] && HOST="[$HOST]"   # IPv6 → [2001:db8::1]
  echo "resolved $RESOLVE → $HOST"
fi

# Port pre-check via bash /dev/tcp — pure-bash (no nc), loopback only, so it checks
# availability without probing anything on the network.
if (echo > /dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
  echo "error: port $PORT already in use — pick another with --port (or free the port)"
  exit 1
fi

# Random 8-char key (a-zA-Z0-9_-) — the key IS the secret, see header. Using the key
# as the filename means the URL path itself carries the access control.
KEYSTR=""
while [[ ${#KEYSTR} -lt 8 ]]; do
  KEYSTR+="$(printf '%s' "$(openssl rand -base64 9 | tr -dc 'A-Za-z0-9_-')")"
done
KEYSTR="${KEYSTR:0:8}"

# Serve from a throwaway temp dir so nothing is persisted on disk past the TTL
# window; the trap removes it on every exit path (incl. SIGTERM'ed dufs).
SRV_DIR="$(mktemp -d)"
cleanup() { rm -rf "$SRV_DIR"; }
trap cleanup EXIT
cp "$FILE" "$SRV_DIR/$KEYSTR"

# TLS: use the caller's cert/key when both are given (paired + validated above),
# else mint a fresh self-signed ECDSA one — dufs requires a cert for HTTPS and a
# throwaway self-signed cert keeps delivery zero-config (clients just add -k).
if [[ -n "$CERT" && -n "$KEY" ]]; then
  :
else
  CERT="$SRV_DIR/cert.pem"; KEY="$SRV_DIR/key.pem"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$KEY" -out "$CERT" -days 1 -subj "/CN=config-delivery" >/dev/null 2>&1
fi

"$DUFS_BIN" "$SRV_DIR" -A --tls-cert "$CERT" --tls-key "$KEY" --port "$PORT" --hidden '*' \
  >"$SRV_DIR/dufs.log" 2>&1 &
DUFS_PID=$!
trap 'kill $DUFS_PID 2>/dev/null; rm -rf "$SRV_DIR"' EXIT
# Startup self-check: the process being alive is not enough (dufs can survive a
# failed bind for a moment) — the link is only printed once the port actually
# answers. Loopback /dev/tcp, same zero-dep style as the port pre-check.
UP=0
for _ in 1 2 3 4 5; do
  if (echo > /dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then UP=1; break; fi
  sleep 0.3
done
if [[ $UP -eq 0 ]] || ! kill -0 "$DUFS_PID" 2>/dev/null; then
  echo "error: dufs failed to start on port $PORT:" >&2
  cat "$SRV_DIR/dufs.log" >&2
  exit 1
fi

SH="${HOST:-localhost}"
echo "one-time download link: https://$SH:$PORT/$KEYSTR"
echo "file auto-deletes after ${TTL}s; dir listing hidden; host is user-supplied (never auto-probed)"
echo "client: curl -kOJ https://$SH:$PORT/$KEYSTR"
# TTL auto-expiry: kill the server after the window so the file and the process
# both vanish — that is what makes the link one-time, not best-effort.
( sleep "$TTL"; kill "$DUFS_PID" 2>/dev/null ) &
TTL_PID=$!
trap 'kill $DUFS_PID $TTL_PID 2>/dev/null; rm -rf "$SRV_DIR"' EXIT

wait "$DUFS_PID" 2>/dev/null
kill "$TTL_PID" 2>/dev/null
rm -rf "$SRV_DIR"
