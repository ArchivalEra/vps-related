#!/usr/bin/env bash
# config-delivery.sh — one-time file delivery over dufs (thin wrapper, zero deps)
#
# dufs (https://github.com/sigoden/dufs) provides the heavy lifting: static file
# serving, native TLS, streaming, cross-compiled musl binaries (x86_64 + arm64).
# This wrapper adds what dufs lacks: a random key URL + TTL auto-expiry, so a file
# is effectively one-time without any state. Nothing persisted beyond the served file.
#
# Usage:
#   config-delivery.sh serve <file> [--port N] [--ttl SEC] [--host HOST] [--cert C] [--key K]
#     --port  default 443
#     --ttl   auto-delete the file after N seconds (default 600)
#     --host  host/IP shown in the link (default localhost)
#     --cert/--key  real PEM cert+key; default: fresh self-signed ECDSA (clients use -k)
#
# Env: DUFS_BIN (path to dufs binary; default: dufs in PATH)

set -uo pipefail

DUFS_BIN="${DUFS_BIN:-dufs}"
command -v "$DUFS_BIN" >/dev/null 2>&1 || { echo "error: dufs binary not found (set DUFS_BIN or add to PATH)"; exit 1; }

PORT=443
TTL=600
HOST=""
CERT=""
KEY=""
FILE=""

args=("$@")
i=0
while [[ $i -lt ${#args[@]} ]]; do
  a="${args[$i]}"
  case "$a" in
    --port) PORT="${args[$((i+1))]}"; i=$((i+2)) ;;
    --ttl)  TTL="${args[$((i+1))]}";  i=$((i+2)) ;;
    --host) HOST="${args[$((i+1))]}"; i=$((i+2)) ;;
    --cert) CERT="${args[$((i+1))]}"; i=$((i+2)) ;;
    --key)  KEY="${args[$((i+1))]}";  i=$((i+2)) ;;
    *)      FILE="$a"; i=$((i+1)) ;;
  esac
done

[[ -n "$FILE" && -f "$FILE" && -r "$FILE" ]] || { echo "error: file not readable: ${FILE:-<none>}"; exit 1; }
[[ "$TTL" =~ ^[0-9]+$ && "$TTL" -ge 1 ]] || { echo "error: --ttl must be >= 1"; exit 1; }

# ---- random 8-char key (same alphabet as before: a-zA-Z0-9_-) ----
KEYSTR=""
while [[ ${#KEYSTR} -lt 8 ]]; do
  KEYSTR+="$(printf '%s' "$(openssl rand -base64 9 | tr -dc 'A-Za-z0-9_-')")"
done
KEYSTR="${KEYSTR:0:8}"

# ---- serve dir + file placement (key = URL) ----
SRV_DIR="$(mktemp -d)"
cleanup() { rm -rf "$SRV_DIR"; }
trap cleanup EXIT
cp "$FILE" "$SRV_DIR/$KEYSTR"

# ---- TLS: real cert or fresh self-signed ECDSA ----
if [[ -n "$CERT" && -n "$KEY" ]]; then
  [[ -r "$CERT" && -r "$KEY" ]] || { echo "error: cert/key not readable"; exit 1; }
else
  CERT="$SRV_DIR/cert.pem"; KEY="$SRV_DIR/key.pem"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$KEY" -out "$CERT" -days 1 -subj "/CN=config-delivery" >/dev/null 2>&1
fi

"$DUFS_BIN" "$SRV_DIR" -A --tls-cert "$CERT" --tls-key "$KEY" --port "$PORT" --hidden '*' \
  >"$SRV_DIR/dufs.log" 2>&1 &
DUFS_PID=$!
trap 'kill $DUFS_PID 2>/dev/null; rm -rf "$SRV_DIR"' EXIT
sleep 0.5
kill -0 "$DUFS_PID" 2>/dev/null || { echo "error: dufs failed to start:"; cat "$SRV_DIR/dufs.log"; exit 1; }

SH="${HOST:-localhost}"
echo "one-time download link: https://$SH:$PORT/$KEYSTR"
echo "file auto-deletes after ${TTL}s (or when dufs exits); dir listing hidden"
echo "client: curl -kOJ https://$SH:$PORT/$KEYSTR"

# ---- TTL auto-expiry (one-time semantics: file vanishes after the window) ----
( sleep "$TTL"; kill "$DUFS_PID" 2>/dev/null ) &
TTL_PID=$!
trap 'kill $DUFS_PID $TTL_PID 2>/dev/null; rm -rf "$SRV_DIR"' EXIT

wait "$DUFS_PID" 2>/dev/null
kill "$TTL_PID" 2>/dev/null
rm -rf "$SRV_DIR"
