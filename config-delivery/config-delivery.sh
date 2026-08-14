#!/usr/bin/env bash
# config-delivery.sh — one-time file delivery over dufs (thin wrapper, zero deps)
#
# dufs (https://github.com/sigoden/dufs) provides the heavy lifting: static file
# serving, native TLS, streaming, cross-compiled musl binaries (x86_64 + arm64).
# This wrapper adds what dufs lacks: a random key URL + TTL auto-expiry.
#
# Guardrails:
#   --port validated (1-65535) and pre-checked for availability before dufs starts
#   --cert/--key must be given together (else refused); missing cert → self-signed
#   file must exist and be readable; empty file warns
#   --host is USER-SUPPLIED only — this script NEVER probes the local IP
#   (connect host shown in the link; default localhost)
#
# Usage:
#   config-delivery.sh serve <file> [--port N] [--ttl SEC] [--host HOST] [--cert C] [--key K]
#     --port  default 443 (1-65535; <1024 needs root)
#     --ttl   auto-delete the file after N seconds (default 600)
#     --host  host/IP shown in the link (default localhost; never auto-probed)
#     --cert/--key  real PEM cert+key (default: fresh self-signed ECDSA, clients use -k)
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

# ---------- Port pre-check (bash /dev/tcp, zero-dep; no IP probing — loopback only) ----------
if (echo > /dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
  echo "error: port $PORT already in use — pick another with --port (or free the port)"
  exit 1
fi

# ---------- Random 8-char key (a-zA-Z0-9_-) ----------
KEYSTR=""
while [[ ${#KEYSTR} -lt 8 ]]; do
  KEYSTR+="$(printf '%s' "$(openssl rand -base64 9 | tr -dc 'A-Za-z0-9_-')")"
done
KEYSTR="${KEYSTR:0:8}"

# ---------- Serve dir + file placement (key = URL) ----------
SRV_DIR="$(mktemp -d)"
cleanup() { rm -rf "$SRV_DIR"; }
trap cleanup EXIT
cp "$FILE" "$SRV_DIR/$KEYSTR"

# ---------- TLS: real cert (paired, validated above) or fresh self-signed ECDSA ----------
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
sleep 0.5
kill -0 "$DUFS_PID" 2>/dev/null || { echo "error: dufs failed to start:"; cat "$SRV_DIR/dufs.log"; exit 1; }

SH="${HOST:-localhost}"
echo "one-time download link: https://$SH:$PORT/$KEYSTR"
echo "file auto-deletes after ${TTL}s; dir listing hidden; host is user-supplied (never auto-probed)"
echo "client: curl -kOJ https://$SH:$PORT/$KEYSTR"

# ---------- TTL auto-expiry (one-time semantics: file/service vanish after the window) ----------
( sleep "$TTL"; kill "$DUFS_PID" 2>/dev/null ) &
TTL_PID=$!
trap 'kill $DUFS_PID $TTL_PID 2>/dev/null; rm -rf "$SRV_DIR"' EXIT

wait "$DUFS_PID" 2>/dev/null
kill "$TTL_PID" 2>/dev/null
rm -rf "$SRV_DIR"
