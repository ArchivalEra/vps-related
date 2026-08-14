#!/usr/bin/env bash
# gen-server.sh — generate server config.json (fresh credentials, single output, zero persistence)
#
# Usage:
#   bash gen-server.sh [--domain D] [--reality-sni S] [--cert P] [--key P] [--outputname NAME] [--outputpath DIR] [--debug] [--test]
#
# Output: ONE server sing-box config.json with 6 inbounds:
#   reality (VLESS+Reality, TCP 443) / hy2 (Hysteria2, UDP 443) / vless-ws (TCP 8443) /
#   vless-grpc (TCP 8444) / anytls (TCP 8445) / ss2022 (Shadowsocks 2022, TCP 8388, no TLS)
#
# Philosophy: credentials are generated fresh on every run and embedded in the output.
#   Nothing persisted — no secrets.env, no intermediate file. Re-run to rotate everything.
#   Compatible with gen-client.sh (server config.json → client config.json, single input).
#
# Args:
#   --domain D      SNI for ws/grpc (and connect address for clients); default prompts interactively
#   --reality-sni S reality handshake server SNI (default www.microsoft.com)
#   --cert P        TLS certificate path (default /etc/ssl/moons.de5.net/cert.pem)
#   --key P         TLS private key path   (default /etc/ssl/moons.de5.net/key.pem)
#   --outputname N  output filename (default config-server.json; filename only, no path)
#   --outputpath D  output directory (default: this script's own dir)
#   --debug         diagnostic output (fully silent by default)
#   --test          self-check: generate to temp dir, sing-box check, exit
#
# Env: SB_OUTPUT (full output path override) / SB_BIN / DEBUG
# Exit codes: 0=ok  1=argument/dependency  2=sing-box check failure

set -uo pipefail

# ---------- Defaults ----------
OUTPUT_NAME_DEFAULT="config-server.json"
OUTPUT_NAME=""
OUTPUT_PATH=""
DOMAIN=""
REALITY_SNI="www.microsoft.com"
CERT_FILE="/etc/ssl/moons.de5.net/cert.pem"
KEY_FILE="/etc/ssl/moons.de5.net/key.pem"
TEST_MODE=0
DEBUG="${DEBUG:-0}"

# ---------- Parse args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) shift; DOMAIN="${1:-}" ;;
    --reality-sni) shift; REALITY_SNI="${1:-}" ;;
    --cert) shift; CERT_FILE="${1:-}" ;;
    --key) shift; KEY_FILE="${1:-}" ;;
    --outputname) shift; OUTPUT_NAME="${1:-}" ;;
    --outputpath) shift; OUTPUT_PATH="${1:-}" ;;
    --debug) DEBUG=1 ;;
    --test) TEST_MODE=1 ;;
    *) die1 "unknown argument: $1 (supported: --domain / --reality-sni / --cert / --key / --outputname / --outputpath / --debug / --test)" ;;
  esac
  shift
done

# ---------- Source secrets library ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/secrets.lib.sh"

# ---------- sing-box binary (for generate + check) ----------
SB_BIN="${SB_BIN:-}"
if [[ -z "$SB_BIN" ]]; then
  SB_BIN="$(command -v sing-box 2>/dev/null || echo "$SCRIPT_DIR/../test-env/bin/sing-box")"
fi
[[ -x "$SB_BIN" ]] || die1 "sing-box binary not found (set SB_BIN or add sing-box to PATH)"

# ---------- --test: self-check then exit ----------
if [[ $TEST_MODE -eq 1 ]]; then
  ok "== running gen-server.sh self-check =="
  local_tmp="$(mktemp -d)"
  trap 'rm -rf "$local_tmp"' EXIT
  # test with the repo's self-signed cert so --test works on any machine
  local_cert="$SCRIPT_DIR/../test-env/server/hy2.crt"
  local_key="$SCRIPT_DIR/../test-env/server/hy2.key"
  if [[ -f "$local_cert" && -f "$local_key" ]]; then
    CERT_FILE="$local_cert"; KEY_FILE="$local_key"
  fi
  # generate into temp, then sing-box check
  if ! "bash" "$0" --domain 127.0.0.1 --cert "$CERT_FILE" --key "$KEY_FILE" \
      --outputpath "$local_tmp" --outputname config-server.json >/dev/null 2>&1; then
    err "self-check: generation failed"; exit 1
  fi
  if timeout 15 "$SB_BIN" check -c "$local_tmp/config-server.json" 2>"$local_tmp/check.err"; then
    ok "self-check: generated + passed sing-box check"
    exit 0
  else
    err "self-check: sing-box check failed:"; cat "$local_tmp/check.err" >&2
    exit 2
  fi
fi

# ---------- Domain (interactive or --domain; never probed) ----------
if [[ -z "$DOMAIN" ]]; then
  read -r -p "Enter domain (SNI for ws/grpc, connect address for clients): " DOMAIN
  [[ -n "$DOMAIN" ]] || die1 "must provide domain (--domain arg or interactive input)"
fi

# ---------- Output path resolution (same tiers as gen-client.sh) ----------
if [[ -z "${SB_OUTPUT:-}" ]]; then
  if [[ -n "$OUTPUT_NAME" && -n "$OUTPUT_PATH" ]]; then
    SB_OUTPUT="$OUTPUT_PATH/$OUTPUT_NAME"
  elif [[ -n "$OUTPUT_NAME" ]]; then
    SB_OUTPUT="$SCRIPT_DIR/$OUTPUT_NAME"
  elif [[ -n "$OUTPUT_PATH" ]]; then
    SB_OUTPUT="$OUTPUT_PATH/$OUTPUT_NAME_DEFAULT"
  else
    SB_OUTPUT="$SCRIPT_DIR/$OUTPUT_NAME_DEFAULT"
  fi
fi
if [[ "$OUTPUT_NAME" == */* ]]; then
  die1 "outputname must be a plain filename (no path): $OUTPUT_NAME"
fi
if [[ -e "$SB_OUTPUT" ]]; then
  die1 "refusing to overwrite existing file: $SB_OUTPUT (delete it first, then re-run)"
fi
debug "output target: $SB_OUTPUT"

# ---------- Credentials (fresh every run) ----------
UUID="$(gen_uuid)" || die1 "failed to generate uuid"
KP="$(gen_reality_keypair)" || die1 "failed to generate reality keypair"
PRIV="${KP%% *}"; PUB="${KP#* }"
SID="$(gen_short_id)"
HY2_PASS="$(gen_hex_pass)"
ANYTLS_PASS="$(gen_hex_pass)"
SS_PASS="$(gen_ss_pass)"
debug "domain=$DOMAIN reality_sni=$REALITY_SNI cert=$CERT_FILE"

# ---------- Render server config.json ----------
if ! mkdir -p "$(dirname "$SB_OUTPUT")" 2>/dev/null; then
  die1 "cannot write output dir (permission?): $(dirname "$SB_OUTPUT") (add --debug for details)"
fi
if ! cat > "$SB_OUTPUT" <<JSON
{
  "log": { "level": "warn" },
  "dns": { "servers": [ { "type": "local", "tag": "local" } ] },
  "inbounds": [
    { "type": "vless", "listen": "::", "listen_port": 443,
      "users": [ { "uuid": "$UUID", "flow": "xtls-rprx-vision" } ],
      "tls": { "enabled": true, "server_name": "$REALITY_SNI",
        "reality": { "enabled": true, "handshake": { "server": "$REALITY_SNI", "server_port": 443 },
          "private_key": "$PRIV", "short_id": ["$SID"] } } },
    { "type": "hysteria2", "listen": "::", "listen_port": 443,
      "users": [ { "password": "$HY2_PASS" } ],
      "tls": { "enabled": true, "certificate_path": "$CERT_FILE", "key_path": "$KEY_FILE" } },
    { "type": "vless", "listen": "::", "listen_port": 8443,
      "users": [ { "uuid": "$UUID" } ],
      "tls": { "enabled": true, "server_name": "$DOMAIN", "certificate_path": "$CERT_FILE", "key_path": "$KEY_FILE" },
      "transport": { "type": "ws", "path": "/ws" } },
    { "type": "vless", "listen": "::", "listen_port": 8444,
      "users": [ { "uuid": "$UUID" } ],
      "tls": { "enabled": true, "server_name": "$DOMAIN", "certificate_path": "$CERT_FILE", "key_path": "$KEY_FILE" },
      "transport": { "type": "grpc", "service_name": "grpc" } },
    { "type": "anytls", "listen": "::", "listen_port": 8445,
      "users": [ { "password": "$ANYTLS_PASS" } ],
      "tls": { "enabled": true, "certificate_path": "$CERT_FILE", "key_path": "$KEY_FILE" } },
    { "type": "shadowsocks", "tag": "ss2022-in", "listen": "::", "listen_port": 8388,
      "method": "2022-blake3-aes-256-gcm", "password": "$SS_PASS" }
  ],
  "outbounds": [ { "type": "direct" } ],
  "route": { "default_domain_resolver": { "server": "local" } }
}
JSON
then
  die1 "cannot write output file (permission?): $SB_OUTPUT (add --debug for details)"
fi

# ---------- sing-box check (net: config must be valid before we claim success) ----------
if timeout 15 "$SB_BIN" check -c "$SB_OUTPUT" 2>"$SCRIPT_DIR/.gen-server-check.err"; then
  rm -f "$SCRIPT_DIR/.gen-server-check.err"
  ok "generated and passed sing-box check: $SB_OUTPUT"
else
  err "config check failed:"; cat "$SCRIPT_DIR/.gen-server-check.err" >&2
  rm -f "$SCRIPT_DIR/.gen-server-check.err"
  exit 2
fi

ok "server config: $SB_OUTPUT (6 inbounds: reality 443/TCP, hy2 443/UDP, ws 8443, grpc 8444, anytls 8445, ss2022 8388)"
ok "credentials embedded (fresh each run, nothing persisted). Reality public key: $PUB"
ok "clients: bash gen-client.sh --from-server $SB_OUTPUT --server $DOMAIN"
