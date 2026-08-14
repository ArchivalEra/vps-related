#!/usr/bin/env bash
# gen-server.sh — generate server config.json (fresh credentials, single output, zero persistence)
#
# Usage:
#   bash gen-server.sh [--domain D] [--reality-sni S] [--certpath P] [--keypath P] [--outputname NAME] [--outputpath DIR] [--debug] [--test]
#
# Output: ONE server sing-box config.json with 6 inbounds:
#   reality (VLESS+Reality, TCP 443) / hy2 (Hysteria2, UDP 443) / vless-ws (TCP 8443) /
#   vless-grpc (TCP 8444) / anytls (TCP 8445) / ss2022 (Shadowsocks 2022, TCP 8388, no TLS)
#
# Philosophy: credentials are generated fresh on every run and embedded in the output.
#   Nothing persisted — no env file, no intermediate state. Re-run to rotate everything.
#   Compatible with gen-client.sh (server config.json → client config.json, single input).
#   Overwrite protection: refuses to clobber an existing output file (delete first, or pick a new name).
#
# Args:
#   --domain D       SNI for ws/grpc (and connect address for clients); default prompts interactively
#   --reality-sni S  reality handshake server SNI (default www.microsoft.com)
#   --certpath P     TLS certificate path (default /your/cert/at/here — pass --certpath to set real path)
#   --keypath P      TLS private key path   (default /your/key/at/here — pass --keypath to set real path)
#   --outputname N   output filename (default config-server.json; filename only, no path)
#   --outputpath D   output directory (default: this script's own dir)
#   --debug          diagnostic output (fully silent by default)
#   --test           self-check: generate to temp dir, sing-box check, exit
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
CERT_FILE="/your/cert/at/here"
KEY_FILE="/your/key/at/here"
TEST_MODE=0
DEBUG="${DEBUG:-0}"

# ---------- Parse args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) shift; DOMAIN="${1:-}" ;;
    --reality-sni) shift; REALITY_SNI="${1:-}" ;;
    --certpath) shift; CERT_FILE="${1:-}" ;;
    --keypath) shift; KEY_FILE="${1:-}" ;;
    --outputname) shift; OUTPUT_NAME="${1:-}" ;;
    --outputpath) shift; OUTPUT_PATH="${1:-}" ;;
    --debug) DEBUG=1 ;;
    --test) TEST_MODE=1 ;;
    *) die1 "unknown argument: $1 (supported: --domain / --reality-sni / --certpath / --keypath / --outputname / --outputpath / --debug / --test)" ;;
  esac
  shift
done

# ---------- Source secrets library (which sources common.lib.sh) ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/secrets.lib.sh"

# ---------- Temp dir (isolates check stderr; zero residue on exit) ----------
TMPD="$(mktemp -d)" || die1 "cannot create temp dir"
trap 'rm -rf "$TMPD"' EXIT
debug "temp dir: $TMPD"

# ---------- sing-box binary (for generate + check) ----------
SB_BIN="${SB_BIN:-}"
if [[ -z "$SB_BIN" ]]; then
  SB_BIN="$(command -v sing-box 2>/dev/null || echo "$SCRIPT_DIR/../test-env/bin/sing-box")"
fi
[[ -x "$SB_BIN" ]] || die1 "sing-box binary not found (set SB_BIN or add sing-box to PATH)"

# ---------- Render server config (fresh credentials embedded) ----------
# $1=cert path  $2=key path  $3=output file  (domain/reality_sni from globals)
render_config() {
  local cert="$1" key="$2" out="$3"
  local uuid kp priv pub sid hy2_pass anytls_pass ss_pass
  uuid="$(gen_uuid)" || die1 "failed to generate uuid"
  kp="$(gen_reality_keypair)" || die1 "failed to generate reality keypair"
  priv="${kp%% *}"; pub="${kp#* }"
  sid="$(gen_short_id)"
  hy2_pass="$(gen_hex_pass)"
  anytls_pass="$(gen_hex_pass)"
  ss_pass="$(gen_ss_pass)"
  debug "domain=$DOMAIN reality_sni=$REALITY_SNI cert=$cert"
  cat > "$out" <<JSON
{
  "log": { "level": "warn" },
  "dns": { "servers": [ { "type": "local", "tag": "local" } ] },
  "inbounds": [
    { "type": "vless", "listen": "::", "listen_port": 443,
      "users": [ { "uuid": "$uuid", "flow": "xtls-rprx-vision" } ],
      "tls": { "enabled": true, "server_name": "$REALITY_SNI",
        "reality": { "enabled": true, "handshake": { "server": "$REALITY_SNI", "server_port": 443 },
          "private_key": "$priv", "short_id": ["$sid"] } } },
    { "type": "hysteria2", "listen": "::", "listen_port": 443,
      "users": [ { "password": "$hy2_pass" } ],
      "tls": { "enabled": true, "certificate_path": "$cert", "key_path": "$key" } },
    { "type": "vless", "listen": "::", "listen_port": 8443,
      "users": [ { "uuid": "$uuid" } ],
      "tls": { "enabled": true, "server_name": "$DOMAIN", "certificate_path": "$cert", "key_path": "$key" },
      "transport": { "type": "ws", "path": "/ws" } },
    { "type": "vless", "listen": "::", "listen_port": 8444,
      "users": [ { "uuid": "$uuid" } ],
      "tls": { "enabled": true, "server_name": "$DOMAIN", "certificate_path": "$cert", "key_path": "$key" },
      "transport": { "type": "grpc", "service_name": "grpc" } },
    { "type": "anytls", "listen": "::", "listen_port": 8445,
      "users": [ { "password": "$anytls_pass" } ],
      "tls": { "enabled": true, "certificate_path": "$cert", "key_path": "$key" } },
    { "type": "shadowsocks", "tag": "ss2022-in", "listen": "::", "listen_port": 8388,
      "method": "2022-blake3-aes-256-gcm", "password": "$ss_pass" }
  ],
  "outbounds": [ { "type": "direct" } ],
  "route": { "default_domain_resolver": { "server": "local" } }
}
JSON
  echo "$pub"
}

# ---------- --test: self-check (no recursion; same render path as production) ----------
if [[ $TEST_MODE -eq 1 ]]; then
  ok "== running gen-server.sh self-check =="
  # repo's self-signed cert so --test works on any machine
  local_cert="$SCRIPT_DIR/../test-env/server/hy2.crt"
  local_key="$SCRIPT_DIR/../test-env/server/hy2.key"
  test_out="$TMPD/config-server.json"
  if [[ -f "$local_cert" && -f "$local_key" ]]; then
    DOMAIN="127.0.0.1"
    render_config "$local_cert" "$local_key" "$test_out" >/dev/null || { err "self-check: generation failed"; exit 1; }
  else
    err "self-check: missing test cert ($local_cert)"; exit 1
  fi
  if timeout 15 "$SB_BIN" check -c "$test_out" 2>"$TMPD/check.err"; then
    ok "self-check: generated + passed sing-box check"
    exit 0
  else
    err "self-check: sing-box check failed:"; cat "$TMPD/check.err" >&2
    exit 2
  fi
fi

# ---------- Domain (interactive or --domain; never probed) ----------
if [[ -z "$DOMAIN" ]]; then
  read -r -p "Enter domain (SNI for ws/grpc, connect address for clients): " DOMAIN
  [[ -n "$DOMAIN" ]] || die1 "must provide domain (--domain arg or interactive input)"
fi

# ---------- Cert/key sanity (neutral placeholders must be overridden) ----------
if [[ "$CERT_FILE" == "/your/cert/at/here" || "$KEY_FILE" == "/your/key/at/here" ]]; then
  die1 "--certpath/--keypath must point at real cert/key files (defaults are placeholders)"
fi
[[ -r "$CERT_FILE" ]] || die1 "certificate not readable: $CERT_FILE"
[[ -r "$KEY_FILE" ]] || die1 "private key not readable: $KEY_FILE"

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
# Overwrite protection: never clobber an existing config (the current one is live on the server)
if [[ -e "$SB_OUTPUT" ]]; then
  die1 "refusing to overwrite existing file: $SB_OUTPUT (delete it first, then re-run)"
fi
debug "output target: $SB_OUTPUT"

# ---------- Render + check ----------
if ! mkdir -p "$(dirname "$SB_OUTPUT")" 2>/dev/null; then
  die1 "cannot write output dir (permission?): $(dirname "$SB_OUTPUT") (add --debug for details)"
fi
PUB="$(render_config "$CERT_FILE" "$KEY_FILE" "$SB_OUTPUT")" || exit 1
if [[ ! -s "$SB_OUTPUT" ]]; then
  die1 "output file empty after write (disk full?): $SB_OUTPUT"
fi
if timeout 15 "$SB_BIN" check -c "$SB_OUTPUT" 2>"$TMPD/check.err"; then
  ok "generated and passed sing-box check: $SB_OUTPUT"
else
  err "config check failed:"; cat "$TMPD/check.err" >&2
  exit 2
fi

ok "server config: $SB_OUTPUT (6 inbounds: reality 443/TCP, hy2 443/UDP, ws 8443, grpc 8444, anytls 8445, ss2022 8388)"
ok "credentials embedded (fresh each run, nothing persisted). Reality public key: $PUB"
ok "clients: bash gen-client.sh --from-server $SB_OUTPUT --server $DOMAIN"
