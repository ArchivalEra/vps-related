#!/usr/bin/env bash
# gen-server.sh — interactive/flag-driven server config generator
# (fresh credentials, single output, zero persistence)
#
# Usage:
#   bash gen-server.sh [--domain D] [--reality-sni S] [--certpath P] [--keypath P]
#                      [--protocols a,b,c] [--ports "name=port,..."]
#                      [--chain-ss-port N] [--ss-method M] [--ss-port N]
#                      [--outputname NAME] [--outputpath DIR] [--debug] [--test]
#
# Output: ONE server sing-box config.json with the SELECTED inbounds (protocols/ports chosen
# interactively, or via flags). Every run rotates all credentials; nothing is persisted.
# Compatible with gen-client.sh (server config.json → client config.json, single input).
# All TLS inbounds share ONE cert/key — designed for a wildcard cert covering all SNIs.
#
# Interactive mode (no --protocols): prompts for domain, protocol selection, per-protocol
# ports, shadowtls→ss chain binding, and standalone ss settings. IDN (non-ASCII) domains
# emit a punycode warning — TLS SNI cannot carry raw IDN.
#
# Args:
#   --domain D        SNI for ws/grpc (and connect address); default prompts interactively
#   --reality-sni S   reality handshake server SNI (default www.microsoft.com)
#   --certpath P      TLS cert path (all TLS inbounds share it; default /your/cert/at/here)
#   --keypath P       TLS key path (default /your/key/at/here)
#   --protocols L     non-interactive: comma list of protocol names (skips selection prompts)
#   --ports K=V,...   non-interactive port overrides (unset → protocol defaults)
#   --chain-ss-port N shadowtls chained ss port (default 8389; 0 = no chain)
#   --ss-method M     standalone ss method (default 2022-blake3-aes-256-gcm)
#   --ss-port N       standalone ss port (default 8388)
#   --outputname N    output filename (default config-server.json; filename only, no path)
#   --outputpath D    output directory (default: this script's own dir)
#   --debug           diagnostic output (fully silent by default)
#   --test            self-check: full default set → temp, sing-box check, exit
#
# Protocols: reality / hysteria2 / vless-ws / vless-grpc / anytls / shadowtls / shadowsocks / tuic / naive
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
PROTOCOLS_ARG=""
PORTS_ARG=""
CHAIN_SS_PORT=""
SS_METHOD=""
SS_PORT=""
TEST_MODE=0
DEBUG="${DEBUG:-0}"

# ---------- Protocol registry ----------
PROTO_ORDER=(reality hysteria2 vless-ws vless-grpc anytls shadowtls shadowsocks tuic naive)
declare -A PROTO_DEFAULT_PORT=(
  [reality]=443 [hysteria2]=443 [vless-ws]=8443 [vless-grpc]=8444
  [anytls]=8445 [shadowtls]=8446 [shadowsocks]=8388 [tuic]=8447 [naive]=8448
)
declare -A PROTO_LAYER=(
  [reality]=tcp [hysteria2]=udp [vless-ws]=tcp [vless-grpc]=tcp [anytls]=tcp
  [shadowtls]=tcp [shadowsocks]=tcp [tuic]=udp [naive]=tcp
)

# ---------- Parse args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) shift; DOMAIN="${1:-}" ;;
    --reality-sni) shift; REALITY_SNI="${1:-}" ;;
    --certpath) shift; CERT_FILE="${1:-}" ;;
    --keypath) shift; KEY_FILE="${1:-}" ;;
    --protocols) shift; PROTOCOLS_ARG="${1:-}" ;;
    --ports) shift; PORTS_ARG="${1:-}" ;;
    --chain-ss-port) shift; CHAIN_SS_PORT="${1:-}" ;;
    --ss-method) shift; SS_METHOD="${1:-}" ;;
    --ss-port) shift; SS_PORT="${1:-}" ;;
    --outputname) shift; OUTPUT_NAME="${1:-}" ;;
    --outputpath) shift; OUTPUT_PATH="${1:-}" ;;
    --debug) DEBUG=1 ;;
    --test) TEST_MODE=1 ;;
    *) die1 "unknown argument: $1 (supported: --domain / --reality-sni / --certpath / --keypath / --protocols / --ports / --chain-ss-port / --ss-method / --ss-port / --outputname / --outputpath / --debug / --test)" ;;
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

# ---------- Shared state (filled by selection; read by renderers) ----------
PROTOCOLS=""                 # space-separated protocol names (selection order)
declare -A PORTS=()          # name → port
CHAIN_SS=0                   # shadowtls binds an internal ss (detour)
CHAIN_SS_PORT_VAL=8389
SS_METHOD_VAL="2022-blake3-aes-256-gcm"
SS_PORT_VAL=8388

# ---------- IDN (non-ASCII domain) warning — TLS SNI needs punycode ----------
check_domain() {
  if printf '%s' "$DOMAIN" | LC_ALL=C grep -q '[^ -~]'; then
    warn "domain contains non-ASCII chars (IDN): TLS SNI requires punycode (xn--...). Convert the domain (e.g. 'idn2' or a punycode converter) or TLS handshakes will fail."
  fi
}

# ---------- Interactive selection ----------
ask_protocols() {
  echo "Select protocols (comma-separated numbers, or empty for all):"
  local i=1 p
  for p in "${PROTO_ORDER[@]}"; do
    printf "  [%d] %-12s (%s, default port %s)\n" "$i" "$p" "${PROTO_LAYER[$p]}" "${PROTO_DEFAULT_PORT[$p]}"
    i=$((i+1))
  done
  read -r -p "Selection: " sel
  sel="$(echo "$sel" | tr -d ' ')"
  local list=()
  if [[ -z "$sel" ]]; then
    list=("${PROTO_ORDER[@]}")
  else
    IFS=',' read -ra nums <<< "$sel"
    local n
    for n in "${nums[@]}"; do
      [[ "$n" =~ ^[0-9]+$ ]] || die1 "invalid selection entry: $n"
      (( n >= 1 && n <= ${#PROTO_ORDER[@]} )) || die1 "selection out of range: $n"
      list+=("${PROTO_ORDER[$((n-1))]}")
    done
  fi
  local seen="" p
  for p in "${list[@]}"; do
    [[ " $seen " == *" $p "* ]] && die1 "duplicate protocol in selection: $p"
    seen+=" $p"; PROTOCOLS+=" $p"
  done
  PROTOCOLS="${PROTOCOLS# }"
}

ask_ports() {
  local p port
  for p in $PROTOCOLS; do
    read -r -p "  $p port [${PROTO_DEFAULT_PORT[$p]}]: " port
    [[ -z "$port" ]] && port="${PROTO_DEFAULT_PORT[$p]}"
    [[ "$port" =~ ^[0-9]+$ ]] || die1 "invalid port for $p: $port"
    PORTS[$p]="$port"
  done
  check_port_conflicts
}

ask_chain_ss() {
  if [[ " $PROTOCOLS " == *" shadowtls "* ]]; then
    local ans p
    read -r -p "  Bind chained ss2022 (detour) for shadowtls? [Y/n]: " ans
    if [[ "${ans:-Y}" =~ ^[Yy] ]]; then
      CHAIN_SS=1
      read -r -p "  chain ss port [8389]: " p
      CHAIN_SS_PORT_VAL="${p:-8389}"
    fi
  fi
  if [[ " $PROTOCOLS " == *" shadowsocks "* ]]; then
    local m p
    read -r -p "  standalone ss method [2022-blake3-aes-256-gcm]: " m
    SS_METHOD_VAL="${m:-2022-blake3-aes-256-gcm}"
    read -r -p "  standalone ss port [8388]: " p
    SS_PORT_VAL="${p:-8388}"
  fi
}

# ---------- Port conflict check (TCP and UDP each must be unique; TCP/UDP may share) ----------
check_port_conflicts() {
  local layer seen p
  for layer in tcp udp; do
    seen=""
    for p in $PROTOCOLS; do
      if [[ "${PROTO_LAYER[$p]}" == "$layer" ]]; then
        if [[ " $seen " == *" ${PORTS[$p]} "* ]]; then
          die1 "port ${PORTS[$p]} used by two $layer protocols ($p) — TCP and UDP may share a port, but two $layer cannot"
        fi
        seen+=" ${PORTS[$p]}"
      fi
    done
  done
}

# ---------- Selection: --test bypasses; else flag-driven (non-interactive) or interactive ----------
if [[ $TEST_MODE -eq 1 ]]; then
  : # --test sets its own selection below (same render path as production)
elif [[ -n "$PROTOCOLS_ARG" ]]; then
  IFS=',' read -ra list <<< "$PROTOCOLS_ARG"
  p=""; seen=""
  for p in "${list[@]}"; do
    p="$(echo "$p" | xargs)"
    [[ -n "$p" ]] || continue
    [[ -n "${PROTO_DEFAULT_PORT[$p]+x}" ]] || die1 "unknown protocol: $p (available: ${PROTO_ORDER[*]})"
    [[ " $seen " == *" $p "* ]] && die1 "duplicate protocol: $p"
    seen+=" $p"; PROTOCOLS+=" $p"
  done
  PROTOCOLS="${PROTOCOLS# }"
  [[ -n "$PROTOCOLS" ]] || die1 "--protocols resolved to empty list"
  for p in $PROTOCOLS; do PORTS[$p]="${PROTO_DEFAULT_PORT[$p]}"; done
  if [[ -n "$PORTS_ARG" ]]; then
    e=""; name=""; val=""
    IFS=',' read -ra kv <<< "$PORTS_ARG"
    for e in "${kv[@]}"; do
      name="${e%%=*}"; val="${e#*=}"
      [[ -n "${PROTO_DEFAULT_PORT[$name]+x}" ]] || die1 "unknown protocol in --ports: $name"
      [[ "$val" =~ ^[0-9]+$ ]] || die1 "bad port entry: $e"
      PORTS[$name]="$val"
    done
  fi
  check_port_conflicts
  # chain ss / standalone ss (flag-driven; chain default ON when shadowtls present)
  if [[ " $PROTOCOLS " == *" shadowtls "* ]]; then
    if [[ -n "$CHAIN_SS_PORT" ]]; then
      [[ "$CHAIN_SS_PORT" =~ ^[0-9]+$ ]] || die1 "bad --chain-ss-port: $CHAIN_SS_PORT"
      CHAIN_SS=0; [[ "$CHAIN_SS_PORT" != "0" ]] && { CHAIN_SS=1; CHAIN_SS_PORT_VAL="$CHAIN_SS_PORT"; }
    else
      CHAIN_SS=1
    fi
  fi
  [[ -n "$SS_METHOD" ]] && SS_METHOD_VAL="$SS_METHOD"
  [[ -n "$SS_PORT" ]] && { [[ "$SS_PORT" =~ ^[0-9]+$ ]] || die1 "bad --ss-port: $SS_PORT"; SS_PORT_VAL="$SS_PORT"; }
else
  ask_protocols
  ask_ports
  ask_chain_ss
fi
debug "protocols: $PROTOCOLS  ports: ${PORTS[*]}  chain_ss=$CHAIN_SS chain_port=$CHAIN_SS_PORT_VAL ss_port=$SS_PORT_VAL"

# ---------- Domain (interactive or --domain; never probed; --test sets its own) ----------
if [[ $TEST_MODE -ne 1 ]]; then
  if [[ -z "$DOMAIN" ]]; then
    read -r -p "Enter domain (SNI for ws/grpc, connect address for clients): " DOMAIN
    [[ -n "$DOMAIN" ]] || die1 "must provide domain (--domain arg or interactive input)"
  fi
  check_domain

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
  # Overwrite protection: never clobber an existing config (the current one may be live on a server)
  if [[ -e "$SB_OUTPUT" ]]; then
    die1 "refusing to overwrite existing file: $SB_OUTPUT (delete it first, then re-run)"
  fi
  debug "output target: $SB_OUTPUT"
fi

# ---------- Per-protocol inbound renderers (read shared state; emit JSON fragments) ----------
render_reality() {
  echo "{ \"type\": \"vless\", \"listen\": \"::\", \"listen_port\": ${PORTS[reality]},
    \"users\": [ { \"uuid\": \"$GEN_UUID\", \"flow\": \"xtls-rprx-vision\" } ],
    \"tls\": { \"enabled\": true, \"server_name\": \"$REALITY_SNI\",
      \"reality\": { \"enabled\": true, \"handshake\": { \"server\": \"$REALITY_SNI\", \"server_port\": 443 },
        \"private_key\": \"$GEN_PRIV\", \"short_id\": [\"$GEN_SID\"] } } }"
}
render_hysteria2() {
  echo "{ \"type\": \"hysteria2\", \"listen\": \"::\", \"listen_port\": ${PORTS[hysteria2]},
    \"users\": [ { \"password\": \"$GEN_HY2_PASS\" } ],
    \"tls\": { \"enabled\": true, \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\" } }"
}
render_vless_ws() {
  echo "{ \"type\": \"vless\", \"listen\": \"::\", \"listen_port\": ${PORTS[vless-ws]},
    \"users\": [ { \"uuid\": \"$GEN_UUID\" } ],
    \"tls\": { \"enabled\": true, \"server_name\": \"$DOMAIN\", \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\" },
    \"transport\": { \"type\": \"ws\", \"path\": \"/ws\" } }"
}
render_vless_grpc() {
  echo "{ \"type\": \"vless\", \"listen\": \"::\", \"listen_port\": ${PORTS[vless-grpc]},
    \"users\": [ { \"uuid\": \"$GEN_UUID\" } ],
    \"tls\": { \"enabled\": true, \"server_name\": \"$DOMAIN\", \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\" },
    \"transport\": { \"type\": \"grpc\", \"service_name\": \"grpc\" } }"
}
render_anytls() {
  echo "{ \"type\": \"anytls\", \"listen\": \"::\", \"listen_port\": ${PORTS[anytls]},
    \"users\": [ { \"password\": \"$GEN_ANYTLS_PASS\" } ],
    \"tls\": { \"enabled\": true, \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\" } }"
}
render_shadowtls() {
  local out
  out="{ \"type\": \"shadowtls\", \"tag\": \"st-in\", \"listen\": \"::\", \"listen_port\": ${PORTS[shadowtls]},
    \"version\": 3, \"users\": [ { \"name\": \"sb\", \"password\": \"$GEN_ST_PASS\" } ],
    \"handshake\": { \"server\": \"$REALITY_SNI\", \"server_port\": 443 }, \"strict_mode\": true,
    \"detour\": \"ss-chain-in\" }"
  if [[ $CHAIN_SS -eq 1 ]]; then
    out+=", { \"type\": \"shadowsocks\", \"tag\": \"ss-chain-in\", \"listen\": \"::\", \"listen_port\": $CHAIN_SS_PORT_VAL,
      \"method\": \"$SS_METHOD_VAL\", \"password\": \"$GEN_SS_CHAIN_PASS\" }"
  fi
  echo "$out"
}
render_shadowsocks() {
  echo "{ \"type\": \"shadowsocks\", \"tag\": \"ss2022-in\", \"listen\": \"::\", \"listen_port\": $SS_PORT_VAL,
    \"method\": \"$SS_METHOD_VAL\", \"password\": \"$GEN_SS_PASS\" }"
}
render_tuic() {
  echo "{ \"type\": \"tuic\", \"listen\": \"::\", \"listen_port\": ${PORTS[tuic]},
    \"users\": [ { \"uuid\": \"$GEN_UUID\", \"password\": \"$GEN_TU_PASS\" } ],
    \"congestion_control\": \"bbr\",
    \"tls\": { \"enabled\": true, \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\" } }"
}
render_naive() {
  echo "{ \"type\": \"naive\", \"listen\": \"::\", \"listen_port\": ${PORTS[naive]},
    \"users\": [ { \"username\": \"sb\", \"password\": \"$GEN_NAIVE_PASS\" } ],
    \"tls\": { \"enabled\": true, \"server_name\": \"$DOMAIN\", \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\" } }"
}

# ---------- Render server config (fresh credentials embedded; $1=cert $2=key $3=out) ----------
render_config() {
  local cert="$1" key="$2" out="$3" inbounds=""
  GEN_CERT="$cert"; GEN_KEY="$key"
  # fresh credentials (generated once per run; unused ones are harmless, never persisted)
  GEN_UUID="$(gen_uuid)" || die1 "failed to generate uuid"
  local kp; kp="$(gen_reality_keypair)" || die1 "failed to generate reality keypair"
  GEN_PRIV="${kp%% *}"; GEN_PUB="${kp#* }"
  GEN_SID="$(gen_short_id)"
  GEN_HY2_PASS="$(gen_hex_pass)"
  GEN_ANYTLS_PASS="$(gen_hex_pass)"
  GEN_ST_PASS="$(gen_hex_pass)"
  GEN_SS_PASS="$(gen_ss_pass)"
  GEN_SS_CHAIN_PASS="$(gen_ss_pass)"
  GEN_TU_PASS="$(gen_hex_pass)"
  GEN_NAIVE_PASS="$(gen_hex_pass)"
  debug "domain=$DOMAIN reality_sni=$REALITY_SNI protocols=$PROTOCOLS"
  local p
  for p in $PROTOCOLS; do
    local frag
    frag="$(render_${p//-/_})" || die1 "render failed for protocol: $p"
    inbounds+="${inbounds:+, }$frag"
  done
  cat > "$out" <<JSON
{
  "log": { "level": "warn" },
  "dns": { "servers": [ { "type": "local", "tag": "local" } ] },
  "inbounds": [
    $inbounds
  ],
  "outbounds": [ { "type": "direct" } ],
  "route": { "default_domain_resolver": { "server": "local" } }
}
JSON
  echo "$GEN_PUB"
}

# ---------- --test: self-check (same render path as production; no recursion) ----------
if [[ $TEST_MODE -eq 1 ]]; then
  ok "== running gen-server.sh self-check =="
  local_cert="$SCRIPT_DIR/../test-env/server/hy2.crt"
  local_key="$SCRIPT_DIR/../test-env/server/hy2.key"
  [[ -f "$local_cert" && -f "$local_key" ]] || { err "self-check: missing test cert ($local_cert)"; exit 1; }
  DOMAIN="127.0.0.1"
  PROTOCOLS="reality hysteria2 vless-ws vless-grpc anytls shadowtls shadowsocks"
  p=""
  for p in $PROTOCOLS; do PORTS[$p]="${PROTO_DEFAULT_PORT[$p]}"; done
  CHAIN_SS=1; CHAIN_SS_PORT_VAL=8389
  SS_METHOD_VAL="2022-blake3-aes-256-gcm"; SS_PORT_VAL=8388
  test_out="$TMPD/config-server.json"
  render_config "$local_cert" "$local_key" "$test_out" >/dev/null || { err "self-check: generation failed"; exit 1; }
  if timeout 15 "$SB_BIN" check -c "$test_out" 2>"$TMPD/check.err"; then
    ok "self-check: generated + passed sing-box check ($PROTOCOLS)"
    exit 0
  else
    err "self-check: sing-box check failed:"; cat "$TMPD/check.err" >&2
    exit 2
  fi
fi

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

ok "server config: $SB_OUTPUT (inbounds: $PROTOCOLS)"
ok "credentials embedded (fresh each run, nothing persisted). Reality public key: $PUB"
ok "clients: bash gen-client.sh --from-server $SB_OUTPUT --server $DOMAIN"
