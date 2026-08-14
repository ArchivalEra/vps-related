#!/usr/bin/env bash
# gen-server.sh — interactive/flag-driven server config generator
# (fresh credentials, single output, zero persistence, multi-instance)
#
# Usage:
#   bash gen-server.sh [--domain D] [--reality-sni S] [--certpath P] [--keypath P]
#                      [--protocols a,a,b,...] [--ports "port,port,..."] [--ss-methods "m1,m2,..."]
#                      [--chain-ss-port N]
#                      [--outputname NAME] [--outputpath DIR] [--debug] [--test]
#
# Output: ONE server sing-box config.json. ANY protocol can appear multiple times —
# each instance gets a unique tag (<proto> for the 1st, <proto>-N for repeats) and its
# own port; TLS protocols share ONE cert/key (wildcard cert design). Every run rotates
# all credentials; nothing is persisted.
#
# Two domains (independent):
#   gen-server.sh + secrets.lib.sh  → server config.json   (this script's only output)
#   gen-client.sh + protocols.lib.sh → client config.json  (reads that server config)
#   common.lib.sh is the shared output layer both libs source; the two domains do not
#   cross-import each other.
#
# Interactive mode (no --protocols): prompts for domain, protocol selection (numbers,
# repeats allowed → multi-instance), per-instance ports, shadowtls→ss chain, and ss
# method/port (repeat the ss choice for more instances). IDN domains warn — TLS SNI
# requires punycode.
#
# Args:
#   --domain D        SNI for ws/grpc/naive (and connect address); default prompts
#   --reality-sni S   reality handshake server SNI (default www.microsoft.com)
#   --certpath P      TLS cert path (all TLS inbounds share it; default /your/cert/at/here)
#   --keypath P       TLS key path (default /your/key/at/here)
#   --protocols L     non-interactive: comma list, repeats allowed (e.g. shadowsocks,shadowsocks)
#   --ports P,P,...   non-interactive: comma port list, positionally aligned with --protocols
#   --ss-methods M    non-interactive: comma method list for ss instances (positional)
#   --chain-ss-port N shadowtls chained ss port (default 8389; 0 = no chain)
#   --outputname N    output filename (default config-server.json; filename only, no path)
#   --outputpath D    output directory (default: this script's own dir)
#   --debug           diagnostic output (fully silent by default)
#   --test            self-check: 8-inbound set incl. dual ss → temp, sing-box check, exit
#
# Protocols (repeatable): reality / hysteria2 / vless-ws / vless-grpc / anytls /
# shadowtls (+chained ss) / shadowsocks / tuic / naive
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
SS_METHODS_ARG=""
CHAIN_SS_PORT=""
ECH=0                   # --ech: add ECH (Encrypted Client Hello) to TLS-terminating inbounds
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
    --ss-methods) shift; SS_METHODS_ARG="${1:-}" ;;
    --chain-ss-port) shift; CHAIN_SS_PORT="${1:-}" ;;
    --ech) ECH=1 ;;
    --outputname) shift; OUTPUT_NAME="${1:-}" ;;
    --outputpath) shift; OUTPUT_PATH="${1:-}" ;;
    --debug) DEBUG=1 ;;
    --test) TEST_MODE=1 ;;
    *) die1 "unknown argument: $1 (supported: --domain / --reality-sni / --certpath / --keypath / --protocols / --ports / --ss-methods / --chain-ss-port / --ech / --outputname / --outputpath / --debug / --test)" ;;
  esac
  shift
done

# ---------- Source: common output layer first, then secrets library ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/common.lib.sh"
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

# ---------- Instance state (filled by instantiate(); read by renderers) ----------
PROTOCOLS=""            # ordered proto list (repeats allowed)
INST_TAGS=""            # ordered unique instance tags ("reality hy2 vless-ws ... ss2022 ss2022-2")
declare -A INST_PORTS=()   # instance tag → port
declare -A INST_LAYER=()   # instance tag → tcp/udp
CHAIN_SS=0              # first shadowtls binds an internal ss (detour)
CHAIN_SS_PORT_VAL=8389

# ---------- IDN (non-ASCII domain) warning — TLS SNI needs punycode ----------
check_domain() {
  if printf '%s' "$DOMAIN" | LC_ALL=C grep -q '[^ -~]'; then
    warn "domain contains non-ASCII chars (IDN): TLS SNI requires punycode (xn--...). Convert the domain (e.g. 'idn2' or a punycode converter) or TLS handshakes will fail."
  fi
}

# ---------- Instantiate: PROTOCOLS (repeats ok) → INST_TAGS/INST_PORTS/INST_LAYER ----------
instantiate() {
  local p tag count
  declare -A _cnt=()
  INST_TAGS=""
  for p in $PROTOCOLS; do
    count=$(( ${_cnt[$p]:-0} + 1 ))
    _cnt[$p]=$count
    if [[ $count -eq 1 ]]; then tag="$p"; else tag="${p}-${count}"; fi
    INST_TAGS+=" $tag"
    INST_PORTS[$tag]="${PROTO_DEFAULT_PORT[$p]}"
    INST_LAYER[$tag]="${PROTO_LAYER[$p]}"
  done
  INST_TAGS="${INST_TAGS# }"
}

# ---------- Port conflict check (TCP and UDP each must be unique; TCP/UDP may share) ----------
check_port_conflicts() {
  local layer seen t
  for layer in tcp udp; do
    seen=""
    for t in $INST_TAGS; do
      if [[ "${INST_LAYER[$t]}" == "$layer" ]]; then
        if [[ " $seen " == *" ${INST_PORTS[$t]} "* ]]; then
          die1 "port ${INST_PORTS[$t]} used by two $layer instances ($t) — TCP and UDP may share a port, but two $layer cannot"
        fi
        seen+=" ${INST_PORTS[$t]}"
      fi
    done
  done
}

# ---------- Interactive selection ----------
ask_protocols() {
  echo "Select protocols (comma-separated numbers, repeats allowed for multi-instance, empty = all):"
  local i=1 p
  for p in "${PROTO_ORDER[@]}"; do
    printf "  [%d] %-12s (%s, default port %s)\n" "$i" "$p" "${PROTO_LAYER[$p]}" "${PROTO_DEFAULT_PORT[$p]}"
    i=$((i+1))
  done
  read -r -p "Selection: " sel
  sel="$(echo "$sel" | tr -d ' ')"
  local list=() n
  if [[ -z "$sel" ]]; then
    list=("${PROTO_ORDER[@]}")
  else
    IFS=',' read -ra nums <<< "$sel"
    for n in "${nums[@]}"; do
      [[ "$n" =~ ^[0-9]+$ ]] || die1 "invalid selection entry: $n"
      (( n >= 1 && n <= ${#PROTO_ORDER[@]} )) || die1 "selection out of range: $n"
      list+=("${PROTO_ORDER[$((n-1))]}")
    done
  fi
  PROTOCOLS="${list[*]}"
}

ask_ports() {
  local t p
  for t in $INST_TAGS; do
    p="${t%%-*}"   # instance's protocol family (strip -N)
    [[ -n "${PROTO_DEFAULT_PORT[$p]+x}" ]] || p="$t"
    read -r -p "  $t port [${INST_PORTS[$t]}]: " port
    [[ -z "$port" ]] && port="${INST_PORTS[$t]}"
    [[ "$port" =~ ^[0-9]+$ ]] || die1 "invalid port for $t: $port"
    INST_PORTS[$t]="$port"
  done
  check_port_conflicts
}

ask_chain_ss() {
  local ans p n ss_i
  # chain ss bound to the FIRST shadowtls instance
  if [[ " $PROTOCOLS " == *" shadowtls "* ]]; then
    read -r -p "  Bind chained ss2022 (detour) for shadowtls? [Y/n]: " ans
    if [[ "${ans:-Y}" =~ ^[Yy] ]]; then
      CHAIN_SS=1
      read -r -p "  chain ss port [8389]: " p
      CHAIN_SS_PORT_VAL="${p:-8389}"
    fi
  fi
  # ss instances: ask method+port per instance
  ss_i=0
  for t in $INST_TAGS; do
    p="${t%%-*}"
    if [[ "$p" == "shadowsocks" ]]; then
      ss_i=$((ss_i+1))
      read -r -p "  ss[$ss_i] ($t) method [2022-blake3-aes-256-gcm]: " m
      [[ -z "$m" ]] && m="2022-blake3-aes-256-gcm"
      INST_SS_METHOD[$t]="$m"
      read -r -p "  ss[$ss_i] ($t) port [${INST_PORTS[$t]}]: " n
      [[ -z "$n" ]] && n="${INST_PORTS[$t]}"
      [[ "$n" =~ ^[0-9]+$ ]] || die1 "invalid ss port: $n"
      INST_PORTS[$t]="$n"
    fi
  done
  [[ $ss_i -ge 1 ]] && check_port_conflicts
}

declare -A INST_SS_METHOD=()   # instance tag → ss method (flag or interactive)

# ---------- Selection: --test bypasses; else flag-driven (non-interactive) or interactive ----------
if [[ $TEST_MODE -eq 1 ]]; then
  : # --test sets its own selection below (same render path as production)
elif [[ -n "$PROTOCOLS_ARG" ]]; then
  p=""
  IFS=',' read -ra list <<< "$PROTOCOLS_ARG"
  for p in "${list[@]}"; do
    p="$(echo "$p" | xargs)"
    [[ -n "$p" ]] || continue
    [[ -n "${PROTO_DEFAULT_PORT[$p]+x}" ]] || die1 "unknown protocol: $p (available: ${PROTO_ORDER[*]})"
    PROTOCOLS+=" $p"
  done
  PROTOCOLS="${PROTOCOLS# }"
  [[ -n "$PROTOCOLS" ]] || die1 "--protocols resolved to empty list"
  instantiate
  if [[ -n "$PORTS_ARG" ]]; then
    e=""; n=0
    read -ra tags <<< "$INST_TAGS"
    IFS=',' read -ra pv <<< "$PORTS_ARG"
    [[ ${#pv[@]} -eq ${#tags[@]} ]] || die1 "--ports has ${#pv[@]} entries but ${#tags[@]} instances (must align with --protocols)"
    for e in "${pv[@]}"; do
      [[ "$e" =~ ^[0-9]+$ ]] || die1 "bad --ports entry: $e"
      INST_PORTS[${tags[$n]}]="$e"
      n=$((n+1))
    done
  fi
  # ss methods (positional across ss instances in selection order)
  if [[ -n "$SS_METHODS_ARG" ]]; then
    e=""; n=0
    IFS=',' read -ra mv <<< "$SS_METHODS_ARG"
    for t in $INST_TAGS; do
      [[ "${t%%-*}" == "shadowsocks" ]] || continue
      [[ $n -lt ${#mv[@]} ]] || die1 "--ss-methods has fewer entries than ss instances"
      INST_SS_METHOD[$t]="${mv[$n]}"; n=$((n+1))
    done
  fi
  check_port_conflicts
  # chain ss (flag-driven; default ON when shadowtls present)
  if [[ " $PROTOCOLS " == *" shadowtls "* ]]; then
    if [[ -n "$CHAIN_SS_PORT" ]]; then
      [[ "$CHAIN_SS_PORT" =~ ^[0-9]+$ ]] || die1 "bad --chain-ss-port: $CHAIN_SS_PORT"
      CHAIN_SS=0; [[ "$CHAIN_SS_PORT" != "0" ]] && { CHAIN_SS=1; CHAIN_SS_PORT_VAL="$CHAIN_SS_PORT"; }
    else
      CHAIN_SS=1
    fi
  fi
else
  ask_protocols
  instantiate
  ask_ports
  ask_chain_ss
fi
debug "instances: $INST_TAGS  ports: ${INST_PORTS[*]}  chain_ss=$CHAIN_SS chain_port=$CHAIN_SS_PORT_VAL"

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

# ---------- Per-protocol inbound renderers (instance-aware; emit JSON fragments) ----------
# Instance context: INST_TAG (current), INST_PORT, INST_SS_METHOD — set by render_config loop.
# Shadowtls chained ss: rendered only for the FIRST shadowtls instance (CHAIN_SS=1).
render_reality() {
  echo "{ \"type\": \"vless\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"uuid\": \"$GEN_UUID\", \"flow\": \"xtls-rprx-vision\" } ],
    \"tls\": { \"enabled\": true, \"server_name\": \"$REALITY_SNI\",
      \"reality\": { \"enabled\": true, \"handshake\": { \"server\": \"$REALITY_SNI\", \"server_port\": 443 },
        \"private_key\": \"$GEN_PRIV\", \"short_id\": [\"$GEN_SID\"] } } }"
}
render_hysteria2() {
  echo "{ \"type\": \"hysteria2\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"password\": \"$GEN_HY2_PASS\" } ],
    \"tls\": { \"enabled\": true, \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\"$(ech_json) } }"
}
render_vless_ws() {
  echo "{ \"type\": \"vless\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"uuid\": \"$GEN_UUID\" } ],
    \"tls\": { \"enabled\": true, \"server_name\": \"$DOMAIN\", \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\"$(ech_json) },
    \"transport\": { \"type\": \"ws\", \"path\": \"/ws\" } }"
}
render_vless_grpc() {
  echo "{ \"type\": \"vless\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"uuid\": \"$GEN_UUID\" } ],
    \"tls\": { \"enabled\": true, \"server_name\": \"$DOMAIN\", \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\"$(ech_json) },
    \"transport\": { \"type\": \"grpc\", \"service_name\": \"grpc\" } }"
}
render_anytls() {
  echo "{ \"type\": \"anytls\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"password\": \"$GEN_ANYTLS_PASS\" } ],
    \"tls\": { \"enabled\": true, \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\"$(ech_json) } }"
}
render_shadowtls() {
  # tag must be unique per instance; the server may have several shadowtls inbounds
  local out detour
  detour=""
  if [[ $CHAIN_SS -eq 1 && "${INST_SHADOWTLS_N:-0}" -eq 0 ]]; then
    detour=", \"detour\": \"ss-chain-in\""
  fi
  INST_SHADOWTLS_N=$(( ${INST_SHADOWTLS_N:-0} + 1 ))
  out="{ \"type\": \"shadowtls\", \"tag\": \"$INST_TAG\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"version\": 3, \"users\": [ { \"name\": \"sb\", \"password\": \"$GEN_ST_PASS\" } ],
    \"handshake\": { \"server\": \"$REALITY_SNI\", \"server_port\": 443 }, \"strict_mode\": true$detour }"
  if [[ $CHAIN_SS -eq 1 && $(( ${INST_SHADOWTLS_N:-0} - 1 )) -eq 1 ]]; then
    out+=", { \"type\": \"shadowsocks\", \"tag\": \"ss-chain-in\", \"listen\": \"::\", \"listen_port\": $CHAIN_SS_PORT_VAL,
      \"method\": \"2022-blake3-aes-256-gcm\", \"password\": \"$GEN_SS_CHAIN_PASS\" }"
  fi
  echo "$out"
}
render_shadowsocks() {
  local method="${INST_SS_METHOD[$INST_TAG]:-2022-blake3-aes-256-gcm}"
  echo "{ \"type\": \"shadowsocks\", \"tag\": \"$INST_TAG\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"method\": \"$method\", \"password\": \"$GEN_SS_PASS\" }"
}
render_tuic() {
  echo "{ \"type\": \"tuic\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"uuid\": \"$GEN_UUID\", \"password\": \"$GEN_TU_PASS\" } ],
    \"congestion_control\": \"bbr\",
    \"tls\": { \"enabled\": true, \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\"$(ech_json) } }"
}
render_naive() {
  echo "{ \"type\": \"naive\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"username\": \"sb\", \"password\": \"$GEN_NAIVE_PASS\" } ],
    \"tls\": { \"enabled\": true, \"server_name\": \"$DOMAIN\", \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\"$(ech_json) } }"
}

# ---------- ECH keypair (server side): PEM line array for tls.ech.key + CONFIGS for DNS ----------
# Generated only when --ech; keys embed the plain server name (domain). CONFIGS block is
# printed for publishing as the HTTPS/SVCB record (client auto-loads via DNS).
gen_ech() {
  local kp
  kp="$(${SB_BIN:-sing-box} generate ech-keypair "$DOMAIN" 2>/dev/null)" || { warn "ECH: ech-keypair failed for $DOMAIN — ECH disabled"; return 1; }
  # configs/keys written to files: render_config runs in a subshell (command subst),
  # so parent cannot read child vars — files survive the boundary.
  echo "$kp" | sed -n '/BEGIN ECH CONFIGS/,/END ECH CONFIGS/p' > "$TMPD/ech.configs"
  echo "$kp" | sed -n '/BEGIN ECH KEYS/,/END ECH KEYS/p' > "$TMPD/ech.keys"
  GEN_ECH_KEY_ARR="$(python3 -c "import json; print(json.dumps(open('$TMPD/ech.keys').read().splitlines()))")"
  return 0
}
# JSON fragment: ', "ech": { "enabled": true, "key": [...] }' or ''
ech_json() {
  [[ $ECH -eq 1 && -n "${GEN_ECH_KEY_ARR:-}" ]] && echo ", \"ech\": { \"enabled\": true, \"key\": $GEN_ECH_KEY_ARR }"
}

# ---------- Render server config (fresh credentials; $1=cert $2=key $3=out) ----------
render_config() {
  local cert="$1" key="$2" out="$3" inbounds="" t proto
  GEN_CERT="$cert"; GEN_KEY="$key"
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
  GEN_ECH_KEY_ARR=""
  GEN_ECH_CONFIGS=""
  [[ $ECH -eq 1 ]] && gen_ech
  INST_SHADOWTLS_N=0
  debug "domain=$DOMAIN reality_sni=$REALITY_SNI instances=$INST_TAGS ech=$ECH"
  for t in $INST_TAGS; do
    INST_TAG="$t"
    INST_PORT="${INST_PORTS[$t]}"
    proto="${t%%-*}"
    [[ -n "${PROTO_DEFAULT_PORT[$proto]+x}" ]] || proto="$t"
    local frag
    frag="$(render_"${proto//-/_}")" || die1 "render failed for instance: $t"
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
  # ECH CONFIGS (public) appended as // comments — sing-box accepts them, and the
  # config is the only artifact we keep (zero extra files). Client side re-extracts.
  if [[ $ECH -eq 1 && -f "$TMPD/ech.configs" && -s "$TMPD/ech.configs" ]]; then
    {
      echo
      echo "// ECH CONFIGS for $DOMAIN — publish as the HTTPS/SVCB record so clients auto-load"
      sed 's/^/\/\/ /' "$TMPD/ech.configs"
    } >> "$out"
  fi
  echo "$GEN_PUB"
}

# ---------- --test: self-check (default set = deployment shape; --protocols overrides) ----------
# Self-contained: throwaway cert generated via openssl (a hard dep of secrets.lib) —
# no repo test-env dependency, works on any machine (deploy hosts included).
if [[ $TEST_MODE -eq 1 ]]; then
  ok "== running gen-server.sh self-check =="
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$TMPD/key.pem" -out "$TMPD/cert.pem" -days 1 -subj "/CN=127.0.0.1" >/dev/null 2>&1 \
    || { err "self-check: openssl cert generation failed"; exit 1; }
  DOMAIN="127.0.0.1"
  # default self-check set mirrors the deployment shape (6 protocols, no ss);
  # pass --protocols (and --ports for repeats) to self-check your own set
  if [[ -n "$PROTOCOLS_ARG" ]]; then
    p=""
    IFS=',' read -ra list <<< "$PROTOCOLS_ARG"
    for p in "${list[@]}"; do
      p="$(echo "$p" | xargs)"
      [[ -n "$p" ]] || continue
      [[ -n "${PROTO_DEFAULT_PORT[$p]+x}" ]] || die1 "unknown protocol: $p (available: ${PROTO_ORDER[*]})"
      PROTOCOLS+=" $p"
    done
    PROTOCOLS="${PROTOCOLS# }"
  else
    PROTOCOLS="reality hysteria2 vless-ws vless-grpc tuic shadowtls"
  fi
  [[ -n "$PROTOCOLS" ]] || die1 "--test: empty protocol set"
  instantiate
  # apply --ports when given (needed e.g. multi-ss self-check: --protocols shadowsocks,shadowsocks --ports 8388,8390)
  if [[ -n "$PORTS_ARG" ]]; then
    e=""; n=0
    read -ra tags <<< "$INST_TAGS"
    IFS=',' read -ra pv <<< "$PORTS_ARG"
    [[ ${#pv[@]} -eq ${#tags[@]} ]] || die1 "--ports has ${#pv[@]} entries but ${#tags[@]} instances"
    for e in "${pv[@]}"; do
      [[ "$e" =~ ^[0-9]+$ ]] || die1 "bad --ports entry: $e"
      INST_PORTS[${tags[$n]}]="$e"
      n=$((n+1))
    done
  fi
  CHAIN_SS=1; CHAIN_SS_PORT_VAL=8389
  test_out="$TMPD/config-server.json"
  render_config "$TMPD/cert.pem" "$TMPD/key.pem" "$test_out" >/dev/null || { err "self-check: generation failed"; exit 1; }
  if timeout 15 "$SB_BIN" check -c "$test_out" 2>"$TMPD/check.err"; then
    ok "self-check: generated + passed sing-box check ($INST_TAGS)"
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

ok "server config: $SB_OUTPUT (inbounds: $INST_TAGS)"
ok "credentials embedded (fresh each run, nothing persisted). Reality public key: $PUB"
if [[ $ECH -eq 1 && -f "$TMPD/ech.configs" && -s "$TMPD/ech.configs" ]]; then
  ok "ECH enabled — CONFIGS embedded as comments at the end of $SB_OUTPUT; publish them as the HTTPS/SVCB record for $DOMAIN (clients auto-load via DNS)"
fi
ok "clients: bash gen-client.sh --from-server $SB_OUTPUT --server $DOMAIN"
