#!/usr/bin/env bash
# secrets.lib.sh — server credential generation library (sourced by gen-server.sh)
#
# Architecture: credentials are generated fresh on every run and embedded directly
# into the server config.json output. Nothing is persisted — no secrets.env, no state.
# Zero storage, zero garbage: re-run gen-server.sh anytime to rotate everything.
#
# Requires: sing-box (generate uuid / reality-keypair), openssl

# Output tiers (ok/warn/err/die1/die2/debug + afterglow colors) are defined inline —
# deliberately duplicated from protocols.lib.sh so each domain can evolve independently
# (server/client behavior diverges often). Keep in sync with protocols.lib.sh when touching.
DEBUG="${DEBUG:-0}"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_GREEN="\033[38;2;144;169;89m"    # afterglow green  #90a959
  C_YELLOW="\033[38;2;244;191;117m"  # afterglow yellow #f4bf75
  C_RED="\033[38;2;172;65;66m"       # afterglow red    #ac4142
  C_BLUE="\033[38;2;106;159;181m"    # afterglow blue   #6a9fb5
  C_RESET="\033[0m"
else
  C_GREEN=""; C_YELLOW=""; C_RED=""; C_BLUE=""; C_RESET=""
fi

ok()    { echo -e "${C_GREEN}$*${C_RESET}"; }                          # success/result → stdout (green)
warn()  { echo -e "${C_YELLOW}⚠ $*${C_RESET}" >&2; }                   # warning → stderr (yellow)
err()   { echo -e "${C_RED}✗ $*${C_RESET}" >&2; }                      # error → stderr (red)
die1()  { err "$@"; exit 1; }                                          # error + exit 1 (argument/dependency)
die2()  { err "$@"; exit 2; }                                          # error + exit 2 (conversion/check)
debug() { [[ $DEBUG -eq 1 ]] && echo -e "${C_BLUE}[debug] $*${C_RESET}" >&2; }   # only with --debug

# ---------- Credential generators (stdout only; failures return non-zero) ----------

# UUID v4 (sing-box native, fallback /proc)
gen_uuid() {
  ${SB_BIN:-sing-box} generate uuid 2>/dev/null || cat /proc/sys/kernel/random/uuid
}

# X25519 reality keypair → stdout "PRIV PUB" (URL-safe raw base64, 43 chars each)
gen_reality_keypair() {
  local kp priv pub
  kp="$(${SB_BIN:-sing-box} generate reality-keypair 2>/dev/null)" || return 1
  priv="$(echo "$kp" | sed -n 's/^PrivateKey: //p')"
  pub="$(echo "$kp" | sed -n 's/^PublicKey: //p')"
  [[ -n "$priv" && -n "$pub" ]] || return 1
  echo "$priv $pub"
}

# reality short_id (hex)
gen_short_id() { openssl rand -hex 8; }

# 12-byte hex password (hy2 / anytls)
gen_hex_pass() { openssl rand -hex 12; }

# SS2022 password: 32 raw bytes → standard base64 WITH padding (Go decoder requires len%4==0)
gen_ss_pass() { openssl rand -base64 32 | tr -d '\n'; }

# Output path resolution — SB_OUTPUT env (full path) > outputpath+outputname >
# outputname > outputpath > default $SCRIPT_DIR/$OUTPUT_NAME_DEFAULT.
# Reads the script's OUTPUT_NAME / OUTPUT_PATH / OUTPUT_NAME_DEFAULT globals.
resolve_output_path() {
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
}

# ---------- Protocol registry (private — gen-server no longer duplicates) ----------
# shellcheck disable=SC2034
PROTO_ORDER=(reality hysteria2 vless-ws vless-grpc anytls shadowtls shadowsocks tuic naive)
declare -A PROTO_DEFAULT_PORT=(
  [reality]=443 [hysteria2]=443 [vless-ws]=8443 [vless-grpc]=8444
  [anytls]=8445 [shadowtls]=8446 [shadowsocks]=8388 [tuic]=8447 [naive]=8448
)
declare -A PROTO_LAYER=(
  [reality]=tcp [hysteria2]=udp [vless-ws]=tcp [vless-grpc]=tcp [anytls]=tcp
  [shadowtls]=tcp [shadowsocks]=tcp [tuic]=udp [naive]=tcp
)
declare -A PROTO_CRED_GEN=(
  [hysteria2]=gen_hex_pass [anytls]=gen_hex_pass [shadowtls]=gen_hex_pass [tuic]=gen_hex_pass
  [shadowsocks]=gen_ss_pass [naive]=gen_hex_pass
)
declare -A PROTO_CRED_VAR=(
  [hysteria2]=GEN_HY2_PASS [anytls]=GEN_ANYTLS_PASS [shadowtls]=GEN_ST_PASS [tuic]=GEN_TU_PASS
  [shadowsocks]=GEN_SS_PASS [naive]=GEN_NAIVE_PASS
)
# Per-protocol hardening constants (not credentials, but protocol behavior):
# - hysteria2: salamander obfs password (QUIC traffic padding to defeat DPI) — fresh per run.
# - tuic: heartbeat keeps the QUIC connection alive through NAT/NAT64 (10s is the
#   sweet spot: alive behind UDP timeouts without meaningful overhead).
TUIC_HEARTBEAT="10s"

# ---------- Port conflict check (TCP and UDP each must be unique; TCP/UDP may share) ----------
check_port_conflicts() {
  local layer seen t p
  for layer in tcp udp; do
    seen=""
    for t in $INST_TAGS; do
      p="$t"; [[ -n "${PROTO_LAYER[$p]+x}" ]] || p="${t%%-*}"
      if [[ "${PROTO_LAYER[$p]}" == "$layer" ]]; then
        if [[ " $seen " == *" ${INST_PORTS[$t]} "* ]]; then
          die1 "port ${INST_PORTS[$t]} used by two $layer instances ($t) — TCP and UDP may share a port, but two $layer cannot"
        fi
        seen+=" ${INST_PORTS[$t]}"
      fi
    done
  done
}

# ---------- Lightweight instantiate interface (pure memory, no file) ----------
# secrets_instantiate --protocols "a,b" [--ports "1,2"]
# Uses declare -n to write back to caller's INST_TAGS (space-separated string)
# and INST_PORTS (associative array). Also sets PROTOCOLS (space-separated).
secrets_instantiate() {
  local protos="" ports=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --protocols) shift; protos="${1:-}" ;;
      --ports) shift; ports="${1:-}" ;;
      *) die1 "secrets_instantiate: unknown argument: $1" ;;
    esac
    shift
  done
  [[ -n "$protos" ]] || die1 "secrets_instantiate: --protocols required"
  # namerefs to caller's variables (fixed names INST_TAGS / INST_PORTS)
  declare -n _si_tags=INST_TAGS
  declare -n _si_ports=INST_PORTS
  # clear previous state (preserve associative type)
  _si_tags=""
  local _k
  for _k in "${!_si_ports[@]}"; do unset "_si_ports[$_k]"; done
  local _p _tag
  declare -A _cnt=()
  local _protocols_space=""
  local _list
  IFS=',' read -ra _list <<< "$protos"
  for _p in "${_list[@]}"; do
    _p="$(echo "$_p" | xargs)"
    [[ -n "$_p" ]] || continue
    [[ -n "${PROTO_DEFAULT_PORT[$_p]+x}" ]] || die1 "unknown protocol: $_p (available: ${PROTO_ORDER[*]})"
    _protocols_space+=" $_p"
    _cnt[$_p]=$((${_cnt[$_p]:-0} + 1))
    if [[ ${_cnt[$_p]} -eq 1 ]]; then _tag="$_p"; else _tag="${_p}-${_cnt[$_p]}"; fi
    _si_tags+=" $_tag"
    _si_ports["$_tag"]="${PROTO_DEFAULT_PORT[$_p]}"
  done
  _si_tags="${_si_tags# }"
  _protocols_space="${_protocols_space# }"
  [[ -n "$_si_tags" ]] || die1 "--protocols resolved to empty list"
  # expose PROTOCOLS for caller's chain logic / debug
  # shellcheck disable=SC2034
  declare -g PROTOCOLS="$_protocols_space"
  # apply --ports positionally if given
  if [[ -n "$ports" ]]; then
    local _e _n _pv _tags_arr
    read -ra _tags_arr <<< "$_si_tags"
    IFS=',' read -ra _pv <<< "$ports"
    [[ ${#_pv[@]} -eq ${#_tags_arr[@]} ]] || die1 "--ports has ${#_pv[@]} entries but ${#_tags_arr[@]} instances (must align with --protocols)"
    _n=0
    for _e in "${_pv[@]}"; do
      [[ "$_e" =~ ^[0-9]+$ ]] || die1 "bad --ports entry: $_e"
      _si_ports["${_tags_arr[$_n]}"]="$_e"
      _n=$((_n + 1))
    done
  fi
  check_port_conflicts
}

# ---------- Per-protocol inbound renderers (instance-aware; emit JSON fragments) ----------
# Instance context: INST_TAG (current), INST_PORT, INST_SS_METHOD — set by render_config loop.
# Shadowtls chained ss: rendered only for the FIRST shadowtls instance (CHAIN_SS=1).
render_reality() {
  echo "{ \"type\": \"vless\", \"tag\": \"$INST_TAG\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"uuid\": \"$GEN_UUID\", \"flow\": \"xtls-rprx-vision\" } ],
    \"tls\": { \"enabled\": true, \"server_name\": \"$REALITY_SNI\",
      \"reality\": { \"enabled\": true, \"handshake\": { \"server\": \"$REALITY_SNI\", \"server_port\": 443 },
        \"private_key\": \"$GEN_PRIV\", \"short_id\": [\"$GEN_SID\"] } } }"
}
render_hysteria2() {
  echo "{ \"type\": \"hysteria2\", \"tag\": \"$INST_TAG\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"password\": \"$GEN_HY2_PASS\" } ],
    \"obfs\": { \"type\": \"salamander\", \"password\": \"$GEN_HY2_OBFS\" },
    \"tls\": { \"enabled\": true, \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\"$(ech_json) } }"
}
render_vless_ws() {
  echo "{ \"type\": \"vless\", \"tag\": \"$INST_TAG\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"uuid\": \"$GEN_UUID\" } ],
    \"tls\": { \"enabled\": true, \"server_name\": \"$DOMAIN\", \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\"$(ech_json) },
    \"transport\": { \"type\": \"ws\", \"path\": \"/ws\" } }"
}
render_vless_grpc() {
  echo "{ \"type\": \"vless\", \"tag\": \"$INST_TAG\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"uuid\": \"$GEN_UUID\" } ],
    \"tls\": { \"enabled\": true, \"server_name\": \"$DOMAIN\", \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\"$(ech_json) },
    \"transport\": { \"type\": \"grpc\", \"service_name\": \"grpc\" } }"
}
render_anytls() {
  echo "{ \"type\": \"anytls\", \"tag\": \"$INST_TAG\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"password\": \"$GEN_ANYTLS_PASS\" } ],
    \"tls\": { \"enabled\": true, \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\"$(ech_json) } }"
}
render_shadowtls() {
  local out detour=""
  if [[ $CHAIN_SS -eq 1 && "${INST_ST_N:-0}" -eq 1 ]]; then
    detour=", \"detour\": \"ss-chain-in\""
  fi
  out="{ \"type\": \"shadowtls\", \"tag\": \"$INST_TAG\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"version\": 3, \"users\": [ { \"name\": \"sb\", \"password\": \"$GEN_ST_PASS\" } ],
    \"handshake\": { \"server\": \"$REALITY_SNI\", \"server_port\": 443 }, \"strict_mode\": true$detour }"
  if [[ $CHAIN_SS -eq 1 && "${INST_ST_N:-0}" -eq 1 ]]; then
    out+=", { \"type\": \"shadowsocks\", \"tag\": \"ss-chain-in\", \"listen\": \"::\", \"listen_port\": $CHAIN_SS_PORT_VAL,
      \"method\": \"2022-blake3-aes-256-gcm\", \"password\": \"$GEN_SS_CHAIN_PASS\" }"
  fi
  echo "$out"
}
render_shadowsocks() {
  local method="${INST_SS_METHOD[$INST_TAG]:-2022-blake3-aes-256-gcm}"
  echo "{ \"type\": \"shadowsocks\", \"tag\": \"$INST_TAG\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"method\": \"$method\", \"password\": \"$GEN_SS_PASS\", \"multiplex\": { \"enabled\": true, \"padding\": true } }"
}
render_tuic() {
  echo "{ \"type\": \"tuic\", \"tag\": \"$INST_TAG\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"uuid\": \"$GEN_UUID\", \"password\": \"$GEN_TU_PASS\" } ],
    \"congestion_control\": \"bbr\", \"heartbeat\": \"$TUIC_HEARTBEAT\",
    \"tls\": { \"enabled\": true, \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\"$(ech_json) } }"
}
render_naive() {
  echo "{ \"type\": \"naive\", \"tag\": \"$INST_TAG\", \"listen\": \"::\", \"listen_port\": $INST_PORT,
    \"users\": [ { \"username\": \"sb\", \"password\": \"$GEN_NAIVE_PASS\" } ],
    \"tls\": { \"enabled\": true, \"server_name\": \"$DOMAIN\", \"certificate_path\": \"$GEN_CERT\", \"key_path\": \"$GEN_KEY\"$(ech_json) } }"
}

# ---------- ECH keypair (server side): PEM line array for tls.ech.key + CONFIGS for DNS ----------
gen_ech() {
  local kp
  kp="$(${SB_BIN:-sing-box} generate ech-keypair "$DOMAIN" 2>/dev/null)" || { warn "ECH: ech-keypair failed for $DOMAIN — ECH disabled"; return 1; }
  echo "$kp" | sed -n '/BEGIN ECH CONFIGS/,/END ECH CONFIGS/p' > "$TMPD/ech.configs"
  echo "$kp" | sed -n '/BEGIN ECH KEYS/,/END ECH KEYS/p' > "$TMPD/ech.keys"
  GEN_ECH_KEY_ARR="$(python3 -c "import json; print(json.dumps(open('$TMPD/ech.keys').read().splitlines()))")"
  return 0
}
ech_json() {
  [[ $ECH -eq 1 && -n "${GEN_ECH_KEY_ARR:-}" ]] && echo ", \"ech\": { \"enabled\": true, \"key\": $GEN_ECH_KEY_ARR }"
}

# ---------- Render server config (fresh credentials; $1=cert $2=key $3=out) ----------
# Internal GEN_* are locals; only GEN_PUB is exported for caller's summary line.
render_config() {
  local cert="$1" key="$2" out="$3" inbounds="" t proto c
  local GEN_CERT GEN_KEY GEN_UUID GEN_PRIV GEN_PUB GEN_SID
  local GEN_HY2_PASS GEN_HY2_OBFS GEN_ANYTLS_PASS GEN_ST_PASS GEN_TU_PASS GEN_SS_PASS GEN_NAIVE_PASS GEN_SS_CHAIN_PASS GEN_ECH_KEY_ARR
  local INST_TAG INST_PORT INST_ST_N ST_N
  GEN_CERT="$cert"; GEN_KEY="$key"
  GEN_UUID="$(gen_uuid)" || die1 "failed to generate uuid"
  local kp; kp="$(gen_reality_keypair)" || die1 "failed to generate reality keypair"
  GEN_PRIV="${kp%% *}"; GEN_PUB="${kp#* }"
  GEN_SID="$(gen_short_id)"
  for c in "${PROTO_ORDER[@]}"; do
    [[ -n "${PROTO_CRED_GEN[$c]+x}" ]] || continue
    # shellcheck disable=SC2034
    printf -v "${PROTO_CRED_VAR[$c]}" '%s' "$(${PROTO_CRED_GEN[$c]})"
  done
  GEN_SS_CHAIN_PASS="$(gen_ss_pass)"
  GEN_HY2_OBFS="$(gen_hex_pass)"   # hysteria2 salamander obfs password (fresh per run)
  GEN_ECH_KEY_ARR=""
  [[ $ECH -eq 1 ]] && gen_ech
  INST_ST_N=0
  ST_N=0
  debug "domain=$DOMAIN reality_sni=$REALITY_SNI instances=$INST_TAGS ech=$ECH"
  for t in $INST_TAGS; do
    INST_TAG="$t"
    INST_PORT="${INST_PORTS[$t]}"
    INST_ST_N=0
    if [[ "$t" == shadowtls || "$t" == shadowtls-* ]]; then
      ST_N=$((ST_N + 1))
      INST_ST_N="$ST_N"
    fi
    proto="${t%%-*}"
    [[ -n "${PROTO_DEFAULT_PORT[$proto]+x}" ]] || proto="$t"
    local frag
    frag="$(render_"${proto//-/_}")" || die1 "render failed for instance: $t"
    inbounds+="${inbounds:+,
        }$frag"
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
  if [[ $ECH -eq 1 && -f "$TMPD/ech.configs" && -s "$TMPD/ech.configs" ]]; then
    {
      echo
      echo "// ECH CONFIGS for $DOMAIN — publish as the HTTPS/SVCB record so clients auto-load"
      sed 's/^/\/\/ /' "$TMPD/ech.configs"
    } >> "$out"
  fi
  # export for caller (thin entry reads GEN_PUB)
  # shellcheck disable=SC2034
  declare -g GEN_PUB="$GEN_PUB"
  # shellcheck disable=SC2034
  declare -g GEN_ECH_KEY_ARR="$GEN_ECH_KEY_ARR"
}
