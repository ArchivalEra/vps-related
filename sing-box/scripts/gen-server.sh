#!/usr/bin/env bash
# gen-server.sh — interactive/flag-driven server config generator
# (fresh credentials, single output, zero persistence, multi-instance)
#
# Usage:
#   bash gen-server.sh --help
#   bash gen-server.sh [--domain D] [--reality-sni S] [--certpath P] [--keypath P]
#                      [--protocols a,a,b,...] [--ports "port,port,..."] [--ss-methods "m1,m2,..."]
#                      [--chain-ss-port N] [--ech]
#                      [--outputname NAME] [--outputpath DIR] [--debug] [--test]
#
# No flags: interactive prompts (TTY). No flags + non-TTY stdin (piped) prints
# "try gen-server.sh --help" and exits 1 — flags are the only batch entry point.
# --help prints the ##help## flag reference and exits 0.
#
# Default ports: reality 443/tcp, hysteria2 443/udp, vless-ws 8443, vless-grpc 8444,
# anytls 8445, shadowtls 8446 (+ chained ss 8389), tuic 8447, shadowsocks 8388, naive 8448.
#
# Output: ONE server sing-box config.json. ANY protocol can appear multiple times —
# each instance gets a unique tag (<proto> for the 1st, <proto>-N for repeats) and its
# own port; TLS protocols share ONE cert/key (wildcard cert design). Every run rotates
# all credentials; nothing is persisted.
#
# Two domains (independent):
#   gen-server.sh + secrets.lib.sh → server config.json   (this script's only output)
#   gen-client.sh + protocols.lib.sh → client config.json  (reads that server config)
#   Each lib ships its own output layer (ok/warn/err/die/debug); the two domains do not
#   cross-import each other.
#
# Interactive mode (no --protocols): prompts for domain, protocol selection (numbers,
# repeats allowed → multi-instance), per-instance ports, shadowtls→ss chain, and ss
# method/port (repeat the ss choice for more instances). IDN domains warn — TLS SNI
# requires punycode.
#
# Args:
#   --help            print the ##help## flag reference and exit 0
#   --domain D        SNI for ws/grpc/naive (and connect address); default prompts
#   --reality-sni S   reality handshake server SNI (default www.microsoft.com)
#   --certpath P      TLS cert path (all TLS inbounds share it; default /your/cert/at/here)
#   --keypath P       TLS key path (default /your/key/at/here)
#   --protocols L     non-interactive: comma list, repeats allowed (e.g. shadowsocks,shadowsocks)
#   --ports P,P,...   non-interactive: comma port list, positionally aligned with --protocols
#   --ss-methods M    non-interactive: comma method list for ss instances (positional)
#   --chain-ss-port N shadowtls chained ss port (default 8389; 0 = no chain)
#   --ech             add ECH (Encrypted Client Hello) to TLS-terminating inbounds
#   --outputname N    output filename (default config-server.json; filename only, no path)
#   --outputpath D    output directory (default: this script's own dir)
#   --debug           diagnostic output (fully silent by default)
#   --test            self-check: default 6-protocol set + shadowtls chain (no ss) → temp, sing-box check, exit
#
# Protocols (repeatable): reality / hysteria2 / vless-ws / vless-grpc / anytls /
# shadowtls (+chained ss) / shadowsocks / tuic / naive
#
# Env: SB_OUTPUT (full output path override) / SB_BIN / DEBUG
# Exit codes: 0=ok  1=argument/dependency  2=sing-box check failure

set -uo pipefail

# ---------- Defaults ----------
# shellcheck disable=SC2034  # OUTPUT_NAME_DEFAULT/OUTPUT_PATH read by resolve_output_path() in secrets.lib.sh
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
CDN=0                   # --cdn: ws/grpc render as plain (no origin tls) for CDN/argo fronting
TEST_MODE=0
DEBUG="${DEBUG:-0}"

# ---------- --help: compact flag reference (##help## block, one flag per line) ----------
help() {
  cat <<'HELP'
gen-server.sh — flag-driven server config generator (flags only; no positional args)

##help##
  --domain D        SNI for ws/grpc/naive (and connect address); default: interactive prompt
  --reality-sni S   reality handshake server SNI (default: www.microsoft.com)
  --certpath P      TLS cert path (default: /your/cert/at/here)
  --keypath P       TLS key path (default: /your/key/at/here)
  --protocols L     comma list, repeats allowed (e.g. shadowsocks,shadowsocks)
  --ports P,P,...   comma port list, aligned positionally with --protocols
  --ss-methods M    comma method list for ss instances (positional)
  --chain-ss-port N shadowtls chained ss port (default: 8389; 0 = no chain)
  --ech             add ECH (Encrypted Client Hello) to TLS-terminating inbounds
  --cdn             CDN/argo fronting for ws/grpc: their inbounds render WITHOUT an
                    origin tls block (the tunnel edge terminates TLS). Cert is then
                    only required if another protocol still needs it. The client
                    keeps TLS on toward the edge — pair with --addr <edge-host>.
  --outputname N    output filename (default: config-server.json; filename only, no path)
  --outputpath D    output directory (default: this script's own dir)
  --debug           diagnostic output (fully silent by default)
  --test            self-check: generate to temp, sing-box check, exit
##help##
HELP
}

# ---------- No flags: TTY → interactive; non-TTY (piped) → point at --help ----------
if [[ $# -eq 0 && ! -t 0 ]]; then
  echo "try gen-server.sh --help"
  exit 1
fi

# ---------- Parse args ----------
while [[ $# -gt 0 ]]; do
  # shellcheck disable=SC2034
  # OUTPUT_NAME/OUTPUT_PATH are read by resolve_output_path() in secrets.lib.sh
  case "$1" in
    --help) help; exit 0 ;;
    --domain) shift; DOMAIN="${1:-}" ;;
    --reality-sni) shift; REALITY_SNI="${1:-}" ;;
    --certpath) shift; CERT_FILE="${1:-}" ;;
    --keypath) shift; KEY_FILE="${1:-}" ;;
    --protocols) shift; PROTOCOLS_ARG="${1:-}" ;;
    --ports) shift; PORTS_ARG="${1:-}" ;;
    --ss-methods) shift; SS_METHODS_ARG="${1:-}" ;;
    --chain-ss-port) shift; CHAIN_SS_PORT="${1:-}" ;;
    --ech) ECH=1 ;;
    --cdn) CDN=1 ;;
    --outputname) shift; OUTPUT_NAME="${1:-}" ;;
    --outputpath) shift; OUTPUT_PATH="${1:-}" ;;
    --debug) DEBUG=1 ;;
    --test) TEST_MODE=1 ;;
    *) die1 "unknown argument: $1 (supported: --domain / --reality-sni / --certpath / --keypath / --protocols / --ports / --ss-methods / --chain-ss-port / --ech / --outputname / --outputpath / --debug / --test)" ;;
  esac
  shift
done

# ---------- Source: secrets library (credentials + output layer + registry + render) ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "$SCRIPT_DIR/secrets.lib.sh" ]]; then
  echo "error: secrets.lib.sh not found next to gen-server.sh ($SCRIPT_DIR)" >&2
  echo "  deploy both files together (see gen-server.sh.readme.md)" >&2
  exit 1
fi
[[ -r "$SCRIPT_DIR/secrets.lib.sh" ]] || die1 "secrets.lib.sh not readable (permission): $SCRIPT_DIR/secrets.lib.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/secrets.lib.sh"
if ! declare -F die1 >/dev/null 2>&1 || ! declare -F ok >/dev/null 2>&1; then
  echo "error: $SCRIPT_DIR/secrets.lib.sh is outdated — it lacks the output layer" >&2
  echo "  (ok/warn/err/die1/die2/debug). Re-fetch the latest scripts from the repo:" >&2
  echo "  wget -O /tmp/vps.tar.gz https://codeload.github.com/ArchivalEra/vps-related/tar.gz/refs/heads/main" >&2
  echo "  rm -rf /tmp/vps-related-main && tar xzf /tmp/vps.tar.gz -C /tmp" >&2
  echo "  cp /tmp/vps-related-main/sing-box/scripts/gen-server.sh /tmp/vps-related-main/sing-box/scripts/secrets.lib.sh \$SCRIPT_DIR/" >&2
  exit 1
fi

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

# ---------- Instance state (filled by secrets_instantiate; read by renderers) ----------
PROTOCOLS=""            # ordered proto list (repeats allowed)
INST_TAGS=""            # ordered unique instance tags
declare -A INST_PORTS=()   # instance tag → port
declare -A INST_SS_METHOD=()   # instance tag → ss method
CHAIN_SS=0              # first shadowtls binds an internal ss (detour)
CHAIN_SS_PORT_VAL=8389

# ---------- IDN (non-ASCII domain) warning ----------
check_domain() {
  if printf '%s' "$DOMAIN" | LC_ALL=C grep -q '[^ -~]'; then
    warn "domain contains non-ASCII chars (IDN): TLS SNI requires punycode (xn--...). Convert the domain (e.g. 'idn2' or a punycode converter) or TLS handshakes will fail."
  fi
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
  if [[ " $PROTOCOLS " == *" shadowtls "* ]]; then
    read -r -p "  Bind chained ss2022 (detour) for shadowtls? [Y/n]: " ans
    if [[ "${ans:-Y}" =~ ^[Yy] ]]; then
      CHAIN_SS=1
      read -r -p "  chain ss port [8389]: " p
      CHAIN_SS_PORT_VAL="${p:-8389}"
    fi
  fi
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

# ---------- Selection: --test bypasses; else flag-driven or interactive ----------
if [[ $TEST_MODE -eq 1 ]]; then
  : # --test sets its own selection below
elif [[ -n "$PROTOCOLS_ARG" ]]; then
  if [[ -n "$PORTS_ARG" ]]; then
    secrets_instantiate --protocols "$PROTOCOLS_ARG" --ports "$PORTS_ARG"
  else
    secrets_instantiate --protocols "$PROTOCOLS_ARG"
  fi
  if [[ -n "$SS_METHODS_ARG" ]]; then
    # shellcheck disable=SC2034  # n / mv used in loop; e is legacy placeholder
    n=0
    IFS=',' read -ra mv <<< "$SS_METHODS_ARG"
    for t in $INST_TAGS; do
      [[ "${t%%-*}" == "shadowsocks" ]] || continue
      [[ $n -lt ${#mv[@]} ]] || die1 "--ss-methods has fewer entries than ss instances"
      # INST_SS_METHOD consumed by render_shadowsocks in secrets.lib.sh
      # shellcheck disable=SC2034
      INST_SS_METHOD[$t]="${mv[$n]}"; n=$((n+1))
    done
  fi
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
  # instantiate via lib (pure memory, declare -n back to INST_TAGS/INST_PORTS)
  secrets_instantiate --protocols "$(echo "$PROTOCOLS" | tr ' ' ',')"
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
  # Cert is needed by inbounds that terminate TLS with a real cert (hy2 / tuic /
  # anytls / naive) and by ws/grpc when NOT CDN-fronted. reality/shadowtls/ss never
  # need it. With --cdn the ws+grpc pair drops out of the requirement set.
  needs_cert=0
  p=""
  for p in $PROTOCOLS; do
    case "$p" in
      hysteria2|tuic|anytls|naive) needs_cert=1 ;;
      vless-ws|vless-grpc) [[ $CDN -eq 0 ]] && needs_cert=1 ;;
    esac
  done
  if [[ $needs_cert -eq 1 ]]; then
    if [[ "$CERT_FILE" == "/your/cert/at/here" || "$KEY_FILE" == "/your/key/at/here" ]]; then
      die1 "--certpath/--keypath must point at real cert/key files (defaults are placeholders)"
    fi
    [[ -r "$CERT_FILE" ]] || die1 "certificate not readable: $CERT_FILE"
    [[ -r "$KEY_FILE" ]] || die1 "private key not readable: $KEY_FILE"
  fi
  resolve_output_path
  if [[ "$OUTPUT_NAME" == */* ]]; then
    die1 "outputname must be a plain filename (no path): $OUTPUT_NAME"
  fi
  if [[ -e "$SB_OUTPUT" ]]; then
    die1 "refusing to overwrite existing file: $SB_OUTPUT (delete it first, then re-run)"
  fi
  debug "output target: $SB_OUTPUT"
fi

# ---------- --test: self-check ----------
if [[ $TEST_MODE -eq 1 ]]; then
  ok "== running gen-server.sh self-check =="
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$TMPD/key.pem" -out "$TMPD/cert.pem" -days 1 -subj "/CN=127.0.0.1" >/dev/null 2>&1 \
    || { err "self-check: openssl cert generation failed"; exit 1; }
  DOMAIN="127.0.0.1"
  if [[ -n "$PROTOCOLS_ARG" ]]; then
    if [[ -n "$PORTS_ARG" ]]; then
      secrets_instantiate --protocols "$PROTOCOLS_ARG" --ports "$PORTS_ARG"
    else
      secrets_instantiate --protocols "$PROTOCOLS_ARG"
    fi
  else
    secrets_instantiate --protocols "reality,hysteria2,vless-ws,vless-grpc,tuic,shadowtls"
  fi
  CHAIN_SS=1; CHAIN_SS_PORT_VAL=8389
  test_out="$TMPD/config-server.json"
  render_config "$TMPD/cert.pem" "$TMPD/key.pem" "$test_out" || { err "self-check: generation failed"; exit 1; }
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
PUB=""
render_config "$CERT_FILE" "$KEY_FILE" "$SB_OUTPUT" || exit 1
PUB="$GEN_PUB"
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
if [[ $CDN -eq 1 ]]; then
  ok "cdn mode: ws/grpc origins are plain (edge terminates TLS)"
  ok "cloudflared: run one quick tunnel per origin port, e.g."
  ok "  cloudflared tunnel --url http://127.0.0.1:<ws-port>    # vless-ws"
  ok "  cloudflared tunnel --url http://127.0.0.1:<grpc-port> --http2-origin  # vless-grpc"
  ok "then: gen-client.sh --from-server <out> --addr <trycloudflare-host> --sni <same>"
fi
if [[ $ECH -eq 1 && -f "$TMPD/ech.configs" && -s "$TMPD/ech.configs" ]]; then
  ok "ECH enabled — CONFIGS embedded as comments at the end of $SB_OUTPUT; publish them as the HTTPS/SVCB record for $DOMAIN (clients auto-load via DNS)"
fi
ok "clients: bash gen-client.sh --from-server $SB_OUTPUT --server $DOMAIN"
