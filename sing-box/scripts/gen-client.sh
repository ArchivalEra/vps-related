#!/usr/bin/env bash
# gen-client.sh — server config.json → client client.json converter
#
# Usage:
#   bash gen-client.sh --from-server /path/config.json [--server host] [--outputname NAME] [--outputpath DIR] [--insecure] [--inbound tun|socks[:port]] [--debug]
#   bash gen-client.sh --test                                    # run self-check assertions
#
# Input: server sing-box config.json (single input; contains all protocols/keys/ports)
# Output: client client.json (import into official SFA/SFI from file)
# No intermediate config file (config.gen.json / secrets.env removed).
#
# Args:
#   --from-server PATH  server config.json path (required unless --test)
#   --server host/IP    client connect address (domain for dual-stack; default prompts interactively, never probes local IP)
#   --outputname NAME   output filename (default config-client.json; spaces/non-ASCII OK, filename only, no path)
#   --outputpath DIR    output directory (default: this script's own dir)
#   --insecure          add insecure:true when cert is self-signed (omit with real cert)
#   --inbound tun       default TUN global; --inbound socks:1080 generates socks5 local listener (testing)
#   --debug             diagnostic output (fully silent by default)
#   --test              run assert_gen self-check then exit
#
# Env: SB_BIN / SB_OUTPUT (full output path override) / DEBUG
# Exit codes: 0=ok  1=argument/dependency  2=conversion/check failure (contract, assert_gen depends on it)
#
# ═══════════════════════════════════════════════════════════════════════
# 【Version policy】— auto-detect sing-box binary version, confirm compatibility via timeline
# Baseline 1.14.0-beta.14; timeline table in protocols.lib.sh VERSION_TABLE.
# To upgrade to 1.15+: add a row to VERSION_TABLE + adapt convert_xxx() per maintenance doc; check is the net.
# Full field audit + breaking-change history + upgrade SOP: docs/protocol-maintenance.md
# ═══════════════════════════════════════════════════════════════════════

set -uo pipefail

# ---------- Defaults ----------
OUTPUT_NAME_DEFAULT="config-client.json"
OUTPUT_NAME=""
OUTPUT_PATH=""
INSECURE=0
INBOUND_TYPE="tun"
INBOUND_PORT=1080
CONFIG_PATH=""
SERVER=""
ARG_INSECURE=0
TEST_MODE=0
DEBUG="${DEBUG:-0}"

# ---------- Parse args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-server) shift; CONFIG_PATH="${1:-}" ;;
    --server) shift; SERVER="${1:-}" ;;
    --outputname) shift; OUTPUT_NAME="${1:-}" ;;
    --outputpath) shift; OUTPUT_PATH="${1:-}" ;;
    --insecure) ARG_INSECURE=1 ;;
    --debug) DEBUG=1 ;;
    --test) TEST_MODE=1 ;;
    --inbound)
      shift
      INBOUND_TYPE="${1%%:*}"
      if [[ "$1" == *:* ]]; then INBOUND_PORT="${1#*:}"; fi
      ;;
    *) die1 "unknown argument: $1 (supported: --from-server / --server / --outputname / --outputpath / --insecure / --debug / --inbound / --test)" ;;
  esac
  shift
done

# ---------- Source: common output layer first, then conversion library ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/common.lib.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/protocols.lib.sh"

# ---------- Temp dir ----------
TMPD="$(mktemp -d)" || die1 "cannot create temp dir"
trap 'rm -rf "$TMPD"' EXIT
debug "temp dir: $TMPD"

# ---------- --test: self-check then exit ----------
if [[ $TEST_MODE -eq 1 ]]; then
  ok "== running gen-client.sh self-check (assert_gen) =="
  assert_gen
  exit $?
fi

# ---------- Input checks ----------
[[ -n "$CONFIG_PATH" ]] || die1 "must specify server config.json via --from-server"
[[ -f "$CONFIG_PATH" ]] || die1 "server config.json not found: $CONFIG_PATH"
[[ -r "$CONFIG_PATH" ]] || die1 "server config.json unreadable (permission): $CONFIG_PATH (add --debug for details)"
debug "server config: $CONFIG_PATH"

# ---------- Parse server config (python3 parses, bash converts) ----------
# sing-box's JSON parser accepts // comments (we append ECH CONFIGS there); python's
# json.load does not — strip comment lines before parsing.
command -v python3 >/dev/null 2>&1 || die1 "python3 required to parse config.json"
if ! python3 - "$CONFIG_PATH" "$TMPD" <<'PY'
import json, sys, os, re
raw = open(sys.argv[1]).read()                       # original (may carry // ECH CONFIGS comments)
stripped = re.sub(r'(?m)^[ \t]*//.*$', '', raw)      # sing-box accepts comments; python json does not
c = json.loads(stripped)
ibs = c.get("inbounds", [])
if not isinstance(ibs, list): ibs = []
json.dump(ibs, open(os.path.join(sys.argv[2], "inbounds.json"), "w"))
open(os.path.join(sys.argv[2], "server-orig.txt"), "w").write(raw)   # keep original for ECH CONFIGS extraction
PY
then
  die1 "failed to parse server config.json (corrupt JSON or unreadable): $CONFIG_PATH (add --debug for details)"
fi
INBOUND_COUNT="$(python3 -c "import json;print(len(json.load(open('$TMPD/inbounds.json'))))")"
if [[ -z "$INBOUND_COUNT" ]]; then
  die1 "failed to parse server config.json (no inbounds index produced): $CONFIG_PATH (add --debug for details)"
fi
if [[ "$INBOUND_COUNT" -eq 0 ]]; then
  die2 "server config has no inbounds"
fi
debug "inbounds: $INBOUND_COUNT"

# ---------- Version detection (timeline compatibility) ----------
SB_BIN="${SB_BIN:-}"
if [[ -z "$SB_BIN" ]]; then
  SB_BIN="$(find_sb_bin)" || SB_BIN=""
  [[ -n "$SB_BIN" ]] || warn "sing-box binary not found, skipping check and version detection"
fi
if [[ -n "$SB_BIN" ]]; then
  DETECTED="$(timeout 5 "$SB_BIN" version 2>/dev/null | head -1 | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -1 | tr -d 'v')"
  check_version "$DETECTED"
  debug "sing-box: $SB_BIN (v${DETECTED:-unknown})"
fi

# ---------- Client connect address (--server or interactive; never probes local IP; domain/IPv4/IPv6 all accepted) ----------
if [[ -z "$SERVER" ]]; then
  read -r -p "Enter client connect address (domain dual-stack / IPv4 / IPv6): " SERVER
  [[ -n "$SERVER" ]] || die1 "must provide connect address (--server arg or interactive input)"
  debug "interactive input: $SERVER"
else
  debug "server: $SERVER"
fi

# ---------- insecure ----------
[[ $ARG_INSECURE -eq 1 ]] && INSECURE=1

# ---------- Convert: server inbounds → client outbounds ----------
render_from_server

# ---------- Validate: at least one line ----------
[[ -n "$OUTS" ]] || die2 "no lines converted"

# ---------- Validate: duplicate tags ----------
if [[ $(echo "$TAGS" | tr ' ' '\n' | sort | uniq -d | wc -l) -gt 0 ]]; then
  die2 "duplicate tags: $(echo "$TAGS" | tr ' ' '\n' | sort | uniq -d | tr '\n' ' ')"
fi

# ---------- Assemble outbounds ----------
# TAGS is space-separated bare tags; quote with JSON commas for arrays (awk trims whitespace)
QUOTED_TAGS="$(echo "$TAGS" | awk '{for(i=1;i<=NF;i++) printf "\"%s\"%s", $i, (i==NF?"\n":", ") }')"
AUTO_REFS="$QUOTED_TAGS"
MANUAL_REFS="\"auto\"${QUOTED_TAGS:+, $QUOTED_TAGS}"
OUTBOUNDS_ALL="${OUTS:+$OUTS, }"
OUTBOUNDS_ALL+="{ \"type\": \"urltest\", \"tag\": \"auto\", \"outbounds\": [ ${AUTO_REFS} ], \"url\": \"https://www.gstatic.com/generate_204\", \"interval\": \"3m\" }, "
OUTBOUNDS_ALL+="{ \"type\": \"selector\", \"tag\": \"manual\", \"outbounds\": [ ${MANUAL_REFS} ], \"default\": \"auto\" }, "
OUTBOUNDS_ALL+="{ \"type\": \"direct\", \"tag\": \"direct\" }, { \"type\": \"block\", \"tag\": \"block\" }"

DNS_DETOUR="reality"
echo "$TAGS" | tr ' ' '\n' | grep -q '^reality$' || DNS_DETOUR="$(echo "$TAGS" | cut -d' ' -f1)"

# ---------- inbound ----------
if [[ "$INBOUND_TYPE" == "tun" ]]; then
  INBOUND_BLOCK='{ "type": "tun", "tag": "tun-in", "interface_name": "utun225", "mtu": 9000, "auto_route": true, "strict_route": true, "stack": "system" }'
elif [[ "$INBOUND_TYPE" == "socks" ]]; then
  INBOUND_BLOCK="{ \"type\": \"socks\", \"tag\": \"socks-in\", \"listen\": \"127.0.0.1\", \"listen_port\": $INBOUND_PORT }"
else
  die1 "unsupported --inbound: $INBOUND_TYPE (tun or socks[:port])"
fi

# ---------- Output path resolution ----------
# Priority: SB_OUTPUT env (full path) > --outputpath + --outputname > --outputname > --outputpath > default $SCRIPT_DIR/config-client.json
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
# Overwrite protection: never clobber the server config
srv_real="$(realpath -m "$CONFIG_PATH" 2>/dev/null || echo "$CONFIG_PATH")"
out_real="$(realpath -m "$SB_OUTPUT" 2>/dev/null || echo "$SB_OUTPUT")"
if [[ "$srv_real" == "$out_real" ]]; then
  die1 "refusing to overwrite server config: $CONFIG_PATH (overwrite disabled by default; pick a different --outputname/--outputpath)"
fi
debug "output target: $SB_OUTPUT"

# ---------- Render ----------
if ! mkdir -p "$(dirname "$SB_OUTPUT")" 2>/dev/null; then
  die1 "cannot write output dir (permission?): $(dirname "$SB_OUTPUT") (add --debug for details)"
fi
if ! cat > "$SB_OUTPUT" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "dns": {
    "servers": [
      { "type": "https", "tag": "remote", "server": "8.8.8.8", "server_port": 443, "path": "/dns-query", "detour": "$DNS_DETOUR" },
      { "type": "local", "tag": "local" }
    ],
    "final": "remote",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    $INBOUND_BLOCK
  ],
  "outbounds": [
    $OUTBOUNDS_ALL
  ],
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "local",
    "final": "auto",
    "rules": [
      { "ip_cidr": [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8" ], "outbound": "direct" }
    ]
  }
}
EOF
then
  die1 "cannot write output file (permission?): $SB_OUTPUT (add --debug for details)"
fi
if [[ ! -s "$SB_OUTPUT" ]]; then
  die1 "output file empty after write (disk full?): $SB_OUTPUT (add --debug for details)"
fi
# Carry the server's ECH CONFIGS comment block into the client config tail
# (single artifact; sing-box accepts // comments)
if grep -q '^// ECH CONFIGS' "$TMPD/server-orig.txt" 2>/dev/null; then
  grep '^// ' "$TMPD/server-orig.txt" >> "$SB_OUTPUT"
  debug "ECH CONFIGS comment block appended to client output"
fi
debug "output written: $SB_OUTPUT"

# ---------- sing-box check (syntax net: final arbiter for breaking changes) ----------
if [[ -n "$SB_BIN" ]]; then
  if timeout 15 "$SB_BIN" check -c "$SB_OUTPUT" 2>"$TMPD/check.err"; then
    ok "generated and passed sing-box check: $SB_OUTPUT"
  else
    err "config check failed:"; cat "$TMPD/check.err" >&2
    exit 2
  fi
else
  warn "generated but not checked (no sing-box binary): $SB_OUTPUT"
fi

ok "server: $CONFIG_PATH → client: $SB_OUTPUT"
ok "connect address: $SERVER   TLS: $([ $INSECURE -eq 1 ] && echo 'self-signed(insecure)' || echo 'real cert')   inbound: $INBOUND_TYPE"
ok "lines enabled: ${TAGS}"
ok "import: official client (SFA/SFI) → import from file"
