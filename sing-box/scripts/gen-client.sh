#!/usr/bin/env bash
# gen-client.sh — server config.json → client client.json converter
#
# Usage:
#   bash gen-client.sh --help
#   bash gen-client.sh --from-server /path/config.json [--addr host] [--sni name] [--outputname NAME] [--outputpath DIR] [--insecure] [--inbound tun|socks[:port]] [--debug]
#   bash gen-client.sh --test                                    # run self-check assertions
#
# No flags: prompts for the connect address interactively (TTY). No flags + non-TTY
# stdin (piped) prints "try gen-client.sh --help" and exits 1 — flags are the only batch mode.
#
# Input: server sing-box config.json (single input; contains all protocols/keys/ports)
# Output: client client.json (import into official SFA/SFI from file)
# No intermediate config file (config.gen.json / secrets.env removed).
#
# Args:
#   --help            print the ##help## flag reference and exit 0
#   --from-server PATH  server config.json path (required unless --test)
#   --addr host         client connect address — domain / IPv4 / IPv6, user-supplied
#                       (default prompts interactively, never probes local IP)
#   --sni name          TLS SNI for real-TLS lines (ws/grpc/hy2/tuic/anytls/naive);
#                       default = the connect address (reality/shadowtls keep config-filtered SNI)
#   --outputname NAME   output filename (default config-client.json; spaces/non-ASCII OK, filename only, no path)
#   --outputpath DIR    output directory (default: this script's own dir)
#   --insecure          add insecure:true when cert is self-signed (omit with real cert)
#   --inbound tun       default TUN global; --inbound socks:1080 generates socks5 local listener (testing)
#   --debug             diagnostic output (fully silent by default)
#   --test              run assert_gen self-check then exit
#
# Env: SB_OUTPUT (full output path override) / DEBUG
# Exit codes: 0=ok  1=argument/dependency  2=conversion/structural check failure (contract, assert_gen depends on it)
#
# ═══════════════════════════════════════════════════════════════════════
# 【Version policy】— the client config runs on the *client's* sing-box, so this
# converter validates structure only, never with a local binary: no version probing,
# no sing-box check. Field drift between sing-box versions is handled at the convert
# layer (unknown transport types are skipped with a warning) and at the client
# device's own sing-box check on import. Timeline table in protocols.lib.sh
# VERSION_TABLE is informational. 1.15+ upgrade path: docs/protocol-maintenance.md
# ═══════════════════════════════════════════════════════════════════════

set -uo pipefail

# ---------- Defaults ----------
# shellcheck disable=SC2034  # OUTPUT_NAME_DEFAULT/OUTPUT_PATH read by resolve_output_path() in protocols.lib.sh
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

# ---------- --help: compact flag reference (##help## block, one flag per line) ----------
# Converter: server config.json → client config.json (single input, single output).
help() {
  cat <<'HELP'
gen-client.sh — converter: server config.json → client config.json (single input, single output)

##help##
  --from-server PATH  server config.json path (required unless --test)
  --addr host         client connect address — domain / IPv4 / IPv6, user-supplied (default: interactive prompt)
  --sni name          TLS SNI for real-TLS lines (default: the connect address; reality/shadowtls keep config-filtered SNI)
  --outputname NAME   output filename (default: config-client.json; filename only, no path)
  --outputpath DIR    output directory (default: this script's own dir)
  --insecure          add insecure:true when the cert is self-signed (omit with a real cert)
  --inbound tun|socks[:port]
                      inbound: tun (global) or socks:1080 for a local socks5 listener
  --debug             diagnostic output (fully silent by default)
  --test              run the assert_gen self-check then exit
##help##
HELP
}

# ---------- No flags: TTY → interactive; non-TTY (piped) → point at --help ----------
# `! -t 0` tells a human terminal apart from piped stdin: a pipe can never answer the
# connect-address prompt below, so fail fast instead of hanging until EOF.
if [[ $# -eq 0 && ! -t 0 ]]; then
  echo "try gen-client.sh --help"
  exit 1
fi

# ---------- Parse args ----------
while [[ $# -gt 0 ]]; do
  # shellcheck disable=SC2034
  # OUTPUT_NAME/OUTPUT_PATH are read by resolve_output_path() in protocols.lib.sh
  case "$1" in
    --help) help; exit 0 ;;
    --from-server) shift; CONFIG_PATH="${1:-}" ;;
    --addr) shift; SERVER="${1:-}" ;;
    --sni) shift; SNI_OVERRIDE="${1:-}" ;;
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
    *) die1 "unknown argument: $1 (supported: --from-server / --addr / --sni / --outputname / --outputpath / --insecure / --debug / --inbound / --test)" ;;
  esac
  shift
done

# ---------- Source: conversion library (helpers + render_from_server) ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Fail loudly if the companion lib is missing — a broken source would otherwise
# surface later as a confusing "command not found" from a lib function.
if [[ ! -f "$SCRIPT_DIR/protocols.lib.sh" ]]; then
  echo "error: protocols.lib.sh not found next to gen-client.sh ($SCRIPT_DIR)" >&2
  echo "  deploy both files together (see gen-client.sh.readme.md)" >&2
  exit 1
fi
[[ -r "$SCRIPT_DIR/protocols.lib.sh" ]] || die1 "protocols.lib.sh not readable (permission): $SCRIPT_DIR/protocols.lib.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/protocols.lib.sh"
# The lib may exist but be an OLD version (pre-output-layer) — then die1/ok etc.
# are undefined and every later call fails with a cryptic "command not found".
# Fail once, right here, with the actual fix (re-fetch the latest pair).
if ! declare -F die1 >/dev/null 2>&1 || ! declare -F ok >/dev/null 2>&1; then
  echo "error: $SCRIPT_DIR/protocols.lib.sh is outdated — it lacks the output layer" >&2
  echo "  (ok/warn/err/die1/die2/debug). Re-fetch the latest scripts from the repo:" >&2
  echo "  wget -O /tmp/vps.tar.gz https://codeload.github.com/ArchivalEra/vps-related/tar.gz/refs/heads/main" >&2
  echo "  rm -rf /tmp/vps-related-main && tar xzf /tmp/vps.tar.gz -C /tmp" >&2
  echo "  cp /tmp/vps-related-main/sing-box/scripts/gen-client.sh /tmp/vps-related-main/sing-box/scripts/protocols.lib.sh \$SCRIPT_DIR/" >&2
  exit 1
fi

# ---------- Temp dir ----------
TMPD="$(mktemp -d)" || die1 "cannot create temp dir"
trap 'rm -rf "$TMPD"' EXIT
debug "temp dir: $TMPD"

# ---------- --test: self-check then exit ----------
if [[ $TEST_MODE -eq 1 ]]; then
  ok "== running gen-client.sh self-check (assert_gen via test-env/assert_gen.sh) =="
  bash "$SCRIPT_DIR/../test-env/assert_gen.sh"
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

# ---------- Client connect address (--addr or interactive; never probes local IP; domain/IPv4/IPv6 all accepted) ----------
# The connect address is a *client-side* fact: probing "our own" IP would only discover the
# machine we happen to run on, not how the client will reach the server — so we always ask.
if [[ -z "$SERVER" ]]; then
  read -r -p "Enter client connect address (domain dual-stack / IPv4 / IPv6): " SERVER
  [[ -n "$SERVER" ]] || die1 "must provide connect address (--addr arg or interactive input)"
  debug "interactive input: $SERVER"
else
  debug "addr: $SERVER"
fi
[[ -n "${SNI_OVERRIDE:-}" ]] && debug "sni override: $SNI_OVERRIDE"

# ---------- insecure ----------
[[ $ARG_INSECURE -eq 1 ]] && INSECURE=1

# ---------- Convert: server inbounds → client outbounds ----------
render_from_server

# ---------- Validate: at least one line ----------
[[ -n "$OUTS" ]] || die2 "no lines converted"

# ---------- Validate: duplicate tags ----------
if [[ $(echo "$TAGS" | tr ' ' '
' | sort | uniq -d | wc -l) -gt 0 ]]; then
  die2 "duplicate tags: $(echo "$TAGS" | tr ' ' '
' | sort | uniq -d | tr '
' ' ')"
fi

# ---------- Assemble outbounds ----------
# TAGS is space-separated bare tags; quote with JSON commas for arrays (awk trims whitespace)
QUOTED_TAGS="$(echo "$TAGS" | awk '{for(i=1;i<=NF;i++) printf "\"%s\"%s", $i, (i==NF?"\n":", ") }')"
AUTO_REFS="$QUOTED_TAGS"
MANUAL_REFS="\"auto\"${QUOTED_TAGS:+, $QUOTED_TAGS}"
OUTBOUNDS_ALL="${OUTS:+$OUTS,
        }"
OUTBOUNDS_ALL+="{ \"type\": \"urltest\", \"tag\": \"auto\", \"outbounds\": [ ${AUTO_REFS} ], \"url\": \"https://www.gstatic.com/generate_204\", \"interval\": \"3m\" }"
OUTBOUNDS_ALL+=",
        { \"type\": \"selector\", \"tag\": \"manual\", \"outbounds\": [ ${MANUAL_REFS} ], \"default\": \"auto\" }"
OUTBOUNDS_ALL+=",
        { \"type\": \"direct\", \"tag\": \"direct\" },
        { \"type\": \"block\", \"tag\": \"block\" }"

# DNS detour: reality lines are the most anti-blocking, so DNS prefers one. Prefix
# match (reality / reality-2) — the server emits unique per-instance tags.
DNS_DETOUR="reality"
echo "$TAGS" | tr ' ' '
' | grep -q '^reality' || DNS_DETOUR="$(echo "$TAGS" | cut -d' ' -f1)"

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
resolve_output_path
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

# ---------- Structural self-check (replaces sing-box check) ----------
# The client config runs on the *client's* sing-box, which this machine may not even
# have — validating it here with a server-side binary would be checking the wrong
# thing. The net is a pure structural check: valid JSON, non-empty outbounds, the
# auto/manual selectors present, route/dns wired. Syntax-level field validation is
# the client device's sing-box check at import time.
if ! python3 - "$SB_OUTPUT" <<'PY'
import json, sys
errs = []
try:
    c = json.load(open(sys.argv[1]))
except Exception as e:
    errs.append(f"not valid JSON: {e}")
else:
    outs = c.get("outbounds")
    if not isinstance(outs, list) or not outs:
        errs.append("outbounds missing or empty")
    else:
        tags = [o.get("tag") for o in outs]
        for o in outs:
            if not o.get("type") or not o.get("tag"):
                errs.append(f"outbound missing type/tag: {o.get('type','?')}")
        for need in ("auto", "manual"):
            if need not in tags:
                errs.append(f"missing {need} selector")
    if not c.get("route", {}).get("final"):
        errs.append("route.final missing")
    if not c.get("dns", {}).get("servers"):
        errs.append("dns.servers missing")
if errs:
    print("  ✗ " + "; ".join(errs)); sys.exit(1)
PY
then
  err "structural self-check failed: $SB_OUTPUT"
  exit 2
fi
ok "structural self-check passed: $SB_OUTPUT"

ok "server: $CONFIG_PATH → client: $SB_OUTPUT"
ok "connect address: $SERVER   TLS: $([ $INSECURE -eq 1 ] && echo 'self-signed(insecure)' || echo 'real cert')   inbound: $INBOUND_TYPE"
ok "lines enabled: ${TAGS}"
ok "import: official client (SFA/SFI) → import from file"
