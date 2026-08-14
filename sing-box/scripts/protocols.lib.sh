#!/usr/bin/env bash
# protocols.lib.sh — sing-box client protocol conversion library (single source of truth, sourced by gen-client.sh)
#
# Architecture: server config.json → conversion → client client.json (single input/output, no intermediate config)
# Usage: sourced by gen-client.sh; after parsing server config, call convert_xxx() per inbound, then render_from_server()
#
# 【When upgrading sing-box】:
#   1. Add a version row to VERSION_TABLE (timeline)
#   2. If the new version changed fields: update the corresponding convert_xxx() (gen-client.sh version probe + check are the net)
#   3. If a new protocol was added: add convert_xxx() + register it in render_from_server()'s dispatch table
# Full field audit + breaking-change history + upgrade SOP: docs/protocol-maintenance.md

# ---------- Output tiers (ok/warn/err/debug; debug is fully silent unless --debug) ----------
DEBUG="${DEBUG:-0}"
ok()    { echo "$@"; }                        # success/result line → stdout
warn()  { echo "⚠ $@" >&2; }                  # warning → stderr
err()   { echo "✗ $@" >&2; }                  # error → stderr
die1()  { err "$@"; exit 1; }                 # error + exit 1 (argument/dependency contract)
die2()  { err "$@"; exit 2; }                 # error + exit 2 (conversion/check contract)
debug() { [[ $DEBUG -eq 1 ]] && echo "[debug] $@" >&2; }   # only with --debug

# ═══════════════════════════════════════════════════════════════════════
# 【Version compatibility timeline】— auto-detect sing-box version, confirm compatibility
# Format: "major.minor:status:note"
#   status: supported=baseline / deprecated_ok=parseable but deprecated fields / future=intercept new syntax
# To upgrade to 1.15+: add a row here + adapt convert_xxx() to new fields; check is the final arbiter
# ═══════════════════════════════════════════════════════════════════════
SINGBOX_VERSION="1.14.0-beta.14"     # baseline version
SINGBOX_MAJOR_MINOR="1.14"
VERSION_TABLE=(
  "1.13:deprecated_ok:legacy DNS address shorthand etc. deprecated but parseable, removed in 1.14"
  "1.14:supported:baseline 1.14.0-beta.14"
  "1.15:future:new transport syntax (xhttp etc.) needs confirmation before generating, see maintenance doc"
)

# Check binary version against timeline; $1=version string (e.g. 1.14.0-beta.14)
check_version() {
  local ver="${1:-}" mm status note
  [[ -z "$ver" ]] && return 0
  mm="$(echo "$ver" | grep -oE '^[0-9]+\.[0-9]+')"
  [[ -z "$mm" ]] && { warn "cannot parse sing-box version: $ver"; return 0; }
  for row in "${VERSION_TABLE[@]}"; do
    local m="${row%%:*}" rest="${row#*:}"
    if [[ "$m" == "$mm" ]]; then
      status="${rest%%:*}" note="${rest#*:}"
      case "$status" in
        supported)  debug "version compatible: v$ver (baseline)"; return 0 ;;
        deprecated_ok) warn "version v$ver: $note"; return 0 ;;
        future)     warn "version v$ver: $note (if errors, adapt fields per maintenance doc)"; return 0 ;;
      esac
    fi
  done
  warn "version v$ver not in compatibility timeline (baseline $SINGBOX_MAJOR_MINOR) — confirm fields before generating"
}

# ---------- X25519 private → public key derivation (server config only has private_key, client needs public_key) ----------
# Input: URL-safe raw base64 private key (43 chars); Output: URL-safe raw base64 public key
derive_pubkey() {
  local priv="$1"
  [[ -z "$priv" ]] && return 1
  # All in one python step (bash vars drop NUL bytes): decode → wrap PKCS#8 DER → write file
  local derfile="${TMPD:-/tmp}/derive-$$.der"
  python3 -c "
import base64, sys
s='''$priv'''
raw=base64.urlsafe_b64decode(s+'='*((4-len(s)%4)%4))
assert len(raw)==32, 'privkey len'
der=bytes.fromhex('302e020100300506032b656e04220420')+raw
open('$derfile','wb').write(der)
" 2>/dev/null || return 1
  # openssl export public key SPKI → tail 32 bytes → URL-safe raw base64
  openssl pkey -inform DER -in "$derfile" -pubout -outform DER 2>/dev/null \
    | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '='
  rm -f "$derfile"
}

# ---------- Conversion functions ----------
# Each convert_xxx() reads one inbound's fields (parsed by python into bash vars) and
# appends to OUTS/TAGS.
# Shared input vars (provided by gen-client.sh): SERVER (client connect address) / INSECURE / TMPD / inbound index
OUTS=""; TAGS=""

# Get field of inbound $1 by dotted path $2; output to stdout
# Path rules: dict → by key; list → numeric segment indexes, else first element (e.g. short_id array)
inb_field() { # $1=inbound index  $2=dotted field path
  local f="${TMPD:-/tmp}/inbounds.json"
  python3 - "$f" "$1" "$2" <<'PY'
import json, sys
ibs = json.load(open(sys.argv[1]))
v = ibs[int(sys.argv[2])]
for k in sys.argv[3].split('.'):
    if isinstance(v, list):
        if k.isdigit():
            try: v = v[int(k)]
            except IndexError: v = ''
        else:
            v = v[0] if v else ''
    elif isinstance(v, dict):
        v = v.get(k, '')
    else:
        v = ''
print(v, end='')
PY
}

convert_vless() { # $1=inbound index — server vless → client vless (reality or ws transport variant)
  local i="$1" uuid flow sni priv short pub port
  uuid="$(inb_field $i 'users.0.uuid')"
  flow="$(inb_field $i 'users.0.flow')"
  sni="$(inb_field $i 'tls.server_name')"
  priv="$(inb_field $i 'tls.reality.private_key')"
  port="$(inb_field $i 'listen_port')"
  [[ -z "$port" || "$port" == "0" ]] && { warn "vless inbound[$i] missing listen_port, skip"; return; }
  # Branch A: reality (has private_key)
  if [[ -n "$priv" ]]; then
    short="$(inb_field $i 'tls.reality.short_id.0')"
    [[ -z "$short" ]] && short="$(inb_field $i 'tls.reality.short_id')"
    local pub
    pub="$(derive_pubkey "$priv")" || { warn "vless inbound[$i] pubkey derivation failed, skip"; return; }
    OUTS+="${OUTS:+, }{ \"type\": \"vless\", \"tag\": \"reality\", \"server\": \"$SERVER\", \"server_port\": $port, \"uuid\": \"$uuid\", \"flow\": \"$flow\", \"packet_encoding\": \"xudp\", \"tls\": { \"enabled\": true, \"server_name\": \"$sni\", \"utls\": { \"enabled\": true, \"fingerprint\": \"chrome\" }, \"reality\": { \"enabled\": true, \"public_key\": \"$pub\", \"short_id\": \"$short\" } } }"
    TAGS+="${TAGS:+, }\"reality\""
    debug "vless[reality] ← inbound[$i] port=$port sni=$sni"
    return
  fi
  # Branch B/C: ws / grpc transport (vless+ws / vless+grpc, self-signed or real cert)
  local ttype ins
  ttype="$(inb_field $i 'transport.type')"
  ins=""
  [[ $INSECURE -eq 1 ]] && ins=', "insecure": true'
  [[ -z "$sni" ]] && sni="$SERVER"    # server config without tls.server_name → use connect address
  case "$ttype" in
    ws)
      local ws_path ws_host
      ws_path="$(inb_field $i 'transport.path')"
      [[ -z "$ws_path" ]] && ws_path="/ws"
      ws_host="$(inb_field $i 'transport.headers.Host')"
      [[ -z "$ws_host" ]] && ws_host="$sni"
      OUTS+="${OUTS:+, }{ \"type\": \"vless\", \"tag\": \"vless-ws\", \"server\": \"$SERVER\", \"server_port\": $port, \"uuid\": \"$uuid\", \"tls\": { \"enabled\": true, \"server_name\": \"$sni\"$ins }, \"transport\": { \"type\": \"ws\", \"path\": \"$ws_path\", \"headers\": { \"Host\": \"$ws_host\" } } }"
      TAGS+="${TAGS:+, }\"vless-ws\""
      debug "vless[ws] ← inbound[$i] port=$port path=$ws_path host=$ws_host"
      ;;
    grpc)
      local service_name
      service_name="$(inb_field $i 'transport.service_name')"
      OUTS+="${OUTS:+, }{ \"type\": \"vless\", \"tag\": \"vless-grpc\", \"server\": \"$SERVER\", \"server_port\": $port, \"uuid\": \"$uuid\", \"tls\": { \"enabled\": true, \"server_name\": \"$sni\"$ins }, \"transport\": { \"type\": \"grpc\", \"service_name\": \"$service_name\" } }"
      TAGS+="${TAGS:+, }\"vless-grpc\""
      debug "vless[grpc] ← inbound[$i] port=$port service=$service_name"
      ;;
    *)
      warn "vless inbound[$i] no reality and transport.type=$ttype (only ws/grpc supported), skip"
      return
      ;;
  esac
}

convert_hy2() { # $1=inbound index — server hysteria2 → client hysteria2
  local i="$1" pass obfs_type obfs_pass
  pass="$(inb_field $i 'users.0.password')"
  obfs_type="$(inb_field $i 'obfs.type')"
  obfs_pass="$(inb_field $i 'obfs.password')"
  local obfs_json=""
  [[ -n "$obfs_type" && -n "$obfs_pass" ]] && obfs_json=", \"obfs\": { \"type\": \"$obfs_type\", \"password\": \"$obfs_pass\" }"
  local ins=""
  [[ $INSECURE -eq 1 ]] && ins=', "insecure": true'
  local port; port="$(inb_field $i 'listen_port')"
  OUTS+="${OUTS:+, }{ \"type\": \"hysteria2\", \"tag\": \"hy2\", \"server\": \"$SERVER\", \"server_port\": $port, \"password\": \"$pass\"$obfs_json, \"tls\": { \"enabled\": true, \"server_name\": \"$SERVER\"$ins } }"
  TAGS+="${TAGS:+, }\"hy2\""
  debug "hy2 ← inbound[$i] port=$port obfs=$obfs_type"
}

convert_shadowtls() { # $1=inbound index — server shadowtls (chain→ss) → client shadowtls + ss(detour)
  local i="$1" pass ver handshake_sni detour_tag ss_in
  pass="$(inb_field $i 'users.0.password')"
  ver="$(inb_field $i 'version')"
  [[ -z "$ver" || "$ver" == "0" ]] && ver=3
  handshake_sni="$(inb_field $i 'handshake.server')"
  local port; port="$(inb_field $i 'listen_port')"
  OUTS+="${OUTS:+, }{ \"type\": \"shadowtls\", \"tag\": \"shadowtls\", \"server\": \"$SERVER\", \"server_port\": $port, \"version\": $ver, \"password\": \"$pass\", \"tls\": { \"enabled\": true, \"server_name\": \"$handshake_sni\", \"utls\": { \"enabled\": true, \"fingerprint\": \"chrome\" } } }"
  TAGS+="${TAGS:+, }\"shadowtls\""
  # Chain: find the ss inbound referenced by detour, emit ss(detour→shadowtls)
  detour_tag="$(inb_field $i 'detour')"
  local n ss_method ss_pass ss_port
  n="$(python3 -c "import json;print(len(json.load(open('$TMPD/inbounds.json'))))")"
  ss_in=""
  for ((j=0; j<n; j++)); do
    local t; t="$(inb_field $j 'type')"
    if [[ "$t" == "shadowsocks" ]]; then
      local tag; tag="$(inb_field $j 'tag')"
      if [[ "$detour_tag" == "$tag" || -z "$detour_tag" ]]; then ss_in=$j; break; fi
    fi
  done
  if [[ -n "$ss_in" ]]; then
    ss_method="$(inb_field $ss_in 'method')"
    ss_pass="$(inb_field $ss_in 'password')"
    ss_port="$(inb_field $ss_in 'listen_port')"
    OUTS+=", { \"type\": \"shadowsocks\", \"tag\": \"ss-over-st\", \"server\": \"$SERVER\", \"server_port\": $ss_port, \"method\": \"$ss_method\", \"password\": \"$ss_pass\", \"detour\": \"shadowtls\" }"
    TAGS+=", \"ss-over-st\""
    debug "shadowtls ← inbound[$i] + ss chain inbound[$ss_in]"
  else
    warn "shadowtls inbound[$i] has no matching ss inbound (detour=$detour_tag), only shadowtls emitted"
  fi
}

convert_tuic() { # $1=inbound index — server tuic → client tuic
  local i="$1" uuid pass cc
  uuid="$(inb_field $i 'users.0.uuid')"
  pass="$(inb_field $i 'users.0.password')"
  cc="$(inb_field $i 'congestion_control')"
  [[ -z "$cc" ]] && cc="bbr"
  local ins=""
  [[ $INSECURE -eq 1 ]] && ins=', "insecure": true'
  local port; port="$(inb_field $i 'listen_port')"
  OUTS+="${OUTS:+, }{ \"type\": \"tuic\", \"tag\": \"tuic\", \"server\": \"$SERVER\", \"server_port\": $port, \"uuid\": \"$uuid\", \"password\": \"$pass\", \"congestion_control\": \"$cc\", \"tls\": { \"enabled\": true, \"server_name\": \"$SERVER\"$ins } }"
  TAGS+="${TAGS:+, }\"tuic\""
  debug "tuic ← inbound[$i] port=$port"
}

convert_anytls() { # $1=inbound index — server anytls → client anytls
  local i="$1" pass
  pass="$(inb_field $i 'users.0.password')"
  local ins=""
  [[ $INSECURE -eq 1 ]] && ins=', "insecure": true'
  local port; port="$(inb_field $i 'listen_port')"
  OUTS+="${OUTS:+, }{ \"type\": \"anytls\", \"tag\": \"anytls\", \"server\": \"$SERVER\", \"server_port\": $port, \"password\": \"$pass\", \"tls\": { \"enabled\": true, \"server_name\": \"$SERVER\"$ins } }"
  TAGS+="${TAGS:+, }\"anytls\""
  debug "anytls ← inbound[$i] port=$port"
}

convert_ss() { # $1=inbound index — direct shadowsocks → client ss (skip ss consumed by shadowtls chain)
  local i="$1" method pass tag
  tag="$(inb_field $i 'tag')"
  if [[ " ${CONSUMED_SS_TAGS:-} " == *" $tag "* ]]; then
    debug "ss inbound[$i]($tag) consumed by shadowtls chain, skip direct conversion"
    return
  fi
  method="$(inb_field $i 'method')"
  pass="$(inb_field $i 'password')"
  local port; port="$(inb_field $i 'listen_port')"
  OUTS+="${OUTS:+, }{ \"type\": \"shadowsocks\", \"tag\": \"ss2022\", \"server\": \"$SERVER\", \"server_port\": $port, \"method\": \"$method\", \"password\": \"$pass\" }"
  TAGS+="${TAGS:+, }\"ss2022\""
  debug "ss ← inbound[$i] port=$port"
}

convert_naive() { # $1=inbound index — server naive → client naive (no insecure; self-signed via certificate_path)
  local i="$1" user pass cert sni
  user="$(inb_field $i 'users.0.username')"
  pass="$(inb_field $i 'users.0.password')"
  sni="$(inb_field $i 'tls.server_name')"
  cert="$(inb_field $i 'tls.certificate_path')"
  local port; port="$(inb_field $i 'listen_port')"
  [[ -z "$port" || "$port" == "0" ]] && { warn "naive inbound[$i] missing listen_port, skip"; return; }
  local cert_json=""
  [[ -n "$cert" ]] && cert_json=", \"certificate_path\": \"$cert\""
  OUTS+="${OUTS:+, }{ \"type\": \"naive\", \"tag\": \"naive\", \"server\": \"$SERVER\", \"server_port\": $port, \"username\": \"$user\", \"password\": \"$pass\", \"tls\": { \"enabled\": true, \"server_name\": \"$sni\"$cert_json } }"
  TAGS+="${TAGS:+, }\"naive\""
  debug "naive ← inbound[$i] port=$port user=$user"
}

# ---------- Entry: iterate server inbounds, convert by type ----------
# Input: $TMPD/inbounds.json (server config's inbounds array)
# Output: OUTS/TAGS (client outbounds fragments)
render_from_server() {
  OUTS=""; TAGS=""
  local ni t j det i
  ni="$(python3 -c "import json;print(len(json.load(open('$TMPD/inbounds.json'))))")"
  # Pre-scan: collect ss tags referenced by shadowtls chains (avoid duplicate direct conversion)
  CONSUMED_SS_TAGS=""
  for ((j=0; j<ni; j++)); do
    t="$(inb_field $j 'type')"
    if [[ "$t" == "shadowtls" ]]; then
      det="$(inb_field $j 'detour')"
      [[ -n "$det" ]] && CONSUMED_SS_TAGS+=" $det"
    fi
  done
  debug "server inbounds: $ni (ss consumed by chains:$CONSUMED_SS_TAGS)"
  for ((i=0; i<ni; i++)); do
    t="$(inb_field $i 'type')"
    case "$t" in
      vless)         convert_vless "$i" ;;
      hysteria2)     convert_hy2 "$i" ;;
      shadowtls)     convert_shadowtls "$i" ;;
      tuic)          convert_tuic "$i" ;;
      anytls)        convert_anytls "$i" ;;
      shadowsocks)   convert_ss "$i" ;;
      naive)         convert_naive "$i" ;;
      *)             warn "inbound[$i] type '$t' unsupported (1.14 client conversion table), skip" ;;
    esac
  done
  [[ -n "$OUTS" ]] || die2 "server config has no convertible inbounds (none of vless/hysteria2/shadowtls/tuic/anytls/shadowsocks)"
}

# ═══════════════════════════════════════════════════════════════════════
# 【Self-check】assert_gen — conversion behavior assertions (invoked by gen-client.sh --test)
# Uses test-env server config (setup.sh) to convert to client.json, asserts structure.
# No intermediate config dependency (config.gen.json/env removed).
# ═══════════════════════════════════════════════════════════════════════
assert_gen() {
  local LIB_DIR ROOT TEST BIN GEN PASS FAIL code M1 M2 TMPD2 SRVCFG
  LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  ROOT="$(dirname "$LIB_DIR")"
  TEST="$ROOT/test-env"
  BIN="${SB_BIN:-/tmp/sing-box-1.14.0-beta.14-linux-amd64/sing-box}"
  GEN="$ROOT/scripts/gen-client.sh"
  SRVCFG="$TEST/server/config.json"
  [[ -x "$BIN" ]] || { err "missing test binary: $BIN"; return 1; }
  if [[ ! -f "$SRVCFG" ]]; then
    warn "missing test-env/server/config.json, running bash test-env/setup.sh first"
    ( cd "$TEST" && bash setup.sh >/dev/null 2>&1 ) || { err "setup.sh failed"; return 1; }
  fi
  TMPD2="$(mktemp -d)" || die1 "cannot create temp dir"
  trap '[[ -n "${TMPD2:-}" ]] && rm -rf "$TMPD2"' EXIT
  PASS=0; FAIL=0
  debug "assert_gen: TMPD=$TMPD2 SRVCFG=$SRVCFG"

  check() { if [[ "$3" -eq "$2" ]]; then echo "  ✔ $1"; PASS=$((PASS+1)); else echo "  ✗ $1 (expected exit $2, got $3) ${4:-}"; FAIL=$((FAIL+1)); fi; }
  run_gen() { # $1=server config  $2=extra args → exit code to stdout
    SB_OUTPUT="$TMPD2/out.json" SB_BIN="$BIN" bash "$GEN" --from-server "$1" --server 127.0.0.1 --insecure ${2:-} >"$TMPD2/log.txt" 2>&1
    echo "$?"
  }

  echo "=== A. argument/dependency errors (exit 1) ==="
  code=$(run_gen /nonexistent.json);         check "server config missing → 1" 1 "$code"
  echo "=== B. conversion failure (exit 2) ==="
  python3 -c "import json;json.dump({'inbounds':[]},open('$TMPD2/empty.json','w'))"
  code=$(run_gen "$TMPD2/empty.json");       check "empty inbounds → 2" 2 "$code"
  echo "=== C. 9-line conversion structure (exit 0 + structure) ==="
  code=$(run_gen "$SRVCFG");                 check "9-line conversion → 0" 0 "$code"
  python3 - "$TMPD2/out.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
errs = []
tags = {o["tag"] for o in c["outbounds"]}
expect = {"reality","hy2","shadowtls","ss-over-st","tuic","anytls","vless-ws","vless-grpc","naive","auto","manual","direct","block"}
if tags != expect: errs.append(f"tag set mismatch: {sorted(tags)} expected {sorted(expect)}")
auto = next(o for o in c["outbounds"] if o["tag"]=="auto")["outbounds"]
manual = next(o for o in c["outbounds"] if o["tag"]=="manual")["outbounds"]
if set(auto) != {"reality","hy2","ss-over-st","tuic","anytls","shadowtls","vless-ws","vless-grpc","naive"}: errs.append(f"auto ref set mismatch: {auto}")
if manual[0] != "auto" or set(manual[1:]) != {"reality","hy2","ss-over-st","tuic","anytls","shadowtls","vless-ws","vless-grpc","naive"}: errs.append(f"manual ref set mismatch: {manual}")
if c["route"]["final"] != "auto": errs.append("route.final not auto")
if c["dns"]["servers"][0].get("detour") != "reality": errs.append("DNS detour not reality")
rv = next(o for o in c["outbounds"] if o["tag"]=="reality")
if not rv["tls"]["reality"].get("public_key"): errs.append("reality pubkey not derived")
if errs:
    print("  ✗ " + "; ".join(errs)); sys.exit(1)
print("  ✔ 8-line conversion structure OK")
PY
  [[ $? -eq 0 ]] || FAIL=$((FAIL+1))
  echo "=== D. idempotency ==="
  code=$(run_gen "$SRVCFG"); check "idempotent run 1 → 0" 0 "$code"
  M1=$(md5sum "$TMPD2/out.json" | cut -d' ' -f1)
  code=$(run_gen "$SRVCFG"); check "idempotent run 2 → 0" 0 "$code"
  M2=$(md5sum "$TMPD2/out.json" | cut -d' ' -f1)
  if [[ "$M1" == "$M2" ]]; then echo "  ✔ both runs identical"; PASS=$((PASS+1)); else echo "  ✗ idempotency failed"; FAIL=$((FAIL+1)); fi

  echo
  echo "=== Result: passed $PASS / $((PASS+FAIL)) ==="
  [[ $FAIL -eq 0 ]]
}
