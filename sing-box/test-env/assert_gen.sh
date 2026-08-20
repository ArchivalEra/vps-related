#!/usr/bin/env bash
# assert_gen.sh — conversion behavior assertions for gen-client.sh
# Usage: bash test-env/assert_gen.sh [server_config.json]
# Extracted from protocols.lib.sh:assert_gen — test harness owns temp dirs and assertions; lib stays pure.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
TEST_DIR="$ROOT/test-env"
# shellcheck disable=SC1091
source "$ROOT/scripts/protocols.lib.sh"

SRVCFG="${1:-$TEST_DIR/server/config.json}"
GEN="$ROOT/scripts/gen-client.sh"
if [[ ! -f "$SRVCFG" ]]; then
  warn "missing server config $SRVCFG, running bash test-env/setup.sh first"
  ( cd "$TEST_DIR" && bash setup.sh >/dev/null 2>&1 ) || { err "setup.sh failed"; exit 1; }
fi
TMPD2="$(mktemp -d)" || die1 "cannot create temp dir"
trap 'rm -rf "$TMPD2"' EXIT
PASS=0; FAIL=0
debug "assert_gen: TMPD=$TMPD2 SRVCFG=$SRVCFG"

check() { if [[ "$3" -eq "$2" ]]; then echo "  ✔ $1"; PASS=$((PASS+1)); else echo "  ✗ $1 (expected exit $2, got $3) ${4:-}"; FAIL=$((FAIL+1)); fi; }
run_gen() {
  SB_OUTPUT="$TMPD2/out.json" bash "$GEN" --from-server "$1" --addr 127.0.0.1 --insecure "${2:-}" >"$TMPD2/log.txt" 2>&1
  echo "$?"
}

echo "=== A. argument/dependency errors (exit 1) ==="
code=$(run_gen /nonexistent.json);         check "server config missing → 1" 1 "$code"
echo "=== B. conversion failure (exit 2) ==="
python3 -c "import json;json.dump({'inbounds':[]},open('$TMPD2/empty.json','w'))"
code=$(run_gen "$TMPD2/empty.json");       check "empty inbounds → 2" 2 "$code"
echo "=== C. 9-line conversion structure (exit 0 + structure) ==="
code=$(run_gen "$SRVCFG");                 check "9-line conversion → 0" 0 "$code"
if ! python3 - "$TMPD2/out.json" <<'PY'
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
then
  FAIL=$((FAIL+1))
fi
echo "=== D. idempotency ==="
code=$(run_gen "$SRVCFG"); check "idempotent run 1 → 0" 0 "$code"
M1=$(md5sum "$TMPD2/out.json" | cut -d' ' -f1)
code=$(run_gen "$SRVCFG"); check "idempotent run 2 → 0" 0 "$code"
M2=$(md5sum "$TMPD2/out.json" | cut -d' ' -f1)
if [[ "$M1" == "$M2" ]]; then echo "  ✔ both runs identical"; PASS=$((PASS+1)); else echo "  ✗ idempotency failed"; FAIL=$((FAIL+1)); fi

echo
echo "=== Result: passed $PASS / $((PASS+FAIL)) ==="
[[ $FAIL -eq 0 ]]
