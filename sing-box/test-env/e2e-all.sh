#!/usr/bin/env bash
# e2e-all.sh — per-line live test of converted client (local dual process: server config → converted client.json → per-line socks + curl 204)
# Usage: bash test-env/e2e-all.sh
# Covers: converter-supported protocols (vless-reality/vless-ws/hy2/shadowtls+ss-chain/tuic/anytls/ss-direct/naive)
# Prereq: sing-box 1.14.0-beta.14 binary (SB_BIN or default path)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$ROOT/test-env"
# shellcheck disable=SC1091
. "$ROOT/scripts/protocols.lib.sh"   # find_sb_bin (single source of truth for binary discovery)
BIN="$(find_sb_bin)" || { echo "✗ sing-box binary not found (set SB_BIN or add sing-box to PATH)"; exit 1; }
GEN="$ROOT/scripts/gen-client.sh"
SRVCFG="$T/server/config.json"
WORK="$(mktemp -d)"
SRV_PID=""; CLI_PID=""
cleanup() { [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null; [[ -n "$CLI_PID" ]] && kill "$CLI_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

echo "=== 0. prepare test-env (server config) ==="
( cd "$T" && bash setup.sh >/dev/null 2>&1 ) || { echo "✗ setup failed"; exit 1; }

echo "=== 1. convert: server config → client json ==="
SB_OUTPUT="$WORK/client-all.json" SB_BIN="$BIN" bash "$GEN" \
  --from-server "$SRVCFG" --server 127.0.0.1 --insecure --inbound socks:10808 >/dev/null 2>&1 \
  || { echo "✗ conversion failed"; exit 1; }
echo "   ✓ client-all.json"

# per-line test: set route.final to that line tag, start client, curl 204
test_line() { # $1=tag
  local tag="$1"
  if [[ "$tag" == "naive" ]]; then
    # naive has no insecure; cronet strict: local self-signed cert fails, needs real cert (VPS deploy satisfies).
    # converter output already check/credential/structure verified; connectivity deferred to real-cert scenario.
    echo "  ⚠ naive needs real cert (no insecure + cronet strict), local self-signed not tested; converter output check-verified"
    return
  fi
  python3 - "$WORK/client-all.json" "$tag" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
c["route"]["final"] = sys.argv[2]
json.dump(c, open(sys.argv[1] + "." + sys.argv[2] + ".json", "w"))
PY
  "$BIN" run -c "$WORK/client-all.json.$tag.json" >"$WORK/c-$tag.log" 2>&1 &
  CLI_PID=$!
  sleep 1.2
  if curl -s -o /dev/null -w "%{http_code}" --max-time 15 --socks5-hostname 127.0.0.1:10808 https://www.gstatic.com/generate_204 2>/dev/null | grep -q 204; then
    echo "  ✔ $tag OK (204)"
  else
    echo "  ✗ $tag failed: $(tail -1 "$WORK/c-$tag.log" | tr '\n' ' ')"
  fi
  kill "$CLI_PID" 2>/dev/null; wait "$CLI_PID" 2>/dev/null; CLI_PID=""
}

echo "=== 2. start server ==="
"$BIN" run -c "$SRVCFG" >"$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1.5

echo "=== 3. per-line live test (lines taken from converted output, skip absent) ==="
LINES="$(python3 - "$WORK/client-all.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
# exclude non-routable lines: auto/manual/direct/block, shadowtls (chain container, covered by ss-over-st)
skip = {"auto","manual","direct","block","shadowtls"}
print(" ".join(o["tag"] for o in c["outbounds"] if o["tag"] not in skip))
PY
)"
echo "  converted lines: $LINES"
for tag in $LINES; do
  test_line "$tag"
done

echo
echo "=== done ==="
