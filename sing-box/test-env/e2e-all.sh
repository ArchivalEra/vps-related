#!/usr/bin/env bash
# e2e-all.sh — 转换产物逐线实战（本机双进程：服务端 config → 转换 client.json → 每线 socks + curl 204）
# 用法: bash test-env/e2e-all.sh
# 覆盖: 转换器支持的协议（vless-reality/vless-ws/hy2/shadowtls+ss链/tuic/anytls/ss直连/naive）
# 前置: sing-box 1.14.0-beta.14 二进制（SB_BIN 或默认路径）
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$ROOT/test-env"
BIN="${SB_BIN:-/tmp/sing-box-1.14.0-beta.14-linux-amd64/sing-box}"
GEN="$ROOT/scripts/gen-client.sh"
SRVCFG="$T/server/config.json"
WORK="$(mktemp -d)"
[[ -x "$BIN" ]] || { echo "✗ 缺二进制: $BIN"; exit 1; }
SRV_PID=""; CLI_PID=""
cleanup() { [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null; [[ -n "$CLI_PID" ]] && kill "$CLI_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

echo "=== 0. 准备 test-env（六线 server config） ==="
( cd "$T" && bash setup.sh >/dev/null 2>&1 ) || { echo "✗ setup 失败"; exit 1; }

echo "=== 1. 转换：服务端 config → 客户端 json ==="
SB_OUTPUT="$WORK/client-all.json" SB_BIN="$BIN" bash "$GEN" \
  --from-server "$SRVCFG" --server 127.0.0.1 --insecure --inbound socks:10808 >/dev/null 2>&1 \
  || { echo "✗ 转换失败"; exit 1; }
echo "   ✓ client-all.json"

# 逐线测：改 route.final 为该线 tag，起 client，curl 204
test_line() { # $1=tag
  local tag="$1"
  if [[ "$tag" == "naive" ]]; then
    # naive 无 insecure，cronet 校验严格：本地自签证书过不去，须真证书（VPS 部署场景天然满足）。
    # 转换器产物已 check/凭据/结构验证，连通性留到真证书场景。
    echo "  ⚠ naive 需真证书（无 insecure + cronet 校验），本地自签不测连通；转换产物已 check 验证"
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
    echo "  ✔ $tag 通 (204)"
  else
    echo "  ✗ $tag 不通: $(tail -1 "$WORK/c-$tag.log" | tr '\n' ' ')"
  fi
  kill "$CLI_PID" 2>/dev/null; wait "$CLI_PID" 2>/dev/null; CLI_PID=""
}

echo "=== 2. 起服务端（六线） ==="
"$BIN" run -c "$SRVCFG" >"$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1.5

echo "=== 3. 逐线实战（从转换产物动态取线路，不在产物里的自动跳过） ==="
LINES="$(python3 - "$WORK/client-all.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
# 排除不可独立路由的线：auto/manual/direct/block、shadowtls(链式容器，测 ss-over-st 已覆盖)
skip = {"auto","manual","direct","block","shadowtls"}
print(" ".join(o["tag"] for o in c["outbounds"] if o["tag"] not in skip))
PY
)"
echo "  产物线路: $LINES"
for tag in $LINES; do
  test_line "$tag"
done

echo
echo "=== 完成 ==="
