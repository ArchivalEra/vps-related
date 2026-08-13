#!/usr/bin/env bash
# run-test.sh — 真实链路测试：本机起 server + client，逐线 curl 验证六线通不通
# 用法: bash test-env/run-test.sh [--insecure]
# 前置: 先跑 bash test-env/setup.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$ROOT/test-env"
BIN="/tmp/sing-box-1.14.0-beta.14-linux-amd64/sing-box"
[[ -x "$BIN" ]] || { echo "✗ 缺二进制: $BIN"; exit 1; }

INSECURE=0
[[ "${1:-}" == "--insecure" ]] && INSECURE=1
. "$T/secrets/env.sh"
INS=$([[ $INSECURE -eq 1 ]] && echo ', "insecure": true' || echo '')

# 单线 outbound 渲染函数：$1=线路名，输出 outbounds 数组体
single_out() {
  local line="$1"
  case "$line" in
    reality) cat <<EOF
{ "type": "vless", "tag": "out", "server": "127.0.0.1", "server_port": 10001, "uuid": "$SB_UUID", "flow": "xtls-rprx-vision", "packet_encoding": "xudp", "tls": { "enabled": true, "server_name": "www.microsoft.com", "utls": { "enabled": true, "fingerprint": "chrome" }, "reality": { "enabled": true, "public_key": "$SB_PUB", "short_id": "$SB_SHORT" } } }
EOF
      ;;
    hy2) cat <<EOF
{ "type": "hysteria2", "tag": "out", "server": "127.0.0.1", "server_port": 10002, "password": "$HY2_PASS", "obfs": { "type": "salamander", "password": "$HY2_OBFS" }, "tls": { "enabled": true, "server_name": "your.domain.example"$INS } }
EOF
      ;;
    ss-over-st) cat <<EOF
{ "type": "shadowsocks", "tag": "out", "server": "127.0.0.1", "server_port": 10003, "method": "2022-blake3-aes-256-gcm", "password": "$SS_PASS", "detour": "shadowtls-out" },
    { "type": "shadowtls", "tag": "shadowtls-out", "server": "127.0.0.1", "server_port": 10003, "version": 3, "password": "$ST_PASS", "tls": { "enabled": true, "server_name": "www.microsoft.com", "utls": { "enabled": true, "fingerprint": "chrome" } } }
EOF
      ;;
    tuic) cat <<EOF
{ "type": "tuic", "tag": "out", "server": "127.0.0.1", "server_port": 10005, "uuid": "$TU_UUID", "password": "$ST_PASS", "congestion_control": "bbr", "tls": { "enabled": true, "server_name": "your.domain.example"$INS } }
EOF
      ;;
    anytls) cat <<EOF
{ "type": "anytls", "tag": "out", "server": "127.0.0.1", "server_port": 10006, "password": "$ANY_PASS", "tls": { "enabled": true, "server_name": "your.domain.example"$INS } }
EOF
      ;;
    ss2022) cat <<EOF
{ "type": "shadowsocks", "tag": "out", "server": "127.0.0.1", "server_port": 10004, "method": "2022-blake3-aes-256-gcm", "password": "$SS_PASS" }
EOF
      ;;
  esac
}

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null
  [[ -n "${CLI_PID:-}" ]] && kill "$CLI_PID" 2>/dev/null
  rm -f /tmp/te-client-*.json
}
trap cleanup EXIT

echo "=== 1. 启动 server (127.0.0.1:10001-10006) ==="
"$BIN" run -c "$T/server/config.json" >/tmp/te-server.log 2>&1 &
SRV_PID=$!
sleep 1.5
if grep -qi "error\|fatal" /tmp/te-server.log; then echo "✗ server 启动失败:"; cat /tmp/te-server.log; exit 1; fi
ss -tlnup 2>/dev/null | grep -E ':1000[1-6]' | awk '{print "  监听:", $4}'

echo
echo "=== 2. 逐线实测（curl 走 socks5 打 gstatic 204） ==="
PASS=0; FAIL=0
for line in reality hy2 ss-over-st tuic anytls ss2022; do
  OUTS="$(single_out "$line")"
  cat > /tmp/te-client-${line}.json <<EOF
{
  "log": { "level": "error", "timestamp": true },
  "inbounds": [ { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 10808 } ],
  "outbounds": [
    $OUTS,
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": { "final": "out", "rules": [ { "ip_cidr": [ "127.0.0.0/8" ], "outbound": "direct" } ] }
}
EOF
  if ! "$BIN" check -c /tmp/te-client-${line}.json 2>/tmp/te-check.err; then
    echo "  ✗ $line check 失败: $(cat /tmp/te-check.err)"; FAIL=$((FAIL+1)); continue
  fi
  "$BIN" run -c /tmp/te-client-${line}.json >/tmp/te-client-${line}.log 2>&1 &
  CLI_PID=$!
  sleep 1.2
  if curl -s -o /dev/null -w "%{http_code}" --max-time 12 --socks5-hostname 127.0.0.1:10808 https://www.gstatic.com/generate_204 2>/dev/null | grep -q 204; then
    echo "  ✔ $line 通"; PASS=$((PASS+1))
  else
    echo "  ✗ $line 不通: $(tail -1 /tmp/te-client-${line}.log | tr '\n' ' ')"; FAIL=$((FAIL+1))
  fi
  kill "$CLI_PID" 2>/dev/null; wait "$CLI_PID" 2>/dev/null; CLI_PID=""
done

echo
echo "=== 结果: 通过 $PASS / 6 ==="
echo "=== 3. 全量 client.json（gen-client.sh 生成 + socks inbound）check ==="
# 由 secrets 生成 test 用 config.gen.json（gen-client.sh 新驱动方式：--config）
. "$T/secrets/env.sh"
python3 - "$T" > /tmp/te-config.gen.json <<'PY'
import json, sys, base64
T = sys.argv[1]
env = {}
for line in open(f"{T}/secrets/env.sh"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        env[k] = v.strip("'")
c = {
    "server_host": "127.0.0.1", "insecure": True,
    "reality": 1, "hy2": 1, "shadowtls": 1, "tuic": 1, "anytls": 1,
    "ss_direct": 0, "vless_ws": 0, "vmess_ws": 0, "trojan": 0, "naive": 0, "wireguard": 0,
    "sb_uuid": env.get("SB_UUID",""), "sb_pub": env.get("SB_PUB",""),
    "sb_short": env.get("SB_SHORT",""), "hy2_pass": env.get("HY2_PASS",""),
    "hy2_obfs": env.get("HY2_OBFS",""), "ss_pass": env.get("SS_PASS",""),
    "st_pass": env.get("ST_PASS",""), "tu_uuid": env.get("TU_UUID",""),
    "any_pass": env.get("ANY_PASS",""),
    "port_reality": 10001, "port_hy2": 10002, "port_st": 10003,
    "port_tuic": 10005, "port_anytls": 10006, "port_ss": 10004,
}
json.dump(c, open("/tmp/te-config.gen.json","w"), indent=2)
PY
SB_OUTPUT="$T/client/client.json" SB_BIN="$BIN" \
  bash "$ROOT/scripts/gen-client.sh" --config /tmp/te-config.gen.json --inbound socks:10809
echo "  (check 失败会输出错误详情)"
