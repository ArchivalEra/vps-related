#!/usr/bin/env bash
# gen-client.sh — sing-box 客户端配置生成器（单文件版）
#
# 用法:
#   bash gen-client.sh --config /path/to/config.json [--insecure] [--inbound tun|socks[:port]]
#   bash gen-client.sh                                   # 交互式输入 config.json 路径
#
# 参数:
#   --config PATH  config.json 路径（唯一输入：密钥/开关/主机，见 templates/config.gen.json.example）
#   --insecure     自签证书模式（或 config 里 "insecure": true）
#   --inbound tun  默认 TUN 全局；--inbound socks:1080 生成 socks5 本地监听（测试用）
#
# 环境变量: SB_BIN / SB_OUTPUT（默认 /etc/sing-box/client.json）/ SB_HOST / SB_IP
# 退出码: 0=成功  1=参数/依赖/未知键  2=校对/校验失败
#
# ═══════════════════════════════════════════════════════════════════════
# 【版本与破坏性变更速查】——升级 sing-box 二进制前先读这里
# ═══════════════════════════════════════════════════════════════════════
# 本脚本协议模板针对: SINGBOX_VERSION="1.14.0-beta.14"
#
# 完整字段审计 + 变更史 + 升级 SOP 见: docs/protocol-maintenance.md（必读）
# 协议模板唯一真源: scripts/protocols.lib.sh（升级只改它 + 本清单）
#
# 1.13 → 1.14 已确认的破坏性变更（本仓库全部踩过，见 docs/protocol-fields-1.14/）:
#   ① reality.handshake.port           → server_port          （templates/server.json.tpl 同改）
#   ② dns.server 的 address 简写格式    → type 新格式           （已用 type:https / type:local）
#   ③ dns.strategy: ipv4_first         → prefer_ipv4
#   ④ 缺 domain_resolver               → route.default_domain_resolver（已配，指 remote）
#   ⑤ Reality 密钥必须 URL-safe raw base64（无 +/=，含 -_）—— 服务端生成时 tr '+/' '-_'
#   ⑥ wireguard outbound 已删除        → 用顶层 endpoints 数组的 endpoint 形态
#   ⑦ vless 无 xhttp transport         → 只有 http/ws/quic/grpc/httpupgrade（xhttp 1.15 才有）
#   ⑧ naive 无 insecure 选项           → 必须真证书（libcronet.so 与二进制同目录）
#
# 升级到新版本时的动作（举例 1.15）:
#   1. 改 SINGBOX_VERSION 常量
#   2. 跑脚本生成 → 若 sing-box check 报 unknown field，去 protocols.lib.sh 对应 proto_* 改
#   3. 按 docs/protocol-maintenance.md 的 SOP 走：回归 → 更新清单
#   本脚本自带二进制版本探测：模板版本与检测到的二进制版本 major.minor 不一致会警告。
# ═══════════════════════════════════════════════════════════════════════

SINGBOX_VERSION="1.14.0-beta.14"
SINGBOX_MAJOR_MINOR="1.14"

set -uo pipefail

# ---------- 默认值 ----------
OUTPUT_DEFAULT="/etc/sing-box/client.json"
INSECURE=0
INBOUND_TYPE="tun"
INBOUND_PORT=1080
CONFIG_PATH=""
ARG_INSECURE=0

# ---------- 解析参数 ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) shift; CONFIG_PATH="${1:-}" ;;
    --insecure) ARG_INSECURE=1 ;;
    --inbound)
      shift
      INBOUND_TYPE="${1%%:*}"
      if [[ "$1" == *:* ]]; then INBOUND_PORT="${1#*:}"; fi
      ;;
    *) echo "✗ 未知参数: $1（支持 --config / --insecure / --inbound tun|socks[:port]）" >&2; exit 1 ;;
  esac
  shift
done

# ---------- 交互式输入 config.json 路径（不保存） ----------
if [[ -z "$CONFIG_PATH" ]]; then
  read -r -p "输入 config.json 路径（回车用 /etc/sing-box/config.gen.json）: " CONFIG_PATH
  CONFIG_PATH="${CONFIG_PATH:-/etc/sing-box/config.gen.json}"
fi
if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "✗ config.json 不存在: $CONFIG_PATH" >&2
  echo "  参考模板: templates/config.gen.json.example" >&2
  exit 1
fi

# ---------- 解析 config.json（python3 只做解析，渲染仍在 bash） ----------
command -v python3 >/dev/null 2>&1 || { echo "✗ 需要 python3 解析 config.json" >&2; exit 1; }
python3 - "$CONFIG_PATH" > /tmp/gen-client-cfg.env <<'PY'
import json, sys
def norm(v):
    if isinstance(v, bool): return "1" if v else "0"
    return str(v)
c = json.load(open(sys.argv[1]))
for k, v in c.items():
    k = k.upper()
    s = str(v).replace(chr(39), chr(92)+chr(39))
    print(f"{k}='{s}'")
PY
# shellcheck disable=SC1091
. /tmp/gen-client-cfg.env

# ---------- 未知键检测 ----------
KNOWN_KEYS="SERVER_HOST INSECURE REALITY HY2 SHADOWTLS TUIC ANYTLS SS_DIRECT VLESS_WS VMESS_WS TROJAN NAIVE WIREGUARD SB_UUID SB_PUB SB_SHORT HY2_PASS HY2_OBFS SS_PASS ST_PASS TU_UUID ANY_PASS TROJAN_PASS NAIVE_USER NAIVE_PASS WG_PRIV WG_PUB WG_PSK WG_LOCAL_ADDR VLESS_WS_PATH VLESS_WS_HOST VMESS_WS_PATH VMESS_WS_HOST PORT_REALITY PORT_HY2 PORT_ST PORT_TUIC PORT_ANYTLS PORT_SS"
grep -oE '^[A-Z_]+=' /tmp/gen-client-cfg.env | tr -d '=' | while read -r k; do
  grep -qw "$k" <<<"$KNOWN_KEYS" || echo "UNKNOWN:$k"
done > /tmp/gen-client-unknown.txt
if [[ -s /tmp/gen-client-unknown.txt ]]; then
  echo "✗ config.json 含未知键: $(sed 's/UNKNOWN://' /tmp/gen-client-unknown.txt | tr '\n' ' ')" >&2
  exit 1
fi
rm -f /tmp/gen-client-unknown.txt

# ---------- insecure：--insecure 参数 > config 值 ----------
[[ $ARG_INSECURE -eq 1 ]] && INSECURE=1
[[ "${INSECURE:-0}" == "1" ]] && INSECURE=1 || INSECURE=0

# ---------- 定位 sing-box 二进制 + 版本探测 ----------
SB_BIN="${SB_BIN:-}"
if [[ -z "$SB_BIN" ]]; then
  if command -v sing-box >/dev/null 2>&1; then SB_BIN=$(command -v sing-box)
  elif [[ -x /opt/sing-box/sing-box ]]; then SB_BIN=/opt/sing-box/sing-box
  elif [[ -x "$(dirname "${BASH_SOURCE[0]}")/../bin/sing-box" ]]; then SB_BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin/sing-box"
  else echo "⚠ 未找到 sing-box 二进制，跳过 check 与版本探测" >&2; fi
fi
if [[ -n "$SB_BIN" ]]; then
  DETECTED_MM="$("$SB_BIN" version 2>/dev/null | head -1 | grep -oE 'v[0-9]+\.[0-9]+' | tr -d 'v')"
  if [[ -n "$DETECTED_MM" && "$DETECTED_MM" != "$SINGBOX_MAJOR_MINOR" ]]; then
    echo "⚠ 二进制版本 v$DETECTED_MM ≠ 模板针对 v$SINGBOX_MAJOR_MINOR" >&2
    echo "  字段可能已破坏性变更：查文件头【版本与破坏性变更速查】，改 SINGBOX_VERSION 后重试" >&2
  fi
fi

# ---------- 必需字段检查 ----------
MISSING=""
for v in SB_UUID SB_PUB SB_SHORT HY2_PASS HY2_OBFS SS_PASS ST_PASS TU_UUID ANY_PASS; do
  [[ -z "${!v:-}" ]] && MISSING="$MISSING $v"
done
if [[ -n "$MISSING" ]]; then echo "✗ config.json 缺少字段:$MISSING" >&2; exit 1; fi

# ---------- 服务器地址：config server_host > 环境 SB_HOST > SB_IP > 自动探测 ----------
SERVER="${SERVER_HOST:-${SB_HOST:-}}"
if [[ -z "$SERVER" ]]; then
  IP="${SB_IP:-}"
  [[ -z "$IP" ]] && IP=$(curl -4 -s --max-time 6 https://ifconfig.me || curl -4 -s --max-time 6 https://icanhazip.com || true)
  [[ -n "$IP" ]] || { echo "✗ 无 server_host 且无法探测公网 IP，请填 config 的 server_host" >&2; exit 1; }
  SERVER="$IP"
fi

# ---------- 端口（config 优先，环境变量兜底，再默认） ----------
PR="${PORT_REALITY:-${SB_PORT_REALITY:-443}}"; PH="${PORT_HY2:-${SB_PORT_HY2:-443}}"
PST="${PORT_ST:-${SB_PORT_ST:-8443}}"; PT="${PORT_TUIC:-${SB_PORT_TUIC:-8445}}"
PA="${PORT_ANYTLS:-${SB_PORT_ANYTLS:-2083}}"; PS="${PORT_SS:-${SB_PORT_SS:-8388}}"
PVW="${SB_PORT_VLESS_WS:-8446}"; PMW="${SB_PORT_VMESS_WS:-8447}"; PTJ="${SB_PORT_TROJAN:-8448}"
PNV="${SB_PORT_NAIVE:-8449}"; PWG="${SB_PORT_WG:-51820}"

# ---------- TLS 后缀与 SNI（供 protocols.lib.sh 模板使用） ----------
TLS_SUFFIX=""
[[ $INSECURE -eq 1 ]] && TLS_SUFFIX=', "insecure": true'
SNI_DEFAULT="${SNI:-your.domain.example}"
REALITY_SNI="www.microsoft.com"

# ---------- 线路开关与协议模板：source 规范库（唯一真源） ----------
# 协议模板/版本注意事项都在 scripts/protocols.lib.sh；升级只改它。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/protocols.lib.sh"

# 输入变量就绪后渲染（OUTS/TAGS/ST_ON/SS_CHAIN_ON/WG_ON 由 render_lines 填充）
render_lines

# ---------- 校对: 至少一条线 ----------
[[ -n "$OUTS" ]] || { echo "✗ 未启用任何线路（开关全关）" >&2; exit 2; }

# ---------- 校对: shadowtls↔ss 绑定 ----------
if [[ $ST_ON -eq 1 && $SS_CHAIN_ON -eq 1 ]]; then :;
elif [[ $ST_ON -eq 1 && $SS_CHAIN_ON -eq 0 ]]; then
  echo "⚠ 生成了 shadowtls 但无 ss 挂 detour 指向它" >&2
fi

# ---------- 校对: 重复 tag ----------
if [[ $(echo "$TAGS" | tr ',' '\n' | sort | uniq -d | wc -l) -gt 0 ]]; then
  echo "✗ 重复 tag: $(echo "$TAGS" | tr ',' '\n' | sort | uniq -d | tr '\n' ' ')" >&2
  exit 2
fi

# ---------- 组装 outbounds ----------
# wg 是 endpoint（顶层 endpoints），不是 outbound → urltest 测不了，只进 manual
AUTO_REFS=""
for t in $(echo "$TAGS" | tr ',' '\n' | tr -d ' "'); do
  [[ "$t" == "wg" ]] && continue
  AUTO_REFS+="${AUTO_REFS:+, }\"$t\""
done
# manual 引用全部（含 wg）
MANUAL_REFS="\"auto\"${TAGS:+, $TAGS}"
# outbounds: 协议线 + auto(urltest) + manual(selector) + direct + block
OUTBOUNDS_ALL="${OUTS:+$OUTS, }"
OUTBOUNDS_ALL+="{ \"type\": \"urltest\", \"tag\": \"auto\", \"outbounds\": [ ${AUTO_REFS} ], \"url\": \"https://www.gstatic.com/generate_204\", \"interval\": \"3m\" }, "
OUTBOUNDS_ALL+="{ \"type\": \"selector\", \"tag\": \"manual\", \"outbounds\": [ ${MANUAL_REFS} ], \"default\": \"auto\" }, "
OUTBOUNDS_ALL+="{ \"type\": \"direct\", \"tag\": \"direct\" }, { \"type\": \"block\", \"tag\": \"block\" }"

DNS_DETOUR="reality"
echo "$TAGS" | tr ',' '\n' | grep -q '"reality"' || DNS_DETOUR="$(echo "$TAGS" | cut -d'"' -f2)"

# ---------- inbound ----------
if [[ "$INBOUND_TYPE" == "tun" ]]; then
  INBOUND_BLOCK='{ "type": "tun", "tag": "tun-in", "interface_name": "utun225", "mtu": 9000, "auto_route": true, "strict_route": true, "stack": "system" }'
elif [[ "$INBOUND_TYPE" == "socks" ]]; then
  INBOUND_BLOCK="{ \"type\": \"socks\", \"tag\": \"socks-in\", \"listen\": \"127.0.0.1\", \"listen_port\": $INBOUND_PORT }"
else
  echo "✗ 不支持的 --inbound: $INBOUND_TYPE" >&2; exit 1
fi

# ---------- 渲染 ----------
SB_OUTPUT="${SB_OUTPUT:-$OUTPUT_DEFAULT}"
if ! mkdir -p "$(dirname "$SB_OUTPUT")" 2>/dev/null; then
  echo "✗ 无法写入输出目录: $(dirname "$SB_OUTPUT")（root 或 SB_OUTPUT 指定可写路径）" >&2
  exit 1
fi
# wireguard endpoint 段（顶层 endpoints，若有）；outbounds 后逗号固定，EP_JSON 无前导逗号
EP_JSON=""
[[ -n "${EP_S:-}" ]] && EP_JSON="
  \"endpoints\": [
    $EP_S
  ],"
cat > "$SB_OUTPUT" <<EOF
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
  ],$EP_JSON
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "remote",
    "final": "auto",
    "rules": [
      { "ip_cidr": [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8" ], "outbound": "direct" }
    ]
  }
}
EOF

# ---------- sing-box check（语法兜底：版本破坏性变更的最终防线） ----------
if [[ -n "$SB_BIN" ]]; then
  if "$SB_BIN" check -c "$SB_OUTPUT" 2>/tmp/gen-client-check.err; then
    echo "✔ 已生成并通过 sing-box 校验: $SB_OUTPUT"
  else
    echo "✗ 配置校验失败:" >&2; cat /tmp/gen-client-check.err >&2; exit 2
  fi
else
  echo "⚠ 已生成但未校验（无 sing-box 二进制）: $SB_OUTPUT" >&2
fi

rm -f /tmp/gen-client-cfg.env
echo "  服务器: $SERVER   TLS: $([ $INSECURE -eq 1 ] && echo '自签(insecure)' || echo '真证书')   inbound: $INBOUND_TYPE"
echo "  已启用线路: ${TAGS}"
echo "  导入: 官方客户端（SFA/SFI）→ 从文件导入此 JSON"
