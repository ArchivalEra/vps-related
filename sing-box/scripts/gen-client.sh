#!/usr/bin/env bash
# gen-client.sh — 服务端 config.json → 客户端 client.json 转换器
#
# 用法:
#   bash gen-client.sh --from-server /path/config.json [--server 域名] [--insecure] [--inbound tun|socks[:port]] [--debug]
#   bash gen-client.sh --test                                    # 跑自检断言
#
# 输入: 服务端 sing-box config.json（唯一输入；含全部协议/密钥/端口）
# 输出: 客户端 client.json（官方 SFA/SFI 从文件导入）
# 无任何中间配置文件（config.gen.json / secrets.env 全部废弃）。
#
# 参数:
#   --from-server PATH  服务端 config.json 路径（必填，除非 --test）
#   --server 域名/IP    客户端连接地址（双栈用域名；缺省交互输入，不主动探测本机 IP）
#   --insecure          证书为自签时加 insecure:true（真证书不用）
#   --inbound tun       默认 TUN 全局；--inbound socks:1080 生成 socks5 本地监听（测试用）
#   --debug             输出诊断（默认完全静默）
#   --test              跑 assert_gen 自检后退出
#
# 环境变量: SB_BIN / SB_OUTPUT（默认 /etc/sing-box/client.json）/ DEBUG
# 退出码: 0=成功  1=参数/依赖错误  2=转换/校验失败（契约，assert_gen 依赖）
#
# ═══════════════════════════════════════════════════════════════════════
# 【版本策略】——自动检测 sing-box 二进制版本，按时间线确认兼容
# 基线 1.14.0-beta.14；时间线表在 protocols.lib.sh 的 VERSION_TABLE。
# 将来升 1.15+: 改 VERSION_TABLE 加行 + 按维护清单适配 convert_xxx()，check 兜底。
# 完整字段审计 + 变更史 + 升级 SOP: docs/protocol-maintenance.md
# ═══════════════════════════════════════════════════════════════════════

set -uo pipefail

# ---------- 默认值 ----------
OUTPUT_DEFAULT="/etc/sing-box/client.json"
INSECURE=0
INBOUND_TYPE="tun"
INBOUND_PORT=1080
CONFIG_PATH=""
SERVER=""
ARG_INSECURE=0
TEST_MODE=0
DEBUG="${DEBUG:-0}"

# ---------- 解析参数 ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-server) shift; CONFIG_PATH="${1:-}" ;;
    --server) shift; SERVER="${1:-}" ;;
    --insecure) ARG_INSECURE=1 ;;
    --debug) DEBUG=1 ;;
    --test) TEST_MODE=1 ;;
    --inbound)
      shift
      INBOUND_TYPE="${1%%:*}"
      if [[ "$1" == *:* ]]; then INBOUND_PORT="${1#*:}"; fi
      ;;
    *) die1 "未知参数: $1（支持 --from-server / --server / --insecure / --debug / --inbound / --test）" ;;
  esac
  shift
done

# ---------- source 协议转换库（含输出函数/版本表/assert_gen） ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/protocols.lib.sh"

# ---------- 临时目录 ----------
TMPD="$(mktemp -d)" || die1 "无法创建临时目录"
trap 'rm -rf "$TMPD"' EXIT
debug "临时目录: $TMPD"

# ---------- --test：自检后退出 ----------
if [[ $TEST_MODE -eq 1 ]]; then
  ok "== 运行 gen-client.sh 自检（assert_gen）=="
  assert_gen
  exit $?
fi

# ---------- 输入检查 ----------
[[ -n "$CONFIG_PATH" ]] || die1 "必须 --from-server 指定服务端 config.json"
[[ -f "$CONFIG_PATH" ]] || die1 "服务端 config.json 不存在: $CONFIG_PATH"
[[ -r "$CONFIG_PATH" ]] || die1 "服务端 config.json 无法读取（权限不足）: $CONFIG_PATH（加 --debug 看详情）"
debug "服务端 config: $CONFIG_PATH"

# ---------- 解析服务端 config（python3 只解析，转换在 bash） ----------
command -v python3 >/dev/null 2>&1 || die1 "需要 python3 解析 config.json"
if ! python3 - "$CONFIG_PATH" "$TMPD" <<'PY'
import json, sys, os
c = json.load(open(sys.argv[1]))
ibs = c.get("inbounds", [])
if not isinstance(ibs, list): ibs = []
json.dump(ibs, open(os.path.join(sys.argv[2], "inbounds.json"), "w"))
PY
then
  die1 "服务端 config.json 解析失败（JSON 损坏或不可读）: $CONFIG_PATH（加 --debug 看详情）"
fi
INBOUND_COUNT="$(python3 -c "import json;print(len(json.load(open('$TMPD/inbounds.json'))))")"
if [[ -z "$INBOUND_COUNT" ]]; then
  die1 "服务端 config.json 解析失败（未生成 inbounds 索引）: $CONFIG_PATH（加 --debug 看详情）"
fi
if [[ "$INBOUND_COUNT" -eq 0 ]]; then
  die2 "服务端 config 没有 inbounds"
fi
debug "inbounds 共 $INBOUND_COUNT 个"

# ---------- 版本检测（时间线兼容） ----------
SB_BIN="${SB_BIN:-}"
if [[ -z "$SB_BIN" ]]; then
  if command -v sing-box >/dev/null 2>&1; then SB_BIN=$(command -v sing-box)
  elif [[ -x /opt/sing-box/sing-box ]]; then SB_BIN=/opt/sing-box/sing-box
  elif [[ -x "$(dirname "${BASH_SOURCE[0]}")/../bin/sing-box" ]]; then SB_BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin/sing-box"
  else warn "未找到 sing-box 二进制，跳过 check 与版本检测"; fi
fi
if [[ -n "$SB_BIN" ]]; then
  DETECTED="$(timeout 5 "$SB_BIN" version 2>/dev/null | head -1 | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -1 | tr -d 'v')"
  check_version "$DETECTED"
  debug "sing-box: $SB_BIN (v${DETECTED:-未知})"
fi

# ---------- 客户端连接地址 ----------
# ---------- 客户端连接地址（--server 参数或交互输入；不主动探测本机 IP，域名/IP 都行） ----------
if [[ -z "$SERVER" ]]; then
  read -r -p "输入客户端连接地址（域名双栈 / IPv4 / IPv6 均可）: " SERVER
  [[ -n "$SERVER" ]] || die1 "必须提供连接地址（--server 参数或交互输入）"
  debug "交互输入: $SERVER"
else
  debug "server: $SERVER"
fi

# ---------- insecure ----------
[[ $ARG_INSECURE -eq 1 ]] && INSECURE=1

# ---------- TLS 后缀与 SNI（供转换库使用） ----------
TLS_SUFFIX=""
[[ $INSECURE -eq 1 ]] && TLS_SUFFIX=', "insecure": true'

# ---------- 转换：服务端 inbounds → 客户端 outbounds ----------
render_from_server

# ---------- 校对: 至少一条线 ----------
[[ -n "$OUTS" ]] || die2 "未转换出任何线路"

# ---------- 校对: 重复 tag ----------
if [[ $(echo "$TAGS" | tr ',' '\n' | sort | uniq -d | wc -l) -gt 0 ]]; then
  die2 "重复 tag: $(echo "$TAGS" | tr ',' '\n' | sort | uniq -d | tr '\n' ' ')"
fi

# ---------- 组装 outbounds ----------
AUTO_REFS="$TAGS"
MANUAL_REFS="\"auto\"${TAGS:+, $TAGS}"
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
  die1 "不支持的 --inbound: $INBOUND_TYPE（tun 或 socks[:port]）"
fi

# ---------- 渲染 ----------
SB_OUTPUT="${SB_OUTPUT:-$OUTPUT_DEFAULT}"
if ! mkdir -p "$(dirname "$SB_OUTPUT")" 2>/dev/null; then
  die1 "无法写入输出目录（权限不足?）: $(dirname "$SB_OUTPUT")（加 --debug 看详情）"
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
  die1 "无法写入输出文件（权限不足?）: $SB_OUTPUT（加 --debug 看详情）"
fi
if [[ ! -s "$SB_OUTPUT" ]]; then
  die1 "输出文件写入后为空（磁盘满?）: $SB_OUTPUT（加 --debug 看详情）"
fi
debug "输出已写入: $SB_OUTPUT"

# ---------- sing-box check（语法兜底：版本破坏性变更的最终防线） ----------
if [[ -n "$SB_BIN" ]]; then
  if timeout 15 "$SB_BIN" check -c "$SB_OUTPUT" 2>"$TMPD/check.err"; then
    ok "已生成并通过 sing-box 校验: $SB_OUTPUT"
  else
    err "配置校验失败:"; cat "$TMPD/check.err" >&2
    exit 2
  fi
else
  warn "已生成但未校验（无 sing-box 二进制）: $SB_OUTPUT"
fi

ok "服务端: $CONFIG_PATH → 客户端: $SB_OUTPUT"
ok "连接地址: $SERVER   TLS: $([ $INSECURE -eq 1 ] && echo '自签(insecure)' || echo '真证书')   inbound: $INBOUND_TYPE"
ok "已启用线路: ${TAGS}"
ok "导入: 官方客户端（SFA/SFI）→ 从文件导入此 JSON"
