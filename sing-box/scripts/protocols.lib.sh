#!/usr/bin/env bash
# protocols.lib.sh — sing-box 客户端协议规范（唯一真源，被 gen-client.sh source）
#
# 用法: 由 gen-client.sh 在设好输入变量后 source，然后调用 render_lines()
#
# 【升级 sing-box 时的唯一动作】：改本文件的模板（配合 gen-client.sh 头部的
#   版本速查 + docs/protocol-maintenance.md 字段审计 + sing-box check 兜底）。
#   加新协议 = 加一个 proto_xxx() + 注册进 render_lines() 的遍历表 +
#   补 config.gen.json.example 键 + gen-client.sh KNOWN_KEYS + 维护清单字段表。
#
# 输入变量（由 gen-client.sh 提供，勿在本文件设置默认之外的值）:
#   SERVER / PR PH PST PT PA PS PVW PMW PTJ PNV PWG 端口
#   SB_UUID SB_PUB SB_SHORT HY2_PASS HY2_OBFS SS_PASS ST_PASS TU_UUID ANY_PASS
#   TROJAN_PASS NAIVE_USER NAIVE_PASS WG_PRIV WG_PUB WG_PSK WG_LOCAL_ADDR
#   VLESS_WS_PATH VLESS_WS_HOST VMESS_WS_PATH VMESS_WS_HOST
#   TLS_SUFFIX / SNI_DEFAULT / REALITY_SNI
# 输出全局（由 gen-client.sh 消费）:
#   OUTS（逗号分隔的 outbound JSON 串）/ TAGS（逗号分隔的 tag 引用串）
#   ST_ON / SS_CHAIN_ON / WG_ON（校对用）

# ---------- 输出分级（ok/warn/err/debug；debug 默认完全静默，--debug 开启） ----------
DEBUG="${DEBUG:-0}"
ok()    { echo "$@"; }                        # 成功/结果行 → stdout
warn()  { echo "⚠ $@" >&2; }                  # 警告 → stderr
err()   { echo "✗ $@" >&2; }                  # 错误 → stderr
die1()  { err "$@"; exit 1; }                 # 错误+退出码 1（参数/依赖/未知键契约）
die2()  { err "$@"; exit 2; }                 # 错误+退出码 2（校对/check 契约）
debug() { [[ $DEBUG -eq 1 ]] && echo "[debug] $@" >&2; }   # 仅 --debug 输出

# ---------- 线路开关（config 缺省：旧六线开、新协议关） ----------
is_on() { local v="${!1:-}"; if [[ -z "$v" ]]; then [[ $2 -eq 1 ]]; else [[ "$v" == "1" ]]; fi; }

# ---------- 模板区 ----------
proto_reality() { # 1.14: public_key 须 URL-safe raw base64；short_id 客户端是字符串；utls.enabled 必须 true
  is_on REALITY 1 || return
  OUTS+="${OUTS:+, }{ \"type\": \"vless\", \"tag\": \"reality\", \"server\": \"$SERVER\", \"server_port\": $PR, \"uuid\": \"$SB_UUID\", \"flow\": \"xtls-rprx-vision\", \"packet_encoding\": \"xudp\", \"tls\": { \"enabled\": true, \"server_name\": \"$REALITY_SNI\", \"utls\": { \"enabled\": true, \"fingerprint\": \"chrome\" }, \"reality\": { \"enabled\": true, \"public_key\": \"$SB_PUB\", \"short_id\": \"$SB_SHORT\" } } }"
  TAGS+="${TAGS:+, }\"reality\""
}

proto_hy2() { # 1.14: disable_chrome_parrot 默认 false（Chrome QUIC 指纹）；obfs 只有 salamander/gecko
  is_on HY2 1 || return
  OUTS+="${OUTS:+, }{ \"type\": \"hysteria2\", \"tag\": \"hy2\", \"server\": \"$SERVER\", \"server_port\": $PH, \"password\": \"$HY2_PASS\", \"obfs\": { \"type\": \"salamander\", \"password\": \"$HY2_OBFS\" }, \"tls\": { \"enabled\": true, \"server_name\": \"$SNI_DEFAULT\"$TLS_SUFFIX } }"
  TAGS+="${TAGS:+, }\"hy2\""
}

proto_shadowtls() { # 1.14: version 3 客户端写法同 v2（version+password+tls）；仅 TCP
  is_on SHADOWTLS 1 || return
  ST_ON=1
  OUTS+="${OUTS:+, }{ \"type\": \"shadowtls\", \"tag\": \"shadowtls\", \"server\": \"$SERVER\", \"server_port\": $PST, \"version\": 3, \"password\": \"$ST_PASS\", \"tls\": { \"enabled\": true, \"server_name\": \"$REALITY_SNI\", \"utls\": { \"enabled\": true, \"fingerprint\": \"chrome\" } } }"
  TAGS+="${TAGS:+, }\"shadowtls\""
}

proto_ss_chain() { # SS 链式（detour→shadowtls）
  is_on SHADOWTLS 1 || return
  SS_CHAIN_ON=1
  OUTS+="${OUTS:+, }{ \"type\": \"shadowsocks\", \"tag\": \"ss-over-st\", \"server\": \"$SERVER\", \"server_port\": $PST, \"method\": \"2022-blake3-aes-256-gcm\", \"password\": \"$SS_PASS\", \"detour\": \"shadowtls\" }"
  TAGS+="${TAGS:+, }\"ss-over-st\""
}

proto_ss_direct() { # 直连 SS（可选独立线）
  is_on SS_DIRECT 0 || return
  OUTS+="${OUTS:+, }{ \"type\": \"shadowsocks\", \"tag\": \"ss2022\", \"server\": \"$SERVER\", \"server_port\": $PS, \"method\": \"2022-blake3-aes-256-gcm\", \"password\": \"$SS_PASS\" }"
  TAGS+="${TAGS:+, }\"ss2022\""
}

proto_tuic() { # 1.14: congestion_control 默认 cubic，要 BBR 显式写 bbr
  is_on TUIC 1 || return
  OUTS+="${OUTS:+, }{ \"type\": \"tuic\", \"tag\": \"tuic\", \"server\": \"$SERVER\", \"server_port\": $PT, \"uuid\": \"$TU_UUID\", \"password\": \"$ST_PASS\", \"congestion_control\": \"bbr\", \"tls\": { \"enabled\": true, \"server_name\": \"$SNI_DEFAULT\"$TLS_SUFFIX } }"
  TAGS+="${TAGS:+, }\"tuic\""
}

proto_anytls() { # 1.14: padding_scheme 是服务端字段（客户端不能配）；tcp_fast_open 禁用
  is_on ANYTLS 1 || return
  OUTS+="${OUTS:+, }{ \"type\": \"anytls\", \"tag\": \"anytls\", \"server\": \"$SERVER\", \"server_port\": $PA, \"password\": \"$ANY_PASS\", \"tls\": { \"enabled\": true, \"server_name\": \"$SNI_DEFAULT\"$TLS_SUFFIX } }"
  TAGS+="${TAGS:+, }\"anytls\""
}

proto_vless_ws() { # 1.14: transport 只有 http/ws/quic/grpc/httpupgrade（无 xhttp）
  is_on VLESS_WS 0 || return
  OUTS+="${OUTS:+, }{ \"type\": \"vless\", \"tag\": \"vless-ws\", \"server\": \"$SERVER\", \"server_port\": $PVW, \"uuid\": \"$SB_UUID\", \"tls\": { \"enabled\": true, \"server_name\": \"$SNI_DEFAULT\"$TLS_SUFFIX }, \"transport\": { \"type\": \"ws\", \"path\": \"${VLESS_WS_PATH:-/ws}\", \"headers\": { \"Host\": \"${VLESS_WS_HOST:-$SNI_DEFAULT}\" } } }"
  TAGS+="${TAGS:+, }\"vless-ws\""
}

proto_vmess_ws() { # 1.14: alter_id 默认 0（AEAD）；packet_encoding 缺省禁用
  is_on VMESS_WS 0 || return
  OUTS+="${OUTS:+, }{ \"type\": \"vmess\", \"tag\": \"vmess-ws\", \"server\": \"$SERVER\", \"server_port\": $PMW, \"uuid\": \"$SB_UUID\", \"alter_id\": 0, \"security\": \"auto\", \"tls\": { \"enabled\": true, \"server_name\": \"$SNI_DEFAULT\"$TLS_SUFFIX }, \"transport\": { \"type\": \"ws\", \"path\": \"${VMESS_WS_PATH:-/ws}\", \"headers\": { \"Host\": \"${VMESS_WS_HOST:-$SNI_DEFAULT}\" } } }"
  TAGS+="${TAGS:+, }\"vmess-ws\""
}

proto_trojan() { # 1.14: tls.enabled 必须 true（Trojan 本身是 TLS 协议）
  is_on TROJAN 0 || return
  OUTS+="${OUTS:+, }{ \"type\": \"trojan\", \"tag\": \"trojan\", \"server\": \"$SERVER\", \"server_port\": $PTJ, \"password\": \"$TROJAN_PASS\", \"tls\": { \"enabled\": true, \"server_name\": \"$SNI_DEFAULT\"$TLS_SUFFIX } }"
  TAGS+="${TAGS:+, }\"trojan\""
}

proto_naive() { # 1.14: 无 insecure（须真证书）；依赖 libcronet.so 与二进制同目录
  is_on NAIVE 0 || return
  [[ ${INSECURE:-0} -eq 1 ]] && warn "naive 不支持 insecure（须真证书），仍将生成（服务端需真证书）"
  OUTS+="${OUTS:+, }{ \"type\": \"naive\", \"tag\": \"naive\", \"server\": \"$SERVER\", \"server_port\": $PNV, \"username\": \"${NAIVE_USER:-sb}\", \"password\": \"$NAIVE_PASS\", \"tls\": { \"enabled\": true, \"server_name\": \"$SNI_DEFAULT\" } }"
  TAGS+="${TAGS:+, }\"naive\""
}

proto_wireguard() { # 1.14: outbound 形态已删除，须用顶层 endpoints 数组的 endpoint 形态
  is_on WIREGUARD 0 || return
  WG_ON=1
  EP_S+="${EP_S:+, }{ \"type\": \"wireguard\", \"tag\": \"wg\", \"system\": ${WG_SYSTEM:-false}, \"address\": [ \"${WG_LOCAL_ADDR:-10.0.0.2/32}\" ], \"private_key\": \"$WG_PRIV\", \"peers\": [ { \"address\": \"$SERVER\", \"port\": $PWG, \"public_key\": \"$WG_PUB\", \"pre_shared_key\": \"$WG_PSK\", \"allowed_ips\": [ \"0.0.0.0/0\" ] } ] }"
  TAGS+="${TAGS:+, }\"wg\""
}

# ---------- 总入口：按序渲染所有协议到 OUTS/TAGS（wireguard → EP_S） ----------
# 顺序即 outbounds 数组顺序（Reality 在前，urltest 测速首线稳定）
render_lines() {
  OUTS=""; TAGS=""; EP_S=""
  ST_ON=0; SS_CHAIN_ON=0; WG_ON=0
  proto_reality
  proto_hy2
  proto_shadowtls
  proto_ss_chain
  proto_ss_direct
  proto_tuic
  proto_anytls
  proto_vless_ws
  proto_vmess_ws
  proto_trojan
  proto_naive
  proto_wireguard
}

# ═══════════════════════════════════════════════════════════════════════
# 【自检】assert_gen — gen-client.sh 行为断言（--test trigger 调用）
# 独立于真链路：用 test-env 的 fake secrets 构造 config，断言退出码/输出结构。
# 用法: 由 gen-client.sh --test 调用；或 bash -c 'source protocols.lib.sh; assert_gen'
# 依赖: test-env/（secrets）、sing-box 二进制（SB_BIN 或默认路径）
# ═══════════════════════════════════════════════════════════════════════
assert_gen() {
  local LIB_DIR ROOT TEST BIN GEN PASS FAIL code M1 M2 TMPD
  LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  ROOT="$(dirname "$LIB_DIR")"
  TEST="$ROOT/test-env"
  BIN="${SB_BIN:-/tmp/sing-box-1.14.0-beta.14-linux-amd64/sing-box}"
  GEN="$ROOT/scripts/gen-client.sh"
  [[ -x "$BIN" ]] || { err "缺测试二进制: $BIN"; return 1; }
  [[ -f "$TEST/secrets/env.sh" ]] || { err "缺 test-env/secrets（先跑 bash test-env/setup.sh）"; return 1; }
  TMPD="$(mktemp -d)" || die1 "无法创建临时目录"
  trap 'rm -rf "$TMPD"' EXIT
  PASS=0; FAIL=0
  debug "assert_gen: TMPD=$TMPD BIN=$BIN"

  check() { if [[ "$3" -eq "$2" ]]; then echo "  ✔ $1"; PASS=$((PASS+1)); else echo "  ✗ $1（期望退出 $2，实际 $3）$4"; FAIL=$((FAIL+1)); fi; }
  run_gen() { SB_OUTPUT=$TMPD/assert-out.json SB_BIN="$BIN" bash "$GEN" --config "$1" ${2:-} >$TMPD/assert-log.txt 2>&1; echo "$?"; }

  local BASE_CFG=$TMPD/assert-base.json
  python3 - "$BASE_CFG" <<PY
import json, sys
env = {}
for line in open("$TEST/secrets/env.sh"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1); env[k] = v.strip("'")
c = {
    "server_host": "127.0.0.1", "insecure": True,
    "reality": 1, "hy2": 1, "shadowtls": 1, "tuic": 1, "anytls": 1,
    "ss_direct": 0, "vless_ws": 0, "vmess_ws": 0, "trojan": 0, "naive": 0, "wireguard": 0,
    "sb_uuid": env["SB_UUID"], "sb_pub": env["SB_PUB"], "sb_short": env["SB_SHORT"],
    "hy2_pass": env["HY2_PASS"], "hy2_obfs": env["HY2_OBFS"], "ss_pass": env["SS_PASS"],
    "st_pass": env["ST_PASS"], "tu_uuid": env["TU_UUID"], "any_pass": env["ANY_PASS"],
    "port_reality": 10001, "port_hy2": 10002, "port_st": 10003,
    "port_tuic": 10005, "port_anytls": 10006, "port_ss": 10004,
}
json.dump(c, open(sys.argv[1], "w"))
PY

  echo "=== A. 参数/依赖错误（退出码 1） ==="
  debug "A: config 不存在 / 未知键"
  code=$(run_gen /nonexistent.json);               check "config 不存在 → 1" 1 "$code"
  python3 -c "import json;c=json.load(open('$TMPD/assert-base.json'));c['frobnicate']=1;json.dump(c,open('$TMPD/assert-badkey.json','w'))"
  code=$(run_gen $TMPD/assert-badkey.json);         check "未知键 → 1" 1 "$code"

  echo "=== B. 校对失败（退出码 2） ==="
  python3 -c "import json;c=json.load(open('$TMPD/assert-base.json'));[c.__setitem__(k,0) for k in ('reality','hy2','shadowtls','tuic','anytls')];json.dump(c,open('$TMPD/assert-alloff.json','w'))"
  code=$(run_gen $TMPD/assert-alloff.json);         check "全关 → 2" 2 "$code"
  python3 -c "import json;c=json.load(open('$TMPD/assert-base.json'));c['wireguard']=1;c['wg_priv']='x';c['wg_pub']='y';c['wg_psk']='z';json.dump(c,open('$TMPD/assert-wgbad.json','w'))"
  code=$(run_gen $TMPD/assert-wgbad.json);          check "wg 非法密钥 → 2(check 报错)" 2 "$code"

  echo "=== C. 正常生成结构断言（退出码 0 + JSON 结构） ==="
  code=$(run_gen $TMPD/assert-base.json);           check "六线正常 → 0" 0 "$code"
  python3 - "$TMPD/assert-out.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
errs = []
auto = next(o for o in c["outbounds"] if o["tag"]=="auto")["outbounds"]
manual = next(o for o in c["outbounds"] if o["tag"]=="manual")["outbounds"]
if set(auto) != {"reality","hy2","ss-over-st","tuic","anytls","shadowtls"}: errs.append(f"auto 引用集不对: {auto}")
if manual[0] != "auto" or set(manual[1:]) != {"reality","hy2","ss-over-st","tuic","anytls","shadowtls"}: errs.append(f"manual 引用集不对: {manual}")
if c["route"]["final"] != "auto": errs.append("route.final 不是 auto")
if c["dns"]["servers"][0].get("detour") != "reality": errs.append("DNS detour 不是 reality")
print("  " + ("✔ 结构断言通过" if not errs else "✗ " + "; ".join(errs)))
PY
  [[ $? -eq 0 ]] || FAIL=$((FAIL+1))

  echo "=== D. 开关增删 → 生成集精确匹配 ==="
  python3 -c "import json;c=json.load(open('$TMPD/assert-base.json'));c['shadowtls']=0;c['ss_direct']=1;c['vless_ws']=1;c['trojan']=1;c['trojan_pass']='tp';json.dump(c,open('$TMPD/assert-sw.json','w'))"
  code=$(run_gen $TMPD/assert-sw.json);             check "开关增删 → 0" 0 "$code"
  python3 - "$TMPD/assert-out.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
tags = {o["tag"] for o in c["outbounds"]}
expect = {"reality","hy2","ss2022","tuic","anytls","vless-ws","trojan","auto","manual","direct","block"}
errs = []
if tags != expect: errs.append(f"生成集不对: {sorted(tags)} 期望 {sorted(expect)}")
if "shadowtls" in tags or "ss-over-st" in tags: errs.append("shadowtls 关闭后仍生成链式线")
print("  " + ("✔ 开关增删精确匹配" if not errs else "✗ " + "; ".join(errs)))
PY

  echo "=== E. 全协议含 wg → endpoints 结构 ==="
  python3 -c "
import json, base64, os
c=json.load(open('$TMPD/assert-base.json'))
for k in ('naive','wireguard'): c[k]=1
c['naive_user']='u'; c['naive_pass']='p'
c['wg_priv']=base64.b64encode(os.urandom(32)).decode()
c['wg_pub']=base64.b64encode(os.urandom(32)).decode()
c['wg_psk']=base64.b64encode(os.urandom(32)).decode()
json.dump(c,open('$TMPD/assert-full.json','w'))
"
  code=$(run_gen $TMPD/assert-full.json);           check "全协议 → 0" 0 "$code"
  python3 - "$TMPD/assert-out.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
errs = []
auto = next(o for o in c["outbounds"] if o["tag"]=="auto")["outbounds"]
manual = next(o for o in c["outbounds"] if o["tag"]=="manual")["outbounds"]
if "wg" in auto: errs.append("wg 出现在 auto（urltest 测不了 endpoint）")
if "wg" not in manual: errs.append("wg 不在 manual")
if not any(e.get("tag")=="wg" for e in c.get("endpoints",[])): errs.append("endpoints 缺 wg")
print("  " + ("✔ 全协议 endpoints 结构通过" if not errs else "✗ " + "; ".join(errs)))
PY

  echo "=== F. 幂等（同 config 两次生成 md5 相同） ==="
  code=$(run_gen $TMPD/assert-base.json); check "幂等第一次 → 0" 0 "$code"
  M1=$(md5sum $TMPD/assert-out.json | cut -d' ' -f1)
  code=$(run_gen $TMPD/assert-base.json); check "幂等第二次 → 0" 0 "$code"
  M2=$(md5sum $TMPD/assert-out.json | cut -d' ' -f1)
  if [[ "$M1" == "$M2" ]]; then echo "  ✔ 两次输出一致"; PASS=$((PASS+1)); else echo "  ✗ 幂等失败"; FAIL=$((FAIL+1)); fi

  echo
  echo "=== 结果: 通过 $PASS / $((PASS+FAIL)) ==="
  [[ $FAIL -eq 0 ]]
}
