#!/usr/bin/env bash
# protocols.lib.sh — sing-box 客户端协议转换库（唯一真源，被 gen-client.sh source）
#
# 架构: 服务端 config.json → 转换 → 客户端 client.json（单输入单输出，无中间配置文件）
# 用法: 由 gen-client.sh 解析服务端 config 后，逐 inbound 调 convert_xxx()，再 render_from_server()
#
# 【升级 sing-box 时的唯一动作】:
#   1. 在 VERSION_TABLE 加版本行（时间线）
#   2. 若新版本改了字段：改对应 convert_xxx()（配合 gen-client.sh 版本探测 + check 兜底）
#   3. 若引入新协议：加 convert_xxx() + 注册进 render_from_server() 的遍历表
# 完整字段审计 + 变更史 + 升级 SOP 见 docs/protocol-maintenance.md

# ---------- 输出分级（ok/warn/err/debug；debug 默认完全静默，--debug 开启） ----------
DEBUG="${DEBUG:-0}"
ok()    { echo "$@"; }                        # 成功/结果行 → stdout
warn()  { echo "⚠ $@" >&2; }                  # 警告 → stderr
err()   { echo "✗ $@" >&2; }                  # 错误 → stderr
die1()  { err "$@"; exit 1; }                 # 错误+退出码 1（参数/依赖错误契约）
die2()  { err "$@"; exit 2; }                 # 错误+退出码 2（转换/校验失败契约）
debug() { [[ $DEBUG -eq 1 ]] && echo "[debug] $@" >&2; }   # 仅 --debug 输出

# ═══════════════════════════════════════════════════════════════════════
# 【版本兼容时间线】——自动检测 sing-box 版本，按时间线确认兼容性
# 格式: "major.minor:状态:说明"
#   状态: supported=基线版本 / deprecated_ok=格式可解析但字段弃用 / future=需拦截检查新写法
# 将来升 1.15+: 在这里加行 + 对应 convert_xxx() 按新字段适配，check 是最终裁决
# ═══════════════════════════════════════════════════════════════════════
SINGBOX_VERSION="1.14.0-beta.14"     # 基线版本
SINGBOX_MAJOR_MINOR="1.14"
VERSION_TABLE=(
  "1.13:deprecated_ok:legacy DNS address 简写等字段已弃用但可解析，1.14 起移除"
  "1.14:supported:基线版本 1.14.0-beta.14"
  "1.15:future:新 transport 写法（xhttp 等）需确认后再生成，见维护清单"
)

# 检查二进制版本 vs 时间线表；$1=版本字符串（如 1.14.0-beta.14）
check_version() {
  local ver="${1:-}" mm status note
  [[ -z "$ver" ]] && return 0
  mm="$(echo "$ver" | grep -oE '^[0-9]+\.[0-9]+')"
  [[ -z "$mm" ]] && { warn "无法解析 sing-box 版本: $ver"; return 0; }
  for row in "${VERSION_TABLE[@]}"; do
    local m="${row%%:*}" rest="${row#*:}"
    if [[ "$m" == "$mm" ]]; then
      status="${rest%%:*}" note="${rest#*:}"
      case "$status" in
        supported)  debug "版本兼容: v$ver（基线）"; return 0 ;;
        deprecated_ok) warn "版本 v$ver: $note"; return 0 ;;
        future)     warn "版本 v$ver: $note（如有报错按维护清单适配字段）"; return 0 ;;
      esac
    fi
  done
  warn "版本 v$ver 不在兼容时间线（基线 $SINGBOX_MAJOR_MINOR）——先确认字段再生成"
}

# ---------- X25519 私钥 → 公钥派生（服务端 config 只有 private_key，客户端需 public_key） ----------
# 输入: URL-safe raw base64 私钥（43 字符）；输出: URL-safe raw base64 公钥
derive_pubkey() {
  local priv="$1" raw hex der
  [[ -z "$priv" ]] && return 1
  # 全部在 python 一步完成（bash 变量存二进制会丢 NUL）：解码 → 包 PKCS#8 DER → 写文件
  local derfile="${TMPD:-/tmp}/derive-$$.der"
  python3 -c "
import base64, sys
s='''$priv'''
raw=base64.urlsafe_b64decode(s+'='*((4-len(s)%4)%4))
assert len(raw)==32, 'privkey len'
der=bytes.fromhex('302e020100300506032b656e04220420')+raw
open('$derfile','wb').write(der)
" 2>/dev/null || return 1
  # openssl 导出公钥 SPKI → 取尾 32 字节 → URL-safe raw base64
  openssl pkey -inform DER -in "$derfile" -pubout -outform DER 2>/dev/null \
    | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '='
  rm -f "$derfile"
}

# ---------- 转换函数区 ----------
# 每个 convert_xxx() 输入一个 inbound 的提取字段（python 已解析为 bash 变量），
# 输出追加到 OUTS/TAGS（wireguard 追加 EP_S）
# 公共输入变量（gen-client.sh 提供）: SERVER（客户端连接地址）/ INSECURE / TMPD / INB 索引
OUTS=""; TAGS=""; EP_S=""

# 取第 $1 个 inbound 的字段；$2=点分路径；输出到 stdout
# 路径规则: dict 按 key 取；list 若下一段是数字按下标取、否则取首元素（如 short_id 数组）
inb_field() { # $1=inbound 索引  $2=点分字段路径
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

convert_vless() { # $1=inbound 索引 —— 服务端 vless(reality) → 客户端 vless(reality)
  local i="$1" uuid flow sni priv short pub
  uuid="$(inb_field $i 'users.0.uuid')"
  flow="$(inb_field $i 'users.0.flow')"
  sni="$(inb_field $i 'tls.server_name')"
  priv="$(inb_field $i 'tls.reality.private_key')"
  short="$(inb_field $i 'tls.reality.short_id.0')"
  [[ -z "$short" ]] && short="$(inb_field $i 'tls.reality.short_id')"
  [[ -z "$priv" ]] && { warn "vless inbound[$i] 缺 reality private_key，跳过"; return; }
  pub="$(derive_pubkey "$priv")" || { warn "vless inbound[$i] 私钥派生公钥失败，跳过"; return; }
  local port
  port="$(inb_field $i 'listen_port')"
  [[ -z "$port" || "$port" == "0" ]] && { warn "vless inbound[$i] 缺 listen_port，跳过"; return; }
  OUTS+="${OUTS:+, }{ \"type\": \"vless\", \"tag\": \"reality\", \"server\": \"$SERVER\", \"server_port\": $port, \"uuid\": \"$uuid\", \"flow\": \"$flow\", \"packet_encoding\": \"xudp\", \"tls\": { \"enabled\": true, \"server_name\": \"$sni\", \"utls\": { \"enabled\": true, \"fingerprint\": \"chrome\" }, \"reality\": { \"enabled\": true, \"public_key\": \"$pub\", \"short_id\": \"$short\" } } }"
  TAGS+="${TAGS:+, }\"reality\""
  debug "vless[reality] ← inbound[$i] port=$port sni=$sni"
}

convert_hy2() { # $1=inbound 索引 —— 服务端 hysteria2 → 客户端 hysteria2
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

convert_shadowtls() { # $1=inbound 索引 —— 服务端 shadowtls(链式→ss) → 客户端 shadowtls + ss(detour)
  local i="$1" pass ver handshake_sni detour_tag ss_in
  pass="$(inb_field $i 'users.0.password')"
  ver="$(inb_field $i 'version')"
  [[ -z "$ver" || "$ver" == "0" ]] && ver=3
  handshake_sni="$(inb_field $i 'handshake.server')"
  local port; port="$(inb_field $i 'listen_port')"
  OUTS+="${OUTS:+, }{ \"type\": \"shadowtls\", \"tag\": \"shadowtls\", \"server\": \"$SERVER\", \"server_port\": $port, \"version\": $ver, \"password\": \"$pass\", \"tls\": { \"enabled\": true, \"server_name\": \"$handshake_sni\", \"utls\": { \"enabled\": true, \"fingerprint\": \"chrome\" } } }"
  TAGS+="${TAGS:+, }\"shadowtls\""
  # 链式: 找 detour 指向的 ss inbound，生成 ss(detour→shadowtls)
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
    debug "shadowtls ← inbound[$i] + ss链 inbound[$ss_in]"
  else
    warn "shadowtls inbound[$i] 无对应 ss inbound（detour=$detour_tag），只生成了 shadowtls"
  fi
}

convert_tuic() { # $1=inbound 索引 —— 服务端 tuic → 客户端 tuic
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

convert_anytls() { # $1=inbound 索引 —— 服务端 anytls → 客户端 anytls
  local i="$1" pass
  pass="$(inb_field $i 'users.0.password')"
  local ins=""
  [[ $INSECURE -eq 1 ]] && ins=', "insecure": true'
  local port; port="$(inb_field $i 'listen_port')"
  OUTS+="${OUTS:+, }{ \"type\": \"anytls\", \"tag\": \"anytls\", \"server\": \"$SERVER\", \"server_port\": $port, \"password\": \"$pass\", \"tls\": { \"enabled\": true, \"server_name\": \"$SERVER\"$ins } }"
  TAGS+="${TAGS:+, }\"anytls\""
  debug "anytls ← inbound[$i] port=$port"
}

convert_ss() { # $1=inbound 索引 —— 直连 shadowsocks → 客户端 ss（被 shadowtls 链消费的跳过）
  local i="$1" method pass tag
  tag="$(inb_field $i 'tag')"
  if [[ " ${CONSUMED_SS_TAGS:-} " == *" $tag "* ]]; then
    debug "ss inbound[$i]($tag) 已被 shadowtls 链消费，跳过直连转换"
    return
  fi
  method="$(inb_field $i 'method')"
  pass="$(inb_field $i 'password')"
  local port; port="$(inb_field $i 'listen_port')"
  OUTS+="${OUTS:+, }{ \"type\": \"shadowsocks\", \"tag\": \"ss2022\", \"server\": \"$SERVER\", \"server_port\": $port, \"method\": \"$method\", \"password\": \"$pass\" }"
  TAGS+="${TAGS:+, }\"ss2022\""
  debug "ss ← inbound[$i] port=$port"
}

convert_wg() { # $1=inbound 索引 —— 服务端 wireguard → 客户端 endpoint（客户端私钥确定性派生，对端公钥从服务端私钥派生）
  local i="$1" srv_priv peer_pub cli_priv
  srv_priv="$(inb_field $i 'private_key')"
  peer_pub="$(derive_pubkey "$srv_priv")" || { warn "wireguard inbound[$i] 对端公钥派生失败，跳过"; return; }
  # ⚠️ wireguard endpoint 密钥用标准 base64（与 reality 的 urlsafe raw 不同）；
  # derive_pubkey 输出 urlsafe raw → python 统一转标准 base64（正确 padding，防 45 字符陷阱）
  peer_pub="$(python3 -c "
import base64
s='''$peer_pub'''
raw=base64.urlsafe_b64decode(s+'='*((4-len(s)%4)%4))
print(base64.b64encode(raw).decode())
")" || { warn "wireguard inbound[$i] 对端公钥编码转换失败，跳过"; return; }
  # 客户端私钥：HMAC(服务端私钥) 确定性生成 → 同一服务端 config 重跑幂等，服务端 peer 只需配一次公钥
  # ⚠️ wireguard endpoint 私钥 = 标准 base64 带 padding（44 字符），实测其它编码全 illegal
  cli_priv="$(python3 -c "
import hmac, hashlib, base64
seed=hmac.new(b'$srv_priv', b'sing-box-wg-client', hashlib.sha256).digest()
print(base64.b64encode(seed).decode())
")" || { warn "wireguard inbound[$i] 客户端密钥派生失败，跳过"; return; }
  local port; port="$(inb_field $i 'listen_port')"
  EP_S+="${EP_S:+, }{ \"type\": \"wireguard\", \"tag\": \"wg\", \"system\": false, \"address\": [ \"${WG_LOCAL_ADDR:-10.0.0.2/32}\" ], \"private_key\": \"$cli_priv\", \"peers\": [ { \"address\": \"$SERVER\", \"port\": $port, \"public_key\": \"$peer_pub\", \"pre_shared_key\": \"\", \"allowed_ips\": [ \"0.0.0.0/0\" ] } ] }"
  TAGS+="${TAGS:+, }\"wg\""
  warn "wireguard：客户端私钥确定性生成（标准 base64，对端公钥已派生，服务端 peer 配一次即可）"
  debug "wg ← inbound[$i] 对端公钥已派生"
}

# ---------- 总入口：遍历服务端 inbounds，按类型转换 ----------
# 输入: $TMPD/inbounds.json（服务端 config 的 inbounds 数组）
# 输出: OUTS/TAGS（客户端 outbounds 片段）
render_from_server() {
  OUTS=""; TAGS=""
  local n t j det
  n="$(python3 -c "import json;print(len(json.load(open('$TMPD/inbounds.json'))))")"
  # 预扫：收集被 shadowtls 链引用的 ss tag（避免被重复转成直连线）
  CONSUMED_SS_TAGS=""
  for ((j=0; j<n; j++)); do
    t="$(inb_field $j 'type')"
    if [[ "$t" == "shadowtls" ]]; then
      det="$(inb_field $j 'detour')"
      [[ -n "$det" ]] && CONSUMED_SS_TAGS+=" $det"
    fi
  done
  debug "服务端 inbounds 共 $n 个（被链消费的 ss tag:$CONSUMED_SS_TAGS）"
  for ((i=0; i<n; i++)); do
    t="$(inb_field $i 'type')"
    case "$t" in
      vless)         convert_vless "$i" ;;
      hysteria2)     convert_hy2 "$i" ;;
      shadowtls)     convert_shadowtls "$i" ;;
      tuic)          convert_tuic "$i" ;;
      anytls)        convert_anytls "$i" ;;
      shadowsocks)   convert_ss "$i" ;;
      wireguard)     convert_wg "$i" ;;
      *)             warn "inbound[$i] 类型 '$t' 未支持（1.14 客户端转换表），跳过" ;;
    esac
  done
  [[ -n "$OUTS" ]] || die2 "服务端 config 没有可转换的 inbound（无 vless/hysteria2/shadowtls/tuic/anytls/shadowsocks）"
}

# ═══════════════════════════════════════════════════════════════════════
# 【自检】assert_gen — 转换行为断言（gen-client.sh --test 调用）
# 用 test-env 的服务端 config（setup.sh 生成）直接转 client.json，断言结构。
# 不依赖任何中间配置（config.gen.json/env 已废弃）。
# ═══════════════════════════════════════════════════════════════════════
assert_gen() {
  local LIB_DIR ROOT TEST BIN GEN PASS FAIL code M1 M2 TMPD2 SRVCFG
  LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  ROOT="$(dirname "$LIB_DIR")"
  TEST="$ROOT/test-env"
  BIN="${SB_BIN:-/tmp/sing-box-1.14.0-beta.14-linux-amd64/sing-box}"
  GEN="$ROOT/scripts/gen-client.sh"
  SRVCFG="$TEST/server/config.json"
  [[ -x "$BIN" ]] || { err "缺测试二进制: $BIN"; return 1; }
  if [[ ! -f "$SRVCFG" ]]; then
    warn "缺 test-env/server/config.json，先跑 bash test-env/setup.sh"
    ( cd "$TEST" && bash setup.sh >/dev/null 2>&1 ) || { err "setup.sh 失败"; return 1; }
  fi
  TMPD2="$(mktemp -d)" || die1 "无法创建临时目录"
  trap '[[ -n "${TMPD2:-}" ]] && rm -rf "$TMPD2"' EXIT
  PASS=0; FAIL=0
  debug "assert_gen: TMPD=$TMPD2 SRVCFG=$SRVCFG"

  check() { if [[ "$3" -eq "$2" ]]; then echo "  ✔ $1"; PASS=$((PASS+1)); else echo "  ✗ $1（期望退出 $2，实际 $3）${4:-}"; FAIL=$((FAIL+1)); fi; }
  run_gen() { # $1=server config  $2=额外参数 → 输出退出码
    SB_OUTPUT="$TMPD2/out.json" SB_BIN="$BIN" bash "$GEN" --from-server "$1" --server 127.0.0.1 --insecure ${2:-} >"$TMPD2/log.txt" 2>&1
    echo "$?"
  }

  echo "=== A. 参数/依赖错误（退出码 1） ==="
  code=$(run_gen /nonexistent.json);         check "server config 不存在 → 1" 1 "$code"
  echo "=== B. 转换失败（退出码 2） ==="
  python3 -c "import json;json.dump({'inbounds':[]},open('$TMPD2/empty.json','w'))"
  code=$(run_gen "$TMPD2/empty.json");       check "空 inbounds → 2" 2 "$code"
  echo "=== C. 六线转换结构断言（退出码 0 + 结构） ==="
  code=$(run_gen "$SRVCFG");                 check "六线转换 → 0" 0 "$code"
  python3 - "$TMPD2/out.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
errs = []
tags = {o["tag"] for o in c["outbounds"]}
expect = {"reality","hy2","shadowtls","ss-over-st","tuic","anytls","auto","manual","direct","block"}
if tags != expect: errs.append(f"生成集不对: {sorted(tags)} 期望 {sorted(expect)}")
auto = next(o for o in c["outbounds"] if o["tag"]=="auto")["outbounds"]
manual = next(o for o in c["outbounds"] if o["tag"]=="manual")["outbounds"]
if set(auto) != {"reality","hy2","ss-over-st","tuic","anytls","shadowtls"}: errs.append(f"auto 引用集不对: {auto}")
if manual[0] != "auto" or set(manual[1:]) != {"reality","hy2","ss-over-st","tuic","anytls","shadowtls"}: errs.append(f"manual 引用集不对: {manual}")
if c["route"]["final"] != "auto": errs.append("route.final 不是 auto")
if c["dns"]["servers"][0].get("detour") != "reality": errs.append("DNS detour 不是 reality")
# reality 公钥已从私钥派生（非空）
rv = next(o for o in c["outbounds"] if o["tag"]=="reality")
if not rv["tls"]["reality"].get("public_key"): errs.append("reality 公钥未派生")
if errs:
    print("  ✗ " + "; ".join(errs)); sys.exit(1)
print("  ✔ 六线转换结构通过")
PY
  [[ $? -eq 0 ]] || FAIL=$((FAIL+1))
  echo "=== D. wg endpoint 结构（动态加 wg inbound） ==="
  python3 - "$SRVCFG" "$TMPD2/withwg.json" <<'PY'
import json, sys, base64, os
c = json.load(open(sys.argv[1]))
c["inbounds"].append({
  "type": "wireguard", "tag": "wg-in",
  "listen": "::", "listen_port": 51820,
  "address": ["10.0.0.1/32"], "private_key": base64.b64encode(os.urandom(32)).decode(),
  "peers": [{"public_key": base64.b64encode(os.urandom(32)).decode(), "allowed_ips": ["0.0.0.0/0"]}]
})
json.dump(c, open(sys.argv[2], "w"))
PY
  code=$(run_gen "$TMPD2/withwg.json");     check "含 wg → 0" 0 "$code"
  python3 - "$TMPD2/out.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
errs = []
auto = next(o for o in c["outbounds"] if o["tag"]=="auto")["outbounds"]
manual = next(o for o in c["outbounds"] if o["tag"]=="manual")["outbounds"]
if "wg" in auto: errs.append("wg 在 auto（urltest 测不了 endpoint）")
if "wg" not in manual: errs.append("wg 不在 manual")
if errs:
    print("  ✗ " + "; ".join(errs)); sys.exit(1)
print("  ✔ wg endpoints 结构通过")
PY
  [[ $? -eq 0 ]] || FAIL=$((FAIL+1))
  echo "=== E. 幂等 ==="
  code=$(run_gen "$SRVCFG"); check "幂等第一次 → 0" 0 "$code"
  M1=$(md5sum "$TMPD2/out.json" | cut -d' ' -f1)
  code=$(run_gen "$SRVCFG"); check "幂等第二次 → 0" 0 "$code"
  M2=$(md5sum "$TMPD2/out.json" | cut -d' ' -f1)
  if [[ "$M1" == "$M2" ]]; then echo "  ✔ 两次输出一致"; PASS=$((PASS+1)); else echo "  ✗ 幂等失败"; FAIL=$((FAIL+1)); fi

  echo
  echo "=== 结果: 通过 $PASS / $((PASS+FAIL)) ==="
  [[ $FAIL -eq 0 ]]
}
