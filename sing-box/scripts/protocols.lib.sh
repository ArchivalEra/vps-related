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
  [[ ${INSECURE:-0} -eq 1 ]] && echo "⚠ naive 不支持 insecure（须真证书），仍将生成（服务端需真证书）" >&2
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
