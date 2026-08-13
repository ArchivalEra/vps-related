#!/usr/bin/env bash
#
# gen.sh — 本地生成整个套件的全部配置（不上服务器执行）
#
# 用法: ./scripts/gen.sh
#
# 依赖: bash、openssl(>=1.1.1)、uuidgen(可选，缺失时用 openssl 兜底)
#
# 输入: hosts.conf  —— 主机清单（cp hosts.conf.example hosts.conf 后填真实 IP）
# 产物 (out/ 已被 .gitignore 排除，含服务端私钥，切勿提交/外传):
#   out/<name>/server.json       → 上传到对应 VPS 使用
#   out/<name>/secrets.env       → 该节点全部密钥存档（重装/换机靠它恢复）
#   out/singbox-client.json      → 官方客户端导入（m×2 条线路 + urltest 自动选择）
#
# 幂等: 已存在的节点密钥会被复用，重复运行不会轮换密钥。
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOSTS_FILE="${ROOT}/hosts.conf"
SERVER_TPL="${ROOT}/templates/server.json.tpl"
OUT_DIR="${ROOT}/out"

# ---------- 版本（升级 sing-box 时只改这里；与 docs/runbook.md 保持一致） ----------
SINGBOX_VERSION="1.14.0-beta.14"

# ---------- 工具函数 ----------

gen_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  else
    local hex
    hex="$(openssl rand -hex 16)"
    printf '%s-%s-%s-%s-%s' "${hex:0:8}" "${hex:8:4}" "${hex:12:4}" "${hex:16:4}" "${hex:20:12}"
  fi
}

# Reality X25519 密钥对：输出两行（私钥\n公钥），URL-safe raw base64
# 注意：全部 openssl 都显式 </dev/null——本函数可能被 while read 循环调用，
# 若继承循环 stdin（即 hosts.conf 的文件流）会把清单行当输入吞掉，导致导出错乱。
# 格式：sing-box 1.14 的 Reality 密钥要求 URL-safe raw base64（官方 reality-keypair
# 输出格式，含 -/_ 且无 = padding）；openssl 默认给的是标准 base64 带 padding，必须转换。
gen_reality_keys() {
  local pem priv pub
  pem="$(mktemp)"
  openssl genpkey -algorithm X25519 -out "$pem" 2>/dev/null </dev/null
  priv="$(openssl pkey -in "$pem" -outform DER 2>/dev/null </dev/null | tail -c 32 | base64 -w0)"
  pub="$(openssl pkey -in "$pem" -pubout -outform DER 2>/dev/null </dev/null | tail -c 32 | base64 -w0)"
  rm -f "$pem"
  priv="$(printf '%s' "$priv" | tr '+/' '-_' | tr -d '=')"
  pub="$(printf '%s' "$pub" | tr '+/' '-_' | tr -d '=')"
  printf '%s\n%s\n' "$priv" "$pub"
}

# sed 替换值专用转义（防 & | \ 破坏替换式）
sed_escape() { printf '%s' "$1" | sed 's/[&|\\]/\\&/g'; }

# ---------- 主流程 ----------

[[ -f "$HOSTS_FILE" ]] || {
  echo "缺少 $HOSTS_FILE：先执行 cp hosts.conf.example hosts.conf 并填入 VPS 真实 IP"
  exit 1
}

mkdir -p "$OUT_DIR"

# 第一遍：读清单 + 生成/复用密钥 + 渲染服务端配置
declare -a HOST_NAMES=()
declare -A HOST_ADDR HOST_SNI HOST_RPORT HOST_HPORT
declare -A CLIENT_UUID CLIENT_PUB CLIENT_SHORT CLIENT_HY2PASS CLIENT_OBFS

while IFS='|' read -r host addr sni dest rport hport sport; do
  [[ -z "$host" || "$host" == \#* ]] && continue
  [[ "$host" =~ ^[a-z0-9-]+$ ]] || { echo "!! 主机名非法（须小写字母/数字/连字符）: $host"; exit 1; }

  dir="$OUT_DIR/$host"
  mkdir -p "$dir"

  if [[ -f "$dir/secrets.env" ]]; then
    echo "==> $host: 复用已有密钥 ($dir/secrets.env)"
    # shellcheck disable=SC1090
    . "$dir/secrets.env"
  else
    echo "==> $host: 生成新密钥"
    SERVER_UUID="$(gen_uuid < /dev/null)"
    # read 一次只消费一行：必须两条 read，分别取私钥行和公钥行
    { read -r REALITY_PRIVATE_KEY; read -r REALITY_PUBLIC_KEY; } <<<"$(gen_reality_keys)"
    REALITY_SHORT_ID="$(openssl rand -hex 4 < /dev/null)"
    HY2_PASSWORD="$(openssl rand -hex 16 < /dev/null)"
    HY2_OBFS="$(openssl rand -hex 8 < /dev/null)"
    SS_PASSWORD="$(openssl rand -base64 32 < /dev/null | tr -d '\n')"
    cat > "$dir/secrets.env" <<EOF
SERVER_UUID='$SERVER_UUID'
REALITY_PRIVATE_KEY='$REALITY_PRIVATE_KEY'
REALITY_PUBLIC_KEY='$REALITY_PUBLIC_KEY'
REALITY_SHORT_ID='$REALITY_SHORT_ID'
HY2_PASSWORD='$HY2_PASSWORD'
HY2_OBFS='$HY2_OBFS'
SS_PASSWORD='$SS_PASSWORD'
EOF
    chmod 600 "$dir/secrets.env"
  fi

  sed -e "s|__SERVER_UUID__|$(sed_escape "$SERVER_UUID")|g" \
      -e "s|__REALITY_PRIVATE_KEY__|$(sed_escape "$REALITY_PRIVATE_KEY")|g" \
      -e "s|__REALITY_SHORT_ID__|$(sed_escape "$REALITY_SHORT_ID")|g" \
      -e "s|__REALITY_SNI__|$(sed_escape "$sni")|g" \
      -e "s|__REALITY_DEST__|$(sed_escape "$dest")|g" \
      -e "s|__REALITY_PORT__|$rport|g" \
      -e "s|__HY2_PORT__|$hport|g" \
      -e "s|__HY2_PASSWORD__|$(sed_escape "$HY2_PASSWORD")|g" \
      -e "s|__HY2_OBFS__|$(sed_escape "$HY2_OBFS")|g" \
      -e "s|__SS_PORT__|$sport|g" \
      -e "s|__SS_PASSWORD__|$(sed_escape "$SS_PASSWORD")|g" \
      "$SERVER_TPL" > "$dir/server.json"

  HOST_NAMES+=("$host")
  HOST_ADDR[$host]="$addr"
  HOST_SNI[$host]="$sni"
  HOST_RPORT[$host]="$rport"
  HOST_HPORT[$host]="$hport"
  CLIENT_UUID[$host]="$SERVER_UUID"
  CLIENT_PUB[$host]="$REALITY_PUBLIC_KEY"
  CLIENT_SHORT[$host]="$REALITY_SHORT_ID"
  CLIENT_HY2PASS[$host]="$HY2_PASSWORD"
  CLIENT_OBFS[$host]="$HY2_OBFS"
done < <(cat "$HOSTS_FILE"; printf '\n')   # 末尾补换行，防止最后一行无换行被 read 丢弃

[[ ${#HOST_NAMES[@]} -gt 0 ]] || { echo "!! hosts.conf 里没有有效主机行"; exit 1; }

# 第二遍：渲染客户端配置（每节点 Reality + Hy2，共 2×N 条线路）
CLIENT_OUT="$OUT_DIR/singbox-client.json"
# DNS 查询固定走第一条节点线路（打破 auto→urltest→测速需解析→又走 DNS 的循环）
DNS_DETOUR="${HOST_NAMES[0]}-reality"
{
  printf '{\n'
  printf '  "log": { "level": "info", "timestamp": true },\n'
  printf '  "dns": {\n'
  printf '    "servers": [\n'
  printf '    { "type": "https", "tag": "remote", "server": "8.8.8.8", "server_port": 443, "path": "/dns-query", "detour": "%s" },\n' "$DNS_DETOUR"
  printf '    { "type": "local", "tag": "local" }\n'
  printf '    ],\n'
  printf '    "final": "remote",\n'
  printf '    "strategy": "prefer_ipv4"\n'
  printf '  },\n'
  printf '  "inbounds": [\n'
  printf '    { "type": "tun", "tag": "tun-in", "interface_name": "utun225", "mtu": 9000, "auto_route": true, "strict_route": true, "stack": "system" }\n'
  printf '  ],\n'
  printf '  "outbounds": [\n'

  first=1
  for h in "${HOST_NAMES[@]}"; do
    [[ $first -eq 1 ]] && first=0 || printf ',\n'
    printf '    { "type": "vless", "tag": "%s-reality", "server": "%s", "server_port": %s, "uuid": "%s", "flow": "xtls-rprx-vision", "packet_encoding": "xudp", "tls": { "enabled": true, "server_name": "%s", "utls": { "enabled": true, "fingerprint": "chrome" }, "reality": { "enabled": true, "public_key": "%s", "short_id": "%s" } } }' \
      "$h" "${HOST_ADDR[$h]}" "${HOST_RPORT[$h]}" "${CLIENT_UUID[$h]}" "${HOST_SNI[$h]}" "${CLIENT_PUB[$h]}" "${CLIENT_SHORT[$h]}"
    printf ',\n'
    printf '    { "type": "hysteria2", "tag": "%s-hy2", "server": "%s", "server_port": %s, "password": "%s", "obfs": { "type": "salamander", "password": "%s" }, "tls": { "enabled": true, "server_name": "%s", "insecure": true } }' \
      "$h" "${HOST_ADDR[$h]}" "${HOST_HPORT[$h]}" "${CLIENT_HY2PASS[$h]}" "${CLIENT_OBFS[$h]}" "${HOST_SNI[$h]}"
  done
  printf ',\n'

  # urltest 自动选优组 + 手动选择组
  tags=""
  for h in "${HOST_NAMES[@]}"; do
    [[ -z "$tags" ]] || tags+=", "
    tags+="\"$h-reality\", \"$h-hy2\""
  done
  printf '    { "type": "urltest", "tag": "auto", "outbounds": [ %s ], "url": "https://www.gstatic.com/generate_204", "interval": "3m" },\n' "$tags"
  printf '    { "type": "selector", "tag": "manual", "outbounds": [ "auto", %s ], "default": "auto" },\n' "$tags"
  printf '    { "type": "direct", "tag": "direct" },\n'
  printf '    { "type": "block", "tag": "block" }\n'
  printf '  ],\n'
  printf '  "route": { "auto_detect_interface": true, "default_domain_resolver": "remote", "final": "auto", "rules": [ { "ip_cidr": [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8" ], "outbound": "direct" } ] }\n'
  printf '}\n'
} > "$CLIENT_OUT"

echo
echo "✔ 全部生成完毕，产物在 $OUT_DIR/:"
echo
printf '  %-12s %-18s %s\n' "节点" "地址" "文件"
for h in "${HOST_NAMES[@]}"; do
  printf '  %-12s %-18s out/%s/server.json (+ secrets.env)\n' "$h" "${HOST_ADDR[$h]}" "$h"
done
echo "  客户端:      out/singbox-client.json（${#HOST_NAMES[@]} 节点 × 2 协议 = $((2 * ${#HOST_NAMES[@]})) 条线路，auto 组自动选优）"
echo
echo "!!! out/ 内含服务端私钥与全部密码，切勿提交 git / 外传 !!!"
echo "部署步骤见 docs/runbook.md；升级版本改本脚本顶部 SINGBOX_VERSION（当前 $SINGBOX_VERSION）"