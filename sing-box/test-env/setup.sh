#!/usr/bin/env bash
# setup.sh — 本机测试环境搭建：生成模拟 VPS 的 secrets + 六线 server 配置 + 自签证书
# 用法: bash test-env/setup.sh
# 产物:
#   test-env/secrets/env.sh     ← 模拟 VPS 的 /etc/sing-box/secrets.env
#   test-env/server/config.json ← 六线服务端配置（listen 127.0.0.1 高端口，非 root 可跑）
#   test-env/server/hy2.{crt,key} ← 自签 ECDSA 证书（模拟 VPS 自签阶段）
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$ROOT/test-env"
mkdir -p "$T/secrets" "$T/server" "$T/client"

cd "$T/secrets"

# ---------- 生成密钥（与 VPS 部署流程同构） ----------
SB_UUID=$(cat /proc/sys/kernel/random/uuid)
openssl genpkey -algorithm X25519 -out /tmp/te-x.pem 2>/dev/null
SB_PRIV=$(openssl pkey -in /tmp/te-x.pem -outform DER 2>/dev/null | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')
SB_PUB=$(openssl pkey -in /tmp/te-x.pem -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')
rm -f /tmp/te-x.pem
SB_SHORT=$(openssl rand -hex 4)
HY2_PASS=$(openssl rand -hex 16)
HY2_OBFS=$(openssl rand -hex 8)
SS_PASS=$(openssl rand -base64 32)
ST_PASS=$(openssl rand -hex 16)
TU_UUID=$(cat /proc/sys/kernel/random/uuid)
ANY_PASS=$(openssl rand -hex 16)
NAIVE_USER="sb"
NAIVE_PASS=$(openssl rand -hex 16)

cat > env.sh <<EOF
SB_UUID='$SB_UUID'
SB_PRIV='$SB_PRIV'
SB_PUB='$SB_PUB'
SB_SHORT='$SB_SHORT'
HY2_PASS='$HY2_PASS'
HY2_OBFS='$HY2_OBFS'
SS_PASS='$SS_PASS'
ST_PASS='$ST_PASS'
TU_UUID='$TU_UUID'
ANY_PASS='$ANY_PASS'
NAIVE_USER='$NAIVE_USER'
NAIVE_PASS='$NAIVE_PASS'
EOF
chmod 600 env.sh

# ---------- 自签 ECDSA 证书（模拟 VPS hy2.crt/hy2.key；CN 用 your.domain.example 与 naive 的 server_name 匹配） ----------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -keyout "$T/server/hy2.key" -out "$T/server/hy2.crt" \
  -days 3650 -subj "/CN=your.domain.example" 2>/dev/null
chmod 600 "$T/server/hy2.key"

# ---------- 六线 server 配置（127.0.0.1 + 高端口，非 root 可监听） ----------
. "$T/secrets/env.sh"
cat > "$T/server/config.json" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    { "type": "vless", "tag": "reality-in", "listen": "127.0.0.1", "listen_port": 10001,
      "users": [ { "uuid": "$SB_UUID", "flow": "xtls-rprx-vision" } ],
      "tls": { "enabled": true, "server_name": "www.microsoft.com",
        "reality": { "enabled": true, "handshake": { "server": "www.microsoft.com", "server_port": 443 }, "private_key": "$SB_PRIV", "short_id": [ "$SB_SHORT" ] } } },
    { "type": "hysteria2", "tag": "hy2-in", "listen": "127.0.0.1", "listen_port": 10002,
      "users": [ { "password": "$HY2_PASS" } ],
      "obfs": { "type": "salamander", "password": "$HY2_OBFS" },
      "tls": { "enabled": true, "certificate_path": "$T/server/hy2.crt", "key_path": "$T/server/hy2.key" } },
    { "type": "shadowtls", "tag": "st-in", "listen": "127.0.0.1", "listen_port": 10003,
      "version": 3, "users": [ { "name": "sb", "password": "$ST_PASS" } ],
      "handshake": { "server": "www.microsoft.com", "server_port": 443 }, "strict_mode": true,
      "detour": "ss2022-in" },
    { "type": "shadowsocks", "tag": "ss2022-in", "listen": "127.0.0.1", "listen_port": 10004,
      "method": "2022-blake3-aes-256-gcm", "password": "$SS_PASS" },
    { "type": "tuic", "tag": "tuic-in", "listen": "127.0.0.1", "listen_port": 10005,
      "users": [ { "uuid": "$TU_UUID", "password": "$ST_PASS" } ],
      "congestion_control": "bbr",
      "tls": { "enabled": true, "certificate_path": "$T/server/hy2.crt", "key_path": "$T/server/hy2.key" } },
    { "type": "anytls", "tag": "anytls-in", "listen": "127.0.0.1", "listen_port": 10006,
      "users": [ { "name": "sb", "password": "$ANY_PASS" } ],
      "tls": { "enabled": true, "certificate_path": "$T/server/hy2.crt", "key_path": "$T/server/hy2.key" } },
    { "type": "vless", "tag": "vless-ws-in", "listen": "127.0.0.1", "listen_port": 10007,
      "users": [ { "uuid": "$SB_UUID" } ],
      "tls": { "enabled": true, "server_name": "your.domain.example", "certificate_path": "$T/server/hy2.crt", "key_path": "$T/server/hy2.key" },
      "transport": { "type": "ws", "path": "/ws" } },
    { "type": "naive", "tag": "naive-in", "listen": "127.0.0.1", "listen_port": 10008,
      "users": [ { "username": "$NAIVE_USER", "password": "$NAIVE_PASS" } ],
      "tls": { "enabled": true, "server_name": "your.domain.example", "certificate_path": "$T/server/hy2.crt", "key_path": "$T/server/hy2.key" } }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ],
  "route": { "final": "direct" }
}
EOF

echo "✔ 测试环境就绪:"
echo "  secrets → $T/secrets/env.sh"
echo "  server  → $T/server/config.json"
echo "  证书    → $T/server/hy2.{crt,key}"
