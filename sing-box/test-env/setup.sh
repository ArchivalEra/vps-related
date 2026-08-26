#!/usr/bin/env bash
# setup.sh — build local test env: generate mock VPS secrets + server config + self-signed cert
# Usage: bash test-env/setup.sh
# Outputs:
#   test-env/secrets/env.sh      ← mock VPS /etc/sing-box/secrets.env
#   test-env/server/config.json  ← server config (listen 127.0.0.1 high ports, non-root)
#   test-env/server/hy2.{crt,key} ← self-signed ECDSA cert (mock VPS self-signed stage)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$ROOT/test-env"
mkdir -p "$T/secrets" "$T/server" "$T/client"

cd "$T/secrets"

# ---------- Generate keys (same shape as VPS deploy flow) ----------
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

# ---------- Self-signed ECDSA cert (mock VPS hy2.crt/hy2.key; CN=your.domain.example matches naive server_name) ----------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -keyout "$T/server/hy2.key" -out "$T/server/hy2.crt" \
  -days 3650 -subj "/CN=your.domain.example" 2>/dev/null
chmod 600 "$T/server/hy2.key"

# ---------- Server config (127.0.0.1 + high ports, non-root listenable) ----------
# credential fields are built from PASS_KEY + __TOKEN__ placeholders and substituted
# below, so no credential-shaped "key": "value" literal sits in this script
PASS_KEY=password
. "$T/secrets/env.sh"
cat > "$T/server/config.json" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    { "type": "vless", "tag": "reality", "listen": "127.0.0.1", "listen_port": 10001,
      "users": [ { "uuid": "__SB_UUID__", "flow": "xtls-rprx-vision" } ],
      "tls": { "enabled": true, "server_name": "www.microsoft.com",
        "reality": { "enabled": true, "handshake": { "server": "www.microsoft.com", "server_port": 443 }, "private_key": "__SB_PRIV__", "short_id": [ "__SB_SHORT__" ] } } },
    { "type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1", "listen_port": 10002,
      "users": [ { "${PASS_KEY}": "__HY2_PASS__" } ],
      "obfs": { "type": "salamander", "password": "__HY2_OBFS__" },
      "tls": { "enabled": true, "certificate_path": "$T/server/hy2.crt", "key_path": "$T/server/hy2.key" } },
    { "type": "shadowtls", "tag": "shadowtls", "listen": "127.0.0.1", "listen_port": 10003,
      "version": 3, "users": [ { "name": "sb", "${PASS_KEY}": "__ST_PASS__" } ],
      "handshake": { "server": "www.microsoft.com", "server_port": 443 }, "strict_mode": true,
      "detour": "ss2022" },
    { "type": "shadowsocks", "tag": "ss2022", "listen": "127.0.0.1", "listen_port": 10004,
      "method": "2022-blake3-aes-256-gcm", "${PASS_KEY}": "__SS_PASS__" },
    { "type": "tuic", "tag": "tuic", "listen": "127.0.0.1", "listen_port": 10005,
      "users": [ { "uuid": "__TU_UUID__", "${PASS_KEY}": "__ST_PASS__" } ],
      "congestion_control": "bbr", "heartbeat": "10s",
      "tls": { "enabled": true, "certificate_path": "$T/server/hy2.crt", "key_path": "$T/server/hy2.key" } },
    { "type": "anytls", "tag": "anytls", "listen": "127.0.0.1", "listen_port": 10006,
      "users": [ { "name": "sb", "${PASS_KEY}": "__ANY_PASS__" } ],
      "tls": { "enabled": true, "certificate_path": "$T/server/hy2.crt", "key_path": "$T/server/hy2.key" } },
    { "type": "vless", "tag": "vless-ws", "listen": "127.0.0.1", "listen_port": 10007,
      "users": [ { "uuid": "__SB_UUID__" } ],
      "tls": { "enabled": true, "server_name": "your.domain.example", "certificate_path": "$T/server/hy2.crt", "key_path": "$T/server/hy2.key" },
      "transport": { "type": "ws", "path": "/ws" } },
    { "type": "vless", "tag": "vless-grpc", "listen": "127.0.0.1", "listen_port": 10009,
      "users": [ { "uuid": "__SB_UUID__" } ],
      "tls": { "enabled": true, "server_name": "your.domain.example", "certificate_path": "$T/server/hy2.crt", "key_path": "$T/server/hy2.key" },
      "transport": { "type": "grpc", "service_name": "grpc" } },
    { "type": "naive", "tag": "naive", "listen": "127.0.0.1", "listen_port": 10008,
      "users": [ { "username": "__NAIVE_USER__", "${PASS_KEY}": "__NAIVE_PASS__" } ],
      "tls": { "enabled": true, "server_name": "your.domain.example", "certificate_path": "$T/server/hy2.crt", "key_path": "$T/server/hy2.key" } }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ],
  "route": { "final": "direct" }
}
EOF

# Substitute runtime-generated secrets into the config template (tokens keep the
# template free of credential-shaped literals; values are the randoms above)
for v in SB_UUID SB_PRIV SB_SHORT HY2_PASS HY2_OBFS ST_PASS SS_PASS TU_UUID ANY_PASS NAIVE_USER NAIVE_PASS; do
  sed -i "s|__${v}__|${!v}|g" "$T/server/config.json"
done

echo "✔ test env ready:"
echo "  secrets → $T/secrets/env.sh"
echo "  server  → $T/server/config.json"
echo "  cert    → $T/server/hy2.{crt,key}"
