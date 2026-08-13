#!/usr/bin/env bash
#
# gen.sh — generate the whole suite locally (never run on the server)
#
# Usage: ./scripts/gen.sh
#
# Deps: bash, openssl(>=1.1.1), uuidgen(optional, falls back to openssl)
#
# Input: hosts.conf — host list (cp hosts.conf.example hosts.conf, fill real IPs)
# Outputs (out/ is .gitignore-excluded, contains server private keys, never commit/leak):
#   out/<name>/server.json       → upload to the VPS
#   out/<name>/secrets.env       → full key archive for that node (recover after reinstall)
#   out/singbox-client.json      → import into official client (m×2 lines + urltest auto-select)
#
# Idempotent: existing node keys are reused; re-runs do not rotate keys.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOSTS_FILE="${ROOT}/hosts.conf"
SERVER_TPL="${ROOT}/templates/server.json.tpl"
OUT_DIR="${ROOT}/out"

# ---------- Version (only change here on upgrade; keep in sync with docs/runbook.md) ----------
SINGBOX_VERSION="1.14.0-beta.14"

# ---------- Helpers ----------

gen_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  else
    local hex
    hex="$(openssl rand -hex 16)"
    printf '%s-%s-%s-%s-%s' "${hex:0:8}" "${hex:8:4}" "${hex:12:4}" "${hex:16:4}" "${hex:20:12}"
  fi
}

# Reality X25519 keypair: prints two lines (priv\npub), URL-safe raw base64
# Note: all openssl calls use explicit </dev/null — this fn may run inside a while read loop,
# inheriting the loop stdin (hosts.conf file stream) would swallow lines and corrupt output.
# Format: sing-box 1.14 Reality keys require URL-safe raw base64 (official reality-keypair
# output: -/_ and no = padding); openssl emits standard base64 with padding, must convert.
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

# sed replacement-value escaping (prevent & | \ breaking the expression)
sed_escape() { printf '%s' "$1" | sed 's/[&|\\]/\\&/g'; }

# ---------- Main ----------

[[ -f "$HOSTS_FILE" ]] || {
  echo "missing $HOSTS_FILE: run cp hosts.conf.example hosts.conf and fill in the real VPS IPs"
  exit 1
}

mkdir -p "$OUT_DIR"

# Pass 1: read list + generate/reuse keys + render server config
declare -a HOST_NAMES=()
declare -A HOST_ADDR HOST_SNI HOST_RPORT HOST_HPORT
declare -A CLIENT_UUID CLIENT_PUB CLIENT_SHORT CLIENT_HY2PASS CLIENT_OBFS

while IFS='|' read -r host addr sni dest rport hport sport; do
  [[ -z "$host" || "$host" == \#* ]] && continue
  [[ "$host" =~ ^[a-z0-9-]+$ ]] || { echo "!! invalid host name (lowercase/digits/hyphens): $host"; exit 1; }

  dir="$OUT_DIR/$host"
  mkdir -p "$dir"

  if [[ -f "$dir/secrets.env" ]]; then
    echo "==> $host: reusing existing keys ($dir/secrets.env)"
    # shellcheck disable=SC1090
    . "$dir/secrets.env"
  else
    echo "==> $host: generating new keys"
    SERVER_UUID="$(gen_uuid < /dev/null)"
    # read consumes one line per call: two reads needed for priv and pub lines
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
done < <(cat "$HOSTS_FILE"; printf '\n')   # trailing newline so read never drops the last line

[[ ${#HOST_NAMES[@]} -gt 0 ]] || { echo "!! no valid host lines in hosts.conf"; exit 1; }

# Pass 2: render client config (Reality + Hy2 per node, 2×N lines)
CLIENT_OUT="$OUT_DIR/singbox-client.json"
# DNS queries pinned to the first node line (breaks the auto→urltest→resolve→DNS loop)
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

  # urltest auto-select group + manual selector group
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
echo "✔ all generated, outputs in $OUT_DIR/:"
echo
printf '  %-12s %-18s %s\n' "node" "address" "file"
for h in "${HOST_NAMES[@]}"; do
  printf '  %-12s %-18s out/%s/server.json (+ secrets.env)\n' "$h" "${HOST_ADDR[$h]}" "$h"
done
echo "  client:      out/singbox-client.json (${#HOST_NAMES[@]} nodes × 2 protocols = $((2 * ${#HOST_NAMES[@]})) lines, auto group) "
echo
echo "!!! out/ contains server private keys and all passwords, never commit / leak !!!"
echo "deploy steps: docs/runbook.md; upgrade: change SINGBOX_VERSION at top (current $SINGBOX_VERSION)"