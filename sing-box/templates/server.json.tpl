{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": "::",
      "listen_port": __REALITY_PORT__,
      "users": [ { "uuid": "__SERVER_UUID__", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true,
        "server_name": "__REALITY_SNI__",
        "reality": {
          "enabled": true,
          "handshake": { "server": "__REALITY_DEST__", "server_port": 443 },
          "private_key": "__REALITY_PRIVATE_KEY__",
          "short_id": [ "__REALITY_SHORT_ID__" ]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": __HY2_PORT__,
      "users": [ { "password": "__HY2_PASSWORD__" } ],
      "obfs": { "type": "salamander", "password": "__HY2_OBFS__" },
      "tls": {
        "enabled": true,
        "certificate_path": "/etc/sing-box/hy2.crt",
        "key_path": "/etc/sing-box/hy2.key"
      }
    },
    {
      "type": "shadowsocks",
      "tag": "ss2022-in",
      "listen": "::",
      "listen_port": __SS_PORT__,
      "method": "2022-blake3-aes-256-gcm",
      "password": "__SS_PASSWORD__"
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": { "final": "direct" }
}