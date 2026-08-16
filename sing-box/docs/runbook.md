# sing-box Two-Node Manual Deployment Runbook

Two VPS nodes (node-a / node-b), Debian/Ubuntu, root, systemd.
**Every section is a command block you can copy-paste directly into SSH.**

---

## 0. Flow Overview

```
Server config.json ──▶ gen-client.sh ──▶ client.json (imported by client)
     (manually maintained on the VPS, contains all protocols/keys/ports)
```

---

## 1. Port Plan (six-line family, aligned with the client generator gen-client.sh defaults)

| Port | Protocol | Service | Role |
|---|---|---|---|
| 443/tcp | VLESS+Reality | primary anti-blocking line | impersonates Microsoft; standard 443 HTTPS semantics |
| 443/udp | Hysteria2 | QUIC high throughput | standard HTTP/3 port + Chrome QUIC fingerprint (1.14 default) |
| 8443/tcp | ShadowTLS → SS2022 | TCP camouflage line | SSL-port camouflage |
| 8445/udp | TUIC | QUIC backup | |
| 2083/tcp | AnyTLS | new in 1.14 | |
| 8388/tcp+udp | Shadowsocks 2022 | fallback | single protocol, dual stack, kept |

**Port discipline**: 443/tcp + 443/udp carry Reality + Hy2 (standard HTTPS + HTTP/3 combo, same as real sites); every other port hosts a single protocol — no same-port tcp/udp dual protocols. QUIC lines rely on protocol-stack fingerprinting for camouflage (Hy2's Chrome QUIC parrot), not on port numbers.

> Note: the server `config.json` is maintained manually on the VPS (`test-env/server/config.json` in this repo is a local test sample); gen-client.sh only reads it to generate the client config — it does not generate the server config.

---

## 2. Client Config Generation (server config.json → client.json)

```bash
# Put the two scripts in the same directory (scripts/gen-client.sh + scripts/protocols.lib.sh); runnable on any machine
SB_OUTPUT=~/client.json bash gen-client.sh --from-server /etc/sing-box/config.json --server your-domain.com
#   --from-server: server-side sing-box config.json (sole input, contains all protocols/keys/ports)
#   --server: client connection address (dual-stack domain / IPv4 / IPv6); omitted -> prompted interactively
#   --insecure: add when the certificate is self-signed; not needed for a real certificate
#   --debug: diagnostic output (fully silent by default)
#   --test: run the self-check assertions (6 items, no test-env dependency)
```

Output: `client.json` — import it into the official client (SFA/SFI) from file.

> Zero persistence: config paths, addresses, and keys are never written to disk; no state files of any kind.

---

## 3. Deploy a Node (both nodes are identical; node-a used as the example)

### 3.1 Upload the server config

> The server `config.json` is maintained manually (contains all protocols/keys/ports); write it directly to the VPS:

```bash
# Edit locally then upload (or edit directly on the VPS)
scp /your/config.json root@<node-a-ip>:/etc/sing-box/config.json
```
If the directory doesn't exist, create it first: `ssh root@<node-a-ip> 'mkdir -p /etc/sing-box'` and then scp.

### 3.2 Install sing-box 1.14.0-beta.14 (x86_64, currently the latest beta)

```bash
# Run on the VPS
cd /tmp
wget -O sb.tar.gz https://github.com/SagerNet/sing-box/releases/download/v1.14.0-beta.14/sing-box-1.14.0-beta.14-linux-amd64.tar.gz
tar -xzf sb.tar.gz
install -m 0755 sing-box-1.14.0-beta.14-linux-amd64/sing-box /usr/local/bin/sing-box
sing-box version    # should show v1.14.0-beta.14
```

### 3.3 Hysteria2 self-signed certificate

> ⚠️ Since 1.14, the Hy2 client mimics Chrome's QUIC handshake by default (`disable_chrome_parrot` can turn it off).
> **Chrome does not support Ed25519 certificates, so the server must use an ECDSA / in-validity-period certificate** — the command below generates exactly that:
> a prime256v1 elliptic-curve certificate, fully compatible. Don't be tempted to switch to Ed25519.

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -keyout /etc/sing-box/hy2.key -out /etc/sing-box/hy2.crt \
  -days 3650 -subj "/CN=hy2.$(hostname)"
chmod 600 /etc/sing-box/hy2.key
```

### 3.4 systemd service

```bash
cat > /etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sing-box
```

### 3.5 Verification

```bash
systemctl status sing-box --no-pager   # Active: active (running)
journalctl -u sing-box -n 20 --no-pager
ss -tlnup | grep -E ':(443|8443|8445|2083|8388)'   # base three lines: at least 443/tcp+udp and 8388; appendix lines each show their port after being added per §7
```

**Reality fallback check**: from a browser that has **not** gone through the proxy, visit `https://<node-a-ip>:443` — you should see the real site
(cert-error page for that IP / Microsoft page content), not a connection refused. Fallback working = Reality camouflage in effect.

---

## 4. Firewall

```bash
# If ufw is enabled (open the same ports on other firewalls / cloud security groups)
ufw allow 443/tcp && ufw allow 443/udp && ufw allow 8388/tcp && ufw allow 8388/udp
ufw reload
```

---

## 5. Client (official sing-box)

1. Send the `client.json` generated by gen-client.sh to your phone/computer (WeChat/AirDrop/iCloud, any way works)
2. Import:
   - **iOS**: sing-box (SFA) → `+` in the top-right corner → import from file
   - **Android**: official sing-box app → Config → import file
   - **macOS/Windows**: same in the official app; or CLI: `sing-box run -c singbox-client.json`
3. Turn on the TUN switch to take over all traffic globally.
4. The `auto` group automatically probes latency across the 4 lines (node-a/node-b × Reality/Hy2) and **picks the lowest; if a node goes down it automatically switches to the other**, no manual intervention needed.

To pin a specific line: change `"final": "auto"` to `"manual"` under `"route"` in the config, then select it manually in the client.

---

## 6. Daily Maintenance

| Operation | Command / steps |
|---|---|
| View logs | `journalctl -u sing-box -f` |
| Upgrade version | replace the sing-box binary (3.2) → update `SINGBOX_VERSION`/`SINGBOX_MAJOR_MINOR` at the top of `gen-client.sh` (per the maintenance guide SOP) → rerun gen-client.sh → `systemctl restart sing-box` |
| Change SNI/port | edit the server `config.json` → `systemctl restart sing-box` → rerun gen-client.sh to produce a new client config |
| Add a third node | add the corresponding inbound to the server config.json → rerun gen-client.sh (the new line joins the `auto` group automatically) |
| Server reinstall | after reinstall, redo section 3 (back up config and keys manually) |
| Rotate keys | change the keys in the server config.json → restart → rerun gen-client.sh (all old client configs become invalid) |

---

## 7. Appendix: Extras (optional)

> Each of the following requires adding a block to the `inbounds` array in `/etc/sing-box/config.json`, then
> `systemctl restart sing-box`. Use keys you generate/save yourself (see the structure of `test-env/secrets/env.sh`).

### 7.1 TUIC (another QUIC protocol, an extra layer of insurance)

```json
{
  "type": "tuic",
  "tag": "tuic-in",
  "listen": "::",
  "listen_port": 8445,
  "users": [ { "uuid": "value of SERVER_UUID", "password": "value of ST_PASS (SHADOWTLS_PASSWORD in secrets.env, same key as ST_PASS in the client gen-client.sh)" } ],
  "congestion_control": "bbr",
  "tls": { "enabled": true, "certificate_path": "/etc/sing-box/hy2.crt", "key_path": "/etc/sing-box/hy2.key" }
}
```

### 7.1b VLESS+WS (WebSocket transport, real cert or self-signed both fine)

```json
{
  "type": "vless",
  "tag": "vless-ws-in",
  "listen": "::",
  "listen_port": 8446,
  "users": [ { "uuid": "value of SERVER_UUID" } ],
  "tls": { "enabled": true, "server_name": "your-domain.com", "certificate_path": "/etc/sing-box/hy2.crt", "key_path": "/etc/sing-box/hy2.key" },
  "transport": { "type": "ws", "path": "/ws" }
}
```

### 7.1c Naive (needs a real certificate + libcronet.so; cronet validation is strict)

> ⚠️ naive has no `insecure` option (cronet hard constraint), **a real certificate is mandatory** (a self-signed cert's CN must match server_name);
> depends on `libcronet.so` sitting in the same dir as the sing-box binary (included in the 1.14 suffix-less package).

```json
{
  "type": "naive",
  "tag": "naive-in",
  "listen": "::",
  "listen_port": 8449,
  "users": [ { "username": "sb", "password": "value of NAIVE_PASS" } ],
  "tls": { "enabled": true, "server_name": "your-domain.com", "certificate_path": "/etc/letsencrypt/live/your-domain.com/fullchain.pem", "key_path": "/etc/letsencrypt/live/your-domain.com/privkey.pem" }
}
```

### 7.2 Trojan (needs a domain + proper certificate)

After the domain resolves to the VPS and a certificate is issued (acme.sh / caddy either works):

```json
{
  "type": "trojan",
  "tag": "trojan-in",
  "listen": "::",
  "listen_port": 8447,
  "users": [ { "password": "value of TROJAN_PASS" } ],
  "tls": {
    "enabled": true,
    "server_name": "your-domain.com",
    "certificate_path": "/etc/letsencrypt/live/your-domain.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/your-domain.com/privkey.pem"
  }
}
```

### 7.3 VMess+WS (needs a domain certificate; CDN fronting has been proven a dead end, direct connection only as backup)

```json
{
  "type": "vmess",
  "tag": "vmess-ws-in",
  "listen": "::",
  "listen_port": 8448,
  "users": [ { "uuid": "value of SERVER_UUID", "alterId": 0 } ],
  "transport": { "type": "ws", "path": "/ws" },
  "tls": {
    "enabled": true,
    "server_name": "your-domain.com",
    "certificate_path": "/etc/letsencrypt/live/your-domain.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/your-domain.com/privkey.pem"
  }
}
```

> 7.2 / 7.3 require "your domain" (a domain from another project, out of this repo's scope); add them later once the domain is configured.
