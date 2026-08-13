# sing-box 双节点手动部署手册

犹他（utah）/ 凤凰城（phoenix）两台 VPS，Debian/Ubuntu，root，systemd。
**每一节都是 SSH 里可直接复制粘贴的命令块。**

---

## 0. 流程总览

```
本地生成 (gen.sh) ──scp──▶ 上传 server.json ──▶ 装二进制 → 生成证书 → systemd 托管 → 验证
                                                     └────────▶ 客户端导入 singbox-client.json
```

---

## 1. 端口规划（默认，六线全家桶）

| 端口 | 协议 | 服务 | 角色 |
|---|---|---|---|
| 443/tcp | VLESS+Reality | 抗封锁主力 | 伪装微软，443 标准 HTTPS 语义 |
| 8443/tcp | ShadowTLS → SS2022 | TCP 伪装线 | SSL 端口伪装 |
| 8444/udp | Hysteria2 | QUIC 高吞吐 | Chrome QUIC 指纹伪装（1.14 默认） |
| 8445/udp | TUIC | QUIC 备用 | |
| 2083/tcp | AnyTLS | 1.14 新贵 | |
| 8388/tcp+udp | Shadowsocks 2022 | 兜底 | 单协议双栈，保留 |

**端口纪律：每个端口单一协议**（不搞同端口 tcp/udp 双协议，降低单 IP 流量画像特征）。443 只留给 Reality；QUIC 线靠协议栈指纹伪装（Hy2 的 Chrome QUIC parrot），不依赖端口号，高位端口无损。

---

## 2. 本地生成（只在本机跑，幂等）

```bash
cd <repo-root>
cp hosts.conf.example hosts.conf
# ✏️ 编辑 hosts.conf：把 1.2.3.4 / 5.6.7.8 换成两台 VPS 的真实公网 IP（SNI/端口可按需改）
./scripts/gen.sh
```

产物：

| 文件 | 用途 |
|---|---|
| `out/utah/server.json` | 上传到犹他 VPS |
| `out/phoenix/server.json` | 上传到凤凰城 VPS |
| `out/singbox-client.json` | 客户端导入 |
| `out/<节点>/secrets.env` | 密钥存档（重装换机靠它恢复，勿外传） |

> 幂等：重复运行不会轮换密钥。密钥丢了 = 老客户端全部失效，@secrets.env 一定要备份。

---

## 3. 部署节点（两台步骤完全一样，以 utah 为例）

### 3.1 上传配置

```bash
# 本机执行
scp out/utah/server.json root@<utah-ip>:/etc/sing-box/config.json
```
提示目录不存在就先生成：`ssh root@<utah-ip> 'mkdir -p /etc/sing-box'` 再 scp。

### 3.2 安装 sing-box 1.14.0-beta.14（x86_64，当前为 beta 最新版）

```bash
# VPS 上执行
cd /tmp
curl -fL -o sb.tar.gz https://github.com/SagerNet/sing-box/releases/download/v1.14.0-beta.14/sing-box-1.14.0-beta.14-linux-amd64.tar.gz
tar -xzf sb.tar.gz
install -m 0755 sing-box-1.14.0-beta.14-linux-amd64/sing-box /usr/local/bin/sing-box
sing-box version    # 应显示 v1.14.0-beta.14
```

### 3.3 Hysteria2 自签证书

> ⚠️ 1.14 起 Hy2 客户端默认模仿 Chrome 的 QUIC 握手（`disable_chrome_parrot` 可关），
> **Chrome 不支持 Ed25519 证书，服务端必须用 ECDSA/有效期内的证书**——下面这条命令生成的正是
> prime256v1 椭圆曲线证书，完美兼容。别手痒改成 Ed25519。

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -keyout /etc/sing-box/hy2.key -out /etc/sing-box/hy2.crt \
  -days 3650 -subj "/CN=hy2.$(hostname)"
chmod 600 /etc/sing-box/hy2.key
```

### 3.4 systemd 托管

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

### 3.5 验证

```bash
systemctl status sing-box --no-pager   # Active: active (running)
journalctl -u sing-box -n 20 --no-pager
ss -tlnup | grep -E ':(443|8443|8444|8445|2083|8388)'   # 应看到六线全部监听
```

**Reality 回落检查**：从**没走代理**的浏览器访问 `https://<utah-ip>:443`——应看到真实网站
（该 IP 的证书错误页/微软页面内容），而不是连接被拒。回落正常 = Reality 伪装生效。

---

## 4. 防火墙

```bash
# 若启用了 ufw（其他防火墙/云安全组同理放行）
ufw allow 443/tcp && ufw allow 443/udp && ufw allow 8388/tcp && ufw allow 8388/udp
ufw reload
```

---

## 5. 客户端（官方 sing-box）

1. 把 `out/singbox-client.json` 发到手机/电脑（微信/AirDrop/iCloud 随意）
2. 导入：
   - **iOS**：sing-box (SFA) → 右上角 `+` → 从文件导入
   - **Android**：sing-box 官方应用 → 配置 → 导入文件
   - **macOS/Windows**：官方应用同上；或 CLI：`sing-box run -c singbox-client.json`
3. 打开 TUN 开关即全局接管。
4. `auto` 组会自动在 4 条线路（犹他/凤凰城 × Reality/Hy2）间轮询测延迟，**选最低者；节点挂了自动切到另一台**，无需手动干预。

想锁定某条线路：把配置里 `"route"` 的 `"final": "auto"` 改成 `"manual"`，然后在客户端手动选。

---

## 6. 日常维护

| 操作 | 命令 / 步骤 |
|---|---|
| 看日志 | `journalctl -u sing-box -f` |
| 升级版本 | 改 `scripts/gen.sh` 顶部 `SINGBOX_VERSION` → 重跑 gen → 服务器重复 3.2 → `systemctl restart sing-box`（配置无需重传） |
| 换 SNI/端口 | 改 `hosts.conf` → 重跑 gen → 重传对应 `server.json` → `systemctl restart sing-box` |
| 加第三个节点 | `hosts.conf` 加一行 → 重跑 gen → 新节点按第 3 节部署；客户端配置会自动包含新节点 |
| 服务器重装 | 重装系统后按第 3 节重来，配置和密钥都在 `out/` 里，不用重新生成 |
| 换密钥 | 删掉 `out/<节点>/secrets.env` → 重跑 gen → 重传配置重启（老密码全作废） |

---

## 7. 附录：加料（可选）

> 以下都需要往 `/etc/sing-box/config.json` 的 `inbounds` 数组里加一段，然后
> `systemctl restart sing-box`。密钥用 `out/<节点>/secrets.env` 里的值。

### 7.1 TUIC（又一个 QUIC 协议，多一份保险）

```json
{
  "type": "tuic",
  "tag": "tuic-in",
  "listen": "::",
  "listen_port": 8443,
  "users": [ { "uuid": "SERVER_UUID 的值", "password": "HY2_PASSWORD 的值" } ],
  "congestion_control": "bbr",
  "tls": { "enabled": true, "certificate_path": "/etc/sing-box/hy2.crt", "key_path": "/etc/sing-box/hy2.key" }
}
```

### 7.2 Trojan（需要域名 + 正规证书，可套 CDN）

域名解析到 VPS 并签发证书（acme.sh / caddy 都行）后：

```json
{
  "type": "trojan",
  "tag": "trojan-in",
  "listen": "::",
  "listen_port": 8443,
  "users": [ { "password": "HY2_PASSWORD 的值" } ],
  "tls": {
    "enabled": true,
    "server_name": "你的域名",
    "certificate_path": "/etc/letsencrypt/live/你的域名/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/你的域名/privkey.pem"
  }
}
```

### 7.3 VMess+WS（CDN 兜底线路，同样需要域名证书）

```json
{
  "type": "vmess",
  "tag": "vmess-ws-in",
  "listen": "::",
  "listen_port": 8443,
  "users": [ { "uuid": "SERVER_UUID 的值", "alterId": 0 } ],
  "transport": { "type": "ws", "path": "/ws" },
  "tls": {
    "enabled": true,
    "server_name": "你的域名",
    "certificate_path": "/etc/letsencrypt/live/你的域名/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/你的域名/privkey.pem"
  }
}
```

> 7.2 / 7.3 需要"你的域名"这两台上暂时没有（`another-project-domain` 在别的项目里），等域名到手再补不迟。