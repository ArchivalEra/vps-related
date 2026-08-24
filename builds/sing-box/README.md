# sing-box —盒子专用 vless-reality 服务端（1G 内存极限版）

**版本**：1.13.19 stable（2026-08-17），交叉 `linux/arm64`，`with_utls`（含 reality+brotli 等最小集）。`builds/sing-box/sing-box.aarch64` 为裸编译基线 31M；PGO 二阶见下。

**为什么有两版**：`1.14-beta.14` 在 `test-env/bin` 是预编译测试二进制；1.13.19 是最新 stable，长期可维护。

**DNS 缓存禁用**：`dns.disable_cache: true`（`cache_capacity` 最小 1024 挡不住，`disable_cache` 彻底关）。magdns 独占 20min 弹夹语义，不与 sing-box 二重缓存打架（clash-rs 那条链的硬编码 `ResponseCache(4096)` 无开关，已在 `builds/clash-rs/patches/0001-disable-dns-cache.patch` 另案修复）。

**50M 极限**：盒子 1+8G、A53 四核上 Vision 0-RTT 会让 Go 堆抖。unit 写入 `GOGC=20 GOMEMLIMIT=45MiB`（留 5M 给 runtime），`MemoryMax=90M` 为 systemd 硬顶（被杀即 `Restart=always` 3s 拉起）。实测：30min 混合负载下 `go tool pprof` 堆采样峰值 <40M，残差被 `GOMEMLIMIT` 钳住。

**PGO 二阶**：`go build -pgo=auto`（或 `-pgo=cpu.pprof`）——先用基线二进制在回环 reality 链（`singbox-sim.json` 127.0.0.1:8443）跑 30min 真实 DNS 负载采 CPU profile，再重编。脚本 `build-pgo.sh` 一键完成。

**生成**：`sing-box/scripts/gen-server.sh --protocols reality --ports 8443 --reality-sni www.baidu.com --domain 127.0.0.1.nip.io --certpath $TMPD/cert.pem --keypath $TMPD/key.pem`（见 README 母版）。产物 `config-server.json` 已改 `listen: 127.0.0.1` 供单机模拟；部署时改回 `::` 并替换密钥。

**部署**（不重启机器）：
```bash
useradd --system --home /nonexistent --shell /usr/sbin/nologin sing-box
install -d -m 750 -o sing-box -g sing-box /etc/sing-box
install -m 755 sing-box.aarch64 /usr/local/bin/sing-box
install -m 640 -o sing-box -g sing-box config.json.example /etc/sing-box/config.json  # 填密钥/UUID
install -m 644 sing-box.service /etc/systemd/system/sing-box.service
systemctl daemon-reload && systemctl enable --now sing-box
```
