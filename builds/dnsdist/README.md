# magdns — 私人 DoT/DoQ 中继（盒子专用）

给那台**不能重启**的 aarch64 Cortex-A53 / 1G 内存 Debian sid 电视机顶盒写的
DNS 中继：朋友连 `853`(DoT) 或 `8853`(DoQ) 进来，命中内存弹夹缓存，未命中则
按**配置顺序**走上游 fallback 链（`quic://` → `tls://` → `https://`，NextDNS
DoQ 优先），全程不落盘、无 cron、无 GC 停顿（纯 Rust + rustls/quinn/tokio）。

```
 客户端 ──DoT:853 / DoQ:8853──▶ magdns ──▶ [弹夹缓存 100MiB/20min]
                                        └─miss─▶ quic://88f745.dns.nextdns.io:853
                                                 └─fail─▶ tls://88f745.dns.nextdns.io:853
                                                          └─fail─▶ https://dns.nextdns.io/88f745
 （以后插一个 ShadowTLS 前置的 https://127.0.0.1:xxxx/dns-query 源 = 加两行配置）
```

## 产物

| 文件 | 说明 |
|---|---|
| `magdns-aarch64` | 最终二进制（ThinLTO + PGO，glibc≥2.38 动态链接） |
| `magdns.conf.example` | 盒子上的 `/etc/magdns/magdns.conf` 模板 |
| `magdns.service` | systemd 单元（CAP_NET_BIND_SERVICE、SIGHUP=热换证书） |
| `build.sh` | native / cross / pgo 全流程复现脚本 |
| `src/` | Rust 源码（11 个模块，~1800 行） |
| `stage/` | loopback 测试戏台：mock DoT/DoH/DoQ 上游 + 客户端 + 负载机 + 17 项测试 |

## 行为要点

- **监听**：`[::]:853` DoT(ALPN `dot`, TLS1.2+1.3) 与 `[::]:8853` DoQ(ALPN `doq`,
  RFC 9250)，双栈单 socket（v6only=0）。空闲连接 45s 回收，连接/流有上限。
- **上游链**：按 `upstream =` 出现顺序即优先级。单源连续 2 次失败 → 标记下线，
  后台每 `probe_interval_s` 探测恢复；每条查询在“活源”耗尽后仍会按序兜底尝试
  “下线源”（防止半死状态卡死整条链）。每个源有独立尝试预算
  (`attempt_timeout_ms`)，总预算 `query_timeout_ms`——一个死源吃不完整个查询。
- **弹夹缓存**：纯内存、按字节预算（默认 100MiB）；每条记录寿命 20min；满了
  从队尾（最老）清起；命中时**应答内 TTL 按 min(原TTL, 1200s) − 已存活秒数
  现算**，客户端永远不会拿到超期 TTL。只缓存 NOERROR/NXDOMAIN 且非截断的应答；
  key = 小写 qname + qtype + qclass + DO 位；并发相同查询单飞（single-flight）
  合并成一次上游请求，省 NextDNS 配额。
- **运行时**：`SIGHUP` 热加载证书（不重启进程、不断连接，DoT/DoQ 同时生效）；
  `SIGUSR1` 向 stderr 打一行 JSON 统计；正常退出也打。无磁盘写（journald 自己
  收 stderr）。
- **SSRF 防线**：上游仅接受 `https://`（拒绝 `http://`）+ `quic://`/`tls://`；
  默认拒绝环回/私网/链路本地目标（字面量在配置期拦截、解析出的地址在连接期
  拦截），本地 ShadowTLS 源需显式 `allow_private_upstream = true`。

## 构建（本机 forky，全部 nice + 默认 -j4）

DoH 上游用 hyper（h2 优先、http/1.1 自动回退），TLS 全 rustls(ring)、QUIC 用
quinn——无 OpenSSL、无 C 依赖（除 ring 自带），交叉干净。

```bash
./build.sh native          # 本机 debug（开发环）
./build.sh cross           # aarch64 release + ThinLTO（产物 target-a64/…）
./build.sh pgo-instrument  # 插桩版
./build.sh pgo-collect     # qemu 里 30min 混合负载（含周期性杀活 mock 练回退）
./build.sh pgo-merge       # profraw → pgo-data/merged.profdata（rustup llvm-tools）
./build.sh pgo-final       # -Cprofile-use 终版（产物 target-a64-final/…）
./build.sh test-qemu       # qemu 里跑全套 17 项戏台测试
```

交叉设施复用 H2O 那套：`~/plum/magdns-cross/aarch64-clang`（clang/sysroot/
cortex-a53/lld，无 LTO 版，ring 的 C 代码用；Rust 侧 ThinLTO 由 rustc 自己做）。

## 部署到盒子（**不重启**）

```bash
# 在盒子上（Debian sid aarch64）：
useradd --system --home /nonexistent --shell /usr/sbin/nologin magdns
install -d -m 750 -o magdns -g magdns /etc/magdns
install -m 755 magdns-aarch64 /usr/local/bin/magdns
install -m 640 -o magdns -g magdns magdns.conf.example /etc/magdns/magdns.conf
$EDITOR /etc/magdns/magdns.conf          # 改 upstream/端口/缓存参数
# 证书就位后（见下）：/etc/magdns/cert.pem + key.pem，属主 magdns
install -m 644 magdns.service /etc/systemd/system/magdns.service
systemctl daemon-reload
systemctl enable --now magdns
systemctl status magdns                  # 验证
journalctl -u magdns -f                  # 看日志（-v 时更多）
```

已生效即用：`kdig +tls @home.isui.ren example.com`（DoT 853）。
升级二进制 = 覆盖 `/usr/local/bin/magdns` + `systemctl restart magdns`（进程级
重启，不重启机器）。路由器端口转发 853/8853 → 盒子（v4），盒子防火墙放行
853/8853（v6 直连）。

## 证书（http-01，待用户提供两样东西）

监听器要有公网可信证书，DoT 客户端（如安卓“私人 DNS”）才不报错。域名用现成
的 DDNS 域名（DNSPod 已钉好）。**需要用户提供：**

1. 确认域名（`home.isui.ren`？）；
2. 路由器把 **TCP:80** 也转发到盒子（http-01 的硬要求；移动家宽偶有封 80
   入站，先测：`curl -H 'Host: home.isui.ren' http://<v4>/x` 外网可达性）。

然后（acme.sh，systemd timer 续期，**不用 cron**）：

```bash
curl https://get.acme.sh | sh -s -- --no-cron     # 明确禁掉它自装 cron
# 盒子上已有 H2O：把 /.well-known/acme-challenge/ 指到一个目录即可（或临时
# python3 -m http.server 80 顶 issuance 那几秒）
~/.acme.sh/home.isui.ren/e=...  # acme.sh --issue -d home.isui.ren --webroot <dir>
install -m 640 -o magdns -g magdns fullchain.cer /etc/magdns/cert.pem
install -m 640 -o magdns -g magdns key.key       /etc/magdns/key.pem
killall -HUP magdns        # 或 systemctl reload magdns —— 热加载，不断连
# 续期：magdns-cert.service + timer（OnCalendar=*-*-* 04:00, AccuracySec=1h,
# 脚本=acme.sh --renew + install + killall -HUP magdns），单元随证书一起给
```

若 80 真被封：回退 DNS-01（DNSPod API Token 已有，acme.sh dnspod 插件），
其余不变。

## stage 测试覆盖（`./run_tests.sh`，SUT=qemu 里的 aarch64 二进制）

T1 DoT→DoQ 上游；T2 缓存命中+TTL 封顶 1200；T3 DoQ 进；T7 [::1] 双栈；
T4a DoQ 死→DoT 兜底；T5a DoT 死→DoH 兜底；T5b 全死→SERVFAIL；T6a 全死后 DoQ
复活即时接管；T6b 探测恢复优先级；T8 畸形输入不断进程；T10 900 条风暴 FIFO
驱逐+最老重取；T9 SIGHUP 换 CA 热生效；T13 QDCOUNT=2 透传；STATS 校验。
——本机 x86 与 qemu aarch64 均 **17/17 PASS**（含 PGO 终版二进制）。

### 真实 NextDNS 实测（`./real_nextdns_test.sh`，qemu 终版二进制）

本机出网走强制本地代理（2080），**直连** nextdns 的 853(DoT/DoQ) 与 443(DoH)
全部被黑洞（裸 TCP 探测四地址全超时）——因此本机能做的诚实断言是：

- 真实端点上的**回退链序**：DoQ→DoT→DoH 逐个尝试（stats 计数各=1）✓
- 全灭时正确降级 SERVFAIL ✓
- 代理通道下 nextdns DoH 真实应答 200 ✓（证明 profile 端点活着且我们的
  hyper 客户端协议栈兼容）
- **盒子那边的家宽出网是否同样封 853/443 需上机验证**；若同样被墙，把
  ShadowTLS 前置的 `https://127.0.0.1:xxxx/dns-query`（1.1.1.3）加进链尾
  即可，两行配置的事。PGO 数据（30min/113,707 查询/99.6% 成功）已采集并
  用于终版构建。

## 安全备注

- 无明文 53、无 UDP 53，只 TLS/QUIC 监听；
- 上游 SSRF 防线见上；配置文件属主 magdns:600 权限即可（无凭据内容）；
- systemd 单元带 CapabilityBoundingSet/ProtectSystem=strict/MemoryMax=400M
  等加固；缓存纯匿名内存，无 emmc 写入（mlock 可选，未默认开）。
- DoQ 客户端连接/流上限 256/128，DoT 512 并发连接，空闲 45s 断——抗扫描噪声。
