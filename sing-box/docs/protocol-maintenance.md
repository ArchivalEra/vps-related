# sing-box 客户端协议维护清单（MAINTENANCE）

> **适配范围**: sing-box 1.13+ 的**客户端** outbound 配置（服务端不在本清单范围）。
> **当前模板针对**: `1.14.0-beta.14`（版本常量在 `scripts/gen-client.sh` 头部 `SINGBOX_VERSION`/`SINGBOX_MAJOR_MINOR`）。
> **用法**: 升级 sing-box 二进制时，对照本清单逐项核对；本仓库实测踩过的坑标注「✅实测」。

---

## 0. 升级 SOP（每次升版本按序执行）

```bash
# 1. 下载新版本二进制到脚本实际查找的位置（gen-client.sh 依次找：PATH 的 sing-box → /opt/sing-box/sing-box → test-env/bin/sing-box）
# 2. 改 scripts/gen-client.sh 头部的 SINGBOX_VERSION / SINGBOX_MAJOR_MINOR
# 3. 用 test-env 配置跑 gen-client.sh，看 sing-box check 是否报 unknown field
#    → 报错字段去下方【字段审计】对应协议找，改 scripts/protocols.lib.sh 对应 proto_* 模板
# 4. 跑全场景回归（--test 自检 + 六线链路 + 新协议）
# 5. 把新版本再变的字段记进本清单【变更史】，标注版本
```

**版本一致性防线**: gen-client.sh 自带二进制版本探测——检测到的 major.minor ≠ `SINGBOX_MAJOR_MINOR` 会警告。**但 check 才是最终裁决**：字段改名了 check 必报 `unknown field`，所以「改版本 → 跑 check → 看报错」是永远不会漏的三步。

---

## 1. 破坏性变更史（踩过 + 已知）

| 版本 | 变更 | 影响面 | 证据 |
|---|---|---|---|
| 1.14 | reality `handshake.port` → `server_port` | 服务端模板 | ✅实测 FATAL `unknown field "port"` |
| 1.14 | DNS server `address` 简写格式**移除** | 客户端 DNS 段 | ✅实测：须 `type:https`/`type:local` 新格式 |
| 1.14 | `dns.strategy: ipv4_first` → `prefer_ipv4` | 客户端 DNS | ✅实测 FATAL `unknown domain strategy` |
| 1.14 | 缺 domain_resolver 被强制 | 客户端 route | ✅实测：须 `route.default_domain_resolver` |
| 1.14 | **wireguard outbound 删除** → endpoint 形态 | 客户端 wg | ✅实测 FATAL `outbounds[].server unknown field`；schema 确认 endpoint |
| 1.14 | reality 客户端须显式 `utls.enabled:true` | 客户端 vless | ✅实测 FATAL `uTLS is required by reality client` |
| 1.14 | `tls.acme` 内联 → `certificate_providers` | 服务端（客户端无影响） | 子代理查证 |
| 1.14 | hy2 新增 `disable_chrome_parrot`（默认 false=Chrome 指纹） | 客户端 hy2 | 子代理查证 |
| 1.14 | naiveproxy → v150（字段无变化） | 客户端 naive | 子代理查证 |
| 1.13 | tls 证书字段反复（certpath → certificate_path 一类改名，用户经验） | 各 tls 段 | 用户经验（非本仓库实测）；**1.14 现状以 schema 为准：`certificate_path`/`certificate`** |
| 1.12 | DNS legacy server 格式开始弃用 | 客户端 DNS | 官方 deprecation 公告 |
| 1.13 | wireguard outbound 弃用（1.14 移除） | 客户端 wg | 官方报错文案 |
| 1.15(预告) | **xhttp transport** 引入 | 客户端 vless 传输 | 1.14 实测无 xhttp，1.15 才有 |

---

## 2. 协议字段审计表

> 每表三列：模板字段 / 1.14 现状（必填、默认）/ 升级检查点（该字段一变会怎样）。

### VLESS + Reality（`proto_reality`）

| 字段 | 1.14 现状 | 升级检查点 |
|---|---|---|
| `flow: xtls-rprx-vision` | 唯一合法值；服务端须同款 | 非法值初始化即报 `unsupported flow` |
| `packet_encoding: xudp` | 缺省即 xudp（显式空串=禁用） | 默认行为变化会影响 UDP |
| `tls.utls.enabled` | **必须显式 true**（reality 客户端） | 1.14 起不自动补，去掉必 FATAL |
| `tls.reality.public_key` | URL-safe raw base64（无 `=`，含 `-_`） | 编码规则变=全部密钥重生成 |
| `tls.reality.short_id` | 客户端**单个字符串**（服务端是数组） | 客户端写数组会报错 |
| `tls.handshake_timeout` | 1.14 新增，默认 15s | 可选，删了无碍 |

### Hysteria2（`proto_hy2`）

| 字段 | 1.14 现状 | 升级检查点 |
|---|---|---|
| `obfs.type: salamander` | 只有 salamander/gecko（1.14 加 gecko） | type 写别的值 check 报错 |
| `obfs.password` | 设了 obfs 则必填 | 空报 `missing obfs password` |
| `password` | 认证密码 | userpass 组合串要整个塞进 password |
| `tls`（disable_chrome_parrot） | 默认 false=Chrome QUIC 指纹 | **服务端必须 ECDSA 证书**（Chrome 不支持 Ed25519） |
| `up_mbps`/`down_mbps` | 字段名不是 up/down | 留空退回 BBR 拥塞控制 |
| `server_ports`/`hop_interval` | 1.11+ 端口跳跃 | 用不到可不配 |

### ShadowTLS（`proto_shadowtls`）

| 字段 | 1.14 现状 | 升级检查点 |
|---|---|---|
| `version: 3` | 默认 1；v2/v3 才用 password | 客户端 v3 写法= v2 同构 |
| `password` | 仅 v2/v3 有意义 | v1 无密码字段 |
| `tls` | server_name + utls chrome | 仅 TCP（UDP 走不了） |

### Shadowsocks（`proto_ss_chain` / `proto_ss_direct`）

| 字段 | 1.14 现状 | 升级检查点 |
|---|---|---|
| `method: 2022-blake3-aes-256-gcm` | 2022 系（密码 base64） | method 拼错 check 报错 |
| `detour`（链式） | ss → shadowtls tag | 目标 tag 不存在会运行时报错 |
| `server_port`（链式） | 填 shadowtls 端口 | 链式下 ss 层对端口透明 |

### TUIC（`proto_tuic`）

| 字段 | 1.14 现状 | 升级检查点 |
|---|---|---|
| `uuid` | 必填，非法 UUID 报错 | 格式必须标准 UUID |
| `congestion_control: bbr` | **默认 cubic**，要 BBR 显式写 | 去掉字段=回 cubic |
| `udp_relay_mode`/`udp_over_stream` | 互斥 | 同时配报错 |
| `zero_rtt_handshake` | 默认 false；需两端同开 | 单端开不生效 |

### AnyTLS（`proto_anytls`）

| 字段 | 1.14 现状 | 升级检查点 |
|---|---|---|
| `password` | 必填 | |
| `padding_scheme` | **服务端字段，客户端不能配** | 别写进模板（写了 check 报错） |
| `tcp_fast_open` | **禁用**（lazy 连接空指针崩溃） | 模板绝不能加 tfo |
| `client_metadata` | 1.14 默认空字符串 | 不加=不发指纹（正确默认） |
| `idle_session_*` | 默认 30s/30s/0 | 可选 |

### VLESS/VMess + WS（`proto_vless_ws`/`proto_vmess_ws`）

| 字段 | 1.14 现状 | 升级检查点 |
|---|---|---|
| `transport.type: ws` | 无 plain TCP；transport 只有 http/ws/quic/grpc/httpupgrade | **xhttp 1.15 才有**，1.14 写 xhttp=unknown |
| `ws.path`/`ws.headers.Host` | 默认 path 空 | |
| `vmess.alter_id` | 默认 0（AEAD）；字段名下划线 | 服务端是驼峰 `alterId` |
| `vmess.packet_encoding` | **缺省禁用**（vless 缺省 xudp，两者不同） | 需要 UDP 要显式写 |

### Trojan（`proto_trojan`）

| 字段 | 1.14 现状 | 升级检查点 |
|---|---|---|
| `tls.enabled` | **必须 true**（Trojan 本身是 TLS） | 去掉即不可用 |
| `password` | 必填 | |

### Naive（`proto_naive`）

| 字段 | 1.14 现状 | 升级检查点 |
|---|---|---|
| `tls` | **无 insecure 选项**（硬校验） | 真证书前提；insecure=true 直接报错 |
| 依赖 | libcronet.so 与二进制同目录 | 1.14 无后缀 linux-amd64 包自带 |
| 性能 | outbound bug #3837（150→1Mbps）**未修** | 别当主力线 |

### ~~WireGuard~~（已从本项目移除，2026-08-13）

> 用户拍板从项目中移除（本地双进程隧道编排不成熟 + 单机代理场景价值低）。
> 1.14 中它是顶层 `endpoints` 形态（outbound 已删）。本转换器不支持，未来若加回参考此表。

| 字段 | 1.14 现状 | 升级检查点 |
|---|---|---|
| 形态 | **outbound 已删**，须顶层 `endpoints` 数组 | 写回 outbounds 报 `unknown field "server"` |
| `endpoints[].address` | 必填（如 10.0.0.2/32） | |
| `peers[].public_key`/`allowed_ips` | 必填 | |
| `system` | true 需 root；1.14 alpha 有崩溃 issue #4334 | 默认 false（gVisor）最稳 |

---

## 3. 模板与二进制的对应关系

```
scripts/protocols.lib.sh   ← 协议模板唯一真源（12 个 proto_* + render_lines 遍历表 + assert_gen 自检）
scripts/gen-client.sh      ← 编排（参数/解析/校对/渲染/check）+ 版本速查注释 + 版本探测
templates/config.gen.json.example  ← 输入字段清单（新增协议要补键 + gen-client.sh KNOWN_KEYS）
docs/protocol-fields-1.14/ ← 字段字典（子代理 research 落盘，含来源 URL，升级时可复核）
```

**改模板的联动点**（漏一处就断）:
1. `protocols.lib.sh` 加 `proto_xxx()` + 注册进 `render_lines()`
2. `config.gen.json.example` 加开关/密钥键
3. `gen-client.sh` 的 `KNOWN_KEYS` 加对应大写键
4. `docs/protocol-maintenance.md` 加字段审计行
5. `test-env/` 加该协议的链路测试

---

## 4. 验证防线（四层，缺一不可）

| 层 | 手段 | 挡什么 |
|---|---|---|
| 0 | **`gen-client.sh --test` 自检断言**（assert_gen 并入 protocols.lib.sh） | 6 项行为回归：退出码契约/空 inbounds/六线结构（含公钥派生、引用集）/幂等 |
| 1 | gen-client.sh 版本探测警告 | 二进制版本与模板不匹配的提醒 |
| 2 | `sing-box check`（生成后必跑） | 字段名/必填项/格式错误（**最终裁决**） |
| 3 | `$schema`（1.14.0-beta.2+ 内置） | 编辑期 IDE 校验（可选项） |

**升级后必跑**：`bash scripts/gen-client.sh --test`（自检）+ `bash test-env/run-test.sh`（六线真链路）双绿才放行。

**排查用**：`bash scripts/gen-client.sh --config ... --debug` 输出全程诊断（config 解析/未知键/二进制探测/临时目录），默认完全静默（不加 `--debug` 零诊断输出）。

> 教训：1.13→1.14 的字段变更，官方 changelog 只写 "Fixes and improvements"，**全靠 check 报错抓出来的**（本仓库实测 6 处）。所以「升级 → 跑 check → 看报错 → 改清单」是唯一可靠循环。
