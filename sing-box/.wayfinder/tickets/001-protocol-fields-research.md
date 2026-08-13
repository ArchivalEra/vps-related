# T1: 1.14 全协议 outbound 字段速查（research）

- **label**: `wayfinder:research`
- **类型**: AFK，由 /research 子代理解决
- **blocks**: T2（002）、T3（003）、T4（004）

## Question

sing-box **1.14.0-beta.14** 的客户端 outbound 配置，以下协议各自的**完整字段 + 最小示例 + 依赖/坑**是什么？产出将作为 gen-client.sh 全协议模板的字段字典。

必须覆盖：
1. **vless 全家**: reality（已有）、vision flow、ws 传输（path/host/headers）、grpc 传输、xhttp？（若 1.14 有）、TLS+uTLS 指纹
2. **vmess**: tcp/ws/grpc 传输、alterId=0 现状
3. **trojan**: password、TLS、ws 传输可选
4. **hysteria2**: 已有（obfs salamander、Chrome QUIC 指纹、disable_chrome_parrot）
5. **shadowtls**: v1/v2/v3、与 ss 链式（detour）
6. **tuic**: v5 固定、congestion_control、0-RTT
7. **anytls**: password、padding_scheme、client_metadata（1.14 默认空）
8. **naive**: username/password、TLS 必填真证书、`libcronet.so` 依赖（1.14 无后缀包自带？）、outbound 性能 bug 现状
9. **wireguard**: server/public_key/private_key/psk、系统 vs sing-box 实现

每协议给出：字段清单（含可选）、一个最小 outbound JSON、注意的坑（必填项/1.14 变化/依赖）。来源：sing-box 官方文档 + 源码 option 包。查不到的明说"查不到"，别编。

## 产出落点

- 子代理把发现写入本仓库 `docs/protocol-fields-1.14.md`（新建）
- resolution comment 一句话总结每协议要点

## Resolution（2026-08-13）

- **status**: resolved
- 三份字段字典已落盘 `docs/protocol-fields-1.14/`：
  - `01-vless-family.md`（177 行）：vless（reality/vision/ws/grpc/http/httpupgrade/quic，**1.14 无 xhttp**）+ vmess（alter_id=0、packet_encoding 缺省禁用、无 reality）+ trojan（tls.enabled 必须）
  - `02-quic-chain.md`（212 行）：hy2（disable_chrome_parrot 默认 false、up_mbps/down_mbps）+ shadowtls（v3 客户端写法同 v2、仅 TCP、detour 链式）+ tuic（congestion_control 默认 cubic、uuid 必填）+ anytls（padding_scheme 是服务端字段、tcp_fast_open 禁用、client_metadata 1.14 默认空）
  - `03-naive-wireguard.md`（68 行）：**naive 无 insecure 选项（必须真证书）、依赖 libcronet.so、性能 bug #3837 未修**；**wireguard 作为 outbound 已在 1.14 删除**（报错指向 endpoint 形态，system:true 需 root 且有崩溃 issue #4334）
- 关键模板输入：reality 客户端必须显式 `utls.enabled:true`；`public_key` URL-safe raw base64；`short_id` 客户端为单字符串；T2 设计清单格式时须能表达这些差异字段
