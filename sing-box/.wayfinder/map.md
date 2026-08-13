# 服务端 config → 客户端 json 单输入单输出生成器（--from-server）— map

> wayfinder map（本地 markdown tracker，label `wayfinder:map`）。tickets 在 `tickets/`，blocking 用文件内文本约定（blocked by / blocks）。
> **注意**：旧架构（config.gen.json + secrets.env 驱动的生成器）已整体作废，旧 map 与旧 T0-T4 归档于 `archived-v1/`，本 map 为新 destination。

## Destination

一个**单输入单输出**的客户端配置生成器：**唯一输入 = 服务端 sing-box config.json**（`--from-server` 直接读服务端配置），**唯一输出 = 客户端 client.json**；删除 config.gen.json / secrets.env 一切中间配置，无状态文件。兼容基线 **sing-box 1.14.0-beta.14**；生成器**自动检测 sing-box 二进制版本**，按**版本时间线表**（`VERSION_TABLE`）确认兼容性，将来升 1.15 只需拦截/适配新的破坏性写法；生成器**必须内置自检**（`assert_gen`，`gen-client.sh --test`），自检不绿即不交付。

## Notes

- 域：sing-box 1.14.0-beta.14。输入是**服务端** config.json（含各协议 inbound 的全部密钥/端口/TLS），输出是**客户端** outbound 结构。
- 会话必 consult：
  - `scripts/protocols.lib.sh` — 转换库唯一真源：`VERSION_TABLE`（版本时间线）/ `check_version` / `convert_xxx()`（vless/hy2/shadowtls+ss链/tuic/anytls/ss（wg 已移除））/ `render_from_server()`（遍历表）/ `assert_gen`（自检）。
  - `scripts/gen-client.sh` — `--from-server` 编排（版本探测 → 解析 inbounds → 转换 → 组装 → `sing-box check` 兜底）。
  - `docs/protocol-maintenance.md` — 字段审计 / 破坏性变更史 / 升级 SOP（§0）/ 验证防线（§4，check 是最终裁决）。
  - `test-env/` — 本机模拟 VPS 的端到端环境（setup.sh 生成服务端 config，run-test.sh 六线真链路）。
- 用户决策（destination 已定死，勿重新 grilling）：单输入单输出、基线 1.14.0-beta.14、版本时间线兼容、内置自检。
- **scripts/ 由另一子代理负责修改，wayfinder 会话不直接改 scripts/ 代码**；本 map 只排决策与研究。
- 已沿用的旧裁决（仍有效）：服务端配置生成/部署不管（keep it stupid）；naive 无 insecure（必须真证书）；wireguard 已从项目移除（1.14 为 endpoint 形态）；客户端必须显式 `utls.enabled:true`；输出导入方式 = SFA/SFI 从文件导入 JSON（分享链接 URI 已被实测推翻）。

## Decisions so far

<!-- 本地图的路线索引。旧 T0-T4 属已作废旧架构，仅留一行记录。 -->

- [T0 六线客户端脚本基线](archived-v1/tickets/000-baseline.md) — **archived/作废**（旧架构）：六线真链路 6/6 与"不破坏三类行为"约束，其输入形态已被新 destination 取代
- [T1 全协议字段字典](archived-v1/tickets/001-protocol-fields-research.md) — **archived/作废**（旧架构）：1.14 客户端字段字典三份，其"线路清单"输入前提已被服务端 config 直接读取取代
- [T2 线路清单输入形态](archived-v1/tickets/002-line-list-input-design.md) — **archived/作废**（旧架构）：config.gen.json + 开关的输入形态已删除，改 `--from-server` 单输入单输出
- [T3 自校对规则集](archived-v1/tickets/003-validation-rules-design.md) — **archived/作废**（旧架构）：引用集严格相等 / shadowtls↔ss 绑定，规则语义可沿用到新输出组装
- [T4 全协议测试矩阵](archived-v1/tickets/004-test-matrix-task.md) — **archived/作废**（旧架构）：assert_gen 并入 protocols.lib.sh，其断言在新架构上需按新 tickets 重新对齐

## Not yet specified

- 服务端 config 的**非标准写法边界**（面板导出、省略默认字段、未知/未来版本字段）在解析层的宽容策略——研究 001 揭示字段形态后，可能毕业为"未知字段忽略 vs 拒绝"决策
- **多入口/多域名服务器**（一个 config 含多个 server_name / 多个 listen 地址）对 `--server` 单一连接地址假设是否成立——等 001 字段盘点与 005 地址策略揭示

## Out of scope

- 服务端配置生成/部署（用户明确不管，keep it stupid；本生成器只读服务端 config，不写它）
- 中间配置层 config.gen.json / secrets.env（destination 已删除；模板 `templates/config.gen.json.example` 随之废弃）
- 分享链接 URI 导入（SFA/SFI 只支持 JSON 文件导入，已实测推翻）
- 非 sing-box 生态（Clash / 其他客户端格式；官方 SFA/SFI 统一喂 sing-box JSON）
- 远程订阅 / 多客户端分发（从文件导入即可）
- xhttp transport（1.15 才引入，非 1.14 基线范围，归入版本时间线策略）
- 同端口 TCP/UDP 分流判定（旧裁决已砍；新架构端口直接来自服务端 config，无冲突面）
- naive 真链路测试（需真证书，超出 test-env 本地能力；用结构断言覆盖）
