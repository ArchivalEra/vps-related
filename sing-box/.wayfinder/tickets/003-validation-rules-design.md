# T3: 自校对规则集（design）

- **label**: `wayfinder:grilling`
- **类型**: HITL
- **blocked by**: T1（001-protocol-fields-research）

## Question

生成期**自校对规则**的精确语义。用户点名的三条：

1. **outbound 数量校对**: urltest/manual/selector 组的 `outbounds` 引用集合必须与实际生成的线路 tag 集合**完全一致**（多引=check 失败，漏引=线路不可达）。规则：引用集 = 生成集，或引用集 ⊆ 生成集 + 校验器兜底？
2. **shadowtls↔ss 绑定检测**: ss 走 shadowtls 时 `detour` 必须存在；若 shadowtls 单独出现（无 ss 挂它）或 ss 配了 shadowtls 但 shadowtls 没生成 → 报错还是自动补？
3. **同端口 TLS/QUIC 判定**: "端口一样的判定为 TLS"——需要一张判定表：同端口下 TCP 监听协议（vless-reality/trojan/shadowtls…）算 TLS 系、UDP 监听协议（hy2/tuic）算 QUIC 系；生成时按传输层自动归类，且检测**同端口同传输层冲突**（两个 TCP 协议抢一个端口 = 必须报错）。

额外规则集（起草，grilling 时确认）：
- 重复 tag 检测
- 未知协议名 → 报错并列出支持列表
- naive 生成时检查 cronet 依赖提示、真证书提示
- wireguard 默认关但配置存在时启用

产出：校验器规则表（每条：触发条件/动作(报错|自动补|提示)/优先级），校验器实现为独立函数 `validate_outbounds()`，生成后先于 `sing-box check` 跑。

## Update（2026-08-13，用户裁减）

- **同端口 TCP/UDP 分流判定规则已砍掉**（用户："不搞同端口分流了，太麻烦"）——客户端生成不需要端口分组，keep it stupid。
- 剩余两条规则默认语义（提案，待确认后 close）：
  1. **outbound 数量校对**：生成后校验 `auto`/`manual` 的 outbounds 引用集合 **==** 实际生成的线路 tag 集合（严格相等；多引或漏引都报错退出，不允许 subset 模糊）
  2. **shadowtls↔ss 绑定检测**：配了 shadowtls 必须有 ss 挂 detour 指向它（无则警告）；ss 配 detour 指向不存在的 shadowtls tag → 报错退出
- 确认后 close → T4 解锁

## Resolution（2026-08-13）

- **status**: resolved
- 用户确认两条规则语义，close：
  1. **outbound 数量校对**：`auto`/`manual` 的 outbounds 引用集合 **严格等于**实际生成的线路 tag 集合——多引或漏引都报错退出（退出码 2）
  2. **shadowtls↔ss 绑定检测**：生成了 shadowtls 但无 ss 挂 detour → 警告（不阻断）；ss 配了 detour 但目标 shadowtls 不存在 → 报错退出（退出码 2）
- 同端口 TCP/UDP 分流判定：已砍（见 Update）
