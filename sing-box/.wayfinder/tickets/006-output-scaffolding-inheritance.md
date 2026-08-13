# T06: 输出骨架行为继承确认（grilling）

- **label**: `wayfinder:grilling`
- **类型**: HITL（与用户对话确认输出骨架的继承与调整）
- **blocked by**: 无（frontier）
- **blocks**: 007（端到端验收矩阵）

## Question

新 destination 重画了**输入/输出契约**（单输入单输出），但输出 client.json 的**固定骨架**继承自旧架构决策（旧 T0/T3），新地图下是否原样继承、要不要调整：

1. **outbounds 骨架**：`auto`（urltest 测速选优组）+ `manual`（selector，default=auto）+ `direct` + `block`——保留？wg endpoint 只进 manual 不进 auto（urltest 测不了 endpoint）——沿用？
2. **DNS 骨架**：DNS 走 `reality` 线（detour）打破 urltest 死循环 + `default_domain_resolver` + `prefer_ipv4`——沿用？若服务端 config 没有 reality（只有 hy2/ss 等），DNS detour 退到哪条线（现实现取第一 tag）——够吗？
3. **route 规则**：局域网直连（10/8, 172.16/12, 192.168/16, 127/8 → direct）+ `final: auto`——沿用？
4. **本地 inbound**：TUN（utun225, mtu 9000, auto_route, strict_route, stack=system）默认 + `--inbound socks` 测试变体——沿用？
5. **输出目标**：默认 `/etc/sing-box/client.json`（需 root）+ `SB_OUTPUT` 覆盖——沿用？

产出：骨架继承确认表（每项：沿用/调整/删，调整给出新行为），作为渲染组装的验收基准。

## 为什么需要

输出骨架是"客户端 json"的另一半。它决定生成的配置在真机上能不能跑（DNS 不死循环、urltest 正常选优、局域网不绕代理），且是验收矩阵（007）的断言基准。
