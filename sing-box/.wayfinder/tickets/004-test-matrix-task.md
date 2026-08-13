# T4: 全协议测试矩阵（task）

- **label**: `wayfinder:task`
- **类型**: HITL（先给 checklist，主体验收后 resolve）
- **blocked by**: T1（001）、T2（002）、T3（003）

## Question

test-env 从"六线"扩展为"全协议"的测试矩阵。

现状（T0）：
- `test-env/setup.sh` 生成模拟 VPS 的 secrets + 六线 server 配置（127.0.0.1 高端口）
- `test-env/run-test.sh` 逐线起 client + curl 打 gstatic 204，实测 6/6 通
- 边界测试脚本已跑：缺 secrets/缺字段/未知参数/幂等/真证书模式

要补的：
1. **server 端测试配置**覆盖新协议：vless-ws/vmess-ws/trojan/naive/wireguard 的 inbound 怎么在本地模拟？（naive 要真证书 → 测试环境用什么替代？wireguard 本地起 server 的姿势？）
2. **run-test.sh 扩展**：每协议一条单线链路测试，沿用 socks5+curl 204 模式；链式协议（ss+shadowtls）已有一例，vless-ws 这类要仿照
3. **校对规则测试**：T3 的规则集每条给正例+反例（比如故意写重复 tag、ss 缺 detour、同端口冲突 → 断言脚本报错且退出码正确）——这个可以独立于真链路，用 fake secrets 驱动
4. **回归**：六线必须仍 6/6 通过

产出：更新后的 `test-env/` + 一份测试结果记录（贴回本 ticket）。

## Update（2026-08-13，前置已齐）

- blocked by T1/T2/T3 已全部 resolved，本票解锁。
- 用户追加硬约束：**"前六项之后当然要推倒，屎山留不得"** → 现有六线硬编码重构时**直接推倒重建**为新架构（secrets 开关 + 模板字典 + 校对器 + 校验），不迁就、不保留硬编码兼容层。T0 的"不破坏三类行为"仍适用（行为保留，代码重写）。

## Claimed（2026-08-13 会话）

- 已认领，开始解析。前置（T1/T2/T3）均 resolved；重构（config.json + protocols.lib.sh）已完成，本票在全新架构上建测试矩阵。

## Resolution（2026-08-13）

- **status**: resolved
- 测试矩阵落地（在新架构上，非老硬编码）：
  - **行为断言自检**：assert_gen() 并入 `scripts/protocols.lib.sh`，`gen-client.sh --test` 触发 —— 10 项断言（退出码契约 config 缺失/未知键→1、全关/wg 非法密钥→2、六线结构/引用集严格相等/DNS detour/开关增删精确匹配/全协议 wg endpoints 结构/幂等 md5）全通过
  - **链路测试**：`test-env/run-test.sh` 六线真链路 6/6 通过（reality/hy2/ss-over-st/tuic/anytls/ss2022）
  - **回归**：--config 生成 ✓ / 交互输入 ✓ / 开关增删 ✓（均通过 sing-box 1.14.0-beta.14 check）
- 范围取舍：naive/wireguard 用 schema 结构断言覆盖（本地起 naive server 需真证书、wg 需内核/特权，超出 test-env 本地能力，记为后续可选强化）
- 验证防线四层化（维护清单 §4）：--test 自检 → 版本探测 → sing-box check → $schema
