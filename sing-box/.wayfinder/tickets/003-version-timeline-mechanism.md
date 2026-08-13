# T03: 版本时间线机制与 1.15 拦截策略（grilling）

- **label**: `wayfinder:grilling`
- **类型**: HITL（与用户对话定时间线语义与拦截策略）
- **blocked by**: 无（frontier）
- **blocks**: —

## Question

用户决策 3：自动检测 sing-box 二进制版本，按**时间线表**（`protocols.lib.sh` 的 `VERSION_TABLE`）确认兼容；将来 1.15 只需拦截/适配新的破坏性写法。现状：

```bash
VERSION_TABLE=(
  "1.13:deprecated_ok:legacy DNS address 简写等字段已弃用但可解析，1.14 起移除"
  "1.14:supported:基线版本 1.14.0-beta.14"
  "1.15:future:新 transport 写法（xhttp 等）需确认后再生成，见维护清单"
)
```
`check_version` 对 `future` 行**只 warn 不阻断**，最终由 `sing-box check` 裁决。

要拍板的问题：
1. **状态语义**：`supported` / `deprecated_ok` / `future` 三态够不够？未收录在表里的版本（如 1.10）行为 = warn 后照常生成（check 兜底）？够不够"拦截"？
2. **拦截 vs 放行**：`future` 版本（1.15 出现后、尚未适配前）应该**警告继续生成**（靠 check 抓字段错），还是**硬停拒绝生成**（退出非 0，要求先适配）？"只需拦截/适配新的破坏性写法"——拦截点在哪里（生成前 / check 后）？
3. **维护流程**：升 1.15 时的动作清单 = ① VERSION_TABLE 加行 ② 改对应 convert_xxx() ③ 更新 `docs/protocol-maintenance.md` 变更史 ④ 跑 --test + run-test 回归。这张清单还要不要补什么（如 schema 校验、文档 §0 SOP 同步）？
4. **版本探测降级**：找不到 sing-box 二进制 / `version` 输出解析失败时——warn + 跳过 check 继续生成（现状），还是**要求 --force** 才放行？自检依赖的测试二进制与生产探测路径要不要统一？
5. **check 的地位**：确认"`sing-box check` 是版本破坏性变更的最终裁决、时间线只是前置提醒"这个分工不变？

产出：时间线行格式与状态语义定案 + 1.15 拦截策略（硬停 or 放行+check）+ 升级动作清单 + 无二进制降级契约。

## 为什么需要

版本兼容是用户点名的 destination 支柱之一。时间线的"拦截"语义（warn vs 硬停）直接决定生成器的健壮性与升级安全性，且 1.15 到来前必须定好接法。
