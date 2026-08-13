# T04: assert_gen 自检断言覆盖规范（grilling）

- **label**: `wayfinder:grilling`
- **类型**: HITL（与用户对话定自检的覆盖契约）
- **blocked by**: 无（frontier）
- **blocks**: —

## Question

用户决策 4：生成器必须**内置自检**（`assert_gen`，`gen-client.sh --test`）。现状 `assert_gen` 已覆盖：A 参数/依赖错误退出码 1、B 空 inbounds 退出码 2、C 六线转换结构断言（tag 集 / auto/manual 引用集严格相等 / DNS detour / reality 公钥派生）、D wg endpoint 结构、E 幂等（md5）。测试二进制路径写死默认 `/tmp/sing-box-1.14.0-beta.14-linux-amd64/sing-box`（可 `SB_BIN` 覆盖）。

要拍板的问题：
1. **覆盖清单**：自检必须断言的行为集合定到什么程度？至少：
   - 退出码契约（1=参数/依赖错，2=转换/校验失败，0=成功）
   - 转换结构：每协议 outbound 的关键字段存在性（不只是 tag 集合）——比如 reality 必须有 public_key 且是 URL-safe raw base64、hy2 的 obfs 联动、ss-over-st 的 detour 指向 shadowtls
   - 覆盖度行为：未支持类型 inbound 的 warn+跳过（若 002 定了）是否纳入断言
   - 版本时间线：`check_version` 对 supported/deprecated_ok/future/未知版本的输出与退出码（若有）是否断言
   - 幂等、无二进制降级路径、`--inbound socks` 变体
2. **门槛地位**：`--test` 不绿 = 拒绝交付/拒绝升级放行，作为硬门槛写进维护清单 §4 的防线 0？还是仅提示？
3. **测试二进制来源**：断言依赖的 sing-box 二进制应该"test-env/bin 自带"还是"下载到固定路径"？升级时断言本身要不要跟着基线版本走（1.15 时断言集是否扩）？
4. **运行代价**：断言每跑一遍要起一次完整转换（含 openssl 派生公钥），控制在什么耗时/次数内？

产出：assert_gen 覆盖行为清单（每条：断言什么、期望退出码/结构）+ --test 在交付与升级流程中的门槛地位 + 测试二进制供给方式。

## 为什么需要

自检是 destination 的第四根支柱，也是唯一不依赖外部网络/真实链路的防线（防线 0）。覆盖到什么程度决定它是"摆设"还是"真正的安全网"。
