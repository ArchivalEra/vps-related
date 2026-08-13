# T02: 转换函数覆盖度与未支持类型行为（grilling）

- **label**: `wayfinder:grilling`
- **类型**: HITL（与用户对话定覆盖清单，必要时 /grilling + /domain-modeling）
- **blocked by**: 001（服务端 inbound 字段盘点）
- **blocks**: 007（端到端验收矩阵）

## Question

新单输入流下，`render_from_server()` 的遍历表（case 分支）**支持哪些服务端 inbound 类型、不支持时什么行为**。现有候选（1.14 客户端可表达）：

- **支持（直接转换）**：vless-reality、hysteria2、shadowtls+ss 链式、tuic、anytls、直连 shadowsocks、wireguard（endpoint 形态）
- **存疑/需定**：vless 的 vision flow / ws 传输（服务端 config 出现 transport 段时怎么办）、vmess、trojan、naive（无 insecure、真证书 + libcronet 依赖）

要拍板的问题：
1. 支持清单：上表哪几类进遍历表？naive/trojan/vmess/vless-ws 进不进？（旧裁决把 naive/trojan 收进过模板，但那是旧"线路清单"架构；新单输入流是否沿用？）
2. 未支持类型的 inbound 行为：`warn + 跳过`（生成成功但少线）还是 `die2 报错`（拒绝生成）？空输出时已有 `die2 "没有可转换的 inbound"` 兜底——那部分支持部分不支持时呢？
3. shadowtls 无链 ss（detour 悬空）：只生成 shadowtls 并警告？还是退出 2？（旧 T3 裁决：ss 配 detour 指向不存在的 st → 退出 2；生成了 st 无 ss 挂 → 警告。新架构沿用？）
4. wireguard：服务端 config 的 peers 信息（endpoint/公钥）能直接取吗，还是仍走"对端公钥从服务端私钥派生 + 客户端新建私钥"？
5. 多用户 inbound（users 数组多条）：取第一个用户？还是报错要求单用户？

产出：支持/不支持清单 + 未支持类型的统一行为契约（警告 vs 阻断）+ 边界情况的判定表。

## 为什么需要

"服务端 config → 客户端 json"这条线健不健壮，首先取决于"遇到什么类型的 inbound 会怎样"。覆盖度与拒收行为是单输入契约的核心决策。
