# T2: 线路清单输入形态与动态生成架构（design）

- **label**: `wayfinder:grilling`
- **类型**: HITL（与用户对话设计，必要时 /grilling + /domain-modeling）
- **blocked by**: T1（001-protocol-fields-research）

## Question

"有几个配置生成几个线路"的**输入形态**怎么定？候选：

1. **secrets.env 扩展**: 每个协议一组变量，脚本按变量存在与否启用线路（当前六线就是这个模式）
2. **独立 lines.conf**: 一行一条线路（`协议|server|port|tag|参数…`），脚本解析后生成
3. **纯命令行参数**: `--add vless-ws --path /ws` 叠加

评估维度：
- 用户在 VPS 上手改的难度（keep it stupid 原则）
- 与现有 secrets.env 的迁移成本（六线已跑通，不能推倒）
- 校对规则的可表达性（端口/TLS 判定、配对关系从清单里读得出来吗）
- 与 `docs/runbook.md` 部署流程的衔接

产出：选型 + 具体文件格式样例（3~5 行线路示例）+ 渲染管线的数据流（清单 → 模板字典(T1) → outbounds 数组 → 校对(T3) → 校验输出）。

## 已确认约束（勿再议）

- 服务端不管，只做客户端
- 不得破坏 T0 的三类行为
- naive/wireguard 进模板但默认不启用（wireguard 默认关）

## Resolution（2026-08-13）

- **status**: resolved
- 用户拍板：**走 secrets.env 扩展**（原方案 1）——保持现有六线模式，每个协议一组变量，按变量存在/开关启用线路。不引入独立 lines.conf，不做纯参数叠加。
- 字段设计草案（供 T4 实现参考）：
  - 开关变量（1/0）：REALITY、HY2、SHADOWTLS、SS_DIRECT、TUIC、ANYTLS、VLESS_WS、VMESS_WS、TROJAN、NAIVE、WIREGUARD
  - SS 默认链式（ss 的 detour 指向 shadowtls tag，沿用现脚本）；SS_DIRECT=1 时额外生成独立直连 SS 线
  - 传输参数（VLESS_WS_PATH、VLESS_WS_HOST、VMESS_WS_PATH 等）按需进 secrets
  - auto/manual 引用只含启用线路（由 T3 校对兜底）
  - 兼容性：现六线 secrets（SB_UUID/SB_PRIV/.../ANY_PASS）不做破坏性改名，开关缺省=对应协议启用（向后兼容）

## Update（2026-08-13，实现路径修正）

- **输出形态改为分享链接 txt**（用户：gen 运行后出个 txt，直接导入 sing-box 客户端），不再是单 JSON。每行一个 URI。
- **双栈语义修正**：不做 v4/v6 分离——服务器地址一律写**域名**（如 your.domain.example，A+AAAA 记录），客户端自动解析选路；一个 outbound 天然双栈。
- **同端口兼容要求**：一个端口上 TCP/UDP 跑不同协议（如 443/tcp=Reality + 443/udp=Hy2）必须兼容——生成时两线各自 URI 正确、不冲突。
- URI 精确格式：T1 字典不覆盖（那是 JSON 字段），已另派 research 子代理查 sing-box 1.14 分享链接规范，结果落盘 docs/uri-schemes-1.14.md。

## Update（2026-08-13，URI 前提推翻，输出形态改回 JSON）

- **research 子代理实测**：sing-box 官方客户端（SFA/SFI）**不支持任何协议分享链接 URI 导入**（无 vless:// 等解析），UI 只有 JSON 文件/远程 URL/.bpf 导入。无 convert/import 命令，`sing-box check` 只吃 JSON。
- shadowtls 链式在 URI 体系里**无表达**。
- **输出形态修正**：gen-client.sh 输出 **JSON 配置文件**（非 txt），客户端从文件导入；可选扩展远程订阅（`sing-box://import-remote-profile?url=` 拉 JSON）。
- 双栈语义维持修正：服务器地址写域名（A+AAAA），客户端自动选路。
- 同端口 TCP/UDP 不同协议兼容维持：443/tcp=Reality + 443/udp=Hy2，各 outbound 各自正确。

## Resolution（2026-08-13，最终定案）

- **status**: resolved
- 输入形态终定：**config.json**（与 env 解耦——secrets.env 仅用于服务端配置生成工具）
- 路径传入：`--config /path/config.json` 参数，或交互式 `read -p` 输入；**不保存路径**（无任何持久化状态文件）
- 输出：JSON 客户端配置（官方 SFA/SFI 从文件导入）
- 模板：`templates/config.gen.json.example`（含全部键：server_host/insecure/线路开关/密钥/端口）
- 脚本已重构并本机实测：--config 参数 ✓ 交互输入 ✓ 未知键检测 ✓ config 缺失报错 ✓ 开关增删 ✓ 无路径状态文件 ✓
- 架构定案：config.json（输入）→ gen-client.sh（解析+生成+自校对+check）→ client.json（输出）
