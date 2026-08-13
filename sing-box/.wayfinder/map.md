# 全协议自校对客户端生成器 — map

> wayfinder map（本地 markdown tracker）。tickets 在 `tickets/`，blocking 用文件内文本约定。

## Destination

一个**自校对的 sing-box 1.14 全协议客户端配置生成器**（`scripts/gen-client.sh` 的重构版）：
根据线路清单**动态生成** client.json——有几个配置生成几个线路，内置 **outbound 引用校对**（urltest/manual/selector 引用与实际线路数一致）、**shadowtls↔ss 配对检测**、**同端口 TLS/QUIC 判定**（443/tcp=reality TLS、443/udp=hy2 QUIC），协议覆盖 vless 全家（reality/vision/ws/grpc）/vmess/trojan/hy2/shadowtls+ss/tuic/anytls/naive/wireguard。**只管客户端，服务端不管（keep it stupid）**。

## Notes

- 域：sing-box 1.14.0-beta.14（client 配置格式，1.14 的 breaking 已踩过：DNS 新格式/`prefer_ipv4`/`default_domain_resolver`/Reality URL-safe 密钥）
- 会话必 consult：本 map、`tickets/`、已存在的 `scripts/gen-client.sh`（六线版，已通过本机真实链路测试 6/6）、`test-env/`（本机模拟 VPS 的测试环境，setup.sh + run-test.sh）
- 用户偏好：动态生成不写死、校验放生成期、命令一次跑通、拒绝"未实验就交付"的脚本
- 已知裁决（已问答确认）：naive 进模板但带依赖警告（真证书 + libcronet.so，outbound 性能 bug 未修）；wireguard 进模板但默认关（单机客户端用不到）；trojan 进模板（作为兼容选项，非推荐主力）；服务端一律不管

## Decisions so far

- [T0 六线客户端脚本基线](tickets/000-baseline.md) — 六线（reality/hy2/shadowtls+ss/tuic/anytls/ss2022）已验证 6/6 链路通；重构为动态生成时不得破坏这三类行为：auto 组测速选优、DNS 固定走 reality 线、直连/局域网规则
- [T1 全协议字段字典](tickets/001-protocol-fields-research.md) — 三份字典落盘 `docs/protocol-fields-1.14/`（vless 家族 / quic 链 / naive+wireguard）。关键结论：1.14 无 xhttp transport；naive 无 insecure（必须真证书+cronet）；**wireguard outbound 已删、须用 endpoint 形态**；reality 客户端必须显式 utls；anytls 的 padding_scheme 是服务端字段；hy2 默认 Chrome QUIC 指纹
- [T2 线路清单输入形态](tickets/002-line-list-input-design.md) — **resolved**：输入与 env 解耦（env 仅服务端生成用），最终 `gen.sh` 只读 **config.json**（模板 `templates/config.gen.json.example`），路径 `--config` 参数或交互输入、**不保存**；输出 JSON 客户端配置（URI 前提已被子代理实测推翻：SFA/SFI 不支持分享链接导入）

## Not yet specified

- （无——原先的 fog 三块已全部毕业为 T2/T3/T4 票）

## Out of scope

- 服务端配置生成/部署（用户明确不管，keep it stupid）
- sing-box 服务端协议实现细节（客户端生成只需 outbound 视角）
- 非 sing-box 生态（Clash/其他客户端格式，官方 SFA/SFI 统一喂 sing-box JSON）
- ~~xhttp transport~~（1.14 不存在，1.15 才引入，非本版本范围）
