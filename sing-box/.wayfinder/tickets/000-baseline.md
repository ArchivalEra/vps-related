# T0: 六线客户端脚本基线（已定）

- **状态**: resolved（2026-08-13 会话中经本机真实链路测试确认）
- **结论**: 现有 `scripts/gen-client.sh`（六线版：reality/hy2/shadowtls+ss/tuic/anytls/ss2022）通过本机 test-env 实测 6/6 链路通 + 边界测试（缺 secrets/缺字段/未知参数/幂等/真证书模式）通过。
- **约束**: 重构为"全协议自校对动态生成"时**不得破坏**这三类既有行为：
  1. `auto` urltest 组自动测速选优、故障切换
  2. DNS 查询固定走 reality 线（打破 auto↔urltest 死循环，1.14 的 `default_domain_resolver` 已配）
  3. 局域网/直连规则（`10/8, 172.16/12, 192.168/16, 127/8 → direct`）
- **遗留 bug（重构时必须修）**: T4 边界测试暴露——IP 探测失败时 `mkdir /etc/sing-box` 权限不足，且**退出码误报 0**（应为非 0）。
