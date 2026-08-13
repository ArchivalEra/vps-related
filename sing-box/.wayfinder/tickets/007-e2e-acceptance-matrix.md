# T07: 新单输入流端到端验收矩阵（task）

- **label**: `wayfinder:task`
- **类型**: 先给 checklist，主体验收后 resolve（AFK 部分可自驱，链路验证需本机 test-env）
- **blocked by**: 002（转换覆盖度）、005（地址策略）、006（输出骨架）
- **blocks**: —

## Question

`assert_gen` 是结构自检（防线 0），不能证明**真实链路连通**。需要把"真实服务端 config.json → `gen-client.sh --from-server` → client.json → `sing-box check` → 真链路 curl"整条线在 `test-env/` 上做成回归矩阵，作为地图终点前最后一道确认。前置（002/005/006）定案后，checklist 含：

1. **服务端 config 供给**：test-env/setup.sh 生成的 server config 要能覆盖新单输入流（多协议 inbounds 一锅出：reality/hy2/shadowtls+ss 链/tuic/anytls/ss（wg 已移除））
2. **端到端回归**：`--from-server server/config.json --server 127.0.0.1 --insecure` → 输出过 `sing-box check` → 每线 socks5+curl 204 真链路（沿用 run-test.sh 模式），五线 5/5（wg 已移除）
3. **异常输入矩阵**：空 inbounds → 2、未支持类型 → 按 002 定案（警告 or 2）、坏 JSON / 缺 python3 / 无二进制降级路径——每条断言退出码
4. **版本时间线场景**：用假版本字符串驱动 `check_version` 断言 supported/deprecated_ok/future/未知的警告与行为（按 003 定案）
5. **幂等回归**：同输入两次输出 md5 一致
6. **记录**：测试结果贴回本票，作为 002/005/006 决策的验收证据

## 为什么需要

自检证明"结构对"，端到端矩阵证明"真能连通且升级没破坏"。两条腿缺一不可，本票是地图终点前确认转换线健壮的最后一关。

## Update（2026-08-13，用户追加）

- 用户要求：**本地跑两个 sing-box 进程做真实的出站/入站实战测试**（不只是 check）——确认转换产物真能代理流量。
- 已做过的最小验证：本机 127.0.0.1 六线 server + 转换产物 client.json，curl 走 socks 打 gstatic 204 通过（HTTP 204）。
- 待补的完整实战（本票执行时）：六线**全部**走转换产物逐一实测、UDP 流量、多轮/长时间稳定性、代理下载大文件测吞吐。
- 前置：本票 block 002/005/006（转换覆盖/地址策略/输出骨架），实战测试应在这些定案后做。
