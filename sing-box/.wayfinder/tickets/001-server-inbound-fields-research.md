# T01: 服务端 config inbound 字段形态盘点（research）

- **label**: `wayfinder:research`
- **类型**: AFK，由 /research 子代理解决
- **blocked by**: 无（frontier）
- **blocks**: 002（转换覆盖度）

## Question

新架构唯一输入是**服务端** sing-box config.json，转换函数靠点分字段路径（`inb_field`：`users.0.uuid` / `tls.reality.private_key` / `tls.server_name` / `detour` / `listen_port` / `obfs.type` / `handshake.server` …）解析。这些路径在**真实服务端 config** 中的准确形态、可选性、多值变体，目前未系统核对——现有路径是随手写的假设。请按 sing-box 1.14.0-beta.14 官方文档 + 源码 option 包逐协议核对服务端 **inbound** 侧字段：

必须覆盖（与转换覆盖度候选一致）：
1. **vless(reality)**：users（多用户数组，uuid/flow 取哪个）、tls.server_name、tls.reality.private_key/short_id（数组还是字符串）、listen_port 与 listen 的关系
2. **hysteria2**：users.0.password、obfs.type/password、ignored 的跳端口字段
3. **shadowtls**：users.0.password、version（默认值）、handshake.server、detour（指向 ss inbound 的 tag）
4. **shadowsocks**（链式挂 shadowtls 与独立两种形态）：method/password、detour 字段在服务端 ss inbound 上的含义
5. **tuic**：users.0.uuid/password、congestion_control
6. **anytls**：users.0.password、padding_scheme 是否服务端字段
7. **wireguard**：private_key、peers（public_key/allowed_ips/endpoint 在服务端 config 里写不写）、address

每协议给出：服务端 inbound 关键字段 JSON 示例（1.14 版）、可选字段表、多用户/多 peer 变体，以及**当前 `inb_field` 路径若写错会在哪种 config 上静默取空**的坑。来源：官方 docs + 源码 option 包 + $schema；查不到的明说。

## 产出落点

- 发现写入 `docs/`（沿用字段字典命名习惯，如 `docs/server-inbound-fields-1.14/`），附来源 URL
- resolution comment 一句话总结每协议要点 + 需要改的 inb_field 路径清单

## 为什么需要

覆盖度决策（002）依赖"这些字段到底解析不解析得出来"；本票先把服务端字段形态钉死，转换函数的解析才可靠。
