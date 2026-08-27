# vps-related — 交接手册

> 给下一个 agent 的入口文档。读完这篇即可直接开工，不必再摸索环境。

---

## 1. 本仓库现状

| 项 | 值 |
|---|---|
| 位置 | `/home/archivalera/plum/zcode-projects/vps-related/` |
| 远端 | `git@github.com:ArchivalEra/vps-related.git`（GitHub 账号 **ArchivalEra**） |
| 分支 | `main`（空仓库默认，尚无任何提交） |
| 用途 | VPS 相关的一切：脚本 / 配置 / 部署笔记 |

## 2. GitHub SSH 认证（已建立）

- 私钥：`/opt/reasonix-cradle/kicad-girl/github_key`（ed25519，公钥注释 `reasonix-kicad`）
- 配置文件：`/opt/reasonix-cradle/kicad-girl/ssh-config`（`github.com` → 使用上面的私钥）
- 已验证：`ssh -T git@github.com` 返回 `Hi ArchivalEra! You've successfully authenticated`
- **本仓库已配置 `core.sshCommand`，`git pull / push / fetch` 直接可用，无需任何环境变量**：

  ```bash
  # 查看配置
  git config --local core.sshCommand        # → ssh -F /opt/reasonix-cradle/kicad-girl/ssh-config

  # 若在新环境（无该配置），手动方式：
  GIT_SSH_COMMAND="ssh -F /opt/reasonix-cradle/kicad-girl/ssh-config" git push origin main
  ```

- 首次连接会提示 `Permanently added 'github.com'`，属正常（ssh-config 里 `StrictHostKeyChecking no`）。

## 3. 目录结构（已理清，寄生已清除）

```
/home/archivalera/plum/                  ← 普通文件夹，不再是任何 git 仓库
└── zcode-projects/
    ├── isui.ren/                        ← 空壳目录（home/ 与 router/ 均为空）
    ├── newifi3/                         ← 独立仓库 → ArchivalEra/newifi3-immortalwrt-personal
    └── vps-related/                     ← ★ 本仓库，只在此文件夹内工作
```

## 4. 历史操作记录（2026-08-12）

1. 用 `github_key` 通过 SSH 认证 GitHub（账号 `ArchivalEra`），验证通过。
2. 克隆空仓库 `ArchivalEra/vps-related` 到本目录（origin 为 SSH URL）。
3. **清除寄生**：删除 `/home/archivalera/plum/.git` 及残留的 `.gitattributes`/`.gitignore`，
   即移除长期压着目录树的 rime/plum 上游仓库 clone。
   - rime/plum 是公开上游仓库（`https://github.com/rime/plum.git`），其代码文件早已删光，
     如需随时可重新 clone，**无任何数据损失**。
4. 三个项目全部自立：`newifi3`、`vps-related` 各自独立 git；`isui.ren` 尚无 git。
5. 为本仓库写入 `core.sshCommand`，固化 GitHub 连接（见第 2 节）。

## 5. 注意事项

- **只修改** `/home/archivalera/plum/zcode-projects/vps-related/` 内的文件。
- **不要动 `isui.ren/`**：用户称 `router` 目录"里面有很多东西"，但本机确认完全为空
  （无隐藏文件、无挂载点）——内容可能在其他机器/路径，原样保留待用户确认。
- `newifi3/.wayfinder/map.md` 中仍留有旧约束文字"仓库是 rime/plum，不碰它的 git/issues"，已过时（属于 newifi3 项目，不在本仓库范围）。
- Dolphin/Qt 的 GUI 书签记着 `plum` 路径，属本地界面状态，无害。

## 6. 下一步

- 仓库有内容但**尚无任何提交**（首个提交待做，等用户指示再做）。
- 业务内容见第 7 节；部署执行看 `docs/runbook.md`。

## 7. 当前进展（2026-08-12 续）

- 首个业务内容已落地：sing-box 双节点部署套件（本轮会话）。
  - 目录：`templates/server.json.tpl`、`scripts/gen.sh`、`hosts.conf.example`、`docs/runbook.md`，根 `README.md` 为项目介绍。
  - 用法：`cp hosts.conf.example hosts.conf`（填两台 VPS 真实 IP）→ `./scripts/gen.sh` → 按 `docs/runbook.md` 手动部署。
  - 版本：**sing-box 1.14.0-beta.14**（用户明确要求上 1.14；beta.7 起 Hy2 客户端默认 Chrome QUIC 指纹伪装，服务端须用 ECDSA 证书——runbook 3.3 的 prime256v1 自签即可）。
- **已用 1.14.0-beta.14 二进制 `sing-box check` 全量验证**：3 份配置（utah/phoenix server + client）全部通过，幂等性 OK。
- **1.14 踩坑记录（4 处 breaking，changelog 未明说，均为实测修复）**：
  1. `inbounds[].tls.reality.handshake`：`port` 字段已改名为 **`server_port`**（`{server, server_port}`）。
  2. **Reality 密钥必须是 URL-safe raw base64**（官方 `reality-keypair` 格式：含 `-`/`_`、无 `=`）；openssl 输出的标准 base64 会被拒（decode private key illegal base64）。gen.sh 已做转换。
  3. DNS server 的 `address` 简写格式在 1.14 **已移除**（1.12 起弃用）：须用 `type` 新格式（`{"type":"https","server":...,"server_port":443,"path":...}` / `{"type":"local"}`）。
  4. `dns.strategy` 枚举改名：`ipv4_first` → **`prefer_ipv4`**。
  5. 缺 domain_resolver 时须在 `route` 加 **`"default_domain_resolver": "<dns tag>"`**（DNS 查询 detour 固定走第一条节点线路，避免 auto→urltest 测速与 DNS 互相依赖的死循环）。
- 本手册在 `docs/HANDOFF.md`（.gitignore 中，不进仓库）。
- 后续待办：
  - 用户两台 VPS 的真实公网 IP 填进 `hosts.conf`（本地生成用，不入库）。
  - 附录的 Trojan / VMess+WS 需要域名证书，用户暂未提供（`isui.ren` 归另一项目）。
