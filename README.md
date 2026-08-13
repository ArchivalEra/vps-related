# vps-related — VPS 相关项目集

VPS 相关的一切（脚本 / 配置 / 部署笔记），按业务分类存放。

## 子项目

| 目录 | 内容 |
|---|---|
| **`sing-box/`** | sing-box 双节点部署套件：客户端配置生成器 + 服务端模板 + 部署手册 + 协议维护清单 + 测试环境 |

## sing-box 快速开始

```bash
cd sing-box
cp hosts.conf.example hosts.conf    # 填 VPS 真实 IP（本地生成用）
./scripts/gen.sh                    # 服务端配置（密钥本地生成，幂等）
# 客户端配置:
./scripts/gen-client.sh --config /path/to/config.gen.json
```
详见 `sing-box/docs/runbook.md`（部署）+ `sing-box/docs/protocol-maintenance.md`（维护）。

> 本地交接手册在 `docs/HANDOFF.md`（被 gitignore，不进仓库，仅本机可见）。