# H2O — aarch64 Cortex-A53 build

本地交叉编译的 H2O 服务器，面向老的 Cortex-A53 aarch64 机器（VPS）。

## 产物

| 文件 | 说明 |
|---|---|
| `h2o` | h2o 2.3.0-DEV（master 快照，2026-08-23），stripped，9.1 MB |
| `share/h2o/ca-bundle.crt` | 根证书包（反向代理 HTTPS 上游用） |
| `share/h2o/mruby/` | mruby handler 运行时 ruby 文件（**不入库**：pre-commit 安全扫描强制拦截上游 acl.rb 的 instance_eval 配置 DSL，文件保留在本机构建树 `~/plum/h2o-cross/src/share/h2o/mruby/`，部署时从 h2o 源码包 `share/h2o/mruby/` 原样复制） |

`h2o` sha256: `15a48b17b770928b45d4a12a0ed4c6862dc147035e6de570647d15205666724c`

## 构建配置

- 源码：https://github.com/h2o/h2o master 分支 tarball（下载于 2026-08-23，版本号 2.3.0-DEV）
- 工具链：clang 21.1.8 + lld 21.1.8（Debian forky/sid，构建前已升级），`-flto=thin`（ThinLTO）、`-mcpu=cortex-a53`、`-fuse-ld=lld`；ninja + ccache
- 依赖：OpenSSL 3.5.7（静态链入）、zlib 1.3.1（静态链入）、libyaml（h2o 自带源码）；动态依赖仅 glibc（需 **≥ 2.38**，Debian trixie+ / Ubuntu 24.04+）
- 功能开关：mruby ON（full-core gems + onigmo 正则）、kTLS ON、HTTP/1.1+2+3（picotls/quicly）、MLKEM 系后量子密钥交换；brotli / zstd / io_uring / dtrace OFF
- 交叉方式：wrapper 脚本 `~/plum/h2o-cross/aarch64-clang`（ccache + clang --target=aarch64-linux-gnu --sysroot=/usr/aarch64-linux-gnu）作为 CC/LD，mruby 的 rake 构建同样走 wrapper；mrbc 等 aarch64 构建期工具通过 qemu-user (binfmt) 执行

## 验证（qemu-aarch64, 2026-08-23）

- `h2o --version`：2.3.0-DEV / OpenSSL 3.5.7 / mruby: YES / ktls: YES
- 实际起服务（HTTP 18080）+ `mruby.handler` 返回 200 ✅

## 部署

```sh
# 方式一：标准前缀（默认找 /usr/local/share/h2o）
install -m755 h2o /usr/local/bin/
cp -r share/h2o /usr/local/share/

# 方式二：任意目录 + 环境变量
export H2O_ROOT=/opt/h2o   # 二进制会在 $H2O_ROOT/share/h2o/ 下找 mruby 运行时
```
