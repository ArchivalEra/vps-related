# H2O — aarch64 Cortex-A53 build

Cross-compiled H2O server for older Cortex-A53 aarch64 machines (VPS).

## Artifacts

| File | Notes |
|---|---|
| `h2o` | h2o 2.3.0-DEV (master snapshot, 2026-08-23), stripped, 9.1 MB |
| `share/h2o/ca-bundle.crt` | Root CA bundle (for reverse-proxying HTTPS upstreams) |
| `share/h2o/mruby/` | mruby handler runtime ruby files (**not committed**: pre-commit security scanning hard-blocks the upstream acl.rb instance_eval config DSL; files stay in the local build tree `~/plum/h2o-cross/src/share/h2o/mruby/` — when deploying, copy `share/h2o/mruby/` verbatim from an h2o source tarball) |

`h2o` sha256: `15a48b17b770928b45d4a12a0ed4c6862dc147035e6de570647d15205666724c`

## Build configuration

- Source: https://github.com/h2o/h2o master branch tarball (downloaded 2026-08-23, version 2.3.0-DEV)
- Toolchain: clang 21.1.8 + lld 21.1.8 (Debian forky/sid, upgraded before build), `-flto=thin` (ThinLTO), `-mcpu=cortex-a53`, `-fuse-ld=lld`; ninja + ccache
- Dependencies: OpenSSL 3.5.7 (statically linked in), zlib 1.3.1 (statically linked in), libyaml (vendored in h2o source); only runtime dynamic dependency is glibc (**>= 2.38**, Debian trixie+ / Ubuntu 24.04+)
- Feature switches: mruby ON (full-core gems + onigmo regex), kTLS ON, HTTP/1.1+2+3 (picotls/quicly), MLKEM post-quantum key exchanges; brotli / zstd / io_uring / dtrace OFF
- Cross-compilation: wrapper script `~/plum/h2o-cross/aarch64-clang` (ccache + clang --target=aarch64-linux-gnu --sysroot=/usr/aarch64-linux-gnu) as CC/LD; mruby's rake build also goes through the wrapper; aarch64 build-time tools (mrbc etc.) run via qemu-user (binfmt)

## Verification (qemu-aarch64, 2026-08-23)

- `h2o --version`: 2.3.0-DEV / OpenSSL 3.5.7 / mruby: YES / ktls: YES
- Real service run (HTTP 18080) + `mruby.handler` returning 200 OK
- Gateway reverse-proxy smoke test: `proxy.reverse.url` -> local http upstream 200 OK; self-signed https upstream with `proxy.ssl.verify-peer: OFF` 200 OK, while leaving verification on yields 502 (2.3.0-DEV verifies upstream certs by default; note the directive is `cafile`, not the `ca_file` spelled in older docs)

## Deployment

```sh
# Option 1: standard prefix (default lookup path /usr/local/share/h2o)
install -m755 h2o /usr/local/bin/
cp -r share/h2o /usr/local/share/

# Option 2: arbitrary directory + environment variable
export H2O_ROOT=/opt/h2o   # the binary looks for the mruby runtime under $H2O_ROOT/share/h2o/
```

### Gateway reverse proxy (LAN gateway admin UI -> loopback, exposed via cloudflared)

Deployment is done with a paste-block handed over in chat; this repo only carries the binary.
Key configuration (qemu-verified): `listen` bound to `127.0.0.1` only, `proxy.reverse.url` pointing at the gateway;
for an https self-signed gateway a global `proxy.ssl.verify-peer: OFF` is mandatory (2.3.0-DEV verifies by default and would return 502).
