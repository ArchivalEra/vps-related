All the binaries were optimized for a53-aarch64.

| binary | source | notes |
|--------|--------|-------|
| `h2o` | H2O 2.3.0-DEV | HTTP/2 + mruby, clang 21 + ThinLTO |
| `sing-box` | SagerNet/sing-box 1.13.19 | vless-reality server, GOMEMLIMIT=45MiB, DNS cache disabled |

Checksums: `*.sha256` alongside each binary where applicable.
