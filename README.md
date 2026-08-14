# vps-related — VPS project collection

Everything VPS-related (scripts / configs / deployment notes), organized by project.

## Subprojects

| Dir | Content |
|---|---|
| **`sing-box/`** | sing-box deployment suite: server-config → client-config converter + one-time HTTPS file sharing + deployment runbook + protocol maintenance guide + local test env |

## sing-box quick start

| Script | Location | Purpose |
|---|---|---|
| `gen-server.sh` + `secrets.lib.sh` | `sing-box/scripts/` | server config generator: interactive/flag-driven protocols (any protocol repeatable), fresh credentials each run, single output, zero persistence |
| `gen-client.sh` + `protocols.lib.sh` | `sing-box/scripts/` | server `config.json` → client `client.json` converter (single input/output, no intermediate config) |
| `common.lib.sh` | `sing-box/scripts/` | shared output tiers (ok/warn/err/die1/die2/debug), sourced by both libs |
| `config-delivery.sh` + `dufs` | `config-delivery/` | one-time HTTPS file sharing — thin wrapper (random-key URL + TTL auto-delete) over dufs (TLS/streaming, single static binary) |

Two independent domains: `gen-server.sh` + `secrets.lib.sh` → server config.json (its only output);
`gen-client.sh` + `protocols.lib.sh` reads that server config → client config.json. The domains
do not cross-import; common.lib.sh is the shared output layer inside both libs.

### 0. Server config generator

```bash
bash gen-server.sh --domain your.domain \
  --certpath /etc/ssl/your/cert.pem --keypath /etc/ssl/your/key.pem \
  --protocols reality,hysteria2,vless-ws,vless-grpc,anytls,shadowtls,shadowsocks,shadowsocks \
  --ports 443,443,8443,8444,8445,8446,8388,8390 \
  --ss-methods 2022-blake3-aes-256-gcm,aes-128-gcm \
  --outputname config-server.json
#   --protocols: comma list, ANY protocol repeatable (multi-instance, unique tags <proto>-N)
#   --ports: comma list positionally aligned with --protocols (tcp/udp may share a port)
#   --ss-methods: per-ss-instance methods (positional)
#   --certpath/--keypath: ONE cert/key shared by all TLS inbounds (wildcard cert design)
#   omit --protocols → interactive: numbered picker, repeats allowed, per-instance ports
#   credentials are FRESH every run and embedded in the output — nothing persisted,
#   re-run to rotate everything. Output exists → refuses to overwrite.
#   --test: self-check (8-instance set incl. dual ss → temp, sing-box check)
#   then: bash gen-client.sh --from-server config-server.json --server your.domain
```

### 1. Client config converter

```bash
SB_OUTPUT=~/client.json bash gen-client.sh --from-server /etc/sing-box/config.json --server your.domain
#   --from-server: server sing-box config.json (single input)
#   --server: connect address (domain for dual-stack / IPv4 / IPv6); omit to be prompted
#   --outputname NAME: output filename (spaces/non-ASCII OK); --outputpath DIR: output dir
#       default output: config-client.json in the scripts dir (overwrite of server config is refused)
#   --insecure: add when cert is self-signed
#   --debug: diagnostics (fully silent by default); --test: self-check
```

### 2. One-time config delivery (config-delivery.sh + dufs)

```bash
# deploy: grab a dufs musl static binary (x86_64 + arm64 prebuilt) + this script
#   https://github.com/sigoden/dufs/releases  → dufs-linux-{x86_64,aarch64} / set DUFS_BIN

# server side — deliver the client json via a random-key link that self-destructs:
./config-delivery.sh serve ./config-client.json --port 443 --ttl 600 --host your.domain
#   → prints: one-time download link:  https://your.domain:443/<8-char-key>
#   --ttl SEC: file auto-deletes after N seconds (default 600; key URL is one-shot by design)
#   --cert/--key: real PEM cert+key (default: fresh self-signed ECDSA → clients use -k)
# client side — open the link in a browser (downloads with the given name), or:
curl -kOJ https://your.domain:443/<8-char-key>     # self-signed → -k
```

`dufs` provides TLS/streaming/static serving (MIT, active, no CVEs); the wrapper adds the
random-key URL + TTL auto-expiry. Zero extra deps, single static binary + one script.
Earlier Go prototype archived at `archived/config-delivery-go/`; original Python at `archived/otd/`.

See `sing-box/docs/runbook.md` (deployment) + `sing-box/docs/protocol-maintenance.md` (maintenance).

> Local handoff doc is in `docs/HANDOFF.md` (gitignored, local-only).
