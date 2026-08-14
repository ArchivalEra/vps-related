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
| `otd.py` | `share/` (top-level, independent) | one-time HTTPS file sharing — serve a file once via an 8-char key link |

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

### 2. One-time HTTPS file sharing (QUIC preferred)

```bash
# server side — serve the generated client json once:
cd share
python3 otd.py serve ./config-client.json --port 443 --name client-config.json
#   → prints: one-time download link:  https://<host>:443/<8-char-key>
# client side — open the link in a browser (downloads with the given name), or:
curl -kOJ https://<host>:443/<8-char-key>     # self-signed → -k
#   one-time: the key works exactly once (2nd request → 410), then invalidated
#   QUIC/HTTP3 preferred (aioquic installed → HTTP/3 on 443/udp), else HTTPS fallback with a warning
```

See `sing-box/docs/runbook.md` (deployment) + `sing-box/docs/protocol-maintenance.md` (maintenance).

> Local handoff doc is in `docs/HANDOFF.md` (gitignored, local-only).
