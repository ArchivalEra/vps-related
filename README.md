# vps-related — VPS project collection

Everything VPS-related (scripts / configs / deployment notes), organized by project.

## Subprojects

| Dir | Content |
|---|---|
| **`sing-box/`** | sing-box deployment suite: server-config → client-config converter + one-time HTTPS file sharing + deployment runbook + protocol maintenance guide + local test env |

## sing-box quick start

| Script | Location | Purpose |
|---|---|---|
| `gen-client.sh` + `protocols.lib.sh` | `sing-box/scripts/` (same dir) | server `config.json` → client `client.json` converter (single input/output, no intermediate config) |
| `otd.py` | `share/` (top-level, independent) | one-time HTTPS file sharing — serve a file once via an 8-char key link |

### 1. Client config converter

```bash
SB_OUTPUT=~/client.json bash gen-client.sh --from-server /etc/sing-box/config.json --server your.domain
#   --from-server: server sing-box config.json (single input)
#   --server: connect address (domain for dual-stack / IPv4 / IPv6); omit to be prompted
#   --outputname NAME: output filename (spaces/non-ASCII OK); --outputpath DIR: output dir
#       default output: config-client.json in the scripts dir (overwrite of server config is refused)
#   --insecure: add when cert is self-signed
#   --map "tag=port,...": override client port per outbound (CF 443 front: --map "vless-ws=443,vless-grpc=443")
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
