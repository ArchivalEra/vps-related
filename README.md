# vps-related — VPS project collection

Everything VPS-related (scripts / configs / deployment notes), organized by project.

## Subprojects

| Dir | Content |
|---|---|
| **`sing-box/`** | sing-box deployment suite: server-config → client-config converter + deployment runbook + protocol maintenance guide + local test env |

## sing-box quick start

```bash
# Put the two scripts in one dir on any machine (VPS, laptop):
#   sing-box/scripts/gen-client.sh + sing-box/scripts/protocols.lib.sh
SB_OUTPUT=~/client.json bash gen-client.sh --from-server /etc/sing-box/config.json --server your.domain
#   --from-server: server sing-box config.json (single input)
#   --server: connect address (domain for dual-stack / IPv4 / IPv6); omit to be prompted
#   --insecure: add when cert is self-signed
#   --debug: diagnostics (fully silent by default); --test: self-check
```
See `sing-box/docs/runbook.md` (deployment) + `sing-box/docs/protocol-maintenance.md` (maintenance).

> Local handoff doc is in `docs/HANDOFF.md` (gitignored, local-only).
