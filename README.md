# vps-related — VPS project collection

Everything VPS-related (scripts / configs / deployment notes), organized by project.

## Subprojects

| Dir | Content |
|---|---|
| **`sing-box/`** | sing-box deployment suite: server-config → client-config converter + one-time HTTPS file sharing + deployment runbook + protocol maintenance guide + local test env |

## sing-box quick start

To learn how any `xxx.sh` is used, read its own `xxx.sh.readme.md`.
Examples: `sing-box/scripts/gen-server.sh.readme.md`, `sing-box/scripts/gen-client.sh.readme.md`, `config-delivery/config-delivery.sh.readme.md`.

| Script | Location | Purpose |
|---|---|---|
| `gen-server.sh` + `secrets.lib.sh` | `sing-box/scripts/` | server config generator: interactive/flag-driven protocols (any protocol repeatable), fresh credentials each run, single output, zero persistence |
| `gen-client.sh` + `protocols.lib.sh` | `sing-box/scripts/` | server `config.json` → client `client.json` converter (single input/output, no intermediate config) |
| `config-delivery.sh` + `dufs` | `config-delivery/` | one-time HTTPS file sharing — thin wrapper (random-key URL + TTL auto-delete) over dufs (TLS/streaming, single static binary) |

Two independent domains: `gen-server.sh` + `secrets.lib.sh` → server config.json (its only output);
`gen-client.sh` + `protocols.lib.sh` reads that server config → client config.json. The domains
do not cross-import; each lib carries its own output layer (ok/warn/err/die/debug), so they can evolve independently.

### 0. Server config generator

Usage: see `sing-box/scripts/gen-server.sh.readme.md`.

### 1. Client config converter

Usage: see `sing-box/scripts/gen-client.sh.readme.md`.

### 2. One-time config delivery (config-delivery.sh + dufs)

Usage: see `config-delivery/config-delivery.sh.readme.md`.

`dufs` provides TLS/streaming/static serving (MIT, active, no CVEs); the wrapper adds the
random-key URL + TTL auto-expiry. Zero extra deps, single static binary + one script.
Original Python implementation archived at `archived/otd/`.

See `sing-box/docs/runbook.md` (deployment) + `sing-box/docs/protocol-maintenance.md` (maintenance).

> Local handoff doc is in `docs/HANDOFF.md` (gitignored, local-only).
