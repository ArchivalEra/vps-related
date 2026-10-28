# vps-related

Everything for running private infrastructure on VPSes and a low-power home
box: proxy server/client config tooling, one-time file delivery, dynamic DNS —
all organized per subproject, all tuned for aarch64 (Cortex-A53) boxes with
1 GB RAM.

## Map

| Path | What lives there |
|---|---|
| [`builds/README.md`](builds/README.md) | provenance of every binary in `builds/` |
| [`sing-box/`](sing-box/) | sing-box deployment suite (server/client config generators, protocol docs, runbook, test env) |
| [`config-delivery/`](config-delivery/) | one-time HTTPS file sharing (thin wrapper over `dufs`) |
| [`duck-ddns/`](duck-ddns/) | DuckDNS A/AAAA updater for home-broadband direct entry |
| [`scripts/git-hooks/`](scripts/git-hooks/) | repo hooks (zero-Chinese enforcement) |

Convention: any `xxx.sh` or deployed artifact carries its own
`xxx.sh.readme.md` next to it. That file is the manual; source files carry
their own comments instead of readmes. These manuals are written to be used,
not maintained — when behavior changes, change the code comment first and
the manual second.

## sing-box suite

Server-side config generator and client converter for sing-box deployments;
protocol field references for 1.14 live under `sing-box/docs/`. Entry
points:

- `sing-box/scripts/gen-server.sh.readme.md` — interactive/flag-driven
  server config generation, fresh credentials per run, zero persistence.
- `sing-box/scripts/gen-client.sh.readme.md` — server `config.json` →
  client `client.json` conversion.
- `sing-box/docs/runbook.md` — deployment runbook.

The two generators are independent domains (`gen-server.sh` +
`secrets.lib.sh` → server config; `gen-client.sh` + `protocols.lib.sh`
reads it back into a client config). They do not cross-import.

## config-delivery

One-time HTTPS file sharing: a thin wrapper over `dufs` adding a random-key
URL and TTL auto-delete. Single static binary, zero extra deps.
Manual: [`config-delivery/config-delivery.sh.readme.md`](config-delivery/config-delivery.sh.readme.md).

## duck-ddns

DuckDNS dynamic A/AAAA updater for home-broadband boxes: systemd-resident
bash loop, change-triggered pushes plus a daily heartbeat, stable-IPv6
address selection across prefix re-dials. Built for no-ICP-filing setups —
web stays on cloudflared, this covers ssh/WireGuard/high-port direct entry.
Manual: [`duck-ddns/README.md`](duck-ddns/README.md).

## Repo rules

- **Zero Chinese in tracked text files.** A pre-push hook
  ([`scripts/git-hooks/pre-push`](scripts/git-hooks/pre-push)) rejects any
  push containing CJK characters in tracked `.sh`/`.md`. Enable it on a
  clone with `git config core.hooksPath scripts/git-hooks`.
- **Whitelist `.gitignore`.** Everything is ignored by default; only
  explicitly allowed paths get tracked. New directories must be added to
  the whitelist deliberately — this is what keeps credentials and local
  test benches out of the repo.
- **Binaries live in `builds/`.** Provenance for every binary is documented
  in `builds/README.md`.
