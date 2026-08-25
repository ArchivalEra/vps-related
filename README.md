# vps-related

Everything for running private infrastructure on VPSes and a low-power home
box: a hand-rolled DNS relay, proxy server/client config tooling, one-time
file delivery, dynamic DNS — all organized per subproject, all tuned for
aarch64 (Cortex-A53) boxes with 1 GB RAM.

## Map

| Path | What lives there |
|---|---|
| [`src/dnsdist/`](src/dnsdist/) | **magdns** source (Rust): private DoT:853 / DoQ:8853 relay with magazine cache |
| [`builds/magdns`](builds/magdns) + [`.readme.md`](builds/magdns.readme.md) | the compiled aarch64 binary + its full usage manual |
| [`builds/maker/doh.js`](builds/maker/doh.js) + [`.readme.md`](builds/maker/doh.js.readme.md) | EdgeOne edge function fronting Google DoH + its deployment manual |
| [`builds/README.md`](builds/README.md) | provenance of every binary in `builds/` |
| [`deploy/`](deploy/) | systemd units + annotated config examples for the box |
| [`sing-box/`](sing-box/) | sing-box deployment suite (server/client config generators, protocol docs, runbook, test env) |
| [`config-delivery/`](config-delivery/) | one-time HTTPS file sharing (thin wrapper over `dufs`) |
| [`duck-ddns/`](duck-ddns/) | DuckDNS A/AAAA updater for home-broadband direct entry |
| [`scripts/git-hooks/`](scripts/git-hooks/) | repo hooks (zero-Chinese enforcement) |

Convention: any `xxx.sh` or deployed artifact carries its own
`xxx.sh.readme.md` next to it. That file is the manual; source files carry
their own comments instead of readmes. These manuals are written to be used,
not maintained — when behavior changes, change the code comment first and
the manual second.

## magdns — the main event

A DNS relay for a box that must never reboot: friends point their stub
resolvers at `:853` (DoT) or `:8853` (DoQ); answers come from an in-RAM
magazine cache; misses traverse upstream chains. Pure Rust on tokio/rustls/
quinn — no GC pauses, nothing on disk, no cron.

```
 client ──DoT:853 / DoQ:8853──▶ magdns
                                  │ ① per-IP → ② per-qname → ③ global QPS token buckets
                                  │ ④ concurrency gate (OOM guard)
                                  ├─ hit ──▶ magazine cache (geo-clustered keys, FIFO tail evict)
                                  ├─ CN qname ──▶ domestic pool: udp://223.5.5.5 / 223.6.6.6
                                  │              round-robin fan-out · single-flight merged
                                  │              health-gated · TC=1→TCP retry · ECS passed through
                                  └─ miss ──▶ foreign chain, strict priority:
                                              Maker relay farm (h2 fanout, serial failover)
                                              └─fail─▶ dns.google / quad9 / adguard-unfiltered
```

Design highlights:

- **Magazine cache** — fixed byte budget with FIFO tail eviction and a
  per-entry lifetime cap. Cache keys are suffixed with a geo-cluster derived
  from the client IP (IPv4 /20, IPv6 /44), so two nearby clients share an
  entry while distant clients get their own geo-correct answer.
- **ECS-aware routing** — sources that ignore EDNS Client Subnet (Quad9,
  114DNS) are declared `noecs`; queries carrying ECS route around them.
- **Maker relay farm** — self-hosted EdgeOne functions in front of Google
  DoH (see `builds/maker/doh.js.readme.md`). Listed one account per line;
  traffic runs **serially**: drain account A's monthly request allowance,
 then B's, then C's, falling back to public springs only when every
  relay is dead. Recovered relays walk back to the head of the line via
  background probes.
- **Layered rate limiting** — three token buckets (per-IP, per-qname,
  global QPS) plus a concurrency gate keep a 5000-QPS flood from OOMing a
  1 GB box. Rate-limit rejections answer REFUSED (dampens retry storms);
  overload drops silently. All values hot-reload on SIGHUP.
- **Single-flight everywhere** — identical concurrent queries collapse into
  one upstream round trip, on both chains, with a drop-guard so cancelled
  handlers never stall later joiners.

Usage: [`builds/magdns.readme.md`](builds/magdns.readme.md) (install,
full config table, signals, stats JSON, build pipeline).
Config example: [`deploy/dnsdist/magdns.conf.example`](deploy/dnsdist/magdns.conf.example).

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
- **Binaries live in `builds/`, sources under `src/`, deployment assets
  under `deploy/`.** Provenance for every binary is documented in
  `builds/README.md`.
