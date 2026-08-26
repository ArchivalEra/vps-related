# Wayfinder map — MGB1 ecosystem (private DNS: client → box → Maker)

Status: **executed to close-out** (this map is the record, not a plan).
Tracker: local markdown (`docs/wayfinder/`). Tickets closed in-place with
their commit hashes.

## Destination

A private DNS system where three ends — magdns-client (local), magdns
(box), Maker relay (EdgeOne) — speak one identical batch protocol (MGB1),
configured by a single config.json per host with hot-reloadable routing,
gated by UUID authentication, with unlimited split/chain routing and a
Flutter console on top.

## Notes

- Constraints that shaped everything: no ICP filing (so no domestic CDN
  fronting for the box), 1 GB RAM aarch64 box that must never reboot,
  GFW-hostile network paths, EdgeOne billed per invocation with three
  accounts' quotas drained serially.
- Operator decisions of record live in docs/protocol-mgb1.md (wire) and
  CONTEXT.md (terms). Key ones: stale-if-error removed (three authorities
  make it pointless); UUID hard gate refuses even standard queries when
  configured; group failure skips the whole group (no intra-group retry);
  REFUSED counts as a failure; ECS passthrough respected + full RFC 7871
  ban-list; overrides outrank cache/splits/rate shaping.

## Decisions so far

- [T1 mgb1 crate](../../src/mgb1/) (5d42b8e): single wire codec, zero IO,
  7 vectors as contract; magic probe collision rate accepted at 2⁻³².
- [T2 config.json](../../src/dnsdist/src/cfg.rs) (6937af0): serde mirror +
  string-aware comment stripping; absent section = feature disabled;
  dead config rejected both directions.
- [T9 hot reload](../../src/dnsdist/src/app.rs) (5d42b8e): Routing
  generation behind RwLock<Arc>; per-query Arc snapshot; opt-in via
  `hot_reload`; broken file keeps old generation. Certs/cache/rate limits
  stay restart-only.
- [T3 stream legs](../../src/dnsdist/src/dot.rs) (ae73619): handshake frame
  carries UUID; wrong UUID = cold drop; bare queries REFUSED under gate.
- [T4 DoH 443](../../src/dnsdist/src/dohserver.rs) (9a3980d): hyper server,
  x-magdns-auth header, mgb1 containers alongside RFC 8484.
- [T6 chains engine](../../src/chains.rs) (e108c42): unlimited named
  splits × balance/priority groups; N4 failure semantics.
- [T5 client skeleton](../../src/client/) (352f8e6): listeners + AIMD
  packer + multi-source failover, 32 tests. TODOs inline: DoQ egress,
  brotli send, pipelined DoT pool.
- [T7 GeoIP research](/mnt/hdd/dns-workplace/research/geoip-report.md):
  RIR delegated table + IPtoASN recommended; City-level DBs excluded
  (border jitter); residential-vs-datacenter classification identified
  as the anti-risk-control key field.
- [T8 overrides](../../src/dnsdist/src/app.rs) (1670411): pin/block before
  cache & splits; suffix matching rejects lookalike collisions.
- [CI](../../.github/workflows/ci.yml) (6be1b38): fmt/clippy/tests across
  magdns + magdns-client + mgb1.

## Not yet specified

- GeoIP implementation ticket (T7 report exists; mmdb/delegated parser +
  sticky-bind persistence design still to be scoped).
- Console (Flutter) implementation beyond docs/gui-design.md proposal.

## Out of scope

- Stale-serving expired answers (operator: three authorities make it moot).
- Public open-resolver service without UUID auth (hard-gated by design).
- mimosa security scanning until the operator returns for a joint audit
  (their explicit instruction).
