# CONTEXT — magdns ecosystem glossary

Terms are canonical. Implementation details live in code/docs, never here.

## Terms

- **magazine (弹夹)** — the authoritative DNS answer cache on the box:
  fixed byte budget, FIFO tail eviction, per-entry lifetime cap, keys carry
  a geo-cluster suffix. The ONLY cache whose answers are trusted as fresh.
- **anti-stampede layer (防击穿层)** — the short-TTL (10 s) edge cache inside
  doh.js/Maker. Absorbs identical concurrent/repeat queries and covers
  transoceanic packet-loss windows. Never outlives magazine freshness.
- **authority (权威)** — a public resolver used as an upstream answer source
  (8.8.8.8, 8.8.4.4, AdGuard-unfiltered, 223.5.5.5, …). Never a synonym for
  the box or the relay.
- **Maker** — our EdgeOne edge function relaying to public authorities.
  Billed per invocation; accounts run serially to drain allowances.
- **MGB1** — the private batch container protocol (see
  docs/protocol-mgb1.md): `[magic][flags][count][len][wire]…`, txid-stripped
  cache keys, slot-independent failure. Spoken identically on all three legs.
- **leg** — one hop where MGB1 travels: client→box, box→Maker.
- **chain (链条)** — ordered sequence of groups; when a group fails
  (timeout / network error / truncation / SERVFAIL / REFUSED), the WHOLE
  group is skipped and the next group takes over. NXDOMAIN and empty NOERROR
  are normal answers, never failures.
- **group (组)** — one chain link with a mode: `balance` (round-robin across
  members) or `priority` (first alive wins). Members are unlimited and may
  speak udp/tls/quic/https.
- **split** — routing unit mapping (domain set × source subnets) → chain.
  First matching split wins; unmatched queries take the default chain.
  Unlimited named splits (`cn`, `fr`, `home-fr`, …).
- **ingress table** — ordered (source subnets → auth requirement) rules;
  unmatched default is refuse. One mechanism feeds both authentication and
  split matching.
- **ECS modes** — `auto` (real client subnet), `force` (declared fixed
  subnet, Ali-style), `off`. Client-supplied globally-routable ECS is passed
  through untouched; banned ranges (RFC 7871 §10.2) are stripped.
- **overrides** — pin (fixed A/AAAA) or block (empty answer) entries that
  outrank every split; applied before cache keying.

## Non-goals

- Public recursive service for strangers: ingress table gates it.
- Stale-serving of expired answers: three independent authorities make it
  pointless; freshness belongs to the magazine.
