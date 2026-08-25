# doh.js — EdgeOne DoH relay function

Usage manual for [`doh.js`](doh.js), the EdgeOne edge function that fronts
Google DoH for `magdns`. It is a blind RFC 8484 pipe (GET and POST) with an
edge-side **anti-stampede cache** and a **batch endpoint** that packs many
queries into one billed request. The authoritative cache is magdns's
magazine on the box; this function only absorbs identical concurrent or
rapidly-repeated queries so the first upstream answer has time to land
(also covering transoceanic packet-loss windows).

## Caching design (why the old version never hit)

A naive DoH cache keys on the raw request — but the DNS transaction ID is
random per client, so identical questions from different clients look
different and the cache never hits. This function strips the two ID bytes
and keys both cache layers on the remaining wire bytes. Answers are stored
ID-less; each caller gets a private copy with their own transaction ID
patched back in. Verified by `src/dnsdist/stage/doh_selftest.js` (run with
node): memory hit consumes zero upstream calls, and ten concurrent identical
queries consume exactly one.

Two layers, both TTL 10 s:

| Layer | Scope | Purpose |
|---|---|---|
| per-isolate memory map | one edge isolate | zero-cost hit, no platform API |
| platform Cache API (`caches.default`, used only if present) | shared across isolates | cross-instance dedup |

Plus single-flight: identical in-flight queries share one upstream round trip.
TTL is deliberately short (10 s) — freshness belongs to the magazine; this
layer must never outlive it.

## Batch endpoint (private protocol, `application/dns-batch`)

magdns with the `batch` source flag POSTs a container of N length-prefixed
wire queries (`[u16 count][u16 len][wire]...`, gzip-compressed via
`Content-Encoding: gzip`) as ONE request. The function decompresses
(DecompressionStream — the platform does NOT auto-decompress request bodies),
serves each slot through the same cache → single-flight → Google pipeline,
and packs the answers back in the same layout. A zero-length slot means that
one query failed alone; batches never fail as a whole.

Effect under load: roughly 10–20× fewer billed requests (measured 198
queries across 11 requests), and one compressed packet on the wire instead
of dozens — a direct mitigation of transoceanic loss amplification. Plain
single-query GET/POST keeps working unchanged; magdns's AIMD packer degrades
to single queries automatically when the relay misbehaves, and drops its
compression if the endpoint ever answers 415.

## Stability

- 3 s upstream deadline (AbortController), one retry on transport errors
  only (never on HTTP error statuses).
- Request size guards: wire messages outside 12..65535 bytes → 400.
- Upstream non-OK / short replies → 502 to the caller, logged via
  `console.error` (visible in the EdgeOne function log panel).

## Deployment (EdgeOne console)

1. EdgeOne console → your site → Edge Functions → Create.
2. Paste all of `doh.js` as the function body. No env vars needed.
3. Route binding: `/dns-query`.
4. Trigger rule (this is where auth lives): match
   - request Host = your relay domain (e.g. `pure-dns.example.com`), AND
   - a custom request header `token` equal to the shared secret.
   Requests failing the match never execute the function — Tencent's edge
   rejects them before any quota is consumed.
5. Deploy, then point the route/domain at the function.

Generate the secret once with `openssl rand -base64 48`; put the same value
in the trigger rule and in magdns's config.

## magdns side

```ini
upstream = https://<relay-domain>/dns-query h2=8
maker_auth_kind = token          # sends raw `token:` header (what the trigger matches)
maker_auth_key = <same secret>
```

Multiple relay domains (one per Tencent Cloud Intl account) stack as strict
priority failover lines — see `deploy/dnsdist/magdns.conf.example`.

## Quota strategy

EdgeOne bills per function invocation. Run accounts **serially**, not in
parallel: list relays in priority order and let magdns drain account A's
monthly allowance before touching B's. The magazine cache on the box absorbs
repeat queries locally; this function's 10 s layer absorbs bursts at the
edge. Never enable hedging or round-robin against metered relays — both
multiply billed requests.

## Smoke test

```bash
# health (no auth)
curl https://<relay-domain>/health                # -> ok

# real query (binary DNS message over POST)
TOKEN=<secret>
python3 -c "
import struct, os
q = os.urandom(2) + struct.pack('!HHHHHH', 0x0100, 1, 0, 0, 0, 1) \
    + b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)
open('/tmp/q.bin', 'wb').write(q)
"
curl -X POST https://<relay-domain>/dns-query \
  -H "token: $TOKEN" \
  -H "Content-Type: application/dns-message" \
  --data-binary @/tmp/q.bin | xxd | head -5
```

A reply with `Content-Type: application/dns-message` and a binary body means
the pipe is live. A 403 without touching the function means the trigger rule
is doing its job.
