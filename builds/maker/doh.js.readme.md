# doh.js — EdgeOne DoH relay function

Usage manual for [`doh.js`](doh.js), the EdgeOne edge function that fronts
public resolvers for `magdns`. It is a blind RFC 8484 pipe (GET and POST)
with an edge-side **anti-stampede cache**, a **private batch endpoint**, and
a **balanced three-upstream fan-out**: `8.8.8.8` and `8.8.4.4` (full peers —
Google's cert carries both IPs) plus `unfiltered.adguard-dns.com`, rotated
round-robin with automatic failover to the next authority on any transport
error or 5xx.

## Architecture

| Layer | What it does |
|---|---|
| trigger rule (token header) | auth at the CDN edge — abuse never reaches this function or its quota |
| question-keyed cache (10 s TTL) | per-isolate memory map, then platform Cache API when present; keys strip the random DNS txid so identical questions from different clients actually hit |
| single-flight | identical in-flight queries share one upstream round trip |
| upstream semaphore | global cap of 48 concurrent Google fetches; excess queues here instead of turning into connection resets out there |
| batch container | `[u16 count][u16 len][wire]...`, gzip/br/raw accepted; ~10–20× fewer billed requests under load |

The 10 s TTL is deliberate: the authoritative cache is magdns's magazine on
the box. This layer absorbs bursts and covers transoceanic packet-loss
windows, nothing more. There is no stale-serving: with three independent
authorities behind rotation, "the internet is down" is not a state this
function needs to paper over.

Measured on the function's own code path (upstream stubbed to zero RTT,
all-miss worst case, random domains × random subnets): 11.8k queries/s
single-query, 16.9k queries/s batched, 50k queries/s pure memory hits.
Reproduce with `src/dnsdist/stage/bench_doh.js`; correctness gates live in
`src/dnsdist/stage/doh_selftest*.js`.

## Stability

- 3 s deadline per fetch (AbortController).
- Upstream rotation IS the retry: one attempt per authority, up to three.
  A 4xx stops immediately — the request itself is wrong.
- Request size guards: wire messages outside 12..65535 bytes → 400.
- Failures log through a one-line-per-second throttle (visible in the
  EdgeOne panel), counted in `/stats`.
- `/stats` endpoint: JSON counters — cache hits/misses, upstream fetches,
  errors, queue depth peak, platform capabilities. Health check stays
  plain-text at `/health` (`ok`).

## Deployment (EdgeOne console)

1. EdgeOne console → your site → Edge Functions → Create.
2. Paste all of `doh.js` as the function body. No env vars needed.
3. Route binding: `/dns-query`.
4. Trigger rule (this is where auth lives): match
   - request Host = your relay domain (e.g. `pure-dns.example.com`), AND
   - a custom request header `token` equal to the shared secret.
   Requests failing the match never execute the function.
5. Deploy, then point the route/domain at the function.

Generate the secret once with `openssl rand -base64 48`; put the same value
in the trigger rule and in magdns's config.

## magdns side

```ini
upstream = https://<relay-domain>/dns-query h2=8 batch
maker_auth_kind = token          # sends raw `token:` header (what the trigger matches)
maker_auth_key = <same secret>
```

Multiple relay domains (one per Tencent Cloud Intl account) stack as strict
priority failover lines — see `deploy/dnsdist/magdns.conf.example`.

## Quota strategy

EdgeOne bills per function invocation; the batch endpoint divides that
count. Run relay accounts **serially**: list relays in priority order and
let magdns drain account A's monthly allowance before touching B's. The
magazine cache on the box absorbs repeats locally, this function's 10 s
layer plus single-flight absorb them regionally, and batching compresses
whatever still has to fly. Never enable hedging or round-robin against
metered relays — both multiply billed requests.

## Smoke test

```bash
curl https://<relay-domain>/health                # -> ok
curl https://<relay-domain>/stats                 # -> JSON counters

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
