# doh.js — EdgeOne DoH relay function

Usage manual for [`doh.js`](doh.js), the EdgeOne edge function that fronts
Google DoH for `magdns`. It is a blind RFC 8484 pipe: whatever DNS wire
message arrives goes to `https://dns.google/dns-query` byte-for-byte, and the
answer comes back untouched. ECS (EDNS Client Subnet) passes through intact,
so geo-sensitive answers stay geo-correct.

## How it works

- `GET /dns-query?dns=<base64url>` → forwarded as a GET with the same query
  string. Identical URLs are cached at the EdgeOne edge for 10 minutes
  (`Cache-Control: public, max-age=600`), so repeated questions from nearby
  clients never reach Google.
- `POST /dns-query` with `Content-Type: application/dns-message` → forwarded
  as POST, response streamed back with the same content type.
- `GET /health` → plain-text `ok`, no auth required (for uptime probes).
- Anything else → 400/405. Upstream fetch failure → 502.

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
priority failover lines — see `magdns.conf.example`.

## Quota strategy

EdgeOne bills per function invocation. Run accounts **serially**, not in
parallel: list relays in priority order and let magdns drain account A's
monthly allowance before touching B's. The magazine cache on the box absorbs
repeat queries locally; the edge cache absorbs repeats regionally. Never
enable hedging or round-robin against metered relays — both multiply billed
requests.

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
