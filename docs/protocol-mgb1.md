# MGB1 — magdns batch protocol, version 1

Private application-layer container that lets trusted peers carry many DNS
queries in one network round trip. Used on three legs of the pipeline with
an identical wire format:

```
magdns-client ──DoT/DoQ/DoH──▶ box (magdns) ──DoH──▶ Maker (doh.js) ──▶ public resolvers
            MGB1 over stream frames        MGB1 over HTTP POST body
```

Standard single-query formats (RFC 1035/7858/8484) remain fully supported
alongside; MGB1 is opt-in per connection (stream transports) or per request
(HTTP), negotiated explicitly — never guessed.

## Container layout

All integers big-endian.

```
offset  size  field
0       4     magic  = 0x4D474231 ("MGB1")
4       2     flags    bit0 = body is gzip-compressed after this header
                       bit1 = body is brotli-compressed after this header
6       2     count    number of slots (1..=64)
8       ..    slots: count × [u16 len][wire bytes]
```

- `wire` is a full RFC 1035 message with exactly one question (QDCOUNT=1),
  EDNS0 permitted. The transaction ID inside each slot is meaningless for
  correlation — responses return **in slot order**, and the caller patches
  its own txid back.
- A response slot of `len = 0` means that query failed alone; the batch
  never fails as a whole. Callers apply their own fallback policy per slot.
- Exactly one of flags bit0/bit1 may be set; both clear means raw bytes.
- Hard limits: `count ≤ 64`, uncompressed container ≤ 256 KiB, each
  `wire` between 12 and 65535 bytes.

## Leg 1: client → box over DoT / DoQ

Stream transports have no HTTP headers, so auth and mode selection ride in
a **handshake frame** sent by the client immediately after connect:

```
[u32 magic "MGB1"][u16 flags][16 bytes UUID][u16 uuid_len][uuid utf8]
```

Wait — simpler and unambiguous: the handshake IS a zero-slot MGB1 container
with the UUID as its only extension field:

```
handshake frame payload:
  "MGB1" | flags=0 | count=0 | [u16 uuid_len][uuid bytes]
```

The box validates the UUID against `auth.client_uuids` from config.json:

- match     → replies with the same handshake frame (count=0, echo uuid)
              and switches the connection to batch mode;
- no match  → closes the connection (RST-equivalent). Standard clients that
              never send the handshake are unaffected and stay in standard
              mode — but if `auth.client_uuids` is non-empty, standard-mode
              queries from unauthenticated connections are REFUSED at the
              frame level, so SNI-driven blockers gain nothing by connecting.

Subsequent frames on an authenticated connection each carry one MGB1
container (the 2-byte DoT length prefix wraps the whole container). DoQ
uses one bidirectional stream per container, same layout.

## Leg 2: client → box over DoH (port 443)

Single queries: standard RFC 8484 GET/POST plus header
`x-magdns-auth: <uuid>` when client auth is enabled.
Batch: POST to `/dns-query` with `content-type: application/mgb1+v1`,
container as body, compression expressed via standard `content-encoding`
and/or flags. Same header carries the UUID.

## Leg 3: box → Maker relay over HTTPS

POST to `/dns-query`, `content-type: application/mgb1+v1`,
`content-encoding: gzip|br` (or identity), container as body. The relay
function decompresses (platforms do not auto-decompress request bodies),
serves every slot through its cache → single-flight → upstream-authority
pipeline, and answers with the same container layout. The relay's own token
header rides alongside as before.

## Compression

Any codec both ends agree on; v1 ships `gzip` (level 6, flate2/miniz_oxide
on the Rust side, native DecompressionStream in the edge function).
`br` is wire-compatible the moment both sides enable it. Senders pick one,
receivers advertise capability out-of-band (`/stats`, handshake flags, or
simply answering 415 — senders treat 415 as "drop compression permanently").

## Why not QDCOUNT>1

RFC 8484 mandates exactly one question per HTTP request and public
authorities FORMERR anything else. MGB1 exists precisely because batching
must terminate at a private endpoint that re-injects individual standard
queries toward the public authorities. This keeps every public-facing byte
standards-clean while private links get their throughput economics.

## Implementation status

| Leg | Status |
|---|---|
| box → Maker (HTTP) | shipped (`batch` upstream flag + doh.js batch endpoint) |
| client → box (DoT/DoQ handshake) | spec'd here, implementation tracked |
| client → box (DoH 443) | spec'd here, implementation tracked |
