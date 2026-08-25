// EdgeOne Function — RFC 8484 DoH relay (GET + POST), blind pipe to Google.
//
// Auth lives entirely in the trigger rule (token header): abuse is rejected
// at the CDN edge before any function time or quota is spent. Zero auth
// logic in this file, by design.
//
// Caching — every layer keys on the QUESTION, not the transaction ID:
//   * the DNS txid is random per client, so a naive URL/body cache would
//     never hit. Both cache layers strip the first two bytes and key on
//     the remaining wire bytes; answers are stored ID-less and the caller's
//     own txid is patched back in on return.
//   * POST: per-isolate memory map first (zero-cost hit), then the platform
//     Cache API when present (cross-isolate share). Identical concurrent
//     queries single-flight into one upstream round trip.
//   * GET ?dns=<b64url>: same pipeline after decode.
//   TTL is fixed (600s) — this is an upstream acceleration layer; magdns's
//   magazine re-applies real per-record TTLs downstream.
//
// Stability: 3s upstream deadline, exactly one retry on transport errors,
// strict size guards. CPU cost on a hit is one map lookup.

const UPSTREAM = "https://dns.google/dns-query";
const TTL_MS = 10000; // 10s anti-stampede layer only: absorbs identical
                      // concurrent/repeat queries so the first answer has
                      // time to land. The authoritative cache is magdns's
                      // magazine; this layer must never outlive its freshness.
const DEADLINE_MS = 3000;
const MEM_MAX = 1024; // entries; ~300B each worst case -> bounded isolate RAM

const mem = new Map(); // hexKey -> { exp, body(Uint8Array, ID-less) }
const inflight = new Map(); // hexKey -> Promise<Uint8Array>
let lastSweep = 0;

const HAS_CACHE_API =
  typeof caches !== "undefined" &&
  !!caches.default &&
  typeof caches.default.match === "function";

addEventListener("fetch", (event) => {
  event.respondWith(handle(event.request));
});

async function handle(req) {
  const url = new URL(req.url);
  if (url.pathname === "/health") {
    const caps = HAS_CACHE_API ? " cache-api" : "";
    caps += typeof DecompressionStream !== "undefined" ? " br" : "";
    return new Response("ok" + caps, { status: 200 });
  }
  if (url.pathname !== "/dns-query") return new Response(null, { status: 404 });

  try {
    // batch container: N length-prefixed wire queries, one HTTP round trip.
    // Private protocol between magdns and this function — slashes the billed
    // request count and sidesteps per-connection stream limits.
    if (
      req.method === "POST" &&
      (req.headers.get("content-type") || "").startsWith("application/dns-batch")
    ) {
      return await handleBatch(req);
    }

    let wire;
    if (req.method === "POST") {
      const body = new Uint8Array(await req.arrayBuffer());
      if (body.byteLength < 12 || body.byteLength > 65535)
        return new Response(null, { status: 400 });
      wire = body;
    } else if (req.method === "GET") {
      const dns = url.searchParams.get("dns");
      if (!dns) return new Response(null, { status: 400 });
      wire = b64urlDecode(dns);
      if (!wire || wire.byteLength < 12 || wire.byteLength > 65535)
        return new Response(null, { status: 400 });
    } else {
      return new Response(null, { status: 405 });
    }

    const key = hex(wire.subarray(2)); // question identity, txid stripped
    const answer = await cached(key, wire);
    return dnsResponse(answer);
  } catch (e) {
    console.error("doh-relay:", e && e.message ? e.message : e);
    return new Response(null, { status: 502 });
  }
}

const BATCH_MAX = 64; // hard safety ceiling; magdns AIMDs well below this

async function handleBatch(req) {
  let bytes = new Uint8Array(await req.arrayBuffer());
  const enc = req.headers.get("content-encoding") || "";
  if (enc === "gzip" || enc === "br") {
    if (typeof DecompressionStream === "undefined")
      return new Response(null, { status: 415 }); // client falls back to raw
    bytes = new Uint8Array(
      await new Response(bytes.stream().pipeThrough(new DecompressionStream(enc))).arrayBuffer()
    );
  }
  if (bytes.byteLength < 2) return new Response(null, { status: 400 });
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = dv.getUint16(0);
  if (count === 0 || count > BATCH_MAX) return new Response(null, { status: 400 });

  // parse + resolve every slot through the shared cache/single-flight path
  const slots = [];
  let off = 2;
  for (let i = 0; i < count; i++) {
    if (off + 2 > bytes.byteLength) break;
    const len = dv.getUint16(off);
    off += 2;
    if (off + len > bytes.byteLength) break;
    const wire = bytes.subarray(off, off + len);
    off += len;
    if (len >= 12) {
      slots.push(cached(hex(wire.subarray(2)), wire).catch(() => null));
    } else {
      slots.push(Promise.resolve(null));
    }
  }
  const answers = await Promise.all(slots);

  // pack: [count][len][answer]... ; empty slot = that query failed alone
  const parts = [new Uint8Array([answers.length >> 8, answers.length & 0xff])];
  for (const a of answers) {
    const len = a ? a.byteLength : 0;
    parts.push(new Uint8Array([len >> 8, len & 0xff]));
    if (a) parts.push(a);
  }
  return new Response(concat(parts), {
    status: 200,
    headers: { "content-type": "application/dns-batch+v1" },
  });
}

function concat(chunks) {
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.byteLength;
  }
  return out.buffer;
}

function dnsResponse(body) {
  return new Response(body.buffer, {
    status: 200,
    headers: {
      "content-type": "application/dns-message",
      "cache-control": "public, max-age=10",
    },
  });
}

function sweep(now) {
  if (now - lastSweep < 60000) return;
  lastSweep = now;
  for (const [k, v] of mem) if (v.exp <= now) mem.delete(k);
}

async function cached(key, wire) {
  const now = Date.now();
  sweep(now);

  const m = mem.get(key);
  if (m && m.exp > now) return withId(m.body, wire);

  let p = inflight.get(key);
  if (!p) {
    p = (async () => {
      if (HAS_CACHE_API) {
        try {
          const cr = await caches.default.match(cacheKey(key));
          if (cr) {
            const b = new Uint8Array(await cr.arrayBuffer());
            if (b.byteLength >= 12) {
              putMem(key, b, Date.now());
              return b;
            }
          }
        } catch (_) {
          /* cache layer is best-effort */
        }
      }
      const fresh = await upstreamFetch(wire);
      putMem(key, fresh, Date.now());
      if (HAS_CACHE_API) {
        try {
          await caches.default.put(
            cacheKey(key),
            new Response(fresh.slice(), {
              headers: { "cache-control": `max-age=${TTL_MS / 1000}` },
            })
          );
        } catch (_) {}
      }
      return fresh;
    })().finally(() => inflight.delete(key));
    inflight.set(key, p);
  }

  // patch the caller's own txid into the shared answer — every waiter gets
  // the same ID-less body and stamps their identity on a private copy
  return withId(await p, wire);
}

function withId(body, wire) {
  const out = new Uint8Array(body); // copy: stored/SharedArray must not leak
  out[0] = wire[0];
  out[1] = wire[1];
  return out;
}

function putMem(key, body, now) {
  mem.set(key, { exp: now + TTL_MS, body });
  if (mem.size > MEM_MAX) {
    for (const [k, v] of mem) if (v.exp <= now) mem.delete(k);
    while (mem.size > MEM_MAX) mem.delete(mem.keys().next().value);
  }
}

async function upstreamFetch(wire) {
  for (let attempt = 0; ; attempt++) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), DEADLINE_MS);
    try {
      const r = await fetch(UPSTREAM, {
        method: "POST",
        headers: {
          "content-type": "application/dns-message",
          accept: "application/dns-message",
        },
        body: wire.slice(), // detach from request lifetime
        signal: ac.signal,
      });
      if (!r.ok) throw new Error("upstream " + r.status);
      const buf = new Uint8Array(await r.arrayBuffer());
      if (buf.byteLength < 12) throw new Error("short upstream reply");
      return buf;
    } catch (e) {
      if (attempt === 1) throw e; // one retry, transport errors only
    } finally {
      clearTimeout(timer);
    }
  }
}

function cacheKey(hexKey) {
  return "https://" + UPSTREAM.split("//")[1] + "/__cache/" + hexKey;
}

function hex(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++)
    s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

function b64urlDecode(s) {
  const T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let acc = 0,
    bits = 0;
  const out = [];
  for (const ch of s) {
    if (ch === "=") break; // tolerate stray padding
    const v = T.indexOf(ch);
    if (v < 0) return null;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}
