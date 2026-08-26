// EdgeOne Function — RFC 8484 DoH relay (GET + POST + private batch),
// blind pipe to Google.
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
//   TTL is fixed and short — an anti-stampede / transoceanic-loss layer.
//     The authoritative cache is magdns's magazine downstream.
//
// Upstream discipline:
//   * global semaphore caps concurrent fetches to Google (queueing happens
//     here, cheaply, instead of as connection resets out there)
//   * 3 s deadline per fetch, exactly one retry for transport errors AND
//     transient 5xx; never for 4xx
//   * error logs are rate-limited to one per second (no log floods under
//     sustained outage)
//
// CPU cost on a hit: one map lookup.

// Three independent authorities, rotated round-robin, failover to the next
// on any transport error or 5xx. 8.8.4.4 is a full peer of 8.8.8.8 (its
// cert carries both IPs), and AdGuard-unfiltered passes ECS untouched.
const UPSTREAMS = [
  "https://8.8.8.8/dns-query",
  "https://8.8.4.4/dns-query",
  "https://unfiltered.adguard-dns.com/dns-query",
];
let upstreamCursor = 0; // module state: spreads load across isolates' lifetimes
const TTL_MS = 10000; // anti-stampede window only
const DEADLINE_MS = 3000;
const MEM_MAX = 1024; // entries; ~300B each worst case -> bounded isolate RAM
const UPSTREAM_CONCURRENCY = 48; // global cap on in-flight Google fetches

const mem = new Map(); // hexKey -> { exp, body(Uint8Array, ID-less) }
const inflight = new Map(); // hexKey -> Promise<Uint8Array>
let lastSweep = 0;

let statsHits = 0,
  statsMisses = 0,
  statsUpstream = 0,
  statsErrors = 0,
  statsQueuedPeak = 0;

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
    return new Response("ok", { status: 200 });
  }
  if (url.pathname === "/stats") {
    return new Response(
      JSON.stringify({
        mem_entries: mem.size,
        inflight_queries: inflight.size,
        cache_hits: statsHits,
        cache_misses: statsMisses,
        upstream_fetches: statsUpstream,
        upstream_errors: statsErrors,
        queue_peak: statsQueuedPeak,
        cache_api: HAS_CACHE_API,
        decompress_gzip: typeof DecompressionStream !== "undefined",
      }),
      { status: 200, headers: { "content-type": "application/json" } }
    );
  }
  if (url.pathname !== "/dns-query") return new Response(null, { status: 404 });

  try {
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
    statsErrors++;
    logThrottled(e && e.message ? e.message : e);
    return new Response(null, { status: 502 });
  }
}

// ---- batch container: [u16 count][u16 len][wire]..., gzip/br/raw accepted

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

// ---- cache core

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

  const entry = mem.get(key);
  if (entry && entry.exp > now) {
    statsHits++;
    return withId(entry.body, wire);
  }

  let p = inflight.get(key);
  if (!p) {
    statsMisses++;
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

  return withId(await p, wire);
}

function withId(body, wire) {
  const out = new Uint8Array(body); // copy: stored bodies must not leak
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

// ---- upstream: queued, deadline-bound, retried once

const upstreamQueue = { active: 0, waiters: [] };

async function withUpstreamSlot(fn) {
  if (upstreamQueue.active >= UPSTREAM_CONCURRENCY) {
    const waiter = new Promise((r) => upstreamQueue.waiters.push(r));
    // track the deepest queue for observability
    if (upstreamQueue.waiters.length > statsQueuedPeak)
      statsQueuedPeak = upstreamQueue.waiters.length;
    await waiter;
  }
  upstreamQueue.active++;
  try {
    return await fn();
  } finally {
    upstreamQueue.active--;
    const w = upstreamQueue.waiters.shift();
    if (w) w();
  }
}

async function upstreamFetch(wire) {
  return withUpstreamSlot(async () => {
    statsUpstream++;
    let lastErr = null;
    // each of the three authorities gets one attempt, in rotation order:
    // a dead or throttling upstream costs one RTT before the next answers
    for (let i = 0; i < UPSTREAMS.length; i++) {
      const idx = (upstreamCursor + i) % UPSTREAMS.length;
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), DEADLINE_MS);
      try {
        const r = await fetch(UPSTREAMS[idx], {
          method: "POST",
          headers: {
            "content-type": "application/dns-message",
            accept: "application/dns-message",
          },
          body: wire.slice(), // detach from request lifetime
          signal: ac.signal,
        });
        // 5xx/transport -> try the NEXT authority; 4xx means the request
        // itself is wrong, no point asking a different resolver the same thing
        if (r.status >= 500) {
          lastErr = new Error("upstream[" + idx + "] " + r.status);
          continue;
        }
        if (!r.ok) throw new Error("upstream[" + idx + "] " + r.status);
        const buf = new Uint8Array(await r.arrayBuffer());
        if (buf.byteLength < 12) throw new Error("short upstream reply");
        upstreamCursor = (idx + 1) % UPSTREAMS.length; // keep spreading load
        return buf;
      } catch (e) {
        lastErr = e;
      } finally {
        clearTimeout(timer);
      }
    }
    statsErrors++;
    logThrottled(lastErr && lastErr.message ? lastErr.message : "all upstreams failed");
    throw lastErr || new Error("all upstreams failed");
  });
}

// ---- misc

let lastErrLog = 0;
function logThrottled(msg) {
  const now = Date.now();
  if (now - lastErrLog < 1000) return; // max one line per second under fire
  lastErrLog = now;
  console.error("doh-relay:", msg);
}

function cacheKey(hexKey) {
  return "https://maker-cache/__doh/" + hexKey;
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
