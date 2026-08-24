// EdgeOne Edge Function — RFC 8484 DoH relay + rotating auth.
//
// Auth: server derives expected token = HMAC-SHA256(SECRET_KEY, lunar_hmac_msg).
// Client (magdns) derives the same token independently. Both share only
// SECRET_KEY + LNY_TABLE (both set as env vars in this console).
// Tokens rotate every 12h at UTC 00:00/12:00.
//
// Setup:
//   Env: SECRET_KEY  = <random hex, openssl rand -hex 16>
//   Env: LNY_TABLE   = <comma-separated ms timestamps, same as magdns LNY_TABLE>
//   Trigger rule: Authorization starts with "Bearer " AND length >= 34
//   Route binding: /dns-query

const UPSTREAM = (__ENV__ && __ENV__.UPSTREAM) || "https://dns.google/dns-query";
const SECRET_KEY = (__ENV__ && __ENV__.SECRET_KEY) || "";
const LNY_TABLE = (__ENV__ && __ENV__.LNY_TABLE)
  ? __ENV__.LNY_TABLE.split(",").map(Number)
  : [];

const HALF_DAY_MS = 43200000;

function lunarHmacMsg(nowMs) {
  let lny = 0, yearIdx = 0;
  for (let i = LNY_TABLE.length - 1; i >= 0; i--) {
    if (LNY_TABLE[i] <= nowMs) { lny = LNY_TABLE[i]; yearIdx = i; break; }
  }
  if (lny === 0) return null;
  return "L" + yearIdx + ":" + Math.floor((nowMs - lny) / HALF_DAY_MS);
}

async function hmacHex(msg) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(SECRET_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

async function authorized(req) {
  if (!SECRET_KEY || LNY_TABLE.length === 0) return false;
  const h = req.headers.get("authorization") || "";
  const token = h.replace(/^Bearer\s+/i, "");
  if (token.length !== 32) return false;

  const now = Date.now();
  // current + previous half-day (boundary tolerance)
  for (const offset of [0, -HALF_DAY_MS]) {
    const msg = lunarHmacMsg(now + offset);
    if (!msg) continue;
    const expected = await hmacHex(msg);
    if (ctEq(token, expected)) return true;
  }
  return false;
}

function ctEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function cors() {
  return {
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "content-type",
  };
}

addEventListener("fetch", (event) => {
  event.respondWith(handle(event.request));
});

async function handle(req) {
  const url = new URL(req.url);

  if (url.pathname === "/health") {
    return new Response("ok", { status: 200 });
  }

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors() });
  }

  if (!(await authorized(req))) {
    return new Response(null, { status: 403, headers: cors() });
  }

  if (req.method === "POST") {
    const body = await req.arrayBuffer();
    if (body.byteLength < 12 || body.byteLength > 65535) {
      return new Response(null, { status: 400, headers: cors() });
    }
    try {
      const r = await fetch(UPSTREAM, {
        method: "POST",
        headers: {
          "content-type": "application/dns-message",
          accept: "application/dns-message",
        },
        body,
      });
      const buf = await r.arrayBuffer();
      return new Response(buf, {
        status: r.status,
        headers: { "content-type": "application/dns-message" },
      });
    } catch (_) {
      return new Response(null, { status: 502, headers: cors() });
    }
  }

  if (req.method === "GET") {
    const dns = url.searchParams.get("dns");
    if (!dns) return new Response(null, { status: 400, headers: cors() });
    try {
      const r = await fetch(
        UPSTREAM + "?dns=" + encodeURIComponent(dns),
        { headers: { accept: "application/dns-message" } }
      );
      const buf = await r.arrayBuffer();
      return new Response(buf, {
        status: r.status,
        headers: { "content-type": "application/dns-message" },
      });
    } catch (_) {
      return new Response(null, { status: 502, headers: cors() });
    }
  }

  return new Response(null, { status: 405 });
}
