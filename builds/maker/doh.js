// EdgeOne Function — RFC 8484 DoH relay.
// Auth handled by trigger rule (custom header match). This is a blind pipe.

const UPSTREAM = "https://dns.google/dns-query";

addEventListener("fetch", (event) => {
  event.respondWith(handle(event.request));
});

async function handle(req) {
  if (new URL(req.url).pathname === "/health") {
    return new Response("ok", { status: 200 });
  }

  try {
    const url = new URL(req.url);
    const dns = url.searchParams.get("dns");
    if (!dns) return new Response(null, { status: 400 });

    const r = await fetch(UPSTREAM + "?dns=" + encodeURIComponent(dns), {
      headers: { accept: "application/dns-message" },
    });
    const buf = await r.arrayBuffer();
    return new Response(buf, {
      status: r.status,
      headers: {
        "content-type": "application/dns-message",
        // EdgeOne edge caches identical ?dns= URLs for 10 min.
        // Same domain + same ECS cluster = same URL = edge cache HIT.
        "cache-control": "public, max-age=600",
      },
    });
  } catch (_) {
    return new Response(null, { status: 502 });
  }
}
