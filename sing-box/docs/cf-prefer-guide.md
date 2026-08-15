# CF Prefer-IP Guide for tunnel routes (ws / grpc / ss)

Experiment guide for connecting to Cloudflare Tunnel routes via a preferred (fast)
CF anycast IP instead of the default edge. Written to be handed to a fresh agent.

## 0. Topology (the one fact everything hangs on)

Tunnel mode means the client never talks to the VPS directly:

```
client ──TLS──> CF edge (preferred IP:443) ──SNI/Host routing──> cloudflared (VPS)
        ──path routing──> HTTPS origin ──> sing-box ws/grpc inbound (8443/8444)
```

- **Preferred IP only replaces the IP the client dials.** SNI, Host, and path stay
  exactly as they are. The CF edge routes on SNI/Host, then the tunnel routes on path.
- This is why path-based routes (ws/grpc) are NOT harder to prefer-IP than SSH: the
  path is applied by the edge AFTER it has already routed on SNI. "path-with-route
  is harder than SSH" is a myth — the client config just adds the transport block.
- **SNI must be the tunnel hostname** (cf-azure.moons.de5.net), NEVER the preferred IP.
  The edge needs the SNI to know which tunnel/hostname to route to.

## 1. Prerequisites (verify before touching anything)

- cloudflared on the VPS is running (remote-managed tunnel, config in Zero Trust
  dashboard). `systemctl status cloudflared`.
- Public Hostnames already added in the dashboard:
  - `cf-azure.moons.de5.net` path `/ws*`   → HTTPS `localhost:8443`
  - `cf-azure.moons.de5.net` path `/grpc*` → HTTPS `localhost:8444`
  - (optional) `cf-ss.moons.de5.net`       → TCP  `localhost:8389` (chain-ss)
- Origin HTTPS reachability proven locally: `curl -k https://127.0.0.1:8443/ws`
  returns 404/400 (sing-box is up, just not a WS handshake). If this fails, fix
  origin before touching preference.
- End-to-end WITHOUT preference works: from a v4-capable machine,
  `curl -k https://cf-azure.moons.de5.net/ws` → 404/400. If this fails, preference
  cannot help — the route itself is broken.

## 2. slow-cf-azure placeholder vs cf-azure final

- `slow-cf-azure.moons.de5.net` is the TEST hostname: point its DNS at CF (orange
  cloud, CNAME to the tunnel) and use it for the first preferred-IP experiment so
  production (`cf-azure`) is never touched during trials.
- `cf-azure.moons.de5.net` is the FINAL client-facing hostname. Once the preferred
  IP + client config is validated on slow-cf-azure, swap the client's server/SNI to
  cf-azure (same preferred IP). The tunnel routes for both hostnames must exist in
  the dashboard (either duplicate the /ws + /grpc routes for slow-cf-azure, or if
  the dashboard hostname field accepts a path, reuse the same entries — verify in
  the dashboard which is possible; the local caddy test proved the ingress engine
  supports same-hostname path split).

## 3. Finding a preferred IP

Use any CF speed-test tool (e.g. XIU2/CloudflareSpeedTest) or manually pick from
known-good ranges; target: lowest RTT + lowest packet loss to the client's region.
Record the IP. For v4 clients the IP is v4. (v6 clients can dial the edge's v6.)

## 4. ws / grpc experiment (client = sing-box)

Generate the client config, then hand-edit ONLY the two lines:

```bash
cd /opt/tools
bash gen-client.sh --from-server /etc/sing-box/config.json \
  --addr cf-azure.moons.de5.net --outputname config-client.json
# delete reality/hy2/tuic/shadowtls/ss-over-st lines (CF terminates TLS; UDP not tunneled)
nano config-client.json
```

For each retained line set:

```json
{
  "type": "vless", "tag": "vless-ws",
  "server": "<PREFERRED_IP>", "server_port": 443,
  "tls": { "enabled": true, "server_name": "cf-azure.moons.de5.net" },
  "transport": { "type": "ws", "path": "/ws" }
}
{
  "type": "vless", "tag": "vless-grpc",
  "server": "<PREFERRED_IP>", "server_port": 443,
  "tls": { "enabled": true, "server_name": "cf-azure.moons.de5.net" },
  "transport": { "type": "grpc", "service_name": "grpc" }
}
```

Validation matrix (per line, `route.final` pinned to that tag, socks inbound, curl 204):

| step | command | expected |
|---|---|---|
| config syntax | `sing-box check -c config-client.json` | no error |
| ws line | curl 204 via socks | 204 |
| grpc line | curl 204 via socks | 204 **or documented failure** |

grpc risk: the dashboard origin may default to HTTP/1.1; grpc needs HTTP/2
origin. If grpc fails while ws passes, that is the known gap — report it, do not
silently drop grpc. (Local caddy proof: HTTPS origin + skip-verify gave both 204.)

## 5. ss experiment (client = cloudflared, NOT sing-box)

Hard fact from CF docs: "Non-HTTP services require installing cloudflared on the
client" — a plain shadowsocks client cannot dial CF :443 (ss has no TLS layer).
sing-box's shadowsocks outbound CANNOT be used for the tunneled ss.

- Preferred IP + ss requires the client to run:
  `cloudflared access tcp --hostname cf-ss.moons.de5.net --url 127.0.0.1:10838`
  then point the local ss client at 127.0.0.1:10838 (with preferred-IP variants:
  `cloudflared access tcp --hostname cf-ss.moons.de5.net` uses the edge anycast;
  there is no documented flag to force a preferred IP on the client side — test
  `--url` against a manual IP only if cloudflared supports it, else ss stays on
  the default edge path).
- Verify: ss client → local cloudflared tunnel → CF edge → chain-ss (8389) →
  shadowtls detour. If the user's existing SSH set-up already runs `cloudflared
  access tcp`, reuse the same pattern for ss.

## 6. Gotchas

- SNI is the hostname, never the IP (else no routing).
- Do NOT use `--sni` to override to www.microsoft.com on CF lines — the CF edge
  cert is for cf-azure.moons.de5.net; mismatch = handshake fail.
- TLS verify: edge cert is valid for the hostname → no `-k`/`insecure` needed on
  CF lines (unlike direct-IP lines).
- First-match-wins: path rules must precede any hostname-only rule in the dashboard.
- Keep the origin HTTPS (port 8443/8444, TLS on sing-box side). Plain-HTTP origin
  fails with `connection reset by peer` (proven locally).
