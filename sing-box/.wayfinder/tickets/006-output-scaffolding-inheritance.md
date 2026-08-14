# T06: Output scaffolding behavior inheritance confirmation (grilling)

- **label**: `wayfinder:grilling`
- **type**: HITL (talk with the user to confirm output-scaffolding inheritance and adjustments)
- **blocked by**: none (frontier)
- **blocks**: 007 (E2E acceptance matrix)

## Question

The new destination redrew the **input/output contract** (single-input single-output), but the client.json output's **fixed scaffolding** is inherited from old-architecture decisions (old T0/T3). Under the new map, is it inherited as-is or adjusted:

1. **outbounds scaffolding**: `auto` (urltest latency-picking group) + `manual` (selector, default=auto) + `direct` + `block` — keep? wg endpoint only in manual, not in auto (urltest can't test endpoints) — keep?
2. **DNS scaffolding**: DNS goes through the `reality` line (detour) to break the urltest loop + `default_domain_resolver` + `prefer_ipv4` — keep? If the server config has no reality (only hy2/ss, etc.), which line does the DNS detour fall back to (current implementation takes the first tag) — is that enough?
3. **route rules**: LAN direct (10/8, 172.16/12, 192.168/16, 127/8 → direct) + `final: auto` — keep?
4. **local inbound**: TUN (utun225, mtu 9000, auto_route, strict_route, stack=system) by default + the `--inbound socks` test variant — keep?
5. **output target**: default `/etc/sing-box/client.json` (needs root) + `SB_OUTPUT` override — keep?

Output: scaffolding inheritance confirmation table (per item: keep/adjust/remove; adjustments give the new behavior), as the acceptance baseline for render/assembly.

## Why needed

The output scaffolding is the other half of the "client json". It decides whether the generated config runs on a real machine (DNS not looped, urltest picks correctly, LAN doesn't bypass the proxy), and it's the assertion baseline for the acceptance matrix (007).
