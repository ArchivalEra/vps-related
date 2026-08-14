# T05: Client connect-address strategy (grilling)

- **label**: `wayfinder:grilling`
- **type**: HITL (talk with the user to fix the address strategy)
- **blocked by**: none (frontier)
- **blocks**: 007 (E2E acceptance matrix)

## Question

The client outbound's `server` field (connect address) is the **only piece of information that can't be taken directly from the server config** — the server config only has the listen port and TLS domain, not its own public address. Current `gen-client.sh`:
- `--server domain/IP` specified explicitly (prefer a domain for dual-stack; A+AAAA auto-selected)
- default is to **auto-detect the public IPv4** via `curl ifconfig.me / icanhazip`; on failure `die1` requires `--server`

Questions to settle:
1. **Default policy**: when `--server` isn't passed, is auto-detecting the public IP still a reasonable default? Or should it be the other way around — strongly recommend a domain (dual-stack + CDN fronting), with auto-detection only as a fallback?
2. **Dual-stack semantics**: domain (A+AAAA) auto-selection vs a single detected IPv4 — should both paths be supported and written into the runbook? Who decides the v6-first or v4-first policy?
3. **Probe-failure behavior**: when offline / no public IP — `die1 error`, or generate a placeholder like `server="localhost"` for the user to change? Must SNI (`tls.server_name`) and `server` be decoupled (server domain vs connect address can differ)?
4. **--insecure self-signed**: with a self-signed cert, is `insecure:true` added automatically or via an explicit flag? hy2/tuic/anytls `server_name` currently gets `$SERVER` — if the server is an IP and the cert is for a domain, should this use the server config's domain?
5. **wireguard peer address**: which `peers[].address` to use (can the server config provide it, or is `--server` required)?

Output: address strategy finalized (default + dual-stack + failure behavior + interplay with SNI/insecure + wg address source), written into the runbook.

## Why needed

The connect address is the only decision point in the single-input flow that needs external information, and the easiest thing for newcomers to misconfigure; the interplay between the address and SNI/insecure directly decides whether the generated client.json can actually connect.
