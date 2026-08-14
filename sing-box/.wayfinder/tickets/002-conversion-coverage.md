# T02: Conversion-function coverage and unsupported-type behavior (grilling)

- **label**: `wayfinder:grilling`
- **type**: HITL (talk with the user to fix the coverage list; /grilling + /domain-modeling as needed)
- **blocked by**: 001 (server inbound field inventory)
- **blocks**: 007 (E2E acceptance matrix)

## Question

Under the new single-input flow, which server inbound types does `render_from_server()`'s dispatch table (case branches) **support, and what happens for the ones it doesn't**. Current candidates (expressible by the 1.14 client):

- **Supported (direct conversion)**: vless-reality, hysteria2, shadowtls+ss chain, tuic, anytls, standalone shadowsocks, wireguard (endpoint form)
- **Questionable/needs decision**: vless with vision flow / ws transport (what to do when the server config has a transport section), vmess, trojan, naive (no insecure; real cert + libcronet dependency)

Questions to settle:
1. Support list: which categories above go into the dispatch table? Do naive/trojan/vmess/vless-ws make it in? (Prior rulings folded naive/trojan into the template, but that was the old "line-list" architecture; does the new single-input flow carry that over?)
2. Behavior for unsupported inbound types: `warn + skip` (generation succeeds but with fewer lines) or `die2 error` (refuse to generate)? There's already a `die2 "no convertible inbound"` fallback for empty output — what about partially supported / partially not?
3. shadowtls without a chained ss (dangling detour): generate only shadowtls with a warning? Or exit 2? (Prior T3 ruling: ss configured with detour pointing to a nonexistent st → exit 2; st generated with no ss attached → warning. Does the new architecture keep this?)
4. wireguard: can the peers info (endpoint/public key) be read directly from the server config, or does it still go through "peer public key derived from server private key + client generates a new private key"?
5. Multi-user inbound (users array with multiple entries): take the first user? Or error, requiring a single user?

Output: supported/unsupported list + a unified behavior contract for unsupported types (warn vs block) + a decision table for edge cases.

## Why needed

How robust the "server config → client json" pipeline is depends first on "what happens when a given inbound type shows up". Coverage and rejection behavior are the core decisions of the single-input contract.
