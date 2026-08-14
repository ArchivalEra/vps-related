# T01: Server config inbound field form inventory (research)

- **label**: `wayfinder:research`
- **type**: AFK, resolved by the /research sub-agent
- **blocked by**: none (frontier)
- **blocks**: 002 (conversion coverage)

## Question

The new architecture's only input is the **server's** sing-box config.json, and the conversion functions parse it via dotted field paths (`inb_field`: `users.0.uuid` / `tls.reality.private_key` / `tls.server_name` / `detour` / `listen_port` / `obfs.type` / `handshake.server` …). The exact shape, optionality, and multi-value variants of these paths in a **real server config** have not been systematically verified — the existing paths are assumptions written ad hoc. Please verify each protocol's server-side **inbound** fields against the sing-box 1.14.0-beta.14 official docs + source option packages:

Must cover (aligned with the conversion-coverage candidates):
1. **vless(reality)**: users (multi-user array — which uuid/flow is taken), tls.server_name, tls.reality.private_key/short_id (array or string), the relation between listen_port and listen
2. **hysteria2**: users.0.password, obfs.type/password, the ignored port-hopping fields
3. **shadowtls**: users.0.password, version (default), handshake.server, detour (points to the ss inbound's tag)
4. **shadowsocks** (both the chained-under-shadowtls and standalone forms): method/password, what detour means on the server-side ss inbound
5. **tuic**: users.0.uuid/password, congestion_control
6. **anytls**: users.0.password, whether padding_scheme is a server-side field
7. **wireguard**: private_key, peers (whether public_key/allowed_ips/endpoint are written in the server config), address

For each protocol, provide: a JSON example of the server inbound's key fields (1.14 version), a table of optional fields, multi-user/multi-peer variants, and the pitfalls where the **current `inb_field` path, if wrong, silently yields empty** on some config. Sources: official docs + source option packages + $schema; state clearly anything that can't be found.

## Output landing spot

- Findings written into `docs/` (following the field-dictionary naming convention, e.g. `docs/server-inbound-fields-1.14/`), with source URLs
- A resolution comment: one-sentence summary of each protocol's key points + the list of inb_field paths that need changing

## Why needed

The coverage decision (002) depends on "whether these fields can actually be parsed at all"; this ticket pins down the server-side field forms first so the conversion functions parse reliably.
