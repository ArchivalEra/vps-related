# Server config → client json single-input single-output generator (--from-server) — map

> wayfinder map (local markdown tracker, label `wayfinder:map`). Tickets live in `tickets/`; blocking uses in-file text conventions (blocked by / blocks).
> **Note**: the old architecture (config.gen.json + secrets.env-driven generator) is fully deprecated; the old map and old T0-T4 are archived in `archived-v1/`; this map is the new destination.

## Destination

A **single-input single-output** client config generator: **the only input = the server's sing-box config.json** (`--from-server` reads the server config directly), **the only output = the client's client.json**; config.gen.json / secrets.env and all intermediate configs are removed, no state files. Compatibility baseline **sing-box 1.14.0-beta.14**; the generator **auto-detects the sing-box binary version** and confirms compatibility via the **version timeline table** (`VERSION_TABLE`); upgrading to 1.15 later only requires intercepting/adapting new breaking syntax; the generator **must have built-in self-checks** (`assert_gen`, `gen-client.sh --test`) — no delivery if the self-check isn't green.

## Notes

- Domain: sing-box 1.14.0-beta.14. Input is the **server** config.json (all protocols' inbound keys/ports/TLS), output is the **client** outbound structure.
- Sessions must consult:
  - `scripts/protocols.lib.sh` — the conversion library, single source of truth: `VERSION_TABLE` (version timeline) / `check_version` / `convert_xxx()` (vless/hy2/shadowtls+ss chain/tuic/anytls/ss (wg removed)) / `render_from_server()` (dispatch table) / `assert_gen` (self-check).
  - `scripts/gen-client.sh` — `--from-server` orchestration (version probe → parse inbounds → convert → assemble → `sing-box check` net).
  - `docs/protocol-maintenance.md` — field audits / breaking-change history / upgrade SOP (§0) / verification layers (§4, check is the final arbiter).
  - `test-env/` — local E2E environment simulating a VPS (setup.sh generates the server config; run-test.sh tests the live lines).
- User decisions (destination already locked; don't re-grill): single-input single-output, baseline 1.14.0-beta.14, version-timeline compatibility, built-in self-check.
- **scripts/ is modified by another sub-agent; wayfinder sessions don't change scripts/ code directly**; this map only schedules decisions and research.
- Prior rulings still in effect: server config generation/deployment is out of scope (keep it stupid); naive has no insecure (real cert required); wireguard removed from the project (1.14 uses the endpoint form); the client must set `utls.enabled:true` explicitly; output import method = SFA/SFI import JSON from file (share-link URI was disproven by testing).

## Decisions so far

<!-- Local route index for this map. Old T0-T4 belong to the deprecated old architecture; one line of record only. -->

- [T0 six-line client script baseline](archived-v1/tickets/000-baseline.md) — **archived/deprecated** (old architecture): the six-line live-chain 6/6 and "don't break three behavior classes" constraints; its input form was superseded by the new destination
- [T1 all-protocol field dictionary](archived-v1/tickets/001-protocol-fields-research.md) — **archived/deprecated** (old architecture): three 1.14 client field dictionaries; its "line list" input premise was superseded by reading the server config directly
- [T2 line-list input form](archived-v1/tickets/002-line-list-input-design.md) — **archived/deprecated** (old architecture): the config.gen.json + toggles input form was removed in favor of `--from-server` single-input single-output
- [T3 self-check rule set](archived-v1/tickets/003-validation-rules-design.md) — **archived/deprecated** (old architecture): strict equality of reference sets / shadowtls↔ss binding; rule semantics can carry over to the new output assembly
- [T4 all-protocol test matrix](archived-v1/tickets/004-test-matrix-task.md) — **archived/deprecated** (old architecture): assert_gen merged into protocols.lib.sh; its assertions need re-alignment to the new tickets under the new architecture

## Not yet specified

- Parsing-layer tolerance for **non-standard server-config forms** (panel exports, omitted default fields, unknown/future-version fields) — after research 001 reveals the field forms, this may graduate into an "ignore unknown fields vs reject" decision
- Whether the **multi-entry/multi-domain server** case (one config with multiple server_name / multiple listen addresses) breaks the `--server` single connect-address assumption — pending 001's field inventory and 005's address strategy

## Out of scope

- Server config generation/deployment (explicitly out of scope for the user; keep it stupid; this generator only reads the server config, never writes it)
- The intermediate config layer config.gen.json / secrets.env (deleted by the destination; the template `templates/config.gen.json.example` is deprecated with it)
- Share-link URI import (SFA/SFI only support JSON-file import; disproven by testing)
- Non-sing-box ecosystems (Clash / other client formats; official SFA/SFI uniformly consume sing-box JSON)
- Remote subscription / multi-client distribution (import from file is enough)
- xhttp transport (introduced in 1.15, outside the 1.14 baseline scope; handled by the version-timeline strategy)
- Same-port TCP/UDP split-routing decision (cut by prior ruling; in the new architecture ports come straight from the server config — no conflict surface)
- naive live-chain testing (needs a real cert, beyond test-env's local capability; covered by structure assertions)
