# T04: assert_gen self-check assertion coverage spec (grilling)

- **label**: `wayfinder:grilling`
- **type**: HITL (talk with the user to fix the self-check's coverage contract)
- **blocked by**: none (frontier)
- **blocks**: —

## Question

User decision 4: the generator must have **built-in self-checks** (`assert_gen`, `gen-client.sh --test`). Current `assert_gen` already covers: A argument/dependency errors exit 1, B empty inbounds exit 2, C six-line conversion structure assertions (tag set / auto & manual ref-set strict equality / DNS detour / reality pubkey derivation), D wg endpoint structure, E idempotency (md5). The test binary path is hardcoded to the default `/tmp/sing-box-1.14.0-beta.14-linux-amd64/sing-box` (overridable via `SB_BIN`).

Questions to settle:
1. **Coverage list**: how far should the set of behaviors the self-check must assert go? At minimum:
   - Exit-code contract (1=argument/dependency error, 2=conversion/check failure, 0=success)
   - Conversion structure: existence of key fields per-protocol outbound (not just the tag set) — e.g. reality must have public_key and it must be URL-safe raw base64, hy2's obfs coupling, ss-over-st's detour pointing to shadowtls
   - Coverage behavior: whether unsupported-type inbound warn+skip (if 002 settles it) is asserted
   - Version timeline: whether `check_version`'s output and exit code (if any) for supported/deprecated_ok/future/unknown versions are asserted
   - Idempotency, the no-binary degradation path, the `--inbound socks` variant
2. **Gate status**: should `--test` non-green = refuse delivery/refuse upgrade release, as a hard gate written into layer 0 of maintenance-guide §4? Or just a hint?
3. **Test binary source**: should the sing-box binary the assertions depend on be "shipped in test-env/bin" or "downloaded to a fixed path"? On upgrade, should the assertions themselves track the baseline version (does the assertion set expand at 1.15)?
4. **Runtime cost**: each assertion run starts a full conversion (incl. openssl pubkey derivation) — what time/number-of-runs budget should it stay within?

Output: assert_gen coverage behavior list (each item: what to assert, expected exit code/structure) + the gate status of `--test` in delivery and upgrade flows + how the test binary is supplied.

## Why needed

The self-check is the fourth pillar of the destination and the only layer that doesn't depend on external network/real links (layer 0). How far it covers decides whether it's a "decoration" or a "real safety net".
