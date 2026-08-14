# T03: Version-timeline mechanism and the 1.15 interception strategy (grilling)

- **label**: `wayfinder:grilling`
- **type**: HITL (talk with the user to fix timeline semantics and the interception strategy)
- **blocked by**: none (frontier)
- **blocks**: —

## Question

User decision 3: auto-detect the sing-box binary version and confirm compatibility via the **timeline table** (`VERSION_TABLE` in `protocols.lib.sh`); for future 1.15, only intercepting/adapting new breaking syntax is needed. Current state:

```bash
VERSION_TABLE=(
  "1.13:deprecated_ok:legacy DNS address shorthand and similar fields are deprecated but still parseable; removed from 1.14"
  "1.14:supported:baseline version 1.14.0-beta.14"
  "1.15:future:new transport syntax (xhttp etc.) must be confirmed before generating; see the maintenance guide"
)
```
`check_version` only **warns, doesn't block** for `future` rows; `sing-box check` makes the final call.

Questions to settle:
1. **Status semantics**: are the three states `supported` / `deprecated_ok` / `future` enough? For versions not in the table (e.g. 1.10), is the behavior warn-then-generate-normally (check as net) enough as "interception"?
2. **Block vs pass**: for a `future` version (after 1.15 appears, before adaptation), should we **warn and continue generating** (let check catch field errors), or **hard-stop and refuse to generate** (exit non-zero, requiring adaptation first)? "Only intercept/adapt new breaking syntax" — where does the interception point live (before generation / after check)?
3. **Maintenance flow**: the action list for upgrading to 1.15 = ① add a row to VERSION_TABLE ② update the corresponding convert_xxx() ③ update the `docs/protocol-maintenance.md` change history ④ run --test + run-test regression. Does this list need anything else (e.g. schema validation, syncing with doc §0 SOP)?
4. **Version-probe degradation**: when the sing-box binary can't be found / the `version` output fails to parse — warn + skip check and continue generating (current state), or require `--force` to proceed? Should the test binary used by the self-check and the production probe path be unified?
5. **Status of check**: confirm that the division of labor stays as "`sing-box check` is the final arbiter for version breaking changes; the timeline is just an upfront reminder"?

Output: timeline row format and status semantics finalized + 1.15 interception strategy (hard-stop or pass+check) + upgrade action list + no-binary degradation contract.

## Why needed

Version compatibility is one of the user-named destination pillars. The timeline's "interception" semantics (warn vs hard-stop) directly determine the generator's robustness and upgrade safety, and the 1.15 hookup must be decided before it arrives.
