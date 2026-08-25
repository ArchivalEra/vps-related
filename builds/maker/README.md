# EdgeOne DoH Maker

Edge relay in front of Google DoH, deployed as an EdgeOne edge function.
`magdns` speaks to it; it blindly forwards to `dns.google`. ECS passes
through untouched.

| File | Role |
|---|---|
| [`doh.js`](doh.js) | the deployed function — blind RFC 8484 pipe, auth done by trigger rule |
| [`doh.js.readme.md`](doh.js.readme.md) | deployment + operations manual for the function |

An older variant with in-function rotating HMAC (lunar calendar) auth lives
out of tree under `archived/maker-lunar-auth/`; the trigger-rule approach
replaced it (auth rejection happens at the CDN edge before the function even
runs, so abusive requests never burn function quotas).
