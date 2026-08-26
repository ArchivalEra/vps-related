# GeoIP consolidation design — stable geography, honest ECS

## Data stack (three tables, all license-clean)

| Table | Source | Provides | Refresh |
|---|---|---|---|
| country | RIR delegated-extended (five RIRs; APNIC endpoint default) | registration geography — country frozen at allocation time, immune to border-model churn | daily |
| ASN | IPtoASN TSV | ASN name per range → keyword-based hosting inference | hourly upstream, daily check |
| datacenter overlay | X4BNet lists_vpn `ipv4.txt` | explicit datacenter CIDR list | CI-rebuilt |

City-level databases are banned from this pipeline: ECS consumers act at
country granularity and city records are exactly where border flapping lives.

## Behavior

1. **ECS precision is adaptive.** Below `consolidate_above_qps` (operator
   set it to **10000**) every query carries its precise /24 (or /56) ECS.
   Above the watermark, queries consolidate to the country's representative
   prefix — one bucket per country slashes cache-key cardinality and
   upstream fan-out exactly when they hurt.
   Hysteresis: consolidation exits at half the entry watermark.
2. **Representative prefix** = the largest non-datacenter IPv4 prefix the
   country actually has in the delegated table (a real residential ISP's
   range). Never synthesized, never collected locally — public registry
   data only.
3. **Residential masquerade** (`residential_masquerade`, default off):
   sources classified as datacenter/hosting report the country's
   representative prefix instead of their own subnet. Operator rationale:
   residential-origin traffic resolving through visible datacenter
   infrastructure is itself a risk signal; a consistent "biggest broadband
   ISP in that country" story reads natural. Non-datacenter sources are
   never masqueraded.
4. **Datacenter-classified sources skip nothing else**: they still resolve,
   cache and batch like everyone else.

## Update pipeline (no cron; systemd timer)

`magdns-geo-update.timer` runs daily: fetch all three artifacts → validate
(parse fully, non-empty, sorted ranges) → atomically rename into
`dir` → SIGHUP magdns when `hot_reload` is on. Failed downloads keep the
previous generation; the service never blocks or degrades because an update
failed.

## Memory

Parsed interval maps are sorted `Vec<(u32 start, u32 end, …)>` probed by
binary search — measured envelope ≈ 5–15 MB RSS total for all three tables
on aarch64, inside the box's budget.

## Config

```json
"geo": {
  "enabled": true,
  "dir": "/var/lib/magdns/geo",
  "sources": {
    "delegated": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "iptoasn":   "https://iptoasn.com/data/ip2asn-v4.tsv.gz",
    "x4bnet_dc": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/ipv4.txt"
  },
  "consolidate_above_qps": 10000,
  "residential_masquerade": false,
  "update_check": "daily"
}
```

## Privacy invariant

The local machine NEVER collects user query data. The only persistent
local state is the DNS answer cache. GeoIP tables are public registry
artifacts; nothing derived from user traffic is ever written beside them.
