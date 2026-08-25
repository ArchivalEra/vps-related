# magdns — binary manual

`magdns` in this directory is the aarch64 (Cortex-A53) release build of
[src/dnsdist](../src/dnsdist/) — a private DNS relay speaking **DoT on :853**
and **DoQ on :8853**, with a geo-aware in-RAM magazine cache, split routing
for domestic (CN) domains, and a layered rate-limiting stack. Built with
ThinLTO + PGO for a 4-core A53 / 1 GB RAM box running Debian sid. Verify the
download against `magdns.sha256`.

## Install

```bash
install -m755 magdns /usr/local/bin/magdns
useradd -r -s /usr/sbin/nologin magdns || true
mkdir -p /etc/magdns
# certs: any PEM cert/key covering your DNS hostname (Let's Encrypt via http-01)
install -m644 cert.pem key.pem /etc/magdns/
install -m644 magdns.conf.example /etc/magdns/magdns.conf && vi /etc/magdns/magdns.conf
install -m644 deploy/dnsdist/magdns.service /etc/systemd/system/   # from repo checkout
systemctl daemon-reload && systemctl enable --now magdns
```

The unit hard-caps memory at `MemoryMax=400M`, drops every capability except
`CAP_NET_BIND_SERVICE`, and sets `Restart=always`. Port 853/8853 bind without
root through that capability.

## What it does per query

1. **Per-IP token bucket** — abusive clients get SERVFAIL (`qps_per_ip`).
2. Parse; malformed queries pass through raw.
3. **Per-qname token bucket** — one hot domain cannot crowd out the rest
   (`qps_domain`); rejections are REFUSED.
4. **Global QPS bucket** — total arrival ceiling (`qps_global`); REFUSED.
5. **Concurrency gate** — at most `max_concurrent_queries` in flight;
   beyond that queries are dropped silently (OOM protection).
6. Split routing: CN-listed qnames go to the domestic UDP pool
   (`cn_upstream`, round-robin fan-out, single-flight merged, health-gated,
   TC→TCP retry). Everything else goes to the foreign chain.
7. Cache lookup first (geo-clustered key); misses traverse the upstream
   chain in strict priority order; on total failure a still-fresh expired
   cache entry is served (stale-on-failure) before giving up.

## Configuration

`key = value` lines, `#` comments. Full annotated example:
[`deploy/dnsdist/magdns.conf.example`](../deploy/dnsdist/magdns.conf.example).

| Key | Default | Meaning |
|---|---|---|
| `listen_dot` / `listen_doq` | `[::]:853` / `[::]:8853` | dual-stack listeners |
| `cert_file` / `key_file` | — | TLS material for both listeners |
| `upstream` | repeatable | foreign chain, strict priority = file order. Schemes: `quic:// tls:// https:// udp://`. Flags after URL: `noecs` (source ignores ECS — ECS queries route around it), `h2` or `h2=N` (HTTP/2 multiplexing over N connections, 1..=20) |
| `cn_upstream` | repeatable | domestic legs, `udp://host:53 [noecs]`; always round-robin spread |
| `cn_domain_file` | — | felixonmars dnsmasq-china-list format (~110k domains) |
| `cache_bytes` / `cache_ttl` | 100 MiB / 1200s | magazine size / lifetime cap |
| `cache_ttl_ignore` | false | serve until evicted, TTL floored at 1s |
| `ecs_enabled` + `ecs_prefix_v4/v6` | true / 24 / 56 | EDNS Client Subnet embedding + geo-cluster cache keys |
| `qps_per_ip` / `burst_per_ip` | 50 / 100 | layer 1 |
| `qps_domain` / `burst_domain` | 100 / 200 | layer 2 (0 = off) |
| `qps_global` / `burst_global` | 5000 / 10000 | layer 3 (0 = off) |
| `max_concurrent_queries` | 1024 | concurrency gate |
| `domain_limit_entries` | 8192 | tracked-qname cap for layer 2 |
| `query_timeout_ms` / `attempt_timeout_ms` | 500 / 200 | budgets per query / per source attempt |
| `probe_interval_s` | 10 | down-source probe cadence (probes bill on metered relays — raise if you care) |
| `spread_upstreams` | false | rotate chain start per query (load-sharing). Keep OFF for metered relays: serial priority drains quotas one account at a time |
| `maker_auth_kind` / `maker_auth_key` | — | `token` → raw `token:` header (EdgeOne trigger rule); `bearer` → `Authorization: Bearer` |
| `stale_on_failure` | true | serve expired entries when all sources fail |

## Operations

| Signal | Effect |
|---|---|
| `SIGHUP` | reload certs, resize/re-TTL the magazine, swap rate-limit values live (changing limits resets those buckets — instant relief under attack) |
| `SIGUSR1` | dump stats JSON to stderr |
| `SIGTERM`/`SIGINT` | graceful exit (also flushes PGO counters in instrumented builds) |

Stats JSON includes cache hits/misses/evictions, RSS, per-transport
up_sent/up_ok/up_err, cn_sent/cn_ok/cn_err, ratelimited /
domain_limited / global_limited counters:

```bash
kill -USR1 $(pidof magdns); journalctl -u magdns -n 1 --no-pager
```

## Building from source

See [`src/dnsdist/build.sh`](../src/dnsdist/build.sh):

```bash
./build.sh cross          # ThinLTO cortex-a53 release
./build.sh pgo-instrument # instrumented build
./build.sh pgo-collect    # 30 min qemu workload -> pgo-data/
./build.sh pgo-merge && ./build.sh pgo-final
```

Memory budget on the box: magazine (as configured) + ~8 MB runtime; RSS is
reported in every stats dump.
