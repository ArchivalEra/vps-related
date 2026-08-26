# magdns-console — Dart + Flutter GUI design proposal

Status: design proposal (not yet approved for implementation).
Scope: a management + status console for `magdns` (box) and
`magdns-client` (local), NOT a DNS resolver itself — all resolution stays
in the Rust daemons; the app is a cockpit.

## Why Flutter

- One codebase for the three surfaces this project actually has: Android/iOS
  (household users of magdns-client), Windows/macOS desktop (the operator's
  laptop) and Linux (the box itself, where it can run as a kiosk).
- Dart's isolates map cleanly onto "poll stats in the background, render on
  the main thread" without jank.
- `dart:io` SecureSocket speaks DoT directly, so the console can also act as
  a thin MGB1 client to query live state through the same authenticated
  channel end users already trust.

## Non-goals

- Editing config.json by hand-shaped form fields that fight the file.
  The GUI reads and renders it, and writes it back only through explicit,
  reviewable diffs (see "Config editing" below).
- Becoming a VPN/traffic app. No TUN, no proxying.

## Architecture

```
┌──────────────────────────── Flutter app ───────────────────────────┐
│  UI (widgets only)                                                 │
│    ▲                                                              │
│  controllers (ChangeNotifier per screen)                          │
│    ▲                                                              │
│  repositories — one per backend surface:                          │
│    StatsRepo      ← GET /stats + SIGUSR1-equivalent JSON          │
│    ConfigRepo     ← config.json over SFTP/SCP or local file       │
│    HealthRepo     ← GET /health, TCP probes per upstream          │
│    OverridesRepo  ← overrides table CRUD (diff → write)           │
└────────────────────────────────────────────────────────────────────┘
         │                                   │
   local mode:                        remote mode:
   talks to magdns-client             SSH to box / HTTPS to relay
   on 127.0.0.1 (same host)           with stored key + known_hosts pinning
```

Key decision: **no new management API on the box**. Everything the console
needs already exists or arrives via config.json hot reload. Remote editing
uses plain SSH file transfer plus a SIGHUP trigger (`systemctl kill -s HUP`),
which keeps the attack surface at exactly "SSH access you already had".
The UUID/token secrets stay in the platform keystore
(`flutter_secure_storage`) — never in config.json, mirroring the env-inject
rule.

## Screens

1. **Dashboard** — resolution rate sparkline (from `/stats` counters),
   cache hit ratio gauge, upstream health dots (green/yellow/red from
   Health probes), magazine fill bar, RSS vs MemoryMax headroom.
2. **Sources & chains** — renders the routing section as an editable tree:
   splits → chains → groups → members. Balance/priority toggles, drag to
   reorder priority members, per-member batch/h2/noecs chips. Writes are
   diffs against the last-applied generation.
3. **Overrides** — list + quick-add (domain, block-or-pin, addresses).
   Bulk import from ad-block style hosts files.
4. **Ingress** — subnet→auth table editor with CIDR validation inline.
5. **Client (local)** — magdns-client service state, current server,
   batch AIMD size live view, switch-server shortcut.
6. **Logs** — streamed journalctl (remote via SSH) or local file tail,
   filtered by rcode/upstream.

## State model

```dart
sealed class Gen { }                 // mirrors Rust Routing generations
class StatsSnapshot { hits, misses, upstreamFetches, rss, queuePeak }
class UpstreamHealth { name, state, latencyMs }
```

Controllers poll `StatsRepo` every 5 s (configurable); every screen reads
from the same controller set so no double-polling. Reload actions show the
pending diff and require explicit apply → triggers SIGHUP remotely.

## Packaging

| Surface | Mechanism |
|---|---|
| Android/iOS | standard store-less APK/IPA builds |
| Windows/macOS | msix / dmg |
| Linux box | deb + systemd user service optional (kiosk mode off by default) |

## Milestones

1. M1: read-only dashboard against /stats + /health (both exist today).
2. M2: overrides CRUD with diff-preview writes.
3. M3: full sources/chains/splits editor.
4. M4: remote SSH transport + multi-box profiles.

## Open questions for the operator

- Does the console need multi-box aggregation (all three Maker accounts'
  quota gauges side-by-side)? Presumed yes.
- Auth for the console itself on shared devices: biometric gate before
  showing/editing overrides?
