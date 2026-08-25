# duck-ddns

DuckDNS dynamic A/AAAA updates: bash + curl resident loop, started by systemd,
no cron dependency, no architecture dependency (aarch64 / any Linux). Target
scenario: home-broadband server without an ICP filing — web traffic keeps
going through cloudflared; this component only solves the direct-entry path
for ssh / WireGuard / high ports (IPv6 direct first, v4 port-forward as a
fallback).

- One update URL writes both A and AAAA; pushes only when the locally
  detected address changed, plus a forced heartbeat every 24h (288 x 300s).
- IPv6 auto-selects the stable address (mngtmpaddr), skipping
  temporary/deprecated ones; follows prefix re-dials automatically.
- Warns in the log when v4 is behind CGNAT (100.64.0.0/10) — router port
  forwarding cannot work in that case.
- Manual debugging: run `sudo /usr/local/bin/duck-ddns.sh` in the foreground,
  or `curl "https://www.duckdns.org/update?domains=<sub>&token=<token>&verbose=true"`.

## Deploy (three paste blocks as root)

```bash
install -m 700 duck-ddns.sh /usr/local/bin/duck-ddns.sh
install -m 600 duck-ddns.env.example /etc/duck-ddns.env
vi /etc/duck-ddns.env   # fill in TOKEN / DOMAINS / IFACE

install -m 644 duck-ddns.service /etc/systemd/system/duck-ddns.service
systemctl daemon-reload && systemctl enable --now duck-ddns
journalctl -u duck-ddns -f
```

## Verify

```bash
dig +short AAAA <sub>.duckdns.org @223.5.5.5   # should equal curl -6 https://6.ipw.cn
dig +short A   <sub>.duckdns.org @223.5.5.5
```

From outside (phone data, NOT the home WiFi):
`ssh -6 user@<sub>.duckdns.org -p <high-port>`.

## Edge cases

- No ICP filing: inbound 80/443 (v4 and v6) can be cut by the ISP at any
  time — keep web on cloudflared; direct entry works best on high ports /
  WireGuard (UDP).
- Router IPv6 firewalls usually block WAN->LAN inbound by default (on
  OpenWrt add a traffic rule allowing it to this host); host-side
  ufw/nftables must allow it too.
- To keep the AAAA from ever drifting: pin the interface suffix with
  `ip token set ::beef dev eth0` (systemd-networkd equivalent:
  `IPv6Token=::beef`).
- HTTPS for direct services later: DuckDNS supports `&txt=` records, so a
  DNS-01 cert for `*.<sub>.duckdns.org` works without opening port 80.
