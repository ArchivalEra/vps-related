#!/usr/bin/env bash
# duck-ddns -- DuckDNS A/AAAA updater, self-looping (no cron needed).
# deps: bash, curl, iproute2. pure shell, arch-independent (aarch64 fine).
set -u

# config comes from /etc/duck-ddns.env (or real env vars)
[[ -z "${TOKEN:-}" && -r /etc/duck-ddns.env ]] && . /etc/duck-ddns.env
: "${TOKEN:?set TOKEN in /etc/duck-ddns.env}" "${DOMAINS:?set DOMAINS in /etc/duck-ddns.env}"
INTERVAL="${INTERVAL:-300}"
IFACE="${IFACE:-$(ip -6 route show default | awk '{for (i=1; i<NF; i++) if ($i=="dev") {print $(i+1); exit}}')}"

pick_v6() {
  # first stable global v6 on $IFACE: prefer mngtmpaddr (SLAAC stable), skip temporary/deprecated
  ip -6 -o addr show dev "$IFACE" scope global 2>/dev/null | awk '
    $3 != "inet6"          { next }
    /temporary|deprecated/ { next }
    {
      if ($0 ~ /mngtmpaddr/ && !p) { split($4, a, "/"); p = a[1] }
      if (!c)                      { split($4, b, "/"); c = b[1] }
    }
    END { print (p ? p : c) }'
}

pick_v4() {
  curl -fs4 --max-time 10 https://4.ipw.cn 2>/dev/null \
    || curl -fs4 --max-time 10 https://api.ipify.org 2>/dev/null
}

is_cgnat() { # 100.64.0.0/10
  local a=0 b=0
  IFS=. read -r a b _ _ <<< "$1"
  (( a == 100 && b >= 64 && b <= 127 ))
}

echo "duck-ddns: domains=${DOMAINS} iface=${IFACE:-auto} interval=${INTERVAL}s"
last4='?'; last6='?'; i=0
while :; do
  v4="$(pick_v4 || true)"
  v6="$(pick_v6 || true)"
  if [[ -n "${v4}${v6}" ]]; then
    if [[ "$v4" != "$last4" || "$v6" != "$last6" ]] || (( i % 288 == 0 )); then
      if [[ -n "$v4" ]] && is_cgnat "$v4"; then
        echo "note: v4 $v4 is CGNAT (100.64/10): v4 port-forwarding won't work, rely on v6"
      fi
      q="domains=${DOMAINS}&token=${TOKEN}"
      [[ -n "$v4" ]] && q="${q}&ip=${v4}"
      [[ -n "$v6" ]] && q="${q}&ipv6=${v6}"
      url="https://www.duckdns.org/update?${q}"
      if [[ -n "$v6" ]]; then
        r="$(curl -fsS --max-time 20 "$url" || echo FAIL)"
      else
        # v4-only push: force -4 so duckdns does not auto-fill AAAA from the connection address
        r="$(curl -fs4 --max-time 20 "$url" || echo FAIL)"
      fi
      if [[ "$r" == "OK" ]]; then
        last4="$v4"; last6="$v6"
        echo "OK A=${v4:-none} AAAA=${v6:-none}"
      else
        echo "update failed: ${r}"
      fi
    fi
  fi
  i=$(( i + 1 ))
  sleep "$INTERVAL"
done
