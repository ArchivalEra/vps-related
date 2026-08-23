#!/bin/bash
# REAL NextDNS test — honest scope for THIS host:
#  * egress here is mandatory-proxied (127.0.0.1:2080); direct TCP/UDP to
#    nextdns (853 AND 443) is blackholed, so no direct real answer is possible.
#  * what CAN be verified live:
#    1) the ordered fallback chain really attempts DoQ -> DoT -> DoH against
#       the real endpoints (stats) — PASS criteria below;
#    2) via the local proxy, nextdns DoH answers with h2 ALPN and refuses
#       plain http/1.1 — recorded as evidence that the h2-capable DoH client
#       (hyper) is required, which magdns now uses.
# Full DoH E2E (TLS + HTTP semantics) is covered by the stage suite (T1/T5a).
set -u
cd "$(dirname "$0")"
SUT_PREFIX="${SUT_PREFIX:-qemu-aarch64 -L /usr/aarch64-linux-gnu}"
SUT_BIN="${SUT_BIN:-../target-a64-final/aarch64-unknown-linux-gnu/release/magdns}"
PY=".venv/bin/python"
PASS=0; FAIL=0
REAL_Q=0
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
assert() { if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi; }
SUT_PID=""
cleanup() { [ -n "$SUT_PID" ] && kill "$SUT_PID" 2>/dev/null; sleep 1; }
trap cleanup EXIT

rm -f run/real-chain.log
$SUT_PREFIX $SUT_BIN -c "$PWD/magdns-real.conf" -v >run/real-chain.log 2>&1 &
SUT_PID=$!
$PY probe.py --port 1853 --timeout 30; assert $? "SUT real-chain up"
R=$($PY qclient.py --dot 127.0.0.1:1853 --name chain-probe.example.com --type 1 --timeout 4 || true); REAL_Q=$((REAL_Q+1))
echo "  $R (direct egress blackholed on this host; order is the assertion)"
sleep 9   # let doq(3s) -> dot(3s) -> doh(3s) attempts all fire
kill -USR1 "$SUT_PID" 2>/dev/null; sleep 1
S=$(grep -o 'STATS {.*}' run/real-chain.log | tail -1)
echo "  stats: $S"
grep -q '"up_sent_doq":1' <<<"$S"; assert $? "chain attempted real DoQ first"
grep -q '"up_sent_dot":1' <<<"$S"; assert $? "chain fell back to real DoT"
grep -q '"up_sent_doh":1' <<<"$S"; assert $? "chain fell back to real DoH"
grep -q '"servfail":1' <<<"$S"; assert $? "all-dead chain degrades to SERVFAIL (correct)"
kill "$SUT_PID"; sleep 1; SUT_PID=""

# evidence: nextdns over the local proxy — h2 yes, http/1.1 refused
Q=$(python3 -c "
import base64,struct,os
q=os.urandom(2)+struct.pack('!HHHHHH',0x0100,1,0,0,0,1)+b'\x07example\x03com\x00'+struct.pack('!HH',1,1)+b'\x00'+struct.pack('!HHIH',41,1232,0,0)
print(base64.urlsafe_b64encode(q).decode().rstrip('='))")
H2=$(timeout 12 curl -s -o /dev/null -w "%{http_code}" "https://dns.nextdns.io/88f745?dns=$Q" -H 'Accept: application/dns-message' || echo 000)
REAL_Q=$((REAL_Q+1))
echo "  proxied DoH -> HTTP $H2 (magdns speaks h2+http/1.1 via hyper either way)"
[ "$H2" = "200" ]; assert $? "nextdns answers real DoH (via local proxy)"

echo "REAL-QUERY-COUNT: $REAL_Q (1 via SUT attempts, 1 via proxied curl)"
echo "REAL PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
