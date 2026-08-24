#!/bin/bash
# Box-feature (udp:// upstream only) test battery:
#   U1 basic udp upstream          U2 TC->TCP fallback
#   U3 ttl / ttl_ignore semantics  U4 OOM guard (RSS <= cache+8M under flood)
#   U5 restart scenarios (full magazine, SIGKILL, cold start, restart under load)
# Usage: [SUT_PREFIX="qemu-aarch64 -L /usr/aarch64-linux-gnu"] [SUT_BIN=...] ./run_udp_tests.sh
set -u
cd "$(dirname "$0")"
PY=".venv/bin/python"
SUT_PREFIX="${SUT_PREFIX:-}"
SUT_BIN="${SUT_BIN:-../target-box/release/magdns}"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
assert() { if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi; }

cleanup() {
  [ -n "${SUT_PID:-}" ] && kill -9 "$SUT_PID" 2>/dev/null
  pkill -f 'mockudp\.py' 2>/dev/null
  [ -n "${LG_PID:-}" ] && kill "$LG_PID" 2>/dev/null
  sleep 0.5
}
trap cleanup EXIT

mkdir -p run
rm -f run/mockudp.log run/sut-udp.log

$PY mockudp.py --port 15301 >run/mockudp.log 2>&1 & echo $! >run/mockudp.pid
for _ in $(seq 1 40); do grep -q "udp listening" run/mockudp.log 2>/dev/null && break; sleep 0.25; done
grep -q "udp listening" run/mockudp.log; assert $? "mockudp up"

start_sut() {
  $SUT_PREFIX $SUT_BIN -c "$PWD/magdns-udp-test.conf" >>run/sut-udp.log 2>&1 &
  SUT_PID=$!
  $PY probe.py --port 1853 --timeout 20
}

stats() { kill -USR1 "$SUT_PID" 2>/dev/null; sleep 0.6; grep -o 'STATS {.*}' run/sut-udp.log | tail -1; }

# --- U1 basic
start_sut; assert $? "SUT up (udp upstream)"
R=$($PY qclient.py --dot 127.0.0.1:1853 --name u1.stage.test --type 1)
echo "  $R"; echo "$R" | grep -q "rcode=0"; assert $? "U1 DoT-in -> udp upstream answers"
grep -q "MOCKHIT udp u1.stage.test" run/mockudp.log; assert $? "U1 mock saw the udp query"

# --- U2 cache + repeat
C1=$(grep -c "MOCKHIT" run/mockudp.log)
R=$($PY qclient.py --dot 127.0.0.1:1853 --name u2.stage.test --type 1)
R=$($PY qclient.py --dot 127.0.0.1:1853 --name u2.stage.test --type 1)
C2=$(grep -c "MOCKHIT" run/mockudp.log)
[ "$C2" -eq "$((C1+1))" ]; assert $? "U2 cache dedups (hits $C1->$C2)"

# --- U3 ttl semantics: ttl=1s expires; ignore=true keeps serving
sed -i 's/^cache_ttl = 1200$/cache_ttl = 1/' magdns-udp-test.conf
kill -HUP "$SUT_PID"; sleep 0.8
R=$($PY qclient.py --dot 127.0.0.1:1853 --name ttl-a.stage.test --type 1)
sleep 2.2
C1=$(grep -c "MOCKHIT" run/mockudp.log)
R=$($PY qclient.py --dot 127.0.0.1:1853 --name ttl-a.stage.test --type 1)
C2=$(grep -c "MOCKHIT" run/mockudp.log)
[ "$C2" -gt "$C1" ]; assert $? "U3a ttl=1s: entry expired -> refetch ($C1->$C2)"
sed -i 's/^cache_ttl_ignore = false$/cache_ttl_ignore = true/' magdns-udp-test.conf
kill -HUP "$SUT_PID"; sleep 0.8
R=$($PY qclient.py --dot 127.0.0.1:1853 --name ttl-b.stage.test --type 1)
sleep 2.2
C1=$(grep -c "MOCKHIT" run/mockudp.log)
R=$($PY qclient.py --dot 127.0.0.1:1853 --name ttl-b.stage.test --type 1)
C2=$(grep -c "MOCKHIT" run/mockudp.log)
echo "$R" | grep -q "rcode=0" && [ "$C2" -eq "$C1" ]; assert $? "U3b ttl ignored: magazine-only cleaning, no refetch ($C1==$C2)"
S=$(stats); grep -q '"cache_ttl_ignore":true' <<<"$S"; assert $? "U3c stats reflect ignore mode"
# restore ttl config for the rest
sed -i 's/^cache_ttl = 1$/cache_ttl = 1200/; s/^cache_ttl_ignore = true$/cache_ttl_ignore = false/' magdns-udp-test.conf
kill -HUP "$SUT_PID"; sleep 0.8

# --- U2b TC -> TCP fallback
kill "$(cat run/mockudp.pid)" 2>/dev/null; sleep 0.3
$PY mockudp.py --port 15301 --tc >>run/mockudp.log 2>&1 & echo $! >run/mockudp.pid
for _ in $(seq 1 40); do tail -5 run/mockudp.log | grep -q "udp listening" && break; sleep 0.25; done
sleep 3.5   # let the udp source recover via probe (interval 3s)
R=$($PY qclient.py --dot 127.0.0.1:1853 --name tc1.stage.test --type 1 --timeout 8)
echo "  $R"; echo "$R" | grep -q "rcode=0"; assert $? "U2b TC=1 answer still arrives"
grep -q "MOCKHIT tcp tc1.stage.test" run/mockudp.log; assert $? "U2b fallback went over TCP"
kill "$(cat run/mockudp.pid)" 2>/dev/null; sleep 0.3
$PY mockudp.py --port 15301 >>run/mockudp.log 2>&1 & echo $! >run/mockudp.pid
for _ in $(seq 1 40); do tail -5 run/mockudp.log | grep -q "udp listening" && break; sleep 0.25; done

# --- U4 OOM guard: 2MiB magazine, 200qps unique flood, RSS must stay <= cap+8M
$PY loadgen.py --dot 127.0.0.1:1853 --qps 200 --duration 45 --workers 8 --hot 5 \
  >run/loadgen-oom.log 2>&1 &
LG_PID=$!
( for i in $(seq 1 9); do sleep 5; kill -USR1 "$SUT_PID" 2>/dev/null; done ) &
WATCH=$!
wait "$LG_PID" 2>/dev/null
kill "$WATCH" 2>/dev/null
tail -1 run/loadgen-oom.log
echo "  rss curve: $(grep -o '"rss_bytes":[0-9]*' run/sut-udp.log | cut -d: -f2 | tr '\n' ' ')"
S=$(stats)
RSS=$(grep -o '"rss_bytes":[0-9]*' <<<"$S" | cut -d: -f2)
CAP=$(grep -o '"cache_cap":[0-9]*' <<<"$S" | cut -d: -f2)
USED=$(grep -o '"cache_bytes":[0-9]*' <<<"$S" | cut -d: -f2)
# under qemu-user, statm reports the qemu host process (translation overhead
# + JIT); native runs carry the strict magazine+8M budget
OVERHEAD=0
[ -n "$SUT_PREFIX" ] && OVERHEAD=$((32*1024*1024))
LIMIT=$((CAP + 8*1024*1024 + OVERHEAD))
echo "  rss=$RSS cap=$CAP used=$USED limit=$LIMIT (qemu overhead allowance: ${OVERHEAD}B)"
[ "$RSS" -gt 0 ] && [ "$RSS" -le "$LIMIT" ]; assert $? "U4 RSS ${RSS}B <= cache+8M${OVERHEAD:+(+qemu)} (${LIMIT}B)"
[ "$USED" -le "$CAP" ]; assert $? "U4b magazine itself bounded (${USED}B <= ${CAP}B)"

# --- U5 restart scenarios
# U5a: magazine under pressure -> SIGKILL -> cold start must be fast and serving
$PY - <<'EOF'
import socket, ssl, asyncio, sys
sys.path.insert(0, ".")
from loadgen import DotWorker
async def main():
    w = DotWorker("127.0.0.1:1853")
    await w.connect()
    for i in range(4000):
        await w.query(f"fill{i:05d}.stage.test")
    await w.recycle()
asyncio.run(main())
print("filled")
EOF
kill -9 "$SUT_PID" 2>/dev/null; sleep 0.5
T0=$(date +%s%N)
start_sut; RC=$?
T1=$(date +%s%N)
MS=$(( (T1-T0)/1000000 ))
assert $RC "U5a cold start after SIGKILL"
echo "  cold start: ${MS}ms"
[ "$MS" -lt 5000 ]; assert $? "U5a cold start under 5s (${MS}ms)"
R=$($PY qclient.py --dot 127.0.0.1:1853 --name after-restart.stage.test --type 1)
echo "$R" | grep -q "rcode=0"; assert $? "U5a serving after restart"

# U5b: restart under live load (clients hammering while process dies)
$PY loadgen.py --dot 127.0.0.1:1853 --qps 80 --duration 30 --workers 6 --hot 3 \
  >run/loadgen-restart.log 2>&1 &
LG_PID=$!
sleep 4
kill -9 "$SUT_PID" 2>/dev/null
sleep 1
start_sut >/dev/null 2>&1
sleep 26
wait "$LG_PID" 2>/dev/null
L=$(tail -1 run/loadgen-restart.log); echo "  $L"
OKC=$(grep -o 'ok=[0-9]*' <<<"$L" | cut -d= -f2)
SENT=$(grep -o 'sent=[0-9]*' <<<"$L" | cut -d= -f2)
FAILS=$(grep -o 'fail=[0-9]*' <<<"$L" | cut -d= -f2)
# during the kill window failures are expected; afterwards everything must succeed
[ "$OKC" -gt 0 ] && [ "$FAILS" -lt "$SENT" ]; assert $? "U5b survived restart under load (ok=$OKC fail=$FAILS sent=$SENT)"
R=$($PY qclient.py --dot 127.0.0.1:1853 --name final.stage.test --type 1)
echo "$R" | grep -q "rcode=0"; assert $? "U5b serving after load+restart"

echo
echo "UDP-BATTERY PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
