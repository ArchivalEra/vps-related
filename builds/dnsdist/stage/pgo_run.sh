#!/bin/bash
# PGO profile collection run: mocks + SUT + loadgen for $DURATION seconds,
# with periodic DoQ-mock kills to exercise the fallback/recovery paths.
# The SUT must be the instrumented aarch64 binary run under qemu; profiles
# land in ../pgo-data/. Graceful SIGTERM at the end flushes counters.
set -u
cd "$(dirname "$0")"
DURATION="${DURATION:-1800}"
PGO_DIR="${PGO_DIR:-$PWD/../pgo-data}"
SUT_PREFIX="${SUT_PREFIX:-qemu-aarch64 -L /usr/aarch64-linux-gnu}"
SUT_BIN="${SUT_BIN:-../target-a64-pgo/aarch64-unknown-linux-gnu/release/magdns}"
PY=".venv/bin/python"

mkdir -p "$PGO_DIR" run
rm -f "$PGO_DIR"/*.profraw

cleanup() {
  [ -n "${LG_PID:-}" ] && kill "$LG_PID" 2>/dev/null
  [ -n "${SUT_PID:-}" ] && kill -TERM "$SUT_PID" 2>/dev/null
  sleep 3
  [ -n "${SUT_PID:-}" ] && kill -9 "$SUT_PID" 2>/dev/null
  pkill -f 'mock(dot|doh|doq)\.py' 2>/dev/null
}
trap cleanup EXIT

start_mock() {
  $PY "$1.py" --port "$2" >>"run/$1.log" 2>&1 & echo $! >"run/$1.pid"
  for _ in $(seq 1 40); do
    tail -50 "run/$1.log" 2>/dev/null | grep -q listening && break
    sleep 0.25
  done
}

rm -f run/mock*.log run/sut-pgo.log
start_mock mockdot 1855
start_mock mockdoh 1856
start_mock mockdoq 1854

LLVM_PROFILE_FILE="$PGO_DIR/default_%m_%p.profraw" \
  $SUT_PREFIX $SUT_BIN -c "$PWD/magdns-pgo.conf" >run/sut-pgo.log 2>&1 &
SUT_PID=$!
$PY probe.py --port 1853 --timeout 30 || { echo "SUT failed to start"; exit 1; }
echo "SUT up (pid $SUT_PID)"

$PY loadgen.py --dot 127.0.0.1:1853 --doq 127.0.0.1:18853 \
  --qps 60 --duration "$DURATION" --workers 4 --hot 50 --reconnect-every 200 \
  >run/loadgen-pgo.log 2>&1 &
LG_PID=$!
echo "loadgen up (pid $LG_PID)"

# cycle the DoQ mock: 150s up, 25s down -> strikes, DoT fallback, probe recovery
END=$((SECONDS + DURATION - 60))
while [ $SECONDS -lt $END ] && kill -0 "$LG_PID" 2>/dev/null; do
  sleep 150
  kill "$(cat run/mockdoq.pid)" 2>/dev/null
  sleep 25
  rm -f run/mockdoq.log
  start_mock mockdoq 1854
done

wait "$LG_PID"
tail -1 run/loadgen-pgo.log

kill -USR1 "$SUT_PID" 2>/dev/null
sleep 1
kill -TERM "$SUT_PID" 2>/dev/null
sleep 5
kill -9 "$SUT_PID" 2>/dev/null
grep -o 'STATS {.*}' run/sut-pgo.log | tail -1
ls -la "$PGO_DIR" | head -8
echo "PGO-RUN-DONE"
