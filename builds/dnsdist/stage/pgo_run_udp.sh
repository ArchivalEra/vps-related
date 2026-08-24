#!/bin/bash
# PGO profile collection for the BOX-feature build (udp:// upstream):
# mockudp + SUT + loadgen for $DURATION, with periodic mock kills to exercise
# strike/probe/fallback and TC->TCP paths. Graceful SIGTERM flushes counters.
set -u
cd "$(dirname "$0")"
DURATION="${DURATION:-1800}"
PGO_DIR="${PGO_DIR:-$PWD/../pgo-data-udp}"
SUT_PREFIX="${SUT_PREFIX:-qemu-aarch64 -L /usr/aarch64-linux-gnu}"
SUT_BIN="${SUT_BIN:-../target-a64-box-pgo/aarch64-unknown-linux-gnu/release/magdns}"
PY=".venv/bin/python"

mkdir -p "$PGO_DIR" run
rm -f "$PGO_DIR"/*.profraw

cleanup() {
  [ -n "${LG_PID:-}" ] && kill "$LG_PID" 2>/dev/null
  [ -n "${SUT_PID:-}" ] && kill -TERM "$SUT_PID" 2>/dev/null
  sleep 3
  [ -n "${SUT_PID:-}" ] && kill -9 "$SUT_PID" 2>/dev/null
  pkill -f 'mockudp\.py' 2>/dev/null
}
trap cleanup EXIT

start_mock() {
  $PY mockudp.py --port 15301 $1 >>run/mockudp-pgo.log 2>&1 & echo $! >run/mockudp.pid
  for _ in $(seq 1 40); do
    tail -20 run/mockudp-pgo.log 2>/dev/null | grep -q "udp listening" && break
    sleep 0.25
  done
}

rm -f run/mockudp-pgo.log run/sut-pgo-udp.log
start_mock ""

LLVM_PROFILE_FILE="$PGO_DIR/default_%m_%p.profraw" \
  $SUT_PREFIX $SUT_BIN -c "$PWD/magdns-pgo-udp.conf" >run/sut-pgo-udp.log 2>&1 &
SUT_PID=$!
$PY probe.py --port 1853 --timeout 30 || { echo "SUT failed to start"; exit 1; }
echo "SUT up (pid $SUT_PID)"

$PY loadgen.py --dot 127.0.0.1:1853 --doq 127.0.0.1:18853 \
  --qps 60 --duration "$DURATION" --workers 4 --hot 50 --reconnect-every 200 \
  >run/loadgen-pgo-udp.log 2>&1 &
LG_PID=$!
echo "loadgen up (pid $LG_PID)"

# cycle the upstream: 150s up / 25s down / 25s in TC mode (forces TCP path)
END=$((SECONDS + DURATION - 60))
while [ $SECONDS -lt $END ] && kill -0 "$LG_PID" 2>/dev/null; do
  sleep 150
  kill "$(cat run/mockudp.pid)" 2>/dev/null
  sleep 25
  start_mock "--tc"
  sleep 25
  kill "$(cat run/mockudp.pid)" 2>/dev/null
  start_mock ""
done

wait "$LG_PID"
tail -1 run/loadgen-pgo-udp.log

kill -USR1 "$SUT_PID" 2>/dev/null
sleep 1
kill -TERM "$SUT_PID" 2>/dev/null
sleep 5
kill -9 "$SUT_PID" 2>/dev/null
grep -o 'STATS {.*}' run/sut-pgo-udp.log | tail -1
ls -la "$PGO_DIR" | head -8
echo "PGO-UDP-RUN-DONE"
