#!/bin/bash
# End-to-end stage tests for magdns against the loopback mock rig.
# Usage: [SUT_PREFIX="qemu-aarch64 -L /usr/aarch64-linux-gnu"] [SUT_BIN=../target-pgo/...] ./run_tests.sh
set -u
cd "$(dirname "$0")"
STAGE="$PWD"
PY=".venv/bin/python"
SUT_PREFIX="${SUT_PREFIX:-}"
SUT_BIN="${SUT_BIN:-../target/debug/magdns}"
PASS=0
FAIL=0
declare -a FAILED_TESTS

ok()   { PASS=$((PASS+1)); echo "PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); FAILED_TESTS+=("$1"); echo "FAIL: $1"; }
check(){ if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi; }

mkdir -p run
cleanup() {
  [ -n "${SUT_PID:-}" ] && kill "$SUT_PID" 2>/dev/null
  pkill -f 'mock(dot|doh|doq)\.py' 2>/dev/null
  sleep 0.3
}
trap cleanup EXIT

start_mocks() {
  rm -f run/mock*.log
  $PY mockdot.py --port 1855 >run/mockdot.log 2>&1 & echo $! >run/mockdot.pid
  $PY mockdoh.py --port 1856 >run/mockdoh.log 2>&1 & echo $! >run/mockdoh.pid
  $PY mockdoq.py --port 1854 >run/mockdoq.log 2>&1 & echo $! >run/mockdoq.pid
  sleep 1.2
}
stop_mock() { kill "$(cat run/$1.pid)" 2>/dev/null; sleep 0.3; }
start_mock() {
  $PY "$1.py" --port "$2" >>"run/$1.log" 2>&1 & echo $! >"run/$1.pid"
  for _ in $(seq 1 40); do
    grep -q listening "run/$1.log" 2>/dev/null && break
    sleep 0.25
  done
  sleep 0.3
}
cnt() { grep -c "MOCKHIT $1" "run/$2.log" 2>/dev/null || true; }

# fresh SUT
rm -f run/sut.log
$SUT_PREFIX $SUT_BIN -c "$STAGE/magdns-test.conf" -v >run/sut.log 2>&1 &
SUT_PID=$!
$PY probe.py --port 1853 --timeout 10; check $? "SUT DoT listener up"
sleep 0.5

# T1 DoT listener -> upstream DoQ
start_mocks
R=$($PY qclient.py --dot 127.0.0.1:1853 --name t1.stage.test --type 1)
echo "$R" | grep -q "rcode=0" && [ "$(cnt doq mockdoq)" -ge 1 ]; check $? "T1 DoT-in -> DoQ upstream"
echo "  $R"

# T2 cache: repeat query served from cache, TTL capped at 1200
c1=$(cnt doq mockdoq)
R=$($PY qclient.py --dot 127.0.0.1:1853 --name t2.stage.test --type 1)
R=$($PY qclient.py --dot 127.0.0.1:1853 --name t2.stage.test --type 1)
c2=$(cnt doq mockdoq)
[ "$c2" -eq "$((c1+1))" ] && echo "$R" | grep -q "ttl=119[89]\|ttl=1200"; check $? "T2 cache hit + TTL cap 1200 (hits $c1->$c2)"
echo "  $R"

# T3 DoQ listener (in via QUIC, out via QUIC)
R=$($PY qclient.py --doq 127.0.0.1:18853 --name t3.stage.test --type 28)
echo "$R" | grep -q "rcode=0"; check $? "T3 DoQ-in works"
echo "  $R"

# T7 dual-stack listener on [::1]
R=$($PY qclient.py --dot "[::1]:1853" --name t7.stage.test --type 1)
echo "$R" | grep -q "rcode=0"; check $? "T7 dual-stack [::1]:1853"
echo "  $R"

# T4 DoQ upstream dies -> fallback to DoT
cd0=$(cnt dot mockdot); stop_mock mockdoq
R=$($PY qclient.py --dot 127.0.0.1:1853 --name t4a.stage.test --type 1)
cd1=$(cnt dot mockdot)
echo "$R" | grep -q "rcode=0" && [ "$cd1" -gt "$cd0" ]; check $? "T4a fallback DoQ->DoT"
echo "  $R"

# T5 DoT dies too -> fallback to DoH
ch0=$(cnt doh mockdoh); stop_mock mockdot
R=$($PY qclient.py --dot 127.0.0.1:1853 --name t5a.stage.test --type 1)
ch1=$(cnt doh mockdoh)
echo "$R" | grep -q "rcode=0" && [ "$ch1" -gt "$ch0" ]; check $? "T5a fallback DoT->DoH"
echo "  $R"

# T5b everything dead -> SERVFAIL
stop_mock mockdoh
R=$($PY qclient.py --dot 127.0.0.1:1853 --name t5b.stage.test --type 1)
echo "$R" | grep -q "rcode=2"; check $? "T5b all dead -> SERVFAIL"
echo "  $R"

# T6 DoQ recovers via probe (dot+doh still down so doq is preferred again)
start_mock mockdoq 1854
R=$($PY qclient.py --dot 127.0.0.1:1853 --name t6a.stage.test --type 1)
echo "$R" | grep -q "rcode=0"; check $? "T6a instant recovery when others down"
echo "  $R"
start_mock mockdot 1855; start_mock mockdoh 1856
c_dq_before=$(cnt doq mockdoq)
R=$($PY qclient.py --dot 127.0.0.1:1853 --name t6b.stage.test --type 1)
sleep 7
R=$($PY qclient.py --dot 127.0.0.1:1853 --name t6c.stage.test --type 1)
c_dq_after=$(cnt doq mockdoq)
[ "$c_dq_after" -gt "$c_dq_before" ]; check $? "T6b probe re-arms DoQ preference ($c_dq_before->$c_dq_after)"
echo "  $R"

# T8 malformed input keeps SUT alive
$PY - <<'EOF'
import socket
s = socket.create_connection(("127.0.0.1", 1853), timeout=3)
s.sendall(b"\xff\xff" + b"GARBAGE" * 10)  # frame len 65535 then junk, then close
s.close()
s2 = socket.create_connection(("127.0.0.1", 1853), timeout=3)
s2.sendall(b"\x00\x00")  # zero-length frame
s2.close()
s3 = socket.create_connection(("127.0.0.1", 1853), timeout=3)
s3.sendall(b"\x00\x0cTOOSHORT")
s3.close()
print("malformed sent")
EOF
sleep 0.3
R=$($PY qclient.py --dot 127.0.0.1:1853 --name t8.stage.test --type 1)
echo "$R" | grep -q "rcode=0"; check $? "T8 survives malformed input"
echo "  $R"

# T10 magazine eviction: 64KB cache, ~900 unique names, oldest must be refetched
cq0=$(cnt doq mockdoq)
$PY - <<'EOF'
import socket, ssl, os, struct, sys
sys.path.insert(0, ".")
from loadgen import DotWorker
import asyncio

async def main():
    w = DotWorker("127.0.0.1:1853")
    await w.connect()
    for i in range(900):
        await w.query(f"ev{i:04d}.stage.test")
    await w.recycle()
asyncio.run(main())
print("eviction storm done")
EOF
cq1=$(cnt doq mockdoq)
R=$($PY qclient.py --dot 127.0.0.1:1853 --name ev0000.stage.test --type 1)
cq2=$(cnt doq mockdoq)
[ "$cq1" -ge "$((cq0+880))" ] && [ "$cq2" -gt "$cq1" ]; check $? "T10 FIFO eviction refetches oldest (q:$cq0/$cq1/$cq2)"
echo "  $R"

# T9 SIGHUP cert hot reload: swap cert signed by a 2nd CA
cp certs/sut.pem certs/sut.bak.pem; cp certs/sut.key certs/sut.bak.key
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout /tmp/ca2.key -out /tmp/ca2.pem -days 30 -nodes -subj "/CN=ca2" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout certs/sut.key -out /tmp/sut2.csr -nodes -subj "/CN=stage.sut.test" 2>/dev/null
printf "subjectAltName=DNS:stage.sut.test,IP:127.0.0.1,IP:::1\n" > /tmp/ext2.txt
openssl x509 -req -in /tmp/sut2.csr -CA /tmp/ca2.pem -CAkey /tmp/ca2.key -CAcreateserial -out certs/sut.pem -days 30 -extfile /tmp/ext2.txt 2>/dev/null
kill -HUP "$SUT_PID"; sleep 0.5
$PY qclient.py --dot 127.0.0.1:1853 --name t9a.stage.test --type 1 >run/t9a.out 2>&1
grep -q "FAIL" run/t9a.out; check $? "T9a old CA rejected after reload"
cp certs/sut.bak.pem certs/sut.pem; cp certs/sut.bak.key certs/sut.key
kill -HUP "$SUT_PID"; sleep 0.5
R=$($PY qclient.py --dot 127.0.0.1:1853 --name t9b.stage.test --type 1)
echo "$R" | grep -q "rcode=0"; check $? "T9b original cert restored + works"
echo "  $R"

# T13 passthrough QDCOUNT=2 -> some sane reply, SUT alive
$PY - <<'EOF'
import socket, ssl, struct, os
qid = struct.unpack("!H", os.urandom(2))[0]
q = struct.pack("!HHHHHH", qid, 0x0100, 2, 0, 0, 0) + b"\x00z\x00z" + b"\x00\x01\x00\x01" * 2
ctx = ssl.create_default_context(cafile="certs/ca.pem")
with socket.create_connection(("127.0.0.1", 1853), timeout=5) as c:
    with ctx.wrap_socket(c, server_hostname="127.0.0.1") as tls:
        tls.sendall(len(q).to_bytes(2, "big") + q)
        lb = tls.recv(2)
        n = int.from_bytes(lb, "big")
        r = b""
        while len(r) < n:
            r += tls.recv(n - len(r))
        assert len(r) == n and len(r) >= 12, "bad passthrough reply"
print("passthrough ok, rcode", r[3] & 0xF)
EOF
check $? "T13 passthrough QDCOUNT=2 answered"

# T14 magazine hot-resize via SIGHUP: 65536 -> 16384 -> back
cp magdns-test.conf run/magdns-test.conf.bak
kill -USR1 "$SUT_PID"; sleep 0.5
BEFORE=$(grep -o '"cache_cap":[0-9]*' run/sut.log | tail -1 | cut -d: -f2)
sed -i 's/^cache_bytes = 65536$/cache_bytes = 16384/' magdns-test.conf
kill -HUP "$SUT_PID"; sleep 0.8
kill -USR1 "$SUT_PID"; sleep 0.5
S=$(grep -o 'STATS {.*}' run/sut.log | tail -1)
AFTER=$(grep -o '"cache_cap":[0-9]*' <<<"$S" | cut -d: -f2)
BYTES=$(grep -o '"cache_bytes":[0-9]*' <<<"$S" | cut -d: -f2)
ENTRIES=$(grep -o '"cache_entries":[0-9]*' <<<"$S" | cut -d: -f2)
[ "$BEFORE" = "65536" ] && [ "$AFTER" = "16384" ] && [ "$ENTRIES" -gt 0 ] && [ "$BYTES" -le 16384 ]
check $? "T14 hot resize 65536->$AFTER, bytes=$BYTES entries=$ENTRIES"
R=$($PY qclient.py --dot 127.0.0.1:1853 --name t14.stage.test --type 1)
echo "$R" | grep -q "rcode=0"; check $? "T14b still serving after resize"
echo "  $R"
cp run/magdns-test.conf.bak magdns-test.conf
kill -HUP "$SUT_PID"; sleep 0.8

# T15 single-flight: slow DoQ mock (400ms), 15 parallel conns, one name
kill "$(cat run/mockdoq.pid)" 2>/dev/null; sleep 0.3
rm -f run/mockdoq.log
$PY mockdoq.py --port 1854 --delay 0.4 >run/mockdoq.log 2>&1 & echo $! >run/mockdoq.pid
for _ in $(seq 1 40); do grep -q listening run/mockdoq.log 2>/dev/null && break; sleep 0.25; done
sleep 0.3
$PY - <<'EOF'
import asyncio, ssl, struct, os, sys
sys.path.insert(0, ".")
from loadgen import build_query

async def one(name, i, out):
    ctx = ssl.create_default_context(cafile="certs/ca.pem")
    try:
        rd, wr = await asyncio.open_connection("127.0.0.1", 1853, ssl=ctx, server_hostname="127.0.0.1")
        q = build_query(name)
        wr.write(len(q).to_bytes(2, "big") + q)
        await wr.drain()
        lb = await asyncio.wait_for(rd.readexactly(2), 8)
        n = int.from_bytes(lb, "big")
        r = await asyncio.wait_for(rd.readexactly(n), 8)
        out[i] = (r[3] & 0xF) == 0
        wr.close()
    except Exception as e:
        out[i] = False

async def main():
    out = {}
    await asyncio.gather(*[one("sf1.stage.test", i, out) for i in range(15)])
    ok = sum(1 for v in out.values() if v)
    print(f"SINGLEFLIGHT ok={ok}/15")
    sys.exit(0 if ok == 15 else 1)

asyncio.run(main())
EOF
check $? "T15 15 parallel clients all answered"
SF=$(cat run/mockdoq.log run/mockdot.log run/mockdoh.log 2>/dev/null | grep -c "sf1.stage.test")
[ "$SF" -eq 1 ]; check $? "T15 single-flight: upstream saw exactly 1 query across all transports (got $SF)"

# stats dump
kill -USR1 "$SUT_PID"; sleep 0.5
S=$(grep -o 'STATS {.*}' run/sut.log | tail -1)
echo "stats: $S"
[ -n "$S" ]; check $? "stats dump present"
grep -q '"cache_entries":' <<<"$S" && grep -q '"fallback":' <<<"$S"; check $? "stats keys present"

echo
echo "===================="
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -gt 0 ]; then printf 'failed: %s\n' "${FAILED_TESTS[@]}"; exit 1; fi
exit 0
