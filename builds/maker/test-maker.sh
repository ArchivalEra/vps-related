#!/bin/bash
# Quick test for the EdgeOne DoH relay (local or deployed).
# Usage: ./test-maker.sh <base_url> <secret_key>
set -euo pipefail
BASE="${1:-http://127.0.0.1:8787}"
SECRET="${2:-dev-only-change-me}"

TODAY=$(date -u +%F)
TOKEN=$(printf '%s' "$TODAY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}' | head -c 32)

echo "== health =="
curl -s "$BASE/health" || echo "(no /health endpoint, skipping)"

echo "== auth reject (bad token) =="
RC=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/dns-query" \
  -H "Authorization: Bearer BADTOKEN1234567890123456789012345" \
  -H "Content-Type: application/dns-message" \
  --data-binary "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b")
[ "$RC" = "401" ] && echo "PASS: bad token rejected (401)" || echo "FAIL: expected 401 got $RC"

echo "== build a real DNS query (dig-style) =="
# Build query: example.com A IN with EDNS0
python3 -c "
import struct, os, sys
qid = struct.unpack('!H', os.urandom(2))[0]
hdr = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 1)
q = b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)
opt = b'\x00' + struct.pack('!HHIH', 41, 1232, 0, 0)
open('/tmp/dns-query.bin','wb').write(hdr + q + opt)
print(f'query built ({len(hdr+q+opt)}B, id={qid})')
"

echo "== POST RFC 8484 =="
RESP=$(curl -s -o /tmp/dns-resp.bin -w "%{http_code}" -X POST "$BASE/dns-query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/dns-message" \
  --data-binary @/tmp/dns-query.bin)
echo "HTTP=$RESP size=$(stat -c%s /tmp/dns-resp.bin 2>/dev/null || echo 0)"
if [ "$RESP" = "200" ]; then
  python3 -c "
r=open('/tmp/dns-resp.bin','rb').read()
if len(r)>=12:
    print(f'DNS response: rcode={r[3]&0xF} ancount={int.from_bytes(r[6:8],\"big\")} len={len(r)}')
else:
    print('response too short:', len(r))
"
fi

echo "== GET RFC 8484 =="
B64=$(python3 -c "
import base64
d=open('/tmp/dns-query.bin','rb').read()
print(base64.urlsafe_b64encode(d).decode().rstrip('='))
")
R2=$(curl -s -o /tmp/dns-resp2.bin -w "%{http_code}" "$BASE/dns-query?dns=$B64" \
  -H "Authorization: Bearer $TOKEN")
echo "GET HTTP=$R2 size=$(stat -c%s /tmp/dns-resp2.bin 2>/dev/null || echo 0)"

echo "DONE"
