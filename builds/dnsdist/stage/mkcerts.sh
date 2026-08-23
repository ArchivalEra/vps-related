#!/bin/bash
# Stage CA + leaf certs for mock upstreams and the SUT. Idempotent.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs
if [ -f certs/ca.pem ] && [ -f certs/upstream.pem ] && [ -f certs/sut.pem ]; then
  echo "stage certs already exist, skipping"
  exit 0
fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout certs/ca.key -out certs/ca.pem -days 3650 -nodes \
  -subj "/CN=stage-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

make_leaf() {
  local name="$1" cn="$2" san="$3"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "certs/${name}.key" -out "certs/${name}.csr" -nodes \
    -subj "/CN=${cn}" 2>/dev/null
  openssl x509 -req -in "certs/${name}.csr" \
    -CA certs/ca.pem -CAkey certs/ca.key -CAcreateserial \
    -out "certs/${name}.pem" -days 3650 2>/dev/null \
    -extfile <(printf "subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyAgreement\nextendedKeyUsage=serverAuth\n" "$san")
  rm -f "certs/${name}.csr"
}

make_leaf upstream stage.upstream.test "DNS:stage.upstream.test,IP:127.0.0.1,IP:::1"
make_leaf sut stage.sut.test "DNS:stage.sut.test,IP:127.0.0.1,IP:::1"
echo "stage certs ready:"
ls -l certs/
