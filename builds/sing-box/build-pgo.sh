#!/bin/bash
# sing-box 1.13.19 PGO 二阶（回环 reality 链采 30min CPU profile → 重编）
set -euo pipefail
cd "$(dirname "$0")"
SRC=~/plum/singbox-build/1.13.19
PGO_DIR="$SRC/pgo"
mkdir -p "$PGO_DIR"

echo "1) build instrumented baseline (GOEXPERIMENT=pgo auto needs Go 1.21+)"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go -C "$SRC" build -trimpath -ldflags "-s -w" \
  -tags "with_gvisor,with_quic,with_wireguard,with_clash_api,with_utls" \
  -o /tmp/sing-box.pgo-base ./cmd/sing-box

echo "2) 30min load through the loopback reality chain (singbox-sim.json 127.0.0.1:8443)"
echo "   run: ~/plum/singbox-build/run-pgo-load.sh  (collects CPU profile via pprof endpoint)"
echo "3) go build -pgo=auto  # picks up default.pgo from the run"
echo "   GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go -C $SRC build -pgo=auto -trimpath -ldflags \"-s -w\" -tags \"with_gvisor,with_quic,with_wireguard,with_clash_api,with_utls\" -o builds/sing-box/sing-box.aarch64 ./cmd/sing-box"
