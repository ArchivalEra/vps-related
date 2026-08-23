#!/bin/bash
# magdns build pipeline (run from this directory or anywhere).
#   ./build.sh native            - host debug build (dev loop)
#   ./build.sh cross             - aarch64 cortex-a53 release (ThinLTO)
#   ./build.sh pgo-instrument    - aarch64 release + profile-generate
#   ./build.sh pgo-collect       - 30min qemu workload, writes pgo-data/
#   ./build.sh pgo-merge         - profraw -> pgo-data/merged.profdata
#   ./build.sh pgo-final         - aarch64 release with -Cprofile-use
#   ./build.sh test-native | test-qemu  - run stage suite (SUT = native/qemu)
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"
CROSS="${CROSS:-/home/archivalera/plum/magdns-cross/aarch64-clang}"
JOBS="${JOBS:-4}"

cross_env() {
  nice -n19 env \
    CARGO_BUILD_JOBS="$JOBS" \
    CARGO_TARGET_DIR="$1" \
    CC_aarch64_unknown_linux_gnu="$CROSS" \
    CXX_aarch64_unknown_linux_gnu="$CROSS" \
    AR_aarch64_unknown_linux_gnu=/usr/bin/llvm-ar \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$CROSS" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="$2" \
    cargo build --release --target aarch64-unknown-linux-gnu
}

case "${1:-}" in
  native)
    nice -n19 env CARGO_BUILD_JOBS="$JOBS" cargo build
    ;;
  cross)
    cross_env "$ROOT/target-a64" "-C target-cpu=cortex-a53"
    ;;
  pgo-instrument)
    mkdir -p pgo-data
    cross_env "$ROOT/target-a64-pgo" \
      "-C target-cpu=cortex-a53 -C profile-generate=$ROOT/pgo-data"
    ;;
  pgo-collect)
    (cd stage && ./pgo_run.sh)
    ;;
  pgo-merge)
    PROFDATA="$(ls -d ~/.rustup/toolchains/stable-*/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata | head -1)"
    "$PROFDATA" merge -output="$ROOT/pgo-data/merged.profdata" "$ROOT"/pgo-data/*.profraw
    ls -la "$ROOT/pgo-data/merged.profdata"
    ;;
  pgo-final)
    cross_env "$ROOT/target-a64-final" \
      "-C target-cpu=cortex-a53 -C profile-use=$ROOT/pgo-data/merged.profdata"
    ;;
  test-native)
    (cd stage && SUT_PREFIX="" SUT_BIN="$ROOT/target/debug/magdns" ./run_tests.sh)
    ;;
  test-qemu)
    (cd stage && SUT_PREFIX="qemu-aarch64 -L /usr/aarch64-linux-gnu" \
      SUT_BIN="$ROOT/target-a64/aarch64-unknown-linux-gnu/release/magdns" ./run_tests.sh)
    ;;
  *)
    grep '^#' "$0" | sed 's/^# \{0,2\}//'
    exit 1
    ;;
esac
