#!/usr/bin/env bash
# secrets.lib.sh — server credential generation library (sourced by gen-server.sh)
#
# Architecture: credentials are generated fresh on every run and embedded directly
# into the server config.json output. Nothing is persisted — no secrets.env, no state.
# Zero storage, zero garbage: re-run gen-server.sh anytime to rotate everything.
#
# Requires: sing-box (generate uuid / reality-keypair), openssl

# ---------- Output tiers (mirror protocols.lib.sh; debug fully silent unless --debug) ----------
DEBUG="${DEBUG:-0}"
ok()    { echo "$@"; }
warn()  { echo "⚠ $@" >&2; }
err()   { echo "✗ $@" >&2; }
die1()  { err "$@"; exit 1; }
debug() { [[ $DEBUG -eq 1 ]] && echo "[debug] $@" >&2; }

# ---------- Credential generators (stdout only; failures return non-zero) ----------

# UUID v4 (sing-box native, fallback /proc)
gen_uuid() {
  ${SB_BIN:-sing-box} generate uuid 2>/dev/null || cat /proc/sys/kernel/random/uuid
}

# X25519 reality keypair → stdout "PRIV PUB" (URL-safe raw base64, 43 chars each)
gen_reality_keypair() {
  local kp priv pub
  kp="$(${SB_BIN:-sing-box} generate reality-keypair 2>/dev/null)" || return 1
  priv="$(echo "$kp" | sed -n 's/^PrivateKey: //p')"
  pub="$(echo "$kp" | sed -n 's/^PublicKey: //p')"
  [[ -n "$priv" && -n "$pub" ]] || return 1
  echo "$priv $pub"
}

# reality short_id (hex)
gen_short_id() { openssl rand -hex 8; }

# 12-byte hex password (hy2 / anytls)
gen_hex_pass() { openssl rand -hex 12; }

# SS2022 password: 32 raw bytes → standard base64 WITH padding (Go decoder requires len%4==0)
gen_ss_pass() { openssl rand -base64 32 | tr -d '\n'; }
