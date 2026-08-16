#!/usr/bin/env bash
# secrets.lib.sh — server credential generation library (sourced by gen-server.sh)
#
# Architecture: credentials are generated fresh on every run and embedded directly
# into the server config.json output. Nothing is persisted — no secrets.env, no state.
# Zero storage, zero garbage: re-run gen-server.sh anytime to rotate everything.
#
# Requires: sing-box (generate uuid / reality-keypair), openssl

# Output tiers (ok/warn/err/die1/die2/debug + afterglow colors) are defined inline —
# deliberately duplicated from protocols.lib.sh so each domain can evolve independently
# (server/client behavior diverges often). Keep in sync with protocols.lib.sh when touching.
DEBUG="${DEBUG:-0}"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_GREEN="\033[38;2;144;169;89m"    # afterglow green  #90a959
  C_YELLOW="\033[38;2;244;191;117m"  # afterglow yellow #f4bf75
  C_RED="\033[38;2;172;65;66m"       # afterglow red    #ac4142
  C_BLUE="\033[38;2;106;159;181m"    # afterglow blue   #6a9fb5
  C_RESET="\033[0m"
else
  C_GREEN=""; C_YELLOW=""; C_RED=""; C_BLUE=""; C_RESET=""
fi

ok()    { echo -e "${C_GREEN}$*${C_RESET}"; }                          # success/result → stdout (green)
warn()  { echo -e "${C_YELLOW}⚠ $*${C_RESET}" >&2; }                   # warning → stderr (yellow)
err()   { echo -e "${C_RED}✗ $*${C_RESET}" >&2; }                      # error → stderr (red)
die1()  { err "$@"; exit 1; }                                          # error + exit 1 (argument/dependency)
die2()  { err "$@"; exit 2; }                                          # error + exit 2 (conversion/check)
debug() { [[ $DEBUG -eq 1 ]] && echo -e "${C_BLUE}[debug] $*${C_RESET}" >&2; }   # only with --debug

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

# Output path resolution — SB_OUTPUT env (full path) > outputpath+outputname >
# outputname > outputpath > default $SCRIPT_DIR/$OUTPUT_NAME_DEFAULT.
# Reads the script's OUTPUT_NAME / OUTPUT_PATH / OUTPUT_NAME_DEFAULT globals.
resolve_output_path() {
  if [[ -z "${SB_OUTPUT:-}" ]]; then
    if [[ -n "$OUTPUT_NAME" && -n "$OUTPUT_PATH" ]]; then
      SB_OUTPUT="$OUTPUT_PATH/$OUTPUT_NAME"
    elif [[ -n "$OUTPUT_NAME" ]]; then
      SB_OUTPUT="$SCRIPT_DIR/$OUTPUT_NAME"
    elif [[ -n "$OUTPUT_PATH" ]]; then
      SB_OUTPUT="$OUTPUT_PATH/$OUTPUT_NAME_DEFAULT"
    else
      SB_OUTPUT="$SCRIPT_DIR/$OUTPUT_NAME_DEFAULT"
    fi
  fi
}
