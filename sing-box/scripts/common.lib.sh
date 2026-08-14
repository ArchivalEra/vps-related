#!/usr/bin/env bash
# common.lib.sh — shared output tiers + debug (single source of truth)
# Sourced by both protocols.lib.sh and secrets.lib.sh; do not re-define these in libs.
#
# Colors: afterglow theme (base16 afterglow) via truecolor ANSI. Auto-disabled when
# stdout is not a TTY or NO_COLOR is set — pipelines/logs stay clean. Errors and
# warnings go to stderr, colored; ok/debug colored on stdout/stderr respectively.
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
