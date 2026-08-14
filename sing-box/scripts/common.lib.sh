#!/usr/bin/env bash
# common.lib.sh — shared output tiers + debug (single source of truth)
# Sourced by both protocols.lib.sh and secrets.lib.sh; do not re-define these in libs.
DEBUG="${DEBUG:-0}"
ok()    { echo "$@"; }                        # success/result line → stdout
warn()  { echo "⚠ $@" >&2; }                  # warning → stderr
err()   { echo "✗ $@" >&2; }                  # error → stderr
die1()  { err "$@"; exit 1; }                 # error + exit 1 (argument/dependency contract)
die2()  { err "$@"; exit 2; }                 # error + exit 2 (conversion/check contract)
debug() { [[ $DEBUG -eq 1 ]] && echo "[debug] $@" >&2; }   # only with --debug
