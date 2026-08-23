#!/bin/bash
# Sidecar for a running pgo_run.sh: twice, kill mockdot for 20s so queries
# exercise the DoH fallback path (mockdoh stays up; master loop only touches
# mockdoq, no conflict).
set -u
cd "$(dirname "$0")"
PY=".venv/bin/python"
for delay in "${@:-600 1200}"; do
  sleep "$delay"
  PID="$(cat run/mockdot.pid 2>/dev/null)" || continue
  kill "$PID" 2>/dev/null || continue
  echo "$(date +%T) killed mockdot for a DoH window"
  sleep 20
  $PY mockdot.py --port 1855 >>run/mockdot.log 2>&1 & echo $! >run/mockdot.pid
  echo "$(date +%T) mockdot back"
done
