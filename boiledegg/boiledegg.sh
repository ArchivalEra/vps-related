#!/usr/bin/env bash
# boiledegg.sh — argo quick-tunnel manager for CDN-capable sing-box lines (ws/grpc)
#
# Positioning: Cloudflare QUICK tunnels are ephemeral (random URL, can vanish, no
# uptime guarantee) — they are the only CDN variant that needs managing. Proper CDNs
# (CF SaaS / CloudFront / EdgeOne) terminate certs at their edge and need zero
# sing-box changes, so this tool deliberately does not serve them.
#
# What it does, in one pass:
#   reads ONE file  → the standard server config.json (vless-ws/vless-grpc listeners,
#                     TLS or plain origins both fine: plain = --url http://…,
#                     TLS = --url https://… --no-tls-verify)
#   lists the CDN-capable lines and lets you multi-select (comma separated)
#   spawns one detached cloudflared quick tunnel per selected line
#   reuses gen-client.sh on the ORIGINAL server config (single converter, single
#   source of truth), then repoints only the selected lines at their tunnel hosts
#   writes ONE file → the argo client config; nothing else lands on disk
#
# Renewal contract: quick-tunnel URLs die whenever cloudflared restarts. Stop the
# printed PIDs, re-run this script, new URLs flow into a fresh config. No pidfiles,
# no state — the PIDs printed in red ARE the handle (same contract as
# config-delivery.sh).

set -uo pipefail

if [[ $# -eq 0 ]]; then
  echo "try boiledegg.sh --help"
  exit 1
fi

SERVER_CFG=""
ADDR=""            # connect address for lines NOT fronted by a tunnel (direct lines)
LINES_ARG=""
OUTPUT_NAME="cdn-client.json"
OUTPUT_PATH=""
GEN_CLIENT=""      # sibling path override; default resolves next to this script
LOGDIR=""          # --logs DIR: keep cloudflared logs (default /dev/null — zero garbage)
DEBUG="${DEBUG:-0}"

C_GREEN="\033[38;2;144;169;89m"; C_YELLOW="\033[38;2;244;191;117m"
C_RED="\033[38;2;172;65;66m"; C_BLUE="\033[38;2;106;159;181m"; C_RESET="\033[0m"
ok()    { echo -e "${C_GREEN}$*${C_RESET}"; }
warn()  { echo -e "${C_YELLOW}⚠ $*${C_RESET}" >&2; }
err()   { echo -e "${C_RED}✗ $*${C_RESET}" >&2; }
die1()  { err "$@"; exit 1; }
debug() { [[ $DEBUG -eq 1 ]] && echo -e "${C_BLUE}[debug] $*${C_RESET}" >&2; }

print_help() {
  cat <<'HELP'
boiledegg.sh — manage CF quick-tunnel (argo) fronting for ws/grpc lines

Reads the server config.json, lists every vless-ws / vless-grpc listener,
multi-select lines, and starts one detached cloudflared quick tunnel per line.
The client config is produced by your existing gen-client.sh pair (converter
reused, not reimplemented) with ONLY the selected lines repointed at tunnel
hosts — everything else keeps the direct connect address.

Output of a run:
  - N detached cloudflared processes (PIDs printed in red — kill them to stop)
  - exactly one artifact: the argo client config (--outputname)

Renewal: quick tunnels are ephemeral. Kill the red PIDs, run boiledegg again,
new URLs land in a fresh output file. Overwrites by design — the file is a
pure derivative.

Usage:
  boiledegg.sh <server-config.json> --addr DIRECT_HOST [--lines 1,3]
               [--outputname NAME] [--outputpath DIR] [--gen-client PATH] [--debug]

  server.json     sing-box server config (the only input)
  --addr HOST     connect address for the non-tunnelled lines (real IP/domain);
                  selected lines get their tunnel host instead
  --lines N,M     skip the interactive menu (numbers from the listed menu)
  --outputname    default cdn-client.json
  --outputpath    default: this script's own directory
  --gen-client    path to gen-client.sh (default: ../sing-box/scripts/gen-client.sh)
  --logs DIR      keep cloudflared logs in DIR (default: discard — zero garbage on disk)
  --debug         diagnostic output

Proxy note: quick-tunnel REGISTRATION must reach api.trycloudflare.com; behind
GFW run with https_proxy=http://127.0.0.1:2080 (cloudflared honors it) plus
--protocol http2 which this script already passes.
HELP
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help) print_help; exit 0 ;;
    --addr) shift; ADDR="${1:-}" ;;
    --lines) shift; LINES_ARG="${1:-}" ;;
    --outputname) shift; OUTPUT_NAME="${1:-}" ;;
    --outputpath) shift; OUTPUT_PATH="${1:-}" ;;
    --gen-client) shift; GEN_CLIENT="${1:-}" ;;
    --logs) shift; LOGDIR="${1:-}" ;;
    --debug) DEBUG=1 ;;
    -*) die1 "unknown flag: $1 (see --help)" ;;
    *) [[ -z "$SERVER_CFG" ]] || die1 "only one positional input allowed: got $SERVER_CFG and $1"; SERVER_CFG="$1" ;;
  esac
  shift
done

[[ -n "$SERVER_CFG" && -f "$SERVER_CFG" && -r "$SERVER_CFG" ]] || die1 "server config not readable: ${SERVER_CFG:-<none>}"
command -v python3 >/dev/null 2>&1 || die1 "python3 required"
command -v cloudflared >/dev/null 2>&1 || { printf "\033[34mno cf, argo management disabled\033[0m\n"; exit 1; }
[[ -n "$ADDR" ]] || { [[ ! -t 0 ]] && die1 "--addr is required (connect address of the direct/un-fronted lines)"; read -r -p "Direct connect address (for lines NOT behind a tunnel): " ADDR; [[ -n "$ADDR" ]] || die1 "must provide --addr"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_CLIENT="${GEN_CLIENT:-$SCRIPT_DIR/../sing-box/scripts/gen-client.sh}"
[[ -f "$GEN_CLIENT" ]] || die1 "gen-client.sh not found at $GEN_CLIENT (pass --gen-client)"

TMPD="$(mktemp -d)" || die1 "cannot create temp dir"
trap 'rm -rf "$TMPD"' EXIT

# ---------- scan: vless-ws / vless-grpc listeners ----------
python3 - "$SERVER_CFG" "$TMPD/lines.lst" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
rows = []
for i in c.get("inbounds", []):
    if i.get("type") != "vless":
        continue
    ttype = (i.get("transport") or {}).get("type", "")
    if ttype not in ("ws", "grpc"):
        continue
    tls = bool((i.get("tls") or {}).get("enabled"))
    rows.append(f'{i.get("tag","?")}\t{ttype}\t{i.get("listen_port",0)}\t{"tls" if tls else "plain"}')
open(sys.argv[2], "w").write("\n".join(rows))
PY
mapfile -t ROWS < "$TMPD/lines.lst"
[[ ${#ROWS[@]} -ge 1 ]] || die1 "no vless-ws/vless-grpc listeners in $SERVER_CFG — nothing to boil"

echo "CDN-capable lines in $(basename "$SERVER_CFG"):"
i=1
for r in "${ROWS[@]}"; do IFS=$'\t' read -r tag tt port tl <<<"$r"
  printf '  [%d] %-14s %-5s port %-6s (%s origin)\n' "$i" "$tag" "$tt" "$port" "$tl"; i=$((i+1)); done

# ---------- selection ----------
SEL=()
if [[ -n "$LINES_ARG" ]]; then
  IFS=',' read -ra nums <<< "$(echo "$LINES_ARG" | tr -d ' ')"
  for n in "${nums[@]}"; do
    [[ "$n" =~ ^[0-9]+$ && $n -ge 1 && $n -le ${#ROWS[@]} ]] || die1 "bad --lines entry: $n (1-${#ROWS[@]})"
    SEL+=("$((n-1))")
  done
else
  [[ -t 0 ]] || die1 "non-interactive stdin: use --lines 1,N"
  read -r -p "Boil which lines (comma-separated numbers, e.g. 1,2)? " sel
  IFS=',' read -ra nums <<< "$(echo "$sel" | tr -d ' ')"
  for n in "${nums[@]}"; do
    [[ "$n" =~ ^[0-9]+$ && $n -ge 1 && $n -le ${#ROWS[@]} ]] || die1 "bad selection: $n"
    SEL+=("$((n-1))")
  done
fi
[[ ${#SEL[@]} -ge 1 ]] || die1 "nothing selected"

# ---------- start one quick tunnel per selection ----------
declare -A TAG_URL

if [[ -n "$LOGDIR" ]]; then
  mkdir -p "$LOGDIR" 2>/dev/null || die1 "cannot write log dir: $LOGDIR"
fi

PIDS=""
for idx in "${SEL[@]}"; do
  IFS=$'\t' read -r tag tt port tl <<<"${ROWS[$idx]}"
  scheme="http"; extra=()
  [[ "$tl" == "tls" ]] && { scheme="https"; extra=(--no-tls-verify); }
  logf="$TMPD/cfd-$tag.log"
  setsid cloudflared tunnel --url "$scheme://127.0.0.1:$port" --protocol http2 \
    "${extra[@]}" >"$logf" 2>&1 &
  cfd_pid=$!
  url=""
  for _ in $(seq 1 80); do
    url="$(grep -aoE 'https://[a-zA-Z0-9]+(-[a-zA-Z0-9]+)+\.trycloudflare\.com' "$logf" | head -1)"
    [[ -n "$url" ]] && break
    kill -0 "$cfd_pid" 2>/dev/null || break
    sleep 0.4
  done
  [[ -z "$url" ]] && {
    err "no trycloudflare URL for $tag within ~30s — log tail:"
    tail -5 "$logf" >&2; kill "$cfd_pid" 2>/dev/null
    die1 "hint: registration must reach api.trycloudflare.com — try https_proxy=http://127.0.0.1:2080"
  }
  TAG_URL["$tag"]="$url"
  PIDS+=" $cfd_pid"
  ok "[$tag] $url (pid $cfd_pid, origin $scheme://127.0.0.1:$port)"
done

# ---------- reuse gen-client on the original config ----------
SB_OUTPUT="$TMPD/base.json" bash "$GEN_CLIENT" --from-server "$SERVER_CFG" --addr "$ADDR" >/dev/null 2>&1 \
  || { err "gen-client failed:"; SB_OUTPUT="$TMPD/base.json" bash "$GEN_CLIENT" --from-server "$SERVER_CFG" --addr "$ADDR" 2>&1 | tail -8 >&2; die1 "cannot build base client config"; }

# repoint ONLY the selected lines at their tunnel hosts (tag=url pairs)
ARGS_PASSED=()
for idx in "${SEL[@]}"; do
  IFS=$'\t' read -r tag _ <<<"${ROWS[$idx]}"
  ARGS_PASSED+=("$tag=${TAG_URL[$tag]}")
done
python3 - "$TMPD/base.json" "$SERVER_CFG" "$TMPD/final.json" "${ARGS_PASSED[@]}" <<'PY'
import json, sys
base_p, srv_p, out_p = sys.argv[1], sys.argv[2], sys.argv[3]
tag_url = {}
for kv in sys.argv[4:]:
    k, v = kv.split("=", 1)
    tag_url[k] = v
c = json.load(open(base_p))
patched = []
for o in c.get("outbounds", []):
    tg = o.get("tag")
    if tg in tag_url:
        host = tag_url[tg].replace("https://", "")
        o["server"] = host
        o["tls"]["server_name"] = host
        patched.append(tg)
json.dump(c, open(out_p, "w"), indent=1)
# carry ECH CONFIGS comments if the server had them
with open(srv_p, errors="replace") as f:
    tail_lines = [l.rstrip("\n") for l in f if l.startswith("//")]
if tail_lines:
    with open(out_p, "a") as f:
        f.write("\n".join(tail_lines) + "\n")
print("repointed:", ",".join(patched))
PY

[[ -s "$TMPD/final.json" ]] || die1 "post-processing failed"

resolve_out() {
  if [[ -n "$OUTPUT_PATH" ]]; then echo "$OUTPUT_PATH/$OUTPUT_NAME"; else echo "$SCRIPT_DIR/$OUTPUT_NAME"; fi
}
OUT="$(resolve_out)"
mkdir -p "$(dirname "$OUT")" 2>/dev/null || die1 "cannot write dir: $(dirname "$OUT")"
cp "$TMPD/final.json" "$OUT"

ok "argo client config: $OUT (overwrites by design — pure derivative)"
ok "fronted lines repointed: see green list above; everything else stays --addr $ADDR"
printf '\033[31mimportant: to stop sharing kill%s ; to renew URLs just re-run boiledegg.sh\033[0m\n' "$PIDS"
if [[ -n "$LOGDIR" ]]; then
  for idx in "${SEL[@]}"; do IFS=$'\t' read -r tag _ <<<"${ROWS[$idx]}"
    cp "$TMPD/cfd-$tag.log" "$LOGDIR/" 2>/dev/null
  done
  ok "tunnel logs kept in $LOGDIR"
fi
