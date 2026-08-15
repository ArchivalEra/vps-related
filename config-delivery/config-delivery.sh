#!/usr/bin/env bash
# config-delivery.sh — one-time file delivery over dufs (thin wrapper, zero deps)
#
# dufs (https://github.com/sigoden/dufs) does the heavy lifting — static file
# serving, native TLS, streaming — as a single static musl binary (x86_64 + arm64).
# We wrap it instead of writing our own server because dufs already owns all the
# hard parts; the wrapper only adds the one-time semantics dufs lacks: a random
# key URL that auto-destructs after a TTL.
#
# Key decisions, and why:
#   - Random 8-char key URL: the key IS the secret. A path without it is a 404 and
#     the directory listing is hidden, so the link is effectively private and
#     one-time without any auth setup.
#   - TTL auto-expiry: after N seconds the server process is killed and the temp
#     dir removed, so the delivered file does not linger on the machine.
#   - Port pre-check via bash /dev/tcp: pure-bash (no nc dependency) and loopback
#     only — it checks availability, it never probes anything external.
#   - --host is user-supplied only, never auto-probed: the script cannot know which
#     host/IP the client can actually reach (public IP, NAT, DNS, interfaces). The
#     operator knows; we just print the link with the host they give.
#   - TLS three-state: real cert HTTPS when --cert + --key are both readable; warning
#     + fresh self-signed HTTPS fallback when only one is given or one is unreadable;
#     plain HTTP (with a secrets-in-clear warning) when neither is given.
#   - --argo quick tunnel: cloudflared owns the public URL + cert (public CA, so
#     browsers show zero warnings) — no domain or open inbound port needed. The
#     local dufs backend then stays plain HTTP on a random loopback port.
#
# Usage: config-delivery.sh [serve] <file> [--port N] [--ttl SEC] [--host HOST [--v4|--v6]]
#                           [--cert FILE] [--key FILE] [--argo]   (details: --help)
# Env: DUFS_BIN (path to dufs binary; default: dufs on PATH)

set -uo pipefail

# No arguments at all → point at --help instead of failing later with a mystery.
if [[ $# -eq 0 ]]; then
  echo "try config-delivery.sh --help"
  exit 1
fi

PORT=443
TTL=600
HOST=""
FAMILY=""          # "" = auto (IPv4 first), "v4" = force IPv4, "v6" = force IPv6
CERT=""
KEY=""
ARGO=0
FILE=""

print_help() {
  cat <<'HELP'
##help##
  --port N        listen port (default 443, 1-65535, <1024 needs root; ignored in
                  --argo mode, where the backend binds a random loopback port)
  --ttl SEC       auto-delete the file after N seconds (default 600, >= 1)
  --host NAME     host in the link — an IP literal (v6 bracketed automatically), or a
                  domain kept as-is (dual-stack: each client resolves it with its own
                  DNS). never auto-probed, user-supplied only. disabled in --argo mode.
  --v4            with --host DOMAIN: force-resolve to an IPv4 for an IP link
                  (errors if no IPv4). mutually exclusive with --v6. disabled in --argo.
  --v6            with --host DOMAIN: force-resolve to an IPv6 for an IP link
                  (errors if no IPv6). mutually exclusive with --v4. disabled in --argo.
  --cert FILE     PEM certificate. three-state TLS: readable --cert + --key = real cert
                  HTTPS; only one given (or unreadable) = warning + self-signed HTTPS
                  fallback (clients use -k); neither = plain HTTP, secrets travel in
                  clear. disabled in --argo mode.
  --key FILE      PEM private key; pairs with --cert (see --cert for the three states)
  --argo          deliver via a cloudflared quick tunnel: public
                  https://<rand>.trycloudflare.com URL, public-CA cert (browser-trusted,
                  zero warnings), no domain or open inbound port needed. dufs backend
                  runs plain HTTP on a random loopback port. disables
                  --host/--v4/--v6/--cert/--key (the tunnel owns public URL + cert).
  FILE            file to deliver (positional, e.g. serve ./config-client.json)
##help##
HELP
}

# Random ephemeral-loopback port that is free right now — same /dev/tcp availability
# check the port pre-check below uses. Only used in --argo mode.
pick_random_port() {
  local p
  while :; do
    p=$((40000 + RANDOM % 25536))
    if ! (echo > /dev/tcp/127.0.0.1/"$p") 2>/dev/null; then
      echo "$p"
      return 0
    fi
  done
}

# dufs is the only runtime this script needs (besides cloudflared in --argo mode);
# if it is missing, print the full install guide instead of a one-line dead end.
# Version note: v0.46.0 below is the pinned default — swap in the latest release
# number from the dufs releases page.
dufs_install_guide() {
  echo "error: dufs binary not found (looked for: $DUFS_BIN)"
  case "$(uname -m)" in
    x86_64)  DUF_TARGET="x86_64-unknown-linux-musl" ;;
    aarch64) DUF_TARGET="aarch64-unknown-linux-musl" ;;
    *)
      echo "error: unsupported architecture: $(uname -m)"
      echo "dufs publishes prebuilt musl binaries for x86_64 and aarch64 only;"
      echo "build from source (cargo install dufs) or run this on a supported machine."
      exit 1
      ;;
  esac
  echo "install dufs for your arch: $(uname -m) -> $DUF_TARGET"
  echo
  echo "  1. Download (v0.46.0 — replace with the latest from"
  echo "     https://github.com/sigoden/dufs/releases if you prefer):"
  echo "     curl -fL -o /tmp/dufs.tar.gz https://github.com/sigoden/dufs/releases/download/v0.46.0/dufs-v0.46.0-$DUF_TARGET.tar.gz"
  echo "  2. Extract the dufs binary into /usr/local/bin:"
  echo "     tar -xzf /tmp/dufs.tar.gz -C /usr/local/bin"
  echo "  3. Verify:"
  echo "     dufs --version"
  echo "  4. Re-run this script."
  exit 1
}

args=("$@")
i=0
while [[ $i -lt ${#args[@]} ]]; do
  a="${args[$i]}"
  case "$a" in
    --help) print_help; exit 0 ;;
    --port) PORT="${args[$((i+1))]}"; i=$((i+2)) ;;
    --ttl)  TTL="${args[$((i+1))]}";  i=$((i+2)) ;;
    --host) HOST="${args[$((i+1))]}"; i=$((i+2)) ;;
    --v4) [[ -n "$FAMILY" && "$FAMILY" != "v4" ]] && { echo "error: --v4 and --v6 are mutually exclusive — pick one"; exit 1; }; FAMILY="v4"; i=$((i+1)) ;;
    --v6) [[ -n "$FAMILY" && "$FAMILY" != "v6" ]] && { echo "error: --v4 and --v6 are mutually exclusive — pick one"; exit 1; }; FAMILY="v6"; i=$((i+1)) ;;
    --cert) CERT="${args[$((i+1))]}"; i=$((i+2)) ;;
    --key)  KEY="${args[$((i+1))]}";  i=$((i+2)) ;;
    --argo) ARGO=1; i=$((i+1)) ;;
    *)      FILE="$a"; i=$((i+1)) ;;
  esac
done

# ---------- --argo mode: guards first ----------
# The quick tunnel owns the public URL + cert, so flags that steer a direct link or
# its TLS are meaningless here — refuse them up front instead of silently ignoring.
if [[ $ARGO -eq 1 ]]; then
  if [[ -n "$HOST" ]]; then
    echo "error: flag --host is disabled in --argo mode (quick tunnel owns public URL + cert)"
    exit 1
  fi
  if [[ -n "$FAMILY" ]]; then
    echo "error: flag --$FAMILY is disabled in --argo mode (quick tunnel owns public URL + cert)"
    exit 1
  fi
  if [[ -n "$CERT" ]]; then
    echo "error: flag --cert is disabled in --argo mode (quick tunnel owns public URL + cert)"
    exit 1
  fi
  if [[ -n "$KEY" ]]; then
    echo "error: flag --key is disabled in --argo mode (quick tunnel owns public URL + cert)"
    exit 1
  fi
  # cloudflared is the argo runtime; missing → blue notice + exit (no install wizard).
  if ! command -v cloudflared >/dev/null 2>&1; then
    printf '\033[34mno cf, argo link generation disabled\033[0m\n'
    exit 1
  fi
  # --port is accepted but unused here: the backend binds a random free loopback port.
  PORT="$(pick_random_port)"
fi

DUFS_BIN="${DUFS_BIN:-dufs}"
if ! command -v "$DUFS_BIN" >/dev/null 2>&1; then
  dufs_install_guide
fi

# ---------- Input guards ----------
[[ -n "$FILE" && -f "$FILE" && -r "$FILE" ]] || { echo "error: file not readable: ${FILE:-<none>}"; exit 1; }
[[ -s "$FILE" ]] || echo "warning: file is empty: $FILE"
[[ "$TTL" =~ ^[0-9]+$ && "$TTL" -ge 1 ]] || { echo "error: --ttl must be an integer >= 1 (got: ${TTL:-<none>})"; exit 1; }
[[ "$TTL" -gt 3600 ]] && echo "warning: TTL ${TTL}s is long — the link stays live until then"
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 1 && "$PORT" -le 65535 ]] || { echo "error: --port must be an integer 1-65535 (got: ${PORT:-<none>})"; exit 1; }
[[ "$PORT" -lt 1024 ]] && echo "note: port $PORT < 1024 — dufs may need root to bind"
# TLS three-state — --cert/--key are no longer required:
#   both readable                  -> real cert HTTPS (clients trust it directly)
#   only one given / unreadable    -> warning + fresh self-signed HTTPS (clients -k)
#   neither                        -> plain HTTP (dufs runs without TLS args)
TLS_MODE="http"
if [[ -n "$CERT" || -n "$KEY" ]]; then
  if [[ -n "$CERT" && -n "$KEY" && -r "$CERT" && -r "$KEY" ]]; then
    TLS_MODE="cert"
  else
    echo "warning: --cert/--key unusable (missing or unreadable pair) — falling back to a self-signed HTTPS cert; clients must use curl -k"
    TLS_MODE="self-signed"
    CERT=""; KEY=""
  fi
fi
# --v4 and --v6 are family selectors; the parse loop above already rejects giving
# both (mutual exclusion enforced at parse time).
# --host: an IP literal is used as-is (v6 gets [brackets]). A DOMAIN stays a domain
# by default — the link is dual-stack, each client resolves it with its own DNS
# (a v4-only device gets the A record, a v6-only device the AAAA). Only when the
# caller EXPLICITLY wants an IP link (no-DNS client, avoid a sniffable SNI) does
# --v4/--v6 force-resolve the domain to that family. Never probed — user-supplied.
if [[ -n "$HOST" ]]; then
  if [[ "$HOST" == *:* ]]; then
    # already an IPv6 literal
    HOST="[$HOST]"
  elif [[ "$HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    : # already an IPv4 literal
  elif [[ -n "$FAMILY" ]]; then
    # explicit family requested → resolve the domain to an IP
    if [[ "$FAMILY" == "v6" ]]; then
      HOST="$(timeout 5 getent ahosts "$HOST" 2>/dev/null | awk '!seen[$1]++ { if ($1 ~ /:/) print $1 }' | head -1)"
      [[ -n "$HOST" ]] || { echo "error: cannot resolve an IPv6 for $HOST (getent ahosts)"; exit 1; }
      HOST="[$HOST]"
    else
      HOST="$(timeout 5 getent ahosts "$HOST" 2>/dev/null | awk '!seen[$1]++ { if ($1 !~ /:/) print $1 }' | head -1)"
      [[ -n "$HOST" ]] || { echo "error: cannot resolve an IPv4 for $HOST (getent ahosts)"; exit 1; }
    fi
  fi
  # a domain with no family flag stays a domain (dual-stack link)
  echo "link host: $HOST"
fi

# Port pre-check via bash /dev/tcp — pure-bash (no nc), loopback only, so it checks
# availability without probing anything on the network.
if (echo > /dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
  echo "error: port $PORT already in use — pick another with --port (or free the port)"
  exit 1
fi

# Random 8-char key (a-zA-Z0-9_-) — the key IS the secret, see header. Using the key
# as the filename means the URL path itself carries the access control.
KEYSTR=""
while [[ ${#KEYSTR} -lt 8 ]]; do
  KEYSTR+="$(printf '%s' "$(openssl rand -base64 9 | tr -dc 'A-Za-z0-9_-')")"
done
KEYSTR="${KEYSTR:0:8}"

# Serve from a throwaway temp dir so nothing is persisted on disk past the TTL
# window — the detached TTL steward below removes it. (The early EXIT trap was
# replaced by `trap - EXIT` so the script can return without killing dufs.)
SRV_DIR="$(mktemp -d)"
cp "$FILE" "$SRV_DIR/$KEYSTR"

# TLS material: real cert from --cert/--key (state "cert") is used as-is; the
# self-signed fallback (state "self-signed") mints a fresh ECDSA cert here; state
# "http" runs dufs with no TLS args at all.
if [[ "$TLS_MODE" == "self-signed" ]]; then
  CERT="$SRV_DIR/cert.pem"; KEY="$SRV_DIR/key.pem"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$KEY" -out "$CERT" -days 1 -subj "/CN=config-delivery" >/dev/null 2>&1
fi

# dufs is detached (setsid) so the script can exit without taking the terminal
# down with it — the TTL steward below owns killing dufs + cleaning the temp dir.
# TLS states "http" (plaintext — also the --argo backend) run dufs without any
# --tls-cert/--tls-key; in --argo mode the backend additionally binds loopback only.
if [[ "$TLS_MODE" == "http" && $ARGO -eq 1 ]]; then
  DUF_CMD=( "$DUFS_BIN" "$SRV_DIR" -A --port "$PORT" --bind 127.0.0.1 --hidden '*' )
elif [[ "$TLS_MODE" == "http" ]]; then
  DUF_CMD=( "$DUFS_BIN" "$SRV_DIR" -A --port "$PORT" --hidden '*' )
else
  DUF_CMD=( "$DUFS_BIN" "$SRV_DIR" -A --tls-cert "$CERT" --tls-key "$KEY" --port "$PORT" --hidden '*' )
fi
setsid "${DUF_CMD[@]}" >"$SRV_DIR/dufs.log" 2>&1 &
DUFS_PID=$!
# Startup self-check: the process being alive is not enough, and neither is the
# port answering — the LINK must actually serve. curl downloads the key URL
# locally (self-signed cert → -k, loopback) with a hard timeout so a stuck
# handshake cannot hang the script silently. Only on 200 is the link printed.
# The scheme is parameterized: https + -k for cert/self-signed, http for plain.
if [[ "$TLS_MODE" == "http" ]]; then
  SELF_CURL=( curl --max-time 2 -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/$KEYSTR" )
else
  SELF_CURL=( curl -k --max-time 2 -o /dev/null -w "%{http_code}" "https://127.0.0.1:$PORT/$KEYSTR" )
fi
SELF_OK=0
for _ in 1 2 3 4 5; do
  if "${SELF_CURL[@]}" 2>/dev/null | grep -q "^200"; then
    SELF_OK=1; break
  fi
  sleep 0.3
done
if [[ $SELF_OK -eq 0 ]] || ! kill -0 "$DUFS_PID" 2>/dev/null; then
  echo "error: dufs failed to serve the link on port $PORT (self-check):" >&2
  cat "$SRV_DIR/dufs.log" >&2
  kill "$DUFS_PID" 2>/dev/null
  rm -rf "$SRV_DIR"
  exit 1
fi

# ---------- --argo mode: cloudflared quick tunnel ----------
# dufs is up (plain HTTP, loopback); now hand the public side to cloudflared. It is
# detached with setsid so it outlives this script; the TTL steward kills it.
CFD_PID=""
PUB_URL=""
if [[ $ARGO -eq 1 ]]; then
  setsid cloudflared tunnel --url "http://127.0.0.1:$PORT" >"$SRV_DIR/cfd.log" 2>&1 &
  CFD_PID=$!
  # Poll the log for the public trycloudflare URL — up to ~20s (0.3s per poll).
  # Break early if cloudflared dies before announcing one.
  for _ in {1..66}; do
    PUB_URL="$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$SRV_DIR/cfd.log" 2>/dev/null | head -1)"
    [[ -n "$PUB_URL" ]] && break
    ! kill -0 "$CFD_PID" 2>/dev/null && break
    sleep 0.3
  done
  if [[ -z "$PUB_URL" ]]; then
    echo "error: no trycloudflare URL within ~20s — cloudflared log tail:" >&2
    tail -20 "$SRV_DIR/cfd.log" >&2
    kill "$DUFS_PID" "$CFD_PID" 2>/dev/null
    rm -rf "$SRV_DIR"
    exit 1
  fi
fi

# Print the link — argo prints the public tunnel URL (HTTPS via public CA, so no -k);
# direct mode prints the --host link with the scheme the TLS state dictates.
if [[ $ARGO -eq 1 ]]; then
  echo "one-time download link: $PUB_URL/$KEYSTR"
  echo "file auto-deletes after ${TTL}s; tunnel cert is a public CA (browser-trusted, zero warnings); no domain or open inbound port needed"
  echo "client: curl -OJ $PUB_URL/$KEYSTR"
else
  SH="${HOST:-localhost}"
  if [[ "$TLS_MODE" == "http" ]]; then
    echo "one-time download link: http://$SH:$PORT/$KEYSTR"
    echo "warning: plain HTTP — the config contains secrets; anyone on the network path can read it"
    echo "file auto-deletes after ${TTL}s; dir listing hidden; host is user-supplied (never auto-probed)"
    echo "client: curl -OJ http://$SH:$PORT/$KEYSTR"
  else
    echo "one-time download link: https://$SH:$PORT/$KEYSTR"
    echo "file auto-deletes after ${TTL}s; dir listing hidden; host is user-supplied (never auto-probed)"
    echo "client: curl -kOJ https://$SH:$PORT/$KEYSTR"
  fi
fi
# TTL steward: sleep the window, then kill the served processes and remove the temp
# dir (the file, the throwaway cert, the logs) — this is what makes the link
# one-time and the delivery zero-residue. The process list is parameterized: dufs
# always, plus cloudflared in --argo mode. Runs detached so the script can exit and
# free the terminal.
trap - EXIT
PROCS=( "$DUFS_PID" )
[[ $ARGO -eq 1 ]] && PROCS+=( "$CFD_PID" )
( sleep "$TTL"; kill "${PROCS[@]}" 2>/dev/null; rm -rf "$SRV_DIR" ) &
disown 2>/dev/null || true
exit 0
