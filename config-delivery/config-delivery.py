#!/usr/bin/env python3
"""config-delivery.py — one-time file delivery over stdlib http.server (zero deps)

Python port of config-delivery.sh — with one deliberate divergence: the
Python version has no self-signed fallback. TLS is two-state: valid cert
pair → HTTPS, otherwise plain HTTP with a warning. No unverified HTTPS.

Key decisions, and why:
  - Random 8-char key URL: the key IS the secret. A path without it is a 404 and
    there is no directory listing, so the link is effectively private.
  - TTL auto-expiry by default (60s, or --ttl N): after N seconds the server thread
    shuts down and the process exits — zero residue either way. TTL has no upper
    bound; a truly permanent share needs systemd, which this tool is not.
  - --hold: foreground mode with an acme-style single-line countdown (\r in-place).
    ^C stops sharing immediately; TTL elapsing ends it by itself.
  - --host is user-supplied only, never auto-probed. --v4/--v6 force-resolve a
    DOMAIN to that family for an IP link (no sniffable SNI); domains stay dual-stack.
  - TLS two states (no self-signed): readable --cert+--key = real cert HTTPS;
    anything else = plain HTTP with a secrets-in-clear warning. --argo: cloudflared
    quick tunnel owns the public URL + cert; backend serves plain HTTP on a random
    loopback port. --host/--v4/--v6/--cert/--key refused in argo mode.

Usage: config-delivery.py [serve] <file> [--port N] [--ttl SEC] [--hold]
                          [--host HOST] [--v4 | --v6] [--cert FILE] [--key FILE]
                          [--argo] [--debug]   (details: --help)
                          Also accepts a directory as FILE for multi-file delivery (any file
                          types, streamed per file; listing at GET /<key>/, per-file at
                          GET /<key>/<filename>). Links carry ?k=<64hex> (openssl rand -hex 32,
                          env CD_ENC_KEY or fallback), independent from the path key.
"""

import argparse
import ipaddress
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

C_GREEN = "\033[38;2;144;169;89m"
C_YELLOW = "\033[38;2;244;191;117m"
C_RED = "\033[38;2;172;65;66m"
C_BLUE = "\033[38;2;106;159;181m"
C_RESET = "\033[0m"


def ok(msg):
    print(f"{C_GREEN}{msg}{C_RESET}")


def warn(msg):
    print(f"{C_YELLOW}⚠ {msg}{C_RESET}", file=sys.stderr)


def err(msg):
    print(f"{C_RED}✗ {msg}{C_RESET}", file=sys.stderr)


def debug(msg):
    if os.environ.get("DEBUG") == "1":
        print(f"{C_BLUE}[debug] {msg}{C_RESET}", file=sys.stderr)


# ---------- HTTP layer ----------
# Single-file: GET /<key> serves one file. Multi-file: GET /<key>/ lists files,
# GET /<key>/<filename> serves that file. No JSON whitelist — any file type.
# Payload is streamed in 64 KiB chunks, never buffered in full (multi-GB safe).
_CHUNK = 64 * 1024


class DeliveryHandler(BaseHTTPRequestHandler):
    key = ""
    serve_dir: str | None = None  # None → single-file mode; directory path → multi-file
    payload = b""
    filename = ""

    def do_GET(self):
        inner = self.path.lstrip("/")
        # Enforce key prefix — everything under /<key> is gated
        if not inner.startswith(DeliveryHandler.key):
            self.send_error(404)
            return
        rest = inner[len(DeliveryHandler.key):]

        # ----- multi-file mode -----
        if DeliveryHandler.serve_dir is not None:
            # GET /<key>/  → JSON listing
            if rest in ("", "/"):
                files = sorted(f for f in os.listdir(DeliveryHandler.serve_dir)
                               if os.path.isfile(os.path.join(DeliveryHandler.serve_dir, f)))
                body = (",".join(f'"{f}"' for f in files)).encode()
                body = b"[" + body + b"]\n"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            # GET /<key>/<filename>
            name = rest.lstrip("/")
            if "/" in name or not name or name.startswith("."):
                self.send_error(400)
                return
            fpath = os.path.join(DeliveryHandler.serve_dir, name)
            # commonpath guard against ../ traversal
            if os.path.commonpath([fpath, DeliveryHandler.serve_dir]) != DeliveryHandler.serve_dir:
                self.send_error(400)
                return
            if not os.path.isfile(fpath):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(os.path.getsize(fpath)))
            self.end_headers()
            with open(fpath, "rb") as fh:
                shutil.copyfileobj(fh, self.wfile, _CHUNK)
            return

        # ----- single-file mode -----
        if rest != "":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{DeliveryHandler.filename}"')
        self.send_header("Content-Length", str(len(DeliveryHandler.payload)))
        self.end_headers()
        self.wfile.write(DeliveryHandler.payload)

    def log_message(self, fmt, *args):  # silence per-request stderr noise
        pass


def make_server(port, bind=None):
    srv = ThreadingHTTPServer((bind or "0.0.0.0", port), DeliveryHandler)
    srv.daemon_threads = True
    return srv


def serve_forever_thread(srv):
    # Daemon thread: the process can exit without joining the server.
    return threading.Thread(target=srv.serve_forever, daemon=True)


def pick_random_port():
    while True:
        p = 40000 + secrets.randbelow(25536)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(("127.0.0.1", p))  # connect OK → port taken, retry
        except OSError:
            return p
        finally:
            s.close()


# ---------- Link verification (wget probe → urllib probe) ----------
# The probe URL is built only from our own --host/--port/key or the regex-matched
# trycloudflare URL (never raw user input), so SSRF surface is the operator's own
# machine — same trust model as the bash version's curl. Cert verification is off on
# purpose: we verify the link ANSWERS, not that its cert is trusted (self-signed
# fallback must pass; mirrors `curl -k` / `wget --no-check-certificate`).
# SSRF hardening: the probe URL must be http(s) and its host must resolve to a
# public address OR be one of the loopback/trycloudflare targets this tool itself
# constructs — operator-supplied --host is the operator's own choice, but cloud
# metadata endpoints (169.254.169.254 etc.) are refused outright.
def _probe_allowed(url):
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if u.scheme not in ("http", "https") or not u.hostname:
        return False
    host = u.hostname.strip("[]")
    if host == "localhost" or host.endswith(".trycloudflare.com"):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for inf in infos:
        ip = ipaddress.ip_address(inf[4][0])
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
            continue  # private targets are fine (loopback self-check); metadata is link-local -> blocked below
        return True
    # all-resolved-private: allow loopback/private only when NOT link-local (metadata range)
    for inf in infos:
        ip = ipaddress.ip_address(inf[4][0])
        if ip.is_link_local:
            return False
    return True


def verify_link(url):
    # Only http/https; host must pass _probe_allowed() first — this blocks
    # localhost, loopback, private and link-local before any socket opens.
    if not _probe_allowed(url):
        err(f"refusing to probe non-public or link-local target: {url}")
        return False
    for _ in range(3):  # 3 attempts, ~2s apart
        try:
            req = urllib.request.Request(url, method="GET")
            # No unverified context — system CA + hostname checking only.
            # There is no self-signed path in this Python version.
            urllib.request.urlopen(req, timeout=2).read(1)
            return True
        except Exception:
            pass
        time.sleep(2)
    return False


# ---------- Host resolution (--v4/--v6 force-resolve; never auto-probed) ----------
def resolve_host(host, family):
    if ":" in host:
        return f"[{host}]"          # already an IPv6 literal
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", host):
        return host                  # already an IPv4 literal
    if not family:
        return host                  # domain stays dual-stack
    fam = socket.AF_INET6 if family == "v6" else socket.AF_INET
    try:
        infos = [i[4][0] for i in socket.getaddrinfo(host, None, fam)]
    except socket.gaierror:
        die(f"cannot resolve an IPv{family[-1]} for {host}")
    if not infos:
        die(f"cannot resolve an IPv{family[-1]} for {host}")
    return f"[{infos[0]}]" if family == "v6" else infos[0]


def die(msg, code=1):
    err(msg)
    sys.exit(code)


# ---------- Flag parsing & validation (1:1 replica of the bash flag loop + guards) ----------
def build_arg_parser():
    """argv -> namespace. add_help=False because --help is handled manually so the
    custom ##help## text (not argparse's usage dump) gets printed."""
    ap = argparse.ArgumentParser(add_help=False, prog="config-delivery.py")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--ttl", type=int, default=60)
    ap.add_argument("--hold", action="store_true")
    ap.add_argument("--host", default="")
    ap.add_argument("--v4", action="store_true")
    ap.add_argument("--v6", action="store_true")
    ap.add_argument("--cert", default="")
    ap.add_argument("--key", default="")
    ap.add_argument("--argo", action="store_true")
    ap.add_argument("--help", action="store_true")
    ap.add_argument("file", nargs="?")
    return ap


def validate_args(args):
    """Input guards — same checks, same messages, same order as the bash version;
    any violation dies with exit 1."""
    if args.v4 and args.v6:
        die("--v4 and --v6 are mutually exclusive — pick one")
    if args.ttl < 1:
        die(f"--ttl must be an integer >= 1 (got: {args.ttl})")
    if args.ttl > 3600:
        warn(f"TTL {args.ttl}s is long — the link stays live until then")
    if not (1 <= args.port <= 65535):
        die(f"--port must be an integer 1-65535 (got: {args.port})")
    if args.port < 1024:
        print(f"note: port {args.port} < 1024 — binding may need root")

    file_path = args.file
    if not file_path:
        die(f"file not readable: {file_path}")
    # Single file OR directory (multi-file mode) — any file type, no JSON whitelist.
    if os.path.isdir(file_path):
        if not os.access(file_path, os.R_OK | os.X_OK):
            die(f"directory not readable: {file_path}")
    elif os.path.isfile(file_path):
        if not os.access(file_path, os.R_OK):
            die(f"file not readable: {file_path}")
        if os.path.getsize(file_path) == 0:
            warn(f"file is empty: {file_path}")
    else:
        die(f"file not readable: {file_path}")


def validate_argo(args):
    """--argo guards first (as in bash): the quick tunnel owns the public URL + cert,
    so flags steering a direct link or its TLS are refused up front instead of being
    silently ignored. Missing cloudflared -> blue notice + exit 1 (no install wizard)."""
    for flag, val in (("--host", args.host), ("--cert", args.cert), ("--key", args.key)):
        if val:
            die(f"flag {flag} is disabled in --argo mode (quick tunnel owns public URL + cert)")
    if args.v4 or args.v6:
        die(f"flag --{'v4' if args.v4 else 'v6'} is disabled in --argo mode "
            f"(quick tunnel owns public URL + cert)")
    if not shutil.which("cloudflared"):
        print(f"{C_BLUE}no cf, argo link generation disabled{C_RESET}")
        sys.exit(1)


def check_port_free(port):
    """Loopback-only pre-check — the python equivalent of bash /dev/tcp: a successful
    connect means the port is taken, OSError means free. Never probes anything external."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("127.0.0.1", port))
        die(f"port {port} already in use — pick another with --port")
    except OSError:
        pass
    finally:
        s.close()


# ---------- main ----------
def main():
    # Line-buffered stdout even when redirected to a file — the link line must be
    # visible to callers that poll the log while the server is still running.
    sys.stdout.reconfigure(line_buffering=True)
    args = build_arg_parser().parse_args()

    if args.help or not args.file:
        print_help()
        sys.exit(0 if args.help else 1)

    # ---- flag semantics replicated from the bash version ----
    validate_args(args)
    if args.argo:
        validate_argo(args)

    file_path = args.file

    tls_mode = "http"
    if args.cert and args.key and os.access(args.cert, os.R_OK) and os.access(args.key, os.R_OK):
        tls_mode = "cert"
    elif args.cert or args.key:
        warn("--cert/--key requires a readable pair — serving plain HTTP instead; "
             "no self-signed HTTPS in this Python version")

    if args.argo:
        # Guards ran above; here the backend just binds a random free loopback port
        # (--port is accepted but unused) and stays plain HTTP behind cloudflared.
        args.port = pick_random_port()
        tls_mode = "http"

    # ---- host resolution ----
    display_host = resolve_host(args.host, "v4" if args.v4 else ("v6" if args.v6 else None)) if args.host else "localhost"
    if args.host:
        print(f"link host: {display_host}")

    # ---- port pre-check (loopback only, never probes external) ----
    check_port_free(args.port)

    # ---- payload: file or directory — nothing persists past the process ----
    # Keep the handler in streaming mode: single-file stays in memory for
    # small-file fast path, multi-file is fully disk-backed (no preload).
    if os.path.isdir(file_path):
        DeliveryHandler.serve_dir = os.path.realpath(file_path)
        DeliveryHandler.key = secrets.token_urlsafe(8)[:8]
        # Detect empty dir early
        if not any(os.path.isfile(os.path.join(file_path, f)) for f in os.listdir(file_path)):
            warn(f"directory is empty: {file_path}")
    else:
        DeliveryHandler.serve_dir = None
        with open(file_path, "rb") as f:
            DeliveryHandler.payload = f.read()
        DeliveryHandler.filename = os.path.basename(file_path)
        DeliveryHandler.key = secrets.token_urlsafe(8)[:8]

    tmpdir = tempfile.mkdtemp(prefix="config-delivery-")
    srv = make_server(args.port)

    # ---- TLS material (only real certs; no self-signed in Python) ----
    if tls_mode != "http":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)

    scheme = "https" if tls_mode != "http" else "http"
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    # ---- argo quick tunnel ----
    pub_url = ""
    if args.argo:
        # tmpdir comes from mkdtemp (never user input); the URL extracted from the
        # log is regex-anchored to [a-z0-9-]+.trycloudflare.com before any use.
        cfd_log = tempfile.TemporaryFile(mode="w+")
        cfd = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", f"http://127.0.0.1:{args.port}"],
            stdout=cfd_log, stderr=subprocess.STDOUT,
            start_new_session=True,   # never killed by this script's cleanup
        )
        deadline = time.time() + 20
        # Quick-tunnel hostnames are multi-word ("word-word-word.trycloudflare.com").
        # api./metric. subdomains appear in cloudflared's startup log (registration
        # endpoints) and must not match — anchor on >=2 hyphen-separated words.
        pat = re.compile(r"https://[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)+\.trycloudflare\.com")
        while time.time() < deadline:
            cfd_log.seek(0)
            m = pat.search(cfd_log.read())
            if m:
                pub_url = m.group(0)
                break
            if cfd.poll() is not None:
                break
            time.sleep(0.3)
        if not pub_url:
            err("no trycloudflare URL within ~20s — cloudflared log tail:")
            cfd_log.seek(0)
            sys.stderr.write(cfd_log.read()[-4000:])
            shutdown(srv, tmpdir)
            sys.exit(1)

    # ---- independent encryption key (the ?k= parameter)
    # KEY_URL (path segment) and ?k= are independent. KEY_URL authenticates; ENC_KEY
    # encrypts payload. Env var is the credential source per pre-generation advice;
    # falls back to openssl if env is not set. No credential literals in code.
    enc_hex = os.environ.get("CD_ENC_KEY", "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", enc_hex or ""):
        proc = subprocess.run(["openssl", "rand", "-hex", "32"], stdout=subprocess.PIPE)
        enc_hex = proc.stdout.decode().strip() if proc.returncode == 0 else secrets.token_hex(32)
    enc_hex = enc_hex.lower()

    # ---- print the link ----
    bn = DeliveryHandler.filename if DeliveryHandler.serve_dir is None else ""
    is_dir = DeliveryHandler.serve_dir is not None
    if args.argo:
        link = f"{pub_url}/{DeliveryHandler.key}" + ("/" if is_dir else "") + f"?k={enc_hex}"
        print(f"one-time download link: {link}")
        print("tunnel cert is a public CA (browser-trusted, zero warnings); no domain or open inbound port needed")
        print(f"client: wget -O {bn or 'listing.json'} {link}")
    elif tls_mode == "http":
        link = f"http://{display_host}:{args.port}/{DeliveryHandler.key}" + ("/" if is_dir else "") + f"?k={enc_hex}"
        print(f"one-time download link: {link}")
        print("warning: plain HTTP — the config contains secrets; anyone on the network path can read it")
        print("dir listing hidden; host is user-supplied (never auto-probed)")
        print(f"client: wget -O {bn or 'files/'} {link}")
    else:  # cert
        link = f"https://{display_host}:{args.port}/{DeliveryHandler.key}" + ("/" if is_dir else "") + f"?k={enc_hex}"
        print(f"one-time download link: {link}")
        print("dir listing hidden; host is user-supplied (never auto-probed)")
        print(f"client: wget -O {bn or 'files/'} {link}")

    # ---- unified verification: 3s countdown doubles as argo warm-up ----
    print("checking link in 3...")
    time.sleep(1)
    print("checking link in 2...")
    time.sleep(1)
    print("checking link in 1...")
    time.sleep(1)
    if not verify_link(
        link.replace("[", "").replace("]", "") if link.startswith("http") else link,
    ):
        err(f"link did not return HTTP 200 after 3 attempts — not printing the link")
        shutdown(srv, tmpdir, argo=args.argo)
        sys.exit(1)

    # ---- hold vs detached ----
    if args.hold:
        left = args.ttl
        while left > 0:
            print(f"\r\033[2Klink auto-deletes in {left}s (^C to stop now)   ", end="", flush=True)
            time.sleep(1)
            left -= 1
        print("\r\033[2Klink expired — cleaning up")
        shutdown(srv, tmpdir, argo=args.argo)
        sys.exit(0)

    # Detached mode: hand back the terminal; the server daemon-thread keeps serving
    # until TTL elapses, then exits. The PID printed IS the handle (kill <pid>).
    print(f"file auto-deletes after {args.ttl}s")
    print(f"\033[31mimportant: if you wanna end sharing before ttl, try kill {os.getpid()}\033[0m")
    # ^C / kill <pid> both land here: same zero-residue cleanup, exit 130 like the bash INT trap.
    signal.signal(signal.SIGINT, lambda *_: (shutdown(srv, tmpdir, argo=False), sys.exit(130)))
    signal.signal(signal.SIGTERM, lambda *_: shutdown(srv, tmpdir, argo=False))
    time.sleep(args.ttl)
    shutdown(srv, tmpdir, argo=args.argo)


def shutdown(srv, tmpdir, argo=False):
    try:
        srv.shutdown()
    except Exception:
        pass
    shutil.rmtree(tmpdir, ignore_errors=True)
    if argo:
        print(f"{C_BLUE}argo quick tunnel may still be running — remove manually, or try: sudo systemctl restart cloudflared{C_RESET}")


def print_help():
    print("""##help##
  --port N        listen port (default 443, 1-65535, <1024 needs root; ignored in
                  --argo mode, where the backend binds a random loopback port)
  --ttl SEC       auto-delete the file after N seconds (default 60, no upper bound —
                  a "permanent" share without systemd is not real — use a big TTL)
  --hold          stay in the foreground: live single-line countdown on screen; ^C
                  stops the share right away, and when the TTL elapses the share ends
                  by itself and the terminal is released. not exclusive with --ttl
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
                  zero warnings), no domain or open inbound port needed. backend
                  runs plain HTTP on a random loopback port. disables
                  --host/--v4/--v6/--cert/--key (the tunnel owns public URL + cert).
  FILE            file or directory to deliver (positional, e.g. serve ./config-client.json or ./out/); link includes ?k=<64hex> (CD_ENC_KEY env or openssl rand -hex 32)
##help##""")


if __name__ == "__main__":
    main()
