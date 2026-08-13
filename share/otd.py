#!/usr/bin/env python3
"""
otd.py — one-time download: temporary HTTPS (QUIC/HTTP3 preferred) file sharing.

Completely independent of gen-client.sh / protocols.lib.sh — its only job is
to serve one file once via a short-lived HTTPS link.

Usage:
  # server side (the machine holding the json) — one command:
  ./otd.py ./client.json --port 443 --name client-config.json [--count N]
  #   or with python3:  python3 otd.py ./client.json ...
  #   (legacy `otd.py serve ./client.json ...` also accepted)
      → prints: one-time download link:  https://<host>:443/<8-char-key>

  # client side (any device)
  curl -kOJ https://<host>:443/<8-char-key>     # -OJ honors the server filename (rename)
  # or just open the link in a browser; the file downloads with the given name.

  Security model:
  - 8-char URL-safe key (alphanumeric), generated fresh per serve (or --key to pin).
  - Download count: --count N allows N downloads (default 1 = one-time), then 410.
  - Temporary self-signed cert (openssl-generated, ECDSA P-256), regenerated per run.
  - HTTPS enforced (no plain HTTP); client uses -k for self-signed.

  Rename note:
  - Served via Content-Disposition: ASCII fallback `filename=otd-download.json` +
    RFC 5987 `filename*=UTF-8''<percent-encoded>` for the real name.
  - Browsers honor filename* (correct non-ASCII/space name).
  - curl -OJ only honors the ASCII `filename` fallback (known curl limitation),
    so `curl -kOJ <link>` saves as otd-download.json — use a browser for the exact rename.

  QUIC/HTTP3:
  - Preferred: if `aioquic` is installed, an HTTP/3 server listens on 443/udp.
  - Fallback: standard-library HTTPS on 443/tcp (always available), with a warning.
  - HTTP/3 is experimental/best-effort: aioquic API varies by version and QUIC handshakes
    are environment-sensitive. HTTPS (TCP) is the dependable path — HTTP/3 never blocks it.
"""
import argparse
import http.server
import os
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

# ── one-time store ─────────────────────────────────────────────────────
# remaining: downloads still allowed (default 1 = one-time; --count N allows N)
_OTD = {"key": None, "file": None, "name": None, "remaining": 0, "expires": 0}


def gen_key(n=8):
    """URL-safe alphanumeric key, exactly n chars (A-Za-z0-9)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))


def prepare_download():
    """One-time download semantics — single source of truth for both transports.

    Streams big files: returns (status, headers, size, fileobj) where fileobj is
    an open binary file for the caller to stream in chunks (never loads the whole
    file into memory — supports huge files). On error, fileobj is None and the
    last element is the error body bytes.
    """
    if _OTD["remaining"] <= 0:
        return 410, [], 0, b"Gone (download count exhausted)"
    if time.time() > _OTD["expires"]:
        return 410, [], 0, b"Gone (key expired)"
    if not os.path.isfile(_OTD["file"]):
        return 404, [], 0, b"file gone"
    try:
        f = open(_OTD["file"], "rb")
    except OSError:
        return 500, [], 0, b"read failed"
    _OTD["remaining"] -= 1  # consume one, after successful open
    size = os.path.getsize(_OTD["file"])
    fname = _OTD["name"] or os.path.basename(_OTD["file"])
    enc = urllib.parse.quote(fname)
    return 200, [
        ("Content-Type", "application/octet-stream"),
        # RFC 5987: ASCII fallback filename + filename* for non-ASCII/space (latin-1 safe)
        ("Content-Disposition",
         "attachment; filename=otd-download.json; filename*=UTF-8''" + enc),
    ], size, f


_CHUNK = 64 * 1024  # 64 KiB streaming chunk


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "OTD/1.0"

    def log_message(self, fmt, *args):  # keep console quiet
        pass

    def _serve_once(self):
        status, headers, size, f = prepare_download()
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(size))
        self.end_headers()
        if f is not None:
            try:
                while True:
                    chunk = f.read(_CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            finally:
                f.close()
        else:
            self.wfile.write(size)  # error body

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path.lstrip("/")
        if path == _OTD["key"]:
            self._serve_once()
        else:
            self.send_error(404, "not found")


def make_cert(cert_path, key_path):
    """Self-signed ECDSA P-256 cert via openssl (CN=otd.local)."""
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-keyout", key_path, "-out", cert_path,
         "-days", "1", "-subj", "/CN=otd.local"],
        check=True, capture_output=True,
    )


def serve_https(port, cert, key):
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


def serve_http3(port, cert, key, host):
    """Best-effort HTTP/3 via aioquic (optional). Returns True if started.

    Never crashes the tool: any aioquic absence/version/API mismatch or thread
    error is reported as a warning and HTTPS keeps serving.
    """
    try:
        import asyncio
        from aioquic.asyncio import serve as aq_serve
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.h3.connection import H3Connection
        from aioquic.h3.events import HeadersReceived
    except ImportError:
        return False

    # fail fast if the UDP port can't be bound
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host, port))
        s.close()
    except OSError as e:
        print(f"  ⚠ HTTP/3 skipped: UDP {port} not bindable ({e})", flush=True)
        return False

    class H3Proto(QuicConnectionProtocol):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.http = None

        def quic_event_received(self, event):
            if self.http is None and isinstance(event, HeadersReceived):
                self.http = H3Connection(self._quic)
                self.http.receive_event(event)
                self._on_headers(event)
            elif self.http is not None:
                self.http.receive_event(event)

        def _on_headers(self, event):
            path = urllib.parse.urlparse(
                event.headers[b":path"].decode()).path.lstrip("/")
            if path != _OTD["key"]:  # routing; semantics come from prepare_download
                status, headers, size, body = 404, [], 0, b"not found"
            else:
                status, headers, size, f = prepare_download()
            hdrs = [(b":status", str(status).encode())]
            hdrs += [(k.encode(), v.encode()) for k, v in headers]
            self.http.send_headers(event.stream_id, hdrs, end_stream=False)
            if f is not None:
                try:
                    while True:
                        chunk = f.read(_CHUNK)
                        if not chunk:
                            break
                        self.http.send_data(event.stream_id, chunk, end_stream=False)
                finally:
                    f.close()
                self.http.send_data(event.stream_id, b"", end_stream=True)
            else:
                self.http.send_data(event.stream_id, body, end_stream=True)

        def quic_event_received_udp(self, event):  # pragma: no cover
            pass

    async def _main():
        cfg = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        cfg.load_cert_chain(cert, key)
        await aq_serve(host, port, configuration=cfg,
                       create_protocol=H3Proto)
        await asyncio.Future()

    def _run():
        try:
            asyncio.run(_main())
        except Exception as e:  # surface thread errors instead of dying silently
            print(f"  ⚠ HTTP/3 thread error: {e}", flush=True)

    threading.Thread(target=_run, daemon=True).start()
    return True


def main():
    # one command:  otd.py ./file.json [--port 443] [--key XXX] [--name X.json] [--count N]
    # compatible:   otd.py serve ./file.json ...
    argv = sys.argv[1:]
    if argv and argv[0] == "serve":
        argv = argv[1:]
    ap = argparse.ArgumentParser(description="one-time HTTPS file sharing")
    ap.add_argument("file", help="path to the file to share (e.g. client.json)")
    ap.add_argument("--port", type=int, default=443, help="listen port (default 443)")
    ap.add_argument("--host", default=None,
                    help="public address for the link (domain/IP; default: auto-detect public IP, "
                         "fallback hostname — on a VPS use --host your.domain or the public IP)")
    ap.add_argument("--key", default=None, help="pin a specific 8-char key (default: random)")
    ap.add_argument("--name", default=None, help="download filename (rename; default: original basename)")
    ap.add_argument("--count", type=int, default=1, help="allowed downloads (default 1 = one-time; must be >= 1)")
    args = ap.parse_args(argv)

    f = os.path.abspath(args.file)
    if not os.path.isfile(f):
        sys.exit(f"file not found: {f}")
    if args.count < 1:
        sys.exit(f"--count must be >= 1 (got {args.count})")
    key = args.key or gen_key()
    if not (4 <= len(key) <= 16 and key.isalnum()):
        sys.exit("key must be 4-16 alphanumeric chars")
    _OTD.update(key=key, file=f, name=args.name, remaining=args.count,
                expires=time.time() + 300)  # 5-min TTL, fixed

    with tempfile.TemporaryDirectory() as td:
        cert, keyf = os.path.join(td, "crt.pem"), os.path.join(td, "key.pem")
        make_cert(cert, keyf)
        # link host: --host > public IP detect > hostname (hostname is often useless on a VPS)
        host = args.host
        if not host:
            import urllib.request
            try:
                with urllib.request.urlopen("https://ifconfig.me/ip", timeout=5) as r:
                    host = r.read().decode().strip()
            except Exception:
                host = socket.gethostname()
        if args.host is None and host != socket.gethostname():
            print(f"  (link host auto-detected: {host} — override with --host if wrong)", flush=True)
        print(f"one-time download link:  https://{host}:{args.port}/{key}", flush=True)
        print(f"  (file: {f}  rename→: {_OTD['name'] or os.path.basename(f)}  downloads: {args.count}  ttl: 300s)", flush=True)
        if args.port == 443:
            h3 = serve_http3(443, cert, keyf, "0.0.0.0")
            if h3:
                print("  http/3 (QUIC) enabled on 443/udp", flush=True)
            else:
                print("  ⚠ aioquic not installed — HTTP/3 skipped; HTTPS (TCP) only", flush=True)
        else:
            print("  (port != 443: HTTP/3 skipped, HTTPS only)", flush=True)
        print(f"  client:  curl -kOJ https://{host}:{args.port}/{key}   (self-signed → -k)", flush=True)
        serve_https(args.port, cert, keyf)


if __name__ == "__main__":
    main()
