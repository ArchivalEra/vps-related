#!/usr/bin/env python3
"""
otd.py — one-time download: temporary HTTPS (QUIC/HTTP3 preferred) file sharing.

Completely independent of gen-client.sh / protocols.lib.sh — its only job is
to serve one file once via a short-lived HTTPS link.

Usage:
  # server side (the machine holding the json)
  python3 otd.py serve ./client.json --port 443 --name client-config.json
      → prints: one-time download link:  https://<host>:443/<8-char-key>

  # client side (any device)
  curl -kOJ https://<host>:443/<8-char-key>     # -OJ honors the server filename (rename)
  # or just open the link in a browser; the file downloads with the given name.

  Security model:
  - 8-char URL-safe key (alphanumeric), generated fresh per serve (or --key to pin).
  - One-time: the key is served exactly once, then invalidated (in-memory + TTL).
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
  - Self-signed certs are unusual on QUIC in practice; HTTP/3 path is best-effort.
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
_OTD = {"key": None, "file": None, "name": None, "used": False, "expires": 0}


def gen_key(n=8):
    """URL-safe alphanumeric key, exactly n chars (A-Za-z0-9)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "OTD/1.0"

    def log_message(self, fmt, *args):  # keep console quiet
        pass

    def _serve_once(self):
        # one-time gate
        if _OTD["used"]:
            self.send_error(410, "Gone (key already used)")
            return
        if time.time() > _OTD["expires"]:
            self.send_error(410, "Gone (key expired)")
            return
        if not os.path.isfile(_OTD["file"]):
            self.send_error(404, "file gone")
            return
        _OTD["used"] = True  # one-time, before sending
        try:
            with open(_OTD["file"], "rb") as f:
                data = f.read()
        except OSError:
            _OTD["used"] = False
            self.send_error(500, "read failed")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        # rename: client gets this filename (curl -OJ / browser saves as)
        fname = _OTD["name"] or os.path.basename(_OTD["file"])
        # RFC 5987: ASCII fallback filename + filename* for non-ASCII/space (latin-1 safe)
        enc = urllib.parse.quote(fname)
        self.send_header("Content-Disposition",
                         "attachment; filename=otd-download.json; filename*=UTF-8''" + enc)
        self.end_headers()
        self.wfile.write(data)

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
    """Best-effort HTTP/3 via aioquic; returns True if started."""
    try:
        import asyncio
        from aioquic.asyncio import serve as aq_serve
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.h3.connection import H3Connection
        from aioquic.h3.events import H3Event, HeadersReceived, DataReceived
    except ImportError:
        return False

    class H3Proto:
        def __init__(self, *a, **k):
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
            if path != _OTD["key"] or _OTD["used"] or time.time() > _OTD["expires"]:
                status, body = 404, b"not found"
            else:
                _OTD["used"] = True
                try:
                    body = open(_OTD["file"], "rb").read()
                    status = 200
                except OSError:
                    body, status = b"read failed", 500
            fname = _OTD["name"] or os.path.basename(_OTD["file"])
            enc = urllib.parse.quote(fname)
            headers = [
                (b":status", str(status).encode()),
                (b"content-type", b"application/json"),
                (b"content-disposition",
                 ("attachment; filename=otd-download.json; filename*=UTF-8''" + enc).encode()),
            ]
            self.http.send_headers(event.stream_id, headers, end_stream=False)
            self.http.send_data(event.stream_id, body, end_stream=True)

        def quic_event_received_udp(self, event):  # pragma: no cover
            pass

    async def _main():
        cfg = QuicConfiguration(is_client=False)
        cfg.load_cert_chain(cert, key)
        await aq_serve(host, port, configuration=cfg,
                       create_protocol=H3Proto, alpn_protocols=["h3"])
        await asyncio.Future()

    threading.Thread(target=lambda: asyncio.run(_main()), daemon=True).start()
    return True


def main():
    ap = argparse.ArgumentParser(description="one-time HTTPS file sharing")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="serve one file once")
    s.add_argument("file", help="path to the file to share (e.g. client.json)")
    s.add_argument("--port", type=int, default=443, help="listen port (default 443)")
    s.add_argument("--key", default=None, help="pin a specific 8-char key (default: random)")
    s.add_argument("--name", default=None, help="download filename (rename; default: original basename)")
    args = ap.parse_args()

    f = os.path.abspath(args.file)
    if not os.path.isfile(f):
        sys.exit(f"file not found: {f}")
    key = args.key or gen_key()
    if not (4 <= len(key) <= 16 and key.isalnum()):
        sys.exit("key must be 4-16 alphanumeric chars")
    _OTD.update(key=key, file=f, name=args.name,
                expires=time.time() + 300)  # 5-min TTL, fixed

    with tempfile.TemporaryDirectory() as td:
        cert, keyf = os.path.join(td, "crt.pem"), os.path.join(td, "key.pem")
        make_cert(cert, keyf)
        print(f"one-time download link:  https://{socket.gethostname()}:{args.port}/{key}", flush=True)
        print(f"  (file: {f}  rename→: {_OTD['name'] or os.path.basename(f)}  ttl: 300s)", flush=True)
        if args.port == 443:
            h3 = serve_http3(443, cert, keyf, "0.0.0.0")
            if h3:
                print("  http/3 (QUIC) enabled on 443/udp", flush=True)
            else:
                print("  ⚠ aioquic not installed — HTTP/3 skipped; HTTPS (TCP) only", flush=True)
        else:
            print("  (port != 443: HTTP/3 skipped, HTTPS only)", flush=True)
        print("  client:  curl -kOJ https://<host>:443/<key>   (self-signed → -k)", flush=True)
        serve_https(args.port, cert, keyf)


if __name__ == "__main__":
    main()
