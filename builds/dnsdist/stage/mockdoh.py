#!/usr/bin/env python3
"""Mock DoH upstream (HTTP/1.1 over TLS). Logs 'MOCKHIT doh <qname> <qtype>'."""
import argparse
import base64
import ssl
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from canned import build_response, parse_question

ARGS = None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def _reply(self, q):
        p = parse_question(q)
        name, qt = (p[0], p[1]) if p else ("?", 0)
        print(f"MOCKHIT doh {name} {qt}", flush=True)
        r = build_response(q, ARGS.ttl)
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(r)))
        self.end_headers()
        self.wfile.write(r)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        q = self.rfile.read(n)
        self._reply(q)

    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        dns = qs.get("dns", [None])[0]
        if not dns:
            self.send_error(400)
            return
        pad = "=" * (-len(dns) % 4)
        try:
            q = base64.urlsafe_b64decode(dns + pad)
        except Exception:
            self.send_error(400)
            return
        self._reply(q)


def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=1856)
    ap.add_argument("--ttl", type=int, default=3600)
    ap.add_argument("--cert", default="certs/upstream.pem")
    ap.add_argument("--key", default="certs/upstream.key")
    ARGS = ap.parse_args()

    httpd = ThreadingHTTPServer(("127.0.0.1", ARGS.port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_alpn_protocols(["http/1.1"])
    ctx.load_cert_chain(ARGS.cert, ARGS.key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"mockdoh listening 127.0.0.1:{ARGS.port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
