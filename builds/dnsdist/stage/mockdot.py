#!/usr/bin/env python3
"""Mock DoT upstream. Logs 'MOCKHIT dot <qname> <qtype>' per query."""
import argparse
import socket
import ssl
import threading

from canned import build_response, parse_question


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            return None
        buf += d
    return buf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=1855)
    ap.add_argument("--ttl", type=int, default=3600)
    ap.add_argument("--cert", default="certs/upstream.pem")
    ap.add_argument("--key", default="certs/upstream.key")
    a = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_alpn_protocols(["dot"])
    ctx.load_cert_chain(a.cert, a.key)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", a.port))
    srv.listen(64)
    print(f"mockdot listening 127.0.0.1:{a.port}", flush=True)

    def serve(c):
        try:
            tls = ctx.wrap_socket(c, server_side=True)
            while True:
                lb = recvn(tls, 2)
                if lb is None:
                    break
                n = int.from_bytes(lb, "big")
                if n == 0 or n > 65535:
                    break
                q = recvn(tls, n)
                if q is None:
                    break
                p = parse_question(q)
                name, qt = (p[0], p[1]) if p else ("?", 0)
                print(f"MOCKHIT dot {name} {qt}", flush=True)
                r = build_response(q, a.ttl)
                tls.sendall(len(r).to_bytes(2, "big") + r)
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass

    while True:
        c, _ = srv.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
