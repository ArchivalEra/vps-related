#!/usr/bin/env python3
"""Mock plain-DNS upstream (UDP + TCP on the same port).
--tc makes UDP answers truncated (TC=1) so clients must retry over TCP.
Logs 'MOCKHIT udp|tcp <qname> <qtype>' per query."""
import argparse
import os
import socket
import struct
import threading

from canned import build_response, parse_question


def truncated(query):
    # recompute the question section so no stray trailing bytes survive
    i = 12
    while query[i] != 0:
        i += 1 + query[i]
    i += 1 + 4
    # QR=1 RD=1 TC=1 | RA=1 rcode=0
    return query[0:2] + struct.pack("!HHHHH", 0x8380, 1, 0, 0, 0) + query[12:i]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=15301)
    ap.add_argument("--ttl", type=int, default=3600)
    ap.add_argument("--tc", action="store_true", help="reply TC=1 over UDP (forces TCP retry)")
    a = ap.parse_args()

    def log(tr, q):
        p = parse_question(q)
        name, qt = (p[0], p[1]) if p else ("?", 0)
        print(f"MOCKHIT {tr} {name} {qt}", flush=True)

    def tcp_server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("127.0.0.1", a.port))
            srv.listen(64)
        except Exception as e:
            print(f"mockudp FATAL: tcp bind failed: {e}", flush=True)
            os._exit(1)
        print(f"mockudp tcp listening :{a.port}", flush=True)

        def serve(c):
            try:
                while True:
                    lb = recvn(c, 2)
                    if lb is None:
                        return
                    n = int.from_bytes(lb, "big")
                    q = recvn(c, n)
                    if q is None:
                        return
                    log("tcp", q)
                    r = build_response(q, a.ttl)
                    c.sendall(len(r).to_bytes(2, "big") + r)
            except Exception:
                pass
            finally:
                c.close()

        while True:
            c, _ = srv.accept()
            threading.Thread(target=serve, args=(c,), daemon=True).start()

    threading.Thread(target=tcp_server, daemon=True).start()

    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", a.port))
    print(f"mockudp udp listening :{a.port} tc={a.tc}", flush=True)
    while True:
        q, addr = u.recvfrom(65535)
        log("udp", q)
        r = truncated(q) if a.tc else build_response(q, a.ttl)
        u.sendto(r, addr)


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            return None
        buf += d
    return buf


if __name__ == "__main__":
    main()
