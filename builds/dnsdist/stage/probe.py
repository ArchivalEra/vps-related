#!/usr/bin/env python3
"""Wait for a TCP (or UDP) port to become reachable on loopback. exit 0/1."""
import argparse
import socket
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("--udp", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    fam = socket.AF_INET6 if ":" in a.host else socket.AF_INET
    deadline = time.monotonic() + a.timeout
    while time.monotonic() < deadline:
        try:
            if a.udp:
                s = socket.socket(fam, socket.SOCK_DGRAM)
                s.settimeout(0.5)
                s.sendto(b"\x00", (a.host, a.port))
                s.close()
                sys.exit(0)
            else:
                with socket.create_connection((a.host, a.port), timeout=0.5):
                    sys.exit(0)
        except OSError:
            time.sleep(0.2)
    sys.exit(1)


if __name__ == "__main__":
    main()
