#!/usr/bin/env python3
"""Stage test client (loopback-only rig): --dot / --doh / --doq / --plain.
Prints 'QRESULT <transport> <name> type<N> rcode=<r> ttl=<t> ans=<a,...>'.
Targets are restricted to loopback; TLS is always verified against the stage CA."""
import argparse
import asyncio
import base64
import ipaddress
import os
import socket
import ssl
import struct
import sys
import urllib.parse
import urllib.request

from canned import rcode_of, ttl_and_answers

STAGE_CA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "ca.pem")


def guard_host(host):
    """This client only ever talks to the loopback test rig."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise SystemExit(f"refusing non-literal host `{host}` (loopback rig only)")
    if not ip.is_loopback:
        raise SystemExit(f"refusing non-loopback target {host}")


def build_query(name, qtype):
    qid = struct.unpack("!H", os.urandom(2))[0]
    hdr = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    q = b""
    for lab in name.rstrip(".").split("."):
        q += bytes([len(lab)]) + lab.encode()
    q += b"\x00"
    q += struct.pack("!HH", qtype, 1)
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    return hdr + q + opt


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            return None
        buf += d
    return buf


def split_hostport(addr, defport):
    if addr.startswith("["):
        h, rest = addr[1:].split("]")
        port = int(rest.lstrip(":") or defport)
        return h, port
    if ":" in addr:
        h, p = addr.rsplit(":", 1)
        return h, int(p)
    return addr, defport


def q_dot(addr, q, timeout):
    host, port = split_hostport(addr, 853)
    guard_host(host)
    ctx = ssl.create_default_context(cafile=STAGE_CA)
    with socket.create_connection((host, port), timeout=timeout) as c:
        with ctx.wrap_socket(c, server_hostname=host) as tls:
            tls.sendall(len(q).to_bytes(2, "big") + q)
            lb = recvn(tls, 2)
            n = int.from_bytes(lb, "big")
            return recvn(tls, n)


def q_doh(url, q, timeout):
    u = urllib.parse.urlparse(url)
    if u.scheme != "https":
        raise SystemExit("only https DoH URLs allowed")
    guard_host(u.hostname)
    ctx = ssl.create_default_context(cafile=STAGE_CA)
    req = urllib.request.Request(
        u._replace(scheme="https").geturl(),
        data=q,
        headers={"Content-Type": "application/dns-message"},
        method="POST",
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        NoRedirect(),
    )
    with opener.open(req, timeout=timeout) as r:
        return r.read()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None  # no redirects in the rig


async def q_doq(addr, q, timeout):
    from aioquic.asyncio import QuicConnectionProtocol, connect
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import StreamDataReceived

    host, port = split_hostport(addr, 853)
    guard_host(host)

    class Client(QuicConnectionProtocol):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.waiter = asyncio.get_event_loop().create_future()

        def quic_event_received(self, event):
            if isinstance(event, StreamDataReceived):
                buf = getattr(self, "buf", b"") + event.data
                if len(buf) >= 2:
                    n = int.from_bytes(buf[:2], "big")
                    if len(buf) >= 2 + n and not self.waiter.done():
                        self.waiter.set_result(buf[2 : 2 + n])
                        return
                self.buf = buf

    cfg = QuicConfiguration(is_client=True, alpn_protocols=["doq"])
    cfg.load_verify_locations(cafile=STAGE_CA)
    async with connect(host, port, configuration=cfg, create_protocol=Client,
                       wait_connected=True) as proto:
        sid = proto._quic.get_next_available_stream_id()
        proto._quic.send_stream_data(sid, len(q).to_bytes(2, "big") + q, end_stream=True)
        proto.transmit()
        return await asyncio.wait_for(proto.waiter, timeout)


def q_plain(addr, q):
    host, port = split_hostport(addr, 53)
    guard_host(host)
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(q, (host, port))
    r, _ = s.recvfrom(65535)
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dot")
    ap.add_argument("--doh")
    ap.add_argument("--doq")
    ap.add_argument("--plain")
    ap.add_argument("--name", required=True)
    ap.add_argument("--type", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=5.0)
    a = ap.parse_args()
    if not os.path.exists(STAGE_CA):
        raise SystemExit(f"stage CA missing: {STAGE_CA} (run ./mkcerts.sh first)")

    q = build_query(a.name, a.type)
    try:
        if a.dot:
            r = q_dot(a.dot, q, a.timeout)
            tr = "dot"
        elif a.doh:
            r = q_doh(a.doh, q, a.timeout)
            tr = "doh"
        elif a.doq:
            r = asyncio.run(q_doq(a.doq, q, a.timeout))
            tr = "doq"
        elif a.plain:
            r = q_plain(a.plain, q)
            tr = "plain"
        else:
            ap.error("pick one of --dot/--doh/--doq/--plain")
            return
    except SystemExit:
        raise
    except Exception as e:
        print(f"QRESULT FAIL {type(e).__name__}: {e}")
        sys.exit(1)
    if not r or len(r) < 12:
        print("QRESULT FAIL short response")
        sys.exit(1)
    ttl, answers = ttl_and_answers(r)
    print(
        f"QRESULT {tr} {a.name} type{a.type} rcode={rcode_of(r)} "
        f"ttl={ttl} ans={','.join(answers) if answers else '-'}"
    )
    sys.exit(0 if rcode_of(r) == 0 else 1)


if __name__ == "__main__":
    main()
