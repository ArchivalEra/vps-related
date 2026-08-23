#!/usr/bin/env python3
"""Loopback load generator for magdns (PGO + soak).

DoT workers with connection churn + optional DoQ share on one long-lived QUIC
connection. Mix: `hot` names (cache hits) + unique names (cache misses).
Final line: LOADGEN done sent=N ok=N fail=N p50=<ms> p95=<ms> conn_err=N"""
import argparse
import asyncio
import ipaddress
import os
import random
import socket
import ssl
import statistics
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from canned import rcode_of  # noqa: E402

STAGE_CA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "ca.pem")

QTYPE_A = 1


def build_query(name):
    qid = struct.unpack("!H", os.urandom(2))[0]
    hdr = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    q = b""
    for lab in name.rstrip(".").split("."):
        q += bytes([len(lab)]) + lab.encode()
    q += b"\x00" + struct.pack("!HH", QTYPE_A, 1)
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    return hdr + q + opt


def split_hostport(addr, defport):
    if addr.startswith("["):
        h, rest = addr[1:].split("]")
        return h, int(rest.lstrip(":") or defport)
    if ":" in addr:
        h, p = addr.rsplit(":", 1)
        return h, int(p)
    return addr, defport


def guard_host(host):
    ip = ipaddress.ip_address(host)
    if not ip.is_loopback:
        raise SystemExit("loopback rig only")


class DotWorker:
    def __init__(self, addr):
        self.host, self.port = split_hostport(addr, 853)
        guard_host(self.host)
        self.tls = None
        self.conn_err = 0

    async def connect(self):
        ctx = ssl.create_default_context(cafile=STAGE_CA)
        rd, wr = await asyncio.open_connection(self.host, self.port, ssl=ctx, server_hostname=self.host)
        self.tls = (rd, wr)

    async def query(self, name):
        if self.tls is None:
            await self.connect()
        q = build_query(name)
        rd, wr = self.tls
        wr.write(len(q).to_bytes(2, "big") + q)
        await wr.drain()
        lb = await rd.readexactly(2)
        n = int.from_bytes(lb, "big")
        if n == 0:
            raise ConnectionError("empty frame")
        r = await rd.readexactly(n)
        if rcode_of(r) not in (0, 3):
            raise ConnectionError(f"rcode {rcode_of(r)}")
        return r

    async def recycle(self):
        if self.tls:
            self.tls[1].close()
            self.tls = None


class DoqClient:
    def __init__(self, addr):
        self.host, self.port = split_hostport(addr, 8853)
        guard_host(self.host)
        self.conn = None
        self.waiters = {}

    async def ensure(self):
        if self.conn is not None:
            return
        from aioquic.asyncio import QuicConnectionProtocol, connect
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import StreamDataReceived

        cfg = QuicConfiguration(is_client=True, alpn_protocols=["doq"])
        cfg.load_verify_locations(cafile=STAGE_CA)

        rig = self

        class Client(QuicConnectionProtocol):
            def quic_event_received(self, event):
                if isinstance(event, StreamDataReceived):
                    buf = getattr(self, "bufs", {}).get(event.stream_id, b"") + event.data
                    if len(buf) >= 2:
                        n = int.from_bytes(buf[:2], "big")
                        if len(buf) >= 2 + n:
                            w = rig.waiters.pop(event.stream_id, None)
                            if w and not w.done():
                                w.set_result(buf[2 : 2 + n])
                            bufs = getattr(self, "bufs", {})
                            bufs.pop(event.stream_id, None)
                            self.bufs = bufs
                            return
                    bufs = getattr(self, "bufs", {})
                    bufs[event.stream_id] = buf
                    self.bufs = bufs

        self.conn = await connect(
            self.host, self.port, configuration=cfg, create_protocol=Client
        ).__aenter__()

    async def query(self, name):
        await self.ensure()
        q = build_query(name)
        sid = self.conn._quic.get_next_available_stream_id()
        w = asyncio.get_event_loop().create_future()
        self.waiters[sid] = w
        self.conn._quic.send_stream_data(sid, len(q).to_bytes(2, "big") + q, end_stream=True)
        self.conn.transmit()
        r = await asyncio.wait_for(w, 5)
        if rcode_of(r) not in (0, 3):
            raise ConnectionError(f"rcode {rcode_of(r)}")
        return r


async def run(args):
    rng = random.Random(20260824)
    hot = [f"h{i}.stage.test" for i in range(args.hot)]
    sent = ok = fail = conn_err = 0
    lat = []
    stop_at = time.monotonic() + args.duration

    async def dot_loop(idx):
        nonlocal sent, ok, fail, conn_err, lat
        w = DotWorker(args.dot)
        n = 0
        while time.monotonic() < stop_at:
            name = hot[rng.randrange(len(hot))] if rng.random() < 0.5 else f"u{rng.getrandbits(48)}.stage.test"
            t0 = time.monotonic()
            try:
                await w.query(name)
                ok += 1
                lat.append((time.monotonic() - t0) * 1000)
            except Exception as e:
                fail += 1
                if "connect" in type(e).__name__.lower() or isinstance(e, (ConnectionError, OSError, ssl.SSLError, asyncio.IncompleteReadError)):
                    conn_err += 1
                    try:
                        await w.recycle()
                    except Exception:
                        pass
            sent += 1
            n += 1
            if n % args.reconnect_every == 0:
                await w.recycle()
            await asyncio.sleep(1.0 / args.qps)

    async def doq_loop():
        nonlocal sent, ok, fail, conn_err, lat
        c = DoqClient(args.doq)
        while time.monotonic() < stop_at:
            name = hot[rng.randrange(len(hot))] if rng.random() < 0.5 else f"u{rng.getrandbits(48)}.stage.test"
            t0 = time.monotonic()
            try:
                await c.query(name)
                ok += 1
                lat.append((time.monotonic() - t0) * 1000)
            except Exception:
                fail += 1
                conn_err += 1
                c.conn = None
            sent += 1
            await asyncio.sleep(1.0 / (args.qps * args.doq_share))

    tasks = [dot_loop(i) for i in range(args.workers)]
    if args.doq:
        tasks.append(doq_loop())
    await asyncio.gather(*tasks)

    lat.sort()
    p50 = lat[len(lat) // 2] if lat else 0
    p95 = lat[int(len(lat) * 0.95)] if lat else 0
    print(
        f"LOADGEN done sent={sent} ok={ok} fail={fail} p50={p50:.1f} p95={p95:.1f} conn_err={conn_err}",
        flush=True,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dot", default="127.0.0.1:1853")
    ap.add_argument("--doq", default=None)
    ap.add_argument("--qps", type=float, default=80)
    ap.add_argument("--duration", type=float, default=1800)
    ap.add_argument("--hot", type=int, default=50)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--reconnect-every", type=int, default=200)
    ap.add_argument("--doq-share", type=float, default=0.3)
    args = ap.parse_args()
    if not os.path.exists(STAGE_CA):
        raise SystemExit("stage CA missing (run mkcerts.sh)")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
