#!/usr/bin/env python3
"""Mock DoQ upstream (RFC 9250, ALPN doq) on aioquic.
One query per bidirectional stream, 2-byte length-prefixed frames.
Logs 'MOCKHIT doq <qname> <qtype>'."""
import argparse
import asyncio
import ssl

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

from canned import build_response, parse_question

ARGS = None


class DoQProtocol(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.bufs = {}

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            sid = event.stream_id
            buf = self.bufs.get(sid, b"") + event.data
            if len(buf) >= 2:
                n = int.from_bytes(buf[:2], "big")
                if len(buf) >= 2 + n:
                    q = buf[2 : 2 + n]
                    p = parse_question(q)
                    name, qt = (p[0], p[1]) if p else ("?", 0)
                    print(f"MOCKHIT doq {name} {qt}", flush=True)
                    r = build_response(q, ARGS.ttl)
                    self._quic.send_stream_data(
                        sid, len(r).to_bytes(2, "big") + r, end_stream=True
                    )
                    self.transmit()
                    self.bufs.pop(sid, None)
                    return
            self.bufs[sid] = buf


def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=1854)
    ap.add_argument("--ttl", type=int, default=3600)
    ap.add_argument("--cert", default="certs/upstream.pem")
    ap.add_argument("--key", default="certs/upstream.key")
    ARGS = ap.parse_args()

    cfg = QuicConfiguration(is_client=False, alpn_protocols=["doq"])
    cfg.load_cert_chain(ARGS.cert, ARGS.key)
    print(f"mockdoq listening 127.0.0.1:{ARGS.port}", flush=True)

    async def amain():
        # serve() returns a QuicServer immediately; hold the loop open forever
        await serve("127.0.0.1", ARGS.port, configuration=cfg, create_protocol=DoQProtocol)
        await asyncio.Event().wait()

    asyncio.run(amain())


if __name__ == "__main__":
    main()
