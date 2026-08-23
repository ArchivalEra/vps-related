#!/usr/bin/env python3
"""Shared canned-response builder for the stage mocks (loopback test rig)."""
import struct


def parse_question(msg):
    """Return (qname_str, qtype, qclass) for a query with QDCOUNT=1, else None."""
    if len(msg) < 12:
        return None
    if struct.unpack_from("!H", msg, 4)[0] != 1:
        return None
    labels = []
    i = 12
    while True:
        if i >= len(msg):
            return None
        l = msg[i]
        if l == 0:
            i += 1
            break
        if l & 0xC0:
            return None  # no compression expected in queries
        if i + 1 + l > len(msg):
            return None
        labels.append(msg[i + 1 : i + 1 + l].decode("latin1"))
        i += 1 + l
    if i + 4 > len(msg):
        return None
    qtype, qclass = struct.unpack_from("!HH", msg, i)
    return (".".join(labels), qtype, qclass)


def servfail(query):
    qid = query[0:2]
    return qid + struct.pack("!HHHHH", 0x8182, 0, 0, 0, 0)


def build_response(query, ttl=3600):
    """A -> 192.0.2.7, AAAA -> 2001:db8::7, TXT -> 'stage-mock', else NOERROR empty."""
    p = parse_question(query)
    if p is None:
        return servfail(query)
    qname, qtype, qclass = p
    # question section spans offset 12 .. end-of-question
    i = 12
    while query[i] != 0:
        i += 1 + query[i]
    i += 1 + 4
    qsection = query[12:i]

    ans = b""
    count = 0
    if qtype == 1 and qclass == 1:
        rdata = bytes([192, 0, 2, 7])
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, len(rdata)) + rdata
        count = 1
    elif qtype == 28 and qclass == 1:
        rdata = bytes.fromhex("20010db8000000000000000000000007")
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, ttl, len(rdata)) + rdata
        count = 1
    elif qtype == 16 and qclass == 1:
        txt = b"stage-mock"
        rdata = bytes([len(txt)]) + txt
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, ttl, len(rdata)) + rdata
        count = 1

    hdr = query[0:2] + struct.pack("!HHHHH", 0x8180, 1, count, 0, 1)
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    return hdr + qsection + ans + opt


def rcode_of(msg):
    return msg[3] & 0x0F if len(msg) >= 4 else 2


def ttl_and_answers(msg):
    """Extract (min_ttl, [answer strings]) from a response (best effort)."""
    if len(msg) < 12:
        return (None, [])
    an = struct.unpack_from("!H", msg, 6)[0]
    # skip question
    i = 12
    while msg[i] != 0:
        i += 1 + msg[i]
    i += 5
    ttls = []
    answers = []
    for _ in range(an):
        # skip name (pointer or labels)
        if msg[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while msg[i] != 0:
                i += 1 + msg[i]
            i += 1
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", msg, i)
        i += 10
        rdata = msg[i : i + rdlen]
        i += rdlen
        ttls.append(ttl)
        if rtype == 1 and rdlen == 4:
            answers.append(".".join(str(b) for b in rdata))
        elif rtype == 28 and rdlen == 16:
            answers.append("2001:db8::…")
        else:
            answers.append(f"type{rtype}")
    return (min(ttls) if ttls else None, answers)
