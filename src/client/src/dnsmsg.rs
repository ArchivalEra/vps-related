// Minimal, bounds-checked DNS wire helpers for the client side: question
// parsing for the cache key, transaction-ID patching, TTL aging of cached
// answers, SERVFAIL synthesis. Deliberately smaller than the box's dnsmsg:
// the client never rewrites queries (EDNS/ECS ride through untouched).
pub const OPT_TYPE: u16 = 41;

#[derive(Debug, Clone)]
pub struct ParsedQuery {
    pub id: [u8; 2],
    /// expanded wire-format labels, original case, root label included
    pub qname: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
    pub do_bit: bool,
}

#[inline]
pub fn be16(m: &[u8], off: usize) -> Option<u16> {
    if off + 2 > m.len() {
        return None;
    }
    Some(u16::from_be_bytes([m[off], m[off + 1]]))
}

#[inline]
pub fn be32(m: &[u8], off: usize) -> Option<u32> {
    if off + 4 > m.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        m[off],
        m[off + 1],
        m[off + 2],
        m[off + 3],
    ]))
}

/// Skip over a (possibly compressed) name; returns the offset just past the
/// name as stored at `off` (a pointer is 2 bytes and not followed).
fn skip_name(m: &[u8], mut off: usize) -> Option<usize> {
    let mut hops = 0usize;
    loop {
        if off >= m.len() {
            return None;
        }
        let l = m[off];
        if l & 0xC0 == 0xC0 {
            if off + 2 > m.len() {
                return None;
            }
            return Some(off + 2);
        }
        if l & 0xC0 != 0 {
            return None;
        }
        let l = l as usize;
        if l == 0 {
            return Some(off + 1);
        }
        off += 1;
        off += l;
        hops += 1;
        if hops > 128 {
            return None;
        }
    }
}

/// Expand a possibly-compressed name into plain wire labels.
fn expand_name(m: &[u8], mut off: usize) -> Option<(Vec<u8>, usize)> {
    let mut out: Vec<u8> = Vec::with_capacity(32);
    let mut end: Option<usize> = None;
    let mut jumps = 0usize;
    loop {
        if off >= m.len() {
            return None;
        }
        let l = m[off];
        if l & 0xC0 == 0xC0 {
            if off + 2 > m.len() {
                return None;
            }
            let target = (((l & 0x3F) as usize) << 8) | m[off + 1] as usize;
            if end.is_none() {
                end = Some(off + 2);
            }
            jumps += 1;
            if jumps > 64 || target >= m.len() {
                return None;
            }
            off = target;
            continue;
        }
        if l & 0xC0 != 0 {
            return None;
        }
        let l = l as usize;
        if l == 0 {
            out.push(0);
            return Some((out, end.unwrap_or(off + 1)));
        }
        off += 1;
        if off + l > m.len() {
            return None;
        }
        out.push(l as u8);
        out.extend_from_slice(&m[off..off + l]);
        off += l;
    }
}

/// Parse an inbound client query. Returns None for responses, non-QUERY
/// opcodes, QDCOUNT != 1 or malformed wire — callers fall back to raw
/// passthrough (no cache, straight upstream).
pub fn parse_query(m: &[u8]) -> Option<ParsedQuery> {
    if m.len() < 12 {
        return None;
    }
    if m[2] & 0x80 != 0 {
        return None; // QR set: this is a response
    }
    if (m[2] >> 3) & 0x0F != 0 {
        return None; // opcode != QUERY → passthrough
    }
    let qdcount = be16(m, 4)?;
    if qdcount != 1 {
        return None;
    }
    let (qname, qend) = expand_name(m, 12)?;
    let qend = qend.checked_add(4)?;
    if qend > m.len() {
        return None;
    }
    let qtype = be16(m, qend - 4)?;
    let qclass = be16(m, qend - 2)?;
    // EDNS0 DO bit lives in the additional section's OPT record TTL field;
    // a malformed additional section only means we miss the DO bit
    let arcount = be16(m, 10).unwrap_or(0) as usize;
    let mut do_bit = false;
    let mut off = qend;
    for _ in 0..arcount {
        let Some(name_end) = skip_name(m, off) else {
            break;
        };
        if name_end + 10 > m.len() {
            break;
        }
        let rtype = be16(m, name_end).unwrap_or(0);
        let ttl = be32(m, name_end + 4).unwrap_or(0);
        if rtype == OPT_TYPE {
            do_bit = ttl & 0x8000_0000 != 0;
        }
        let rdlen = match be16(m, name_end + 8) {
            Some(v) => v as usize,
            None => break,
        };
        off = name_end + 10 + rdlen;
        if off > m.len() {
            break;
        }
    }
    Some(ParsedQuery {
        id: [m[0], m[1]],
        qname,
        qtype,
        qclass,
        do_bit,
    })
}

/// Lowercased qname + type + class + DO flag: the magazine cache key.
pub fn cache_key(pq: &ParsedQuery) -> Vec<u8> {
    let mut k = Vec::with_capacity(pq.qname.len() + 7);
    k.extend(pq.qname.iter().map(|b| b.to_ascii_lowercase()));
    k.extend_from_slice(&pq.qtype.to_be_bytes());
    k.extend_from_slice(&pq.qclass.to_be_bytes());
    k.push(pq.do_bit as u8);
    k
}

#[inline]
pub fn patch_id(m: &mut [u8], id: &[u8; 2]) {
    if m.len() >= 2 {
        m[0] = id[0];
        m[1] = id[1];
    }
}

/// Age every answer/authority RR by `age` seconds (additional records are NOT
/// walked — that section carries the OPT pseudo-RR whose "TTL" is flags).
/// Returns false when any record would expire now: the entry must be dropped.
pub fn patch_ttls(m: &mut [u8], age: u32, cap: u32) -> bool {
    if m.len() < 12 {
        return false;
    }
    let an = u16::from_be_bytes([m[6], m[7]]) as usize;
    let ns = u16::from_be_bytes([m[8], m[9]]) as usize;
    let mut off = match skip_name(m, 12) {
        Some(o) => o + 4,
        None => return false,
    };
    for count in [an, ns] {
        for _ in 0..count {
            off = match skip_name(m, off) {
                Some(o) => o,
                None => return false,
            };
            if off + 10 > m.len() {
                return false;
            }
            let orig = be32(m, off + 4).unwrap_or(0);
            let capped = orig.min(cap);
            if capped <= age {
                return false;
            }
            m[off + 4..off + 8].copy_from_slice(&(capped - age).to_be_bytes());
            let rdlen = be16(m, off + 8).unwrap_or(0) as usize;
            off += 10 + rdlen;
            if off > m.len() {
                return false;
            }
        }
    }
    true
}

/// SERVFAIL reply for a raw query, keeping the question section when parseable.
pub fn make_servfail(q: &[u8]) -> Vec<u8> {
    let mut v = q.to_vec();
    if v.len() < 12 {
        let mut m = vec![0u8; 12];
        m[2] = 0x80;
        m[3] = 2;
        return m;
    }
    v[2] = 0x80 | (v[2] & 0x78) | (v[2] & 0x01); // QR=1, keep opcode+RD
    v[3] = (v[3] & 0xF0) | 2; // RA stays clear, RCODE=SERVFAIL
                              // keep QDCOUNT (question bytes stay); zero answer/authority/additional
    v[6..12].fill(0);
    match skip_name(q, 12) {
        Some(o) if o + 4 <= q.len() => v.truncate(o + 4),
        _ => v.truncate(12),
    }
    v
}

/// Debug-printable qname ("a.b.example.") for future verbose logging.
#[allow(dead_code)]
pub fn qname_str(wire: &[u8]) -> String {
    let mut s = String::new();
    let mut off = 0usize;
    while off < wire.len() {
        let l = wire[off] as usize;
        if l == 0 {
            break;
        }
        off += 1;
        if off + l > wire.len() {
            break;
        }
        s.push_str(&String::from_utf8_lossy(&wire[off..off + l]));
        s.push('.');
        off += l;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_bytes(qname: &str, qtype: u16) -> Vec<u8> {
        // header with RD + one question, no EDNS
        let mut m = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(qname.as_bytes());
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m
    }

    #[test]
    fn parse_plain_query() {
        let m = query_bytes("\x07example\x03com\x00", 1);
        let pq = parse_query(&m).unwrap();
        assert_eq!(pq.id, [0xab, 0xcd]);
        assert_eq!(pq.qname, b"\x07example\x03com\x00".to_vec());
        assert_eq!(pq.qtype, 1);
        assert!(!pq.do_bit);
    }

    #[test]
    fn parse_query_with_edns_do_bit() {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        m.extend_from_slice(b"\x03www\x07example\x03com\x00");
        m.extend_from_slice(&28u16.to_be_bytes()); // AAAA
        m.extend_from_slice(&1u16.to_be_bytes());
        // OPT: root, type 41, udpsize 1232, TTL with DO set
        m.push(0);
        m.extend_from_slice(&OPT_TYPE.to_be_bytes());
        m.extend_from_slice(&1232u16.to_be_bytes());
        m.extend_from_slice(&0x8000_0000u32.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        let pq = parse_query(&m).unwrap();
        assert!(pq.do_bit);
        assert_eq!(pq.qtype, 28);
    }

    #[test]
    fn responses_and_garbage_rejected() {
        let mut m = query_bytes("\x01a\x00", 1);
        m[2] |= 0x80; // QR
        assert!(parse_query(&m).is_none(), "responses are not queries");
        assert!(parse_query(&[0u8; 5]).is_none());
        assert!(parse_query(&[]).is_none());
    }

    #[test]
    fn servfail_echoes_question_with_rcode_2() {
        let m = query_bytes("\x07example\x03com\x00", 16);
        let sf = make_servfail(&m);
        assert_eq!(&sf[..2], &[0xab, 0xcd], "requester txid preserved");
        assert_eq!(sf[2] & 0x80, 0x80, "QR set");
        assert_eq!(sf[3] & 0x0F, 2, "RCODE=SERVFAIL");
        assert_eq!(sf.len(), m.len(), "header + question only");
        assert_eq!(be16(&sf, 6), Some(0), "answer count zeroed");
    }

    #[test]
    fn ttl_aging_walks_answers_only_and_expires() {
        // one question + one answer A record with TTL 300
        let mut msg = vec![0, 1, 0x01, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        msg.extend_from_slice(b"\x07example\x03com\x00");
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        // answer: pointer to qname, A, IN, ttl=300, rdlen=4, rdata
        msg.extend_from_slice(&[0xc0, 0x0c]);
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[192, 0, 2, 1]);

        assert!(patch_ttls(&mut msg, 100, 600), "still alive at age 100");
        // answer RR layout: name(2 ptr) type(2) class(2) ttl(4) rdlen(2) rdata(4)
        let ttl_off = msg.len() - 10;
        assert_eq!(be32(&msg, ttl_off), Some(200), "ttl decremented");
        assert!(!patch_ttls(&mut msg, 300, 600), "expired at full age");
        assert!(!patch_ttls(&mut msg, 999, 600), "cap makes it older still");
    }

    #[test]
    fn cache_key_is_case_insensitive_on_name_only() {
        let a = parse_query(&query_bytes("\x03WWW\x07Example\x03COM\x00", 1)).unwrap();
        let b = parse_query(&query_bytes("\x03www\x07example\x03com\x00", 1)).unwrap();
        assert_eq!(cache_key(&a), cache_key(&b));
        let c = parse_query(&query_bytes("\x03www\x07example\x03com\x00", 28)).unwrap();
        assert_ne!(cache_key(&b), cache_key(&c), "qtype separates entries");
    }

    #[test]
    fn qname_printable() {
        assert_eq!(
            qname_str(b"\x03www\x07example\x03com\x00"),
            "www.example.com."
        );
    }
}
