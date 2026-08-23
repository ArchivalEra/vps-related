// Minimal, bounds-checked DNS wire helpers: question parsing, key building,
// upstream query rebuild, TTL patching, SERVFAIL synthesis.
pub const OPT_TYPE: u16 = 41;

#[derive(Debug, Clone)]
pub struct ParsedQuery {
    pub id: [u8; 2],
    pub qname: Vec<u8>, // expanded wire-format labels, original case, root label included
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
    Some(u32::from_be_bytes([m[off], m[off + 1], m[off + 2], m[off + 3]]))
}

/// Skip over a (possibly compressed) name; returns offset just past the name as
/// stored at `off` (pointer = 2 bytes, not followed).
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
        off += 1 + l;
        hops += 1;
        if hops > 128 {
            return None;
        }
    }
}

/// Expand a possibly-compressed name into plain wire labels. Returns
/// (expanded_name, offset_past_name_in_original_location).
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
            let e = end.unwrap_or(off + 1);
            return Some((out, e));
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

/// Parse a client query. Returns None for responses, non-QUERY opcode,
/// QDCOUNT != 1 or malformed wire (caller falls back to raw passthrough).
pub fn parse_query(m: &[u8]) -> Option<ParsedQuery> {
    if m.len() < 12 {
        return None;
    }
    if m[2] & 0x80 != 0 {
        return None; // QR set: this is a response
    }
    if (m[2] >> 3) & 0x0F != 0 {
        return None; // opcode != QUERY -> passthrough
    }
    if be16(m, 4)? != 1 {
        return None; // QDCOUNT != 1 -> passthrough
    }
    let (qname, mut off) = expand_name(m, 12)?;
    if qname.len() > 255 {
        return None;
    }
    let qtype = be16(m, off)?;
    let qclass = be16(m, off + 2)?;
    off += 4;
    // skip answer + authority sections (queries normally have none)
    for count in [be16(m, 6)? as usize, be16(m, 8)? as usize] {
        for _ in 0..count {
            off = skip_name(m, off)?;
            let rdlen = be16(m, off + 8)? as usize;
            off += 10 + rdlen;
            if off > m.len() {
                return None;
            }
        }
    }
    // additional: look for OPT to find the DO bit; be lenient on garbage
    let mut do_bit = false;
    let ar = be16(m, 10)? as usize;
    for _ in 0..ar {
        let name_end = match skip_name(m, off) {
            Some(v) => v,
            None => break,
        };
        let rtype = match be16(m, name_end) {
            Some(v) => v,
            None => break,
        };
        if rtype == OPT_TYPE {
            if let Some(ttl) = be32(m, name_end + 4) {
                do_bit = ttl & 0x8000_0000 != 0;
            }
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

/// Lowercased qname + type + class + DO flag: the cache / single-flight key.
pub fn cache_key(pq: &ParsedQuery) -> Vec<u8> {
    let mut k = Vec::with_capacity(pq.qname.len() + 6);
    k.extend(pq.qname.iter().map(|b| b.to_ascii_lowercase()));
    k.extend_from_slice(&pq.qtype.to_be_bytes());
    k.extend_from_slice(&pq.qclass.to_be_bytes());
    k.push(pq.do_bit as u8);
    k
}

/// Build a fresh upstream query from the parsed client question.
pub fn build_query(pq: &ParsedQuery) -> Vec<u8> {
    let mut v = Vec::with_capacity(12 + pq.qname.len() + 4 + 11);
    v.extend_from_slice(&pq.id);
    v.push(0x01); // RD
    v.push(0x00);
    v.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    v.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    v.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    v.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT
    v.extend_from_slice(&pq.qname);
    v.extend_from_slice(&pq.qtype.to_be_bytes());
    v.extend_from_slice(&pq.qclass.to_be_bytes());
    // OPT: name=root, type=41, udpsize=1232, TTL.DO
    v.push(0x00);
    v.extend_from_slice(&OPT_TYPE.to_be_bytes());
    v.extend_from_slice(&1232u16.to_be_bytes());
    v.extend_from_slice(&if pq.do_bit { 0x8000_0000u32 } else { 0u32 }.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    v
}

/// Cheap probe query used by upstream health checks.
pub fn build_probe_query() -> Vec<u8> {
    let pq = ParsedQuery {
        id: [0x1a, 0x2b],
        qname: b"\x03www\x07example\x03com\x00".to_vec(),
        qtype: 1,
        qclass: 1,
        do_bit: false,
    };
    build_query(&pq)
}

#[inline]
pub fn patch_id(m: &mut [u8], id: &[u8; 2]) {
    if m.len() >= 2 {
        m[0] = id[0];
        m[1] = id[1];
    }
}

#[inline]
pub fn rcode(m: &[u8]) -> u8 {
    if m.len() >= 4 {
        m[3] & 0x0F
    } else {
        2
    }
}

#[inline]
pub fn is_truncated(m: &[u8]) -> bool {
    m.len() >= 4 && m[2] & 0x02 != 0
}

/// Rewrite TTLs of answer+authority RRs: served_ttl = min(orig, cap) - age.
/// Returns false when anything reaches zero (entry counts as expired).
pub fn patch_ttls(m: &mut [u8], age: u32, cap: u32) -> bool {
    if m.len() < 12 {
        return false;
    }
    let an = u16::from_be_bytes([m[6], m[7]]) as usize;
    let ns = u16::from_be_bytes([m[8], m[9]]) as usize;
    let off = match skip_name(m, 12) {
        Some(o) => o + 4,
        None => return false,
    };
    let mut off = off;
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
            let nt = capped - age;
            m[off + 4..off + 8].copy_from_slice(&nt.to_be_bytes());
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
    v[2] = 0x80 | (v[2] & 0x78) | (v[2] & 0x01);
    v[3] = 2;
    v[4..12].fill(0);
    match skip_name(q, 12) {
        Some(o) if o + 4 <= q.len() => {
            v.truncate(o + 4);
        }
        _ => v.truncate(12),
    }
    v
}

/// Debug-ish printable qname ("a.b.test.")
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
    if s.is_empty() {
        s.push('.');
    }
    s
}
