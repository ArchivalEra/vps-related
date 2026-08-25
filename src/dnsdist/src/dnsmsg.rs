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
    Some(u32::from_be_bytes([
        m[off],
        m[off + 1],
        m[off + 2],
        m[off + 3],
    ]))
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
    v.extend_from_slice(&0u16.to_be_bytes()); // rdlen=0; caller appends options via append_ecs_to_query
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

/// Magazine-only mode variant: same math but the served TTL floors at 1s
/// and the walk never declares the entry expired.
pub fn patch_ttls_min1(m: &mut [u8], age: u32, cap: u32) -> bool {
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
            let nt = orig.min(cap).saturating_sub(age).max(1);
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

/// RFC 7871 §10.2 + BCP: address ranges that must NEVER be expressed as
/// EDNS Client Subnet. Household-WiFi clients (RFC1918) and any spoofed
/// local-range source therefore resolve without ECS — the upstream answers
/// from its own vantage point instead of being handed a bogus "geography"
/// (or worse, a pointer at link-local metadata services).
pub fn ecs_source_ok(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()                       // 10/8, 172.16/12, 192.168/16
                || v4.is_loopback()                 // 127/8
                || v4.is_link_local()               // 169.254/16 (incl. cloud metadata)
                || v4.is_unspecified()
                || v4.is_broadcast()                // 255.255.255.255
                || o[0] == 0                        // 0.0.0.0/8 this-network
                || (o[0] == 100 && o[1] >= 64 && o[1] < 128) // 100.64/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)   // 192.0.0.0/24
                || v4.is_documentation()            // TEST-NET-1/2/3
                || o[0] >= 240)                     // 240/4 reserved + broadcast
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()                      // ::1
                || v6.is_unspecified()              // ::
                || (s[0] & 0xfe00) == 0xfe00        // fe80::/10 link-local
                || (s[0] & 0xff00) == 0xfc00        // fc00::/7 ULA
                || v6.is_multicast()                // ff00::/8
                || (s[0] == 0x2001 && s[1] == 0x0db8)) // 2001:db8::/32 doc
        }
    }
}

/// Build EDNS0 Client Subnet option data (RFC 7871).
/// Returns (family, source_prefix, scope_prefix=0, address_bytes).
/// The caller embeds this into the OPT RR's RDATA.
pub fn ecs_option_bytes(ip: std::net::IpAddr, source_prefix: u8) -> Vec<u8> {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            let nbytes = ((source_prefix as usize) + 7) / 8;
            let mut v = vec![0x00, 0x01]; // family = 1 (IPv4)
            v.push(source_prefix);
            v.push(0); // scope prefix (must be 0 in queries)
            v.extend_from_slice(&o[..nbytes.min(4)]);
            v
        }
        std::net::IpAddr::V6(v6) => {
            let o = v6.octets();
            let nbytes = ((source_prefix as usize) + 7) / 8;
            let mut v = vec![0x00, 0x02]; // family = 2 (IPv6)
            v.push(source_prefix);
            v.push(0);
            v.extend_from_slice(&o[..nbytes.min(16)]);
            v
        }
    }
}

/// Append an EDNS0 Client Subnet option to an existing query's OPT RR.
/// Rewrites the OPT RR's RDATA to include the ECS option (code 8).
/// If the query has no OPT, one is appended with the ECS inside.
pub fn append_ecs_to_query(msg: &mut Vec<u8>, ecs_data: &[u8]) {
    // Find existing OPT RR in additional section
    if msg.len() < 12 {
        return;
    }
    let arcount = be16(msg, 10).unwrap_or(0);
    let mut off = 12usize;
    // Skip question
    for _ in 0..be16(msg, 4).unwrap_or(0) {
        if let Some(o) = skip_name(msg, off) {
            off = o + 4;
        } else {
            return;
        }
    }
    // Skip answer + authority
    for count in [be16(msg, 6).unwrap_or(0), be16(msg, 8).unwrap_or(0)] {
        for _ in 0..count {
            if let Some(o) = skip_name(msg, off) {
                off = o;
            } else {
                return;
            }
            let rdlen = match be16(msg, off + 8) {
                Some(v) => v as usize,
                None => return,
            };
            off += 10 + rdlen;
            if off > msg.len() {
                return;
            }
        }
    }
    // Walk additional looking for OPT (type 41)
    for i in 0..arcount {
        let name_end = match skip_name(msg, off) {
            Some(v) => v,
            None => break,
        };
        let rtype = match be16(msg, name_end) {
            Some(v) => v,
            None => break,
        };
        if rtype == OPT_TYPE {
            let rdlen = match be16(msg, name_end + 8) {
                Some(v) => v as usize,
                None => break,
            };
            let rdata_start = name_end + 10;
            // Append ECS option: [option_code=8 (2B)][option_len (2B)][ecs_data]
            let mut new_rdata = msg[rdata_start..rdata_start + rdlen].to_vec();
            new_rdata.extend_from_slice(&8u16.to_be_bytes());
            new_rdata.extend_from_slice(&(ecs_data.len() as u16).to_be_bytes());
            new_rdata.extend_from_slice(ecs_data);
            // Rewrite RDLEN
            let new_rdlen = new_rdata.len() as u16;
            msg[name_end + 8..name_end + 10].copy_from_slice(&new_rdlen.to_be_bytes());
            // Splice: remove old rdata, insert new rdata
            msg.splice(rdata_start..rdata_start + rdlen, new_rdata);
            return;
        }
        let rdlen = match be16(msg, name_end + 8) {
            Some(v) => v as usize,
            None => break,
        };
        off = name_end + 10 + rdlen;
        if off > msg.len() {
            break;
        }
    }
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
    // keep QDCOUNT (question bytes stay); zero answer/authority/additional
    v[6..12].fill(0);
    match skip_name(q, 12) {
        Some(o) if o + 4 <= q.len() => {
            v.truncate(o + 4);
        }
        _ => v.truncate(12),
    }
    v
}

/// REFUSED reply (rcode 5) for rate-limit rejections: unlike SERVFAIL it
/// tells stubs the server refuses to answer, damping retry storms.
pub fn make_refused(q: &[u8]) -> Vec<u8> {
    let mut v = make_servfail(q);
    if v.len() >= 4 {
        v[3] = (v[3] & 0xF0) | 5;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// deterministic LCG: reproducible fuzz sequences, no external deps
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 16
        }
    }

    fn rand_name(rng: &mut Rng) -> Vec<u8> {
        let labels = (rng.next() % 4) as usize + 1;
        let mut wire = Vec::new();
        for _ in 0..labels {
            let len = (rng.next() % 12) as usize + 1;
            let lab: Vec<u8> = (0..len).map(|_| b'a' + (rng.next() % 26) as u8).collect();
            wire.push(lab.len() as u8);
            wire.extend_from_slice(&lab);
        }
        wire.push(0);
        wire
    }

    fn rand_query(rng: &mut Rng) -> ParsedQuery {
        ParsedQuery {
            id: [(rng.next() % 256) as u8, (rng.next() % 256) as u8],
            qname: rand_name(rng),
            qtype: [1u16, 2, 16, 28, 33, 65][(rng.next() % 6) as usize],
            qclass: if rng.next() % 8 == 0 { 3 } else { 1 },
            do_bit: rng.next() % 2 == 0,
        }
    }

    #[test]
    fn parse_build_roundtrip() {
        let mut rng = Rng(0x5eed);
        for _ in 0..2000 {
            let pq = rand_query(&mut rng);
            let msg = build_query(&pq);
            let back = parse_query(&msg).expect("own build must parse");
            assert_eq!(back.qname, pq.qname);
            assert_eq!(back.qtype, pq.qtype);
            assert_eq!(back.qclass, pq.qclass);
            assert_eq!(back.do_bit, pq.do_bit);
            assert_eq!(back.id, pq.id);
            // cache key must be case-insensitive on qname
            let mut upper = pq.clone();
            for b in upper.qname.iter_mut() {
                *b = b.to_ascii_uppercase();
            }
            assert_eq!(cache_key(&pq), cache_key(&upper));
        }
    }

    fn response_with_ttls(ttls: &[u32]) -> Vec<u8> {
        let pq = ParsedQuery {
            id: [0xab, 0xcd],
            qname: b"\x04test\x00".to_vec(),
            qtype: 1,
            qclass: 1,
            do_bit: false,
        };
        let mut v = build_query(&pq);
        v[2] = 0x80; // QR=1
        v.truncate(v.len() - 11); // drop the trailing OPT RR (we add sections below)
        v[6..8].copy_from_slice(&(ttls.len() as u16).to_be_bytes()); // ANCOUNT
        for &t in ttls {
            v.extend_from_slice(b"\xc0\x0c"); // name ptr
            v.extend_from_slice(&1u16.to_be_bytes()); // A
            v.extend_from_slice(&1u16.to_be_bytes()); // IN
            v.extend_from_slice(&t.to_be_bytes());
            v.extend_from_slice(&4u16.to_be_bytes());
            v.extend_from_slice(&[192, 0, 2, 7]);
        }
        v
    }

    #[test]
    fn patch_ttls_math() {
        // orig 3600, cap 1200: ttl after age must be 1200-age until it hits 0
        for age in 0..1200u32 {
            let mut m = response_with_ttls(&[3600]);
            assert!(patch_ttls(&mut m, age, 1200), "age {age}");
            let served = u32::from_be_bytes(m[m.len() - 10..m.len() - 6].try_into().unwrap());
            assert_eq!(served, 1200 - age);
        }
        let mut m = response_with_ttls(&[3600]);
        assert!(!patch_ttls(&mut m, 1200, 1200)); // exhausted -> expired
                                                  // short orig wins over cap
        let mut m = response_with_ttls(&[30]);
        assert!(patch_ttls(&mut m, 20, 1200));
        let served = u32::from_be_bytes(m[m.len() - 10..m.len() - 6].try_into().unwrap());
        assert_eq!(served, 10);
        let mut m = response_with_ttls(&[30]);
        assert!(!patch_ttls(&mut m, 30, 1200));
    }

    #[test]
    fn patch_ttls_walks_all_rrs_and_names() {
        // answer with pointer name + authority section
        let mut m = response_with_ttls(&[300, 200]);
        m[8..10].copy_from_slice(&1u16.to_be_bytes()); // NSCOUNT
        m.extend_from_slice(b"\x02ns\x04test\x00"); // uncompressed name
        m.extend_from_slice(&2u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&600u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[192, 0, 2, 7]);
        assert!(patch_ttls(&mut m, 100, 1200));
        assert_eq!(
            u32::from_be_bytes(m[m.len() - 10..m.len() - 6].try_into().unwrap()),
            500
        );
    }

    #[test]
    fn parse_rejects_malformed() {
        // QR set
        let pq = ParsedQuery {
            id: [0, 0],
            qname: b"\x01a\x00".to_vec(),
            qtype: 1,
            qclass: 1,
            do_bit: false,
        };
        let mut m = build_query(&pq);
        m[2] |= 0x80;
        assert!(parse_query(&m).is_none());
        // opcode != QUERY
        let mut m = build_query(&pq);
        m[2] |= 0x08;
        assert!(parse_query(&m).is_none());
        // QDCOUNT = 2
        let mut m = build_query(&pq);
        m[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert!(parse_query(&m).is_none());
        // compression pointer loop in question
        let mut m = build_query(&pq);
        m[12] = 0xc0;
        m[13] = 0x0c;
        assert!(parse_query(&m).is_none());
        // pointer into the future
        let mut m = build_query(&pq);
        m[12] = 0xc0;
        m[13] = 0xff;
        assert!(parse_query(&m).is_none());
        // oversized label runs off the buffer
        let mut m = build_query(&pq);
        m[12] = 0x40;
        assert!(parse_query(&m).is_none());
        // truncated mid-question
        let m = build_query(&pq);
        assert!(parse_query(&m[..13]).is_none());
        // ANCOUNT lies about a section that is not there
        let mut m = build_query(&pq);
        m[6..8].copy_from_slice(&5u16.to_be_bytes());
        assert!(parse_query(&m).is_none());
    }

    #[test]
    fn servfail_keeps_question() {
        let pq = ParsedQuery {
            id: [0x11, 0x22],
            qname: b"\x04test\x00".to_vec(),
            qtype: 28,
            qclass: 1,
            do_bit: false,
        };
        let q = build_query(&pq);
        let r = make_servfail(&q);
        assert_eq!(rcode(&r), 2);
        assert_eq!(&r[0..2], &[0x11, 0x22]);
        assert_eq!(r[4..6], q[4..6]); // QDCOUNT preserved
                                      // question bytes identical
        assert_eq!(&r[12..], &q[12..12 + (r.len() - 12)]);
    }

    #[test]
    fn fuzz_random_buffers_never_panic() {
        let mut rng = Rng(0xf00d);
        for _ in 0..20000 {
            let len = (rng.next() % 300) as usize;
            let buf: Vec<u8> = (0..len).map(|_| (rng.next() % 256) as u8).collect();
            let _ = parse_query(&buf);
            let mut c = buf.clone();
            let _ = patch_ttls(&mut c, 5, 1200);
            let _ = make_servfail(&buf);
            let _ = qname_str(&buf);
        }
    }

    #[test]
    fn ecs_append_grows_by_option_size() {
        let pq = ParsedQuery {
            id: [0x8e, 0x1a],
            qname: b"\x03www\x06google\x03com\x00".to_vec(),
            qtype: 1,
            qclass: 1,
            do_bit: false,
        };
        let mut msg = build_query(&pq);
        let before = msg.len();

        let ecs_data = ecs_option_bytes("49.36.179.100".parse().unwrap(), 24);
        assert_eq!(ecs_data.len(), 7); // family(2)+prefix(1)+scope(1)+addr(3)

        append_ecs_to_query(&mut msg, &ecs_data);

        // Growth = option_code(2) + option_len(2) + ecs_data(7) = 11
        assert_eq!(msg.len(), before + 11);

        // ARCOUNT should be 1
        assert_eq!(u16::from_be_bytes([msg[10], msg[11]]), 1);

        // Round-trip: must still be a valid query
        let parsed = parse_query(&msg).expect("ECS query must parse");
        assert_eq!(parsed.qtype, 1);
    }

    #[test]
    fn ecs_option_data_format() {
        // Verify ECS option data format per RFC 7871 §4.2
        let ecs = ecs_option_bytes("49.36.179.100".parse().unwrap(), 24);
        assert_eq!(ecs.len(), 7); // family(2)+prefix(1)+scope(1)+addr(3)
        assert_eq!(&ecs[0..2], &[0x00, 0x01]); // family=IPv4
        assert_eq!(ecs[2], 24); // source prefix
        assert_eq!(ecs[3], 0); // scope=0 in queries
        assert_eq!(&ecs[4..], &[49, 36, 179]); // first 3 bytes of IP

        let ecs6 = ecs_option_bytes("2001:db8::1".parse().unwrap(), 56);
        assert_eq!(ecs6.len(), 11); // family(2)+prefix(1)+scope(1)+addr(7) for /56
        assert_eq!(&ecs6[0..2], &[0x00, 0x02]); // family=IPv6
    }

    #[test]
    fn ecs_source_banlist() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let ok = |s: &str| ecs_source_ok(s.parse::<IpAddr>().unwrap());
        // public answers are fine
        assert!(ok("8.8.8.8") && ok("2001:4860:4860::8888") && ok("1.1.1.1"));
        // every banned range
        for bad in [
            "10.0.0.9", "172.16.1.1", "192.168.1.7",       // RFC1918
            "127.0.0.1", "127.9.9.9",                      // loopback
            "169.254.169.254",                             // link-local metadata
            "100.64.0.1", "100.127.255.254",               // CGNAT
            "0.0.0.5",                                     // this-network
            "192.0.0.9", "192.0.2.9", "198.51.100.9", "203.0.113.9", // reserved/TEST-NET
            "240.0.0.1", "255.255.255.255",                // reserved/broadcast
        ] {
            assert!(!ok(bad), "{bad} must be banned as ECS");
        }
        let _ = (Ipv4Addr::new(0, 0, 0, 0), Ipv6Addr::LOCALHOST);
        for bad in ["fe80::1", "fc00::5", "ff02::1", "::1", "::", "2001:db8::9"] {
            assert!(!ok(bad), "{bad} must be banned as ECS");
        }
    }
}
