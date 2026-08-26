// Magazine-style cache, client edition: fixed byte budget, FIFO eviction from
// the tail of insertion order, per-entry lifetime cap. Same shape as the
// box's MagCache minus geo clustering and parent bookkeeping — a stub has one
// vantage point, so keys are just (lowercased qname, qtype, qclass, DO).
//
// Stored answers carry a zeroed transaction ID; the requester's ID is patched
// in at delivery time, never stored. On a hit the remaining DNS TTLs are aged
// by the entry's residence time; an entry whose any RR would expire is dropped.
use crate::dnsmsg;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

struct Entry {
    msg: Vec<u8>,
    base: Instant,
}

const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

pub struct MagCache {
    cap_bytes: usize,
    ttl: Duration,
    map: HashMap<Vec<u8>, Entry>,
    order: VecDeque<Vec<u8>>,
    bytes: usize,
    last_sweep: Instant,
    pub hits: u64,
    pub misses: u64,
    pub evicts: u64,
    pub expired: u64,
    pub inserts: u64,
}

impl MagCache {
    pub fn new(cap_bytes: usize, ttl: Duration) -> Self {
        MagCache {
            cap_bytes,
            ttl,
            map: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            last_sweep: Instant::now(),
            hits: 0,
            misses: 0,
            evicts: 0,
            expired: 0,
            inserts: 0,
        }
    }

    /// Cache lookup. Returns an owned copy with TTLs aged down to their
    /// remaining lifetime (requester still patches its own txid onto it).
    pub fn get(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_at(key, Instant::now())
    }

    pub(crate) fn get_at(&mut self, key: &[u8], now: Instant) -> Option<Vec<u8>> {
        let Some(e) = self.map.get(key) else {
            self.misses += 1;
            self.maybe_sweep(now);
            return None;
        };
        let Some(age) = now.checked_duration_since(e.base) else {
            // clock went backwards between put and get: treat as fresh
            return Some(e.msg.clone());
        };
        if age >= self.ttl {
            self.drop_entry(key);
            self.expired += 1;
            self.misses += 1;
            return None;
        }
        let cap = self.ttl.as_secs() as u32;
        let mut msg = e.msg.clone();
        if !dnsmsg::patch_ttls(&mut msg, age.as_secs() as u32, cap) {
            self.drop_entry(key);
            self.expired += 1;
            self.misses += 1;
            return None;
        }
        self.hits += 1;
        Some(msg)
    }

    /// Insert an upstream answer. The transaction ID is zeroed before storage;
    /// oversized entries (> 1/8 of the budget) are refused outright.
    pub fn put(&mut self, key: Vec<u8>, mut msg: Vec<u8>) {
        if msg.len() >= 2 {
            msg[0] = 0;
            msg[1] = 0;
        }
        let sz = key.len() + msg.len();
        if sz > self.cap_bytes / 8 || self.map.contains_key(&key) {
            return;
        }
        while self.bytes + sz > self.cap_bytes {
            match self.order.pop_front() {
                Some(k) => self.drop_entry(&k),
                None => break,
            }
        }
        self.bytes += sz;
        self.order.push_back(key.clone());
        self.map.insert(
            key,
            Entry {
                msg,
                base: Instant::now(),
            },
        );
        self.inserts += 1;
    }

    fn drop_entry(&mut self, key: &[u8]) {
        if let Some(e) = self.map.remove(key) {
            self.bytes -= key.len() + e.msg.len();
            self.evicts += 1;
        }
    }

    fn maybe_sweep(&mut self, now: Instant) {
        if now.duration_since(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        let ttl = self.ttl;
        let dead: Vec<Vec<u8>> = self
            .map
            .iter()
            .filter(|(_, e)| now.checked_duration_since(e.base).unwrap_or_default() >= ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for k in dead {
            self.drop_entry(&k);
            self.expired += 1;
        }
    }

    /// (entries, bytes, hits, misses) — test/diagnostics hook.
    #[cfg(test)]
    pub fn snapshot(&self) -> (usize, usize, u64, u64) {
        (self.map.len(), self.bytes, self.hits, self.misses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsmsg::ParsedQuery;

    fn key_for(name: &[u8], qtype: u16) -> Vec<u8> {
        dnsmsg::cache_key(&ParsedQuery {
            id: [0, 0],
            qname: name.to_vec(),
            qtype,
            qclass: 1,
            do_bit: false,
        })
    }

    /// One question + one A answer with the given TTL, requester id 0x1234.
    fn answer(ttl: u32) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend_from_slice(b"\x07example\x03com\x00");
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&[0xc0, 0x0c]);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[203, 0, 113, 1]);
        m
    }

    #[test]
    fn hit_serves_aged_answer_with_zeroed_id() {
        let mut c = MagCache::new(65536, Duration::from_secs(300));
        let k = key_for(b"\x07example\x03com\x00", 1);
        c.put(k.clone(), answer(300));
        let t0 = Instant::now();

        let got = c.get_at(&k, t0 + Duration::from_secs(100)).unwrap();
        assert_eq!((got[0], got[1]), (0, 0), "stored id must be zeroed");
        // served TTL ≈ 300 − 100 (residence time), never above
        // answer RR tail: type(2) class(2) ttl(4) rdlen(2) rdata(4)
        let t = got.len() - 10;
        let served_ttl = u32::from_be_bytes([got[t], got[t + 1], got[t + 2], got[t + 3]]);
        assert!(
            (194..=200).contains(&served_ttl),
            "aged ttl {served_ttl}, want ~200"
        );
        assert_eq!(c.snapshot().2, 1, "one hit");
    }

    #[test]
    fn miss_and_expiry_counted() {
        let mut c = MagCache::new(65536, Duration::from_secs(300));
        let k = key_for(b"\x07example\x03com\x00", 1);
        let t0 = Instant::now();

        assert!(c.get_at(&k, t0).is_none(), "cold cache misses");
        assert_eq!(c.snapshot().3, 1);

        c.put(k.clone(), answer(300));
        assert!(
            c.get_at(&k, t0 + Duration::from_secs(301)).is_none(),
            "expired"
        );
        assert!(
            c.get_at(&k, t0 + Duration::from_secs(302)).is_none(),
            "stays gone"
        );
        let (_, _, hits, misses) = c.snapshot();
        assert_eq!((hits, misses), (0, 3), "expiry counts as miss");
    }

    #[test]
    fn fifo_eviction_respects_byte_budget() {
        let mut c = MagCache::new(2048, Duration::from_secs(300));
        let val = answer(60); // ~55 bytes
        for i in 0..40u8 {
            let k = key_for(format!("\x04n{i:\x30>4}\x00").as_bytes(), 1);
            c.put(k, val.clone());
        }
        let (entries, bytes, _, _) = c.snapshot();
        assert!(bytes <= 2048, "{bytes} bytes over budget");
        assert!(entries < 40, "eviction had to run");
        assert!(c.evicts > 0, "FIFO evictions recorded");
    }

    #[test]
    fn oversized_entries_are_refused_not_truncated() {
        let mut c = MagCache::new(1024, Duration::from_secs(300)); // max single entry 128B
        let big = vec![0xa5u8; 600];
        let k = key_for(b"\x04bigg\x00", 1);
        c.put(k.clone(), big);
        assert_eq!(c.snapshot().0, 0, "entry larger than budget/8 rejected");
    }

    #[test]
    fn do_bit_and_qtype_separate_entries() {
        let mut c = MagCache::new(65536, Duration::from_secs(300));
        let k_plain = key_for(b"\x07example\x03com\x00", 1);
        let mut pq_do = ParsedQuery {
            id: [0, 0],
            qname: b"\x07example\x03com\x00".to_vec(),
            qtype: 1,
            qclass: 1,
            do_bit: true,
        };
        let k_do = dnsmsg::cache_key(&pq_do);
        assert_ne!(k_plain, k_do);
        c.put(k_plain.clone(), answer(300));
        assert!(c.get(&k_do).is_none(), "DO variant is its own entry");
        assert!(c.get(&k_plain).is_some());
        pq_do.qtype = 28;
        assert_ne!(k_plain, dnsmsg::cache_key(&pq_do), "qtype separates");
    }
}
