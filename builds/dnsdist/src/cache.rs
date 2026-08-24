// Magazine-style cache: fixed byte budget, FIFO eviction from the tail of
// insertion order, per-entry lifetime cap (optional). Memory only, no disk.
// Owns ALL of its metrics; Stats::dump reads them from CacheSnap.
use crate::dnsmsg;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Entry {
    msg: Arc<Vec<u8>>,
    base: Instant,
}

/// Cache hit: `Shared` bodies were TTL-capped at insert (ignore_ttl mode) and
/// are served zero-copy (the client ID is written as a prefix by the caller);
/// `Owned` is a per-serve patched copy (TTL aging needs the rewrite).
pub enum Hit {
    Shared(Arc<Vec<u8>>),
    Owned(Vec<u8>),
}

pub struct MagCache {
    cap_bytes: usize,
    ttl: Duration,
    ignore_ttl: bool, // magazine-only cleaning: entries never expire by time
    map: HashMap<Vec<u8>, Entry>,
    order: VecDeque<Vec<u8>>, // insertion order; front = oldest ("tail of the magazine")
    bytes: usize,
    last_sweep: Instant,
    pub hits: u64,
    pub misses: u64,
    pub expired: u64,
    pub evicts: u64,
    pub inserts: u64,
}

pub struct CacheSnap {
    pub entries: usize,
    pub bytes: usize,
    pub cap_bytes: usize,
    pub ttl_secs: u64,
    pub ignore_ttl: bool,
    pub hits: u64,
    pub misses: u64,
    pub expired: u64,
    pub evicts: u64,
    pub inserts: u64,
}

const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

impl MagCache {
    pub fn new(cap_bytes: usize, ttl_secs: u64, ignore_ttl: bool) -> Self {
        MagCache {
            cap_bytes,
            ttl: Duration::from_secs(ttl_secs),
            ignore_ttl,
            map: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            last_sweep: Instant::now(),
            hits: 0,
            misses: 0,
            expired: 0,
            evicts: 0,
            inserts: 0,
        }
    }

    fn entry_live(&self, e: &Entry, now: Instant) -> bool {
        self.ignore_ttl || now.duration_since(e.base) < self.ttl
    }

    /// Hit only while the entry is considered live. ignore_ttl mode returns
    /// the shared body (zero-copy, TTLs capped at insert); normal mode
    /// returns a copy with TTLs aged.
    pub fn get(&mut self, key: &[u8]) -> Option<Hit> {
        let now = Instant::now();
        let live = match self.map.get(key) {
            Some(e) => self.entry_live(e, now),
            None => {
                self.misses += 1;
                self.maybe_sweep(now);
                return None;
            }
        };
        if !live {
            if let Some(e) = self.map.remove(key) {
                self.bytes -= key.len() + e.msg.len();
                self.expired += 1;
            }
            self.misses += 1;
            return None;
        }
        let entry_msg = self.map.get(key).unwrap().msg.clone();
        if self.ignore_ttl {
            self.hits += 1;
            return Some(Hit::Shared(entry_msg));
        }
        let age = now.duration_since(self.map.get(key).unwrap().base).as_secs() as u32;
        let cap = self.ttl.as_secs() as u32;
        let mut msg = (*entry_msg).clone();
        if !dnsmsg::patch_ttls(&mut msg, age, cap) {
            if let Some(e) = self.map.remove(key) {
                self.bytes -= key.len() + e.msg.len();
                self.expired += 1;
            }
            self.misses += 1;
            return None;
        }
        self.hits += 1;
        Some(Hit::Owned(msg))
    }

    /// Insert; evict oldest entries from the front until the new entry fits.
    /// Returns the canonical shared body (callers serve it zero-copy with a
    /// 2-byte ID prefix) whether or not it was actually stored.
    pub fn put(&mut self, key: Vec<u8>, mut msg: Vec<u8>) -> Arc<Vec<u8>> {
        if self.ignore_ttl {
            // cap once at insert; hits then never rewrite the body
            let cap = self.ttl.as_secs() as u32;
            let _ = dnsmsg::patch_ttls_min1(&mut msg, 0, cap);
        }
        let arc = Arc::new(msg);
        let sz = key.len() + arc.len();
        if sz > self.cap_bytes / 8 {
            return arc; // oversized responses are not worth the whole magazine
        }
        if self.map.contains_key(&key) {
            return arc;
        }
        while self.bytes + sz > self.cap_bytes {
            match self.order.pop_front() {
                Some(k) => {
                    if let Some(e) = self.map.remove(&k) {
                        self.bytes -= k.len() + e.msg.len();
                        self.evicts += 1;
                    }
                }
                None => break,
            }
        }
        self.bytes += sz;
        self.order.push_back(key.clone());
        self.map.insert(key, Entry { msg: arc.clone(), base: Instant::now() });
        self.inserts += 1;
        arc
    }

    /// Lazy sweep of time-expired entries (no-op in ignore_ttl mode) so an
    /// idle box does not keep peak-load memory forever.
    fn maybe_sweep(&mut self, now: Instant) {
        if self.ignore_ttl || now.duration_since(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        let ttl = self.ttl;
        let mut expired = 0usize;
        self.map.retain(|k, e| {
            let live = now.duration_since(e.base) < ttl;
            if !live {
                self.bytes -= k.len() + e.msg.len();
                expired += 1;
            }
            live
        });
        self.expired += expired as u64;
    }

    /// Hot policy change (SIGHUP): new budget, TTL, ignore flag. TTL applies
    /// retroactively; shrinking evicts from the tail of insertion order.
    pub fn resize(&mut self, cap_bytes: usize, ttl_secs: u64, ignore_ttl: bool) {
        self.cap_bytes = cap_bytes;
        self.ttl = Duration::from_secs(ttl_secs);
        self.ignore_ttl = ignore_ttl;
        while self.bytes > self.cap_bytes {
            match self.order.pop_front() {
                Some(k) => {
                    if let Some(e) = self.map.remove(&k) {
                        self.bytes -= k.len() + e.msg.len();
                        self.evicts += 1;
                    }
                }
                None => break,
            }
        }
    }

    pub fn snapshot(&self) -> CacheSnap {
        CacheSnap {
            entries: self.map.len(),
            bytes: self.bytes,
            cap_bytes: self.cap_bytes,
            ttl_secs: self.ttl.as_secs(),
            ignore_ttl: self.ignore_ttl,
            expired: self.expired,
            evicts: self.evicts,
            inserts: self.inserts,
            hits: self.hits,
            misses: self.misses,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_for(name: &str, ttl: u32) -> (Vec<u8>, Vec<u8>) {
        let pq = crate::dnsmsg::ParsedQuery {
            id: [0, 0],
            qname: name.as_bytes().iter().map(|c| vec![1u8, *c]).flatten().chain(std::iter::once(0u8)).collect(),
            qtype: 1,
            qclass: 1,
            do_bit: false,
        };
        let q = crate::dnsmsg::build_query(&pq);
        let mut v = q.clone();
        v[2] = 0x80;
        v.truncate(v.len() - 11);
        v[6..8].copy_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(b"\xc0\x0c");
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&4u16.to_be_bytes());
        v.extend_from_slice(&[192, 0, 2, 7]);
        (crate::dnsmsg::cache_key(&pq), v)
    }

    #[test]
    fn fifo_eviction_order() {
        let mut c = MagCache::new(1000, 1200, false);
        for i in 0..40 {
            let (k, m) = msg_for(&format!("n{}", i), 3600);
            assert!(m.len() > 20 && m.len() < 40, "msg size {} out of expected range", m.len());
            let _arc = c.put(k, m);
        }
        let snap = c.snapshot();
        assert!(snap.entries >= 5, "expected most entries retained, got {}", snap.entries);
        assert!(c.snapshot().bytes <= 1000);
        // oldest must be gone: first name now misses
        let (k0, _) = msg_for("n0", 3600);
        assert!(c.get(&k0).is_none());
        let (k39, _) = msg_for("n39", 3600);
        assert!(matches!(c.get(&k39), Some(Hit::Owned(_)) | Some(Hit::Shared(_))));
    }

    #[test]
    fn ignore_ttl_never_expires_but_evicts() {
        let mut c = MagCache::new(1_000_000, 0, true); // ttl=0s but ignored
        let (k, m) = msg_for("immortal", 5);
        let _ = c.put(k.clone(), m);
        std::thread::sleep(Duration::from_millis(50));
        // served ttl floored at 1 despite age > ttl; zero-copy shared body
        match c.get(&k).expect("ignore_ttl keeps serving") {
            Hit::Shared(body) => {
                assert!(body.len() > 12);
                let t = u32::from_be_bytes(body[body.len() - 10..body.len() - 6].try_into().unwrap());
                assert_eq!(t, 1, "ttl capped to floor 1 at insert");
            }
            Hit::Owned(_) => panic!("ignore mode must serve zero-copy"),
        }
        assert_eq!(c.snapshot().expired, 0);
    }

    #[test]
    fn sweep_clears_idle_entries() {
        let mut c = MagCache::new(1_000_000, 0, false); // ttl=0: everything instantly stale
        let (k, m) = msg_for("dies", 5);
        c.put(k.clone(), m);
        c.misses = 0;
        c.last_sweep = Instant::now() - Duration::from_secs(10);
        let (other, _) = msg_for("trigger", 5);
        let _ = c.get(&other); // miss triggers sweep
        assert_eq!(c.map.len(), 0);
        assert!(c.snapshot().bytes == 0);
    }
}
