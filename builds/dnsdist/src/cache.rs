// Magazine-style cache: fixed byte budget, FIFO eviction from the tail of
// insertion order, per-entry lifetime cap. Memory only, no disk.
use crate::dnsmsg;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

struct Entry {
    msg: Vec<u8>,
    base: Instant,
}

pub struct MagCache {
    cap_bytes: usize,
    ttl: Duration,
    map: HashMap<Vec<u8>, Entry>,
    order: VecDeque<Vec<u8>>, // insertion order; front = oldest ("tail of the magazine")
    bytes: usize,
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
    pub expired: u64,
    pub evicts: u64,
    pub inserts: u64,
}

impl MagCache {
    pub fn new(cap_bytes: usize, ttl_secs: u64) -> Self {
        MagCache {
            cap_bytes,
            ttl: Duration::from_secs(ttl_secs),
            map: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            hits: 0,
            misses: 0,
            expired: 0,
            evicts: 0,
            inserts: 0,
        }
    }

    /// Hit only if within the entry lifetime and every answer TTL still has
    /// time left after decrementing. Returned message has TTLs patched.
    pub fn get(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let now = Instant::now();
        let cap = self.ttl.as_secs() as u32;
        let expired = match self.map.get(key) {
            Some(e) => now.duration_since(e.base) >= self.ttl,
            None => {
                self.misses += 1;
                return None;
            }
        };
        if expired {
            if let Some(e) = self.map.remove(key) {
                self.bytes -= key.len() + e.msg.len();
            }
            self.expired += 1;
            self.misses += 1;
            return None;
        }
        let age = now.duration_since(self.map.get(key).unwrap().base).as_secs() as u32;
        let mut msg = match self.map.get(key) {
            Some(e) => e.msg.clone(),
            None => return None,
        };
        if !dnsmsg::patch_ttls(&mut msg, age, cap) {
            if let Some(e) = self.map.remove(key) {
                self.bytes -= key.len() + e.msg.len();
            }
            self.expired += 1;
            self.misses += 1;
            return None;
        }
        self.hits += 1;
        Some(msg)
    }

    /// Insert; evict oldest entries from the front until the new entry fits.
    pub fn put(&mut self, key: Vec<u8>, msg: Vec<u8>) {
        let sz = key.len() + msg.len();
        if sz > self.cap_bytes / 8 {
            return; // oversized responses are not worth the whole magazine
        }
        if self.map.contains_key(&key) {
            return;
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
        self.map.insert(key, Entry { msg, base: Instant::now() });
        self.inserts += 1;
    }

    pub fn snapshot(&self) -> CacheSnap {
        CacheSnap {
            entries: self.map.len(),
            bytes: self.bytes,
            cap_bytes: self.cap_bytes,
            ttl_secs: self.ttl.as_secs(),
            expired: self.expired,
            evicts: self.evicts,
            inserts: self.inserts,
        }
    }
}
