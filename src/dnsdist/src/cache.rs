// Magazine-style geo-aware cache: fixed byte budget, FIFO eviction from the
// tail of insertion order, per-entry lifetime cap (optional). Entries are
// keyed by (qname+qtype+qclass+DO + geo_cluster) — the parent key groups
// children by domain; the cluster dimension separates CDN answers per metro.
use crate::dnsmsg;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Geographic cluster derived from client IP.
///   IPv4 /20 ≈ same metro (~4096 /24s)
///   IPv6 /44 ≈ same city
///   0 = shared/global entry
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GeoCluster(pub u64);

impl GeoCluster {
    pub fn from_client_ip(ip: std::net::IpAddr) -> Self {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                let c = ((o[0] as u64) << 56)
                    | ((o[1] as u64) << 48)
                    | (((o[2] as u64) & 0xF0) << 40);
                GeoCluster(c | 0x4000_0000_0000_0000)
            }
            std::net::IpAddr::V6(v6) => {
                let s = v6.segments();
                let c = ((s[0] as u64) << 48)
                    | ((s[1] as u64) << 32)
                    | (((s[2] as u64) & 0xFFF0) << 16);
                GeoCluster(c | 0x8000_0000_0000_0000)
            }
        }
    }

    pub fn shared() -> Self {
        GeoCluster(0)
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

struct Entry {
    msg: Arc<Vec<u8>>,
    base: Instant,
}

pub enum Hit {
    Shared(Arc<Vec<u8>>),
    Owned(Vec<u8>),
}

const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

pub struct MagCache {
    cap_bytes: usize,
    ttl: Duration,
    ignore_ttl: bool,
    map: HashMap<Vec<u8>, Entry>,
    order: VecDeque<Vec<u8>>,
    bytes: usize,
    last_sweep: Instant,
    /// parent_key → live child count; zero → parent dropped
    parent_refs: HashMap<Vec<u8>, u32>,
    pub hits: u64,
    pub misses: u64,
    pub expired: u64,
    pub evicts: u64,
    pub inserts: u64,
}

pub struct CacheSnap {
    pub entries: usize,
    pub parents: usize,
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
            parent_refs: HashMap::new(),
            hits: 0,
            misses: 0,
            expired: 0,
            evicts: 0,
            inserts: 0,
        }
    }

    /// Split a full key into (parent_key, cluster_suffix).
    /// Full key layout: [parent_key][8-byte cluster]
    fn split_key(full: &[u8]) -> (&[u8], &[u8]) {
        let split = full.len().saturating_sub(8);
        (&full[..split], &full[split..])
    }

    fn on_child_removed(&mut self, full_key: &[u8]) {
        let (parent, _) = Self::split_key(full_key);
        let parent = parent.to_vec();
        if let Some(count) = self.parent_refs.get_mut(&parent) {
            *count -= 1;
            if *count == 0 {
                self.parent_refs.remove(&parent);
            }
        }
    }

    fn on_child_added(&mut self, full_key: &[u8]) {
        let (parent, _) = Self::split_key(full_key);
        *self.parent_refs.entry(parent.to_vec()).or_insert(0) += 1;
    }

    fn entry_live(&self, e: &Entry, now: Instant) -> bool {
        self.ignore_ttl || now.duration_since(e.base) < self.ttl
    }

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
                self.on_child_removed(key);
            }
            self.misses += 1;
            return None;
        }
        let age = now.duration_since(self.map.get(key).unwrap().base).as_secs() as u32;
        let cap = self.ttl.as_secs() as u32;
        let arc_msg = self.map.get(key).unwrap().msg.clone();
        if self.ignore_ttl {
            self.hits += 1;
            return Some(Hit::Shared(arc_msg));
        }
        let mut msg = (*arc_msg).clone();
        if !dnsmsg::patch_ttls(&mut msg, age, cap) {
            if let Some(e) = self.map.remove(key) {
                self.bytes -= key.len() + e.msg.len();
                self.expired += 1;
                self.on_child_removed(key);
            }
            self.misses += 1;
            return None;
        }
        self.hits += 1;
        Some(Hit::Owned(msg))
    }

    pub fn put(&mut self, key: Vec<u8>, mut msg: Vec<u8>) -> Arc<Vec<u8>> {
        if self.ignore_ttl {
            let cap = self.ttl.as_secs() as u32;
            let _ = dnsmsg::patch_ttls_min1(&mut msg, 0, cap);
        }
        let arc = Arc::new(msg);
        let sz = key.len() + arc.len();
        if sz > self.cap_bytes / 8 {
            return arc;
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
                        self.on_child_removed(&k);
                    }
                }
                None => break,
            }
        }
        self.bytes += sz;
        self.order.push_back(key.clone());
        self.map.insert(key.clone(), Entry { msg: arc.clone(), base: Instant::now() });
        self.on_child_added(&key);
        self.inserts += 1;
        arc
    }

    fn maybe_sweep(&mut self, now: Instant) {
        if self.ignore_ttl || now.duration_since(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        let ttl = self.ttl;
        let mut dead_keys = Vec::new();
        self.map.retain(|k, e| {
            let live = now.duration_since(e.base) < ttl;
            if !live {
                self.bytes -= k.len() + e.msg.len();
                dead_keys.push(k.clone());
            }
            live
        });
        self.expired += dead_keys.len() as u64;
        for k in &dead_keys {
            self.on_child_removed(k);
        }
    }

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
                        self.on_child_removed(&k);
                    }
                }
                None => break,
            }
        }
    }

    pub fn snapshot(&self) -> CacheSnap {
        CacheSnap {
            entries: self.map.len(),
            parents: self.parent_refs.len(),
            bytes: self.bytes,
            cap_bytes: self.cap_bytes,
            ttl_secs: self.ttl.as_secs(),
            ignore_ttl: self.ignore_ttl,
            hits: self.hits,
            misses: self.misses,
            expired: self.expired,
            evicts: self.evicts,
            inserts: self.inserts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geo_cluster_v4_same_metro() {
        // Same /24 → same cluster
        let a = GeoCluster::from_client_ip("203.0.113.1".parse().unwrap());
        let b = GeoCluster::from_client_ip("203.0.113.200".parse().unwrap());
        assert_eq!(a, b, "same /24 must be same cluster");
        // Same /20 (byte2 top nibble same) → still same cluster
        let c = GeoCluster::from_client_ip("203.0.112.1".parse().unwrap());
        assert_eq!(a, c, "same /20 must merge");
        // Different /20 (byte2 top nibble differs) → different cluster
        let d = GeoCluster::from_client_ip("203.0.64.1".parse().unwrap());
        assert_ne!(a, d, "different /20 must not merge");
    }

    #[test]
    fn geo_cluster_v6_same_city() {
        let a = GeoCluster::from_client_ip("2001:db8:1000:2000::1".parse().unwrap());
        let b = GeoCluster::from_client_ip("2001:db8:1000:2000::ffff".parse().unwrap());
        assert_eq!(a, b, "same /44 prefix");
    }

    #[test]
    fn parent_lifecycle() {
        let mut c = MagCache::new(10000, 1200, false);
        // two clusters for the same domain
        let pq = crate::dnsmsg::ParsedQuery {
            id: [0, 0],
            qname: b"\x07example\x03com\x00".to_vec(),
            qtype: 1, qclass: 1, do_bit: false,
        };
        let pk = dnsmsg::cache_key(&pq);

        let cl_a = GeoCluster::from_client_ip("203.0.113.1".parse().unwrap()).to_bytes();
        let cl_b = GeoCluster::from_client_ip("198.51.100.1".parse().unwrap()).to_bytes();

        let mut ka = pk.clone(); ka.extend_from_slice(&cl_a);
        let mut kb = pk.clone(); kb.extend_from_slice(&cl_b);

        let resp = vec![0u8; 40];
        c.put(ka.clone(), resp.clone());
        c.put(kb.clone(), resp);
        assert_eq!(c.snapshot().parents, 1, "one domain, one parent");

        // remove one child
        let _ = c.get(&ka); // triggers potential expiry path
        // force expire ALL entries: set ttl=0 so every get misses
        c.resize(10000, 0, false);
        let _ = c.get(&kb); // expired → removed
        let _ = c.get(&ka); // already gone from earlier get, but sweep may fire
        assert_eq!(c.parent_refs.len(), 0, "all children gone → parent dropped");
    }

    #[test]
    fn eviction_cleans_parent_refs() {
        let mut c = MagCache::new(500, 1200, false);
        for i in 0..30 {
            let pq = crate::dnsmsg::ParsedQuery {
                id: [0, 0],
                qname: format!("\x04n{i}\x00").as_bytes().to_vec(),
                qtype: 1, qclass: 1, do_bit: false,
            };
            let k = dnsmsg::cache_key(&pq);
            let _ = c.put(k, vec![0u8; 30]);
        }
        assert!(c.snapshot().bytes <= 500);
        // all entries evicted or retained consistently with parent_refs
        let total_children: u32 = c.parent_refs.values().sum();
        assert_eq!(total_children as usize, c.map.len());
    }
}
