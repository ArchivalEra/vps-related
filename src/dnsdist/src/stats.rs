// Atomic counters; dumped to stderr on SIGUSR1 and at shutdown.
use crate::cache::CacheSnap;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Stats {
    pub in_dot: AtomicU64,
    pub in_doq: AtomicU64,
    pub servfail: AtomicU64,
    pub passthrough: AtomicU64,
    pub fallback: AtomicU64,
    pub up_sent_doq: AtomicU64,
    pub up_ok_doq: AtomicU64,
    pub up_err_doq: AtomicU64,
    pub up_sent_dot: AtomicU64,
    pub up_ok_dot: AtomicU64,
    pub up_err_dot: AtomicU64,
    pub up_sent_doh: AtomicU64,
    pub up_ok_doh: AtomicU64,
    pub up_err_doh: AtomicU64,
    pub up_sent_udp: AtomicU64,
    pub up_ok_udp: AtomicU64,
    pub up_err_udp: AtomicU64,
    pub dot_conns: AtomicU64,
    pub doq_conns: AtomicU64,
    pub reloads: AtomicU64,
    pub probe_ok: AtomicU64,
    pub probe_fail: AtomicU64,
}

impl Stats {
    #[inline]
    pub fn bump(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dump(&self, snap: &CacheSnap, rss_bytes: u64) -> String {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        format!(
            "STATS {{\
\"in_dot\":{},\"in_doq\":{},\
\"cache_hit\":{},\"cache_miss\":{},\"cache_expired\":{},\"cache_evict\":{},\
\"cache_entries\":{},\"cache_bytes\":{},\"cache_cap\":{},\"cache_ttl_s\":{},\"cache_ttl_ignore\":{},\"rss_bytes\":{},\
\"servfail\":{},\"passthrough\":{},\"fallback\":{},\
\"up_sent_doq\":{},\"up_ok_doq\":{},\"up_err_doq\":{},\
\"up_sent_dot\":{},\"up_ok_dot\":{},\"up_err_dot\":{},\
\"up_sent_doh\":{},\"up_ok_doh\":{},\"up_err_doh\":{},\
\"up_sent_udp\":{},\"up_ok_udp\":{},\"up_err_udp\":{},\
\"dot_conns\":{},\"doq_conns\":{},\"reloads\":{},\
\"probe_ok\":{},\"probe_fail\":{},\
\"cache_inserts\":{}}}",
            g(&self.in_dot), g(&self.in_doq),
            snap.hits, snap.misses, snap.expired, snap.evicts,
            snap.entries, snap.bytes, snap.cap_bytes, snap.ttl_secs, snap.ignore_ttl, rss_bytes,
            g(&self.servfail), g(&self.passthrough), g(&self.fallback),
            g(&self.up_sent_doq), g(&self.up_ok_doq), g(&self.up_err_doq),
            g(&self.up_sent_dot), g(&self.up_ok_dot), g(&self.up_err_dot),
            g(&self.up_sent_doh), g(&self.up_ok_doh), g(&self.up_err_doh),
            g(&self.up_sent_udp), g(&self.up_ok_udp), g(&self.up_err_udp),
            g(&self.dot_conns), g(&self.doq_conns), g(&self.reloads),
            g(&self.probe_ok), g(&self.probe_fail),
            snap.inserts)
    }
}
