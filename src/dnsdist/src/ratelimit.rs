// Three-layer rate limiting, all token buckets:
//   per-IP    — abusive client isolation (attribution first)
//   per-domain — one hot qname (NAT household or attacker) cannot monopolize us
//   global QPS — total arrival ceiling protecting upstreams and bandwidth
// Plus the global concurrency gate living in app.rs; the four together are
// the 5000-QPS OOM story. Zero dependencies; state is a flat HashMap swept
// lazily. Buckets evict oldest-quarter when full so memory stays bounded
// under key-diversity floods without failing honest traffic.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// (rate tokens/sec, burst ceiling); rate <= 0 disables the layer.
type Limits = (f64, u32);

fn refill_and_take(b: &mut Bucket, now: Instant, limits: Limits) -> bool {
    let elapsed = now.duration_since(b.last_refill).as_secs_f64();
    b.tokens = (b.tokens + elapsed * limits.0).min(limits.1 as f64);
    b.last_refill = now;
    if b.tokens >= 1.0 {
        b.tokens -= 1.0;
        true
    } else {
        false
    }
}

fn sweep_oldest<K: Eq + std::hash::Hash + Clone>(
    map: &mut HashMap<K, Bucket>,
    cap: usize,
    now: Instant,
    last_idle: &mut Instant,
) {
    // lazy idle sweep keeps long-tail keys from lingering
    if now.duration_since(*last_idle) > Duration::from_secs(60) {
        map.retain(|_, b| now.duration_since(b.last_refill) <= Duration::from_secs(120));
        *last_idle = now;
    }
    // hard memory bound, self-amortizing: past the cap, drop the oldest
    // half. Each trigger costs O(cap) and frees room for cap/2 fresh keys,
    // so even a 5000 QPS random-qname flood pays ~O(2) per query while
    // memory peaks at `cap` buckets.
    if map.len() > cap {
        let n = map.len();
        let mut by_age: Vec<(Instant, K)> = map
            .iter()
            .map(|(k, b)| (b.last_refill, k.clone()))
            .collect();
        by_age.select_nth_unstable_by_key(n / 2, |(t, _)| *t);
        let victims: Vec<K> = by_age[..n / 2].iter().map(|(_, k)| k.clone()).collect();
        for k in victims {
            map.remove(&k);
        }
    }
}

/// Keyed token-bucket limiter (per-IP / per-domain share this shape).
pub struct KeyedLimiter<K: Eq + std::hash::Hash + Clone> {
    state: Mutex<State<K>>,
    limits: Mutex<Limits>,
    max_entries: usize,
}

struct State<K> {
    map: HashMap<K, Bucket>,
    last_idle: Instant,
}

impl<K: Eq + std::hash::Hash + Clone> KeyedLimiter<K> {
    pub fn new(rate_per_sec: u32, burst: u32, max_entries: usize) -> Self {
        KeyedLimiter {
            state: Mutex::new(State {
                map: HashMap::new(),
                last_idle: Instant::now(),
            }),
            limits: Mutex::new((rate_per_sec as f64, burst.max(1))),
            max_entries: max_entries.max(16),
        }
    }

    /// SIGHUP: swap rate/burst live. Changing limits resets every bucket to
    /// the new burst — an operator relaxing under attack gets relief
    /// immediately instead of waiting out slow refills; tightening drops
    /// hoarded tokens symmetrically.
    pub fn set_limits(&self, rate_per_sec: u32, burst: u32) {
        let burst = burst.max(1);
        *self.limits.lock().unwrap() = (rate_per_sec as f64, burst);
        if rate_per_sec > 0 {
            self.state.lock().unwrap().map.values_mut().for_each(|b| {
                b.tokens = burst as f64;
            });
        }
    }

    pub fn check(&self, key: K) -> bool {
        let limits = *self.limits.lock().unwrap();
        if limits.0 <= 0.0 {
            return true; // layer disabled
        }
        let now = Instant::now();
        let mut st = self.state.lock().unwrap();
        let State { map, last_idle } = &mut *st;
        sweep_oldest(map, self.max_entries, now, last_idle);
        let b = map.entry(key).or_insert(Bucket {
            tokens: limits.1 as f64,
            last_refill: now,
        });
        refill_and_take(b, now, limits)
    }

    pub fn entries(&self) -> usize {
        self.state.lock().unwrap().map.len()
    }
}

/// Single global bucket: the whole process's QPS ceiling.
pub struct GlobalLimiter {
    bucket: Mutex<Option<Bucket>>,
    limits: Mutex<Limits>,
}

impl GlobalLimiter {
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        GlobalLimiter {
            bucket: Mutex::new(None),
            limits: Mutex::new((rate_per_sec as f64, burst.max(1))),
        }
    }

    pub fn set_limits(&self, rate_per_sec: u32, burst: u32) {
        let burst = burst.max(1);
        *self.limits.lock().unwrap() = (rate_per_sec as f64, burst);
        if rate_per_sec > 0 {
            // same reset semantics as KeyedLimiter: fresh full bucket
            *self.bucket.lock().unwrap() = None;
        }
    }

    pub fn check(&self) -> bool {
        let limits = *self.limits.lock().unwrap();
        if limits.0 <= 0.0 {
            return true;
        }
        let mut slot = self.bucket.lock().unwrap();
        let now = Instant::now();
        match slot.as_mut() {
            Some(b) => refill_and_take(b, now, limits),
            None => {
                let mut b = Bucket {
                    tokens: limits.1 as f64,
                    last_refill: now,
                };
                let ok = refill_and_take(&mut b, now, limits);
                *slot = Some(b);
                ok
            }
        }
    }
}

/// Per-IP limiter with the historical constructor signature.
pub type RateLimiter = KeyedLimiter<IpAddr>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(o: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]))
    }

    #[test]
    fn allows_burst_then_limits() {
        let rl = KeyedLimiter::new(10, 5, 1024); // 10/sec refill, burst 5
        let a = ip([127, 0, 0, 1]);
        for _ in 0..5 {
            assert!(rl.check(a), "burst should pass");
        }
        assert!(!rl.check(a), "over burst should fail");
    }

    #[test]
    fn different_keys_independent() {
        let rl = KeyedLimiter::new(1, 1, 1024);
        let (a, b) = (ip([1, 0, 0, 1]), ip([2, 0, 0, 2]));
        assert!(rl.check(a));
        assert!(rl.check(b), "different IP independent");
        assert!(!rl.check(a));
        assert!(!rl.check(b));
    }

    #[test]
    fn domain_buckets_isolate_hot_qname() {
        let dl: KeyedLimiter<Vec<u8>> = KeyedLimiter::new(1, 2, 1024);
        let cdn = b"www.cdncdn.com".to_vec();
        let other = b"api.example.net".to_vec();
        assert!(dl.check(cdn.clone()));
        assert!(dl.check(cdn.clone()));
        assert!(!dl.check(cdn), "hot domain exhausted");
        assert!(dl.check(other), "other domain unaffected");
    }

    #[test]
    fn zero_rate_disables_layer() {
        let rl: KeyedLimiter<Vec<u8>> = KeyedLimiter::new(0, 1, 1024);
        let k = b"anything.test".to_vec();
        for _ in 0..1000 {
            assert!(rl.check(k.clone()), "rate=0 must disable");
        }
        let g = GlobalLimiter::new(0, 1);
        for _ in 0..1000 {
            assert!(g.check(), "global rate=0 must disable");
        }
    }

    #[test]
    fn global_bucket_is_single() {
        let g = GlobalLimiter::new(1, 3);
        assert!(g.check());
        assert!(g.check());
        assert!(g.check());
        assert!(!g.check(), "global burst exhausted regardless of source");
    }

    #[test]
    fn hot_reload_swaps_limits_live() {
        let rl = KeyedLimiter::new(1, 1, 1024);
        let a = ip([9, 9, 9, 9]);
        assert!(rl.check(a));
        assert!(!rl.check(a));
        rl.set_limits(1, 100); // operator raises burst via SIGHUP
        assert!(rl.check(a), "new burst must apply immediately");
        // and disabling works too
        rl.set_limits(0, 1);
        for _ in 0..50 {
            assert!(rl.check(a));
        }
    }

    #[test]
    fn entry_cap_evicts_instead_of_growing() {
        let rl: KeyedLimiter<IpAddr> = KeyedLimiter::new(1, 1, 64);
        for i in 0..2000u32 {
            let _ = rl.check(ip([10, (i >> 8) as u8, i as u8, 1]));
        }
        assert!(
            rl.entries() <= 65,
            "cap must bound growth even under key flood, got {}",
            rl.entries()
        );
    }

    #[tokio::test]
    async fn refill_recovers_after_interval() {
        let rl = KeyedLimiter::new(1000, 1, 64);
        let a = ip([7, 7, 7, 7]);
        assert!(rl.check(a));
        assert!(!rl.check(a));
        tokio::time::sleep(Duration::from_millis(8)).await; // ~8 tokens at 1000/s
        assert!(rl.check(a), "tokens must refill at configured rate");
    }
}
