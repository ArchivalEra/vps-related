// Domestic (CN) resolver pool: plain-DNS UDP legs with pooled sockets and
// TC=1 -> TCP retry (reuses UdpSource). Concurrent distinct queries fan out
// across peer legs (round-robin); identical concurrent queries collapse into
// one upstream round trip (shared flightmap). Two strikes mark a leg down;
// a background probe brings it back.
// The flight key hashes the upstream query with its transaction ID zeroed,
// because each client's rebuilt query carries that client's ID — merging
// must key on question+EDNS only.
#[cfg(feature = "up-udp")]
use crate::cfg::{Cfg, SourceSpec, SrcKind};
#[cfg(feature = "up-udp")]
use crate::flightmap::{await_flight, Entered, FlightMap};
#[cfg(feature = "up-udp")]
use crate::stats::Stats;
#[cfg(feature = "up-udp")]
use crate::upstream::{Health, UpErr};
#[cfg(feature = "up-udp")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "up-udp")]
use std::sync::Arc;
#[cfg(feature = "up-udp")]
use std::time::{Duration, Instant};

/// Single-flight ceiling for the CN pool; beyond this, queries bypass dedup
/// instead of growing the map (same degradation contract as the Chain).
const CN_MAX_INFLIGHT: usize = 1024;

#[cfg(feature = "up-udp")]
struct CnLeg {
    spec: SourceSpec,
    src: crate::udpsrc::UdpSource,
    health: Health,
}

#[cfg(feature = "up-udp")]
pub struct CnPool {
    legs: Vec<Arc<CnLeg>>,
    flights: FlightMap,
    rr: AtomicUsize,
    stats: Arc<Stats>,
    verbose: bool,
    attempt_timeout: Duration,
    probe_interval: Duration,
}

/// Alive-first dispatch order starting at `start` (round-robin among the
/// alive prefix); dead legs trail as last resort, preserving their index
/// order. Pure so the spread/fallback shape is unit-testable.
pub fn dispatch_order(alive: impl Fn(usize) -> bool + Copy, n: usize, start: usize) -> Vec<usize> {
    let mut ord: Vec<usize> = (0..n).filter(|&i| alive(i)).collect();
    if ord.len() > 1 {
        let s = start % ord.len();
        ord.rotate_left(s);
    }
    ord.extend((0..n).filter(|&i| !alive(i)));
    ord
}

/// FNV-1a over the query with the transaction ID zeroed: identical questions
/// from different clients share one flight.
fn flight_key(msg: &[u8]) -> Vec<u8> {
    let mut h: u64 = 0xcbf29ce484222325;
    for (i, b) in msg.iter().enumerate() {
        let b = if i < 2 { 0 } else { *b };
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    let mut k = vec![b'C'];
    k.extend_from_slice(&h.to_be_bytes());
    k
}

#[cfg(feature = "up-udp")]
impl CnPool {
    /// None when no `cn_upstream` is configured (split routing disabled).
    pub fn new(cfg: &Cfg, stats: Arc<Stats>) -> Result<Option<Self>, String> {
        if cfg.cn_upstreams.is_empty() {
            return Ok(None);
        }
        let mut legs = Vec::with_capacity(cfg.cn_upstreams.len());
        for raw in &cfg.cn_upstreams {
            let spec = crate::cfg::parse_upstream(raw)?;
            if spec.kind != SrcKind::Udp {
                return Err(format!(
                    "cn_upstream `{raw}`: domestic legs speak udp:// only"
                ));
            }
            legs.push(Arc::new(CnLeg {
                src: crate::udpsrc::UdpSource::new(spec.clone(), cfg.allow_private_upstream)?,
                spec,
                health: Health::new(),
            }));
        }
        Ok(Some(CnPool {
            legs,
            flights: FlightMap::new(),
            rr: AtomicUsize::new(0),
            stats,
            verbose: cfg.verbose,
            attempt_timeout: Duration::from_millis(cfg.attempt_timeout_ms.max(200)),
            probe_interval: Duration::from_secs(cfg.probe_interval_s.max(2)),
        }))
    }

    pub fn legs_desc(&self) -> Vec<String> {
        self.legs
            .iter()
            .map(|l| format!("udp://{}:{}", l.spec.host, l.spec.port))
            .collect()
    }

    /// Resolve through the domestic legs. Returns the raw upstream reply
    /// (caller patches the client's transaction ID).
    pub async fn resolve(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        let key = flight_key(msg);
        // one takeover round: a failed joined flight means we run it ourselves
        for _ in 0..2 {
            match self.flights.enter(&key, CN_MAX_INFLIGHT) {
                Entered::Joiner(f) => match await_flight(f, deadline).await {
                    Ok(v) => return Ok((*v).clone()),
                    Err(_) => continue,
                },
                Entered::Bypass => return self.run_legs(msg, deadline).await,
                Entered::Initiator(guard) => {
                    let result = self.run_legs(msg, deadline).await;
                    guard.settle(result.as_ref().ok().map(|v| Arc::new(v.clone())));
                    return result;
                }
            }
        }
        self.run_legs(msg, deadline).await
    }

    async fn run_legs(&self, query: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        let now_ms = crate::app::unix_ms();
        let start = self.rr.fetch_add(1, Ordering::Relaxed);
        let order = dispatch_order(
            |i| self.legs[i].health.alive(now_ms),
            self.legs.len(),
            start,
        );
        for (t, &i) in order.iter().enumerate() {
            if t > 0 {
                Stats::bump(&self.stats.cn_fallback);
            }
            let leg = &self.legs[i];
            Stats::bump(&self.stats.cn_sent);
            // per-leg budget keeps a black-holing resolver from eating the
            // whole query budget before the fallback legs are tried
            let attempt_deadline = Instant::now()
                .checked_add(self.attempt_timeout)
                .unwrap_or(deadline)
                .min(deadline);
            match leg.src.query(query, attempt_deadline).await {
                Ok(v) => {
                    Stats::bump(&self.stats.cn_ok);
                    leg.health.record_success();
                    return Ok(v);
                }
                Err(e) => {
                    Stats::bump(&self.stats.cn_err);
                    if self.verbose {
                        eprintln!(
                            "magdns: cn_upstream udp://{}:{} failed: {e:?}",
                            leg.spec.host, leg.spec.port
                        );
                    }
                    self.strike(i);
                    if Instant::now() >= deadline {
                        return Err(UpErr::Timeout);
                    }
                }
            }
        }
        Err(UpErr::Conn("all cn sources failed".into()))
    }

    fn strike(&self, idx: usize) {
        let leg = self.legs[idx].clone();
        let stats = self.stats.clone();
        let interval = self.probe_interval;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if leg.health.alive(crate::app::unix_ms()) {
                    break; // someone else marked it up
                }
                let q = crate::dnsmsg::build_probe_query();
                let ok = match leg
                    .src
                    .query(&q, Instant::now() + Duration::from_millis(2000))
                    .await
                {
                    Ok(r) => crate::dnsmsg::rcode(&r) != 2,
                    Err(_) => false,
                };
                if ok {
                    Stats::bump(&stats.probe_ok);
                    leg.health.record_success();
                    break;
                }
                Stats::bump(&stats.probe_fail);
                leg.health
                    .record_failure(crate::app::unix_ms(), interval.as_millis() as u64);
            }
            leg.health.release_probe_slot();
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spread_rotates_alive_prefix_keeps_dead_trailing() {
        // 3 legs, middle one down: alive = {0, 2}, dead = {1}
        let alive = |i: usize| i != 1;
        assert_eq!(dispatch_order(alive, 3, 0), vec![0, 2, 1]);
        assert_eq!(dispatch_order(alive, 3, 1), vec![2, 0, 1]);
        assert_eq!(dispatch_order(alive, 3, 2), vec![0, 2, 1]); // wraps
                                                                // all down: order is just the trailing indices
        let none = |_: usize| false;
        assert_eq!(dispatch_order(none, 3, 5), vec![0, 1, 2]);
        // single alive leg never rotates
        let one = |i: usize| i == 2;
        assert_eq!(dispatch_order(one, 3, 9), vec![2, 0, 1]);
    }

    #[test]
    fn flight_key_ignores_transaction_id() {
        let mut q = vec![0xAB, 0xCD];
        q.extend_from_slice(b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01");
        let mut other_id = q.clone();
        other_id[0] = 0x11;
        other_id[1] = 0x22;
        assert_eq!(flight_key(&q), flight_key(&other_id));
        // different question -> different key
        let mut diff = q.clone();
        let last = diff.len() - 1;
        diff[last] ^= 0xFF; // flip class bits
        assert_ne!(flight_key(&q), flight_key(&diff));
    }
}
