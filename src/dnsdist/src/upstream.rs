// Ordered source chain: try sources by configured priority; two consecutive
// failures mark a source down and a background probe brings it back.
// Identical concurrent queries collapse into one upstream request.
// Concurrency is bounded (semaphore + inflight cap) so worst-case memory
// stays proportional to config, not to attacker load.
use crate::cache::MagCache;
use crate::cfg::{Cfg, SrcKind, SourceSpec};
use crate::dnsmsg;
use crate::stats::Stats;
use crate::tlsconf;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, Semaphore};

#[derive(Debug)]
pub enum UpErr {
    Timeout,
    Conn(String),
}

/// Resolution result: `Shared` bodies are served zero-copy (the caller
/// prepends the client's 2-byte ID); `Owned` still needs an ID patch.
pub enum Out {
    Shared(Arc<Vec<u8>>),
    Owned(Vec<u8>),
}

/// Health bookkeeping for one source. All time comes in as `now_ms` so the
/// transitions are unit-testable without sleeping.
pub struct Health {
    failures: AtomicU32,
    down_until_ms: AtomicU64,
    probing: AtomicBool,
}

impl Health {
    fn new() -> Self {
        Health {
            failures: AtomicU32::new(0),
            down_until_ms: AtomicU64::new(0),
            probing: AtomicBool::new(false),
        }
    }

    pub fn alive(&self, now_ms: u64) -> bool {
        self.down_until_ms.load(Ordering::Relaxed) <= now_ms
    }

    /// 2 consecutive failures -> down for one probe interval.
    pub fn record_failure(&self, now_ms: u64, probe_interval_ms: u64) {
        let f = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if f >= 2 {
            self.down_until_ms
                .store(now_ms + probe_interval_ms, Ordering::Relaxed);
        }
    }

    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.down_until_ms.store(0, Ordering::Relaxed);
    }

    /// Only one probe task may run per source.
    pub fn take_probe_slot(&self) -> bool {
        !self.probing.swap(true, Ordering::SeqCst)
    }

    pub fn release_probe_slot(&self) {
        self.probing.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod health_tests {
    use super::*;

    #[test]
    fn two_strikes_down_then_recover() {
        let h = Health::new();
        assert!(h.alive(0));
        h.record_failure(100, 3000);
        assert!(h.alive(200), "single failure keeps source alive");
        h.record_failure(400, 3000);
        assert!(!h.alive(500), "two strikes mark it down");
        assert!(h.alive(4000), "down window expires");
        h.record_failure(4100, 3000);
        h.record_failure(4150, 3000);
        assert!(!h.alive(4200));
        h.record_success();
        assert!(h.alive(1), "success clears immediately");
    }

    #[test]
    fn probe_slot_is_exclusive() {
        let h = Health::new();
        assert!(h.take_probe_slot());
        assert!(!h.take_probe_slot());
        h.release_probe_slot();
        assert!(h.take_probe_slot());
    }
}

enum Kind {
    #[cfg(feature = "up-quic")]
    Doq(crate::doq::DoqClient),
    #[cfg(feature = "up-tls")]
    Dot(crate::dot::DotPool),
    #[cfg(feature = "up-doh")]
    Doh(crate::doh::DoHPool),
    #[cfg(feature = "up-udp")]
    Udp(crate::udpsrc::UdpSource),
}

pub struct Source {
    pub spec: SourceSpec,
    kind: Kind,
    health: Health,
}

impl Source {
    fn alive(&self, now_ms: u64) -> bool {
        self.health.alive(now_ms)
    }

    async fn attempt(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        match &self.kind {
            #[cfg(feature = "up-quic")]
            Kind::Doq(c) => c.query(msg, deadline).await,
            #[cfg(feature = "up-tls")]
            Kind::Dot(p) => p.query(msg, deadline).await,
            #[cfg(feature = "up-doh")]
            Kind::Doh(p) => p.query(msg, deadline).await,
            #[cfg(feature = "up-udp")]
            Kind::Udp(u) => u.query(msg, deadline).await,
        }
    }

    async fn probe_once(&self) -> bool {
        let q = dnsmsg::build_probe_query();
        match self.attempt(&q, Instant::now() + Duration::from_millis(2000)).await {
            Ok(r) => dnsmsg::rcode(&r) != 2,
            Err(_) => false,
        }
    }
}

enum FlightState {
    Pending,
    Ok(Arc<Vec<u8>>),
    Failed,
}

struct Flight {
    state: Mutex<FlightState>,
    notify: Notify,
}

/// Hard memory bounds for concurrency: at most this many chain resolutions
/// in flight and this many single-flight keys; anything beyond degrades
/// (direct pass-through / no dedup) instead of growing.
const MAX_INFLIGHT: usize = 4096;
const MAX_CONCURRENT_RESOLVE: usize = 256;

pub struct Chain {
    sources: Vec<Arc<Source>>,
    inflight: Mutex<HashMap<Vec<u8>, Arc<Flight>>>,
    cache: Arc<Mutex<MagCache>>,
    stats: Arc<Stats>,
    verbose: bool,
    attempt_timeout: Duration,
    probe_interval: Duration,
    resolve_permits: Arc<Semaphore>,
}

impl Chain {
    pub fn new(cfg: &Cfg, stats: Arc<Stats>, cache: Arc<Mutex<MagCache>>) -> Result<Self, String> {
        let roots = tlsconf::root_store(cfg.extra_ca.as_deref())?;
        let mut sources = Vec::new();
        for spec in &cfg.upstreams {
            let kind = match spec.kind {
                #[cfg(feature = "up-quic")]
                SrcKind::Quic => {
                    let rc = tlsconf::client_config(roots.clone(), &[b"doq", b"doq-i03", b"doq-i02"], false);
                    Kind::Doq(crate::doq::DoqClient::new(spec.clone(), Arc::new(rc), cfg.allow_private_upstream)?)
                }
                #[cfg(feature = "up-tls")]
                SrcKind::Tls => {
                    let rc = tlsconf::client_config(roots.clone(), &[b"dot"], true);
                    Kind::Dot(crate::dot::DotPool::new(spec.clone(), Arc::new(rc), cfg.allow_private_upstream)?)
                }
                #[cfg(feature = "up-doh")]
                SrcKind::Doh => {
                    let rc = tlsconf::client_config(roots.clone(), &[], true);
                    Kind::Doh(crate::doh::DoHPool::new(spec.clone(), rc, cfg.allow_private_upstream)?)
                }
                #[cfg(feature = "up-udp")]
                SrcKind::Udp => Kind::Udp(crate::udpsrc::UdpSource::new(spec.clone(), cfg.allow_private_upstream)?),
                #[allow(unreachable_patterns)]
                _ => {
                    return Err(format!(
                        "upstream `{}`: transport not compiled into this binary",
                        spec.raw
                    ))
                }
            };
            sources.push(Arc::new(Source {
                spec: spec.clone(),
                kind,
                health: Health::new(),
            }));
        }
        Ok(Chain {
            sources,
            inflight: Mutex::new(HashMap::new()),
            cache,
            stats,
            verbose: cfg.verbose,
            attempt_timeout: Duration::from_millis(cfg.attempt_timeout_ms.max(200)),
            probe_interval: Duration::from_secs(cfg.probe_interval_s.max(2)),
            resolve_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_RESOLVE)),
        })
    }

    pub fn sources_desc(&self) -> Vec<String> {
        self.sources
            .iter()
            .map(|s| format!("{}://{}:{}", s.spec.kind.tag(), s.spec.host, s.spec.port))
            .collect()
    }

    /// Resolve one query through the chain. `cacheable` false = raw
    /// passthrough (unusual opcodes / QDCOUNT != 1) which skips the cache.
    pub async fn resolve(
        &self,
        key: Vec<u8>,
        cacheable: bool,
        deadline: Instant,
        make_query: impl FnOnce() -> Vec<u8>,
    ) -> Result<Out, UpErr> {
        // fast path: join an in-flight query (bounded; excess bypasses dedup)
        let existing = {
            let g = self.inflight.lock().unwrap();
            if g.len() < MAX_INFLIGHT {
                g.get(&key).cloned()
            } else {
                None
            }
        };
        if let Some(f) = existing {
            return self.wait_flight(f, deadline).await;
        }
        // try to become the initiator (same bound applies)
        let flight = {
            let mut g = self.inflight.lock().unwrap();
            if g.len() >= MAX_INFLIGHT {
                None // over budget: run without dedup, concurrency still bounded below
            } else if let Some(f) = g.get(&key) {
                Some(FlightRole::Joiner(f.clone()))
            } else {
                let f = Arc::new(Flight {
                    state: Mutex::new(FlightState::Pending),
                    notify: Notify::new(),
                });
                g.insert(key.clone(), f.clone());
                Some(FlightRole::Initiator(f))
            }
        };
        let flight = match flight {
            Some(FlightRole::Joiner(f)) => return self.wait_flight(f, deadline).await,
            Some(FlightRole::Initiator(f)) => Some(f),
            None => None,
        };

        // bound concurrent upstream work; waiters beyond the budget fail fast
        let permit = {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(UpErr::Timeout)?;
            match tokio::time::timeout(remaining, self.resolve_permits.clone().acquire_owned()).await {
                Ok(Ok(p)) => p,
                _ => {
                    if let Some(f) = &flight {
                        // release the slot we took
                        self.inflight.lock().unwrap().remove(&key);
                    }
                    return Err(UpErr::Timeout);
                }
            }
        };

        let query = make_query();
        let result = self.run_sources(&key, cacheable, &query, deadline).await;
        drop(permit);

        if let Some(f) = &flight {
            let out = match &result {
                Ok(Out::Shared(v)) => FlightState::Ok(v.clone()),
                Ok(Out::Owned(_)) => {
                    // owned results never come from run_sources' success path
                    FlightState::Failed
                }
                Err(_) => FlightState::Failed,
            };
            {
                let mut st = f.state.lock().unwrap();
                *st = out;
            }
            self.inflight.lock().unwrap().remove(&key);
            f.notify.notify_waiters();
        }
        result
    }

    async fn wait_flight(&self, f: Arc<Flight>, deadline: Instant) -> Result<Out, UpErr> {
        let mut notified = std::pin::pin!(f.notify.notified());
        loop {
            match &*f.state.lock().unwrap() {
                FlightState::Ok(v) => return Ok(Out::Shared(v.clone())),
                FlightState::Failed => return Err(UpErr::Conn("in-flight query failed".into())),
                FlightState::Pending => {}
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(UpErr::Timeout)?;
            match tokio::time::timeout(remaining, notified.as_mut()).await {
                Ok(_) => continue,
                Err(_) => return Err(UpErr::Timeout),
            }
        }
    }

    async fn run_sources(
        &self,
        key: &[u8],
        cacheable: bool,
        query: &[u8],
        deadline: Instant,
    ) -> Result<Out, UpErr> {
        let now_ms = crate::app::unix_ms();
        // alive sources keep their configured priority; down sources are
        // appended as last resort so a query still gets a full chance when
        // the "alive" ones are actually dead (single-strike state)
        let mut order: Vec<usize> = (0..self.sources.len())
            .filter(|&i| self.sources[i].alive(now_ms))
            .collect();
        for i in 0..self.sources.len() {
            if !self.sources[i].alive(now_ms) {
                order.push(i);
            }
        }
        let mut tried = 0usize;
        for &i in &order {
            tried += 1;
            if tried > 1 {
                Stats::bump(&self.stats.fallback);
            }
            let s = &self.sources[i];
            self.bump_sent(&s.spec.kind);
            // each source gets its own budget so a dead peer cannot eat the
            // whole query budget before the fallback sources are tried
            let attempt_deadline = Instant::now()
                .checked_add(self.attempt_timeout)
                .unwrap_or(deadline)
                .min(deadline);
            match s.attempt(query, attempt_deadline).await {
                Ok(v) => {
                    self.bump_kind(&s.spec.kind, 1);
                    s.health.record_success();
                    let ok_rc = matches!(dnsmsg::rcode(&v), 0 | 3);
                    if cacheable && ok_rc && !dnsmsg::is_truncated(&v) && v.len() >= 12 {
                        // put() TTL-caps at insert in ignore mode and returns
                        // the canonical shared body -> zero-copy serve
                        let arc = self.cache.lock().unwrap().put(key.to_vec(), v);
                        return Ok(Out::Shared(arc));
                    }
                    return Ok(Out::Owned(v));
                }
                Err(e) => {
                    self.bump_kind(&s.spec.kind, 2);
                    if self.verbose {
                        eprintln!(
                            "magdns: upstream {}://{}:{} failed: {e:?}",
                            s.spec.kind.tag(), s.spec.host, s.spec.port
                        );
                    }
                    self.strike(s);
                    if Instant::now() >= deadline {
                        return Err(UpErr::Timeout);
                    }
                }
            }
        }
        Err(UpErr::Conn("all sources failed".into()))
    }

    fn bump_sent(&self, kind: &SrcKind) {
        match kind {
            #[cfg(feature = "up-quic")]
            SrcKind::Quic => Stats::bump(&self.stats.up_sent_doq),
            #[cfg(feature = "up-tls")]
            SrcKind::Tls => Stats::bump(&self.stats.up_sent_dot),
            #[cfg(feature = "up-doh")]
            SrcKind::Doh => Stats::bump(&self.stats.up_sent_doh),
            #[cfg(feature = "up-udp")]
            SrcKind::Udp => Stats::bump(&self.stats.up_sent_udp),
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }

    fn bump_kind(&self, kind: &SrcKind, which: u8) {
        let s = &self.stats;
        match (kind, which) {
            #[cfg(feature = "up-quic")]
            (SrcKind::Quic, 1) => Stats::bump(&s.up_ok_doq),
            #[cfg(feature = "up-quic")]
            (SrcKind::Quic, 2) => Stats::bump(&s.up_err_doq),
            #[cfg(feature = "up-tls")]
            (SrcKind::Tls, 1) => Stats::bump(&s.up_ok_dot),
            #[cfg(feature = "up-tls")]
            (SrcKind::Tls, 2) => Stats::bump(&s.up_err_dot),
            #[cfg(feature = "up-doh")]
            (SrcKind::Doh, 1) => Stats::bump(&s.up_ok_doh),
            #[cfg(feature = "up-doh")]
            (SrcKind::Doh, 2) => Stats::bump(&s.up_err_doh),
            #[cfg(feature = "up-udp")]
            (SrcKind::Udp, 1) => Stats::bump(&s.up_ok_udp),
            #[cfg(feature = "up-udp")]
            (SrcKind::Udp, 2) => Stats::bump(&s.up_err_udp),
            _ => {}
        }
    }

    fn strike(&self, s: &Arc<Source>) {
        s.health
            .record_failure(crate::app::unix_ms(), self.probe_interval.as_millis() as u64);
        if s.health.take_probe_slot() {
            let s = s.clone();
            let stats = self.stats.clone();
            let interval = self.probe_interval;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(interval).await;
                    if s.health.alive(crate::app::unix_ms()) {
                        break; // someone else marked it up
                    }
                    if s.probe_once().await {
                        Stats::bump(&stats.probe_ok);
                        s.health.record_success();
                        break;
                    }
                    Stats::bump(&stats.probe_fail);
                    s.health
                        .record_failure(crate::app::unix_ms(), interval.as_millis() as u64);
                }
                s.health.release_probe_slot();
            });
        }
    }
}

enum FlightRole {
    Initiator(Arc<Flight>),
    Joiner(Arc<Flight>),
}
