// Ordered source chain: try sources by configured priority; two consecutive
// failures mark a source down and a background probe brings it back.
// Identical concurrent queries collapse into one upstream request.
use crate::cache::MagCache;
use crate::cfg::{Cfg, SrcKind, SourceSpec};
use crate::doh::DoHPool;
use crate::doq::DoqClient;
use crate::dnsmsg;
use crate::dot::DotPool;
use crate::stats::Stats;
use crate::tlsconf;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

#[derive(Debug)]
pub enum UpErr {
    Timeout,
    Conn(String),
}

enum Kind {
    Doq(DoqClient),
    Dot(DotPool),
    Doh(DoHPool),
}

pub struct Source {
    pub spec: SourceSpec,
    kind: Kind,
    failures: AtomicU32,
    down_until_ms: AtomicU64,
    probing: AtomicBool,
}

impl Source {
    fn alive(&self, now_ms: u64) -> bool {
        self.down_until_ms.load(Ordering::Relaxed) <= now_ms
    }

    async fn attempt(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        match &self.kind {
            Kind::Doq(c) => c.query(msg, deadline).await,
            Kind::Dot(p) => p.query(msg, deadline).await,
            Kind::Doh(p) => p.query(msg, deadline).await,
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

pub struct Chain {
    sources: Vec<Arc<Source>>,
    inflight: Mutex<HashMap<Vec<u8>, Arc<Flight>>>,
    cache: Arc<Mutex<MagCache>>,
    stats: Arc<Stats>,
    verbose: bool,
    attempt_timeout: Duration,
    probe_interval: Duration,
}

impl Chain {
    pub fn new(cfg: &Cfg, stats: Arc<Stats>, cache: Arc<Mutex<MagCache>>) -> Result<Self, String> {
        let roots = tlsconf::root_store(cfg.extra_ca.as_deref())?;
        let mut sources = Vec::new();
        for spec in &cfg.upstreams {
            let kind = match spec.kind {
                SrcKind::Quic => {
                    let rc = tlsconf::client_config(roots.clone(), &[b"doq", b"doq-i03", b"doq-i02"], false);
                    Kind::Doq(DoqClient::new(spec.clone(), Arc::new(rc), cfg.allow_private_upstream)?)
                }
                SrcKind::Tls => {
                    let rc = tlsconf::client_config(roots.clone(), &[b"dot"], true);
                    Kind::Dot(DotPool::new(spec.clone(), Arc::new(rc), cfg.allow_private_upstream)?)
                }
                SrcKind::Doh => {
                    let rc = tlsconf::client_config(roots.clone(), &[], true);
                    Kind::Doh(DoHPool::new(spec.clone(), rc, cfg.allow_private_upstream)?)
                }
            };
            sources.push(Arc::new(Source {
                spec: spec.clone(),
                kind,
                failures: AtomicU32::new(0),
                down_until_ms: AtomicU64::new(0),
                probing: AtomicBool::new(false),
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
    ) -> Result<Vec<u8>, UpErr> {
        // fast path: join an in-flight query
        let existing = {
            let g = self.inflight.lock().unwrap();
            g.get(&key).cloned()
        };
        if let Some(f) = existing {
            return self.wait_flight(f, deadline).await;
        }
        // try to become the initiator
        let flight = Arc::new(Flight {
            state: Mutex::new(FlightState::Pending),
            notify: Notify::new(),
        });
        let lost_race = {
            let mut g = self.inflight.lock().unwrap();
            match g.get(&key) {
                Some(f) => Some(f.clone()),
                None => {
                    g.insert(key.clone(), flight.clone());
                    None
                }
            }
        };
        if let Some(f) = lost_race {
            return self.wait_flight(f, deadline).await;
        }
        let query = make_query();
        let result = self.run_sources(&key, cacheable, &query, deadline).await;
        let out = match &result {
            Ok(v) => FlightState::Ok(Arc::new(v.clone())),
            Err(_) => FlightState::Failed,
        };
        {
            let mut st = flight.state.lock().unwrap();
            *st = out;
        }
        self.inflight.lock().unwrap().remove(&key);
        flight.notify.notify_waiters();
        result
    }

    async fn wait_flight(&self, f: Arc<Flight>, deadline: Instant) -> Result<Vec<u8>, UpErr> {
        let mut notified = std::pin::pin!(f.notify.notified());
        loop {
            match &*f.state.lock().unwrap() {
                FlightState::Ok(v) => return Ok((**v).clone()),
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
    ) -> Result<Vec<u8>, UpErr> {
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
            Stats::bump(match s.spec.kind {
                SrcKind::Quic => &self.stats.up_sent_doq,
                SrcKind::Tls => &self.stats.up_sent_dot,
                SrcKind::Doh => &self.stats.up_sent_doh,
            });
            // each source gets its own budget so a dead peer cannot eat the
            // whole query budget before the fallback sources are tried
            let attempt_deadline = Instant::now()
                .checked_add(self.attempt_timeout)
                .unwrap_or(deadline)
                .min(deadline);
            match s.attempt(query, attempt_deadline).await {
                Ok(v) => {
                    Stats::bump(match s.spec.kind {
                        SrcKind::Quic => &self.stats.up_ok_doq,
                        SrcKind::Tls => &self.stats.up_ok_dot,
                        SrcKind::Doh => &self.stats.up_ok_doh,
                    });
                    s.failures.store(0, Ordering::Relaxed);
                    s.down_until_ms.store(0, Ordering::Relaxed);
                    let ok_rc = matches!(dnsmsg::rcode(&v), 0 | 3);
                    if cacheable && ok_rc && !dnsmsg::is_truncated(&v) {
                        self.cache.lock().unwrap().put(key.to_vec(), v.clone());
                    }
                    return Ok(v);
                }
                Err(e) => {
                    Stats::bump(match s.spec.kind {
                        SrcKind::Quic => &self.stats.up_err_doq,
                        SrcKind::Tls => &self.stats.up_err_dot,
                        SrcKind::Doh => &self.stats.up_err_doh,
                    });
                    if self.verbose {
                        eprintln!("magdns: upstream {}://{}:{} failed: {e:?}",
                            s.spec.kind.tag(), s.spec.host, s.spec.port);
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

    fn strike(&self, s: &Arc<Source>) {
        let f = s.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if f >= 2 {
            let down = crate::app::unix_ms() + self.probe_interval.as_millis() as u64;
            s.down_until_ms.store(down, Ordering::Relaxed);
            if !s.probing.swap(true, Ordering::SeqCst) {
                let s = s.clone();
                let stats = self.stats.clone();
                let interval = self.probe_interval;
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(interval).await;
                        if s.alive(crate::app::unix_ms()) {
                            break; // someone else marked it up
                        }
                        if s.probe_once().await {
                            Stats::bump(&stats.probe_ok);
                            s.failures.store(0, Ordering::Relaxed);
                            s.down_until_ms.store(0, Ordering::Relaxed);
                            break;
                        }
                        Stats::bump(&stats.probe_fail);
                        let down = crate::app::unix_ms() + interval.as_millis() as u64;
                        s.down_until_ms.store(down, Ordering::Relaxed);
                    }
                    s.probing.store(false, Ordering::SeqCst);
                });
            }
        }
    }
}
