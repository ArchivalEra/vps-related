// Shared application state and the single query pipeline used by both listeners.
use crate::cache::MagCache;
use crate::cfg::{self, Cfg};
use crate::dnsmsg;
use crate::router::Router;
use crate::stats::Stats;
use crate::upstream::Chain;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// A reply ready for the wire. `Shared` is the zero-copy shape: the 2-byte
/// client ID rides as a prefix in front of the Arc'd body (whose first two
/// bytes are replaced), so hits and misses never copy the payload.
pub enum Reply {
    Owned(Vec<u8>),
    Shared { prefix: [u8; 2], body: Arc<Vec<u8>> },
}

impl Reply {
    pub fn is_empty(&self) -> bool {
        matches!(self, Reply::Owned(v) if v.is_empty())
    }
}

pub async fn write_reply<W: AsyncWrite + Unpin>(w: &mut W, r: &Reply) -> std::io::Result<()> {
    match r {
        Reply::Owned(v) => crate::frame::write_frame(w, v).await,
        Reply::Shared { prefix, body } => {
            if body.len() < 2 {
                return Ok(()); // malformed guard; should never happen
            }
            let lb = (body.len() as u16).to_be_bytes();
            w.write_all(&lb).await?;
            w.write_all(prefix).await?;
            w.write_all(&body[2..]).await?;
            w.flush().await
        }
    }
}

pub struct App {
    pub cfg: Cfg,
    pub stats: Arc<Stats>,
    pub cache: Arc<Mutex<MagCache>>,
    pub chain: Chain,
    /// CN domain router: match qname → route to domestic or foreign chain
    pub router: RwLock<Option<Router>>,
    /// Layered rate limiting: per-IP, per-domain (lowercase qname), global QPS
    pub rate_limiter: crate::ratelimit::RateLimiter,
    pub domain_limiter: crate::ratelimit::KeyedLimiter<Vec<u8>>,
    pub global_limiter: crate::ratelimit::GlobalLimiter,
    /// domestic legs for split routing; None = no `cn_upstream` configured
    #[cfg(feature = "up-udp")]
    pub cn_pool: Option<crate::cnpool::CnPool>,
    pub query_gate: std::sync::Arc<tokio::sync::Semaphore>,
    pub server_tls_dot: RwLock<Arc<rustls::ServerConfig>>,
    pub server_tls_doq: RwLock<Arc<rustls::ServerConfig>>,
    pub doq_endpoint: RwLock<Option<quinn::Endpoint>>,
}

pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn fnv1a(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for x in b {
        h ^= *x as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// The whole pipeline: cache -> single-flight -> ordered upstream chain.
/// Returns the wire-ready reply; Reply::Owned(vec![]) means "drop / close".
/// `client_ip` feeds both the geo-cluster cache key and the EDNS0 Client Subnet.
pub async fn handle_query(
    app: &Arc<App>,
    q: Vec<u8>,
    transport: &str,
    client_ip: std::net::IpAddr,
) -> Reply {
    let t0 = Instant::now();
    match transport {
        "dot" => Stats::bump(&app.stats.in_dot),
        "doq" => Stats::bump(&app.stats.in_doq),
        _ => {}
    }

    // Layer 1: per-IP rate limit (token bucket)
    if !app.rate_limiter.check(client_ip) {
        Stats::bump(&app.stats.ratelimited);
        return Reply::Owned(dnsmsg::make_servfail(&q));
    } // Layer 2: global concurrency gate (prevents OOM under flood)
    let permit = match app.query_gate.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            Stats::bump(&app.stats.servfail);
            return Reply::Owned(Vec::new()); // overloaded, drop
        }
    };

    if q.len() < 12 {
        drop(permit);
        return Reply::Owned(Vec::new());
    }
    let id = [q[0], q[1]];
    let deadline = Instant::now() + Duration::from_millis(app.cfg.query_timeout_ms);
    let cluster = crate::cache::GeoCluster::from_client_ip(client_ip);

    let (key, cacheable, upstream_query, qname, qtype, is_cn) = match dnsmsg::parse_query(&q) {
        Some(pq) => {
            let base_key = dnsmsg::cache_key(&pq);
            // geo-aware: append cluster bytes to the cache key
            let mut key = base_key.clone();
            key.extend_from_slice(&cluster.to_bytes());
            let n = dnsmsg::qname_str(&pq.qname);
            let t = pq.qtype;
            // Layer 2: per-domain limit keyed on the lowercase qname — one
            // hot name (NAT household or random-qname flood) cannot crowd out
            // everything else
            if !app.domain_limiter.check(n.to_lowercase().into_bytes()) {
                Stats::bump(&app.stats.domain_limited);
                return Reply::Owned(dnsmsg::make_refused(&q));
            }
            // Layer 3: global QPS ceiling protecting upstreams + bandwidth
            if !app.global_limiter.check() {
                Stats::bump(&app.stats.global_limited);
                return Reply::Owned(dnsmsg::make_refused(&q));
            }
            // build upstream query; embed ECS if enabled
            let mut uq = dnsmsg::build_query(&pq);
            if app.cfg.ecs_enabled {
                dnsmsg::append_ecs_to_query(&mut uq, &dnsmsg::ecs_option_bytes(client_ip, 24));
            }
            // split routing: check router for CN domain classification
            let cn = {
                let r = app.router.read().unwrap();
                match r.as_ref() {
                    Some(router) => {
                        let lower = n.to_lowercase();
                        matches!(router.resolve(&lower), Some(0)) // route 0 = CN
                    }
                    None => false,
                }
            };
            (key, true && !cn, uq, n, t, cn)
        }
        None => {
            let mut k = vec![b'P'];
            k.extend_from_slice(&fnv1a(&q).to_be_bytes());
            k.extend_from_slice(&cluster.to_bytes());
            (k, false, q.clone(), String::new(), 0, false)
        }
    };

    // cache
    if cacheable {
        match app.cache.lock().unwrap().get(&key) {
            Some(crate::cache::Hit::Shared(body)) => {
                if app.cfg.log_queries {
                    eprintln!(
                        "Q {} {} {} hit0 rcode={} {}us",
                        transport,
                        qname,
                        qtype,
                        dnsmsg::rcode(&body),
                        t0.elapsed().as_micros()
                    );
                }
                return Reply::Shared { prefix: id, body };
            }
            Some(crate::cache::Hit::Owned(mut m)) => {
                dnsmsg::patch_id(&mut m, &id);
                if app.cfg.log_queries {
                    eprintln!(
                        "Q {} {} {} hit rcode={} {}us",
                        transport,
                        qname,
                        qtype,
                        dnsmsg::rcode(&m),
                        t0.elapsed().as_micros()
                    );
                }
                return Reply::Owned(m);
            }
            None => {}
        }
    }

    // split routing: CN domains go to the domestic pool (fan-out across
    // legs, single-flight merged). Without a configured pool the query
    // falls through to the foreign chain instead of guessing a resolver.
    if is_cn {
        #[cfg(feature = "up-udp")]
        if let Some(pool) = app.cn_pool.as_ref() {
            return match pool.resolve(&upstream_query, deadline).await {
                Ok(mut r) => {
                    dnsmsg::patch_id(&mut r, &id);
                    if app.cfg.log_queries {
                        eprintln!(
                            "Q {} {} {} CN rcode={} {}us",
                            transport,
                            qname,
                            qtype,
                            dnsmsg::rcode(&r),
                            t0.elapsed().as_micros()
                        );
                    }
                    Reply::Owned(r)
                }
                Err(_) => {
                    Stats::bump(&app.stats.servfail);
                    Reply::Owned(dnsmsg::make_servfail(&q))
                }
            };
        }
    }

    let result = app
        .chain
        .resolve(key.clone(), cacheable, deadline, || upstream_query.clone())
        .await;

    match result {
        Ok(crate::upstream::Out::Shared(body)) => {
            if app.cfg.log_queries {
                eprintln!(
                    "Q {} {} {} miss0 rcode={} {}us",
                    transport,
                    qname,
                    qtype,
                    dnsmsg::rcode(&body),
                    t0.elapsed().as_micros()
                );
            }
            Reply::Shared { prefix: id, body }
        }
        Ok(crate::upstream::Out::Owned(mut r)) => {
            dnsmsg::patch_id(&mut r, &id);
            if app.cfg.log_queries {
                eprintln!(
                    "Q {} {} {} miss rcode={} {}us",
                    transport,
                    qname,
                    qtype,
                    dnsmsg::rcode(&r),
                    t0.elapsed().as_micros()
                );
            }
            Reply::Owned(r)
        }
        Err(_) => {
            // stale fallback: serve expired cache entry rather than SERVFAIL
            if cacheable {
                if let Some(mut stale) = app.cache.lock().unwrap().get_stale(&key) {
                    dnsmsg::patch_id(&mut stale, &id);
                    Stats::bump(&app.stats.stale_serves);
                    return Reply::Owned(stale);
                }
            }
            Stats::bump(&app.stats.servfail);
            Reply::Owned(dnsmsg::make_servfail(&q))
        }
    }
}

/// Resolve a host:port into candidate socket addrs, filtered by the SSRF guard.
/// For literal IPs no DNS lookup happens.
pub async fn resolve_addrs(host: &str, port: u16, allow_private: bool) -> Vec<SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return if cfg::addr_allowed(ip, allow_private) {
            vec![SocketAddr::new(ip, port)]
        } else {
            Vec::new()
        };
    }
    match tokio::net::lookup_host((host, port)).await {
        Ok(it) => it
            .filter(|a| cfg::addr_allowed(a.ip(), allow_private))
            .take(4)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Bind a dual-stack listening TCP socket: [::] with IPV6_V6ONLY=0 accepts v4 too.
pub fn dual_tcp_socket(addr: SocketAddr, backlog: i32) -> Result<std::net::TcpListener, String> {
    let domain = Domain::for_address(addr);
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| format!("socket: {e}"))?;
    if addr.is_ipv6() {
        sock.set_only_v6(false)
            .map_err(|e| format!("v6only: {e}"))?;
    }
    sock.set_reuse_address(true)
        .map_err(|e| format!("reuse: {e}"))?;
    sock.bind(&addr.into())
        .map_err(|e| format!("bind {addr}: {e}"))?;
    sock.listen(backlog).map_err(|e| format!("listen: {e}"))?;
    sock.set_nonblocking(true)
        .map_err(|e| format!("nonblocking: {e}"))?;
    Ok(sock.into())
}

/// Dual-stack UDP socket for QUIC.
pub fn dual_udp_socket(addr: SocketAddr) -> Result<std::net::UdpSocket, String> {
    let domain = Domain::for_address(addr);
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("socket: {e}"))?;
    if addr.is_ipv6() {
        sock.set_only_v6(false)
            .map_err(|e| format!("v6only: {e}"))?;
    }
    sock.bind(&addr.into())
        .map_err(|e| format!("bind {addr}: {e}"))?;
    sock.set_nonblocking(true)
        .map_err(|e| format!("nonblocking: {e}"))?;
    Ok(sock.into())
}
