mod app;
mod cache;
mod chains;
mod cfg;
#[cfg(feature = "up-udp")]
mod cnpool;
mod dnsmsg;
#[cfg(feature = "up-doh")]
mod doh;
mod dohserver;
mod doq;
mod dot;
mod flightmap;
mod frame;
mod ingress;
mod maker_auth;
mod ratelimit;
mod router;
mod stats;
mod tlsconf;
#[cfg(feature = "up-udp")]
mod udpsrc;
mod upstream;

use app::App;
use cache::MagCache;
use cfg::Cfg;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use tokio::signal::unix::{signal, SignalKind};

const DEFAULT_CONF: &str = "/etc/magdns/config.json";

fn usage() {
    eprintln!("magdns - private DoT/DoQ relay with magazine cache");
    eprintln!("usage: magdns [-c /path/config.json] [-v] [--check]");
}

/// Operator-supplied config path: must be absolute, no `..` components.
fn checked_path(p: &str) -> Result<String, String> {
    if !p.starts_with('/') {
        return Err(format!("path `{p}` must be absolute"));
    }
    if p.split('/').any(|seg| seg == "..") {
        return Err(format!("path `{p}` must not contain `..`"));
    }
    Ok(p.to_string())
}

fn main() {
    let mut conf_path = DEFAULT_CONF.to_string();
    let mut verbose = false;
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => match args.next().map(|p| checked_path(&p)).transpose() {
                Ok(Some(p)) => conf_path = p,
                Ok(None) => {
                    usage();
                    std::process::exit(2);
                }
                Err(e) => {
                    eprintln!("magdns: {e}");
                    std::process::exit(2);
                }
            },
            "-v" | "--verbose" => verbose = true,
            "--check" => check = true,
            "--version" => {
                println!("magdns {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => {
                usage();
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown arg {other}");
                usage();
                std::process::exit(2);
            }
        }
    }

    let text = match std::fs::read_to_string(&conf_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("magdns: cannot read config {conf_path}: {e}");
            std::process::exit(1);
        }
    };
    let mut c: Cfg = match cfg::parse(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("magdns: config error: {e}");
            std::process::exit(1);
        }
    };
    if verbose {
        c.verbose = true;
    }
    c.conf_path = conf_path.clone();
    if let Err(e) = cfg::validate(&c) {
        eprintln!("magdns: config invalid: {e}");
        std::process::exit(1);
    }
    if check {
        println!(
            "listen dot={} doq={} doh={} cache={}B/{}s",
            c.listen_dot, c.listen_doq,
            if c.listen_doh.is_empty() { "off" } else { &c.listen_doh },
            c.cache_bytes, c.cache_ttl
        );
        println!("foreign: enabled={} spread={} sources={}",
            c.foreign_enabled, c.spread_upstreams, c.upstreams.len());
        for (i, s) in c.upstreams.iter().enumerate() {
            println!(
                "  #{} {}://{}:{}{} batch={} h2={} cache={}",
                i + 1, s.kind.tag(), s.host, s.port, s.path,
                s.batch, s.h2_fanout, s.cache
            );
        }
        if c.cn_enabled {
            println!("cn_split: enabled domains={} legs={}",
                c.cn_domain_file, c.cn_upstreams.len());
        }
        println!("auth client_uuids={} ecs={} rate per_ip={}/{} global={}/{} domain={}/{}",
            c.client_uuids.len(), c.ecs_enabled,
            c.qps_per_ip, c.burst_per_ip,
            c.qps_global, c.burst_global,
            c.qps_domain, c.burst_domain);
        println!("config OK");
        std::process::exit(0);
    }

    // 2 workers + modest stacks: DNS relay work is tiny; keeps RSS inside the
    // magazine + 8MB budget on the 1G box. 1MB (not 256KB): unoptimized dev
    // builds overflow 256KB inside hyper/rustls handshakes, and the extra
    // ~1.5MB resident for two workers is cheap insurance everywhere.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(1024 * 1024)
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(run(c));
}

async fn run(c: Cfg) {
    let rustls_dot = match tlsconf::load_server_config(&c.cert_file, &c.key_file, &[b"dot"], true) {
        Ok(v) => Arc::new(v),
        Err(e) => {
            eprintln!("magdns: {e}");
            std::process::exit(1);
        }
    };
    let rustls_doq = match tlsconf::load_server_config(&c.cert_file, &c.key_file, &[b"doq"], false)
    {
        Ok(v) => Arc::new(v),
        Err(e) => {
            eprintln!("magdns: {e}");
            std::process::exit(1);
        }
    };

    let stats = Arc::new(stats::Stats::default());
    let cache = Arc::new(Mutex::new(MagCache::new(
        c.cache_bytes,
        c.cache_ttl,
        c.cache_ttl_ignore,
    )));
    let routing = RwLock::new(match app::Routing::build(&c, stats.clone(), cache.clone()) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            eprintln!("magdns: {e}");
            std::process::exit(1);
        }
    });

    // optional inbound standard DoH (443): same pipeline, UUID-gated
    let (doh_listener, doh_tls) = if c.listen_doh.is_empty() {
        (None, None)
    } else {
        let addr: std::net::SocketAddr = c.listen_doh.parse().unwrap_or_else(|e| {
            eprintln!("magdns: bad listen.doh: {e}");
            std::process::exit(1);
        });
        let tls = tlsconf::load_server_config(&c.cert_file, &c.key_file, &[b"h2", b"http/1.1"], false)
            .map(Arc::new)
            .map_err(|e| {
                eprintln!("magdns: {e}");
                std::process::exit(1);
            })
            .unwrap();
        match app::dual_tcp_socket(addr, 256) {
            Ok(std_l) => match tokio::net::TcpListener::from_std(std_l) {
                Ok(l) => (Some(l), Some(tls)),
                Err(e) => {
                    eprintln!("magdns: doh bind: {e}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("magdns: doh socket: {e}");
                std::process::exit(1);
            }
        }
    };

    let dot_addr = c.listen_dot.parse().unwrap();
    let doq_addr = c.listen_doq.parse().unwrap();
    let tcp_listener = match app::dual_tcp_socket(dot_addr, 1024)
        .map_err(|e| e.to_string())
        .and_then(|l| tokio::net::TcpListener::from_std(l).map_err(|e| e.to_string()))
    {
        Ok(l) => l,
        Err(e) => {
            eprintln!("magdns: {e}");
            std::process::exit(1);
        }
    };
    let udp_sock = match app::dual_udp_socket(doq_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("magdns: {e}");
            std::process::exit(1);
        }
    };
    let quinn_server = doq::build_server_config(rustls_doq.clone(), c.idle_timeout_ms);
    let doq_endpoint = match quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quinn_server),
        udp_sock,
        Arc::new(quinn::TokioRuntime),
    ) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("magdns: quic endpoint: {e}");
            std::process::exit(1);
        }
    };

    // router: load CN domain list if configured
    let mut router = router::Router::new(vec![
        router::Route {
            name: "cn".into(),
            upstreams: vec![],
            cache_enabled: false,
            ecs_enabled: false,
        },
        router::Route {
            name: "foreign".into(),
            upstreams: vec![],
            cache_enabled: true,
            ecs_enabled: true,
        },
    ]);
    if !c.cn_domain_file.is_empty() {
        match std::fs::read_to_string(&c.cn_domain_file) {
            Ok(content) => {
                let count = router.load_domain_list(&content, 0);
                eprintln!(
                    "magdns: loaded {} CN domains from {}",
                    count, c.cn_domain_file
                );
            }
            Err(e) => eprintln!("magdns: WARN cannot read {}: {}", c.cn_domain_file, e),
        }
    }

    let rate_limiter = crate::ratelimit::RateLimiter::new(c.qps_per_ip, c.burst_per_ip, 65536);
    let domain_limiter =
        crate::ratelimit::KeyedLimiter::new(c.qps_domain, c.burst_domain, c.domain_limit_entries);
    let global_limiter = crate::ratelimit::GlobalLimiter::new(c.qps_global, c.burst_global);
    let query_gate = std::sync::Arc::new(tokio::sync::Semaphore::new(c.max_concurrent_queries));

    let app = Arc::new(App {
        cfg: c.clone(),
        stats: stats.clone(),
        cache: cache.clone(),
        routing,
        router: RwLock::new(Some(router)),
        rate_limiter,
        domain_limiter,
        global_limiter,
        query_gate,
        server_tls_dot: RwLock::new(rustls_dot),
        server_tls_doh: RwLock::new(doh_tls.clone().unwrap_or_else(|| {
            Arc::new(tlsconf::load_server_config(&c.cert_file, &c.key_file, &[], false).expect("doh tls"))
        })),
        server_tls_doq: RwLock::new(rustls_doq),
        doq_endpoint: RwLock::new(Some(doq_endpoint.clone())),
    });

    tokio::spawn(dot::run_listener(app.clone(), tcp_listener));
    tokio::spawn(doq::run_server(app.clone(), doq_endpoint));
    if let (Some(l), Some(t)) = (doh_listener, doh_tls) {
        *app.server_tls_doh.write().unwrap() = t;
        tokio::spawn(dohserver::run_listener(app.clone(), l));
        eprintln!("magdns: serving inbound DoH on {}", c.listen_doh);
    }

    eprintln!(
        "magdns {} up: dot={} doq={} upstreams=[{}]",
        env!("CARGO_PKG_VERSION"),
        c.listen_dot,
        c.listen_doq,
        app.routing.read().unwrap().sources_desc().join(", ")
    );

    // Hot reload is opt-in via config.json (`"hot_reload": true`). When off,
    // SIGHUP does nothing and config changes take effect on restart — the
    // steady-state costs nothing. When on, SIGHUP rebuilds ONLY the routing
    // generation (foreign sources + CN legs): a fresh validated Routing is
    // built first and swapped in atomically; a broken file keeps the old
    // generation untouched. Certs/cache/rate limits remain startup-only.
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT");
    let mut hup = if c.hot_reload {
        Some(signal(SignalKind::hangup()).expect("SIGHUP"))
    } else {
        None
    };
    let mut usr1 = signal(SignalKind::user_defined1()).expect("SIGUSR1");

    loop {
        tokio::select! {
            _ = term.recv() => {
                eprintln!("magdns: terminating");
                dump_stats(&app);
                break;
            }
            _ = int.recv() => {
                eprintln!("magdns: interrupted");
                dump_stats(&app);
                break;
            }
            _ = async {
                match hup.as_mut() {
                    Some(h) => h.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match app::Routing::build(&c, stats.clone(), app.cache.clone()) {
                    Ok(new_gen) => {
                        *app.routing.write().unwrap() = Arc::new(new_gen);
                        app.stats.reloads.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "magdns: hot reload applied — foreign={} cn={} (gen {})",
                            app.routing.read().unwrap().chain.sources_desc().join(", "),
                            c.cn_enabled,
                            app.stats.reloads.load(Ordering::Relaxed)
                        );
                    }
                    Err(e) => eprintln!("magdns: hot reload rejected, keeping old generation: {e}"),
                }
            }
            _ = usr1.recv() => {
                dump_stats(&app);
            }
        }
    }
    // exit(0) so the LLVM PGO runtime flushes counters; systemd restarts us on
    // the target box, which is never rebooted.
    std::process::exit(0);
}

fn dump_stats(app: &Arc<App>) {
    let snap = app.cache.lock().unwrap().snapshot();
    let rss = rss_bytes();
    eprintln!("{}", app.stats.dump(&snap, rss));
}

/// RSS via /proc/self/statm (2nd field = resident pages; 1st is VmSize); 0 when unavailable.
fn rss_bytes() -> u64 {
    if let Ok(s) = std::fs::read_to_string("/proc/self/statm") {
        if let Some(resident) = s.split_whitespace().nth(1) {
            if let Ok(pages) = resident.parse::<u64>() {
                return pages * 4096;
            }
        }
    }
    0
}
