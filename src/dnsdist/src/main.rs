mod app;
mod cache;
mod cfg;
mod dnsmsg;
#[cfg(feature = "up-doh")]
mod doh;
mod doq;
mod dot;
mod frame;
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

const DEFAULT_CONF: &str = "/etc/magdns/magdns.conf";

fn usage() {
    eprintln!("magdns - private DoT/DoQ relay with magazine cache");
    eprintln!("usage: magdns [-c /path/magdns.conf] [-v] [--check]");
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
        for (i, s) in c.upstreams.iter().enumerate() {
            println!("upstream #{} {}://{}:{}{}", i + 1, s.kind.tag(), s.host, s.port, s.path);
        }
        println!(
            "listen_dot={} listen_doq={} cache={}B/{}s cert={}",
            c.listen_dot, c.listen_doq, c.cache_bytes, c.cache_ttl, c.cert_file
        );
        println!("config OK");
        std::process::exit(0);
    }

    // 2 workers + small stacks: DNS relay work is tiny; keeps RSS inside the
    // magazine + 8MB budget on the 1G box
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(256 * 1024)
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
    let rustls_doq = match tlsconf::load_server_config(&c.cert_file, &c.key_file, &[b"doq"], false) {
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
    let chain = match upstream::Chain::new(&c, stats.clone(), cache.clone()) {
        Ok(ch) => ch,
        Err(e) => {
            eprintln!("magdns: {e}");
            std::process::exit(1);
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

    let app = Arc::new(App {
        cfg: c.clone(),
        stats: stats.clone(),
        cache: cache.clone(),
        chain,
        server_tls_dot: RwLock::new(rustls_dot),
        server_tls_doq: RwLock::new(rustls_doq),
        doq_endpoint: RwLock::new(Some(doq_endpoint.clone())),
    });

    tokio::spawn(dot::run_listener(app.clone(), tcp_listener));
    tokio::spawn(doq::run_server(app.clone(), doq_endpoint));

    eprintln!(
        "magdns {} up: dot={} doq={} upstreams=[{}]",
        env!("CARGO_PKG_VERSION"),
        c.listen_dot,
        c.listen_doq,
        app.chain.sources_desc().join(", ")
    );

    let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT");
    let mut hup = signal(SignalKind::hangup()).expect("SIGHUP");
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
            _ = hup.recv() => {
                match reload_dynamic(&app) {
                    Ok(()) => eprintln!("magdns: dynamic reload ok (certs + magazine)"),
                    Err(e) => eprintln!("magdns: reload failed, keeping old: {e}"),
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

/// SIGHUP: re-read the config file and apply the hot-reloadable knobs:
/// listener certificates + magazine size/TTL. Everything else keeps its
/// startup value until a process restart.
fn reload_dynamic(app: &Arc<App>) -> Result<(), String> {
    let text = std::fs::read_to_string(&app.cfg.conf_path)
        .map_err(|e| format!("read {}: {e}", app.cfg.conf_path))?;
    let c = cfg::parse(&text)?;
    cfg::validate(&c)?;
    // certs (paths may have changed too)
    let new_dot = tlsconf::load_server_config(&c.cert_file, &c.key_file, &[b"dot"], true)?;
    let new_doq = tlsconf::load_server_config(&c.cert_file, &c.key_file, &[b"doq"], false)?;
    *app.server_tls_dot.write().unwrap() = Arc::new(new_dot);
    *app.server_tls_doq.write().unwrap() = Arc::new(new_doq);
    let quinn_cfg = doq::build_server_config(
        app.server_tls_doq.read().unwrap().clone(),
        app.cfg.idle_timeout_ms,
    );
    if let Some(ep) = app.doq_endpoint.read().unwrap().as_ref() {
        ep.set_server_config(Some(quinn_cfg));
    }
    // magazine resize (evicts from the tail on shrink)
    {
        let mut cache = app.cache.lock().unwrap();
        let snap = cache.snapshot();
        if snap.cap_bytes != c.cache_bytes || snap.ttl_secs != c.cache_ttl
            || snap.ignore_ttl != c.cache_ttl_ignore
        {
            eprintln!(
                "magdns: magazine resize {}B/{}s{} -> {}B/{}s{}",
                snap.cap_bytes, snap.ttl_secs,
                if snap.ignore_ttl { " (ttl ignored)" } else { "" },
                c.cache_bytes, c.cache_ttl,
                if c.cache_ttl_ignore { " (ttl ignored)" } else { "" }
            );
            cache.resize(c.cache_bytes, c.cache_ttl, c.cache_ttl_ignore);
        }
    }
    app.stats.reloads.fetch_add(1, Ordering::Relaxed);
    Ok(())
}
