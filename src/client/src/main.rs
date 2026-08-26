// magdns-client — local stub of the private DNS pipeline: standard DNS in
// (UDP / TCP RFC 7766 / plain-HTTP DoH), magazine cache in front, ordered
// MGB1 failover out toward the box (DoT/DoH) and public fallbacks (DoH).
//
//   usage: magdns-client [-c /path/config.json] [--check] [--version]
//
// Secrets never touch disk: server entries name an auth_key_env variable and
// the UUID is read from the environment once at startup.
mod batcher;
mod cache;
mod cfg;
mod dnsmsg;
mod doh;
mod dot;
mod frame;
mod ingress;
mod upstream;

use cfg::ClientCfg;
use std::sync::Arc;

const DEFAULT_CONF: &str = "config.json";

fn usage() {
    eprintln!("magdns-client - local DNS stub with MGB1 batching upstream");
    eprintln!("usage: magdns-client [-c /path/config.json] [--check]");
}

fn main() {
    let mut conf_path = DEFAULT_CONF.to_string();
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => match args.next() {
                Some(p) => conf_path = p,
                None => {
                    usage();
                    std::process::exit(2);
                }
            },
            "--check" => check = true,
            "--version" => {
                println!("magdns-client {}", env!("CARGO_PKG_VERSION"));
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
            eprintln!("magdns-client: cannot read config {conf_path}: {e}");
            std::process::exit(1);
        }
    };
    let c = match cfg::parse(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("magdns-client: config error: {e}");
            std::process::exit(1);
        }
    };
    if check {
        println!(
            "listen udp={} tcp={} doh={}",
            fmt_opt(&c.listen_udp),
            fmt_opt(&c.listen_tcp),
            fmt_opt(&c.listen_doh)
        );
        for (i, s) in c.servers.iter().enumerate() {
            println!(
                "  #{} {} {}://{}:{}{} batch={} compress={:?} h2={} auth={}",
                i + 1,
                s.name,
                s.proto.tag(),
                s.host,
                s.port,
                s.path,
                s.batch,
                s.compress,
                s.h2_fanout,
                if s.uuid.is_some() { "uuid-env" } else { "none" },
            );
        }
        println!("cache: {}B/{}s", c.cache_bytes, c.cache_ttl.as_secs());
        println!("config OK");
        std::process::exit(0);
    }

    // 2 workers + modest stacks, same sizing rationale as the box: relay work
    // is tiny and unoptimized dev builds overflow small stacks inside rustls.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(1024 * 1024)
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(run(c));
}

fn fmt_opt(v: &Option<std::net::SocketAddr>) -> String {
    match v {
        Some(a) => a.to_string(),
        None => "off".to_string(),
    }
}

async fn run(c: ClientCfg) {
    let chain = match upstream::Chain::build(&c) {
        Ok(ch) => Arc::new(ch),
        Err(e) => {
            eprintln!("magdns-client: {e}");
            std::process::exit(1);
        }
    };

    // Bind everything up front: a taken port must abort startup loudly.
    let mut listeners: Vec<tokio::task::JoinHandle<std::io::Result<()>>> = Vec::new();
    if let Some(addr) = c.listen_udp {
        match tokio::net::UdpSocket::bind(addr).await {
            Ok(s) => {
                eprintln!("magdns-client: udp listening on {addr}");
                listeners.push(tokio::spawn(ingress::udp_loop(chain.clone(), Arc::new(s))));
            }
            Err(e) => {
                eprintln!("magdns-client: bind udp {addr}: {e}");
                std::process::exit(1);
            }
        }
    }
    if let Some(addr) = c.listen_tcp {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                eprintln!("magdns-client: tcp listening on {addr}");
                listeners.push(tokio::spawn(ingress::tcp_loop(chain.clone(), l)));
            }
            Err(e) => {
                eprintln!("magdns-client: bind tcp {addr}: {e}");
                std::process::exit(1);
            }
        }
    }
    if let Some(addr) = c.listen_doh {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                eprintln!("magdns-client: doh (plain http) listening on {addr}");
                listeners.push(tokio::spawn(ingress::doh_loop(chain.clone(), l)));
            }
            Err(e) => {
                eprintln!("magdns-client: bind doh {addr}: {e}");
                std::process::exit(1);
            }
        }
    }
    if listeners.is_empty() {
        eprintln!("magdns-client: no listener configured — set listen.udp/tcp/doh");
        std::process::exit(1);
    }

    eprintln!(
        "magdns-client {} up: sources=[{}]",
        env!("CARGO_PKG_VERSION"),
        chain.describe().join(", ")
    );

    // Listener loops never return; only a signal ends the process.
    let mut term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM");
    let mut int =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).expect("SIGINT");
    tokio::select! {
        _ = term.recv() => eprintln!("magdns-client: terminating"),
        _ = int.recv() => eprintln!("magdns-client: interrupted"),
    }
}
