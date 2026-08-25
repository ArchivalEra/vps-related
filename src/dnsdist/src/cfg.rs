// magdns configuration: simple `key = value` lines, '#' comments, repeatable `upstream`.
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrcKind {
    Quic,
    Tls,
    Doh,
    Udp,
}

impl SrcKind {
    pub fn tag(&self) -> &'static str {
        match self {
            SrcKind::Quic => "doq",
            SrcKind::Tls => "dot",
            SrcKind::Doh => "doh",
            SrcKind::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SourceSpec {
    pub kind: SrcKind,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub raw: String,
}

#[derive(Clone, Debug)]
pub struct Cfg {
    pub conf_path: String, // set by main(); SIGHUP re-reads this file
    pub listen_dot: String,
    pub listen_doq: String,
    pub cert_file: String,
    pub key_file: String,
    pub extra_ca: Option<String>,
    pub upstreams: Vec<SourceSpec>,
    pub allow_private_upstream: bool,
    pub cache_bytes: usize,
    pub cache_ttl: u64,
    pub cache_ttl_ignore: bool,
    pub ecs_enabled: bool,
    pub ecs_prefix_v4: u8,
    pub ecs_prefix_v6: u8,
    // Split routing: domestic chain (bypasses cache entirely)
    pub cn_upstreams: Vec<String>,
    pub cn_domain_file: String,
    pub cn_cache: bool,
    pub maker_auth_kind: String,
    pub maker_auth_key: String,
    pub query_timeout_ms: u64,
    pub attempt_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub probe_interval_s: u64,
    pub stale_on_failure: bool,
    pub verbose: bool,
    pub log_queries: bool,
    // 5000 QPS hardening: layered token buckets (rate=0 disables a layer)
    pub qps_per_ip: u32,
    pub burst_per_ip: u32,
    pub qps_global: u32,
    pub burst_global: u32,
    pub qps_domain: u32,
    pub burst_domain: u32,
    pub domain_limit_entries: usize,
    pub max_concurrent_queries: usize,
    /// rotate the alive-source start per query so concurrent queries fan out
    /// across peer upstreams (off = strict configured priority)
    pub spread_upstreams: bool,
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg {
            conf_path: String::new(),
            listen_dot: "[::]:853".into(),
            listen_doq: "[::]:8853".into(),
            cert_file: String::new(),
            key_file: String::new(),
            extra_ca: None,
            upstreams: Vec::new(),
            allow_private_upstream: false,
            cache_bytes: 100 * 1024 * 1024,
            cache_ttl: 1200,
            cache_ttl_ignore: false,
            ecs_enabled: true,
            ecs_prefix_v4: 24,
            ecs_prefix_v6: 56,
            cn_upstreams: Vec::new(),
            cn_domain_file: String::new(),
            cn_cache: false,
            maker_auth_kind: String::new(),
            maker_auth_key: String::new(),
            query_timeout_ms: 500,
            attempt_timeout_ms: 200,
            idle_timeout_ms: 30_000,
            probe_interval_s: 10,
            stale_on_failure: true,
            verbose: false,
            log_queries: false,
            qps_per_ip: 50,
            burst_per_ip: 100,
            qps_global: 5000,
            burst_global: 10000,
            qps_domain: 100,
            burst_domain: 200,
            domain_limit_entries: 8192,
            max_concurrent_queries: 1024,
            spread_upstreams: false,
        }
    }
}

pub fn parse(text: &str) -> Result<Cfg, String> {
    let mut c = Cfg::default();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected key = value", lineno + 1))?;
        let k = k.trim();
        let v = v.trim().trim_matches('"');
        match k {
            "listen_dot" => c.listen_dot = v.to_string(),
            "listen_doq" => c.listen_doq = v.to_string(),
            "cert_file" => c.cert_file = v.to_string(),
            "key_file" => c.key_file = v.to_string(),
            "extra_ca" => c.extra_ca = Some(v.to_string()),
            "upstream" => c.upstreams.push(parse_upstream(v)?),
            "allow_private_upstream" => c.allow_private_upstream = v == "true" || v == "1",
            "cache_bytes" => c.cache_bytes = v.parse().map_err(|_| "bad cache_bytes")?,
            "cache_ttl" => c.cache_ttl = v.parse().map_err(|_| "bad cache_ttl")?,
            "cache_ttl_ignore" => c.cache_ttl_ignore = v == "true" || v == "1",
            "ecs_enabled" => c.ecs_enabled = v == "true" || v == "1",
            "ecs_prefix_v4" => c.ecs_prefix_v4 = v.parse().map_err(|_| "bad ecs_prefix_v4")?,
            "ecs_prefix_v6" => c.ecs_prefix_v6 = v.parse().map_err(|_| "bad ecs_prefix_v6")?,
            "cn_upstream" => c.cn_upstreams.push(v.to_string()),
            "cn_domain_file" => c.cn_domain_file = v.to_string(),
            "cn_cache" => c.cn_cache = v == "true" || v == "1",
            "maker_auth_kind" => c.maker_auth_kind = v.to_string(),
            "maker_auth_key" => c.maker_auth_key = v.to_string(),
            "query_timeout_ms" => {
                c.query_timeout_ms = v.parse().map_err(|_| "bad query_timeout_ms")?
            }
            "attempt_timeout_ms" => {
                c.attempt_timeout_ms = v.parse().map_err(|_| "bad attempt_timeout_ms")?
            }
            "idle_timeout_ms" => {
                c.idle_timeout_ms = v.parse().map_err(|_| "bad idle_timeout_ms")?
            }
            "probe_interval_s" => {
                c.probe_interval_s = v.parse().map_err(|_| "bad probe_interval_s")?
            }
            "stale_on_failure" => c.stale_on_failure = v == "true" || v == "1",
            "verbose" => c.verbose = v == "true" || v == "1",
            "log_queries" => c.log_queries = v == "true" || v == "1",
            "qps_per_ip" => c.qps_per_ip = v.parse().map_err(|_| "bad qps_per_ip")?,
            "burst_per_ip" => c.burst_per_ip = v.parse().map_err(|_| "bad burst_per_ip")?,
            "qps_global" => c.qps_global = v.parse().map_err(|_| "bad qps_global")?,
            "burst_global" => c.burst_global = v.parse().map_err(|_| "bad burst_global")?,
            "qps_domain" => c.qps_domain = v.parse().map_err(|_| "bad qps_domain")?,
            "burst_domain" => c.burst_domain = v.parse().map_err(|_| "bad burst_domain")?,
            "domain_limit_entries" => {
                c.domain_limit_entries = v.parse().map_err(|_| "bad domain_limit_entries")?
            }
            "spread_upstreams" => c.spread_upstreams = v == "true" || v == "1",
            "max_concurrent_queries" => {
                c.max_concurrent_queries = v.parse().map_err(|_| "bad max_concurrent_queries")?
            }
            other => return Err(format!("line {}: unknown key {}", lineno + 1, other)),
        }
    }
    Ok(c)
}

pub fn parse_upstream(raw: &str) -> Result<SourceSpec, String> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| format!("upstream `{}`: missing scheme://", raw))?;
    let kind = match scheme {
        "quic" if cfg!(feature = "up-quic") => SrcKind::Quic,
        "tls" if cfg!(feature = "up-tls") => SrcKind::Tls,
        "https" if cfg!(feature = "up-doh") => SrcKind::Doh,
        "udp" if cfg!(feature = "up-udp") => SrcKind::Udp,
        "http" => {
            return Err(format!(
                "upstream `{}`: plain http is not allowed, use https",
                raw
            ))
        }
        other => {
            return Err(format!(
                "upstream `{}`: scheme `{}` not compiled into this binary",
                raw, other
            ))
        }
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(format!("upstream `{}`: empty host", raw));
    }
    let default_port = match kind {
        SrcKind::Doh => 443u16,
        SrcKind::Udp => 53u16,
        _ => 853u16,
    };
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (h, tail) = inner
            .split_once(']')
            .ok_or_else(|| format!("upstream `{}`: unterminated [ipv6]", raw))?;
        let p = match tail.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| format!("upstream `{}`: bad port", raw))?,
            None => default_port,
        };
        (h.to_string(), p)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (
                h.to_string(),
                p.parse()
                    .map_err(|_| format!("upstream `{}`: bad port", raw))?,
            ),
            _ => (authority.to_string(), default_port),
        }
    };
    if host.is_empty() {
        return Err(format!("upstream `{}`: empty host", raw));
    }
    let path = match kind {
        SrcKind::Doh => {
            if path.is_empty() {
                "/dns-query".to_string()
            } else if path.starts_with('/') {
                path.to_string()
            } else {
                return Err(format!("upstream `{}`: path must start with /", raw));
            }
        }
        _ => {
            if !path.is_empty() {
                return Err(format!(
                    "upstream `{}`: path not allowed for {}://",
                    raw, scheme
                ));
            }
            String::new()
        }
    };
    Ok(SourceSpec {
        kind,
        host,
        port,
        path,
        raw: raw.to_string(),
    })
}

/// SSRF guard: reject loopback/private/link-local upstream endpoints unless explicitly allowed
/// by the operator (stage tests / a local ShadowTLS forwarder need this).
pub fn addr_allowed(ip: IpAddr, allow_private: bool) -> bool {
    if allow_private {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfe00 // link-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // deprecated ll
                || (v6.segments()[0] & 0xff00) == 0xfc00) // ULA
        }
    }
}

pub fn validate(c: &Cfg) -> Result<(), String> {
    if c.upstreams.is_empty() {
        return Err("no upstream configured (need at least one `upstream = ...`)".into());
    }
    for s in &c.upstreams {
        if s.host.eq_ignore_ascii_case("localhost") && !c.allow_private_upstream {
            return Err(format!(
                "upstream `{}`: localhost rejected (set allow_private_upstream = true if intended)",
                s.raw
            ));
        }
        if let Ok(ip) = s.host.parse::<IpAddr>() {
            if !addr_allowed(ip, c.allow_private_upstream) {
                return Err(format!(
                    "upstream `{}`: private/loopback address rejected (set allow_private_upstream = true if intended)",
                    s.raw
                ));
            }
        }
    }
    if c.cert_file.is_empty() || c.key_file.is_empty() {
        return Err("cert_file/key_file required (listeners speak DoT/DoQ)".into());
    }
    c.listen_dot
        .parse::<SocketAddr>()
        .map_err(|_| format!("bad listen_dot `{}`", c.listen_dot))?;
    c.listen_doq
        .parse::<SocketAddr>()
        .map_err(|_| format!("bad listen_doq `{}`", c.listen_doq))?;
    if c.cache_bytes < 1024 {
        return Err("cache_bytes too small".into());
    }
    if c.cache_ttl == 0 {
        return Err("cache_ttl must be > 0".into());
    }
    Ok(())
}
