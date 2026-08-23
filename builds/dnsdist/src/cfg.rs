// magdns configuration: simple `key = value` lines, '#' comments, repeatable `upstream`.
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrcKind {
    Quic,
    Tls,
    Doh,
}

impl SrcKind {
    pub fn tag(&self) -> &'static str {
        match self {
            SrcKind::Quic => "doq",
            SrcKind::Tls => "dot",
            SrcKind::Doh => "doh",
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
    pub query_timeout_ms: u64,
    pub attempt_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub probe_interval_s: u64,
    pub verbose: bool,
    pub log_queries: bool,
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
            query_timeout_ms: 3000,
            attempt_timeout_ms: 1500,
            idle_timeout_ms: 45_000,
            probe_interval_s: 12,
            verbose: false,
            log_queries: false,
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
            "query_timeout_ms" => c.query_timeout_ms = v.parse().map_err(|_| "bad query_timeout_ms")?,
            "attempt_timeout_ms" => c.attempt_timeout_ms = v.parse().map_err(|_| "bad attempt_timeout_ms")?,
            "idle_timeout_ms" => c.idle_timeout_ms = v.parse().map_err(|_| "bad idle_timeout_ms")?,
            "probe_interval_s" => c.probe_interval_s = v.parse().map_err(|_| "bad probe_interval_s")?,
            "verbose" => c.verbose = v == "true" || v == "1",
            "log_queries" => c.log_queries = v == "true" || v == "1",
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
        "quic" => SrcKind::Quic,
        "tls" => SrcKind::Tls,
        "https" => SrcKind::Doh,
        "http" => return Err(format!("upstream `{}`: plain http is not allowed, use https", raw)),
        other => return Err(format!("upstream `{}`: unknown scheme `{}`", raw, other)),
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
        _ => 853u16,
    };
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (h, tail) = inner
            .split_once(']')
            .ok_or_else(|| format!("upstream `{}`: unterminated [ipv6]", raw))?;
        let p = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| format!("upstream `{}`: bad port", raw))?,
            None => default_port,
        };
        (h.to_string(), p)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (
                h.to_string(),
                p.parse().map_err(|_| format!("upstream `{}`: bad port", raw))?,
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
                return Err(format!("upstream `{}`: path not allowed for {}://", raw, scheme));
            }
            String::new()
        }
    };
    Ok(SourceSpec { kind, host, port, path, raw: raw.to_string() })
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
