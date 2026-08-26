// magdns configuration: one JSON file, `config.json`. Changing anything
// requires a service restart — there is deliberately no hot reload.
//
// Schema (every section optional unless marked required; absent sections
// disable that feature entirely):
//
// {
//   "listen":  { "dot": "[::]:853", "doq": "[::]:8853", "doh": "[::]:443" },
//   "tls":     { "cert_file": "...", "key_file": "...", "extra_ca": "..." },
//   "auth":    { "client_uuids": ["…"] },            // empty = trust all
//   "cache":   { "bytes": 104857600, "ttl": 1200, "ttl_ignore": false },
//   "ecs":     { "enabled": true, "prefix_v4": 24, "prefix_v6": 56 },
//   "foreign": {                                      // absent = no foreign chain
//     "enabled": true, "spread": false,
//     "upstreams": [ { "url": "https://…", "auth_kind": "token",
//                      "auth_key_env": "MAKER_A_TOKEN", "h2": 8,
//                      "batch": true, "noecs": false, "cache": true } ]
//   },
//   "cn_split": {                                     // absent = never split
//     "enabled": true, "domain_file": "…",
//     "upstreams": [ { "url": "udp://223.5.5.5:53", "cache": false } ]
//   },
//   "rate_limit": { "per_ip_qps": 50, "per_ip_burst": 100,
//                   "domain_qps": 100, "domain_burst": 200,
//                   "global_qps": 5000, "global_burst": 10000,
//                   "max_concurrent": 1024 },
//   "timeouts_ms": { "query": 500, "attempt": 200, "idle": 30000 },
//   "probe_interval_s": 10, "stale_on_failure": true, "hot_reload": false,
//   "allow_private_upstream": false, "verbose": false, "log_queries": false
// }
//
// Secrets are injected via the environment: an upstream's auth_key_env names
// the variable holding the key; the file itself stays shell-safe to publish.
use std::collections::BTreeMap;
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
    /// source ignores EDNS Client Subnet (Quad9, 114): queries carrying ECS
    /// route around it so geo answers stay geo-correct
    pub noecs: bool,
    /// HTTP/2 connection fan-out for DoH (0 = HTTP/1.1 per-query; 1..=20 =
    /// multiplexed H2 over that many independent connections)
    pub h2_fanout: usize,
    /// pack concurrent queries into one br-compressed request (Maker private
    /// protocol, AIMD-sized); slashes billed request count at the relay
    pub batch: bool,
    /// magazine-cache eligibility for THIS source alone (per-source cache
    /// granularity; foreign legs default true, domestic default false)
    pub cache: bool,
    /// pre-built auth header (header name + value) resolved from the env at
    /// startup — config.json names the variable, never the secret itself
    pub auth: Option<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct Cfg {
    pub conf_path: String, // set by main(); informational after the no-hot-reload decision
    pub listen_dot: String,
    pub listen_doq: String,
    pub listen_doh: String, // empty = DoH listener off
    pub cert_file: String,
    pub key_file: String,
    pub extra_ca: Option<String>,
    pub client_uuids: Vec<String>,
    pub upstreams: Vec<SourceSpec>,
    pub foreign_enabled: bool,
    pub spread_upstreams: bool,
    pub allow_private_upstream: bool,
    pub cache_bytes: usize,
    pub cache_ttl: u64,
    pub cache_ttl_ignore: bool,
    pub ecs_enabled: bool,
    pub ecs_prefix_v4: u8,
    pub ecs_prefix_v6: u8,
    pub cn_enabled: bool,
    pub cn_domain_file: String,
    pub cn_upstreams: Vec<SourceSpec>,
    pub routing: Option<RoutingCfg>,
    pub query_timeout_ms: u64,
    pub attempt_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub probe_interval_s: u64,
    pub stale_on_failure: bool,
    /// when true, SIGHUP re-reads config.json and atomically swaps the
    /// routing generation (sources/splits live); false = restart-only mode.
    /// Listener certs, cache sizing and rate limits are startup-only either way.
    pub hot_reload: bool,
    pub verbose: bool,
    pub log_queries: bool,
    // layered token buckets (rate=0 disables a layer)
    pub qps_per_ip: u32,
    pub burst_per_ip: u32,
    pub qps_global: u32,
    pub burst_global: u32,
    pub qps_domain: u32,
    pub burst_domain: u32,
    pub domain_limit_entries: usize,
    pub max_concurrent_queries: usize,
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg {
            conf_path: String::new(),
            listen_dot: "[::]:853".into(),
            listen_doq: "[::]:8853".into(),
            listen_doh: String::new(),
            cert_file: String::new(),
            key_file: String::new(),
            extra_ca: None,
            client_uuids: Vec::new(),
            upstreams: Vec::new(),
            foreign_enabled: true,
            spread_upstreams: false,
            allow_private_upstream: false,
            cache_bytes: 100 * 1024 * 1024,
            cache_ttl: 1200,
            cache_ttl_ignore: false,
            ecs_enabled: true,
            ecs_prefix_v4: 24,
            ecs_prefix_v6: 56,
            cn_enabled: false,
            cn_domain_file: String::new(),
            cn_upstreams: Vec::new(),
            routing: None,
            query_timeout_ms: 500,
            attempt_timeout_ms: 200,
            idle_timeout_ms: 30_000,
            probe_interval_s: 10,
            stale_on_failure: true,
            hot_reload: false,
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
        }
    }
}

// ---- serde mirror of the schema

fn d_true() -> bool {
    true
}
fn d_false() -> bool {
    false
}

#[derive(serde::Deserialize)]
struct JsonConfig {
    #[serde(default)]
    listen: BTreeMap<String, String>,
    #[serde(default)]
    tls: BTreeMap<String, String>,
    #[serde(default)]
    auth: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    cache: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    ecs: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    foreign: Option<JsonForeign>,
    #[serde(default)]
    routing: Option<RoutingCfg>,
    #[serde(default)]
    cn_split: Option<JsonCnSplit>,
    #[serde(default)]
    rate_limit: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    timeouts_ms: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    probe_interval_s: Option<u64>,
    #[serde(default = "d_false")]
    hot_reload: bool,
    #[serde(default = "d_true")]
    stale_on_failure: bool,
    #[serde(default)]
    allow_private_upstream: bool,
    #[serde(default)]
    verbose: bool,
    #[serde(default)]
    log_queries: bool,
}

#[derive(serde::Deserialize)]
struct JsonForeign {
    #[serde(default = "d_true")]
    enabled: bool,
    #[serde(default)]
    spread: bool,
    // optional when the section only toggles state; empty+enabled is still
    // rejected by validate()
    #[serde(default)]
    upstreams: Option<Vec<JsonUpstream>>,
}

#[derive(serde::Deserialize)]
struct JsonCnSplit {
    #[serde(default = "d_true")]
    enabled: bool,
    #[serde(default)]
    domain_file: String,
    // optional: a split can exist for routing rules alone
    upstreams: Option<Vec<JsonUpstream>>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct JsonUpstream {
    pub url: String,
    #[serde(default)]
    pub auth_kind: Option<String>,
    #[serde(default)]
    pub auth_key_env: Option<String>,
    #[serde(default)]
    pub h2: Option<usize>,
    #[serde(default = "d_false")]
    pub batch: bool,
    #[serde(default = "d_false")]
    pub noecs: bool,
    #[serde(default = "d_true")]
    pub cache: bool,
}

// small typed getters over the Value maps with friendly errors
fn get_u64(m: &BTreeMap<String, serde_json::Value>, key: &str, what: &str) -> Result<Option<u64>, String> {
    match m.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{what}.{key}: expected a non-negative integer")),
    }
}
fn get_bool(m: &BTreeMap<String, serde_json::Value>, key: &str, what: &str) -> Result<Option<bool>, String> {
    match m.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("{what}.{key}: expected true or false")),
    }
}
fn get_str<'a>(m: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    m.get(key).map(|s| s.as_str())
}

fn build_spec(ju: &JsonUpstream, what: &str) -> Result<SourceSpec, String> {
    let mut spec = parse_upstream(&ju.url)?;
    spec.noecs = ju.noecs;
    spec.batch = ju.batch;
    spec.cache = ju.cache;
    match ju.h2 {
        Some(h2) if h2 == 0 || h2 > 20 => {
            return Err(format!("{what} `{}`: h2 must be 1..=20", ju.url))
        }
        // h2 only means anything to https:// legs; other kinds ignore it
        Some(h2) => spec.h2_fanout = if spec.kind == SrcKind::Doh { h2 } else { 0 },
        None => {
            if spec.kind == SrcKind::Doh {
                return Err(format!("{what} `{}`: h2 is required (1..=20)", ju.url));
            }
        }
    }
    if let Some(kind) = &ju.auth_kind {
        let env_name = ju.auth_key_env.as_deref().ok_or_else(|| {
            format!("{what} `{}`: auth_kind requires auth_key_env", ju.url)
        })?;
        let key = std::env::var(env_name).map_err(|_| {
            format!(
                "{what} `{url}`: environment variable {env_name} is not set (secrets are env-injected by design)",
                url = ju.url
            )
        })?;
        if key.is_empty() {
            return Err(format!("{what} `{}`: {} is set but empty", ju.url, env_name));
        }
        spec.auth = Some(match kind.as_str() {
            "token" => ("token".to_string(), key),
            "bearer" => ("authorization".to_string(), format!("Bearer {key}")),
            other => {
                return Err(format!(
                    "{what} `{}`: unknown auth_kind `{other}` (token|bearer)",
                    ju.url,
                ))
            }
        });
    }
    Ok(spec)
}

/// Strip // and /* */ comments outside of string literals, so operator
/// configs can carry annotations. String-aware: `https://` inside a value
/// is never touched.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
                i += 1;
            }
            '/' if i + 1 < bytes.len() && bytes[i + 1] == '/' => {
                while i < bytes.len() && bytes[i] != '\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < bytes.len() && bytes[i + 1] == '*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == '*' && bytes[i + 1] == '/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Parse a config.json into the runtime configuration.
pub fn parse(text: &str) -> Result<Cfg, String> {
    let j: JsonConfig = serde_json::from_str(&strip_comments(text))
        .map_err(|e| format!("config.json: {e}"))?;
    let mut c = Cfg::default();

    if let Some(dot) = get_str(&j.listen, "dot") {
        c.listen_dot = dot.to_string();
    }
    if let Some(doq) = get_str(&j.listen, "doq") {
        c.listen_doq = doq.to_string();
    }
    c.listen_doh = get_str(&j.listen, "doh").unwrap_or("").to_string();

    if let Some(cert) = get_str(&j.tls, "cert_file") {
        c.cert_file = cert.to_string();
    }
    if let Some(key) = get_str(&j.tls, "key_file") {
        c.key_file = key.to_string();
    }
    if let Some(ca) = get_str(&j.tls, "extra_ca") {
        c.extra_ca = Some(ca.to_string());
    }
    if let Some(uuids) = j.auth.get("client_uuids") {
        c.client_uuids = uuids.clone();
    }

    if let Some(v) = get_u64(&j.cache, "bytes", "cache")? {
        c.cache_bytes = v as usize;
    }
    if let Some(v) = get_u64(&j.cache, "ttl", "cache")? {
        c.cache_ttl = v;
    }
    if let Some(v) = get_bool(&j.cache, "ttl_ignore", "cache")? {
        c.cache_ttl_ignore = v;
    }

    if let Some(v) = get_bool(&j.ecs, "enabled", "ecs")? {
        c.ecs_enabled = v;
    }
    if let Some(v) = get_u64(&j.ecs, "prefix_v4", "ecs")? {
        c.ecs_prefix_v4 = v as u8;
    }
    if let Some(v) = get_u64(&j.ecs, "prefix_v6", "ecs")? {
        c.ecs_prefix_v6 = v as u8;
    }

    if j.foreign.is_none() {
        c.foreign_enabled = false;
    }
    c.routing = j.routing.clone();
    if let Some(f) = j.foreign {
        c.foreign_enabled = f.enabled;
        c.spread_upstreams = f.spread;
        for ju in f.upstreams.iter().flatten() {
            c.upstreams.push(build_spec(ju, "foreign upstream")?);
        }
    }

    if let Some(cn) = j.cn_split {
        c.cn_enabled = cn.enabled;
        c.cn_domain_file = cn.domain_file;
        for ju in cn.upstreams.iter().flatten() {
            let mut spec = build_spec(ju, "cn_split upstream")?;
            if spec.kind != SrcKind::Udp {
                return Err(format!(
                    "cn_split upstream `{}`: domestic legs speak udp:// only",
                    ju.url
                ));
            }
            c.cn_upstreams.push(spec);
        }
    }

    if let Some(v) = get_u64(&j.rate_limit, "per_ip_qps", "rate_limit")? {
        c.qps_per_ip = v as u32;
    }
    if let Some(v) = get_u64(&j.rate_limit, "per_ip_burst", "rate_limit")? {
        c.burst_per_ip = v as u32;
    }
    if let Some(v) = get_u64(&j.rate_limit, "domain_qps", "rate_limit")? {
        c.qps_domain = v as u32;
    }
    if let Some(v) = get_u64(&j.rate_limit, "domain_burst", "rate_limit")? {
        c.burst_domain = v as u32;
    }
    if let Some(v) = get_u64(&j.rate_limit, "global_qps", "rate_limit")? {
        c.qps_global = v as u32;
    }
    if let Some(v) = get_u64(&j.rate_limit, "global_burst", "rate_limit")? {
        c.burst_global = v as u32;
    }
    if let Some(v) = get_u64(&j.rate_limit, "max_concurrent", "rate_limit")? {
        c.max_concurrent_queries = v as usize;
    }

    if let Some(v) = get_u64(&j.timeouts_ms, "query", "timeouts_ms")? {
        c.query_timeout_ms = v;
    }
    if let Some(v) = get_u64(&j.timeouts_ms, "attempt", "timeouts_ms")? {
        c.attempt_timeout_ms = v;
    }
    if let Some(v) = get_u64(&j.timeouts_ms, "idle", "timeouts_ms")? {
        c.idle_timeout_ms = v;
    }
    if let Some(v) = j.probe_interval_s {
        c.probe_interval_s = v;
    }
    c.stale_on_failure = j.stale_on_failure;
    c.hot_reload = j.hot_reload;
    c.allow_private_upstream = j.allow_private_upstream;
    c.verbose = j.verbose;
    c.log_queries = j.log_queries;

    Ok(c)
}

/// URL parser kept from the flag era: scheme/host/port/path validation only.
/// Feature switches now arrive as explicit JSON fields.
pub fn parse_upstream(raw: &str) -> Result<SourceSpec, String> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| format!("upstream `{raw}`: missing scheme://"))?;
    let kind = match scheme {
        "quic" if cfg!(feature = "up-quic") => SrcKind::Quic,
        "tls" if cfg!(feature = "up-tls") => SrcKind::Tls,
        "https" if cfg!(feature = "up-doh") => SrcKind::Doh,
        "udp" if cfg!(feature = "up-udp") => SrcKind::Udp,
        "http" => {
            return Err(format!(
                "upstream `{raw}`: plain http is not allowed, use https"
            ))
        }
        other => {
            return Err(format!(
                "upstream `{raw}`: scheme `{other}` not compiled into this binary"
            ))
        }
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(format!("upstream `{raw}`: empty host"));
    }
    let default_port = match kind {
        SrcKind::Doh => 443u16,
        SrcKind::Udp => 53u16,
        _ => 853u16,
    };
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (h, tail) = inner
            .split_once(']')
            .ok_or_else(|| format!("upstream `{raw}`: unterminated [ipv6]"))?;
        let p = match tail.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| format!("upstream `{raw}`: bad port")),
            None => Ok(default_port),
        }?;
        (h.to_string(), p)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (
                h.to_string(),
                p.parse()
                    .map_err(|_| format!("upstream `{raw}`: bad port"))?,
            ),
            _ => (authority.to_string(), default_port),
        }
    };
    if host.is_empty() {
        return Err(format!("upstream `{raw}`: empty host"));
    }
    let path = match kind {
        SrcKind::Doh => {
            if path.is_empty() {
                "/dns-query".to_string()
            } else if path.starts_with('/') {
                path.to_string()
            } else {
                return Err(format!("upstream `{raw}`: path must start with /"));
            }
        }
        _ => {
            if !path.is_empty() {
                return Err(format!(
                    "upstream `{raw}`: path not allowed for {scheme}://"
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
        noecs: false,
        h2_fanout: 0,
        batch: false,
        cache: true,
        auth: None,
    })
}

/// SSRF guard: reject loopback/private/link-local upstream endpoints unless
/// explicitly allowed by the operator.
pub fn addr_allowed(ip: IpAddr, allow_private: bool) -> bool {
    if allow_private {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback() || v4.is_private() || v4.is_link_local()
                || v4.is_broadcast() || v4.is_unspecified())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback() || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfe00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xff00) == 0xfc00)
        }
    }
}

pub fn validate(c: &Cfg) -> Result<(), String> {
    if !c.listen_dot.is_empty() {
        c.listen_dot.parse::<SocketAddr>().map_err(|_| format!("bad listen.dot `{}`", c.listen_dot))?;
    }
    if !c.listen_doq.is_empty() {
        c.listen_doq.parse::<SocketAddr>().map_err(|_| format!("bad listen.doq `{}`", c.listen_doq))?;
    }
    if !c.listen_doh.is_empty() {
        c.listen_doh.parse::<SocketAddr>().map_err(|_| format!("bad listen.doh `{}`", c.listen_doh))?;
    }
    if (!c.listen_dot.is_empty() || !c.listen_doq.is_empty() || !c.listen_doh.is_empty())
        && (c.cert_file.is_empty() || c.key_file.is_empty())
    {
        return Err("tls.cert_file/key_file required while any TLS listener is on".into());
    }
    if c.foreign_enabled && c.upstreams.is_empty() {
        return Err(
            "foreign.enabled is true but foreign.upstreams is empty — either add \
             upstreams or remove the section"
                .into(),
        );
    }
    if !c.upstreams.is_empty() && !c.foreign_enabled {
        return Err(
            "foreign section present but disabled — remove foreign.upstreams or enable it".into(),
        );
    }
    if !c.cn_enabled && !c.cn_upstreams.is_empty() {
        return Err(
            "cn_split section present but disabled — remove cn_split.upstreams or enable it"
                .into(),
        );
    }
    if c.cn_enabled && c.cn_upstreams.is_empty() {
        return Err("cn_split.enabled is true but cn_split.upstreams is empty".into());
    }
    for s in c.upstreams.iter().chain(c.cn_upstreams.iter()) {
        if s.host.eq_ignore_ascii_case("localhost") && !c.allow_private_upstream {
            return Err(format!(
                "upstream `{}`: localhost rejected (set allow_private_upstream if intended)",
                s.raw
            ));
        }
        if let Ok(ip) = s.host.parse::<IpAddr>() {
            if !addr_allowed(ip, c.allow_private_upstream) {
                return Err(format!(
                    "upstream `{}`: private/loopback address rejected (set allow_private_upstream if intended)",
                    s.raw
                ));
            }
        }
    }
    if c.cache_bytes < 1024 {
        return Err("cache.bytes too small".into());
    }
    if c.cache_ttl == 0 {
        return Err("cache.ttl must be > 0".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "listen": {"dot": "[::]:853", "doq": "[::]:8853"},
        "tls": {"cert_file": "/a.pem", "key_file": "/b.pem"},
        "auth": {"client_uuids": ["u-1"]},
        "cache": {"bytes": 1048576, "ttl": 60},
        "ecs": {"enabled": true},
        "foreign": {
            "enabled": true, "spread": false,
            "upstreams": [
                {"url": "https://maker-a.test/dns-query", "auth_kind": "token",
                 "auth_key_env": "MAGDNS_TEST_TOKEN", "h2": 8, "batch": true},
                {"url": "https://dns9.quad9.net/dns-query", "noecs": true, "h2": 4}
            ]
        },
        "cn_split": {
            "enabled": true, "domain_file": "/cn.txt",
            "upstreams": [{"url": "udp://223.5.5.5:53", "cache": false}]
        },
        "rate_limit": {"per_ip_qps": 80, "global_qps": 9000},
        "timeouts_ms": {"attempt": 1500}
    }"#;

    #[test]
    fn sample_config_parses_end_to_end() {
        std::env::set_var("MAGDNS_TEST_TOKEN", "test-secret-value");
        let c = parse(SAMPLE).unwrap();
        validate(&c).unwrap();
        assert_eq!(c.client_uuids, vec!["u-1"]);
        assert_eq!(c.qps_per_ip, 80);
        assert_eq!(c.qps_global, 9000);
        assert_eq!(c.attempt_timeout_ms, 1500);
        assert_eq!(c.upstreams.len(), 2);
        let maker = &c.upstreams[0];
        assert_eq!(maker.h2_fanout, 8);
        assert!(maker.batch);
        assert_eq!(
            maker.auth,
            Some(("token".to_string(), "test-secret-value".to_string()))
        );
        let quad9 = &c.upstreams[1];
        assert!(quad9.noecs && !quad9.batch);
        assert!(quad9.cache, "default cache=true");
        assert!(c.cn_enabled);
        assert_eq!(c.cn_upstreams.len(), 1);
        assert!(!c.cn_upstreams[0].cache, "explicit per-leg cache=false");
        assert_eq!(c.cn_upstreams[0].port, 53);
    }

    #[test]
    fn absent_sections_disable_features() {
        let c = parse(r#"{"listen":{"dot":"[::]:853"},"tls":{"cert_file":"/a","key_file":"/b"}}"#).unwrap();
        validate(&c).unwrap();
        assert!(!c.foreign_enabled || c.upstreams.is_empty());
        assert!(c.cn_upstreams.is_empty() && !c.cn_enabled);
        assert!(c.client_uuids.is_empty(), "no auth section = trust all");
        assert_eq!(c.listen_doh, "", "doh listener off by default");
    }

    #[test]
    fn enabled_without_upstreams_is_config_error() {
        let c = parse(r#"{"foreign":{"enabled":true,"upstreams":[]}}"#).unwrap();
        assert!(validate(&c).is_err());
        // inverse: present but disabled also rejected — dead config is a lie
        let c = parse(r#"{"foreign":{"enabled":false,"upstreams":[{"url":"https://a.test/dns-query","h2":1}]}}"#).unwrap();
        assert!(validate(&c).is_err());
    }

    #[test]
    fn missing_secret_env_fails_at_parse_time() {
        std::env::remove_var("MAGDNS_DEFINITELY_UNSET_VAR_42");
        let bad = r#"{"foreign":{"enabled":true,"upstreams":[
            {"url":"https://a.test/dns-query","auth_kind":"token",
             "auth_key_env":"MAGDNS_DEFINITELY_UNSET_VAR_42","h2":4}]}}"#;
        assert!(parse(bad).is_err(), "unset env must fail fast");
    }
}

#[test]
fn comments_strip_without_harming_urls() {
    let annotated = r#"{
        // leading note
        "listen": { "dot": "[::]:853" }, /* block
              spanning lines */
        "foreign": { "enabled": false },
        "cn_split": { "enabled": true,
            "upstreams": [{ "url": "udp://223.5.5.5:53" }] }
    }"#;
    let c = parse(annotated).unwrap();
    assert!(c.cn_enabled);
    assert_eq!(c.cn_upstreams[0].raw, "udp://223.5.5.5:53");
    assert!(!c.foreign_enabled);
}

// ---- routing: chains of groups + named splits (the generalized model)

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RoutingCfg {
    #[serde(default = "default_chain_name")]
    pub default_chain: String,
    #[serde(default)]
    pub chains: BTreeMap<String, Vec<JsonChainGroup>>,
    #[serde(default)]
    pub splits: Vec<JsonSplit>,
}
fn default_chain_name() -> String {
    "main".into()
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct JsonChainGroup {
    /// balance = round-robin across members; priority = first alive wins.
    /// On member failure the WHOLE group is skipped (no intra-group retry).
    #[serde(default = "balance_mode")]
    pub mode: String,
    pub members: Vec<JsonUpstream>,
}
fn balance_mode() -> String {
    "balance".into()
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct JsonSplit {
    pub name: String,
    #[serde(default)]
    pub domains_file: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub source_subnets: Vec<String>,
    pub chain: String,
}

/// Convenience alias used by the chain-group engine builder.
pub fn spec_from_member(ju: &JsonUpstream) -> Result<SourceSpec, String> {
    build_spec(ju, "chain member")
}
