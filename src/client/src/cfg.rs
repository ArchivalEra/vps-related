// magdns-client configuration: one JSON file, `config.json`. No hot reload —
// changing anything requires a restart, same policy as the box.
//
// Schema:
//
// {
//   "listen":  { "doh": "127.0.0.1:8053", "udp": "127.0.0.1:53", "tcp": "127.0.0.1:53" },
//   "servers": [                                   // ORDERED failover list; [0] is primary
//     { "name": "box", "url": "tls://box.example.com:853",
//       "auth_kind": "uuid-header", "auth_key_env": "BOX_UUID",
//       "proto": "dot", "batch": true, "compress": "gzip", "h2": 0 },
//     { "url": "https://1.1.1.1/dns-query", "proto": "doh" }
//   ],
//   "cache": { "bytes": 20971520, "ttl": 300 }
// }
//
// - `proto` ∈ dot|doq|doh; derived from the URL scheme when absent
//   (tls:// → dot, https:// → doh, quic:// → doq). doq parses today but the
//   transport answers an error until implemented (TODO).
// - `compress` ∈ gzip|br|null (JSON null or absent = send uncompressed).
// - Secrets are NEVER written to this file: `auth_key_env` names the
//   environment variable holding the client UUID; it is read once at parse
//   time and a missing/empty variable fails startup immediately.
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Dot,
    Doq,
    Doh,
}

impl Proto {
    pub fn tag(&self) -> &'static str {
        match self {
            Proto::Dot => "dot",
            Proto::Doq => "doq",
            Proto::Doh => "doh",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compress {
    Gzip,
    Brotli,
    None,
}

/// One configured outbound source (the box, or a public DoH fallback).
#[derive(Clone, Debug)]
pub struct ServerCfg {
    pub name: String,
    pub proto: Proto,
    pub host: String,
    pub port: u16,
    /// path for DoH legs ("" on stream legs)
    pub path: String,
    /// original URL as written in config, for error messages only
    pub raw_url: String,
    /// pack concurrent queries into one MGB1 container per round trip
    pub batch: bool,
    pub compress: Compress,
    /// HTTP/2 fanout for DoH (0 = HTTP/1.1 keep-alive per concurrent query)
    pub h2_fanout: usize,
    /// client UUID resolved from the environment at startup; rides the MGB1
    /// handshake on stream legs and the x-magdns-auth header on DoH
    pub uuid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ClientCfg {
    pub listen_doh: Option<SocketAddr>,
    pub listen_udp: Option<SocketAddr>,
    pub listen_tcp: Option<SocketAddr>,
    /// ordered sources; index 0 is primary, later entries are fallbacks
    pub servers: Vec<ServerCfg>,
    pub cache_bytes: usize,
    pub cache_ttl: Duration,
}

// ---- serde mirror of the schema

#[derive(serde::Deserialize)]
struct JsonListen {
    #[serde(default)]
    doh: Option<String>,
    #[serde(default)]
    udp: Option<String>,
    #[serde(default)]
    tcp: Option<String>,
}

#[derive(serde::Deserialize)]
struct JsonServer {
    #[serde(default)]
    name: Option<String>,
    url: String,
    #[serde(default)]
    auth_kind: Option<String>,
    #[serde(default)]
    auth_key_env: Option<String>,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    batch: bool,
    /// "gzip" | "br" | "null"; JSON null and absence also mean no compression
    #[serde(default)]
    compress: Option<String>,
    #[serde(default)]
    h2: Option<usize>,
}

#[derive(serde::Deserialize)]
struct JsonCache {
    #[serde(default)]
    bytes: Option<u64>,
    #[serde(default)]
    ttl: Option<u64>,
}

#[derive(serde::Deserialize)]
struct JsonConfig {
    #[serde(default)]
    listen: Option<JsonListen>,
    #[serde(default)]
    servers: Option<Vec<JsonServer>>,
    #[serde(default)]
    cache: Option<JsonCache>,
}

const DEFAULT_CACHE_BYTES: usize = 20 * 1024 * 1024;
const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// Strip // and /* */ comments outside string literals so operator configs can
/// carry annotations (same helper as the box's cfg.rs). String-aware:
/// `https://` inside a value is never touched.
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

/// Split scheme://authority[/path] into parts; no userinfo, IPv6 in brackets.
fn split_url(raw: &str) -> Result<(String, String, u16, String), String> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| format!("server `{raw}`: missing scheme://"))?;
    let default_port = match scheme {
        "tls" | "quic" => 853u16,
        "https" => 443u16,
        "http" => {
            return Err(format!(
                "server `{raw}`: plain http is not allowed, use https"
            ))
        }
        other => {
            return Err(format!(
                "server `{raw}`: unknown scheme `{other}` (tls|quic|https)"
            ))
        }
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(format!("server `{raw}`: empty host"));
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        // [v6]:port
        let (h, tail) = inner
            .split_once(']')
            .ok_or_else(|| format!("server `{raw}`: unterminated [ipv6]"))?;
        let p = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| format!("server `{raw}`: bad port"))?,
            None => default_port,
        };
        (h.to_string(), p)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (
                h.to_string(),
                p.parse().map_err(|_| format!("server `{raw}`: bad port"))?,
            ),
            _ => (authority.to_string(), default_port),
        }
    };
    if host.is_empty() {
        return Err(format!("server `{raw}`: empty host"));
    }
    Ok((scheme.to_string(), host, port, path.to_string()))
}

fn build_server(js: &JsonServer, idx: usize) -> Result<ServerCfg, String> {
    let what = format!("servers[{idx}]");
    let (scheme, host, port, path) = split_url(&js.url)?;
    // proto: explicit field wins over the scheme default, but they must agree
    let scheme_proto = match scheme.as_str() {
        "tls" => Proto::Dot,
        "quic" => Proto::Doq,
        _ => Proto::Doh,
    };
    let proto = match js.proto.as_deref() {
        None => scheme_proto,
        Some("dot") => Proto::Dot,
        Some("doq") => Proto::Doq,
        Some("doh") => Proto::Doh,
        Some(other) => return Err(format!("{what}: unknown proto `{other}` (dot|doq|doh)")),
    };
    if proto != scheme_proto {
        return Err(format!(
            "{what}: proto `{}` contradicts url scheme `{scheme}://`",
            proto.tag()
        ));
    }
    let path = match proto {
        Proto::Doh => {
            if path.is_empty() {
                "/dns-query".to_string()
            } else {
                path
            }
        }
        _ => {
            if !path.is_empty() {
                return Err(format!("{what}: path not allowed for {}:// urls", scheme));
            }
            String::new()
        }
    };
    let compress = match js.compress.as_deref() {
        None | Some("null") | Some("none") | Some("") => Compress::None,
        Some("gzip") => Compress::Gzip,
        // parses today; the transport sends raw until brotli lands (TODO)
        Some("br") => Compress::Brotli,
        Some(other) => return Err(format!("{what}: unknown compress `{other}` (gzip|br|null)")),
    };
    let h2_fanout = match js.h2 {
        Some(h) if h > 20 => return Err(format!("{what}: h2 must be 0..=20")),
        Some(h) if proto == Proto::Doh => h,
        _ => 0, // non-DoH legs ignore it; DoH defaults to per-query HTTP/1.1
    };
    // auth: the file names the env var, never the secret itself
    let uuid = match (&js.auth_kind, &js.auth_key_env) {
        (None, None) => None,
        (Some(kind), Some(env_name)) => {
            if kind != "uuid-header" {
                return Err(format!("{what}: unknown auth_kind `{kind}` (uuid-header)"));
            }
            let key = std::env::var(env_name).map_err(|_| {
                format!(
                    "{what}: environment variable {env_name} is not set \
                     (secrets are env-injected by design)"
                )
            })?;
            if key.trim().is_empty() {
                return Err(format!("{what}: {env_name} is set but empty"));
            }
            Some(key)
        }
        (Some(_), None) => {
            return Err(format!("{what}: auth_kind requires auth_key_env"));
        }
        (None, Some(_)) => {
            return Err(format!("{what}: auth_key_env requires auth_kind"));
        }
    };
    Ok(ServerCfg {
        name: js.name.clone().unwrap_or_else(|| format!("server-{idx}")),
        proto,
        host,
        port,
        path,
        raw_url: js.url.clone(),
        batch: js.batch,
        compress,
        h2_fanout,
        uuid,
    })
}

/// Parse a config.json into runtime configuration. Fails fast on unset auth
/// env vars, malformed URLs and contradictory fields.
pub fn parse(text: &str) -> Result<ClientCfg, String> {
    let j: JsonConfig =
        serde_json::from_str(&strip_comments(text)).map_err(|e| format!("config.json: {e}"))?;
    let mut c = ClientCfg {
        listen_doh: None,
        listen_udp: None,
        listen_tcp: None,
        servers: Vec::new(),
        cache_bytes: DEFAULT_CACHE_BYTES,
        cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
    };

    if let Some(l) = j.listen {
        let one = |raw: &Option<String>, what: &str| -> Result<Option<SocketAddr>, String> {
            match raw {
                None => Ok(None),
                Some(s) => s
                    .parse()
                    .map(Some)
                    .map_err(|_| format!("listen.{what}: not a valid socket address: {s}")),
            }
        };
        c.listen_doh = one(&l.doh, "doh")?;
        c.listen_udp = one(&l.udp, "udp")?;
        c.listen_tcp = one(&l.tcp, "tcp")?;
    }

    let empty: Vec<JsonServer> = Vec::new();
    for (i, js) in j.servers.as_ref().unwrap_or(&empty).iter().enumerate() {
        c.servers.push(build_server(js, i)?);
    }
    if c.servers.is_empty() {
        return Err("config.json: `servers` must list at least one source".into());
    }

    if let Some(cc) = j.cache {
        if let Some(b) = cc.bytes {
            c.cache_bytes = b as usize;
        }
        if let Some(t) = cc.ttl {
            c.cache_ttl = Duration::from_secs(t);
        }
    }
    if c.cache_bytes < 1024 {
        return Err("cache.bytes too small (min 1024)".into());
    }
    if c.cache_ttl.is_zero() {
        return Err("cache.ttl must be > 0".into());
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "listen": { "doh": "127.0.0.1:8053", "udp": "127.0.0.1:53", "tcp": "127.0.0.1:53" },
        "servers": [
            { "name": "box", "url": "tls://box.example.com:853",
              "auth_kind": "uuid-header", "auth_key_env": "MAGDNS_CLIENT_TEST_UUID",
              "proto": "dot", "batch": true, "compress": "gzip", "h2": 0 },
            { "url": "https://1.1.1.1/dns-query", "proto": "doh" }
        ],
        "cache": { "bytes": 20971520, "ttl": 300 }
    }"#;

    #[test]
    fn sample_config_parses_end_to_end() {
        std::env::set_var("MAGDNS_CLIENT_TEST_UUID", "01893a7c-test-uuid");
        let c = parse(SAMPLE).unwrap();
        assert_eq!(c.listen_udp.unwrap().to_string(), "127.0.0.1:53");
        assert_eq!(c.listen_tcp.unwrap().to_string(), "127.0.0.1:53");
        assert_eq!(c.listen_doh.unwrap().to_string(), "127.0.0.1:8053");
        assert_eq!(c.servers.len(), 2);
        assert_eq!(c.cache_bytes, 20971520);
        assert_eq!(c.cache_ttl, Duration::from_secs(300));

        let primary = &c.servers[0];
        assert_eq!(primary.name, "box");
        assert_eq!(primary.proto, Proto::Dot);
        assert!(primary.batch, "primary speaks MGB1 batches");
        assert_eq!(primary.compress, Compress::Gzip);
        assert_eq!(primary.port, 853);
        assert_eq!(
            primary.uuid.as_deref(),
            Some("01893a7c-test-uuid"),
            "secret resolved from env, never stored in the file"
        );

        let fallback = &c.servers[1];
        assert_eq!(fallback.proto, Proto::Doh);
        assert!(!fallback.batch);
        assert_eq!(fallback.compress, Compress::None);
        assert_eq!(fallback.path, "/dns-query");
        assert_eq!(fallback.uuid, None, "no auth configured = anonymous leg");
    }

    #[test]
    fn missing_secret_env_fails_at_parse_time() {
        std::env::remove_var("MAGDNS_CLIENT_DEFINITELY_UNSET_42");
        let bad = r#"{"servers":[{"url":"tls://box.test:853","auth_kind":"uuid-header",
            "auth_key_env":"MAGDNS_CLIENT_DEFINITELY_UNSET_42"}]}"#;
        let err = parse(bad).unwrap_err();
        assert!(err.contains("MAGDNS_CLIENT_DEFINITELY_UNSET_42"), "{err}");
    }

    #[test]
    fn empty_secret_env_fails_too() {
        std::env::set_var("MAGDNS_CLIENT_EMPTY_VAR", "");
        let bad = r#"{"servers":[{"url":"tls://box.test","auth_kind":"uuid-header",
            "auth_key_env":"MAGDNS_CLIENT_EMPTY_VAR"}]}"#;
        assert!(parse(bad).is_err());
    }

    #[test]
    fn compress_null_absent_and_garbage() {
        let none = r#"{"servers":[{"url":"https://a.test/dns-query","compress":null}]}"#;
        assert_eq!(parse(none).unwrap().servers[0].compress, Compress::None);
        let absent = r#"{"servers":[{"url":"https://a.test/dns-query"}]}"#;
        assert_eq!(parse(absent).unwrap().servers[0].compress, Compress::None);
        let br = r#"{"servers":[{"url":"https://a.test/dns-query","compress":"br"}]}"#;
        assert_eq!(parse(br).unwrap().servers[0].compress, Compress::Brotli);
        let junk = r#"{"servers":[{"url":"https://a.test/dns-query","compress":"zstd"}]}"#;
        assert!(parse(junk).is_err());
    }

    #[test]
    fn proto_must_agree_with_scheme() {
        let bad = r#"{"servers":[{"url":"tls://box.test:853","proto":"doh"}]}"#;
        assert!(parse(bad).is_err());
        // scheme alone implies proto
        let good = r#"{"servers":[{"url":"tls://box.test"}]}"#;
        let c = parse(good).unwrap();
        assert_eq!(c.servers[0].proto, Proto::Dot);
        assert_eq!(c.servers[0].port, 853, "default DoT port");
        assert_eq!(c.servers[0].path, "", "no path on stream legs");
    }

    #[test]
    fn doq_parses_but_is_a_transport_todo() {
        let c = parse(r#"{"servers":[{"url":"quic://box.test:853","proto":"doq"}]}"#).unwrap();
        assert_eq!(c.servers[0].proto, Proto::Doq);
    }

    #[test]
    fn comments_are_stripped_like_on_the_box() {
        let annotated = r#"
            // local stub config
            { "listen": { "udp": "127.0.0.1:5300" }, /* block
               spanning lines */
              "servers": [ { "url": "https://a.test/dns-query" } ] }"#;
        let c = parse(annotated).unwrap();
        assert_eq!(c.listen_udp.unwrap().to_string(), "127.0.0.1:5300");
        assert_eq!(c.servers.len(), 1);
    }

    #[test]
    fn defaults_and_validation() {
        let c = parse(r#"{"servers":[{"url":"https://a.test/dns-query"}]}"#).unwrap();
        assert_eq!(c.cache_bytes, DEFAULT_CACHE_BYTES, "20 MiB default");
        assert_eq!(c.cache_ttl, Duration::from_secs(DEFAULT_CACHE_TTL_SECS));
        assert!(c.listen_udp.is_none(), "listeners off unless configured");

        assert!(
            parse(r#"{"cache":{"bytes":1},"servers":[{"url":"https://a.test/dns-query"}]}"#)
                .is_err()
        );
        assert!(
            parse(r#"{"servers":[]}"#).is_err(),
            "need at least one source"
        );
        assert!(parse(r#"{}"#).is_err());
        assert!(parse(
            r#"{"listen":{"udp":"not-an-addr"},"servers":[{"url":"https://a.test/dns-query"}]}"#
        )
        .is_err());
    }
}
