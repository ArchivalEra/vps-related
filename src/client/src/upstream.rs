// Outbound pipeline: magazine cache → ordered source failover.
//
// `servers` from config.json form an ORDERED list; resolution sticks to the
// last healthy source and walks forward on failure (wrapping back to [0]),
// SERVFAIL only after every source had its chance. Answers are stored with a
// zeroed transaction ID and re-stamped with the requester's ID at delivery —
// MGB1 batches answer positionally, so an inbound ID can never be trusted.
use crate::cache::MagCache;
use crate::cfg::{ClientCfg, Proto, ServerCfg};
use crate::dnsmsg;
use crate::{doh, dot};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Whole-pipeline budget per query, shared across failover attempts.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug)]
pub enum UpErr {
    Timeout,
    Conn(String),
}

impl std::fmt::Display for UpErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpErr::Timeout => write!(f, "upstream timeout"),
            UpErr::Conn(s) => write!(f, "upstream connection: {s}"),
        }
    }
}
impl std::error::Error for UpErr {}

/// One outbound leg. `slots` speaks pure MGB1 containers (used by the batch
/// dispatcher); `query` is the per-query entry point that owns batching and
/// the single-query formats.
pub enum Transport {
    Dot(dot::DotUpstream),
    Doh(doh::DohUpstream),
    /// TODO(T-doq): quinn-based QUIC transport; parses in config today,
    /// answers a transport error so failover skips past it.
    Doq(ServerCfg),
}

impl Transport {
    pub fn build(spec: &ServerCfg, dot_tls: Arc<rustls::ClientConfig>, doh_tls: Arc<rustls::ClientConfig>) -> Result<Transport, String> {
        match spec.proto {
            Proto::Dot => Ok(Transport::Dot(dot::DotUpstream::new(spec, dot_tls)?)),
            Proto::Doh => Ok(Transport::Doh(doh::DohUpstream::new(spec, doh_tls)?)),
            Proto::Doq => Ok(Transport::Doq(spec.clone())),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Transport::Dot(u) => u.describe(),
            Transport::Doh(u) => u.describe(),
            Transport::Doq(s) => format!("doq://{}:{} (not implemented)", s.host, s.port),
        }
    }

    /// Single-query entry point (batcher-aware inside each transport).
    pub async fn query(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        match self {
            Transport::Dot(u) => u.query(msg, deadline).await,
            Transport::Doh(u) => u.query(msg, deadline).await,
            Transport::Doq(s) => Err(UpErr::Conn(format!(
                "doq://{}:{} not implemented yet (TODO)",
                s.host, s.port
            ))),
        }
    }
}

/// The whole exit pipeline, shared by every listener.
pub struct Chain {
    sources: Vec<Transport>,
    current: AtomicUsize,
    cache: Mutex<MagCache>,
}

impl Chain {
    pub fn build(c: &ClientCfg) -> Result<Chain, String> {
        // one rustls ClientConfig per ALPN story; the DoH one must NOT carry
        // alpn_protocols — hyper-rustls installs its own and panics otherwise
        let dot_tls = Arc::new(client_tls_config(&[b"dot"]));
        let doh_tls = Arc::new(client_tls_config(&[]));
        let mut sources = Vec::with_capacity(c.servers.len());
        for s in &c.servers {
            sources.push(Transport::build(s, dot_tls.clone(), doh_tls.clone())?);
        }
        Ok(Chain {
            sources,
            current: AtomicUsize::new(0),
            cache: Mutex::new(MagCache::new(c.cache_bytes, c.cache_ttl)),
        })
    }

    /// Explicit-source constructor used by tests (and future hot-reload work).
    #[cfg(test)]
    pub(crate) fn from_sources(sources: Vec<Transport>, cache: MagCache) -> Chain {
        Chain {
            sources,
            current: AtomicUsize::new(0),
            cache: Mutex::new(cache),
        }
    }

    /// Cache → failover walk → SERVFAIL. Always returns deliverable bytes.
    pub async fn resolve(self: &Arc<Self>, q: &[u8]) -> Vec<u8> {
        let parsed = dnsmsg::parse_query(q);
        let key = parsed.as_ref().map(dnsmsg::cache_key);

        if let (Some(pq), Some(k)) = (&parsed, &key) {
            if let Some(mut hit) = self.cache.lock().unwrap().get(k) {
                dnsmsg::patch_id(&mut hit, &pq.id);
                return hit;
            }
        }

        let n = self.sources.len();
        let start = self.current.load(Ordering::Relaxed).min(n.saturating_sub(1));
        let deadline = Instant::now() + QUERY_TIMEOUT;
        for i in 0..n {
            let idx = (start + i) % n;
            match self.sources[idx].query(q, deadline).await {
                Ok(mut resp) if resp.len() >= 12 => {
                    // stick to the proven source
                    self.current.store(idx, Ordering::Relaxed);
                    if let (Some(pq), Some(k)) = (&parsed, &key) {
                        self.cache.lock().unwrap().put(k.clone(), resp.clone());
                        dnsmsg::patch_id(&mut resp, &pq.id);
                    }
                    return resp;
                }
                Ok(_) => {
                    eprintln!("chain: {} returned a short body, skipping", self.sources[idx].describe());
                }
                Err(e) => {
                    eprintln!("chain: {}: {e}", self.sources[idx].describe());
                }
            }
        }
        dnsmsg::make_servfail(q)
    }

    /// Startup banner line describing the ordered sources.
    pub fn describe(&self) -> Vec<String> {
        self.sources.iter().map(|t| t.describe()).collect()
    }
}

/// Pure-rust TLS client config off the Mozilla root store (ring provider,
/// installed explicitly — no process-global default), mirroring the box's
/// tlsconf.rs. Pass an empty `alpn` for hyper-rustls legs.
pub fn client_tls_config(alpn: &[&[u8]]) -> rustls::ClientConfig {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
    };
    let mut conf = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .expect("provider supports TLS1.2/1.3")
    .with_root_certificates(roots)
    .with_no_client_auth();
    conf.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    conf
}

/// Resolve + failover exercised end to end without any real network:
/// unreachable loopback ports must degrade to SERVFAIL, never panic.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::Compress;

    fn servfail_chain() -> Chain {
        let mk = |url: &str| ServerCfg {
            name: url.to_string(),
            proto: Proto::Dot,
            host: "127.0.0.1".into(),
            port: 1, // loopback, refused instantly
            path: String::new(),
            raw_url: url.into(),
            batch: false,
            compress: Compress::None,
            h2_fanout: 0,
            uuid: None,
        };
        Chain {
            sources: vec![
                Transport::Dot(dot::DotUpstream::new(&mk("tls://127.0.0.1:1"), Arc::new(client_tls_config(&[b"dot"]))).unwrap()),
                Transport::Dot(dot::DotUpstream::new(&mk("tls://127.0.0.1:2"), Arc::new(client_tls_config(&[b"dot"]))).unwrap()),
            ],
            current: AtomicUsize::new(0),
            cache: Mutex::new(MagCache::new(65536, Duration::from_secs(300))),
        }
    }

    #[tokio::test]
    async fn every_source_failing_yields_servfail_with_requester_id() {
        let chain = Arc::new(servfail_chain());
        let mut q = vec![0x7e, 0x57, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x03com\x00");
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());

        let resp = chain.resolve(&q).await;
        assert_eq!(&resp[..2], &[0x7e, 0x57], "requester txid preserved");
        assert_eq!(resp[3] & 0x0F, 2, "RCODE=SERVFAIL");
        assert!(resp.len() > 12, "question section echoed");
    }

    #[test]
    fn cache_key_ignores_the_requester_txid() {
        let a = dnsmsg::parse_query(&[0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1]);
        let b = dnsmsg::parse_query(&[9, 9, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1]);
        assert_eq!(
            a.as_ref().map(dnsmsg::cache_key),
            b.as_ref().map(dnsmsg::cache_key),
            "two stubs asking the same name share one cache entry"
        );
    }
}
