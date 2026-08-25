// DoH upstream via hyper. Default: HTTP/1.1 keep-alive — each concurrent
// query holds its own TCP+TLS connection, so transoceanic packet loss can
// never head-of-line-block unrelated queries.
// With the `h2` source flag (near-edge relays like our Maker): a round-robin
// fan of 4 independent hyper clients, each multiplexing HTTP/2 streams over
// one pooled connection — one stalled connection costs at most 1/4 of the
// traffic while saving 3/4 of the handshakes.
// We own deadlines and the SSRF guard; hyper owns per-client pools.
use crate::app;
use crate::cfg::SourceSpec;
use crate::upstream::UpErr;
use http::Method;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const BODY_CAP: usize = 128 * 1024;

fn deep_source(e: &dyn std::error::Error) -> String {
    let mut cur = e.source();
    let mut parts = Vec::new();
    while let Some(c) = cur {
        parts.push(c.to_string());
        cur = c.source();
    }
    parts.join(" | ")
}

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

pub struct DoHPool {
    spec: SourceSpec,
    /// one client per connection-fanout slot (len 1 without the `h2` flag)
    clients: Vec<HttpsClient>,
    rr: AtomicUsize,
    allow_private: bool,
    /// pre-built auth header for Maker relays, e.g. ("token", "<key>")
    auth_header: Option<(String, String)>,
}

impl DoHPool {
    pub fn new(
        spec: SourceSpec,
        tls: rustls::ClientConfig,
        allow_private: bool,
        auth_header: Option<(String, String)>,
    ) -> Result<Self, String> {
        // NOTE: hyper-rustls sets ALPN itself (h2 + http/1.1 as enabled) and
        // panics if the config already carries alpn_protocols
        let n = spec.h2_fanout.max(1);
        let mut clients = Vec::with_capacity(n);
        for _ in 0..n {
            let mut http = HttpConnector::new();
            // mandatory when wrapping a custom connector: the inner
            // HttpConnector must not enforce http-only, the outer
            // HttpsConnector handles https
            http.enforce_http(false);
            http.set_connect_timeout(Some(std::time::Duration::from_secs(4)));
            let builder = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(tls.clone())
                .https_or_http();
            let https = if spec.h2_fanout > 0 {
                builder.enable_http1().enable_http2().wrap_connector(http)
            } else {
                builder.enable_http1().wrap_connector(http)
            };
            clients.push(Client::builder(TokioExecutor::new()).build(https));
        }
        Ok(DoHPool {
            spec,
            clients,
            rr: AtomicUsize::new(0),
            allow_private,
            auth_header,
        })
    }

    pub async fn query(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        // SSRF guard: resolve+filter here (hyper resolves again internally;
        // for operator-configured upstreams this TOCTOU window is acceptable)
        let addrs = app::resolve_addrs(&self.spec.host, self.spec.port, self.allow_private).await;
        if addrs.is_empty() {
            return Err(UpErr::Conn("doh: address rejected/none".into()));
        }
        let authority = if self.spec.port == 443 {
            self.spec.host.clone()
        } else {
            format!("{}:{}", self.spec.host, self.spec.port)
        };
        let uri: http::Uri = format!("https://{}{}", authority, self.spec.path)
            .parse()
            .map_err(|e| UpErr::Conn(format!("doh: bad uri: {e}")))?;
        let mut req = http::Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message");
        if let Some((name, value)) = &self.auth_header {
            req = req.header(name.as_str(), value.as_str());
        }
        let req = req
            .body(Full::new(Bytes::copy_from_slice(msg)))
            .map_err(|e| UpErr::Conn(format!("doh: build: {e}")))?;
        // fan-out slot: distinct queries land on distinct connections;
        // single-flight already collapses identical ones before we get here
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % self.clients.len();
        let client = &self.clients[idx];
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(UpErr::Timeout)?;
        let resp = tokio::time::timeout(remaining, client.request(req))
            .await
            .map_err(|_| UpErr::Timeout)?
            .map_err(|e| UpErr::Conn(format!("doh: {}: {}", e, deep_source(&e))))?;
        if resp.status() != http::StatusCode::OK {
            return Err(UpErr::Conn(format!("doh: status {}", resp.status())));
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(UpErr::Timeout)?;
        let body = tokio::time::timeout(remaining, async {
            resp.into_body()
                .collect()
                .await
                .map_err(|e| UpErr::Conn(format!("doh: body: {e}")))
        })
        .await
        .map_err(|_| UpErr::Timeout)??;
        let buf = body.to_bytes();
        if buf.len() > BODY_CAP {
            return Err(UpErr::Conn("doh: body too large".into()));
        }
        Ok(buf.to_vec())
    }
}
