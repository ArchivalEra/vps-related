// DoH upstream via hyper (HTTP/2 first — nextdns's edge refuses plain
// http/1.1 ALPN — with automatic http/1.1 fallback for local forwarders).
// hyper owns the connection pool and keep-alive; we own deadlines and the
// SSRF guard (pre-resolve + filter before each request).
use crate::app;
use crate::cfg::SourceSpec;
use crate::upstream::UpErr;
use http::Method;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
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

pub struct DoHPool {
    spec: SourceSpec,
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
    allow_private: bool,
    /// Bearer token for Maker auth (None = no auth header)
    auth_token: Option<String>,
}

impl DoHPool {
    pub fn new(
        spec: SourceSpec,
        tls: rustls::ClientConfig,
        allow_private: bool,
        auth_token: Option<String>,
    ) -> Result<Self, String> {
        // NOTE: hyper-rustls sets ALPN itself (h2 + http/1.1) and panics if
        // the config already carries alpn_protocols
        let mut http = HttpConnector::new();
        // mandatory when wrapping a custom connector: the inner HttpConnector
        // must not enforce http-only, the outer HttpsConnector handles https
        http.enforce_http(false);
        http.set_connect_timeout(Some(std::time::Duration::from_secs(4)));
        // Force HTTP/1.1 only: each query gets its own TCP+TLS connection.
        // H2 multiplexing over transoceanic links causes head-of-line
        // blocking on packet loss — one dropped byte stalls ALL streams.
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .wrap_connector(http);
        let client = Client::builder(TokioExecutor::new()).build(https);
        Ok(DoHPool { spec, client, allow_private, auth_token: None })
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
        let req = http::Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message");
        // attach Bearer token for Maker auth when configured
        let req = match &self.auth_token {
            Some(tok) => req.header("authorization", format!("Bearer {tok}")),
            None => req,
        };
        let req = req
            .body(Full::new(Bytes::copy_from_slice(msg)))
            .map_err(|e| UpErr::Conn(format!("doh: build: {e}")))?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(UpErr::Timeout)?;
        let resp = tokio::time::timeout(remaining, self.client.request(req))
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
            resp.into_body().collect().await.map_err(|e| UpErr::Conn(format!("doh: body: {e}")))
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
