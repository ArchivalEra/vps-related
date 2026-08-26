// DoH upstream (RFC 8484) via hyper-rustls. Default HTTP/1.1 keep-alive —
// each concurrent query holds its own TCP+TLS connection so transoceanic
// loss never head-of-line-blocks unrelated queries; `h2: n` switches to a
// round-robin fan of n independent clients multiplexing HTTP/2.
//
// With `batch: true` concurrent queries ride the zero-wait AIMD packer into
// ONE POST of an MGB1 container (`application/mgb1+v1`, docs leg 2); the box
// answers slot-ordered. Compression rides `content-encoding: gzip`; a 415
// answer means "drop compression permanently" (protocol §Compression).
use crate::batcher::{Batcher, Pending};
use crate::cfg::{Compress, ServerCfg};
use crate::upstream::UpErr;
use http::{Method, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

const BODY_CAP: usize = 128 * 1024;

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

pub struct DohUpstream {
    host: String,
    port: u16,
    path: String,
    /// one client per fanout slot (len 1 without the h2 flag)
    clients: Vec<HttpsClient>,
    rr: AtomicUsize,
    /// ("x-magdns-auth", uuid) when auth_kind=uuid-header
    auth_header: Option<(String, String)>,
    compress: Compress,
    /// peer answered 415 → send raw containers from now on
    compress_off: AtomicBool,
    batcher: Option<Batcher>,
}

impl DohUpstream {
    pub fn new(spec: &ServerCfg, tls: Arc<rustls::ClientConfig>) -> Result<Self, String> {
        // NOTE: hyper-rustls installs ALPN itself and panics if the config
        // already carries alpn_protocols — hence the alpn-free tls config.
        let n = spec.h2_fanout.max(1);
        let mut clients = Vec::with_capacity(n);
        for _ in 0..n {
            let mut http = HttpConnector::new();
            // mandatory when wrapping a custom connector: the inner connector
            // must not enforce http-only, the outer one handles https
            http.enforce_http(false);
            http.set_connect_timeout(Some(std::time::Duration::from_secs(4)));
            let builder = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config((*tls).clone())
                .https_or_http();
            let https = if spec.h2_fanout > 0 {
                builder.enable_http1().enable_http2().wrap_connector(http)
            } else {
                builder.enable_http1().wrap_connector(http)
            };
            clients.push(Client::builder(TokioExecutor::new()).build(https));
        }
        let authority = if spec.port == 443 {
            format!("https://{}{}", spec.host, spec.path)
        } else {
            format!("https://{}:{}{}", spec.host, spec.port, spec.path)
        };
        let _: Uri = authority
            .parse()
            .map_err(|e| format!("doh upstream `{}`: bad uri: {e}", spec.raw_url))?;
        Ok(DohUpstream {
            host: spec.host.clone(),
            port: spec.port,
            path: spec.path.clone(),
            clients,
            rr: AtomicUsize::new(0),
            auth_header: spec
                .uuid
                .as_ref()
                .map(|u| ("x-magdns-auth".to_string(), u.clone())),
            compress: spec.compress,
            compress_off: AtomicBool::new(false),
            batcher: spec.batch.then(Batcher::new),
        })
    }

    pub fn describe(&self) -> String {
        format!(
            "https://{}:{}{} batch={} compress={} h2={}",
            self.host,
            self.port,
            self.path,
            self.batcher.is_some(),
            match self.compress {
                Compress::Gzip => "gzip",
                Compress::Brotli => "br(todo)",
                Compress::None => "null",
            },
            self.clients.len(),
        )
    }

    pub async fn query(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        if let Some(b) = &self.batcher {
            let (mut rx, mut drain) = b.enter(msg.to_vec());
            while let Some(mut batch) = drain.take() {
                let ok = self.send_batch(&mut batch, deadline).await;
                drain = b.next_batch(ok);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(UpErr::Timeout)?;
            return match tokio::time::timeout(remaining, &mut rx).await {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => Err(UpErr::Conn("doh batch: dispatcher dropped".into())),
                Err(_) => Err(UpErr::Timeout),
            };
        }
        // plain RFC 8484 single query
        let (_, enc, body) = self
            .post(
                msg,
                "application/dns-message",
                None,
                "application/dns-message",
                deadline,
            )
            .await?;
        match enc.as_deref() {
            Some("gzip") | Some("x-gzip") => gunzip(&body),
            _ => Ok(body),
        }
    }

    /// Dispatcher duty: one container round trip per batch. Returns whether
    /// the transport behaved (AIMD input), independent of slot outcomes.
    async fn send_batch(&self, batch: &mut Vec<Pending>, deadline: Instant) -> bool {
        loop {
            let refs: Vec<&[u8]> = batch.iter().map(|p| p.msg.as_slice()).collect();
            let container =
                match mgb1::encode(&refs) {
                    Ok(c) => c,
                    Err(e) => {
                        for p in batch.drain(..) {
                            let _ = p.tx.send(Err(UpErr::Conn(format!("pack: {e}"))));
                        }
                        return false;
                    }
                };
            // brotli is parsed in config but not shipped yet (TODO): raw until then
            let want_gzip = self.compress == Compress::Gzip && !self.compress_off.load(Ordering::Relaxed);
            let gzipped = want_gzip && !container.is_empty();
            let payload = if gzipped { gzip_compress(&container) } else { container };
            match self
                .post(
                    &payload,
                    "application/mgb1+v1",
                    gzipped.then_some("gzip"),
                    "application/mgb1+v1",
                    deadline,
                )
                .await
            {
                Ok((_, enc, body)) => {
                    let body = match enc.as_deref() {
                        Some("gzip") | Some("x-gzip") => match gunzip(&body) {
                            Ok(b) => b,
                            Err(e) => {
                                for p in batch.drain(..) {
                                    let _ = p.tx.send(Err(e.clone()));
                                }
                                return false;
                            }
                        },
                        _ => body,
                    };
                    // A clean HTTP exchange counts as AIMD success even if some
                    // slots carry failures — those are DNS-level outcomes.
                    match mgb1::decode(&body) {
                        Ok(slots) => {
                            for (p, slot) in batch.drain(..).zip(slots) {
                                let _ = p.tx.send(
                                    slot.ok_or_else(|| UpErr::Conn("batch: empty slot".into())),
                                );
                            }
                            return true;
                        }
                        Err(e) => {
                            for p in batch.drain(..) {
                                let _ = p.tx.send(Err(UpErr::Conn(format!("unpack: {e}"))));
                            }
                            return false;
                        }
                    }
                }
                Err(UpErr::Conn(s)) if s.contains("status 415") => {
                    // relay cannot decompress our choice — go raw for good and
                    // retry the same batch; not a transport failure
                    self.compress_off.store(true, Ordering::Relaxed);
                    continue;
                }
                Err(e) => {
                    for p in batch.drain(..) {
                        let _ = p.tx.send(Err(e.clone()));
                    }
                    return false;
                }
            }
        }
    }

    /// Shared HTTP mechanics. Returns (status, content-encoding, body).
    async fn post(
        &self,
        body: &[u8],
        content_type: &str,
        request_encoding: Option<&str>,
        accept: &str,
        deadline: Instant,
    ) -> Result<(u16, Option<String>, Vec<u8>), UpErr> {
        let uri: Uri = if self.port == 443 {
            format!("https://{}{}", self.host, self.path)
        } else {
            format!("https://{}:{}{}", self.host, self.port, self.path)
        }
        .parse()
        .map_err(|e| UpErr::Conn(format!("doh: uri: {e}")))?;
        let mut req = http::Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", content_type)
            .header("accept", accept);
        if let Some(enc) = request_encoding {
            req = req.header("content-encoding", enc);
        }
        if let Some((name, value)) = &self.auth_header {
            req = req.header(name.as_str(), value.as_str());
        }
        let req = req
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| UpErr::Conn(format!("doh: build: {e}")))?;
        // fan-out slot: distinct queries land on distinct connections
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % self.clients.len();
        let client = &self.clients[idx];
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(UpErr::Timeout)?;
        let resp = tokio::time::timeout(remaining, client.request(req))
            .await
            .map_err(|_| UpErr::Timeout)?
            .map_err(|e| UpErr::Conn(format!("doh: status fetch: {e}")))?;
        let status = resp.status().as_u16();
        let enc = resp
            .headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if status != 200 {
            // drain what we can so the connection stays reusable, then report
            let _ = resp.into_body().collect().await;
            return Err(UpErr::Conn(format!("doh: status {status}")));
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(UpErr::Timeout)?;
        let collected = tokio::time::timeout(remaining, resp.into_body().collect())
            .await
            .map_err(|_| UpErr::Timeout)?
            .map_err(|e| UpErr::Conn(format!("doh: body: {e}")))?
            .to_bytes();
        if collected.len() > BODY_CAP * 4 {
            return Err(UpErr::Conn("doh: body too large".into()));
        }
        Ok((status, enc, collected.to_vec()))
    }
}

/// gzip level 6: speed-first, the wire is small and links are long.
pub(crate) fn gzip_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(
        Vec::with_capacity(data.len() / 2),
        flate2::Compression::new(6),
    );
    let _ = enc.write_all(data);
    enc.finish().unwrap_or_else(|_| data.to_vec())
}

/// Bounded gunzip: refuse decompression bombs past 512 KiB.
pub(crate) fn gunzip(data: &[u8]) -> Result<Vec<u8>, UpErr> {
    let cap = BODY_CAP * 4;
    let mut out = Vec::with_capacity(data.len() * 2);
    let mut dec = flate2::read::GzDecoder::new(data).take(cap as u64 + 1);
    dec.read_to_end(&mut out)
        .map_err(|e| UpErr::Conn(format!("gunzip: {e}")))?;
    if out.len() > cap {
        return Err(UpErr::Conn("gunzip: output over cap".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::Proto;

    fn spec(h2: usize, batch: bool, compress: Compress) -> ServerCfg {
        ServerCfg {
            name: "fallback".into(),
            proto: Proto::Doh,
            host: "example.test".into(),
            port: 443,
            path: "/dns-query".into(),
            raw_url: "https://example.test/dns-query".into(),
            batch,
            compress,
            h2_fanout: h2,
            uuid: Some("test-uuid".into()),
        }
    }

    #[test]
    fn construction_validates_and_configures() {
        assert!(DohUpstream::new(&spec(0, false, Compress::None), Arc::new(crate::upstream::client_tls_config(&[]))).is_ok());
        assert!(DohUpstream::new(&spec(8, true, Compress::Gzip), Arc::new(crate::upstream::client_tls_config(&[]))).is_ok());
        // h2 fanout builds one client per slot
        let fanned = DohUpstream::new(&spec(3, false, Compress::None), Arc::new(crate::upstream::client_tls_config(&[]))).unwrap();
        assert_eq!(fanned.clients.len(), 3);
        // uuid-header auth becomes the x-magdns-auth header
        assert_eq!(
            DohUpstream::new(&spec(0, false, Compress::None), Arc::new(crate::upstream::client_tls_config(&[])))
                .unwrap()
                .auth_header,
            Some(("x-magdns-auth".into(), "test-uuid".into()))
        );
    }

    #[test]
    fn gzip_roundtrip_smaller_for_realistic_containers() {
        let msgs: Vec<Vec<u8>> = (0..8)
            .map(|i| {
                let mut m = vec![0u8; 12];
                m.extend_from_slice(format!("z{i}.burst.example.com\x00").as_bytes());
                m.extend_from_slice(&[0, 1, 0, 1]);
                m
            })
            .collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let raw = mgb1::encode(&refs).unwrap();
        let gz = gzip_compress(&raw);
        assert!(gz.len() < raw.len() / 2, "gz={} raw={}", gz.len(), raw.len());
        assert_eq!(gunzip(&gz).unwrap(), raw, "lossless round trip");
    }

    #[tokio::test]
    async fn batcher_attached_only_with_batch_flag() {
        assert!(DohUpstream::new(&spec(0, true, Compress::Gzip), Arc::new(crate::upstream::client_tls_config(&[])))
            .unwrap()
            .batcher
            .is_some());
        assert!(DohUpstream::new(&spec(0, false, Compress::Gzip), Arc::new(crate::upstream::client_tls_config(&[])))
            .unwrap()
            .batcher
            .is_none());
    }
}
