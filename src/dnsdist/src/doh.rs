// DoH upstream via hyper. Default: HTTP/1.1 keep-alive — each concurrent
// query holds its own TCP+TLS connection, so transoceanic packet loss can
// never head-of-line-block unrelated queries.
// With the `h2` source flag (near-edge relays like our Maker): a round-robin
// fan of N independent hyper clients, each multiplexing HTTP/2 streams over
// one pooled connection — one stalled connection costs at most 1/N of the
// traffic while saving the handshakes.
// With the `batch` flag: concurrent queries are packed (AIMD-sized, br-
// compressed) into ONE request for the Maker's private batch protocol —
// the relay unpacks, serves from its cache and fans out to Google. Slashes
// the billed request count; every slot fails independently.
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
use std::sync::{Arc, Mutex};
use std::time::Instant;

const BODY_CAP: usize = 128 * 1024;
/// AIMD bounds for the batch packer. Start conservative, double on success,
/// halve on any transport failure; 1 degrades to plain single-query POST.
const BATCH_MIN: usize = 1;
const BATCH_MAX: usize = 24;
const BATCH_INIT: usize = 6;
/// br quality: speed-first — the wire is small and the box CPU-bound.
const BROTLI_QUALITY: u32 = 5;

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

/// One query waiting for its batch to come back.
struct Pending {
    msg: Vec<u8>,
    tx: tokio::sync::oneshot::Sender<Result<Vec<u8>, UpErr>>,
}

/// Zero-wait batcher: arriving queries join whatever is already queued; a
/// single dispatcher drains up to `cap` per request. `cap` follows AIMD —
/// doubles on clean batches, halves on transport failure, floor 1 = plain
/// single-query POST (the batch protocol simply switches itself off under
/// hostile conditions and back on when the sky clears).
pub struct Batcher {
    state: Mutex<BatchState>,
}

struct BatchState {
    pending: Vec<Pending>,
    dispatching: bool,
    cap: usize,
    /// relay refused our encoding (HTTP 415) — drop it for good; the batch
    /// protocol itself is encoding-agnostic (gzip/br/raw all valid)
    compress: bool,
}

impl Batcher {
    fn new() -> Self {
        Batcher {
            state: Mutex::new(BatchState {
                pending: Vec::new(),
                dispatching: false,
                cap: BATCH_INIT,
                compress: true,
            }),
        }
    }

    /// Enqueue this query. The caller that flips `dispatching` becomes the
    /// dispatcher and receives the first batch (older queries first, its own
    /// last). Everyone else just awaits their receiver.
    fn enter(&self, msg: Vec<u8>) -> (tokio::sync::oneshot::Receiver<Result<Vec<u8>, UpErr>>, Option<Vec<Pending>>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut st = self.state.lock().unwrap();
        if st.dispatching {
            st.pending.push(Pending { msg, tx });
            return (rx, None);
        }
        st.dispatching = true;
        let take = (st.cap - 1).min(st.pending.len());
        let mut batch: Vec<Pending> = st.pending.drain(..take).collect();
        batch.push(Pending { msg, tx });
        (rx, Some(batch))
    }

    /// Dispatcher hand-off after each request: next batch to send, or
    /// release the duty when the queue is dry. `ok` drives AIMD.
    fn next_batch(&self, ok: bool) -> Option<Vec<Pending>> {
        let mut st = self.state.lock().unwrap();
        if ok {
            if st.cap < BATCH_MAX {
                st.cap = (st.cap * 2).min(BATCH_MAX);
            }
        } else if st.cap > BATCH_MIN {
            st.cap /= 2;
        }
        if st.pending.is_empty() {
            st.dispatching = false;
            None
        } else {
            let n = st.cap.min(st.pending.len());
            Some(st.pending.drain(..n).collect())
        }
    }

    fn cap(&self) -> usize {
        self.state.lock().unwrap().cap
    }
}

/// [u16 count][u16 len][wire]... container shared with the relay function.
fn pack_batch(items: &[&Pending]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + items.iter().map(|p| p.msg.len() + 2).sum::<usize>());
    out.extend_from_slice(&(items.len() as u16).to_be_bytes());
    for p in items {
        out.extend_from_slice(&(p.msg.len() as u16).to_be_bytes());
        out.extend_from_slice(&p.msg);
    }
    out
}

/// Inverse of the wire layout doh.js answers with; a zero-length or missing
/// slot means that one query failed alone (never the whole batch).
fn unpack_batch(body: &[u8], slots: usize) -> Vec<Option<Vec<u8>>> {
    let mut out = vec![None; slots];
    if body.len() < 2 || u16::from_be_bytes([body[0], body[1]]) == 0 {
        return out;
    }
    let count = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut off = 2usize;
    for slot in out.iter_mut().take(count) {
        if off + 2 > body.len() {
            break;
        }
        let len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
        off += 2;
        if len == 0 || off + len > body.len() {
            continue;
        }
        *slot = Some(body[off..off + len].to_vec());
        off += len;
    }
    out
}

pub struct DoHPool {
    spec: SourceSpec,
    /// one client per connection-fanout slot (len 1 without the `h2` flag)
    clients: Vec<HttpsClient>,
    rr: AtomicUsize,
    allow_private: bool,
    /// pre-built auth header for Maker relays, e.g. ("token", "<key>")
    auth_header: Option<(String, String)>,
    /// present only with the `batch` flag
    batcher: Option<Batcher>,
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
        let wants_batch = spec.batch;
        Ok(DoHPool {
            spec,
            clients,
            rr: AtomicUsize::new(0),
            allow_private,
            auth_header,
            batcher: if wants_batch { Some(Batcher::new()) } else { None },
        })
    }

    pub async fn query(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        if let Some(b) = &self.batcher {
            return self.query_batched(b, msg, deadline).await;
        }
        self.query_single(msg, deadline).await
    }

    /// Batched path: enqueue, drain batches while on dispatcher duty, then
    /// await the slot answer. Zero-wait — a batch is whatever is queued when
    /// we grab the duty; under low load this degenerates to single queries.
    async fn query_batched(
        &self,
        batcher: &Batcher,
        msg: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, UpErr> {
        let (mut rx, mut drain) = batcher.enter(msg.to_vec());
        while let Some(mut batch) = drain.take() {
            let ok = self.send_batch(&mut batch, deadline).await;
            drain = batcher.next_batch(ok);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(UpErr::Timeout)?;
        match tokio::time::timeout(remaining, &mut rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(UpErr::Conn("batch: dispatcher dropped".into())),
            Err(_) => Err(UpErr::Timeout),
        }
    }

    /// One HTTP round trip carrying `batch.len()` queries. Returns whether
    /// the transport behaved (AIMD input), independent of per-slot answers.
    async fn send_batch(&self, batch: &mut Vec<Pending>, deadline: Instant) -> bool {
        loop {
            let (enc, packed) = {
                let st = self.batcher.as_ref().unwrap().state.lock().unwrap();
                let refs: Vec<&Pending> = batch.iter().collect();
                if st.compress {
                    ("gzip", gzip_compress(&pack_batch(&refs)))
                } else {
                    ("", pack_batch(&refs))
                }
            };
            let enc = if enc.is_empty() { None } else { Some(enc) };
            match self
                .post_http(&packed, "application/dns-batch+v1", enc, deadline)
                .await
            {
                Ok(body) => {
                    // AIMD counts a clean HTTP exchange as success even if
                    // some slots carry failures — those are DNS-level
                    // outcomes, not transport ones.
                    let answers = unpack_batch(&body, batch.len());
                    for (p, slot) in batch.drain(..).zip(answers) {
                        let _ = p
                            .tx
                            .send(slot.ok_or(UpErr::Conn("batch: empty slot".into())));
                    }
                    return true;
                }
                Err(UpErr::Conn(s)) if s.contains("status 415") => {
                    // relay can't decompress what we picked — switch this
                    // source to raw containers for good and retry the same
                    // batch uncompressed; no AIMD penalty, it's a handshake
                    self.batcher.as_ref().unwrap().state.lock().unwrap().compress = false;
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

    /// Shared HTTP mechanics for both paths. `body` must be < BODY_CAP.
    async fn post_http(
        &self,
        body: &[u8],
        content_type: &str,
        content_encoding: Option<&str>,
        deadline: Instant,
    ) -> Result<Vec<u8>, UpErr> {
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
            .header("content-type", content_type)
            .header("accept", "application/dns-message");
        if let Some(enc) = content_encoding {
            req = req.header("content-encoding", enc);
        }
        if let Some((name, value)) = &self.auth_header {
            req = req.header(name.as_str(), value.as_str());
        }
        let req = req
            .body(Full::new(Bytes::copy_from_slice(body)))
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
        let collected = tokio::time::timeout(remaining, async {
            resp.into_body()
                .collect()
                .await
                .map_err(|e| UpErr::Conn(format!("doh: body: {e}")))
        })
        .await
        .map_err(|_| UpErr::Timeout)??;
        let buf = collected.to_bytes();
        if buf.len() > BODY_CAP {
            return Err(UpErr::Conn("doh: body too large".into()));
        }
        Ok(buf.to_vec())
    }

    async fn query_single(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        self.post_http(msg, "application/dns-message", None, deadline).await
    }
}

fn gzip_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(
        Vec::with_capacity(data.len() / 2),
        flate2::Compression::new(6),
    );
    let _ = enc.write_all(data);
    enc.finish().unwrap_or_else(|_| data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(msg: &[u8]) -> Pending {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        Pending { msg: msg.to_vec(), tx }
    }

    #[test]
    fn batch_pack_unpack_roundtrip() {
        let items = [pending(b"\x00\x01query-one"), pending(b"\x00\x02query-two-longer")];
        let refs: Vec<&Pending> = items.iter().collect();
        let packed = pack_batch(&refs);
        // header
        assert_eq!((packed[0] as usize) << 8 | packed[1] as usize, 2);
        let slots = unpack_batch(&packed, 2);
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].as_deref(), Some(b"\x00\x01query-one".as_slice()));
        assert_eq!(slots[1].as_deref(), Some(b"\x00\x02query-two-longer".as_slice()));
    }

    #[test]
    fn unpack_tolerates_truncation_and_empty_slots() {
        // count=2 but body carries only an empty slot for slot 0
        let body = [0u8, 2, 0, 0];
        let slots = unpack_batch(&body, 2);
        assert!(slots[0].is_none() && slots[1].is_none(), "empty slot stays None");
        // garbage must not panic and must not fabricate answers
        let slots = unpack_batch(&[9, 9, 1, 2], 3);
        assert_eq!(slots.len(), 3);
        assert!(slots.iter().all(|s| s.is_none()));
    }

    #[test]
    fn gzip_roundtrip_smaller_than_raw_for_realistic_batch() {
        let items: Vec<Pending> = (0..24)
            .map(|i| {
                let mut m = vec![0u8; 12];
                m.extend_from_slice(format!("z{i}.burst{i}.example.com\x00").as_bytes());
                m.extend_from_slice(&[0, 1, 0, 1]);
                Pending { msg: m, tx: tokio::sync::oneshot::channel().0 }
            })
            .collect();
        let refs: Vec<&Pending> = items.iter().collect();
        let raw = pack_batch(&refs);
        let gz = gzip_compress(&raw);
        // compression pays for itself on realistic batches
        assert!(gz.len() < raw.len() * 4 / 10, "gz={} raw={}", gz.len(), raw.len());
    }

    #[test]
    fn aimd_grows_on_success_halves_on_failure() {
        let b = Batcher::new();
        assert_eq!(b.cap(), BATCH_INIT);
        b.next_batch(true);
        b.next_batch(true);
        assert_eq!(b.cap(), BATCH_INIT * 4);
        for _ in 0..10 { b.next_batch(true); }
        assert_eq!(b.cap(), BATCH_MAX, "growth saturates at the ceiling");
        b.next_batch(false);
        b.next_batch(false);
        assert_eq!(b.cap(), BATCH_MAX / 4);
        for _ in 0..20 { b.next_batch(false); }
        assert_eq!(b.cap(), BATCH_MIN, "shrink floors at single-query mode");
    }

    #[tokio::test]
    async fn dispatcher_duty_hands_off_and_releases() {
        let b = Batcher::new();
        let (_rx, first) = b.enter(b"q1".to_vec());
        assert!(first.is_some(), "first enter must dispatch");
        drop(first);
        // second query while duty held: queued, no drain handed out
        let (_rx2, none) = b.enter(b"q2".to_vec());
        assert!(none.is_none());
        // duty held: the queued q2 is handed over on the next drain
        let handoff = b.next_batch(false);
        assert_eq!(handoff.as_ref().map(|v| v.len()), Some(1));
        // queue dry: duty released
        assert!(b.next_batch(false).is_none());
        // and a fresh enter takes over again
        let (_rx3, again) = b.enter(b"q3".to_vec());
        assert!(again.is_some());
    }
}
