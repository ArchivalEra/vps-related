// DoT upstream (RFC 7858) with two wire modes on one connection shape:
//
//   * MGB1 mode (default whenever the source has a UUID or `batch: true`):
//     right after the TLS handshake the client sends the MGB1 handshake frame
//     carrying its UUID (docs/protocol-mgb1.md leg 1); every later frame wraps
//     one MGB1 container, answered by a container in slot order.
//   * Standard mode (no UUID, no batching): plain RFC 7766 framed DNS.
//
// Skeleton simplification: ONE connection per source behind an async mutex,
// requests strictly serialized (a batch occupies it for exactly one round
// trip). A dead connection is re-established once per exchange before the
// failure propagates to the failover chain.
use crate::batcher::{Batcher, Pending};
use crate::cfg::ServerCfg;
use crate::frame::{read_frame, write_frame};
use crate::upstream::UpErr;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Anonymous placeholder UUID for boxes that trust all clients; an
/// auth-enforcing box will rightly refuse it, which surfaces the missing
/// env var instead of silently degrading the wire format.
const ANON_UUID: &str = "magdns-client-anonymous";

fn io_deadline<F: std::future::Future<Output = std::io::Result<T>>, T>(
    deadline: Instant,
    fut: F,
) -> impl std::future::Future<Output = Result<T, UpErr>> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(UpErr::Timeout);
    async move {
        let remaining = remaining?;
        tokio::time::timeout(remaining, fut)
            .await
            .map_err(|_| UpErr::Timeout)?
            .map_err(|e| UpErr::Conn(format!("dot io: {e}")))
    }
}

pub struct DotUpstream {
    host: String,
    port: u16,
    /// true → handshake + MGB1 containers; false → standard RFC 7766 frames
    mgb1_mode: bool,
    handshake_uuid: String,
    tls: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
    conn: Mutex<Option<TlsStream>>,
    batcher: Option<Batcher>,
}

impl DotUpstream {
    pub fn new(spec: &ServerCfg, tls: Arc<rustls::ClientConfig>) -> Result<Self, String> {
        let server_name = ServerName::try_from(spec.host.clone())
            .map_err(|e| format!("dot upstream `{}`: bad server name: {e}", spec.raw_url))?;
        // MGB1 needs the handshake channel for the UUID, so any authenticated
        // or batching source speaks containers; only bare sources stay plain
        let mgb1_mode = spec.batch || spec.uuid.is_some();
        let handshake_uuid = spec.uuid.clone().unwrap_or_else(|| ANON_UUID.to_string());
        Ok(DotUpstream {
            host: spec.host.clone(),
            port: spec.port,
            mgb1_mode,
            handshake_uuid,
            tls,
            server_name,
            conn: Mutex::new(None),
            batcher: (mgb1_mode && spec.batch).then(Batcher::new),
        })
    }

    pub fn describe(&self) -> String {
        format!(
            "dot://{}:{} {}{}",
            self.host,
            self.port,
            if self.mgb1_mode { "mgb1" } else { "std" },
            if self.batcher.is_some() { "+batch" } else { "" },
        )
    }

    /// Per-query entry point: batched container path or single-shot formats.
    pub async fn query(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        if !self.mgb1_mode {
            return self.standard_exchange(msg, deadline).await;
        }
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
                Ok(Err(_)) => Err(UpErr::Conn("dot batch: dispatcher dropped".into())),
                Err(_) => Err(UpErr::Timeout),
            };
        }
        // MGB1 without the batcher: a one-slot container per query
        let mut slots = self.slots(&[msg], deadline).await?;
        slots
            .pop()
            .flatten()
            .ok_or_else(|| UpErr::Conn("dot: empty slot".into()))
    }

    /// One container round trip: `msgs.len()` queries in, positional answers
    /// out (`None` = that slot failed alone).
    pub async fn slots(
        &self,
        msgs: &[&[u8]],
        deadline: Instant,
    ) -> Result<Vec<Option<Vec<u8>>>, UpErr> {
        let container = mgb1::encode(msgs).map_err(|e| UpErr::Conn(format!("dot: pack: {e}")))?;
        let buf = self.exchange(&container, deadline).await?;
        if !mgb1::is_mgb1(&buf) {
            return Err(UpErr::Conn("dot: peer answered outside MGB1".into()));
        }
        mgb1::decode(&buf).map_err(|e| UpErr::Conn(format!("dot: unpack: {e}")))
    }

    /// Dispatcher duty: carry one batch through one container round trip and
    /// hand every pending its own slot. Returns whether the transport behaved
    /// (the AIMD input), independent of per-slot DNS outcomes.
    async fn send_batch(&self, batch: &mut Vec<Pending>, deadline: Instant) -> bool {
        let refs: Vec<&[u8]> = batch.iter().map(|p| p.msg.as_slice()).collect();
        match self.slots(&refs, deadline).await {
            Ok(slots) => {
                for (p, slot) in batch.drain(..).zip(slots) {
                    let _ =
                        p.tx.send(slot.ok_or_else(|| UpErr::Conn("batch: empty slot".into())));
                }
                true
            }
            Err(e) => {
                for p in batch.drain(..) {
                    let _ = p.tx.send(Err(e.clone()));
                }
                false
            }
        }
    }

    /// Serialized container exchange with one reconnect retry.
    async fn exchange(&self, payload: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        let mut g = self.conn.lock().await;
        for attempt in 0..2 {
            if g.is_none() {
                *g = Some(self.connect(deadline).await?);
            }
            match roundtrip_frame(g.as_mut().unwrap(), payload, deadline).await {
                Ok(reply) => return Ok(reply),
                Err(e) => {
                    *g = None; // corpse: next attempt reconnects
                    if attempt == 1 {
                        return Err(e);
                    }
                }
            }
        }
        unreachable!("loop returns or continues twice")
    }

    /// Standard-mode request/response with transaction ID verification (safe:
    /// the connection mutex serializes, so IDs cannot interleave).
    async fn standard_exchange(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        let mut g = self.conn.lock().await;
        for attempt in 0..2 {
            if g.is_none() {
                *g = Some(self.connect(deadline).await?);
            }
            let s = g.as_mut().unwrap();
            let wrote = io_deadline(deadline, write_frame(s, msg)).await.is_ok();
            let reply: Result<Vec<u8>, UpErr> = if wrote {
                match io_deadline(deadline, read_frame(s)).await {
                    Ok(Some(m)) if m.len() >= 12 => {
                        let want = u16::from_be_bytes([msg[0], msg[1]]);
                        let got = u16::from_be_bytes([m[0], m[1]]);
                        if got == want {
                            return Ok(m);
                        }
                        // mismatched ID means the stream desynced: rebuild
                        Err(UpErr::Conn("dot: reply id mismatch".into()))
                    }
                    Ok(_) => Err(UpErr::Conn("dot: short/closed reply".into())),
                    Err(e) => Err(e),
                }
            } else {
                Err(UpErr::Conn("dot: write failed".into()))
            };
            *g = None;
            if attempt == 1 {
                return Err(reply.err().unwrap_or(UpErr::Conn("dot: unusable".into())));
            }
        }
        unreachable!("loop returns or continues twice")
    }

    async fn connect(&self, deadline: Instant) -> Result<TlsStream, UpErr> {
        let addrs = tokio::net::lookup_host((self.host.as_str(), self.port))
            .await
            .map_err(|e| UpErr::Conn(format!("dot: resolve {}: {e}", self.host)))?;
        let mut last = UpErr::Conn("dot: no usable address".into());
        for a in addrs {
            let tcp = match io_deadline(deadline, TcpStream::connect(a)).await {
                Ok(t) => t,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let connector = tokio_rustls::TlsConnector::from(self.tls.clone());
            let name = self.server_name.clone();
            match io_deadline(deadline, connector.connect(name, tcp)).await {
                Ok(mut s) => {
                    if self.mgb1_mode {
                        return self.handshake(&mut s, deadline).await.map(|_| s);
                    }
                    return Ok(s);
                }
                Err(e) => {
                    last = e;
                    continue;
                }
            }
        }
        Err(last)
    }

    /// Send the MGB1 handshake frame; the box must echo it byte-for-byte.
    async fn handshake(&self, s: &mut TlsStream, deadline: Instant) -> Result<(), UpErr> {
        let frame = mgb1::encode_handshake(&self.handshake_uuid)
            .map_err(|e| UpErr::Conn(format!("dot: handshake pack: {e}")))?;
        io_deadline(deadline, write_frame(s, &frame)).await?;
        let echo = io_deadline(deadline, read_frame(s)).await?;
        match echo {
            Some(e) if mgb1::decode_handshake(&e) == Ok(Some(self.handshake_uuid.clone())) => {
                Ok(())
            }
            _ => Err(UpErr::Conn("dot: handshake rejected".into())),
        }
    }
}

async fn roundtrip_frame(
    s: &mut TlsStream,
    payload: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, UpErr> {
    io_deadline(deadline, write_frame(s, payload)).await?;
    match io_deadline(deadline, read_frame(s)).await? {
        Some(m) if !m.is_empty() => Ok(m),
        _ => Err(UpErr::Conn("dot: empty reply frame".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{Compress, Proto};

    fn spec(uuid: Option<&str>, batch: bool) -> ServerCfg {
        ServerCfg {
            name: "box".into(),
            proto: Proto::Dot,
            host: "127.0.0.1".into(),
            port: 1853,
            path: String::new(),
            raw_url: "tls://127.0.0.1:1853".into(),
            batch,
            compress: Compress::None,
            h2_fanout: 0,
            uuid: uuid.map(str::to_string),
        }
    }

    #[test]
    fn wire_mode_follows_uuid_and_batch_flags() {
        let tls = Arc::new(crate::upstream::client_tls_config(&[b"dot"]));
        assert!(
            !DotUpstream::new(&spec(None, false), tls.clone())
                .unwrap()
                .mgb1_mode
        );
        assert!(
            DotUpstream::new(&spec(None, true), tls.clone())
                .unwrap()
                .mgb1_mode
        );
        assert!(
            DotUpstream::new(&spec(Some("u"), false), tls.clone())
                .unwrap()
                .mgb1_mode
        );

        let anon = DotUpstream::new(&spec(None, true), tls.clone()).unwrap();
        assert_eq!(anon.handshake_uuid, ANON_UUID, "anonymous fallback uuid");
        let named = DotUpstream::new(&spec(Some("secret-uuid"), true), tls.clone()).unwrap();
        assert_eq!(named.handshake_uuid, "secret-uuid");
        assert!(named.batcher.is_some(), "batch flag attaches a batcher");
        assert!(DotUpstream::new(&spec(Some("u"), false), tls)
            .unwrap()
            .batcher
            .is_none());
    }
}
