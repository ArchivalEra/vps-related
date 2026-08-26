// DoQ (RFC 9250): quinn-based dual-stack listener + single multiplexed
// upstream connection per source. One bidirectional stream per query,
// 2-byte length-prefixed frames, ALPN "doq".
use crate::app::{self, App};
use crate::cfg::SourceSpec;
use crate::frame::{read_frame, write_frame};
use crate::ingress;
use crate::upstream::UpErr;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime,
    TransportConfig, VarInt,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

fn server_transport(idle_ms: u64) -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(
        idle_ms.max(5000) as u32
    ))));
    tc.max_concurrent_bidi_streams(VarInt::from_u32(128));
    // memory diet: small windows keep per-conn state well under 8MB total
    tc.stream_receive_window(VarInt::from_u32(64 * 1024));
    tc.receive_window(VarInt::from_u32(256 * 1024));
    tc.datagram_receive_buffer_size(Some(64 * 1024));
    Arc::new(tc)
}

fn client_transport() -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.keep_alive_interval(Some(Duration::from_secs(15)));
    tc.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(60_000))));
    tc.stream_receive_window(VarInt::from_u32(64 * 1024));
    tc.receive_window(VarInt::from_u32(256 * 1024));
    tc.datagram_receive_buffer_size(Some(64 * 1024));
    Arc::new(tc)
}

pub fn build_server_config(rustls_cfg: Arc<rustls::ServerConfig>, idle_ms: u64) -> ServerConfig {
    // ring always ships TLS13_AES_128_GCM_SHA256 so this cannot fail
    let quic = QuicServerConfig::try_from(rustls_cfg).expect("initial cipher suite");
    let mut sc = ServerConfig::with_crypto(Arc::new(quic));
    sc.transport_config(server_transport(idle_ms));
    sc
}

pub async fn run_server(app: Arc<App>, endpoint: Endpoint) {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };
        let app = app.clone();
        tokio::spawn(async move {
            if app.stats.doq_conns.load(Ordering::Relaxed) >= 256 {
                return; // let it time out; guard against conn flooding
            }
            if let Ok(conn) = incoming.await {
                app.stats.doq_conns.fetch_add(1, Ordering::Relaxed);
                let peer_ip = conn.remote_address().ip();
                serve_conn(&app, conn, peer_ip).await;
                app.stats.doq_conns.fetch_sub(1, Ordering::Relaxed);
            }
        });
    }
}

async fn serve_conn(app: &Arc<App>, conn: Connection, peer_ip: std::net::IpAddr) {
    // connection-level MGB1 authentication state, shared by every stream:
    // the first handshake frame flips it, later containers require it.
    let batch_authed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
        let app = app.clone();
        let batch_authed = batch_authed.clone();
        tokio::spawn(async move {
            if handle_stream(&app, &mut tx, &mut rx, peer_ip, batch_authed)
                .await
                .is_ok()
            {
                let _ = tx.finish();
            }
        });
    }
}

/// One bidirectional stream = one standard query OR one MGB1 container.
/// Returns Err to drop the stream without a reply (protocol violations).
async fn handle_stream(
    app: &Arc<App>,
    tx: &mut quinn::SendStream,
    rx: &mut quinn::RecvStream,
    peer_ip: std::net::IpAddr,
    batch_authed: Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), ()> {
    use std::sync::atomic::Ordering;
    let idle = Duration::from_millis(app.cfg.idle_timeout_ms.max(5000));
    let q = match tokio::time::timeout(idle, read_frame(rx)).await {
        Ok(Ok(Some(q))) => q,
        _ => return Err(()),
    };

    if mgb1::is_mgb1(&q) {
        match mgb1::decode_handshake(&q) {
            Ok(Some(uuid)) => {
                if !ingress::authed(app, Some(&uuid)) {
                    return Err(()); // wrong UUID: stream dropped cold
                }
                batch_authed.store(true, Ordering::Relaxed);
                if write_frame(tx, &q).await.is_err() {
                    return Err(());
                }
                return Ok(());
            }
            Ok(None) => {
                // a bare container before any handshake is a violation unless
                // this connection already authenticated on an earlier stream
                if !batch_authed.load(Ordering::Relaxed) {
                    return Err(());
                }
                let packed = match ingress::run_container(app, "doq", peer_ip, &q).await {
                    Ok(p) => p,
                    Err(_) => return Err(()),
                };
                if write_frame(tx, &packed).await.is_err() {
                    return Err(());
                }
                return Ok(());
            }
            Err(_) => return Err(()),
        }
    }

    // hard gate: UUIDs configured but this connection never authenticated
    if !app.cfg.client_uuids.is_empty() && !batch_authed.load(Ordering::Relaxed) {
        let refused = ingress::refused(&q);
        let _ = write_frame(tx, &refused).await;
        return Ok(());
    }

    if q.len() < 12 {
        return Err(());
    }
    let resp = app::handle_query(app, q, "doq", peer_ip).await;
    if resp.is_empty() {
        return Err(());
    }
    if app::write_reply(tx, &resp).await.is_err() {
        return Err(());
    }
    Ok(())
}

// ---------- upstream ----------

pub struct DoqClient {
    spec: SourceSpec,
    endpoint: Endpoint,
    conn: Mutex<Option<Connection>>,
    allow_private: bool,
}

impl DoqClient {
    pub fn new(
        spec: SourceSpec,
        client_cfg: Arc<rustls::ClientConfig>,
        allow_private: bool,
    ) -> Result<Self, String> {
        let addr: std::net::SocketAddr = "[::]:0".parse().unwrap();
        let sock = app::dual_udp_socket(addr).map_err(|e| format!("doq client bind: {e}"))?;
        let mut endpoint = Endpoint::new(
            EndpointConfig::default(),
            None,
            sock,
            Arc::new(TokioRuntime),
        )
        .map_err(|e| format!("doq endpoint: {e}"))?;
        let quic = QuicClientConfig::try_from(client_cfg).expect("initial cipher suite");
        let mut qcfg = ClientConfig::new(Arc::new(quic));
        qcfg.transport_config(client_transport());
        endpoint.set_default_client_config(qcfg);
        Ok(DoqClient {
            spec,
            endpoint,
            conn: Mutex::new(None),
            allow_private,
        })
    }

    pub async fn query(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        let existing = self.conn.lock().await.clone();
        if let Some(c) = existing {
            match query_on(&c, msg, deadline).await {
                Ok(v) => return Ok(v),
                Err(_) => {
                    *self.conn.lock().await = None;
                }
            }
        }
        let c = self.connect(deadline).await?;
        let r = query_on(&c, msg, deadline).await;
        if r.is_ok() {
            *self.conn.lock().await = Some(c);
        }
        r
    }

    async fn connect(&self, deadline: Instant) -> Result<Connection, UpErr> {
        let addrs = app::resolve_addrs(&self.spec.host, self.spec.port, self.allow_private).await;
        for a in addrs {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(UpErr::Timeout)?
                .min(Duration::from_secs(5));
            match self.endpoint.connect(a, &self.spec.host) {
                Ok(connecting) => match tokio::time::timeout(remaining, connecting).await {
                    Ok(Ok(c)) => return Ok(c),
                    _ => continue,
                },
                Err(_) => continue,
            }
        }
        Err(UpErr::Conn("doq: connect failed".into()))
    }
}

async fn query_on(c: &Connection, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(UpErr::Timeout)?;
    let (mut tx, mut rx) = tokio::time::timeout(remaining, c.open_bi())
        .await
        .map_err(|_| UpErr::Timeout)?
        .map_err(|e| UpErr::Conn(e.to_string()))?;
    tokio::time::timeout(remaining, write_frame(&mut tx, msg))
        .await
        .map_err(|_| UpErr::Timeout)?
        .map_err(|e| UpErr::Conn(e.to_string()))?;
    let _ = tx.finish();
    match tokio::time::timeout(remaining, read_frame(&mut rx)).await {
        Ok(Ok(Some(v))) if !v.is_empty() => Ok(v),
        Ok(_) => Err(UpErr::Conn("doq: empty response".into())),
        Err(_) => Err(UpErr::Timeout),
    }
}
