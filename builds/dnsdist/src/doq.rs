// DoQ (RFC 9250): quinn-based dual-stack listener + single multiplexed
// upstream connection per source. One bidirectional stream per query,
// 2-byte length-prefixed frames, ALPN "doq".
use crate::app::{self, App};
use crate::cfg::SourceSpec;
use crate::frame::{read_frame, write_frame};
use crate::upstream::UpErr;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime, TransportConfig, VarInt};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

fn server_transport(idle_ms: u64) -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(idle_ms.max(5000) as u32))));
    tc.max_concurrent_bidi_streams(VarInt::from_u32(128));
    Arc::new(tc)
}

fn client_transport() -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.keep_alive_interval(Some(Duration::from_secs(15)));
    tc.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(60_000))));
    Arc::new(tc)
}

pub fn build_server_config(
    rustls_cfg: Arc<rustls::ServerConfig>,
    idle_ms: u64,
) -> ServerConfig {
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
            match incoming.await {
                Ok(conn) => {
                    app.stats.doq_conns.fetch_add(1, Ordering::Relaxed);
                    serve_conn(&app, conn).await;
                    app.stats.doq_conns.fetch_sub(1, Ordering::Relaxed);
                }
                Err(_) => {}
            }
        });
    }
}

async fn serve_conn(app: &Arc<App>, conn: Connection) {
    loop {
        match conn.accept_bi().await {
            Ok((mut tx, mut rx)) => {
                let app = app.clone();
                tokio::spawn(async move {
                    let idle = Duration::from_millis(app.cfg.idle_timeout_ms.max(5000));
                    let q = match tokio::time::timeout(idle, read_frame(&mut rx)).await {
                        Ok(Ok(Some(q))) => q,
                        _ => return,
                    };
                    if q.len() < 12 {
                        return;
                    }
                    let resp = app::handle_query(&app, q, "doq").await;
                    if resp.is_empty() {
                        return;
                    }
                    if write_frame(&mut tx, &resp).await.is_ok() {
                        let _ = tx.finish();
                    }
                });
            }
            Err(_) => break,
        }
    }
}

// ---------- upstream ----------

pub struct DoqClient {
    spec: SourceSpec,
    endpoint: Endpoint,
    conn: Mutex<Option<Connection>>,
    allow_private: bool,
}

impl DoqClient {
    pub fn new(spec: SourceSpec, client_cfg: Arc<rustls::ClientConfig>, allow_private: bool) -> Result<Self, String> {
        let addr: std::net::SocketAddr = "[::]:0".parse().unwrap();
        let sock = app::dual_udp_socket(addr).map_err(|e| format!("doq client bind: {e}"))?;
        let mut endpoint = Endpoint::new(EndpointConfig::default(), None, sock, Arc::new(TokioRuntime))
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
