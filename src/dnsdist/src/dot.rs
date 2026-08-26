// DoT: listener (dual-stack) and a single pipelined upstream connection with
// auto-reconnect, ID remapping and per-query oneshots.
use crate::app::{self, App};
use crate::cfg::SourceSpec;
use crate::frame::{read_frame, write_frame};
use crate::ingress;
use crate::upstream::UpErr;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

type ClientTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

pub async fn run_listener(app: Arc<App>, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                let peer_ip = peer.ip();
                if app.stats.dot_conns.load(Ordering::Relaxed) >= 128 {
                    continue; // per-conn TLS buffers are the main off-cache cost
                }
                let app = app.clone();
                tokio::spawn(async move {
                    app.stats.dot_conns.fetch_add(1, Ordering::Relaxed);
                    let _ = handle_conn(&app, tcp, peer_ip).await;
                    app.stats.dot_conns.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) => {
                eprintln!("dot: accept error: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_conn(app: &Arc<App>, tcp: TcpStream, peer_ip: std::net::IpAddr) {
    let acceptor = {
        let g = app.server_tls_dot.read().unwrap();
        tokio_rustls::TlsAcceptor::from(g.clone())
    };
    let mut tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
        Ok(Ok(s)) => s,
        _ => return,
    };
    let idle = Duration::from_millis(app.cfg.idle_timeout_ms.max(5000));
    let mut batch_mode = false;
    loop {
        let q = match tokio::time::timeout(idle, read_frame(&mut tls)).await {
            Ok(Ok(Some(q))) => q,
            _ => break,
        };

        // MGB1 first-contact: the very frame from a batch-capable client is
        // its handshake. Validate the UUID against the ingress table.
        if !batch_mode && mgb1::is_mgb1(&q) {
            match mgb1::decode_handshake(&q) {
                Ok(Some(uuid)) => {
                    if !ingress::authed(app, Some(&uuid)) {
                        break; // wrong UUID: drop the connection, no answers
                    }
                    batch_mode = true;
                    if write_frame(&mut tls, &q).await.is_err() {
                        break;
                    }
                    continue;
                }
                _ => {
                    // a container that arrives without ever handshaking is a
                    // protocol violation — close instead of guessing
                    break;
                }
            }
        }

        // hard gate: configured UUIDs but the connection never authenticated
        if !app.cfg.client_uuids.is_empty() && !batch_mode {
            let refused = ingress::refused(&q);
            if write_frame(&mut tls, &refused).await.is_err() {
                break;
            }
            continue;
        }

        if batch_mode && mgb1::is_mgb1(&q) {
            let packed = match ingress::run_container(app, "dot", peer_ip, &q).await {
                Ok(p) => p,
                Err(_) => break,
            };
            if write_frame(&mut tls, &packed).await.is_err() {
                break;
            }
            continue;
        }

        if q.len() < 12 {
            break;
        }
        let resp = app::handle_query(app, q, "dot", peer_ip).await;
        if resp.is_empty() {
            break;
        }
        if app::write_reply(&mut tls, &resp).await.is_err() {
            break;
        }
    }
}

// ---------- upstream ----------

struct Job {
    msg: Vec<u8>,
    tx: oneshot::Sender<Result<Vec<u8>, String>>,
}

pub struct DotPool {
    spec: SourceSpec,
    client_cfg: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    allow_private: bool,
    conn: Mutex<Option<mpsc::Sender<Job>>>,
}

impl DotPool {
    pub fn new(
        spec: SourceSpec,
        client_cfg: Arc<ClientConfig>,
        allow_private: bool,
    ) -> Result<Self, String> {
        let server_name = ServerName::try_from(spec.host.clone())
            .map_err(|e| format!("upstream `{}`: bad server name: {e}", spec.raw))?;
        Ok(DotPool {
            spec,
            client_cfg,
            server_name,
            allow_private,
            conn: Mutex::new(None),
        })
    }

    pub async fn query(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        for _attempt in 0..3 {
            let remaining = deadline.checked_duration_since(Instant::now());
            let Some(remaining) = remaining.filter(|d| !d.is_zero()) else {
                return Err(UpErr::Timeout);
            };
            let sender = self.acquire().await;
            let (tx, rx) = oneshot::channel();
            if sender
                .send(Job {
                    msg: msg.to_vec(),
                    tx,
                })
                .await
                .is_err()
            {
                self.discard();
                continue;
            }
            match tokio::time::timeout(remaining, rx).await {
                Ok(Ok(Ok(v))) => return Ok(v),
                Ok(Ok(Err(e))) => {
                    self.discard();
                    if Instant::now() >= deadline {
                        return Err(UpErr::Timeout);
                    }
                    let _ = e;
                    continue;
                }
                Ok(Err(_)) => {
                    self.discard();
                    continue;
                }
                Err(_) => {
                    // slow or dead peer: drop the conn so the next attempt
                    // reconnects instead of piling onto the same corpse
                    self.discard();
                    return Err(UpErr::Timeout);
                }
            }
        }
        Err(UpErr::Conn("dot: upstream unusable".into()))
    }

    fn discard(&self) {
        *self.conn.lock().unwrap() = None;
    }

    async fn acquire(&self) -> mpsc::Sender<Job> {
        {
            let mut g = self.conn.lock().unwrap();
            if let Some(s) = g.as_ref() {
                if !s.is_closed() {
                    return s.clone();
                }
            }
            let (tx, rx) = mpsc::channel::<Job>(512);
            let spec = self.spec.clone();
            let cfg = self.client_cfg.clone();
            let name = self.server_name.clone();
            let allow = self.allow_private;
            tokio::spawn(async move {
                run_conn(spec, cfg, name, allow, rx).await;
            });
            *g = Some(tx.clone());
            tx
        }
    }
}

async fn run_conn(
    spec: SourceSpec,
    client_cfg: Arc<ClientConfig>,
    name: ServerName<'static>,
    allow_private: bool,
    mut rx: mpsc::Receiver<Job>,
) {
    let stream = match connect(&spec, &client_cfg, &name, allow_private).await {
        Some(s) => s,
        None => {
            // fail queued jobs by dropping rx; senders error out
            while let Some(job) = rx.recv().await {
                let _ = job.tx.send(Err("dot: connect failed".into()));
            }
            return;
        }
    };
    let (rh, wh): (ReadHalf<ClientTlsStream>, WriteHalf<ClientTlsStream>) =
        tokio::io::split(stream);
    let inflight: Arc<Mutex<HashMap<u16, oneshot::Sender<Result<Vec<u8>, String>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let reader = {
        let inflight = inflight.clone();
        tokio::spawn(async move {
            let mut rh = rh;
            loop {
                match read_frame(&mut rh).await {
                    Ok(Some(m)) if m.len() >= 2 => {
                        let id = u16::from_be_bytes([m[0], m[1]]);
                        if let Some(tx) = inflight.lock().unwrap().remove(&id) {
                            let _ = tx.send(Ok(m));
                        }
                    }
                    _ => break,
                }
            }
            let mut g = inflight.lock().unwrap();
            for (_, tx) in g.drain() {
                let _ = tx.send(Err("dot: connection lost".into()));
            }
        })
    };

    let mut wh = wh;
    let mut next_id: u16 = 0;
    while let Some(job) = rx.recv().await {
        // pick a free id
        let mut tries = 0u32;
        loop {
            next_id = next_id.wrapping_add(1);
            if !inflight.lock().unwrap().contains_key(&next_id) || tries > 3000 {
                break;
            }
            tries += 1;
        }
        inflight.lock().unwrap().insert(next_id, job.tx);
        let mut m = job.msg;
        m[0] = (next_id >> 8) as u8;
        m[1] = (next_id & 0xFF) as u8;
        if write_frame(&mut wh, &m).await.is_err() {
            inflight.lock().unwrap().remove(&next_id);
            break;
        }
    }
    reader.abort();
    let mut g = inflight.lock().unwrap();
    for (_, tx) in g.drain() {
        let _ = tx.send(Err("dot: writer stopped".into()));
    }
}

async fn connect(
    spec: &SourceSpec,
    client_cfg: &Arc<ClientConfig>,
    name: &ServerName<'static>,
    allow_private: bool,
) -> Option<ClientTlsStream> {
    let addrs = app::resolve_addrs(&spec.host, spec.port, allow_private).await;
    for a in addrs {
        let tcp = match tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(a)).await {
            Ok(Ok(t)) => t,
            _ => continue,
        };
        let connector = tokio_rustls::TlsConnector::from(client_cfg.clone());
        match tokio::time::timeout(Duration::from_secs(4), connector.connect(name.clone(), tcp))
            .await
        {
            Ok(Ok(s)) => return Some(s),
            _ => continue,
        }
    }
    None
}
