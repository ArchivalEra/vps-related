// Plain DNS-over-UDP upstream (for a local resolver leg, e.g. clash's
// dns listen on loopback). RFC 1035 semantics with the standard
// TC=1 -> TCP retry, 2-byte length framed.
// Sockets are pooled per target address (exclusive checkout) so a query
// never pays bind+register costs, and concurrent queries never race on
// recv from the same socket.
use crate::app;
use crate::cfg::SourceSpec;
use crate::frame::{read_frame, write_frame};
use crate::upstream::UpErr;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

const IDLE_PER_ADDR: usize = 8;

pub struct UdpSource {
    spec: SourceSpec,
    allow_private: bool,
    idle: Mutex<HashMap<std::net::SocketAddr, Vec<Arc<UdpSocket>>>>,
}

impl UdpSource {
    pub fn new(spec: SourceSpec, allow_private: bool) -> Result<Self, String> {
        Ok(UdpSource {
            spec,
            allow_private,
            idle: Mutex::new(HashMap::new()),
        })
    }

    async fn checkout(&self, addr: std::net::SocketAddr) -> Result<Arc<UdpSocket>, UpErr> {
        {
            let mut pool = self.idle.lock().await;
            if let Some(s) = pool.get_mut(&addr).and_then(|v| v.pop()) {
                return Ok(s);
            }
        }
        let bind: std::net::SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::from_std(app::dual_udp_socket(bind).map_err(UpErr::Conn)?)
            .map_err(|e| UpErr::Conn(format!("udp bind: {e}")))?;
        sock.connect(addr)
            .await
            .map_err(|e| UpErr::Conn(format!("udp connect: {e}")))?;
        Ok(Arc::new(sock))
    }

    async fn checkin(&self, addr: std::net::SocketAddr, s: Arc<UdpSocket>) {
        let mut pool = self.idle.lock().await;
        let v = pool.entry(addr).or_default();
        if v.len() < IDLE_PER_ADDR {
            v.push(s);
        }
    }

    pub async fn query(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, UpErr> {
        let addrs = app::resolve_addrs(&self.spec.host, self.spec.port, self.allow_private).await;
        let mut last = UpErr::Conn("udp: no address".into());
        for a in addrs {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(UpErr::Timeout)?;
            let sock = match self.checkout(a).await {
                Ok(s) => s,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let round = tokio::time::timeout(remaining, udp_round(&sock, msg, &a)).await;
            self.checkin(a, sock).await;
            match round {
                Ok(Ok(resp)) => {
                    if crate::dnsmsg::is_truncated(&resp) {
                        // truncated: retry the same query over TCP, framed
                        let remaining = deadline
                            .checked_duration_since(Instant::now())
                            .filter(|d| !d.is_zero())
                            .ok_or(UpErr::Timeout)?;
                        match tcp_round(&a, msg, remaining).await {
                            Ok(r) => return Ok(r),
                            Err(e) => {
                                last = e;
                                continue;
                            }
                        }
                    }
                    return Ok(resp);
                }
                Ok(Err(e)) => {
                    last = e;
                    continue;
                }
                Err(_) => return Err(UpErr::Timeout),
            }
        }
        Err(last)
    }
}

async fn udp_round(
    sock: &UdpSocket,
    msg: &[u8],
    _addr: &std::net::SocketAddr,
) -> Result<Vec<u8>, UpErr> {
    sock.send(msg)
        .await
        .map_err(|e| UpErr::Conn(format!("udp send: {e}")))?;
    let mut buf = vec![0u8; 65535];
    loop {
        let n = sock
            .recv(&mut buf)
            .await
            .map_err(|e| UpErr::Conn(format!("udp recv: {e}")))?;
        // socket is connected to the upstream: any datagram is from it; only
        // the transaction id filters late/stale answers from earlier queries
        if n >= 12 && buf[0..2] == msg[0..2] {
            return Ok(buf[..n].to_vec());
        }
    }
}

async fn tcp_round(
    addr: &std::net::SocketAddr,
    msg: &[u8],
    budget: std::time::Duration,
) -> Result<Vec<u8>, UpErr> {
    let tcp = tokio::time::timeout(
        budget.min(std::time::Duration::from_secs(2)),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| UpErr::Timeout)?
    .map_err(|e| UpErr::Conn(format!("udp-tcp connect: {e}")))?;
    let mut tcp = tcp;
    tokio::time::timeout(budget, async {
        write_frame(&mut tcp, msg)
            .await
            .map_err(|e| UpErr::Conn(format!("udp-tcp send: {e}")))?;
        read_frame(&mut tcp)
            .await
            .map_err(|e| UpErr::Conn(format!("udp-tcp recv: {e}")))?
            .ok_or_else(|| UpErr::Conn("udp-tcp: closed".into()))
    })
    .await
    .map_err(|_| UpErr::Timeout)?
}
