// Inbound listeners for standard DNS: UDP (one task per packet), TCP with
// RFC 7766 2-byte length framing, and a plaintext local DoH endpoint
// (RFC 8484 GET ?dns=base64url and POST application/dns-message).
//
// TLS termination on the client is deliberately out of scope: the stub faces
// the LAN only — TODO(T-tls-listen) if that ever changes.
use crate::frame::{read_frame, write_frame};
use crate::upstream::Chain;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const IDLE_TCP: Duration = Duration::from_secs(30);

/// UDP packet loop over an already-bound socket (bind happens in main so a
/// taken port aborts startup instead of hiding inside a spawned task).
pub async fn udp_loop(chain: Arc<Chain>, sock: Arc<UdpSocket>) -> std::io::Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("udp: recv: {e}");
                continue;
            }
        };
        // every datagram is one DNS message → one task
        let msg = buf[..n].to_vec();
        let chain = chain.clone();
        let sock = sock.clone();
        tokio::spawn(async move {
            let resp = chain.resolve(&msg).await;
            let _ = sock.send_to(&resp, peer).await;
        });
    }
}

pub async fn tcp_loop(chain: Arc<Chain>, listener: TcpListener) -> std::io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((tcp, _peer)) => {
                let chain = chain.clone();
                tokio::spawn(handle_tcp_conn(chain, tcp));
            }
            Err(e) => {
                eprintln!("tcp: accept error: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

pub async fn doh_loop(chain: Arc<Chain>, listener: TcpListener) -> std::io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((tcp, _peer)) => {
                let chain = chain.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req| {
                        let chain = chain.clone();
                        async move { Ok::<_, std::convert::Infallible>(handle_http(chain, req).await) }
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(tcp), svc)
                        .await;
                });
            }
            Err(e) => {
                eprintln!("doh-serve: accept error: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// One framed query at a time per connection; answers go back in order.
async fn handle_tcp_conn(chain: Arc<Chain>, mut tcp: TcpStream) {
    loop {
        let q = match tokio::time::timeout(IDLE_TCP, read_frame(&mut tcp)).await {
            Ok(Ok(Some(q))) if !q.is_empty() => q,
            // clean EOF or idle timeout ends the connection politely
            _ => return,
        };
        let resp = chain.resolve(&q).await;
        if write_frame(&mut tcp, &resp).await.is_err() {
            return;
        }
    }
}

fn text_response(status: u16, body: &'static str) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("static response")
}

fn wire_response(wire: Vec<u8>) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(200)
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from(wire)))
        .expect("wire response")
}

async fn handle_http(
    chain: Arc<Chain>,
    req: hyper::Request<Incoming>,
) -> hyper::Response<Full<Bytes>> {
    if req.uri().path() == "/health" {
        return text_response(200, "ok");
    }
    match *req.method() {
        hyper::Method::GET => {
            let Some(dns_b64) = req
                .uri()
                .query()
                .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("dns=")))
            else {
                return text_response(400, "missing dns parameter");
            };
            let Some(wire) = base64url_decode(dns_b64) else {
                return text_response(400, "bad dns parameter");
            };
            wire_response(chain.resolve(&wire).await)
        }
        hyper::Method::POST => {
            let ct_ok = req
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| ct.starts_with("application/dns-message"));
            if !ct_ok {
                return text_response(415, "unsupported media type");
            }
            let body = match req.collect().await {
                Ok(c) => c.to_bytes(),
                Err(_) => return text_response(400, "bad body"),
            };
            if !(12..=65535).contains(&body.len()) {
                return text_response(400, "bad wire size");
            }
            wire_response(chain.resolve(&body).await)
        }
        _ => text_response(405, "method not allowed"),
    }
}

/// RFC 4648 base64url decode without padding requirements. Hand-rolled to
/// keep the codec in one place per binary, mirroring the box's decoder.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for ch in s.chars() {
        if ch == '=' {
            break;
        }
        let v = T.iter().position(|t| *t as char == ch)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    /// RFC 4648 base64url encoder (test-side counterpart of the decoder).
    fn b64url_encode(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(T[(n >> 6) as usize & 63] as char);
            }
            if chunk.len() > 2 {
                out.push(T[n as usize & 63] as char);
            }
        }
        out
    }

    #[test]
    fn base64url_roundtrip_without_padding() {
        for data in [
            b"".to_vec(),
            b"f".to_vec(),
            b"fo".to_vec(),
            b"foo".to_vec(),
            (0u8..=255).collect::<Vec<u8>>(),
        ] {
            assert_eq!(base64url_decode(&b64url_encode(&data)).unwrap(), data);
        }
        // '+' and '/' belong to standard base64, not the url alphabet → rejected
        assert!(base64url_decode("a+b/c==").is_none());
    }

    #[tokio::test]
    async fn udp_loop_answers_servfail_when_all_sources_fail() {
        use crate::cache::MagCache;
        use crate::cfg::{Compress, Proto, ServerCfg};

        let spec = ServerCfg {
            name: "dead".into(),
            proto: Proto::Dot,
            host: "127.0.0.1".into(),
            port: 1, // loopback refused instantly
            path: String::new(),
            raw_url: "tls://127.0.0.1:1".into(),
            batch: false,
            compress: Compress::None,
            h2_fanout: 0,
            uuid: None,
        };
        let dot_tls = Arc::new(crate::upstream::client_tls_config(&[b"dot"]));
        let chain = Arc::new(crate::upstream::Chain::from_sources(
            vec![crate::upstream::Transport::Dot(Box::new(
                crate::dot::DotUpstream::new(&spec, dot_tls).unwrap(),
            ))],
            MagCache::new(65536, Duration::from_secs(300)),
        ));

        // client side of the exchange
        let cli = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        // server side: pre-bound socket handed to the packet loop
        let srv = Arc::new(
            UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .await
                .unwrap(),
        );
        let bound = srv.local_addr().unwrap();
        let server = tokio::spawn(udp_loop(chain, srv));

        let q = [
            0x11u8, 0x22, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
        ];
        cli.send_to(&q, bound).await.unwrap();
        let mut buf = [0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), cli.recv_from(&mut buf))
            .await
            .expect("answer within deadline")
            .expect("recv ok");
        assert_eq!(&buf[..2], &[0x11, 0x22], "requester txid patched back");
        assert_eq!(buf[3] & 0x0F, 2, "SERVFAIL after all sources fail");
        assert!(n > 12, "question section echoed");
        server.abort();
    }
}
