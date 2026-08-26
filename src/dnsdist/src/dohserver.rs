// Inbound standard DoH (RFC 8484) on port 443, with MGB1 batch support and
// UUID authentication via the `x-magdns-auth` header. This is the box's own
// front door for magdns-client instances — auth semantics mirror the stream
// legs: when client_uuids is configured, unauthenticated requests get 403.
// Public resolvers are never contacted here; everything flows through
// handle_query (cache → ingress → split → chains), same as DoT/DoQ.
use crate::app::{self, App};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use tokio::net::{TcpListener, TcpStream};

pub async fn run_listener(app: Arc<App>, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                let peer_ip = peer.ip();
                if app.stats.dot_conns.load(Ordering::Relaxed) >= 256 {
                    continue; // same per-conn budget as the other listeners
                }
                let app = app.clone();
                tokio::spawn(async move {
                    app.stats.dot_conns.fetch_add(1, Ordering::Relaxed);
                    let _ = serve_tls(&app, tcp, peer_ip).await;
                    app.stats.dot_conns.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) => {
                eprintln!("doh-serve: accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn serve_tls(app: &Arc<App>, tcp: TcpStream, peer_ip: std::net::IpAddr) {
    let acceptor = {
        let g = app.server_tls_doh.read().unwrap();
        tokio_rustls::TlsAcceptor::from(g.clone())
    };
    let tls = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        acceptor.accept(tcp),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return,
    };
    let svc = service_fn(move |req| {
        let app = app.clone();
        async move {
            Ok::<_, std::convert::Infallible>(handle_http(app, req, peer_ip).await)
        }
    });
    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(tls), svc)
        .await;
}

fn text_response(status: u16, body: &'static str) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("static response")
}

fn wire_response(status: u16, ctype: &str, wire: Vec<u8>) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", ctype)
        .body(Full::new(Bytes::from(wire)))
        .expect("wire response")
}

async fn handle_http(
    app: Arc<App>,
    mut req: hyper::Request<Incoming>,
    peer_ip: std::net::IpAddr,
) -> hyper::Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    if path == "/health" {
        return text_response(200, "ok");
    }

    // UUID gate mirrors the stream legs: header carries the identity, and
    // when client_uuids is configured a missing/wrong one gets 403.
    let uuid = req
        .headers()
        .get("x-magdns-auth")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if !crate::ingress::authed(&app, uuid.as_deref()) {
        return text_response(403, "forbidden");
    }

    let is_batch = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/mgb1+v1"));

    match *req.method() {
        hyper::Method::POST => {
            let body = match req.collect().await {
                Ok(c) => c.to_bytes(),
                Err(_) => return text_response(400, "bad body"),
            };
            if is_batch {
                return match crate::ingress::run_container(&app, "doh", peer_ip, &body)
                    .await
                {
                    Ok(packed) => wire_response(200, "application/mgb1+v1", packed),
                    Err(_) => text_response(400, "bad container"),
                };
            }
            if !(12..=65535).contains(&body.len()) {
                return text_response(400, "bad wire size");
            }
            let resp = app::handle_query(&app, body.to_vec(), "doh", peer_ip).await;
            match reply_wire(resp) {
                Some(wire) => wire_response(200, "application/dns-message", wire),
                None => text_response(502, "dropped"),
            }
        }
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
            if !(12..=65535).contains(&wire.len()) {
                return text_response(400, "bad dns parameter");
            }
            let resp = app::handle_query(&app, wire, "doh", peer_ip).await;
            match reply_wire(resp) {
                Some(wire) => wire_response(200, "application/dns-message", wire),
                None => text_response(502, "dropped"),
            }
        }
        _ => text_response(405, "method not allowed"),
    }
}

fn reply_wire(resp: app::Reply) -> Option<Vec<u8>> {
    match resp {
        app::Reply::Owned(mut v) => {
            if v.len() < 12 {
                return None;
            }
            Some(std::mem::take(&mut v))
        }
        app::Reply::Shared { prefix, body } => {
            if body.len() < 12 {
                return None;
            }
            let mut out = Vec::with_capacity(body.len());
            out.extend_from_slice(&prefix);
            out.extend_from_slice(&body[2..]);
            Some(out)
        }
    }
}

/// RFC 4648 base64url decode without padding requirements. Hand-rolled to
/// keep the codec in one place per binary, mirroring the relay's decoder.
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
