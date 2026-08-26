// Ingress gate + MGB1 container execution shared by every listener
// (DoT / DoQ / DoH). One definition so the hard-gate semantics can never
// drift between transports.
use std::sync::Arc;

use crate::app::{self, App};

/// Ingress gate: when client UUIDs are configured, every connection must
/// present a matching handshake before ANY answer leaves the box — a bare
/// standard-mode query gets REFUSED so SNI-driven freeloaders gain nothing.
pub fn authed(app: &App, uuid: Option<&str>) -> bool {
    if app.cfg.client_uuids.is_empty() {
        return true;
    }
    match uuid {
        Some(u) => app
            .cfg
            .client_uuids
            .iter()
            .any(|known| crate::maker_auth::ct_eq(known.as_bytes(), u.as_bytes())),
        None => false,
    }
}

/// Flatten a pipeline Reply into raw wire bytes for container slots.
fn reply_bytes(resp: app::Reply) -> Option<Vec<u8>> {
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

/// Execute one MGB1 container through the full per-slot pipeline and pack
/// the answers back into a response container. Slot order is preserved; a
/// failed slot packs as zero-length instead of failing its siblings.
pub async fn run_container(
    app: &Arc<App>,
    transport: &'static str,
    peer_ip: std::net::IpAddr,
    container: &[u8],
) -> Result<Vec<u8>, mgb1::Error> {
    let slots = mgb1::decode(container)?;
    let mut replies = Vec::with_capacity(slots.len());
    for slot in slots {
        match slot {
            Some(q) => {
                let resp = app::handle_query(app, q.clone(), transport, peer_ip).await;
                replies.push(reply_bytes(resp));
            }
            None => replies.push(None),
        }
    }
    let refs: Vec<Option<&[u8]>> = replies.iter().map(|r| r.as_deref()).collect();
    mgb1::encode_slots(refs)
}

/// Standard-mode query from a connection that never authenticated while the
/// UUID gate is active: cheapest possible honest answer.
pub fn refused(q: &[u8]) -> Vec<u8> {
    crate::dnsmsg::make_refused(q)
}
