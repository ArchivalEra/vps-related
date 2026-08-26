//! MGB1 — the private DNS batch container, version 1.
//!
//! One wire format spoken identically on every leg of the pipeline:
//! client→box (stream frames / HTTP), box→relay (HTTP body). See
//! `docs/protocol-mgb1.md` for the normative spec; this crate is the
//! single implementation — pure functions, zero IO, zero async, so all
//! three ends and their tests share exactly one set of wire semantics.
//!
//! Container layout (all integers big-endian):
//!
//! ```text
//! "MGB1" | flags u16 | count u16 | count × [u16 len][wire bytes]
//! ```
//!
//! Slot order IS response order: callers patch their own transaction ID
//! onto the answer at `slots[i]`. A `len = 0` slot means that query failed
//! alone — the batch never fails as a whole.
//!
//! Compression lives OUTSIDE this codec: transports express it natively
//! (`Content-Encoding` on HTTP legs, handshake flags on stream legs). This
//! crate always sees decompressed container bytes.

#![forbid(unsafe_code)]

/// Container magic: "MGB1".
pub const MAGIC: u32 = 0x4D47_4231;

/// Hard ceiling on slots per container. The AIMD packer on the box stays
/// well below this; the ceiling exists so a hostile sender cannot make a
/// receiver allocate unbounded bookkeeping before any validation pays off.
pub const MAX_SLOTS: usize = 64;

/// Per-slot wire message bounds (RFC 1035 practical envelope).
pub const MIN_WIRE: usize = 12;
pub const MAX_WIRE: usize = 65535;

/// Uncompressed container bound: 64 × (2 + 65535) rounded up.
pub const MAX_CONTAINER: usize = MAX_SLOTS * (2 + MAX_WIRE) + 8;

pub const FLAG_GZIP: u16 = 1 << 0;
pub const FLAG_BROTLI: u16 = 1 << 1;
pub const FLAG_HANDSHAKE: u16 = 1 << 15;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooShort,
    BadMagic,
    /// slot count outside 0..=MAX_SLOTS
    BadCount(usize),
    /// a length prefix ran past the end of the buffer
    Truncated,
    /// wire payload outside MIN_WIRE..=MAX_WIRE
    BadSlotLen(usize),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TooShort => write!(f, "container shorter than its header"),
            Error::BadMagic => write!(f, "magic mismatch"),
            Error::BadCount(n) => write!(f, "slot count {n} exceeds {MAX_SLOTS}"),
            Error::Truncated => write!(f, "length prefix runs past end of container"),
            Error::BadSlotLen(n) => write!(f, "wire slot of {n} bytes outside bounds"),
        }
    }
}
impl std::error::Error for Error {}

/// Encode one container from raw wire messages. Slots are emitted in order.
pub fn encode(slots: &[&[u8]]) -> Result<Vec<u8>, Error> {
    if slots.len() > MAX_SLOTS {
        return Err(Error::BadCount(slots.len()));
    }
    let mut out = Vec::with_capacity(8 + slots.iter().map(|s| s.len() + 2).sum::<usize>());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // flags: transport owns compression
    out.extend_from_slice(&(slots.len() as u16).to_be_bytes());
    for s in slots {
        if s.len() < MIN_WIRE || s.len() > MAX_WIRE {
            return Err(Error::BadSlotLen(s.len()));
        }
        out.extend_from_slice(&(s.len() as u16).to_be_bytes());
        out.extend_from_slice(s);
    }
    Ok(out)
}

/// Decode a container into per-slot answers. A missing/empty/oversized slot
/// decodes to `None` (that query failed alone); structural corruption stops
/// parsing and returns what was salvaged so far — callers decide whether a
/// half-answered batch is worth acting on.
pub fn decode(buf: &[u8]) -> Result<Vec<Option<Vec<u8>>>, Error> {
    if buf.len() < 8 {
        return Err(Error::TooShort);
    }
    if u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) != MAGIC {
        return Err(Error::BadMagic);
    }
    let _flags = u16::from_be_bytes([buf[4], buf[5]]);
    let count = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if count > MAX_SLOTS {
        return Err(Error::BadCount(count));
    }
    let mut slots = vec![None; count];
    let mut off = 8usize;
    for slot in slots.iter_mut() {
        if off + 2 > buf.len() {
            break;
        }
        let len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        off += 2;
        if len == 0 || len < MIN_WIRE || len > MAX_WIRE || off + len > buf.len() {
            continue;
        }
        *slot = Some(buf[off..off + len].to_vec());
        off += len;
    }
    Ok(slots)
}

/// True when the buffer starts with the MGB1 magic. Safe on any input:
/// DNS transaction IDs collide with the magic at a rate of 2⁻³², which for
/// a probe is indistinguishable from never.
pub fn is_mgb1(buf: &[u8]) -> bool {
    buf.len() >= 4 && u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) == MAGIC
}

/// Stream-leg handshake: a zero-slot container that carries only the client
/// UUID. The peer echoes it byte-for-byte on acceptance and switches the
/// connection to batch mode; anything else means rejected.
pub fn encode_handshake(uuid: &str) -> Result<Vec<u8>, Error> {
    let ub = uuid.as_bytes();
    if ub.is_empty() || ub.len() > u16::MAX as usize {
        return Err(Error::BadSlotLen(ub.len()));
    }
    let mut out = Vec::with_capacity(12 + ub.len());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&FLAG_HANDSHAKE.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // zero slots
    out.extend_from_slice(&(ub.len() as u16).to_be_bytes());
    out.extend_from_slice(ub);
    Ok(out)
}

/// Decode a handshake frame. Returns `None` when the frame is not a
/// handshake (regular containers have no trailing uuid block).
pub fn decode_handshake(buf: &[u8]) -> Result<Option<String>, Error> {
    if buf.len() < 10 {
        return Err(Error::TooShort);
    }
    if u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) != MAGIC {
        return Err(Error::BadMagic);
    }
    let flags = u16::from_be_bytes([buf[4], buf[5]]);
    if flags & FLAG_HANDSHAKE == 0 {
        return Ok(None);
    }
    // zero-slot container followed by [u16 len][uuid utf8]
    if buf.len() < 12 {
        return Err(Error::TooShort);
    }
    let ulen = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let uuid = buf
        .get(10..10 + ulen)
        .ok_or(Error::Truncated)?;
    String::from_utf8(uuid.to_vec())
        .map(Some)
        .map_err(|_| Error::Truncated.into())
}
