// 2-byte big-endian length-prefixed DNS frames (RFC 7766 / RFC 7858 §4),
// shared by the inbound TCP listener and the DoT upstream.
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Ok(None) = clean EOF before any frame byte; mid-frame EOF is an error.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut lb = [0u8; 2];
    match r.read_exact(&mut lb).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u16::from_be_bytes(lb) as usize;
    if len == 0 {
        return Ok(Some(Vec::new()));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) -> std::io::Result<()> {
    let lb = (msg.len() as u16).to_be_bytes();
    w.write_all(&lb).await?;
    w.write_all(msg).await?;
    w.flush().await
}
