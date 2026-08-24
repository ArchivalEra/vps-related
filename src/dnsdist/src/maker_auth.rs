// Pluggable auth for Maker upstream. Implementation injected at deploy time.
// Public repo ships only the interface + deny-all stub. Zero crypto surface.

pub trait MakerAuth: Send + Sync {
    fn token(&self) -> String;
    fn ready(&self) -> bool;
}

struct Closed;

impl MakerAuth for Closed {
    fn token(&self) -> String {
        String::new()
    }
    fn ready(&self) -> bool {
        false
    }
}

/// Static bearer: whatever string the operator provides. Works with fixed
/// secrets, pre-computed hashes, TOTP output, or any opaque token —
/// the Maker side decides what to accept.
pub struct Bearer {
    pub token: String,
}

impl MakerAuth for Bearer {
    fn token(&self) -> String {
        self.token.clone()
    }
    fn ready(&self) -> bool {
        !self.token.is_empty()
    }
}

/// Create auth backend from explicit parameters (called once at startup).
pub fn create(kind: &str, key: &str) -> Box<dyn MakerAuth> {
    match kind {
        "bearer" if !key.is_empty() => Box::new(Bearer { token: key.to_string() }),
        _ => Box::new(Closed),
    }
}

/// Constant-time comparison (prevents timing attacks on token check).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_default() {
        let auth = create("closed", "");
        assert!(!auth.ready());
    }

    #[test]
    fn bearer_any_string() {
        // Any UTF-8 string works as bearer token
        let auth = create("bearer", "这就是我的密钥啦啦啦啦");
        assert!(auth.ready());
        assert_eq!(auth.token(), "这就是我的密钥啦啦啦啦");

        let auth2 = create("bearer", "a1b2c3d4e5f6g7h8");
        assert!(auth2.ready());
    }

    #[test]
    fn unknown_kind_fails_closed() {
        let auth = create("totp-super-secret", "key");
        assert!(!auth.ready(), "unregistered kind must fail closed");
    }

    #[test]
    fn ct_eq_correct() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"hellO"));
        assert!(!ct_eq(b"hi", b"hi!"));
    }
}
