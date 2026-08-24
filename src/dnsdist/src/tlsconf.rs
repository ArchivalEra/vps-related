// Certificate/key loading and rustls config builders (pure-rust TLS, ring
// provider passed explicitly - no process-global install).
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

const V13: &[&'static SupportedProtocolVersion] = &[&rustls::version::TLS13];
const V12_13: &[&'static SupportedProtocolVersion] = &[&rustls::version::TLS13, &rustls::version::TLS12];

fn versions(tls12: bool) -> &'static [&'static SupportedProtocolVersion] {
    if tls12 {
        V12_13
    } else {
        V13
    }
}

pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut r = BufReader::new(f);
    rustls_pemfile::certs(&mut r)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs {path}: {e}"))
}

pub fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let f = File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut r = BufReader::new(f);
    rustls_pemfile::private_key(&mut r)
        .map_err(|e| format!("read key {path}: {e}"))?
        .ok_or_else(|| format!("no private key in {path}"))
}

pub fn load_server_config(
    cert_file: &str,
    key_file: &str,
    alpn: &[&[u8]],
    tls12: bool,
) -> Result<ServerConfig, String> {
    let certs = load_certs(cert_file)?;
    let key = load_key(key_file)?;
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions(tls12))
        .map_err(|e| format!("protocol versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("cert/key mismatch: {e}"))?;
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(cfg)
}

/// Mozilla roots (+ optional operator-provided CA, e.g. the stage CA or a
/// private CA fronting a ShadowTLS endpoint).
pub fn root_store(extra_ca: Option<&str>) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
    };
    if let Some(p) = extra_ca {
        for der in load_certs(p)? {
            let _ = roots.add(der);
        }
    }
    Ok(roots)
}

pub fn client_config(roots: RootCertStore, alpn: &[&[u8]], tls12: bool) -> ClientConfig {
    let mut c = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions(tls12))
        .expect("provider supports TLS1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    c
}
