//! TLS for load tests: a throw-away test PKI, the simulated hosts' acceptor and the simulated
//! browsers' connector.
//!
//! With TLS on both sides a run measures the gateway's real production path: TLS 1.2 / 1.3
//! towards the host (as to z/OS AT-TLS) and its own HTTPS / WSS listener (`[server.tls]`).

use std::io;
use std::path::Path;
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

/// Common name of the test CA; the server certificate's is `127.0.0.1`. The two must differ:
/// with rcgen's default name for both, OpenSSL-based clients (curl, browsers, proxies) take the
/// server certificate for a self-signed one and reject it.
pub const CA_NAME: &str = "bastion3270-loadgen test CA";

/// File names written by [`write_test_pki`].
pub const CA_FILE: &str = "ca.pem";
/// Server certificate (for `127.0.0.1` and `localhost`), signed by the CA.
pub const CERT_FILE: &str = "server.pem";
/// The server certificate's private key.
pub const KEY_FILE: &str = "server.key";

/// Writes a new CA and a server certificate for `127.0.0.1` / `localhost` into `dir`
/// ([`CA_FILE`], [`CERT_FILE`], [`KEY_FILE`]). For load tests only: the key is not protected.
///
/// # Errors
/// If the certificates cannot be generated or the files cannot be written.
pub fn write_test_pki(dir: &Path) -> io::Result<()> {
    let ca_key = KeyPair::generate().map_err(io::Error::other)?;
    let mut ca_params = CertificateParams::new(Vec::new()).map_err(io::Error::other)?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, CA_NAME);
    let ca = ca_params.self_signed(&ca_key).map_err(io::Error::other)?;
    let server_key = KeyPair::generate().map_err(io::Error::other)?;
    let mut server_params = CertificateParams::new(vec!["127.0.0.1".into(), "localhost".into()])
        .map_err(io::Error::other)?;
    server_params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    let server = server_params
        .signed_by(&server_key, &Issuer::from_params(&ca_params, &ca_key))
        .map_err(io::Error::other)?;
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(CA_FILE), ca.pem())?;
    std::fs::write(dir.join(CERT_FILE), server.pem())?;
    std::fs::write(dir.join(KEY_FILE), server_key.serialize_pem())?;
    Ok(())
}

/// Acceptor for the simulated hosts (TLS 1.2 / 1.3, no client certificate).
///
/// # Errors
/// If a file is missing, malformed, or the key does not fit the certificate.
pub fn acceptor(cert: &Path, key: &Path) -> io::Result<TlsAcceptor> {
    let certs = certs(cert)?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(io::Error::other)?;
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(io::Error::other)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Client configuration for the simulated browsers, trusting only the CA in `ca` (HTTP/1.1
/// via ALPN, as the gateway's listener requires for WebSocket upgrades).
///
/// # Errors
/// If the file is missing or holds no usable CA certificate.
pub fn client_config(ca: &Path) -> io::Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for cert in certs(ca)? {
        roots.add(cert).map_err(io::Error::other)?;
    }
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no certificate in {}", path.display()),
        ));
    }
    Ok(certs)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The server certificate names the CA as its issuer and itself differently, so
    /// OpenSSL-based clients do not take it for self-signed.
    #[test]
    fn server_certificate_subject_differs_from_its_issuer() {
        let dir = std::env::temp_dir().join(format!("bastion3270-pki-unit-{}", std::process::id()));
        write_test_pki(&dir).unwrap();
        let server = CertificateDer::from_pem_file(dir.join(CERT_FILE)).unwrap();
        let ca = CertificateDer::from_pem_file(dir.join(CA_FILE)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let has = |der: &[u8], text: &str| der.windows(text.len()).any(|w| w == text.as_bytes());
        // Issuer (the CA's name) and subject (127.0.0.1) are both in the server certificate.
        assert!(has(&server, CA_NAME) && has(&server, "127.0.0.1"));
        assert!(!has(&server, "rcgen self signed cert"));
        assert!(has(&ca, CA_NAME));
    }
}
