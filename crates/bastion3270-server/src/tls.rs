//! TLS for the gateway's own listener (`[server.tls]`): HTTPS / WSS, optionally with client
//! certificates (mutual TLS), so the hop from an ingress to the pod is encrypted and
//! authenticated as well.
//!
//! Same protocol policy as the host side (`bastion3270-net`): rustls with the `ring` provider,
//! TLS 1.3 and 1.2 only, AEAD cipher suites only.

use std::path::Path;
use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls::version::{TLS12, TLS13};
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use crate::config::ListenerTls;
use crate::error::{Result, ServerError};

/// Builds the acceptor from the configured files. Fails at startup (never per connection) if a
/// file is missing or invalid.
///
/// # Errors
/// [`ServerError::Config`] naming the file and what is wrong with it.
pub fn acceptor(cfg: &ListenerTls) -> Result<TlsAcceptor> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certs = load_certs(&cfg.cert)?;
    let key = PrivateKeyDer::from_pem_file(&cfg.key)
        .map_err(|e| config_err(&cfg.key, &format!("no usable private key: {e}")))?;
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&TLS13, &TLS12])
        .map_err(|e| ServerError::Config(format!("server.tls: {e}")))?;
    let builder = match &cfg.client_ca {
        None => builder.with_no_client_auth(),
        Some(path) => {
            let mut roots = RootCertStore::empty();
            for cert in load_certs(path)? {
                roots
                    .add(cert)
                    .map_err(|e| config_err(path, &format!("invalid CA certificate: {e}")))?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| config_err(path, &format!("unusable client CA: {e}")))?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut config = builder
        .with_single_cert(certs, key)
        .map_err(|e| config_err(&cfg.cert, &format!("certificate and key do not fit: {e}")))?;
    // WebSockets are upgraded HTTP/1.1 connections; the listener speaks HTTP/1 only.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| config_err(path, &format!("cannot read: {e}")))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| config_err(path, &format!("malformed PEM: {e}")))?;
    if certs.is_empty() {
        return Err(config_err(path, "no certificate in the file"));
    }
    Ok(certs)
}

fn config_err(path: &Path, what: &str) -> ServerError {
    ServerError::Config(format!("server.tls '{}': {what}", path.display()))
}
