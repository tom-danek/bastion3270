//! Direct TLS 1.2/1.3 transport connector and CA certificate loader.
//!
//! Provides asynchronous TLS connection establishment using `rustls` 0.23 with the
//! `ring` cryptographic provider and `tokio-rustls` 0.26, custom Root CA certificate
//! loading (PEM and DER formats); which certificates are trusted is decided in
//! [`super::trust`].
//!
//! ## Invariants
//! - Enforces `#![forbid(unsafe_code)]` with zero `unsafe` blocks.
//! - Protocol versions are strictly limited to TLS 1.2 and TLS 1.3 (RFC 5246, RFC 8446).
//! - All errors are strongly typed via [`NetError`].
//! - Zero `.unwrap()`, zero `.expect()`, zero panics, zero index slicing.

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use super::certificate::{parse_sha256_hex, CertificateRejection};
use super::trust::{HostCertVerifier, HostTrust};
use crate::error::{NetError, Result};
use crate::profile::ConnectionProfile;

/// The Mozilla trust roots ([`webpki_roots`]) alone; connections trust more, see
/// [`HostTrust`].
#[must_use]
pub fn load_default_root_store() -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

/// Loads a custom CA certificate store from a PEM or DER file (only that file's certificates).
///
/// # Errors
/// Returns [`NetError::InvalidCertificate`] on I/O error, corrupt PEM/DER data, or empty store.
pub fn load_ca_cert_store(path: &Path) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for cert in read_ca_certs(path)? {
        store.add(cert).map_err(|e| {
            NetError::InvalidCertificate(format!(
                "invalid CA certificate in '{}': {e}",
                path.display()
            ))
        })?;
    }
    Ok(store)
}

/// Reads the certificates of a CA file: one or more PEM certificates, or one DER certificate.
///
/// # Errors
/// Returns [`NetError::InvalidCertificate`] if the file cannot be read, is empty, or holds
/// malformed PEM.
pub fn read_ca_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let raw = std::fs::read(path).map_err(|e| {
        NetError::InvalidCertificate(format!(
            "failed to read CA certificate from '{}': {e}",
            path.display()
        ))
    })?;

    if raw.is_empty() {
        return Err(NetError::InvalidCertificate(format!(
            "CA certificate file is empty: '{}'",
            path.display()
        )));
    }

    let certs = CertificateDer::pem_slice_iter(&raw)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            NetError::InvalidCertificate(format!(
                "malformed PEM certificate in '{}': {e}",
                path.display()
            ))
        })?;

    if certs.is_empty() {
        // No PEM block: the file is one binary DER certificate (checked when it is added).
        return Ok(vec![CertificateDer::from(raw)]);
    }
    Ok(certs)
}

/// Parses the target host into a strongly typed TLS [`ServerName`].
///
/// Supports DNS domain names (e.g. `"mainframe.ibm.com"`, `"localhost"`) and
/// IPv4 / IPv6 addresses (e.g. `"127.0.0.1"`, `"::1"`).
///
/// # Errors
/// Returns [`NetError::InvalidCertificate`] if `host` is empty or invalid for TLS SNI.
pub fn parse_server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).map_err(|e| {
        NetError::InvalidCertificate(format!("invalid server name '{host}' for TLS SNI: {e}"))
    })
}

/// Constructs a [`rustls::ClientConfig`] configured with the `ring` provider and TLS 1.2/1.3,
/// trusting [`HostTrust::system`] and the profile's `ca_cert`.
///
/// # Errors
/// Returns [`NetError::InvalidCertificate`] if CA certificate loading fails.
/// Returns [`NetError::Tls`] if protocol version configuration fails.
pub fn create_tls_client_config(profile: &ConnectionProfile) -> Result<Arc<ClientConfig>> {
    tls_client_config(profile, &HostTrust::system()).map(|(config, _)| config)
}

/// A refused host certificate, filled in during the handshake.
type RejectionSlot = Arc<OnceLock<CertificateRejection>>;

/// The TLS configuration of one connection, and where a refused certificate is reported.
fn tls_client_config(
    profile: &ConnectionProfile,
    trust: &HostTrust,
) -> Result<(Arc<ClientConfig>, RejectionSlot)> {
    let roots = trust.roots_with(profile.ca_cert.as_deref())?;
    let accept_name = profile
        .accept_hostname
        .as_deref()
        .map(parse_server_name)
        .transpose()?;
    let pin = match profile.pinned_cert_sha256.as_deref() {
        Some(text) => Some(parse_sha256_hex(text).ok_or_else(|| {
            NetError::Config("profile 'pinned_cert_sha256' must be 64 hex digits".to_owned())
        })?),
        None => None,
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = HostCertVerifier::new(roots, Arc::clone(&provider), accept_name, pin);
    let rejection = verifier.rejection();

    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13, &TLS12])
        .map_err(NetError::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier));
    // Mutual TLS: the gateway authenticates itself to the host (e.g. AT-TLS with
    // `HandshakeRole ServerWithClientAuth`). Validation guarantees both paths or neither.
    let config = match (&profile.client_cert, &profile.client_key) {
        (Some(cert), Some(key)) => builder
            .with_client_auth_cert(load_cert_chain(cert)?, load_private_key(key)?)
            .map_err(|e| {
                NetError::InvalidCertificate(format!(
                    "client certificate '{}' and key '{}' do not fit: {e}",
                    cert.display(),
                    key.display()
                ))
            })?,
        _ => builder.with_no_client_auth(),
    };

    Ok((Arc::new(config), rejection))
}

/// Loads a certificate chain (leaf first, then intermediates) from a PEM file.
///
/// # Errors
/// [`NetError::InvalidCertificate`] if the file cannot be read, is malformed or has no
/// certificate.
pub fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let chain = CertificateDer::pem_file_iter(path)
        .map_err(|e| {
            NetError::InvalidCertificate(format!("cannot read '{}': {e}", path.display()))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            NetError::InvalidCertificate(format!("malformed PEM in '{}': {e}", path.display()))
        })?;
    if chain.is_empty() {
        return Err(NetError::InvalidCertificate(format!(
            "no certificate in '{}'",
            path.display()
        )));
    }
    Ok(chain)
}

/// Loads a private key (PKCS#8, PKCS#1 or SEC1) from a PEM file.
///
/// # Errors
/// [`NetError::InvalidCertificate`] if the file has no usable private key.
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(|e| {
        NetError::InvalidCertificate(format!(
            "no usable private key in '{}': {e}",
            path.display()
        ))
    })
}

/// Performs a direct implicit TLS handshake on an existing TCP stream.
///
/// # Arguments
/// - `stream`: Connected [`TcpStream`].
/// - `server_name`: Verified SNI server name.
/// - `config`: Pre-configured [`ClientConfig`].
/// - `handshake_timeout`: Maximum duration allowed for the TLS handshake.
///
/// # Errors
/// - Returns [`NetError::ConnectTimeout`] if the deadline expires.
/// - Returns [`NetError::Tls`] if the handshake fails due to a TLS protocol alert or certificate rejection.
/// - Returns [`NetError::Io`] if an underlying OS transport failure occurs.
pub async fn connect_tls_handshake(
    stream: TcpStream,
    server_name: ServerName<'static>,
    config: Arc<ClientConfig>,
    handshake_timeout: Duration,
) -> Result<TlsStream<TcpStream>> {
    if handshake_timeout.is_zero() {
        return Err(NetError::ConnectTimeout);
    }

    let connector = TlsConnector::from(config);
    let handshake_fut = connector.connect(server_name, stream);

    let tls_stream = tokio::time::timeout(handshake_timeout, handshake_fut)
        .await
        .map_err(|_| NetError::ConnectTimeout)?
        .map_err(|io_err| {
            if let Some(tls_err) = io_err
                .get_ref()
                .and_then(|e| e.downcast_ref::<rustls::Error>())
            {
                NetError::Tls(tls_err.clone())
            } else {
                NetError::Io(io_err)
            }
        })?;

    Ok(tls_stream)
}

/// Establishes an asynchronous TLS connection to the host specified in `profile`.
///
/// Enforces a single unified deadline (`timeout`) spanning:
/// 1. Hostname / SNI validation.
/// 2. CA certificate loading and `ClientConfig` construction.
/// 3. Asynchronous TCP 3-way handshake.
/// 4. `TCP_NODELAY` configuration.
/// 5. Direct implicit TLS 1.2/1.3 handshake.
///
/// # Errors
/// - Returns [`NetError::ConnectTimeout`] if TCP connect or TLS handshake exceeds the deadline.
/// - Returns [`NetError::InvalidCertificate`] if the CA cert or host is invalid.
/// - Returns [`NetError::Tls`] if the TLS handshake fails.
/// - Returns [`NetError::Io`] on OS network errors (e.g. connection refused).
pub async fn connect_tls(
    profile: &ConnectionProfile,
    timeout: Duration,
) -> Result<TlsStream<TcpStream>> {
    connect_tls_with_trust(profile, &HostTrust::system(), timeout).await
}

/// [`connect_tls`] with the application's trust anchors.
///
/// # Errors
/// As [`connect_tls`]; a refused host certificate is
/// [`NetError::UntrustedCertificate`] with the reason and the certificate's details.
pub async fn connect_tls_with_trust(
    profile: &ConnectionProfile,
    trust: &HostTrust,
    timeout: Duration,
) -> Result<TlsStream<TcpStream>> {
    if timeout.is_zero() {
        return Err(NetError::ConnectTimeout);
    }

    let server_name = parse_server_name(&profile.host)?;
    let (client_config, rejection) = tls_client_config(profile, trust)?;

    // The budget is tracked as elapsed time, not as `now + timeout`: an `Instant + Duration`
    // overflows (and panics) for a timeout too large to represent as a point in time.
    let start = tokio::time::Instant::now();

    // 1. Establish raw TCP connection bounded by the timeout
    let tcp_stream = match tokio::time::timeout(
        timeout,
        super::tcp::connect_tcp_stream(&profile.host, profile.port),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(err),
        Err(_) => return Err(NetError::ConnectTimeout),
    };

    // 2. Perform direct implicit TLS handshake within remaining deadline
    let remaining = timeout.saturating_sub(start.elapsed());
    if remaining.is_zero() {
        return Err(NetError::ConnectTimeout);
    }

    connect_tls_handshake(tcp_stream, server_name, client_config, remaining)
        .await
        .map_err(|error| match rejection.get() {
            Some(refused) => NetError::UntrustedCertificate(Box::new(refused.clone())),
            None => error,
        })
}
