//! Which host certificates are trusted.
//!
//! Banks run their own certificate authorities. A connection should not fail only because that
//! CA was deployed somewhere the client does not look, so the trust anchors are the union of:
//!
//! 1. the Mozilla roots ([`webpki_roots`]);
//! 2. the operating system's certificate store (Windows certificate store, macOS keychain,
//!    the Linux CA bundle; `SSL_CERT_FILE` / `SSL_CERT_DIR` if set), loaded once per process;
//! 3. CA files of the application ([`HostTrust::with_ca_files`], e.g. the gateway's
//!    `[host_tls] ca_certs`);
//! 4. the profile's own `ca_cert`.
//!
//! A CA file may also contain an intermediate certificate the host does not send: an anchor
//! does not have to be self-signed.
//!
//! [`HostCertVerifier`] then checks the host's certificate like x3270 (`sio_openssl.c`):
//! the chain always, then the name (`accept_hostname` or the host), accepting the common name
//! of a certificate without subject alternative names. A desktop profile may pin one exact
//! certificate (`pinned_cert_sha256`), which is then trusted like an SSH host key.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{verify_server_cert_signed_by_trust_anchor, verify_server_name};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use super::certificate::{
    common_name_matches, sha256, CertProblem, CertificateRejection, PeerCertificate,
};
use super::tls::read_ca_certs;
use crate::error::{NetError, Result};

/// How many trust anchors came from where (for the startup log).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrustSummary {
    /// Mozilla roots.
    pub mozilla: usize,
    /// Certificates from the operating system's store.
    pub system: usize,
    /// Certificates from the application's CA files.
    pub configured: usize,
}

/// The trust anchors for host certificates, shared by every connection of a process.
#[derive(Debug, Clone)]
pub struct HostTrust {
    roots: Arc<RootCertStore>,
    summary: TrustSummary,
}

impl HostTrust {
    /// The Mozilla roots and the operating system's store, loaded on first use and then shared
    /// (a CA installed later needs a restart).
    #[must_use]
    pub fn system() -> Self {
        static SYSTEM: OnceLock<HostTrust> = OnceLock::new();
        SYSTEM.get_or_init(Self::load_system).clone()
    }

    fn load_system() -> Self {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mozilla = store.len();

        let native = rustls_native_certs::load_native_certs();
        for error in &native.errors {
            // Paths only, never certificate contents. An empty store (e.g. a `scratch`
            // container) is normal: the Mozilla roots and configured CAs still apply.
            tracing::debug!(%error, "could not read part of the system certificate store");
        }
        let (system, ignored) = store.add_parsable_certificates(native.certs);
        if ignored > 0 {
            tracing::debug!(
                ignored,
                "system certificates that are not usable as trust anchors"
            );
        }
        Self {
            roots: Arc::new(store),
            summary: TrustSummary {
                mozilla,
                system,
                configured: 0,
            },
        }
    }

    /// [`HostTrust::system`] plus the CA certificates in `files` (PEM or DER).
    ///
    /// # Errors
    /// [`NetError::InvalidCertificate`] if a file cannot be read or holds no usable
    /// certificate.
    pub fn with_ca_files(files: &[PathBuf]) -> Result<Self> {
        let mut trust = Self::system();
        if files.is_empty() {
            return Ok(trust);
        }
        let mut store = (*trust.roots).clone();
        for path in files {
            let added = add_ca_file(&mut store, path)?;
            trust.summary.configured = trust.summary.configured.saturating_add(added);
        }
        trust.roots = Arc::new(store);
        Ok(trust)
    }

    /// Where the trust anchors came from.
    #[must_use]
    pub const fn summary(&self) -> TrustSummary {
        self.summary
    }

    /// The anchors for one connection: these plus the profile's `ca_cert`.
    pub(crate) fn roots_with(&self, ca_cert: Option<&Path>) -> Result<Arc<RootCertStore>> {
        match ca_cert {
            None => Ok(Arc::clone(&self.roots)),
            Some(path) => {
                let mut store = (*self.roots).clone();
                add_ca_file(&mut store, path)?;
                Ok(Arc::new(store))
            }
        }
    }
}

/// Adds every certificate of a CA file; returns how many.
fn add_ca_file(store: &mut RootCertStore, path: &Path) -> Result<usize> {
    let certs = read_ca_certs(path)?;
    let count = certs.len();
    for cert in certs {
        store.add(cert).map_err(|e| {
            NetError::InvalidCertificate(format!(
                "invalid CA certificate in '{}': {e}",
                path.display()
            ))
        })?;
    }
    Ok(count)
}

/// Checks the host's certificate (see the module documentation).
///
/// One verifier serves one connection: a refusal is kept in [`HostCertVerifier::rejection`],
/// because the TLS library reports only its own error type through the handshake.
#[derive(Debug)]
pub struct HostCertVerifier {
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
    /// The name the certificate must match instead of the host (x3270 `acceptHostname`).
    accept_name: Option<ServerName<'static>>,
    /// A desktop pin: this exact certificate is trusted.
    pin: Option<[u8; 32]>,
    rejection: Arc<OnceLock<CertificateRejection>>,
}

impl HostCertVerifier {
    /// A verifier over `roots`.
    #[must_use]
    pub fn new(
        roots: Arc<RootCertStore>,
        provider: Arc<CryptoProvider>,
        accept_name: Option<ServerName<'static>>,
        pin: Option<[u8; 32]>,
    ) -> Self {
        Self {
            roots,
            provider,
            accept_name,
            pin,
            rejection: Arc::new(OnceLock::new()),
        }
    }

    /// Where a refusal is kept (shared, so it can be read after the handshake failed).
    #[must_use]
    pub fn rejection(&self) -> Arc<OnceLock<CertificateRejection>> {
        Arc::clone(&self.rejection)
    }

    fn check(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        now: UnixTime,
    ) -> core::result::Result<(), rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        // The chain first: a name never makes an untrusted certificate acceptable.
        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        match verify_server_name(&cert, name) {
            Ok(()) => Ok(()),
            Err(_) if common_name_matches(end_entity, name) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl ServerCertVerifier for HostCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> core::result::Result<ServerCertVerified, rustls::Error> {
        if self.pin.is_some_and(|pin| pin == sha256(end_entity)) {
            return Ok(ServerCertVerified::assertion());
        }
        let name = self.accept_name.as_ref().unwrap_or(server_name);
        match self.check(end_entity, intermediates, name, now) {
            Ok(()) => Ok(ServerCertVerified::assertion()),
            Err(error) => {
                let _ = self.rejection.set(CertificateRejection {
                    problem: CertProblem::from_tls_error(&error, name),
                    certificate: PeerCertificate::from_der(end_entity),
                });
                Err(error)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
