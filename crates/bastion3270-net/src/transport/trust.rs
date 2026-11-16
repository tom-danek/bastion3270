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

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{verify_server_cert_signed_by_trust_anchor, verify_server_name};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use super::certificate::{
    check_cert_validity, common_name_matches, sha256, CertProblem, CertificateRejection,
    PeerCertificate,
};
use super::ecdsa::extended_verification_algorithms;
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

/// SHA-256 fingerprints of certificates explicitly present in the system store or CA files.
pub type CertFingerprints = HashSet<[u8; 32]>;

/// The trust anchors for host certificates, shared by every connection of a process.
#[derive(Debug, Clone)]
pub struct HostTrust {
    roots: Arc<RootCertStore>,
    /// Fingerprints of certificates explicitly trusted in the system store or CA files
    /// (e.g. a host or self-signed certificate marked as trusted in macOS Keychain).
    trusted_certs: Arc<CertFingerprints>,
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
        let mut trusted_certs = HashSet::with_capacity(native.certs.len());
        for cert in &native.certs {
            trusted_certs.insert(sha256(cert));
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
            trusted_certs: Arc::new(trusted_certs),
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
        let mut trusted = (*trust.trusted_certs).clone();
        for path in files {
            let added = add_ca_file(&mut store, &mut trusted, path)?;
            trust.summary.configured = trust.summary.configured.saturating_add(added);
        }
        trust.roots = Arc::new(store);
        trust.trusted_certs = Arc::new(trusted);
        Ok(trust)
    }

    /// Where the trust anchors came from.
    #[must_use]
    pub const fn summary(&self) -> TrustSummary {
        self.summary
    }

    /// The anchors and directly trusted certificates for one connection: these plus the
    /// profile's `ca_cert`.
    pub(crate) fn roots_with(
        &self,
        ca_cert: Option<&Path>,
    ) -> Result<(Arc<RootCertStore>, Arc<CertFingerprints>)> {
        match ca_cert {
            None => Ok((Arc::clone(&self.roots), Arc::clone(&self.trusted_certs))),
            Some(path) => {
                let mut store = (*self.roots).clone();
                let mut trusted = (*self.trusted_certs).clone();
                add_ca_file(&mut store, &mut trusted, path)?;
                Ok((Arc::new(store), Arc::new(trusted)))
            }
        }
    }
}

/// Adds every certificate of a CA file; returns how many.
fn add_ca_file(
    store: &mut RootCertStore,
    trusted_certs: &mut CertFingerprints,
    path: &Path,
) -> Result<usize> {
    let certs = read_ca_certs(path)?;
    let count = certs.len();
    for cert in certs {
        let fingerprint = sha256(&cert);
        store.add(cert).map_err(|e| {
            NetError::InvalidCertificate(format!(
                "invalid CA certificate in '{}': {e}",
                path.display()
            ))
        })?;
        trusted_certs.insert(fingerprint);
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
    trusted_certs: Arc<CertFingerprints>,
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
        Self::with_trusted_certs(roots, Arc::new(HashSet::new()), provider, accept_name, pin)
    }

    /// A verifier over `roots` and directly trusted certificates from the system store / `ca_cert`.
    #[must_use]
    pub fn with_trusted_certs(
        roots: Arc<RootCertStore>,
        trusted_certs: Arc<CertFingerprints>,
        provider: Arc<CryptoProvider>,
        accept_name: Option<ServerName<'static>>,
        pin: Option<[u8; 32]>,
    ) -> Self {
        Self {
            roots,
            trusted_certs,
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
        // A certificate directly present in the system store (e.g. a host or self-signed
        // certificate marked as trusted in macOS Keychain) or in `ca_cert` is trusted
        // once its validity period and name are checked.
        if self.trusted_certs.contains(&sha256(end_entity)) {
            check_cert_validity(end_entity, now)?;
        } else {
            let algs = extended_verification_algorithms(
                self.provider.signature_verification_algorithms.all,
            );
            // The chain first: a name never makes an untrusted certificate acceptable.
            if let Err(err) = verify_server_cert_signed_by_trust_anchor(
                &cert,
                &self.roots,
                intermediates,
                now,
                &algs,
            ) {
                if macos_keychain_trusts(end_entity, intermediates) {
                    check_cert_validity(end_entity, now)?;
                } else {
                    return Err(err);
                }
            }
        }
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

/// Evaluates the certificate chain with macOS `SecTrust` when `rustls-native-certs` did not
/// export an MDM-deployed CA or an intermediate certificate stored in Keychain with default
/// ("Use System Defaults") trust settings.
#[cfg(target_os = "macos")]
fn macos_keychain_trusts(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> bool {
    use security_framework::certificate::SecCertificate;
    use security_framework::policy::SecPolicy;
    use security_framework::secure_transport::SslProtocolSide;
    use security_framework::trust::SecTrust;

    let Ok(leaf) = SecCertificate::from_der(end_entity) else {
        return false;
    };
    let mut certs = Vec::with_capacity(intermediates.len().saturating_add(1));
    certs.push(leaf);
    for inter in intermediates {
        if let Ok(c) = SecCertificate::from_der(inter) {
            certs.push(c);
        }
    }

    let ssl_policy = SecPolicy::create_ssl(SslProtocolSide::SERVER, None);
    if let Ok(trust) = SecTrust::create_with_certificates(&certs, std::slice::from_ref(&ssl_policy))
    {
        if trust.evaluate_with_error().is_ok() {
            return true;
        }
    }

    let x509_policy = SecPolicy::create_x509();
    if let Ok(trust) =
        SecTrust::create_with_certificates(&certs, std::slice::from_ref(&x509_policy))
    {
        if trust.evaluate_with_error().is_ok() {
            return true;
        }
    }

    false
}

#[cfg(not(target_os = "macos"))]
const fn macos_keychain_trusts(
    _end_entity: &CertificateDer<'_>,
    _intermediates: &[CertificateDer<'_>],
) -> bool {
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        SanType,
    };
    use std::time::Duration;

    fn dn(cn: &str) -> DistinguishedName {
        let mut d = DistinguishedName::new();
        d.push(DnType::CommonName, cn);
        d
    }

    #[test]
    fn leaf_certificate_trusted_in_system_keychain_is_accepted_directly() {
        // A user marks the host's leaf certificate as trusted in macOS Keychain (`native.certs`),
        // without importing the issuing CA (or while an older RSA CA of the same name is in the
        // store). `RootCertStore` alone would ignore the leaf cert because its subject != issuer.
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name = dn("Bank Issuing CA");

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut leaf_params = CertificateParams::default();
        leaf_params.distinguished_name = dn("zos1.bank.example");
        leaf_params.subject_alt_names =
            vec![SanType::DnsName("zos1.bank.example".try_into().unwrap())];
        let leaf = leaf_params
            .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
            .unwrap();
        let leaf_der = CertificateDer::from(leaf.der().to_vec());

        // Also put an unrelated Ed25519 CA of the same issuer name in `roots` to verify it does
        // not shadow the directly trusted leaf certificate (without direct trust, `webpki` would
        // fail with `UnsupportedSignatureAlgorithmForPublicKeyContext`).
        let old_ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut old_ca_params = CertificateParams::default();
        old_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        old_ca_params.distinguished_name = dn("Bank Issuing CA");
        let old_ca = old_ca_params.self_signed(&old_ca_key).unwrap();

        let mut store = RootCertStore::empty();
        store
            .add(CertificateDer::from(old_ca.der().to_vec()))
            .unwrap();
        let mut trusted = HashSet::new();
        trusted.insert(sha256(&leaf_der));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = HostCertVerifier::with_trusted_certs(
            Arc::new(store),
            Arc::new(trusted),
            provider,
            None,
            None,
        );
        let name = ServerName::try_from("zos1.bank.example".to_owned()).unwrap();
        let now = UnixTime::now();

        assert!(verifier
            .verify_server_cert(&leaf_der, &[], &name, &[], now)
            .is_ok());

        // Name check still applies to a certificate trusted in Keychain.
        let wrong_name = ServerName::try_from("zos2.bank.example".to_owned()).unwrap();
        assert!(verifier
            .verify_server_cert(&leaf_der, &[], &wrong_name, &[], now)
            .is_err());
        assert_eq!(
            verifier.rejection().get().unwrap().problem,
            CertProblem::NameMismatch {
                expected: "zos2.bank.example".to_owned()
            }
        );
    }

    #[test]
    fn self_signed_ca_certificate_trusted_in_keychain_is_accepted_as_end_entity() {
        // `openssl req -x509` sets `BasicConstraints: CA:TRUE` by default; `webpki` rejects that
        // with `CaUsedAsEndEntity` unless direct certificate trust handles it.
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = dn("zos1.bank.example");
        let cert = params.self_signed(&key).unwrap();
        let der = CertificateDer::from(cert.der().to_vec());

        let mut store = RootCertStore::empty();
        store.add(der.clone()).unwrap();
        let mut trusted = HashSet::new();
        trusted.insert(sha256(&der));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = HostCertVerifier::with_trusted_certs(
            Arc::new(store),
            Arc::new(trusted),
            provider,
            None,
            None,
        );
        let name = ServerName::try_from("zos1.bank.example".to_owned()).unwrap();
        let now = UnixTime::now();

        assert!(verifier
            .verify_server_cert(&der, &[], &name, &[], now)
            .is_ok());

        // Validity period is still enforced on certificates in Keychain (`rcgen` defaults start
        // at 1975-01-01, so 1970-01-01 is before `not_before`).
        let before_valid = UnixTime::since_unix_epoch(Duration::ZERO);
        assert!(verifier
            .verify_server_cert(&der, &[], &name, &[], before_valid)
            .is_err());
        assert_eq!(
            verifier.rejection().get().unwrap().problem,
            CertProblem::NotYetValid
        );
    }
}
