//! In-process hermetic PKI fixture for zero-dependency TLS loopback testing.
//!
//! Generates ephemeral self-signed Root CA and server certificates in memory using [`rcgen`]
//! without requiring OpenSSL CLI or external network connectivity.

#![allow(dead_code)]

use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

/// In-memory PKI fixture containing CA and server certificates.
#[derive(Debug, Clone)]
pub(crate) struct TestPki {
    /// CA certificate in PEM encoding.
    pub(crate) ca_cert_pem: String,
    /// CA certificate in binary DER encoding.
    pub(crate) ca_cert_der: Vec<u8>,
    /// Server certificate in PEM encoding.
    pub(crate) server_cert_pem: String,
    /// Server certificate in binary DER encoding.
    pub(crate) server_cert_der: Vec<u8>,
    /// Server private key in PEM encoding.
    pub(crate) server_key_pem: String,
    /// Server private key in binary DER (PKCS#8) encoding.
    pub(crate) server_key_der: Vec<u8>,
}

impl TestPki {
    /// Generates a new self-signed Root CA and a server certificate signed by that CA.
    ///
    /// # Arguments
    /// - `san_names`: List of Subject Alternative Names (e.g. `&["localhost", "127.0.0.1"]`).
    pub(crate) fn new(
        san_names: &[&str],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // 1. Generate Root CA
        let ca_key = KeyPair::generate()?;
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, "Bastion3270 Hermetic Test CA");
        ca_params.distinguished_name = ca_dn;

        let ca_cert = ca_params.self_signed(&ca_key)?;
        let ca_cert_pem = ca_cert.pem();
        let ca_cert_der = ca_cert.der().to_vec();

        // 2. Generate Server Certificate signed by CA
        let srv_key = KeyPair::generate()?;
        let sans: Vec<String> = san_names.iter().map(|s| (*s).to_string()).collect();
        let mut srv_params = CertificateParams::new(sans)?;
        srv_params.is_ca = IsCa::NoCa;
        let mut srv_dn = DistinguishedName::new();
        srv_dn.push(DnType::CommonName, "Bastion3270 Mock Mainframe Server");
        srv_params.distinguished_name = srv_dn;

        let srv_cert =
            srv_params.signed_by(&srv_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))?;
        let server_cert_pem = srv_cert.pem();
        let server_cert_der = srv_cert.der().to_vec();
        let server_key_pem = srv_key.serialize_pem();
        let server_key_der = srv_key.serialize_der();

        Ok(Self {
            ca_cert_pem,
            ca_cert_der,
            server_cert_pem,
            server_cert_der,
            server_key_pem,
            server_key_der,
        })
    }

    /// Builds a [`RootCertStore`] trusting only this fixture's CA certificate.
    pub(crate) fn root_cert_store(&self) -> Result<RootCertStore, rustls::Error> {
        let mut store = RootCertStore::empty();
        let cert_der = CertificateDer::from(self.ca_cert_der.clone());
        store.add(cert_der)?;
        Ok(store)
    }

    /// Constructs a client [`ClientConfig`] configured with `ring` provider and trusting this CA.
    pub(crate) fn client_config(&self) -> Result<Arc<ClientConfig>, rustls::Error> {
        let root_store = self.root_cert_store()?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13, &TLS12])?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// Constructs a server [`ServerConfig`] configured with `ring` provider and presenting this server cert/key.
    pub(crate) fn server_config(
        &self,
    ) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
        let cert_der = CertificateDer::from(self.server_cert_der.clone());
        let key_der = PrivateKeyDer::try_from(self.server_key_der.clone())
            .map_err(|e| format!("invalid server private key: {e}"))?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13, &TLS12])?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?;

        Ok(Arc::new(config))
    }
}
