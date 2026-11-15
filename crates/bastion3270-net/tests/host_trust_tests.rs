//! Trust in the host's certificate as banks deploy it: internal CAs, z/OS certificates with
//! a common name only, connections by IP address, intermediates the host does not send, and
//! certificates a desktop user pins.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair, SanType,
};
use rustls::version::{TLS12, TLS13};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use bastion3270_net::profile::{ConnectionProfile, ConnectionProfileBuilder, TlsMode};
use bastion3270_net::transport::{connect_tls_with_trust, CertProblem, HostTrust};
use bastion3270_net::NetError;

/// A certificate authority of the test (a bank's internal CA).
struct Ca {
    params: CertificateParams,
    key: KeyPair,
    pem: String,
}

impl Ca {
    fn new(name: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = dn(name);
        let pem = params.self_signed(&key).unwrap().pem();
        Self { params, key, pem }
    }

    /// An intermediate CA signed by this one.
    fn intermediate(&self, name: &str) -> (Self, CertificateDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = dn(name);
        let cert = params
            .signed_by(&key, &Issuer::from_params(&self.params, &self.key))
            .unwrap();
        let der = CertificateDer::from(cert.der().to_vec());
        let pem = cert.pem();
        (Self { params, key, pem }, der)
    }

    /// A host certificate with this common name and these alternative names.
    fn host_cert(&self, cn: &str, sans: Vec<SanType>) -> (CertificateDer<'static>, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = dn(cn);
        params.subject_alt_names = sans;
        let cert = params
            .signed_by(&key, &Issuer::from_params(&self.params, &self.key))
            .unwrap();
        (CertificateDer::from(cert.der().to_vec()), key)
    }
}

fn dn(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

fn dns(name: &str) -> SanType {
    SanType::DnsName(name.try_into().unwrap())
}

/// A file removed on drop.
struct TempFile(PathBuf);

impl TempFile {
    fn new(content: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("bastion3270_trust_{}_{n}.pem", std::process::id()));
        std::fs::write(&path, content).unwrap();
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A TLS host on localhost presenting `chain`; it answers `OK` to every connection.
async fn host(chain: Vec<CertificateDer<'static>>, key: &KeyPair) -> u16 {
    let key = PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&TLS13, &TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let _ = tls.write_all(b"OK").await;
                    let _ = tls.flush().await;
                }
            });
        }
    });
    port
}

fn profile(host: &str, port: u16) -> ConnectionProfileBuilder {
    ConnectionProfileBuilder::new()
        .host(host)
        .port(port)
        .tls_mode(TlsMode::Enabled)
}

async fn connect(profile: &ConnectionProfile, trust: &HostTrust) -> Result<(), NetError> {
    let mut stream = connect_tls_with_trust(profile, trust, Duration::from_secs(5)).await?;
    let mut answer = [0u8; 2];
    stream.read_exact(&mut answer).await.map_err(NetError::Io)?;
    assert_eq!(&answer, b"OK");
    Ok(())
}

fn refusal(error: NetError) -> bastion3270_net::transport::CertificateRejection {
    match error {
        NetError::UntrustedCertificate(rejection) => *rejection,
        other => panic!("expected a refused certificate, got {other:?}"),
    }
}

#[tokio::test]
async fn zos_certificate_with_a_common_name_only_is_accepted_from_a_trusted_ca() {
    // RACF `RACDCERT GENCERT` without ALTNAME: no subject alternative name at all. x3270
    // accepts the common name; rustls alone refuses it ("not valid for name").
    let ca = Ca::new("Bank Internal CA");
    let (cert, key) = ca.host_cert("localhost", vec![]);
    let port = host(vec![cert], &key).await;
    let ca_file = TempFile::new(&ca.pem);

    let ok = profile("localhost", port)
        .ca_cert(&ca_file.0)
        .build()
        .unwrap();
    connect(&ok, &HostTrust::system()).await.unwrap();

    let wrong = profile("127.0.0.1", port)
        .ca_cert(&ca_file.0)
        .build()
        .unwrap();
    let rejection = refusal(connect(&wrong, &HostTrust::system()).await.unwrap_err());
    assert_eq!(
        rejection.problem,
        CertProblem::NameMismatch {
            expected: "127.0.0.1".into()
        }
    );
}

#[tokio::test]
async fn a_common_name_never_makes_an_untrusted_certificate_acceptable() {
    let unknown = Ca::new("Some Other CA");
    let (cert, key) = unknown.host_cert("localhost", vec![]);
    let port = host(vec![cert], &key).await;

    let p = profile("localhost", port).build().unwrap();
    let rejection = refusal(connect(&p, &HostTrust::system()).await.unwrap_err());
    assert_eq!(rejection.problem, CertProblem::UnknownIssuer);
    assert_eq!(rejection.certificate.subject, "CN=localhost");
    assert_eq!(rejection.certificate.issuer, "CN=Some Other CA");
    let text = rejection.to_string();
    assert!(
        text.contains("not trusted") && text.contains("ca_cert"),
        "{text}"
    );
}

#[tokio::test]
async fn connecting_by_address_needs_accept_hostname() {
    let ca = Ca::new("Bank Internal CA");
    let (cert, key) = ca.host_cert("zos1", vec![dns("zos1.bank.example")]);
    let port = host(vec![cert], &key).await;
    let ca_file = TempFile::new(&ca.pem);

    let by_ip = profile("127.0.0.1", port)
        .ca_cert(&ca_file.0)
        .build()
        .unwrap();
    let rejection = refusal(connect(&by_ip, &HostTrust::system()).await.unwrap_err());
    assert_eq!(
        rejection.problem,
        CertProblem::NameMismatch {
            expected: "127.0.0.1".into()
        }
    );
    assert_eq!(rejection.certificate.names, ["DNS:zos1.bank.example"]);

    let accepted = profile("127.0.0.1", port)
        .ca_cert(&ca_file.0)
        .accept_hostname("zos1.bank.example")
        .build()
        .unwrap();
    connect(&accepted, &HostTrust::system()).await.unwrap();

    // The other name must be right too.
    let other = profile("127.0.0.1", port)
        .ca_cert(&ca_file.0)
        .accept_hostname("zos2.bank.example")
        .build()
        .unwrap();
    assert!(connect(&other, &HostTrust::system()).await.is_err());
}

#[tokio::test]
async fn application_ca_files_are_trusted_for_every_profile() {
    // The gateway's `[host_tls] ca_certs`: no profile names the CA, custom connections too.
    let ca = Ca::new("Bank Internal CA");
    let (cert, key) = ca.host_cert("localhost", vec![dns("localhost")]);
    let port = host(vec![cert], &key).await;
    let ca_file = TempFile::new(&ca.pem);
    let p = profile("localhost", port).build().unwrap();

    let rejection = refusal(connect(&p, &HostTrust::system()).await.unwrap_err());
    assert_eq!(rejection.problem, CertProblem::UnknownIssuer);

    let trust = HostTrust::with_ca_files(std::slice::from_ref(&ca_file.0)).unwrap();
    assert_eq!(trust.summary().configured, 1);
    connect(&p, &trust).await.unwrap();
}

#[tokio::test]
async fn a_profile_ca_cert_adds_to_the_trusted_cas() {
    // A profile naming one CA still reaches a host of another trusted CA.
    let gateway_ca = Ca::new("Gateway CA");
    let profile_ca = Ca::new("Profile CA");
    let (cert, key) = gateway_ca.host_cert("localhost", vec![dns("localhost")]);
    let port = host(vec![cert], &key).await;
    let gateway_file = TempFile::new(&gateway_ca.pem);
    let profile_file = TempFile::new(&profile_ca.pem);

    let trust = HostTrust::with_ca_files(std::slice::from_ref(&gateway_file.0)).unwrap();
    let p = profile("localhost", port)
        .ca_cert(&profile_file.0)
        .build()
        .unwrap();
    connect(&p, &trust).await.unwrap();
}

#[tokio::test]
async fn an_intermediate_the_host_does_not_send_can_be_trusted_directly() {
    let root = Ca::new("Bank Root CA");
    let (intermediate, _) = root.intermediate("Bank Issuing CA");
    let (cert, key) = intermediate.host_cert("localhost", vec![dns("localhost")]);
    // The host sends its certificate only.
    let port = host(vec![cert], &key).await;

    let root_file = TempFile::new(&root.pem);
    let p = profile("localhost", port)
        .ca_cert(&root_file.0)
        .build()
        .unwrap();
    let rejection = refusal(connect(&p, &HostTrust::system()).await.unwrap_err());
    assert_eq!(rejection.problem, CertProblem::UnknownIssuer);

    let intermediate_file = TempFile::new(&intermediate.pem);
    let p = profile("localhost", port)
        .ca_cert(&intermediate_file.0)
        .build()
        .unwrap();
    connect(&p, &HostTrust::system()).await.unwrap();
}

#[tokio::test]
async fn a_pinned_certificate_is_trusted_and_only_that_one() {
    // The desktop flow: refused, the user checks the fingerprint and trusts it.
    let self_signed = Ca::new("zos1.bank.example");
    let (cert, key) = self_signed.host_cert("zos1", vec![]);
    let port = host(vec![cert], &key).await;

    let p = profile("127.0.0.1", port).build().unwrap();
    let rejection = refusal(connect(&p, &HostTrust::system()).await.unwrap_err());
    let fingerprint = rejection.certificate.sha256_hex();

    let pinned = profile("127.0.0.1", port)
        .pinned_cert_sha256(&fingerprint)
        .build()
        .unwrap();
    connect(&pinned, &HostTrust::system()).await.unwrap();

    let other = profile("127.0.0.1", port)
        .pinned_cert_sha256("00".repeat(32))
        .build()
        .unwrap();
    let rejection = refusal(connect(&other, &HostTrust::system()).await.unwrap_err());
    assert_eq!(rejection.certificate.sha256_hex(), fingerprint);
}

#[test]
fn certificate_settings_need_tls_and_valid_values() {
    let plain = || ConnectionProfileBuilder::new().host("h").port(23);
    assert!(plain().accept_hostname("zos1").build().is_err());
    assert!(plain().pinned_cert_sha256("ab".repeat(32)).build().is_err());

    let tls = || profile("h", 992);
    assert!(tls().accept_hostname("zos1.bank.example").build().is_ok());
    assert!(tls().accept_hostname("10.1.2.3").build().is_ok());
    assert!(tls().accept_hostname("not a name").build().is_err());
    assert!(tls().pinned_cert_sha256("AB".repeat(32)).build().is_ok());
    assert!(tls().pinned_cert_sha256("ab".repeat(31)).build().is_err());
    assert!(tls().pinned_cert_sha256("xy".repeat(32)).build().is_err());
}
