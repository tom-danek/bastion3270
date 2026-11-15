//! Adversarial stress tests for TLS transport, CA certificate loader, and SNI parsing.
//!
//! Validates resilience against corrupt/truncated PEM & DER certificates, missing/permission-denied
//! paths, invalid SNI strings, untrusted CAs, hostname mismatches, intermediate chain validation,
//! and connection/handshake timeouts.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use rustls::version::{TLS12, TLS13};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use bastion3270_net::profile::{ConnectionProfileBuilder, TlsMode};
use bastion3270_net::transport::tls::{
    connect_tls, connect_tls_handshake, create_tls_client_config, load_ca_cert_store,
    load_default_root_store, parse_server_name,
};
use bastion3270_net::transport::{connect, connect_with_idle_timeout, CertProblem};
use bastion3270_net::NetError;

mod common;
use common::test_pki::TestPki;

// Helper to create a unique temporary file path with automatic cleanup guard
struct TempFileGuard {
    path: PathBuf,
}

impl TempFileGuard {
    fn new(prefix: &str, content: &[u8]) -> Self {
        let unique = format!(
            "{prefix}_{}_{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::write(&path, content).expect("failed to write temp file");
        Self { path }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // Restore write/read permissions so deletion succeeds even if permissions were set to 000
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// 1. PEM Certificate Loader Boundary Tests
// ---------------------------------------------------------------------------

#[test]
fn test_pem_truncated_header_only() {
    let guard = TempFileGuard::new("pem_trunc_hdr", b"-----BEGIN CERTIFICATE-----\n");
    let err = load_ca_cert_store(guard.path()).expect_err("Truncated header only must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_pem_truncated_mid_payload() {
    let guard = TempFileGuard::new(
        "pem_trunc_mid",
        b"-----BEGIN CERTIFICATE-----\nMIICXzCCAgWgAwIBAgII\n",
    );
    let err = load_ca_cert_store(guard.path()).expect_err("Truncated body must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_pem_truncated_footer() {
    let guard = TempFileGuard::new(
        "pem_trunc_footer",
        b"-----BEGIN CERTIFICATE-----\nMIICXzCCAgWgAwIBAgII\n-----END CERTI",
    );
    let err = load_ca_cert_store(guard.path()).expect_err("Truncated footer must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_pem_mismatched_boundary_markers() {
    let guard = TempFileGuard::new(
        "pem_mismatched",
        b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END RSA PRIVATE KEY-----",
    );
    let err = load_ca_cert_store(guard.path()).expect_err("Mismatched headers must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_pem_corrupted_base64_payload() {
    let guard = TempFileGuard::new(
        "pem_corrupt_b64",
        b"-----BEGIN CERTIFICATE-----\n###@@@!!!$$$%%%\n-----END CERTIFICATE-----",
    );
    let err = load_ca_cert_store(guard.path()).expect_err("Corrupt base64 must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_pem_valid_cert_followed_by_corrupted_trailer() {
    let pki = TestPki::new(&["localhost"]).expect("PKI init");
    let mut combined = pki.ca_cert_pem.into_bytes();
    combined.extend_from_slice(
        b"\n-----BEGIN CERTIFICATE-----\nCORRUPT_PAYLOAD\n-----END CERTIFICATE-----\n",
    );

    let guard = TempFileGuard::new("pem_valid_plus_corrupt", &combined);
    let err = load_ca_cert_store(guard.path()).expect_err("Corrupted second cert in PEM must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_pem_non_certificate_pem_type_rejected() {
    let private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIP...dummy...\n-----END PRIVATE KEY-----";
    let guard = TempFileGuard::new("pem_non_cert", private_key_pem);
    let err = load_ca_cert_store(guard.path()).expect_err("Non-certificate PEM must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_pem_multi_cert_bundle_loaded() {
    let pki1 = TestPki::new(&["host1.local"]).expect("PKI 1 init");
    let pki2 = TestPki::new(&["host2.local"]).expect("PKI 2 init");

    let mut bundle = pki1.ca_cert_pem;
    bundle.push('\n');
    bundle.push_str(&pki2.ca_cert_pem);

    let guard = TempFileGuard::new("pem_multi_bundle", bundle.as_bytes());
    let store = load_ca_cert_store(guard.path()).expect("Valid multi-cert bundle must succeed");
    assert_eq!(
        store.len(),
        2,
        "RootCertStore must contain both CA certificates"
    );
}

#[test]
fn test_pem_duplicate_certificate_handling() {
    let pki = TestPki::new(&["duplicate.local"]).expect("PKI init");
    let mut bundle = pki.ca_cert_pem.clone();
    bundle.push('\n');
    bundle.push_str(&pki.ca_cert_pem);

    let guard = TempFileGuard::new("pem_duplicate", bundle.as_bytes());
    // Real-world CA bundles often contain duplicates; Rustls RootCertStore accepts both entries
    let store = load_ca_cert_store(guard.path())
        .expect("Duplicate CA certs in bundle should be handled gracefully");
    assert_eq!(store.len(), 2, "Store holds both parsed entries");
}

#[test]
fn test_pem_with_comments_and_surrounding_whitespace() {
    let pki = TestPki::new(&["localhost"]).expect("PKI init");
    let mut padded =
        String::from("# Corporate CA Certificate\n# Issued for internal test\n\n   \n");
    padded.push_str(&pki.ca_cert_pem);
    padded.push_str("\n\n   # End of CA file\n");

    let guard = TempFileGuard::new("pem_padded", padded.as_bytes());
    let store =
        load_ca_cert_store(guard.path()).expect("PEM with comments and padding must succeed");
    assert_eq!(store.len(), 1);
}

// ---------------------------------------------------------------------------
// 2. Binary DER Certificate Loader Boundary Tests
// ---------------------------------------------------------------------------

#[test]
fn test_der_single_byte_truncated() {
    let guard = TempFileGuard::new("der_single_byte", &[0x30]);
    let err = load_ca_cert_store(guard.path()).expect_err("Single byte DER must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_der_two_bytes_truncated() {
    let guard = TempFileGuard::new("der_two_bytes", &[0x30, 0x82]);
    let err = load_ca_cert_store(guard.path()).expect_err("Two bytes DER must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_der_truncated_valid_payload() {
    let pki = TestPki::new(&["localhost"]).expect("PKI init");
    assert!(pki.ca_cert_der.len() > 20);
    let half_len = pki.ca_cert_der.len() / 2;
    let truncated = &pki.ca_cert_der[..half_len];

    let guard = TempFileGuard::new("der_truncated", truncated);
    let err = load_ca_cert_store(guard.path()).expect_err("Truncated DER must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_der_corrupted_length_field() {
    let pki = TestPki::new(&["localhost"]).expect("PKI init");
    let mut corrupted = pki.ca_cert_der.clone();
    if corrupted.len() > 3 {
        corrupted[1] = 0x82;
        corrupted[2] = 0xFF;
        corrupted[3] = 0xFF;
    }

    let guard = TempFileGuard::new("der_corrupt_len", &corrupted);
    let err = load_ca_cert_store(guard.path()).expect_err("Corrupted DER length must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_der_arbitrary_random_garbage() {
    let garbage: Vec<u8> = (0u8..128u8).map(|i| i.wrapping_mul(37)).collect();
    let guard = TempFileGuard::new("der_garbage", &garbage);
    let err = load_ca_cert_store(guard.path()).expect_err("Garbage DER must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_der_private_key_rejected_as_ca_cert() {
    let pki = TestPki::new(&["localhost"]).expect("PKI init");
    let guard = TempFileGuard::new("der_key_not_cert", &pki.server_key_der);
    let err =
        load_ca_cert_store(guard.path()).expect_err("Private key DER must not parse as CA cert");
    assert!(err.is_invalid_certificate());
}

// ---------------------------------------------------------------------------
// 3. File System & Path Boundary Conditions
// ---------------------------------------------------------------------------

#[test]
fn test_path_empty_file_rejected() {
    let guard = TempFileGuard::new("empty_file", b"");
    let err = load_ca_cert_store(guard.path()).expect_err("Empty file must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_path_nonexistent_file_rejected() {
    let non_existent = std::path::Path::new("/non/existent/corporate/ca_never_exists.pem");
    let err = load_ca_cert_store(non_existent).expect_err("Non-existent file must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_path_directory_instead_of_file() {
    let temp_dir = std::env::temp_dir();
    let err = load_ca_cert_store(&temp_dir).expect_err("Directory path must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_path_broken_symlink() {
    let target =
        std::env::temp_dir().join(format!("non_existent_target_{}.tmp", std::process::id()));
    let symlink = std::env::temp_dir().join(format!("broken_symlink_{}.tmp", std::process::id()));

    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink(&target, &symlink);
        let err = load_ca_cert_store(&symlink).expect_err("Broken symlink must fail");
        let _ = std::fs::remove_file(&symlink);
        assert!(err.is_invalid_certificate());
    }
}

#[cfg(unix)]
#[test]
fn test_path_permission_denied() {
    let guard = TempFileGuard::new("pem_perm_denied", b"some certificate data");
    // Revoke all read/write permissions
    std::fs::set_permissions(guard.path(), std::fs::Permissions::from_mode(0o000))
        .expect("chmod 000 failed");

    let err = load_ca_cert_store(guard.path()).expect_err("Permission denied must fail");
    assert!(err.is_invalid_certificate());
}

// ---------------------------------------------------------------------------
// 4. SNI and Server Name Parsing Boundary Conditions
// ---------------------------------------------------------------------------

#[test]
fn test_sni_empty_string_rejected() {
    let err = parse_server_name("").expect_err("Empty SNI string must fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_sni_whitespace_variations() {
    let cases = [
        " localhost",
        "localhost ",
        "  127.0.0.1",
        "127.0.0.1  ",
        "mainframe .ibm.com",
        "mainframe. ibm.com",
        "mainframe.ibm .com",
    ];
    for &case in &cases {
        let err = parse_server_name(case).expect_err(&format!("Whitespace in '{case}' must fail"));
        assert!(err.is_invalid_certificate());
    }
}

#[test]
fn test_sni_host_with_port_rejected() {
    let cases = [
        "localhost:3270",
        "127.0.0.1:23",
        "[::1]:992",
        "mainframe.ibm.com:443",
    ];
    for &case in &cases {
        let err = parse_server_name(case).expect_err(&format!("Host with port '{case}' must fail"));
        assert!(err.is_invalid_certificate());
    }
}

#[test]
fn test_sni_invalid_ip_formats() {
    let cases = [
        "256.1.1.1",
        "127.0.0.1.1",
        "127.0.0",
        "127.0.0.999",
        "::gggg",
        "::1:1:1:1:1:1:1:1",
        "127.0.0.1/24",
    ];
    for &case in &cases {
        let err = parse_server_name(case).expect_err(&format!("Invalid IP '{case}' must fail"));
        assert!(err.is_invalid_certificate());
    }
}

#[test]
fn test_sni_hostname_length_boundaries() {
    // Single label > 63 characters
    let long_label = format!("{}.com", "a".repeat(64));
    let err1 = parse_server_name(&long_label).expect_err("Label > 63 chars must fail");
    assert!(err1.is_invalid_certificate());

    // Hostname > 253 characters total (4 labels of 63 chars + dots = 255 chars)
    let label = "a".repeat(63);
    let long_host = format!("{label}.{label}.{label}.{label}");
    assert!(long_host.len() > 253);
    let err2 = parse_server_name(&long_host).expect_err("Hostname > 253 chars must fail");
    assert!(err2.is_invalid_certificate());

    // Valid 63-char label + short domain (total <= 253)
    let valid_long_label = format!("{}.ibm.com", "a".repeat(63));
    let parsed = parse_server_name(&valid_long_label).expect("Label of 63 chars must succeed");
    assert!(matches!(parsed, ServerName::DnsName(_)));
}

#[test]
fn test_sni_invalid_characters_and_control_bytes() {
    let cases = [
        "mainframe\0.ibm.com",
        "mainframe\n.ibm.com",
        "mainframe\r.ibm.com",
        "mainframe\t.ibm.com",
        "mainframe@ibm.com",
        "mainframe!ibm.com",
        "mainframe#ibm.com",
        "mainframe$ibm.com",
    ];
    for &case in &cases {
        let err =
            parse_server_name(case).expect_err(&format!("Invalid char in '{case}' must fail"));
        assert!(err.is_invalid_certificate());
    }
}

#[test]
fn test_sni_non_ascii_unicode_rejected() {
    // Non-ASCII internationalized domain names (IDN) without Punycode encoding must be rejected
    let cases = ["münchen.de", "příliš.cz", "сервер.рф"];
    for &case in &cases {
        let err = parse_server_name(case).expect_err(&format!("Non-ASCII '{case}' must fail"));
        assert!(err.is_invalid_certificate());
    }
}

#[test]
fn test_sni_valid_variations() {
    // Valid standard DNS
    let dns = parse_server_name("mainframe.ibm.com").expect("DNS");
    assert!(matches!(dns, ServerName::DnsName(_)));

    // Valid IPv4
    let ip4 = parse_server_name("192.168.1.100").expect("IPv4");
    assert!(matches!(ip4, ServerName::IpAddress(_)));

    // Valid IPv6
    let ip6 = parse_server_name("2001:db8::1").expect("IPv6");
    assert!(matches!(ip6, ServerName::IpAddress(_)));

    // Valid case-insensitivity in domain
    let mixed = parse_server_name("MainFrame.IBM.Com").expect("Mixed case DNS");
    assert!(matches!(mixed, ServerName::DnsName(_)));
}

// ---------------------------------------------------------------------------
// 5. TLS Handshake, Untrusted CAs, SAN Mismatches & Intermediate Chains
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tls_handshake_rejects_san_hostname_mismatch() {
    let pki = TestPki::new(&["otherhost.internal"]).expect("PKI init");
    let server_config = pki.server_config().expect("server config");
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = acceptor.accept(tcp).await;
        }
    });

    let guard = TempFileGuard::new("ca_san_mismatch", pki.ca_cert_pem.as_bytes());

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .ca_cert(guard.path())
        .connect_timeout_ms(3_000)
        .build()
        .expect("profile build");

    let err = connect_tls(&profile, Duration::from_secs(3))
        .await
        .expect_err("Handshake with SAN mismatch must fail");

    // A refused certificate is reported with its reason and details.
    assert!(
        matches!(&err, NetError::UntrustedCertificate(r) if matches!(r.problem, CertProblem::NameMismatch { .. })),
        "Expected a refused certificate: got {err:?}"
    );
}

#[tokio::test]
async fn test_tls_rejects_self_signed_cert_not_in_trust_store() {
    let srv_key = KeyPair::generate().expect("key generation");
    let mut srv_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("params");
    srv_params.is_ca = IsCa::NoCa;
    let mut srv_dn = DistinguishedName::new();
    srv_dn.push(DnType::CommonName, "Standalone Self-Signed");
    srv_params.distinguished_name = srv_dn;

    let cert = srv_params.self_signed(&srv_key).expect("self-signed cert");
    let cert_der = cert.der().to_vec();
    let key_der = srv_key.serialize_der();

    let cert_pki = CertificateDer::from(cert_der);
    let key_pki = PrivateKeyDer::try_from(key_der).expect("key der");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13, &TLS12])
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_pki], key_pki)
        .expect("single cert");

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = acceptor.accept(tcp).await;
        }
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .connect_timeout_ms(3_000)
        .build()
        .expect("profile build");

    let err = connect_tls(&profile, Duration::from_secs(3))
        .await
        .expect_err("Self-signed untrusted cert must fail");

    // A refused certificate is reported with its reason and details.
    assert!(
        matches!(&err, NetError::UntrustedCertificate(r) if r.problem == CertProblem::UnknownIssuer),
        "Expected a refused certificate: got {err:?}"
    );
}

#[tokio::test]
async fn test_tls_intermediate_ca_chain_validation() {
    // Generate Root CA -> Intermediate CA -> Server Cert
    let root_key = KeyPair::generate().expect("root key");
    let mut root_params = CertificateParams::default();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut root_dn = DistinguishedName::new();
    root_dn.push(DnType::CommonName, "Bastion3270 Root CA");
    root_params.distinguished_name = root_dn;
    let root_cert = root_params.self_signed(&root_key).expect("root cert");

    let inter_key = KeyPair::generate().expect("inter key");
    let mut inter_params = CertificateParams::default();
    inter_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut inter_dn = DistinguishedName::new();
    inter_dn.push(DnType::CommonName, "Bastion3270 Intermediate CA");
    inter_params.distinguished_name = inter_dn;
    let inter_cert = inter_params
        .signed_by(
            &inter_key,
            &rcgen::Issuer::from_params(&root_params, &root_key),
        )
        .expect("inter cert");

    let srv_key = KeyPair::generate().expect("srv key");
    let mut srv_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("srv params");
    srv_params.is_ca = IsCa::NoCa;
    let mut srv_dn = DistinguishedName::new();
    srv_dn.push(DnType::CommonName, "Bastion3270 Server");
    srv_params.distinguished_name = srv_dn;
    let srv_cert = srv_params
        .signed_by(
            &srv_key,
            &rcgen::Issuer::from_params(&inter_params, &inter_key),
        )
        .expect("srv cert");

    // Server presents full chain: [ServerCert, IntermediateCert]
    let chain = vec![
        CertificateDer::from(srv_cert.der().to_vec()),
        CertificateDer::from(inter_cert.der().to_vec()),
    ];
    let key_der = PrivateKeyDer::try_from(srv_key.serialize_der()).expect("key");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13, &TLS12])
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(chain, key_der)
        .expect("single cert");

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut buf = [0u8; 4];
                let _ = tls.read_exact(&mut buf).await;
                let _ = tls.write_all(b"CHAIN_OK").await;
                let _ = tls.flush().await;
            }
        }
    });

    let guard = TempFileGuard::new("root_ca_only", root_cert.pem().as_bytes());

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .ca_cert(guard.path())
        .connect_timeout_ms(3_000)
        .build()
        .expect("profile build");

    let mut stream = connect_tls(&profile, Duration::from_secs(3))
        .await
        .expect("Handshake with full intermediate chain must succeed");

    stream.write_all(b"TEST").await.expect("write");
    stream.flush().await.expect("flush");
    let mut resp = [0u8; 8];
    stream.read_exact(&mut resp).await.expect("read");
    assert_eq!(&resp, b"CHAIN_OK");
}

#[tokio::test]
async fn test_tls_intermediate_ca_missing_from_server_fails() {
    let root_key = KeyPair::generate().expect("root key");
    let mut root_params = CertificateParams::default();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut root_dn = DistinguishedName::new();
    root_dn.push(DnType::CommonName, "Root CA");
    root_params.distinguished_name = root_dn;
    let root_cert = root_params.self_signed(&root_key).expect("root cert");

    let inter_key = KeyPair::generate().expect("inter key");
    let mut inter_params = CertificateParams::default();
    inter_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut inter_dn = DistinguishedName::new();
    inter_dn.push(DnType::CommonName, "Intermediate CA");
    inter_params.distinguished_name = inter_dn;
    // Issued, but deliberately not sent by the server (the chain is incomplete).
    let _inter_cert = inter_params
        .signed_by(
            &inter_key,
            &rcgen::Issuer::from_params(&root_params, &root_key),
        )
        .expect("inter cert");

    let srv_key = KeyPair::generate().expect("srv key");
    let mut srv_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("srv params");
    srv_params.is_ca = IsCa::NoCa;
    let mut srv_dn = DistinguishedName::new();
    srv_dn.push(DnType::CommonName, "Server");
    srv_params.distinguished_name = srv_dn;
    let srv_cert = srv_params
        .signed_by(
            &srv_key,
            &rcgen::Issuer::from_params(&inter_params, &inter_key),
        )
        .expect("srv cert");

    // Server sends ONLY [ServerCert], omitting IntermediateCert
    let incomplete_chain = vec![CertificateDer::from(srv_cert.der().to_vec())];
    let key_der = PrivateKeyDer::try_from(srv_key.serialize_der()).expect("key");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13, &TLS12])
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(incomplete_chain, key_der)
        .expect("single cert");

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = acceptor.accept(tcp).await;
        }
    });

    let guard = TempFileGuard::new("root_only", root_cert.pem().as_bytes());

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .ca_cert(guard.path())
        .connect_timeout_ms(3_000)
        .build()
        .expect("profile build");

    let err = connect_tls(&profile, Duration::from_secs(3))
        .await
        .expect_err("Omitted intermediate certificate must cause handshake failure");

    // A refused certificate is reported with its reason and details.
    assert!(
        matches!(&err, NetError::UntrustedCertificate(r) if r.problem == CertProblem::UnknownIssuer),
        "Expected a refused certificate: got {err:?}"
    );
}

#[tokio::test]
async fn test_tls_client_connecting_to_plain_tcp_server_fails() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((mut tcp, _)) = listener.accept().await {
            let mut buf = [0u8; 128];
            let _ = tcp.read(&mut buf).await;
            let _ = tcp.write_all(b"NOT_TLS_DATA").await;
            let _ = tcp.flush().await;
        }
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .connect_timeout_ms(3_000)
        .build()
        .expect("profile build");

    let err = connect_tls(&profile, Duration::from_secs(3))
        .await
        .expect_err("TLS handshake against plain TCP server must fail");

    assert!(
        err.is_tls() || err.is_io(),
        "Expected TLS/IO error: got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 6. Timeouts, Idle Tracking and TransportStream Operations over TLS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_connect_tls_zero_timeout_rejected_immediately() {
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(992)
        .tls_mode(TlsMode::Enabled)
        .connect_timeout_ms(1_000)
        .build()
        .expect("profile build");

    let err = connect_tls(&profile, Duration::ZERO)
        .await
        .expect_err("Zero timeout passed to connect_tls must fail immediately");

    assert!(err.is_connect_timeout());
}

/// Regression: a timeout too large to represent as an `Instant` must bound nothing, not
/// panic. `connect_tls` computed `Instant::now() + timeout`, which overflowed.
#[tokio::test]
async fn test_connect_tls_unrepresentably_large_timeout_does_not_panic() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((mut tcp, _)) = listener.accept().await {
            let _ = tcp.write_all(b"NOT_TLS_DATA").await;
            let _ = tcp.flush().await;
        }
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .connect_timeout_ms(3_000)
        .build()
        .expect("profile build");

    let err = connect_tls(&profile, Duration::MAX)
        .await
        .expect_err("TLS handshake against plain TCP server must fail");

    assert!(
        err.is_tls() || err.is_io(),
        "Expected TLS/IO error: got {err:?}"
    );
}

#[tokio::test]
async fn test_connect_tls_handshake_zero_timeout_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let client_stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = parse_server_name("127.0.0.1").expect("server name");
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .build()
        .expect("profile build");
    let config = create_tls_client_config(&profile).expect("config");

    let err = connect_tls_handshake(client_stream, server_name, config, Duration::ZERO)
        .await
        .expect_err("Zero handshake timeout must fail");

    assert!(err.is_connect_timeout());
}

#[tokio::test]
async fn test_connect_tls_handshake_aborts_on_closed_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            drop(tcp);
        }
    });

    let client_stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = parse_server_name("127.0.0.1").expect("server name");
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .build()
        .expect("profile build");
    let config = create_tls_client_config(&profile).expect("config");

    let err = connect_tls_handshake(client_stream, server_name, config, Duration::from_secs(3))
        .await
        .expect_err("Handshake on immediately closed peer must fail");

    assert!(
        err.is_io() || err.is_tls(),
        "Expected IO/TLS error on closed peer: got {err:?}"
    );
}

#[tokio::test]
async fn test_connect_unified_fails_early_on_invalid_ca_path() {
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(992)
        .tls_mode(TlsMode::Enabled)
        .ca_cert("/nonexistent/corporate/ca.pem")
        .build()
        .expect("profile build");

    let err = connect(&profile)
        .await
        .expect_err("Connect with missing CA path must fail");
    assert!(err.is_invalid_certificate());
}

#[tokio::test]
async fn test_connect_unified_fails_early_on_invalid_sni_hostname() {
    let profile = ConnectionProfileBuilder::new()
        .host("invalid host with spaces")
        .port(992)
        .tls_mode(TlsMode::Enabled)
        .build()
        .expect("profile build");

    let err = connect(&profile)
        .await
        .expect_err("Connect with invalid host must fail");
    assert!(err.is_invalid_certificate());
}

#[tokio::test]
async fn test_tls_transport_stream_socket_options_and_splitting() {
    let pki = TestPki::new(&["127.0.0.1"]).expect("PKI");
    let server_config = pki.server_config().expect("server config");
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut buf = [0u8; 4];
                let _ = tls.read_exact(&mut buf).await;
                let _ = tls.write_all(b"PONG").await;
                let _ = tls.flush().await;
            }
        }
    });

    let guard = TempFileGuard::new("ca_opt_split", pki.ca_cert_pem.as_bytes());

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .ca_cert(guard.path())
        .connect_timeout_ms(3_000)
        .build()
        .expect("profile build");

    let mut stream = connect(&profile).await.expect("connect");

    // Diagnostic & Socket accessors
    assert_eq!(stream.peer_addr().expect("peer_addr"), addr);
    assert!(stream.local_addr().is_ok());
    assert!(stream.set_nodelay(true).is_ok());
    assert!(stream.nodelay().unwrap_or(false));
    assert!(stream.set_ttl(64).is_ok());
    assert!(stream.ttl().is_ok());

    // Stream borrowing split
    {
        let (mut reader, mut writer) = stream.split();
        writer.write_all(b"PING").await.expect("write");
        writer.flush().await.expect("flush");

        let mut resp = [0u8; 4];
        reader.read_exact(&mut resp).await.expect("read");
        assert_eq!(&resp, b"PONG");
    }

    // Stream owned split
    let (mut owned_reader, mut owned_writer) = stream.into_split();
    // Dropping or writing works without issues
    let _ = owned_writer.shutdown().await;
    let mut eof_buf = [0u8; 1];
    let n = owned_reader.read(&mut eof_buf).await.unwrap_or(0);
    assert_eq!(n, 0, "EOF reached after peer shutdown");
}

#[tokio::test]
async fn test_tls_connect_with_idle_timeout_tracks_activity() {
    let pki = TestPki::new(&["127.0.0.1"]).expect("PKI");
    let server_config = pki.server_config().expect("server config");
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut buf = [0u8; 4];
                let _ = tls.read_exact(&mut buf).await;
                let _ = tls.write_all(b"DATA").await;
                let _ = tls.flush().await;
            }
        }
    });

    let guard = TempFileGuard::new("ca_idle", pki.ca_cert_pem.as_bytes());

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .ca_cert(guard.path())
        .idle_timeout_ms(100)
        .connect_timeout_ms(3_000)
        .build()
        .expect("profile build");

    let mut stream = connect_with_idle_timeout(&profile)
        .await
        .expect("connect with idle timeout");

    assert!(!stream.detector().is_idle());
    assert_eq!(stream.timeout(), Duration::from_millis(100));

    stream.write_all(b"PING").await.expect("write");
    stream.flush().await.expect("flush");

    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, b"DATA");

    // Sleep past the idle timeout threshold
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        stream.detector().is_idle(),
        "Stream must detect idle condition"
    );
    assert!(stream.detector().check().is_err());
}

#[test]
fn test_default_root_store_contains_sufficient_anchors() {
    let store = load_default_root_store();
    assert!(
        store.len() > 100,
        "Default Mozilla webpki store should have >100 root anchors, got {}",
        store.len()
    );
}

/// A TLS server that requires a client certificate signed by `client_ca` (AT-TLS with client
/// authentication); answers `MTLS_OK` and reports whether the client presented a certificate.
async fn spawn_mtls_server(
    client_ca: CertificateDer<'static>,
) -> (
    u16,
    rcgen::Certificate,
    tokio::sync::oneshot::Receiver<bool>,
) {
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("ca");
    let srv_key = KeyPair::generate().expect("srv key");
    let srv = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("params")
        .signed_by(&srv_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
        .expect("srv cert");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(client_ca).expect("client ca");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    .build()
    .expect("verifier");
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13, &TLS12])
        .expect("versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(srv.der().to_vec())],
            PrivateKeyDer::try_from(srv_key.serialize_der()).expect("key"),
        )
        .expect("cert");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    let presented = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .is_some_and(|c| !c.is_empty());
                    let _ = tx.send(presented);
                    let _ = tls.write_all(b"MTLS_OK").await;
                    let _ = tls.flush().await;
                }
                Err(_) => {
                    let _ = tx.send(false);
                }
            }
        }
    });
    (port, ca, rx)
}

/// Mutual TLS towards the host: with `client_cert` / `client_key` the gateway presents its
/// certificate and a host that requires client authentication accepts the connection; without
/// them the same host refuses it.
#[tokio::test]
async fn test_tls_client_certificate_is_presented_to_the_host() {
    let cli_ca_key = KeyPair::generate().expect("client ca key");
    let mut cli_ca_params = CertificateParams::default();
    cli_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cli_ca = cli_ca_params.self_signed(&cli_ca_key).expect("client ca");
    let cli_key = KeyPair::generate().expect("client key");
    let cli = CertificateParams::new(vec!["gateway".to_string()])
        .expect("params")
        .signed_by(
            &cli_key,
            &rcgen::Issuer::from_params(&cli_ca_params, &cli_ca_key),
        )
        .expect("client cert");
    let cert_file = TempFileGuard::new("mtls_client_cert", cli.pem().as_bytes());
    let key_file = TempFileGuard::new("mtls_client_key", cli_key.serialize_pem().as_bytes());

    // With the client certificate.
    let (port, srv_ca, presented) =
        spawn_mtls_server(CertificateDer::from(cli_ca.der().to_vec())).await;
    let ca_file = TempFileGuard::new("mtls_server_ca", srv_ca.pem().as_bytes());
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Enabled)
        .ca_cert(ca_file.path())
        .client_cert(cert_file.path())
        .client_key(key_file.path())
        .build()
        .expect("profile");
    let mut stream = connect_tls(&profile, Duration::from_secs(3))
        .await
        .expect("the host accepts the client certificate");
    let mut resp = [0u8; 7];
    stream.read_exact(&mut resp).await.expect("read");
    assert_eq!(&resp, b"MTLS_OK");
    assert!(
        presented.await.expect("server result"),
        "the certificate reached the host"
    );

    // Without it, the same kind of host refuses the connection.
    let (port, srv_ca, presented) =
        spawn_mtls_server(CertificateDer::from(cli_ca.der().to_vec())).await;
    let ca_file = TempFileGuard::new("mtls_server_ca2", srv_ca.pem().as_bytes());
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Enabled)
        .ca_cert(ca_file.path())
        .build()
        .expect("profile");
    let outcome = match connect_tls(&profile, Duration::from_secs(3)).await {
        Err(_) => true,
        // TLS 1.3: the client may finish before the server's alert arrives; the first read fails.
        Ok(mut s) => s.read_exact(&mut [0u8; 7]).await.is_err(),
    };
    assert!(outcome, "without a client certificate the host refuses");
    assert!(!presented.await.unwrap_or(false));
}
