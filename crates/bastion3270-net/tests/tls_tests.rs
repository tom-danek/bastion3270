//! Comprehensive unit and integration tests for TLS transport and CA certificate loader.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::time::Duration;

use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use bastion3270_net::profile::{ConnectionProfileBuilder, TlsMode};
use bastion3270_net::transport::tls::{
    connect_tls, load_ca_cert_store, load_default_root_store, parse_server_name,
};
use bastion3270_net::transport::{connect, CertProblem};
use bastion3270_net::NetError;

mod common;
use common::test_pki::TestPki;

#[test]
fn test_default_root_store_is_populated() {
    let store = load_default_root_store();
    assert!(
        !store.is_empty(),
        "webpki root store must contain Mozilla trust roots"
    );
}

#[test]
fn test_parse_server_name_dns_and_ip() {
    let s_dns = parse_server_name("mainframe.ibm.com").expect("DNS name parsing should succeed");
    assert!(matches!(s_dns, ServerName::DnsName(_)));

    let s_ip = parse_server_name("127.0.0.1").expect("IPv4 address parsing should succeed");
    assert!(matches!(s_ip, ServerName::IpAddress(_)));

    let s_ipv6 = parse_server_name("::1").expect("IPv6 address parsing should succeed");
    assert!(matches!(s_ipv6, ServerName::IpAddress(_)));

    let err = parse_server_name("").expect_err("Empty string should fail");
    assert!(err.is_invalid_certificate());
}

#[test]
fn test_ca_loader_rejects_empty_file() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("test_ca_empty.pem");
    std::fs::write(&file_path, b"").expect("write empty file");

    let res = load_ca_cert_store(&file_path);
    let _ = std::fs::remove_file(&file_path);

    assert!(res.is_err());
    assert!(res.expect_err("must be error").is_invalid_certificate());
}

#[test]
fn test_ca_loader_rejects_corrupted_pem() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("test_ca_corrupt.pem");
    std::fs::write(
        &file_path,
        b"-----BEGIN CERTIFICATE-----\nNOT_BASE_64_!@#$%\n-----END CERTIFICATE-----",
    )
    .expect("write corrupt PEM");

    let res = load_ca_cert_store(&file_path);
    let _ = std::fs::remove_file(&file_path);

    assert!(res.is_err());
    assert!(res.expect_err("must be error").is_invalid_certificate());
}

#[test]
fn test_ca_loader_rejects_corrupted_binary() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("test_ca_corrupt.der");
    std::fs::write(&file_path, [0xDE, 0xAD, 0xBE, 0xEF]).expect("write corrupt DER");

    let res = load_ca_cert_store(&file_path);
    let _ = std::fs::remove_file(&file_path);

    assert!(res.is_err());
    assert!(res.expect_err("must be error").is_invalid_certificate());
}

#[test]
fn test_ca_loader_rejects_non_existent_file() {
    let non_existent = std::path::Path::new("/non/existent/path/ca.pem");
    let res = load_ca_cert_store(non_existent);
    assert!(res.is_err());
    assert!(res.expect_err("must be error").is_invalid_certificate());
}

#[test]
fn test_ca_loader_accepts_valid_pem_and_der() {
    let pki = TestPki::new(&["127.0.0.1", "localhost"]).expect("PKI generation failed");
    let temp_dir = std::env::temp_dir();

    // 1. Valid PEM
    let pem_path = temp_dir.join("test_ca_valid.pem");
    std::fs::write(&pem_path, &pki.ca_cert_pem).expect("write PEM failed");
    let store_pem = load_ca_cert_store(&pem_path).expect("load PEM failed");
    let _ = std::fs::remove_file(&pem_path);
    assert_eq!(store_pem.len(), 1);

    // 2. Valid DER
    let der_path = temp_dir.join("test_ca_valid.der");
    std::fs::write(&der_path, &pki.ca_cert_der).expect("write DER failed");
    let store_der = load_ca_cert_store(&der_path).expect("load DER failed");
    let _ = std::fs::remove_file(&der_path);
    assert_eq!(store_der.len(), 1);
}

#[tokio::test]
async fn test_hermetic_tls_loopback_handshake_and_transfer() {
    let pki = TestPki::new(&["127.0.0.1", "localhost"]).expect("PKI failed");
    let server_config = pki.server_config().expect("server config failed");
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let addr = listener.local_addr().expect("addr failed");

    // Spawn mock TLS mainframe server
    tokio::spawn(async move {
        if let Ok((tcp_stream, _)) = listener.accept().await {
            if let Ok(mut tls_stream) = acceptor.accept(tcp_stream).await {
                let mut buf = [0u8; 8];
                let _ = tls_stream.read_exact(&mut buf).await;
                assert_eq!(&buf, b"HELO3270");
                let _ = tls_stream.write_all(b"TN3270OK").await;
                let _ = tls_stream.flush().await;
            }
        }
    });

    // Write CA cert to temp file for profile consumption
    let temp_dir = std::env::temp_dir();
    let ca_path = temp_dir.join("test_loopback_ca.pem");
    std::fs::write(&ca_path, &pki.ca_cert_pem).expect("write CA cert failed");

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .ca_cert(&ca_path)
        .connect_timeout_ms(5_000)
        .build()
        .expect("profile build failed");

    let mut tls_stream = connect_tls(&profile, Duration::from_secs(5))
        .await
        .expect("TLS connect failed");

    let _ = std::fs::remove_file(&ca_path);

    tls_stream
        .write_all(b"HELO3270")
        .await
        .expect("write failed");
    tls_stream.flush().await.expect("flush failed");

    let mut response = [0u8; 8];
    tls_stream
        .read_exact(&mut response)
        .await
        .expect("read response failed");
    assert_eq!(&response, b"TN3270OK");
}

#[tokio::test]
async fn test_tls_handshake_fails_on_untrusted_ca() {
    let pki_server = TestPki::new(&["127.0.0.1"]).expect("server PKI failed");
    let pki_untrusted = TestPki::new(&["127.0.0.1"]).expect("untrusted PKI failed");

    let server_config = pki_server.server_config().expect("server config failed");
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let addr = listener.local_addr().expect("addr failed");

    tokio::spawn(async move {
        if let Ok((tcp_stream, _)) = listener.accept().await {
            let _ = acceptor.accept(tcp_stream).await;
        }
    });

    let temp_dir = std::env::temp_dir();
    let ca_path = temp_dir.join("untrusted_ca.pem");
    std::fs::write(&ca_path, &pki_untrusted.ca_cert_pem).expect("write failed");

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .ca_cert(&ca_path)
        .connect_timeout_ms(2_000)
        .build()
        .expect("profile build failed");

    let err = connect_tls(&profile, Duration::from_secs(2))
        .await
        .expect_err("Connection must fail on untrusted CA");

    let _ = std::fs::remove_file(&ca_path);

    // A refused certificate is reported with its reason.
    assert!(
        matches!(&err, NetError::UntrustedCertificate(r) if r.problem == CertProblem::UnknownIssuer),
        "Expected a refused certificate: got {err:?}"
    );
}

#[tokio::test]
async fn test_tls_handshake_timeout_expires() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let addr = listener.local_addr().expect("addr failed");

    // Server accepts TCP connection but hangs indefinitely without sending TLS ServerHello
    tokio::spawn(async move {
        if let Ok((_tcp, _)) = listener.accept().await {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .connect_timeout_ms(50)
        .build()
        .expect("profile build failed");

    let err = connect_tls(&profile, Duration::from_millis(50))
        .await
        .expect_err("Handshake must time out");

    assert!(
        err.is_connect_timeout(),
        "Expected ConnectTimeout: got {err:?}"
    );
}

#[tokio::test]
async fn test_tls_transport_stream_accessors_and_unified_connect() {
    let pki = TestPki::new(&["127.0.0.1", "localhost"]).expect("PKI failed");
    let server_config = pki.server_config().expect("server config failed");
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let addr = listener.local_addr().expect("addr failed");

    tokio::spawn(async move {
        if let Ok((tcp_stream, _)) = listener.accept().await {
            if let Ok(mut tls_stream) = acceptor.accept(tcp_stream).await {
                let mut buf = [0u8; 4];
                let _ = tls_stream.read_exact(&mut buf).await;
                assert_eq!(&buf, b"PING");
                let _ = tls_stream.write_all(b"PONG").await;
                let _ = tls_stream.flush().await;
            }
        }
    });

    let temp_dir = std::env::temp_dir();
    let ca_path = temp_dir.join("test_accessors_ca.pem");
    std::fs::write(&ca_path, &pki.ca_cert_pem).expect("write CA cert failed");

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .ca_cert(&ca_path)
        .connect_timeout_ms(5_000)
        .build()
        .expect("profile build failed");

    let mut stream = connect(&profile).await.expect("unified connect failed");
    let _ = std::fs::remove_file(&ca_path);

    assert!(stream.is_tls());
    assert!(!stream.is_plain());
    assert!(stream.tls_ref().is_some());
    assert!(stream.tls_mut().is_some());
    assert!(stream.plain_ref().is_none());
    assert!(stream.plain_mut().is_none());

    assert!(stream.tls_negotiated_cipher_suite().is_some());
    assert!(stream.tls_protocol_version().is_some());
    assert!(stream.tls_peer_certificates().is_some());
    assert_eq!(format!("{stream}"), "TransportStream(TLS Encrypted)");

    stream.write_all(b"PING").await.expect("write failed");
    stream.flush().await.expect("flush failed");

    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp).await.expect("read failed");
    assert_eq!(&resp, b"PONG");

    stream.shutdown().await.expect("shutdown failed");
}
