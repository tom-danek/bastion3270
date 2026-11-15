//! Integration and unit tests for asynchronous network transport (TCP, Timeouts, `TransportStream`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use bastion3270_net::profile::{ConnectionProfileBuilder, TlsMode};
use bastion3270_net::transport::{
    connect, connect_tcp, connect_tcp_stream, connect_with_idle_timeout, read_with_idle_timeout,
    IdleTimeoutDetector, IdleTimeoutStream, TransportStream,
};

const fn assert_unpin<T: Unpin>() {}
const fn assert_send<T: Send>() {}
const fn assert_sync<T: Sync>() {}

#[test]
fn test_transport_stream_trait_bounds() {
    assert_unpin::<TransportStream>();
    assert_send::<TransportStream>();
    assert_sync::<TransportStream>();
}

#[tokio::test]
async fn test_plain_loopback_io_and_accessors() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let server_addr = listener.local_addr().expect("local addr");

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 5];
        socket.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"HELLO");
        socket.write_all(b"WORLD").await.expect("write");
        socket.shutdown().await.expect("shutdown");
    });

    let client = connect_tcp_stream("127.0.0.1", server_addr.port())
        .await
        .expect("connect");
    let mut transport = TransportStream::from_plain(client);

    assert!(transport.is_plain());
    assert!(!transport.is_tls());
    assert_eq!(transport.peer_addr().expect("peer_addr"), server_addr);
    assert!(transport.local_addr().is_ok());
    assert!(transport.plain_ref().is_some());
    assert!(transport.plain_mut().is_some());
    assert!(transport.tls_ref().is_none());
    assert!(transport.tls_mut().is_none());

    transport.set_nodelay(true).expect("set nodelay");
    assert!(transport.nodelay().expect("get nodelay"));
    transport.set_ttl(64).expect("set ttl");
    assert_eq!(transport.ttl().expect("get ttl"), 64);

    assert!(transport.tls_negotiated_cipher_suite().is_none());
    assert!(transport.tls_protocol_version().is_none());
    assert!(transport.tls_alpn_protocol().is_none());
    assert!(transport.tls_peer_certificates().is_none());
    assert_eq!(format!("{transport}"), "TransportStream(Plain TCP)");

    transport.write_all(b"HELLO").await.expect("write");
    let mut resp = [0u8; 5];
    transport.read_exact(&mut resp).await.expect("read");
    assert_eq!(&resp, b"WORLD");

    transport.shutdown().await.expect("shutdown");
    srv.await.expect("server join");
}

#[tokio::test]
async fn test_plain_into_split() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let server_addr = listener.local_addr().expect("local addr");

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 4];
        socket.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"PING");
        socket.write_all(b"PONG").await.expect("write");
    });

    let client = connect_tcp_stream("127.0.0.1", server_addr.port())
        .await
        .expect("connect");
    let transport = TransportStream::from(client);
    let (mut r, mut w) = transport.into_split();

    w.write_all(b"PING").await.expect("write");
    let mut resp = [0u8; 4];
    r.read_exact(&mut resp).await.expect("read");
    assert_eq!(&resp, b"PONG");

    srv.await.expect("server join");
}

#[tokio::test]
async fn test_plain_split_borrowed() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let server_addr = listener.local_addr().expect("local addr");

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 4];
        socket.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ECHO");
        socket.write_all(b"ECHO").await.expect("write");
    });

    let client = connect_tcp_stream("127.0.0.1", server_addr.port())
        .await
        .expect("connect");
    let mut transport = TransportStream::from(client);
    {
        let (mut r, mut w) = transport.split();
        w.write_all(b"ECHO").await.expect("write");
        let mut resp = [0u8; 4];
        r.read_exact(&mut resp).await.expect("read");
        assert_eq!(&resp, b"ECHO");
    }

    srv.await.expect("server join");
}

#[tokio::test]
async fn test_connect_tcp_validation_guards() {
    let err_empty = connect_tcp("", 3270, Duration::from_secs(1))
        .await
        .expect_err("empty host must fail");
    assert!(err_empty.is_config());

    let err_spaces = connect_tcp("   ", 3270, Duration::from_secs(1))
        .await
        .expect_err("whitespace host must fail");
    assert!(err_spaces.is_config());

    let err_port = connect_tcp("127.0.0.1", 0, Duration::from_secs(1))
        .await
        .expect_err("port 0 must fail");
    assert!(err_port.is_config());

    let err_timeout = connect_tcp("127.0.0.1", 3270, Duration::ZERO)
        .await
        .expect_err("zero timeout must fail");
    assert!(err_timeout.is_config());
}

#[tokio::test]
async fn test_connect_tcp_connection_refused() {
    // Bind a listener to get an unused port, then drop it
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);

    // Generous deadline: Windows retries the SYN after a reset and reports the refusal only
    // after about two seconds, so a short deadline would turn it into a timeout.
    let err = connect_tcp("127.0.0.1", port, Duration::from_secs(10))
        .await
        .expect_err("connection to closed port must fail");
    assert!(err.is_io(), "Expected NetError::Io, got: {err:?}");
}

#[tokio::test]
async fn test_connect_tcp_timeout_triggered() {
    // 192.0.2.1 is TEST-NET-1 (RFC 5737), non-routable on public internet.
    // In sandboxed environments without a default route, the OS returns NetworkUnreachable immediately.
    // In environments with a default route, the connection times out.
    let err = connect_tcp("192.0.2.1", 3270, Duration::from_millis(30))
        .await
        .expect_err("non-routable IP must fail with timeout or unreachable");
    assert!(
        matches!(
            err,
            bastion3270_net::NetError::ConnectTimeout | bastion3270_net::NetError::Io(_)
        ),
        "Expected ConnectTimeout or NetworkUnreachable Io, got: {err:?}"
    );
}

#[test]
fn test_idle_detector_lifecycle() {
    let mut detector = IdleTimeoutDetector::new(Duration::from_millis(40));
    assert_eq!(detector.timeout(), Duration::from_millis(40));
    assert!(!detector.is_idle());
    assert!(detector.check().is_ok());
    assert!(detector.remaining() <= Duration::from_millis(40));

    std::thread::sleep(Duration::from_millis(50));
    assert!(detector.is_idle());
    assert!(detector.check().is_err());
    assert_eq!(detector.remaining(), Duration::ZERO);

    detector.record_activity();
    assert!(!detector.is_idle());
    assert!(detector.check().is_ok());
}

#[tokio::test]
async fn test_read_with_idle_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    // Server sends nothing and sleeps
    tokio::spawn(async move {
        if let Ok((_socket, _)) = listener.accept().await {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let mut client = connect_tcp_stream("127.0.0.1", addr.port())
        .await
        .expect("connect");
    let mut buf = [0u8; 10];

    // Read with short timeout should expire
    let err = read_with_idle_timeout(&mut client, &mut buf, Duration::from_millis(20))
        .await
        .expect_err("idle timeout must fire");
    assert!(err.is_idle_timeout());

    // Zero timeout should return NetError::Config
    let err_zero = read_with_idle_timeout(&mut client, &mut buf, Duration::ZERO)
        .await
        .expect_err("zero timeout must fail");
    assert!(err_zero.is_config());
}

#[tokio::test]
async fn test_idle_timeout_stream_read_write() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 4];
        socket.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"TEST");
        socket.write_all(b"BACK").await.expect("write");
    });

    let client = connect_tcp_stream("127.0.0.1", addr.port())
        .await
        .expect("connect");
    let mut stream = IdleTimeoutStream::new(client, Duration::from_secs(5));

    assert_eq!(stream.timeout(), Duration::from_secs(5));
    assert!(!stream.detector().is_idle());

    stream.write_all(b"TEST").await.expect("write");
    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp).await.expect("read");
    assert_eq!(&resp, b"BACK");

    stream.record_activity();
    assert!(!stream.detector().is_idle());

    let raw = stream.into_inner();
    assert!(raw.local_addr().is_ok());
}

#[tokio::test]
async fn test_idle_timeout_stream_poll_read_expiry() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((_socket, _)) = listener.accept().await {
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    });

    let client = connect_tcp_stream("127.0.0.1", addr.port())
        .await
        .expect("connect");
    let mut stream = IdleTimeoutStream::new(client, Duration::from_millis(25));

    // Wait until idle detector expires
    tokio::time::sleep(Duration::from_millis(35)).await;

    // AsyncRead trait poll_read should detect that idle timeout was exceeded
    let mut buf = [0u8; 4];
    let err = stream
        .read(&mut buf)
        .await
        .expect_err("read must fail after idle expiry");
    assert!(err.is_idle_timeout());
}

#[tokio::test]
async fn test_connector_connect_plain_profile() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 3];
            let _ = socket.read_exact(&mut buf).await;
            let _ = socket.write_all(b"ACK").await;
        }
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Disabled)
        .connect_timeout_ms(2_000)
        .idle_timeout_ms(10_000)
        .build()
        .expect("profile build");

    let mut stream = connect(&profile).await.expect("connect");
    assert!(stream.is_plain());

    stream.write_all(b"SYN").await.expect("write");
    let mut resp = [0u8; 3];
    stream.read_exact(&mut resp).await.expect("read");
    assert_eq!(&resp, b"ACK");
}

#[tokio::test]
async fn test_connector_connect_with_idle_timeout_profile() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket.write_all(b"READY").await;
        }
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Disabled)
        .connect_timeout_ms(2_000)
        .idle_timeout_ms(5_000)
        .build()
        .expect("profile build");

    let mut stream = connect_with_idle_timeout(&profile).await.expect("connect");
    assert_eq!(stream.timeout(), Duration::from_millis(5_000));

    let mut resp = [0u8; 5];
    stream.read_exact(&mut resp).await.expect("read");
    assert_eq!(&resp, b"READY");
}
