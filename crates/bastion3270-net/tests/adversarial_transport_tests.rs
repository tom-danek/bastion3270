//! Adversarial empirical verification suite for the network transport.
//!
//! Stress-tests:
//! 1. `connect_tcp` & `connect_tcp_stream` boundary conditions, host sanitization fuzzing, extreme timeouts.
//! 2. `read_with_idle_timeout` edge cases (zero timeout, extreme durations, empty buffers, EOF vs timeout).
//! 3. `IdleTimeoutDetector` invariant stress (zero duration, extreme duration, rapid resets, monotonicity).
//! 4. `IdleTimeoutStream` rapid alternating read/write (ping-pong across idle thresholds, zero-length I/O, poll_read).
//! 5. `TransportStream` Plain split halves concurrent stress (`into_split` and borrowed `split` with concurrent tasks).
//! 6. `TransportStream` TLS split halves concurrent stress (`into_split` and borrowed `split` with concurrent tasks).
//! 7. `TransportStream` socket options & accessors (rapid nodelay toggling, TTL boundaries, display, write_vectored).
//! 8. High-throughput chunk streaming & byte-integrity fuzzing across `TransportStream`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::doc_markdown,
    clippy::duration_suboptimal_units,
    clippy::unreadable_literal
)]

use std::io::IoSlice;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use bastion3270_net::profile::{ConnectionProfileBuilder, TlsMode};
use bastion3270_net::transport::{
    connect, connect_tcp, connect_tcp_stream, read_with_idle_timeout, IdleTimeoutDetector,
    IdleTimeoutStream, TransportStream,
};
use bastion3270_net::NetError;

mod common;
use common::test_pki::TestPki;

// =========================================================================
// Category 1: connect_tcp & connect_tcp_stream Boundaries & Host Fuzzing
// =========================================================================

#[tokio::test]
async fn test_connect_tcp_zero_and_extreme_durations() {
    // 1. Zero duration must be rejected with NetError::Config
    let err_zero = connect_tcp("127.0.0.1", 3270, Duration::ZERO)
        .await
        .expect_err("zero timeout must fail with Config error");
    assert!(
        err_zero.is_config(),
        "Expected NetError::Config, got: {err_zero:?}"
    );

    // 2. Extremely large duration (1 year) against a live listener must connect immediately without delay or overflow
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 4];
        socket.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"TEST");
    });

    let one_year = Duration::from_secs(365 * 24 * 3600);
    let mut client = connect_tcp("127.0.0.1", addr.port(), one_year)
        .await
        .expect("connection with 1 year timeout must succeed against live listener");
    client.write_all(b"TEST").await.expect("write");
    srv.await.expect("server join");

    // 3. Sub-millisecond duration against non-routable IP (TEST-NET-1: 192.0.2.1)
    let tiny_timeout = Duration::from_micros(50);
    let err_tiny = connect_tcp("192.0.2.1", 3270, tiny_timeout)
        .await
        .expect_err("tiny timeout on non-routable host must fail");
    assert!(
        matches!(err_tiny, NetError::ConnectTimeout | NetError::Io(_)),
        "Expected ConnectTimeout or NetworkUnreachable Io, got: {err_tiny:?}"
    );
}

#[tokio::test]
async fn test_connect_tcp_host_boundary_and_fuzz() {
    let dummy_timeout = Duration::from_millis(200);

    // Whitespace variations
    for ws in &["", " ", "   ", "\t", "\r\n", "  \t\r\n  "] {
        let err = connect_tcp(ws, 3270, dummy_timeout)
            .await
            .expect_err("whitespace host must fail");
        assert!(
            err.is_config(),
            "Expected Config error for host '{ws}', got: {err:?}"
        );
    }

    // Port 0 must be rejected
    let err_port = connect_tcp("127.0.0.1", 0, dummy_timeout)
        .await
        .expect_err("port 0 must fail");
    assert!(err_port.is_config(), "Expected Config error for port 0");

    // Leading and trailing whitespace that trims to valid host
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("addr").port();

    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let client = connect_tcp("  127.0.0.1  \t", port, dummy_timeout)
        .await
        .expect("trimmed host must connect successfully");
    assert_eq!(client.peer_addr().expect("peer_addr").port(), port);

    // Adversarial host strings (null bytes, invalid characters, Unicode, long strings)
    // None of these should panic; they should return NetError::Io (or Config)
    let adversarial_hosts = [
        "127.0.0.1\0malicious.org",
        "invalid..double..dots.example",
        "999.999.999.999",
        "💻.mainframe.ibm.com",
        "newline\nbreak.com",
        &"A".repeat(5_000),
    ];

    for adv_host in adversarial_hosts {
        let res = connect_tcp(adv_host, 3270, Duration::from_millis(50)).await;
        assert!(
            res.is_err(),
            "Adversarial host '{adv_host}' should have failed"
        );
        let err = res.expect_err("must be err");
        assert!(
            !err.to_string().is_empty(),
            "Error message must be non-empty"
        );
    }
}

// =========================================================================
// Category 2: read_with_idle_timeout Boundaries & Corner Cases
// =========================================================================

#[tokio::test]
async fn test_read_with_idle_timeout_zero_and_buffer_boundaries() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket.write_all(b"AVAILABLE_DATA").await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let mut client = connect_tcp_stream("127.0.0.1", addr.port())
        .await
        .expect("connect");

    // Zero idle timeout returns NetError::Config
    let mut buf = [0u8; 16];
    let err_zero = read_with_idle_timeout(&mut client, &mut buf, Duration::ZERO)
        .await
        .expect_err("zero timeout must fail with Config");
    assert!(err_zero.is_config());

    // Empty buffer with positive timeout should return Ok(0) immediately
    let mut empty_buf = [0u8; 0];
    let n_empty = read_with_idle_timeout(&mut client, &mut empty_buf, Duration::from_secs(5))
        .await
        .expect("empty buffer read should succeed");
    assert_eq!(n_empty, 0);

    // Reading available data should return immediately
    let mut data_buf = [0u8; 14];
    let n_data = read_with_idle_timeout(&mut client, &mut data_buf, Duration::from_secs(5))
        .await
        .expect("read available data");
    assert_eq!(n_data, 14);
    assert_eq!(&data_buf, b"AVAILABLE_DATA");

    // Next read on quiet socket with tiny timeout should trigger NetError::IdleTimeout
    let mut quiet_buf = [0u8; 10];
    let err_idle = read_with_idle_timeout(&mut client, &mut quiet_buf, Duration::from_millis(20))
        .await
        .expect_err("idle timeout should fire");
    assert!(err_idle.is_idle_timeout());
}

#[tokio::test]
async fn test_read_with_idle_timeout_eof_behavior() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket.write_all(b"BYE").await;
            let _ = socket.shutdown().await;
        }
    });

    let mut client = connect_tcp_stream("127.0.0.1", addr.port())
        .await
        .expect("connect");

    // First read: retrieves 3 bytes
    let mut buf = [0u8; 10];
    let n1 = read_with_idle_timeout(&mut client, &mut buf, Duration::from_secs(2))
        .await
        .expect("first read must succeed");
    assert_eq!(n1, 3);
    assert_eq!(&buf[0..3], b"BYE");

    // Second read: peer has shutdown write half -> EOF (returns Ok(0), not NetError::IdleTimeout)
    let n2 = read_with_idle_timeout(&mut client, &mut buf, Duration::from_secs(2))
        .await
        .expect("EOF must return Ok(0)");
    assert_eq!(n2, 0);
}

// =========================================================================
// Category 3: IdleTimeoutDetector Boundary Invariants & Monotonicity
// =========================================================================

#[test]
fn test_idle_timeout_detector_zero_and_extreme_durations() {
    // 1. Zero timeout detector is immediately idle
    let zero_det = IdleTimeoutDetector::new(Duration::ZERO);
    assert_eq!(zero_det.timeout(), Duration::ZERO);
    assert!(zero_det.is_idle());
    assert_eq!(zero_det.remaining(), Duration::ZERO);
    assert!(zero_det.check().is_err());
    assert!(zero_det.check().expect_err("idle").is_idle_timeout());

    // 2. Extreme timeout (100 years) saturating subtraction without overflow
    let extreme_det = IdleTimeoutDetector::new(Duration::from_secs(100 * 365 * 86400));
    assert!(!extreme_det.is_idle());
    assert!(extreme_det.check().is_ok());
    assert!(extreme_det.remaining() > Duration::from_secs(99 * 365 * 86400));

    // 3. Rapid activity recording in tight loop
    let mut det = IdleTimeoutDetector::new(Duration::from_millis(50));
    for _ in 0..10_000 {
        det.record_activity();
        assert!(!det.is_idle());
        assert!(det.check().is_ok());
        assert!(det.remaining() > Duration::ZERO);
    }
}

// =========================================================================
// Category 4: IdleTimeoutStream Rapid Alternating & Boundary Stress
// =========================================================================

#[tokio::test]
async fn test_idle_timeout_stream_rapid_alternating_ping_pong() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    // Server echoes back 100 packets with byte inversion
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        for _ in 0..100 {
            let mut buf = [0u8; 8];
            socket.read_exact(&mut buf).await.expect("server read");
            for b in &mut buf {
                *b = !*b;
            }
            socket.write_all(&buf).await.expect("server write");
        }
    });

    let client = connect_tcp_stream("127.0.0.1", addr.port())
        .await
        .expect("connect");

    // Short timeout: 100ms
    let mut stream = IdleTimeoutStream::new(client, Duration::from_millis(100));

    // Perform 100 ping-pong rounds with slight delay between each
    // Total elapsed time will exceed 100ms, but every exchange refreshes activity
    for i in 0..100u8 {
        let send_data = [i; 8];
        stream.write_all(&send_data).await.expect("client write");

        let mut recv_data = [0u8; 8];
        stream
            .read_exact(&mut recv_data)
            .await
            .expect("client read");
        assert_eq!(recv_data, [!i; 8]);

        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    // Verify stream is still active
    assert!(!stream.detector().is_idle());
    assert!(stream.detector().check().is_ok());

    // Now intentionally allow the stream to idle for 120ms (> 100ms timeout)
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(stream.detector().is_idle());

    // Subsequent read must immediately fail with NetError::IdleTimeout
    let mut after_idle = [0u8; 8];
    let err = stream
        .read(&mut after_idle)
        .await
        .expect_err("read after idle expiry must fail");
    assert!(err.is_idle_timeout());
}

#[tokio::test]
async fn test_idle_timeout_stream_empty_io_and_accessors() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let client = connect_tcp_stream("127.0.0.1", addr.port())
        .await
        .expect("connect");
    let mut stream = IdleTimeoutStream::new(client, Duration::from_secs(10));

    // Empty write and write_all should succeed without panic
    let n_write = stream.write(&[]).await.expect("empty write");
    assert_eq!(n_write, 0);
    stream.write_all(&[]).await.expect("empty write_all");

    // Empty read and read_exact should succeed without panic
    let mut empty_buf = [0u8; 0];
    let n_read = stream.read(&mut empty_buf).await.expect("empty read");
    assert_eq!(n_read, 0);
    stream
        .read_exact(&mut empty_buf)
        .await
        .expect("empty read_exact");

    // Accessors
    assert_eq!(stream.timeout(), Duration::from_secs(10));
    assert!(stream.get_ref().local_addr().is_ok());
    assert!(stream.get_mut().peer_addr().is_ok());

    // Debug formatting
    let debug_str = format!("{stream:?}");
    assert!(debug_str.contains("IdleTimeoutStream"));

    // Flush and shutdown
    stream.flush().await.expect("flush");
    stream.shutdown().await.expect("shutdown");

    // into_inner recovery
    let inner = stream.into_inner();
    assert!(inner.local_addr().is_ok());

    // Display formatting on IdleTimeoutStream<TransportStream>
    let transport_stream =
        IdleTimeoutStream::new(TransportStream::from_plain(inner), Duration::from_secs(10));
    let display_str = format!("{transport_stream}");
    assert!(display_str.contains("IdleTimeoutStream(TransportStream(Plain TCP)"));
}

#[tokio::test]
async fn test_idle_timeout_stream_zero_timeout_immediate_rejection() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let client = connect_tcp_stream("127.0.0.1", addr.port())
        .await
        .expect("connect");
    let mut stream = IdleTimeoutStream::new(client, Duration::ZERO);

    let mut buf = [0u8; 10];
    let err_read = stream.read(&mut buf).await.expect_err("read must fail");
    assert!(err_read.is_idle_timeout());

    let err_read_exact = stream
        .read_exact(&mut buf)
        .await
        .expect_err("read_exact must fail");
    assert!(err_read_exact.is_idle_timeout());
}

// =========================================================================
// Category 5: TransportStream Plain Concurrent Split Stress
// =========================================================================

#[tokio::test]
async fn test_transport_stream_plain_into_split_concurrent_stress() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let server_addr = listener.local_addr().expect("local addr");

    const MESSAGE_COUNT: usize = 300;

    // Server loopback: reads messages and echoes them back
    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        for _ in 0..MESSAGE_COUNT {
            let len = socket.read_u32().await.expect("server read len") as usize;
            let mut payload = vec![0u8; len];
            socket
                .read_exact(&mut payload)
                .await
                .expect("server read payload");

            socket
                .write_u32(len as u32)
                .await
                .expect("server write len");
            socket
                .write_all(&payload)
                .await
                .expect("server write payload");
        }
    });

    let client = connect_tcp_stream("127.0.0.1", server_addr.port())
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(client);
    let (mut read_half, mut write_half) = transport.into_split();

    // Writer task: sends MESSAGE_COUNT messages of varying sizes (from 1 byte to 2048 bytes)
    let writer_task = tokio::spawn(async move {
        for i in 0..MESSAGE_COUNT {
            let size = (i % 256) * 7 + 1;
            let pattern = (i % 251) as u8;
            let payload = vec![pattern; size];

            write_half
                .write_u32(size as u32)
                .await
                .expect("client write len");
            write_half
                .write_all(&payload)
                .await
                .expect("client write payload");
        }
    });

    // Reader task: reads MESSAGE_COUNT messages concurrently and validates payload integrity
    let reader_task = tokio::spawn(async move {
        for i in 0..MESSAGE_COUNT {
            let size = (i % 256) * 7 + 1;
            let pattern = (i % 251) as u8;

            let recv_len = read_half.read_u32().await.expect("client read len") as usize;
            assert_eq!(recv_len, size, "Message {i} length mismatch");

            let mut recv_payload = vec![0u8; recv_len];
            read_half
                .read_exact(&mut recv_payload)
                .await
                .expect("client read payload");
            assert_eq!(
                recv_payload,
                vec![pattern; size],
                "Message {i} payload corruption"
            );
        }
    });

    let (res_w, res_r, res_s) = tokio::join!(writer_task, reader_task, server_task);
    res_w.expect("writer join");
    res_r.expect("reader join");
    res_s.expect("server join");
}

#[tokio::test]
async fn test_transport_stream_plain_borrowed_split_concurrent_stress() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let server_addr = listener.local_addr().expect("local addr");

    const MESSAGE_COUNT: usize = 200;

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        for _ in 0..MESSAGE_COUNT {
            let seq = socket.read_u32().await.expect("server read seq");
            let mut data = [0u8; 16];
            socket
                .read_exact(&mut data)
                .await
                .expect("server read data");

            socket.write_u32(seq).await.expect("server write seq");
            socket.write_all(&data).await.expect("server write data");
        }
    });

    let client = connect_tcp_stream("127.0.0.1", server_addr.port())
        .await
        .expect("connect");
    let mut transport = TransportStream::from(client);

    {
        let (mut r, mut w) = transport.split();

        let write_future = async move {
            for seq in 0..MESSAGE_COUNT as u32 {
                w.write_u32(seq).await.expect("write seq");
                let data = [(seq % 255) as u8; 16];
                w.write_all(&data).await.expect("write data");
            }
        };

        let read_future = async move {
            for expected_seq in 0..MESSAGE_COUNT as u32 {
                let seq = r.read_u32().await.expect("read seq");
                assert_eq!(seq, expected_seq);
                let mut data = [0u8; 16];
                r.read_exact(&mut data).await.expect("read data");
                assert_eq!(data, [(expected_seq % 255) as u8; 16]);
            }
        };

        tokio::join!(write_future, read_future);
    }

    server_task.await.expect("server join");
}

// =========================================================================
// Category 6: TransportStream TLS Concurrent Split Stress
// =========================================================================

#[tokio::test]
async fn test_transport_stream_tls_into_split_concurrent_stress() {
    let pki = TestPki::new(&["127.0.0.1", "localhost"]).expect("PKI init");
    let server_config = pki.server_config().expect("server config");
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    const TLS_MESSAGE_COUNT: usize = 150;

    // TLS Server Echo Task
    let server_task = tokio::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.expect("tcp accept");
        let mut tls_stream = acceptor.accept(tcp_stream).await.expect("tls accept");

        for _ in 0..TLS_MESSAGE_COUNT {
            let len = tls_stream.read_u32().await.expect("server read len") as usize;
            let mut payload = vec![0u8; len];
            tls_stream
                .read_exact(&mut payload)
                .await
                .expect("server read payload");

            tls_stream
                .write_u32(len as u32)
                .await
                .expect("server write len");
            tls_stream
                .write_all(&payload)
                .await
                .expect("server write payload");
            tls_stream.flush().await.expect("server flush");
        }
    });

    let temp_dir = std::env::temp_dir();
    let ca_path = temp_dir.join("test_tls_split_ca.pem");
    std::fs::write(&ca_path, &pki.ca_cert_pem).expect("write CA cert");

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .ca_cert(&ca_path)
        .connect_timeout_ms(5_000)
        .build()
        .expect("profile build");

    let transport = connect(&profile).await.expect("TLS connect");
    let _ = std::fs::remove_file(&ca_path);

    assert!(transport.is_tls());
    let (mut read_half, mut write_half) = transport.into_split();

    // Concurrent TLS Writer Task
    let writer_task = tokio::spawn(async move {
        for i in 0..TLS_MESSAGE_COUNT {
            let size = (i % 64) * 8 + 4;
            let pattern = (i % 251) as u8;
            let payload = vec![pattern; size];

            write_half
                .write_u32(size as u32)
                .await
                .expect("tls client write len");
            write_half
                .write_all(&payload)
                .await
                .expect("tls client write payload");
            write_half.flush().await.expect("tls client flush");
        }
    });

    // Concurrent TLS Reader Task
    let reader_task = tokio::spawn(async move {
        for i in 0..TLS_MESSAGE_COUNT {
            let size = (i % 64) * 8 + 4;
            let pattern = (i % 251) as u8;

            let recv_len = read_half.read_u32().await.expect("tls client read len") as usize;
            assert_eq!(recv_len, size, "TLS message {i} size mismatch");

            let mut recv_payload = vec![0u8; recv_len];
            read_half
                .read_exact(&mut recv_payload)
                .await
                .expect("tls client read payload");
            assert_eq!(
                recv_payload,
                vec![pattern; size],
                "TLS message {i} payload corrupted"
            );
        }
    });

    let (res_w, res_r, res_s) = tokio::join!(writer_task, reader_task, server_task);
    res_w.expect("tls writer join");
    res_r.expect("tls reader join");
    res_s.expect("tls server join");
}

#[tokio::test]
async fn test_transport_stream_tls_borrowed_split_concurrent_stress() {
    let pki = TestPki::new(&["127.0.0.1", "localhost"]).expect("PKI init");
    let server_config = pki.server_config().expect("server config");
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    const COUNT: usize = 80;

    let server_task = tokio::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.expect("tcp accept");
        let mut tls = acceptor.accept(tcp_stream).await.expect("tls accept");

        for _ in 0..COUNT {
            let seq = tls.read_u32().await.expect("server read seq");
            tls.write_u32(seq).await.expect("server write seq");
            tls.flush().await.expect("server flush");
        }
    });

    let temp_dir = std::env::temp_dir();
    let ca_path = temp_dir.join("test_tls_borrowed_ca.pem");
    std::fs::write(&ca_path, &pki.ca_cert_pem).expect("write CA cert");

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(addr.port())
        .tls_mode(TlsMode::Enabled)
        .ca_cert(&ca_path)
        .connect_timeout_ms(5_000)
        .build()
        .expect("profile build");

    let mut transport = connect(&profile).await.expect("TLS connect");
    let _ = std::fs::remove_file(&ca_path);

    {
        let (mut r, mut w) = transport.split();

        let write_future = async move {
            for seq in 0..COUNT as u32 {
                w.write_u32(seq).await.expect("write seq");
                w.flush().await.expect("flush");
            }
        };

        let read_future = async move {
            for expected_seq in 0..COUNT as u32 {
                let seq = r.read_u32().await.expect("read seq");
                assert_eq!(seq, expected_seq);
            }
        };

        tokio::join!(write_future, read_future);
    }

    server_task.await.expect("server join");
}

// =========================================================================
// Category 7: Socket Options & Accessor Invariants
// =========================================================================

#[tokio::test]
async fn test_transport_stream_socket_options_rapid_toggle() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let client = connect_tcp_stream("127.0.0.1", addr.port())
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(client);

    // Rapid toggle of TCP_NODELAY (100 cycles)
    for _ in 0..100 {
        transport.set_nodelay(true).expect("set nodelay true");
        assert!(transport.nodelay().expect("get nodelay true"));

        transport.set_nodelay(false).expect("set nodelay false");
        assert!(!transport.nodelay().expect("get nodelay false"));
    }

    // TTL valid values
    for ttl_val in [1, 32, 64, 128, 255] {
        transport.set_ttl(ttl_val).expect("set ttl");
        assert_eq!(transport.ttl().expect("get ttl"), ttl_val);
    }

    // TTL invalid boundary values (TTL > 255 returns error on Linux)
    let err_ttl = transport.set_ttl(1_000);
    assert!(
        err_ttl.is_err(),
        "Setting TTL > 255 should fail with OS error"
    );

    // Display string
    assert_eq!(format!("{transport}"), "TransportStream(Plain TCP)");
}

#[tokio::test]
async fn test_transport_stream_write_vectored_and_shutdown() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut full_buf = [0u8; 12];
        socket.read_exact(&mut full_buf).await.expect("read exact");
        assert_eq!(&full_buf, b"AAAABBBBCCCC");

        // After client shutdowns, reader should encounter EOF
        let mut eof_check = [0u8; 1];
        let n = socket.read(&mut eof_check).await.expect("eof read");
        assert_eq!(n, 0, "Expected EOF after client shutdown");
    });

    let client = connect_tcp_stream("127.0.0.1", addr.port())
        .await
        .expect("connect");
    let mut transport = TransportStream::from_plain(client);

    // Write vectored across 3 distinct slices
    let slice1 = b"AAAA";
    let slice2 = b"BBBB";
    let slice3 = b"CCCC";
    let io_slices = [
        IoSlice::new(slice1),
        IoSlice::new(slice2),
        IoSlice::new(slice3),
    ];

    let mut written = 0;
    while written < 12 {
        let n = transport
            .write_vectored(&io_slices)
            .await
            .expect("write_vectored");
        written += n;
    }
    transport.flush().await.expect("flush");

    // Shutdown client write side
    transport.shutdown().await.expect("shutdown");

    server_task.await.expect("server join");
}

#[tokio::test]
async fn test_transport_stream_peer_and_local_addr_consistency() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let listener_addr = listener.local_addr().expect("listener addr");

    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let client = connect_tcp_stream("127.0.0.1", listener_addr.port())
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(client);

    let peer = transport.peer_addr().expect("peer_addr");
    let local = transport.local_addr().expect("local_addr");

    assert_eq!(peer, listener_addr);
    assert_eq!(local.ip(), listener_addr.ip());
    assert_ne!(local.port(), 0);
    assert_ne!(local.port(), listener_addr.port());
}

// =========================================================================
// Category 8: High-Throughput Burst & Fragmented Packet Streaming
// =========================================================================

#[tokio::test]
async fn test_transport_stream_fragmented_packet_reassembly() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        // Send a 64-byte payload fragmented byte-by-byte with micro-yields
        for b in 0..64u8 {
            socket.write_all(&[b]).await.expect("fragment write");
            tokio::task::yield_now().await;
        }
    });

    let client = connect_tcp_stream("127.0.0.1", addr.port())
        .await
        .expect("connect");
    let mut transport = TransportStream::from_plain(client);

    let mut full_buf = [0u8; 64];
    transport
        .read_exact(&mut full_buf)
        .await
        .expect("reassemble");

    let expected: Vec<u8> = (0..64u8).collect();
    assert_eq!(&full_buf[..], &expected[..]);

    server_task.await.expect("server join");
}

#[tokio::test]
async fn test_transport_stream_burst_transfer_integrity() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    const TOTAL_BYTES: usize = 256 * 1024; // 256 KB burst

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = vec![0u8; 16 * 1024];
        let mut total_read = 0;
        let mut checksum: u64 = 0;

        while total_read < TOTAL_BYTES {
            let n = socket.read(&mut buf).await.expect("server read");
            if n == 0 {
                break;
            }
            total_read += n;
            for b in &buf[..n] {
                checksum = checksum.wrapping_add(*b as u64);
            }
        }
        (total_read, checksum)
    });

    let client = connect_tcp_stream("127.0.0.1", addr.port())
        .await
        .expect("connect");
    let mut transport = TransportStream::from_plain(client);

    // Client generates 256 KB of pseudo-random data with known checksum
    let mut client_data = vec![0u8; TOTAL_BYTES];
    let mut client_checksum: u64 = 0;
    for (idx, byte) in client_data.iter_mut().enumerate() {
        *byte = ((idx * 31 + 17) % 256) as u8;
        client_checksum = client_checksum.wrapping_add(*byte as u64);
    }

    transport
        .write_all(&client_data)
        .await
        .expect("client write burst");
    transport.shutdown().await.expect("client shutdown");

    let (server_total, server_checksum) = server_task.await.expect("server join");
    assert_eq!(server_total, TOTAL_BYTES, "Byte count mismatch");
    assert_eq!(
        server_checksum, client_checksum,
        "Burst data checksum mismatch"
    );
}
