//! Adversarial stress test suite for `SessionCoordinator`, `SessionHandle`,
//! split-stream full-duplex I/O, bounded backpressure channels, and extreme timeouts.
//!
//! # Stress Dimensions
//! 1. **Extreme Timeouts & Silence Boundaries**:
//!    - Zero ms timeout rejection in profile builder and validator.
//!    - Ultra-short silence timeouts (1ms, 5ms) triggering deterministic `NetError::IdleTimeout`.
//!    - High-frequency host packet streaming resetting silence timer and preventing premature timeout.
//!    - Rapid successive connect/disconnect cycles preventing leaked background tasks or socket exhaustion.
//! 2. **Bounded Channel Saturation & Backpressure**:
//!    - `channel_capacity = 1` sequential and concurrent keystroke streaming under tight backpressure.
//!    - `channel_capacity = 4` heavy saturation from multiple concurrent tasks.
//!    - Dropped event receiver resilience (ensuring coordinator never blocks when event channel closes).
//!    - Slow event receiver backpressure pacing client keystrokes safely without deadlock.
//! 3. **Concurrency Stress & Stream Splitting**:
//!    - Rapid client typing concurrent with continuous host screen/status updates.
//!    - Concurrent typing interleaved with autonomous RFC 2355 positive responses.
//!    - Concurrent typing during host Write Structured Field (Query) and autonomous Query Reply.
//! 4. **Multiple Handle Clones & Cross-Task Contention**:
//!    - 25 concurrent tasks querying screen, status, keyboard, and cursor across cloned handles.
//!    - In-flight keystroke commands racing against handle disconnect.
//!    - Abrupt host socket RST/closure during heavy multi-task concurrency.

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
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::duration_suboptimal_units,
    clippy::unreadable_literal,
    clippy::uninlined_format_args,
    clippy::redundant_pattern_matching
)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Barrier;

use bastion3270_core::keyboard::{ActionKey, AidKey, KeyboardState};
use bastion3270_net::profile::{ConnectionProfileBuilder, ProfileTerminalModel, TlsMode};
use bastion3270_net::session::{SessionCoordinator, SessionEvent, SessionState};
use bastion3270_net::transport::{connect_tcp_stream, TransportStream};
use bastion3270_net::NetError;

/// Helper: performs complete TN3270E option negotiation on mock server socket.
async fn mock_negotiate_tn3270e(socket: &mut tokio::net::TcpStream, assigned_lu: Option<&str>) {
    let mut buf = [0u8; 512];
    // 1. The host opens negotiation (the client is purely reactive): IAC DO TN3270E (FF FD 28)
    socket
        .write_all(&[0xFF, 0xFD, 0x28])
        .await
        .expect("write do tn3270e");

    // Client responds with IAC WILL TN3270E (FF FB 28)
    let n = socket.read(&mut buf).await.expect("read will tn3270e");
    assert!(n > 0);

    // 3. Server requests device type:
    // IAC SB TN3270E OP_SEND (8) OP_DEVICE_TYPE (2) IAC SE
    socket
        .write_all(&[0xFF, 0xFA, 0x28, 0x08, 0x02, 0xFF, 0xF0])
        .await
        .expect("send device type query");

    // 4. Client responds with: IAC SB TN3270E OP_DEVICE_TYPE (2) OP_REQUEST (7) <name> IAC SE
    let n = socket.read(&mut buf).await.expect("read devtype request");
    assert!(n > 0);

    // 5. Server confirms device type (OP_DEVICE_TYPE: 2, OP_IS: 4, "IBM-3278-2-E")
    let mut dev_confirm = vec![
        0xFF, 0xFA, 0x28, 0x02, 0x04, b'I', b'B', b'M', b'-', b'3', b'2', b'7', b'8', b'-', b'2',
        b'-', b'E',
    ];
    if let Some(lu) = assigned_lu {
        dev_confirm.push(0x01); // TN3270E_OP_CONNECT
        dev_confirm.extend_from_slice(lu.as_bytes());
    }
    dev_confirm.extend_from_slice(&[0xFF, 0xF0]);
    socket
        .write_all(&dev_confirm)
        .await
        .expect("confirm devtype");

    // 6. Client responds with: IAC SB TN3270E OP_FUNCTIONS (3) OP_REQUEST (7) ... IAC SE
    let n = socket.read(&mut buf).await.expect("read funcs request");
    assert!(n > 0);

    // 7. Server confirms functions: IAC SB TN3270E OP_FUNCTIONS (3) OP_IS (4) [RESPONSES: 2] IAC SE
    // (no BIND_IMAGE so session is bound immediately!)
    socket
        .write_all(&[0xFF, 0xFA, 0x28, 0x03, 0x04, 0x02, 0xFF, 0xF0])
        .await
        .expect("confirm functions");
}

/// Helper: sends initial EraseWrite record with keyboard unlocked and unprotected field.
async fn mock_send_screen_setup(socket: &mut tokio::net::TcpStream) {
    // TN3270E Header: [0x00, 0x00, 0x00, 0x00, 0x01]
    // 3270 Payload:
    // - 0x05, 0xC3 (EraseWrite, restore keyboard)
    // - 0x1D, 0x00 (SF: unprotected, normal)
    // - 0x13 (IC: cursor at 0, 1)
    // - 0xFF, 0xEF (IAC EOR)
    let screen_setup = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x00, 0x13, 0xFF, 0xEF,
    ];
    socket
        .write_all(&screen_setup)
        .await
        .expect("write screen setup");
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. Extreme Timeouts & Silence Boundaries
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_extreme_timeout_zero_ms_rejection() {
    // 1. ConnectionProfileBuilder with idle_timeout_ms = 0 is rejected by validation
    let err = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(3270)
        .idle_timeout_ms(0)
        .build();
    assert!(
        matches!(err, Err(NetError::Config(msg)) if msg.contains("idle_timeout_ms")),
        "idle_timeout_ms = 0 must be rejected by profile validation"
    );

    // 2. Direct modification with validate() rejection
    let mut profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(3270)
        .build()
        .expect("build default profile");
    profile.idle_timeout_ms = 0;
    assert!(profile.validate().is_err());

    // 3. connect_timeout_ms = 0 is also rejected
    profile.idle_timeout_ms = 5000;
    profile.connect_timeout_ms = 0;
    assert!(profile.validate().is_err());
}

#[tokio::test]
async fn test_extreme_timeout_1ms_silence_expiration() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        // Accept and stay silent (the client sends nothing until asked)
        let mut buf = [0u8; 128];
        let _ = socket.read(&mut buf).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .idle_timeout_ms(1) // 1ms extreme silence timeout
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (_handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let res = tokio::time::timeout(Duration::from_millis(200), join_handle)
        .await
        .expect("must not hang on 1ms timeout")
        .expect("join handle");

    assert!(
        matches!(res, Err(NetError::IdleTimeout)),
        "actor must terminate promptly with NetError::IdleTimeout on 1ms silence"
    );

    let mut got_error_event = false;
    while let Ok(event) = event_rx.try_recv() {
        if let SessionEvent::Error(msg) = event {
            assert!(msg.to_lowercase().contains("timeout"));
            got_error_event = true;
            break;
        }
    }
    assert!(got_error_event, "SessionEvent::Error must be emitted");

    let _ = srv.await;
}

#[tokio::test]
async fn test_extreme_timeout_5ms_silence_expiration() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        mock_send_screen_setup(&mut socket).await;

        // Go completely silent for 100ms
        tokio::time::sleep(Duration::from_millis(1000)).await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .idle_timeout_ms(5) // 5ms silence timeout
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (_handle, _event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let res = tokio::time::timeout(Duration::from_millis(250), join_handle)
        .await
        .expect("coordinator must terminate on 5ms silence")
        .expect("join handle");

    assert!(
        matches!(res, Err(NetError::IdleTimeout)),
        "coordinator actor must exit with IdleTimeout"
    );

    let _ = srv.await;
}

#[tokio::test]
async fn test_extreme_timeout_streaming_host_resets_silence_timer() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Stream 12 packets, one every 10ms. Total streaming duration ~120ms.
        // With an idle_timeout of 60ms, packets arrive well before the 60ms threshold,
        // so the session must stay alive past 60ms throughout streaming.
        for seq in 1..=12u16 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let packet = [
                0x00,
                0x00,
                0x00,
                (seq >> 8) as u8,
                (seq & 0xFF) as u8,
                0x01,
                0xC3, // Write + unlock WCC
                0xFF,
                0xEF,
            ];
            if socket.write_all(&packet).await.is_err() {
                break;
            }
        }

        // Now stop sending and sleep for 120ms, allowing the 60ms silence timeout to trigger
        tokio::time::sleep(Duration::from_millis(120)).await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .idle_timeout_ms(60) // 60ms silence timeout
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // Spawn consumer to prevent event channel backpressure
    let consumer = tokio::spawn(async move {
        let mut count = 0;
        while let Some(evt) = event_rx.recv().await {
            if let SessionEvent::ScreenUpdated(_) = evt {
                count += 1;
            }
        }
        count
    });

    let start = tokio::time::Instant::now();
    let res = tokio::time::timeout(Duration::from_secs(2), join_handle)
        .await
        .expect("actor must terminate after host stops streaming")
        .expect("join handle");

    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(100),
        "session must stay alive during the streaming phase (elapsed: {elapsed:?})"
    );
    assert!(
        matches!(res, Err(NetError::IdleTimeout)),
        "must terminate with IdleTimeout once host goes silent"
    );

    let screen_updates = consumer.await.expect("consumer join");
    assert!(
        screen_updates >= 10,
        "must have processed multiple screen updates during streaming: {screen_updates}"
    );

    assert!(!handle.is_open());
    let _ = srv.await;
}

#[tokio::test]
async fn test_rapid_connect_disconnect_stress_loop() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);

    let srv = tokio::spawn(async move {
        while !stop_srv.load(Ordering::Relaxed) {
            if let Ok(Ok((mut socket, _))) =
                tokio::time::timeout(Duration::from_millis(50), listener.accept()).await
            {
                tokio::spawn(async move {
                    mock_negotiate_tn3270e(&mut socket, None).await;
                    let mut b = [0u8; 64];
                    let _ = socket.read(&mut b).await;
                });
            }
        }
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .idle_timeout_ms(5_000)
        .build()
        .expect("build profile");

    // 15 rapid connect -> wait for negotiation -> immediate disconnect cycles
    for _ in 0..15 {
        let tcp_stream = connect_tcp_stream("127.0.0.1", port)
            .await
            .expect("connect");
        let transport = TransportStream::from_plain(tcp_stream);
        let (handle, mut event_rx, join_handle) =
            SessionCoordinator::spawn(profile.clone(), transport).expect("spawn coordinator");

        // Wait until connected
        while let Some(event) = event_rx.recv().await {
            if let SessionEvent::StateChanged(SessionState::Connected3270) = event {
                break;
            }
        }

        // Immediately disconnect
        handle.disconnect().await.expect("disconnect");
        let res = join_handle.await.expect("join handle");
        assert!(res.is_ok(), "rapid disconnect must return Ok(())");
    }

    stop.store(true, Ordering::Relaxed);
    let _ = srv.await;
}

#[tokio::test]
async fn test_immediate_disconnect_before_negotiation() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut b = [0u8; 64];
        let _ = socket.read(&mut b).await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, _event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // Disconnect before server even responds to Telnet options
    handle.disconnect().await.expect("disconnect");
    let res = tokio::time::timeout(Duration::from_millis(500), join_handle)
        .await
        .expect("immediate disconnect must not hang")
        .expect("join handle");

    assert!(res.is_ok());
    let _ = srv.await;
}

/// The largest timeouts profile validation accepts (`u64::MAX` ms) must neither expire nor
/// break the coordinator: its deadlines are computed with `Instant::checked_add`, and a
/// deadline that cannot be represented disables that timeout instead of panicking.
#[tokio::test]
async fn test_unrepresentably_large_timeouts_never_expire_and_do_not_panic() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut b = [0u8; 64];
        let _ = socket.read(&mut b).await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .idle_timeout_ms(u64::MAX)
        .negotiation_timeout_ms(u64::MAX)
        .build()
        .expect("u64::MAX timeouts pass profile validation");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, _event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // Neither deadline fires: the session is still alive and ends only on disconnect.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!join_handle.is_finished(), "no deadline may expire");
    handle.disconnect().await.expect("disconnect");
    let res = tokio::time::timeout(Duration::from_millis(500), join_handle)
        .await
        .expect("disconnect must not hang")
        .expect("coordinator task must not panic");

    assert!(res.is_ok());
    let _ = srv.await;
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Bounded Channel Saturation & Backpressure
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_channel_capacity_1_sequential_keystroke_stream() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        mock_send_screen_setup(&mut socket).await;

        let mut b = [0u8; 64];
        let _ = socket.read(&mut b).await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .channel_capacity(1) // strictly 1 slot capacity!
        .build()
        .expect("build profile");

    assert_eq!(profile.channel_capacity, 1);

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // Wait until the host's screen setup has been applied
    while let Some(event) = event_rx.recv().await {
        if matches!(event, SessionEvent::ScreenUpdated(_)) {
            break;
        }
    }

    // Background consumer draining event channel
    let event_count = Arc::new(AtomicUsize::new(0));
    let ec = Arc::clone(&event_count);
    let consumer = tokio::spawn(async move {
        while let Some(_) = event_rx.recv().await {
            ec.fetch_add(1, Ordering::Relaxed);
        }
    });

    // Sequentially stream 50 keystrokes through capacity 1 channel
    for i in 0..50 {
        let ch = (b'A' + (i % 26) as u8) as char;
        handle
            .send_key(ch)
            .await
            .expect("send_key under capacity 1");
    }

    // Verify screen content
    let screen = handle.query_screen().await.expect("query screen");
    let text = screen.row_text(0).expect("row 0");
    assert!(
        text.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "streamed keystrokes must appear in screen view under capacity 1"
    );

    handle.disconnect().await.expect("disconnect");
    let res = join_handle.await.expect("join");
    assert!(res.is_ok(), "coordinator must exit cleanly: {:?}", res);
    let _ = consumer.await;
    let _ = srv.await;
}

#[tokio::test]
async fn test_channel_capacity_1_concurrent_task_saturation() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        mock_send_screen_setup(&mut socket).await;

        let mut b = [0u8; 64];
        let _ = socket.read(&mut b).await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .channel_capacity(1) // capacity = 1
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // Background consumer draining event channel
    let consumer = tokio::spawn(async move {
        let mut count = 0;
        while let Some(_) = event_rx.recv().await {
            count += 1;
        }
        count
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 10 concurrent tasks each firing 5 keystrokes
    let barrier = Arc::new(Barrier::new(10));
    let mut tasks = Vec::new();

    for t in 0..10 {
        let h = handle.clone();
        let b = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            b.wait().await;
            for i in 0..5 {
                let ch = (b'0' + ((t * 5 + i) % 10) as u8) as char;
                h.send_key(ch).await.expect("concurrent send_key");
            }
        }));
    }

    // Await all tasks with a safety timeout to catch deadlocks
    tokio::time::timeout(Duration::from_secs(3), async {
        for t in tasks {
            t.await.expect("task join");
        }
    })
    .await
    .expect("concurrent keystrokes must complete without deadlock under capacity 1");

    handle.disconnect().await.expect("disconnect");
    let res = join_handle.await.expect("join");
    assert!(res.is_ok(), "coordinator must exit cleanly: {:?}", res);
    let _ = consumer.await;
    let _ = srv.await;
}

#[tokio::test]
async fn test_channel_capacity_4_backpressure_burst() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        mock_send_screen_setup(&mut socket).await;

        let mut b = [0u8; 64];
        let _ = socket.read(&mut b).await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .channel_capacity(4) // capacity = 4
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let consumer = tokio::spawn(async move {
        let mut count = 0;
        while let Some(_) = event_rx.recv().await {
            count += 1;
        }
        count
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 12 concurrent tasks bursting mixed commands
    let barrier = Arc::new(Barrier::new(12));
    let mut tasks = Vec::new();

    for t in 0..12 {
        let h = handle.clone();
        let b = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            b.wait().await;
            for _ in 0..10 {
                match t % 4 {
                    0 => {
                        let _ = h.send_key('X').await;
                    }
                    1 => {
                        let _ = h.send_action(ActionKey::Tab).await;
                    }
                    2 => {
                        let _ = h.query_status().await;
                    }
                    _ => {
                        let _ = h.query_cursor().await;
                    }
                }
            }
        }));
    }

    tokio::time::timeout(Duration::from_secs(3), async {
        for t in tasks {
            t.await.expect("task join");
        }
    })
    .await
    .expect("mixed command burst must complete without deadlock under capacity 4");

    handle.disconnect().await.expect("disconnect");
    let res = join_handle.await.expect("join");
    assert!(res.is_ok(), "coordinator must exit cleanly: {:?}", res);
    let _ = consumer.await;
    let _ = srv.await;
}

#[tokio::test]
async fn test_dropped_event_receiver_does_not_deadlock() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        mock_send_screen_setup(&mut socket).await;

        // Read AID response
        let mut b = [0u8; 128];
        let n = socket.read(&mut b).await.expect("read aid");
        assert!(n >= 5);
        socket.shutdown().await.expect("shutdown");
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .channel_capacity(1) // capacity = 1
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // DROP event_rx immediately!
    drop(event_rx);

    // Wait until the host's first screen has unlocked the keyboard (typed keys would
    // otherwise be queued as typeahead and not be on the screen yet).
    tokio::time::timeout(Duration::from_secs(2), async {
        while handle.query_keyboard_state().await.expect("query keyboard")
            != bastion3270_core::keyboard::KeyboardState::Unlocked
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("keyboard unlocked");

    // Commands should continue executing without deadlock even though event_tx sends fail
    for ch in ['A', 'D', 'V', 'E', 'R', 'S', 'A', 'R', 'Y'] {
        handle
            .send_key(ch)
            .await
            .expect("send_key with dropped event_rx");
    }

    let screen = handle.query_screen().await.expect("query screen");
    let text = screen.row_text(0).expect("row 0");
    assert!(text.contains("ADVERSARY"));

    handle
        .press_aid(AidKey::Enter)
        .await
        .expect("press aid with dropped event_rx");

    let _ = join_handle.await;
    let _ = srv.await;
}

#[tokio::test]
async fn test_slow_event_receiver_backpressure_throttling() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        mock_send_screen_setup(&mut socket).await;

        let mut b = [0u8; 64];
        let _ = socket.read(&mut b).await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .channel_capacity(2) // capacity = 2
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // Slow consumer: sleeps 2ms before receiving each event
    let slow_consumer = tokio::spawn(async move {
        let mut count = 0;
        while let Some(_) = event_rx.recv().await {
            count += 1;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        count
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send 15 keystrokes; the producer will experience backpressure when capacity is filled
    for ch in "BACKPRESSURE!".chars() {
        handle.send_key(ch).await.expect("throttled send_key");
    }

    let screen = handle.query_screen().await.expect("query screen");
    assert!(screen.row_text(0).expect("row 0").contains("BACKPRESSURE!"));

    handle.disconnect().await.expect("disconnect");
    let res = join_handle.await.expect("join");
    assert!(res.is_ok(), "coordinator must exit cleanly: {:?}", res);
    let _ = slow_consumer.await;
    let _ = srv.await;
}

#[tokio::test]
async fn test_channel_capacity_boundary_zero_rejection() {
    let err = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(3270)
        .channel_capacity(0)
        .build();
    assert!(
        matches!(err, Err(NetError::Config(msg)) if msg.contains("channel_capacity")),
        "channel_capacity = 0 must be rejected"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Concurrency Stress & Stream Splitting
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_concurrency_stress_typing_while_host_continuous_streaming() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        mock_send_screen_setup(&mut socket).await;

        let mut seq = 2u16;
        while !stop_srv.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(1)).await;
            // Write + restore keyboard packet
            let packet = [
                0x00,
                0x00,
                0x00,
                (seq >> 8) as u8,
                (seq & 0xFF) as u8,
                0x01,
                0xC3,
                0xFF,
                0xEF,
            ];
            seq = seq.wrapping_add(1);
            if socket.write_all(&packet).await.is_err() {
                break;
            }
        }
        let _ = socket.shutdown().await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .idle_timeout_ms(5_000)
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let consumer = tokio::spawn(async move { while let Some(_) = event_rx.recv().await {} });

    tokio::time::sleep(Duration::from_millis(30)).await;

    // 5 concurrent client tasks typing and sending actions while host is streaming packets
    let barrier = Arc::new(Barrier::new(5));
    let mut tasks = Vec::new();

    for t in 0..5 {
        let h = handle.clone();
        let b = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            b.wait().await;
            for i in 0..15 {
                let ch = (b'a' + ((t * 15 + i) % 26) as u8) as char;
                let _ = h.send_key(ch).await;
                if i % 3 == 0 {
                    let _ = h.send_action(ActionKey::Tab).await;
                }
            }
        }));
    }

    tokio::time::timeout(Duration::from_secs(4), async {
        for t in tasks {
            t.await.expect("task join");
        }
    })
    .await
    .expect("concurrent typing during streaming host packets must not deadlock");

    stop.store(true, Ordering::Relaxed);
    handle.disconnect().await.expect("disconnect");
    let res = join_handle.await.expect("join");
    assert!(res.is_ok(), "coordinator must exit cleanly: {:?}", res);
    let _ = consumer.await;
    let _ = srv.await;
}

#[tokio::test]
async fn test_concurrency_stress_typing_and_autonomous_positive_response() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let acks_received = Arc::new(AtomicUsize::new(0));
    let acks_srv = Arc::clone(&acks_received);

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        mock_send_screen_setup(&mut socket).await;

        // Host sends 10 records with ALWAYS_RESPONSE (0x02) and verifies positive response
        for seq in 100..110u16 {
            let record = [
                0x00,
                0x00,
                0x02,
                (seq >> 8) as u8,
                (seq & 0xFF) as u8,
                0x01,
                0xC3, // Write + unlock WCC
                0xFF,
                0xEF,
            ];
            socket
                .write_all(&record)
                .await
                .expect("write always_response record");

            // Read 8-byte RFC 2355 positive response
            let mut resp = [0u8; 8];
            socket
                .read_exact(&mut resp)
                .await
                .expect("read positive ack");
            assert_eq!(
                resp,
                [
                    0x02,
                    0x00,
                    0x00,
                    (seq >> 8) as u8,
                    (seq & 0xFF) as u8,
                    0x00,
                    0xFF,
                    0xEF
                ],
                "positive ack must match sequence number {seq}"
            );
            acks_srv.fetch_add(1, Ordering::Relaxed);
        }

        let mut b = [0u8; 64];
        let _ = socket.read(&mut b).await;
        let _ = socket.shutdown().await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let consumer = tokio::spawn(async move { while let Some(_) = event_rx.recv().await {} });

    tokio::time::sleep(Duration::from_millis(30)).await;

    // Concurrently send keystrokes while host is demanding and verifying autonomous responses
    for ch in "AUTONOMOUS-ACK-STRESS".chars() {
        let _ = handle.send_key(ch).await;
    }

    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert_eq!(
        acks_received.load(Ordering::Relaxed),
        10,
        "all 10 autonomous positive responses must be transmitted and verified by host"
    );

    handle.disconnect().await.expect("disconnect");
    let res = join_handle.await.expect("join");
    assert!(res.is_ok(), "coordinator must exit cleanly: {:?}", res);
    let _ = consumer.await;
    let _ = srv.await;
}

#[tokio::test]
async fn test_concurrency_stress_typing_and_wsf_query_reply() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        mock_send_screen_setup(&mut socket).await;

        tokio::time::sleep(Duration::from_millis(30)).await;

        // Host sends Write Structured Field with Read Partition (Query):
        // 0x11 (WSF), structured field: len=5, ID=0x01 (Read Partition), partition=0xFF, type=0x02 (Query)
        let wsf_cmd = [
            0x00, 0x00, 0x00, 0x00, 0x05, 0x11, 0x00, 0x05, 0x01, 0xFF, 0xFF,
            0x02, // 0xFF escaped as IAC IAC
            0xFF, 0xEF,
        ];
        socket.write_all(&wsf_cmd).await.expect("write wsf");

        // Read Query Reply response
        let mut qr_buf = [0u8; 1024];
        let n = socket.read(&mut qr_buf).await.expect("read query reply");
        assert!(n >= 10, "query reply must be received");
        let payload = &qr_buf[5..n];
        // Query Reply AID = 0x88
        assert_eq!(payload[0], 0x88, "query reply must start with AID 0x88");

        let mut b = [0u8; 64];
        let _ = socket.read(&mut b).await;
        let _ = socket.shutdown().await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let consumer = tokio::spawn(async move { while let Some(_) = event_rx.recv().await {} });

    // Client types concurrently while host sends WSF Query
    for ch in "WSF-QUERY-TEST".chars() {
        let _ = handle.send_key(ch).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    handle.disconnect().await.expect("disconnect");
    let res = join_handle.await.expect("join");
    assert!(res.is_ok(), "coordinator must exit cleanly: {:?}", res);
    let _ = consumer.await;
    let _ = srv.await;
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Multiple Handle Clones & Cross-Task Contention
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_multiple_handle_clones_massive_concurrent_queries() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, Some("LUCONCUR")).await;
        mock_send_screen_setup(&mut socket).await;

        let mut b = [0u8; 64];
        let _ = socket.read(&mut b).await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .terminal_model(ProfileTerminalModel::Model2)
        .channel_capacity(64)
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let consumer = tokio::spawn(async move { while let Some(_) = event_rx.recv().await {} });

    // Wait for the negotiated, unlocked session instead of a fixed sleep (under a loaded test
    // run, 50 ms were sometimes not enough).
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = handle.query_status().await.expect("query status");
            if status.assigned_lu.is_some() && status.keyboard_state == KeyboardState::Unlocked {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("negotiation and the first screen must complete");

    // 10 concurrent cloned handles executing multiple query types
    let barrier = Arc::new(Barrier::new(10));
    let mut tasks = Vec::new();

    for _ in 0..10 {
        let h = handle.clone();
        let b = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            b.wait().await;
            for _ in 0..8 {
                let status = h.query_status().await.expect("query status");
                assert_eq!(status.assigned_lu.as_deref(), Some("LUCONCUR"));
                assert!(status.is_tn3270e);

                let view = h.query_screen().await.expect("query screen");
                assert_eq!(view.rows(), 24);
                assert_eq!(view.cols(), 80);

                let kb = h.query_keyboard_state().await.expect("query kb");
                assert_eq!(kb, KeyboardState::Unlocked);

                let (row, col) = h.query_cursor().await.expect("query cursor");
                assert_eq!((row, col), (0, 1));
            }
        }));
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        for t in tasks {
            t.await.expect("task join");
        }
    })
    .await
    .expect("massive concurrent queries must complete without deadlock or corruption");

    handle.disconnect().await.expect("disconnect");
    let res = join_handle.await.expect("join");
    assert!(res.is_ok(), "coordinator must exit cleanly: {:?}", res);
    let _ = consumer.await;
    let _ = srv.await;
}

#[tokio::test]
async fn test_concurrent_handle_disconnect_race_with_in_flight_commands() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        mock_send_screen_setup(&mut socket).await;

        let mut b = [0u8; 64];
        let _ = socket.read(&mut b).await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let consumer = tokio::spawn(async move { while let Some(_) = event_rx.recv().await {} });

    tokio::time::sleep(Duration::from_millis(30)).await;

    // 10 tasks hammering keystrokes
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let h = handle.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..50 {
                if h.send_key('Z').await.is_err() {
                    // Command dropped or actor terminated — expected once disconnected
                    break;
                }
            }
        }));
    }

    // Racing disconnect from separate task
    let h_disc = handle.clone();
    let disc_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(5)).await;
        let _ = h_disc.disconnect().await;
    });

    tokio::time::timeout(Duration::from_secs(3), async {
        let _ = disc_task.await;
        for t in tasks {
            let _ = t.await;
        }
    })
    .await
    .expect("racing disconnect must cleanly resolve in-flight tasks without deadlocks");

    let res = join_handle.await.expect("join handle");
    assert!(res.is_ok(), "clean disconnect returns Ok");
    let _ = consumer.await;
    let _ = srv.await;
}

#[tokio::test]
async fn test_abrupt_host_rst_under_heavy_concurrency() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        mock_send_screen_setup(&mut socket).await;

        tokio::time::sleep(Duration::from_millis(20)).await;
        // Abruptly close socket without clean shutdown
        drop(socket);
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let consumer = tokio::spawn(async move { while let Some(_) = event_rx.recv().await {} });

    // 8 concurrent tasks sending commands while host drops connection
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let h = handle.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..30 {
                tokio::time::sleep(Duration::from_millis(2)).await;
                if h.send_key('Q').await.is_err() {
                    break;
                }
            }
        }));
    }

    // Coordinator actor must terminate cleanly on EOF / connection reset
    let join_res = tokio::time::timeout(Duration::from_secs(3), join_handle)
        .await
        .expect("actor must exit on abrupt host RST")
        .expect("join handle");

    // Clean EOF or IO error are both acceptable depending on TCP timing
    assert!(
        join_res.is_ok() || matches!(join_res, Err(NetError::Io(_))),
        "actor should terminate with Ok(()) or NetError::Io on abrupt RST"
    );

    for t in tasks {
        let _ = t.await;
    }

    let _ = consumer.await;
    let _ = srv.await;
}

/// A host that stops reading (zero TCP window) while it keeps asking for replies must end the
/// session with a write timeout. The session loop awaits its writes inline, so without a write
/// deadline the loop blocks forever: no idle timeout, no disconnect, the session never ends.
#[tokio::test]
async fn test_host_that_stops_reading_ends_the_session_with_a_write_timeout() {
    // Small socket buffers on both sides, so a few replies fill them.
    let host_socket = tokio::net::TcpSocket::new_v4().expect("socket");
    host_socket.set_recv_buffer_size(4096).expect("rcvbuf");
    host_socket
        .bind("127.0.0.1:0".parse().expect("addr"))
        .expect("bind");
    let port = host_socket.local_addr().expect("local addr").port();
    let listener = host_socket.listen(1).expect("listen");

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        // TN3270E 3270-DATA record: Read Buffer (0xF2). Each reply is a whole screen buffer.
        let read_buffer = [0x00, 0x00, 0x00, 0x00, 0x00, 0xF2, 0xFF, 0xEF];
        // Never read again; stop when the client side is gone.
        while socket.write_all(&read_buffer).await.is_ok() {}
    });

    let client_socket = tokio::net::TcpSocket::new_v4().expect("socket");
    client_socket.set_send_buffer_size(4096).expect("sndbuf");
    let tcp = client_socket
        .connect(format!("127.0.0.1:{port}").parse().expect("addr"))
        .await
        .expect("connect");
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .idle_timeout_ms(30_000) // far away: it must not be what ends the session
        .write_timeout_ms(200)
        .build()
        .expect("build profile");
    let (_handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, TransportStream::from_plain(tcp))
            .expect("spawn coordinator");
    let consumer = tokio::spawn(async move { while event_rx.recv().await.is_some() {} });

    let res = tokio::time::timeout(Duration::from_secs(5), join_handle)
        .await
        .expect("a host that stops reading must not block the session forever")
        .expect("join handle");
    assert!(
        matches!(res, Err(NetError::WriteTimeout)),
        "must end with WriteTimeout, got {res:?}"
    );
    consumer.abort();
    srv.abort();
}

/// A host that keeps a session negotiating by trickling Telnet NOPs must not hold it forever:
/// the negotiation deadline is not extended by host traffic.
#[tokio::test]
async fn test_host_that_never_completes_negotiation_hits_the_negotiation_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        // IAC NOP every 20 ms: keeps the idle timer alive, never negotiates.
        while socket.write_all(&[0xFF, 0xF1]).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .idle_timeout_ms(30_000)
        .negotiation_timeout_ms(200)
        .build()
        .expect("build profile");
    let tcp = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let (_handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, TransportStream::from_plain(tcp))
            .expect("spawn coordinator");
    let consumer = tokio::spawn(async move { while event_rx.recv().await.is_some() {} });

    let res = tokio::time::timeout(Duration::from_secs(5), join_handle)
        .await
        .expect("negotiation must not last forever")
        .expect("join handle");
    assert!(
        matches!(res, Err(NetError::NegotiationTimeout)),
        "must end with NegotiationTimeout, got {res:?}"
    );
    consumer.abort();
    srv.abort();
}
