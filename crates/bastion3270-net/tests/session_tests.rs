//! Integration and end-to-end tests for [`SessionCoordinator`], [`SessionHandle`],
//! lifecycle states, backpressure channels, autonomous responses, and Zero-Trust `SafeScreenView`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use bastion3270_core::keyboard::{ActionKey, AidKey, KeyboardState};
use bastion3270_net::profile::{ConnectionProfileBuilder, ProfileTerminalModel, TlsMode};
use bastion3270_net::session::{SessionCoordinator, SessionEvent, SessionHandle, SessionState};
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

#[tokio::test]
async fn test_session_lifecycle_and_tn3270e_negotiation() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, Some("LU3270A")).await;

        tokio::time::sleep(Duration::from_millis(100)).await;
        socket.shutdown().await.expect("shutdown");
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .terminal_model(ProfileTerminalModel::Model2)
        .idle_timeout_ms(5_000)
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);

    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // Read events until NegotiationComplete
    let mut neg_complete = false;
    let mut state_connected = false;
    while let Some(event) = event_rx.recv().await {
        match event {
            SessionEvent::StateChanged(SessionState::Connected3270) => {
                state_connected = true;
            }
            SessionEvent::NegotiationComplete {
                is_tn3270e,
                assigned_lu,
            } => {
                assert!(is_tn3270e);
                assert_eq!(assigned_lu.as_deref(), Some("LU3270A"));
                neg_complete = true;
                break;
            }
            _ => {}
        }
    }
    assert!(neg_complete);
    assert!(state_connected);

    let status = handle.query_status().await.expect("query status");
    assert_eq!(status.state, SessionState::Connected3270);
    assert_eq!(status.assigned_lu.as_deref(), Some("LU3270A"));
    assert!(status.is_tn3270e);
    assert!(!status.is_tls);
    assert_eq!(status.terminal_model, ProfileTerminalModel::Model2);

    let _ = srv.await;
    let _ = join_handle.await;
}

#[tokio::test]
async fn test_autonomous_tn3270e_positive_response() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Host sends TN3270E Data3270 record requiring positive response (seq 0x0042):
        // Header: [data_type: 0x00 (Data3270), req: 0x00, resp: 0x02 (ALWAYS_RESPONSE), seq: 0x00, 0x42]
        // Payload: [0x05, 0xC3] (EraseWrite, restore keyboard)
        // Telnet: [0xFF, 0xEF] (IAC EOR)
        let host_record = [0x00, 0x00, 0x02, 0x00, 0x42, 0x05, 0xC3, 0xFF, 0xEF];
        socket
            .write_all(&host_record)
            .await
            .expect("write host record");

        // Host expects autonomous TN3270E positive response:
        // [0x02, 0x00, 0x00, 0x00, 0x42, 0x00, 0xFF, 0xEF]
        let mut resp_buf = [0u8; 8];
        socket
            .read_exact(&mut resp_buf)
            .await
            .expect("read positive response");
        assert_eq!(
            &resp_buf,
            &[0x02, 0x00, 0x00, 0x00, 0x42, 0x00, 0xFF, 0xEF],
            "TN3270E positive response must match sequence number 0x0042"
        );

        socket.shutdown().await.expect("shutdown");
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

    // Await screen update event triggered by host record
    let mut got_screen_update = false;
    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::ScreenUpdated(_) = event {
            got_screen_update = true;
            break;
        }
    }
    assert!(got_screen_update);

    let kb_state = handle
        .query_keyboard_state()
        .await
        .expect("query keyboard state");
    assert_eq!(kb_state, KeyboardState::Unlocked);

    let _ = srv.await;
    let _ = join_handle.await;
}

#[tokio::test]
async fn test_autonomous_wsf_query_reply() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Host sends WSF command with SF_READ_PART:
        // TN3270E Header: [0x00, 0x00, 0x00, 0x00, 0x01] (no response requested)
        // 3270 Payload:
        // - 0x11 (CMD_WSF)
        // - 0x00, 0x05 (length 5)
        // - 0x01 (SF_READ_PART)
        // - 0xFF (partition) — escaped on the wire as IAC IAC (0xFF, 0xFF) per RFC 854
        // - 0x02 (query type: Query)
        // Telnet: 0xFF, 0xEF (IAC EOR)
        let wsf_cmd = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x00, 0x05, 0x01, 0xFF, 0xFF, 0x02, 0xFF, 0xEF,
        ];
        socket.write_all(&wsf_cmd).await.expect("write wsf command");

        // Host reads Query Reply from client
        let mut qr_buf = [0u8; 1024];
        let n = socket.read(&mut qr_buf).await.expect("read query reply");
        assert!(n > 10, "query reply must be a substantial response");

        // In TN3270E mode, first 5 bytes are TN3270E header
        let payload = &qr_buf[5..n];
        // Query Reply envelope begins with AID_SF (0x88)
        assert_eq!(payload[0], 0x88, "reply must start with AID_SF (0x88)");
        // Last 2 bytes before payload end are IAC EOR (0xFF, 0xEF)
        let last2 = &payload[payload.len() - 2..];
        assert_eq!(last2, &[0xFF, 0xEF], "reply must terminate with IAC EOR");

        socket.shutdown().await.expect("shutdown");
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
    let (_handle, _event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    srv.await
        .expect("mock host assertions must pass (Query Reply received)");
    let _ = join_handle.await;
}

/// Regression (x3270 conformance): a malformed structured field after a Query must not end
/// the session. The query is still answered; because a reply was produced, no negative response
/// follows (x3270 `process_eor()` only NAKs when there was no output), and the next record is
/// processed normally.
#[tokio::test]
async fn test_wsf_malformed_field_after_query_keeps_session() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // TN3270E 3270-DATA, ALWAYS-RESPONSE, seq 7: WSF [Query] [field of length 2]
        let wsf = [
            0x00, 0x00, 0x02, 0x00, 0x07, 0xF3, 0x00, 0x05, 0x01, 0xFF, 0xFF, 0x02, 0x00, 0x02,
            0x03, 0xFF, 0xEF,
        ];
        socket.write_all(&wsf).await.expect("write wsf");

        // ALWAYS-RESPONSE with output: the positive response comes first, before the query
        // reply (x3270 `net_output`), and no negative response follows for the bad field.
        let mut ack = [0u8; 8];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.read_exact(&mut ack),
        )
        .await
        .expect("response must arrive")
        .expect("read response");
        assert_eq!(&ack, &[0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0xFF, 0xEF]);
        let mut buf = [0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), socket.read(&mut buf))
            .await
            .expect("query reply must arrive")
            .expect("read query reply");
        assert!(n > 10);
        assert_eq!(buf[0], 0x00, "3270-DATA header, not a RESPONSE record");
        assert_eq!(buf[5], 0x88, "query reply starts with AID_SF");

        // Next record: a valid Write with ALWAYS-RESPONSE seq 8 → positive response only
        socket
            .write_all(&[0x00, 0x00, 0x02, 0x00, 0x08, 0xF1, 0xC2, 0xFF, 0xEF])
            .await
            .expect("write valid record");
        let mut resp = [0u8; 8];
        socket.read_exact(&mut resp).await.expect("read response");
        assert_eq!(&resp, &[0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0xFF, 0xEF]);

        socket.shutdown().await.expect("shutdown");
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
    let (_handle, _event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    srv.await.expect("mock host assertions must pass");
    let res = join_handle.await.expect("join handle");
    assert!(
        res.is_ok(),
        "session must survive the malformed field: {res:?}"
    );
}

/// Regression (z/OS): the Read Partition Query is not the first structured
/// field of the WSF. The terminal must still answer it, otherwise the host waits forever and
/// the keyboard stays locked.
#[tokio::test]
async fn test_wsf_query_after_erase_reset_is_answered() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // TN3270E header + WSF (0xF3) with two structured fields:
        //   [00 04 03 00]  Erase/Reset (default size)
        //   [00 05 01 FF 02] Read Partition Query (0xFF escaped as IAC IAC)
        let wsf_cmd = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0xF3, 0x00, 0x04, 0x03, 0x00, 0x00, 0x05, 0x01, 0xFF,
            0xFF, 0x02, 0xFF, 0xEF,
        ];
        socket.write_all(&wsf_cmd).await.expect("write wsf command");

        let mut qr_buf = [0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), socket.read(&mut qr_buf))
            .await
            .expect("query reply must arrive (no hang)")
            .expect("read query reply");
        assert!(n > 10, "query reply must be a substantial response");
        assert_eq!(qr_buf[5], 0x88, "reply must start with AID_SF (0x88)");

        socket.shutdown().await.expect("shutdown");
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
    let (_handle, _event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    srv.await
        .expect("mock host assertions must pass (Query Reply received)");
    let _ = join_handle.await;
}

#[tokio::test]
async fn test_virtual_keyboard_keystrokes_and_read_modified_aid() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Host sends EraseWrite creating an unprotected field at row 0, col 0:
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

        // Wait for client to send AID response
        let mut read_buf = [0u8; 256];
        let n = socket.read(&mut read_buf).await.expect("read aid response");
        assert!(n >= 5, "aid response must have TN3270E header + 3270 data");

        let payload = &read_buf[5..n];
        // Read Modified AID Enter = 0x7D
        assert_eq!(payload[0], 0x7D, "AID byte must be Enter (0x7D)");
        // Must contain EBCDIC bytes for "TEST" = [0xE3, 0xC5, 0xE2, 0xE3]
        assert!(
            payload.windows(4).any(|w| w == [0xE3, 0xC5, 0xE2, 0xE3]),
            "Read Modified datastream must contain typed EBCDIC characters 'TEST'"
        );

        socket.shutdown().await.expect("shutdown");
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

    // Wait for screen update from host setup
    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::ScreenUpdated(_) = event {
            break;
        }
    }

    // Type "TEST"
    handle.send_string("TEST").await.expect("send_string TEST");

    // Query screen view to verify typed characters locally
    let view = handle.query_screen().await.expect("query screen");
    let plain = view.row_text(0).expect("row text 0");
    assert!(
        plain.contains("TEST"),
        "safe view should display typed text"
    );

    // Press Enter
    handle
        .press_aid(AidKey::Enter)
        .await
        .expect("press aid enter");

    // Keyboard must now be locked in TimeWait (X Wait)
    let kb = handle.query_keyboard_state().await.expect("query kb");
    assert_eq!(kb, KeyboardState::TimeWait);

    let _ = srv.await;
    let _ = join_handle.await;
}

#[tokio::test]
async fn test_zero_trust_password_masking_security() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Host setup:
        // - EraseWrite (0x05, 0xC3)
        // - SF 0x20 (protected): "PASS: " (EBCDIC: 0xD7, 0xC1, 0xE2, 0xE2, 0x7A, 0x40)
        // - SF 0x0C (unprotected, NonDisplay)
        // - IC (insert cursor into password field)
        // - IAC EOR
        let screen_setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x20, 0xD7, 0xC1, 0xE2, 0xE2, 0x7A,
            0x40, 0x1D, 0x0C, 0x13, 0xFF, 0xEF,
        ];
        socket.write_all(&screen_setup).await.expect("write setup");

        // Read client AID response
        let mut read_buf = [0u8; 256];
        let n = socket.read(&mut read_buf).await.expect("read aid");
        let payload = &read_buf[5..n];

        // Mainframe verifies it DOES receive the raw EBCDIC password bytes:
        // "SECRET" = [0xE2, 0xC5, 0xC3, 0xD9, 0xC5, 0xE3]
        assert!(
            payload
                .windows(6)
                .any(|w| w == [0xE2, 0xC5, 0xC3, 0xD9, 0xC5, 0xE3]),
            "host must receive raw EBCDIC password bytes in Read Modified record"
        );

        socket.shutdown().await.expect("shutdown");
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

    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::ScreenUpdated(_) = event {
            break;
        }
    }

    // Type secret password into the non-display field
    handle.send_string("SECRET").await.expect("send password");

    // ZERO-TRUST VERIFICATION: SafeScreenView must NEVER contain "SECRET"!
    let safe_view = handle.query_screen().await.expect("query screen");
    let row_text = safe_view.row_text(0).expect("row text 0");
    assert!(
        !row_text.contains("SECRET"),
        "CRITICAL SECURITY: SafeScreenView MUST NOT leak password characters!"
    );

    // Verify individual cell masking: characters must be masked to space ' '
    for col in 8..14 {
        let cell = safe_view.cell_at(0, col).expect("cell at col");
        assert_eq!(cell.ch, ' ', "cell character must be masked to space ' '");
        assert!(cell.is_blank(), "non-display cell must report as blank");
    }

    // Now press Enter and let host verify wire delivery
    handle
        .press_aid(AidKey::Enter)
        .await
        .expect("press aid enter");

    let _ = srv.await;
    let _ = join_handle.await;
}

#[tokio::test]
async fn test_silence_idle_timeout_expiration() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        // Accept and stay completely silent (the client sends nothing until asked)
        let mut buf = [0u8; 128];
        let _ = socket.read(&mut buf).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .idle_timeout_ms(60) // short silence timeout: 60ms
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (_handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // Await coordinator task completion
    let res = join_handle.await.expect("join handle");
    assert!(
        matches!(res, Err(NetError::IdleTimeout)),
        "actor should terminate with IdleTimeout error"
    );

    // Verify Error event was emitted
    let mut got_err_event = false;
    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::Error(_) = event {
            got_err_event = true;
            break;
        }
    }
    assert!(got_err_event, "error event must be emitted on timeout");

    let _ = srv.await;
}

#[tokio::test]
async fn test_graceful_client_disconnect() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 128];
        let _ = socket.read(&mut buf).await;
        // Keep alive until client closes
        let _ = socket.read(&mut buf).await;
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

    // Request client disconnect
    handle.disconnect().await.expect("disconnect");

    let res = join_handle.await.expect("join handle");
    assert!(res.is_ok(), "clean disconnect should return Ok(())");

    let mut got_disconnected_event = false;
    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::Disconnected = event {
            got_disconnected_event = true;
            break;
        }
    }
    assert!(got_disconnected_event);

    let _ = srv.await;
}

#[tokio::test]
async fn test_remote_host_eof() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        // Host immediately shuts down (clean EOF)
        socket.shutdown().await.expect("shutdown");
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
    let (_handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let res = join_handle.await.expect("join handle");
    assert!(res.is_ok(), "clean remote EOF should exit with Ok(())");

    let mut got_disconnected_event = false;
    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::Disconnected = event {
            got_disconnected_event = true;
            break;
        }
    }
    assert!(got_disconnected_event);

    let _ = srv.await;
}

#[tokio::test]
async fn test_protected_field_rejection_and_reset() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // EraseWrite with protected field:
        // SF: 0x20 (protected)
        let screen_setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x20, 0x13, 0xFF, 0xEF,
        ];
        socket.write_all(&screen_setup).await.expect("write setup");

        tokio::time::sleep(Duration::from_millis(100)).await;
        socket.shutdown().await.expect("shutdown");
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

    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::ScreenUpdated(_) = event {
            break;
        }
    }

    // Typing into protected field MUST return error and lock keyboard into Protected
    let err = handle.send_key('Z').await;
    assert!(err.is_err(), "must reject typing into protected field");

    let kb = handle.query_keyboard_state().await.expect("query kb");
    assert_eq!(kb, KeyboardState::Protected);

    // Operator Reset clears the lock
    handle.send_action(ActionKey::Reset).await.expect("reset");
    let kb_after = handle
        .query_keyboard_state()
        .await
        .expect("query kb after reset");
    assert_eq!(kb_after, KeyboardState::Unlocked);

    let _ = srv.await;
    let _ = join_handle.await;
}

#[tokio::test]
async fn test_short_read_aids() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // EraseWrite unlock keyboard
        let screen_setup = [0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0xFF, 0xEF];
        socket.write_all(&screen_setup).await.expect("write setup");

        // Read short-read Clear AID
        let mut read_buf = [0u8; 64];
        let n = socket.read(&mut read_buf).await.expect("read clear aid");
        let payload = &read_buf[5..n];
        // Short-read AID contains ONLY the AID byte (0x6D for Clear) followed by IAC EOR
        assert_eq!(payload, &[0x6D, 0xFF, 0xEF]);

        socket.shutdown().await.expect("shutdown");
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

    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::ScreenUpdated(_) = event {
            break;
        }
    }

    handle.press_aid(AidKey::Clear).await.expect("press clear");

    let _ = srv.await;
    let _ = join_handle.await;
}

#[tokio::test]
async fn test_alarm_and_nvt_data_events() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Host sends TN3270E NVT-DATA record:
        // Header: [0x05 (NvtData), 0x00, 0x00, 0x00, 0x01]
        // Payload: b"IBM VM/ESA LOGIN BANNER"
        // Telnet: [0xFF, 0xEF] (IAC EOR)
        let mut nvt_record = vec![0x05, 0x00, 0x00, 0x00, 0x01];
        nvt_record.extend_from_slice(b"IBM VM/ESA LOGIN BANNER");
        nvt_record.extend_from_slice(&[0xFF, 0xEF]);
        socket.write_all(&nvt_record).await.expect("write nvt");

        // Host sends EraseWrite with sound_alarm bit set (0x04) in WCC: 0xC3 | 0x04 = 0xC7
        let alarm_record = [0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0xC7, 0xFF, 0xEF];
        socket.write_all(&alarm_record).await.expect("write alarm");

        tokio::time::sleep(Duration::from_millis(50)).await;
        socket.shutdown().await.expect("shutdown");
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
    let (_handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let mut got_nvt = false;
    let mut got_alarm = false;

    while let Some(event) = event_rx.recv().await {
        match event {
            SessionEvent::NvtData(data) => {
                let s = String::from_utf8_lossy(&data);
                if s.contains("IBM VM/ESA") {
                    got_nvt = true;
                }
            }
            SessionEvent::Alarm => {
                got_alarm = true;
                break;
            }
            _ => {}
        }
    }

    assert!(got_nvt, "should receive NVT data event for ASCII banner");
    assert!(got_alarm, "should receive Alarm event from WCC");

    let _ = srv.await;
    let _ = join_handle.await;
}

#[tokio::test]
async fn test_coordinator_accessors() {
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(3270)
        .tls_mode(TlsMode::Disabled)
        .terminal_model(ProfileTerminalModel::Model3)
        .build()
        .expect("build profile");

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(16);
    let (evt_tx, _evt_rx) = tokio::sync::mpsc::channel(16);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let srv = tokio::spawn(async move {
        let (s, _) = listener.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(s);
    });

    let tcp = connect_tcp_stream("127.0.0.1", port).await.expect("tcp");
    let transport = TransportStream::from_plain(tcp);

    let coordinator = SessionCoordinator::new(profile.clone(), transport, cmd_rx, evt_tx)
        .expect("new coordinator");

    assert_eq!(coordinator.state(), &SessionState::Connecting);
    assert_eq!(coordinator.presentation_space().rows(), 24);
    assert_eq!(coordinator.presentation_space().cols(), 80);
    // Not running yet: no connection, keyboard locked (x3270 starts `KL_NOT_CONNECTED`).
    assert_eq!(coordinator.keyboard().state(), KeyboardState::NotConnected);
    assert_eq!(
        coordinator.profile().terminal_model,
        ProfileTerminalModel::Model3
    );
    assert!(!coordinator.is_tls());

    let handle = SessionHandle::new(cmd_tx);
    assert!(handle.is_open());

    let _ = srv.await;
}

#[tokio::test]
async fn test_read_buffer_and_read_modified_host_commands() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // 1. Host sends ReadBuffer command (opcode 0x02)
        let read_buf_cmd = [0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0xFF, 0xEF];
        socket
            .write_all(&read_buf_cmd)
            .await
            .expect("write read buffer cmd");

        // Host reads ReadBuffer response
        let mut buf = [0u8; 256];
        let n = socket.read(&mut buf).await.expect("read rb response");
        assert!(
            n >= 8,
            "ReadBuffer response must contain TN3270E header + 3270 stream"
        );
        let payload = &buf[5..n];
        assert_eq!(
            payload[0], 0x60,
            "ReadBuffer stream must begin with AID_NO (0x60)"
        );

        // 2. Host sends ReadModified command (opcode 0x06)
        let read_mod_cmd = [0x00, 0x00, 0x00, 0x00, 0x02, 0x06, 0xFF, 0xEF];
        socket
            .write_all(&read_mod_cmd)
            .await
            .expect("write read modified cmd");

        let n = socket.read(&mut buf).await.expect("read rm response");
        assert!(n >= 5, "ReadModified response received");

        socket.shutdown().await.expect("shutdown");
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
    let (_handle, _event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let _ = srv.await;
    let _ = join_handle.await;
}

#[tokio::test]
async fn test_negative_response_on_invalid_3270_datastream() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Host sends record with ALWAYS_RESPONSE (0x02) and seq 0x0055,
        // but with an INVALID 3270 opcode: 0x99!
        let bad_cmd = [
            0x00, 0x00, 0x02, 0x00, 0x55, 0x99, // invalid opcode
            0xFF, 0xEF,
        ];
        socket.write_all(&bad_cmd).await.expect("write bad cmd");

        // Host expects TN3270E Negative Response per RFC 2355 (unknown command = COMMAND-REJECT,
        // x3270 PDS_BAD_CMD):
        // [data_type: 0x02 (Response), req: 0x00, resp: 0x01 (NEGATIVE_RESPONSE), seq_hi: 0x00, seq_lo: 0x55, code: 0x00 (COMMAND_REJECT), IAC, EOR]
        let mut resp_buf = [0u8; 8];
        socket
            .read_exact(&mut resp_buf)
            .await
            .expect("read negative response");
        assert_eq!(
            &resp_buf,
            &[0x02, 0x00, 0x01, 0x00, 0x55, 0x00, 0xFF, 0xEF],
            "must emit negative response with COMMAND_REJECT on invalid datastream"
        );

        socket.shutdown().await.expect("shutdown");
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
    let (_handle, _event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // The rejected record is reported to the host but does not end the session
    let res = join_handle.await.expect("join handle");
    assert!(
        res.is_ok(),
        "a rejected record must not end the session: {res:?}"
    );

    let _ = srv.await;
}

#[tokio::test]
async fn test_erase_write_alternate_model_dimensions() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // 1. Host sends EraseWriteAlternate (0x0D / EWA): switches Model 4 to 43x80
        let ewa_record = [0x00, 0x00, 0x00, 0x00, 0x01, 0x0D, 0xC3, 0xFF, 0xEF];
        socket.write_all(&ewa_record).await.expect("write ewa");

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 2. Host sends EraseWrite (0x05 / EW): resets back to default 24x80
        let reset_record = [0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0xC3, 0xFF, 0xEF];
        socket.write_all(&reset_record).await.expect("write ew");

        tokio::time::sleep(Duration::from_millis(50)).await;
        socket.shutdown().await.expect("shutdown");
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .terminal_model(ProfileTerminalModel::Model4) // Model 4: 24x80 default, 43x80 alternate
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // Wait for EWA screen update
    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::ScreenUpdated(view) = event {
            if view.rows() == 43 {
                assert_eq!(
                    view.rows(),
                    43,
                    "EWA must expand rows to alternate dimensions (43)"
                );
                assert_eq!(view.cols(), 80);
                break;
            }
        }
    }

    // Wait for EW screen update (resets to 24x80)
    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::ScreenUpdated(view) = event {
            if view.rows() == 24 {
                assert_eq!(
                    view.rows(),
                    24,
                    "EW must restore rows to default dimensions (24)"
                );
                assert_eq!(view.cols(), 80);
                break;
            }
        }
    }

    let status = handle.query_status().await.expect("query status");
    assert_eq!(status.terminal_model, ProfileTerminalModel::Model4);

    let _ = srv.await;
    let _ = join_handle.await;
}

#[tokio::test]
async fn test_keyboard_navigation_tab_home_newline() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Setup 2 unprotected fields:
        // Field 1 at (0, 0), data at (0, 1)
        // SBA to 90 -> row 1 col 10: 14-bit [0x00, 0x5A]
        // Field 2 at (1, 10), data at (1, 11)
        // SBA to 1 -> row 0 col 1: 14-bit [0x00, 0x01]
        // IC: insert cursor at (0, 1)
        let screen_setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x00, // SF at (0, 0)
            0x11, 0x00, 0x5A, // SBA 90 -> (1, 10)
            0x1D, 0x00, // SF at (1, 10)
            0x11, 0x00, 0x01, // SBA 1 -> (0, 1)
            0x13, // IC
            0xFF, 0xEF,
        ];
        socket.write_all(&screen_setup).await.expect("write setup");

        // Keep connection alive until client finishes
        let mut buf = [0u8; 128];
        let _ = socket.read(&mut buf).await;
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

    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::ScreenUpdated(_) = event {
            break;
        }
    }

    // Initial cursor is at (0, 1)
    let (r, c) = handle.query_cursor().await.expect("cursor");
    assert_eq!((r, c), (0, 1));

    // Tab -> jumps to next field at (1, 11)
    handle.send_action(ActionKey::Tab).await.expect("tab");
    let (r, c) = handle.query_cursor().await.expect("cursor after tab");
    assert_eq!((r, c), (1, 11));

    // BackTab -> jumps back to first field at (0, 1)
    handle
        .send_action(ActionKey::BackTab)
        .await
        .expect("backtab");
    let (r, c) = handle.query_cursor().await.expect("cursor after backtab");
    assert_eq!((r, c), (0, 1));

    // Tab then Home -> jumps back to first unprotected field at (0, 1)
    handle.send_action(ActionKey::Tab).await.expect("tab");
    handle.send_action(ActionKey::Home).await.expect("home");
    let (r, c) = handle.query_cursor().await.expect("cursor after home");
    assert_eq!((r, c), (0, 1));

    handle.disconnect().await.expect("disconnect");
    let _ = srv.await;
    let _ = join_handle.await;
}

#[tokio::test]
async fn test_bounded_channel_backpressure_and_capacity() {
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(3270)
        .tls_mode(TlsMode::Disabled)
        .channel_capacity(8) // bounded capacity
        .build()
        .expect("build profile");

    assert_eq!(profile.channel_capacity, 8);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let srv = tokio::spawn(async move {
        let (s, _) = listener.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(s);
    });

    let tcp = connect_tcp_stream("127.0.0.1", port).await.expect("tcp");
    let transport = TransportStream::from_plain(tcp);
    let (handle, _event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    assert!(handle.is_open());
    let _ = handle.disconnect().await;
    let _ = join_handle.await;
    let _ = srv.await;
}

/// Regression: a subscriber that stops reading for longer than the actor's 50 ms send
/// deadline must still end up with the current session state. While the bounded event
/// channel is full the actor drops events (it never blocks on a slow subscriber); once the
/// subscriber reads again the actor re-sends a snapshot of every state event (lifecycle,
/// negotiation, host mode, screen, keyboard, insert mode), so the last screen is never lost.
#[tokio::test]
async fn test_stalled_subscriber_receives_the_current_state_after_dropped_events() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, Some("LUSTALL1")).await;
        // Two screens, both restoring the keyboard: EraseWrite, WCC 0xC3, SF protected, text.
        // "ONE" = D6 D5 C5, "TWO" = E3 E6 D6 (EBCDIC CP037).
        let one = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x20, 0xD6, 0xD5, 0xC5, 0xFF, 0xEF,
        ];
        let two = [
            0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0xC3, 0x1D, 0x20, 0xE3, 0xE6, 0xD6, 0xFF, 0xEF,
        ];
        socket.write_all(&one).await.expect("write one");
        tokio::time::sleep(Duration::from_millis(20)).await;
        socket.write_all(&two).await.expect("write two");
        // Keep the session open until the subscriber has seen everything.
        let _ = done_rx.await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .terminal_model(ProfileTerminalModel::Model2)
        .channel_capacity(1)
        .idle_timeout_ms(10_000)
        .build()
        .expect("build profile");
    let tcp = connect_tcp_stream("127.0.0.1", port).await.expect("tcp");
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, TransportStream::from_plain(tcp))
            .expect("spawn coordinator");

    // The subscriber stalls: the actor fills the one slot and drops what follows.
    tokio::time::sleep(Duration::from_millis(600)).await;

    let mut last_screen = None;
    let mut last_keyboard = None;
    let mut last_state = None;
    let mut lu = None;
    while let Ok(Some(event)) =
        tokio::time::timeout(Duration::from_millis(300), event_rx.recv()).await
    {
        match event {
            SessionEvent::ScreenUpdated(view) => {
                // Column 0 holds the field attribute (shown as a blank).
                last_screen = view.row_text_trimmed(0).map(|t| t.trim_start().to_string());
            }
            SessionEvent::KeyboardStateChanged(kb) => last_keyboard = Some(kb),
            SessionEvent::StateChanged(state) => last_state = Some(state),
            SessionEvent::NegotiationComplete { assigned_lu, .. } => lu = assigned_lu,
            _ => {}
        }
    }

    assert_eq!(
        last_screen.as_deref(),
        Some("TWO"),
        "the last host screen was lost"
    );
    assert_eq!(last_keyboard, Some(KeyboardState::Unlocked));
    assert_eq!(last_state, Some(SessionState::Connected3270));
    assert_eq!(lu.as_deref(), Some("LUSTALL1"));

    let _ = done_tx.send(());
    handle.disconnect().await.expect("disconnect");
    let _ = join_handle.await;
    let _ = srv.await;
}
