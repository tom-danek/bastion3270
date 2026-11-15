//! Adversarial integration tests for the session coordinator:
//! Protocol edge cases, malformed datastreams, RFC 2355 negative responses,
//! and Zero-Trust password masking penetration testing.

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
    clippy::unreadable_literal
)]

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use bastion3270_core::keyboard::{ActionKey, AidKey, KeyboardState};
use bastion3270_net::profile::{ConnectionProfileBuilder, ProfileTerminalModel, TlsMode};
use bastion3270_net::session::{SessionCoordinator, SessionEvent, SessionState};
use bastion3270_net::transport::{connect_tcp_stream, TransportStream};

/// Helper: performs complete TN3270E option negotiation on mock server socket for a given model.
async fn mock_negotiate_tn3270e_model(
    socket: &mut tokio::net::TcpStream,
    assigned_lu: Option<&str>,
    model_name: &str,
) {
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

    // 5. Server confirms device type (OP_DEVICE_TYPE: 2, OP_IS: 4, model_name)
    let mut dev_confirm = vec![0xFF, 0xFA, 0x28, 0x02, 0x04];
    dev_confirm.extend_from_slice(model_name.as_bytes());
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
    socket
        .write_all(&[0xFF, 0xFA, 0x28, 0x03, 0x04, 0x02, 0xFF, 0xF0])
        .await
        .expect("confirm functions");
}

/// Helper: default Model 2 TN3270E negotiation.
async fn mock_negotiate_tn3270e(socket: &mut tokio::net::TcpStream, assigned_lu: Option<&str>) {
    mock_negotiate_tn3270e_model(socket, assigned_lu, "IBM-3278-2-E").await;
}

// ============================================================================
// AREA 1: ZERO-TRUST PASSWORD MASKING PENETRATION TESTING
// ============================================================================

/// Penetration test: Exhaustively tests all SafeScreenView projections (row text,
/// trimmed row text, full plain text, individual cells, row cell slices, diffs,
/// and full buffer cells) to prove that NonDisplay password characters are NEVER leaked,
/// while verifying wire fidelity on AID submission.
#[tokio::test]
async fn test_password_masking_comprehensive_leak_vectors() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let secret_password = "P@ssw0rd!#Secret99";

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Host screen setup:
        // - EraseWrite (0x05, 0xC3)
        // - SF 0x20 (protected): "KEY: " (EBCDIC: 0xD2, 0xC5, 0xE8, 0x7A, 0x40)
        // - SF 0x0C (unprotected, NonDisplay)
        // - IC (insert cursor into password field)
        // - IAC EOR
        let screen_setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x20, 0xD2, 0xC5, 0xE8, 0x7A, 0x40,
            0x1D, 0x0C, 0x13, 0xFF, 0xEF,
        ];
        socket.write_all(&screen_setup).await.expect("write setup");

        // Read client AID response
        let mut read_buf = [0u8; 512];
        let n = socket.read(&mut read_buf).await.expect("read aid");
        assert!(n >= 5, "aid response must have TN3270E header + 3270 data");
        let payload = &read_buf[5..n];

        // EBCDIC bytes for "P@ssw0rd!#Secret99" using CP037
        // P=0xD7, @=0x7C, s=0xA2, s=0xA2, w=0xA6, 0=0xF0, r=0x99, d=0x84,
        // !=0x5A, #=0x7B, S=0xE2, e=0x85, c=0x83, r=0x99, e=0x85, t=0xA3, 9=0xF9, 9=0xF9
        let expected_ebcdic = [
            0xD7, 0x7C, 0xA2, 0xA2, 0xA6, 0xF0, 0x99, 0x84, 0x5A, 0x7B, 0xE2, 0x85, 0x83, 0x99,
            0x85, 0xA3, 0xF9, 0xF9,
        ];

        assert!(
            payload
                .windows(expected_ebcdic.len())
                .any(|w| w == expected_ebcdic),
            "Host must receive raw EBCDIC bytes across network wire"
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

    // Capture initial screen view before typing
    let initial_view = loop {
        if let Some(SessionEvent::ScreenUpdated(v)) = event_rx.recv().await {
            break v;
        }
    };

    // Type the sensitive secret string
    handle
        .send_string(secret_password)
        .await
        .expect("send secret string");

    // Query SafeScreenView from session handle
    let view = handle.query_screen().await.expect("query screen");

    // 1. Vector: row_text
    for r in 0..view.rows() {
        let row_str = view.row_text(r).expect("row text");
        assert!(
            !row_str.contains("P@ssw0rd"),
            "LEAK VECTOR row_text: contains secret substring"
        );
        assert!(
            !row_str.contains("Secret99"),
            "LEAK VECTOR row_text: contains secret suffix"
        );
    }

    // 2. Vector: row_text_trimmed
    for r in 0..view.rows() {
        let row_trim = view.row_text_trimmed(r).expect("row text trimmed");
        assert!(
            !row_trim.contains(secret_password),
            "LEAK VECTOR row_text_trimmed contains secret password"
        );
    }

    // 3. Vector: to_plain_text & to_plain_text_trimmed
    let plain = view.to_plain_text();
    let plain_trim = view.to_plain_text_trimmed();
    assert!(
        !plain.contains("Secret99"),
        "LEAK VECTOR to_plain_text contains secret password"
    );
    assert!(
        !plain_trim.contains("Secret99"),
        "LEAK VECTOR to_plain_text_trimmed contains secret password"
    );

    // 4. Vector: cell_at across the password field (starts at row 0, col 7)
    // Label "KEY: " takes cols 1..5, SF 0x0C is at col 6, data starts at col 7
    let pass_len = secret_password.chars().count() as u16;
    for col in 7..(7 + pass_len) {
        let cell = view.cell_at(0, col).expect("cell at col");
        assert_eq!(
            cell.ch, ' ',
            "LEAK VECTOR cell_at: NonDisplay cell glyph MUST be space ' '"
        );
        assert!(
            cell.is_blank(),
            "LEAK VECTOR cell_at: NonDisplay cell must report is_blank() == true"
        );
        assert!(
            !cell.is_visible(),
            "LEAK VECTOR cell_at: NonDisplay cell must report is_visible() == false"
        );
    }

    // 5. Vector: row_cells
    let row_0_cells = view.row_cells(0).expect("row 0 cells");
    for cell in &row_0_cells[7..(7 + pass_len) as usize] {
        assert_eq!(
            cell.ch, ' ',
            "LEAK VECTOR row_cells: cell glyph MUST be space"
        );
        assert!(cell.is_blank());
    }

    // 6. Vector: cells() full screen slice
    for cell in view.cells() {
        assert_ne!(cell.ch, '@', "LEAK VECTOR cells: character '@' leaked");
        assert_ne!(cell.ch, '#', "LEAK VECTOR cells: character '#' leaked");
        assert_ne!(cell.ch, '9', "LEAK VECTOR cells: character '9' leaked");
        assert_ne!(cell.ch, '0', "LEAK VECTOR cells: character '0' leaked");
        assert_ne!(cell.ch, '!', "LEAK VECTOR cells: character '!' leaked");
    }

    // 7. Vector: diff()
    let diff = view.diff(&initial_view);
    for (_r, _c, cell) in diff {
        assert_ne!(
            cell.ch, '@',
            "LEAK VECTOR diff: cell glyph '@' leaked in diff"
        );
        assert_ne!(
            cell.ch, '#',
            "LEAK VECTOR diff: cell glyph '#' leaked in diff"
        );
        assert_ne!(
            cell.ch, '9',
            "LEAK VECTOR diff: cell glyph '9' leaked in diff"
        );
        assert!(
            cell.is_blank(),
            "LEAK VECTOR diff: cell in diff must be blank"
        );
    }

    // Submit AID Enter and verify host receives intact data
    handle
        .press_aid(AidKey::Enter)
        .await
        .expect("press aid enter");

    srv.await.expect("srv join");
    join_handle.abort();
}

/// Penetration test: Zero-Length Leakage Verification.
/// Verifies that an observer inspecting SafeScreenView CANNOT deduce whether
/// 0, 1, 5, or 10 characters have been typed into a NonDisplay field.
/// Every position in the field must exhibit identical SafeCell attributes.
#[tokio::test]
async fn test_password_masking_zero_length_leakage() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    let (done_tx, done_rx) = oneshot::channel();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // EraseWrite with NonDisplay field of 20 columns (from col 1 to 21) followed by protected field
        let screen_setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x0C, // SF NonDisplay at 0,0
            0x13, // IC at 0,1
            0x11, 0x40, 0xD5, // SBA row 0, col 21
            0x1D, 0x20, // SF Protected at 0,21
            0xFF, 0xEF,
        ];
        socket.write_all(&screen_setup).await.expect("write setup");

        let _ = done_rx.await;
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

    // Wait for setup
    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::ScreenUpdated(_) = event {
            break;
        }
    }

    // Screen state 0: 0 characters typed
    let view_0 = handle.query_screen().await.expect("view 0");
    let baseline_cell = *view_0.cell_at(0, 1).expect("cell 1");
    assert_eq!(baseline_cell.ch, ' ');
    assert!(baseline_cell.is_blank());

    // Type 1 character
    handle.send_key('A').await.expect("send A");
    let view_1 = handle.query_screen().await.expect("view 1");

    // Type 4 more characters (total 5)
    handle.send_string("BCDE").await.expect("send BCDE");
    let view_5 = handle.query_screen().await.expect("view 5");

    // Type 5 more characters (total 10)
    handle.send_string("FGHIJ").await.expect("send FGHIJ");
    let view_10 = handle.query_screen().await.expect("view 10");

    // Adversarial verification:
    // In view_10, cols 1..11 have typed chars, cols 11..21 have untyped chars.
    // BOTH sets of cells must be indistinguishable in SafeScreenView!
    for col in 1..21 {
        let cell = view_10.cell_at(0, col).expect("cell in view_10");
        assert_eq!(
            cell.ch, baseline_cell.ch,
            "Cell glyph at col {col} differs from empty baseline"
        );
        assert_eq!(
            cell.foreground, baseline_cell.foreground,
            "Cell foreground at col {col} differs from empty baseline"
        );
        assert_eq!(
            cell.background, baseline_cell.background,
            "Cell background at col {col} differs from empty baseline"
        );
        assert_eq!(
            cell.highlight, baseline_cell.highlight,
            "Cell highlight at col {col} differs from empty baseline"
        );
        assert_eq!(
            cell.charset, baseline_cell.charset,
            "Cell charset at col {col} differs from empty baseline"
        );
        assert_eq!(
            cell.protected, baseline_cell.protected,
            "Cell protected status at col {col} differs from empty baseline"
        );
        assert_eq!(
            cell.is_field_marker, baseline_cell.is_field_marker,
            "Cell field marker status at col {col} differs from empty baseline"
        );
        assert_eq!(cell.is_blank(), baseline_cell.is_blank());
        assert_eq!(cell.is_visible(), baseline_cell.is_visible());
    }

    // In all views (view_0, view_1, view_5, view_10), row_text(0) must be identical!
    let r0_0 = view_0.row_text(0).expect("r0 view 0");
    let r0_1 = view_1.row_text(0).expect("r0 view 1");
    let r0_5 = view_5.row_text(0).expect("r0 view 5");
    let r0_10 = view_10.row_text(0).expect("r0 view 10");

    assert_eq!(
        r0_0, r0_1,
        "ZERO-LENGTH LEAKAGE: row_text changed after typing 1 character"
    );
    assert_eq!(
        r0_1, r0_5,
        "ZERO-LENGTH LEAKAGE: row_text changed after typing 5 characters"
    );
    assert_eq!(
        r0_5, r0_10,
        "ZERO-LENGTH LEAKAGE: row_text changed after typing 10 characters"
    );

    let _ = done_tx.send(());
    let _ = srv.await;
    join_handle.abort();
}

/// Penetration test: Screen Resize via EraseWriteAlternate (EWA) Purge.
/// Verifies that switching screen geometry via EWA and EW completely reinitializes
/// the presentation buffer, purging all secret password bytes without any residual leakage.
#[tokio::test]
async fn test_password_masking_screen_resize_erase_write_alternate_purge() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        // Negotiate Model 4 (24x80 default, 43x80 alternate)
        mock_negotiate_tn3270e_model(&mut socket, None, "IBM-3278-4-E").await;

        // 1. Initial screen: Model 4 default (24x80) with password field
        let screen_setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, // EraseWrite (24x80)
            0x1D, 0x0C, 0x13, // SF NonDisplay at 0,0, IC at 0,1
            0xFF, 0xEF,
        ];
        socket.write_all(&screen_setup).await.expect("write setup");

        tokio::time::sleep(Duration::from_millis(60)).await;

        // 2. Host sends EraseWriteAlternate (0x0D): switches to 43x80
        let ewa_record = [
            0x00, 0x00, 0x00, 0x00, 0x02, 0x0D, 0xC3, // EWA (43x80)
            0xFF, 0xEF,
        ];
        socket.write_all(&ewa_record).await.expect("write ewa");

        tokio::time::sleep(Duration::from_millis(60)).await;

        // 3. Host sends EraseWrite (0x05): switches back to 24x80
        let ew_record = [
            0x00, 0x00, 0x00, 0x00, 0x03, 0x05, 0xC3, // EW (24x80)
            0xFF, 0xEF,
        ];
        socket.write_all(&ew_record).await.expect("write ew");

        tokio::time::sleep(Duration::from_millis(60)).await;
        socket.shutdown().await.expect("shutdown");
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .terminal_model(ProfileTerminalModel::Model4)
        .build()
        .expect("build profile");

    let tcp_stream = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp_stream);
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // Wait for initial setup
    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::ScreenUpdated(_) = event {
            break;
        }
    }

    // Type confidential password in default 24x80 geometry
    handle
        .send_string("TOP_SECRET_PASSPHRASE_12345")
        .await
        .expect("send pwd");

    // Receive EWA update (switches to 43x80)
    let ewa_view = loop {
        if let Some(SessionEvent::ScreenUpdated(v)) = event_rx.recv().await {
            if v.rows() == 43 {
                break v;
            }
        }
    };
    assert_eq!(ewa_view.rows(), 43);
    assert_eq!(ewa_view.cols(), 80);

    // Verify 43x80 buffer has NO remnants of TOP_SECRET
    let ewa_text = ewa_view.to_plain_text();
    assert!(
        !ewa_text.contains("TOP_SECRET"),
        "RESIZE RESIDUAL LEAK: EWA buffer contains remnant of password"
    );
    for cell in ewa_view.cells() {
        assert_eq!(cell.ch, ' ', "EWA buffer must be completely blank");
    }

    // Receive EW update (switches back to 24x80)
    let ew_view = loop {
        if let Some(SessionEvent::ScreenUpdated(v)) = event_rx.recv().await {
            if v.rows() == 24 {
                break v;
            }
        }
    };
    assert_eq!(ew_view.rows(), 24);
    assert_eq!(ew_view.cols(), 80);

    // Verify 24x80 buffer has NO remnants of TOP_SECRET
    let ew_text = ew_view.to_plain_text();
    assert!(
        !ew_text.contains("TOP_SECRET"),
        "RESIZE RESIDUAL LEAK: EW buffer contains remnant of password"
    );
    for cell in ew_view.cells() {
        assert_eq!(cell.ch, ' ', "EW buffer must be completely blank");
    }

    let _ = srv.await;
    join_handle.abort();
}

/// Penetration test: Field boundary wrap (screen row wrap and physical buffer address wrap).
/// Verifies masking when NonDisplay fields wrap across line endings or across the entire screen buffer.
#[tokio::test]
async fn test_password_masking_boundary_wrap_and_zero_length_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    let (done_tx, done_rx) = oneshot::channel();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Setup screen:
        // - EraseWrite (0x05, 0xC3)
        // - SBA to row 0, col 75 (Buffer address 75 = 0x41 0x4B)
        // - SF 0x0C (NonDisplay field starting at row 0, col 75 and wrapping into row 1)
        // - IC at row 0, col 76 (0x41 0x4C)
        // - SBA to row 1, col 10 (Buffer address 90 = 0x41 0x5A)
        // - SF 0x20 (Protected field terminating password field)
        // - SF 0x0C immediately followed by SF 0x20 (Zero-length non-display field)
        let setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x11, 0x41, 0x4B, // SBA 75
            0x1D, 0x0C, // SF NonDisplay
            0x13, // IC
            0x11, 0x41, 0x5A, // SBA 90
            0x1D, 0x20, // SF Protected
            0x1D, 0x0C, // SF NonDisplay (zero-length)
            0x1D, 0x20, // SF Protected
            0xFF, 0xEF,
        ];
        socket.write_all(&setup).await.expect("write setup");

        let _ = done_rx.await;
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

    // Type across the row boundary: cols 76..80 of row 0, then cols 0..9 of row 1 (14 chars)
    handle
        .send_string("WRAP_PASSWORD!")
        .await
        .expect("send wrap password");

    let view = handle.query_screen().await.expect("query screen");

    // Check row 0 text
    let row0 = view.row_text(0).expect("row 0 text");
    assert!(
        !row0.contains("WRAP"),
        "ROW WRAP LEAK: row 0 contains WRAP prefix"
    );

    // Check row 1 text
    let row1 = view.row_text(1).expect("row 1 text");
    assert!(
        !row1.contains("PASSWORD"),
        "ROW WRAP LEAK: row 1 contains PASSWORD suffix"
    );

    // Verify cell masking across wrap points
    for col in 76..80 {
        let cell = view.cell_at(0, col).expect("cell at col");
        assert_eq!(cell.ch, ' ', "Cell at row 0 col {col} must be space");
        assert!(cell.is_blank());
    }
    for col in 0..10 {
        let cell = view.cell_at(1, col).expect("cell at col");
        assert_eq!(cell.ch, ' ', "Cell at row 1 col {col} must be space");
        assert!(cell.is_blank());
    }

    let _ = done_tx.send(());
    let _ = srv.await;
    join_handle.abort();
}

/// Penetration test: Editing and navigation inside NonDisplay field (Backspace, Delete, Left arrow).
/// Verifies that partial edits, character replacements, and cursor movements inside
/// a password field never leak the underlying characters into SafeScreenView.
#[tokio::test]
async fn test_password_masking_in_field_editing_and_backspace() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    let (done_tx, done_rx) = oneshot::channel();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        let setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x0C,
            0x13, // SF NonDisplay at 0,0, IC at 0,1
            0xFF, 0xEF,
        ];
        socket.write_all(&setup).await.expect("write setup");

        let _ = done_rx.await;
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

    // Type "Secret"
    handle.send_string("Secret").await.expect("send secret");

    // Move cursor Left twice
    handle.send_action(ActionKey::Left).await.expect("left 1");
    handle.send_action(ActionKey::Left).await.expect("left 2");

    // Erase to end of field
    handle
        .send_action(ActionKey::EraseEof)
        .await
        .expect("erase eof");

    // Type "New"
    handle.send_string("New").await.expect("send new");

    // Move cursor Left and navigate Right
    handle.send_action(ActionKey::Left).await.expect("left");
    handle.send_action(ActionKey::Right).await.expect("right");

    // Check view: zero leakage of any secret chars
    let view = handle.query_screen().await.expect("query screen");
    let row0 = view.row_text(0).expect("row text");
    assert!(!row0.contains("Sec"), "Contains Sec");
    assert!(!row0.contains("New"), "Contains New");

    for col in 1..10 {
        let cell = view.cell_at(0, col).expect("cell");
        assert_eq!(cell.ch, ' ', "Glyph must remain space");
        assert!(cell.is_blank());
    }

    let _ = done_tx.send(());
    let _ = srv.await;
    join_handle.abort();
}

// ============================================================================
// AREA 2: MALFORMED 3270 DATASTREAMS & RFC 2355 NEGATIVE RESPONSES
// ============================================================================

/// Adversarial test: Verifies that invalid 3270 command opcodes (e.g. 0x00, 0x42, 0x77, 0x99, 0xFE, 0xFF)
/// trigger an RFC 2355 negative response with COMMAND-REJECT (0x00) — x3270 `PDS_BAD_CMD` —
/// and that the session survives: the next valid record is processed and acknowledged.
#[tokio::test]
async fn test_malformed_3270_invalid_opcodes_negative_response() {
    let invalid_opcodes = [0x00, 0x42, 0x77, 0x99, 0xFE, 0xFF];

    for &opcode in &invalid_opcodes {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let srv = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            mock_negotiate_tn3270e(&mut socket, None).await;

            // Host sends invalid opcode with ALWAYS_RESPONSE (0x02) and seq 0x1234
            // In Telnet framing, byte 0xFF must be escaped as [0xFF, 0xFF]
            let mut bad_cmd = vec![0x00, 0x00, 0x02, 0x12, 0x34];
            if opcode == 0xFF {
                bad_cmd.extend_from_slice(&[0xFF, 0xFF]);
            } else {
                bad_cmd.push(opcode);
            }
            bad_cmd.extend_from_slice(&[0xFF, 0xEF]); // IAC EOR

            socket.write_all(&bad_cmd).await.expect("write bad cmd");

            // Host expects RFC 2355 Negative Response:
            // [0x02 (Response), 0x00, 0x01 (NEGATIVE_RESPONSE), 0x12, 0x34, 0x00 (COMMAND_REJECT), 0xFF, 0xEF]
            let mut resp_buf = [0u8; 8];
            socket
                .read_exact(&mut resp_buf)
                .await
                .expect("read negative response");
            assert_eq!(
                &resp_buf,
                &[0x02, 0x00, 0x01, 0x12, 0x34, 0x00, 0xFF, 0xEF],
                "Must emit negative response with COMMAND_REJECT on invalid opcode 0x{opcode:02X}"
            );

            // The session is still alive: a valid Write (ALWAYS-RESPONSE, seq 0x1235) is
            // processed and acknowledged with a positive response.
            socket
                .write_all(&[0x00, 0x00, 0x02, 0x12, 0x35, 0xF1, 0xC2, 0xFF, 0xEF])
                .await
                .expect("write valid record");
            socket
                .read_exact(&mut resp_buf)
                .await
                .expect("read positive response");
            assert_eq!(&resp_buf, &[0x02, 0x00, 0x00, 0x12, 0x35, 0x00, 0xFF, 0xEF]);

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

        // The bad record did not end the session: it ends cleanly on the host's EOF
        let res = join_handle
            .await
            .expect("coordinator task completed without panic");
        assert!(
            res.is_ok(),
            "a rejected record must not end the session: {res:?}"
        );

        srv.await.expect("srv completed");
    }
}

/// Adversarial test: RFC 2355 ERROR_RESPONSE flag (0x01).
/// RFC 2355 §8 specifies:
/// - ERROR-RESPONSE (0x01): The receiving partner should generate a response ONLY if it
///   encounters an error processing the data.
/// For valid data, NO response is emitted.
/// For invalid datastreams, Negative Response OPERATION_CHECK MUST be emitted.
#[tokio::test]
async fn test_malformed_3270_error_response_flag_handling() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // 1. Host sends valid data with ERROR_RESPONSE (0x01) and seq 0x0001
        let valid_cmd = [
            0x00, 0x00, 0x01, 0x00, 0x01, // RSF_ERROR_RESPONSE
            0x05, 0xC3, // EraseWrite, restore keyboard
            0xFF, 0xEF,
        ];
        socket.write_all(&valid_cmd).await.expect("write valid cmd");

        // Give coordinator a short window to verify NO response is sent for valid data
        let mut check_buf = [0u8; 8];
        let timeout_res =
            tokio::time::timeout(Duration::from_millis(100), socket.read(&mut check_buf)).await;
        // Should timeout because no response is requested on success
        assert!(
            timeout_res.is_err(),
            "RFC 2355: ERROR_RESPONSE (0x01) must NOT elicit response on successful processing"
        );

        // 2. Host sends INVALID data with ERROR_RESPONSE (0x01) and seq 0x0002
        let invalid_cmd = [
            0x00, 0x00, 0x01, 0x00, 0x02, // RSF_ERROR_RESPONSE
            0x99, // invalid opcode
            0xFF, 0xEF,
        ];
        socket
            .write_all(&invalid_cmd)
            .await
            .expect("write invalid cmd");

        // Host expects RFC 2355 Negative Response (unknown command = COMMAND-REJECT, x3270
        // PDS_BAD_CMD):
        // [0x02, 0x00, 0x01 (NEGATIVE_RESPONSE), 0x00, 0x02, 0x00 (COMMAND_REJECT), 0xFF, 0xEF]
        let mut resp_buf = [0u8; 8];
        socket
            .read_exact(&mut resp_buf)
            .await
            .expect("read negative response on ERROR_RESPONSE");
        assert_eq!(
            &resp_buf,
            &[0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0xFF, 0xEF],
            "Must emit negative response with COMMAND_REJECT when ERROR_RESPONSE flag is set"
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

    // The rejected record does not end the session
    let res = join_handle.await.expect("coordinator task completed");
    assert!(
        res.is_ok(),
        "a rejected record must not end the session: {res:?}"
    );

    srv.await.expect("srv completed");
}

/// Adversarial test: Truncated 3270 orders (SF missing attribute, SFE missing pairs,
/// SBA missing address byte, RA missing character/address, Write missing WCC).
/// Verifies that all truncated orders trigger RFC 2355 Negative Response with OPERATION_CHECK
/// and zero panics.
#[tokio::test]
async fn test_malformed_3270_truncated_orders_negative_response() {
    let truncated_payloads: Vec<(&'static str, Vec<u8>)> = vec![
        ("Write missing WCC", vec![0x01]),
        ("EraseWrite missing WCC", vec![0x05]),
        ("ORDER_SF missing attribute byte", vec![0x05, 0xC3, 0x1D]),
        (
            "ORDER_SBA missing 2nd address byte",
            vec![0x05, 0xC3, 0x11, 0x40],
        ),
        ("ORDER_SFE missing attribute count", vec![0x05, 0xC3, 0x29]),
        (
            "ORDER_SFE missing pair bytes",
            vec![0x05, 0xC3, 0x29, 0x02, 0xC0],
        ),
        (
            "ORDER_RA missing repeat address",
            vec![0x05, 0xC3, 0x3C, 0x40],
        ),
    ];

    for (name, payload) in truncated_payloads {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let srv = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            mock_negotiate_tn3270e(&mut socket, None).await;

            let mut msg = vec![0x00, 0x00, 0x02, 0xAB, 0xCD];
            msg.extend_from_slice(&payload);
            msg.extend_from_slice(&[0xFF, 0xEF]); // IAC EOR
            socket
                .write_all(&msg)
                .await
                .expect("write truncated payload");

            // Await RFC 2355 Negative Response
            let mut resp_buf = [0u8; 8];
            socket
                .read_exact(&mut resp_buf)
                .await
                .expect("read negative response");
            assert_eq!(
                &resp_buf,
                &[0x02, 0x00, 0x01, 0xAB, 0xCD, 0x02, 0xFF, 0xEF],
                "Truncated order '{name}' must produce OPERATION_CHECK negative response"
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

        // An aborted write is reported (negative response) but does not end the session
        let res = join_handle.await.expect("join handle");
        assert!(res.is_ok(), "{name} must not end the session: {res:?}");

        srv.await.expect("srv completed");
    }
}

/// Adversarial test: Corrupted SBA buffer address.
/// Buffer address exceeding capacity (e.g. 0x7F 0x7F = 16383 on 1920 capacity screen)
/// or illegal address format must emit RFC 2355 Negative Response OPERATION_CHECK.
#[tokio::test]
async fn test_malformed_3270_corrupted_sba_address_out_of_bounds() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // SBA with out-of-bounds address: 0x7F 0x7F
        let bad_sba = [
            0x00, 0x00, 0x02, 0x00, 0x99, 0x05, 0xC3, 0x11, 0x7F, 0x7F, 0xFF, 0xEF,
        ];
        socket.write_all(&bad_sba).await.expect("write bad sba");

        let mut resp_buf = [0u8; 8];
        socket
            .read_exact(&mut resp_buf)
            .await
            .expect("read negative response");
        assert_eq!(
            &resp_buf,
            &[0x02, 0x00, 0x01, 0x00, 0x99, 0x02, 0xFF, 0xEF],
            "Out-of-bounds SBA must trigger negative response with OPERATION_CHECK"
        );

        // The session is still alive after the aborted write
        socket
            .write_all(&[0x00, 0x00, 0x02, 0x00, 0x9A, 0xF1, 0xC2, 0xFF, 0xEF])
            .await
            .expect("write valid record");
        socket
            .read_exact(&mut resp_buf)
            .await
            .expect("read positive response");
        assert_eq!(&resp_buf, &[0x02, 0x00, 0x00, 0x00, 0x9A, 0x00, 0xFF, 0xEF]);

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

    let res = join_handle.await.expect("join handle");
    assert!(
        res.is_ok(),
        "an aborted write must not end the session: {res:?}"
    );

    srv.await.expect("srv completed");
}

// ============================================================================
// AREA 3: INTERRUPTED / TRUNCATED TELNET NEGOTIATION
// ============================================================================

/// Adversarial test: Fragmented Telnet negotiation sequences.
/// Sends Telnet IAC commands and TN3270E subnegotiation bytes split across
/// microscopic single-byte TCP writes to stress reassembly and state machine resilience.
#[tokio::test]
async fn test_truncated_telnet_fragmented_iac_and_subnegotiation() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");

        let mut buf = [0u8; 512];

        // The host opens negotiation: IAC DO TN3270E, byte-by-byte with delays
        for &b in &[0xFF, 0xFD, 0x28] {
            socket.write_all(&[b]).await.expect("write byte");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // Read client IAC WILL TN3270E
        let n = socket.read(&mut buf).await.expect("read will tn3270e");
        assert!(n > 0);

        // Send SEND DEVICE-TYPE fragmented: [FF FA], then [28 08], then [02 FF F0]
        socket.write_all(&[0xFF, 0xFA]).await.expect("w1");
        tokio::time::sleep(Duration::from_millis(5)).await;
        socket.write_all(&[0x28, 0x08]).await.expect("w2");
        tokio::time::sleep(Duration::from_millis(5)).await;
        socket.write_all(&[0x02, 0xFF, 0xF0]).await.expect("w3");

        // Read client DEVICE-TYPE REQUEST
        let n = socket.read(&mut buf).await.expect("read devtype request");
        assert!(n > 0);

        // Send DEVICE-TYPE CONFIRMATION byte-by-byte
        let dev_confirm = [
            0xFF, 0xFA, 0x28, 0x02, 0x04, b'I', b'B', b'M', b'-', b'3', b'2', b'7', b'8', b'-',
            b'2', b'-', b'E', 0xFF, 0xF0,
        ];
        for &b in &dev_confirm {
            socket.write_all(&[b]).await.expect("write byte");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // Read client FUNCTIONS REQUEST
        let n = socket.read(&mut buf).await.expect("read funcs request");
        assert!(n > 0);

        // Send FUNCTIONS CONFIRMATION
        socket
            .write_all(&[0xFF, 0xFA, 0x28, 0x03, 0x04, 0x02, 0xFF, 0xF0])
            .await
            .expect("confirm funcs");

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
    let (handle, mut event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    // Coordinator must successfully reassemble fragmented negotiation
    let mut reached_connected = false;
    while let Some(event) = event_rx.recv().await {
        if let SessionEvent::NegotiationComplete { is_tn3270e, .. } = event {
            assert!(is_tn3270e);
            reached_connected = true;
            break;
        }
    }
    assert!(
        reached_connected,
        "Fragmented Telnet stream must successfully reach Connected3270"
    );

    let status = handle.query_status().await.expect("query status");
    assert_eq!(status.state, SessionState::Connected3270);

    let _ = srv.await;
    let _ = join_handle.await;
}

/// Adversarial test: Abrupt host EOF mid-negotiation.
/// Server accepts connection, reads client request, and abruptly closes socket (EOF)
/// without completing option negotiation. Coordinator must cleanly terminate
/// without deadlocking, panicking, or hanging indefinitely.
#[tokio::test]
async fn test_interrupted_negotiation_server_abrupt_eof() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 128];
        // Open negotiation (IAC DO TTYPE), read the client's WILL, then close mid-handshake
        socket
            .write_all(&[0xFF, 0xFD, 0x18])
            .await
            .expect("do ttype");
        let _ = socket.read(&mut buf).await;
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

    // Coordinator task must resolve cleanly with Ok(()) on EOF
    let res = tokio::time::timeout(Duration::from_secs(2), join_handle)
        .await
        .expect("coordinator must not hang on remote EOF")
        .expect("task join");

    assert!(
        res.is_ok(),
        "Clean remote EOF should result in Ok(()) shutdown"
    );

    // Must emit Disconnected event
    let mut got_disconnect = false;
    while let Ok(event) = tokio::time::timeout(Duration::from_millis(100), event_rx.recv()).await {
        if let Some(SessionEvent::Disconnected) = event {
            got_disconnect = true;
            break;
        }
    }
    assert!(
        got_disconnect,
        "Must emit SessionEvent::Disconnected on remote EOF"
    );

    let _ = srv.await;
}

/// Adversarial test: Mid-subnegotiation EOF.
/// Server initiates subnegotiation (IAC SB ...) and abruptly terminates without sending IAC SE.
/// Coordinator must cleanly terminate without panicking or hanging.
#[tokio::test]
async fn test_interrupted_negotiation_mid_subnegotiation_eof() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 512];

        // Open TN3270E negotiation
        socket.write_all(&[0xFF, 0xFD, 0x28]).await.expect("do");
        let _ = socket.read(&mut buf).await;

        // Send partial subnegotiation without IAC SE, then abruptly close
        socket
            .write_all(&[0xFF, 0xFA, 0x28, 0x08])
            .await
            .expect("partial sb");
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

    let res = tokio::time::timeout(Duration::from_secs(2), join_handle)
        .await
        .expect("coordinator must not hang on truncated subnegotiation")
        .expect("join handle");

    assert!(
        res.is_ok(),
        "Remote EOF during subnegotiation should resolve cleanly"
    );

    let _ = srv.await;
}

// ============================================================================
// AREA 4: AID KEY SUBMISSION WHILE KEYBOARD LOCKED
// ============================================================================

/// Adversarial test: AID key submission while keyboard is locked in TimeWait (X Wait).
/// After pressing an AID key (Enter), the keyboard is locked awaiting host response.
/// Another AID pressed meanwhile is held in the typeahead queue (x3270 `enq_ta`): nothing
/// reaches the host until it restores the keyboard, then the queued PF1 is sent by itself.
#[tokio::test]
async fn test_aid_while_locked_is_queued_and_sent_after_restore() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Setup screen with unprotected field
        let screen_setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, // EW, restore keyboard
            0x1D, 0x00, // SF unprotected
            0x13, // IC
            0xFF, 0xEF,
        ];
        socket.write_all(&screen_setup).await.expect("write setup");

        // Read first AID response (Enter)
        let mut read_buf = [0u8; 256];
        let n = socket.read(&mut read_buf).await.expect("read first aid");
        assert!(n >= 5);

        // Host deliberately does NOT restore keyboard for 200ms; the queued PF1 must not
        // arrive meanwhile.
        let early =
            tokio::time::timeout(Duration::from_millis(200), socket.read(&mut read_buf)).await;
        assert!(
            early.is_err(),
            "queued AID was sent while the keyboard was locked"
        );

        // Now host restores keyboard with WCC 0xC3
        let unlock_setup = [
            0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0xC3, // Write, restore keyboard
            0xFF, 0xEF,
        ];
        socket.write_all(&unlock_setup).await.expect("write unlock");

        // Read second AID response (PF1)
        let n2 = socket.read(&mut read_buf).await.expect("read second aid");
        assert!(n2 >= 5);
        let payload = &read_buf[5..n2];
        assert_eq!(payload[0], 0xF1, "PF1 AID code is 0xF1");

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

    // 1. Submit first AID key (Enter)
    handle
        .press_aid(AidKey::Enter)
        .await
        .expect("press aid enter");

    // Keyboard state must now be TimeWait
    let kb = handle.query_keyboard_state().await.expect("query kb");
    assert_eq!(kb, KeyboardState::TimeWait);

    // 2. PF1 while locked is accepted into the typeahead queue, not sent.
    handle
        .press_aid(AidKey::PF1)
        .await
        .expect("PF1 is queued while locked");
    let kb = handle.query_keyboard_state().await.expect("query kb");
    assert_eq!(kb, KeyboardState::TimeWait);

    // 3. The host restores the keyboard; the queued PF1 goes out by itself (checked by the
    //    mock host).
    srv.await.expect("mock host");
    join_handle.abort();
}

/// Adversarial test: AID key submission while keyboard is locked in Protected state.
/// Typing into a protected field locks the keyboard in Protected mode.
/// Submitting AID keys must be rejected until the user issues ActionKey::Reset.
#[tokio::test]
async fn test_aid_submission_rejected_when_locked_in_protected_state() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Setup screen: entire screen is protected
        let screen_setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, // EW, restore keyboard
            0x1D, 0x20, // SF Protected
            0xFF, 0xEF,
        ];
        socket.write_all(&screen_setup).await.expect("write setup");

        // Read AID response after client resets
        let mut read_buf = [0u8; 256];
        let n = socket.read(&mut read_buf).await.expect("read aid");
        assert!(n >= 5);

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

    // 1. Attempt to type into protected field -> locks keyboard
    let type_err = handle.send_key('X').await;
    assert!(type_err.is_err(), "Typing into protected field must error");

    let kb = handle.query_keyboard_state().await.expect("query kb");
    assert_eq!(kb, KeyboardState::Protected);

    // 2. ADVERSARIAL ATTEMPT: Try pressing AID Enter while in Protected lock
    let aid_err = handle.press_aid(AidKey::Enter).await;
    assert!(
        aid_err.is_err(),
        "Pressing AID while locked in Protected state MUST be rejected"
    );

    // 3. User issues Reset action
    handle
        .send_action(ActionKey::Reset)
        .await
        .expect("send reset");

    let kb_after_reset = handle.query_keyboard_state().await.expect("query kb");
    assert_eq!(kb_after_reset, KeyboardState::Unlocked);

    // 4. Now AID submission succeeds
    handle
        .press_aid(AidKey::Enter)
        .await
        .expect("press aid enter after reset");

    let _ = srv.await;
    join_handle.abort();
}

/// Adversarial test: Rapid consecutive AID key submission race condition.
/// Firing multiple concurrent AID keys before host acknowledges must reject
/// secondary AIDs deterministically because the first transition to TimeWait locks out subsequent AIDs.
#[tokio::test]
async fn test_aid_submission_rapid_consecutive_aids_race() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        let screen_setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x00, 0x13, 0xFF, 0xEF,
        ];
        socket.write_all(&screen_setup).await.expect("write setup");

        // Read first AID
        let mut read_buf = [0u8; 256];
        let n = socket.read(&mut read_buf).await.expect("read aid");
        assert!(n >= 5);

        // The host never restores the keyboard, so the queued PF1 / PF2 must never arrive.
        let more =
            tokio::time::timeout(Duration::from_millis(150), socket.read(&mut read_buf)).await;
        assert!(
            more.is_err(),
            "a second AID was sent while waiting for the host"
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

    // Submit first AID
    let res1 = handle.press_aid(AidKey::Enter).await;
    assert!(res1.is_ok(), "First AID should succeed");

    // Immediately submit second and third AIDs
    let res2 = handle.press_aid(AidKey::PF1).await;
    let res3 = handle.press_aid(AidKey::PF2).await;

    // Both are held in the typeahead queue (x3270 `enq_ta`), not sent.
    assert!(res2.is_ok(), "second AID is queued");
    assert!(res3.is_ok(), "third AID is queued");
    assert_eq!(
        handle.query_keyboard_state().await.expect("kb"),
        KeyboardState::TimeWait
    );

    srv.await.expect("mock host");
    join_handle.abort();
}
