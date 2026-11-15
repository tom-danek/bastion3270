//! Comprehensive End-to-End Headless GUI Integration Tests for `bastion3270-gui`.
//!
//! Verifies:
//! 1. Full headless `egui::Context` rendering of `Bastion3270GuiApp` across all panels and color schemes.
//! 2. End-to-end loop with an in-process mock TN3270E mainframe:
//!    - Negotiation -> `4A` OIA badge -> `SafeScreenView` rendering.
//!    - Hardware keyboard injection (`Event::Text`, `Event::Key`) -> `GuiSessionBridge` -> `SessionCoordinator`.
//!    - `Backspace`, `Delete`, `MoveCursor` (mouse click positioning), and `Escape` (`Reset` of `X PROTECTED`).
//!    - Zero-Trust password masking inside the GUI screen buffer.
//! 3. Profile Manager CRUD and file-based TOML import/export.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use bastion3270_core::{ActionKey, AidKey, KeyboardState};
use bastion3270_gui::{
    Bastion3270GuiApp, CursorStyle, GuiKeyAction, KeyboardPreset, ProfileCatalog,
    TerminalColorScheme,
};
use bastion3270_net::transport::connect_tcp_stream;
use bastion3270_net::{
    ConnectionProfileBuilder, SessionCoordinator, SessionState, TlsMode, TransportStream,
};
use egui::{Event, Key, Modifiers, RawInput};

async fn mock_negotiate_tn3270e(socket: &mut tokio::net::TcpStream, assigned_lu: Option<&str>) {
    let mut buf = [0u8; 512];
    // 1. The host opens negotiation (the client is purely reactive): IAC DO TN3270E (FF FD 28)
    socket
        .write_all(&[0xFF, 0xFD, 0x28])
        .await
        .expect("write do tn3270e");
    let n = socket.read(&mut buf).await.expect("read will tn3270e");
    assert!(n > 0);

    // 3. Server requests device type
    socket
        .write_all(&[0xFF, 0xFA, 0x28, 0x08, 0x02, 0xFF, 0xF0])
        .await
        .expect("send devtype");
    let n = socket.read(&mut buf).await.expect("read devtype req");
    assert!(n > 0);

    // 4. Server confirms device type
    let mut dev_confirm = vec![
        0xFF, 0xFA, 0x28, 0x02, 0x04, b'I', b'B', b'M', b'-', b'3', b'2', b'7', b'8', b'-', b'2',
        b'-', b'E',
    ];
    if let Some(lu) = assigned_lu {
        dev_confirm.push(0x01);
        dev_confirm.extend_from_slice(lu.as_bytes());
    }
    dev_confirm.extend_from_slice(&[0xFF, 0xF0]);
    socket
        .write_all(&dev_confirm)
        .await
        .expect("confirm devtype");

    // 5. Read functions request and confirm
    let n = socket.read(&mut buf).await.expect("read funcs");
    assert!(n > 0);
    socket
        .write_all(&[0xFF, 0xFA, 0x28, 0x03, 0x04, 0x02, 0xFF, 0xF0])
        .await
        .expect("confirm funcs");
}

#[tokio::test]
async fn test_gui_end_to_end_live_loopback_typing_and_oia() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, Some("LU3279A")).await;

        // Send EraseWrite with:
        // - SF 0x00 (unprotected) at (0,0), IC at (0,1)
        // - SBA to (1,0) [addr 80 = 0x41, 0x50], SF 0x20 (protected)
        let setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, // TN3270E header
            0x05, 0xC3, // EraseWrite, restore keyboard
            0x1D, 0x00, // SF unprotected at (0,0)
            0x13, // IC at (0,1)
            0x11, 0x41, 0x50, // SBA (1,0)
            0x1D, 0x20, // SF protected at (1,0)
            0xFF, 0xEF, // IAC EOR
        ];
        socket.write_all(&setup).await.expect("write setup");

        // Wait for client AID Enter after typing "TSO"
        let mut aid_buf = [0u8; 256];
        let n = socket.read(&mut aid_buf).await.expect("read aid");
        assert!(n > 5);
        let payload = &aid_buf[5..n];
        // AID Enter is 0x7D; EBCDIC "TSO" in CP037 is [0xE3, 0xE2, 0xD6]
        assert_eq!(payload[0], 0x7D, "must begin with AID Enter (0x7D)");
        assert!(
            payload.windows(3).any(|w| w == [0xE3, 0xE2, 0xD6]),
            "AID payload must contain EBCDIC 'TSO'"
        );

        socket.shutdown().await.expect("shutdown");
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .build()
        .expect("build profile");

    let tcp = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp);
    let (handle, event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let mut app = Bastion3270GuiApp::new().expect("create gui app");
    app.bridge.attach_session(handle, event_rx);

    let ctx = egui::Context::default();

    // Poll until initial screen update arrives
    for _ in 0..40 {
        ctx.run_ui(RawInput::default(), |ui| {
            app.render_ui(ui);
        })
        .drop_without_applying_deltas();
        if app.oia.is_formatted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(app.oia.session_state, SessionState::Connected3270);
    assert_eq!(app.oia.connection_code(), "4A");
    assert_eq!(app.oia.protocol_badge(), "TN3270E [LU3279A]");
    assert_eq!(app.oia.cursor_rc_text(), "001/002");

    // Inject "TSO9" followed by Backspace (leaving "TSO") via egui RawInput
    let mut input_events = RawInput::default();
    input_events.events.push(Event::Text("TSO9".to_string()));
    input_events.events.push(Event::Key {
        key: Key::Backspace,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: Modifiers::NONE,
    });
    ctx.run_ui(input_events, |ui| {
        app.render_ui(ui);
    })
    .drop_without_applying_deltas();

    // Wait for async actor to process keystrokes and emit updated SafeScreenView
    for _ in 0..40 {
        app.process_session_events();
        if app
            .screen
            .row_text(0)
            .is_some_and(|r| r.contains("TSO") && !r.contains('9'))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let row0 = app.screen.row_text(0).expect("row 0");
    assert!(
        row0.contains("TSO"),
        "screen row 0 must contain 'TSO': {row0:?}"
    );
    assert!(
        !row0.contains('9'),
        "Backspace must have deleted '9': {row0:?}"
    );
    assert_eq!(app.oia.cursor_rc_text(), "001/005");

    // Now press Enter via GuiKeyAction
    app.apply_key_action(GuiKeyAction::Aid(AidKey::Enter));

    srv.await.expect("mock server assertions passed");
    let _ = join_handle.await;
}

#[tokio::test]
async fn test_gui_cursor_move_delete_and_protected_reset() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Row 0: unprotected field starting at (0,0), Row 1: protected field starting at (1,0) [12-bit addr 80 = 0xC1, 0x50]
        let setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x00, 0x13, 0x11, 0xC1, 0x50, 0x1D,
            0x20, 0xFF, 0xEF,
        ];
        socket.write_all(&setup).await.expect("write setup");

        let _ = done_rx.await;
        let _ = socket.shutdown().await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .build()
        .expect("build profile");

    let tcp = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp);
    let (handle, event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let mut app = Bastion3270GuiApp::new().expect("create gui app");
    app.bridge.attach_session(handle.clone(), event_rx);

    for _ in 0..40 {
        app.process_session_events();
        if app.oia.is_formatted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Type "AXBC", move left 3 cells to 'X', and press Delete -> should leave "ABC"
    handle.send_string("AXBC").await.expect("type AXBC");
    handle
        .send_action(ActionKey::MoveCursor { row: 0, col: 2 })
        .await
        .expect("move cursor to col 2");
    handle
        .send_action(ActionKey::Delete)
        .await
        .expect("delete X");

    // Move cursor to protected Row 1, Col 5 and attempt to type 'Z' -> locks X PROTECTED
    handle
        .send_action(ActionKey::MoveCursor { row: 1, col: 5 })
        .await
        .expect("move to protected row");
    assert!(handle.send_key('Z').await.is_err());

    for _ in 0..20 {
        app.process_session_events();
        if app.oia.keyboard_state == KeyboardState::Protected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(app.oia.keyboard_badge(), "X PROTECTED");
    assert_eq!(app.oia.cursor_rc_text(), "002/006");
    let row0 = app.screen.row_text(0).expect("row 0");
    assert!(
        row0.starts_with(" ABC "),
        "Delete should shift field left to 'ABC': {row0:?}"
    );

    // Press Escape in GUI to trigger ActionKey::Reset and unlock X PROTECTED
    let mut esc_input = RawInput::default();
    esc_input.events.push(Event::Key {
        key: Key::Escape,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: Modifiers::NONE,
    });
    let ctx = egui::Context::default();
    ctx.run_ui(esc_input, |ui| {
        app.render_ui(ui);
    })
    .drop_without_applying_deltas();

    for _ in 0..20 {
        app.process_session_events();
        if app.oia.keyboard_state == KeyboardState::Unlocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(app.oia.keyboard_badge(), "READY");

    let _ = done_tx.send(());
    app.disconnect_session();
    let _ = srv.await;
    let _ = join_handle.await;
}

#[test]
fn test_headless_panels_color_schemes_and_profile_persistence() {
    let mut app = Bastion3270GuiApp::new().expect("create gui app");
    app.open_profile_manager();
    app.show_keypad_bar = true;
    app.keypad_shift_pf13_24 = true;

    let ctx = egui::Context::default();

    for scheme in TerminalColorScheme::ALL {
        app.theme.color_scheme = scheme;
        for style in CursorStyle::ALL {
            app.theme.cursor_style = style;
            for preset in KeyboardPreset::ALL {
                app.keyboard = preset;
                ctx.run_ui(RawInput::default(), |ui| {
                    app.render_ui(ui);
                })
                .drop_without_applying_deltas();
            }
        }
    }

    // Verify TOML file save & load in /tmp
    let tmp_path = std::env::temp_dir().join("bastion3270_gui_test_profiles.toml");
    app.catalog
        .save_to_file(&tmp_path)
        .expect("save catalog to /tmp");
    let loaded = ProfileCatalog::load_from_file(&tmp_path).expect("load catalog from /tmp");
    assert_eq!(loaded, app.catalog);
    let _ = std::fs::remove_file(&tmp_path);
}

#[test]
fn test_profile_model_change_propagates_to_oia_and_canvas_when_disconnected() {
    use bastion3270_net::ProfileTerminalModel;

    let mut app = Bastion3270GuiApp::new().expect("create gui app");
    assert_eq!(app.oia.rows, 24);
    assert_eq!(app.oia.cols, 80);
    assert!(app.oia.geometry_badge().contains("M2 24×80"));

    // The user sets Model 4 (43x80) in the profile manager and saves.
    app.open_profile_manager();
    if let Some(profile) = app
        .profile_manager
        .as_mut()
        .and_then(|manager| manager.selected_mut())
    {
        profile.connection.terminal_model = ProfileTerminalModel::Model4;
        profile.connection.codepage = "ibm870".to_string();
    }
    assert!(app.save_profile_manager());

    let ctx = egui::Context::default();
    ctx.run_ui(RawInput::default(), |ui| {
        app.render_ui(ui);
    })
    .drop_without_applying_deltas();

    assert_eq!(app.oia.terminal_model, ProfileTerminalModel::Model4);
    assert_eq!(app.oia.rows, 43);
    assert_eq!(app.oia.cols, 80);
    assert_eq!(app.screen.rows(), 43);
    assert_eq!(app.screen.cols(), 80);
    assert_eq!(app.oia.geometry_badge(), "M4 43×80 UNFMT IBM870");
}

#[tokio::test]
async fn test_tab_key_jumps_between_3270_fields_instead_of_gui_buttons() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;

        // Build a screen with two unprotected input fields:
        // Field 1: SF unprotected at (0,0) -> first data cell is (0,1) [R=001, C=002]
        //          SF protected at (0,10) [12-bit addr 10 = 0x40, 0x4A]
        // Field 2: SBA to (1,0) [12-bit addr 80 = 0xC1, 0x50], SF unprotected -> first data cell is (1,1) [R=002, C=002]
        //          SF protected at (1,10) [12-bit addr 90 = 0xC1, 0x5A]
        let setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, // TN3270E header
            0x05, 0xC3, // EraseWrite, restore keyboard
            0x1D, 0x00, // SF unprotected at (0,0)
            0x13, // IC at (0,1)
            0x11, 0x40, 0x4A, // SBA (0,10)
            0x1D, 0x20, // SF protected
            0x11, 0xC1, 0x50, // SBA (1,0)
            0x1D, 0x00, // SF unprotected at (1,0)
            0x11, 0xC1, 0x5A, // SBA (1,10)
            0x1D, 0x20, // SF protected
            0xFF, 0xEF, // IAC EOR
        ];
        socket.write_all(&setup).await.expect("write setup");

        let _ = done_rx.await;
        let _ = socket.shutdown().await;
    });

    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .build()
        .expect("build profile");

    let tcp = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let transport = TransportStream::from_plain(tcp);
    let (handle, event_rx, join_handle) =
        SessionCoordinator::spawn(profile, transport).expect("spawn coordinator");

    let mut app = Bastion3270GuiApp::new().expect("create gui app");
    app.bridge.attach_session(handle, event_rx);

    let ctx = egui::Context::default();
    for _ in 0..40 {
        ctx.run_ui(RawInput::default(), |ui| {
            app.render_ui(ui);
        })
        .drop_without_applying_deltas();
        if app.oia.is_formatted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Initially cursor is at (0, 1) -> OIA 001/002, and NO egui button has focus
    assert_eq!(app.oia.cursor_rc_text(), "001/002");

    // Press Tab without clicking the canvas first:
    // Must jump to the second 3270 input field at (1, 1) -> OIA 002/002,
    // and must keep focus locked on the terminal canvas (never on any GUI toolbar button/ComboBox!).
    let mut tab_input = RawInput::default();
    tab_input.events.push(Event::Key {
        key: Key::Tab,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: Modifiers::NONE,
    });
    ctx.run_ui(tab_input, |ui| {
        // Even at the very start of the frame (before render_ui runs), focus must still be
        // the terminal canvas, proving that egui's begin_pass did NOT move focus to the
        // profile selector ComboBox!
        let canvas_id = egui::Id::unique("bastion3270_terminal_canvas");
        assert_eq!(
            ui.memory(egui::Memory::focused),
            Some(canvas_id),
            "Focus must remain locked on terminal canvas at start of Tab frame (no ComboBox flicker)"
        );
        app.render_ui(ui);
        assert_eq!(
            ui.memory(egui::Memory::focused),
            Some(canvas_id),
            "Focus must remain locked on terminal canvas after render_ui"
        );
    })
.drop_without_applying_deltas();

    for _ in 0..40 {
        app.process_session_events();
        if app.oia.cursor_row == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(app.oia.cursor_rc_text(), "002/002");

    let _ = done_tx.send(());
    app.disconnect_session();
    let _ = srv.await;
    let _ = join_handle.await;
}

/// A mouse click on the terminal moves the 3270 cursor, through the whole application frame
/// (panels, scroll area, focus handling) as in a real window.
#[tokio::test]
async fn test_mouse_click_moves_the_cursor_in_the_app() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        // One unprotected field over the whole screen, cursor at (0, 1).
        let setup = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x00, 0x13, 0xFF, 0xEF,
        ];
        socket.write_all(&setup).await.expect("write setup");
        let _ = done_rx.await;
    });
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .build()
        .expect("build profile");
    let tcp = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let (handle, event_rx, _join) =
        SessionCoordinator::spawn(profile, TransportStream::from_plain(tcp)).expect("spawn");
    let mut app = Bastion3270GuiApp::new().expect("create gui app");
    app.bridge.attach_session(handle.clone(), event_rx);
    for _ in 0..40 {
        app.process_session_events();
        if app.oia.is_formatted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let before = app.oia.cursor_rc_text();

    let ctx = egui::Context::default();
    let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1400.0, 900.0));
    let frame = |app: &mut Bastion3270GuiApp, events: Vec<Event>| {
        let mut input = RawInput {
            screen_rect: Some(screen),
            ..RawInput::default()
        };
        input.events = events;
        ctx.run_ui(input, |ui| app.render_ui(ui))
            .drop_without_applying_deltas();
    };
    frame(&mut app, Vec::new());
    frame(&mut app, Vec::new());
    let at = egui::pos2(400.0, 300.0);
    let press = |pressed| Event::PointerButton {
        pos: at,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: Modifiers::NONE,
    };
    frame(&mut app, vec![Event::PointerMoved(at), press(true)]);
    frame(&mut app, vec![press(false)]);
    for _ in 0..40 {
        app.process_session_events();
        if app.oia.cursor_rc_text() != before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_ne!(
        app.oia.cursor_rc_text(),
        before,
        "the click must move the cursor"
    );
    let _ = done_tx.send(());
    let _ = srv.await;
}

/// Mouse drag selects a rectangle, Ctrl+C copies it, Ctrl+V pastes through the core's paste
/// rules into the field at the cursor (the same behaviour as the web client).
#[tokio::test]
async fn test_drag_select_copy_and_paste() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        mock_negotiate_tn3270e(&mut socket, None).await;
        // Row 0: protected "HELLO WORLD", row 1: unprotected field with the cursor.
        let mut setup = vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x20];
        setup.extend([
            0xC8, 0xC5, 0xD3, 0xD3, 0xD6, 0x40, 0xE6, 0xD6, 0xD9, 0xD3, 0xC4,
        ]);
        setup.extend([0x11, 0xC1, 0x50, 0x1D, 0x00, 0x13, 0xFF, 0xEF]);
        socket.write_all(&setup).await.expect("write setup");
        let _ = done_rx.await;
    });
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .build()
        .expect("build profile");
    let tcp = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let (handle, event_rx, _join) =
        SessionCoordinator::spawn(profile, TransportStream::from_plain(tcp)).expect("spawn");
    let mut app = Bastion3270GuiApp::new().expect("create gui app");
    app.bridge.attach_session(handle.clone(), event_rx);
    for _ in 0..40 {
        app.process_session_events();
        if app.oia.is_formatted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let ctx = egui::Context::default();
    let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1400.0, 900.0));
    let frame = |app: &mut Bastion3270GuiApp, events: Vec<Event>| {
        let mut input = RawInput {
            screen_rect: Some(screen),
            ..RawInput::default()
        };
        input.events = events;
        ctx.run_ui(input, |ui| app.render_ui(ui))
    };
    frame(&mut app, Vec::new()).drop_without_applying_deltas();
    // Drag over a rectangle of row 0 (several cells), then release.
    let start = egui::pos2(300.0, 200.0);
    let end = egui::pos2(420.0, 205.0);
    let button = |pos, pressed| Event::PointerButton {
        pos,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: Modifiers::NONE,
    };
    frame(
        &mut app,
        vec![Event::PointerMoved(start), button(start, true)],
    )
    .drop_without_applying_deltas();
    for step in [1.0_f32, 2.0, 3.0, 4.0, 5.0, 6.0] {
        let p = start + (end - start) * (step / 6.0);
        frame(&mut app, vec![Event::PointerMoved(p)]).drop_without_applying_deltas();
    }
    frame(&mut app, vec![button(end, false)]).drop_without_applying_deltas();
    let sel = app.selection.expect("a drag selects");
    assert!(sel.c1 > sel.c0, "several columns: {sel:?}");

    // Ctrl+C copies exactly the selected text.
    let out = frame(&mut app, vec![Event::Copy]);
    let copied: Vec<String> = out
        .platform_output
        .commands
        .iter()
        .filter_map(|c| match c {
            egui::OutputCommand::CopyText(t) => Some(t.clone()),
            _ => None,
        })
        .collect();
    out.drop_without_applying_deltas();
    let expected = bastion3270_gui::selection::selection_text(&app.screen, Some(sel));
    assert_eq!(copied, vec![expected]);

    // Ctrl+V pastes into the field at the cursor (row 1).
    frame(&mut app, vec![Event::Paste("PASTED".into())]).drop_without_applying_deltas();
    for _ in 0..40 {
        app.process_session_events();
        if app.screen.row_text(1).is_some_and(|r| r.contains("PASTED")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let row1 = app.screen.row_text(1).expect("row 1");
    assert!(row1.contains("PASTED"), "{row1:?}");
    let _ = done_tx.send(());
    let _ = srv.await;
}

/// A host that accepts the connection and never negotiates: the session ends with a timeout.
/// The error is shown once, by the OIA bar — not repeated in the message line, and the
/// "Connecting…" note disappears.
#[tokio::test(flavor = "multi_thread")]
async fn test_session_error_is_shown_only_in_the_oia() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let silent_host = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop(socket);
    });

    let mut app = Bastion3270GuiApp::new().expect("create gui app");
    let profile = app.catalog.selected_mut().expect("selected profile");
    profile.connection.host = "127.0.0.1".to_string();
    profile.connection.port = port;
    profile.connection.tls_mode = TlsMode::Disabled;
    profile.connection.negotiation_timeout_ms = 200;
    app.connect_selected_profile();
    assert!(app
        .status_message
        .as_ref()
        .is_some_and(|m| m.text().starts_with("Connecting to 127.0.0.1")));

    for _ in 0..100 {
        app.process_session_events();
        if matches!(app.oia.session_state, SessionState::Error(_)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let SessionState::Error(err) = &app.oia.session_state else {
        panic!("no session error: {:?}", app.oia.session_state);
    };
    assert!(app.oia.protocol_badge().contains(err.as_str()));
    assert_eq!(app.status_message, None, "the error must not be repeated");
    silent_host.abort();
}

/// A host whose certificate no trusted CA issued (self-signed, as many z/OS test systems): the
/// app opens the trust dialog with the certificate's details; trusting it pins the SHA-256 to
/// the profile and the next connection is accepted.
#[tokio::test(flavor = "multi_thread")]
async fn test_refused_host_certificate_can_be_trusted_for_the_profile() {
    use std::sync::Arc;
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["zos1.bank.example".to_owned()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "zos1.bank.example");
    let cert = params.self_signed(&key).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls_pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
    let host = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            if let Ok(tls) = acceptor.accept(tcp).await {
                let _ = accepted_tx.send(());
                tokio::time::sleep(Duration::from_secs(5)).await;
                drop(tls);
            }
        }
    });

    let mut app = Bastion3270GuiApp::new().expect("create gui app");
    let profile = app.catalog.selected_mut().expect("selected profile");
    profile.connection.host = "127.0.0.1".to_string();
    profile.connection.port = port;
    profile.connection.tls_mode = TlsMode::Enabled;
    let profile_name = profile.name.clone();
    app.connect_selected_profile();
    for _ in 0..100 {
        app.process_session_events();
        if app.untrusted_certificate.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let prompt = app.untrusted_certificate.clone().expect("trust dialog");
    assert_eq!(prompt.profile_name, profile_name);
    assert_eq!(prompt.rejection.certificate.subject, "CN=zos1.bank.example");
    assert_eq!(
        prompt.rejection.certificate.names,
        ["DNS:zos1.bank.example"]
    );

    // The dialog renders.
    let ctx = egui::Context::default();
    ctx.run_ui(RawInput::default(), |ui| app.render_ui(ui))
        .drop_without_applying_deltas();

    app.trust_refused_certificate();
    assert_eq!(app.untrusted_certificate, None);
    assert_eq!(
        app.catalog
            .selected()
            .unwrap()
            .connection
            .pinned_cert_sha256,
        Some(prompt.rejection.certificate.sha256_hex()),
        "the pin is stored in the profile (and so saved)"
    );
    tokio::time::timeout(Duration::from_secs(5), accepted_rx.recv())
        .await
        .expect("the pinned certificate is accepted")
        .expect("host running");
    host.abort();
}

/// View menu settings change the session and are stored in the selected profile (and so saved).
#[test]
fn test_view_settings_are_stored_in_the_selected_profile() {
    let mut app = Bastion3270GuiApp::new().expect("create gui app");
    let scheme = TerminalColorScheme::ALL[1];
    app.set_color_scheme(scheme);
    app.set_crosshair(true);
    app.set_highlight_input_fields(true);

    assert_eq!(app.theme.color_scheme, scheme);
    assert!(app.theme.crosshair_enabled && app.theme.highlight_input_fields);
    let profile = app.catalog.selected().expect("selected profile");
    assert_eq!(profile.color_scheme, scheme);
    assert!(profile.crosshair_enabled && profile.highlight_input_fields);

    // The menu bar, message line and About window render headless.
    app.show_about = true;
    app.status_message = Some(bastion3270_gui::message::StatusMessage::warning("check"));
    let ctx = egui::Context::default();
    ctx.run_ui(RawInput::default(), |ui| app.render_ui(ui))
        .drop_without_applying_deltas();
    assert!(app.show_about);
}

/// The desktop profile example of `docs/CONFIGURATION.md` is a valid profile file.
#[test]
fn test_documented_profile_file_example_loads() {
    // A Windows checkout may have CRLF line ends (Git's `core.autocrlf`).
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/CONFIGURATION.md"
    ))
    .expect("read the configuration reference")
    .replace("\r\n", "\n");
    let section = doc
        .split("## 3. Desktop client profiles")
        .nth(1)
        .expect("section 3");
    let example = section
        .split("```toml\n")
        .nth(1)
        .and_then(|rest| rest.split("```").next())
        .expect("a TOML example");
    let catalog = ProfileCatalog::from_toml_str(example).expect("the example loads");
    let profile = catalog.selected().expect("one profile");
    assert_eq!(profile.keyboard, KeyboardPreset::Pcomm);
    assert_eq!(profile.color_scheme, TerminalColorScheme::Classic3279);
    assert_eq!(profile.cursor_style, CursorStyle::Block);
}
