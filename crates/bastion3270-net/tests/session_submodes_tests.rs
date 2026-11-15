//! TN3270E session submodes through a real session against a mock host: BIND screen sizes and
//! UNBIND, SSCP-LU data, NVT data (`x3270` `telnet.c` `process_bind`, `process_eor`,
//! `net_output`, `telnet_fsm`; `ctlr.c` `ctlr_write_sscp_lu`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use bastion3270_core::keyboard::{AidKey, KeyboardState};
use bastion3270_core::SafeScreenView;
use bastion3270_net::profile::{ConnectionProfileBuilder, ProfileTerminalModel, TlsMode};
use bastion3270_net::session::{SessionCoordinator, SessionEvent, SessionHandle};
use bastion3270_net::transport::{connect_tcp_stream, TransportStream};

const IAC: u8 = 0xFF;
const EOR: u8 = 0xEF;
/// TN3270E 3270-DATA header with no response requested.
const HDR: [u8; 5] = [0x00, 0x00, 0x00, 0x00, 0x01];
/// Erase/Write, WCC keyboard restore, one unprotected field.
const EW_RESTORE: [u8; 4] = [0xF5, 0xC3, 0x1D, 0x40];
/// TN3270E function RESPONSES only (bound at once, no BIND).
const FUNCTIONS_RESPONSES: &[u8] = &[0x02];
/// TN3270E functions BIND-IMAGE, RESPONSES and SYSREQ.
const FUNCTIONS_BOUND: &[u8] = &[0x00, 0x02, 0x04];

/// Frames a TN3270E record: header and body with IAC doubled, then `IAC EOR`.
fn record(header: [u8; 5], body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    for &b in header.iter().chain(body) {
        v.push(b);
        if b == IAC {
            v.push(IAC);
        }
    }
    v.extend_from_slice(&[IAC, EOR]);
    v
}

/// A BIND-IMAGE record with screen size byte `ssize` and RD/CD/RA/CA.
fn bind_record(opcode: u8, ssize: u8, sizes: [u8; 4]) -> Vec<u8> {
    let mut ru = vec![0x00; 35];
    ru[0] = opcode;
    ru[20..24].copy_from_slice(&sizes);
    ru[24] = ssize;
    record([0x03, 0x00, 0x00, 0x00, 0x00], &ru)
}

/// Host side of TN3270E negotiation with the given functions, after an optional NVT banner.
async fn host_tn3270e(socket: &mut TcpStream, banner: &[u8], functions: &[u8]) {
    let mut buf = [0u8; 512];
    if !banner.is_empty() {
        socket.write_all(banner).await.unwrap();
    }
    socket.write_all(&[IAC, 0xFD, 0x28]).await.unwrap();
    let _ = socket.read(&mut buf).await.unwrap();
    socket
        .write_all(&[IAC, 0xFA, 0x28, 0x08, 0x02, IAC, 0xF0])
        .await
        .unwrap();
    let _ = socket.read(&mut buf).await.unwrap();
    let mut is = vec![IAC, 0xFA, 0x28, 0x02, 0x04];
    is.extend_from_slice(b"IBM-3278-5-E");
    is.extend_from_slice(&[IAC, 0xF0]);
    socket.write_all(&is).await.unwrap();
    let _ = socket.read(&mut buf).await.unwrap();
    let mut fis = vec![IAC, 0xFA, 0x28, 0x03, 0x04];
    fis.extend_from_slice(functions);
    fis.extend_from_slice(&[IAC, 0xF0]);
    socket.write_all(&fis).await.unwrap();
}

/// Mock host: negotiates TN3270E, then sends each scripted chunk and forwards what the client
/// sends.
fn spawn_host(
    listener: TcpListener,
    banner: &'static [u8],
    functions: &'static [u8],
) -> (
    mpsc::UnboundedSender<Vec<u8>>,
    mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let (to_host, mut script) = mpsc::unbounded_channel::<Vec<u8>>();
    let (from_client_tx, from_client) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        host_tn3270e(&mut socket, banner, functions).await;
        let (mut rd, mut wr) = socket.into_split();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok(n) = rd.read(&mut buf).await {
                if n == 0 {
                    return;
                }
                let _ = from_client_tx.send(buf[..n].to_vec());
            }
        });
        while let Some(chunk) = script.recv().await {
            wr.write_all(&chunk).await.unwrap();
        }
    });
    (to_host, from_client)
}

async fn session(
    functions: &'static [u8],
) -> (
    SessionHandle,
    mpsc::Receiver<SessionEvent>,
    mpsc::UnboundedSender<Vec<u8>>,
    mpsc::UnboundedReceiver<Vec<u8>>,
) {
    session_with_banner(b"", functions).await
}

async fn session_with_banner(
    banner: &'static [u8],
    functions: &'static [u8],
) -> (
    SessionHandle,
    mpsc::Receiver<SessionEvent>,
    mpsc::UnboundedSender<Vec<u8>>,
    mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (host, client) = spawn_host(listener, banner, functions);
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .terminal_model(ProfileTerminalModel::Model5)
        .idle_timeout_ms(10_000)
        .build()
        .expect("profile");
    let tcp = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let (handle, events, _join) =
        SessionCoordinator::spawn(profile, TransportStream::from_plain(tcp)).expect("spawn");
    (handle, events, host, client)
}

/// Waits for an event matching `pred`.
async fn event_where(
    events: &mut mpsc::Receiver<SessionEvent>,
    what: &str,
    mut pred: impl FnMut(&SessionEvent) -> bool,
) -> SessionEvent {
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(ev) = events.recv().await {
            if pred(&ev) {
                return ev;
            }
        }
        panic!("event channel closed");
    })
    .await
    .unwrap_or_else(|_| panic!("never saw {what}"))
}

async fn screen_where(
    events: &mut mpsc::Receiver<SessionEvent>,
    what: &str,
    mut pred: impl FnMut(&SafeScreenView) -> bool,
) -> SafeScreenView {
    match event_where(
        events,
        what,
        |ev| matches!(ev, SessionEvent::ScreenUpdated(v) if pred(v)),
    )
    .await
    {
        SessionEvent::ScreenUpdated(view) => view,
        _ => unreachable!(),
    }
}

async fn keyboard_becomes(events: &mut mpsc::Receiver<SessionEvent>, want: KeyboardState) {
    event_where(events, &format!("keyboard {want:?}"), |ev| {
        *ev == SessionEvent::KeyboardStateChanged(want)
    })
    .await;
}

#[tokio::test]
async fn bind_sets_the_screen_size_and_unbind_restores_it() {
    let (_handle, mut events, host, _client) = session(FUNCTIONS_BOUND).await;
    keyboard_becomes(&mut events, KeyboardState::AwaitingFirst).await;

    // BIND: 27x132 as default and alternate size.
    host.send(bind_record(0x31, 0x7E, [27, 132, 0, 0])).unwrap();
    screen_where(&mut events, "27x132 screen", |v| {
        v.rows() == 27 && v.cols() == 132
    })
    .await;

    host.send(record(HDR, &EW_RESTORE)).unwrap();
    keyboard_becomes(&mut events, KeyboardState::Unlocked).await;

    // UNBIND: erased, 24x80, waiting for the next BIND.
    host.send(record([0x04, 0x00, 0x00, 0x00, 0x00], &[0x01]))
        .unwrap();
    keyboard_becomes(&mut events, KeyboardState::AwaitingFirst).await;
    screen_where(&mut events, "erased 24x80 screen", |v| {
        v.rows() == 24 && v.cols() == 80 && !v.is_formatted()
    })
    .await;

    // A normal UNBIND followed by the next BIND is what `logon` at the VTAM screen does: no
    // warning for the operator (x3270 only traces it), the mode change is in the OIA.
    host.send(bind_record(0x31, 0x7E, [27, 132, 0, 0])).unwrap();
    let mut warned = false;
    event_where(&mut events, "the next BIND", |ev| {
        warned |= matches!(ev, SessionEvent::Warning(_));
        matches!(ev, SessionEvent::ScreenUpdated(v) if v.cols() == 132)
    })
    .await;
    assert!(!warned, "a normal UNBIND is not a warning");
}

#[tokio::test]
async fn bind_with_an_impossible_size_warns_and_keeps_24x80() {
    let (_handle, mut events, host, _client) = session(FUNCTIONS_BOUND).await;
    keyboard_becomes(&mut events, KeyboardState::AwaitingFirst).await;
    host.send(bind_record(0x31, 0x7E, [62, 160, 0, 0])).unwrap();
    event_where(
        &mut events,
        "BIND size warning",
        |ev| matches!(ev, SessionEvent::Warning(w) if w.contains("62x160")),
    )
    .await;
    screen_where(&mut events, "24x80 screen", |v| {
        v.rows() == 24 && v.cols() == 80
    })
    .await;
}

#[tokio::test]
async fn malformed_bind_still_binds_the_session() {
    let (_handle, mut events, host, _client) = session(FUNCTIONS_BOUND).await;
    keyboard_becomes(&mut events, KeyboardState::AwaitingFirst).await;
    // Wrong BIND opcode: discarded, but 3270 data is accepted afterwards.
    host.send(bind_record(0x99, 0x00, [0; 4])).unwrap();
    host.send(record(HDR, &EW_RESTORE)).unwrap();
    keyboard_becomes(&mut events, KeyboardState::Unlocked).await;
}

/// Collects the client's bytes for a while.
async fn client_bytes(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>, ms: u64) -> Vec<u8> {
    let mut all = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    while let Ok(Some(chunk)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        all.extend_from_slice(&chunk);
    }
    all
}

/// "USS" followed by NL, in EBCDIC.
const USS_TEXT: [u8; 4] = [0xE4, 0xE2, 0xE2, 0x15];

#[tokio::test]
async fn sscp_lu_data_is_shown_unacknowledged_and_input_goes_back_as_sscp_lu_data() {
    let (handle, mut events, host, mut client) = session(FUNCTIONS_RESPONSES).await;
    keyboard_becomes(&mut events, KeyboardState::AwaitingFirst).await;
    let _ = client_bytes(&mut client, 50).await;

    // SSCP-LU-DATA with ALWAYS-RESPONSE: shown, keyboard free, no response (x3270).
    host.send(record([0x07, 0x00, 0x02, 0x00, 0x05], &USS_TEXT))
        .unwrap();
    screen_where(&mut events, "USS text", |v| {
        v.row_text_trimmed(0).as_deref() == Some("USS")
    })
    .await;
    keyboard_becomes(&mut events, KeyboardState::Unlocked).await;
    assert_eq!(client_bytes(&mut client, 150).await, Vec::<u8>::new());

    // Typed input and Enter go back as SSCP-LU-DATA, without AID or cursor address.
    handle.send_string("LOGON").await.unwrap();
    handle.press_aid(AidKey::Enter).await.unwrap();
    let sent = client_bytes(&mut client, 300).await;
    assert_eq!(
        sent.first(),
        Some(&0x07),
        "SSCP-LU-DATA header: {sent:02X?}"
    );
    assert_eq!(
        sent.get(5..),
        Some(&[0xD3, 0xD6, 0xC7, 0xD6, 0xD5, IAC, EOR][..]),
        "{sent:02X?}"
    );

    // Other AIDs are invalid in SSCP-LU mode.
    assert!(handle.press_aid(AidKey::PF3).await.is_err());
    assert_eq!(
        handle.query_keyboard_state().await.unwrap(),
        KeyboardState::NotAvailable
    );

    // 3270 data returns to 3270 mode: replies carry the 3270-DATA header again.
    handle
        .send_action(bastion3270_core::ActionKey::Reset)
        .await
        .unwrap();
    host.send(record(HDR, &EW_RESTORE)).unwrap();
    screen_where(
        &mut events,
        "formatted screen",
        SafeScreenView::is_formatted,
    )
    .await;
    let _ = client_bytes(&mut client, 50).await;
    handle.press_aid(AidKey::Enter).await.unwrap();
    let sent = client_bytes(&mut client, 300).await;
    assert_eq!(sent.first(), Some(&0x00), "3270-DATA header: {sent:02X?}");
}

#[tokio::test]
async fn non_display_records_get_no_response() {
    let (_handle, mut events, host, mut client) = session(FUNCTIONS_RESPONSES).await;
    keyboard_becomes(&mut events, KeyboardState::AwaitingFirst).await;
    let _ = client_bytes(&mut client, 50).await;
    // SCS, REQUEST and RESPONSE records with ALWAYS-RESPONSE are ignored (x3270 `process_eor`).
    for data_type in [0x01, 0x06, 0x02] {
        host.send(record([data_type, 0x00, 0x02, 0x00, 0x09], &[0x00]))
            .unwrap();
    }
    assert_eq!(client_bytes(&mut client, 200).await, Vec::<u8>::new());
}

#[tokio::test]
async fn nvt_banner_before_negotiation_is_not_part_of_the_first_record() {
    let (_handle, mut events, host, _client) =
        session_with_banner(b"Welcome to the host\r\n", FUNCTIONS_RESPONSES).await;
    event_where(
        &mut events,
        "NVT banner",
        |ev| matches!(ev, SessionEvent::NvtData(d) if d.as_slice() == b"Welcome to the host\r\n"),
    )
    .await;
    keyboard_becomes(&mut events, KeyboardState::AwaitingFirst).await;
    // The first 3270 record is executed on its own: a formatted screen, keyboard unlocked.
    host.send(record(HDR, &EW_RESTORE)).unwrap();
    screen_where(
        &mut events,
        "formatted screen",
        SafeScreenView::is_formatted,
    )
    .await;
    keyboard_becomes(&mut events, KeyboardState::Unlocked).await;
}

#[tokio::test]
async fn nvt_data_with_always_response_is_acknowledged() {
    let (handle, mut events, host, mut client) = session(FUNCTIONS_RESPONSES).await;
    keyboard_becomes(&mut events, KeyboardState::AwaitingFirst).await;
    let _ = client_bytes(&mut client, 50).await;

    host.send(record([0x05, 0x00, 0x02, 0x00, 0x07], b"IBM VM"))
        .unwrap();
    event_where(&mut events, "NVT mode", |ev| {
        *ev == SessionEvent::HostModeChanged(bastion3270_core::HostMode::Nvt)
    })
    .await;
    // Positive response for sequence 7 (x3270 `process_eor` NVT-DATA).
    assert_eq!(
        client_bytes(&mut client, 200).await,
        vec![0x02, 0x00, 0x00, 0x00, 0x07, 0x00, IAC, EOR]
    );
    // No NVT input path: the keyboard says so.
    assert_eq!(
        handle.query_keyboard_state().await.unwrap(),
        KeyboardState::NotAvailable
    );

    // NVT-DATA without ALWAYS-RESPONSE is not acknowledged.
    host.send(record([0x05, 0x00, 0x00, 0x00, 0x08], b"more"))
        .unwrap();
    assert_eq!(client_bytes(&mut client, 200).await, Vec::<u8>::new());
}
