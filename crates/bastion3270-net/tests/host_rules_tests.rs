//! Host-side rules through a real session against a mock host: keyboard locks and typeahead
//! (`x3270` `ctlr_write`, `ctlr_erase_all_unprotected`, `restore_keyboard`,
//! `query_reply_end`, `kybd_connect`, `enq_xta`, `run_ta`) and inbound replies with their
//! TN3270E responses (`process_ds`, `net_output`, `process_eor`).

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
use bastion3270_net::profile::{ConnectionProfileBuilder, TlsMode};
use bastion3270_net::session::{SessionCoordinator, SessionEvent, SessionHandle};
use bastion3270_net::transport::{connect_tcp_stream, TransportStream};

const IAC: u8 = 0xFF;
const EOR: u8 = 0xEF;
/// TN3270E 3270-DATA header with no response requested.
const HDR: [u8; 5] = [0x00, 0x00, 0x00, 0x00, 0x01];
/// TN3270E 3270-DATA header with the KEYBOARD-RESTORE request flag.
const HDR_RESTORE: [u8; 5] = [0x00, 0x02, 0x00, 0x00, 0x02];
/// Erase/Write, WCC keyboard restore, one unprotected field, IC.
const EW_RESTORE: [u8; 5] = [0xF5, 0xC3, 0x1D, 0x40, 0x13];
/// Write, WCC without keyboard restore.
const W_NO_RESTORE: [u8; 2] = [0xF1, 0x00];
/// Erase All Unprotected.
const EAU: [u8; 1] = [0x6F];
/// WSF Read Partition Query.
const WSF_QUERY: [u8; 6] = [0xF3, 0x00, 0x05, 0x01, 0xFF, 0x02];

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

/// Host side of TN3270E with RESPONSES only (no BIND, 3270 data flows at once).
async fn host_tn3270e(socket: &mut TcpStream) {
    let mut buf = [0u8; 512];
    socket.write_all(&[IAC, 0xFD, 0x28]).await.unwrap();
    let _ = socket.read(&mut buf).await.unwrap();
    socket
        .write_all(&[IAC, 0xFA, 0x28, 0x08, 0x02, IAC, 0xF0])
        .await
        .unwrap();
    let _ = socket.read(&mut buf).await.unwrap();
    let mut is = vec![IAC, 0xFA, 0x28, 0x02, 0x04];
    is.extend_from_slice(b"IBM-3278-2-E");
    is.extend_from_slice(&[IAC, 0xF0]);
    socket.write_all(&is).await.unwrap();
    let _ = socket.read(&mut buf).await.unwrap();
    socket
        .write_all(&[IAC, 0xFA, 0x28, 0x03, 0x04, 0x02, IAC, 0xF0])
        .await
        .unwrap();
}

/// Mock host: negotiates TN3270E, then sends each scripted record when the test asks for it
/// and forwards everything the client sends.
fn spawn_host(
    listener: TcpListener,
) -> (
    mpsc::UnboundedSender<Vec<u8>>,
    mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let (to_host, mut script) = mpsc::unbounded_channel::<Vec<u8>>();
    let (from_client_tx, from_client) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = socket;
        host_tn3270e(&mut socket).await;
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
        while let Some(rec) = script.recv().await {
            wr.write_all(&rec).await.unwrap();
        }
    });
    (to_host, from_client)
}

async fn connect(port: u16) -> (SessionHandle, mpsc::Receiver<SessionEvent>) {
    let profile = ConnectionProfileBuilder::new()
        .host("127.0.0.1")
        .port(port)
        .tls_mode(TlsMode::Disabled)
        .idle_timeout_ms(10_000)
        .build()
        .expect("profile");
    let tcp = connect_tcp_stream("127.0.0.1", port)
        .await
        .expect("connect");
    let (handle, events, _join) =
        SessionCoordinator::spawn(profile, TransportStream::from_plain(tcp)).expect("spawn");
    (handle, events)
}

/// Waits until the keyboard reports `want`.
async fn keyboard_becomes(events: &mut mpsc::Receiver<SessionEvent>, want: KeyboardState) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(ev) = events.recv().await {
            if ev == SessionEvent::KeyboardStateChanged(want) {
                return;
            }
        }
        panic!("event channel closed");
    })
    .await
    .unwrap_or_else(|_| panic!("keyboard never became {want:?}"));
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

/// Session with the first screen written and the keyboard unlocked.
async fn ready_session() -> (
    SessionHandle,
    mpsc::Receiver<SessionEvent>,
    mpsc::UnboundedSender<Vec<u8>>,
    mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (host, client) = spawn_host(listener);
    let (handle, mut events) = connect(port).await;
    keyboard_becomes(&mut events, KeyboardState::AwaitingFirst).await;
    host.send(record(HDR, &EW_RESTORE)).unwrap();
    keyboard_becomes(&mut events, KeyboardState::Unlocked).await;
    (handle, events, host, client)
}

#[tokio::test]
async fn enter_before_the_first_screen_is_sent_after_it() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (host, mut client) = spawn_host(listener);
    let (handle, mut events) = connect(port).await;
    keyboard_becomes(&mut events, KeyboardState::AwaitingFirst).await;
    let _ = client_bytes(&mut client, 100).await; // negotiation replies

    // Pressed before the host wrote anything: held, nothing on the wire.
    handle.press_aid(AidKey::Enter).await.expect("queued");
    assert_eq!(client_bytes(&mut client, 150).await, Vec::<u8>::new());

    // The first screen arrives; the queued Enter goes out by itself.
    host.send(record(HDR, &EW_RESTORE)).unwrap();
    let sent = client_bytes(&mut client, 300).await;
    assert_eq!(
        sent.get(5),
        Some(&0x7D),
        "Enter AID after the header: {sent:02X?}"
    );
}

#[tokio::test]
async fn erase_all_unprotected_restores_the_keyboard() {
    let (handle, mut events, host, _client) = ready_session().await;
    handle.press_aid(AidKey::Enter).await.unwrap();
    keyboard_becomes(&mut events, KeyboardState::TimeWait).await;

    host.send(record(HDR, &EAU)).unwrap();
    keyboard_becomes(&mut events, KeyboardState::Unlocked).await;
}

#[tokio::test]
async fn write_without_restore_leaves_x_system_until_reset() {
    let (handle, mut events, host, _client) = ready_session().await;
    handle.press_aid(AidKey::Enter).await.unwrap();
    keyboard_becomes(&mut events, KeyboardState::TimeWait).await;

    host.send(record(HDR, &W_NO_RESTORE)).unwrap();
    keyboard_becomes(&mut events, KeyboardState::SystemLock).await;

    handle
        .send_action(bastion3270_core::keyboard::ActionKey::Reset)
        .await
        .unwrap();
    keyboard_becomes(&mut events, KeyboardState::Unlocked).await;
}

#[tokio::test]
async fn tn3270e_keyboard_restore_flag_unlocks() {
    let (handle, mut events, host, _client) = ready_session().await;
    handle.press_aid(AidKey::Enter).await.unwrap();
    keyboard_becomes(&mut events, KeyboardState::TimeWait).await;

    // A Write without WCC restore, but with the TN3270E KEYBOARD-RESTORE request flag.
    host.send(record(HDR_RESTORE, &W_NO_RESTORE)).unwrap();
    keyboard_becomes(&mut events, KeyboardState::Unlocked).await;
}

#[tokio::test]
async fn query_reply_inhibits_input_until_the_next_write() {
    let (_handle, mut events, host, mut client) = ready_session().await;
    let _ = client_bytes(&mut client, 50).await;

    host.send(record(HDR, &WSF_QUERY)).unwrap();
    keyboard_becomes(&mut events, KeyboardState::Inhibit).await;
    assert_eq!(
        client_bytes(&mut client, 200).await.get(5),
        Some(&0x88),
        "query reply AID"
    );

    host.send(record(HDR, &W_NO_RESTORE)).unwrap();
    keyboard_becomes(&mut events, KeyboardState::Unlocked).await;
}

#[tokio::test]
async fn input_dropped_by_an_operator_error_rings_the_bell() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (host, _client) = spawn_host(listener);
    let (handle, mut events) = connect(port).await;
    keyboard_becomes(&mut events, KeyboardState::AwaitingFirst).await;
    // Erase/Write with restore, one *protected* field, cursor inside it.
    host.send(record(HDR, &[0xF5, 0xC3, 0x1D, 0x60, 0x13]))
        .unwrap();
    keyboard_becomes(&mut events, KeyboardState::Unlocked).await;

    assert!(handle.send_key('A').await.is_err());
    keyboard_becomes(&mut events, KeyboardState::Protected).await;

    // Typing on is refused under the operator error: the bell rings, nothing is lost silently.
    assert!(handle.send_key('B').await.is_err());
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(ev) = events.recv().await {
            if ev == SessionEvent::Alarm {
                return;
            }
        }
    })
    .await
    .expect("alarm for dropped input");
}

/// TN3270E 3270-DATA header with ALWAYS-RESPONSE, sequence `seq`.
const fn hdr_always(seq: u8) -> [u8; 5] {
    [0x00, 0x00, 0x02, 0x00, seq]
}

/// Positive TN3270E response record for sequence `seq`.
fn positive(seq: u8) -> Vec<u8> {
    vec![0x02, 0x00, 0x00, 0x00, seq, 0x00, IAC, EOR]
}

#[tokio::test]
async fn host_read_modified_is_answered_with_the_current_aid() {
    let (handle, mut events, host, mut client) = ready_session().await;
    let _ = client_bytes(&mut client, 50).await;
    handle.press_aid(AidKey::PF3).await.unwrap();
    keyboard_becomes(&mut events, KeyboardState::TimeWait).await;
    let _ = client_bytes(&mut client, 100).await; // the PF3 record itself

    // Read Modified from the host: answered with PF3, not 0x60.
    host.send(record(HDR, &[0xF6])).unwrap();
    let reply = client_bytes(&mut client, 200).await;
    assert_eq!(reply.get(5), Some(&0xF3), "{reply:02X?}");
}

#[tokio::test]
async fn positive_response_precedes_the_reply() {
    let (_handle, _events, host, mut client) = ready_session().await;
    let _ = client_bytes(&mut client, 50).await;

    // Read Buffer with ALWAYS-RESPONSE: the response comes first, then the data, once.
    host.send(record(hdr_always(9), &[0xF2])).unwrap();
    let wire = client_bytes(&mut client, 200).await;
    let ack = positive(9);
    assert_eq!(&wire[..ack.len()], ack.as_slice(), "{wire:02X?}");
    assert_eq!(wire.get(ack.len()), Some(&0x00), "3270-DATA record follows");
    assert_eq!(
        wire.get(ack.len() + 5),
        Some(&0x60),
        "Read Buffer with no AID"
    );
    assert_eq!(
        wire.windows(ack.len())
            .filter(|w| *w == ack.as_slice())
            .count(),
        1,
        "exactly one positive response"
    );
}

#[tokio::test]
async fn error_response_is_sent_even_after_a_reply() {
    let (_handle, _events, host, mut client) = ready_session().await;
    let _ = client_bytes(&mut client, 50).await;

    // ERROR-RESPONSE, WSF [Query] [malformed field]: the query reply goes out, and the
    // error still gets its negative response (x3270 clears `response_required` only for
    // ALWAYS-RESPONSE).
    let hdr = [0x00, 0x00, 0x01, 0x00, 0x0A];
    host.send(record(
        hdr,
        &[0xF3, 0x00, 0x05, 0x01, 0xFF, 0x02, 0x00, 0x02, 0x03],
    ))
    .unwrap();
    let wire = client_bytes(&mut client, 300).await;
    assert_eq!(wire.get(5), Some(&0x88), "query reply first: {wire:02X?}");
    let nak = [0x02, 0x00, 0x01, 0x00, 0x0A, 0x00, IAC, EOR];
    assert!(
        wire.windows(nak.len()).any(|w| w == nak),
        "COMMAND-REJECT response: {wire:02X?}"
    );
}

#[tokio::test]
async fn write_inside_a_wsf_restores_the_keyboard() {
    let (handle, mut events, host, _client) = ready_session().await;
    handle.press_aid(AidKey::Enter).await.unwrap();
    keyboard_becomes(&mut events, KeyboardState::TimeWait).await;

    // WSF Outbound 3270DS: Write with WCC keyboard restore.
    host.send(record(HDR, &[0xF3, 0x00, 0x06, 0x40, 0x00, 0xF1, 0xC2]))
        .unwrap();
    keyboard_becomes(&mut events, KeyboardState::Unlocked).await;
}
