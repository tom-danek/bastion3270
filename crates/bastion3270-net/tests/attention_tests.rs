//! Attn / `SysReq` on the wire: what the client sends to a (mock) host in each connection mode
//! (`x3270` `Attn_action`, `SysReq_action`, `net_interrupt`, `net_abort`, `net_break`).

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

use bastion3270_core::keyboard::{AttentionKey, KeyboardState};
use bastion3270_net::profile::{ConnectionProfileBuilder, TlsMode};
use bastion3270_net::session::{SessionCoordinator, SessionEvent, SessionHandle};
use bastion3270_net::transport::{connect_tcp_stream, TransportStream};

const IAC: u8 = 0xFF;
const EOR: u8 = 0xEF;
const IP: u8 = 0xF4;
const AO: u8 = 0xF5;
const BREAK: u8 = 0xF3;

/// Reads exactly `want` bytes from the client. Never more: two client records that arrive in
/// one TCP segment must still be returned by two calls.
async fn read_exact_n(socket: &mut TcpStream, want: usize) -> Vec<u8> {
    let mut got = vec![0u8; want];
    tokio::time::timeout(Duration::from_secs(2), socket.read_exact(&mut got))
        .await
        .expect("client bytes in time")
        .expect("read");
    got
}

/// Host side of TN3270E with BIND-IMAGE, RESPONSES and SYSREQ, followed by a BIND.
async fn host_tn3270e_bound(socket: &mut TcpStream) {
    let mut buf = [0u8; 512];
    socket.write_all(&[IAC, 0xFD, 0x28]).await.unwrap(); // DO TN3270E
    let _ = socket.read(&mut buf).await.unwrap();
    socket
        .write_all(&[IAC, 0xFA, 0x28, 0x08, 0x02, IAC, 0xF0]) // SEND DEVICE-TYPE
        .await
        .unwrap();
    let _ = socket.read(&mut buf).await.unwrap();
    let mut is = vec![IAC, 0xFA, 0x28, 0x02, 0x04];
    is.extend_from_slice(b"IBM-3278-2-E");
    is.extend_from_slice(&[IAC, 0xF0]);
    socket.write_all(&is).await.unwrap(); // DEVICE-TYPE IS
    let _ = socket.read(&mut buf).await.unwrap();
    socket
        .write_all(&[IAC, 0xFA, 0x28, 0x03, 0x04, 0x00, 0x02, 0x04, IAC, 0xF0]) // FUNCTIONS IS
        .await
        .unwrap();
    let mut bind = vec![0x03, 0x00, 0x00, 0x00, 0x01, 0x31];
    bind.extend_from_slice(&[0x00; 34]);
    bind.extend_from_slice(&[IAC, EOR]);
    socket.write_all(&bind).await.unwrap(); // BIND-IMAGE
}

/// Host side of plain TN3270 (TTYPE, EOR and BINARY both ways).
async fn host_tn3270(socket: &mut TcpStream) {
    let mut buf = [0u8; 512];
    socket.write_all(&[IAC, 0xFD, 0x18]).await.unwrap(); // DO TTYPE
    let _ = socket.read(&mut buf).await.unwrap();
    socket
        .write_all(&[
            IAC, 0xFA, 0x18, 0x01, IAC, 0xF0, // SB TTYPE SEND
            IAC, 0xFD, 0x19, IAC, 0xFB, 0x19, // DO EOR, WILL EOR
            IAC, 0xFD, 0x00, IAC, 0xFB, 0x00, // DO BINARY, WILL BINARY
        ])
        .await
        .unwrap();
    // First screen: Erase/Write with keyboard restore (the keyboard waits for it).
    socket.write_all(&[0xF5, 0xC3, IAC, EOR]).await.unwrap();
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

async fn wait_negotiated(events: &mut mpsc::Receiver<SessionEvent>) {
    while let Some(ev) = events.recv().await {
        if matches!(ev, SessionEvent::NegotiationComplete { .. }) {
            return;
        }
    }
    panic!("negotiation never completed");
}

/// Waits until the client has processed the host's last record (status reflects the BIND).
async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn tn3270e_attn_sends_ip_and_sysreq_sends_ao() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let host = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        host_tn3270e_bound(&mut socket).await;
        tx.send(read_exact_n(&mut socket, 2).await).unwrap();
        tx.send(read_exact_n(&mut socket, 2).await).unwrap();
    });

    let (handle, mut events) = connect(port).await;
    wait_negotiated(&mut events).await;
    settle().await;

    handle.press_attention(AttentionKey::Attn).await.unwrap();
    assert_eq!(rx.recv().await.unwrap(), vec![IAC, IP]);
    handle.press_attention(AttentionKey::SysReq).await.unwrap();
    assert_eq!(rx.recv().await.unwrap(), vec![IAC, AO]);
    host.await.unwrap();
}

#[tokio::test]
async fn tn3270_attn_sends_pa1_then_break_even_while_locked() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let host = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        host_tn3270(&mut socket).await;
        // Drain the client's negotiation replies, then collect the Enter and the Attn.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut buf = [0u8; 512];
        let _ = socket.read(&mut buf).await.unwrap();
        tx.send(Vec::new()).unwrap();
        // Enter on an empty unformatted screen: AID + cursor + IAC EOR.
        let _enter = read_exact_n(&mut socket, 5).await;
        tx.send(read_exact_n(&mut socket, 5).await).unwrap();
    });

    let (handle, mut events) = connect(port).await;
    wait_negotiated(&mut events).await;
    assert_eq!(rx.recv().await.unwrap(), Vec::<u8>::new());
    while let Some(ev) = events.recv().await {
        if matches!(ev, SessionEvent::ScreenUpdated(_)) {
            break;
        }
    }

    // Enter locks the keyboard (X Wait); Attn must still reach the host.
    handle
        .press_aid(bastion3270_core::keyboard::AidKey::Enter)
        .await
        .unwrap();
    handle.press_attention(AttentionKey::Attn).await.unwrap();
    assert_eq!(rx.recv().await.unwrap(), vec![0x6C, IAC, EOR, IAC, BREAK]);
    host.await.unwrap();
}

#[tokio::test]
async fn tn3270e_attn_without_bind_shows_function_not_available() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
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
        // RESPONSES only: no BIND-IMAGE, so no SNA session to interrupt.
        socket
            .write_all(&[IAC, 0xFA, 0x28, 0x03, 0x04, 0x02, IAC, 0xF0])
            .await
            .unwrap();
        // Nothing may be sent for the Attn.
        let res = tokio::time::timeout(Duration::from_millis(300), socket.read(&mut buf)).await;
        assert!(res.is_err(), "client sent {res:?} for an unavailable Attn");
    });

    let (handle, mut events) = connect(port).await;
    wait_negotiated(&mut events).await;
    handle.press_attention(AttentionKey::Attn).await.unwrap();
    let status = handle.query_status().await.unwrap();
    assert_eq!(status.keyboard_state, KeyboardState::NotAvailable);
    host.await.unwrap();
}
