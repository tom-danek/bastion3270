//! A scripted mock mainframe: a TN3270E host on `127.0.0.1` that negotiates like z/OS, sends a
//! first screen and answers each inbound record through a reply function.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// How long a test waits for the host to receive something.
pub const HOST_TIMEOUT: Duration = Duration::from_secs(5);

/// Pause between the end of the negotiation and the first screen. A real host also sends its
/// first screen (e.g. the z/OS USS logon screen) some time after the session is bound, so the
/// clients show the bound session while the keyboard is still `X [Field]`. The pause makes that
/// window wide enough that a test which waits only for the session state, not for the screen,
/// fails every time instead of now and then on a slow CI runner.
pub const FIRST_SCREEN_DELAY: Duration = Duration::from_millis(150);

/// `PASS: ` (protected) followed by an unprotected **Non-display** field with the cursor in it.
/// Row 0: col 0 = SF(protected), cols 1..=6 = "PASS: ", col 7 = SF(non-display), col 8.. = input.
pub const LOGON_SCREEN: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x01, // TN3270E header (3270-DATA)
    0x05, 0xC3, // Erase/Write, WCC restore keyboard
    0x1D, 0x20, 0xD7, 0xC1, 0xE2, 0xE2, 0x7A, 0x40, // SF protected + "PASS: "
    0x1D, 0x0C, 0x13, // SF unprotected non-display + IC
    0xFF, 0xEF, // IAC EOR
];

/// Answers one read from the gateway (raw bytes, possibly several records) with bytes to send
/// back, already framed (`IAC EOR`), or `None`.
pub type Reply = fn(&[u8]) -> Option<Vec<u8>>;

/// The host's bound port, everything the gateway sent it after negotiation, and how many
/// connections it accepted and saw closed by the gateway.
pub struct MockHost {
    pub port: u16,
    pub received: mpsc::UnboundedReceiver<Vec<u8>>,
    pub connections: Arc<AtomicUsize>,
    pub closed: Arc<AtomicUsize>,
}

impl MockHost {
    /// Number of TN3270E connections the host accepted so far.
    pub fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Number of connections the gateway closed so far.
    #[allow(dead_code)] // not every test binary that shares this module uses it
    pub fn closed_count(&self) -> usize {
        self.closed.load(Ordering::SeqCst)
    }
}

/// Plays the host side of the TN3270E negotiation (the client is purely reactive): DO TN3270E,
/// SEND DEVICE-TYPE, DEVICE-TYPE IS `IBM-3278-2-E` CONNECT `LUTEST01`, FUNCTIONS IS (none).
async fn negotiate_tn3270e(socket: &mut TcpStream) {
    let mut buf = [0u8; 512];
    socket.write_all(&[0xFF, 0xFD, 0x28]).await.unwrap();
    assert!(socket.read(&mut buf).await.unwrap() > 0);
    socket
        .write_all(&[0xFF, 0xFA, 0x28, 0x08, 0x02, 0xFF, 0xF0])
        .await
        .unwrap();
    assert!(socket.read(&mut buf).await.unwrap() > 0);
    let mut confirm = vec![0xFF, 0xFA, 0x28, 0x02, 0x04];
    confirm.extend_from_slice(b"IBM-3278-2-E");
    confirm.extend_from_slice(&[0x01]);
    confirm.extend_from_slice(b"LUTEST01");
    confirm.extend_from_slice(&[0xFF, 0xF0]);
    socket.write_all(&confirm).await.unwrap();
    assert!(socket.read(&mut buf).await.unwrap() > 0);
    socket
        .write_all(&[0xFF, 0xFA, 0x28, 0x03, 0x04, 0x02, 0xFF, 0xF0])
        .await
        .unwrap();
}

/// Accepts any number of connections; each is negotiated, gets `first_screen` after
/// [`FIRST_SCREEN_DELAY`], and every read
/// is forwarded to [`MockHost::received`] and answered with `reply`.
pub async fn spawn(first_screen: &'static [u8], reply: Reply) -> MockHost {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, received) = mpsc::unbounded_channel();
    let connections = Arc::new(AtomicUsize::new(0));
    let accepted = Arc::clone(&connections);
    let closed = Arc::new(AtomicUsize::new(0));
    let ended = Arc::clone(&closed);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            accepted.fetch_add(1, Ordering::SeqCst);
            let tx = tx.clone();
            let ended = Arc::clone(&ended);
            tokio::spawn(async move {
                // Counts the connection as closed however this task ends.
                struct Closed(Arc<AtomicUsize>);
                impl Drop for Closed {
                    fn drop(&mut self) {
                        self.0.fetch_add(1, Ordering::SeqCst);
                    }
                }
                let _closed = Closed(ended);
                negotiate_tn3270e(&mut socket).await;
                tokio::time::sleep(FIRST_SCREEN_DELAY).await;
                socket.write_all(first_screen).await.unwrap();
                let mut buf = [0u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            let data = &buf[..n];
                            let _ = tx.send(data.to_vec());
                            if let Some(answer) = reply(data) {
                                if socket.write_all(&answer).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
            });
        }
    });
    MockHost {
        port,
        received,
        connections,
        closed,
    }
}

/// A host that sends [`LOGON_SCREEN`] and never answers.
pub async fn spawn_mock_host() -> (u16, mpsc::UnboundedReceiver<Vec<u8>>) {
    let host = spawn(LOGON_SCREEN, |_| None).await;
    (host.port, host.received)
}

/// Waits until the host received a read containing `needle` and returns it.
pub async fn host_receives(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>, needle: &[u8]) -> Vec<u8> {
    tokio::time::timeout(HOST_TIMEOUT, async {
        loop {
            let rec = rx.recv().await.expect("host channel closed");
            if rec.windows(needle.len()).any(|w| w == needle) {
                return rec;
            }
        }
    })
    .await
    .expect("host did not receive expected bytes")
}

/// The AID of an inbound TN3270E 3270-DATA record (the byte after the 5-byte header).
pub fn aid_of(read: &[u8]) -> Option<u8> {
    (read.first() == Some(&0x00))
        .then(|| read.get(5).copied())
        .flatten()
}

/// Waits until the host received a record with `aid` and returns it.
pub async fn host_receives_aid(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>, aid: u8) -> Vec<u8> {
    tokio::time::timeout(HOST_TIMEOUT, async {
        loop {
            let rec = rx.recv().await.expect("host channel closed");
            if aid_of(&rec) == Some(aid) {
                return rec;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("host did not receive AID 0x{aid:02X}"))
}
