//! Simulated TN3270E hosts.
//!
//! Each connection is negotiated like a z/OS TN3270E server (DEVICE-TYPE `IBM-3278-2-E`, an LU
//! name, no functions), gets an ISPF-like panel and, after every record from the client (an
//! AID), a new full-screen write after `delay`. Every answer carries a counter, so it differs
//! from the previous screen. With a [`TlsAcceptor`] the hosts speak TLS, like z/OS AT-TLS.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bastion3270_core::{CodePage, CP037};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const IAC: u8 = 0xFF;

/// Counts what the simulated hosts did.
#[derive(Debug, Default)]
pub struct HostStats {
    /// Connections accepted.
    pub connections: AtomicU64,
    /// Screens sent.
    pub screens: AtomicU64,
}

/// Starts simulated hosts on `listen` (over TLS with `tls`); returns the bound address. Runs
/// until the process ends.
///
/// # Errors
/// If the address cannot be bound.
pub async fn spawn(
    listen: SocketAddr,
    delay: Duration,
    stats: Arc<HostStats>,
    tls: Option<TlsAcceptor>,
) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            };
            let stats = Arc::clone(&stats);
            stats.connections.fetch_add(1, Ordering::Relaxed);
            let tls = tls.clone();
            tokio::spawn(async move {
                if socket.set_nodelay(true).is_err() {
                    return;
                }
                match tls {
                    None => {
                        let _ = serve(socket, delay, &stats).await;
                    }
                    Some(acceptor) => {
                        if let Ok(stream) = acceptor.accept(socket).await {
                            let _ = serve(stream, delay, &stats).await;
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

async fn serve<S>(mut socket: S, delay: Duration, stats: &HostStats) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate(&mut socket).await?;
    let mut counter: u64 = 0;
    socket.write_all(&panel(counter)).await?;
    stats.screens.fetch_add(1, Ordering::Relaxed);
    let mut buf = vec![0_u8; 4096];
    loop {
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        // Every complete client record (an AID with its fields) gets a new screen.
        let records = buf
            .get(..n)
            .unwrap_or_default()
            .windows(2)
            .filter(|w| *w == [IAC, 0xEF])
            .count();
        for _ in 0..records {
            tokio::time::sleep(delay).await;
            counter = counter.wrapping_add(1);
            socket.write_all(&panel(counter)).await?;
            stats.screens.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The host side of the TN3270E negotiation (the client only reacts).
async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut S) -> std::io::Result<()> {
    socket.write_all(&[IAC, 0xFD, 0x28]).await?; // DO TN3270E
    client_reply(socket).await?;
    socket
        .write_all(&[IAC, 0xFA, 0x28, 0x08, 0x02, IAC, 0xF0])
        .await?; // SEND DEVICE-TYPE
    client_reply(socket).await?;
    let mut is = vec![IAC, 0xFA, 0x28, 0x02, 0x04];
    is.extend_from_slice(b"IBM-3278-2-E");
    is.push(0x01); // CONNECT
    is.extend_from_slice(b"LOADLU01");
    is.extend_from_slice(&[IAC, 0xF0]);
    socket.write_all(&is).await?;
    client_reply(socket).await?;
    socket
        .write_all(&[IAC, 0xFA, 0x28, 0x03, 0x04, 0x02, IAC, 0xF0])
        .await // FUNCTIONS IS
}

/// Waits for the client's answer to a negotiation step (its content is not checked).
async fn client_reply<S: AsyncRead + Unpin>(socket: &mut S) -> std::io::Result<()> {
    let mut buf = [0_u8; 512];
    match socket.read(&mut buf).await? {
        0 => Err(std::io::ErrorKind::UnexpectedEof.into()),
        _ => Ok(()),
    }
}

/// 12-bit buffer address of `row`, `col` on a 24x80 screen.
fn sba(row: u16, col: u16) -> [u8; 3] {
    let addr = row.saturating_mul(80).saturating_add(col);
    let table = bastion3270_core::CODE_TABLE;
    let hi = table.get(usize::from(addr >> 6)).copied().unwrap_or(0x40);
    let lo = table.get(usize::from(addr & 0x3F)).copied().unwrap_or(0x40);
    [0x11, hi, lo]
}

fn text(out: &mut Vec<u8>, s: &str) {
    out.extend(s.chars().map(|c| CP037.char_to_ebcdic(c).unwrap_or(0x40)));
}

/// An ISPF-like 24x80 panel as one TN3270E 3270-DATA record (Erase/Write), with `counter` in it.
#[must_use]
pub fn panel(counter: u64) -> Vec<u8> {
    let mut o = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0xF5, 0xC3]; // header, EW, WCC restore
    o.extend(sba(0, 0));
    o.extend([0x1D, 0x60]); // SF protected
    text(
        &mut o,
        "   Menu  Utilities  Compilers  Options  Status  Help",
    );
    o.extend(sba(2, 28));
    o.extend([0x1D, 0xE8]);
    text(&mut o, &format!("ISPF Primary Option Menu  #{counter:06}"));
    for (i, line) in [
        "0  Settings      Terminal and user parameters",
        "1  View          Display source data or listings",
        "2  Edit          Create or change source data",
        "3  Utilities     Perform utility functions",
        "4  Foreground    Interactive language processing",
        "5  Batch         Submit job for language processing",
        "6  Command       Enter TSO or Workstation commands",
        "7  Dialog Test   Perform dialog testing",
        "9  IBM Products  IBM program development products",
        "SD SDSF          System Display and Search Facility",
    ]
    .iter()
    .enumerate()
    {
        let row = u16::try_from(i).unwrap_or(0).saturating_add(4);
        o.extend(sba(row, 1));
        o.extend([0x1D, 0x60]);
        text(&mut o, line);
    }
    o.extend(sba(20, 1));
    o.extend([0x1D, 0xE8]);
    text(&mut o, "Option ===>");
    o.extend([0x1D, 0x40, 0x13]); // unprotected input field, insert cursor
    o.extend(sba(20, 79));
    o.extend([0x1D, 0x60]);
    o.extend(sba(22, 1));
    o.extend([0x1D, 0x60]);
    text(&mut o, "F1=Help  F3=Exit  F10=Actions  F12=Cancel");
    o.extend([IAC, 0xEF]);
    o
}
