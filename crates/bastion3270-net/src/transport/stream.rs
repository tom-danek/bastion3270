//! # Asynchronous Transport Stream Abstraction
//!
//! Provides [`TransportStream`], a unified asynchronous stream enum encapsulating either
//! an unencrypted plain TCP connection ([`tokio::net::TcpStream`]) or a TLS 1.2/1.3 encrypted
//! connection ([`tokio_rustls::client::TlsStream`]).
//!
//! ## Architectural Role
//! In `bastion3270-net`, [`TransportStream`] forms the unified I/O interface connecting
//! the session coordinator actor (`SessionCoordinator`) with either:
//! - Local Hercules mainframe emulators running plain unencrypted TN3270 on port 3270.
//! - Remote IBM z/OS mainframes requiring TLS 1.2 or 1.3 encryption (AT-TLS) on port 992 or custom ports.
//!
//! ## Zero-Panic and Memory Safety Guarantee
//! In strict adherence to the workspace zero-panic lints (`Cargo.toml`), this module:
//! - Enforces `#![forbid(unsafe_code)]` with zero `unsafe` blocks.
//! - Relies on the fact that both [`tokio::net::TcpStream`] and [`tokio_rustls::client::TlsStream`]
//!   implement [`Unpin`], allowing safe pin projection via [`Pin::get_mut`] and [`Pin::new`].
//! - Denies panics, indexing/slicing, and unwraps in production code.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// Unified asynchronous transport stream for `bastion3270-net`.
///
/// Encapsulates either an unencrypted plain TCP stream ([`TcpStream`]) for local Hercules
/// emulation or a direct TLS 1.2/1.3 encrypted stream ([`TlsStream`]) for IBM z/OS mainframes
/// (AT-TLS).
///
/// Both variants implement [`AsyncRead`] and [`AsyncWrite`]. Pin projections are performed
/// completely safely without `unsafe` code because both inner stream types implement [`Unpin`].
///
/// # Note on Variant Sizes
/// The [`TransportStream::Tls`] variant is larger than [`TransportStream::Plain`] (~1 KB vs ~40 B)
/// because `TlsStream` contains the Rustls client session state machine and record buffers.
/// Because `TransportStream` is created once per mainframe connection and held for the lifetime
/// of the session (rather than repeatedly passed by value on the stack), boxing the TLS variant
/// would introduce unnecessary heap allocation without performance benefit.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TransportStream {
    /// Unencrypted plain TCP transport stream (typically Hercules emulator on port 3270).
    Plain(TcpStream),
    /// TLS 1.2 or TLS 1.3 encrypted transport stream (IBM z/OS AT-TLS).
    Tls(TlsStream<TcpStream>),
}

impl TransportStream {
    /// Constructs a plain unencrypted TCP transport stream.
    #[must_use]
    pub fn from_plain(stream: TcpStream) -> Self {
        Self::Plain(stream)
    }

    /// Constructs a TLS encrypted transport stream.
    #[must_use]
    pub fn from_tls(stream: TlsStream<TcpStream>) -> Self {
        Self::Tls(stream)
    }

    /// Returns `true` if this stream is encrypted with TLS.
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    /// Returns `true` if this stream is unencrypted plain TCP.
    #[must_use]
    pub const fn is_plain(&self) -> bool {
        matches!(self, Self::Plain(_))
    }

    /// Returns the remote peer socket address of the underlying TCP connection.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if querying the socket for peer address fails.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Plain(stream) => stream.peer_addr(),
            Self::Tls(stream) => stream.get_ref().0.peer_addr(),
        }
    }

    /// Returns the local socket address of the underlying TCP connection.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if querying the socket for local address fails.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Plain(stream) => stream.local_addr(),
            Self::Tls(stream) => stream.get_ref().0.local_addr(),
        }
    }

    /// Enables or disables `TCP_NODELAY` (Nagle's algorithm) on the underlying TCP stream.
    ///
    /// Setting `nodelay` to `true` is strongly recommended for interactive 3270 sessions
    /// to eliminate transmission latency for keystrokes and AID submissions.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if setting the socket option fails.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.set_nodelay(nodelay),
            Self::Tls(stream) => stream.get_ref().0.set_nodelay(nodelay),
        }
    }

    /// Retrieves the current `TCP_NODELAY` setting on the underlying TCP stream.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if querying the socket option fails.
    pub fn nodelay(&self) -> io::Result<bool> {
        match self {
            Self::Plain(stream) => stream.nodelay(),
            Self::Tls(stream) => stream.get_ref().0.nodelay(),
        }
    }

    /// Sets the Time-To-Live (TTL) field on outgoing packets.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if setting the socket option fails.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.set_ttl(ttl),
            Self::Tls(stream) => stream.get_ref().0.set_ttl(ttl),
        }
    }

    /// Returns the Time-To-Live (TTL) setting for outgoing packets.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if querying the socket option fails.
    pub fn ttl(&self) -> io::Result<u32> {
        match self {
            Self::Plain(stream) => stream.ttl(),
            Self::Tls(stream) => stream.get_ref().0.ttl(),
        }
    }

    /// Returns the negotiated TLS cipher suite if this stream is TLS encrypted.
    ///
    /// Returns `None` if this stream is unencrypted plain TCP.
    #[must_use]
    pub fn tls_negotiated_cipher_suite(&self) -> Option<rustls::SupportedCipherSuite> {
        match self {
            Self::Plain(_) => None,
            Self::Tls(stream) => stream.get_ref().1.negotiated_cipher_suite(),
        }
    }

    /// Returns the negotiated TLS protocol version (e.g. TLS 1.2 or TLS 1.3) if encrypted.
    ///
    /// Returns `None` if this stream is unencrypted plain TCP.
    #[must_use]
    pub fn tls_protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        match self {
            Self::Plain(_) => None,
            Self::Tls(stream) => stream.get_ref().1.protocol_version(),
        }
    }

    /// Returns the negotiated ALPN protocol if TLS encryption is active.
    ///
    /// Returns `None` if this stream is unencrypted plain TCP or no ALPN was negotiated.
    #[must_use]
    pub fn tls_alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Plain(_) => None,
            Self::Tls(stream) => stream.get_ref().1.alpn_protocol(),
        }
    }

    /// Returns the peer certificates presented by the mainframe during TLS handshake.
    ///
    /// Returns `None` if this stream is unencrypted plain TCP.
    #[must_use]
    pub fn tls_peer_certificates(&self) -> Option<&[rustls_pki_types::CertificateDer<'_>]> {
        match self {
            Self::Plain(_) => None,
            Self::Tls(stream) => stream.get_ref().1.peer_certificates(),
        }
    }

    /// Returns an immutable reference to the plain TCP stream if this is a [`TransportStream::Plain`].
    #[must_use]
    pub const fn plain_ref(&self) -> Option<&TcpStream> {
        match self {
            Self::Plain(stream) => Some(stream),
            Self::Tls(_) => None,
        }
    }

    /// Returns a mutable reference to the plain TCP stream if this is a [`TransportStream::Plain`].
    #[must_use]
    pub fn plain_mut(&mut self) -> Option<&mut TcpStream> {
        match self {
            Self::Plain(stream) => Some(stream),
            Self::Tls(_) => None,
        }
    }

    /// Returns an immutable reference to the TLS stream if this is a [`TransportStream::Tls`].
    #[must_use]
    pub const fn tls_ref(&self) -> Option<&TlsStream<TcpStream>> {
        match self {
            Self::Plain(_) => None,
            Self::Tls(stream) => Some(stream),
        }
    }

    /// Returns a mutable reference to the TLS stream if this is a [`TransportStream::Tls`].
    #[must_use]
    pub fn tls_mut(&mut self) -> Option<&mut TlsStream<TcpStream>> {
        match self {
            Self::Plain(_) => None,
            Self::Tls(stream) => Some(stream),
        }
    }

    /// Splits the stream into an owned read half and an owned write half.
    ///
    /// This uses [`tokio::io::split`] internally and allows concurrent read and write
    /// tasks to operate on the same stream without lifetime constraints.
    #[must_use]
    pub fn into_split(self) -> (ReadHalf<Self>, WriteHalf<Self>) {
        tokio::io::split(self)
    }

    /// Splits a mutable reference to the stream into borrowed read and write halves.
    ///
    /// This uses [`tokio::io::split`] internally and is zero-allocation.
    #[must_use]
    pub fn split(&mut self) -> (ReadHalf<&mut Self>, WriteHalf<&mut Self>) {
        tokio::io::split(self)
    }

    /// Asynchronously shuts down the transport stream.
    ///
    /// For plain TCP streams, this closes the write side of the connection.
    /// For TLS streams, this exchanges the TLS `close_notify` alert before shutting down
    /// the underlying TCP transport, ensuring clean mainframe session termination without
    /// truncation alerts or connection resets.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if shutdown fails.
    pub async fn shutdown(&mut self) -> io::Result<()> {
        AsyncWriteExt::shutdown(self).await
    }
}

impl From<TcpStream> for TransportStream {
    fn from(stream: TcpStream) -> Self {
        Self::Plain(stream)
    }
}

impl From<TlsStream<TcpStream>> for TransportStream {
    fn from(stream: TlsStream<TcpStream>) -> Self {
        Self::Tls(stream)
    }
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }
}

impl fmt::Display for TransportStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(_) => write!(f, "TransportStream(Plain TCP)"),
            Self::Tls(_) => write!(f, "TransportStream(TLS Encrypted)"),
        }
    }
}
