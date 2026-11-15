//! Asynchronous TCP transport connector, socket configuration, and idle silence detection.
//!
//! Provides connection establishment with deadline enforcement ([`connect_tcp`]),
//! socket tuning (`TCP_NODELAY`), and idle silence monitoring ([`IdleTimeoutDetector`],
//! [`read_with_idle_timeout`], and [`IdleTimeoutStream`]).

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::error::{NetError, Result};

/// Establishes a raw asynchronous TCP connection and configures socket options (`TCP_NODELAY`).
///
/// This function connects without an explicit deadline. Callers should either wrap it in
/// [`tokio::time::timeout`] or use [`connect_tcp`].
///
/// # Errors
/// Returns [`NetError::Config`] if `host` is empty or `port` is 0.
/// Returns [`NetError::Io`] if DNS resolution or the OS TCP connection fails.
pub async fn connect_tcp_stream(host: &str, port: u16) -> Result<TcpStream> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(NetError::Config("TCP host cannot be empty".to_string()));
    }
    if port == 0 {
        return Err(NetError::Config("TCP port cannot be zero".to_string()));
    }

    let stream = TcpStream::connect((trimmed, port))
        .await
        .map_err(NetError::Io)?;

    // Mainframe 3270 protocol requires immediate packet transmission without Nagle latency.
    if let Err(err) = stream.set_nodelay(true) {
        tracing::warn!(
            target: "bastion3270_net::transport::tcp",
            %err,
            "failed to set TCP_NODELAY on socket"
        );
    }

    tracing::debug!(
        target: "bastion3270_net::transport::tcp",
        peer_addr = ?stream.peer_addr().ok(),
        local_addr = ?stream.local_addr().ok(),
        "TCP connection established successfully"
    );

    Ok(stream)
}

/// Establishes an asynchronous TCP connection guarded by a connection deadline.
///
/// Covers DNS hostname resolution and the TCP 3-way handshake.
///
/// # Errors
/// Returns [`NetError::ConnectTimeout`] if the deadline expires.
/// Returns [`NetError::Config`] if parameters are invalid.
/// Returns [`NetError::Io`] if an OS-level network error occurs (e.g. connection refused).
pub async fn connect_tcp(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    if timeout.is_zero() {
        return Err(NetError::Config(
            "connect timeout cannot be zero".to_string(),
        ));
    }

    tokio::time::timeout(timeout, connect_tcp_stream(host, port))
        .await
        .map_err(|_| NetError::ConnectTimeout)?
}

/// Reads bytes from an asynchronous reader guarded by an inactivity silence timeout.
///
/// If no data is received within `idle_timeout`, returns [`NetError::IdleTimeout`].
/// If the reader returns EOF (`0` bytes read), returns `Ok(0)`.
///
/// # Errors
/// Returns [`NetError::IdleTimeout`] if inactivity exceeds `idle_timeout`.
/// Returns [`NetError::Io`] if the underlying read operation fails.
/// Returns [`NetError::Config`] if `idle_timeout` is zero.
pub async fn read_with_idle_timeout<R>(
    reader: &mut R,
    buf: &mut [u8],
    idle_timeout: Duration,
) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    if idle_timeout.is_zero() {
        return Err(NetError::Config("idle timeout cannot be zero".to_string()));
    }

    match tokio::time::timeout(idle_timeout, reader.read(buf)).await {
        Ok(Ok(n)) => Ok(n),
        Ok(Err(io_err)) => Err(NetError::Io(io_err)),
        Err(_) => Err(NetError::IdleTimeout),
    }
}

/// Inactivity silence tracker for detecting dead connections.
///
/// Tracks the timestamp of the most recent network activity and calculates remaining
/// time before an idle timeout occurs.
#[derive(Debug, Clone, Copy)]
pub struct IdleTimeoutDetector {
    idle_timeout: Duration,
    last_activity: tokio::time::Instant,
}

impl IdleTimeoutDetector {
    /// Creates a new [`IdleTimeoutDetector`] with the specified timeout and current time.
    #[must_use]
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            idle_timeout,
            last_activity: tokio::time::Instant::now(),
        }
    }

    /// Records that network activity occurred, resetting the inactivity timer.
    pub fn record_activity(&mut self) {
        self.last_activity = tokio::time::Instant::now();
    }

    /// Returns the duration elapsed since the last recorded network activity.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Returns the remaining duration before an idle timeout fires.
    ///
    /// If the idle threshold has already passed, returns [`Duration::ZERO`].
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.idle_timeout.saturating_sub(self.elapsed())
    }

    /// Returns `true` if silence has exceeded the configured idle threshold.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.elapsed() >= self.idle_timeout
    }

    /// Checks if the stream has gone idle, returning [`NetError::IdleTimeout`] if expired.
    ///
    /// # Errors
    /// Returns [`NetError::IdleTimeout`] if the stream has been inactive longer than `idle_timeout`.
    pub fn check(&self) -> Result<()> {
        if self.is_idle() {
            Err(NetError::IdleTimeout)
        } else {
            Ok(())
        }
    }

    /// Returns the configured idle timeout duration.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Returns the timestamp of the last recorded network activity.
    #[must_use]
    pub const fn last_activity(&self) -> tokio::time::Instant {
        self.last_activity
    }
}

/// Wrapper around an asynchronous transport stream that enforces idle silence timeouts.
///
/// Automatically tracks last activity on read/write operations and guards read calls
/// with the remaining idle silence threshold.
#[derive(Debug)]
pub struct IdleTimeoutStream<S> {
    inner: S,
    detector: IdleTimeoutDetector,
}

impl<S> IdleTimeoutStream<S> {
    /// Wraps an existing stream with an inactivity silence timeout.
    pub fn new(inner: S, idle_timeout: Duration) -> Self {
        Self {
            inner,
            detector: IdleTimeoutDetector::new(idle_timeout),
        }
    }

    /// Returns a reference to the underlying stream.
    #[must_use]
    pub const fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consumes the wrapper, returning the underlying stream.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Returns a reference to the idle timeout detector.
    #[must_use]
    pub const fn detector(&self) -> &IdleTimeoutDetector {
        &self.detector
    }

    /// Returns the configured idle timeout duration.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.detector.timeout()
    }

    /// Records manual activity (e.g. protocol keepalive or timing-mark exchange).
    pub fn record_activity(&mut self) {
        self.detector.record_activity();
    }
}

impl<S> IdleTimeoutStream<S>
where
    S: AsyncRead + Unpin,
{
    /// Reads data from the stream, guarded by the remaining idle silence timeout.
    ///
    /// # Errors
    /// Returns [`NetError::IdleTimeout`] if the idle threshold expires before data arrives.
    /// Returns [`NetError::Io`] if the underlying read fails.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let remaining = self.detector.remaining();
        if remaining.is_zero() {
            return Err(NetError::IdleTimeout);
        }

        match tokio::time::timeout(remaining, self.inner.read(buf)).await {
            Ok(Ok(n)) => {
                if n > 0 {
                    self.detector.record_activity();
                }
                Ok(n)
            }
            Ok(Err(io_err)) => Err(NetError::Io(io_err)),
            Err(_) => Err(NetError::IdleTimeout),
        }
    }

    /// Reads exact number of bytes from the stream, guarded by the remaining idle timeout.
    ///
    /// # Errors
    /// Returns [`NetError::IdleTimeout`] if silence threshold expires.
    /// Returns [`NetError::Io`] if reading fails or unexpected EOF occurs.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let remaining = self.detector.remaining();
        if remaining.is_zero() {
            return Err(NetError::IdleTimeout);
        }

        match tokio::time::timeout(remaining, self.inner.read_exact(buf)).await {
            Ok(Ok(_)) => {
                self.detector.record_activity();
                Ok(())
            }
            Ok(Err(io_err)) => Err(NetError::Io(io_err)),
            Err(_) => Err(NetError::IdleTimeout),
        }
    }
}

impl<S> IdleTimeoutStream<S>
where
    S: AsyncWrite + Unpin,
{
    /// Writes a buffer to the stream, resetting the activity timer on success.
    ///
    /// # Errors
    /// Returns [`NetError::Io`] if the write operation fails.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self.inner.write(buf).await {
            Ok(n) => {
                if n > 0 {
                    self.detector.record_activity();
                }
                Ok(n)
            }
            Err(io_err) => Err(NetError::Io(io_err)),
        }
    }

    /// Writes the entire buffer to the stream, resetting the activity timer on success.
    ///
    /// # Errors
    /// Returns [`NetError::Io`] if writing fails.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.inner.write_all(buf).await.map_err(NetError::Io)?;
        self.detector.record_activity();
        Ok(())
    }

    /// Flushes pending output to the stream.
    ///
    /// # Errors
    /// Returns [`NetError::Io`] if flushing fails.
    pub async fn flush(&mut self) -> Result<()> {
        self.inner.flush().await.map_err(NetError::Io)
    }

    /// Gracefully shuts down the output half of the stream.
    ///
    /// # Errors
    /// Returns [`NetError::Io`] if shutdown fails.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.inner.shutdown().await.map_err(NetError::Io)
    }
}

impl<S> AsyncRead for IdleTimeoutStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.detector.is_idle() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "idle timeout exceeded before read",
            )));
        }

        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    this.detector.record_activity();
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S> AsyncWrite for IdleTimeoutStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.detector.record_activity();
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.detector.record_activity();
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<S> fmt::Display for IdleTimeoutStream<S>
where
    S: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IdleTimeoutStream({}, timeout={:?})",
            self.inner, self.detector.idle_timeout
        )
    }
}
