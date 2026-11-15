//! # Typed Network Error Hierarchy
//!
//! Provides the primary error type [`NetError`] and [`Result`] alias for all fallible
//! networking, TLS, configuration, protocol, and session operations in `bastion3270-net`.
//!
//! In accordance with the workspace zero-panic lints (`Cargo.toml`),
//! all errors are strongly typed, implement [`std::error::Error`] and [`std::fmt::Display`],
//! and never cause thread panics.

use std::fmt;

/// A specialized [`Result`](std::result::Result) type for `bastion3270-net` operations.
pub type Result<T, E = NetError> = std::result::Result<T, E>;

/// Comprehensive error hierarchy for `bastion3270-net`.
#[derive(Debug)]
pub enum NetError {
    /// Underlying I/O failure (TCP connect, read, write, unexpected EOF).
    Io(std::io::Error),

    /// TLS transport or handshake failure (AT-TLS negotiation, cipher suite, alert).
    Tls(rustls::Error),

    /// Configuration parsing, validation, or deserialization error.
    Config(String),

    /// Invalid, malformed, or unreadable TLS CA certificate / key.
    InvalidCertificate(String),

    /// The host's certificate was refused: why, and what the certificate says (boxed: the
    /// details are large and rare).
    UntrustedCertificate(Box<crate::transport::CertificateRejection>),

    /// Network connection or TLS handshake deadline expired.
    ConnectTimeout,

    /// Connection inactive silence deadline expired without host communication.
    IdleTimeout,

    /// The host did not accept data within the write deadline (it stopped reading).
    WriteTimeout,

    /// The Telnet negotiation did not complete within its deadline.
    NegotiationTimeout,

    /// Protocol violation (Telnet option negotiation, TN3270E framing, 3270 datastream error).
    Protocol(String),

    /// Inter-task channel closed, dropped receiver, or bounded queue backpressure error.
    Channel(String),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Tls(err) => write!(f, "TLS error: {err}"),
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::InvalidCertificate(msg) => write!(f, "invalid certificate: {msg}"),
            Self::UntrustedCertificate(rejection) => write!(f, "{rejection}"),
            Self::ConnectTimeout => {
                write!(f, "connection timed out during connect or TLS handshake")
            }
            Self::IdleTimeout => {
                write!(
                    f,
                    "connection timed out due to host inactivity (idle timeout)"
                )
            }
            Self::WriteTimeout => write!(f, "the host did not accept data in time (write timeout)"),
            Self::NegotiationTimeout => {
                write!(
                    f,
                    "Telnet negotiation with the host did not complete in time"
                )
            }
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::Channel(msg) => write!(f, "channel communication error: {msg}"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Tls(err) => Some(err),
            Self::Config(_)
            | Self::InvalidCertificate(_)
            | Self::UntrustedCertificate(_)
            | Self::ConnectTimeout
            | Self::IdleTimeout
            | Self::WriteTimeout
            | Self::NegotiationTimeout
            | Self::Protocol(_)
            | Self::Channel(_) => None,
        }
    }
}

impl NetError {
    /// Constructs a [`NetError::Config`] from any string-like message.
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Constructs a [`NetError::InvalidCertificate`] from any string-like message.
    pub fn invalid_certificate(msg: impl Into<String>) -> Self {
        Self::InvalidCertificate(msg.into())
    }

    /// Constructs a [`NetError::Protocol`] from any string-like message.
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    /// Constructs a [`NetError::Channel`] from any string-like message.
    pub fn channel(msg: impl Into<String>) -> Self {
        Self::Channel(msg.into())
    }

    /// Returns `true` if this error is [`NetError::ConnectTimeout`].
    #[must_use]
    pub fn is_connect_timeout(&self) -> bool {
        matches!(self, Self::ConnectTimeout)
    }

    /// Returns `true` if this error is [`NetError::IdleTimeout`].
    #[must_use]
    pub fn is_idle_timeout(&self) -> bool {
        matches!(self, Self::IdleTimeout)
    }

    /// Returns `true` if this error is [`NetError::Io`].
    #[must_use]
    pub fn is_io(&self) -> bool {
        matches!(self, Self::Io(_))
    }

    /// Returns `true` if this error is [`NetError::Tls`].
    #[must_use]
    pub fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    /// Returns `true` if this error is [`NetError::Config`].
    #[must_use]
    pub fn is_config(&self) -> bool {
        matches!(self, Self::Config(_))
    }

    /// Returns `true` if this error is [`NetError::InvalidCertificate`].
    #[must_use]
    pub fn is_invalid_certificate(&self) -> bool {
        matches!(self, Self::InvalidCertificate(_))
    }

    /// Returns `true` if this error is [`NetError::Protocol`].
    #[must_use]
    pub fn is_protocol(&self) -> bool {
        matches!(self, Self::Protocol(_))
    }

    /// Returns `true` if this error is [`NetError::Channel`].
    #[must_use]
    pub fn is_channel(&self) -> bool {
        matches!(self, Self::Channel(_))
    }
}

impl From<std::io::Error> for NetError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<rustls::Error> for NetError {
    fn from(err: rustls::Error) -> Self {
        Self::Tls(err)
    }
}

impl From<toml::de::Error> for NetError {
    fn from(err: toml::de::Error) -> Self {
        Self::Config(format!("TOML deserialization error: {err}"))
    }
}

impl From<toml::ser::Error> for NetError {
    fn from(err: toml::ser::Error) -> Self {
        Self::Config(format!("TOML serialization error: {err}"))
    }
}

impl From<bastion3270_core::TelnetError> for NetError {
    fn from(err: bastion3270_core::TelnetError) -> Self {
        Self::Protocol(format!("telnet protocol error: {err}"))
    }
}

impl From<bastion3270_core::DatastreamError> for NetError {
    fn from(err: bastion3270_core::DatastreamError) -> Self {
        Self::Protocol(format!("3270 datastream error: {err}"))
    }
}

impl From<bastion3270_core::KeyboardError> for NetError {
    fn from(err: bastion3270_core::KeyboardError) -> Self {
        Self::Protocol(format!("virtual keyboard error: {err}"))
    }
}

impl From<bastion3270_core::WsfError> for NetError {
    fn from(err: bastion3270_core::WsfError) -> Self {
        Self::Protocol(format!("structured field error: {err}"))
    }
}

impl From<bastion3270_core::ModelError> for NetError {
    fn from(err: bastion3270_core::ModelError) -> Self {
        Self::Config(format!("terminal model error: {err}"))
    }
}

impl From<bastion3270_core::SafeViewError> for NetError {
    fn from(err: bastion3270_core::SafeViewError) -> Self {
        Self::Protocol(format!("safe view error: {err}"))
    }
}

impl From<bastion3270_core::ScreenError> for NetError {
    fn from(err: bastion3270_core::ScreenError) -> Self {
        Self::Protocol(format!("screen error: {err}"))
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for NetError {
    fn from(err: tokio::sync::oneshot::error::RecvError) -> Self {
        Self::Channel(format!("oneshot channel receive error: {err}"))
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for NetError {
    fn from(_err: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Self::Channel("mpsc channel closed: receiver dropped".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_all_variants() {
        let io_err = NetError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));
        assert!(format!("{io_err}").contains("I/O error: connection refused"));

        let tls_err = NetError::Tls(rustls::Error::HandshakeNotComplete);
        assert!(format!("{tls_err}").contains("TLS error:"));

        let cfg_err = NetError::Config("missing port".to_string());
        assert_eq!(format!("{cfg_err}"), "configuration error: missing port");

        let cert_err = NetError::InvalidCertificate("empty store".to_string());
        assert_eq!(format!("{cert_err}"), "invalid certificate: empty store");

        let conn_tout = NetError::ConnectTimeout;
        assert_eq!(
            format!("{conn_tout}"),
            "connection timed out during connect or TLS handshake"
        );

        let idle_tout = NetError::IdleTimeout;
        assert_eq!(
            format!("{idle_tout}"),
            "connection timed out due to host inactivity (idle timeout)"
        );

        let proto_err = NetError::Protocol("invalid IAC".to_string());
        assert_eq!(format!("{proto_err}"), "protocol error: invalid IAC");

        let chan_err = NetError::Channel("receiver dropped".to_string());
        assert_eq!(
            format!("{chan_err}"),
            "channel communication error: receiver dropped"
        );
    }

    #[test]
    fn test_error_source() {
        use std::error::Error;

        let io_err = NetError::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken pipe",
        ));
        assert!(io_err.source().is_some());

        let tls_err = NetError::Tls(rustls::Error::HandshakeNotComplete);
        assert!(tls_err.source().is_some());

        assert!(NetError::ConnectTimeout.source().is_none());
        assert!(NetError::IdleTimeout.source().is_none());
        assert!(NetError::Config("test".into()).source().is_none());
        assert!(NetError::InvalidCertificate("test".into())
            .source()
            .is_none());
        assert!(NetError::Protocol("test".into()).source().is_none());
        assert!(NetError::Channel("test".into()).source().is_none());
    }

    #[test]
    fn test_boolean_predicates_and_constructors() {
        let conn_tout = NetError::ConnectTimeout;
        assert!(conn_tout.is_connect_timeout());
        assert!(!conn_tout.is_idle_timeout());

        let idle_tout = NetError::IdleTimeout;
        assert!(idle_tout.is_idle_timeout());
        assert!(!idle_tout.is_connect_timeout());

        let cfg = NetError::config("bad port");
        assert!(cfg.is_config());
        assert!(!cfg.is_protocol());

        let cert = NetError::invalid_certificate("bad cert");
        assert!(cert.is_invalid_certificate());

        let proto = NetError::protocol("bad order");
        assert!(proto.is_protocol());

        let chan = NetError::channel("dropped");
        assert!(chan.is_channel());
    }

    #[test]
    fn test_from_conversions() {
        let io: NetError = std::io::Error::other("disk full").into();
        assert!(io.is_io());

        let tls: NetError = rustls::Error::General("tls issue".into()).into();
        assert!(tls.is_tls());

        let telnet: NetError = bastion3270_core::TelnetError::TruncatedHeader {
            needed: 5,
            available: 2,
        }
        .into();
        assert!(telnet.is_protocol());
        assert!(format!("{telnet}").contains("truncated TN3270E header"));

        let datastream: NetError = bastion3270_core::DatastreamError::UnknownCommand(0x99).into();
        assert!(datastream.is_protocol());

        let keyboard: NetError = bastion3270_core::KeyboardError::ProtectedField.into();
        assert!(keyboard.is_protocol());

        let wsf: NetError = bastion3270_core::WsfError::TruncatedField {
            expected: 4,
            available: 2,
        }
        .into();
        assert!(wsf.is_protocol());

        let model: NetError =
            bastion3270_core::ModelError::InvalidDimension { rows: 0, cols: 0 }.into();
        assert!(model.is_config());
    }
}
