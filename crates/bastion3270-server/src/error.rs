//! Typed error hierarchy of the gateway ([`ServerError`]).
//!
//! Every fallible operation in `bastion3270-server` returns [`Result<T, ServerError>`](Result).
//! Errors are split into *startup* errors (configuration, bind failures — the process exits)
//! and *per-session* errors (a single browser session is closed, the process keeps serving
//! thousands of other sessions).

use core::fmt;

use bastion3270_net::NetError;

/// Convenience alias used throughout the server crate.
pub type Result<T> = core::result::Result<T, ServerError>;

/// Errors produced by the `bastion3270-server` gateway.
#[derive(Debug)]
pub enum ServerError {
    /// Invalid or inconsistent server configuration (`bastion3270-server.toml`).
    Config(String),
    /// I/O failure (bind, config file read, socket).
    Io(std::io::Error),
    /// Failure inside the `bastion3270-net` transport / session layer.
    Net(NetError),
    /// A configured capacity limit was reached (sessions per pod, sessions per identity).
    LimitExceeded(String),
    /// A session store extension (`SessionStore`) failed.
    Store(String),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Net(err) => write!(f, "mainframe session error: {err}"),
            Self::LimitExceeded(msg) => write!(f, "limit exceeded: {msg}"),
            Self::Store(msg) => write!(f, "session store error: {msg}"),
        }
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Net(err) => Some(err),
            Self::Config(_) | Self::LimitExceeded(_) | Self::Store(_) => None,
        }
    }
}

impl From<std::io::Error> for ServerError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<NetError> for ServerError {
    fn from(err: NetError) -> Self {
        Self::Net(err)
    }
}
