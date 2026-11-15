//! Session lifecycle state machine and status types.

use core::fmt;

/// Clean lifecycle states of an IBM 3270 host session.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SessionState {
    /// Establishing TCP connection and performing TLS handshake (if enabled).
    #[default]
    Connecting,

    /// Transport established; negotiating Telnet options (RFC 854) and TN3270E (RFC 2355).
    Negotiating,

    /// Telnet negotiation and SNA binding complete; 3270 datastream active and accepting input.
    Connected3270,

    /// Gracefully disconnected by user command, remote host EOF, or clean shutdown.
    Disconnected,

    /// Terminated due to protocol error, I/O failure, timeout, or channel closure.
    Error(String),
}

impl SessionState {
    /// Returns `true` if the session is currently in the active 3270 data state.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        matches!(self, Self::Connected3270)
    }

    /// Returns `true` if the session is still active (Connecting, Negotiating, or Connected3270).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Connecting | Self::Negotiating | Self::Connected3270
        )
    }

    /// Returns `true` if the session has reached a terminal state (Disconnected or Error).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Disconnected | Self::Error(_))
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting => write!(f, "connecting"),
            Self::Negotiating => write!(f, "negotiating"),
            Self::Connected3270 => write!(f, "connected (3270)"),
            Self::Disconnected => write!(f, "disconnected"),
            Self::Error(msg) => write!(f, "error: {msg}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state_lifecycle_predicates() {
        assert!(SessionState::Connecting.is_active());
        assert!(!SessionState::Connecting.is_connected());
        assert!(!SessionState::Connecting.is_terminal());

        assert!(SessionState::Negotiating.is_active());
        assert!(!SessionState::Negotiating.is_connected());
        assert!(!SessionState::Negotiating.is_terminal());

        assert!(SessionState::Connected3270.is_active());
        assert!(SessionState::Connected3270.is_connected());
        assert!(!SessionState::Connected3270.is_terminal());

        assert!(!SessionState::Disconnected.is_active());
        assert!(!SessionState::Disconnected.is_connected());
        assert!(SessionState::Disconnected.is_terminal());

        let err_state = SessionState::Error("connection reset".to_string());
        assert!(!err_state.is_active());
        assert!(!err_state.is_connected());
        assert!(err_state.is_terminal());
    }

    #[test]
    fn test_session_state_display() {
        assert_eq!(SessionState::Connecting.to_string(), "connecting");
        assert_eq!(SessionState::Negotiating.to_string(), "negotiating");
        assert_eq!(SessionState::Connected3270.to_string(), "connected (3270)");
        assert_eq!(SessionState::Disconnected.to_string(), "disconnected");
        assert_eq!(
            SessionState::Error("timeout".to_string()).to_string(),
            "error: timeout"
        );
    }
}
