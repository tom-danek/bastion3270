//! The message line at the bottom of the window, just above the OIA bar.
//!
//! It shows what the client itself has to say (profile file problems, import results, warnings
//! from the session). The state of the session — connected, error, keyboard lock — is shown only
//! by the OIA bar, never repeated here.

use std::time::{Duration, Instant};

/// How long an informational message stays; warnings and errors stay until dismissed.
pub const INFO_LIFETIME: Duration = Duration::from_secs(10);

/// Severity of a [`StatusMessage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageLevel {
    /// Progress or a confirmation; disappears after [`INFO_LIFETIME`].
    Info,
    /// Something the user should know about; stays until dismissed or replaced.
    Warning,
    /// Something failed; stays until dismissed or replaced.
    Error,
}

/// One message for the message line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusMessage {
    level: MessageLevel,
    text: String,
    since: Instant,
}

impl StatusMessage {
    /// A message of `level`, shown from now.
    #[must_use]
    pub fn new(level: MessageLevel, text: impl Into<String>) -> Self {
        Self {
            level,
            text: text.into(),
            since: Instant::now(),
        }
    }

    /// An informational message.
    #[must_use]
    pub fn info(text: impl Into<String>) -> Self {
        Self::new(MessageLevel::Info, text)
    }

    /// A warning.
    #[must_use]
    pub fn warning(text: impl Into<String>) -> Self {
        Self::new(MessageLevel::Warning, text)
    }

    /// An error.
    #[must_use]
    pub fn error(text: impl Into<String>) -> Self {
        Self::new(MessageLevel::Error, text)
    }

    /// Severity.
    #[must_use]
    pub const fn level(&self) -> MessageLevel {
        self.level
    }

    /// Text to show.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether the message should no longer be shown at `now`.
    #[must_use]
    pub fn is_expired(&self, now: Instant) -> bool {
        self.level == MessageLevel::Info
            && now.saturating_duration_since(self.since) >= INFO_LIFETIME
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_expires_warnings_and_errors_stay() {
        let info = StatusMessage::info("x");
        let later = info.since + INFO_LIFETIME;
        assert!(!info.is_expired(info.since));
        assert!(info.is_expired(later));
        assert!(!StatusMessage::warning("x").is_expired(later + INFO_LIFETIME));
        assert!(!StatusMessage::error("x").is_expired(later + INFO_LIFETIME));
    }
}
