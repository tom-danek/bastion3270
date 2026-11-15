//! [`Secret`] — a string wrapper for credentials that never leaks into logs and is
//! wiped from memory when dropped.
//!
//! Used for RACF passwords / `PassTickets` handed over by an [`AuthProvider`](crate::AuthProvider)
//! for server-side auto-logon, and for bearer tokens read from configuration.

use core::fmt;

use zeroize::Zeroizing;

/// A secret string (password, `PassTicket`, token).
///
/// * `Debug` and `Display` print `"[REDACTED]"` instead of the content, so an accidental
///   `tracing::info!(?secret)` cannot leak the credential into a SIEM.
/// * The backing buffer is overwritten with zeros on drop ([`Zeroizing`]).
/// * The plaintext is only reachable through the explicit [`Secret::expose`] call, which is
///   easy to grep for in code review.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps a plaintext value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Returns the plaintext. Every call site is a deliberate, reviewable data flow.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    /// Returns `true` when the secret is an empty string.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_never_prints_plaintext() {
        let s = Secret::new("CUL8TR");
        assert_eq!(format!("{s:?}"), "Secret([REDACTED])");
        assert_eq!(format!("{s}"), "[REDACTED]");
        assert_eq!(s.expose(), "CUL8TR");
        assert!(!s.is_empty());
    }
}
