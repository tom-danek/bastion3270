//! Operator Information Area (OIA) status indicators and keyboard lock state.
//!
//! Reference: `x3270` (`include/kybd.h`, `Common/vstatus.c`).

use core::fmt;

/// The keyboard indicator shown in the terminal OIA status line.
///
/// This is a *projection* of the [`KeyboardLock`](crate::keyboard::KeyboardLock) set: several
/// lock conditions can hold at once, and the most significant one is shown (`x3270`
/// `vstatus.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum KeyboardState {
    /// Keyboard is unlocked; operator input is accepted.
    #[default]
    Unlocked,
    /// No host connection (`KL_NOT_CONNECTED`, `X Not Connected`).
    NotConnected,
    /// Connected, waiting for the first host write (`KL_AWAITING_FIRST`, `X [Field]`).
    AwaitingFirst,
    /// An AID was sent and the host has not answered yet (`KL_OIA_TWAIT`, `X Wait`).
    TimeWait,
    /// The host answered without restoring the keyboard; it stays locked until the host
    /// restores it or the operator presses Reset (`KL_OIA_LOCKED`, `X SYSTEM`).
    SystemLock,
    /// Operator attempted to edit a protected field or attribute byte (`X PROTECTED`).
    Protected,
    /// Operator attempted to enter non-numeric data into an `FA_NUMERIC` field (`X NUMERIC`).
    Numeric,
    /// Operator input overflowed the available field length (`X >` / `X Overflow`).
    Overflow,
    /// Input inhibited after a query reply until the next host write (`KL_ENTER_INHIBIT`).
    Inhibit,
    /// The requested function is not available in the current session state, e.g. Attn on a
    /// TN3270E session without a BIND (`x3270` `KL_OIA_MINUS`, `X -f`). Cleared by `Reset`.
    NotAvailable,
}

impl KeyboardState {
    /// Returns `true` if the keyboard is locked (any state other than [`KeyboardState::Unlocked`]).
    #[must_use]
    pub const fn is_locked(self) -> bool {
        !matches!(self, Self::Unlocked)
    }

    /// Returns `true` for a local operator error ([`Protected`](Self::Protected),
    /// [`Numeric`](Self::Numeric), [`Overflow`](Self::Overflow)).
    #[must_use]
    pub const fn is_operator_error(self) -> bool {
        matches!(self, Self::Protected | Self::Numeric | Self::Overflow)
    }

    /// Returns the standard IBM 3270 OIA text indicator string.
    #[must_use]
    pub const fn oia_indicator(self) -> &'static str {
        match self {
            Self::Unlocked => "",
            Self::NotConnected => "X Not Connected",
            Self::AwaitingFirst => "X [Field]",
            Self::TimeWait => "X Wait",
            Self::SystemLock => "X SYSTEM",
            Self::Protected => "X PROTECTED",
            Self::Numeric => "X NUMERIC",
            Self::Overflow => "X >",
            Self::Inhibit => "X INHIBIT",
            Self::NotAvailable => "X -f",
        }
    }

    /// Returns the short OIA indicator string, as `x3270` displays it (`vstatus.c`).
    #[must_use]
    pub const fn oia_short_indicator(self) -> &'static str {
        match self {
            Self::Unlocked => "",
            Self::NotConnected => "X Not Connected",
            Self::AwaitingFirst => "X [Field]",
            Self::TimeWait | Self::Inhibit => "X Wait",
            Self::SystemLock => "X SYSTEM",
            Self::Protected => "X Protected",
            Self::NotAvailable => "X -f",
            Self::Numeric => "X NUM",
            Self::Overflow => "X Overflow",
        }
    }
}

impl fmt::Display for KeyboardState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.oia_indicator())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyboard_state_properties() {
        assert!(!KeyboardState::Unlocked.is_locked());
        assert!(KeyboardState::TimeWait.is_locked());
        assert!(!KeyboardState::TimeWait.is_operator_error());

        assert!(KeyboardState::Protected.is_locked());
        assert!(KeyboardState::Protected.is_operator_error());
        assert_eq!(KeyboardState::Protected.oia_indicator(), "X PROTECTED");
        assert_eq!(
            KeyboardState::Protected.oia_short_indicator(),
            "X Protected"
        );

        assert!(KeyboardState::Numeric.is_operator_error());
        assert_eq!(KeyboardState::Numeric.oia_indicator(), "X NUMERIC");
        assert_eq!(KeyboardState::Numeric.oia_short_indicator(), "X NUM");
    }
}
