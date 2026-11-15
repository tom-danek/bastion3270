//! Keyboard lock set, modelled on the `x3270` `kybdlock` word (`include/kybd.h`,
//! `Common/kybd.c`).
//!
//! The keyboard is not in *one* state: several independent conditions can lock it at the
//! same time (waiting for the host, an operator error, no connection yet, ...), and each is
//! cleared by different events. [`KeyboardLock`] keeps them as a set; the single
//! [`KeyboardState`] shown in the status line is derived from it by [`KeyboardLock::indicator`].
//!
//! Not modelled because the matching feature does not exist in this client: deferred unlock
//! (`KL_DEFERRED_UNLOCK`, `unlockDelay` is off by default in `x3270`), scroll-back
//! (`KL_SCROLLED`), file transfer (`KL_FT`), TN3270E contention resolution (`KL_BID`) and the
//! DBCS operator error.

use crate::keyboard::oia::KeyboardState;

/// An operator error (`x3270` `KL_OERR_MASK`): a *value*, not a set of bits — at most one
/// operator error is in effect at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorError {
    /// Input into a protected field or onto a field attribute (`KL_OERR_PROTECTED`).
    Protected,
    /// Non-numeric input into a numeric field (`KL_OERR_NUMERIC`).
    Numeric,
    /// Input beyond the end of the field (`KL_OERR_OVERFLOW`).
    Overflow,
}

/// A lock condition other than an operator error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockReason {
    /// No host connection (`KL_NOT_CONNECTED`).
    NotConnected,
    /// Connected, but the host has not written to the screen yet (`KL_AWAITING_FIRST`).
    AwaitingFirst,
    /// An AID was sent; waiting for the host to answer (`KL_OIA_TWAIT`).
    TimeWait,
    /// Locked by an AID until the host restores the keyboard or the operator presses Reset;
    /// survives a host write without keyboard restore (`KL_OIA_LOCKED`).
    SystemLock,
    /// A query reply was sent; input waits for the next host write (`KL_ENTER_INHIBIT`).
    EnterInhibit,
    /// The requested function is not available (`KL_OIA_MINUS`).
    NotAvailable,
}

impl LockReason {
    const fn bit(self) -> u8 {
        match self {
            Self::NotConnected => 0x01,
            Self::AwaitingFirst => 0x02,
            Self::TimeWait => 0x04,
            Self::SystemLock => 0x08,
            Self::EnterInhibit => 0x10,
            Self::NotAvailable => 0x20,
        }
    }
}

/// The set of conditions currently locking the keyboard (`x3270` `kybdlock`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct KeyboardLock {
    oerr: Option<OperatorError>,
    flags: u8,
}

impl KeyboardLock {
    /// No lock at all.
    pub const UNLOCKED: Self = Self {
        oerr: None,
        flags: 0,
    };

    /// `true` if any condition locks the keyboard (`kybdlock != 0`).
    #[must_use]
    pub const fn is_locked(self) -> bool {
        self.oerr.is_some() || self.flags != 0
    }

    /// `true` if `reason` is one of the current lock conditions.
    #[must_use]
    pub const fn has(self, reason: LockReason) -> bool {
        self.flags & reason.bit() != 0
    }

    /// The operator error in effect, if any.
    #[must_use]
    pub const fn operator_error(self) -> Option<OperatorError> {
        self.oerr
    }

    /// `true` if an operator error is the *only* lock (`x3270` `KYBDLOCK_IS_OERR`).
    #[must_use]
    pub const fn is_operator_error_only(self) -> bool {
        self.oerr.is_some() && self.flags == 0
    }

    /// The single indicator shown in the status line.
    ///
    /// Follows `x3270` `vstatus.c`: conditions announced directly by the code that sets them
    /// (operator error, `X -f`, `X Wait`, `X SYSTEM`) win over the connection-phase and
    /// background conditions.
    #[must_use]
    pub const fn indicator(self) -> KeyboardState {
        if self.has(LockReason::NotConnected) {
            return KeyboardState::NotConnected;
        }
        match self.oerr {
            Some(OperatorError::Protected) => return KeyboardState::Protected,
            Some(OperatorError::Numeric) => return KeyboardState::Numeric,
            Some(OperatorError::Overflow) => return KeyboardState::Overflow,
            None => {}
        }
        if self.has(LockReason::NotAvailable) {
            KeyboardState::NotAvailable
        } else if self.has(LockReason::TimeWait) {
            KeyboardState::TimeWait
        } else if self.has(LockReason::SystemLock) {
            KeyboardState::SystemLock
        } else if self.has(LockReason::AwaitingFirst) {
            KeyboardState::AwaitingFirst
        } else if self.has(LockReason::EnterInhibit) {
            KeyboardState::Inhibit
        } else {
            KeyboardState::Unlocked
        }
    }

    pub(crate) fn set(&mut self, reason: LockReason) {
        self.flags |= reason.bit();
    }

    pub(crate) fn clear(&mut self, reason: LockReason) {
        self.flags &= !reason.bit();
    }

    pub(crate) fn set_operator_error(&mut self, oerr: OperatorError) {
        self.oerr = Some(oerr);
    }

    pub(crate) fn clear_operator_error(&mut self) {
        self.oerr = None;
    }

    /// Clears everything except the listed conditions.
    pub(crate) fn clear_all_except(&mut self, keep: &[LockReason]) {
        let mask = keep.iter().fold(0_u8, |m, r| m | r.bit());
        self.flags &= mask;
        self.oerr = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indicator_priority_follows_vstatus() {
        let mut lock = KeyboardLock::UNLOCKED;
        assert_eq!(lock.indicator(), KeyboardState::Unlocked);
        lock.set(LockReason::EnterInhibit);
        assert_eq!(lock.indicator(), KeyboardState::Inhibit);
        lock.set(LockReason::AwaitingFirst);
        assert_eq!(lock.indicator(), KeyboardState::AwaitingFirst);
        lock.set(LockReason::SystemLock);
        assert_eq!(lock.indicator(), KeyboardState::SystemLock);
        lock.set(LockReason::TimeWait);
        assert_eq!(lock.indicator(), KeyboardState::TimeWait);
        lock.set(LockReason::NotAvailable);
        assert_eq!(lock.indicator(), KeyboardState::NotAvailable);
        lock.set_operator_error(OperatorError::Numeric);
        assert_eq!(lock.indicator(), KeyboardState::Numeric);
        lock.set(LockReason::NotConnected);
        assert_eq!(lock.indicator(), KeyboardState::NotConnected);
    }

    #[test]
    fn operator_error_only() {
        let mut lock = KeyboardLock::UNLOCKED;
        lock.set_operator_error(OperatorError::Protected);
        assert!(lock.is_operator_error_only());
        lock.set(LockReason::TimeWait);
        assert!(!lock.is_operator_error_only());
        lock.clear_all_except(&[LockReason::TimeWait]);
        assert_eq!(lock.operator_error(), None);
        assert!(lock.has(LockReason::TimeWait));
    }
}
