//! Asynchronous events emitted by the [`SessionCoordinator`] actor.

use bastion3270_core::keyboard::KeyboardState;
use bastion3270_core::safe_view::SafeScreenView;
use bastion3270_core::telnet::HostMode;

use crate::session::state::SessionState;

/// Events emitted across the bounded event channel to UI, CLI, or test subscribers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// Session lifecycle state transitioned to a new state.
    StateChanged(SessionState),

    /// Telnet / TN3270E option negotiation and LU binding completed.
    NegotiationComplete {
        /// `true` if TN3270E mode was negotiated; `false` if standard TN3270.
        is_tn3270e: bool,
        /// Host-assigned Logical Unit name, if any.
        assigned_lu: Option<String>,
    },

    /// Screen contents or cursor position updated.
    ScreenUpdated(SafeScreenView),

    /// Virtual keyboard state / OIA status indicator changed.
    KeyboardStateChanged(KeyboardState),

    /// Insert mode was switched on or off (by the operator, or off again by a reset).
    InsertModeChanged(bool),

    /// Host requested an audible alarm via WCC.
    Alarm,

    /// Host transmitted ASCII NVT data (e.g. login banner before 3270 bind).
    NvtData(Vec<u8>),

    /// The host switched between 3270, SSCP-LU and NVT data (or unbound the session).
    HostModeChanged(HostMode),

    /// Non-fatal diagnostic or protocol warning.
    Warning(String),

    /// Session terminated with an error.
    Error(String),

    /// Session gracefully disconnected.
    Disconnected,
}
