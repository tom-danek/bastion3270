//! Commands sent to the [`SessionCoordinator`] actor and status query responses.

use bastion3270_core::keyboard::{ActionKey, AidKey, AttentionKey, KeyboardState, PasteOutcome};
use bastion3270_core::safe_view::SafeScreenView;
use tokio::sync::oneshot;

use crate::error::NetError;
use crate::profile::ProfileTerminalModel;
use crate::session::state::SessionState;

/// Commands received by the [`SessionCoordinator`] from the [`SessionHandle`].
///
/// [`SessionCoordinator`]: crate::session::coordinator::SessionCoordinator
/// [`SessionHandle`]: crate::session::handle::SessionHandle
#[derive(Debug)]
pub enum SessionCommand {
    /// Inserts a character into the screen buffer at the current cursor position.
    InputChar {
        /// Character to insert.
        ch: char,
        /// Optional channel for receiving keystroke execution result.
        respond_to: Option<oneshot::Sender<Result<(), NetError>>>,
    },

    /// Types a secret (password, `PassTicket`) at the cursor, but only into an unprotected
    /// non-display field: before every character the keyboard must be unlocked and the cursor
    /// in such a field, otherwise typing stops with an error. One command, so no other input
    /// can move the cursor between the characters.
    InputSecret {
        /// The secret; never printed by `Debug`.
        text: SecretText,
        /// Channel for receiving the result.
        respond_to: Option<oneshot::Sender<Result<(), NetError>>>,
    },
    /// Pastes text with the operator paste rules (margin, no wrap, unmappable characters
    /// skipped).
    Paste {
        /// Text to paste.
        text: String,
        /// Channel for receiving how the paste ended.
        respond_to: Option<oneshot::Sender<Result<PasteOutcome, NetError>>>,
    },

    /// Executes a keyboard navigation, editing, or reset action.
    InputAction {
        /// Navigation or editing action key.
        action: ActionKey,
        /// Optional channel for receiving action execution result.
        respond_to: Option<oneshot::Sender<Result<(), NetError>>>,
    },

    /// Presses an Attention Identification (AID) key (Enter, PF1-PF24, PA1-PA3, Clear).
    PressAid {
        /// Attention Identification key.
        aid: AidKey,
        /// Optional channel for receiving AID transmission result.
        respond_to: Option<oneshot::Sender<Result<(), NetError>>>,
    },

    /// Presses Attn or `SysReq`. These keys interrupt the host and work even while the keyboard
    /// waits for the host.
    PressAttention {
        /// Attn or `SysReq`.
        key: AttentionKey,
        /// Optional channel for receiving the transmission result.
        respond_to: Option<oneshot::Sender<Result<(), NetError>>>,
    },

    /// Queries an immutable Zero-Trust [`SafeScreenView`] snapshot of the screen.
    QueryScreen {
        /// Channel for returning the safe screen view snapshot.
        respond_to: oneshot::Sender<SafeScreenView>,
    },

    /// Queries the complete runtime status of the session.
    QueryStatus {
        /// Channel for returning the session runtime status.
        respond_to: oneshot::Sender<SessionStatus>,
    },

    /// Switches blank fill on or off for the rest of the session (an operator preference).
    SetBlankFill(bool),

    /// Gracefully closes the session and shuts down the transport stream.
    Disconnect,
}

/// Comprehensive runtime status snapshot of a 3270 session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStatus {
    /// Current lifecycle state of the session.
    pub state: SessionState,
    /// OIA keyboard lock status (Unlocked, `TimeWait`, Protected, Numeric, etc.).
    pub keyboard_state: KeyboardState,
    /// Current cursor row (0-indexed).
    pub cursor_row: u16,
    /// Current cursor column (0-indexed).
    pub cursor_col: u16,
    /// Whether the presentation space is formatted with field attributes.
    pub is_formatted: bool,
    /// Configured display model.
    pub terminal_model: ProfileTerminalModel,
    /// Host-assigned Logical Unit (LU) name if negotiated.
    pub assigned_lu: Option<String>,
    /// Whether TN3270E protocol enhancements are active.
    pub is_tn3270e: bool,
    /// Whether the underlying transport stream is TLS encrypted.
    pub is_tls: bool,
}

/// Text that must not be printed (a password): `Debug` shows only its length, and the memory
/// is overwritten when it is dropped.
pub struct SecretText(zeroize::Zeroizing<String>);

impl SecretText {
    /// Wraps a secret.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(zeroize::Zeroizing::new(text.to_owned()))
    }

    /// The secret itself.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretText(<{} chars redacted>)", self.0.chars().count())
    }
}
