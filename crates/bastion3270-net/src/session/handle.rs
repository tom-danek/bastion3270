//! Ergonomic async client handle for controlling 3270 sessions.

use bastion3270_core::keyboard::{ActionKey, AidKey, AttentionKey, KeyboardState, PasteOutcome};
use bastion3270_core::safe_view::SafeScreenView;
use tokio::sync::{mpsc, oneshot};

use crate::error::NetError;
use crate::session::command::{SecretText, SessionCommand, SessionStatus};

/// Ergonomic, cloneable async client handle for interacting with a running [`SessionCoordinator`].
///
/// [`SessionCoordinator`]: crate::session::coordinator::SessionCoordinator
#[derive(Debug, Clone)]
pub struct SessionHandle {
    command_tx: mpsc::Sender<SessionCommand>,
}

impl SessionHandle {
    /// Creates a new [`SessionHandle`] backed by the specified bounded command channel.
    #[must_use]
    pub const fn new(command_tx: mpsc::Sender<SessionCommand>) -> Self {
        Self { command_tx }
    }

    /// Inserts a character into the screen at the current cursor position.
    ///
    /// # Errors
    /// Returns [`NetError::Protocol`] if the keyboard is locked or field is protected/numeric.
    /// Returns [`NetError::Channel`] if the session actor is no longer running.
    pub async fn send_key(&self, ch: char) -> Result<(), NetError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SessionCommand::InputChar {
                ch,
                respond_to: Some(tx),
            })
            .await
            .map_err(|_| NetError::channel("session actor dropped command channel"))?;

        rx.await
            .map_err(|_| NetError::channel("session actor dropped response oneshot"))?
    }

    /// Pastes text as an operator paste (`x3270` paste rules: every line starts at the column
    /// where the paste started, the paste stops at the end of the screen, characters without
    /// an EBCDIC code are skipped).
    ///
    /// # Errors
    /// Returns [`NetError::Protocol`] if the keyboard is locked before the paste starts.
    /// Returns [`NetError::Channel`] if the session actor terminates prematurely.
    pub async fn paste(&self, text: &str) -> Result<PasteOutcome, NetError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SessionCommand::Paste {
                text: text.to_string(),
                respond_to: Some(tx),
            })
            .await
            .map_err(|_| NetError::channel("session actor dropped command channel"))?;
        rx.await
            .map_err(|_| NetError::channel("session actor dropped response oneshot"))?
    }

    /// Inserts a string of characters sequentially into the screen.
    ///
    /// Stops on the first character that triggers an error (e.g. protected field or keyboard lock).
    ///
    /// # Errors
    /// Returns [`NetError::Protocol`] if any character causes an input error.
    /// Returns [`NetError::Channel`] if the session actor terminates prematurely.
    pub async fn send_string(&self, s: &str) -> Result<(), NetError> {
        for ch in s.chars() {
            self.send_key(ch).await?;
        }
        Ok(())
    }

    /// Types a secret into the unprotected non-display field at the cursor (see
    /// [`SessionCommand::InputSecret`]).
    ///
    /// # Errors
    /// Returns [`NetError::Protocol`] if the keyboard is locked or the cursor is not (or no
    /// longer) in an unprotected non-display field; nothing more is typed then.
    /// Returns [`NetError::Channel`] if the session actor is no longer running.
    pub async fn send_secret(&self, text: &str) -> Result<(), NetError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SessionCommand::InputSecret {
                text: SecretText::new(text),
                respond_to: Some(tx),
            })
            .await
            .map_err(|_| NetError::channel("session actor dropped command channel"))?;

        rx.await
            .map_err(|_| NetError::channel("session actor dropped response oneshot"))?
    }

    /// Sends a navigation or editing action key (Tab, Home, Newline, Arrow, Reset, etc.).
    ///
    /// # Errors
    /// Returns [`NetError::Protocol`] if the keyboard is locked against navigation.
    /// Returns [`NetError::Channel`] if the session actor is no longer running.
    pub async fn send_action(&self, action: ActionKey) -> Result<(), NetError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SessionCommand::InputAction {
                action,
                respond_to: Some(tx),
            })
            .await
            .map_err(|_| NetError::channel("session actor dropped command channel"))?;

        rx.await
            .map_err(|_| NetError::channel("session actor dropped response oneshot"))?
    }

    /// Presses an Attention Identification (AID) key (Enter, PF1-PF24, PA1-PA3, Clear).
    ///
    /// Locks the keyboard waiting for the host (`X Wait`), constructs the Read Modified datastream,
    /// and transmits the packet to the mainframe.
    ///
    /// # Errors
    /// Returns [`NetError::Protocol`] if keyboard is already locked.
    /// Returns [`NetError::Channel`] if the session actor is no longer running.
    pub async fn press_aid(&self, aid: AidKey) -> Result<(), NetError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SessionCommand::PressAid {
                aid,
                respond_to: Some(tx),
            })
            .await
            .map_err(|_| NetError::channel("session actor dropped command channel"))?;

        rx.await
            .map_err(|_| NetError::channel("session actor dropped response oneshot"))?
    }

    /// Presses Attn or `SysReq` (`x3270` `Attn_action`, `SysReq_action`).
    ///
    /// Depending on the connection mode this sends `IAC IP` / `IAC AO` (TN3270E), a PA1 read
    /// followed by `IAC BREAK` or a test request read (plain TN3270), or sets the keyboard to
    /// `X -f` when the function is not available.
    ///
    /// # Errors
    /// Returns [`NetError::Protocol`] if a plain TN3270 `SysReq` is pressed while the keyboard is
    /// locked. Returns [`NetError::Channel`] if the session actor is no longer running.
    pub async fn press_attention(&self, key: AttentionKey) -> Result<(), NetError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SessionCommand::PressAttention {
                key,
                respond_to: Some(tx),
            })
            .await
            .map_err(|_| NetError::channel("session actor dropped command channel"))?;

        rx.await
            .map_err(|_| NetError::channel("session actor dropped response oneshot"))?
    }

    /// Asynchronously queries an immutable Zero-Trust [`SafeScreenView`] snapshot.
    ///
    /// All characters in `NonDisplay` (password) fields are guaranteed to be masked to `' '`.
    ///
    /// # Errors
    /// Returns [`NetError::Channel`] if the session actor has terminated.
    pub async fn query_screen(&self) -> Result<SafeScreenView, NetError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SessionCommand::QueryScreen { respond_to: tx })
            .await
            .map_err(|_| NetError::channel("session actor dropped command channel"))?;

        rx.await
            .map_err(|_| NetError::channel("session actor dropped response oneshot"))
    }

    /// Asynchronously queries the complete runtime status of the session.
    ///
    /// # Errors
    /// Returns [`NetError::Channel`] if the session actor has terminated.
    pub async fn query_status(&self) -> Result<SessionStatus, NetError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SessionCommand::QueryStatus { respond_to: tx })
            .await
            .map_err(|_| NetError::channel("session actor dropped command channel"))?;

        rx.await
            .map_err(|_| NetError::channel("session actor dropped response oneshot"))
    }

    /// Asynchronously queries the current keyboard / OIA lock state.
    ///
    /// # Errors
    /// Returns [`NetError::Channel`] if the session actor has terminated.
    pub async fn query_keyboard_state(&self) -> Result<KeyboardState, NetError> {
        let status = self.query_status().await?;
        Ok(status.keyboard_state)
    }

    /// Asynchronously queries the 0-indexed `(row, col)` cursor position.
    ///
    /// # Errors
    /// Returns [`NetError::Channel`] if the session actor has terminated.
    pub async fn query_cursor(&self) -> Result<(u16, u16), NetError> {
        let status = self.query_status().await?;
        Ok((status.cursor_row, status.cursor_col))
    }

    /// Switches blank fill on or off for what is typed from now on.
    ///
    /// # Errors
    /// Returns [`NetError::Channel`] if the session actor has terminated.
    pub async fn set_blank_fill(&self, on: bool) -> Result<(), NetError> {
        self.command_tx
            .send(SessionCommand::SetBlankFill(on))
            .await
            .map_err(|_| NetError::channel("session actor dropped command channel"))
    }

    /// Requests a graceful disconnect and shutdown of the network session.
    ///
    /// # Errors
    /// Returns [`NetError::Channel`] if the session actor has already closed.
    pub async fn disconnect(&self) -> Result<(), NetError> {
        self.command_tx
            .send(SessionCommand::Disconnect)
            .await
            .map_err(|_| NetError::channel("session actor dropped command channel"))
    }

    /// Returns `true` if the session actor channel is open and receptive to commands.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.command_tx.is_closed()
    }
}
