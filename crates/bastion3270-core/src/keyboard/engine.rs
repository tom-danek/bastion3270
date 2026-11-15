//! 3270 Virtual Keyboard state machine and Presentation Space editing engine.
//!
//! Reference: `x3270` (`Common/kybd.c`, `Common/ctlr.c`).

use core::fmt;
use std::collections::VecDeque;

use crate::address::{AddressError, BufferAddress};
use crate::datastream::response::{
    build_read_modified, build_sscp_read, build_test_request, AID_NO, AID_SYSREQ,
};
use crate::datastream::wcc::WriteControlCharacter;
use crate::ebcdic::{CodePage, EncodingError, EBC_DUP, EBC_FM};
use crate::keyboard::key::{ActionKey, AidKey};
use crate::keyboard::lock::{KeyboardLock, LockReason, OperatorError};
use crate::keyboard::oia::KeyboardState;
use crate::screen::{PresentationSpace, ScreenError};
use crate::telnet::HostMode;

mod edit;
pub use edit::{KeyboardOptions, PasteEnd, PasteOutcome};

/// Errors returned by virtual keyboard operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardError {
    /// Keyboard is currently locked in the given state.
    Locked(KeyboardState),
    /// Attempted to write into a protected field or onto a field attribute marker.
    ProtectedField,
    /// Attempted to write non-numeric characters into an `FA_NUMERIC` field.
    NumericField,
    /// The input character could not be encoded in the active EBCDIC code page.
    Encoding(EncodingError),
    /// Screen buffer addressing or navigation error.
    Screen(ScreenError),
}

impl fmt::Display for KeyboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked(state) => write!(f, "keyboard locked: {}", state.oia_indicator()),
            Self::ProtectedField => write!(f, "cannot edit protected field or attribute cell"),
            Self::NumericField => write!(f, "cannot insert non-numeric character in numeric field"),
            Self::Encoding(err) => write!(f, "EBCDIC encoding error: {err}"),
            Self::Screen(err) => write!(f, "screen error: {err}"),
        }
    }
}

impl std::error::Error for KeyboardError {}

impl From<ScreenError> for KeyboardError {
    fn from(err: ScreenError) -> Self {
        Self::Screen(err)
    }
}

impl From<AddressError> for KeyboardError {
    fn from(err: AddressError) -> Self {
        Self::Screen(ScreenError::InvalidAddress(err))
    }
}

impl From<EncodingError> for KeyboardError {
    fn from(err: EncodingError) -> Self {
        Self::Encoding(err)
    }
}

/// Maximum number of keys held in the typeahead queue. `x3270` does not limit it; a bound
/// keeps a flooding client from growing the server's memory.
pub const MAX_TYPEAHEAD: usize = 128;

/// One operator input, as submitted to [`VirtualKeyboard::submit`] and held in the typeahead
/// queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyInput {
    /// A printable character.
    Char(char),
    /// A navigation, editing or reset key.
    Action(ActionKey),
    /// An AID key.
    Aid(AidKey),
    /// System Request on a plain TN3270 session (a *test request* read).
    SysReq,
}

/// What [`VirtualKeyboard::submit`] did with an input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOutcome {
    /// Applied to the screen / cursor locally.
    Applied,
    /// The keyboard is locked: the input was queued and runs once it unlocks (typeahead).
    Queued,
    /// An inbound record for the host (AID read or test request); the keyboard is now locked
    /// waiting for the answer.
    Transmit(Vec<u8>),
}

/// Pure-Rust IBM 3270 virtual keyboard controller.
///
/// Manages the keyboard lock set ([`KeyboardLock`], `x3270` `kybdlock`), typeahead, cursor
/// navigation, protected field enforcement, numeric validation, auto-skip, automatic MDT
/// marking, and AID datastream emission.
///
/// The `input_char`, `action`, `press_aid` and `press_sysreq` methods are the strict
/// primitives: they act only when the keyboard is unlocked. [`Self::submit`] is the operator
/// entry point that also applies the `x3270` lock policy and typeahead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualKeyboard {
    lock: KeyboardLock,
    typeahead: VecDeque<KeyInput>,
    /// The AID of the last AID key, until the host restores the keyboard (`x3270` `aid`).
    aid: u8,
    /// What the host exchanges with the terminal; SSCP-LU and NVT change the key rules.
    host_mode: HostMode,
    /// Behaviour switches (numeric lock, blank fill).
    options: KeyboardOptions,
    /// Insert mode (`x3270` `insertMode` toggle): typing shifts the field right.
    insert_mode: bool,
}

impl Default for VirtualKeyboard {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualKeyboard {
    /// Creates an unlocked keyboard. A session follows the connection lifecycle with
    /// [`Self::disconnected`], [`Self::connected`] and [`Self::entered_3270`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lock: KeyboardLock::UNLOCKED,
            typeahead: VecDeque::new(),
            aid: AID_NO,
            host_mode: HostMode::Negotiating,
            options: KeyboardOptions::DEFAULT,
            insert_mode: false,
        }
    }

    /// A keyboard with the given behaviour switches.
    #[must_use]
    pub const fn with_options(options: KeyboardOptions) -> Self {
        let mut kb = Self::new();
        kb.options = options;
        kb
    }

    /// The behaviour switches in effect.
    #[must_use]
    pub const fn options(&self) -> KeyboardOptions {
        self.options
    }

    /// Switches blank fill on or off for what is typed from now on (`x3270` `blankFill`, a
    /// toggle there too); the screen is not changed.
    pub const fn set_blank_fill(&mut self, on: bool) {
        self.options.blank_fill = on;
    }

    /// `true` while insert mode is on.
    #[must_use]
    pub const fn insert_mode(&self) -> bool {
        self.insert_mode
    }

    /// The host mode the keyboard follows.
    #[must_use]
    pub const fn host_mode(&self) -> HostMode {
        self.host_mode
    }

    /// The host switched modes (`x3270` `kybd_in3270` on a connection state change):
    ///
    /// * SSCP-LU: every lock is cleared, the operator types into the unformatted screen.
    /// * NVT: every lock is cleared, but there is no NVT input path, so the keyboard shows
    ///   `X -f` (function not available) instead of dropping keys silently.
    /// * 3270 (TN3270E): locks are cleared except the first-write wait and an AID lock.
    /// * Unbound: the keyboard waits for the first write of the next BIND.
    ///
    /// The first 3270 mode after negotiation is set up by [`Self::entered_3270`]; leaving
    /// it again by a new negotiation changes no locks here.
    pub fn set_host_mode(&mut self, mode: HostMode) {
        let previous = self.host_mode;
        if mode == previous {
            return;
        }
        self.host_mode = mode;
        match (previous, mode) {
            (_, HostMode::SscpLu) => self.lock = KeyboardLock::UNLOCKED,
            (_, HostMode::Nvt) => {
                self.lock = KeyboardLock::UNLOCKED;
                self.lock.set(LockReason::NotAvailable);
            }
            (HostMode::Negotiating, _) | (_, HostMode::Negotiating) => {}
            (_, HostMode::Data3270) => self.entered_3270(true),
            (_, HostMode::Unbound) => self.unbound(),
        }
    }

    /// The current AID: the last AID key pressed, or `0x60` (no AID) once the host has
    /// restored the keyboard. A host Read Buffer / Read Modified is answered with it
    /// (`x3270` `process_ds` → `ctlr_read_buffer(aid)` / `ctlr_read_modified(aid, ..)`).
    #[must_use]
    pub const fn current_aid(&self) -> u8 {
        self.aid
    }

    /// Returns the OIA indicator derived from the current lock set.
    #[must_use]
    pub const fn state(&self) -> KeyboardState {
        self.lock.indicator()
    }

    /// Returns the full lock set.
    #[must_use]
    pub const fn lock(&self) -> KeyboardLock {
        self.lock
    }

    /// Returns `true` if operator input is currently blocked.
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.lock.is_locked()
    }

    /// Number of keys waiting in the typeahead queue.
    #[must_use]
    pub fn typeahead_len(&self) -> usize {
        self.typeahead.len()
    }

    fn check_unlocked(&self) -> Result<(), KeyboardError> {
        if self.lock.is_locked() {
            return Err(KeyboardError::Locked(self.state()));
        }
        Ok(())
    }

    /// Records an operator error (`x3270` `operator_error`): locks the keyboard and discards
    /// the typeahead queue.
    fn operator_error(&mut self, oerr: OperatorError) {
        self.lock.set_operator_error(oerr);
        self.typeahead.clear();
    }

    // ── Connection lifecycle (`x3270` `kybd_connect`, `kybd_in3270`) ──────────────────────

    /// The connection is gone: everything is cleared, the keyboard shows `X Not Connected`
    /// and the typeahead queue is discarded.
    pub fn disconnected(&mut self) {
        self.lock = KeyboardLock::UNLOCKED;
        self.lock.set(LockReason::NotConnected);
        self.typeahead.clear();
        self.host_mode = HostMode::Negotiating;
    }

    /// The TCP/TLS connection is up: the keyboard stays locked until the host writes the
    /// first screen (`KL_AWAITING_FIRST`).
    pub fn connected(&mut self) {
        self.lock = KeyboardLock::UNLOCKED;
        self.lock.set(LockReason::AwaitingFirst);
        self.aid = AID_NO;
    }

    /// Negotiation entered a 3270 mode. Locks from the previous mode are dropped; the wait
    /// for the first host write stays, and in TN3270E an AID lock survives the mode change.
    pub fn entered_3270(&mut self, tn3270e: bool) {
        if tn3270e {
            self.lock
                .clear_all_except(&[LockReason::AwaitingFirst, LockReason::SystemLock]);
        } else {
            self.lock.clear_all_except(&[LockReason::AwaitingFirst]);
        }
    }

    /// The host unbound the TN3270E session: the keyboard waits for the next first write.
    pub fn unbound(&mut self) {
        self.lock.set(LockReason::AwaitingFirst);
    }

    // ── Host-side events (`x3270` `ctlr.c`) ───────────────────────────────────────────────

    /// A host Write / Erase Write / Erase Write Alternate was processed (`x3270`
    /// `ctlr_write`): enter-inhibit and the first-write wait end; with WCC keyboard restore
    /// the keyboard is reset, otherwise only the AID wait ends and an AID lock stays
    /// (`X SYSTEM`).
    pub fn host_write(&mut self, restore: bool) {
        self.lock.clear(LockReason::EnterInhibit);
        self.lock.clear(LockReason::AwaitingFirst);
        if restore {
            self.host_reset();
        } else {
            self.lock.clear(LockReason::TimeWait);
        }
    }

    /// Keyboard restore from the host (`x3270` `do_reset(false)`): WCC restore, Erase All
    /// Unprotected, TN3270E KEYBOARD-RESTORE. Clears every lock; nothing happens while
    /// disconnected.
    pub fn host_reset(&mut self) {
        if self.lock.has(LockReason::NotConnected) {
            return;
        }
        self.lock = KeyboardLock::UNLOCKED;
        // `x3270` `restore_keyboard` / `ctlr_write`: `aid = AID_NO`.
        self.aid = AID_NO;
        // `x3270` `do_reset`: insert mode back to its default (off).
        self.insert_mode = false;
    }

    /// A query reply was sent: input waits for the next host write (`x3270`
    /// `query_reply_end` → `kybd_inhibit(true)`).
    pub fn enter_inhibit(&mut self) {
        self.lock.set(LockReason::EnterInhibit);
    }

    /// The pressed function is not available now (`KL_OIA_MINUS`, `X -f`).
    pub fn not_available(&mut self) {
        self.lock.set(LockReason::NotAvailable);
    }

    /// The operator Reset key (`x3270` `do_reset(true)`).
    ///
    /// A *half reset* first: if keys are waiting in the typeahead queue, they are discarded
    /// and nothing else happens — a second Reset unlocks. Otherwise every lock is cleared,
    /// including the AID wait and `X SYSTEM`, so the operator can never be stuck. While
    /// disconnected Reset does nothing.
    pub fn reset(&mut self) {
        if !self.typeahead.is_empty() {
            self.typeahead.clear();
            return;
        }
        // `x3270` `do_reset`: insert mode back to its default (off), connected or not.
        self.insert_mode = false;
        if self.lock.has(LockReason::NotConnected) {
            return;
        }
        self.lock = KeyboardLock::UNLOCKED;
    }

    // ── Operator input with lock policy and typeahead ─────────────────────────────────────

    /// Submits one operator input, applying the `x3270` lock policy (`kybd.c`):
    ///
    /// * Reset always runs.
    /// * A mouse cursor move is ignored while locked (`xkybd.c` `MoveCursor`).
    /// * Navigation and field-erase keys (Tab, `BackTab`, Home, arrows, `EraseEOF`,
    ///   `EraseInput`) clear an operator-error lock and proceed (`OERR_CLEAR_OR_ENQ`).
    /// * Otherwise a locked keyboard queues the input (typeahead), unless the lock is an
    ///   operator error, the connection is down or the queue is full — then it is dropped
    ///   with [`KeyboardError::Locked`] (`enq_xta`).
    ///
    /// # Errors
    /// [`KeyboardError::Locked`] if the input was dropped; the other [`KeyboardError`]s when
    /// the input itself is invalid (protected field, numeric field, encoding).
    pub fn submit(
        &mut self,
        ps: &mut PresentationSpace,
        input: KeyInput,
        codepage: &dyn CodePage,
    ) -> Result<KeyOutcome, KeyboardError> {
        if input == KeyInput::Action(ActionKey::Reset) {
            self.reset();
            return Ok(KeyOutcome::Applied);
        }
        if input == KeyInput::Action(ActionKey::ToggleInsert) {
            // A toggle, not a key: it works whatever the lock state (`x3270` `Toggle`).
            self.insert_mode = !self.insert_mode;
            return Ok(KeyOutcome::Applied);
        }
        if self.lock.is_locked() {
            if matches!(input, KeyInput::Action(ActionKey::MoveCursor { .. })) {
                return Err(KeyboardError::Locked(self.state()));
            }
            let clears_oerr = matches!(input, KeyInput::Action(a) if a.clears_operator_error());
            if !(clears_oerr && self.lock.is_operator_error_only()) {
                return self.enqueue(input);
            }
        }
        self.execute(ps, input, codepage)
    }

    /// Takes the next typeahead key, but only while the keyboard is unlocked (`x3270`
    /// `run_ta`). The caller replays it through [`Self::submit`]; an AID that locks the
    /// keyboard again stops the replay.
    pub fn pop_typeahead(&mut self) -> Option<KeyInput> {
        if self.lock.is_locked() {
            return None;
        }
        self.typeahead.pop_front()
    }

    fn enqueue(&mut self, input: KeyInput) -> Result<KeyOutcome, KeyboardError> {
        let refuse = self.lock.has(LockReason::NotConnected)
            || self.lock.operator_error().is_some()
            || self.typeahead.len() >= MAX_TYPEAHEAD;
        if refuse {
            return Err(KeyboardError::Locked(self.state()));
        }
        self.typeahead.push_back(input);
        Ok(KeyOutcome::Queued)
    }

    fn execute(
        &mut self,
        ps: &mut PresentationSpace,
        input: KeyInput,
        codepage: &dyn CodePage,
    ) -> Result<KeyOutcome, KeyboardError> {
        if self.host_mode == HostMode::Nvt {
            // No NVT input path: say so instead of editing a screen the host does not read.
            self.not_available();
            return Err(KeyboardError::Locked(self.state()));
        }
        match input {
            KeyInput::Aid(aid) if self.host_mode == HostMode::SscpLu => self.sscp_aid(ps, aid),
            KeyInput::Char(ch) => self
                .input_char(ps, ch, codepage)
                .map(|()| KeyOutcome::Applied),
            KeyInput::Action(action) => self.action(ps, action).map(|()| KeyOutcome::Applied),
            KeyInput::Aid(aid) => self.press_aid(ps, aid).map(KeyOutcome::Transmit),
            KeyInput::SysReq => self.press_sysreq(ps).map(KeyOutcome::Transmit),
        }
    }

    /// Types a character at the cursor (`x3270` `key_UCharacter` → `key_Character`); see
    /// the rules in [`edit`].
    ///
    /// # Errors
    /// [`KeyboardError::Locked`] while locked (also `X Overflow` in insert mode),
    /// [`KeyboardError::ProtectedField`], [`KeyboardError::NumericField`], or
    /// [`KeyboardError::Encoding`] if the code page has no EBCDIC code for `ch`.
    pub fn input_char(
        &mut self,
        ps: &mut PresentationSpace,
        ch: char,
        codepage: &dyn CodePage,
    ) -> Result<(), KeyboardError> {
        self.check_unlocked()?;
        let ebcdic = codepage
            .char_to_ebcdic(ch)
            .ok_or(EncodingError::UnmappableChar {
                ch,
                codepage: codepage.name(),
            })?;
        self.key_character(ps, ebcdic, false)
    }

    /// Executes a non-character navigation, editing, or reset action.
    ///
    /// # Errors
    /// Returns [`KeyboardError::Locked`] if keyboard is locked against the action.
    pub fn action(
        &mut self,
        ps: &mut PresentationSpace,
        action: ActionKey,
    ) -> Result<(), KeyboardError> {
        if action == ActionKey::Reset {
            self.reset();
            return Ok(());
        }
        // `OERR_CLEAR_OR_ENQ`: navigation / field-erase keys clear an operator error.
        if action.clears_operator_error() && self.lock.is_operator_error_only() {
            self.lock.clear_operator_error();
        }
        self.check_unlocked()?;
        match action {
            ActionKey::Reset => Ok(()),
            ActionKey::Tab => Self::action_tab(ps),
            ActionKey::BackTab => Self::action_backtab(ps),
            ActionKey::Home => Self::action_home(ps),
            ActionKey::Newline => Self::action_newline(ps),
            ActionKey::Left | ActionKey::Right | ActionKey::Up | ActionKey::Down => {
                Self::action_arrow(ps, action)
            }
            ActionKey::EraseEof => self.erase_eof(ps),
            ActionKey::FieldEnd => Self::field_end(ps),
            ActionKey::ToggleInsert => {
                self.insert_mode = !self.insert_mode;
                Ok(())
            }
            ActionKey::EraseInput => {
                ps.erase_all_unprotected();
                Ok(())
            }
            ActionKey::Dup => {
                self.key_character(ps, EBC_DUP, false)?;
                Self::action_tab(ps)
            }
            ActionKey::FieldMark => self.key_character(ps, EBC_FM, false),
            ActionKey::EraseField => self.erase_field(ps),
            ActionKey::Backspace => self.erase_before_cursor(ps),
            ActionKey::Delete => self.delete_at_cursor(ps),
            ActionKey::MoveCursor { row, col } => {
                let addr = BufferAddress::from_row_col(row, col, ps.rows(), ps.cols())?;
                ps.set_cursor_addr(addr)?;
                Ok(())
            }
        }
    }

    /// Tab (`x3270` `Tab_action`): to the next unprotected field; without one (or on an
    /// unformatted screen) to address 0.
    fn action_tab(ps: &mut PresentationSpace) -> Result<(), KeyboardError> {
        let target = ps
            .next_unprotected_data_addr(ps.cursor_addr())
            .unwrap_or(BufferAddress::ZERO);
        ps.set_cursor_addr(target)?;
        Ok(())
    }

    /// `BackTab` (`x3270` `BackTab_action`): to the start of this or the previous unprotected
    /// field; without one to address 0.
    fn action_backtab(ps: &mut PresentationSpace) -> Result<(), KeyboardError> {
        let target = ps
            .prev_unprotected_data_addr(ps.cursor_addr())
            .unwrap_or(BufferAddress::ZERO);
        ps.set_cursor_addr(target)?;
        Ok(())
    }

    fn action_home(ps: &mut PresentationSpace) -> Result<(), KeyboardError> {
        let home = ps
            .first_unprotected_data_addr()
            .unwrap_or(BufferAddress::ZERO);
        ps.set_cursor_addr(home)?;
        Ok(())
    }

    fn action_newline(ps: &mut PresentationSpace) -> Result<(), KeyboardError> {
        let (row, _) = ps.cursor_addr().to_row_col(ps.cols());
        let next_row = row.saturating_add(1).checked_rem(ps.rows()).unwrap_or(0);
        let col0_addr = BufferAddress::from_row_col(next_row, 0, ps.rows(), ps.cols())?;

        if !ps.is_formatted() {
            ps.set_cursor_addr(col0_addr)?;
            return Ok(());
        }

        let is_attr_cell = ps
            .cell(col0_addr)
            .is_some_and(crate::screen::Cell::is_field_attribute);
        let is_protected = ps.effective_field_attribute(col0_addr).is_protected();

        if !is_attr_cell && !is_protected {
            ps.set_cursor_addr(col0_addr)?;
        } else {
            // `x3270` `Newline_action`: `next_unprotected`, 0 if there is none.
            let target = ps
                .next_unprotected_data_addr(col0_addr)
                .unwrap_or(BufferAddress::ZERO);
            ps.set_cursor_addr(target)?;
        }
        Ok(())
    }

    fn action_arrow(ps: &mut PresentationSpace, action: ActionKey) -> Result<(), KeyboardError> {
        let target = match action {
            ActionKey::Left => ps.cursor_addr().prev_wrapped(ps.capacity()),
            ActionKey::Right => ps.cursor_addr().next_wrapped(ps.capacity()),
            ActionKey::Up => {
                let (row, col) = ps.cursor_addr().to_row_col(ps.cols());
                let new_row = if row == 0 {
                    ps.rows().saturating_sub(1)
                } else {
                    row.saturating_sub(1)
                };
                BufferAddress::from_row_col(new_row, col, ps.rows(), ps.cols())?
            }
            ActionKey::Down => {
                let (row, col) = ps.cursor_addr().to_row_col(ps.cols());
                let new_row = row.saturating_add(1).checked_rem(ps.rows()).unwrap_or(0);
                BufferAddress::from_row_col(new_row, col, ps.rows(), ps.cols())?
            }
            _ => ps.cursor_addr(),
        };
        ps.set_cursor_addr(target)?;
        Ok(())
    }

    /// Processes an Attention Identification (AID) key press.
    ///
    /// # Workflow
    /// 1. Rejects if keyboard is already locked.
    /// 2. Locks the keyboard waiting for the host (`TimeWait` + `SystemLock`, `x3270`
    ///    `key_AID`).
    /// 3. If `aid == AidKey::Clear`, resets the presentation space to default/alternate mode.
    /// 4. Generates inbound Read Modified datastream via [`build_read_modified`].
    /// 5. Returns outbound byte stream.
    ///
    /// # Errors
    /// Returns [`KeyboardError::Locked`] if the keyboard is locked.
    pub fn press_aid(
        &mut self,
        ps: &mut PresentationSpace,
        aid: AidKey,
    ) -> Result<Vec<u8>, KeyboardError> {
        self.check_unlocked()?;
        // `x3270` `key_AID`: wait for the host (`X Wait`) and stay locked until it restores
        // the keyboard.
        self.lock.set(LockReason::TimeWait);
        self.lock.set(LockReason::SystemLock);
        self.aid = aid.to_byte();

        if aid == AidKey::Clear {
            ps.erase_reset(ps.is_alternate_mode());
        }

        let stream = build_read_modified(ps, aid.to_byte(), false);
        Ok(stream)
    }

    /// An AID key in SSCP-LU mode (`x3270` `key_AID`, `IN_SSCP`):
    ///
    /// * Enter moves the cursor to the start of the next row (scrolling on the last row) and
    ///   sends the typed text ([`build_sscp_read`]) without locking the keyboard.
    /// * Clear only clears the screen locally.
    /// * Every other AID is invalid in SSCP-LU mode: `X -f`.
    fn sscp_aid(
        &mut self,
        ps: &mut PresentationSpace,
        aid: AidKey,
    ) -> Result<KeyOutcome, KeyboardError> {
        self.check_unlocked()?;
        match aid {
            AidKey::Clear => {
                ps.erase_reset(ps.is_alternate_mode());
                Ok(KeyOutcome::Applied)
            }
            AidKey::Enter => {
                let cols = ps.cols_nonzero();
                let cap = ps.capacity();
                let cursor = ps.cursor_addr().as_usize();
                let on_last_row = cursor / cols == usize::from(ps.rows()).saturating_sub(1);
                if !on_last_row {
                    // Not on the last row, so the next row start is `< cap`; saturation could
                    // only yield an address `new` rejects.
                    let next_row_start =
                        (cursor / cols).saturating_add(1).saturating_mul(cols.get());
                    let next_row = BufferAddress::new(next_row_start, cap)?;
                    ps.set_cursor_addr(next_row)?;
                }
                ps.set_buffer_addr(ps.cursor_addr())?;
                self.aid = aid.to_byte();
                let bytes = build_sscp_read(ps);
                if on_last_row {
                    ps.scroll_up();
                    let last = ps.last_row_start();
                    ps.set_cursor_addr(last)?;
                    ps.set_buffer_addr(last)?;
                }
                Ok(KeyOutcome::Transmit(bytes))
            }
            _ => {
                self.not_available();
                Err(KeyboardError::Locked(self.state()))
            }
        }
    }

    /// Presses System Request on a plain TN3270 session (`x3270` `SysReq_action` →
    /// `key_AID(AID_SYSREQ)`): like an AID key it locks the keyboard into `TimeWait`, and it
    /// returns the *test request* read for the host.
    ///
    /// # Errors
    /// Returns [`KeyboardError::Locked`] if the keyboard is locked.
    pub fn press_sysreq(&mut self, ps: &PresentationSpace) -> Result<Vec<u8>, KeyboardError> {
        self.check_unlocked()?;
        self.lock.set(LockReason::TimeWait);
        self.lock.set(LockReason::SystemLock);
        self.aid = AID_SYSREQ;
        Ok(build_test_request(ps))
    }

    /// Handles host Write Control Character (WCC) instructions.
    ///
    /// - If `wcc.reset_mdt`, clears all MDTs across the presentation space.
    /// - Applies the host-write keyboard rules of [`Self::host_write`] with
    ///   `wcc.restore_keyboard`.
    pub fn handle_wcc(&mut self, ps: &mut PresentationSpace, wcc: WriteControlCharacter) {
        if wcc.reset_mdt {
            ps.reset_all_mdt();
        }
        self.host_write(wcc.restore_keyboard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebcdic::CP037;
    use crate::field::{ExtendedAttributes, FieldAttribute};
    use crate::model::TerminalModel;

    #[test]
    fn test_initial_state_unlocked() {
        let kb = VirtualKeyboard::new();
        assert_eq!(kb.state(), KeyboardState::Unlocked);
        assert!(!kb.is_locked());
    }

    #[test]
    fn test_input_char_unprotected() {
        let mut kb = VirtualKeyboard::new();
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let fa = FieldAttribute::from_wire_byte(0x00);
        assert_eq!(
            ps.place_field(BufferAddress::ZERO, fa, ExtendedAttributes::DEFAULT),
            Ok(())
        );

        let c1 = BufferAddress::new(1, 1920);
        assert!(c1.is_ok());
        if let Ok(addr1) = c1 {
            assert_eq!(ps.set_cursor_addr(addr1), Ok(()));
            assert_eq!(kb.input_char(&mut ps, 'A', &CP037), Ok(()));
            let cell_ebcdic = ps.cell(addr1).map(crate::screen::Cell::raw_ebcdic);
            assert_eq!(cell_ebcdic, Some(0xC1));
            assert_eq!(ps.cursor_addr().as_usize(), 2);
            let gov_modified = ps.governing_field(addr1).map(|(_, f, _)| f.is_modified());
            assert_eq!(gov_modified, Some(true));
        }
    }
}
