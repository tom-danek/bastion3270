//! Operator editing as in `x3270` `kybd.c`: typing a character (`key_Character`, with
//! insert mode `ins_prep`, blank fill and auto-skip), Erase / Delete (`do_erase`,
//! `do_delete`), `FieldEnd`, `EraseEOF`, and the navigation keys when no unprotected field
//! exists.
//!
//! The functions work on whole cells: when characters shift, their extended attributes
//! (colour, highlighting, character set) move with them, as `x3270` `ctlr_bcopy` /
//! `ctlr_wrapping_memmove` copy the complete `struct ea`.

use super::{KeyboardError, VirtualKeyboard};
use crate::address::BufferAddress;
use crate::ebcdic::{CodePage, EBC_NULL};
use crate::field::{CharacterSet, Color3270, ExtendedAttributes, Highlight3270};
use crate::keyboard::key::ActionKey;
use crate::keyboard::lock::OperatorError;
use crate::screen::{Cell, PresentationSpace, ReplyMode};
use crate::telnet::HostMode;

/// EBCDIC space.
const EBC_SPACE: u8 = 0x40;
/// EBCDIC underscore (blank for insert room, `x3270` `UNDERSCORE_BLANK_FILL`).
const EBC_UNDERSCORE: u8 = 0x6D;

/// Behaviour switches of the operator keyboard, as the corresponding `x3270` resources
/// (both default to the `x3270` defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyboardOptions {
    /// Only digits, `+`, `-`, `.` and `,` may be typed into a numeric field (`x3270`
    /// `numericLock`, default off: the host validates numeric fields).
    pub numeric_lock: bool,
    /// Typing after empty (null) positions of a field turns them into spaces, so the host
    /// receives the text at the position it was typed (`x3270` `blankFill`, default on).
    pub blank_fill: bool,
}

impl KeyboardOptions {
    /// The `x3270` defaults: no numeric lock, blank fill on.
    pub const DEFAULT: Self = Self {
        numeric_lock: false,
        blank_fill: true,
    };
}

impl Default for KeyboardOptions {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How a paste ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasteEnd {
    /// All text was processed.
    Complete,
    /// The text reached the end of the screen; the rest was not pasted (a paste never wraps
    /// over the fields at the top of the screen).
    ScreenEnd,
    /// A character was refused (protected, numeric or overflow operator error, or a locked
    /// keyboard); the keyboard is locked and the rest was not pasted.
    Rejected(KeyboardError),
}

/// The result of [`VirtualKeyboard::paste`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasteOutcome {
    /// How the paste ended.
    pub end: PasteEnd,
    /// Characters skipped because they are control characters or have no EBCDIC code in the
    /// session code page.
    pub dropped: usize,
}

/// `true` for the characters a numeric field accepts under numeric lock (`x3270`
/// `key_Character`: digits, plus, minus, period, comma).
const fn numeric_allowed(ebc: u8) -> bool {
    matches!(ebc, 0xF0..=0xF9 | 0x4E | 0x60 | 0x4B | 0x6B)
}

/// A cell holding `ebcdic` that keeps the colour and highlighting of `like` but uses the base
/// character set (`x3270` `ctlr_add(baddr, c, 0)`, which leaves fg / bg / gr alone).
fn null_like(like: Option<&Cell>) -> (u8, ExtendedAttributes) {
    let mut xa = like.map_or(ExtendedAttributes::DEFAULT, Cell::extended);
    xa.charset = CharacterSet::Base;
    (EBC_NULL, xa)
}

/// The address of the field attribute that ends the field starting after `fa_addr` (the next
/// attribute, or `fa_addr` itself if the field covers the whole screen).
fn next_field_attribute(ps: &PresentationSpace, fa_addr: BufferAddress) -> BufferAddress {
    let cap = ps.capacity();
    let mut addr = fa_addr.next_wrapped(cap);
    for _ in 0..cap {
        if addr == fa_addr || ps.cell(addr).is_some_and(Cell::is_field_attribute) {
            return addr;
        }
        addr = addr.next_wrapped(cap);
    }
    fa_addr
}

/// Copies the cell at `from` (character and extended attributes) to `to`.
fn copy_cell(
    ps: &mut PresentationSpace,
    from: BufferAddress,
    to: BufferAddress,
) -> Result<(), KeyboardError> {
    let (ebc, xa) = ps
        .cell(from)
        .map_or((EBC_NULL, ExtendedAttributes::DEFAULT), |c| {
            (c.raw_ebcdic(), c.extended())
        });
    ps.write_char(to, ebc, xa)?;
    Ok(())
}

impl VirtualKeyboard {
    /// The governing field of `addr` on a formatted screen: `(attribute address, protected)`.
    fn field_at(ps: &PresentationSpace, addr: BufferAddress) -> Option<(BufferAddress, bool)> {
        if !ps.is_formatted() {
            return None;
        }
        ps.governing_field(addr)
            .map(|(fa_addr, fa, _)| (fa_addr, fa.is_protected()))
    }

    /// Types one EBCDIC character at the cursor (`x3270` `key_Character`).
    ///
    /// * On an attribute or in a protected field: `X Protected`; in an overlay paste the
    ///   character is dropped and the cursor moves on.
    /// * Numeric fields accept only digits and `+ - . ,` when numeric lock is on.
    /// * In insert mode the rest of the field shifts right first; a full field is
    ///   `X Overflow`.
    /// * The cell keeps its background colour; foreground, highlighting and character set
    ///   return to "inherit from the field" (`ctlr_add`, `ctlr_add_fg`, `ctlr_add_gr`).
    /// * Blank fill turns the nulls before the character into spaces; the field's MDT is set.
    /// * Auto-skip: after the last position of a field the cursor moves over the attributes
    ///   that follow, to the next unprotected field for a skip field, otherwise to the next
    ///   position. An overlay paste does not skip.
    pub(super) fn key_character(
        &mut self,
        ps: &mut PresentationSpace,
        ebc: u8,
        overlay: bool,
    ) -> Result<(), KeyboardError> {
        let cap = ps.capacity();
        let cursor = ps.cursor_addr();
        let field = Self::field_at(ps, cursor);

        if ps.is_formatted() {
            let on_attribute = ps.cell(cursor).is_some_and(Cell::is_field_attribute);
            if on_attribute || field.is_some_and(|(_, protected)| protected) {
                if overlay {
                    ps.set_cursor_addr(cursor.next_wrapped(cap))?;
                    return Ok(());
                }
                self.operator_error(OperatorError::Protected);
                return Err(KeyboardError::ProtectedField);
            }
            let numeric = ps.effective_field_attribute(cursor).is_numeric();
            if numeric && self.options.numeric_lock && !numeric_allowed(ebc) {
                self.operator_error(OperatorError::Numeric);
                return Err(KeyboardError::NumericField);
            }
        }

        let field_addr = field.map(|(fa_addr, _)| fa_addr);
        if self.insert_mode && !self.make_room(ps, field_addr, cursor)? {
            self.operator_error(OperatorError::Overflow);
            return Err(KeyboardError::Locked(self.state()));
        }

        let mut xa = ps
            .cell(cursor)
            .map_or(ExtendedAttributes::DEFAULT, Cell::extended);
        xa.foreground = Color3270::Default;
        xa.highlight = Highlight3270::DEFAULT;
        xa.charset = CharacterSet::Base;
        ps.write_char(cursor, ebc, xa)?;

        let mut next = cursor.next_wrapped(cap);
        if next == BufferAddress::ZERO && !ps.is_formatted() && self.host_mode == HostMode::SscpLu {
            // SSCP-LU input scrolls instead of wrapping (`x3270` `key_Character` →
            // `ctlr_scroll`, `ctlr_sscp_up`).
            ps.scroll_up();
            ps.sscp_start_up();
            next = ps.last_row_start();
        }

        if let Some(fa_addr) = field_addr {
            if self.options.blank_fill {
                Self::blank_fill(ps, fa_addr, cursor)?;
            }
            if let Some(fa) = ps.field_attribute_mut(fa_addr) {
                fa.set_modified(true);
            }
            if !overlay {
                next = Self::skip_attributes(ps, next);
            }
        }
        ps.set_cursor_addr(next)?;
        Ok(())
    }

    /// Moves `addr` over field attributes (`x3270` `key_Character` auto-skip): past a skip
    /// (protected numeric) attribute to the next unprotected field, past any other attribute
    /// to the next position.
    fn skip_attributes(ps: &PresentationSpace, mut addr: BufferAddress) -> BufferAddress {
        let cap = ps.capacity();
        for _ in 0..cap {
            match ps.cell(addr).and_then(Cell::field_attribute) {
                Some(fa) if fa.is_skip() => {
                    addr = ps
                        .next_unprotected_data_addr(addr)
                        .unwrap_or(BufferAddress::ZERO);
                }
                Some(_) => addr = addr.next_wrapped(cap),
                None => break,
            }
        }
        addr
    }

    /// Blank fill (`x3270` `key_Character`, `BLANK_FILL`): the nulls between the field
    /// start and `typed` become spaces. The fill stops at a preceding line of the field that
    /// holds only nulls.
    fn blank_fill(
        ps: &mut PresentationSpace,
        fa_addr: BufferAddress,
        typed: BufferAddress,
    ) -> Result<(), KeyboardError> {
        let cap = ps.capacity();
        let cols = ps.cols_nonzero();
        let mut addr = typed.prev_wrapped(cap);
        for _ in 0..cap {
            if addr == fa_addr {
                break;
            }
            if addr.as_usize() % cols == cols.get().saturating_sub(1)
                && Self::line_is_empty(ps, fa_addr, addr)
            {
                break;
            }
            if ps.cell(addr).is_some_and(|c| c.raw_ebcdic() == EBC_NULL) {
                let (_, mut xa) = null_like(ps.cell(addr));
                xa.charset = CharacterSet::Base;
                ps.write_char(addr, EBC_SPACE, xa)?;
            }
            addr = addr.prev_wrapped(cap);
        }
        Ok(())
    }

    /// `true` if the part of the field on the line ending at `line_end` holds only nulls.
    fn line_is_empty(
        ps: &PresentationSpace,
        fa_addr: BufferAddress,
        line_end: BufferAddress,
    ) -> bool {
        let cap = ps.capacity();
        let cols = usize::from(ps.cols()).max(1);
        let mut addr = line_end;
        for _ in 0..cols {
            if addr == fa_addr {
                break;
            }
            if ps.cell(addr).is_some_and(|c| c.raw_ebcdic() != EBC_NULL) {
                return false;
            }
            if addr.as_usize().is_multiple_of(cols) {
                break;
            }
            addr = addr.prev_wrapped(cap);
        }
        true
    }

    /// Insert mode: makes room for one character at `at` by shifting the field right
    /// (`x3270` `ins_prep` with `count = 1`). The first null after `at` absorbs the shift;
    /// without one, a trailing blank (space or underscore, with blank fill) does. Returns
    /// `false` if the field is full.
    ///
    /// Unlike `x3270`, characters with their own character set may shift too: cells move
    /// with their attributes here, so the `x3270` restriction does not apply.
    fn make_room(
        &self,
        ps: &mut PresentationSpace,
        field_addr: Option<BufferAddress>,
        at: BufferAddress,
    ) -> Result<bool, KeyboardError> {
        let cap = ps.capacity();
        // End of the field (exclusive); an unformatted screen ends at its last cell.
        let end = match field_addr {
            Some(fa_addr) => next_field_attribute(ps, fa_addr),
            None => BufferAddress::new(cap.saturating_sub(1), cap)?,
        };

        let mut first_null = None;
        let mut trailing_blanks = 0usize;
        let mut addr = at;
        for _ in 0..cap {
            if addr == end {
                break;
            }
            let ebc = ps.cell(addr).map_or(EBC_NULL, Cell::raw_ebcdic);
            if ebc == EBC_NULL {
                first_null = Some(addr);
                break;
            } else if self.options.blank_fill && (ebc == EBC_SPACE || ebc == EBC_UNDERSCORE) {
                trailing_blanks = trailing_blanks.saturating_add(1);
            } else {
                trailing_blanks = 0;
            }
            addr = addr.next_wrapped(cap);
        }

        // The cell that is given up: the first null, else the last (blank) cell of the field.
        let sink = match first_null {
            Some(null) => null,
            None if trailing_blanks > 0 => end.prev_wrapped(cap),
            None => return Ok(false),
        };
        let mut to = sink;
        for _ in 0..cap {
            if to == at {
                break;
            }
            let from = to.prev_wrapped(cap);
            copy_cell(ps, from, to)?;
            to = from;
        }
        Ok(true)
    }

    /// Delete (`x3270` `do_delete`): removes the character at the cursor; the rest of the
    /// field (on an unformatted screen: of the screen) shifts left and a null fills the end.
    /// The cursor stays.
    pub(super) fn delete_at_cursor(
        &mut self,
        ps: &mut PresentationSpace,
    ) -> Result<(), KeyboardError> {
        let cap = ps.capacity();
        let cursor = ps.cursor_addr();
        let field = Self::field_at(ps, cursor);
        if ps.is_formatted() {
            let on_attribute = ps.cell(cursor).is_some_and(Cell::is_field_attribute);
            if on_attribute || field.is_some_and(|(_, protected)| protected) {
                self.operator_error(OperatorError::Protected);
                return Err(KeyboardError::ProtectedField);
            }
        }

        // Last cell that shifts (inclusive).
        let last = match field {
            Some((fa_addr, _)) => next_field_attribute(ps, fa_addr).prev_wrapped(cap),
            None => BufferAddress::new(cap.saturating_sub(1), cap)?,
        };
        let mut addr = cursor;
        for _ in 0..cap {
            if addr == last {
                break;
            }
            let next = addr.next_wrapped(cap);
            copy_cell(ps, next, addr)?;
            addr = next;
        }
        let (null, xa) = null_like(ps.cell(last));
        ps.write_char(last, null, xa)?;

        if let Some((fa_addr, _)) = field {
            if let Some(fa) = ps.field_attribute_mut(fa_addr) {
                fa.set_modified(true);
            }
        }
        Ok(())
    }

    /// Erase, the 3270 backspace (`x3270` `do_erase`): at the first position of a field
    /// nothing happens; otherwise the cursor moves left and that character is deleted.
    /// On an attribute it is `X Protected`; inside a protected field the delete reports it.
    pub(super) fn erase_before_cursor(
        &mut self,
        ps: &mut PresentationSpace,
    ) -> Result<(), KeyboardError> {
        let cap = ps.capacity();
        let cursor = ps.cursor_addr();
        if let Some((fa_addr, _)) = Self::field_at(ps, cursor) {
            if fa_addr == cursor {
                self.operator_error(OperatorError::Protected);
                return Err(KeyboardError::ProtectedField);
            }
            if cursor != BufferAddress::ZERO && fa_addr == cursor.prev_wrapped(cap) {
                return Ok(());
            }
        }
        ps.set_cursor_addr(cursor.prev_wrapped(cap))?;
        self.delete_at_cursor(ps)
    }

    /// `FieldEnd` (`x3270` `FieldEnd_action`): the cursor goes after the last character of
    /// the field that is neither null nor space (onto it if the field is full), or to the
    /// first position of an empty field. Nothing happens on an unformatted screen, on an
    /// attribute or in a protected field.
    pub(super) fn field_end(ps: &mut PresentationSpace) -> Result<(), KeyboardError> {
        let cap = ps.capacity();
        let cursor = ps.cursor_addr();
        let Some((fa_addr, protected)) = Self::field_at(ps, cursor) else {
            return Ok(());
        };
        if protected || fa_addr == cursor {
            return Ok(());
        }
        let end = next_field_attribute(ps, fa_addr);
        let first = fa_addr.next_wrapped(cap);
        let mut last_nonblank = None;
        let mut addr = first;
        for _ in 0..cap {
            if addr == end {
                break;
            }
            let ebc = ps.cell(addr).map_or(EBC_NULL, Cell::raw_ebcdic);
            if ebc != EBC_NULL && ebc != EBC_SPACE {
                last_nonblank = Some(addr);
            }
            addr = addr.next_wrapped(cap);
        }
        let target = match last_nonblank {
            None => first,
            Some(last) => {
                let after = last.next_wrapped(cap);
                if after == end {
                    last
                } else {
                    after
                }
            }
        };
        ps.set_cursor_addr(target)?;
        Ok(())
    }

    /// `EraseEOF` (`x3270` `EraseEOF_action`): nulls from the cursor to the end of the field
    /// (unformatted: of the screen). Colour and highlighting stay; the character set is reset
    /// only when the host can see it (character reply mode reporting character sets).
    pub(super) fn erase_eof(&mut self, ps: &mut PresentationSpace) -> Result<(), KeyboardError> {
        let cap = ps.capacity();
        let cursor = ps.cursor_addr();
        let field = Self::field_at(ps, cursor);
        if ps.is_formatted() {
            let on_attribute = ps.cell(cursor).is_some_and(Cell::is_field_attribute);
            if on_attribute || field.is_some_and(|(_, protected)| protected) {
                self.operator_error(OperatorError::Protected);
                return Err(KeyboardError::ProtectedField);
            }
        }
        let mutable_cs = matches!(ps.reply_mode(), ReplyMode::Character(attrs) if attrs.charset());
        let end = field.map(|(fa_addr, _)| next_field_attribute(ps, fa_addr));
        let mut addr = cursor;
        for _ in 0..cap {
            if Some(addr) == end {
                break;
            }
            let mut xa = ps
                .cell(addr)
                .map_or(ExtendedAttributes::DEFAULT, Cell::extended);
            if mutable_cs {
                xa.charset = CharacterSet::Base;
            }
            ps.write_char(addr, EBC_NULL, xa)?;
            if end.is_none() && addr.as_usize().saturating_add(1) >= cap {
                break;
            }
            addr = addr.next_wrapped(cap);
        }
        if let Some((fa_addr, _)) = field {
            if let Some(fa) = ps.field_attribute_mut(fa_addr) {
                fa.set_modified(true);
            }
        }
        Ok(())
    }

    /// Erase Field (`x3270` `DeleteField_action`): nulls the field from its first position to
    /// the next attribute, sets its MDT and moves the cursor to the first position. On an
    /// attribute or in a protected field `X Protected`; nothing on an unformatted screen. The
    /// cells keep colour and highlighting; the character set returns to the base set
    /// (`ctlr_add(baddr, EBC_null, 0)`).
    pub(super) fn erase_field(&mut self, ps: &mut PresentationSpace) -> Result<(), KeyboardError> {
        if !ps.is_formatted() {
            return Ok(());
        }
        let cap = ps.capacity();
        let cursor = ps.cursor_addr();
        let on_attribute = ps.cell(cursor).is_some_and(Cell::is_field_attribute);
        let Some((fa_addr, protected)) = Self::field_at(ps, cursor) else {
            return Ok(());
        };
        if on_attribute || protected {
            self.operator_error(OperatorError::Protected);
            return Err(KeyboardError::ProtectedField);
        }
        let start = fa_addr.next_wrapped(cap);
        let end = next_field_attribute(ps, fa_addr);
        let mut addr = start;
        for _ in 0..cap {
            if addr == end {
                break;
            }
            let mut xa = ps
                .cell(addr)
                .map_or(ExtendedAttributes::DEFAULT, Cell::extended);
            xa.charset = CharacterSet::Base;
            ps.write_char(addr, EBC_NULL, xa)?;
            addr = addr.next_wrapped(cap);
        }
        if let Some(fa) = ps.field_attribute_mut(fa_addr) {
            fa.set_modified(true);
        }
        ps.set_cursor_addr(start)?;
        Ok(())
    }

    /// Pastes text as the operator would type it, with the `x3270` paste rules
    /// (`emulate_uinput` with `pasting`, overlay and margined paste, the `x3270` defaults):
    ///
    /// * Characters go in like typed ones, but protected positions are skipped without an
    ///   error and the cursor does not auto-skip.
    /// * Every line starts at the column where the paste started (the left margin).
    /// * `\n` moves to the next line, unless the text has just wrapped to it; a final `\n`
    ///   is ignored. `\t` is Tab, `\b` is cursor left, `\f` is a space, `\r` is ignored.
    /// * The paste stops at the end of the screen instead of wrapping to the top.
    /// * Other control characters, and characters the code page cannot encode, are skipped.
    /// * An operator error (numeric lock, insert overflow) locks the keyboard and ends the
    ///   paste.
    ///
    /// # Errors
    /// [`KeyboardError::Locked`] if the keyboard is locked before the paste starts (nothing is
    /// pasted, as in `x3270`).
    pub fn paste(
        &mut self,
        ps: &mut PresentationSpace,
        text: &str,
        codepage: &dyn CodePage,
    ) -> Result<PasteOutcome, KeyboardError> {
        if self.host_mode == HostMode::Nvt {
            self.not_available();
        }
        self.check_unlocked()?;

        let cols = ps.cols_nonzero();
        let rows = usize::from(ps.rows());
        let row_of = |addr: BufferAddress| addr.as_usize() / cols;
        let orig = ps.cursor_addr();
        let margin = orig.as_usize() % cols;
        let mut last_addr = orig;
        let mut last_row = row_of(orig);
        let mut just_wrapped = false;
        let mut dropped = 0usize;

        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            if self.lock.is_locked() {
                return Ok(PasteOutcome {
                    end: PasteEnd::Rejected(KeyboardError::Locked(self.state())),
                    dropped,
                });
            }
            let mut cursor = ps.cursor_addr();
            if cursor.as_usize() < orig.as_usize() {
                return Ok(PasteOutcome {
                    end: PasteEnd::ScreenEnd,
                    dropped,
                });
            }
            if cursor.as_usize() % cols < margin {
                // `remargin` (overlay paste): down to the margin column of this line.
                // `margin < cols`, so this is a cell of the cursor's row; saturation could only
                // yield an address `new` rejects.
                let remargined = row_of(cursor)
                    .saturating_mul(cols.get())
                    .saturating_add(margin);
                cursor = BufferAddress::new(remargined, ps.capacity())?;
                ps.set_cursor_addr(cursor)?;
            }
            if last_addr != cursor {
                last_addr = cursor;
                just_wrapped = last_row != row_of(cursor);
                last_row = row_of(cursor);
            }

            let result = match c {
                '\u{8}' => self.action(ps, ActionKey::Left),
                '\u{c}' => self.key_character(ps, EBC_SPACE, true),
                '\n' => {
                    if chars.peek().is_none() {
                        break;
                    }
                    if !just_wrapped {
                        let row = row_of(cursor);
                        if row.saturating_add(1) >= rows {
                            return Ok(PasteOutcome {
                                end: PasteEnd::ScreenEnd,
                                dropped,
                            });
                        }
                        let next_row_start = row.saturating_add(1).saturating_mul(cols.get());
                        ps.set_cursor_addr(BufferAddress::new(next_row_start, ps.capacity())?)?;
                    }
                    last_row = row_of(ps.cursor_addr());
                    just_wrapped = false;
                    Ok(())
                }
                '\r' => Ok(()),
                '\t' => self.action(ps, ActionKey::Tab),
                c if c.is_control() => {
                    dropped = dropped.saturating_add(1);
                    Ok(())
                }
                c => {
                    if let Some(ebc) = codepage.char_to_ebcdic(c) {
                        self.key_character(ps, ebc, true)
                    } else {
                        // `x3270` `key_UCharacter`: "dropped (no EBCDIC translation)".
                        dropped = dropped.saturating_add(1);
                        Ok(())
                    }
                }
            };
            if let Err(err) = result {
                return Ok(PasteOutcome {
                    end: PasteEnd::Rejected(err),
                    dropped,
                });
            }
        }
        Ok(PasteOutcome {
            end: PasteEnd::Complete,
            dropped,
        })
    }
}
