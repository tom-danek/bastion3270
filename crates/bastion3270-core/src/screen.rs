//! 3270 Presentation Space (screen buffer, field lookup, cursor navigation, and Zero-Trust cell projection).
//!
//! Reference: `x3270` (`Common/ctlr.c`, `include/ctlr.h`, `include/globals.h`).

use core::fmt;
use core::num::NonZeroUsize;

use crate::address::{AddressError, BufferAddress};
use crate::ebcdic::{CodePage, EBC_NULL};
use crate::field::{CharacterSet, Color3270, ExtendedAttributes, FieldAttribute, Highlight3270};
use crate::model::{BindSizes, ScreenSize, TerminalModel};

/// Errors returned by [`PresentationSpace`] operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenError {
    /// The buffer address is out of bounds for the active screen dimensions.
    InvalidAddress(AddressError),
}

impl fmt::Display for ScreenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress(err) => write!(f, "{err}"),
        }
    }
}

/// A BIND requested a screen size this terminal cannot show: smaller than 24x80 or larger than
/// the model (`x3270` `process_bind`, "Ignoring invalid BIND image screen size parameters").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindSizeError {
    /// The rejected size.
    pub requested: ScreenSize,
    /// The largest size the model supports.
    pub max: ScreenSize,
}

impl fmt::Display for BindSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BIND screen size {} outside {}..={}",
            self.requested,
            ScreenSize::DEFAULT,
            self.max
        )
    }
}

impl From<AddressError> for ScreenError {
    fn from(err: AddressError) -> Self {
        Self::InvalidAddress(err)
    }
}

/// A single cell in the internal 3270 [`PresentationSpace`] (`struct ea` in `x3270`).
///
/// A cell either holds a **Field Attribute** (`field_attribute: Some(fa)`, placed by an `SF` or `SFE` order)
/// or a **data character** (`ebcdic: u8` with optional character-level `SA` [`ExtendedAttributes`]).
///
/// Note: The `ebcdic` field is intentionally kept module-private behind accessor methods so that
/// external rendering/network crates are encouraged to use [`PresentationSpace::safe_cell_at`],
/// which enforces `NonDisplay` password masking.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    ebcdic: u8,
    field_attribute: Option<FieldAttribute>,
    extended: ExtendedAttributes,
}

impl Cell {
    /// Blank/null cell (`EBC_NULL`, no field attribute, default extended attributes).
    pub const EMPTY: Self = Self {
        ebcdic: EBC_NULL,
        field_attribute: None,
        extended: ExtendedAttributes::DEFAULT,
    };

    /// Creates a data character cell with the given EBCDIC byte and extended attributes.
    pub const fn new_char(ebcdic: u8, extended: ExtendedAttributes) -> Self {
        Self {
            ebcdic,
            field_attribute: None,
            extended,
        }
    }

    /// Creates a `Start Field` (`SF` / `SFE`) attribute cell.
    ///
    /// On 3270 hardware, a field attribute occupies one buffer cell and is displayed as a blank space.
    pub const fn new_field(attribute: FieldAttribute, extended: ExtendedAttributes) -> Self {
        Self {
            ebcdic: EBC_NULL,
            field_attribute: Some(attribute),
            extended,
        }
    }

    /// Returns `true` if this cell is a Field Attribute marker (`SF` / `SFE`).
    pub const fn is_field_attribute(&self) -> bool {
        self.field_attribute.is_some()
    }

    /// Returns the [`FieldAttribute`] if this cell is a `Start Field` marker.
    pub const fn field_attribute(&self) -> Option<FieldAttribute> {
        self.field_attribute
    }

    /// Returns a mutable reference to the [`FieldAttribute`] if this cell is a `Start Field` marker.
    pub fn field_attribute_mut(&mut self) -> Option<&mut FieldAttribute> {
        self.field_attribute.as_mut()
    }

    /// Returns the raw EBCDIC byte stored in this cell (`0x00` if it is a field attribute or null).
    pub const fn raw_ebcdic(&self) -> u8 {
        self.ebcdic
    }

    /// Returns the extended attributes stored directly on this cell (from `SFE`, `MF`, or `SA`).
    pub const fn extended(&self) -> ExtendedAttributes {
        self.extended
    }

    /// Returns a mutable reference to the cell's extended attributes.
    pub fn extended_mut(&mut self) -> &mut ExtendedAttributes {
        &mut self.extended
    }

    /// Explicitly overwrites the cell with zeros to sanitize sensitive `NonDisplay` data in memory.
    pub fn zeroize(&mut self) {
        *self = Self::EMPTY;
    }
}

pub use crate::safe_view::{SafeCell, SafeScreenView};

/// Reply mode of a partition (3270 Data Stream *Set Reply Mode*, `x3270` `reply_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReplyMode {
    /// Field mode: Read Buffer marks fields with `SF` (`SF_SRM_FIELD`).
    #[default]
    Field,
    /// Extended field mode: fields as `SFE` with their extended attributes
    /// (`SF_SRM_XFIELD`).
    ExtendedField,
    /// Character mode: like extended field mode, plus `SA` orders for the listed
    /// character attributes (`SF_SRM_CHAR`).
    Character(CharacterReplyAttrs),
}

/// The character attributes reported by [`ReplyMode::Character`] (`x3270` `crm_attr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CharacterReplyAttrs(u8);

impl CharacterReplyAttrs {
    const FOREGROUND: u8 = 0x01;
    const BACKGROUND: u8 = 0x02;
    const HIGHLIGHT: u8 = 0x04;
    const CHARSET: u8 = 0x08;

    /// Builds the set from the attribute type bytes of a *Set Reply Mode* field
    /// (`XA_FOREGROUND` `0x42`, `XA_BACKGROUND` `0x45`, `XA_HIGHLIGHTING` `0x41`,
    /// `XA_CHARSET` `0x43`); other types are ignored.
    pub fn from_xa_types(types: &[u8]) -> Self {
        Self(types.iter().fold(0, |m, &t| {
            m | match t {
                0x42 => Self::FOREGROUND,
                0x45 => Self::BACKGROUND,
                0x41 => Self::HIGHLIGHT,
                0x43 => Self::CHARSET,
                _ => 0,
            }
        }))
    }

    /// Foreground colour is reported.
    pub const fn foreground(self) -> bool {
        self.0 & Self::FOREGROUND != 0
    }

    /// Background colour is reported.
    pub const fn background(self) -> bool {
        self.0 & Self::BACKGROUND != 0
    }

    /// Highlighting is reported.
    pub const fn highlight(self) -> bool {
        self.0 & Self::HIGHLIGHT != 0
    }

    /// Character set is reported.
    pub const fn charset(self) -> bool {
        self.0 & Self::CHARSET != 0
    }
}

/// The IBM 3270 Presentation Space (virtual screen buffer and controller state).
#[derive(Debug, Clone)]
pub struct PresentationSpace {
    model: TerminalModel,
    /// Size selected by `Erase/Write` (24x80, or the size of the current BIND).
    default_size: ScreenSize,
    /// Size selected by `Erase/Write Alternate` (the model size, or the size of the BIND).
    alternate_size: ScreenSize,
    reply_mode: ReplyMode,
    is_alternate: bool,
    rows: u16,
    cols: u16,
    cells: Vec<Cell>,
    cursor_addr: BufferAddress,
    buffer_addr: BufferAddress,
    /// Number of field attribute cells; the screen is formatted when it is not zero. Kept up to
    /// date by every change that adds or removes an attribute, so no operation has to scan the
    /// buffer to find out (which made writes over many attributes quadratic).
    field_count: usize,
    /// Where the host left the cursor after the last SSCP-LU write; an SSCP-LU Enter reads
    /// from here (`x3270` `sscp_start`).
    sscp_start: BufferAddress,
}

impl Drop for PresentationSpace {
    /// The session ended or the screen was replaced: wipe what was on it (DEVELOPMENT.md
    /// "sensitive buffers are zeroised when ... the session ends").
    fn drop(&mut self) {
        self.wipe();
    }
}

impl PresentationSpace {
    /// Creates a new [`PresentationSpace`] for the given [`TerminalModel`], initially in default
    /// (24x80) screen mode.
    pub fn new(model: TerminalModel) -> Self {
        let (rows, cols) = model.default_dimensions();
        let capacity = ScreenSize::new(rows, cols).capacity();
        Self {
            model,
            default_size: ScreenSize::DEFAULT,
            alternate_size: model.max_size(),
            reply_mode: ReplyMode::Field,
            is_alternate: false,
            rows,
            cols,
            cells: vec![Cell::EMPTY; capacity],
            cursor_addr: BufferAddress::ZERO,
            buffer_addr: BufferAddress::ZERO,
            field_count: 0,
            sscp_start: BufferAddress::ZERO,
        }
    }

    /// Returns the configured [`TerminalModel`].
    pub const fn model(&self) -> TerminalModel {
        self.model
    }

    /// The sizes `Erase/Write` and `Erase/Write Alternate` currently select.
    pub const fn screen_sizes(&self) -> BindSizes {
        BindSizes {
            default: self.default_size,
            alternate: self.alternate_size,
        }
    }

    /// Applies the screen sizes of an SNA BIND and erases the screen to the default size
    /// (`x3270` `process_bind`, `ctlr_erase(false)`).
    ///
    /// `None` (no or unknown screen size in the BIND) keeps the current sizes. A size smaller
    /// than 24x80 or larger than the model is not applied either; the screen is still erased.
    ///
    /// # Errors
    ///
    /// Returns [`BindSizeError`] for a size outside the supported range; the previous sizes
    /// stay in effect.
    pub fn apply_bind(&mut self, sizes: Option<BindSizes>) -> Result<(), BindSizeError> {
        let max = self.model.max_size();
        let check = |requested: ScreenSize| {
            if max.covers(requested) && requested.covers(ScreenSize::DEFAULT) {
                Ok(())
            } else {
                Err(BindSizeError { requested, max })
            }
        };
        let result = sizes.map_or(Ok(()), |s| {
            check(s.default)?;
            check(s.alternate)?;
            self.default_size = s.default;
            self.alternate_size = s.alternate;
            Ok(())
        });
        self.erase_reset(false);
        result
    }

    /// Returns to the model sizes and erases the screen (UNBIND, `x3270` `process_eor`:
    /// `defROWS = MODEL_2_ROWS ... ctlr_erase(false)`).
    pub fn unbind(&mut self) {
        self.default_size = ScreenSize::DEFAULT;
        self.alternate_size = self.model.max_size();
        self.erase_reset(false);
    }

    /// Returns the reply mode of the (implicit) partition, which shapes Read Buffer / Read
    /// Modified replies.
    pub const fn reply_mode(&self) -> ReplyMode {
        self.reply_mode
    }

    /// Sets the reply mode (WSF *Set Reply Mode*; reset to [`ReplyMode::Field`] by an
    /// Erase/Write with WCC reset).
    pub fn set_reply_mode(&mut self, mode: ReplyMode) {
        self.reply_mode = mode;
    }

    /// Returns `true` if the screen is currently in alternate screen size mode (`Erase/Write Alternate`).
    pub const fn is_alternate_mode(&self) -> bool {
        self.is_alternate
    }

    /// Returns the active number of rows (`24` in default mode, or model rows in alternate mode).
    pub const fn rows(&self) -> u16 {
        self.rows
    }

    /// Returns the active number of columns (`80` in default mode, or model cols in alternate mode).
    pub const fn cols(&self) -> u16 {
        self.cols
    }

    /// Returns the active screen capacity (`rows * cols`).
    pub const fn capacity(&self) -> usize {
        ScreenSize::new(self.rows, self.cols).capacity()
    }

    /// Returns the active number of columns as a divisor for row/column arithmetic. A
    /// presentation space always has at least one column; a `0` would be treated as `1`.
    pub const fn cols_nonzero(&self) -> NonZeroUsize {
        match NonZeroUsize::new(self.cols as usize) {
            Some(cols) => cols,
            None => NonZeroUsize::MIN,
        }
    }

    /// Returns the current cursor address (`cursor_addr` in `x3270`).
    pub const fn cursor_addr(&self) -> BufferAddress {
        self.cursor_addr
    }

    /// Sets the cursor address (`IC` order or user keyboard navigation).
    ///
    /// # Errors
    ///
    /// Returns [`ScreenError::InvalidAddress`] if `addr` is out of bounds for the active screen.
    pub fn set_cursor_addr(&mut self, addr: BufferAddress) -> Result<(), ScreenError> {
        let _ = self.validate_addr(addr)?;
        self.cursor_addr = addr;
        Ok(())
    }

    /// Returns the current controller buffer address (`buffer_addr` in `x3270`, used during stream writing).
    pub const fn buffer_addr(&self) -> BufferAddress {
        self.buffer_addr
    }

    /// Sets the controller buffer address (`SBA` order).
    ///
    /// # Errors
    ///
    /// Returns [`ScreenError::InvalidAddress`] if `addr` is out of bounds for the active screen.
    pub fn set_buffer_addr(&mut self, addr: BufferAddress) -> Result<(), ScreenError> {
        let _ = self.validate_addr(addr)?;
        self.buffer_addr = addr;
        Ok(())
    }

    /// Advances `buffer_addr` by 1 cell, wrapping around at the end of the screen (`INC_BA` in `x3270`).
    pub fn advance_buffer_addr(&mut self) {
        self.buffer_addr = self.buffer_addr.next_wrapped(self.capacity());
    }

    /// Overwrites every cell (hidden field contents included) with zeros. Called when the
    /// presentation space is dropped, so typed passwords do not stay in freed memory.
    pub fn wipe(&mut self) {
        for cell in &mut self.cells {
            cell.zeroize();
        }
        self.field_count = 0;
        // Best effort without `unsafe`: keep the optimiser from treating the writes as dead
        // stores before the memory is freed.
        std::hint::black_box(&mut self.cells);
    }

    /// Returns `true` if the screen contains at least one `Start Field` (`SF` / `SFE`) attribute.
    pub const fn is_formatted(&self) -> bool {
        self.field_count > 0
    }

    /// Actively zeroizes and clears the entire screen buffer, switching between the default
    /// size (`alternate = false`, used by `EW`; 24x80 unless a BIND set another) and the
    /// alternate size (`alternate = true`, used by `EWA`; the model size unless a BIND set
    /// another).
    ///
    /// Resets `cursor_addr` and `buffer_addr` to `0` (`ctlr_erase` / `ctlr_clear` in `x3270`).
    pub fn erase_reset(&mut self, alternate: bool) {
        // Security hygiene: overwrite all existing cells with zeros before dropping/resizing
        for cell in &mut self.cells {
            cell.zeroize();
        }

        let size = if alternate {
            self.alternate_size
        } else {
            self.default_size
        };
        let new_cap = size.capacity();

        self.is_alternate = alternate;
        self.rows = size.rows;
        self.cols = size.cols;
        self.cells.clear();
        self.cells.resize(new_cap, Cell::EMPTY);
        self.cursor_addr = BufferAddress::ZERO;
        self.buffer_addr = BufferAddress::ZERO;
        self.field_count = 0;
        self.sscp_start = BufferAddress::ZERO;
    }

    /// Start of the operator input in SSCP-LU mode (`x3270` `sscp_start`).
    pub const fn sscp_start(&self) -> BufferAddress {
        self.sscp_start
    }

    /// Sets the start of the operator input in SSCP-LU mode.
    ///
    /// # Errors
    ///
    /// Returns [`ScreenError::InvalidAddress`] if `addr` is out of bounds for the active screen.
    pub fn set_sscp_start(&mut self, addr: BufferAddress) -> Result<(), ScreenError> {
        let _ = self.validate_addr(addr)?;
        self.sscp_start = addr;
        Ok(())
    }

    /// Moves the SSCP-LU input start up one row after the screen scrolled (`x3270`
    /// `ctlr_sscp_up`).
    pub fn sscp_start_up(&mut self) {
        let cols = usize::from(self.cols);
        let start = self.sscp_start.as_usize();
        if start > cols {
            if let Some(Ok(addr)) = start
                .checked_sub(cols)
                .map(|up| BufferAddress::new(up, self.capacity()))
            {
                self.sscp_start = addr;
            }
        }
    }

    /// Scrolls the screen up one row: the top row is zeroized and dropped, the last row is
    /// blank (`x3270` `ctlr_scroll`). Used by unformatted SSCP-LU output and input.
    pub fn scroll_up(&mut self) {
        let cols = usize::from(self.cols);
        let cap = self.capacity();
        if cols == 0 || cols > cap {
            return;
        }
        if let Some(top) = self.cells.get_mut(..cols) {
            for cell in top {
                if cell.is_field_attribute() {
                    self.field_count = self.field_count.saturating_sub(1);
                }
                cell.zeroize();
            }
        }
        self.cells.rotate_left(cols);
    }

    /// The address of the first column of the last row.
    pub fn last_row_start(&self) -> BufferAddress {
        let cap = self.capacity();
        BufferAddress::new(cap.saturating_sub(usize::from(self.cols)), cap)
            .unwrap_or(BufferAddress::ZERO)
    }

    /// Returns an immutable reference to the [`Cell`] at `addr`.
    pub fn cell(&self, addr: BufferAddress) -> Option<&Cell> {
        self.cells.get(addr.as_usize())
    }

    /// Returns a mutable reference to the [`FieldAttribute`] at `addr`, if that cell is a
    /// `Start Field` marker (to set the MDT or apply a `Modify Field` order).
    ///
    /// There is deliberately no mutable access to a whole [`Cell`]: adding or removing a field
    /// attribute goes through [`Self::place_field`] and [`Self::write_char`], which keep the
    /// formatted state consistent.
    pub fn field_attribute_mut(&mut self, addr: BufferAddress) -> Option<&mut FieldAttribute> {
        self.cells
            .get_mut(addr.as_usize())
            .and_then(Cell::field_attribute_mut)
    }

    /// Returns a mutable reference to the extended attributes of the cell at `addr`.
    pub fn extended_mut(&mut self, addr: BufferAddress) -> Option<&mut ExtendedAttributes> {
        self.cells.get_mut(addr.as_usize()).map(Cell::extended_mut)
    }

    /// Places a `Start Field` (`SF` or `SFE`) attribute at `addr` (`START_FIELD` in `x3270`).
    ///
    /// # Errors
    ///
    /// Returns [`ScreenError::InvalidAddress`] if `addr` is out of bounds.
    pub fn place_field(
        &mut self,
        addr: BufferAddress,
        attribute: FieldAttribute,
        extended: ExtendedAttributes,
    ) -> Result<(), ScreenError> {
        let idx = self.validate_addr(addr)?;
        if let Some(cell) = self.cells.get_mut(idx) {
            if !cell.is_field_attribute() {
                self.field_count = self.field_count.saturating_add(1);
            }
            cell.zeroize();
            *cell = Cell::new_field(attribute, extended);
        }
        Ok(())
    }

    /// Writes an EBCDIC data character at `addr` with the given [`ExtendedAttributes`].
    ///
    /// If `addr` previously held a `Start Field` attribute, overwriting it with a character
    /// removes that field attribute and updates the formatted state (`ctlr_add` in `x3270`).
    ///
    /// # Errors
    ///
    /// Returns [`ScreenError::InvalidAddress`] if `addr` is out of bounds.
    pub fn write_char(
        &mut self,
        addr: BufferAddress,
        ebcdic: u8,
        extended: ExtendedAttributes,
    ) -> Result<(), ScreenError> {
        let idx = self.validate_addr(addr)?;
        if let Some(cell) = self.cells.get_mut(idx) {
            if cell.is_field_attribute() {
                self.field_count = self.field_count.saturating_sub(1);
            }
            *cell = Cell::new_char(ebcdic, extended);
        }
        Ok(())
    }

    /// Finds the [`BufferAddress`] of the `Start Field` attribute that governs `addr`, walking
    /// backwards with wrap-around (`find_field_attribute_ea` in `x3270`).
    ///
    /// - If the cell at `addr` itself is a `Start Field` marker, returns `Some(addr)`.
    /// - If the screen is unformatted (no `Start Field` markers exist), returns `None`.
    pub fn find_field_attribute_addr(&self, addr: BufferAddress) -> Option<BufferAddress> {
        if !self.is_formatted() {
            return None;
        }
        let cap = self.capacity();
        if cap == 0 || addr.as_usize() >= cap {
            return None;
        }

        let mut curr = addr;
        loop {
            if self
                .cells
                .get(curr.as_usize())
                .is_some_and(Cell::is_field_attribute)
            {
                return Some(curr);
            }
            curr = curr.prev_wrapped(cap);
            if curr == addr {
                break;
            }
        }
        None
    }

    /// Returns the governing `(field_attr_addr, FieldAttribute, field_extended_attrs)` for `addr`.
    ///
    /// Returns `None` if the screen is unformatted.
    pub fn governing_field(
        &self,
        addr: BufferAddress,
    ) -> Option<(BufferAddress, FieldAttribute, ExtendedAttributes)> {
        let fa_addr = self.find_field_attribute_addr(addr)?;
        let fa_cell = self.cells.get(fa_addr.as_usize())?;
        let fa = fa_cell.field_attribute()?;
        Some((fa_addr, fa, fa_cell.extended()))
    }

    /// Returns `true` if `addr` is a data position of an unprotected non-display field (a
    /// password field): typed text there never becomes visible.
    pub fn is_hidden_input(&self, addr: BufferAddress) -> bool {
        self.governing_field(addr).is_some_and(|(fa_addr, fa, _)| {
            fa_addr != addr && !fa.is_protected() && fa.is_non_display()
        })
    }

    /// Returns the effective [`FieldAttribute`] at `addr` (`get_field_attribute` in `x3270`).
    ///
    /// On an unformatted screen, returns [`FieldAttribute::UNPROTECTED_NORMAL`].
    pub fn effective_field_attribute(&self, addr: BufferAddress) -> FieldAttribute {
        self.governing_field(addr)
            .map_or(FieldAttribute::UNPROTECTED_NORMAL, |(_, fa, _)| fa)
    }

    /// Finds the first data cell address of the next unprotected, non-zero-width field after `from_addr`
    /// (`next_unprotected` in `x3270`).
    ///
    /// Returns `None` if the screen is unformatted or contains no non-empty unprotected fields.
    pub fn next_unprotected_data_addr(&self, from_addr: BufferAddress) -> Option<BufferAddress> {
        if !self.is_formatted() {
            return None;
        }
        let cap = self.capacity();
        if cap == 0 {
            return None;
        }

        let mut nbaddr = from_addr;
        loop {
            let baddr = nbaddr;
            nbaddr = nbaddr.next_wrapped(cap);

            if let (Some(curr_cell), Some(next_cell)) = (
                self.cells.get(baddr.as_usize()),
                self.cells.get(nbaddr.as_usize()),
            ) {
                if let Some(fa) = curr_cell.field_attribute() {
                    if !fa.is_protected() && !next_cell.is_field_attribute() {
                        return Some(nbaddr);
                    }
                }
            }

            if nbaddr == from_addr {
                break;
            }
        }
        None
    }

    /// Finds the first data cell address of the previous unprotected, non-zero-width field before
    /// `from_addr` (used by `BackTab`).
    pub fn prev_unprotected_data_addr(&self, from_addr: BufferAddress) -> Option<BufferAddress> {
        if !self.is_formatted() {
            return None;
        }
        let cap = self.capacity();
        if cap == 0 {
            return None;
        }

        // If `from_addr` is inside an unprotected field (beyond its first data cell),
        // jumping backwards first checks whether we should go to the start of the previous field.
        // In 3270 hardware, BackTab from the first data position of a field jumps to the first
        // data position of the preceding unprotected field; BackTab from middle of an unprotected
        // field jumps to the first data position of the current unprotected field.
        let mut curr = from_addr.prev_wrapped(cap);
        loop {
            let prev = curr.prev_wrapped(cap);
            if let (Some(prev_cell), Some(curr_cell)) = (
                self.cells.get(prev.as_usize()),
                self.cells.get(curr.as_usize()),
            ) {
                if let Some(fa) = prev_cell.field_attribute() {
                    if !fa.is_protected() && !curr_cell.is_field_attribute() {
                        return Some(curr);
                    }
                }
            }
            if curr == from_addr {
                break;
            }
            curr = prev;
        }
        None
    }

    /// Returns the first unprotected data cell on the screen (starting search from buffer address `0`,
    /// used by `Home` and after `Erase/Write`).
    pub fn first_unprotected_data_addr(&self) -> Option<BufferAddress> {
        if !self.is_formatted() {
            return Some(BufferAddress::ZERO);
        }
        let cap = self.capacity();
        if cap == 0 {
            return None;
        }
        // Check if address 0 itself is the first data cell of an unprotected field whose SF is at `cap - 1`
        let last = BufferAddress::ZERO.prev_wrapped(cap);
        self.next_unprotected_data_addr(last)
    }

    /// Executes the 3270 `Erase All Unprotected` (`EAU` command / `Erase Input` key) operation:
    /// - Sets all unprotected non-field-attribute cells to `EBC_NULL` (`0x00`, zeroizing memory).
    /// - Resets the `MDT` (`Modified Data Tag`) bit on all unprotected fields to `false`.
    /// - Moves the cursor to the position after the first unprotected field attribute, even
    ///   when that field has no data positions, or to `0` if there is no unprotected field
    ///   (`x3270` `ctlr_erase_all_unprotected()` and `EraseInput_action()`).
    pub fn erase_all_unprotected(&mut self) {
        if !self.is_formatted() {
            for cell in &mut self.cells {
                cell.zeroize();
            }
            self.cursor_addr = BufferAddress::ZERO;
            return;
        }

        let cap = self.capacity();
        let mut current_fa = self.effective_field_attribute(BufferAddress::ZERO);
        let mut first_unprotected_fa: Option<usize> = None;

        for idx in 0..cap {
            if let Some(cell) = self.cells.get_mut(idx) {
                if let Some(fa) = cell.field_attribute_mut() {
                    if !fa.is_protected() {
                        fa.set_modified(false);
                        first_unprotected_fa.get_or_insert(idx);
                    }
                    current_fa = *fa;
                } else if !current_fa.is_protected() {
                    // `x3270` `ctlr_add(baddr, EBC_null, 0)`: the character (and character
                    // set) go, colour and highlighting stay.
                    let mut xa = cell.extended();
                    xa.charset = CharacterSet::Base;
                    *cell = Cell::new_char(EBC_NULL, xa);
                }
            }
        }

        self.cursor_addr = first_unprotected_fa
            .and_then(|idx| BufferAddress::new(idx, cap).ok())
            .map_or(BufferAddress::ZERO, |fa_addr| fa_addr.next_wrapped(cap));
    }

    /// Resets the `MDT` (`Modified Data Tag`) bit on all fields on the screen (`WCC_RESET_MDT`).
    pub fn reset_all_mdt(&mut self) {
        for cell in &mut self.cells {
            if let Some(fa) = cell.field_attribute_mut() {
                fa.set_modified(false);
            }
        }
    }

    /// Projects the cell at `addr` into a Zero-Trust [`SafeCell`] ready for GUI or Web rendering.
    ///
    /// **Security Guarantee:**
    /// - If the cell is a `Start Field` marker, `SafeCell.ch` is `' '`.
    /// - If the governing field has `is_non_display() == true` (e.g., TSO/RACF password field),
    ///   `SafeCell.ch` is unconditionally `' '` (`U+0020`).
    ///
    /// This looks up the governing field, which walks back through the buffer; to project the
    /// whole screen use [`Self::safe_cells`], which does it in one pass.
    pub fn safe_cell_at(&self, addr: BufferAddress, codepage: &dyn CodePage) -> Option<SafeCell> {
        let cell = self.cell(addr)?;
        let governing = self
            .governing_field(addr)
            .map_or(Self::UNFORMATTED, |(_, fa, xa)| (fa, xa));
        Some(Self::project_cell(*cell, governing, codepage))
    }

    /// Projects every cell of the screen, in buffer order, with the same guarantees as
    /// [`Self::safe_cell_at`].
    ///
    /// The governing field is carried forward from cell to cell (starting with the field that
    /// governs address 0, which may wrap around from the end of the buffer), so the cost is
    /// linear in the screen size however few fields the host defines.
    pub fn safe_cells(&self, codepage: &dyn CodePage) -> Vec<SafeCell> {
        let mut governing = self
            .governing_field(BufferAddress::ZERO)
            .map_or(Self::UNFORMATTED, |(_, fa, xa)| (fa, xa));
        let mut out = Vec::with_capacity(self.cells.len());
        for cell in &self.cells {
            if let Some(fa) = cell.field_attribute() {
                governing = (fa, cell.extended());
            }
            out.push(Self::project_cell(*cell, governing, codepage));
        }
        out
    }

    /// The field attributes that govern a cell of an unformatted screen.
    const UNFORMATTED: (FieldAttribute, ExtendedAttributes) = (
        FieldAttribute::UNPROTECTED_NORMAL,
        ExtendedAttributes::DEFAULT,
    );

    /// Projects one cell, given the attribute and extended attributes of its governing field.
    fn project_cell(
        cell: Cell,
        (fa, field_xa): (FieldAttribute, ExtendedAttributes),
        codepage: &dyn CodePage,
    ) -> SafeCell {
        if let Some(own_fa) = cell.field_attribute() {
            return SafeCell {
                ch: ' ',
                foreground: Self::default_3279_color(own_fa),
                background: Color3270::Default,
                highlight: Highlight3270::DEFAULT,
                charset: CharacterSet::Base,
                protected: true,
                is_field_marker: true,
            };
        }

        let cell_xa = cell.extended();

        let foreground = if cell_xa.foreground != Color3270::Default {
            cell_xa.foreground
        } else if field_xa.foreground != Color3270::Default {
            field_xa.foreground
        } else {
            Self::default_3279_color(fa)
        };

        let background = if cell_xa.background == Color3270::Default {
            field_xa.background
        } else {
            cell_xa.background
        };

        let highlight = if cell_xa.highlight.is_default() {
            field_xa.highlight
        } else {
            cell_xa.highlight
        };

        let charset = if cell_xa.charset == CharacterSet::Base {
            field_xa.charset
        } else {
            cell_xa.charset
        };

        // Zero-Trust masking: NonDisplay fields NEVER reveal their characters!
        // APL / Graphic Escape cells (ISPF box drawing) use CP310 instead of the base code page.
        let raw = cell.raw_ebcdic();
        let ch = if fa.is_non_display() {
            ' '
        } else if charset == CharacterSet::Apl {
            crate::ebcdic::apl_to_char(raw).unwrap_or_else(|| codepage.ebcdic_to_display_char(raw))
        } else {
            codepage.ebcdic_to_display_char(raw)
        };

        SafeCell {
            ch,
            foreground,
            background,
            highlight,
            charset,
            protected: fa.is_protected(),
            is_field_marker: false,
        }
    }

    /// Projects this presentation space into an immutable, Zero-Trust [`SafeScreenView`] snapshot.
    pub fn to_safe_view(&self, codepage: &dyn CodePage) -> SafeScreenView {
        SafeScreenView::from_presentation_space(self, codepage)
    }

    /// Standard IBM 3279 four-color mapping derived from base 3270 field attribute bits
    /// when no explicit `XA_FOREGROUND` color is set.
    pub const fn default_3279_color(fa: FieldAttribute) -> Color3270 {
        match (fa.is_protected(), fa.is_intensified()) {
            (false, false) => Color3270::Green,
            (false, true) => Color3270::Red,
            (true, false) => Color3270::Blue,
            (true, true) => Color3270::NeutralWhite,
        }
    }

    fn validate_addr(&self, addr: BufferAddress) -> Result<usize, AddressError> {
        let cap = self.capacity();
        let idx = addr.as_usize();
        if idx >= cap {
            return Err(AddressError::OutOfBounds {
                address: idx,
                capacity: cap,
            });
        }
        Ok(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebcdic::CP037;
    use crate::field::FieldIntensity;

    #[test]
    fn test_hidden_input_is_only_an_unprotected_non_display_field() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();
        let at = |i| BufferAddress::new(i, cap);
        let (Ok(a0), Ok(a1), Ok(a10), Ok(a11), Ok(a20), Ok(a21)) =
            (at(0), at(1), at(10), at(11), at(20), at(21))
        else {
            return;
        };
        let hidden = FieldAttribute::new(false, false, FieldIntensity::NonDisplay, false);
        let shown = FieldAttribute::UNPROTECTED_NORMAL;
        let protected_hidden = FieldAttribute::new(true, false, FieldIntensity::NonDisplay, false);
        assert!(!ps.is_hidden_input(a1), "unformatted screen");
        for (addr, fa) in [(a0, hidden), (a10, shown), (a20, protected_hidden)] {
            assert!(ps
                .place_field(addr, fa, ExtendedAttributes::DEFAULT)
                .is_ok());
        }
        assert!(ps.is_hidden_input(a1));
        assert!(!ps.is_hidden_input(a0), "the attribute position itself");
        assert!(!ps.is_hidden_input(a11), "visible field");
        assert!(!ps.is_hidden_input(a21), "protected field");
    }

    /// What a dropped presentation space leaves behind: `wipe` (run by `Drop`) clears every
    /// cell, so a password typed into a non-display field does not stay in freed memory.
    #[test]
    fn test_wipe_clears_hidden_field_contents() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();
        let (fa, first) = (BufferAddress::new(0, cap), BufferAddress::new(1, cap));
        assert!(fa.is_ok() && first.is_ok());
        if let (Ok(fa), Ok(first)) = (fa, first) {
            let password = FieldAttribute::new(false, false, FieldIntensity::NonDisplay, false);
            assert!(ps
                .place_field(fa, password, ExtendedAttributes::DEFAULT)
                .is_ok());
            assert!(ps
                .write_char(first, 0xE2, ExtendedAttributes::DEFAULT)
                .is_ok()); // 'S'
        }
        assert!(ps.is_formatted());

        ps.wipe();
        assert!(!ps.is_formatted());
        for i in 0..cap {
            let addr = BufferAddress::new(i, cap).ok();
            assert_eq!(
                addr.and_then(|a| ps.cell(a).copied()),
                Some(Cell::EMPTY),
                "cell {i}"
            );
        }
    }

    #[test]
    fn test_field_wrap_around_and_navigation() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();
        assert_eq!(cap, 1920);
        assert!(!ps.is_formatted());

        // Place a Protected label field at address 10
        let addr10 = BufferAddress::new(10, cap);
        // Place an Unprotected input field at address 20
        let addr20 = BufferAddress::new(20, cap);
        // Place a Protected field at address 30 (closing the input field)
        let addr30 = BufferAddress::new(30, cap);
        assert!(addr10.is_ok() && addr20.is_ok() && addr30.is_ok());

        if let (Ok(a10), Ok(a20), Ok(a30)) = (addr10, addr20, addr30) {
            assert!(ps
                .place_field(
                    a10,
                    FieldAttribute::PROTECTED_NORMAL,
                    ExtendedAttributes::DEFAULT
                )
                .is_ok());
            assert!(ps
                .place_field(
                    a20,
                    FieldAttribute::UNPROTECTED_NORMAL,
                    ExtendedAttributes::DEFAULT
                )
                .is_ok());
            assert!(ps
                .place_field(
                    a30,
                    FieldAttribute::PROTECTED_SKIP,
                    ExtendedAttributes::DEFAULT
                )
                .is_ok());

            assert!(ps.is_formatted());

            // Address 5 wraps backwards around the end of the buffer and is governed by the field at address 30!
            let addr5 = BufferAddress::new(5, cap);
            assert!(addr5.is_ok());
            if let Ok(a5) = addr5 {
                assert_eq!(ps.find_field_attribute_addr(a5), Some(a30));
                assert!(ps.effective_field_attribute(a5).is_skip());
            }

            // First unprotected data cell on screen is 21 (right after SF at 20)
            let addr21 = BufferAddress::new(21, cap);
            assert_eq!(ps.first_unprotected_data_addr(), addr21.ok());
            assert_eq!(
                ps.next_unprotected_data_addr(BufferAddress::ZERO),
                addr21.ok()
            );
        }
    }

    #[test]
    fn test_zero_width_unprotected_field_is_skipped() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();

        if let (Ok(a10), Ok(a11), Ok(a20), Ok(a21)) = (
            BufferAddress::new(10, cap),
            BufferAddress::new(11, cap),
            BufferAddress::new(20, cap),
            BufferAddress::new(21, cap),
        ) {
            // Unprotected SF at 10 immediately followed by Protected SF at 11 -> zero-width field!
            let _ = ps.place_field(
                a10,
                FieldAttribute::UNPROTECTED_NORMAL,
                ExtendedAttributes::DEFAULT,
            );
            let _ = ps.place_field(
                a11,
                FieldAttribute::PROTECTED_NORMAL,
                ExtendedAttributes::DEFAULT,
            );
            // Real unprotected field at 20
            let _ = ps.place_field(
                a20,
                FieldAttribute::UNPROTECTED_NORMAL,
                ExtendedAttributes::DEFAULT,
            );

            // Navigation must skip 10/11 and land on 21!
            assert_eq!(ps.first_unprotected_data_addr(), Some(a21));
        }
    }

    #[test]
    fn test_zero_trust_safe_cell_masks_non_display_passwords() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();

        let passwd_fa = FieldAttribute::new(false, false, FieldIntensity::NonDisplay, true);
        if let (Ok(a100), Ok(a101)) = (BufferAddress::new(100, cap), BufferAddress::new(101, cap)) {
            let _ = ps.place_field(a100, passwd_fa, ExtendedAttributes::DEFAULT);
            // Write 'S' (0xE2 in EBCDIC) into the password field at 101
            let _ = ps.write_char(a101, 0xE2, ExtendedAttributes::DEFAULT);

            // Internal cell holds 0xE2 ('S') for Read Modified transmission to mainframe
            assert_eq!(ps.cell(a101).map(Cell::raw_ebcdic), Some(0xE2));

            // SafeCell MUST mask it as ' ' so the browser/GUI never sees 'S'!
            let safe = ps.safe_cell_at(a101, &CP037);
            assert!(safe.is_some());
            if let Some(sc) = safe {
                assert_eq!(sc.ch, ' ');
                assert!(!sc.protected);
                assert!(!sc.is_field_marker);
            }

            // Erase All Unprotected clears the secret byte from memory and resets MDT
            ps.erase_all_unprotected();
            assert_eq!(ps.cell(a101).map(Cell::raw_ebcdic), Some(EBC_NULL));
            assert_eq!(
                ps.cell(a100)
                    .and_then(Cell::field_attribute)
                    .map(FieldAttribute::is_modified),
                Some(false)
            );
        }
    }
}
