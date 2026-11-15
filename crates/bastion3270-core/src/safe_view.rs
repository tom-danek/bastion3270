//! Zero-Trust 3270 Safe Screen View and Sanitized Cell Projection.
//!
//! This module provides [`SafeScreenView`] and [`SafeCell`], which guarantee that
//! sensitive `NonDisplay` field contents (passwords, encryption keys) and internal
//! presentation space metadata are never exposed to untrusted front-ends (HTML5 Canvas,
//! `WebSockets`, GUI clients).

use core::fmt;
use core::num::NonZeroUsize;

use crate::address::BufferAddress;
use crate::ebcdic::CodePage;
use crate::field::{CharacterSet, Color3270, Highlight3270};
use crate::screen::PresentationSpace;

/// Errors returned when validating or constructing a [`SafeScreenView`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeViewError {
    /// The number of cells provided does not match `rows * cols`.
    DimensionMismatch {
        rows: u16,
        cols: u16,
        expected_cells: usize,
        actual_cells: usize,
    },
    /// The cursor position is outside screen boundaries.
    CursorOutOfBounds {
        cursor_row: u16,
        cursor_col: u16,
        rows: u16,
        cols: u16,
    },
}

impl fmt::Display for SafeViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DimensionMismatch {
                rows,
                cols,
                expected_cells,
                actual_cells,
            } => write!(
                f,
                "cell vector length {actual_cells} does not match {rows}x{cols} ({expected_cells} cells)"
            ),
            Self::CursorOutOfBounds {
                cursor_row,
                cursor_col,
                rows,
                cols,
            } => write!(
                f,
                "cursor position ({cursor_row}, {cursor_col}) is outside screen dimensions {rows}x{cols}"
            ),
        }
    }
}

/// Zero-Trust representation of a single screen cell safe for transmission to a browser or GUI.
///
/// **Security Guarantees:**
/// 1. Characters inside `NonDisplay` (hidden/password) fields are unconditionally replaced with `' '` (`U+0020`).
/// 2. Field Attribute marker positions are unconditionally rendered as `' '` (`U+0020`) with `is_field_marker = true` and `protected = true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeCell {
    /// Sanitized Unicode character to draw on screen (`' '` if hidden or field attribute).
    pub ch: char,
    /// Effective foreground color (resolved from character `SA`, field `SFE`, or 3279 base rules).
    pub foreground: Color3270,
    /// Effective background color.
    pub background: Color3270,
    /// Effective highlighting (underscore, reverse video, blink).
    pub highlight: Highlight3270,
    /// Effective character set (`Base`, `Apl` box-drawing, etc.).
    pub charset: CharacterSet,
    /// `true` if this cell is a `Start Field` marker or belongs to a `Protected` field.
    pub protected: bool,
    /// `true` if this cell is the `Start Field` marker byte itself.
    pub is_field_marker: bool,
}

impl SafeCell {
    /// Blank, unprotected cell (`' '`, default colors, base charset, unprotected, not a field marker).
    pub const BLANK: Self = Self {
        ch: ' ',
        foreground: Color3270::Default,
        background: Color3270::Default,
        highlight: Highlight3270::DEFAULT,
        charset: CharacterSet::Base,
        protected: false,
        is_field_marker: false,
    };

    /// Returns `true` if this cell represents a blank space (`' '` or null).
    pub const fn is_blank(&self) -> bool {
        self.ch == ' ' || self.ch == '\0'
    }

    /// Returns `true` if this cell contains a visible display character (not a field marker and not blank).
    pub const fn is_visible(&self) -> bool {
        !self.is_field_marker && !self.is_blank()
    }
}

impl Default for SafeCell {
    fn default() -> Self {
        Self::BLANK
    }
}

impl fmt::Display for SafeCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.ch)
    }
}

/// Zero-Trust immutable snapshot grid of a 3270 screen.
///
/// Front-ends (HTML5 canvas, WebSocket gateways, desktop GUI) consume this structure
/// rather than the mutable, secret-bearing [`PresentationSpace`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeScreenView {
    rows: u16,
    cols: u16,
    cursor_row: u16,
    cursor_col: u16,
    is_formatted: bool,
    cells: Vec<SafeCell>,
}

impl SafeScreenView {
    /// Creates a new [`SafeScreenView`] with explicitly provided dimensions, cursor position,
    /// and cell buffer.
    ///
    /// # Errors
    ///
    /// Returns [`SafeViewError::DimensionMismatch`] if `cells.len() != (rows as usize) * (cols as usize)`.
    /// Returns [`SafeViewError::CursorOutOfBounds`] if `cursor_row >= rows` or `cursor_col >= cols` (when rows > 0 && cols > 0).
    pub fn new(
        rows: u16,
        cols: u16,
        cursor_row: u16,
        cursor_col: u16,
        is_formatted: bool,
        cells: Vec<SafeCell>,
    ) -> Result<Self, SafeViewError> {
        let expected_cells = (rows as usize).saturating_mul(cols as usize);
        if cells.len() != expected_cells {
            return Err(SafeViewError::DimensionMismatch {
                rows,
                cols,
                expected_cells,
                actual_cells: cells.len(),
            });
        }
        if rows > 0 && cols > 0 && (cursor_row >= rows || cursor_col >= cols) {
            return Err(SafeViewError::CursorOutOfBounds {
                cursor_row,
                cursor_col,
                rows,
                cols,
            });
        }
        Ok(Self {
            rows,
            cols,
            cursor_row,
            cursor_col,
            is_formatted,
            cells,
        })
    }

    /// Creates an empty blank [`SafeScreenView`] with the given dimensions and cursor at `(0, 0)`.
    pub fn empty(rows: u16, cols: u16) -> Self {
        let capacity = (rows as usize).saturating_mul(cols as usize);
        Self {
            rows,
            cols,
            cursor_row: 0,
            cursor_col: 0,
            is_formatted: false,
            cells: vec![SafeCell::BLANK; capacity],
        }
    }

    /// Projects an internal [`PresentationSpace`] into a Zero-Trust [`SafeScreenView`] using
    /// the given [`CodePage`].
    ///
    /// **Zero-Trust Invariant:** Characters in `NonDisplay` fields are unconditionally masked to `' '`.
    pub fn from_presentation_space(ps: &PresentationSpace, codepage: &dyn CodePage) -> Self {
        let rows = ps.rows();
        let cols = ps.cols();
        let (cursor_row, cursor_col) = ps.cursor_addr().to_row_col(cols);
        let is_formatted = ps.is_formatted();

        let cells = ps.safe_cells(codepage);

        Self {
            rows,
            cols,
            cursor_row,
            cursor_col,
            is_formatted,
            cells,
        }
    }

    /// Returns the number of rows on screen.
    pub const fn rows(&self) -> u16 {
        self.rows
    }

    /// Returns the number of columns on screen.
    pub const fn cols(&self) -> u16 {
        self.cols
    }

    /// Returns the total screen cell capacity (`rows * cols`).
    pub fn capacity(&self) -> usize {
        self.cells.len()
    }

    /// Returns the active cursor position as 0-based `(row, col)`.
    pub const fn cursor_position(&self) -> (u16, u16) {
        (self.cursor_row, self.cursor_col)
    }

    /// Returns the active cursor row (0-based).
    pub const fn cursor_row(&self) -> u16 {
        self.cursor_row
    }

    /// Returns the active cursor column (0-based).
    pub const fn cursor_col(&self) -> u16 {
        self.cursor_col
    }

    /// Returns `true` if the screen contains at least one field attribute marker.
    pub const fn is_formatted(&self) -> bool {
        self.is_formatted
    }

    /// Returns a slice of all cells on the screen in linear reading order (row 0, row 1, ...).
    pub fn cells(&self) -> &[SafeCell] {
        &self.cells
    }

    /// Returns an immutable reference to the [`SafeCell`] at the specified `(row, col)` coordinate.
    ///
    /// Returns `None` if `row >= rows` or `col >= cols`.
    pub fn cell_at(&self, row: u16, col: u16) -> Option<&SafeCell> {
        if row >= self.rows || col >= self.cols {
            return None;
        }
        let start = (row as usize).checked_mul(self.cols as usize)?;
        let idx = start.checked_add(col as usize)?;
        self.cells.get(idx)
    }

    /// Returns an immutable reference to the [`SafeCell`] at the given [`BufferAddress`].
    pub fn cell_at_addr(&self, addr: BufferAddress) -> Option<&SafeCell> {
        self.cells.get(addr.as_usize())
    }

    /// Returns a slice of [`SafeCell`]s for an entire row.
    ///
    /// Returns `None` if `row >= rows`.
    pub fn row_cells(&self, row: u16) -> Option<&[SafeCell]> {
        if row >= self.rows {
            return None;
        }
        let start = (row as usize).checked_mul(self.cols as usize)?;
        let end = start.checked_add(self.cols as usize)?;
        self.cells.get(start..end)
    }

    /// Extracts the text content of a single row as a `String` of length `cols`.
    ///
    /// Returns `None` if `row >= rows`.
    ///
    /// **Security Guarantee:** Non-display password fields are guaranteed to be spaces.
    pub fn row_text(&self, row: u16) -> Option<String> {
        let slice = self.row_cells(row)?;
        let mut s = String::with_capacity(slice.len());
        for cell in slice {
            s.push(cell.ch);
        }
        Some(s)
    }

    /// Extracts the text content of a single row with trailing blanks trimmed.
    pub fn row_text_trimmed(&self, row: u16) -> Option<String> {
        self.row_text(row).map(|s| s.trim_end().to_string())
    }

    /// Converts the entire screen snapshot into a plain text representation, with lines separated
    /// by newline characters (`\n`).
    ///
    /// **Security Guarantee:** Non-display password fields are unconditionally masked to spaces.
    pub fn to_plain_text(&self) -> String {
        let cap = (self.rows as usize).saturating_mul((self.cols as usize).saturating_add(1));
        let mut out = String::with_capacity(cap);
        for r in 0..self.rows {
            if let Some(row_str) = self.row_text(r) {
                if r > 0 {
                    out.push('\n');
                }
                out.push_str(&row_str);
            }
        }
        out
    }

    /// Converts the entire screen snapshot into a plain text representation with trailing blanks
    /// trimmed from each row.
    pub fn to_plain_text_trimmed(&self) -> String {
        let mut out = String::new();
        for r in 0..self.rows {
            if let Some(row_str) = self.row_text_trimmed(r) {
                if r > 0 {
                    out.push('\n');
                }
                out.push_str(&row_str);
            }
        }
        out
    }

    /// Computes the minimal diff of cells that changed between `previous` and `self`.
    ///
    /// Returns a list of `(row, col, new_cell)` tuples representing updated screen locations.
    ///
    /// - If screen dimensions (`rows` or `cols`) differ, the entire screen has been reconfigured,
    ///   so all cells of `self` are emitted.
    /// - If dimensions match, only cells where `self.cells[i] != previous.cells[i]` are emitted.
    ///
    /// **WebSocket Optimization:** For typical interactive typing or mainframe field updates,
    /// this reduces transmission volume by over 99%.
    pub fn diff(&self, previous: &SafeScreenView) -> Vec<(u16, u16, SafeCell)> {
        // `NonZeroUsize` proves the divisor below is never zero.
        let Some(cols) = NonZeroUsize::new(usize::from(self.cols)) else {
            return Vec::new();
        };

        // Full redraw if screen geometry changed
        if self.rows != previous.rows || self.cols != previous.cols {
            let mut changes = Vec::with_capacity(self.cells.len());
            for (idx, cell) in self.cells.iter().enumerate() {
                let row = u16::try_from(idx / cols).unwrap_or(0);
                let col = u16::try_from(idx % cols).unwrap_or(0);
                changes.push((row, col, *cell));
            }
            return changes;
        }

        // Incremental diff for identical geometry
        let mut changes = Vec::new();
        for (idx, (current, prev)) in self.cells.iter().zip(previous.cells.iter()).enumerate() {
            if current != prev {
                let row = u16::try_from(idx / cols).unwrap_or(0);
                let col = u16::try_from(idx % cols).unwrap_or(0);
                changes.push((row, col, *current));
            }
        }
        changes
    }

    /// Returns `true` if the cursor position changed between `previous` and `self`.
    pub fn cursor_changed(&self, previous: &SafeScreenView) -> bool {
        self.cursor_position() != previous.cursor_position()
    }
}

impl Default for SafeScreenView {
    /// Creates a default IBM Model 2 (24x80) blank screen view with cursor at `(0, 0)`.
    fn default() -> Self {
        Self::empty(24, 80)
    }
}

impl fmt::Display for SafeScreenView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_plain_text())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use crate::ebcdic::CP037;
    use crate::field::{ExtendedAttributes, FieldAttribute, FieldIntensity};
    use crate::model::TerminalModel;

    #[test]
    fn test_safe_cell_properties() {
        let blank = SafeCell::BLANK;
        assert!(blank.is_blank());
        assert!(!blank.is_visible());
        assert!(!blank.protected);
        assert!(!blank.is_field_marker);

        let visible = SafeCell {
            ch: 'A',
            foreground: Color3270::Green,
            background: Color3270::Default,
            highlight: Highlight3270::DEFAULT,
            charset: CharacterSet::Base,
            protected: false,
            is_field_marker: false,
        };
        assert!(!visible.is_blank());
        assert!(visible.is_visible());
    }

    #[test]
    fn test_safe_screen_view_empty_and_accessors() {
        let view = SafeScreenView::empty(24, 80);
        assert_eq!(view.rows(), 24);
        assert_eq!(view.cols(), 80);
        assert_eq!(view.capacity(), 1920);
        assert_eq!(view.cursor_position(), (0, 0));
        assert_eq!(view.cursor_row(), 0);
        assert_eq!(view.cursor_col(), 0);
        assert!(!view.is_formatted());
        assert_eq!(view.cells().len(), 1920);
        assert!(view.cell_at(0, 0).is_some());
        assert!(view.cell_at(23, 79).is_some());
        assert!(view.cell_at(24, 0).is_none());
        assert!(view.cell_at(0, 80).is_none());
    }

    #[test]
    fn test_safe_screen_view_text_extraction() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        // Write "HELLO" at row 0, col 0..4
        let text = ['H', 'E', 'L', 'L', 'O'];
        for (i, &ch) in text.iter().enumerate() {
            let addr = BufferAddress::new(i, ps.capacity()).unwrap();
            let ebcdic = CP037.char_to_ebcdic(ch).unwrap();
            ps.write_char(addr, ebcdic, ExtendedAttributes::DEFAULT)
                .unwrap();
        }
        let view = SafeScreenView::from_presentation_space(&ps, &CP037);
        let row0 = view.row_text(0).unwrap();
        assert_eq!(&row0[0..5], "HELLO");
        assert_eq!(row0.len(), 80);
        let row0_trimmed = view.row_text_trimmed(0).unwrap();
        assert_eq!(row0_trimmed, "HELLO");
        assert!(view.row_text(99).is_none());
    }

    #[test]
    fn test_zero_trust_password_masking_in_safe_view() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();

        // Place a NonDisplay field attribute at cell 10
        let fa_addr = BufferAddress::new(10, cap).unwrap();
        let fa = FieldAttribute::new(false, false, FieldIntensity::NonDisplay, false);
        ps.place_field(fa_addr, fa, ExtendedAttributes::DEFAULT)
            .unwrap();

        // Write password "SECRET" at cells 11..16
        let pw = "SECRET";
        for (i, ch) in pw.chars().enumerate() {
            let addr = BufferAddress::new(11 + i, cap).unwrap();
            let ebcdic = CP037.char_to_ebcdic(ch).unwrap();
            ps.write_char(addr, ebcdic, ExtendedAttributes::DEFAULT)
                .unwrap();
        }

        // Verify PresentationSpace internally has the raw EBCDIC bytes
        for (i, ch) in pw.chars().enumerate() {
            let addr = BufferAddress::new(11 + i, cap).unwrap();
            let expected_ebcdic = CP037.char_to_ebcdic(ch).unwrap();
            assert_eq!(ps.cell(addr).unwrap().raw_ebcdic(), expected_ebcdic);
        }

        // Now project to SafeScreenView
        let view = SafeScreenView::from_presentation_space(&ps, &CP037);

        // Attribute marker must be space with is_field_marker = true
        let marker = view.cell_at(0, 10).unwrap();
        assert_eq!(marker.ch, ' ');
        assert!(marker.is_field_marker);
        assert!(marker.protected);

        // Every cell of the password MUST be masked to ' '
        for i in 0..pw.len() {
            let cell = view.cell_at(0, 11 + i as u16).unwrap();
            assert_eq!(cell.ch, ' ');
            assert!(!cell.is_field_marker);
        }

        // Plain text extract must NOT contain "SECRET"
        let row0 = view.row_text(0).unwrap();
        assert!(!row0.contains("SECRET"));
        let plain = view.to_plain_text();
        assert!(!plain.contains("SECRET"));
    }

    #[test]
    fn test_safe_screen_view_diff() {
        let view1 = SafeScreenView::empty(24, 80);
        let mut view2 = SafeScreenView::empty(24, 80);

        // Empty diff
        assert_eq!(view1.diff(&view1), vec![]);
        assert!(!view1.cursor_changed(&view1));

        // Modify cell at (5, 10)
        let modified_cell = SafeCell {
            ch: 'Z',
            foreground: Color3270::Red,
            background: Color3270::Default,
            highlight: Highlight3270::DEFAULT,
            charset: CharacterSet::Base,
            protected: false,
            is_field_marker: false,
        };
        let idx = 5 * 80 + 10;
        view2.cells[idx] = modified_cell;

        let diff = view2.diff(&view1);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].0, 5);
        assert_eq!(diff[0].1, 10);
        assert_eq!(diff[0].2, modified_cell);

        // Geometry change diff
        let view_alt = SafeScreenView::empty(32, 80);
        let diff_geo = view_alt.diff(&view1);
        assert_eq!(diff_geo.len(), 2560);
    }
}
