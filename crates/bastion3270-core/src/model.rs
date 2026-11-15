//! Terminal model definitions and screen dimension validation for IBM 3278/3279 and `IBM-DYNAMIC`.

use core::fmt;

/// Maximum number of rows or columns allowed by the 3270 architecture (`0xFF` = 255).
pub const MAX_ROWS_OR_COLS: u16 = 255;

/// Maximum total buffer cells (`rows * cols`) addressable by 14-bit 3270 addressing (`0x4000` = 16,384).
pub const MAX_BUFFER_CELLS_14BIT: usize = 16_384;

/// Maximum total buffer cells (`rows * cols`) addressable by 12-bit 3270 addressing (`0x1000` = 4,096).
pub const MAX_BUFFER_CELLS_12BIT: usize = 4_096;

/// Standard default screen rows (Model 2 base mode).
pub const DEFAULT_ROWS: u16 = 24;

/// Standard default screen columns (Model 2 base mode).
pub const DEFAULT_COLS: u16 = 80;

/// Screen dimensions in rows and columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScreenSize {
    /// Number of rows.
    pub rows: u16,
    /// Number of columns.
    pub cols: u16,
}

impl ScreenSize {
    /// The standard default size, 24x80 (Model 2).
    pub const DEFAULT: Self = Self {
        rows: DEFAULT_ROWS,
        cols: DEFAULT_COLS,
    };

    /// Creates a size of `rows` x `cols` (not validated).
    pub const fn new(rows: u16, cols: u16) -> Self {
        Self { rows, cols }
    }

    /// Number of cells (`rows * cols`).
    ///
    /// `u16 * u16` is below `2^32`, so it never overflows a 32- or 64-bit `usize`; on a smaller
    /// `usize` the product saturates, which every capacity check then rejects as too large.
    pub const fn capacity(self) -> usize {
        (self.rows as usize).saturating_mul(self.cols as usize)
    }

    /// `true` if both dimensions are at least those of `other`.
    pub const fn covers(self, other: Self) -> bool {
        self.rows >= other.rows && self.cols >= other.cols
    }
}

impl fmt::Display for ScreenSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}x{}", self.rows, self.cols)
    }
}

/// The default and alternate screen sizes a host requests in an SNA BIND
/// (`x3270` `process_bind`: `bind_rd`, `bind_cd`, `bind_ra`, `bind_ca`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BindSizes {
    /// Size used by `Erase/Write`.
    pub default: ScreenSize,
    /// Size used by `Erase/Write Alternate`.
    pub alternate: ScreenSize,
}

/// Errors returned when constructing or validating a [`TerminalModel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelError {
    /// Rows or columns were zero, or exceeded [`MAX_ROWS_OR_COLS`] (255).
    InvalidDimension { rows: u16, cols: u16 },
    /// Total cells (`rows * cols`) exceeded [`MAX_BUFFER_CELLS_14BIT`] (16,384).
    CapacityExceeded {
        rows: u16,
        cols: u16,
        total_cells: usize,
    },
    /// A dynamic size smaller than the 24x80 base model (`x3270` `oversize_init`: "Less than
    /// minimum").
    BelowMinimum { rows: u16, cols: u16 },
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDimension { rows, cols } => write!(
                f,
                "invalid 3270 screen dimensions {rows}x{cols}: rows and cols must be in 1..={MAX_ROWS_OR_COLS}"
            ),
            Self::CapacityExceeded {
                rows,
                cols,
                total_cells,
            } => write!(
                f,
                "screen dimensions {rows}x{cols} ({total_cells} cells) exceed 14-bit 3270 limit of {MAX_BUFFER_CELLS_14BIT} cells"
            ),
            Self::BelowMinimum { rows, cols } => write!(
                f,
                "screen dimensions {rows}x{cols} are below the minimum of {DEFAULT_ROWS}x{DEFAULT_COLS}"
            ),
        }
    }
}

/// Screen dimensions and device model for IBM 3278/3279 terminals.
///
/// Supports standard fixed models (2, 3, 4, 5) as well as user-defined dynamic dimensions
/// (`IBM-DYNAMIC`, e.g., `62x160` for modern z/OS ISPF).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TerminalModel {
    /// Model 2: 24 rows x 80 columns (1,920 cells).
    #[default]
    Model2,
    /// Model 3: 32 rows x 80 columns (2,560 cells).
    Model3,
    /// Model 4: 43 rows x 80 columns (3,440 cells).
    Model4,
    /// Model 5: 27 rows x 132 columns (3,564 cells).
    Model5,
    /// Dynamic (`IBM-DYNAMIC`): custom alternate rows and columns validated up to 16,384 cells.
    Dynamic { rows: u16, cols: u16 },
}

impl TerminalModel {
    /// Creates a validated [`TerminalModel::Dynamic`] (`IBM-DYNAMIC`) with custom alternate dimensions.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidDimension`] if `rows` or `cols` is `0` or `> 255`, or
    /// [`ModelError::CapacityExceeded`] if `rows * cols > 16_384`.
    pub const fn new_dynamic(rows: u16, cols: u16) -> Result<Self, ModelError> {
        if rows == 0 || cols == 0 || rows > MAX_ROWS_OR_COLS || cols > MAX_ROWS_OR_COLS {
            return Err(ModelError::InvalidDimension { rows, cols });
        }
        let total_cells = ScreenSize::new(rows, cols).capacity();
        if total_cells > MAX_BUFFER_CELLS_14BIT {
            return Err(ModelError::CapacityExceeded {
                rows,
                cols,
                total_cells,
            });
        }
        if rows < DEFAULT_ROWS || cols < DEFAULT_COLS {
            return Err(ModelError::BelowMinimum { rows, cols });
        }
        Ok(Self::Dynamic { rows, cols })
    }

    /// Returns the default (primary) dimensions `(rows, cols)` used by the `Erase/Write` (`EW`) command.
    ///
    /// On all 3270 models, primary screen mode is always 24 rows by 80 columns.
    pub const fn default_dimensions(self) -> (u16, u16) {
        (DEFAULT_ROWS, DEFAULT_COLS)
    }

    /// Returns the alternate dimensions `(rows, cols)` used by the `Erase/Write Alternate` (`EWA`) command.
    pub const fn alternate_dimensions(self) -> (u16, u16) {
        match self {
            Self::Model2 => (24, 80),
            Self::Model3 => (32, 80),
            Self::Model4 => (43, 80),
            Self::Model5 => (27, 132),
            Self::Dynamic { rows, cols } => (rows, cols),
        }
    }

    /// The largest screen this model supports (its alternate size, `maxROWS` x `maxCOLS` in
    /// `x3270`).
    pub const fn max_size(self) -> ScreenSize {
        let (rows, cols) = self.alternate_dimensions();
        ScreenSize { rows, cols }
    }

    /// Returns the alternate dimensions as `(usize, usize)` for buffer sizing.
    pub const fn dimensions(self) -> (usize, usize) {
        let (r, c) = self.alternate_dimensions();
        (r as usize, c as usize)
    }

    /// Returns the total number of cells in alternate screen mode (`rows * cols`).
    pub const fn alternate_capacity(self) -> usize {
        self.max_size().capacity()
    }

    /// Returns `true` if the alternate screen requires 14-bit buffer addressing (`> 4,096` cells).
    pub const fn requires_14bit_addressing(self) -> bool {
        self.alternate_capacity() > MAX_BUFFER_CELLS_12BIT
    }

    /// Returns the Telnet / TN3270E `TERMINAL-TYPE` for this model (`x3270`
    /// `create_3270_termtype`):
    ///
    /// * a dynamic size is `IBM-DYNAMIC` (it requires the extended data stream, see
    ///   [`Self::requires_extended`]);
    /// * a colour terminal reports `3279` only for models 2 and 3, models 4 and 5 always report
    ///   `3278`;
    /// * the extended data stream adds `-E`.
    pub const fn terminal_type_name(self, color_3279: bool, extended: bool) -> &'static str {
        let color = color_3279 && matches!(self, Self::Model2 | Self::Model3);
        match (self, color, extended) {
            (Self::Dynamic { .. }, _, _) => "IBM-DYNAMIC",
            (Self::Model2, true, true) => "IBM-3279-2-E",
            (Self::Model2, true, false) => "IBM-3279-2",
            (Self::Model2, false, true) => "IBM-3278-2-E",
            (Self::Model2, false, false) => "IBM-3278-2",
            (Self::Model3, true, true) => "IBM-3279-3-E",
            (Self::Model3, true, false) => "IBM-3279-3",
            (Self::Model3, false, true) => "IBM-3278-3-E",
            (Self::Model3, false, false) => "IBM-3278-3",
            (Self::Model4, _, true) => "IBM-3278-4-E",
            (Self::Model4, _, false) => "IBM-3278-4",
            (Self::Model5, _, true) => "IBM-3278-5-E",
            (Self::Model5, _, false) => "IBM-3278-5",
        }
    }

    /// `true` for the models that need the extended data stream: a dynamic size exists only
    /// with it (`x3270` `oversize_init` drops the oversize without `extendedDataStream`).
    pub const fn requires_extended(self) -> bool {
        matches!(self, Self::Dynamic { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_models() {
        assert_eq!(TerminalModel::Model2.dimensions(), (24, 80));
        assert_eq!(TerminalModel::Model3.dimensions(), (32, 80));
        assert_eq!(TerminalModel::Model4.dimensions(), (43, 80));
        assert_eq!(TerminalModel::Model5.dimensions(), (27, 132));
        assert!(!TerminalModel::Model5.requires_14bit_addressing());
        // x3270 `create_3270_termtype`: models 4 and 5 report 3278 even in colour.
        assert_eq!(
            TerminalModel::Model4.terminal_type_name(true, true),
            "IBM-3278-4-E"
        );
        assert_eq!(
            TerminalModel::Model3.terminal_type_name(true, true),
            "IBM-3279-3-E"
        );
    }

    #[test]
    fn test_dynamic_model_validation() {
        // Popular modern z/OS ISPF large screen: 62x160 = 9,920 cells (uses 14-bit addressing)
        let res = TerminalModel::new_dynamic(62, 160);
        assert!(res.is_ok());
        if let Ok(model) = res {
            assert_eq!(model.dimensions(), (62, 160));
            assert_eq!(model.alternate_capacity(), 9_920);
            assert!(model.requires_14bit_addressing());
            assert_eq!(model.terminal_type_name(true, true), "IBM-DYNAMIC");
        }

        // Zero dimension is rejected
        assert_eq!(
            TerminalModel::new_dynamic(0, 80),
            Err(ModelError::InvalidDimension { rows: 0, cols: 80 })
        );
        assert_eq!(
            TerminalModel::new_dynamic(24, 256),
            Err(ModelError::InvalidDimension {
                rows: 24,
                cols: 256
            })
        );

        // Exceeding 16,384 cells (e.g. 200x100 = 20,000) is rejected
        assert_eq!(
            TerminalModel::new_dynamic(200, 100),
            Err(ModelError::CapacityExceeded {
                rows: 200,
                cols: 100,
                total_cells: 20_000,
            })
        );
    }
}
