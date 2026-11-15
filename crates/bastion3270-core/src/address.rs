//! 12-bit and 14-bit IBM 3270 buffer addressing and coordinate conversion.
//!
//! Reference: IBM 3270 Data Stream Programmer's Reference (GA23-0059) and `x3270` (`Common/ctlr.c`).

use core::fmt;

use crate::model::{ScreenSize, MAX_BUFFER_CELLS_12BIT, MAX_BUFFER_CELLS_14BIT};

/// Standard 64-entry IBM 3270 6-bit-to-EBCDIC address/attribute translation table.
///
/// Matches `code_table[64]` in `x3270` (`Common/ctlr.c`).
pub const CODE_TABLE: [u8; 64] = [
    0x40, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, // 00..07
    0xC8, 0xC9, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, // 08..15
    0x50, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, // 16..23
    0xD8, 0xD9, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, // 24..31
    0x60, 0x61, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, // 32..39
    0xE8, 0xE9, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, // 40..47
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, // 48..55
    0xF8, 0xF9, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, // 56..63
];

/// Translates the lower 6 bits (`0..=63`) of `val` into its printable 3270 EBCDIC representation.
#[allow(clippy::indexing_slicing)]
pub const fn encode_six_bit(val: u8) -> u8 {
    // Bitmask `& 0x3F` mathematically guarantees the index is in `0..=63`, within `[u8; 64]`.
    CODE_TABLE[(val & 0x3F) as usize]
}

/// Errors returned by buffer address operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// Address exceeds the active screen buffer capacity (`rows * cols`).
    OutOfBounds { address: usize, capacity: usize },
    /// Row or column coordinate is outside `(0..rows, 0..cols)`.
    InvalidCoordinates {
        row: u16,
        col: u16,
        rows: u16,
        cols: u16,
    },
    /// Address cannot be represented in 12-bit addressing (`>= 4,096`).
    Exceeds12BitLimit { address: usize },
    /// Address cannot be represented in 14-bit addressing (`>= 16,384`).
    Exceeds14BitLimit { address: usize },
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds { address, capacity } => write!(
                f,
                "3270 buffer address {address} is out of bounds for screen capacity {capacity}"
            ),
            Self::InvalidCoordinates {
                row,
                col,
                rows,
                cols,
            } => write!(
                f,
                "screen coordinates ({row}, {col}) are outside screen dimensions {rows}x{cols}"
            ),
            Self::Exceeds12BitLimit { address } => write!(
                f,
                "buffer address {address} exceeds 12-bit limit ({MAX_BUFFER_CELLS_12BIT})"
            ),
            Self::Exceeds14BitLimit { address } => write!(
                f,
                "buffer address {address} exceeds 14-bit limit ({MAX_BUFFER_CELLS_14BIT})"
            ),
        }
    }
}

/// A linear 0-based position in the 3270 presentation space buffer (`0 .. rows * cols`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BufferAddress(u16);

impl BufferAddress {
    /// Buffer address `0` (top-left corner: row 0, column 0).
    pub const ZERO: Self = Self(0);

    /// Creates a [`BufferAddress`] checked against the given screen `capacity` (`rows * cols`).
    ///
    /// # Errors
    ///
    /// Returns [`AddressError::OutOfBounds`] if `address >= capacity` or `address >= 16,384`.
    #[allow(clippy::cast_possible_truncation)]
    pub const fn new(address: usize, capacity: usize) -> Result<Self, AddressError> {
        if address >= capacity || address >= MAX_BUFFER_CELLS_14BIT {
            return Err(AddressError::OutOfBounds { address, capacity });
        }
        Ok(Self(address as u16))
    }

    /// Creates a [`BufferAddress`] from 0-based `(row, col)` coordinates for a screen of `(rows, cols)`.
    ///
    /// # Errors
    ///
    /// Returns [`AddressError::InvalidCoordinates`] if `row >= rows` or `col >= cols`, or
    /// [`AddressError::OutOfBounds`] if the resulting linear index exceeds the 14-bit limit.
    pub const fn from_row_col(
        row: u16,
        col: u16,
        rows: u16,
        cols: u16,
    ) -> Result<Self, AddressError> {
        if row >= rows || col >= cols {
            return Err(AddressError::InvalidCoordinates {
                row,
                col,
                rows,
                cols,
            });
        }
        let capacity = ScreenSize::new(rows, cols).capacity();
        // `row < rows` and `col < cols`, so `linear < capacity`; saturation can only produce a
        // value that `new` rejects, never a wrapped address.
        let linear = (row as usize)
            .saturating_mul(cols as usize)
            .saturating_add(col as usize);
        Self::new(linear, capacity)
    }

    /// Returns the 0-based linear index as `usize`.
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    /// Returns the 0-based linear index as `u16`.
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Converts this linear buffer address into 0-based `(row, col)` for a screen with `cols` columns.
    ///
    /// If `cols == 0`, returns `(0, 0)`.
    pub const fn to_row_col(self, cols: u16) -> (u16, u16) {
        match (self.0.checked_div(cols), self.0.checked_rem(cols)) {
            (Some(row), Some(col)) => (row, col),
            _ => (0, 0),
        }
    }

    /// Returns the next buffer address, wrapping around to `0` at `capacity` (`INC_BA` in `x3270`).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn next_wrapped(self, capacity: usize) -> Self {
        // A `u16` plus one always fits a `usize`; the address is defined modulo `capacity`,
        // and a zero capacity (no screen) yields address 0.
        let next = (self.0 as usize).saturating_add(1);
        match next.checked_rem(capacity) {
            Some(next) => Self(next as u16),
            None => Self::ZERO,
        }
    }

    /// Returns the previous buffer address, wrapping around to `capacity - 1` from `0` (`DEC_BA` in `x3270`).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn prev_wrapped(self, capacity: usize) -> Self {
        if capacity == 0 {
            return Self::ZERO;
        }
        let prev = match self.0.checked_sub(1) {
            Some(prev) => prev as usize,
            None => capacity.saturating_sub(1),
        };
        Self(prev as u16)
    }

    /// Decodes a 2-byte 3270 buffer address (`c1`, `c2`) using the standard 12-bit / 14-bit rule
    /// (`DECODE_BADDR` in `x3270`) and validates it against `capacity`.
    ///
    /// - If the top two bits of `c1` (`c1 & 0xC0`) are `0x00`, it is a **14-bit address**:
    ///   `((c1 & 0x3F) << 8) | c2`.
    /// - Otherwise, it is a **12-bit coded address**:
    ///   `((c1 & 0x3F) << 6) | (c2 & 0x3F)`.
    ///
    /// # Errors
    ///
    /// Returns [`AddressError::OutOfBounds`] if the decoded address is `>= capacity`.
    pub const fn decode(c1: u8, c2: u8, capacity: usize) -> Result<Self, AddressError> {
        let raw = Self::decode_raw(c1, c2) as usize;
        Self::new(raw, capacity)
    }

    /// Decodes a 2-byte 3270 buffer address (`c1`, `c2`) into its raw `0..16384` value without screen bounds check.
    pub const fn decode_raw(c1: u8, c2: u8) -> u16 {
        if (c1 & 0xC0) == 0x00 {
            (((c1 & 0x3F) as u16) << 8) | (c2 as u16)
        } else {
            (((c1 & 0x3F) as u16) << 6) | ((c2 & 0x3F) as u16)
        }
    }

    /// Encodes this buffer address in **12-bit coded format** (valid for addresses `0..4096`).
    ///
    /// # Errors
    ///
    /// Returns [`AddressError::Exceeds12BitLimit`] if `self.as_usize() >= 4,096`.
    #[allow(clippy::cast_possible_truncation)]
    pub const fn encode_12bit(self) -> Result<[u8; 2], AddressError> {
        let addr = self.as_usize();
        if addr >= MAX_BUFFER_CELLS_12BIT {
            return Err(AddressError::Exceeds12BitLimit { address: addr });
        }
        let b1 = encode_six_bit(((self.0 >> 6) & 0x3F) as u8);
        let b2 = encode_six_bit((self.0 & 0x3F) as u8);
        Ok([b1, b2])
    }

    /// Encodes this buffer address in **14-bit binary format** (valid for addresses `0..16384`).
    ///
    /// # Errors
    ///
    /// Returns [`AddressError::Exceeds14BitLimit`] if `self.as_usize() >= 16,384`.
    #[allow(clippy::cast_possible_truncation)]
    pub const fn encode_14bit(self) -> Result<[u8; 2], AddressError> {
        let addr = self.as_usize();
        if addr >= MAX_BUFFER_CELLS_14BIT {
            return Err(AddressError::Exceeds14BitLimit { address: addr });
        }
        let b1 = ((self.0 >> 8) & 0x3F) as u8;
        let b2 = (self.0 & 0xFF) as u8;
        Ok([b1, b2])
    }

    /// Encodes this buffer address automatically selecting 12-bit or 14-bit format based on
    /// screen `capacity` (`ENCODE_BADDR` in `x3270`).
    ///
    /// Uses 14-bit encoding when `capacity > 4,096`, and 12-bit encoding otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`AddressError`] if the address exceeds the selected encoding limit.
    pub const fn encode_for_capacity(self, capacity: usize) -> Result<[u8; 2], AddressError> {
        if capacity > MAX_BUFFER_CELLS_12BIT {
            self.encode_14bit()
        } else {
            self.encode_12bit()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_12bit_encode_decode_roundtrip() {
        let capacity = 4_096;
        for raw in 0..capacity {
            let addr = BufferAddress::new(raw, capacity);
            assert!(addr.is_ok());
            if let Ok(a) = addr {
                let encoded = a.encode_12bit();
                assert!(encoded.is_ok());
                if let Ok([b1, b2]) = encoded {
                    // Top two bits of b1 in 12-bit mode are never 00 (0x40..0xF9)
                    assert_ne!(b1 & 0xC0, 0x00);
                    let decoded = BufferAddress::decode(b1, b2, capacity);
                    assert_eq!(decoded, Ok(a));
                }
            }
        }
    }

    #[test]
    fn test_14bit_encode_decode_roundtrip() {
        let capacity = 9_920; // 62x160 IBM-DYNAMIC
        for raw in [0, 1, 79, 1919, 4095, 4096, 8192, 9919] {
            let addr = BufferAddress::new(raw, capacity);
            assert!(addr.is_ok());
            if let Ok(a) = addr {
                let encoded = a.encode_for_capacity(capacity);
                assert!(encoded.is_ok());
                if let Ok([b1, b2]) = encoded {
                    // Top two bits of b1 in 14-bit mode are always 00
                    assert_eq!(b1 & 0xC0, 0x00);
                    let decoded = BufferAddress::decode(b1, b2, capacity);
                    assert_eq!(decoded, Ok(a));
                }
            }
        }
    }

    #[test]
    fn test_known_3270_addresses() {
        // Address 0 (Row 0, Col 0) in 12-bit is 0x40, 0x40
        let a0 = BufferAddress::ZERO;
        assert_eq!(a0.encode_12bit(), Ok([0x40, 0x40]));

        // Address 80 (Row 1, Col 0 on 24x80): 80 = (1 << 6) | 16 -> code_table[1]=0xC1, code_table[16]=0x50
        let a80 = BufferAddress::from_row_col(1, 0, 24, 80);
        assert_eq!(a80.map(BufferAddress::as_usize), Ok(80));
        if let Ok(addr) = a80 {
            assert_eq!(addr.encode_12bit(), Ok([0xC1, 0x50]));
            assert_eq!(addr.to_row_col(80), (1, 0));
        }
    }

    #[test]
    fn test_wrap_navigation_and_bounds() {
        let cap = 1920; // 24x80
        let first = BufferAddress::ZERO;
        let last = BufferAddress::new(1919, cap);
        assert!(last.is_ok());
        if let Ok(last_addr) = last {
            assert_eq!(first.prev_wrapped(cap), last_addr);
            assert_eq!(last_addr.next_wrapped(cap), first);
        }

        // Decoding an address >= 1920 on a 24x80 screen returns OutOfBounds, never panics
        assert_eq!(
            BufferAddress::decode(0x5D, 0x7F, cap), // 1919 is (29 << 6) | 63 -> 0x5D, 0x7F; let's test 1920: (30 << 6) | 0 -> 0x5E, 0x40
            Ok(BufferAddress(1919))
        );
        assert_eq!(
            BufferAddress::decode(0x5E, 0x40, cap),
            Err(AddressError::OutOfBounds {
                address: 1920,
                capacity: 1920
            })
        );
    }
}
