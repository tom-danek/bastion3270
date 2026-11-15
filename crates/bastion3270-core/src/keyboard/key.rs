//! 3270 Action and Attention Identification (AID) key definitions.
//!
//! Reference: `x3270` (`include/3270ds.h`, `include/kybd.h`).

use core::fmt;

/// Non-character keyboard actions (cursor navigation, editing, and error reset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionKey {
    /// Advances cursor to the first data cell of the next unprotected field.
    Tab,
    /// Moves cursor to the start of the current field, or to the previous unprotected field.
    BackTab,
    /// Moves cursor to the first unprotected data cell on the screen.
    Home,
    /// Moves cursor to the next line (row + 1, col 0) or the next unprotected field.
    Newline,
    /// Moves cursor one cell to the left with buffer wrapping.
    Left,
    /// Moves cursor one cell to the right with buffer wrapping.
    Right,
    /// Moves cursor one row up with buffer wrapping.
    Up,
    /// Moves cursor one row down with buffer wrapping.
    Down,
    /// Erases all characters from the cursor position to the end of the field, setting MDT.
    EraseEof,
    /// Moves the cursor after the last non-blank character of the field (`x3270`
    /// `FieldEnd`).
    FieldEnd,
    /// Switches insert mode on or off (`x3270` `Toggle(insertMode)`); works while locked.
    ToggleInsert,
    /// Erases all unprotected fields across the screen, clearing MDTs and moving Home.
    EraseInput,
    /// The 3270 Erase key (`x3270` `Erase`): deletes the character left of the cursor and
    /// shifts the rest of the field left; nothing happens at the first position of a field.
    Backspace,
    /// Deletes the character at the cursor and shifts the rest of the field (on an unformatted
    /// screen: the rest of the screen) left (`x3270` `Delete`).
    Delete,
    /// Moves cursor directly to the specified 0-based `(row, col)` coordinates (e.g. via mouse click).
    MoveCursor {
        /// Target 0-based row index.
        row: u16,
        /// Target 0-based column index.
        col: u16,
    },
    /// Unlocks operator error locks (`Protected`, `Numeric`, `Overflow`) without affecting `TimeWait`.
    Reset,
    /// Dup (`x3270` `Dup_action`): types `X'1C'` (shown as `*`; the application fills the
    /// field from the previous record) and moves to the next unprotected field, as Tab does.
    Dup,
    /// Field Mark (`x3270` `FieldMark_action`): types `X'1E'` (shown as `;`) like a character.
    FieldMark,
    /// Erase Field (`x3270` `DeleteField_action`): nulls the whole field the cursor is in, sets
    /// its MDT and moves the cursor to the field's first position.
    EraseField,
}

impl ActionKey {
    /// `true` for the keys that clear an operator-error lock and then proceed (`x3270`
    /// `OERR_CLEAR_OR_ENQ`: Tab, `BackTab`, Home, the arrows, `EraseEOF`, `EraseInput`,
    /// `FieldEnd`, `DeleteField`).
    /// Other keys are refused while an operator error is shown.
    #[must_use]
    pub const fn clears_operator_error(self) -> bool {
        matches!(
            self,
            Self::Tab
                | Self::BackTab
                | Self::Home
                | Self::Left
                | Self::Right
                | Self::Up
                | Self::Down
                | Self::EraseEof
                | Self::EraseInput
                | Self::FieldEnd
                | Self::EraseField
        )
    }
}

/// Keys that interrupt the host instead of sending an AID: they work even while the keyboard
/// is locked waiting for the host (`x3270` `Attn_action`, `SysReq_action`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttentionKey {
    /// Attention: interrupts the running host program (e.g. a TSO command).
    Attn,
    /// System Request: switches between the application and the SSCP (e.g. to log off a hung
    /// session).
    SysReq,
}

/// 3270 Attention Identification (AID) keys that trigger inbound Read Modified transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AidKey {
    /// Enter key (`0x7D`).
    Enter,
    /// Program Function key 1 (`0xF1`).
    PF1,
    /// Program Function key 2 (`0xF2`).
    PF2,
    /// Program Function key 3 (`0xF3`).
    PF3,
    /// Program Function key 4 (`0xF4`).
    PF4,
    /// Program Function key 5 (`0xF5`).
    PF5,
    /// Program Function key 6 (`0xF6`).
    PF6,
    /// Program Function key 7 (`0xF7`).
    PF7,
    /// Program Function key 8 (`0xF8`).
    PF8,
    /// Program Function key 9 (`0xF9`).
    PF9,
    /// Program Function key 10 (`0x7A`).
    PF10,
    /// Program Function key 11 (`0x7B`).
    PF11,
    /// Program Function key 12 (`0x7C`).
    PF12,
    /// Program Function key 13 (`0xC1`).
    PF13,
    /// Program Function key 14 (`0xC2`).
    PF14,
    /// Program Function key 15 (`0xC3`).
    PF15,
    /// Program Function key 16 (`0xC4`).
    PF16,
    /// Program Function key 17 (`0xC5`).
    PF17,
    /// Program Function key 18 (`0xC6`).
    PF18,
    /// Program Function key 19 (`0xC7`).
    PF19,
    /// Program Function key 20 (`0xC8`).
    PF20,
    /// Program Function key 21 (`0xC9`).
    PF21,
    /// Program Function key 22 (`0x4A`).
    PF22,
    /// Program Function key 23 (`0x4B`).
    PF23,
    /// Program Function key 24 (`0x4C`).
    PF24,
    /// Program Attention 1 key (`0x6C`, short-read).
    PA1,
    /// Program Attention 2 key (`0x6E`, short-read).
    PA2,
    /// Program Attention 3 key (`0x6B`, short-read).
    PA3,
    /// Clear screen key (`0x6D`, short-read).
    Clear,
}

impl AidKey {
    /// Encodes this [`AidKey`] into its standard 3270 wire AID byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Enter => 0x7D,
            Self::PF1 => 0xF1,
            Self::PF2 => 0xF2,
            Self::PF3 => 0xF3,
            Self::PF4 => 0xF4,
            Self::PF5 => 0xF5,
            Self::PF6 => 0xF6,
            Self::PF7 => 0xF7,
            Self::PF8 => 0xF8,
            Self::PF9 => 0xF9,
            Self::PF10 => 0x7A,
            Self::PF11 => 0x7B,
            Self::PF12 => 0x7C,
            Self::PF13 => 0xC1,
            Self::PF14 => 0xC2,
            Self::PF15 => 0xC3,
            Self::PF16 => 0xC4,
            Self::PF17 => 0xC5,
            Self::PF18 => 0xC6,
            Self::PF19 => 0xC7,
            Self::PF20 => 0xC8,
            Self::PF21 => 0xC9,
            Self::PF22 => 0x4A,
            Self::PF23 => 0x4B,
            Self::PF24 => 0x4C,
            Self::PA1 => 0x6C,
            Self::PA2 => 0x6E,
            Self::PA3 => 0x6B,
            Self::Clear => 0x6D,
        }
    }

    /// Decodes a 3270 wire AID byte into the corresponding [`AidKey`], or `None` if unknown.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x7D => Some(Self::Enter),
            0xF1 => Some(Self::PF1),
            0xF2 => Some(Self::PF2),
            0xF3 => Some(Self::PF3),
            0xF4 => Some(Self::PF4),
            0xF5 => Some(Self::PF5),
            0xF6 => Some(Self::PF6),
            0xF7 => Some(Self::PF7),
            0xF8 => Some(Self::PF8),
            0xF9 => Some(Self::PF9),
            0x7A => Some(Self::PF10),
            0x7B => Some(Self::PF11),
            0x7C => Some(Self::PF12),
            0xC1 => Some(Self::PF13),
            0xC2 => Some(Self::PF14),
            0xC3 => Some(Self::PF15),
            0xC4 => Some(Self::PF16),
            0xC5 => Some(Self::PF17),
            0xC6 => Some(Self::PF18),
            0xC7 => Some(Self::PF19),
            0xC8 => Some(Self::PF20),
            0xC9 => Some(Self::PF21),
            0x4A => Some(Self::PF22),
            0x4B => Some(Self::PF23),
            0x4C => Some(Self::PF24),
            0x6C => Some(Self::PA1),
            0x6E => Some(Self::PA2),
            0x6B => Some(Self::PA3),
            0x6D => Some(Self::Clear),
            _ => None,
        }
    }

    /// Constructs a Program Function [`AidKey`] from a 1-based index `1..=24`.
    #[must_use]
    pub const fn pf(num: u8) -> Option<Self> {
        match num {
            1 => Some(Self::PF1),
            2 => Some(Self::PF2),
            3 => Some(Self::PF3),
            4 => Some(Self::PF4),
            5 => Some(Self::PF5),
            6 => Some(Self::PF6),
            7 => Some(Self::PF7),
            8 => Some(Self::PF8),
            9 => Some(Self::PF9),
            10 => Some(Self::PF10),
            11 => Some(Self::PF11),
            12 => Some(Self::PF12),
            13 => Some(Self::PF13),
            14 => Some(Self::PF14),
            15 => Some(Self::PF15),
            16 => Some(Self::PF16),
            17 => Some(Self::PF17),
            18 => Some(Self::PF18),
            19 => Some(Self::PF19),
            20 => Some(Self::PF20),
            21 => Some(Self::PF21),
            22 => Some(Self::PF22),
            23 => Some(Self::PF23),
            24 => Some(Self::PF24),
            _ => None,
        }
    }

    /// Constructs a Program Attention [`AidKey`] from a 1-based index `1..=3`.
    #[must_use]
    pub const fn pa(num: u8) -> Option<Self> {
        match num {
            1 => Some(Self::PA1),
            2 => Some(Self::PA2),
            3 => Some(Self::PA3),
            _ => None,
        }
    }

    /// Returns `true` if this key is a short-read AID (PA1, PA2, PA3, or Clear)
    /// which transmits only the 1-byte AID code without cursor address or field data.
    #[must_use]
    pub const fn is_short_read(self) -> bool {
        matches!(self, Self::PA1 | Self::PA2 | Self::PA3 | Self::Clear)
    }
}

impl fmt::Display for AidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enter => write!(f, "Enter"),
            Self::PF1 => write!(f, "PF1"),
            Self::PF2 => write!(f, "PF2"),
            Self::PF3 => write!(f, "PF3"),
            Self::PF4 => write!(f, "PF4"),
            Self::PF5 => write!(f, "PF5"),
            Self::PF6 => write!(f, "PF6"),
            Self::PF7 => write!(f, "PF7"),
            Self::PF8 => write!(f, "PF8"),
            Self::PF9 => write!(f, "PF9"),
            Self::PF10 => write!(f, "PF10"),
            Self::PF11 => write!(f, "PF11"),
            Self::PF12 => write!(f, "PF12"),
            Self::PF13 => write!(f, "PF13"),
            Self::PF14 => write!(f, "PF14"),
            Self::PF15 => write!(f, "PF15"),
            Self::PF16 => write!(f, "PF16"),
            Self::PF17 => write!(f, "PF17"),
            Self::PF18 => write!(f, "PF18"),
            Self::PF19 => write!(f, "PF19"),
            Self::PF20 => write!(f, "PF20"),
            Self::PF21 => write!(f, "PF21"),
            Self::PF22 => write!(f, "PF22"),
            Self::PF23 => write!(f, "PF23"),
            Self::PF24 => write!(f, "PF24"),
            Self::PA1 => write!(f, "PA1"),
            Self::PA2 => write!(f, "PA2"),
            Self::PA3 => write!(f, "PA3"),
            Self::Clear => write!(f, "Clear"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aid_key_mappings() {
        assert_eq!(AidKey::Enter.to_byte(), 0x7D);
        assert_eq!(AidKey::from_byte(0x7D), Some(AidKey::Enter));
        assert_eq!(AidKey::pf(3), Some(AidKey::PF3));
        assert_eq!(AidKey::PF3.to_byte(), 0xF3);
        assert_eq!(AidKey::pa(1), Some(AidKey::PA1));
        assert_eq!(AidKey::PA1.to_byte(), 0x6C);
        assert!(AidKey::PA1.is_short_read());
        assert!(AidKey::Clear.is_short_read());
        assert!(!AidKey::Enter.is_short_read());
    }
}
