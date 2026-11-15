//! IBM 3270 Data Stream Orders and Format Control Characters.

/// Program Tab (`0x05`).
pub const ORDER_PT: u8 = 0x05;
/// Graphic Escape (`0x08`).
pub const ORDER_GE: u8 = 0x08;
/// Set Buffer Address (`0x11`).
pub const ORDER_SBA: u8 = 0x11;
/// Erase Unprotected to Address (`0x12`).
pub const ORDER_EUA: u8 = 0x12;
/// Insert Cursor (`0x13`).
pub const ORDER_IC: u8 = 0x13;
/// Start Field (`0x1D`).
pub const ORDER_SF: u8 = 0x1D;
/// Set Attribute (`0x28`).
pub const ORDER_SA: u8 = 0x28;
/// Start Field Extended (`0x29`).
pub const ORDER_SFE: u8 = 0x29;
/// Modify Field (`0x2C`).
pub const ORDER_MF: u8 = 0x2C;
/// Repeat to Address (`0x3C`).
pub const ORDER_RA: u8 = 0x3C;

// Format control characters that can appear in 3270 text streams
/// Null character (`0x00`).
pub const FC_NULL: u8 = 0x00;
/// Form Feed (`0x0C`).
pub const FC_FF: u8 = 0x0C;
/// Carriage Return (`0x0D`).
pub const FC_CR: u8 = 0x0D;
/// Newline (`0x15`).
pub const FC_NL: u8 = 0x15;
/// End of Medium (`0x19`).
pub const FC_EM: u8 = 0x19;
/// Duplicate (`0x1C`).
pub const FC_DUP: u8 = 0x1C;
/// Field Mark (`0x1E`).
pub const FC_FM: u8 = 0x1E;
/// Line Feed (`0x25`).
pub const FC_LF: u8 = 0x25;
/// Substitute (`0x3F`).
pub const FC_SUB: u8 = 0x3F;
/// Eight Ones (`0xFF`).
pub const FC_EO: u8 = 0xFF;
/// Shift Out (`0x0E`): starts a DBCS subfield; stored in the buffer like a character.
pub const FC_SO: u8 = 0x0E;
/// Shift In (`0x0F`): ends a DBCS subfield; stored in the buffer like a character.
pub const FC_SI: u8 = 0x0F;

/// Returns `true` if `byte` matches one of the 10 IBM 3270 order opcodes.
pub const fn is_order(byte: u8) -> bool {
    matches!(
        byte,
        ORDER_PT
            | ORDER_GE
            | ORDER_SBA
            | ORDER_EUA
            | ORDER_IC
            | ORDER_SF
            | ORDER_SA
            | ORDER_SFE
            | ORDER_MF
            | ORDER_RA
    )
}

/// Returns `true` if `byte` is an acknowledged 3270 format control character.
pub const fn is_format_control(byte: u8) -> bool {
    matches!(
        byte,
        FC_NULL | FC_FF | FC_CR | FC_NL | FC_EM | FC_DUP | FC_FM | FC_LF | FC_SUB | FC_EO
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_order_all_ten() {
        let orders = [
            ORDER_PT, ORDER_GE, ORDER_SBA, ORDER_EUA, ORDER_IC, ORDER_SF, ORDER_SA, ORDER_SFE,
            ORDER_MF, ORDER_RA,
        ];
        for &ord in &orders {
            assert!(is_order(ord));
        }
        assert!(!is_order(0x00));
        assert!(!is_order(0x40));
        assert!(!is_order(0xF1));
    }

    #[test]
    fn test_is_format_control() {
        assert!(is_format_control(FC_NULL));
        assert!(is_format_control(FC_NL));
        assert!(is_format_control(FC_CR));
        assert!(is_format_control(FC_DUP));
        assert!(is_format_control(FC_FM));
        assert!(!is_format_control(0x40)); // Space is a data character, not FC
    }
}
