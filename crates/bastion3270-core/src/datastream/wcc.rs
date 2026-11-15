//! IBM 3270 Write Control Character (WCC) bitmask decoding and application.

use crate::screen::PresentationSpace;

/// WCC Bit 1 (`0x40`): Reset keyboard lock/error conditions.
pub const WCC_RESET_BIT: u8 = 0x40;
/// WCC Bit 4 (`0x08`): Start local attached printer.
pub const WCC_START_PRINTER_BIT: u8 = 0x08;
/// WCC Bit 5 (`0x04`): Sound terminal audible alarm / bell.
pub const WCC_SOUND_ALARM_BIT: u8 = 0x04;
/// WCC Bit 6 (`0x02`): Restore keyboard and unlock operator input.
pub const WCC_KEYBOARD_RESTORE_BIT: u8 = 0x02;
/// WCC Bit 7 (`0x01`): Reset Modified Data Tags (MDT) across all fields.
pub const WCC_RESET_MDT_BIT: u8 = 0x01;

/// Decoded 3270 Write Control Character (WCC).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WriteControlCharacter {
    /// Raw wire byte received from the host.
    pub raw: u8,
    /// Reset error status and unlock keyboard.
    pub reset: bool,
    /// Trigger local printer output.
    pub start_printer: bool,
    /// Trigger audible alarm on terminal.
    pub sound_alarm: bool,
    /// Restore keyboard and unlock operator input.
    pub restore_keyboard: bool,
    /// Reset MDT bits on all fields across the screen.
    pub reset_mdt: bool,
}

impl WriteControlCharacter {
    /// Decodes a WCC byte into its constituent bit flags.
    pub const fn from_wire(byte: u8) -> Self {
        Self {
            raw: byte,
            reset: (byte & WCC_RESET_BIT) != 0,
            start_printer: (byte & WCC_START_PRINTER_BIT) != 0,
            sound_alarm: (byte & WCC_SOUND_ALARM_BIT) != 0,
            restore_keyboard: (byte & WCC_KEYBOARD_RESTORE_BIT) != 0,
            reset_mdt: (byte & WCC_RESET_MDT_BIT) != 0,
        }
    }

    /// Applies immediate presentation space modifications dictated by the WCC.
    pub fn apply(self, ps: &mut PresentationSpace) {
        if self.reset_mdt {
            ps.reset_all_mdt();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::address::BufferAddress;
    use crate::field::{ExtendedAttributes, FieldAttribute, FieldIntensity};
    use crate::model::TerminalModel;

    #[test]
    fn test_wcc_bit_decoding() {
        // Wire byte with reset_mdt (0x01) and sound_alarm (0x04) and reset (0x40) -> 0x45
        let wcc = WriteControlCharacter::from_wire(0x45);
        assert_eq!(wcc.raw, 0x45);
        assert!(wcc.reset);
        assert!(!wcc.start_printer);
        assert!(wcc.sound_alarm);
        assert!(!wcc.restore_keyboard);
        assert!(wcc.reset_mdt);

        // Restore keyboard (0x02) and start printer (0x08) -> 0x0A
        let wcc2 = WriteControlCharacter::from_wire(0x0A);
        assert!(wcc2.restore_keyboard);
        assert!(wcc2.start_printer);
        assert!(!wcc2.sound_alarm);
        assert!(!wcc2.reset_mdt);
    }

    #[test]
    fn test_wcc_apply_resets_mdt() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();

        // Place a field with MDT set
        let fa = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, true);
        assert!(fa.is_modified());
        let addr = BufferAddress::new(10, cap).unwrap();
        ps.place_field(addr, fa, ExtendedAttributes::DEFAULT)
            .unwrap();
        assert!(ps.effective_field_attribute(addr).is_modified());

        // Apply WCC without reset_mdt
        let wcc_no_reset = WriteControlCharacter::from_wire(0x00);
        wcc_no_reset.apply(&mut ps);
        assert!(ps.effective_field_attribute(addr).is_modified());

        // Apply WCC with reset_mdt
        let wcc_reset = WriteControlCharacter::from_wire(WCC_RESET_MDT_BIT);
        wcc_reset.apply(&mut ps);
        assert!(!ps.effective_field_attribute(addr).is_modified());
    }
}
