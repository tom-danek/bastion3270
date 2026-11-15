//! IBM 3270 Data Stream Commands (standard local and SNA opcodes).

use crate::datastream::DatastreamError;

// Standard local 3270 command opcodes
pub const CMD_W: u8 = 0x01;
pub const CMD_RB: u8 = 0x02;
pub const CMD_NOP: u8 = 0x03;
pub const CMD_EW: u8 = 0x05;
pub const CMD_RM: u8 = 0x06;
pub const CMD_EWA: u8 = 0x0D;
pub const CMD_RMA: u8 = 0x0E;
pub const CMD_EAU: u8 = 0x0F;
pub const CMD_WSF: u8 = 0x11;

// SNA 3270 command opcodes
pub const SNA_CMD_W: u8 = 0xF1;
pub const SNA_CMD_RB: u8 = 0xF2;
pub const SNA_CMD_EW: u8 = 0xF5;
pub const SNA_CMD_RM: u8 = 0xF6;
pub const SNA_CMD_EWA: u8 = 0x7E;
pub const SNA_CMD_RMA: u8 = 0x6E;
pub const SNA_CMD_EAU: u8 = 0x6F;
pub const SNA_CMD_WSF: u8 = 0xF3;

/// Recognized IBM 3270 Data Stream Commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    /// Write without erasing screen (`0x01` / `0xF1`).
    Write,
    /// Erase screen to default dimensions (24x80) and write (`0x05` / `0xF5`).
    EraseWrite,
    /// Erase screen to alternate model dimensions and write (`0x0D` / `0x7E`).
    EraseWriteAlternate,
    /// Erase all unprotected data cells to nulls (`0x0F` / `0x6F`).
    EraseAllUnprotected,
    /// Read entire screen buffer (`0x02` / `0xF2`).
    ReadBuffer,
    /// Read fields modified by user (`0x06` / `0xF6`).
    ReadModified,
    /// Read all modified fields regardless of trigger key (`0x0E` / `0x6E`).
    ReadModifiedAll,
    /// Write Structured Field length-prefixed records (`0x11` / `0xF3`).
    WriteStructuredField,
    /// No operation acknowledged (`0x03`).
    NoOp,
}

impl Command {
    /// Maps a raw opcode byte (either standard or SNA) to a [`Command`].
    ///
    /// # Errors
    ///
    /// Returns [`DatastreamError::UnknownCommand`] if `opcode` is not recognized.
    pub const fn from_opcode(opcode: u8) -> Result<Self, DatastreamError> {
        match opcode {
            CMD_W | SNA_CMD_W => Ok(Self::Write),
            CMD_EW | SNA_CMD_EW => Ok(Self::EraseWrite),
            CMD_EWA | SNA_CMD_EWA => Ok(Self::EraseWriteAlternate),
            CMD_EAU | SNA_CMD_EAU => Ok(Self::EraseAllUnprotected),
            CMD_RB | SNA_CMD_RB => Ok(Self::ReadBuffer),
            CMD_RM | SNA_CMD_RM => Ok(Self::ReadModified),
            CMD_RMA | SNA_CMD_RMA => Ok(Self::ReadModifiedAll),
            CMD_WSF | SNA_CMD_WSF => Ok(Self::WriteStructuredField),
            CMD_NOP => Ok(Self::NoOp),
            _ => Err(DatastreamError::UnknownCommand(opcode)),
        }
    }

    /// Returns `true` if this command contains write payload (WCC + orders).
    pub const fn is_write(self) -> bool {
        matches!(
            self,
            Self::Write | Self::EraseWrite | Self::EraseWriteAlternate
        )
    }

    /// Returns `true` if this command requests an inbound response transmission.
    pub const fn requires_inbound_reply(self) -> bool {
        matches!(
            self,
            Self::ReadBuffer | Self::ReadModified | Self::ReadModifiedAll
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_all_standard_and_sna_opcodes() {
        assert_eq!(Command::from_opcode(0x01).unwrap(), Command::Write);
        assert_eq!(Command::from_opcode(0xF1).unwrap(), Command::Write);
        assert_eq!(Command::from_opcode(0x05).unwrap(), Command::EraseWrite);
        assert_eq!(Command::from_opcode(0xF5).unwrap(), Command::EraseWrite);
        assert_eq!(
            Command::from_opcode(0x0D).unwrap(),
            Command::EraseWriteAlternate
        );
        assert_eq!(
            Command::from_opcode(0x7E).unwrap(),
            Command::EraseWriteAlternate
        );
        assert_eq!(
            Command::from_opcode(0x0F).unwrap(),
            Command::EraseAllUnprotected
        );
        assert_eq!(
            Command::from_opcode(0x6F).unwrap(),
            Command::EraseAllUnprotected
        );
        assert_eq!(Command::from_opcode(0x02).unwrap(), Command::ReadBuffer);
        assert_eq!(Command::from_opcode(0xF2).unwrap(), Command::ReadBuffer);
        assert_eq!(Command::from_opcode(0x06).unwrap(), Command::ReadModified);
        assert_eq!(Command::from_opcode(0xF6).unwrap(), Command::ReadModified);
        assert_eq!(
            Command::from_opcode(0x0E).unwrap(),
            Command::ReadModifiedAll
        );
        assert_eq!(
            Command::from_opcode(0x6E).unwrap(),
            Command::ReadModifiedAll
        );
        assert_eq!(
            Command::from_opcode(0x11).unwrap(),
            Command::WriteStructuredField
        );
        assert_eq!(
            Command::from_opcode(0xF3).unwrap(),
            Command::WriteStructuredField
        );
        assert_eq!(Command::from_opcode(0x03).unwrap(), Command::NoOp);

        assert!(Command::from_opcode(0x99).is_err());
    }

    #[test]
    fn test_command_properties() {
        assert!(Command::Write.is_write());
        assert!(Command::EraseWrite.is_write());
        assert!(Command::EraseWriteAlternate.is_write());
        assert!(!Command::NoOp.is_write());
        assert!(!Command::EraseAllUnprotected.is_write());

        assert!(Command::ReadBuffer.requires_inbound_reply());
        assert!(Command::ReadModified.requires_inbound_reply());
        assert!(Command::ReadModifiedAll.requires_inbound_reply());
        assert!(!Command::Write.requires_inbound_reply());
    }
}
