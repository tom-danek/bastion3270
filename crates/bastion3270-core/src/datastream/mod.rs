//! IBM 3270 Data Stream parser, commands, orders, and response formatting.

use crate::address::AddressError;
use crate::screen::ScreenError;
use core::fmt;

pub mod command;
pub mod order;
pub mod parser;
pub mod reader;
pub mod response;
pub mod sscp;
pub mod wcc;

pub use command::Command;
pub use parser::DataStreamParser;
pub use reader::ByteReader;
pub use response::{
    build_read_buffer, build_read_buffer_with_aid, build_read_modified, build_test_request,
};
pub use wcc::WriteControlCharacter;

/// AID sent in front of a Read Buffer / Read Modified reply that was requested through a
/// Write Structured Field *Read Partition* (`0x61`, `AID_QREPLY` in `x3270`).
pub const AID_READ_PARTITION: u8 = 0x61;

/// An inbound reply requested by a *Read Partition* structured field inside a WSF.
///
/// A single WSF may carry several structured fields; every Read Partition found is returned in
/// order so the session layer can answer each one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadPartitionRequest {
    /// Query / Query List for partition `0xFF`, already validated, ready for
    /// `QueryReplyBuilder::build_from_request`.
    Query(crate::wsf::QueryRequest),
    /// Read Buffer of partition `0x00`.
    ReadBuffer,
    /// Read Modified (`all = false`) or Read Modified All (`all = true`) of partition `0x00`.
    ReadModified {
        /// `true` for Read Modified All.
        all: bool,
    },
}

/// Result of parsing and executing a 3270 command and data stream buffer.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    /// The 3270 command executed.
    pub command: Command,
    /// Parsed WCC if command was Write, Erase/Write, or Erase/Write Alternate.
    pub wcc: Option<WriteControlCharacter>,
    /// `true` if WCC requested audio alarm.
    pub sound_alarm: bool,
    /// `true` if the host restores the keyboard: WCC keyboard restore, or Erase All Unprotected.
    pub restore_keyboard: bool,
    /// `true` if MDT bits across the screen were reset.
    pub reset_mdt: bool,
    /// `true` if command requires outbound transmission back to host (RB, RM, RMA, WSF Query).
    pub requires_inbound_reply: bool,
    /// `true` if the host wrote the screen: a W / EW / EWA with its WCC, or an Erase All
    /// Unprotected — directly or inside a WSF *Outbound 3270DS*. The keyboard follows the
    /// host-write rules then (`x3270` `ctlr_write`), with [`Self::restore_keyboard`] telling
    /// whether the keyboard is restored.
    pub screen_written: bool,
    /// Read Partition requests found in a Write Structured Field, in stream order.
    pub read_partition: Vec<ReadPartitionRequest>,
    /// `Some` if the command was rejected or aborted part-way.
    ///
    /// Everything before the failing point has been applied, as in `x3270`: a write that hits a
    /// bad address still honours a preceding `IC` and its WCC (keyboard restore, alarm), and the
    /// structured fields before a malformed one still produce their replies. The session layer
    /// reports the rejection to the host and carries on.
    pub rejected: Option<DatastreamError>,
}

impl CommandResult {
    /// Creates an empty result default.
    pub const fn empty() -> Self {
        Self {
            command: Command::NoOp,
            wcc: None,
            sound_alarm: false,
            restore_keyboard: false,
            reset_mdt: false,
            requires_inbound_reply: false,
            screen_written: false,
            read_partition: Vec::new(),
            rejected: None,
        }
    }
}

/// Errors produced during 3270 datastream parsing and execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatastreamError {
    /// Datastream slice was empty.
    EmptyStream,
    /// Unknown 3270 command opcode.
    UnknownCommand(u8),
    /// Stream ended prematurely while expecting an order parameter.
    UnexpectedEof {
        expected: &'static str,
        needed: usize,
        remaining: usize,
    },
    /// An address in SBA, RA, or EUA was invalid or out of bounds for the screen.
    InvalidAddress(AddressError),
    /// Invalid length in Write Structured Field.
    InvalidStructuredFieldLength { length: usize, remaining: usize },
    /// A structured field with invalid contents (e.g. Set Reply Mode for an unknown mode).
    InvalidStructuredField(&'static str),
    /// Screen buffer mutation error.
    Screen(ScreenError),
}

impl fmt::Display for DatastreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStream => write!(f, "empty 3270 datastream"),
            Self::UnknownCommand(cmd) => write!(f, "unknown 3270 command opcode: 0x{cmd:02X}"),
            Self::UnexpectedEof {
                expected,
                needed,
                remaining,
            } => write!(
                f,
                "unexpected EOF reading {expected}: needed {needed} bytes, remaining {remaining}"
            ),
            Self::InvalidAddress(err) => write!(f, "invalid buffer address: {err}"),
            Self::InvalidStructuredFieldLength { length, remaining } => write!(
                f,
                "invalid structured field length {length} (remaining: {remaining})"
            ),
            Self::InvalidStructuredField(msg) => write!(f, "invalid structured field: {msg}"),
            Self::Screen(err) => write!(f, "screen error: {err}"),
        }
    }
}

/// How the host must be told that a command was rejected, following the two `enum pds` error
/// codes of `x3270` (`ctlr.c` `process_ds`, `sf.c` `write_structured_field`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectKind {
    /// The command itself is invalid (unknown command, malformed structured field).
    /// `x3270` `PDS_BAD_CMD`; TN3270E negative response `COMMAND-REJECT`.
    CommandReject,
    /// A write was aborted part-way (bad buffer address, truncated order).
    /// `x3270` `PDS_BAD_ADDR`; TN3270E negative response `OPERATION-CHECK`.
    OperationCheck,
}

impl DatastreamError {
    /// Classifies the error the way `x3270` reports it to the host.
    pub const fn reject_kind(&self) -> RejectKind {
        match self {
            Self::EmptyStream
            | Self::UnknownCommand(_)
            | Self::InvalidStructuredFieldLength { .. }
            | Self::InvalidStructuredField(_) => RejectKind::CommandReject,
            Self::UnexpectedEof { .. } | Self::InvalidAddress(_) | Self::Screen(_) => {
                RejectKind::OperationCheck
            }
        }
    }
}

impl From<AddressError> for DatastreamError {
    fn from(err: AddressError) -> Self {
        Self::InvalidAddress(err)
    }
}

impl From<ScreenError> for DatastreamError {
    fn from(err: ScreenError) -> Self {
        Self::Screen(err)
    }
}
