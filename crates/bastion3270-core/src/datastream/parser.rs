//! IBM 3270 Data Stream execution engine and command processor.

use crate::address::BufferAddress;
use crate::datastream::command::{
    Command, SNA_CMD_EAU, SNA_CMD_EW, SNA_CMD_EWA, SNA_CMD_RB, SNA_CMD_RM, SNA_CMD_RMA, SNA_CMD_W,
};
use crate::datastream::order::{
    is_format_control, FC_NULL, FC_SI, FC_SO, ORDER_EUA, ORDER_GE, ORDER_IC, ORDER_MF, ORDER_PT,
    ORDER_RA, ORDER_SA, ORDER_SBA, ORDER_SF, ORDER_SFE,
};
use crate::datastream::reader::ByteReader;
use crate::datastream::wcc::WriteControlCharacter;
use crate::datastream::{CommandResult, DatastreamError, ReadPartitionRequest};
use crate::ebcdic::EBC_NULL;
use crate::field::{AttributeOrder, CharacterSet, ExtendedAttributes, FieldAttribute, XA_3270};
use crate::screen::{Cell, CharacterReplyAttrs, PresentationSpace, ReplyMode};
use crate::wsf::{parse_read_partition, SF_SRM_CHAR, SF_SRM_FIELD, SF_SRM_XFIELD};

/// Structured Field IDs.
pub const SF_READ_PART: u8 = 0x01;
pub const SF_ERASE_RESET: u8 = 0x03;
pub const SF_SET_REPLY_MODE: u8 = 0x09;
pub const SF_CREATE_PART: u8 = 0x0C;
pub const SF_OUTBOUND_DS: u8 = 0x40;

/// Erase/Reset type: use the default screen size.
const SF_ER_DEFAULT: u8 = 0x00;
/// Erase/Reset type: use the alternate screen size.
const SF_ER_ALT: u8 = 0x80;
/// Read Partition types for partition `0xFF` (Query / Query List).
const SF_RP_QUERY: u8 = 0x02;
const SF_RP_QLIST: u8 = 0x03;
/// Partition ID addressing all partitions (queries).
const PID_QUERY: u8 = 0xFF;
/// The implicit partition (the only one this terminal supports).
const PID_IMPLICIT: u8 = 0x00;

/// Side effects accumulated while executing the structured fields of one WSF; the flags
/// mirror those of [`CommandResult`].
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
struct WsfOutcome {
    screen_written: bool,
    sound_alarm: bool,
    restore_keyboard: bool,
    reset_mdt: bool,
    read_partition: Vec<ReadPartitionRequest>,
    /// First error encountered; fields before it (and, for per-field errors, after it) were
    /// still executed.
    rejected: Option<DatastreamError>,
}

/// Result of a `Write` / `Erase/Write` / `Erase/Write Alternate`.
#[derive(Debug)]
struct WriteOutcome {
    /// The WCC, if the command carried one.
    wcc: Option<WriteControlCharacter>,
    /// Set if the write was aborted part-way (everything before the failing order applied).
    error: Option<DatastreamError>,
}

/// How the erase implied by `EW` / `EWA` sizes the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EraseSize {
    /// A plain command: `EW` selects the default size, `EWA` the alternate size.
    ByCommand,
    /// Inside an *Outbound 3270DS* structured field both keep the current size (`x3270`
    /// `sf_outbound_ds()`: `ctlr_erase(screen_alt)` for `EW` and `EWA`).
    Current,
}

/// What a following Program Tab needs to know about the previous token of a write
/// (`x3270` `ctlr_write()` variables `last_cmd` and `last_zpt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TabContext {
    /// The previous token was the command or an order, not data (`last_cmd`).
    after_order: bool,
    /// The previous token was a nulling Program Tab that stopped at address 0 (`last_zpt`).
    after_wrapped_null_tab: bool,
}

impl TabContext {
    /// After the command itself and after any order except `PT`.
    const ORDER: Self = Self {
        after_order: true,
        after_wrapped_null_tab: false,
    };
    /// After a character, `NUL` or `GE`.
    const DATA: Self = Self {
        after_order: false,
        after_wrapped_null_tab: false,
    };
}

/// IBM 3270 Data Stream parser and execution state machine.
#[derive(Debug)]
pub struct DataStreamParser;

impl DataStreamParser {
    /// Executes one inbound 3270 record (command + data) against the presentation space.
    ///
    /// Never fails: errors are reported in [`CommandResult::rejected`] after everything up to
    /// the failing point has been applied, exactly like `process_ds()` in `x3270` `ctlr.c`
    /// (an aborted write still moves the cursor for a preceding `IC` and honours its WCC; the
    /// structured fields of a WSF before a malformed one still take effect). The session layer
    /// tells the host (TN3270E negative response) and the session continues — a single bad
    /// record from the host must never end the user's session.
    pub fn process(stream: &[u8], ps: &mut PresentationSpace) -> CommandResult {
        let mut result = CommandResult::empty();
        let mut reader = ByteReader::new(stream);
        let Ok(opcode) = reader.read_byte() else {
            result.rejected = Some(DatastreamError::EmptyStream);
            return result;
        };
        let cmd = match Command::from_opcode(opcode) {
            Ok(cmd) => cmd,
            Err(err) => {
                result.rejected = Some(err);
                return result;
            }
        };
        result.command = cmd;

        match cmd {
            Command::NoOp => {}
            Command::EraseAllUnprotected => {
                ps.erase_all_unprotected();
                result.reset_mdt = true;
                // `x3270` `ctlr_erase_all_unprotected`: always restores the keyboard.
                result.screen_written = true;
                result.restore_keyboard = true;
            }
            Command::ReadBuffer | Command::ReadModified | Command::ReadModifiedAll => {
                result.requires_inbound_reply = true;
            }
            Command::WriteStructuredField => {
                let outcome = Self::process_wsf(&mut reader, ps);
                result.screen_written = outcome.screen_written;
                result.sound_alarm = outcome.sound_alarm;
                result.restore_keyboard = outcome.restore_keyboard;
                result.reset_mdt = outcome.reset_mdt;
                result.requires_inbound_reply = !outcome.read_partition.is_empty();
                result.read_partition = outcome.read_partition;
                result.rejected = outcome.rejected;
            }
            Command::Write | Command::EraseWrite | Command::EraseWriteAlternate => {
                let outcome = Self::apply_write(cmd, EraseSize::ByCommand, &mut reader, ps);
                if let Some(wcc) = outcome.wcc {
                    result.screen_written = true;
                    result.wcc = Some(wcc);
                    result.sound_alarm = wcc.sound_alarm;
                    result.restore_keyboard = wcc.restore_keyboard;
                    result.reset_mdt = wcc.reset_mdt;
                }
                result.rejected = outcome.error;
            }
        }
        result
    }

    /// Strict variant of [`process`](Self::process): returns the rejection as an error.
    ///
    /// Partial effects are still applied to `ps`; use [`process`](Self::process) when the
    /// caller needs them (WCC flags, queued replies) despite the error.
    ///
    /// # Errors
    ///
    /// Returns the [`DatastreamError`] that [`process`](Self::process) would report in
    /// [`CommandResult::rejected`]: empty stream, unknown command, truncated order, buffer
    /// address out of range, or malformed structured field length.
    pub fn parse_and_apply(
        stream: &[u8],
        ps: &mut PresentationSpace,
    ) -> Result<CommandResult, DatastreamError> {
        let mut result = Self::process(stream, ps);
        match result.rejected.take() {
            Some(err) => Err(err),
            None => Ok(result),
        }
    }

    /// Executes `Write`, `Erase/Write` or `Erase/Write Alternate` (`ctlr_write()` in `x3270`).
    ///
    /// The erase implied by `EW` / `EWA` happens first, so it takes effect even when the WCC is
    /// missing (`process_ds()` erases before `ctlr_write()` checks the length). Then the WCC is
    /// applied and the order loop runs; if an order fails, the write stops there but the WCC
    /// and any preceding `IC` still apply.
    ///
    /// Shared by plain write commands and by the *Outbound 3270DS* structured field; `size`
    /// tells how the implied erase sizes the screen.
    fn apply_write(
        cmd: Command,
        size: EraseSize,
        reader: &mut ByteReader<'_>,
        ps: &mut PresentationSpace,
    ) -> WriteOutcome {
        Self::implied_erase(cmd, size, ps);

        let Ok(wcc_byte) = reader.read_byte() else {
            return WriteOutcome {
                wcc: None,
                error: Some(DatastreamError::UnexpectedEof {
                    expected: "WCC",
                    needed: 1,
                    remaining: 0,
                }),
            };
        };
        let wcc = WriteControlCharacter::from_wire(wcc_byte);

        if cmd == Command::Write {
            // A plain Write starts at the cursor address.
            let cur = ps.cursor_addr();
            if let Err(err) = ps.set_buffer_addr(cur) {
                return WriteOutcome {
                    wcc: Some(wcc),
                    error: Some(err.into()),
                };
            }
        }

        // EW / EWA with WCC reset return the partition to field reply mode (`x3270`
        // `ctlr_write`).
        if wcc.reset && cmd != Command::Write {
            ps.set_reply_mode(ReplyMode::Field);
        }

        // Apply WCC side effects, then the write orders and character loop
        wcc.apply(ps);
        WriteOutcome {
            wcc: Some(wcc),
            error: Self::execute_write_loop(reader, ps).err(),
        }
    }

    /// The erase implied by `EW` / `EWA`; other commands do not erase.
    fn implied_erase(cmd: Command, size: EraseSize, ps: &mut PresentationSpace) {
        let alternate = match (cmd, size) {
            (Command::EraseWrite | Command::EraseWriteAlternate, EraseSize::Current) => {
                ps.is_alternate_mode()
            }
            (Command::EraseWrite, EraseSize::ByCommand) => false,
            (Command::EraseWriteAlternate, EraseSize::ByCommand) => true,
            _ => return,
        };
        ps.erase_reset(alternate);
    }

    /// Runs the order loop and then applies a deferred `IC`, even if the loop was aborted
    /// (`x3270` `ctlr_write()` moves the cursor after the loop regardless of `aborted`).
    fn execute_write_loop(
        reader: &mut ByteReader<'_>,
        ps: &mut PresentationSpace,
    ) -> Result<(), DatastreamError> {
        let mut deferred_ic: Option<BufferAddress> = None;
        let loop_result = Self::write_orders(reader, ps, &mut deferred_ic);
        if let Some(ic_addr) = deferred_ic {
            ps.set_cursor_addr(ic_addr)?;
        }
        loop_result
    }

    /// Order and data loop of a write, until the end of the record or the first error.
    /// The address of the last `IC` is stored in `deferred_ic` for the caller to apply.
    #[allow(clippy::too_many_lines)]
    fn write_orders(
        reader: &mut ByteReader<'_>,
        ps: &mut PresentationSpace,
        deferred_ic: &mut Option<BufferAddress>,
    ) -> Result<(), DatastreamError> {
        let mut running_xa = ExtendedAttributes::DEFAULT;
        let mut tab = TabContext::ORDER;

        while !reader.is_empty() {
            let Some(b) = reader.peek_byte() else {
                break;
            };

            match b {
                ORDER_SF => {
                    let _ = reader.read_byte()?;
                    let fa_byte = reader.read_byte()?;
                    let fa = FieldAttribute::from_wire_byte(fa_byte);
                    ps.place_field(ps.buffer_addr(), fa, ExtendedAttributes::DEFAULT)?;
                    ps.advance_buffer_addr();
                    tab = TabContext::ORDER;
                }

                ORDER_SFE => {
                    let _ = reader.read_byte()?;
                    let na = reader.read_byte()?;
                    let mut base_fa = FieldAttribute::UNPROTECTED_NORMAL;
                    let mut ext = ExtendedAttributes::DEFAULT;
                    for _ in 0..na {
                        let (attr_type, attr_val) = reader.read_two_bytes()?;
                        if attr_type == XA_3270 {
                            base_fa = FieldAttribute::from_wire_byte(attr_val);
                        } else {
                            ext.apply_pair(AttributeOrder::StartFieldExtended, attr_type, attr_val);
                        }
                    }
                    ps.place_field(ps.buffer_addr(), base_fa, ext)?;
                    ps.advance_buffer_addr();
                    tab = TabContext::ORDER;
                }

                ORDER_SBA => {
                    let _ = reader.read_byte()?;
                    let (c1, c2) = reader.read_two_bytes()?;
                    let target_addr = BufferAddress::decode(c1, c2, ps.capacity())?;
                    ps.set_buffer_addr(target_addr)?;
                    tab = TabContext::ORDER;
                }

                ORDER_SA => {
                    let _ = reader.read_byte()?;
                    let (attr_type, attr_val) = reader.read_two_bytes()?;
                    running_xa.apply_pair(AttributeOrder::SetAttribute, attr_type, attr_val);
                    tab = TabContext::ORDER;
                }

                ORDER_IC => {
                    let _ = reader.read_byte()?;
                    *deferred_ic = Some(ps.buffer_addr());
                    tab = TabContext::ORDER;
                }

                ORDER_PT => {
                    let _ = reader.read_byte()?;
                    tab = Self::program_tab(ps, tab)?;
                }

                ORDER_RA => {
                    let _ = reader.read_byte()?;
                    let (c1, c2) = reader.read_two_bytes()?;
                    let stop_addr = BufferAddress::decode(c1, c2, ps.capacity())?;
                    let char_byte = reader.read_byte()?;
                    let (ch, is_ge) = if char_byte == ORDER_GE {
                        let ge_ch = reader.read_byte()?;
                        (ge_ch, true)
                    } else {
                        (char_byte, false)
                    };

                    let cap = ps.capacity();
                    let mut steps: usize = 0;
                    let max_steps = cap.saturating_add(1);
                    loop {
                        let mut cell_xa = running_xa;
                        if is_ge {
                            cell_xa.charset = CharacterSet::Apl;
                        }
                        ps.write_char(ps.buffer_addr(), ch, cell_xa)?;
                        ps.advance_buffer_addr();
                        steps = steps.saturating_add(1);
                        if ps.buffer_addr() == stop_addr || steps >= max_steps {
                            break;
                        }
                    }
                    tab = TabContext::ORDER;
                }

                ORDER_EUA => {
                    let _ = reader.read_byte()?;
                    let (c1, c2) = reader.read_two_bytes()?;
                    let stop_addr = BufferAddress::decode(c1, c2, ps.capacity())?;

                    // `x3270` `ctlr_write` `ORDER_EUA`: the governing attribute is looked up
                    // once and carried forward, so one EUA costs one pass over the buffer.
                    // `ctlr_add(baddr, EBC_null, CS_BASE)` replaces the character and its
                    // character set; colour and highlighting stay.
                    let cap = ps.capacity();
                    let mut steps: usize = 0;
                    let max_steps = cap.saturating_add(1);
                    let mut current_fa = ps.effective_field_attribute(ps.buffer_addr());
                    loop {
                        let curr = ps.buffer_addr();
                        if let Some(cell) = ps.cell(curr) {
                            if let Some(fa) = cell.field_attribute() {
                                current_fa = fa;
                            } else if !current_fa.is_protected() {
                                let mut xa = cell.extended();
                                xa.charset = CharacterSet::Base;
                                ps.write_char(curr, EBC_NULL, xa)?;
                            }
                        }
                        ps.advance_buffer_addr();
                        steps = steps.saturating_add(1);
                        if ps.buffer_addr() == stop_addr || steps >= max_steps {
                            break;
                        }
                    }
                    tab = TabContext::ORDER;
                }

                ORDER_GE => {
                    let _ = reader.read_byte()?;
                    let ch = reader.read_byte()?;
                    let mut xa = running_xa;
                    xa.charset = CharacterSet::Apl;
                    ps.write_char(ps.buffer_addr(), ch, xa)?;
                    ps.advance_buffer_addr();
                    tab = TabContext::DATA;
                }

                ORDER_MF => {
                    let _ = reader.read_byte()?;
                    let na = reader.read_byte()?;
                    let curr_addr = ps.buffer_addr();
                    let is_fa = ps.cell(curr_addr).is_some_and(Cell::is_field_attribute);

                    for _ in 0..na {
                        let (attr_type, attr_val) = reader.read_two_bytes()?;
                        if !is_fa {
                            continue;
                        }
                        if attr_type == XA_3270 {
                            if let Some(fa) = ps.field_attribute_mut(curr_addr) {
                                *fa = FieldAttribute::from_wire_byte(attr_val);
                            }
                        } else if let Some(xa) = ps.extended_mut(curr_addr) {
                            xa.apply_pair(AttributeOrder::ModifyField, attr_type, attr_val);
                        }
                    }

                    if is_fa {
                        ps.advance_buffer_addr();
                    }
                    tab = TabContext::ORDER;
                }

                FC_SO | FC_SI => {
                    // Stored like a character, but counts as an order for a following PT
                    // (`x3270` `ctlr_write()`: `last_cmd = true`).
                    let byte = reader.read_byte()?;
                    ps.write_char(ps.buffer_addr(), byte, running_xa)?;
                    ps.advance_buffer_addr();
                    tab = TabContext::ORDER;
                }

                _ => {
                    let byte = reader.read_byte()?;
                    if byte >= 0x40 || is_format_control(byte) {
                        ps.write_char(ps.buffer_addr(), byte, running_xa)?;
                        ps.advance_buffer_addr();
                        // Format control orders (DUP, FM, NL, ...) are stored like characters
                        // but count as orders for a following PT; NUL and graphic characters
                        // are data (`x3270` `ctlr_write()` cases `FCORDER_*`, `FCORDER_NULL`).
                        tab = if byte != FC_NULL && is_format_control(byte) {
                            TabContext::ORDER
                        } else {
                            TabContext::DATA
                        };
                    } else {
                        // Unsupported order: skipped without moving the buffer address
                        // (`x3270` `ctlr_write()` default branch, "UnsupportedOrder").
                        tab = TabContext::ORDER;
                    }
                }
            }
        }

        Ok(())
    }

    /// Program Tab (`x3270` `ctlr_write()` case `ORDER_PT`).
    ///
    /// On the attribute of an unprotected field the tab only advances one position.
    /// Otherwise it moves to the first data position of the next unprotected field; it never
    /// wraps: when that field lies before the current address, the tab stops at address 0.
    ///
    /// A tab that follows data (or a previous nulling tab that stopped at 0) first nulls the
    /// rest of the current field — even if protected — up to the next field attribute or the
    /// target, whichever comes first.
    fn program_tab(
        ps: &mut PresentationSpace,
        tab: TabContext,
    ) -> Result<TabContext, DatastreamError> {
        let curr = ps.buffer_addr();
        let on_unprotected_fa = ps
            .cell(curr)
            .and_then(Cell::field_attribute)
            .is_some_and(|fa| !fa.is_protected());
        if on_unprotected_fa {
            ps.advance_buffer_addr();
            return Ok(TabContext::ORDER);
        }

        let target = ps
            .next_unprotected_data_addr(curr)
            .filter(|next| next.as_usize() >= curr.as_usize())
            .unwrap_or(BufferAddress::ZERO);

        let mut after_wrapped_null_tab = false;
        if !tab.after_order || tab.after_wrapped_null_tab {
            let cap = ps.capacity();
            let mut addr = curr;
            // Bounded by the screen size: an unformatted screen has no attribute to stop at.
            for _ in 0..cap {
                if addr == target || ps.cell(addr).is_none_or(Cell::is_field_attribute) {
                    break;
                }
                ps.write_char(addr, 0x00, ExtendedAttributes::DEFAULT)?;
                addr = addr.next_wrapped(cap);
            }
            after_wrapped_null_tab = target == BufferAddress::ZERO;
        }
        ps.set_buffer_addr(target)?;
        Ok(TabContext {
            after_order: true,
            after_wrapped_null_tab,
        })
    }

    /// Executes every length-prefixed structured field of a Write Structured Field (WSF), in
    /// order, following `write_structured_field()` in `x3270` `sf.c`:
    ///
    /// | SFID   | Structured field   | Effect                                                     |
    /// | :----- | :----------------- | :--------------------------------------------------------- |
    /// | `0x01` | Read Partition     | queued as a [`ReadPartitionRequest`] for the session layer |
    /// | `0x03` | Erase/Reset        | clears the screen (default or alternate size)              |
    /// | `0x09` | Set Reply Mode     | sets field / extended field / character reply mode         |
    /// | `0x40` | Outbound 3270DS    | runs the wrapped `W` / `EW` / `EWA` / `EAU` command        |
    /// | other  | (unsupported)      | skipped                                                    |
    ///
    /// A malformed field length stops processing (fields before it keep their effect); an
    /// error inside one field is recorded and processing continues with the next field, as in
    /// `x3270`. Unknown or unsupported field contents are skipped, so a host using an exotic
    /// structured field cannot lock up the session.
    fn process_wsf(reader: &mut ByteReader<'_>, ps: &mut PresentationSpace) -> WsfOutcome {
        let mut outcome = WsfOutcome::default();
        while !reader.is_empty() {
            let Some(payload) = Self::next_structured_field(reader) else {
                outcome
                    .rejected
                    .get_or_insert(DatastreamError::InvalidStructuredFieldLength {
                        length: reader.remaining(),
                        remaining: reader.remaining(),
                    });
                break;
            };

            // payload = [SFID, partition / type, ...]
            if let Err(err) = Self::structured_field(payload, ps, &mut outcome) {
                outcome.rejected.get_or_insert(err);
            }
        }
        outcome
    }

    /// Reads the next length-prefixed structured field and returns its payload (without the
    /// length bytes). `None` if the length is invalid: fewer than 3, longer than the rest of the
    /// record, or a single byte left (`x3270` `write_structured_field()` checks).
    /// A length of 0 means "the rest of the record".
    fn next_structured_field<'a>(reader: &mut ByteReader<'a>) -> Option<&'a [u8]> {
        let len = usize::from(reader.read_u16_be().ok()?);
        if len == 0 {
            return Some(reader.read_remaining());
        }
        let needed = len.checked_sub(2).filter(|&n| n >= 1)?;
        if needed > reader.remaining() {
            return None;
        }
        reader.read_bytes(needed).ok()
    }

    /// *Set Reply Mode* (`x3270` `sf_set_reply_mode`): `[0x09, partition, mode, attr...]`.
    /// Only the implicit partition `0x00` and the three modes are valid; character mode
    /// carries the list of character attribute types to report.
    fn set_reply_mode(payload: &[u8], ps: &mut PresentationSpace) -> Result<(), DatastreamError> {
        let (Some(&partition), Some(&mode)) = (payload.get(1), payload.get(2)) else {
            return Err(DatastreamError::InvalidStructuredField(
                "Set Reply Mode too short",
            ));
        };
        if partition != PID_IMPLICIT {
            return Err(DatastreamError::InvalidStructuredField(
                "Set Reply Mode for an unknown partition",
            ));
        }
        let mode = match mode {
            SF_SRM_FIELD => ReplyMode::Field,
            SF_SRM_XFIELD => ReplyMode::ExtendedField,
            SF_SRM_CHAR => ReplyMode::Character(CharacterReplyAttrs::from_xa_types(
                payload.get(3..).unwrap_or(&[]),
            )),
            _ => {
                return Err(DatastreamError::InvalidStructuredField(
                    "unknown reply mode",
                ))
            }
        };
        ps.set_reply_mode(mode);
        Ok(())
    }

    /// Executes one structured field of a WSF (`x3270` `write_structured_field` dispatch).
    /// Every field this terminal does not support, or whose parameters are invalid, is
    /// rejected (`PDS_BAD_CMD`, reported to the host as COMMAND-REJECT); the fields after it
    /// are still executed.
    fn structured_field(
        payload: &[u8],
        ps: &mut PresentationSpace,
        outcome: &mut WsfOutcome,
    ) -> Result<(), DatastreamError> {
        let reject = DatastreamError::InvalidStructuredField;
        match payload.first().copied() {
            Some(SF_READ_PART) => {
                let request = Self::read_partition_request(payload)?;
                outcome.read_partition.push(request);
                Ok(())
            }
            // `sf_erase_reset`: exactly one type byte.
            Some(SF_ERASE_RESET) => match payload {
                [_, SF_ER_DEFAULT] => {
                    ps.erase_reset(false);
                    Ok(())
                }
                [_, SF_ER_ALT] => {
                    ps.erase_reset(true);
                    Ok(())
                }
                _ => Err(reject("invalid Erase/Reset")),
            },
            Some(SF_SET_REPLY_MODE) => Self::set_reply_mode(payload, ps),
            Some(SF_CREATE_PART) => Self::create_partition(payload),
            Some(SF_OUTBOUND_DS) => {
                // `sf_outbound_ds`: partition 0 and a command byte.
                let (Some(&pid), Some(&opcode)) = (payload.get(1), payload.get(2)) else {
                    return Err(reject("Outbound 3270DS too short"));
                };
                if pid != PID_IMPLICIT {
                    return Err(reject("Outbound 3270DS for an unknown partition"));
                }
                let data = payload.get(3..).unwrap_or(&[]);
                Self::outbound_3270ds(opcode, data, ps, outcome)
            }
            _ => Err(reject("unsupported structured field")),
        }
    }

    /// *Read Partition* (`x3270` `sf_read_part`): Query and Query List address partition
    /// `0xFF`, Read Buffer / Read Modified (All) partition `0x00`.
    fn read_partition_request(payload: &[u8]) -> Result<ReadPartitionRequest, DatastreamError> {
        let reject = DatastreamError::InvalidStructuredField;
        let (Some(&pid), Some(&kind)) = (payload.get(1), payload.get(2)) else {
            return Err(reject("Read Partition too short"));
        };
        match (pid, kind) {
            (PID_QUERY, SF_RP_QUERY | SF_RP_QLIST) => parse_read_partition(payload)
                .map(ReadPartitionRequest::Query)
                .map_err(|_| reject("invalid Read Partition query")),
            (PID_IMPLICIT, SNA_CMD_RB) => Ok(ReadPartitionRequest::ReadBuffer),
            (PID_IMPLICIT, SNA_CMD_RM) => Ok(ReadPartitionRequest::ReadModified { all: false }),
            (PID_IMPLICIT, SNA_CMD_RMA) => Ok(ReadPartitionRequest::ReadModified { all: true }),
            _ => Err(reject("invalid Read Partition")),
        }
    }

    /// *Create Partition* (`x3270` `sf_create_partition`): only the implicit partition with
    /// the units of measure and addressing modes `x3270` accepts; it has no further effect.
    fn create_partition(payload: &[u8]) -> Result<(), DatastreamError> {
        let reject = DatastreamError::InvalidStructuredField;
        if payload.get(1).is_some_and(|&pid| pid != PID_IMPLICIT) {
            return Err(reject("Create Partition for an unknown partition"));
        }
        if let Some(&b) = payload.get(2) {
            let unit_of_measure = b >> 4;
            let addressing_mode = b & 0x0F;
            if !matches!(unit_of_measure, 0x0 | 0x2) || addressing_mode > 0x2 {
                return Err(reject("invalid Create Partition parameters"));
            }
        }
        Ok(())
    }

    /// Executes the 3270 command wrapped in an *Outbound 3270DS* structured field.
    ///
    /// `data` starts after the command byte: `[WCC, orders/data...]` for writes.
    fn outbound_3270ds(
        opcode: u8,
        data: &[u8],
        ps: &mut PresentationSpace,
        outcome: &mut WsfOutcome,
    ) -> Result<(), DatastreamError> {
        // `sf_outbound_ds` accepts the SNA command codes only (no CCW codes).
        if !matches!(opcode, SNA_CMD_W | SNA_CMD_EW | SNA_CMD_EWA | SNA_CMD_EAU) {
            return Err(DatastreamError::InvalidStructuredField(
                "invalid command in Outbound 3270DS",
            ));
        }
        let Ok(cmd) = Command::from_opcode(opcode) else {
            return Err(DatastreamError::InvalidStructuredField(
                "invalid command in Outbound 3270DS",
            ));
        };
        match cmd {
            Command::Write | Command::EraseWrite | Command::EraseWriteAlternate => {
                if data.is_empty() {
                    // Command without WCC: only the implied erase happens.
                    Self::implied_erase(cmd, EraseSize::Current, ps);
                    return Ok(());
                }
                let mut inner = ByteReader::new(data);
                let write = Self::apply_write(cmd, EraseSize::Current, &mut inner, ps);
                if let Some(wcc) = write.wcc {
                    outcome.screen_written = true;
                    outcome.sound_alarm |= wcc.sound_alarm;
                    outcome.restore_keyboard |= wcc.restore_keyboard;
                    outcome.reset_mdt |= wcc.reset_mdt;
                }
                if let Some(err) = write.error {
                    return Err(err);
                }
            }
            Command::EraseAllUnprotected => {
                ps.erase_all_unprotected();
                outcome.reset_mdt = true;
                // `x3270` `ctlr_erase_all_unprotected`: always restores the keyboard.
                outcome.screen_written = true;
                outcome.restore_keyboard = true;
            }
            _ => {} // not reachable: only W / EW / EWA / EAU pass the check above
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::address::BufferAddress;
    use crate::datastream::command::{CMD_EAU, CMD_EW, CMD_EWA, CMD_NOP, CMD_W};
    use crate::datastream::wcc::WCC_SOUND_ALARM_BIT;
    use crate::ebcdic::{CodePage, CP037};
    use crate::field::{Color3270, FieldIntensity, Highlight3270};
    use crate::model::TerminalModel;

    #[test]
    fn test_graphic_escape_renders_cp310_box_drawing() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        // EW, WCC, then GE 0xC5 (┌), GE 0xA2 (─), and a plain 0xC5 ('E' in CP037).
        let stream = [CMD_EW, 0xC2, ORDER_GE, 0xC5, ORDER_GE, 0xA2, 0xC5];
        DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();
        let cap = ps.capacity();
        let ch = |i: usize| {
            ps.safe_cell_at(BufferAddress::new(i, cap).unwrap(), &CP037)
                .unwrap()
                .ch
        };
        assert_eq!(ch(0), '┌');
        assert_eq!(ch(1), '─');
        assert_eq!(ch(2), 'E', "without GE the base code page applies");
    }

    #[test]
    fn test_graphic_escape_in_non_display_field_stays_masked() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        // EW, WCC, SF (non-display, unprotected = 0x4C), GE 0xC5.
        let stream = [CMD_EW, 0xC2, ORDER_SF, 0x4C, ORDER_GE, 0xC5];
        DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();
        let cap = ps.capacity();
        let cell = ps
            .safe_cell_at(BufferAddress::new(1, cap).unwrap(), &CP037)
            .unwrap();
        assert_eq!(cell.ch, ' ');
    }

    // ── Write Structured Field (WSF) ─────────────────────────────────────────────

    #[test]
    fn test_wsf_query_not_first_field_is_still_requested() {
        // Regression (z/OS): Erase/Reset precedes the Read Partition Query.
        let mut ps = PresentationSpace::new(TerminalModel::Model4);
        let stream = [0xF3, 0x00, 0x04, 0x03, 0x00, 0x00, 0x05, 0x01, 0xFF, 0x02];
        let res = DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();
        assert!(res.requires_inbound_reply);
        assert_eq!(
            res.read_partition,
            vec![ReadPartitionRequest::Query(
                crate::wsf::QueryRequest::QueryAll
            )]
        );
    }

    #[test]
    fn test_wsf_erase_reset_alternate_switches_screen_size() {
        let mut ps = PresentationSpace::new(TerminalModel::Model4); // alternate 43x80
        let res =
            DataStreamParser::parse_and_apply(&[0xF3, 0x00, 0x04, 0x03, 0x80], &mut ps).unwrap();
        assert!(!res.requires_inbound_reply);
        assert!(ps.is_alternate_mode());
        assert_eq!(ps.rows(), 43);

        DataStreamParser::parse_and_apply(&[0xF3, 0x00, 0x04, 0x03, 0x00], &mut ps).unwrap();
        assert!(!ps.is_alternate_mode());
        assert_eq!(ps.rows(), 24);
    }

    #[test]
    fn test_wsf_outbound_3270ds_erase_write_renders_and_unlocks() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let a = CP037.char_to_ebcdic('A').unwrap();
        let b = CP037.char_to_ebcdic('B').unwrap();
        // SF length 8: [00 08] [40 Outbound DS] [00 partition] [F5 EW] [C2 WCC restore+reset MDT] A B
        let stream = [0xF3, 0x00, 0x08, 0x40, 0x00, 0xF5, 0xC2, a, b];
        let res = DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();
        assert_eq!(res.command, Command::WriteStructuredField);
        assert!(
            res.restore_keyboard,
            "WCC inside Outbound 3270DS must unlock the keyboard"
        );
        assert!(!res.requires_inbound_reply);
        let cap = ps.capacity();
        assert_eq!(
            ps.cell(BufferAddress::new(0, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            a
        );
        assert_eq!(
            ps.cell(BufferAddress::new(1, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            b
        );
    }

    #[test]
    fn test_wsf_read_partition_rb_rm_rma_for_implicit_partition() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let stream = [
            0xF3, 0x00, 0x05, 0x01, 0x00, 0xF2, // RB
            0x00, 0x05, 0x01, 0x00, 0xF6, // RM
            0x00, 0x05, 0x01, 0x00, 0x6E, // RMA
        ];
        let res = DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();
        assert_eq!(
            res.read_partition,
            vec![
                ReadPartitionRequest::ReadBuffer,
                ReadPartitionRequest::ReadModified { all: false },
                ReadPartitionRequest::ReadModified { all: true },
            ]
        );
    }

    #[test]
    fn test_wsf_unknown_field_is_rejected_and_later_fields_still_run() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        // Set Reply Mode (field) + unknown SFID 0x77 + Query (x3270 `write_structured_field`:
        // the unknown field is PDS_BAD_CMD, processing continues).
        let stream = [
            0xF3, 0x00, 0x05, 0x09, 0x00, 0x00, 0x00, 0x04, 0x77, 0x01, 0x00, 0x05, 0x01, 0xFF,
            0x02,
        ];
        let res = DataStreamParser::process(&stream, &mut ps);
        assert_eq!(res.read_partition.len(), 1);
        assert_eq!(
            res.rejected.map(|e| e.reject_kind()),
            Some(crate::datastream::RejectKind::CommandReject)
        );
    }

    #[test]
    fn test_wsf_rejects_field_length_too_small_or_too_long() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        assert!(matches!(
            DataStreamParser::parse_and_apply(&[0xF3, 0x00, 0x02, 0x01], &mut ps),
            Err(DatastreamError::InvalidStructuredFieldLength { .. })
        ));
        assert!(matches!(
            DataStreamParser::parse_and_apply(&[0xF3, 0x00, 0x09, 0x01, 0xFF, 0x02], &mut ps),
            Err(DatastreamError::InvalidStructuredFieldLength { .. })
        ));
    }

    #[test]
    fn test_empty_stream_error() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        assert_eq!(
            DataStreamParser::parse_and_apply(&[], &mut ps),
            Err(DatastreamError::EmptyStream)
        );
    }

    #[test]
    fn test_command_noop() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let res = DataStreamParser::parse_and_apply(&[CMD_NOP], &mut ps).unwrap();
        assert_eq!(res.command, Command::NoOp);
        assert!(!res.requires_inbound_reply);
    }

    #[test]
    fn test_command_erase_all_unprotected() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();
        // Setup unprotected field with data
        let fa = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, true);
        ps.place_field(
            BufferAddress::new(0, cap).unwrap(),
            fa,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
        let ebcdic_x = CP037.char_to_ebcdic('X').unwrap();
        ps.write_char(
            BufferAddress::new(1, cap).unwrap(),
            ebcdic_x,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();

        let res = DataStreamParser::parse_and_apply(&[CMD_EAU], &mut ps).unwrap();
        assert_eq!(res.command, Command::EraseAllUnprotected);
        assert!(res.reset_mdt);
        // Cell 1 should now be 0x00
        assert_eq!(
            ps.cell(BufferAddress::new(1, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            0x00
        );
    }

    #[test]
    fn test_erase_write_default_dimensions_and_wcc() {
        let mut ps = PresentationSpace::new(TerminalModel::Model3); // Model 3 has alternate 32x80
                                                                    // Put in alternate mode first
        ps.erase_reset(true);
        assert_eq!(ps.rows(), 32);

        // EraseWrite (0x05) with WCC sound alarm (0x04)
        let stream = [CMD_EW, WCC_SOUND_ALARM_BIT];
        let res = DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();
        assert_eq!(res.command, Command::EraseWrite);
        assert!(res.sound_alarm);
        // Dimensions should have reset to 24x80 default
        assert_eq!(ps.rows(), 24);
        assert_eq!(ps.cols(), 80);
    }

    #[test]
    fn test_erase_write_alternate_dimensions() {
        let mut ps = PresentationSpace::new(TerminalModel::Model3);
        assert_eq!(ps.rows(), 24);

        // EraseWriteAlternate (0x0D) with WCC 0x00
        let stream = [CMD_EWA, 0x00];
        let res = DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();
        assert_eq!(res.command, Command::EraseWriteAlternate);
        // Dimensions should have switched to 32x80 alternate
        assert_eq!(ps.rows(), 32);
        assert_eq!(ps.cols(), 80);
    }

    #[test]
    fn test_orders_sf_sba_ic_text() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();

        // Stream: EW (0x05) + WCC(0x00) + SBA(0,0 -> 0x40,0x40) + SF(0x60: protected) + text("ABC") + IC + text("D")
        let [sba1, sba2] = BufferAddress::new(0, cap).unwrap().encode_12bit().unwrap();
        let text_abc = [
            CP037.char_to_ebcdic('A').unwrap(),
            CP037.char_to_ebcdic('B').unwrap(),
            CP037.char_to_ebcdic('C').unwrap(),
        ];
        let text_d = CP037.char_to_ebcdic('D').unwrap();

        let mut stream = vec![CMD_EW, 0x00, ORDER_SBA, sba1, sba2, ORDER_SF, 0x60];
        stream.extend_from_slice(&text_abc);
        stream.push(ORDER_IC);
        stream.push(text_d);

        let res = DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();
        assert_eq!(res.command, Command::EraseWrite);

        // Cell 0 is SF marker
        assert!(ps
            .cell(BufferAddress::new(0, cap).unwrap())
            .unwrap()
            .is_field_attribute());
        // Cells 1..3 are 'A', 'B', 'C'
        assert_eq!(
            ps.cell(BufferAddress::new(1, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            text_abc[0]
        );
        assert_eq!(
            ps.cell(BufferAddress::new(2, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            text_abc[1]
        );
        assert_eq!(
            ps.cell(BufferAddress::new(3, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            text_abc[2]
        );
        // Cell 4 is 'D'
        assert_eq!(
            ps.cell(BufferAddress::new(4, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            text_d
        );

        // Cursor should have been set by ORDER_IC at address 4 (before 'D' was written)
        assert_eq!(ps.cursor_addr().as_usize(), 4);
    }

    #[test]
    fn test_order_sfe_and_sa() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();

        // Stream: EW + WCC + SFE(na=2: XA_3270=0x40, XA_FOREGROUND=Blue:0xF1) + SA(XA_HIGHLIGHT=Reverse:0xF2) + text('Z')
        let stream = [
            CMD_EW,
            0x00,
            ORDER_SFE,
            0x02,
            0xC0,
            0x40,
            0x42,
            0xF1, // Blue
            ORDER_SA,
            0x41,
            0xF2, // Reverse video
            CP037.char_to_ebcdic('Z').unwrap(),
        ];

        DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

        // Cell 0 is SFE marker with Blue foreground
        let cell0 = ps.cell(BufferAddress::new(0, cap).unwrap()).unwrap();
        assert!(cell0.is_field_attribute());
        assert_eq!(cell0.extended().foreground, Color3270::Blue);

        // Cell 1 has 'Z' with Reverse video
        let cell1 = ps.cell(BufferAddress::new(1, cap).unwrap()).unwrap();
        assert_eq!(cell1.extended().highlight, Highlight3270::REVERSE_VIDEO);
    }

    #[test]
    fn test_order_repeat_to_address_wrap() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();

        // SBA to 500, RA to 500 with 'X' -> full screen wrap around 1920 cells
        let [sba1, sba2] = BufferAddress::new(500, cap)
            .unwrap()
            .encode_12bit()
            .unwrap();
        let [ra1, ra2] = BufferAddress::new(500, cap)
            .unwrap()
            .encode_12bit()
            .unwrap();
        let ebcdic_x = CP037.char_to_ebcdic('X').unwrap();

        let stream = [
            CMD_W, 0x00, ORDER_SBA, sba1, sba2, ORDER_RA, ra1, ra2, ebcdic_x,
        ];

        DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

        // All cells should be 'X'
        for i in 0..cap {
            assert_eq!(
                ps.cell(BufferAddress::new(i, cap).unwrap())
                    .unwrap()
                    .raw_ebcdic(),
                ebcdic_x
            );
        }
        // Buffer address finishes at 500
        assert_eq!(ps.buffer_addr().as_usize(), 500);
    }

    #[test]
    fn test_order_erase_unprotected_to_address() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();

        let ebcdic_x = CP037.char_to_ebcdic('X').unwrap();

        // Fill cells 0..20 with 'X'
        for i in 0..20 {
            ps.write_char(
                BufferAddress::new(i, cap).unwrap(),
                ebcdic_x,
                ExtendedAttributes::DEFAULT,
            )
            .unwrap();
        }

        // Put protected field at 0, unprotected field at 10
        ps.place_field(
            BufferAddress::new(0, cap).unwrap(),
            FieldAttribute::new(true, false, FieldIntensity::NormalNonDetectable, false),
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
        ps.place_field(
            BufferAddress::new(10, cap).unwrap(),
            FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false),
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();

        // EUA from 0 to 20
        let [sba1, sba2] = BufferAddress::new(0, cap).unwrap().encode_12bit().unwrap();
        let [eua1, eua2] = BufferAddress::new(20, cap).unwrap().encode_12bit().unwrap();
        let stream = [CMD_W, 0x00, ORDER_SBA, sba1, sba2, ORDER_EUA, eua1, eua2];

        DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

        // Protected cells 1..9 should still have 'X'
        for i in 1..10 {
            assert_eq!(
                ps.cell(BufferAddress::new(i, cap).unwrap())
                    .unwrap()
                    .raw_ebcdic(),
                ebcdic_x
            );
        }
        // Unprotected cells 11..19 should be cleared to 0x00
        for i in 11..20 {
            assert_eq!(
                ps.cell(BufferAddress::new(i, cap).unwrap())
                    .unwrap()
                    .raw_ebcdic(),
                0x00
            );
        }
    }

    #[test]
    fn test_order_program_tab_nulling() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();

        // Field 1 at 0: unprotected
        ps.place_field(
            BufferAddress::new(0, cap).unwrap(),
            FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false),
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();

        // Field 2 at 10: unprotected
        ps.place_field(
            BufferAddress::new(10, cap).unwrap(),
            FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false),
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();

        // Fill cells 1..9 with 'X'
        let ebcdic_x = CP037.char_to_ebcdic('X').unwrap();
        for i in 1..10 {
            ps.write_char(
                BufferAddress::new(i, cap).unwrap(),
                ebcdic_x,
                ExtendedAttributes::DEFAULT,
            )
            .unwrap();
        }

        // SBA 1, write 'A', then PT
        let [sba1, sba2] = BufferAddress::new(1, cap).unwrap().encode_12bit().unwrap();
        let stream = [
            CMD_W,
            0x00,
            ORDER_SBA,
            sba1,
            sba2,
            CP037.char_to_ebcdic('A').unwrap(),
            ORDER_PT,
        ];

        DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

        // Cell 1 has 'A'
        assert_eq!(
            ps.cell(BufferAddress::new(1, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            CP037.char_to_ebcdic('A').unwrap()
        );
        // Cells 2..9 were nulled by PT because PT followed data!
        for i in 2..10 {
            assert_eq!(
                ps.cell(BufferAddress::new(i, cap).unwrap())
                    .unwrap()
                    .raw_ebcdic(),
                0x00
            );
        }
        // Buffer address should now be 11 (first data cell of Field 2)
        assert_eq!(ps.buffer_addr().as_usize(), 11);
    }
}
