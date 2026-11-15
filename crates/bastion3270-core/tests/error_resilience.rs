//! Regression tests: bad host data never ends a session (x3270 conformance).
//!
//! `x3270` isolates errors in inbound records: an aborted write keeps what was applied before
//! the error (including a preceding `IC` and the WCC), unsupported order bytes are skipped,
//! structured fields before a malformed one keep their effect, and malformed TN3270E records
//! are dropped. The host is told through a negative response; the session continues.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use bastion3270_core::address::BufferAddress;
use bastion3270_core::datastream::{
    DataStreamParser, DatastreamError, ReadPartitionRequest, RejectKind,
};
use bastion3270_core::model::TerminalModel;
use bastion3270_core::screen::PresentationSpace;
use bastion3270_core::telnet::state_machine::TelnetStateMachine;
use bastion3270_core::telnet::{TelnetError, TelnetEvent};

const IAC: u8 = 0xFF;
const EOR: u8 = 0xEF;

fn byte_at(ps: &PresentationSpace, addr: usize) -> u8 {
    let cap = ps.capacity();
    ps.cell(BufferAddress::new(addr, cap).unwrap())
        .unwrap()
        .raw_ebcdic()
}

/// A byte <= 0x3F that is not an order or format control is skipped without moving the
/// buffer address; the write and its WCC complete normally (x3270 `ctlr_write()` default).
#[test]
fn unsupported_order_byte_is_skipped_and_write_completes() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    // Write, WCC restore keyboard, 'A', 0x01 (unsupported), 'B'
    let res = DataStreamParser::process(&[0xF1, 0xC2, 0xC1, 0x01, 0xC2], &mut ps);
    assert_eq!(res.rejected, None);
    assert!(res.restore_keyboard);
    assert_eq!(byte_at(&ps, 0), 0xC1);
    assert_eq!(byte_at(&ps, 1), 0xC2);
}

/// SO (0x0E) and SI (0x0F) are stored in the buffer like characters.
#[test]
fn shift_out_and_shift_in_are_stored() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let res = DataStreamParser::process(&[0xF5, 0xC2, 0xC1, 0x0E, 0xC2, 0x0F, 0xC3], &mut ps);
    assert_eq!(res.rejected, None);
    let written: Vec<u8> = (0..5).map(|a| byte_at(&ps, a)).collect();
    assert_eq!(written, vec![0xC1, 0x0E, 0xC2, 0x0F, 0xC3]);
}

/// A write aborted by an out-of-range SBA still applies the preceding IC and the WCC
/// keyboard restore, and is classified as OPERATION-CHECK (x3270 `PDS_BAD_ADDR`).
#[test]
fn aborted_write_keeps_insert_cursor_and_wcc() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    // Write, WCC restore, SBA 5, IC, SBA 4095 (> 1920 cells)
    let res = DataStreamParser::process(
        &[0xF1, 0xC2, 0x11, 0x40, 0xC5, 0x13, 0x11, 0x7F, 0x7F],
        &mut ps,
    );
    let err = res.rejected.expect("write must be reported as rejected");
    assert!(matches!(err, DatastreamError::InvalidAddress(_)));
    assert_eq!(err.reject_kind(), RejectKind::OperationCheck);
    assert!(res.restore_keyboard, "WCC restore must still apply");
    assert_eq!(
        ps.cursor_addr().as_usize(),
        5,
        "IC before the error must still apply"
    );
}

/// Erase/Write without a WCC still erases the screen before reporting the error.
#[test]
fn erase_write_without_wcc_still_erases() {
    let mut ps = PresentationSpace::new(TerminalModel::Model4);
    DataStreamParser::process(&[0xF5, 0xC2, 0xC1, 0xC2], &mut ps);
    assert_eq!(byte_at(&ps, 0), 0xC1);

    let res = DataStreamParser::process(&[0xF5], &mut ps);
    assert!(matches!(
        res.rejected,
        Some(DatastreamError::UnexpectedEof { .. })
    ));
    assert_eq!(byte_at(&ps, 0), 0x00, "screen must be erased");

    // EWA without WCC switches to the alternate size
    let res = DataStreamParser::process(&[0x7E], &mut ps);
    assert!(res.rejected.is_some());
    assert_eq!(ps.rows(), 43);
}

/// Unknown command opcode: rejected as COMMAND-REJECT (x3270 `PDS_BAD_CMD`).
#[test]
fn unknown_command_is_command_reject() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let res = DataStreamParser::process(&[0x99], &mut ps);
    let err = res.rejected.expect("unknown command must be rejected");
    assert_eq!(err, DatastreamError::UnknownCommand(0x99));
    assert_eq!(err.reject_kind(), RejectKind::CommandReject);
}

/// A malformed structured field after a Query keeps the query request; the WSF is
/// reported as COMMAND-REJECT.
#[test]
fn malformed_structured_field_keeps_earlier_query() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    // Query (00 05 01 FF 02), then a field with length 2 (too small)
    let res = DataStreamParser::process(
        &[0xF3, 0x00, 0x05, 0x01, 0xFF, 0x02, 0x00, 0x02, 0x03],
        &mut ps,
    );
    assert_eq!(
        res.read_partition,
        vec![ReadPartitionRequest::Query(
            bastion3270_core::wsf::QueryRequest::QueryAll
        )]
    );
    let err = res.rejected.expect("malformed field must be reported");
    assert_eq!(err.reject_kind(), RejectKind::CommandReject);

    // A single trailing byte after the query
    let res = DataStreamParser::process(&[0xF3, 0x00, 0x05, 0x01, 0xFF, 0x02, 0x07], &mut ps);
    assert_eq!(res.read_partition.len(), 1);
    assert!(matches!(
        res.rejected,
        Some(DatastreamError::InvalidStructuredFieldLength { .. })
    ));
}

/// An error inside one structured field does not stop the following fields
/// (x3270 `write_structured_field()` continues after a per-field error).
#[test]
fn error_inside_outbound_3270ds_does_not_stop_following_fields() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let res = DataStreamParser::process(
        &[
            0xF3, // WSF
            0x00, 0x09, 0x40, 0x00, 0xF1, 0xC2, 0x11, 0x7F, 0x7F, // Outbound DS: W, bad SBA
            0x00, 0x05, 0x01, 0xFF, 0x02, // Query
        ],
        &mut ps,
    );
    assert!(res.rejected.is_some());
    assert!(
        res.restore_keyboard,
        "WCC of the aborted write still applies"
    );
    assert_eq!(
        res.read_partition.len(),
        1,
        "query after the bad field still requested"
    );
}

/// In TN3270E mode a record with a short header, an unknown data type or an invalid BIND
/// image is discarded; the state machine keeps working.
#[test]
fn malformed_tn3270e_records_are_discarded_not_fatal() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
    // DO TN3270E, SEND DEVICE-TYPE, DEVICE-TYPE IS, FUNCTIONS IS (no BIND-IMAGE)
    let handshake = [
        IAC, 0xFD, 0x28, IAC, 0xFA, 0x28, 0x08, 0x02, IAC, 0xF0, IAC, 0xFA, 0x28, 0x02, 0x04, 0x00,
        IAC, 0xF0, IAC, 0xFA, 0x28, 0x03, 0x04, 0x02, IAC, 0xF0,
    ];
    sm.process_inbound(&handshake).unwrap();
    assert!(sm.is_tn3270e());

    let short = sm.process_inbound(&[0x00, 0x00, IAC, EOR]).unwrap();
    assert!(matches!(
        short.as_slice(),
        [TelnetEvent::RecordDiscarded(
            TelnetError::TruncatedHeader { .. }
        )]
    ));

    let unknown = sm
        .process_inbound(&[0x0A, 0x00, 0x00, 0x00, 0x01, 0xF5, IAC, EOR])
        .unwrap();
    assert_eq!(
        unknown,
        vec![TelnetEvent::RecordDiscarded(TelnetError::InvalidDataType(
            0x0A
        ))]
    );

    let bad_bind = sm
        .process_inbound(&[0x03, 0x00, 0x00, 0x00, 0x01, 0x99, IAC, EOR])
        .unwrap();
    assert!(matches!(
        bad_bind.as_slice(),
        [TelnetEvent::RecordDiscarded(_)]
    ));

    // A valid 3270-DATA record is still delivered afterwards
    let ok = sm
        .process_inbound(&[0x00, 0x00, 0x00, 0x00, 0x02, 0xF5, 0xC3, IAC, EOR])
        .unwrap();
    assert!(matches!(ok.as_slice(), [TelnetEvent::Tn3270eRecord { .. }]));
}
