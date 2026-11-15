//! Integration tests for all 9 IBM 3270 Data Stream Commands.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::doc_markdown
)]

use bastion3270_core::address::BufferAddress;
use bastion3270_core::datastream::command::*;
use bastion3270_core::datastream::order::*;
use bastion3270_core::datastream::response::{
    build_read_buffer, build_read_modified, AID_CLEAR, AID_PA1, AID_PA2, AID_PA3,
};
use bastion3270_core::datastream::wcc::*;
use bastion3270_core::datastream::DataStreamParser;
use bastion3270_core::ebcdic::{CodePage, CP037};
use bastion3270_core::field::{ExtendedAttributes, FieldAttribute, FieldIntensity};
use bastion3270_core::model::TerminalModel;
use bastion3270_core::screen::PresentationSpace;

#[test]
fn test_cmd_write_standard_and_sna() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Move cursor to position 100
    ps.set_cursor_addr(BufferAddress::new(100, cap).unwrap())
        .unwrap();

    // Standard local CMD_W (0x01) with WCC (sound alarm 0x04)
    let stream_local = [CMD_W, WCC_SOUND_ALARM_BIT];
    let res = DataStreamParser::parse_and_apply(&stream_local, &mut ps).unwrap();
    assert_eq!(res.command, Command::Write);
    assert!(res.sound_alarm);
    assert!(!res.requires_inbound_reply);
    // Buffer address started at cursor position 100
    assert_eq!(ps.buffer_addr().as_usize(), 100);

    // SNA CMD_W (0xF1) with WCC (restore keyboard 0x02)
    let stream_sna = [SNA_CMD_W, WCC_KEYBOARD_RESTORE_BIT];
    let res_sna = DataStreamParser::parse_and_apply(&stream_sna, &mut ps).unwrap();
    assert_eq!(res_sna.command, Command::Write);
    assert!(res_sna.restore_keyboard);
}

#[test]
fn test_cmd_erase_write_default_dimensions() {
    let mut ps = PresentationSpace::new(TerminalModel::Model4); // Model 4 alternate is 43x80
                                                                // Put screen into alternate mode first
    ps.erase_reset(true);
    assert_eq!(ps.rows(), 43);
    assert_eq!(ps.cols(), 80);

    // Erase/Write (0x05) must reset screen to 24x80 default
    let stream = [CMD_EW, WCC_RESET_MDT_BIT];
    let res = DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();
    assert_eq!(res.command, Command::EraseWrite);
    assert!(res.reset_mdt);
    assert_eq!(ps.rows(), 24);
    assert_eq!(ps.cols(), 80);
    assert_eq!(ps.cursor_addr().as_usize(), 0);
    assert_eq!(ps.buffer_addr().as_usize(), 0);

    // SNA Erase/Write (0xF5)
    let stream_sna = [SNA_CMD_EW, 0x00];
    let res_sna = DataStreamParser::parse_and_apply(&stream_sna, &mut ps).unwrap();
    assert_eq!(res_sna.command, Command::EraseWrite);
}

#[test]
fn test_cmd_erase_write_alternate_dimensions() {
    let mut ps = PresentationSpace::new(TerminalModel::Model4); // 43x80
    assert_eq!(ps.rows(), 24);

    // Erase/Write Alternate (0x0D) transitions to alternate dimensions
    let stream = [CMD_EWA, 0x00];
    let res = DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();
    assert_eq!(res.command, Command::EraseWriteAlternate);
    assert_eq!(ps.rows(), 43);
    assert_eq!(ps.cols(), 80);
    assert_eq!(ps.capacity(), 43 * 80);

    // SNA Erase/Write Alternate (0x7E) on Model 3 (32x80)
    let mut ps3 = PresentationSpace::new(TerminalModel::Model3);
    let stream_sna = [SNA_CMD_EWA, 0x00];
    let res_sna = DataStreamParser::parse_and_apply(&stream_sna, &mut ps3).unwrap();
    assert_eq!(res_sna.command, Command::EraseWriteAlternate);
    assert_eq!(ps3.rows(), 32);
    assert_eq!(ps3.cols(), 80);
}

#[test]
fn test_cmd_erase_all_unprotected() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Protected field at 0: label "NAME:"
    let fa_prot = FieldAttribute::new(true, false, FieldIntensity::NormalNonDetectable, false);
    ps.place_field(
        BufferAddress::new(0, cap).unwrap(),
        fa_prot,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();
    for (i, ch) in "NAME:".chars().enumerate() {
        let ebcdic = CP037.char_to_ebcdic(ch).unwrap();
        ps.write_char(
            BufferAddress::new(1 + i, cap).unwrap(),
            ebcdic,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
    }

    // Unprotected field at 10: value "JOHN" with MDT=1
    let fa_unprot = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, true);
    ps.place_field(
        BufferAddress::new(10, cap).unwrap(),
        fa_unprot,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();
    for (i, ch) in "JOHN".chars().enumerate() {
        let ebcdic = CP037.char_to_ebcdic(ch).unwrap();
        ps.write_char(
            BufferAddress::new(11 + i, cap).unwrap(),
            ebcdic,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
    }

    // Verify MDT is set before EAU
    assert!(ps
        .effective_field_attribute(BufferAddress::new(10, cap).unwrap())
        .is_modified());

    // Execute EAU (0x0F)
    let res = DataStreamParser::parse_and_apply(&[CMD_EAU], &mut ps).unwrap();
    assert_eq!(res.command, Command::EraseAllUnprotected);
    assert!(res.reset_mdt);

    // Protected label "NAME:" must be unchanged
    for (i, ch) in "NAME:".chars().enumerate() {
        let expected = CP037.char_to_ebcdic(ch).unwrap();
        assert_eq!(
            ps.cell(BufferAddress::new(1 + i, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            expected
        );
    }

    // Unprotected data "JOHN" must be cleared to 0x00
    for i in 0..4 {
        assert_eq!(
            ps.cell(BufferAddress::new(11 + i, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            0x00
        );
    }

    // Unprotected field MDT must be reset to 0
    assert!(!ps
        .effective_field_attribute(BufferAddress::new(10, cap).unwrap())
        .is_modified());

    // Cursor should be relocated to first unprotected data position (cell 11)
    assert_eq!(ps.cursor_addr().as_usize(), 11);

    // SNA opcode CMD_EAU (0x6F)
    let res_sna = DataStreamParser::parse_and_apply(&[SNA_CMD_EAU], &mut ps).unwrap();
    assert_eq!(res_sna.command, Command::EraseAllUnprotected);
}

#[test]
fn test_cmd_read_buffer() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Standard CMD_RB (0x02)
    let res = DataStreamParser::parse_and_apply(&[CMD_RB], &mut ps).unwrap();
    assert_eq!(res.command, Command::ReadBuffer);
    assert!(res.requires_inbound_reply);

    // SNA CMD_RB (0xF2)
    let res_sna = DataStreamParser::parse_and_apply(&[SNA_CMD_RB], &mut ps).unwrap();
    assert_eq!(res_sna.command, Command::ReadBuffer);
    assert!(res_sna.requires_inbound_reply);

    // Response stream generation
    let stream = build_read_buffer(&ps);
    assert_eq!(stream[0], 0x60); // AID_NO
    assert_eq!(stream.len(), cap + 3);
}

#[test]
fn test_cmd_read_modified_and_short_read() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Standard CMD_RM (0x06) and SNA CMD_RM (0xF6)
    let res = DataStreamParser::parse_and_apply(&[CMD_RM], &mut ps).unwrap();
    assert_eq!(res.command, Command::ReadModified);
    assert!(res.requires_inbound_reply);

    let res_sna = DataStreamParser::parse_and_apply(&[SNA_CMD_RM], &mut ps).unwrap();
    assert_eq!(res_sna.command, Command::ReadModified);
    assert!(res_sna.requires_inbound_reply);

    // Setup a modified field
    let fa = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, true);
    ps.place_field(
        BufferAddress::new(5, cap).unwrap(),
        fa,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();
    let ebcdic_v = CP037.char_to_ebcdic('V').unwrap();
    ps.write_char(
        BufferAddress::new(6, cap).unwrap(),
        ebcdic_v,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();

    // Normal AID (Enter = 0x7D): returns AID + cursor + SBA + data
    let stream_enter = build_read_modified(&ps, 0x7D, false);
    assert_eq!(stream_enter[0], 0x7D);
    assert_eq!(stream_enter[3], ORDER_SBA);
    assert_eq!(stream_enter[6], ebcdic_v);

    // Short-read AIDs: Clear, PA1, PA2, PA3 emit exactly 1 byte
    assert_eq!(build_read_modified(&ps, AID_CLEAR, false), vec![AID_CLEAR]);
    assert_eq!(build_read_modified(&ps, AID_PA1, false), vec![AID_PA1]);
    assert_eq!(build_read_modified(&ps, AID_PA2, false), vec![AID_PA2]);
    assert_eq!(build_read_modified(&ps, AID_PA3, false), vec![AID_PA3]);
}

#[test]
fn test_cmd_read_modified_all() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Standard CMD_RMA (0x0E) and SNA CMD_RMA (0x6E)
    let res = DataStreamParser::parse_and_apply(&[CMD_RMA], &mut ps).unwrap();
    assert_eq!(res.command, Command::ReadModifiedAll);
    assert!(res.requires_inbound_reply);

    let res_sna = DataStreamParser::parse_and_apply(&[SNA_CMD_RMA], &mut ps).unwrap();
    assert_eq!(res_sna.command, Command::ReadModifiedAll);
    assert!(res_sna.requires_inbound_reply);

    // Setup unmodified field (MDT=0)
    let fa = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false);
    ps.place_field(
        BufferAddress::new(5, cap).unwrap(),
        fa,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();
    let ebcdic_w = CP037.char_to_ebcdic('W').unwrap();
    ps.write_char(
        BufferAddress::new(6, cap).unwrap(),
        ebcdic_w,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();

    // Read Modified All still sends only modified fields (x3270 `ctlr_read_modified`): with an
    // ordinary AID it equals Read Modified ...
    let stream_rma = build_read_modified(&ps, 0x7D, true);
    assert_eq!(stream_rma, build_read_modified(&ps, 0x7D, false));
    assert_eq!(
        stream_rma.len(),
        3,
        "AID + cursor, the unmodified field is not sent"
    );

    // ... and differs only for a short-read AID, which RMA reads in full.
    assert_eq!(build_read_modified(&ps, 0x6C, false), vec![0x6C]);
    assert_eq!(build_read_modified(&ps, 0x6C, true).len(), 3);
    let _ = ebcdic_w;
}

#[test]
fn test_cmd_write_structured_field() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // WSF with SF_READ_PART (0x01) query: length=5, id=0x01, part=0xFF, type=0x02
    let stream = [CMD_WSF, 0x00, 0x05, 0x01, 0xFF, 0x02];
    let res = DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();
    assert_eq!(res.command, Command::WriteStructuredField);
    assert!(res.requires_inbound_reply);

    // Truncated Read Partition without a type byte is rejected (x3270 `sf_read_part`).
    let stream_truncated = [CMD_WSF, 0x00, 0x04, 0x01, 0xFF];
    let res_truncated = DataStreamParser::process(&stream_truncated, &mut ps);
    assert!(!res_truncated.requires_inbound_reply);
    assert_eq!(
        res_truncated.rejected.map(|e| e.reject_kind()),
        Some(bastion3270_core::datastream::RejectKind::CommandReject)
    );

    // Erase/Reset without its type byte is rejected too (x3270 `sf_erase_reset`).
    let stream_other = [SNA_CMD_WSF, 0x00, 0x03, 0x03];
    let res_other = DataStreamParser::process(&stream_other, &mut ps);
    assert_eq!(res_other.command, Command::WriteStructuredField);
    assert!(!res_other.requires_inbound_reply);
    assert!(res_other.rejected.is_some());

    // WSF with length=0 (extends to end of stream)
    let stream_zero_len = [CMD_WSF, 0x00, 0x00, 0x01, 0xFF, 0x02];
    let res_zero = DataStreamParser::parse_and_apply(&stream_zero_len, &mut ps).unwrap();
    assert_eq!(res_zero.command, Command::WriteStructuredField);
    assert!(res_zero.requires_inbound_reply);
}

#[test]
fn test_cmd_noop() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cur_before = ps.cursor_addr();

    let res = DataStreamParser::parse_and_apply(&[CMD_NOP], &mut ps).unwrap();
    assert_eq!(res.command, Command::NoOp);
    assert!(!res.sound_alarm);
    assert!(!res.restore_keyboard);
    assert!(!res.reset_mdt);
    assert!(!res.requires_inbound_reply);
    assert_eq!(ps.cursor_addr(), cur_before);
}
