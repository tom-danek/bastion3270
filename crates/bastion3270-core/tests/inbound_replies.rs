//! Inbound replies (Read Buffer, Read Modified, AID records), checked against `x3270`
//! `ctlr.c` (`process_ds`, `ctlr_read_buffer`, `ctlr_read_modified`, `ctlr_write`) and
//! `sf.c` (`sf_set_reply_mode`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use bastion3270_core::datastream::response::AID_NO;
use bastion3270_core::datastream::{
    build_read_buffer_with_aid, build_read_modified, DataStreamParser, RejectKind,
};
use bastion3270_core::{AidKey, PresentationSpace, ReplyMode, TerminalModel, VirtualKeyboard};

const SF: u8 = 0x1D;
const SFE: u8 = 0x29;
const SA: u8 = 0x28;
const GE: u8 = 0x08;
const SBA: u8 = 0x11;

fn screen(stream: &[u8]) -> PresentationSpace {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let res = DataStreamParser::process(stream, &mut ps);
    assert_eq!(res.rejected, None);
    ps
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// WSF Set Reply Mode for the implicit partition.
fn set_reply_mode(ps: &mut PresentationSpace, mode_and_attrs: &[u8]) -> Option<RejectKind> {
    let len = u16::try_from(mode_and_attrs.len() + 4)
        .unwrap()
        .to_be_bytes();
    let mut wsf = vec![0xF3, len[0], len[1], 0x09, 0x00];
    wsf.extend_from_slice(mode_and_attrs);
    DataStreamParser::process(&wsf, ps)
        .rejected
        .map(|e| e.reject_kind())
}

#[test]
fn host_reads_carry_the_current_aid() {
    // EW, one modified unprotected field (attr 0x01 = MDT) holding "A".
    let mut ps = screen(&[0xF5, 0xC3, SF, 0x01, 0xC1]);
    let mut kb = VirtualKeyboard::new();
    assert_eq!(kb.current_aid(), AID_NO);

    kb.press_aid(&mut ps, AidKey::PF3).unwrap();
    assert_eq!(kb.current_aid(), 0xF3);
    // A host Read Modified now answers with PF3, not 0x60.
    assert_eq!(build_read_modified(&ps, kb.current_aid(), false)[0], 0xF3);

    // The host restores the keyboard: back to "no AID".
    kb.host_write(true);
    assert_eq!(kb.current_aid(), AID_NO);

    // After PA1 a host Read Modified is a short read; Read Modified All is not.
    kb.press_aid(&mut ps, AidKey::PA1).unwrap();
    assert_eq!(
        build_read_modified(&ps, kb.current_aid(), false),
        vec![0x6C]
    );
    assert!(build_read_modified(&ps, kb.current_aid(), true).len() > 1);
}

#[test]
fn read_modified_all_sends_only_modified_fields() {
    // Unmodified field "A", modified field "B".
    let ps = screen(&[0xF5, 0xC3, SF, 0x00, 0xC1, SF, 0x01, 0xC2]);
    let rma = build_read_modified(&ps, 0x7D, true);
    assert_eq!(rma, build_read_modified(&ps, 0x7D, false));
    assert!(contains(&rma, &[0xC2]));
    assert!(
        !contains(&rma, &[0xC1]),
        "unmodified field must not be read"
    );
}

#[test]
fn ge_characters_are_read_back_with_the_ge_prefix() {
    // Modified field: GE 0xC5 (APL), then a base 'A'.
    let ps = screen(&[0xF5, 0xC3, SF, 0x01, GE, 0xC5, 0xC1]);
    let rm = build_read_modified(&ps, 0x7D, false);
    assert!(contains(&rm, &[SBA]));
    assert!(contains(&rm, &[GE, 0xC5, 0xC1]), "{rm:02X?}");

    let rb = build_read_buffer_with_aid(&ps, AID_NO);
    assert!(contains(&rb, &[GE, 0xC5, 0xC1]), "{rb:02X?}");
}

#[test]
fn characters_of_an_apl_field_are_read_back_with_ge() {
    // SFE: modified unprotected field with character set APL (0x43 = 0xF1), data 0xC5.
    let ps = screen(&[0xF5, 0xC3, SFE, 0x02, 0xC0, 0x01, 0x43, 0xF1, 0xC5]);
    let rb = build_read_buffer_with_aid(&ps, AID_NO);
    assert!(contains(&rb, &[GE, 0xC5]), "{rb:02X?}");
}

#[test]
fn extended_field_mode_reads_fields_as_sfe() {
    // SFE: unprotected field, foreground red; data 'A'.
    let mut ps = screen(&[0xF5, 0xC3, SFE, 0x02, 0xC0, 0x00, 0x42, 0xF2, 0xC1]);
    let fa = ps
        .cell(bastion3270_core::BufferAddress::ZERO)
        .unwrap()
        .field_attribute()
        .unwrap()
        .to_wire_byte();

    // Field mode: plain SF.
    let rb = build_read_buffer_with_aid(&ps, AID_NO);
    assert_eq!(&rb[3..6], &[SF, fa, 0xC1]);

    assert_eq!(set_reply_mode(&mut ps, &[0x01]), None);
    assert_eq!(ps.reply_mode(), ReplyMode::ExtendedField);
    let rb = build_read_buffer_with_aid(&ps, AID_NO);
    assert_eq!(&rb[3..10], &[SFE, 0x02, 0xC0, fa, 0x42, 0xF2, 0xC1]);
}

#[test]
fn character_mode_reports_listed_attributes_with_sa() {
    // Modified field (red via SFE), 'A' inheriting red, then SA green 'B'.
    let mut ps = screen(&[
        0xF5, 0xC3, SFE, 0x02, 0xC0, 0x01, 0x42, 0xF2, 0xC1, SA, 0x42, 0xF4, 0xC2,
    ]);
    // Character mode reporting foreground only.
    assert_eq!(set_reply_mode(&mut ps, &[0x02, 0x42]), None);

    // Read Modified: characters inherit the field colour.
    let rm = build_read_modified(&ps, 0x7D, false);
    assert!(
        contains(&rm, &[SA, 0x42, 0xF2, 0xC1, SA, 0x42, 0xF4, 0xC2]),
        "{rm:02X?}"
    );

    // Read Buffer: SFE for the field, SA for colour changes between characters.
    let rb = build_read_buffer_with_aid(&ps, AID_NO);
    assert_eq!(rb[3], SFE);
    assert!(contains(&rb, &[SA, 0x42, 0xF4, 0xC2]), "{rb:02X?}");
}

#[test]
fn erase_write_with_wcc_reset_returns_to_field_mode() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    assert_eq!(set_reply_mode(&mut ps, &[0x01]), None);

    // A plain Write with WCC reset keeps the mode ...
    DataStreamParser::process(&[0xF1, 0x40], &mut ps);
    assert_eq!(ps.reply_mode(), ReplyMode::ExtendedField);
    // ... an Erase/Write without WCC reset too ...
    DataStreamParser::process(&[0xF5, 0x00], &mut ps);
    assert_eq!(ps.reply_mode(), ReplyMode::ExtendedField);
    // ... Erase/Write with WCC reset resets it.
    DataStreamParser::process(&[0xF5, 0x40], &mut ps);
    assert_eq!(ps.reply_mode(), ReplyMode::Field);
}

#[test]
fn invalid_set_reply_mode_is_rejected() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    assert_eq!(
        set_reply_mode(&mut ps, &[0x07]),
        Some(RejectKind::CommandReject)
    );
    // Partition 1 does not exist.
    let res = DataStreamParser::process(&[0xF3, 0x00, 0x05, 0x09, 0x01, 0x01], &mut ps);
    assert_eq!(
        res.rejected.map(|e| e.reject_kind()),
        Some(RejectKind::CommandReject)
    );
    assert_eq!(ps.reply_mode(), ReplyMode::Field);
}

#[test]
fn writes_inside_a_wsf_count_as_host_writes() {
    // WSF Outbound 3270DS (0x40) for partition 0: Write with WCC keyboard restore.
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let res = DataStreamParser::process(&[0xF3, 0x00, 0x06, 0x40, 0x00, 0xF1, 0xC2], &mut ps);
    assert!(res.screen_written);
    assert!(res.restore_keyboard);

    // Erase All Unprotected always restores the keyboard.
    let res = DataStreamParser::process(&[0x6F], &mut ps);
    assert!(res.screen_written);
    assert!(res.restore_keyboard);
}
