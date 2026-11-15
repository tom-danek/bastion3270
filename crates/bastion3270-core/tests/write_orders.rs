//! Write order semantics (Program Tab, extended attributes, Erase All Unprotected, writes
//! inside Outbound 3270DS), checked against `x3270` `ctlr.c` (`ctlr_write`,
//! `ctlr_erase_all_unprotected`, `next_unprotected`) and `sf.c` (`sf_outbound_ds`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use bastion3270_core::datastream::response::AID_NO;
use bastion3270_core::datastream::{build_read_buffer_with_aid, DataStreamParser};
use bastion3270_core::ebcdic::CP037;
use bastion3270_core::{
    BufferAddress, CharacterSet, Color3270, Highlight3270, PresentationSpace, TerminalModel,
};

const W: u8 = 0xF1;
const EW: u8 = 0xF5;
const EWA: u8 = 0x7E;
const SF: u8 = 0x1D;
const SFE: u8 = 0x29;
const SA: u8 = 0x28;
const MF: u8 = 0x2C;
const SBA: u8 = 0x11;
const PT: u8 = 0x05;
const DUP: u8 = 0x1C;
const XA_ALL: u8 = 0x00;
const XA_3270: u8 = 0xC0;
const XA_HIGHLIGHTING: u8 = 0x41;
const XA_FOREGROUND: u8 = 0x42;
const XA_CHARSET: u8 = 0x43;
/// Protected field attribute byte.
const FA_PROT: u8 = 0x60;
/// Unprotected field attribute byte.
const FA_UNPROT: u8 = 0x40;

fn sba(addr: usize) -> [u8; 3] {
    let [a, b] = BufferAddress::new(addr, 1920)
        .unwrap()
        .encode_12bit()
        .unwrap();
    [SBA, a, b]
}

/// Concatenates byte slices into one record.
fn record(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn run(ps: &mut PresentationSpace, stream: &[u8]) {
    let res = DataStreamParser::process(stream, ps);
    assert_eq!(res.rejected, None, "{stream:02X?}");
}

fn byte_at(ps: &PresentationSpace, addr: usize) -> u8 {
    ps.cell(BufferAddress::new(addr, ps.capacity()).unwrap())
        .unwrap()
        .raw_ebcdic()
}

fn fill(ps: &mut PresentationSpace, range: std::ops::Range<usize>, byte: u8) {
    let mut data = Vec::new();
    for addr in range {
        data.extend_from_slice(&sba(addr));
        data.push(byte);
    }
    let mut stream = vec![W, 0x00];
    stream.extend_from_slice(&data);
    run(ps, &stream);
}

/// Protected fields at 0 and 10, unprotected field at 20; every data cell holds 'X'.
fn three_fields() -> PresentationSpace {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    run(
        &mut ps,
        &record(&[
            &[EW, 0x00, SF, FA_PROT],
            &sba(10),
            &[SF, FA_PROT],
            &sba(20),
            &[SF, FA_UNPROT],
        ]),
    );
    fill(&mut ps, 1..10, 0xE7);
    fill(&mut ps, 11..20, 0xE7);
    fill(&mut ps, 21..40, 0xE7);
    ps
}

#[test]
fn program_tab_after_data_nulls_only_the_rest_of_the_current_field() {
    // Data at 2 in the first protected field, then PT to the unprotected field at 20.
    let mut ps = three_fields();
    run(&mut ps, &record(&[&[W, 0x00], &sba(2), &[0xC1, PT]]));
    assert_eq!(byte_at(&ps, 2), 0xC1);
    for addr in 3..10 {
        assert_eq!(byte_at(&ps, addr), 0x00, "cell {addr} of the current field");
    }
    // The second protected field is not touched.
    for addr in 11..20 {
        assert_eq!(byte_at(&ps, addr), 0xE7, "cell {addr} beyond the field");
    }
    assert_eq!(ps.buffer_addr().as_usize(), 21);
}

#[test]
fn program_tab_does_not_wrap_past_the_end_of_the_screen() {
    // From 30 (inside the last unprotected field) the next unprotected field is the one at
    // 20 again, which lies before: the tab stops at address 0.
    let mut ps = three_fields();
    run(&mut ps, &record(&[&[W, 0x00], &sba(30), &[PT]]));
    assert_eq!(ps.buffer_addr().as_usize(), 0);
    assert_eq!(byte_at(&ps, 30), 0xE7, "PT after an order does not null");
}

#[test]
fn program_tab_after_a_format_control_order_does_not_null() {
    let mut ps = three_fields();
    run(&mut ps, &record(&[&[W, 0x00], &sba(2), &[DUP, PT]]));
    assert_eq!(byte_at(&ps, 2), DUP);
    assert_eq!(byte_at(&ps, 3), 0xE7);
    assert_eq!(ps.buffer_addr().as_usize(), 21);
}

#[test]
fn a_second_tab_after_a_nulling_tab_that_stopped_at_zero_nulls_again() {
    // Unprotected field at 5 (data 6..39), protected field at 40 (data 41..). Cells 0..4
    // belong to the protected field that wraps around from 40.
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    run(
        &mut ps,
        &record(&[
            &[EW, 0x00],
            &sba(5),
            &[SF, FA_UNPROT],
            &sba(40),
            &[SF, FA_PROT],
        ]),
    );
    fill(&mut ps, 0..5, 0xE7);
    fill(&mut ps, 45..50, 0xE7);

    // 'A' at 45, PT: the next unprotected field (6) lies before 45, so the tab nulls up to
    // the end of the screen and stops at 0; the second PT nulls 0..4 as well.
    run(&mut ps, &record(&[&[W, 0x00], &sba(45), &[0xC1, PT, PT]]));
    assert_eq!(byte_at(&ps, 46), 0x00);
    for addr in 0..5 {
        assert_eq!(byte_at(&ps, addr), 0x00, "cell {addr}");
    }
    assert_eq!(ps.buffer_addr().as_usize(), 6);

    // Without the preceding nulling tab, a PT at 0 does not null.
    fill(&mut ps, 0..5, 0xE7);
    run(&mut ps, &record(&[&[W, 0x00], &sba(0), &[PT]]));
    assert_eq!(byte_at(&ps, 0), 0xE7);
}

#[test]
fn highlighting_flags_combine() {
    // SA reverse video + underscore (X'F6') on 'A'.
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    run(&mut ps, &[EW, 0x00, SA, XA_HIGHLIGHTING, 0xF6, 0xC1]);
    let hl = ps.cell(BufferAddress::ZERO).unwrap().extended().highlight;
    assert!(hl.contains(Highlight3270::REVERSE_VIDEO));
    assert!(hl.contains(Highlight3270::UNDERSCORE));
    assert!(!hl.contains(Highlight3270::BLINK));
    assert_eq!(hl.to_xa_byte(), 0xF6);
}

#[test]
fn sfe_highlighting_drops_intensify() {
    // SFE intensify (X'F8') is not a field highlight in x3270; reverse (X'F2') is.
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    run(
        &mut ps,
        &[
            EW,
            0x00,
            SFE,
            0x02,
            XA_3270,
            FA_UNPROT,
            XA_HIGHLIGHTING,
            0xF8,
            SFE,
            0x02,
            XA_3270,
            FA_UNPROT,
            XA_HIGHLIGHTING,
            0xFA,
        ],
    );
    let first = ps.cell(BufferAddress::ZERO).unwrap().extended().highlight;
    assert!(first.is_default());
    let second = ps
        .cell(BufferAddress::new(1, ps.capacity()).unwrap())
        .unwrap()
        .extended()
        .highlight;
    assert_eq!(second, Highlight3270::REVERSE_VIDEO);
}

#[test]
fn sa_normal_highlighting_inherits_the_field_highlighting() {
    // Field with reverse video; SA X'F0' ("normal") on 'A' means "no own highlighting".
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    run(
        &mut ps,
        &[
            EW,
            0x00,
            SFE,
            0x02,
            XA_3270,
            FA_UNPROT,
            XA_HIGHLIGHTING,
            0xF2,
            SA,
            XA_HIGHLIGHTING,
            0xF0,
            0xC1,
        ],
    );
    let addr = BufferAddress::new(1, ps.capacity()).unwrap();
    assert!(ps.cell(addr).unwrap().extended().highlight.is_default());
    let safe = ps.safe_cell_at(addr, &CP037).unwrap();
    assert_eq!(safe.highlight, Highlight3270::REVERSE_VIDEO);
}

#[test]
fn highlighting_is_read_back_as_flags() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    run(
        &mut ps,
        &[
            EW,
            0x00,
            SFE,
            0x02,
            XA_3270,
            FA_UNPROT,
            XA_HIGHLIGHTING,
            0xF6,
            0xC1,
        ],
    );
    ps.set_reply_mode(bastion3270_core::ReplyMode::ExtendedField);
    let rb = build_read_buffer_with_aid(&ps, AID_NO);
    assert!(
        rb.windows(2).any(|w| w == [XA_HIGHLIGHTING, 0xF6]),
        "{rb:02X?}"
    );
}

#[test]
fn xa_all_is_ignored_in_sfe_and_mf() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    // SFE: foreground red, then XA_ALL — red stays.
    run(
        &mut ps,
        &[
            EW,
            0x00,
            SFE,
            0x03,
            XA_3270,
            FA_UNPROT,
            XA_FOREGROUND,
            0xF2,
            XA_ALL,
            0x00,
        ],
    );
    let fa_cell = |ps: &PresentationSpace| ps.cell(BufferAddress::ZERO).unwrap().extended();
    assert_eq!(fa_cell(&ps).foreground, Color3270::Red);

    // MF on the same field: XA_ALL does not reset it either.
    run(
        &mut ps,
        &record(&[&[W, 0x00], &sba(0), &[MF, 0x01, XA_ALL, 0x00]]),
    );
    assert_eq!(fa_cell(&ps).foreground, Color3270::Red);

    // SA XA_ALL does reset the character attributes.
    run(
        &mut ps,
        &record(&[
            &[W, 0x00],
            &sba(5),
            &[SA, XA_FOREGROUND, 0xF4, SA, XA_ALL, 0x00, 0xC1],
        ]),
    );
    let ch = ps
        .cell(BufferAddress::new(5, ps.capacity()).unwrap())
        .unwrap()
        .extended();
    assert_eq!(ch.foreground, Color3270::Default);
}

#[test]
fn only_f1_and_f8_select_a_special_character_set() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    run(
        &mut ps,
        &[
            EW, 0x00, SA, XA_CHARSET, 0x01, 0xC1, SA, XA_CHARSET, 0x02, 0xC2, SA, XA_CHARSET, 0xF1,
            0xC3, SA, XA_CHARSET, 0xF8, 0xC4,
        ],
    );
    let cs = |addr: usize| {
        ps.cell(BufferAddress::new(addr, ps.capacity()).unwrap())
            .unwrap()
            .extended()
            .charset
    };
    assert_eq!(cs(0), CharacterSet::Base);
    assert_eq!(cs(1), CharacterSet::Base);
    assert_eq!(cs(2), CharacterSet::Apl);
    assert_eq!(cs(3), CharacterSet::Dbcs);

    // A DBCS field needs a DBCS terminal: SFE X'F8' selects the base set here.
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    run(
        &mut ps,
        &[EW, 0x00, SFE, 0x02, XA_3270, FA_UNPROT, XA_CHARSET, 0xF8],
    );
    assert_eq!(
        ps.cell(BufferAddress::ZERO).unwrap().extended().charset,
        CharacterSet::Base
    );
}

#[test]
fn erase_all_unprotected_puts_the_cursor_after_the_first_unprotected_attribute() {
    // Zero-width unprotected field at 10 (protected attribute right after it at 11),
    // unprotected field with data at 20.
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    run(
        &mut ps,
        &record(&[
            &[EW, 0x00],
            &sba(10),
            &[SF, FA_UNPROT, SF, FA_PROT],
            &sba(20),
            &[SF, FA_UNPROT],
        ]),
    );
    run(&mut ps, &[0x6F]); // Erase All Unprotected
    assert_eq!(ps.cursor_addr().as_usize(), 11);
}

#[test]
fn erase_write_inside_outbound_3270ds_keeps_the_current_size() {
    let mut ps = PresentationSpace::new(TerminalModel::Model4);
    run(&mut ps, &[EWA, 0x00]);
    assert!(ps.is_alternate_mode());
    let alt_rows = ps.rows();

    // WSF Outbound 3270DS, partition 0: EW with WCC.
    run(&mut ps, &[0xF3, 0x00, 0x06, 0x40, 0x00, EW, 0x00]);
    assert!(
        ps.is_alternate_mode(),
        "EW inside WSF keeps the alternate size"
    );
    assert_eq!(ps.rows(), alt_rows);

    // ... also without a WCC.
    run(&mut ps, &[0xF3, 0x00, 0x05, 0x40, 0x00, EW]);
    assert!(ps.is_alternate_mode());

    // A plain EW still selects the default size.
    run(&mut ps, &[EW, 0x00]);
    assert!(!ps.is_alternate_mode());
}
