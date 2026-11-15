//! Integration tests for all 10 IBM 3270 Data Stream Orders.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::doc_markdown
)]

use bastion3270_core::address::BufferAddress;
use bastion3270_core::datastream::command::*;
use bastion3270_core::datastream::order::*;
use bastion3270_core::datastream::DataStreamParser;
use bastion3270_core::ebcdic::{CodePage, CP037};
use bastion3270_core::field::{
    CharacterSet, Color3270, ExtendedAttributes, FieldAttribute, FieldIntensity, Highlight3270,
    XA_3270, XA_ALL, XA_CHARSET, XA_FOREGROUND, XA_HIGHLIGHTING,
};
use bastion3270_core::model::TerminalModel;
use bastion3270_core::screen::PresentationSpace;

#[test]
fn test_order_sf_start_field() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Stream: EW + WCC(0) + SF(wire byte 0x60 -> protected, normal)
    let stream = [CMD_EW, 0x00, ORDER_SF, 0x60];
    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    let cell0 = ps.cell(BufferAddress::new(0, cap).unwrap()).unwrap();
    assert!(cell0.is_field_attribute());
    let fa = cell0.field_attribute().unwrap();
    assert!(fa.is_protected());
    assert!(!fa.is_intensified());
    assert!(!fa.is_modified());
    // Buffer address advanced to 1
    assert_eq!(ps.buffer_addr().as_usize(), 1);
}

#[test]
fn test_order_sfe_start_field_extended() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // SFE with 4 pairs:
    // 1. XA_3270 (0xC0): 0x48 (unprotected, intensified)
    // 2. XA_FOREGROUND (0x42): 0xF4 (Green)
    // 3. XA_HIGHLIGHTING (0x41): 0xF4 (Underline)
    // 4. XA_CHARSET (0x43): 0xF1 (Apl)
    let stream = [
        CMD_EW,
        0x00,
        ORDER_SFE,
        0x04,
        XA_3270,
        0x48,
        XA_FOREGROUND,
        0xF4,
        XA_HIGHLIGHTING,
        0xF4,
        XA_CHARSET,
        0xF1,
    ];
    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    let cell0 = ps.cell(BufferAddress::new(0, cap).unwrap()).unwrap();
    assert!(cell0.is_field_attribute());
    let fa = cell0.field_attribute().unwrap();
    assert!(!fa.is_protected());
    assert!(fa.is_intensified());

    let ext = cell0.extended();
    assert_eq!(ext.foreground, Color3270::Green);
    assert_eq!(ext.highlight, Highlight3270::UNDERSCORE);
    assert_eq!(ext.charset, CharacterSet::Apl);
    assert_eq!(ps.buffer_addr().as_usize(), 1);
}

#[test]
fn test_order_sba_12bit_and_14bit() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // 12-bit coded address 80 (Row 1, Col 0): [0x41, 0x50]
    let [c1_12, c2_12] = BufferAddress::new(80, cap).unwrap().encode_12bit().unwrap();
    let stream_12 = [CMD_W, 0x00, ORDER_SBA, c1_12, c2_12];
    DataStreamParser::parse_and_apply(&stream_12, &mut ps).unwrap();
    assert_eq!(ps.buffer_addr().as_usize(), 80);

    // 14-bit binary address 160 (Row 2, Col 0): [0x00, 0xA0]
    let [c1_14, c2_14] = BufferAddress::new(160, cap)
        .unwrap()
        .encode_14bit()
        .unwrap();
    let stream_14 = [CMD_W, 0x00, ORDER_SBA, c1_14, c2_14];
    DataStreamParser::parse_and_apply(&stream_14, &mut ps).unwrap();
    assert_eq!(ps.buffer_addr().as_usize(), 160);
}

#[test]
fn test_order_sa_running_attributes() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // SA(XA_FOREGROUND, Red: 0xF2) + text('A') + SA(XA_ALL, 0) + text('B')
    let stream = [
        CMD_EW,
        0x00,
        ORDER_SA,
        XA_FOREGROUND,
        0xF2, // Red
        CP037.char_to_ebcdic('A').unwrap(),
        ORDER_SA,
        XA_ALL,
        0x00, // Reset to default
        CP037.char_to_ebcdic('B').unwrap(),
    ];
    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    let cell0 = ps.cell(BufferAddress::new(0, cap).unwrap()).unwrap();
    assert_eq!(cell0.raw_ebcdic(), CP037.char_to_ebcdic('A').unwrap());
    assert_eq!(cell0.extended().foreground, Color3270::Red);

    let cell1 = ps.cell(BufferAddress::new(1, cap).unwrap()).unwrap();
    assert_eq!(cell1.raw_ebcdic(), CP037.char_to_ebcdic('B').unwrap());
    assert_eq!(cell1.extended().foreground, Color3270::Default);
}

#[test]
fn test_order_ic_insert_cursor_last_wins() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Stream with two ICs: SBA(10) + IC + SBA(50) + IC
    let [sba10_1, sba10_2] = BufferAddress::new(10, cap).unwrap().encode_12bit().unwrap();
    let [sba50_1, sba50_2] = BufferAddress::new(50, cap).unwrap().encode_12bit().unwrap();

    let stream = [
        CMD_EW, 0x00, ORDER_SBA, sba10_1, sba10_2, ORDER_IC, ORDER_SBA, sba50_1, sba50_2, ORDER_IC,
    ];
    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    // Last IC at address 50 wins
    assert_eq!(ps.cursor_addr().as_usize(), 50);
}

#[test]
fn test_order_pt_without_preceding_data() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Field 1 at 0: protected
    ps.place_field(
        BufferAddress::new(0, cap).unwrap(),
        FieldAttribute::new(true, false, FieldIntensity::NormalNonDetectable, false),
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();

    // Field 2 at 20: unprotected
    ps.place_field(
        BufferAddress::new(20, cap).unwrap(),
        FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false),
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();

    // SBA 5 (inside Field 1, no data preceding) + PT
    let [sba1, sba2] = BufferAddress::new(5, cap).unwrap().encode_12bit().unwrap();
    let stream = [CMD_W, 0x00, ORDER_SBA, sba1, sba2, ORDER_PT];
    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    // Jumps directly to first data cell of Field 2 (cell 21) without modifying cells
    assert_eq!(ps.buffer_addr().as_usize(), 21);
}

#[test]
fn test_order_ra_repeat_character_and_ge() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // 1. RA normal character: SBA 0 + RA 10 with 'K'
    let [sba0_1, sba0_2] = BufferAddress::new(0, cap).unwrap().encode_12bit().unwrap();
    let [ra10_1, ra10_2] = BufferAddress::new(10, cap).unwrap().encode_12bit().unwrap();
    let ebcdic_k = CP037.char_to_ebcdic('K').unwrap();

    let stream = [
        CMD_EW, 0x00, ORDER_SBA, sba0_1, sba0_2, ORDER_RA, ra10_1, ra10_2, ebcdic_k,
    ];
    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    for i in 0..10 {
        assert_eq!(
            ps.cell(BufferAddress::new(i, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            ebcdic_k
        );
    }
    assert_eq!(ps.buffer_addr().as_usize(), 10);

    // 2. RA with Graphic Escape: RA 20 with GE + 'M'
    let [ra20_1, ra20_2] = BufferAddress::new(20, cap).unwrap().encode_12bit().unwrap();
    let ebcdic_m = CP037.char_to_ebcdic('M').unwrap();

    let stream_ge = [CMD_W, 0x00, ORDER_RA, ra20_1, ra20_2, ORDER_GE, ebcdic_m];
    DataStreamParser::parse_and_apply(&stream_ge, &mut ps).unwrap();

    for i in 10..20 {
        let cell = ps.cell(BufferAddress::new(i, cap).unwrap()).unwrap();
        assert_eq!(cell.raw_ebcdic(), ebcdic_m);
        assert_eq!(cell.extended().charset, CharacterSet::Apl);
    }
    assert_eq!(ps.buffer_addr().as_usize(), 20);
}

#[test]
fn test_order_eua_erase_unprotected_to_address() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    let ebcdic_z = CP037.char_to_ebcdic('Z').unwrap();

    // Fill cells 0..30 with 'Z'
    for i in 0..30 {
        ps.write_char(
            BufferAddress::new(i, cap).unwrap(),
            ebcdic_z,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
    }

    // Protected field at 0..9, unprotected field at 10..29
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

    // SBA 0 + EUA to 30
    let [sba1, sba2] = BufferAddress::new(0, cap).unwrap().encode_12bit().unwrap();
    let [eua1, eua2] = BufferAddress::new(30, cap).unwrap().encode_12bit().unwrap();
    let stream = [CMD_W, 0x00, ORDER_SBA, sba1, sba2, ORDER_EUA, eua1, eua2];
    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    // Cells 1..9 (protected) are still 'Z'
    for i in 1..10 {
        assert_eq!(
            ps.cell(BufferAddress::new(i, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            ebcdic_z
        );
    }
    // Cell 10 is field attribute marker, untouched
    assert!(ps
        .cell(BufferAddress::new(10, cap).unwrap())
        .unwrap()
        .is_field_attribute());
    // Cells 11..29 (unprotected) are erased to 0x00
    for i in 11..30 {
        assert_eq!(
            ps.cell(BufferAddress::new(i, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            0x00
        );
    }
    assert_eq!(ps.buffer_addr().as_usize(), 30);
}

/// `x3270` `ctlr_write` `ORDER_EUA` erases with `ctlr_add(baddr, EBC_null, CS_BASE)`: the
/// character and its character set go, the colour and highlighting of the cell stay (as for
/// Erase All Unprotected).
#[test]
fn test_order_eua_keeps_colour_and_highlighting() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();
    let a = CP037.char_to_ebcdic('A').unwrap();

    // EW, SF unprotected at 0, SA red + reverse + APL, 'A' at 1..=3, SBA 1, EUA to 4.
    let [sba1, sba2] = BufferAddress::new(1, cap).unwrap().encode_12bit().unwrap();
    let [eua1, eua2] = BufferAddress::new(4, cap).unwrap().encode_12bit().unwrap();
    let stream = [
        CMD_EW,
        0x00,
        ORDER_SF,
        0x40,
        ORDER_SA,
        XA_FOREGROUND,
        0xF2,
        ORDER_SA,
        XA_HIGHLIGHTING,
        0xF2,
        ORDER_SA,
        XA_CHARSET,
        0xF1,
        a,
        a,
        a,
        ORDER_SBA,
        sba1,
        sba2,
        ORDER_EUA,
        eua1,
        eua2,
    ];
    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    for i in 1..=3 {
        let cell = ps.cell(BufferAddress::new(i, cap).unwrap()).unwrap();
        assert_eq!(cell.raw_ebcdic(), 0x00, "cell {i} erased");
        let xa = cell.extended();
        assert_eq!(xa.foreground, Color3270::Red, "cell {i} keeps its colour");
        assert_eq!(
            xa.highlight,
            Highlight3270::REVERSE_VIDEO,
            "cell {i} keeps its highlighting"
        );
        assert_eq!(
            xa.charset,
            CharacterSet::Base,
            "cell {i} back to the base character set"
        );
    }
}

#[test]
fn test_order_ge_single_graphic_escape() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    let ebcdic_box = CP037.char_to_ebcdic('Q').unwrap();
    let stream = [CMD_EW, 0x00, ORDER_GE, ebcdic_box];
    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    let cell0 = ps.cell(BufferAddress::new(0, cap).unwrap()).unwrap();
    assert_eq!(cell0.raw_ebcdic(), ebcdic_box);
    assert_eq!(cell0.extended().charset, CharacterSet::Apl);
    assert_eq!(ps.buffer_addr().as_usize(), 1);
}

#[test]
fn test_order_mf_modify_field() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Place an initial field at address 10 (protected, normal)
    let fa_init = FieldAttribute::new(true, false, FieldIntensity::NormalNonDetectable, false);
    ps.place_field(
        BufferAddress::new(10, cap).unwrap(),
        fa_init,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();

    // SBA 10 + MF with 2 pairs:
    // 1. XA_3270: 0x48 (unprotected, intensified)
    // 2. XA_FOREGROUND: 0xF3 (Pink)
    let [sba1, sba2] = BufferAddress::new(10, cap).unwrap().encode_12bit().unwrap();
    let stream = [
        CMD_W,
        0x00,
        ORDER_SBA,
        sba1,
        sba2,
        ORDER_MF,
        0x02,
        XA_3270,
        0x48,
        XA_FOREGROUND,
        0xF3,
    ];
    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    let cell10 = ps.cell(BufferAddress::new(10, cap).unwrap()).unwrap();
    assert!(cell10.is_field_attribute());
    let fa = cell10.field_attribute().unwrap();
    assert!(!fa.is_protected());
    assert!(fa.is_intensified());
    assert_eq!(cell10.extended().foreground, Color3270::Pink);
    assert_eq!(ps.buffer_addr().as_usize(), 11);
}
