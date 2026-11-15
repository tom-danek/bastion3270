//! Adversarial Stress and Fuzz Verification Suite for IBM 3270 Parser and SafeScreenView.
//!
//! Covers:
//! 1. Malformed inputs (empty streams, truncated orders, addresses >= capacity, unknown opcodes/orders).
//! 2. Extreme boundary conditions (full screen RA wrap, EUA across entire buffer, multiple ICs, PT behavior).
//! 3. Deterministic pseudo-random fuzzing to prove panic-freedom.
//! 4. Zero-Trust SafeScreenView invariant and boundary enforcement.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::manual_is_multiple_of
)]

use bastion3270_core::address::{AddressError, BufferAddress};
use bastion3270_core::datastream::command::*;
use bastion3270_core::datastream::order::*;
use bastion3270_core::datastream::{DataStreamParser, DatastreamError};
use bastion3270_core::ebcdic::{CodePage, CP037};
use bastion3270_core::field::{CharacterSet, ExtendedAttributes, FieldAttribute, FieldIntensity};
use bastion3270_core::model::TerminalModel;
use bastion3270_core::safe_view::{SafeCell, SafeScreenView, SafeViewError};
use bastion3270_core::screen::PresentationSpace;

// ============================================================================
// 1. MALFORMED INPUTS & ROBUSTNESS TESTS
// ============================================================================

#[test]
fn test_adversarial_empty_and_minimal_streams() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Completely empty stream must error with EmptyStream
    assert_eq!(
        DataStreamParser::parse_and_apply(&[], &mut ps),
        Err(DatastreamError::EmptyStream)
    );

    // Write command with no WCC must error with UnexpectedEof for WCC
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W], &mut ps),
        Err(DatastreamError::UnexpectedEof {
            expected: "WCC",
            ..
        })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_EW], &mut ps),
        Err(DatastreamError::UnexpectedEof {
            expected: "WCC",
            ..
        })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_EWA], &mut ps),
        Err(DatastreamError::UnexpectedEof {
            expected: "WCC",
            ..
        })
    ));
}

#[test]
fn test_adversarial_truncated_orders() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Truncated SBA (0 bytes, 1 byte)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SBA], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SBA, 0x40], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated SF
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SF], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated SFE (na missing, na given but pairs missing or incomplete)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SFE], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SFE, 0x01], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SFE, 0x01, 0xC0], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(
            &[CMD_W, 0x00, ORDER_SFE, 0x03, 0x42, 0xF1, 0x41],
            &mut ps
        ),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated SA
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SA], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SA, 0x42], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated RA (missing stop addr, partial stop addr, missing char, missing GE char)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_RA], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_RA, 0x40], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_RA, 0x40, 0x40], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_RA, 0x40, 0x40, ORDER_GE], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated EUA
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_EUA], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_EUA, 0x40], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated GE
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_GE], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated MF
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_MF], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_MF, 0x02, 0x42], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated WSF: a single length byte is a malformed structured field (x3270: "single
    // byte at end of message", PDS_BAD_CMD)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_WSF, 0x00], &mut ps),
        Err(DatastreamError::InvalidStructuredFieldLength { .. })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_WSF, 0x00, 0x01], &mut ps),
        Err(DatastreamError::InvalidStructuredFieldLength { .. })
    ));
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_WSF, 0x00, 0x10, 0x01, 0x02], &mut ps),
        Err(DatastreamError::InvalidStructuredFieldLength { .. })
    ));
}

#[test]
fn test_adversarial_out_of_bounds_addresses_12bit_and_14bit() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2); // Capacity = 1920

    // Exactly capacity (1920) is illegal (valid are 0..1919)
    // 12-bit: 1920 = (30 << 6) | 0 -> index 30 = 0x5E, index 0 = 0x40
    let b1_1920_12bit = 0x5E;
    let b2_1920_12bit = 0x40;
    assert!(matches!(
        DataStreamParser::parse_and_apply(
            &[CMD_W, 0x00, ORDER_SBA, b1_1920_12bit, b2_1920_12bit],
            &mut ps
        ),
        Err(DatastreamError::InvalidAddress(AddressError::OutOfBounds {
            address: 1920,
            capacity: 1920
        }))
    ));

    // 14-bit: 1920 = (7 << 8) | 128 -> c1 = 0x07, c2 = 0x80
    let b1_1920_14bit = 0x07;
    let b2_1920_14bit = 0x80;
    assert!(matches!(
        DataStreamParser::parse_and_apply(
            &[CMD_W, 0x00, ORDER_SBA, b1_1920_14bit, b2_1920_14bit],
            &mut ps
        ),
        Err(DatastreamError::InvalidAddress(AddressError::OutOfBounds {
            address: 1920,
            capacity: 1920
        }))
    ));

    // Address 1921
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_RA, 0x07, 0x81, 0x40], &mut ps),
        Err(DatastreamError::InvalidAddress(AddressError::OutOfBounds {
            address: 1921,
            capacity: 1920
        }))
    ));

    // Address 4095 (0x7F, 0x7F in 12-bit)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_EUA, 0x7F, 0x7F], &mut ps),
        Err(DatastreamError::InvalidAddress(AddressError::OutOfBounds {
            address: 4095,
            capacity: 1920
        }))
    ));

    // Address 16383 (0x3F, 0xFF in 14-bit)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SBA, 0x3F, 0xFF], &mut ps),
        Err(DatastreamError::InvalidAddress(AddressError::OutOfBounds {
            address: 16383,
            capacity: 1920
        }))
    ));

    // Raw 0xFFFF
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SBA, 0xFF, 0xFF], &mut ps),
        Err(DatastreamError::InvalidAddress(
            AddressError::OutOfBounds { .. }
        ))
    ));
}

#[test]
fn test_adversarial_model_alternate_dimensions_address_bounds() {
    // Model 3: 32x80 = 2560 cells
    let mut ps3 = PresentationSpace::new(TerminalModel::Model3);
    ps3.erase_reset(true); // switch to alternate mode
    assert_eq!(ps3.capacity(), 2560);

    // 2559 is valid, 2560 is out of bounds
    // 2559 = (39 << 6) | 63 -> index 39 = 0xE7, index 63 = 0x7F
    let [ok1, ok2] = BufferAddress::new(2559, 2560)
        .unwrap()
        .encode_12bit()
        .unwrap();
    assert!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SBA, ok1, ok2], &mut ps3).is_ok()
    );

    // 2560 = (40 << 6) | 0 -> index 40 = 0xE8, index 0 = 0x40
    let bad1 = 0xE8;
    let bad2 = 0x40;
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SBA, bad1, bad2], &mut ps3),
        Err(DatastreamError::InvalidAddress(AddressError::OutOfBounds {
            address: 2560,
            capacity: 2560
        }))
    ));
}

#[test]
fn test_adversarial_unknown_commands_and_orders() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Unknown command opcodes
    let bad_commands = [0x00, 0x04, 0x07, 0x10, 0x14, 0x20, 0x60, 0x80, 0xFE, 0xFF];
    for &cmd in &bad_commands {
        assert_eq!(
            DataStreamParser::parse_and_apply(&[cmd], &mut ps),
            Err(DatastreamError::UnknownCommand(cmd))
        );
    }

    // Unknown orders inside write loop (< 0x40, not an order, not a format control, not SO/SI)
    // are skipped without moving the buffer address, as in x3270 `ctlr_write()`.
    let bad_orders = [
        0x01, 0x02, 0x04, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0x10, 0x14, 0x16, 0x17, 0x18, 0x1A, 0x1B,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x26, 0x27, 0x2A, 0x2B, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3D, 0x3E,
    ];
    for &bad in &bad_orders {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let stream = [CMD_EW, 0x00, bad, 0xC1];
        let res = DataStreamParser::parse_and_apply(&stream, &mut ps);
        assert!(res.is_ok(), "Byte 0x{bad:02X} must be skipped, got {res:?}");
        let cap = ps.capacity();
        assert_eq!(
            ps.cell(BufferAddress::new(0, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            0xC1,
            "Byte 0x{bad:02X} must not move the buffer address"
        );
    }

    // Valid format control characters (< 0x40) must be accepted
    let valid_format_controls = [
        FC_NULL, FC_FF, FC_CR, FC_NL, FC_EM, FC_DUP, FC_FM, FC_LF, FC_SUB, FC_EO,
    ];
    for &fc in &valid_format_controls {
        let stream = [CMD_W, 0x00, fc];
        assert!(
            DataStreamParser::parse_and_apply(&stream, &mut ps).is_ok(),
            "Format control byte 0x{fc:02X} must be accepted"
        );
    }
}

// ============================================================================
// 2. EXTREME BOUNDARY CONDITIONS
// ============================================================================

#[test]
fn test_adversarial_ra_full_screen_wraps() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity(); // 1920

    // Case 1: Start at 0, RA to 0 -> fills all 1920 cells, buffer_addr ends at 0
    let [ra1, ra2] = BufferAddress::ZERO.encode_12bit().unwrap();
    let ebcdic_z = CP037.char_to_ebcdic('Z').unwrap();
    let stream1 = [CMD_EW, 0x00, ORDER_RA, ra1, ra2, ebcdic_z];
    DataStreamParser::parse_and_apply(&stream1, &mut ps).unwrap();

    for i in 0..cap {
        assert_eq!(
            ps.cell(BufferAddress::new(i, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            ebcdic_z
        );
    }
    assert_eq!(ps.buffer_addr(), BufferAddress::ZERO);

    // Case 2: Start at 1919, RA to 1919 -> fills all 1920 cells, buffer_addr ends at 1919
    let last_addr = BufferAddress::new(1919, cap).unwrap();
    let [sba1, sba2] = last_addr.encode_12bit().unwrap();
    let ebcdic_q = CP037.char_to_ebcdic('Q').unwrap();
    let stream2 = [
        CMD_W, 0x00, ORDER_SBA, sba1, sba2, ORDER_RA, sba1, sba2, ebcdic_q,
    ];
    DataStreamParser::parse_and_apply(&stream2, &mut ps).unwrap();

    for i in 0..cap {
        assert_eq!(
            ps.cell(BufferAddress::new(i, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            ebcdic_q
        );
    }
    assert_eq!(ps.buffer_addr(), last_addr);

    // Case 3: RA with Graphic Escape (Apl charset) full wrap
    let stream3 = [
        CMD_EW, 0x00, ORDER_RA, ra1, ra2, ORDER_GE, 0xC4, // GE character
    ];
    DataStreamParser::parse_and_apply(&stream3, &mut ps).unwrap();
    for i in 0..cap {
        let cell = ps.cell(BufferAddress::new(i, cap).unwrap()).unwrap();
        assert_eq!(cell.raw_ebcdic(), 0xC4);
        assert_eq!(cell.extended().charset, CharacterSet::Apl);
    }
}

#[test]
fn test_adversarial_eua_entire_buffer_and_selective_protection() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // 1. Unformatted screen: EUA start=0, stop=0 wipes all 1920 cells to 0x00
    // First fill with 'K'
    let [zero1, zero2] = BufferAddress::ZERO.encode_12bit().unwrap();
    let ebcdic_k = CP037.char_to_ebcdic('K').unwrap();
    let fill_stream = [CMD_EW, 0x00, ORDER_RA, zero1, zero2, ebcdic_k];
    DataStreamParser::parse_and_apply(&fill_stream, &mut ps).unwrap();
    assert_eq!(ps.cell(BufferAddress::ZERO).unwrap().raw_ebcdic(), ebcdic_k);

    let eua_stream = [CMD_W, 0x00, ORDER_EUA, zero1, zero2];
    DataStreamParser::parse_and_apply(&eua_stream, &mut ps).unwrap();
    for i in 0..cap {
        assert_eq!(
            ps.cell(BufferAddress::new(i, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            0x00,
            "Cell {i} must be zeroized by unformatted EUA"
        );
    }

    // 2. Formatted screen: Protected fields vs Unprotected fields
    // Place protected field at 0 (data 1..99)
    let fa_prot = FieldAttribute::new(true, false, FieldIntensity::NormalNonDetectable, false);
    ps.place_field(BufferAddress::ZERO, fa_prot, ExtendedAttributes::DEFAULT)
        .unwrap();
    // Place unprotected field at 100 (data 101..199)
    let fa_unprot = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, true);
    let addr_100 = BufferAddress::new(100, cap).unwrap();
    ps.place_field(addr_100, fa_unprot, ExtendedAttributes::DEFAULT)
        .unwrap();

    // Fill cell 50 (protected) with 'P'
    let addr_50 = BufferAddress::new(50, cap).unwrap();
    let ebcdic_p = CP037.char_to_ebcdic('P').unwrap();
    ps.write_char(addr_50, ebcdic_p, ExtendedAttributes::DEFAULT)
        .unwrap();

    // Fill cell 150 (unprotected) with 'U'
    let addr_150 = BufferAddress::new(150, cap).unwrap();
    let ebcdic_u = CP037.char_to_ebcdic('U').unwrap();
    ps.write_char(addr_150, ebcdic_u, ExtendedAttributes::DEFAULT)
        .unwrap();

    // Execute EUA across entire screen (start 0, stop 0)
    DataStreamParser::parse_and_apply(&eua_stream, &mut ps).unwrap();

    // Protected cell 50 must still be 'P'
    assert_eq!(ps.cell(addr_50).unwrap().raw_ebcdic(), ebcdic_p);
    // Unprotected cell 150 must have been erased to 0x00
    assert_eq!(ps.cell(addr_150).unwrap().raw_ebcdic(), 0x00);
    // Field attribute at 0 and 100 must be completely preserved
    assert!(ps.cell(BufferAddress::ZERO).unwrap().is_field_attribute());
    assert!(ps.cell(addr_100).unwrap().is_field_attribute());
}

#[test]
fn test_adversarial_multiple_ic_orders_last_wins() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    let [sba10_1, sba10_2] = BufferAddress::new(10, cap).unwrap().encode_12bit().unwrap();
    let [sba500_1, sba500_2] = BufferAddress::new(500, cap)
        .unwrap()
        .encode_12bit()
        .unwrap();
    let [sba1200_1, sba1200_2] = BufferAddress::new(1200, cap)
        .unwrap()
        .encode_12bit()
        .unwrap();
    let [sba42_1, sba42_2] = BufferAddress::new(42, cap).unwrap().encode_12bit().unwrap();

    // Multiple IC orders interleaved with SBA and data
    let stream = [
        CMD_EW, 0x00, ORDER_SBA, sba10_1, sba10_2, ORDER_IC, // IC at 10
        ORDER_SBA, sba500_1, sba500_2, ORDER_IC, // IC at 500
        ORDER_SBA, sba1200_1, sba1200_2, ORDER_IC, // IC at 1200
        ORDER_SBA, sba42_1, sba42_2, 0xC1, // Write 'A' at 42 (buffer_addr becomes 43)
    ];

    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    // Buffer address is at 43 (advanced by 'A')
    assert_eq!(ps.buffer_addr().as_usize(), 43);
    // Cursor address MUST be 1200 because the last IC order in the stream was at 1200
    assert_eq!(ps.cursor_addr().as_usize(), 1200);
}

#[test]
fn test_adversarial_pt_following_data_vs_pt_following_order() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Formatted screen setup:
    // Field 1 (Protected):   0..9   (SF at 0)
    // Field 2 (Unprotected): 10..19 (SF at 10)
    // Field 3 (Protected):   20..29 (SF at 20)
    // Field 4 (Unprotected): 30..39 (SF at 30)
    let fa_p = FieldAttribute::new(true, false, FieldIntensity::NormalNonDetectable, false);
    let fa_u = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false);

    ps.place_field(
        BufferAddress::new(0, cap).unwrap(),
        fa_p,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();
    ps.place_field(
        BufferAddress::new(10, cap).unwrap(),
        fa_u,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();
    ps.place_field(
        BufferAddress::new(20, cap).unwrap(),
        fa_p,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();
    ps.place_field(
        BufferAddress::new(30, cap).unwrap(),
        fa_u,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();

    // Pre-fill Field 2 (11..19) with 'X'
    let ebcdic_x = CP037.char_to_ebcdic('X').unwrap();
    for i in 11..20 {
        ps.write_char(
            BufferAddress::new(i, cap).unwrap(),
            ebcdic_x,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
    }
    // Pre-fill Field 4 (31..39) with 'Y'
    let ebcdic_y = CP037.char_to_ebcdic('Y').unwrap();
    for i in 31..40 {
        ps.write_char(
            BufferAddress::new(i, cap).unwrap(),
            ebcdic_y,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
    }

    // -------------------------------------------------------------
    // Case A: PT following text data -> NULLS OUT remaining field!
    // Write "AB" at cell 11 (cells 11, 12 written, buffer_addr becomes 13).
    // PT immediately follows -> must null out cells 13..19 to 0x00, and advance to 31!
    // -------------------------------------------------------------
    let [sba11_1, sba11_2] = BufferAddress::new(11, cap).unwrap().encode_12bit().unwrap();
    let stream_a = [
        CMD_W, 0x00, ORDER_SBA, sba11_1, sba11_2, 0xC1, 0xC2, // "AB"
        ORDER_PT,
    ];
    DataStreamParser::parse_and_apply(&stream_a, &mut ps).unwrap();

    assert_eq!(
        ps.cell(BufferAddress::new(11, cap).unwrap())
            .unwrap()
            .raw_ebcdic(),
        0xC1
    ); // 'A'
    assert_eq!(
        ps.cell(BufferAddress::new(12, cap).unwrap())
            .unwrap()
            .raw_ebcdic(),
        0xC2
    ); // 'B'
    for i in 13..20 {
        assert_eq!(
            ps.cell(BufferAddress::new(i, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            0x00,
            "Cell {i} must be nulled by PT following data"
        );
    }
    // Buffer address must now be at 31 (first data cell of Field 4)
    assert_eq!(ps.buffer_addr().as_usize(), 31);
    // Field 4 content 'Y' must still be intact
    assert_eq!(
        ps.cell(BufferAddress::new(31, cap).unwrap())
            .unwrap()
            .raw_ebcdic(),
        ebcdic_y
    );

    // -------------------------------------------------------------
    // Case B: PT following ORDER (SBA) -> does NOT null out data!
    // Refill Field 2 with 'Z'
    // -------------------------------------------------------------
    let ebcdic_z = CP037.char_to_ebcdic('Z').unwrap();
    for i in 11..20 {
        ps.write_char(
            BufferAddress::new(i, cap).unwrap(),
            ebcdic_z,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
    }

    // Stream: SBA 13, then PT directly!
    let [sba13_1, sba13_2] = BufferAddress::new(13, cap).unwrap().encode_12bit().unwrap();
    let stream_b = [CMD_W, 0x00, ORDER_SBA, sba13_1, sba13_2, ORDER_PT];
    DataStreamParser::parse_and_apply(&stream_b, &mut ps).unwrap();

    // Since PT followed an order (SBA), cells 13..19 must NOT be nulled out! They retain 'Z'
    for i in 11..20 {
        assert_eq!(
            ps.cell(BufferAddress::new(i, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            ebcdic_z,
            "Cell {i} must NOT be nulled when PT follows an order"
        );
    }
    assert_eq!(ps.buffer_addr().as_usize(), 31);

    // -------------------------------------------------------------
    // Case C: Consecutive PT orders [PT, PT]
    // -------------------------------------------------------------
    let stream_c = [
        CMD_W, 0x00, ORDER_SBA, sba11_1, sba11_2, 0xC3,     // 'C'
        ORDER_PT, // First PT (follows data): zeroes 12..19, moves to 31
        ORDER_PT, // Second PT (follows order): the next unprotected field (11) lies
                  // before 31, so the tab stops at address 0 without zeroing 31..39
                  // (x3270 `ctlr_write()`: a PT never wraps).
    ];
    DataStreamParser::parse_and_apply(&stream_c, &mut ps).unwrap();

    assert_eq!(ps.buffer_addr().as_usize(), 0);
    // Cells 31..39 in Field 4 must still have 'Y', not zeroed!
    assert_eq!(
        ps.cell(BufferAddress::new(31, cap).unwrap())
            .unwrap()
            .raw_ebcdic(),
        ebcdic_y
    );
}

// ============================================================================
// 3. DETERMINISTIC PSEUDO-RANDOM FUZZING
// ============================================================================

/// Fast deterministic 64-bit XorShift PRNG for zero-dependency fuzz testing.
struct FuzzRng(u64);

impl FuzzRng {
    const fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0xDEAD_BEEF_CAFE_BABE
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.next_u8();
        }
    }
}

#[test]
fn test_fuzz_adversarial_random_streams_never_panic() {
    let mut rng = FuzzRng::new(0x1337_2026_ABCD);
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Run 1,000 randomized adversarial fuzz iterations
    for iteration in 0..1_000 {
        // Vary stream lengths from 0 to 128 bytes
        let len = (rng.next_u64() % 129) as usize;
        let mut stream = vec![0u8; len];
        rng.fill_bytes(&mut stream);

        // Inject high frequency of valid command opcodes and orders mixed with garbage
        if len > 0 && rng.next_u64() % 3 == 0 {
            let opcodes = [
                CMD_W, CMD_EW, CMD_EWA, CMD_EAU, CMD_RB, CMD_RM, CMD_WSF, CMD_NOP,
            ];
            let idx = (rng.next_u64() as usize) % opcodes.len();
            stream[0] = opcodes[idx];
        }

        // Execute parser: it must NEVER panic
        let res = DataStreamParser::parse_and_apply(&stream, &mut ps);

        // Validate internal invariants regardless of Ok or Err
        let cap = ps.capacity();
        assert!(
            ps.cursor_addr().as_usize() < cap,
            "Iteration {iteration}: cursor out of bounds: {}",
            ps.cursor_addr().as_usize()
        );
        assert!(
            ps.buffer_addr().as_usize() < cap,
            "Iteration {iteration}: buffer_addr out of bounds: {}",
            ps.buffer_addr().as_usize()
        );

        // Zero-Trust SafeScreenView conversion must never panic
        let safe_view = SafeScreenView::from_presentation_space(&ps, &CP037);
        assert_eq!(safe_view.capacity(), cap);
        let _ = safe_view.to_plain_text();
        let _ = safe_view.to_plain_text_trimmed();

        // Check if error was returned or successful parse
        if res.is_ok() {
            // Screen state remains valid and queryable
            assert!(safe_view.rows() == 24 || safe_view.rows() == 32);
        }
    }
}

// ============================================================================
// 4. ZERO-TRUST SAFESCREENVIEW INVARIANTS & BOUNDARIES
// ============================================================================

#[test]
fn test_adversarial_safe_view_zero_trust_password_masking() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Place non-display (hidden/password) field at address 10
    // Intensity = NonDisplay
    let fa_pwd = FieldAttribute::new(false, false, FieldIntensity::NonDisplay, false);
    assert!(fa_pwd.is_non_display());

    ps.place_field(
        BufferAddress::new(10, cap).unwrap(),
        fa_pwd,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();

    // Write top secret password into cells 11..18
    let secret = "P@ssw0rd";
    for (offset, ch) in secret.chars().enumerate() {
        let addr = BufferAddress::new(11 + offset, cap).unwrap();
        let ebcdic = CP037.char_to_ebcdic(ch).unwrap();
        ps.write_char(addr, ebcdic, ExtendedAttributes::DEFAULT)
            .unwrap();
    }

    // Verify presentation space has the raw secret
    let raw_cell11 = ps.cell(BufferAddress::new(11, cap).unwrap()).unwrap();
    assert_eq!(raw_cell11.raw_ebcdic(), CP037.char_to_ebcdic('P').unwrap());

    // Project to Zero-Trust SafeScreenView
    let view = SafeScreenView::from_presentation_space(&ps, &CP037);

    // 1. Password characters MUST be masked to ' ' in SafeCell
    for offset in 0..secret.len() {
        let addr = BufferAddress::new(11 + offset, cap).unwrap();
        let cell = view.cell_at_addr(addr).unwrap();
        assert_eq!(
            cell.ch, ' ',
            "Password cell at offset {offset} leaked: {:?}",
            cell.ch
        );
    }

    // 2. Plain text representation MUST NOT contain any part of the password
    let plain = view.to_plain_text();
    assert!(!plain.contains("P@ssw0rd"));
    assert!(!plain.contains("P@ss"));

    // 3. SafeScreenView diff against blank screen MUST NOT leak characters
    let blank_view = SafeScreenView::default();
    let diff = view.diff(&blank_view);
    for (_, _, changed_cell) in &diff {
        assert_ne!(changed_cell.ch, 'P');
        assert_ne!(changed_cell.ch, '@');
        assert_ne!(changed_cell.ch, 's');
        assert_ne!(changed_cell.ch, 'w');
        assert_ne!(changed_cell.ch, '0');
        assert_ne!(changed_cell.ch, 'r');
        assert_ne!(changed_cell.ch, 'd');
    }

    // 4. Start Field marker itself must be ' ' with is_field_marker = true and protected = true
    let fa_cell = view
        .cell_at_addr(BufferAddress::new(10, cap).unwrap())
        .unwrap();
    assert_eq!(fa_cell.ch, ' ');
    assert!(fa_cell.is_field_marker);
    assert!(fa_cell.protected);
}

#[test]
fn test_adversarial_safe_view_boundary_and_validation_errors() {
    // 1. SafeScreenView::new with dimension mismatch
    let bad_cells = vec![SafeCell::BLANK; 100];
    let err_dim = SafeScreenView::new(24, 80, 0, 0, false, bad_cells);
    assert!(matches!(
        err_dim,
        Err(SafeViewError::DimensionMismatch {
            expected_cells: 1920,
            actual_cells: 100,
            ..
        })
    ));

    // 2. SafeScreenView::new with cursor out of bounds
    let valid_cells = vec![SafeCell::BLANK; 1920];
    let err_cursor = SafeScreenView::new(24, 80, 24, 0, false, valid_cells.clone());
    assert!(matches!(
        err_cursor,
        Err(SafeViewError::CursorOutOfBounds {
            cursor_row: 24,
            cursor_col: 0,
            ..
        })
    ));

    let err_cursor_col = SafeScreenView::new(24, 80, 0, 80, false, valid_cells);
    assert!(matches!(
        err_cursor_col,
        Err(SafeViewError::CursorOutOfBounds {
            cursor_row: 0,
            cursor_col: 80,
            ..
        })
    ));

    // 3. SafeScreenView::empty with 0x0
    let empty_zero = SafeScreenView::empty(0, 0);
    assert_eq!(empty_zero.capacity(), 0);
    assert_eq!(empty_zero.diff(&empty_zero), Vec::new());
    assert_eq!(empty_zero.to_plain_text(), "");
}

#[test]
fn test_adversarial_wrapped_password_field_masking() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity(); // 1920

    // Place non-display field at address 1915 (5 cells before end of screen)
    // There are NO other fields on the screen!
    let fa_pwd = FieldAttribute::new(false, false, FieldIntensity::NonDisplay, false);
    ps.place_field(
        BufferAddress::new(1915, cap).unwrap(),
        fa_pwd,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();

    // Data wraps around: cells 1916..1919 and 0..10 are in the same non-display field!
    // Write secrets across the screen boundary
    let ebcdic_sec = CP037.char_to_ebcdic('X').unwrap();
    ps.write_char(
        BufferAddress::new(1918, cap).unwrap(),
        ebcdic_sec,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();
    ps.write_char(
        BufferAddress::new(0, cap).unwrap(),
        ebcdic_sec,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();
    ps.write_char(
        BufferAddress::new(5, cap).unwrap(),
        ebcdic_sec,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();

    let view = SafeScreenView::from_presentation_space(&ps, &CP037);

    // Both wrapped cells and beginning of screen cells MUST be masked to ' '
    assert_eq!(
        view.cell_at_addr(BufferAddress::new(1918, cap).unwrap())
            .unwrap()
            .ch,
        ' '
    );
    assert_eq!(
        view.cell_at_addr(BufferAddress::new(0, cap).unwrap())
            .unwrap()
            .ch,
        ' '
    );
    assert_eq!(
        view.cell_at_addr(BufferAddress::new(5, cap).unwrap())
            .unwrap()
            .ch,
        ' '
    );

    let plain = view.to_plain_text();
    assert!(!plain.contains('X'));
}

#[test]
fn test_adversarial_field_overwrite_and_unformat() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Place field attribute at cell 100
    let fa = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false);
    ps.place_field(
        BufferAddress::new(100, cap).unwrap(),
        fa,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();
    assert!(ps.is_formatted());

    // Overwrite the field attribute with a regular character
    let ebcdic_a = CP037.char_to_ebcdic('A').unwrap();
    ps.write_char(
        BufferAddress::new(100, cap).unwrap(),
        ebcdic_a,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();

    // Now screen should be unformatted
    assert!(!ps.is_formatted());
    assert!(!ps
        .cell(BufferAddress::new(100, cap).unwrap())
        .unwrap()
        .is_field_attribute());
    assert_eq!(
        ps.cell(BufferAddress::new(100, cap).unwrap())
            .unwrap()
            .raw_ebcdic(),
        ebcdic_a
    );
}

#[test]
fn test_adversarial_rapid_dimension_switching() {
    let mut ps = PresentationSpace::new(TerminalModel::Model4); // Default 24x80 (1920), Alternate 43x80 (3440)

    for _ in 0..50 {
        // Switch to alternate (EWA)
        let res_ewa = DataStreamParser::parse_and_apply(&[CMD_EWA, 0x00], &mut ps).unwrap();
        assert_eq!(res_ewa.command, Command::EraseWriteAlternate);
        assert_eq!(ps.rows(), 43);
        assert_eq!(ps.capacity(), 3440);

        // Switch back to primary (EW)
        let res_ew = DataStreamParser::parse_and_apply(&[CMD_EW, 0x00], &mut ps).unwrap();
        assert_eq!(res_ew.command, Command::EraseWrite);
        assert_eq!(ps.rows(), 24);
        assert_eq!(ps.capacity(), 1920);
    }
}
