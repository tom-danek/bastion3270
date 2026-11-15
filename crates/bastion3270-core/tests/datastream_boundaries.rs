//! Adversarial boundary, edge cases, truncations, and wrap-around stress tests.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::doc_markdown
)]

use bastion3270_core::address::{AddressError, BufferAddress};
use bastion3270_core::datastream::command::*;
use bastion3270_core::datastream::order::*;
use bastion3270_core::datastream::{DataStreamParser, DatastreamError};
use bastion3270_core::ebcdic::{CodePage, CP037};
use bastion3270_core::model::TerminalModel;
use bastion3270_core::screen::PresentationSpace;

#[test]
fn test_empty_stream_returns_error() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    assert_eq!(
        DataStreamParser::parse_and_apply(&[], &mut ps),
        Err(DatastreamError::EmptyStream)
    );
}

#[test]
fn test_unknown_command_opcode() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let bad_opcodes = [0x00, 0x04, 0x07, 0x10, 0x99, 0xFE];
    for &op in &bad_opcodes {
        assert_eq!(
            DataStreamParser::parse_and_apply(&[op], &mut ps),
            Err(DatastreamError::UnknownCommand(op))
        );
    }
}

#[test]
fn test_truncated_write_commands_missing_wcc() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
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
fn test_truncated_orders() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Truncated SF (missing attribute byte)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SF], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated SFE (na=2, only 1 byte given)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SFE, 0x02, 0xC0], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated SBA (missing 2nd byte)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SBA, 0x40], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated SA (missing value byte)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SA, 0x42], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated RA (missing repeat char)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_RA, 0x40, 0x40], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated EUA (missing 2nd address byte)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_EUA, 0x40], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated GE (missing char byte)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_GE], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));

    // Truncated MF (na=1, missing value byte)
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_MF, 0x01, 0xC0], &mut ps),
        Err(DatastreamError::UnexpectedEof { .. })
    ));
}

#[test]
fn test_out_of_bounds_addresses() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2); // capacity 1920

    // Create an address encoding that decodes to 2000 (Row 25, out of bounds for Model 2)
    // 2000 = (31 << 6) | 16
    let b1 = bastion3270_core::address::CODE_TABLE
        .get(31)
        .copied()
        .unwrap_or(0x40);
    let b2 = bastion3270_core::address::CODE_TABLE
        .get(16)
        .copied()
        .unwrap_or(0x40);

    // SBA out of bounds
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_SBA, b1, b2], &mut ps),
        Err(DatastreamError::InvalidAddress(
            AddressError::OutOfBounds { .. }
        ))
    ));

    // RA out of bounds
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_RA, b1, b2, 0x40], &mut ps),
        Err(DatastreamError::InvalidAddress(
            AddressError::OutOfBounds { .. }
        ))
    ));

    // EUA out of bounds
    assert!(matches!(
        DataStreamParser::parse_and_apply(&[CMD_W, 0x00, ORDER_EUA, b1, b2], &mut ps),
        Err(DatastreamError::InvalidAddress(
            AddressError::OutOfBounds { .. }
        ))
    ));
}

#[test]
fn test_buffer_address_wrap_around_screen_boundary() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity(); // 1920

    // SBA to cell 1918 (2 cells before end of screen)
    let [sba1, sba2] = BufferAddress::new(1918, cap)
        .unwrap()
        .encode_12bit()
        .unwrap();
    let chars = ['A', 'B', 'C', 'D']; // 4 characters: should write to 1918, 1919, 0, 1
    let mut stream = vec![CMD_W, 0x00, ORDER_SBA, sba1, sba2];
    for &ch in &chars {
        stream.push(CP037.char_to_ebcdic(ch).unwrap());
    }

    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    assert_eq!(
        ps.cell(BufferAddress::new(1918, cap).unwrap())
            .unwrap()
            .raw_ebcdic(),
        CP037.char_to_ebcdic('A').unwrap()
    );
    assert_eq!(
        ps.cell(BufferAddress::new(1919, cap).unwrap())
            .unwrap()
            .raw_ebcdic(),
        CP037.char_to_ebcdic('B').unwrap()
    );
    assert_eq!(
        ps.cell(BufferAddress::new(0, cap).unwrap())
            .unwrap()
            .raw_ebcdic(),
        CP037.char_to_ebcdic('C').unwrap()
    );
    assert_eq!(
        ps.cell(BufferAddress::new(1, cap).unwrap())
            .unwrap()
            .raw_ebcdic(),
        CP037.char_to_ebcdic('D').unwrap()
    );
    assert_eq!(ps.buffer_addr().as_usize(), 2);
}

#[test]
fn test_ra_full_screen_wrap_and_loop_safety() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Start at 100, RA to 100 with 'F' -> full screen wrap (all 1920 cells)
    let [sba1, sba2] = BufferAddress::new(100, cap)
        .unwrap()
        .encode_12bit()
        .unwrap();
    let [ra1, ra2] = BufferAddress::new(100, cap)
        .unwrap()
        .encode_12bit()
        .unwrap();
    let ebcdic_f = CP037.char_to_ebcdic('F').unwrap();

    let stream = [
        CMD_W, 0x00, ORDER_SBA, sba1, sba2, ORDER_RA, ra1, ra2, ebcdic_f,
    ];

    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    for i in 0..cap {
        assert_eq!(
            ps.cell(BufferAddress::new(i, cap).unwrap())
                .unwrap()
                .raw_ebcdic(),
            ebcdic_f
        );
    }
    assert_eq!(ps.buffer_addr().as_usize(), 100);
}

#[test]
fn test_wsf_invalid_length_errors() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // WSF length=1 (invalid because 2-byte length prefix requires len >= 2 or len == 0)
    let stream_len1 = [CMD_WSF, 0x00, 0x01];
    assert!(matches!(
        DataStreamParser::parse_and_apply(&stream_len1, &mut ps),
        Err(DatastreamError::InvalidStructuredFieldLength { .. })
    ));

    // WSF length=100 with only 4 bytes remaining
    let stream_overflow = [CMD_WSF, 0x00, 0x64, 0x01, 0x02];
    assert!(matches!(
        DataStreamParser::parse_and_apply(&stream_overflow, &mut ps),
        Err(DatastreamError::InvalidStructuredFieldLength { .. })
    ));
}

#[test]
fn test_unsupported_order_opcode_skipped() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Byte 0x20 is not an order and not a format control character (< 0x40): x3270 skips it
    // without moving the buffer address, so the following 'A' lands at address 0.
    let stream = [CMD_EW, 0x00, 0x20, 0xC1];
    assert!(DataStreamParser::parse_and_apply(&stream, &mut ps).is_ok());
    let cap = ps.capacity();
    assert_eq!(
        ps.cell(BufferAddress::new(0, cap).unwrap())
            .unwrap()
            .raw_ebcdic(),
        0xC1
    );
}
