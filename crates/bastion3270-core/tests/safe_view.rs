//! Integration tests for Zero-Trust SafeScreenView and SafeCell.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use bastion3270_core::address::BufferAddress;
use bastion3270_core::datastream::command::*;
use bastion3270_core::datastream::order::*;
use bastion3270_core::datastream::DataStreamParser;
use bastion3270_core::ebcdic::{CodePage, CP037};
use bastion3270_core::field::{
    CharacterSet, Color3270, ExtendedAttributes, FieldAttribute, FieldIntensity, Highlight3270,
};
use bastion3270_core::model::TerminalModel;
use bastion3270_core::safe_view::{SafeCell, SafeScreenView, SafeViewError};
use bastion3270_core::screen::PresentationSpace;

#[test]
fn test_zero_trust_tso_racf_password_masking_integration() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Construct a classic TSO login screen:
    // Row 10: "USERID   ===> " followed by "SYSADMIN"
    // Row 12: "PASSWORD ===> " followed by "SUPERSECRET99" in NonDisplay field
    let [sba_user_lbl1, sba_user_lbl2] = BufferAddress::new(10 * 80, cap)
        .unwrap()
        .encode_12bit()
        .unwrap();
    let [sba_user_inp1, sba_user_inp2] = BufferAddress::new(10 * 80 + 14, cap)
        .unwrap()
        .encode_12bit()
        .unwrap();
    let [sba_pw_lbl1, sba_pw_lbl2] = BufferAddress::new(12 * 80, cap)
        .unwrap()
        .encode_12bit()
        .unwrap();
    let [sba_pw_inp1, sba_pw_inp2] = BufferAddress::new(12 * 80 + 14, cap)
        .unwrap()
        .encode_12bit()
        .unwrap();

    let mut stream = vec![CMD_EW, 0x00];

    // User label
    stream.extend_from_slice(&[ORDER_SBA, sba_user_lbl1, sba_user_lbl2, ORDER_SF, 0x60]); // protected
    for ch in "USERID   ===> ".chars() {
        stream.push(CP037.char_to_ebcdic(ch).unwrap());
    }

    // User input
    stream.extend_from_slice(&[ORDER_SBA, sba_user_inp1, sba_user_inp2, ORDER_SF, 0x40]); // unprotected normal
    for ch in "SYSADMIN".chars() {
        stream.push(CP037.char_to_ebcdic(ch).unwrap());
    }

    // Password label
    stream.extend_from_slice(&[ORDER_SBA, sba_pw_lbl1, sba_pw_lbl2, ORDER_SF, 0x60]); // protected
    for ch in "PASSWORD ===> ".chars() {
        stream.push(CP037.char_to_ebcdic(ch).unwrap());
    }

    // Password input (NonDisplay: intensity=0x0C, wire byte=0x4C)
    stream.extend_from_slice(&[ORDER_SBA, sba_pw_inp1, sba_pw_inp2, ORDER_SF, 0x4C]); // unprotected non-display
    for ch in "SUPERSECRET99".chars() {
        stream.push(CP037.char_to_ebcdic(ch).unwrap());
    }

    DataStreamParser::parse_and_apply(&stream, &mut ps).unwrap();

    // 1. Verify PresentationSpace internally retains the secret password bytes:
    for (i, ch) in "SUPERSECRET99".chars().enumerate() {
        let addr = BufferAddress::new(12 * 80 + 15 + i, cap).unwrap();
        assert_eq!(
            ps.cell(addr).unwrap().raw_ebcdic(),
            CP037.char_to_ebcdic(ch).unwrap()
        );
    }

    // 2. Project into SafeScreenView
    let view = ps.to_safe_view(&CP037);

    // 3. Verify zero-trust password masking on each cell:
    for i in 0..13 {
        let cell = view.cell_at(12, 15 + i as u16).unwrap();
        assert_eq!(
            cell.ch,
            ' ',
            "Password cell at col {} must be masked to ' '",
            15 + i
        );
        assert!(!cell.is_field_marker);
    }

    // 4. Verify row text never exposes the password:
    let row12 = view.row_text(12).unwrap();
    assert!(row12.contains("PASSWORD ===> "));
    assert!(!row12.contains("SUPERSECRET99"));
    assert!(!row12.contains("SUPER"));
    assert!(!row12.contains("SECRET"));

    // 5. Verify whole screen plain text never exposes the password:
    let plain = view.to_plain_text();
    assert!(plain.contains("SYSADMIN"));
    assert!(plain.contains("USERID   ===> "));
    assert!(plain.contains("PASSWORD ===> "));
    assert!(!plain.contains("SUPERSECRET99"));

    let trimmed = view.to_plain_text_trimmed();
    assert!(!trimmed.contains("SUPERSECRET99"));
}

#[test]
fn test_field_attribute_marker_blanking() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Field attribute at (0, 0)
    let fa = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false);
    ps.place_field(
        BufferAddress::new(0, cap).unwrap(),
        fa,
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();

    let view = ps.to_safe_view(&CP037);
    let marker = view.cell_at(0, 0).unwrap();
    assert_eq!(marker.ch, ' ');
    assert!(marker.is_field_marker);
    assert!(marker.protected);
}

#[test]
fn test_thin_client_websocket_diffing_optimizations() {
    let view1 = SafeScreenView::empty(24, 80);
    assert_eq!(view1.diff(&view1), vec![]);
    assert!(!view1.cursor_changed(&view1));

    // Create view2 with cursor moved and 2 cells changed
    let mut cells = vec![SafeCell::BLANK; 1920];
    let custom_cell = SafeCell {
        ch: 'X',
        foreground: Color3270::Yellow,
        background: Color3270::Default,
        highlight: Highlight3270::BLINK,
        charset: CharacterSet::Base,
        protected: false,
        is_field_marker: false,
    };
    cells[85] = custom_cell; // Row 1, Col 5
    cells[100] = custom_cell; // Row 1, Col 20

    let view2 = SafeScreenView::new(24, 80, 5, 10, false, cells).unwrap();

    assert!(view2.cursor_changed(&view1));
    assert_eq!(view2.cursor_position(), (5, 10));

    let diff = view2.diff(&view1);
    assert_eq!(diff.len(), 2);
    assert_eq!(diff[0], (1, 5, custom_cell));
    assert_eq!(diff[1], (1, 20, custom_cell));

    // Screen dimension change (24x80 -> 32x80) yields full refresh
    let view_alt = SafeScreenView::empty(32, 80);
    let full_diff = view_alt.diff(&view1);
    assert_eq!(full_diff.len(), 2560);
}

#[test]
fn test_safe_screen_view_validation_errors() {
    // Dimension mismatch
    let bad_cells = vec![SafeCell::BLANK; 100];
    let res = SafeScreenView::new(24, 80, 0, 0, false, bad_cells);
    assert!(matches!(
        res,
        Err(SafeViewError::DimensionMismatch {
            rows: 24,
            cols: 80,
            expected_cells: 1920,
            actual_cells: 100,
        })
    ));

    // Cursor out of bounds
    let good_cells = vec![SafeCell::BLANK; 1920];
    let res_cursor = SafeScreenView::new(24, 80, 24, 0, false, good_cells.clone());
    assert!(matches!(
        res_cursor,
        Err(SafeViewError::CursorOutOfBounds {
            cursor_row: 24,
            cursor_col: 0,
            rows: 24,
            cols: 80,
        })
    ));

    let res_cursor_col = SafeScreenView::new(24, 80, 0, 80, false, good_cells);
    assert!(matches!(
        res_cursor_col,
        Err(SafeViewError::CursorOutOfBounds {
            cursor_row: 0,
            cursor_col: 80,
            rows: 24,
            cols: 80,
        })
    ));
}
