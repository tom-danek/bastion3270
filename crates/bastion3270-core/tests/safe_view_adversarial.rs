//! Adversarial verification test suite for Zero-Trust SafeScreenView and 3270 Response Generation.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::uninlined_format_args,
    clippy::assert_is_empty
)]

use bastion3270_core::address::BufferAddress;
use bastion3270_core::datastream::order::*;
use bastion3270_core::datastream::response::{
    build_read_buffer, build_read_modified, is_short_read_aid, AID_CLEAR, AID_PA1, AID_PA2, AID_PA3,
};
use bastion3270_core::ebcdic::{CodePage, CP037, IBM870};
use bastion3270_core::field::{
    CharacterSet, Color3270, ExtendedAttributes, FieldAttribute, FieldIntensity, Highlight3270,
};
use bastion3270_core::model::TerminalModel;
use bastion3270_core::safe_view::{SafeCell, SafeScreenView};
use bastion3270_core::screen::PresentationSpace;

// ============================================================================
// CHALLENGE 1: PASSWORD & NON-DISPLAY ZERO-TRUST ISOLATION
// ============================================================================

/// Adversarially tests that passwords in CP037 NonDisplay fields NEVER leak into SafeCell or string extracts.
#[test]
fn test_adversarial_password_isolation_cp037() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Field 1: Normal username field at row 5, col 10
    let user_fa_addr = BufferAddress::new(5 * 80 + 10, cap).unwrap();
    let user_fa = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false);
    ps.place_field(user_fa_addr, user_fa, ExtendedAttributes::DEFAULT)
        .unwrap();

    let username = "ADMINUSER";
    for (i, ch) in username.chars().enumerate() {
        let addr = BufferAddress::new(5 * 80 + 11 + i, cap).unwrap();
        let ebcdic = CP037.char_to_ebcdic(ch).unwrap();
        ps.write_char(addr, ebcdic, ExtendedAttributes::DEFAULT)
            .unwrap();
    }

    // Field 2: NonDisplay password field at row 5, col 30
    let pw_fa_addr = BufferAddress::new(5 * 80 + 30, cap).unwrap();
    let pw_fa = FieldAttribute::new(false, false, FieldIntensity::NonDisplay, true);
    ps.place_field(pw_fa_addr, pw_fa, ExtendedAttributes::DEFAULT)
        .unwrap();

    let password = "Super$ecretP@ssw0rd!#99";
    for (i, ch) in password.chars().enumerate() {
        let addr = BufferAddress::new(5 * 80 + 31 + i, cap).unwrap();
        let ebcdic = CP037.char_to_ebcdic(ch).unwrap();
        ps.write_char(addr, ebcdic, ExtendedAttributes::DEFAULT)
            .unwrap();
    }

    // Verify presentation space still holds the raw EBCDIC bytes for host transmission
    for (i, ch) in password.chars().enumerate() {
        let addr = BufferAddress::new(5 * 80 + 31 + i, cap).unwrap();
        let expected_ebcdic = CP037.char_to_ebcdic(ch).unwrap();
        assert_eq!(
            ps.cell(addr).unwrap().raw_ebcdic(),
            expected_ebcdic,
            "Presentation space must preserve raw password byte"
        );
    }

    // Project to SafeScreenView
    let view = ps.to_safe_view(&CP037);

    // 1. Check all cells in the password field: SafeCell.ch MUST be ' '
    for i in 0..password.len() {
        let col = 31 + i as u16;
        let cell = view.cell_at(5, col).unwrap();
        assert_eq!(
            cell.ch, ' ',
            "Zero-trust violation: cell at (5, {}) has ch='{}' instead of ' '",
            col, cell.ch
        );
        assert!(!cell.is_field_marker);
    }

    // 2. Check row text
    let row5 = view.row_text(5).unwrap();
    assert!(row5.contains("ADMINUSER"), "Visible username must appear");
    assert!(
        !row5.contains(password),
        "Password leaked into row_text(5): {row5}"
    );
    for sub in &["Super", "ecret", "P@ss", "w0rd", "!#99"] {
        assert!(
            !row5.contains(sub),
            "Password substring '{sub}' leaked into row_text: {row5}"
        );
    }

    // 3. Check trimmed row text
    let row5_trimmed = view.row_text_trimmed(5).unwrap();
    assert!(!row5_trimmed.contains(password));

    // 4. Check whole-screen plain text and trimmed plain text
    let plain = view.to_plain_text();
    let plain_trimmed = view.to_plain_text_trimmed();
    assert!(!plain.contains(password));
    assert!(!plain_trimmed.contains(password));

    // 5. Check linear cells() slice: not a single non-space cell in the password range
    let cells_slice = view.cells();
    for i in 0..password.len() {
        let idx = 5 * 80 + 31 + i;
        assert_eq!(cells_slice[idx].ch, ' ');
    }
}

/// Adversarially tests that Czech/Latin-2 passwords in IBM870 NonDisplay fields NEVER leak.
#[test]
fn test_adversarial_password_isolation_ibm870_czech() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // NonDisplay password field with Czech accented characters
    let fa_addr = BufferAddress::new(100, cap).unwrap();
    let fa = FieldAttribute::new(false, false, FieldIntensity::NonDisplay, false);
    ps.place_field(fa_addr, fa, ExtendedAttributes::DEFAULT)
        .unwrap();

    let czech_password = "TajnéHeslo123ěřžýáíéůúďťň";
    let encoded_bytes = IBM870.encode_str(czech_password).unwrap();
    for (i, &b) in encoded_bytes.iter().enumerate() {
        let addr = BufferAddress::new(101 + i, cap).unwrap();
        ps.write_char(addr, b, ExtendedAttributes::DEFAULT).unwrap();
    }

    // Verify raw bytes are in PresentationSpace
    for (i, &b) in encoded_bytes.iter().enumerate() {
        let addr = BufferAddress::new(101 + i, cap).unwrap();
        assert_eq!(ps.cell(addr).unwrap().raw_ebcdic(), b);
    }

    // Project using IBM870 codepage
    let view = ps.to_safe_view(&IBM870);

    // Verify cell-by-cell isolation
    for i in 0..encoded_bytes.len() {
        let addr = BufferAddress::new(101 + i, cap).unwrap();
        let cell = view.cell_at_addr(addr).unwrap();
        assert_eq!(
            cell.ch, ' ',
            "Czech character leaked at offset {}: '{}'",
            i, cell.ch
        );
    }

    // Verify plain text extractions
    let plain = view.to_plain_text();
    assert!(!plain.contains(czech_password));
    assert!(!plain.contains("Tajné"));
    assert!(!plain.contains("Heslo"));
    assert!(!plain.contains("ěřžýáíéůúďťň"));

    let plain_trimmed = view.to_plain_text_trimmed();
    assert!(!plain_trimmed.contains(czech_password));
}

/// Adversarially tests all 256 possible byte values inside a NonDisplay field.
/// Mathematical certainty: absolutely zero byte values can decode to anything other than ' '.
#[test]
fn test_adversarial_nondisplay_all_256_bytes_masked() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Place NonDisplay field at cell 0
    let fa_addr = BufferAddress::new(0, cap).unwrap();
    let fa = FieldAttribute::new(false, false, FieldIntensity::NonDisplay, false);
    ps.place_field(fa_addr, fa, ExtendedAttributes::DEFAULT)
        .unwrap();

    // Fill the next 256 cells (1..=256) with byte values 0..=255
    for b in 0..=255u8 {
        let addr = BufferAddress::new(1 + b as usize, cap).unwrap();
        ps.write_char(addr, b, ExtendedAttributes::DEFAULT).unwrap();
    }

    // Project using both CP037 and IBM870
    for codepage in [&CP037 as &dyn CodePage, &IBM870 as &dyn CodePage] {
        let view = ps.to_safe_view(codepage);

        // Attribute marker at cell 0
        let marker = view.cell_at_addr(BufferAddress::ZERO).unwrap();
        assert_eq!(marker.ch, ' ');
        assert!(marker.is_field_marker);
        assert!(marker.protected);

        // Every single byte from 0 to 255 must be masked to ' '
        for b in 0..=255u8 {
            let addr = BufferAddress::new(1 + b as usize, cap).unwrap();
            let cell = view.cell_at_addr(addr).unwrap();
            assert_eq!(
                cell.ch, ' ',
                "Byte 0x{:02X} was not masked! got ch='{}'",
                b, cell.ch
            );
            assert!(!cell.is_field_marker);
        }
    }
}

/// Adversarially tests a NonDisplay field that wraps around the screen buffer boundary (end of buffer -> 0).
#[test]
fn test_adversarial_nondisplay_buffer_wrap_around() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity(); // 1920

    // Place NonDisplay field at the second-to-last cell (1918)
    let fa_addr = BufferAddress::new(1918, cap).unwrap();
    let fa = FieldAttribute::new(false, false, FieldIntensity::NonDisplay, false);
    ps.place_field(fa_addr, fa, ExtendedAttributes::DEFAULT)
        .unwrap();

    // Cell 1919 (last cell of screen)
    let addr_last = BufferAddress::new(1919, cap).unwrap();
    let ebcdic_x = CP037.char_to_ebcdic('X').unwrap();
    ps.write_char(addr_last, ebcdic_x, ExtendedAttributes::DEFAULT)
        .unwrap();

    // Cells 0..=10 (wrapped to beginning of screen)
    let secret = "WRAPPEDSECR";
    for (i, ch) in secret.chars().enumerate() {
        let addr = BufferAddress::new(i, cap).unwrap();
        let ebcdic = CP037.char_to_ebcdic(ch).unwrap();
        ps.write_char(addr, ebcdic, ExtendedAttributes::DEFAULT)
            .unwrap();
    }

    // Next field starts at cell 11 (normal display)
    let next_fa_addr = BufferAddress::new(11, cap).unwrap();
    let next_fa = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false);
    ps.place_field(next_fa_addr, next_fa, ExtendedAttributes::DEFAULT)
        .unwrap();

    let view = ps.to_safe_view(&CP037);

    // Cell 1919 must be masked to ' '
    assert_eq!(view.cell_at_addr(addr_last).unwrap().ch, ' ');

    // Cells 0..=10 must be masked to ' '
    for i in 0..11 {
        let cell = view
            .cell_at_addr(BufferAddress::new(i, cap).unwrap())
            .unwrap();
        assert_eq!(cell.ch, ' ', "Wrapped cell at {} must be masked to ' '", i);
    }

    // Row 0 text must NOT contain "WRAPPEDSECR"
    let row0 = view.row_text(0).unwrap();
    assert!(!row0.contains("WRAPPEDSECR"));
    assert!(!row0.contains("WRAPPED"));

    // Whole plain text must NOT contain "WRAPPEDSECR"
    let plain = view.to_plain_text();
    assert!(!plain.contains("WRAPPEDSECR"));
}

// ============================================================================
// CHALLENGE 2: SCREEN DIFFING & THIN-CLIENT OPTIMIZATION
// ============================================================================

/// Tests empty diff on identical screens.
#[test]
fn test_adversarial_diff_identical_screens() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Populate with some fields and characters
    let fa_addr = BufferAddress::new(0, cap).unwrap();
    let fa = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false);
    ps.place_field(fa_addr, fa, ExtendedAttributes::DEFAULT)
        .unwrap();

    for i in 1..20 {
        let addr = BufferAddress::new(i, cap).unwrap();
        let ebcdic = CP037.char_to_ebcdic('A').unwrap();
        ps.write_char(addr, ebcdic, ExtendedAttributes::DEFAULT)
            .unwrap();
    }

    let view_a = ps.to_safe_view(&CP037);
    let view_b = ps.to_safe_view(&CP037);

    let diff = view_b.diff(&view_a);
    assert!(
        diff.is_empty(),
        "Identical screens must return empty diff, got {} changes",
        diff.len()
    );
    assert!(
        !view_b.cursor_changed(&view_a),
        "Cursor did not change, cursor_changed must be false"
    );
}

/// Tests single cell update diff (must return exactly 1 tuple).
#[test]
fn test_adversarial_diff_single_cell_update() {
    let view1 = SafeScreenView::empty(24, 80);

    // Test single cell updates at all four screen corners:
    let test_coords = [(0, 0), (0, 79), (23, 0), (23, 79), (12, 40)];

    for &(row, col) in &test_coords {
        let mut cells = vec![SafeCell::BLANK; 1920];
        let idx = (row as usize) * 80 + (col as usize);

        let custom_cell = SafeCell {
            ch: 'Q',
            foreground: Color3270::Turquoise,
            background: Color3270::Blue,
            highlight: Highlight3270::REVERSE_VIDEO,
            charset: CharacterSet::Base,
            protected: true,
            is_field_marker: false,
        };
        cells[idx] = custom_cell;

        let view2 = SafeScreenView::new(24, 80, 0, 0, false, cells).unwrap();
        let diff = view2.diff(&view1);

        assert_eq!(
            diff.len(),
            1,
            "Diff must contain exactly 1 tuple for single cell update at ({row}, {col})"
        );
        assert_eq!(diff[0].0, row);
        assert_eq!(diff[0].1, col);
        assert_eq!(diff[0].2, custom_cell);
        assert!(!view2.cursor_changed(&view1));
    }
}

/// Tests diff when ONLY non-character styling attributes change (color, highlight).
#[test]
fn test_adversarial_diff_style_change_only() {
    let view1 = SafeScreenView::empty(24, 80);
    let mut cells = vec![SafeCell::BLANK; 1920];

    // Same character ' ' but different highlight and color
    let styled_cell = SafeCell {
        ch: ' ',
        foreground: Color3270::Pink,
        background: Color3270::Default,
        highlight: Highlight3270::UNDERSCORE,
        charset: CharacterSet::Base,
        protected: false,
        is_field_marker: false,
    };
    cells[100] = styled_cell;

    let view2 = SafeScreenView::new(24, 80, 0, 0, false, cells).unwrap();
    let diff = view2.diff(&view1);

    assert_eq!(
        diff.len(),
        1,
        "Diff must detect styling change even when ch=' '"
    );
    assert_eq!(diff[0], (1, 20, styled_cell));
}

/// Tests dimension changes (24x80 -> 32x80 -> 43x80 -> 27x132).
/// Must return full screen diff for every cell.
#[test]
fn test_adversarial_diff_dimension_changes() {
    let view_model2 = SafeScreenView::empty(24, 80); // 1920 cells
    let view_model3 = SafeScreenView::empty(32, 80); // 2560 cells
    let view_model4 = SafeScreenView::empty(43, 80); // 3440 cells
    let view_model5 = SafeScreenView::empty(27, 132); // 3564 cells

    // 24x80 -> 32x80
    let diff_2_to_3 = view_model3.diff(&view_model2);
    assert_eq!(
        diff_2_to_3.len(),
        2560,
        "Dimension change 24x80 -> 32x80 must return full screen diff"
    );
    assert_eq!(diff_2_to_3[0].0, 0);
    assert_eq!(diff_2_to_3[0].1, 0);
    assert_eq!(diff_2_to_3[2559].0, 31);
    assert_eq!(diff_2_to_3[2559].1, 79);

    // 24x80 -> 43x80
    let diff_2_to_4 = view_model4.diff(&view_model2);
    assert_eq!(
        diff_2_to_4.len(),
        3440,
        "Dimension change 24x80 -> 43x80 must return full screen diff"
    );
    assert_eq!(diff_2_to_4[3439].0, 42);
    assert_eq!(diff_2_to_4[3439].1, 79);

    // 43x80 -> 24x80 (shrink back)
    let diff_4_to_2 = view_model2.diff(&view_model4);
    assert_eq!(
        diff_4_to_2.len(),
        1920,
        "Dimension change 43x80 -> 24x80 must return 1920 full screen diff"
    );

    // 24x80 -> 27x132 (columns and rows change)
    let diff_2_to_5 = view_model5.diff(&view_model2);
    assert_eq!(
        diff_2_to_5.len(),
        3564,
        "Dimension change 24x80 -> 27x132 must return 3564 full screen diff"
    );
    assert_eq!(diff_2_to_5[3563].0, 26);
    assert_eq!(diff_2_to_5[3563].1, 131);
}

/// Tests cursor position changes with and without cell updates.
#[test]
fn test_adversarial_cursor_and_cell_diff_combinations() {
    let base_cells = vec![SafeCell::BLANK; 1920];
    let view_base = SafeScreenView::new(24, 80, 0, 0, false, base_cells.clone()).unwrap();

    // Scenario A: Cursor changed, cells unchanged
    let view_cursor_only = SafeScreenView::new(24, 80, 10, 25, false, base_cells.clone()).unwrap();
    let diff_a = view_cursor_only.diff(&view_base);
    assert!(
        diff_a.is_empty(),
        "Cells did not change, diff must be empty"
    );
    assert!(
        view_cursor_only.cursor_changed(&view_base),
        "Cursor changed, cursor_changed must be true"
    );

    // Scenario B: Cells changed, cursor unchanged
    let mut modified_cells = base_cells.clone();
    modified_cells[50] = SafeCell {
        ch: 'K',
        ..SafeCell::BLANK
    };
    let view_cells_only = SafeScreenView::new(24, 80, 0, 0, false, modified_cells.clone()).unwrap();
    let diff_b = view_cells_only.diff(&view_base);
    assert_eq!(diff_b.len(), 1);
    assert!(!view_cells_only.cursor_changed(&view_base));

    // Scenario C: Both cursor changed and cells changed
    let view_both = SafeScreenView::new(24, 80, 15, 30, false, modified_cells).unwrap();
    let diff_c = view_both.diff(&view_base);
    assert_eq!(diff_c.len(), 1);
    assert!(view_both.cursor_changed(&view_base));

    // Scenario D: Neither cursor nor cells changed
    let view_same = SafeScreenView::new(24, 80, 0, 0, false, base_cells).unwrap();
    assert!(view_same.diff(&view_base).is_empty());
    assert!(!view_same.cursor_changed(&view_base));
}

// ============================================================================
// CHALLENGE 3: RESPONSE BUILDERS (READ MODIFIED & SHORT-READ AIDS)
// ============================================================================

/// Tests `build_read_modified` with ZERO modified fields.
/// Must emit ONLY AID + 2-byte cursor address (exactly 3 bytes).
#[test]
fn test_adversarial_read_modified_zero_modified_fields() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Set cursor at (row 12, col 40) = 1000
    let cursor_addr = BufferAddress::new(1000, cap).unwrap();
    ps.set_cursor_addr(cursor_addr).unwrap();

    // 1. Unformatted screen: all nulls
    let aid_enter = 0x7D;
    let stream_unformatted = build_read_modified(&ps, aid_enter, false);
    assert_eq!(
        stream_unformatted.len(),
        3,
        "Unformatted empty screen must emit exactly 3 bytes (AID + 2-byte cursor)"
    );
    assert_eq!(stream_unformatted[0], aid_enter);
    let [c1, c2] = cursor_addr.encode_12bit().unwrap();
    assert_eq!(stream_unformatted[1], c1);
    assert_eq!(stream_unformatted[2], c2);

    // 2. Formatted screen with multiple fields, ALL unmodified (MDT = 0)
    for f in 0..5 {
        let fa_addr = BufferAddress::new(f * 100, cap).unwrap();
        let fa = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false);
        ps.place_field(fa_addr, fa, ExtendedAttributes::DEFAULT)
            .unwrap();

        // Write non-null text into this unmodified field
        let text_addr = BufferAddress::new(f * 100 + 1, cap).unwrap();
        let ebcdic_z = CP037.char_to_ebcdic('Z').unwrap();
        ps.write_char(text_addr, ebcdic_z, ExtendedAttributes::DEFAULT)
            .unwrap();
    }

    let stream_formatted_zero_mod = build_read_modified(&ps, aid_enter, false);
    assert_eq!(
        stream_formatted_zero_mod.len(),
        3,
        "Formatted screen with 0 modified fields must emit exactly 3 bytes (AID + 2-byte cursor)"
    );
    assert_eq!(stream_formatted_zero_mod[0], aid_enter);
    assert_eq!(stream_formatted_zero_mod[1], c1);
    assert_eq!(stream_formatted_zero_mod[2], c2);
}

/// Tests `build_read_modified` with null characters:
/// Must suppress nulls (0x00) and preserve spaces (0x40).
#[test]
fn test_adversarial_read_modified_null_suppression_and_space_preservation() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Setup cursor at 0
    ps.set_cursor_addr(BufferAddress::ZERO).unwrap();

    // Field 1: at address 10, MDT=true
    let fa1_addr = BufferAddress::new(10, cap).unwrap();
    let fa1 = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, true);
    ps.place_field(fa1_addr, fa1, ExtendedAttributes::DEFAULT)
        .unwrap();

    // Write sequence: 'A' (0xC1), 0x00 (null), ' ' (0x40), 0x00 (null), 'B' (0xC2), ' ' (0x40)
    let seq = [
        (11, 0xC1u8), // 'A'
        (12, 0x00u8), // null -> must be suppressed
        (13, 0x40u8), // space -> MUST BE PRESERVED
        (14, 0x00u8), // null -> must be suppressed
        (15, 0xC2u8), // 'B'
        (16, 0x40u8), // space -> MUST BE PRESERVED
    ];
    for (pos, val) in seq {
        let addr = BufferAddress::new(pos, cap).unwrap();
        ps.write_char(addr, val, ExtendedAttributes::DEFAULT)
            .unwrap();
    }

    // Terminating field attribute at address 20
    let fa2_addr = BufferAddress::new(20, cap).unwrap();
    let fa2 = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false);
    ps.place_field(fa2_addr, fa2, ExtendedAttributes::DEFAULT)
        .unwrap();

    let aid_enter = 0x7D;
    let stream = build_read_modified(&ps, aid_enter, false);

    // Expected structure:
    // [0] AID = 0x7D
    // [1..=2] Cursor address (0 -> [0x40, 0x40])
    // [3] ORDER_SBA (0x11)
    // [4..=5] Address of first data cell (11 -> [c1, c2])
    // [6..=9] 0xC1 ('A'), 0x40 (' '), 0xC2 ('B'), 0x40 (' ')
    assert_eq!(stream[0], aid_enter);
    assert_eq!(stream[3], ORDER_SBA);
    let [exp_a1, exp_a2] = BufferAddress::new(11, cap).unwrap().encode_12bit().unwrap();
    assert_eq!(stream[4], exp_a1);
    assert_eq!(stream[5], exp_a2);

    let data_bytes = &stream[6..];
    assert_eq!(
        data_bytes,
        &[0xC1, 0x40, 0xC2, 0x40],
        "Nulls (0x00) must be suppressed and spaces (0x40) must be preserved!"
    );
    assert_eq!(stream.len(), 10);
}

/// Tests modified field containing ONLY nulls vs modified field containing ONLY spaces.
#[test]
fn test_adversarial_read_modified_all_null_field_vs_all_space_field() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Field 1: at address 10, MDT=true, contains only 5 nulls (11..15)
    let fa1_addr = BufferAddress::new(10, cap).unwrap();
    let fa1 = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, true);
    ps.place_field(fa1_addr, fa1, ExtendedAttributes::DEFAULT)
        .unwrap();
    for i in 11..16 {
        ps.write_char(
            BufferAddress::new(i, cap).unwrap(),
            0x00,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
    }

    // Field 2: at address 20, MDT=true, contains only 3 spaces (21..23)
    let fa2_addr = BufferAddress::new(20, cap).unwrap();
    let fa2 = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, true);
    ps.place_field(fa2_addr, fa2, ExtendedAttributes::DEFAULT)
        .unwrap();
    for i in 21..24 {
        ps.write_char(
            BufferAddress::new(i, cap).unwrap(),
            0x40,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
    }

    // End field marker at 30
    let fa3_addr = BufferAddress::new(30, cap).unwrap();
    let fa3 = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false);
    ps.place_field(fa3_addr, fa3, ExtendedAttributes::DEFAULT)
        .unwrap();

    let stream = build_read_modified(&ps, 0x7D, false);

    // Field 1 has only nulls: MUST emit SBA(11) with 0 data bytes!
    // Field 2 has 3 spaces: MUST emit SBA(21) with 3 bytes of 0x40!
    // Total: AID(1) + Cursor(2) + SBA1(3) + SBA2(3) + Spaces(3) = 12 bytes
    assert_eq!(stream[0], 0x7D);
    assert_eq!(stream[3], ORDER_SBA);
    let [a1_1, a1_2] = BufferAddress::new(11, cap).unwrap().encode_12bit().unwrap();
    assert_eq!(stream[4], a1_1);
    assert_eq!(stream[5], a1_2);

    // Right after SBA1 is SBA2 (no data bytes for Field 1!)
    assert_eq!(stream[6], ORDER_SBA);
    let [a2_1, a2_2] = BufferAddress::new(21, cap).unwrap().encode_12bit().unwrap();
    assert_eq!(stream[7], a2_1);
    assert_eq!(stream[8], a2_2);

    // Data for Field 2: 3 spaces
    assert_eq!(&stream[9..12], &[0x40, 0x40, 0x40]);
    assert_eq!(stream.len(), 12);
}

/// Tests short-read AIDs (PA1, PA2, PA3, Clear):
/// In 3270 hardware and RFC 2355, these MUST emit EXACTLY 1 byte,
/// even when the screen is heavily populated with modified fields and cursor is not at zero.
#[test]
fn test_adversarial_short_read_aids() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Populate multiple modified fields with text
    for f in 0..10 {
        let fa_addr = BufferAddress::new(f * 50, cap).unwrap();
        let fa = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, true);
        ps.place_field(fa_addr, fa, ExtendedAttributes::DEFAULT)
            .unwrap();

        for c in 1..20 {
            let addr = BufferAddress::new(f * 50 + c, cap).unwrap();
            let ebcdic = CP037.char_to_ebcdic('M').unwrap();
            ps.write_char(addr, ebcdic, ExtendedAttributes::DEFAULT)
                .unwrap();
        }
    }

    // Set cursor at (row 18, col 60)
    ps.set_cursor_addr(BufferAddress::new(18 * 80 + 60, cap).unwrap())
        .unwrap();

    let short_aids = [AID_CLEAR, AID_PA1, AID_PA2, AID_PA3];

    for &aid in &short_aids {
        assert!(
            is_short_read_aid(aid),
            "0x{:02X} must be recognized as short read AID",
            aid
        );

        let stream = build_read_modified(&ps, aid, false);
        assert_eq!(
            stream.len(),
            1,
            "Short read AID 0x{:02X} must emit EXACTLY 1 byte, but emitted {} bytes: {:?}",
            aid,
            stream.len(),
            stream
        );
        assert_eq!(stream[0], aid);
    }

    // Verification of Read Modified All override:
    // If read_all=true (Read Modified All), short-read AIDs do NOT short-circuit
    for &aid in &short_aids {
        let stream_all = build_read_modified(&ps, aid, true);
        assert!(
            stream_all.len() > 1,
            "Read Modified All with AID 0x{:02X} must emit full stream, not 1 byte",
            aid
        );
        assert_eq!(stream_all[0], aid);
    }
}

/// Tests `build_read_buffer` full screen capture fidelity.
#[test]
fn test_adversarial_read_buffer_fidelity() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Set cursor
    let cursor_pos = BufferAddress::new(250, cap).unwrap();
    ps.set_cursor_addr(cursor_pos).unwrap();

    // Place field attribute at 10
    let fa_addr = BufferAddress::new(10, cap).unwrap();
    let fa = FieldAttribute::new(true, true, FieldIntensity::HighDetectable, true);
    ps.place_field(fa_addr, fa, ExtendedAttributes::DEFAULT)
        .unwrap();

    let stream = build_read_buffer(&ps);
    assert_eq!(stream[0], 0x60); // AID_NO
    let [c1, c2] = cursor_pos.encode_12bit().unwrap();
    assert_eq!(stream[1], c1);
    assert_eq!(stream[2], c2);

    // At index 3 + 10 = 13, ORDER_SF and wire attribute byte must appear
    assert_eq!(stream[13], ORDER_SF);
    assert_eq!(stream[14], fa.to_wire_byte());
}
