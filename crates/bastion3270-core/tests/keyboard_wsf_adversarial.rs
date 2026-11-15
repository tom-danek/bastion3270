//! Adversarial integration tests for Virtual Keyboard, OIA, and WSF Query Reply Engine.
//!
//! Covers:
//! 1. Virtual keyboard boundary & security stress (protected fields, attribute cells, numeric validation, 1919->0 wrapping).
//! 2. Auto-skip navigation edge cases (chains of auto-skips, 100% protected screen panic/infinite loop defense, coordinate wrapping).
//! 3. AID keystrokes & Read Modified generation stress (lock state enforcement, full vs short-read AIDs, exact null suppression).
//! 4. WSF Query Reply adversarial queries (malformed inputs, deduplication, canonical ordering, QR_NULL fallback, multi-model/codepage).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::cast_possible_truncation
)]

use bastion3270_core::address::BufferAddress;
use bastion3270_core::datastream::order::ORDER_SBA;
use bastion3270_core::datastream::wcc::WriteControlCharacter;
use bastion3270_core::ebcdic::{CodePage, CP037, IBM870};
use bastion3270_core::field::{ExtendedAttributes, FieldAttribute};
use bastion3270_core::keyboard::{
    ActionKey, AidKey, KeyboardError, KeyboardState, VirtualKeyboard,
};
use bastion3270_core::model::TerminalModel;
use bastion3270_core::screen::PresentationSpace;
use bastion3270_core::wsf::{
    parse_read_partition, QueryReplyBuilder, QueryRequest, WsfError, AID_SF, QR_ALPHA_PART,
    QR_CHARSETS, QR_COLOR, QR_HIGHLIGHTING, QR_IMP_PART, QR_NULL, QR_REPLY_MODES, QR_SUMMARY,
    QR_USABLE_AREA, SFID_QREPLY, SUPPORTED_QUERY_CODES,
};

// ============================================================================
// PART 1: Virtual Keyboard Boundary & Security Stress
// ============================================================================

#[test]
fn test_adversarial_type_into_protected_field_locks_and_rejects() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Place protected field at addr 10 (data cells 11..19)
    let fa_prot = FieldAttribute::from_wire_byte(0x20); // Bit 5 set = protected
    assert!(fa_prot.is_protected());
    assert_eq!(
        ps.place_field(
            BufferAddress::new(10, 1920).unwrap(),
            fa_prot,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Place unprotected field at addr 20 (data cells 21..29)
    let fa_unprot = FieldAttribute::from_wire_byte(0x00);
    assert_eq!(
        ps.place_field(
            BufferAddress::new(20, 1920).unwrap(),
            fa_unprot,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Cursor positioned in protected field (cell 15)
    let c15 = BufferAddress::new(15, 1920).unwrap();
    assert_eq!(ps.set_cursor_addr(c15), Ok(()));

    // Attempting character input must immediately fail and transition to Protected state
    let res = kb.input_char(&mut ps, 'A', &CP037);
    assert_eq!(res, Err(KeyboardError::ProtectedField));
    assert_eq!(kb.state(), KeyboardState::Protected);
    assert!(kb.is_locked());
    assert!(kb.state().is_operator_error());
    assert_eq!(kb.state().oia_indicator(), "X PROTECTED");

    // While locked in Protected, ANY subsequent character input is rejected with Locked(Protected)
    let res_followup = kb.input_char(&mut ps, 'B', &CP037);
    assert_eq!(
        res_followup,
        Err(KeyboardError::Locked(KeyboardState::Protected))
    );

    // AID key presses are also rejected while locked
    let res_aid = kb.press_aid(&mut ps, AidKey::Enter);
    assert_eq!(
        res_aid,
        Err(KeyboardError::Locked(KeyboardState::Protected))
    );

    // Newline does not clear an operator error, so it is rejected while locked (x3270 uses a
    // plain enqueue for Newline, not `OERR_CLEAR_OR_ENQ`).
    let res_newline = kb.action(&mut ps, ActionKey::Newline);
    assert_eq!(
        res_newline,
        Err(KeyboardError::Locked(KeyboardState::Protected))
    );

    // ActionKey::Reset unlocks operator error
    assert_eq!(kb.action(&mut ps, ActionKey::Reset), Ok(()));
    assert_eq!(kb.state(), KeyboardState::Unlocked);
    assert!(!kb.is_locked());

    // Move to unprotected field (cell 21) and verify input succeeds
    let c21 = BufferAddress::new(21, 1920).unwrap();
    assert_eq!(ps.set_cursor_addr(c21), Ok(()));
    assert_eq!(kb.input_char(&mut ps, 'X', &CP037), Ok(()));
    assert_eq!(
        ps.cell(c21).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0xE7) // 'X' in CP037
    );
    assert_eq!(ps.cursor_addr().as_usize(), 22);
}

#[test]
fn test_adversarial_type_onto_field_attribute_marker_cell() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Field 1 at addr 0 (unprotected)
    let fa_unprot = FieldAttribute::from_wire_byte(0x00);
    assert_eq!(
        ps.place_field(BufferAddress::ZERO, fa_unprot, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    // Field 2 at addr 40 (protected)
    let fa_prot = FieldAttribute::from_wire_byte(0x20);
    let a40 = BufferAddress::new(40, 1920).unwrap();
    assert_eq!(
        ps.place_field(a40, fa_prot, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    // 1. Attempt to type directly on cell 0 (unprotected field attribute marker)
    assert_eq!(ps.set_cursor_addr(BufferAddress::ZERO), Ok(()));
    let res1 = kb.input_char(&mut ps, 'T', &CP037);
    assert_eq!(res1, Err(KeyboardError::ProtectedField));
    assert_eq!(kb.state(), KeyboardState::Protected);

    // Unlock
    assert_eq!(kb.action(&mut ps, ActionKey::Reset), Ok(()));
    assert_eq!(kb.state(), KeyboardState::Unlocked);

    // 2. Attempt to type directly on cell 40 (protected field attribute marker)
    assert_eq!(ps.set_cursor_addr(a40), Ok(()));
    let res2 = kb.input_char(&mut ps, 'U', &CP037);
    assert_eq!(res2, Err(KeyboardError::ProtectedField));
    assert_eq!(kb.state(), KeyboardState::Protected);

    // Verify cell 40 is still a field attribute and was not overwritten
    let cell_40 = ps.cell(a40).unwrap();
    assert!(cell_40.is_field_attribute());
}

#[test]
fn test_adversarial_numeric_field_rejections_and_recovery() {
    // Numeric lock is off by default (x3270 `numericLock`); this test turns it on.
    let mut kb = VirtualKeyboard::with_options(bastion3270_core::KeyboardOptions {
        numeric_lock: true,
        ..bastion3270_core::KeyboardOptions::DEFAULT
    });
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Numeric field at addr 0 (wire byte 0x10 = numeric, unprotected)
    let fa_num = FieldAttribute::from_wire_byte(0x10);
    assert!(fa_num.is_numeric());
    assert!(!fa_num.is_protected());
    assert_eq!(
        ps.place_field(BufferAddress::ZERO, fa_num, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    let c1 = BufferAddress::new(1, 1920).unwrap();
    assert_eq!(ps.set_cursor_addr(c1), Ok(()));

    // Valid numeric characters: '0'..'9', '+', '-', '.', ','
    let valid_chars = ['1', '9', '0', '+', '-', '.', ','];
    for ch in valid_chars {
        assert_eq!(kb.input_char(&mut ps, ch, &CP037), Ok(()));
        assert_eq!(kb.state(), KeyboardState::Unlocked);
    }
    assert_eq!(ps.cursor_addr().as_usize(), 1 + valid_chars.len());

    // Invalid characters: letters, spaces, symbols
    let invalid_chars = ['A', 'z', ' ', '$', '#', '@', '/', '*', '!', '?'];
    for ch in invalid_chars {
        // Character entry must fail with NumericField error
        let err = kb.input_char(&mut ps, ch, &CP037);
        assert_eq!(err, Err(KeyboardError::NumericField));

        // State is locked in Numeric
        assert_eq!(kb.state(), KeyboardState::Numeric);
        assert!(kb.is_locked());
        assert_eq!(kb.state().oia_indicator(), "X NUMERIC");

        // Subsequent inputs are rejected with Locked(Numeric)
        assert_eq!(
            kb.input_char(&mut ps, '1', &CP037),
            Err(KeyboardError::Locked(KeyboardState::Numeric))
        );

        // AID key is rejected with Locked(Numeric)
        assert_eq!(
            kb.press_aid(&mut ps, AidKey::Enter),
            Err(KeyboardError::Locked(KeyboardState::Numeric))
        );

        // Reset clears error lock
        assert_eq!(kb.action(&mut ps, ActionKey::Reset), Ok(()));
        assert_eq!(kb.state(), KeyboardState::Unlocked);
    }
}

#[test]
fn test_adversarial_buffer_wraparound_typing_at_corner_formatted() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Place unprotected field at address 1915.
    // In 3270 circular memory, this field spans data cells 1916..=1919 and wraps into 0..=9!
    let a1915 = BufferAddress::new(1915, 1920).unwrap();
    let fa_wrap = FieldAttribute::from_wire_byte(0x00);
    assert_eq!(
        ps.place_field(a1915, fa_wrap, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    // Place terminating protected field at address 10
    let a10 = BufferAddress::new(10, 1920).unwrap();
    let fa_term = FieldAttribute::from_wire_byte(0x20);
    assert_eq!(
        ps.place_field(a10, fa_term, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    // Position cursor at bottom-right corner of screen (address 1919: row 23, col 79)
    let c1919 = BufferAddress::new(1919, 1920).unwrap();
    assert_eq!(ps.set_cursor_addr(c1919), Ok(()));
    assert_eq!(ps.cursor_addr().to_row_col(80), (23, 79));

    // Type 'Z' into corner cell 1919
    assert_eq!(kb.input_char(&mut ps, 'Z', &CP037), Ok(()));

    // Cursor must have cleanly wrapped from 1919 -> 0 (row 0, col 0)
    assert_eq!(ps.cursor_addr().as_usize(), 0);
    assert_eq!(ps.cursor_addr().to_row_col(80), (0, 0));

    // Cell 1919 must contain EBCDIC 'Z' (0xE9)
    assert_eq!(
        ps.cell(c1919)
            .map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0xE9)
    );

    // Type 'A' into cell 0 across the boundary
    assert_eq!(kb.input_char(&mut ps, 'A', &CP037), Ok(()));

    // Cursor advances to 1
    assert_eq!(ps.cursor_addr().as_usize(), 1);

    // Cell 0 must contain EBCDIC 'A' (0xC1)
    let c0 = BufferAddress::ZERO;
    assert_eq!(
        ps.cell(c0).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0xC1)
    );

    // Governing field at 1915 must be modified
    let gov = ps.governing_field(c0);
    assert!(gov.is_some());
    let (gov_addr, gov_fa, _) = gov.unwrap();
    assert_eq!(gov_addr.as_usize(), 1915);
    assert!(gov_fa.is_modified());
}

#[test]
fn test_adversarial_buffer_wraparound_typing_at_corner_unformatted() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    assert!(!ps.is_formatted());

    // Position cursor at 1919 on unformatted screen
    let c1919 = BufferAddress::new(1919, 1920).unwrap();
    assert_eq!(ps.set_cursor_addr(c1919), Ok(()));

    // Type 'X' at 1919
    assert_eq!(kb.input_char(&mut ps, 'X', &CP037), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 0); // Wrapped to top-left!
    assert_eq!(
        ps.cell(c1919)
            .map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0xE7)
    );

    // Type 'Y' at 0
    assert_eq!(kb.input_char(&mut ps, 'Y', &CP037), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 1);
    assert_eq!(
        ps.cell(BufferAddress::ZERO)
            .map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0xE8)
    );
}

#[test]
fn test_adversarial_wraparound_typing_onto_autoskip_marker_at_zero() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Unprotected field at 1910 (data 1911..=1919)
    let a1910 = BufferAddress::new(1910, 1920).unwrap();
    assert_eq!(
        ps.place_field(
            a1910,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Auto-skip field at address 0 (Protected | Numeric = wire byte 0x30, data 1..=9)
    let fa_skip = FieldAttribute::from_wire_byte(0x30);
    assert!(fa_skip.is_skip());
    assert_eq!(
        ps.place_field(BufferAddress::ZERO, fa_skip, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    // Unprotected field at address 10 (data 11..=19)
    let a10 = BufferAddress::new(10, 1920).unwrap();
    assert_eq!(
        ps.place_field(
            a10,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Cursor at bottom-right corner 1919
    let c1919 = BufferAddress::new(1919, 1920).unwrap();
    assert_eq!(ps.set_cursor_addr(c1919), Ok(()));

    // Type 'Q' into cell 1919.
    // Next cell is 0, which is an auto-skip field attribute marker!
    // VirtualKeyboard must automatically skip past the auto-skip field to cell 11!
    assert_eq!(kb.input_char(&mut ps, 'Q', &CP037), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 11);
}

// ============================================================================
// PART 2: Auto-Skip Navigation Edge Cases
// ============================================================================

#[test]
fn test_adversarial_chain_of_consecutive_autoskip_fields() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Field 1 at addr 0: Unprotected (data cells 1..=4)
    assert_eq!(
        ps.place_field(
            BufferAddress::ZERO,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // 4 consecutive auto-skip fields:
    // Field 2 at addr 5 (skip)
    // Field 3 at addr 10 (skip)
    // Field 4 at addr 15 (skip)
    // Field 5 at addr 20 (skip)
    for idx in [5, 10, 15, 20] {
        let addr = BufferAddress::new(idx, 1920).unwrap();
        assert_eq!(
            ps.place_field(
                addr,
                FieldAttribute::from_wire_byte(0x30),
                ExtendedAttributes::DEFAULT
            ),
            Ok(())
        );
    }

    // Field 6 at addr 25: Unprotected (data cells 26..=30)
    let a25 = BufferAddress::new(25, 1920).unwrap();
    assert_eq!(
        ps.place_field(
            a25,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Position cursor at cell 4 (last cell of Field 1)
    let c4 = BufferAddress::new(4, 1920).unwrap();
    assert_eq!(ps.set_cursor_addr(c4), Ok(()));

    // Typing a character into cell 4 triggers auto-skip at cell 5.
    // It must jump past all 4 auto-skip fields (5, 10, 15, 20) and land on cell 26!
    assert_eq!(kb.input_char(&mut ps, 'H', &CP037), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 26);
}

#[test]
fn test_adversarial_chain_of_autoskip_fields_wrapping_around_screen() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Only ONE unprotected field on entire screen: Field 1 at addr 0 (data cells 1..=4)
    assert_eq!(
        ps.place_field(
            BufferAddress::ZERO,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Remaining fields across screen are all auto-skip fields
    for idx in [5, 500, 1000, 1500, 1800] {
        let addr = BufferAddress::new(idx, 1920).unwrap();
        assert_eq!(
            ps.place_field(
                addr,
                FieldAttribute::from_wire_byte(0x30),
                ExtendedAttributes::DEFAULT
            ),
            Ok(())
        );
    }

    // Cursor at cell 4
    let c4 = BufferAddress::new(4, 1920).unwrap();
    assert_eq!(ps.set_cursor_addr(c4), Ok(()));

    // Typing into cell 4 triggers auto-skip at cell 5.
    // It must search forward, wrap past 1919->0, and jump back to cell 1 (first data cell of Field 1)!
    assert_eq!(kb.input_char(&mut ps, 'W', &CP037), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 1);
}

#[test]
fn test_adversarial_100_percent_protected_screen_no_hang_or_panic() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Create a 100% protected screen (zero unprotected fields):
    // Mix of protected and auto-skip (protected+numeric) fields
    let fields = [(0, 0x20), (200, 0x30), (800, 0x28), (1400, 0x30)];
    for (idx, wire) in fields {
        let addr = BufferAddress::new(idx, 1920).unwrap();
        assert_eq!(
            ps.place_field(
                addr,
                FieldAttribute::from_wire_byte(wire),
                ExtendedAttributes::DEFAULT
            ),
            Ok(())
        );
    }

    assert!(ps.is_formatted());
    assert_eq!(ps.first_unprotected_data_addr(), None);

    // Set cursor to cell 50
    let c50 = BufferAddress::new(50, 1920).unwrap();
    assert_eq!(ps.set_cursor_addr(c50), Ok(()));

    // 1. Tab must NOT loop infinitely; with no unprotected field it goes to address 0
    //    (x3270 `Tab_action`: `next_unprotected` returns 0)
    assert_eq!(kb.action(&mut ps, ActionKey::Tab), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 0);

    // 2. BackTab must NOT loop infinitely; with no unprotected field it goes to address 0
    assert_eq!(ps.set_cursor_addr(c50), Ok(()));
    assert_eq!(kb.action(&mut ps, ActionKey::BackTab), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 0);

    // 3. Home defaults safely to BufferAddress::ZERO without panic
    assert_eq!(kb.action(&mut ps, ActionKey::Home), Ok(()));
    assert_eq!(ps.cursor_addr(), BufferAddress::ZERO);

    // Reset cursor to 50
    assert_eq!(ps.set_cursor_addr(c50), Ok(()));

    // 4. Newline safely handles 100% protected screen without infinite loop or panic
    assert_eq!(kb.action(&mut ps, ActionKey::Newline), Ok(()));

    // 5. Arrow keys wrap cleanly
    assert_eq!(kb.action(&mut ps, ActionKey::Left), Ok(()));
    assert_eq!(kb.action(&mut ps, ActionKey::Right), Ok(()));
    assert_eq!(kb.action(&mut ps, ActionKey::Up), Ok(()));
    assert_eq!(kb.action(&mut ps, ActionKey::Down), Ok(()));

    // 6. EraseInput on 100% protected screen does not touch protected cells
    assert_eq!(kb.action(&mut ps, ActionKey::EraseInput), Ok(()));

    // 7. Attempting character entry safely locks in Protected without panic
    assert_eq!(ps.set_cursor_addr(c50), Ok(()));
    let input_res = kb.input_char(&mut ps, 'A', &CP037);
    assert_eq!(input_res, Err(KeyboardError::ProtectedField));
    assert_eq!(kb.state(), KeyboardState::Protected);
}

#[test]
fn test_adversarial_screen_boundary_wrapping_all_directions() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Top-left corner (row 0, col 0) = addr 0
    assert_eq!(ps.set_cursor_addr(BufferAddress::ZERO), Ok(()));

    // Left from (0, 0) wraps to bottom-right (23, 79) = addr 1919
    assert_eq!(kb.action(&mut ps, ActionKey::Left), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 1919);
    assert_eq!(ps.cursor_addr().to_row_col(80), (23, 79));

    // Right from 1919 wraps to 0
    assert_eq!(kb.action(&mut ps, ActionKey::Right), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 0);

    // Up from (0, 40) wraps vertically to (23, 40)
    let c0_40 = BufferAddress::from_row_col(0, 40, 24, 80).unwrap();
    assert_eq!(ps.set_cursor_addr(c0_40), Ok(()));
    assert_eq!(kb.action(&mut ps, ActionKey::Up), Ok(()));
    assert_eq!(ps.cursor_addr().to_row_col(80), (23, 40));

    // Down from (23, 40) wraps vertically to (0, 40)
    assert_eq!(kb.action(&mut ps, ActionKey::Down), Ok(()));
    assert_eq!(ps.cursor_addr().to_row_col(80), (0, 40));

    // Tab and BackTab wrapping across bottom and top:
    // Field 1 at addr 10 (data 11..19)
    // Field 2 at addr 1900 (data 1901..1909)
    let a10 = BufferAddress::new(10, 1920).unwrap();
    let a1900 = BufferAddress::new(1900, 1920).unwrap();
    assert_eq!(
        ps.place_field(
            a10,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.place_field(
            a1900,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Tab from Field 2 (cell 1901) wraps around to Field 1 (cell 11)
    let c1901 = BufferAddress::new(1901, 1920).unwrap();
    assert_eq!(ps.set_cursor_addr(c1901), Ok(()));
    assert_eq!(kb.action(&mut ps, ActionKey::Tab), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 11);

    // BackTab from Field 1 (cell 11) wraps backwards to Field 2 (cell 1901)
    assert_eq!(kb.action(&mut ps, ActionKey::BackTab), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 1901);
}

#[test]
fn test_adversarial_zero_width_unprotected_fields_navigation() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Adjacent field attributes: addr 10 is unprotected FA, addr 11 is protected FA.
    // Field at 10 has zero data cells!
    let a10 = BufferAddress::new(10, 1920).unwrap();
    let a11 = BufferAddress::new(11, 1920).unwrap();
    let a20 = BufferAddress::new(20, 1920).unwrap();

    assert_eq!(
        ps.place_field(
            a10,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.place_field(
            a11,
            FieldAttribute::from_wire_byte(0x20),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.place_field(
            a20,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Start cursor at 0
    assert_eq!(ps.set_cursor_addr(BufferAddress::ZERO), Ok(()));

    // Tab must skip the zero-width field at 10 and land on first data cell of field at 20 (cell 21)!
    assert_eq!(kb.action(&mut ps, ActionKey::Tab), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 21);
}

// ============================================================================
// PART 3: AID Keystrokes & Read Modified Generation Stress
// ============================================================================

#[test]
fn test_adversarial_aid_lock_state_and_wcc_restoration() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Create unprotected field at addr 0
    assert_eq!(
        ps.place_field(
            BufferAddress::ZERO,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Pressing AID transitions to TimeWait
    let stream_res = kb.press_aid(&mut ps, AidKey::Enter);
    assert!(stream_res.is_ok());
    assert_eq!(kb.state(), KeyboardState::TimeWait);
    assert!(kb.is_locked());
    assert!(!kb.state().is_operator_error());
    assert_eq!(kb.state().oia_indicator(), "X Wait");

    // All key operations must be rejected with Locked(TimeWait)
    assert_eq!(
        kb.input_char(&mut ps, 'A', &CP037),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
    assert_eq!(
        kb.press_aid(&mut ps, AidKey::PF1),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
    assert_eq!(
        kb.action(&mut ps, ActionKey::Tab),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
    assert_eq!(
        kb.action(&mut ps, ActionKey::BackTab),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
    assert_eq!(
        kb.action(&mut ps, ActionKey::Home),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
    assert_eq!(
        kb.action(&mut ps, ActionKey::Newline),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
    assert_eq!(
        kb.action(&mut ps, ActionKey::Left),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
    assert_eq!(
        kb.action(&mut ps, ActionKey::Right),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
    assert_eq!(
        kb.action(&mut ps, ActionKey::Up),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
    assert_eq!(
        kb.action(&mut ps, ActionKey::Down),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
    assert_eq!(
        kb.action(&mut ps, ActionKey::EraseEof),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
    assert_eq!(
        kb.action(&mut ps, ActionKey::EraseInput),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );

    // Host WCC with restore_keyboard = false ends the AID wait but keeps the AID lock
    // (x3270 `ctlr_write`: only TWAIT is cleared → X SYSTEM).
    kb.handle_wcc(
        &mut ps,
        WriteControlCharacter {
            restore_keyboard: false,
            ..Default::default()
        },
    );
    assert_eq!(kb.state(), KeyboardState::SystemLock);
    assert!(kb.is_locked());

    // Host WCC with restore_keyboard = true unlocks keyboard
    kb.handle_wcc(
        &mut ps,
        WriteControlCharacter {
            restore_keyboard: true,
            ..Default::default()
        },
    );
    assert_eq!(kb.state(), KeyboardState::Unlocked);
    assert!(!kb.is_locked());
}

#[test]
fn test_adversarial_short_read_aids_vs_full_aids() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Populate a field with text
    assert_eq!(
        ps.place_field(
            BufferAddress::ZERO,
            FieldAttribute::from_wire_byte(0x01), // MDT=true
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    let c1 = BufferAddress::new(1, 1920).unwrap();
    assert_eq!(ps.write_char(c1, 0xC1, ExtendedAttributes::DEFAULT), Ok(()));

    // 1. Test short-read AIDs: PA1..PA3, Clear
    let short_aids = [
        (AidKey::PA1, 0x6C),
        (AidKey::PA2, 0x6E),
        (AidKey::PA3, 0x6B),
        (AidKey::Clear, 0x6D),
    ];

    for (aid, wire) in short_aids {
        kb.host_reset();
        let res = kb.press_aid(&mut ps, aid).unwrap();
        // Short read AID transmits ONLY the 1-byte AID code
        assert_eq!(res, vec![wire]);
        assert_eq!(kb.state(), KeyboardState::TimeWait);
    }

    // Clear must also erase all presentation space cells
    assert_eq!(
        ps.cell(c1).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0x00)
    );

    // 2. Test all 24 Program Function keys (PF1..PF24)
    let pf_keys = [
        (AidKey::PF1, 0xF1),
        (AidKey::PF2, 0xF2),
        (AidKey::PF3, 0xF3),
        (AidKey::PF4, 0xF4),
        (AidKey::PF5, 0xF5),
        (AidKey::PF6, 0xF6),
        (AidKey::PF7, 0xF7),
        (AidKey::PF8, 0xF8),
        (AidKey::PF9, 0xF9),
        (AidKey::PF10, 0x7A),
        (AidKey::PF11, 0x7B),
        (AidKey::PF12, 0x7C),
        (AidKey::PF13, 0xC1),
        (AidKey::PF14, 0xC2),
        (AidKey::PF15, 0xC3),
        (AidKey::PF16, 0xC4),
        (AidKey::PF17, 0xC5),
        (AidKey::PF18, 0xC6),
        (AidKey::PF19, 0xC7),
        (AidKey::PF20, 0xC8),
        (AidKey::PF21, 0xC9),
        (AidKey::PF22, 0x4A),
        (AidKey::PF23, 0x4B),
        (AidKey::PF24, 0x4C),
    ];

    for (pf_key, expected_byte) in pf_keys {
        assert_eq!(pf_key.to_byte(), expected_byte);
        assert!(!pf_key.is_short_read());
        kb.host_reset();
        let stream = kb.press_aid(&mut ps, pf_key).unwrap();
        // Full AID stream starts with AID byte followed by 2-byte cursor address
        assert_eq!(stream.first(), Some(&expected_byte));
        assert!(stream.len() >= 3);
    }
}

#[test]
fn test_adversarial_read_modified_null_suppression_comprehensive() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Field 1 at addr 10: MDT=true. Cells 11..15: leading nulls [0x00, 0x00, 0xC1, 0xC2, 0xC3]
    let a10 = BufferAddress::new(10, cap).unwrap();
    assert_eq!(
        ps.place_field(
            a10,
            FieldAttribute::from_wire_byte(0x01),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(11, cap).unwrap(),
            0x00,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(12, cap).unwrap(),
            0x00,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(13, cap).unwrap(),
            0xC1,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(14, cap).unwrap(),
            0xC2,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(15, cap).unwrap(),
            0xC3,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Field 2 at addr 20: MDT=true. Cells 21..25: middle nulls [0xC4, 0x00, 0xC5, 0x00, 0xC6]
    let a20 = BufferAddress::new(20, cap).unwrap();
    assert_eq!(
        ps.place_field(
            a20,
            FieldAttribute::from_wire_byte(0x01),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(21, cap).unwrap(),
            0xC4,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(22, cap).unwrap(),
            0x00,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(23, cap).unwrap(),
            0xC5,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(24, cap).unwrap(),
            0x00,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(25, cap).unwrap(),
            0xC6,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Field 3 at addr 30: MDT=true. Cells 31..35: trailing nulls [0xC7, 0xC8, 0xC9, 0x00, 0x00]
    let a30 = BufferAddress::new(30, cap).unwrap();
    assert_eq!(
        ps.place_field(
            a30,
            FieldAttribute::from_wire_byte(0x01),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(31, cap).unwrap(),
            0xC7,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(32, cap).unwrap(),
            0xC8,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(33, cap).unwrap(),
            0xC9,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(34, cap).unwrap(),
            0x00,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(35, cap).unwrap(),
            0x00,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Field 4 at addr 40: MDT=true. Cells 41..45: ONLY nulls [0x00, 0x00, 0x00, 0x00, 0x00]
    let a40 = BufferAddress::new(40, cap).unwrap();
    assert_eq!(
        ps.place_field(
            a40,
            FieldAttribute::from_wire_byte(0x01),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    for idx in 41..=45 {
        assert_eq!(
            ps.write_char(
                BufferAddress::new(idx, cap).unwrap(),
                0x00,
                ExtendedAttributes::DEFAULT
            ),
            Ok(())
        );
    }

    // Field 5 at addr 50: MDT=true. Cells 51..54: NO nulls [0xD1, 0xD2, 0xD3, 0xD4]
    let a50 = BufferAddress::new(50, cap).unwrap();
    assert_eq!(
        ps.place_field(
            a50,
            FieldAttribute::from_wire_byte(0x01),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(51, cap).unwrap(),
            0xD1,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(52, cap).unwrap(),
            0xD2,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(53, cap).unwrap(),
            0xD3,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    assert_eq!(
        ps.write_char(
            BufferAddress::new(54, cap).unwrap(),
            0xD4,
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Field 6 at addr 60: MDT=false (unmodified). Cells 61..65
    let a60 = BufferAddress::new(60, cap).unwrap();
    assert_eq!(
        ps.place_field(
            a60,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    for idx in 61..=65 {
        assert_eq!(
            ps.write_char(
                BufferAddress::new(idx, cap).unwrap(),
                0xE2,
                ExtendedAttributes::DEFAULT
            ),
            Ok(())
        );
    }

    // Set cursor at cell 12
    let cursor_addr = BufferAddress::new(12, cap).unwrap();
    assert_eq!(ps.set_cursor_addr(cursor_addr), Ok(()));
    let [exp_cur1, exp_cur2] = cursor_addr.encode_for_capacity(cap).unwrap();

    // Trigger Enter AID (0x7D)
    let stream = kb.press_aid(&mut ps, AidKey::Enter).unwrap();

    // Construct expected exact byte stream:
    let [sba1_1, sba1_2] = BufferAddress::new(11, cap)
        .unwrap()
        .encode_for_capacity(cap)
        .unwrap();
    let [sba2_1, sba2_2] = BufferAddress::new(21, cap)
        .unwrap()
        .encode_for_capacity(cap)
        .unwrap();
    let [sba3_1, sba3_2] = BufferAddress::new(31, cap)
        .unwrap()
        .encode_for_capacity(cap)
        .unwrap();
    let [sba4_1, sba4_2] = BufferAddress::new(41, cap)
        .unwrap()
        .encode_for_capacity(cap)
        .unwrap();
    let [sba5_1, sba5_2] = BufferAddress::new(51, cap)
        .unwrap()
        .encode_for_capacity(cap)
        .unwrap();

    // 1. Header: AID + 2-byte cursor address
    let mut expected = vec![0x7D, exp_cur1, exp_cur2];

    // 2. Field 1: SBA(11) + [0xC1, 0xC2, 0xC3]
    expected.push(ORDER_SBA);
    expected.push(sba1_1);
    expected.push(sba1_2);
    expected.extend_from_slice(&[0xC1, 0xC2, 0xC3]);

    // 3. Field 2: SBA(21) + [0xC4, 0xC5, 0xC6]
    expected.push(ORDER_SBA);
    expected.push(sba2_1);
    expected.push(sba2_2);
    expected.extend_from_slice(&[0xC4, 0xC5, 0xC6]);

    // 4. Field 3: SBA(31) + [0xC7, 0xC8, 0xC9]
    expected.push(ORDER_SBA);
    expected.push(sba3_1);
    expected.push(sba3_2);
    expected.extend_from_slice(&[0xC7, 0xC8, 0xC9]);

    // 5. Field 4: SBA(41) with NO characters!
    expected.push(ORDER_SBA);
    expected.push(sba4_1);
    expected.push(sba4_2);

    // 6. Field 5: SBA(51) + [0xD1, 0xD2, 0xD3, 0xD4]
    expected.push(ORDER_SBA);
    expected.push(sba5_1);
    expected.push(sba5_2);
    expected.extend_from_slice(&[0xD1, 0xD2, 0xD3, 0xD4]);

    // Field 6 must NOT be in stream (MDT=false)
    assert_eq!(stream, expected);

    // Host resets MDT via WCC
    kb.handle_wcc(
        &mut ps,
        WriteControlCharacter {
            restore_keyboard: true,
            reset_mdt: true,
            ..Default::default()
        },
    );

    // All MDTs are now false
    for fa_idx in [10, 20, 30, 40, 50] {
        let addr = BufferAddress::new(fa_idx, cap).unwrap();
        let gov = ps.governing_field(addr);
        assert_eq!(gov.map(|(_, f, _)| f.is_modified()), Some(false));
    }
}

#[test]
fn test_adversarial_read_modified_unformatted_screen_null_suppression() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Write sparse characters with surrounding nulls on unformatted screen
    let a5 = BufferAddress::new(5, cap).unwrap();
    let a10 = BufferAddress::new(10, cap).unwrap();
    assert_eq!(ps.write_char(a5, 0xC1, ExtendedAttributes::DEFAULT), Ok(()));
    assert_eq!(
        ps.write_char(a10, 0xC2, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    let cur = BufferAddress::new(15, cap).unwrap();
    assert_eq!(ps.set_cursor_addr(cur), Ok(()));
    let [c1, c2] = cur.encode_for_capacity(cap).unwrap();

    let stream = kb.press_aid(&mut ps, AidKey::Enter).unwrap();
    // Unformatted stream contains AID + cursor address + non-null characters without SBA
    assert_eq!(stream, vec![0x7D, c1, c2, 0xC1, 0xC2]);
}

#[test]
fn test_adversarial_read_modified_screen_with_no_modified_fields() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();

    // Fields exist but NONE are modified
    for idx in [0, 50, 100] {
        let addr = BufferAddress::new(idx, cap).unwrap();
        assert_eq!(
            ps.place_field(
                addr,
                FieldAttribute::from_wire_byte(0x00),
                ExtendedAttributes::DEFAULT
            ),
            Ok(())
        );
    }

    let cur = BufferAddress::new(25, cap).unwrap();
    assert_eq!(ps.set_cursor_addr(cur), Ok(()));
    let [c1, c2] = cur.encode_for_capacity(cap).unwrap();

    let stream = kb.press_aid(&mut ps, AidKey::PF3).unwrap();
    // Screen has no modified fields: stream contains ONLY AID + cursor address (3 bytes)
    assert_eq!(stream, vec![0xF3, c1, c2]);
}

// ============================================================================
// PART 4: WSF Query Reply Adversarial Queries
// ============================================================================

#[test]
fn test_adversarial_parse_read_partition_malformed_inputs() {
    // 1. Truncated fields
    assert_eq!(
        parse_read_partition(&[]),
        Err(WsfError::TruncatedField {
            expected: 3,
            available: 0
        })
    );
    assert_eq!(
        parse_read_partition(&[0x01]),
        Err(WsfError::TruncatedField {
            expected: 2,
            available: 1
        })
    );
    assert_eq!(
        parse_read_partition(&[0x01, 0xFF]),
        Err(WsfError::TruncatedField {
            expected: 3,
            available: 2
        })
    );
    assert_eq!(
        parse_read_partition(&[0x01, 0xFF, 0x03]),
        Err(WsfError::TruncatedField {
            expected: 4,
            available: 3
        })
    );

    // 2. Length header prefixes with truncated bodies
    assert_eq!(
        parse_read_partition(&[0x00, 0x03, 0x01]),
        Err(WsfError::TruncatedField {
            expected: 2,
            available: 1
        })
    );
    assert_eq!(
        parse_read_partition(&[0x00, 0x04, 0x01, 0xFF]),
        Err(WsfError::TruncatedField {
            expected: 3,
            available: 2
        })
    );
    assert_eq!(
        parse_read_partition(&[0x00, 0x05, 0x01, 0xFF, 0x03]),
        Err(WsfError::TruncatedField {
            expected: 4,
            available: 3
        })
    );

    // 3. Invalid SFID (not SF_READ_PART = 0x01)
    assert_eq!(
        parse_read_partition(&[0x02, 0xFF, 0x02]),
        Err(WsfError::InvalidQueryType(0x02))
    );
    assert_eq!(
        parse_read_partition(&[0xFF, 0xFF, 0x02]),
        Err(WsfError::InvalidQueryType(0xFF))
    );

    // 4. Invalid Partition ID (expected 0xFF)
    assert_eq!(
        parse_read_partition(&[0x01, 0x00, 0x02]),
        Err(WsfError::InvalidPartition {
            expected: 0xFF,
            actual: 0x00
        })
    );
    assert_eq!(
        parse_read_partition(&[0x01, 0xFE, 0x02]),
        Err(WsfError::InvalidPartition {
            expected: 0xFF,
            actual: 0xFE
        })
    );

    // 5. Invalid Query Type (expected 0x02 or 0x03)
    assert_eq!(
        parse_read_partition(&[0x01, 0xFF, 0x00]),
        Err(WsfError::InvalidQueryType(0x00))
    );
    assert_eq!(
        parse_read_partition(&[0x01, 0xFF, 0x05]),
        Err(WsfError::InvalidQueryType(0x05))
    );

    // 6. Invalid Request Type for Query List (expected 0x00, 0x40, or 0x80)
    assert_eq!(
        parse_read_partition(&[0x01, 0xFF, 0x03, 0x01]),
        Err(WsfError::InvalidRequestType(0x01))
    );
    assert_eq!(
        parse_read_partition(&[0x01, 0xFF, 0x03, 0x7F]),
        Err(WsfError::InvalidRequestType(0x7F))
    );
    assert_eq!(
        parse_read_partition(&[0x01, 0xFF, 0x03, 0xFF]),
        Err(WsfError::InvalidRequestType(0xFF))
    );
}

#[test]
fn test_adversarial_query_list_empty_and_unknown_fallback_to_null() {
    let builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);

    // 1. Empty requested list -> QR_NULL (0xFF)
    let resp_empty = builder.build_list(&[]);
    assert_eq!(resp_empty, vec![AID_SF, 0x00, 0x04, SFID_QREPLY, QR_NULL]);

    // 2. All unknown / unsupported query codes -> QR_NULL (0xFF)
    let resp_unknown = builder.build_list(&[0xFE, 0x42, 0x00]);
    assert_eq!(resp_unknown, vec![AID_SF, 0x00, 0x04, SFID_QREPLY, QR_NULL]);

    // 3. Single unknown query code -> QR_NULL (0xFF)
    let resp_single = builder.build_list(&[0x99]);
    assert_eq!(resp_single, vec![AID_SF, 0x00, 0x04, SFID_QREPLY, QR_NULL]);

    // 4. Inbound SF_READ_PART with empty query list
    let raw_empty_qlist = [0x01, 0xFF, 0x03, 0x00];
    let resp_parsed = builder.handle_read_partition(&raw_empty_qlist).unwrap();
    assert_eq!(resp_parsed, vec![AID_SF, 0x00, 0x04, SFID_QREPLY, QR_NULL]);
}

#[test]
fn test_adversarial_query_list_deduplication_and_canonical_ordering() {
    let builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);

    // Pass heavily duplicated codes in reverse order:
    // Requested: Implicit Partition (0xA6), Color (0x86), Usable Area (0x81), Summary (0x80)
    let requested = [0xA6, 0x86, 0xA6, 0x81, 0x86, 0x81, 0xA6, 0x80, 0x80];
    let resp = builder.build_list(&requested);

    assert_eq!(resp.first(), Some(&AID_SF));

    // Parse returned structured fields to verify deduplication and ordering
    let mut offset = 1;
    let mut returned_qcodes = Vec::new();

    while offset < resp.len() {
        let len = (usize::from(resp[offset]) << 8) | usize::from(resp[offset + 1]);
        assert!(len >= 4);
        assert_eq!(resp[offset + 2], SFID_QREPLY);
        let qcode = resp[offset + 3];
        returned_qcodes.push(qcode);
        offset += len;
    }

    // Must contain exactly 4 replies:
    // Exactly ONE Summary (0x80), ONE Usable Area (0x81), ONE Color (0x86), ONE Implicit Partition (0xA6)
    // in CANONICAL ASCENDING ORDER!
    assert_eq!(
        returned_qcodes,
        vec![QR_SUMMARY, QR_USABLE_AREA, QR_COLOR, QR_IMP_PART]
    );
}

#[test]
fn test_adversarial_query_list_mixed_supported_unsupported_and_duplicates() {
    let builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);

    // Mixed supported, duplicates, and garbage unsupported codes
    let requested = [
        0xFE, 0x87, 0x42, 0x85, 0x00, 0x87, 0x12, 0x85, 0x99, 0x87, 0xFE,
    ];
    let resp = builder.build_list(&requested);

    let mut offset = 1;
    let mut returned_qcodes = Vec::new();

    while offset < resp.len() {
        let len = (usize::from(resp[offset]) << 8) | usize::from(resp[offset + 1]);
        assert_eq!(resp[offset + 2], SFID_QREPLY);
        let qcode = resp[offset + 3];
        returned_qcodes.push(qcode);
        offset += len;
    }

    // Must emit exactly Character Sets (0x85) and Highlighting (0x87) in canonical order.
    // No duplicates, and NO QR_NULL fallback because supported replies were present!
    assert_eq!(returned_qcodes, vec![QR_CHARSETS, QR_HIGHLIGHTING]);
}

#[test]
fn test_adversarial_query_reply_across_models_and_codepages() {
    // 1. Verify Usable Area and Implicit Partition across Terminal Models
    let models = [
        (TerminalModel::Model2, 24_u16, 80_u16, 1920_u16),
        (TerminalModel::Model3, 32_u16, 80_u16, 2560_u16),
        (TerminalModel::Model4, 43_u16, 80_u16, 3440_u16),
        (TerminalModel::Model5, 27_u16, 132_u16, 3564_u16),
    ];

    for (model, exp_rows, exp_cols, exp_cap) in models {
        let builder = QueryReplyBuilder::new(model, &CP037);

        // Usable Area
        let mut ua_buf = Vec::new();
        builder.append_usable_area(&mut ua_buf);
        let ua_len = (usize::from(ua_buf[0]) << 8) | usize::from(ua_buf[1]);
        assert_eq!(ua_len, ua_buf.len());
        assert_eq!(ua_buf[2], SFID_QREPLY);
        assert_eq!(ua_buf[3], QR_USABLE_AREA);

        let cols = (u16::from(ua_buf[6]) << 8) | u16::from(ua_buf[7]);
        let rows = (u16::from(ua_buf[8]) << 8) | u16::from(ua_buf[9]);
        let cap = (u16::from(ua_buf[21]) << 8) | u16::from(ua_buf[22]);
        assert_eq!(cols, exp_cols);
        assert_eq!(rows, exp_rows);
        assert_eq!(cap, exp_cap);

        // Implicit Partition
        let mut ip_buf = Vec::new();
        builder.append_implicit_partition(&mut ip_buf);
        assert_eq!(ip_buf[3], QR_IMP_PART);
        let def_cols = (u16::from(ip_buf[9]) << 8) | u16::from(ip_buf[10]);
        let def_rows = (u16::from(ip_buf[11]) << 8) | u16::from(ip_buf[12]);
        assert_eq!(def_cols, 80);
        assert_eq!(def_rows, 24);
        let alt_cols = (u16::from(ip_buf[13]) << 8) | u16::from(ip_buf[14]);
        let alt_rows = (u16::from(ip_buf[15]) << 8) | u16::from(ip_buf[16]);
        assert_eq!(alt_cols, exp_cols);
        assert_eq!(alt_rows, exp_rows);
    }

    // 2. Verify Character Sets across CodePages (CGCSGID)
    let cp037_builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);
    let mut cs_cp037 = Vec::new();
    cp037_builder.append_charsets(&mut cs_cp037);
    assert_eq!(cs_cp037[3], QR_CHARSETS);
    // CGCSGID for CP037
    let c037_cgcsgid = (u32::from(cs_cp037[16]) << 24)
        | (u32::from(cs_cp037[17]) << 16)
        | (u32::from(cs_cp037[18]) << 8)
        | u32::from(cs_cp037[19]);
    assert_eq!(c037_cgcsgid, CP037.cgcsgid());

    let ibm870_builder = QueryReplyBuilder::new(TerminalModel::Model2, &IBM870);
    let mut cs_ibm870 = Vec::new();
    ibm870_builder.append_charsets(&mut cs_ibm870);
    let ibm870_cgcsgid = (u32::from(cs_ibm870[16]) << 24)
        | (u32::from(cs_ibm870[17]) << 16)
        | (u32::from(cs_ibm870[18]) << 8)
        | u32::from(cs_ibm870[19]);
    assert_eq!(ibm870_cgcsgid, IBM870.cgcsgid());

    // 3. Verify Color 3279 vs Monochrome 3278
    let color_builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037).with_color(true);
    let mut color_buf = Vec::new();
    color_builder.append_color(&mut color_buf);
    // In color mode, color attribute pairs 0xF1..0xFF map to code itself
    assert_eq!(color_buf[8], 0xF1);
    assert_eq!(color_buf[9], 0xF1);

    let mono_builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037).with_color(false);
    let mut mono_buf = Vec::new();
    mono_builder.append_color(&mut mono_buf);
    // In monochrome mode, color attribute pairs map to 0x00
    assert_eq!(mono_buf[8], 0xF1);
    assert_eq!(mono_buf[9], 0x00);
}

#[test]
fn test_adversarial_query_all_and_list_all_equivalents() {
    let builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);

    // 1. Query (0x02)
    let q_all = builder.build_from_request(&QueryRequest::QueryAll);

    // 2. Query List Equivalent (0x03, 0x40)
    let q_equiv = builder.build_from_request(&QueryRequest::QueryListEquivalent);

    // 3. Query List All (0x03, 0x80)
    let q_list_all = builder.build_from_request(&QueryRequest::QueryListAll);

    // All three forms MUST yield identical full Query Reply envelopes
    assert_eq!(q_all, q_equiv);
    assert_eq!(q_all, q_list_all);

    // Verify all 8 supported query replies are present in canonical order
    let mut offset = 1;
    let mut returned_qcodes = Vec::new();

    while offset < q_all.len() {
        let len = (usize::from(q_all[offset]) << 8) | usize::from(q_all[offset + 1]);
        assert_eq!(q_all[offset + 2], SFID_QREPLY);
        let qcode = q_all[offset + 3];
        returned_qcodes.push(qcode);
        offset += len;
    }

    assert_eq!(returned_qcodes, SUPPORTED_QUERY_CODES);
    assert_eq!(
        returned_qcodes,
        vec![
            QR_SUMMARY,
            QR_USABLE_AREA,
            QR_ALPHA_PART,
            QR_CHARSETS,
            QR_COLOR,
            QR_HIGHLIGHTING,
            QR_REPLY_MODES,
            bastion3270_core::wsf::QR_RPQNAMES,
            QR_IMP_PART,
        ]
    );
}
