//! Integration tests for the virtual keyboard and the OIA status machine.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::doc_markdown,
    clippy::cast_possible_truncation
)]

use bastion3270_core::address::BufferAddress;
use bastion3270_core::datastream::wcc::WriteControlCharacter;
use bastion3270_core::ebcdic::CP037;
use bastion3270_core::field::{ExtendedAttributes, FieldAttribute};
use bastion3270_core::keyboard::{
    ActionKey, AidKey, KeyboardError, KeyboardState, VirtualKeyboard,
};
use bastion3270_core::model::TerminalModel;
use bastion3270_core::screen::PresentationSpace;

#[test]
fn test_keyboard_initial_state_and_oia_indicators() {
    let kb = VirtualKeyboard::new();
    assert_eq!(kb.state(), KeyboardState::Unlocked);
    assert!(!kb.is_locked());

    // Verify all OIA string indicators
    assert_eq!(KeyboardState::Unlocked.oia_indicator(), "");
    assert_eq!(KeyboardState::Unlocked.oia_short_indicator(), "");
    assert!(!KeyboardState::Unlocked.is_locked());
    assert!(!KeyboardState::Unlocked.is_operator_error());

    assert_eq!(KeyboardState::TimeWait.oia_indicator(), "X Wait");
    assert_eq!(KeyboardState::TimeWait.oia_short_indicator(), "X Wait");
    assert_eq!(KeyboardState::SystemLock.oia_indicator(), "X SYSTEM");
    assert!(KeyboardState::TimeWait.is_locked());
    assert!(!KeyboardState::TimeWait.is_operator_error());

    assert_eq!(KeyboardState::Protected.oia_indicator(), "X PROTECTED");
    assert_eq!(
        KeyboardState::Protected.oia_short_indicator(),
        "X Protected"
    );
    assert!(KeyboardState::Protected.is_locked());
    assert!(KeyboardState::Protected.is_operator_error());

    assert_eq!(KeyboardState::Numeric.oia_indicator(), "X NUMERIC");
    assert_eq!(KeyboardState::Numeric.oia_short_indicator(), "X NUM");
    assert!(KeyboardState::Numeric.is_locked());
    assert!(KeyboardState::Numeric.is_operator_error());

    assert_eq!(KeyboardState::Overflow.oia_indicator(), "X >");
    assert_eq!(KeyboardState::Overflow.oia_short_indicator(), "X Overflow");
    assert!(KeyboardState::Overflow.is_locked());
    assert!(KeyboardState::Overflow.is_operator_error());

    assert_eq!(KeyboardState::Inhibit.oia_indicator(), "X INHIBIT");
    assert_eq!(KeyboardState::Inhibit.oia_short_indicator(), "X Wait");
    assert!(KeyboardState::Inhibit.is_locked());
    assert!(!KeyboardState::Inhibit.is_operator_error());
}

#[test]
fn test_keyboard_input_char_unprotected_and_mdt() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Place unprotected field at index 0
    let fa = FieldAttribute::from_wire_byte(0x00);
    assert_eq!(
        ps.place_field(BufferAddress::ZERO, fa, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    let Ok(c1) = BufferAddress::new(1, 1920) else {
        panic!("invalid address");
    };
    assert_eq!(ps.set_cursor_addr(c1), Ok(()));

    // Type "IBM"
    assert_eq!(kb.input_char(&mut ps, 'I', &CP037), Ok(()));
    assert_eq!(kb.input_char(&mut ps, 'B', &CP037), Ok(()));
    assert_eq!(kb.input_char(&mut ps, 'M', &CP037), Ok(()));

    // Cursor should have advanced from 1 to 4
    assert_eq!(ps.cursor_addr().as_usize(), 4);

    // Verify characters in PresentationSpace:
    // 'I' in CP037 = 0xC9
    // 'B' in CP037 = 0xC2
    // 'M' in CP037 = 0xD4
    let Ok(a1) = BufferAddress::new(1, 1920) else {
        panic!()
    };
    let Ok(a2) = BufferAddress::new(2, 1920) else {
        panic!()
    };
    let Ok(a3) = BufferAddress::new(3, 1920) else {
        panic!()
    };

    assert_eq!(
        ps.cell(a1).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0xC9)
    );
    assert_eq!(
        ps.cell(a2).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0xC2)
    );
    assert_eq!(
        ps.cell(a3).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0xD4)
    );

    // Verify MDT flag is now true
    let gov = ps.governing_field(a1);
    assert_eq!(gov.map(|(_, f, _)| f.is_modified()), Some(true));
}

#[test]
fn test_keyboard_protected_field_rejection_and_reset() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Place protected field at index 0 (wire byte 0x20 has bit 5 set = protected)
    let fa_prot = FieldAttribute::from_wire_byte(0x20);
    assert_eq!(
        ps.place_field(BufferAddress::ZERO, fa_prot, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    let Ok(c1) = BufferAddress::new(1, 1920) else {
        panic!()
    };
    assert_eq!(ps.set_cursor_addr(c1), Ok(()));

    // Attempting to type into protected field fails
    let res = kb.input_char(&mut ps, 'A', &CP037);
    assert_eq!(res, Err(KeyboardError::ProtectedField));

    // Keyboard enters Protected lock state
    assert_eq!(kb.state(), KeyboardState::Protected);
    assert!(kb.is_locked());
    assert_eq!(kb.state().oia_indicator(), "X PROTECTED");

    // Subsequent key entry fails with Locked(Protected)
    let res2 = kb.input_char(&mut ps, 'B', &CP037);
    assert_eq!(res2, Err(KeyboardError::Locked(KeyboardState::Protected)));

    // Reset clears operator lock
    assert_eq!(kb.action(&mut ps, ActionKey::Reset), Ok(()));
    assert_eq!(kb.state(), KeyboardState::Unlocked);
    assert!(!kb.is_locked());
}

#[test]
fn test_keyboard_attribute_cell_rejection() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Place unprotected field at index 0
    let fa = FieldAttribute::from_wire_byte(0x00);
    assert_eq!(
        ps.place_field(BufferAddress::ZERO, fa, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    // Position cursor exactly on the field attribute marker cell (index 0)
    assert_eq!(ps.set_cursor_addr(BufferAddress::ZERO), Ok(()));

    // Attempting to type directly onto attribute byte cell fails
    let res = kb.input_char(&mut ps, 'X', &CP037);
    assert_eq!(res, Err(KeyboardError::ProtectedField));
    assert_eq!(kb.state(), KeyboardState::Protected);
}

#[test]
fn test_keyboard_numeric_field_validation() {
    // Numeric lock is off by default (x3270 `numericLock`); this test turns it on.
    let mut kb = VirtualKeyboard::with_options(bastion3270_core::KeyboardOptions {
        numeric_lock: true,
        ..bastion3270_core::KeyboardOptions::DEFAULT
    });
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Place numeric field at index 0 (wire byte 0x10 = numeric, unprotected)
    let fa_num = FieldAttribute::from_wire_byte(0x10);
    assert_eq!(
        ps.place_field(BufferAddress::ZERO, fa_num, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    let Ok(c1) = BufferAddress::new(1, 1920) else {
        panic!()
    };
    assert_eq!(ps.set_cursor_addr(c1), Ok(()));

    // Valid numeric characters succeed: '0'..'9', '+', '-', '.', ','
    assert_eq!(kb.input_char(&mut ps, '4', &CP037), Ok(()));
    assert_eq!(kb.input_char(&mut ps, '2', &CP037), Ok(()));
    assert_eq!(kb.input_char(&mut ps, '.', &CP037), Ok(()));
    assert_eq!(kb.input_char(&mut ps, '5', &CP037), Ok(()));

    // Letter 'Z' into numeric field fails and locks keyboard with Numeric error
    let res = kb.input_char(&mut ps, 'Z', &CP037);
    assert_eq!(res, Err(KeyboardError::NumericField));
    assert_eq!(kb.state(), KeyboardState::Numeric);
    assert_eq!(kb.state().oia_indicator(), "X NUMERIC");

    // Reset clears error lock
    assert_eq!(kb.action(&mut ps, ActionKey::Reset), Ok(()));
    assert_eq!(kb.state(), KeyboardState::Unlocked);
}

#[test]
fn test_keyboard_autoskip_on_boundary() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Field 1 at index 0: unprotected (length 5: data cells 1..=4)
    let fa1 = FieldAttribute::from_wire_byte(0x00);
    assert_eq!(
        ps.place_field(BufferAddress::ZERO, fa1, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    // Field 2 at index 5: auto-skip (protected + numeric = wire byte 0x30)
    let Ok(a5) = BufferAddress::new(5, 1920) else {
        panic!()
    };
    let fa2_skip = FieldAttribute::from_wire_byte(0x30);
    assert_eq!(
        ps.place_field(a5, fa2_skip, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    // Field 3 at index 10: unprotected (data cells 11..)
    let Ok(a10) = BufferAddress::new(10, 1920) else {
        panic!()
    };
    let fa3 = FieldAttribute::from_wire_byte(0x00);
    assert_eq!(
        ps.place_field(a10, fa3, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    // Place cursor at index 4 (last cell of Field 1 before Field 2's attribute at index 5)
    let Ok(a4) = BufferAddress::new(4, 1920) else {
        panic!()
    };
    assert_eq!(ps.set_cursor_addr(a4), Ok(()));

    // Typing a character into index 4 should trigger auto-skip past Field 2 into Field 3!
    assert_eq!(kb.input_char(&mut ps, 'W', &CP037), Ok(()));

    // Cursor should have jumped past Field 2 (at 5) directly to first data cell of Field 3 (index 11)
    assert_eq!(ps.cursor_addr().as_usize(), 11);
}

#[test]
fn test_keyboard_navigation_tab_backtab_home_newline() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Field 1: index 10 (unprotected, data 11..19)
    let Ok(a10) = BufferAddress::new(10, 1920) else {
        panic!()
    };
    assert_eq!(
        ps.place_field(
            a10,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Field 2: index 30 (protected, data 31..49)
    let Ok(a30) = BufferAddress::new(30, 1920) else {
        panic!()
    };
    assert_eq!(
        ps.place_field(
            a30,
            FieldAttribute::from_wire_byte(0x20),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Field 3: index 50 (unprotected, data 51..99)
    let Ok(a50) = BufferAddress::new(50, 1920) else {
        panic!()
    };
    assert_eq!(
        ps.place_field(
            a50,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Cursor starts at 0
    assert_eq!(ps.set_cursor_addr(BufferAddress::ZERO), Ok(()));

    // Tab moves to first data cell of Field 1 (11)
    assert_eq!(kb.action(&mut ps, ActionKey::Tab), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 11);

    // Tab from Field 1 skips protected Field 2 and jumps to Field 3 (51)
    assert_eq!(kb.action(&mut ps, ActionKey::Tab), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 51);

    // Tab from Field 3 wraps around back to Field 1 (11)
    assert_eq!(kb.action(&mut ps, ActionKey::Tab), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 11);

    // Move cursor into middle of Field 1 (15)
    let Ok(a15) = BufferAddress::new(15, 1920) else {
        panic!()
    };
    assert_eq!(ps.set_cursor_addr(a15), Ok(()));

    // BackTab from middle of Field 1 jumps to start of Field 1 (11)
    assert_eq!(kb.action(&mut ps, ActionKey::BackTab), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 11);

    // BackTab from start of Field 1 wraps back to start of previous unprotected field (51)
    assert_eq!(kb.action(&mut ps, ActionKey::BackTab), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 51);

    // Home jumps to first unprotected field on screen (11)
    assert_eq!(kb.action(&mut ps, ActionKey::Home), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 11);

    // Newline jumps to first unprotected field on next line
    assert_eq!(kb.action(&mut ps, ActionKey::Newline), Ok(()));
    let (nl_row, _) = ps.cursor_addr().to_row_col(ps.cols());
    assert!(nl_row >= 1);
}

#[test]
fn test_keyboard_arrow_keys_wrapping() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    assert_eq!(ps.set_cursor_addr(BufferAddress::ZERO), Ok(()));

    // Left from ZERO wraps to bottom-right cell (1919)
    assert_eq!(kb.action(&mut ps, ActionKey::Left), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 1919);

    // Right from 1919 wraps to 0
    assert_eq!(kb.action(&mut ps, ActionKey::Right), Ok(()));
    assert_eq!(ps.cursor_addr().as_usize(), 0);

    // Up from (0, 10) wraps to (23, 10)
    let Ok(top_cell) = BufferAddress::from_row_col(0, 10, 24, 80) else {
        panic!()
    };
    assert_eq!(ps.set_cursor_addr(top_cell), Ok(()));
    assert_eq!(kb.action(&mut ps, ActionKey::Up), Ok(()));
    let (up_row, up_col) = ps.cursor_addr().to_row_col(80);
    assert_eq!(up_row, 23);
    assert_eq!(up_col, 10);

    // Down from (23, 10) wraps to (0, 10)
    assert_eq!(kb.action(&mut ps, ActionKey::Down), Ok(()));
    let (down_row, down_col) = ps.cursor_addr().to_row_col(80);
    assert_eq!(down_row, 0);
    assert_eq!(down_col, 10);
}

#[test]
fn test_keyboard_erase_eof() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Unprotected field at index 0 (data cells 1..9)
    assert_eq!(
        ps.place_field(
            BufferAddress::ZERO,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Terminating field at index 10
    let Ok(a10) = BufferAddress::new(10, 1920) else {
        panic!()
    };
    assert_eq!(
        ps.place_field(
            a10,
            FieldAttribute::from_wire_byte(0x20),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Write 'A', 'B', 'C', 'D' into cells 1, 2, 3, 4
    let Ok(a1) = BufferAddress::new(1, 1920) else {
        panic!()
    };
    let Ok(a2) = BufferAddress::new(2, 1920) else {
        panic!()
    };
    let Ok(a3) = BufferAddress::new(3, 1920) else {
        panic!()
    };
    let Ok(a4) = BufferAddress::new(4, 1920) else {
        panic!()
    };

    assert_eq!(ps.write_char(a1, 0xC1, ExtendedAttributes::DEFAULT), Ok(()));
    assert_eq!(ps.write_char(a2, 0xC2, ExtendedAttributes::DEFAULT), Ok(()));
    assert_eq!(ps.write_char(a3, 0xC3, ExtendedAttributes::DEFAULT), Ok(()));
    assert_eq!(ps.write_char(a4, 0xC4, ExtendedAttributes::DEFAULT), Ok(()));

    // Place cursor at index 3 ('C')
    assert_eq!(ps.set_cursor_addr(a3), Ok(()));

    // EraseEOF
    assert_eq!(kb.action(&mut ps, ActionKey::EraseEof), Ok(()));

    // Cells 1 and 2 are preserved
    assert_eq!(
        ps.cell(a1).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0xC1)
    );
    assert_eq!(
        ps.cell(a2).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0xC2)
    );

    // Cells 3 and 4 were nulled (0x00)
    assert_eq!(
        ps.cell(a3).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0x00)
    );
    assert_eq!(
        ps.cell(a4).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0x00)
    );

    // Cursor position is still at index 3
    assert_eq!(ps.cursor_addr().as_usize(), 3);

    // Field MDT is now true
    let gov = ps.governing_field(a1);
    assert_eq!(gov.map(|(_, f, _)| f.is_modified()), Some(true));
}

#[test]
fn test_keyboard_erase_input() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Field 1: index 0 (unprotected)
    assert_eq!(
        ps.place_field(
            BufferAddress::ZERO,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    let Ok(a1) = BufferAddress::new(1, 1920) else {
        panic!()
    };
    assert_eq!(ps.write_char(a1, 0xC1, ExtendedAttributes::DEFAULT), Ok(()));

    // Field 2: index 20 (protected)
    let Ok(a20) = BufferAddress::new(20, 1920) else {
        panic!()
    };
    assert_eq!(
        ps.place_field(
            a20,
            FieldAttribute::from_wire_byte(0x20),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );
    let Ok(a21) = BufferAddress::new(21, 1920) else {
        panic!()
    };
    assert_eq!(
        ps.write_char(a21, 0xC2, ExtendedAttributes::DEFAULT),
        Ok(())
    );

    // Mark field 1 modified
    if let Some(fa) = ps.field_attribute_mut(BufferAddress::ZERO) {
        fa.set_modified(true);
    }

    // Call EraseInput
    assert_eq!(kb.action(&mut ps, ActionKey::EraseInput), Ok(()));

    // Unprotected field 1 is cleared to 0x00 and MDT reset
    assert_eq!(
        ps.cell(a1).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0x00)
    );
    let gov1 = ps.governing_field(a1);
    assert_eq!(gov1.map(|(_, f, _)| f.is_modified()), Some(false));

    // Protected field 2 text is PRESERVED!
    assert_eq!(
        ps.cell(a21).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0xC2)
    );

    // Cursor is moved to Home (first unprotected data cell, index 1)
    assert_eq!(ps.cursor_addr().as_usize(), 1);
}

#[test]
fn test_keyboard_aid_short_reads_and_clear() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Press PA1 (short-read AID 0x6C)
    let res = kb.press_aid(&mut ps, AidKey::PA1);
    assert_eq!(res, Ok(vec![0x6C]));

    // Keyboard transitions to TimeWait
    assert_eq!(kb.state(), KeyboardState::TimeWait);
    assert!(kb.is_locked());
    assert_eq!(kb.state().oia_indicator(), "X Wait");

    // A host write without keyboard restore ends the wait but keeps the AID lock (X SYSTEM).
    kb.host_write(false);
    assert_eq!(kb.state(), KeyboardState::SystemLock);

    // Operator Reset clears every lock, X SYSTEM included (x3270 `do_reset(true)`).
    kb.reset();
    assert_eq!(kb.state(), KeyboardState::Unlocked);

    // Clear AID (short-read AID 0x6D)
    let Ok(a5) = BufferAddress::new(5, 1920) else {
        panic!()
    };
    assert_eq!(ps.write_char(a5, 0xC1, ExtendedAttributes::DEFAULT), Ok(()));

    let res_clear = kb.press_aid(&mut ps, AidKey::Clear);
    assert_eq!(res_clear, Ok(vec![0x6D]));
    assert_eq!(kb.state(), KeyboardState::TimeWait);

    // Clear must also erase presentation space
    assert_eq!(
        ps.cell(a5).map(bastion3270_core::screen::Cell::raw_ebcdic),
        Some(0x00)
    );
}

#[test]
fn test_keyboard_aid_read_modified_and_wcc() {
    let mut kb = VirtualKeyboard::new();
    let mut ps = PresentationSpace::new(TerminalModel::Model2);

    // Create unprotected field at index 0
    assert_eq!(
        ps.place_field(
            BufferAddress::ZERO,
            FieldAttribute::from_wire_byte(0x00),
            ExtendedAttributes::DEFAULT
        ),
        Ok(())
    );

    // Type "XYZ" into cells 1, 2, 3
    let Ok(a1) = BufferAddress::new(1, 1920) else {
        panic!()
    };
    assert_eq!(ps.set_cursor_addr(a1), Ok(()));
    assert_eq!(kb.input_char(&mut ps, 'X', &CP037), Ok(()));
    assert_eq!(kb.input_char(&mut ps, 'Y', &CP037), Ok(()));
    assert_eq!(kb.input_char(&mut ps, 'Z', &CP037), Ok(()));

    // Press Enter (AID 0x7D)
    let stream_res = kb.press_aid(&mut ps, AidKey::Enter);
    assert!(stream_res.is_ok());
    let stream = stream_res.unwrap_or_default();

    // Inbound stream starts with AID_ENTER (0x7D)
    assert_eq!(stream.first(), Some(&0x7D));

    // Followed by 2-byte cursor address
    assert!(stream.len() >= 3);

    // Contains SBA (0x11) followed by field contents (EBCDIC for 'X', 'Y', 'Z': 0xE7, 0xE8, 0xE9)
    assert!(stream.contains(&0x11));
    assert!(stream.contains(&0xE7));
    assert!(stream.contains(&0xE8));
    assert!(stream.contains(&0xE9));

    // Keyboard is in TimeWait
    assert_eq!(kb.state(), KeyboardState::TimeWait);

    // Simulate host WCC response: restore_keyboard = true, reset_mdt = true
    let wcc = WriteControlCharacter {
        restore_keyboard: true,
        reset_mdt: true,
        ..Default::default()
    };
    kb.handle_wcc(&mut ps, wcc);

    // Keyboard is unlocked
    assert_eq!(kb.state(), KeyboardState::Unlocked);

    // Field MDT is reset
    let gov = ps.governing_field(a1);
    assert_eq!(gov.map(|(_, f, _)| f.is_modified()), Some(false));
}
