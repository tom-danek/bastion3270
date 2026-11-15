//! Operator editing and paste, checked against `x3270` `kybd.c` (`key_Character`, `ins_prep`,
//! `do_erase`, `do_delete`, `FieldEnd_action`, `EraseEOF_action`, `Tab_action`,
//! `BackTab_action`, `Newline_action`, `emulate_uinput`) and `ctlr.c` (`next_unprotected`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use bastion3270_core::ebcdic::{CodePage, CP037};
use bastion3270_core::field::{Color3270, ExtendedAttributes, FieldAttribute};
use bastion3270_core::{
    ActionKey, BufferAddress, KeyInput, KeyOutcome, KeyboardError, KeyboardOptions, KeyboardState,
    OperatorError, PasteEnd, PresentationSpace, TerminalModel, VirtualKeyboard,
};

const UNPROT: u8 = 0x40;
const PROT: u8 = 0x60;
/// Protected numeric: an auto-skip field.
const SKIP: u8 = 0xF0;

fn addr(a: usize) -> BufferAddress {
    BufferAddress::new(a, 1920).unwrap()
}

/// A Model 2 screen with field attributes `(address, attribute byte)`.
fn screen(fields: &[(usize, u8)]) -> PresentationSpace {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    for &(a, fa) in fields {
        ps.place_field(
            addr(a),
            FieldAttribute::from_wire_byte(fa),
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
    }
    ps
}

/// An unlocked keyboard with the given options.
fn keyboard(options: KeyboardOptions) -> VirtualKeyboard {
    let mut kb = VirtualKeyboard::with_options(options);
    kb.disconnected();
    kb.connected();
    kb.entered_3270(false);
    kb.host_write(true);
    kb
}

fn kb() -> VirtualKeyboard {
    keyboard(KeyboardOptions::DEFAULT)
}

fn put(ps: &mut PresentationSpace, at: usize, text: &str) {
    for (i, c) in text.chars().enumerate() {
        ps.write_char(
            addr(at + i),
            CP037.char_to_ebcdic(c).unwrap(),
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
    }
}

fn text(ps: &PresentationSpace, from: usize, len: usize) -> String {
    (from..from + len)
        .map(|a| match ps.cell(addr(a)).unwrap().raw_ebcdic() {
            0x00 => '.',
            b => CP037.ebcdic_to_char(b).unwrap_or('?'),
        })
        .collect()
}

fn type_str(kb: &mut VirtualKeyboard, ps: &mut PresentationSpace, s: &str) {
    for c in s.chars() {
        kb.submit(ps, KeyInput::Char(c), &CP037).unwrap();
    }
}

fn act(kb: &mut VirtualKeyboard, ps: &mut PresentationSpace, a: ActionKey) {
    kb.submit(ps, KeyInput::Action(a), &CP037).unwrap();
}

#[test]
fn typing_past_a_field_end_steps_over_a_non_skip_attribute() {
    // Field 1..3, then an unprotected attribute at 4, its field 5..9, protected at 10.
    let mut ps = screen(&[(0, UNPROT), (4, UNPROT), (10, PROT)]);
    ps.set_cursor_addr(addr(1)).unwrap();
    let mut kb = kb();
    type_str(&mut kb, &mut ps, "ABC");
    assert_eq!(ps.cursor_addr().as_usize(), 5, "onto the next field's data");

    // Before a skip attribute the cursor goes to the next unprotected field.
    let mut ps = screen(&[(0, UNPROT), (4, SKIP), (8, UNPROT), (12, PROT)]);
    ps.set_cursor_addr(addr(1)).unwrap();
    type_str(&mut kb, &mut ps, "ABC");
    assert_eq!(ps.cursor_addr().as_usize(), 9);
}

#[test]
fn erase_at_the_first_position_of_a_field_does_nothing() {
    let mut ps = screen(&[(0, UNPROT), (10, PROT)]);
    put(&mut ps, 1, "ABC");
    ps.set_cursor_addr(addr(1)).unwrap();
    let mut kb = kb();
    act(&mut kb, &mut ps, ActionKey::Backspace);
    assert_eq!(kb.state(), KeyboardState::Unlocked);
    assert_eq!(ps.cursor_addr().as_usize(), 1);
    assert_eq!(text(&ps, 1, 3), "ABC");

    // Elsewhere it deletes the character on the left and shifts the field.
    ps.set_cursor_addr(addr(3)).unwrap();
    act(&mut kb, &mut ps, ActionKey::Backspace);
    assert_eq!(text(&ps, 1, 3), "AC.");
    assert_eq!(ps.cursor_addr().as_usize(), 2);
}

#[test]
fn delete_on_an_unformatted_screen_shifts_the_rest_of_the_screen() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    put(&mut ps, 78, "ABCD"); // wraps from row 0 into row 1
    ps.set_cursor_addr(addr(78)).unwrap();
    let mut kb = kb();
    act(&mut kb, &mut ps, ActionKey::Delete);
    assert_eq!(text(&ps, 78, 4), "BCD.");
}

#[test]
fn navigation_without_an_unprotected_field_goes_to_address_zero() {
    let mut ps = screen(&[(0, PROT), (40, PROT)]);
    let mut kb = kb();
    for key in [ActionKey::Tab, ActionKey::BackTab, ActionKey::Newline] {
        ps.set_cursor_addr(addr(50)).unwrap();
        act(&mut kb, &mut ps, key);
        assert_eq!(ps.cursor_addr().as_usize(), 0, "{key:?}");
    }
}

#[test]
fn numeric_lock_is_off_by_default_and_can_be_switched_on() {
    // Unprotected numeric field (0x50).
    let mut ps = screen(&[(0, 0x50), (10, PROT)]);
    ps.set_cursor_addr(addr(1)).unwrap();
    let mut kb = kb();
    type_str(&mut kb, &mut ps, "A1");
    assert_eq!(text(&ps, 1, 2), "A1");

    let mut kb = keyboard(KeyboardOptions {
        numeric_lock: true,
        ..KeyboardOptions::DEFAULT
    });
    assert_eq!(
        kb.submit(&mut ps, KeyInput::Char('B'), &CP037),
        Err(KeyboardError::NumericField)
    );
    assert_eq!(kb.lock().operator_error(), Some(OperatorError::Numeric));
}

#[test]
fn typed_characters_keep_the_cell_background() {
    let mut ps = screen(&[(0, UNPROT), (10, PROT)]);
    let xa = ExtendedAttributes {
        foreground: Color3270::Red,
        background: Color3270::Blue,
        ..ExtendedAttributes::DEFAULT
    };
    ps.write_char(addr(1), 0x00, xa).unwrap();
    ps.set_cursor_addr(addr(1)).unwrap();
    let mut kb = kb();
    type_str(&mut kb, &mut ps, "X");
    let cell = ps.cell(addr(1)).unwrap().extended();
    assert_eq!(cell.background, Color3270::Blue);
    assert_eq!(
        cell.foreground,
        Color3270::Default,
        "foreground inherits the field"
    );
}

#[test]
fn blank_fill_turns_skipped_nulls_into_spaces() {
    let mut ps = screen(&[(0, UNPROT), (10, PROT)]);
    ps.set_cursor_addr(addr(4)).unwrap();
    let mut kb = kb();
    type_str(&mut kb, &mut ps, "X");
    assert_eq!(text(&ps, 1, 4), "   X");

    let mut ps = screen(&[(0, UNPROT), (10, PROT)]);
    ps.set_cursor_addr(addr(4)).unwrap();
    let mut kb = keyboard(KeyboardOptions {
        blank_fill: false,
        ..KeyboardOptions::DEFAULT
    });
    type_str(&mut kb, &mut ps, "X");
    assert_eq!(text(&ps, 1, 4), "...X");
}

#[test]
fn field_end_moves_after_the_last_character() {
    let mut ps = screen(&[(0, UNPROT), (10, PROT)]);
    put(&mut ps, 1, "AB  ");
    let mut kb = kb();
    ps.set_cursor_addr(addr(7)).unwrap();
    act(&mut kb, &mut ps, ActionKey::FieldEnd);
    assert_eq!(ps.cursor_addr().as_usize(), 3);

    // A full field: onto the last character.
    put(&mut ps, 1, "ABCDEFGHI");
    act(&mut kb, &mut ps, ActionKey::FieldEnd);
    assert_eq!(ps.cursor_addr().as_usize(), 9);
}

#[test]
fn insert_mode_shifts_the_field_and_reports_overflow() {
    let mut ps = screen(&[(0, UNPROT), (5, PROT)]); // field 1..4
    put(&mut ps, 1, "BC");
    ps.set_cursor_addr(addr(1)).unwrap();
    let mut kb = kb();
    act(&mut kb, &mut ps, ActionKey::ToggleInsert);
    assert!(kb.insert_mode());
    type_str(&mut kb, &mut ps, "A");
    assert_eq!(text(&ps, 1, 4), "ABC.");
    type_str(&mut kb, &mut ps, "X");
    assert_eq!(text(&ps, 1, 4), "AXBC");
    // Full field: overflow.
    assert!(kb.submit(&mut ps, KeyInput::Char('Y'), &CP037).is_err());
    assert_eq!(kb.lock().operator_error(), Some(OperatorError::Overflow));
    // Reset ends the error and insert mode (x3270 `do_reset`).
    act(&mut kb, &mut ps, ActionKey::Reset);
    assert!(!kb.insert_mode());
    assert_eq!(kb.state(), KeyboardState::Unlocked);
}

#[test]
fn erase_eof_keeps_colours() {
    let mut ps = screen(&[(0, UNPROT), (10, PROT)]);
    let xa = ExtendedAttributes {
        background: Color3270::Green,
        ..ExtendedAttributes::DEFAULT
    };
    ps.write_char(addr(2), 0xC1, xa).unwrap();
    ps.set_cursor_addr(addr(1)).unwrap();
    let mut kb = kb();
    act(&mut kb, &mut ps, ActionKey::EraseEof);
    let cell = *ps.cell(addr(2)).unwrap();
    assert_eq!(cell.raw_ebcdic(), 0x00);
    assert_eq!(cell.extended().background, Color3270::Green);
}

// ── Paste (`x3270` `emulate_uinput`, overlay and margined paste) ─────────────────────────

#[test]
fn paste_stops_at_the_end_of_the_screen() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    put(&mut ps, 0, "TOP");
    ps.set_cursor_addr(addr(1918)).unwrap();
    let mut kb = kb();
    let out = kb.paste(&mut ps, "XYZW", &CP037).unwrap();
    assert_eq!(out.end, PasteEnd::ScreenEnd);
    assert_eq!(text(&ps, 1918, 2), "XY");
    assert_eq!(
        text(&ps, 0, 3),
        "TOP",
        "never wraps over the top of the screen"
    );
}

#[test]
fn pasted_lines_start_at_the_paste_column() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    ps.set_cursor_addr(addr(5)).unwrap();
    let mut kb = kb();
    let out = kb.paste(&mut ps, "AB\nCD\n", &CP037).unwrap();
    assert_eq!(out.end, PasteEnd::Complete);
    assert_eq!(text(&ps, 5, 2), "AB");
    assert_eq!(text(&ps, 85, 2), "CD");
    // The final newline is ignored.
    assert_eq!(ps.cursor_addr().as_usize(), 87);
}

#[test]
fn paste_control_characters() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let mut kb = kb();
    // \b is cursor left, \f a space, \r ignored, other controls skipped.
    let out = kb
        .paste(&mut ps, "AB\u{8}C\u{c}D\rE\u{1}F", &CP037)
        .unwrap();
    assert_eq!(text(&ps, 0, 5), "AC DE");
    assert_eq!(text(&ps, 5, 1), "F");
    assert_eq!(out.dropped, 1);
}

#[test]
fn a_newline_right_after_the_text_wrapped_is_not_a_second_line_break() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    ps.set_cursor_addr(addr(0)).unwrap();
    let mut kb = kb();
    let line = "X".repeat(80);
    kb.paste(&mut ps, &format!("{line}\nY"), &CP037).unwrap();
    assert_eq!(text(&ps, 80, 1), "Y", "Y on row 1, not row 2");
}

#[test]
fn unmappable_characters_are_skipped_and_the_paste_goes_on() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let mut kb = kb();
    let out = kb.paste(&mut ps, "A\u{4E2D}B", &CP037).unwrap();
    assert_eq!(out.end, PasteEnd::Complete);
    assert_eq!(out.dropped, 1);
    assert_eq!(text(&ps, 0, 2), "AB");
}

#[test]
fn paste_skips_protected_positions_without_an_error() {
    // Field 1..4 unprotected, protected attribute at 5 and its field 6..9.
    let mut ps = screen(&[(0, UNPROT), (5, PROT), (10, UNPROT)]);
    ps.set_cursor_addr(addr(1)).unwrap();
    let mut kb = kb();
    let out = kb.paste(&mut ps, "ABCDEFGHIJKL", &CP037).unwrap();
    assert_eq!(out.end, PasteEnd::Complete);
    assert_eq!(kb.state(), KeyboardState::Unlocked);
    assert_eq!(text(&ps, 1, 4), "ABCD");
    assert_eq!(text(&ps, 6, 4), "....");
    assert_eq!(text(&ps, 11, 2), "KL");
}

#[test]
fn paste_on_a_locked_keyboard_pastes_nothing() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let mut kb = kb();
    kb.enter_inhibit();
    assert!(matches!(
        kb.paste(&mut ps, "ABC", &CP037),
        Err(KeyboardError::Locked(_))
    ));
    assert_eq!(text(&ps, 0, 1), ".");
    let _ = KeyOutcome::Applied;
}

// ─── Dup, Field Mark, Erase Field (x3270 `Dup_action`, `FieldMark_action`,
//     `DeleteField_action`) ─────────────────────────────────────────────────────────

fn byte_at(ps: &PresentationSpace, a: usize) -> u8 {
    ps.cell(addr(a)).unwrap().raw_ebcdic()
}

/// Dup types X'1C' (shown as `*`) and moves to the next unprotected field, as Tab does.
#[test]
fn dup_types_x1c_and_moves_to_the_next_unprotected_field() {
    let mut ps = screen(&[(0, UNPROT), (10, PROT), (20, UNPROT), (30, PROT)]);
    let mut kb = kb();
    ps.set_cursor_addr(addr(3)).unwrap();
    act(&mut kb, &mut ps, ActionKey::Dup);
    assert_eq!(byte_at(&ps, 3), 0x1C);
    assert_eq!(ps.cursor_addr(), addr(21));
    assert!(ps.field_attribute_mut(addr(0)).unwrap().is_modified());
    assert_eq!(CP037.ebcdic_to_display_char(0x1C), '*');
}

/// Field Mark types X'1E' (shown as `;`) like a character: the cursor moves one position.
#[test]
fn field_mark_types_x1e_like_a_character() {
    let mut ps = screen(&[(0, UNPROT), (10, PROT)]);
    let mut kb = kb();
    ps.set_cursor_addr(addr(3)).unwrap();
    act(&mut kb, &mut ps, ActionKey::FieldMark);
    assert_eq!(byte_at(&ps, 3), 0x1E);
    assert_eq!(ps.cursor_addr(), addr(4));
}

/// Dup and Field Mark in a protected field are `X PROTECTED`, like any typed character.
#[test]
fn dup_and_field_mark_are_refused_in_a_protected_field() {
    for action in [ActionKey::Dup, ActionKey::FieldMark] {
        let mut ps = screen(&[(0, PROT), (10, UNPROT)]);
        let mut kb = kb();
        ps.set_cursor_addr(addr(3)).unwrap();
        assert!(matches!(
            kb.action(&mut ps, action),
            Err(KeyboardError::ProtectedField)
        ));
        assert_eq!(kb.state(), KeyboardState::Protected);
        assert_eq!(byte_at(&ps, 3), 0x00);
    }
}

/// Erase Field nulls the whole field the cursor is in (also left of the cursor), sets its MDT
/// and puts the cursor at the field's first position.
#[test]
fn erase_field_clears_the_whole_field_and_goes_to_its_start() {
    let mut ps = screen(&[(0, UNPROT), (10, PROT)]);
    put(&mut ps, 1, "ABCDEFGHI");
    put(&mut ps, 11, "KEEP");
    let mut kb = kb();
    ps.set_cursor_addr(addr(5)).unwrap();
    act(&mut kb, &mut ps, ActionKey::EraseField);
    assert!(
        (1..10).all(|a| byte_at(&ps, a) == 0x00),
        "the whole field is null"
    );
    assert_eq!(text(&ps, 11, 4), "KEEP");
    assert_eq!(ps.cursor_addr(), addr(1));
    assert!(ps.field_attribute_mut(addr(0)).unwrap().is_modified());
}

/// Erase Field in a protected field or on an attribute is `X PROTECTED`; on an unformatted
/// screen it does nothing; it clears an operator error first, as the other erase keys do.
#[test]
fn erase_field_refuses_protected_fields_and_clears_an_operator_error() {
    let mut ps = screen(&[(0, PROT), (10, UNPROT)]);
    put(&mut ps, 1, "ABC");
    let mut kb = kb();
    ps.set_cursor_addr(addr(2)).unwrap();
    assert!(matches!(
        kb.action(&mut ps, ActionKey::EraseField),
        Err(KeyboardError::ProtectedField)
    ));
    assert_eq!(text(&ps, 1, 3), "ABC");
    // From the operator error, Erase Field in an unprotected field proceeds.
    ps.set_cursor_addr(addr(12)).unwrap();
    act(&mut kb, &mut ps, ActionKey::EraseField);
    assert_eq!(kb.state(), KeyboardState::Unlocked);
    assert_eq!(ps.cursor_addr(), addr(11));

    let mut plain = PresentationSpace::new(TerminalModel::Model2);
    put(&mut plain, 0, "TEXT");
    let mut kb = self::kb();
    act(&mut kb, &mut plain, ActionKey::EraseField);
    assert_eq!(text(&plain, 0, 4), "TEXT");
}
