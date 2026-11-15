//! Keyboard lock set and typeahead, checked against `x3270` `kybd.c` (`do_reset`,
//! `kybd_connect`, `kybd_in3270`, `key_AID`, `OERR_CLEAR_OR_ENQ`, `enq_xta`, `run_ta`) and
//! `ctlr.c` (`ctlr_write`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use bastion3270_core::ebcdic::CP037;
use bastion3270_core::field::{ExtendedAttributes, FieldAttribute};
use bastion3270_core::{
    ActionKey, AidKey, BufferAddress, KeyInput, KeyOutcome, KeyboardError, KeyboardState,
    LockReason, OperatorError, PresentationSpace, TerminalModel, VirtualKeyboard,
};

/// A screen with a protected field at 0 and an unprotected field at 10; cursor in the
/// unprotected field.
fn screen() -> PresentationSpace {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    let cap = ps.capacity();
    ps.place_field(
        BufferAddress::ZERO,
        FieldAttribute::from_wire_byte(0x20),
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();
    ps.place_field(
        BufferAddress::new(10, cap).unwrap(),
        FieldAttribute::from_wire_byte(0x00),
        ExtendedAttributes::DEFAULT,
    )
    .unwrap();
    ps.set_cursor_addr(BufferAddress::new(11, cap).unwrap())
        .unwrap();
    ps
}

fn submit(
    kb: &mut VirtualKeyboard,
    ps: &mut PresentationSpace,
    input: KeyInput,
) -> Result<KeyOutcome, KeyboardError> {
    kb.submit(ps, input, &CP037)
}

/// A keyboard of a connected session whose host has written the first screen.
fn ready() -> VirtualKeyboard {
    let mut kb = VirtualKeyboard::new();
    kb.disconnected();
    kb.connected();
    kb.entered_3270(false);
    kb.host_write(true);
    assert_eq!(kb.state(), KeyboardState::Unlocked);
    kb
}

#[test]
fn reset_clears_the_aid_lock() {
    // An AID locks the keyboard; Reset must always free the operator (x3270 `do_reset(true)`).
    let mut ps = screen();
    let mut kb = ready();
    assert!(matches!(
        submit(&mut kb, &mut ps, KeyInput::Aid(AidKey::Enter)),
        Ok(KeyOutcome::Transmit(_))
    ));
    assert_eq!(kb.state(), KeyboardState::TimeWait);
    kb.host_write(false);
    assert_eq!(kb.state(), KeyboardState::SystemLock);
    submit(&mut kb, &mut ps, KeyInput::Action(ActionKey::Reset)).unwrap();
    assert_eq!(kb.state(), KeyboardState::Unlocked);
}

#[test]
fn host_write_without_restore_keeps_the_aid_lock() {
    let mut ps = screen();
    let mut kb = ready();
    kb.press_aid(&mut ps, AidKey::Enter).unwrap();
    assert!(kb.lock().has(LockReason::TimeWait));
    assert!(kb.lock().has(LockReason::SystemLock));

    // x3270 `ctlr_write` without WCC restore: only TWAIT goes, X SYSTEM stays.
    kb.host_write(false);
    assert!(!kb.lock().has(LockReason::TimeWait));
    assert_eq!(kb.state(), KeyboardState::SystemLock);

    // With WCC restore everything goes.
    kb.host_write(true);
    assert_eq!(kb.state(), KeyboardState::Unlocked);
}

#[test]
fn host_reset_unlocks_from_any_lock_but_not_while_disconnected() {
    let mut ps = screen();
    let mut kb = ready();
    kb.press_aid(&mut ps, AidKey::Enter).unwrap();
    kb.not_available();
    kb.host_reset();
    assert_eq!(kb.state(), KeyboardState::Unlocked);

    kb.disconnected();
    kb.host_reset();
    assert_eq!(kb.state(), KeyboardState::NotConnected);
}

#[test]
fn keyboard_waits_for_the_first_host_write() {
    let mut ps = screen();
    let mut kb = VirtualKeyboard::new();
    kb.disconnected();
    assert_eq!(
        submit(&mut kb, &mut ps, KeyInput::Char('A')),
        Err(KeyboardError::Locked(KeyboardState::NotConnected))
    );

    kb.connected();
    kb.entered_3270(true);
    assert_eq!(kb.state(), KeyboardState::AwaitingFirst);
    // An AID before the first screen is held, not sent.
    assert_eq!(
        submit(&mut kb, &mut ps, KeyInput::Aid(AidKey::Enter)),
        Ok(KeyOutcome::Queued)
    );
    assert_eq!(kb.pop_typeahead(), None, "nothing runs while locked");

    // The first host write (even without restore) ends the wait; the queued Enter runs.
    kb.host_write(false);
    assert_eq!(kb.state(), KeyboardState::Unlocked);
    assert_eq!(kb.pop_typeahead(), Some(KeyInput::Aid(AidKey::Enter)));
}

#[test]
fn tn3270e_mode_change_keeps_an_aid_lock_plain_tn3270_drops_it() {
    let mut ps = screen();
    for (tn3270e, still_locked) in [(true, true), (false, false)] {
        let mut kb = ready();
        kb.press_aid(&mut ps, AidKey::Enter).unwrap();
        kb.entered_3270(tn3270e);
        assert_eq!(kb.lock().has(LockReason::SystemLock), still_locked);
    }
}

#[test]
fn query_reply_inhibits_input_until_the_next_host_write() {
    let mut ps = screen();
    let mut kb = ready();
    kb.enter_inhibit();
    assert_eq!(kb.state(), KeyboardState::Inhibit);
    assert_eq!(
        submit(&mut kb, &mut ps, KeyInput::Char('A')),
        Ok(KeyOutcome::Queued)
    );
    kb.host_write(false);
    assert_eq!(kb.state(), KeyboardState::Unlocked);
}

#[test]
fn navigation_keys_clear_an_operator_error_other_keys_do_not() {
    let mut ps = screen();
    let mut kb = ready();
    let cap = ps.capacity();
    ps.set_cursor_addr(BufferAddress::new(3, cap).unwrap())
        .unwrap(); // inside the protected field
    assert_eq!(
        submit(&mut kb, &mut ps, KeyInput::Char('A')),
        Err(KeyboardError::ProtectedField)
    );
    assert_eq!(kb.lock().operator_error(), Some(OperatorError::Protected));

    // Newline and characters are refused under an operator error (dropped, not queued).
    assert_eq!(
        submit(&mut kb, &mut ps, KeyInput::Action(ActionKey::Newline)),
        Err(KeyboardError::Locked(KeyboardState::Protected))
    );
    assert_eq!(
        submit(&mut kb, &mut ps, KeyInput::Char('B')),
        Err(KeyboardError::Locked(KeyboardState::Protected))
    );
    assert_eq!(kb.typeahead_len(), 0);

    // Tab clears the error and moves to the unprotected field (x3270 `OERR_CLEAR_OR_ENQ`).
    assert_eq!(
        submit(&mut kb, &mut ps, KeyInput::Action(ActionKey::Tab)),
        Ok(KeyOutcome::Applied)
    );
    assert_eq!(kb.state(), KeyboardState::Unlocked);
    assert_eq!(ps.cursor_addr().as_usize(), 11);
}

#[test]
fn mouse_cursor_moves_are_ignored_while_locked() {
    let mut ps = screen();
    let mut kb = ready();
    kb.press_aid(&mut ps, AidKey::Enter).unwrap();
    let before = ps.cursor_addr();
    assert!(submit(
        &mut kb,
        &mut ps,
        KeyInput::Action(ActionKey::MoveCursor { row: 1, col: 1 })
    )
    .is_err());
    assert_eq!(ps.cursor_addr(), before);
    assert_eq!(kb.typeahead_len(), 0);
}

#[test]
fn typeahead_runs_in_order_and_stops_when_an_aid_locks_again() {
    let mut ps = screen();
    let mut kb = ready();
    kb.press_aid(&mut ps, AidKey::Enter).unwrap();
    for input in [
        KeyInput::Char('X'),
        KeyInput::Aid(AidKey::PF3),
        KeyInput::Char('Y'),
    ] {
        assert_eq!(submit(&mut kb, &mut ps, input), Ok(KeyOutcome::Queued));
    }
    kb.host_write(true);

    // Replay as the session does: pop while unlocked, submit each.
    let mut sent = Vec::new();
    while let Some(input) = kb.pop_typeahead() {
        if let Ok(KeyOutcome::Transmit(bytes)) = submit(&mut kb, &mut ps, input) {
            sent.push(bytes[0]);
        }
    }
    assert_eq!(sent, vec![0xF3], "PF3 sent, then the replay stopped");
    assert_eq!(kb.typeahead_len(), 1, "'Y' waits for the next unlock");
    assert_eq!(kb.state(), KeyboardState::TimeWait);
}

#[test]
fn typeahead_is_bounded() {
    let mut ps = screen();
    let mut kb = ready();
    kb.press_aid(&mut ps, AidKey::Enter).unwrap();
    for _ in 0..bastion3270_core::keyboard::MAX_TYPEAHEAD {
        assert_eq!(
            submit(&mut kb, &mut ps, KeyInput::Char('Z')),
            Ok(KeyOutcome::Queued)
        );
    }
    assert_eq!(
        submit(&mut kb, &mut ps, KeyInput::Char('Z')),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
}

#[test]
fn first_reset_discards_typeahead_second_reset_unlocks() {
    let mut ps = screen();
    let mut kb = ready();
    kb.press_aid(&mut ps, AidKey::Enter).unwrap();
    submit(&mut kb, &mut ps, KeyInput::Char('Q')).unwrap();

    // x3270 "half reset": the first Reset only flushes the queue.
    kb.reset();
    assert_eq!(kb.typeahead_len(), 0);
    assert_eq!(kb.state(), KeyboardState::TimeWait);
    kb.reset();
    assert_eq!(kb.state(), KeyboardState::Unlocked);
}

#[test]
fn operator_error_discards_typeahead() {
    let mut ps = screen();
    let mut kb = ready();
    kb.enter_inhibit();
    submit(&mut kb, &mut ps, KeyInput::Char('Q')).unwrap();
    kb.host_write(false);
    let cap = ps.capacity();
    ps.set_cursor_addr(BufferAddress::new(3, cap).unwrap())
        .unwrap();
    // The queued 'Q' runs into the protected field: operator error, queue flushed.
    let input = kb.pop_typeahead().unwrap();
    assert_eq!(
        submit(&mut kb, &mut ps, input),
        Err(KeyboardError::ProtectedField)
    );
    assert_eq!(kb.typeahead_len(), 0);
}
