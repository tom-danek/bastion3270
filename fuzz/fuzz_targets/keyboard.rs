//! Fuzzes the operator keyboard (`x3270` `kybd.c`) on a host-written screen.
//!
//! The input (decoded with `arbitrary`) is a terminal model, keyboard options, a 3270 record
//! that builds the starting screen, and up to [`MAX_OPS`] operations: typed characters,
//! editing and navigation keys (including mouse moves to arbitrary coordinates), AID keys,
//! System Request, paste, further host records, and the connection / host-mode lifecycle
//! events that lock and unlock the keyboard. Keys queued while the keyboard is locked are
//! replayed through `submit` after every operation, as the session layer does (`x3270`
//! `run_ta`).
//!
//! After every operation the target asserts:
//! * cursor and buffer address are inside the screen;
//! * the typeahead queue never exceeds `MAX_TYPEAHEAD`;
//! * operator input never changes a protected field or moves / removes a field attribute
//!   (only its MDT bit may change) — the `X PROTECTED` rule of `x3270` `key_Character` and
//!   `ctlr_erase_all_unprotected`. Clear, which erases the screen locally, and SSCP-LU AID
//!   keys, which scroll the screen, are exempt;
//! * the zero-trust projection still masks non-display fields.
#![no_main]

use arbitrary::Arbitrary;
use bastion3270_core::keyboard::MAX_TYPEAHEAD;
use bastion3270_core::{
    ActionKey, AidKey, DataStreamParser, HostMode, KeyInput, KeyboardOptions, PresentationSpace,
    VirtualKeyboard, CP037,
};
use bastion3270_fuzz::{
    assert_addresses_in_bounds, assert_safe_view, governing_attributes, model_from_selector,
    screen_cells,
};
use libfuzzer_sys::fuzz_target;

/// Upper bound of operations per input, so one input cannot run for long.
const MAX_OPS: usize = 200;

/// Navigation and editing keys without coordinates, selected by index.
const ACTIONS: [ActionKey; 15] = [
    ActionKey::Tab,
    ActionKey::BackTab,
    ActionKey::Home,
    ActionKey::Newline,
    ActionKey::Left,
    ActionKey::Right,
    ActionKey::Up,
    ActionKey::Down,
    ActionKey::EraseEof,
    ActionKey::FieldEnd,
    ActionKey::ToggleInsert,
    ActionKey::EraseInput,
    ActionKey::Backspace,
    ActionKey::Delete,
    ActionKey::Reset,
];

const HOST_MODES: [HostMode; 5] = [
    HostMode::Negotiating,
    HostMode::Unbound,
    HostMode::Data3270,
    HostMode::SscpLu,
    HostMode::Nvt,
];

#[derive(Debug, Arbitrary)]
enum Op {
    Char(char),
    Action(u8),
    MoveCursor { row: u16, col: u16 },
    Aid(u8),
    SysReq,
    Paste(String),
    HostRecord(Vec<u8>),
    HostWrite(bool),
    HostReset,
    Reset,
    EnterInhibit,
    NotAvailable,
    SetHostMode(u8),
    Disconnected,
    Connected,
    Entered3270(bool),
    Unbound,
}

#[derive(Debug, Arbitrary)]
struct Input {
    model: u8,
    options: Option<(bool, bool)>,
    screen: Vec<u8>,
    ops: Vec<Op>,
}

fn action_key(index: u8) -> ActionKey {
    ACTIONS
        .get(usize::from(index) % ACTIONS.len())
        .copied()
        .unwrap_or(ActionKey::Tab)
}

/// `0` = Enter, `1..=24` = PF keys, `25..=27` = PA keys, everything else = Clear.
fn aid_key(index: u8) -> AidKey {
    match index % 29 {
        0 => AidKey::Enter,
        n @ 1..=24 => AidKey::pf(n).unwrap_or(AidKey::Enter),
        n @ 25..=27 => AidKey::pa(n - 24).unwrap_or(AidKey::Enter),
        _ => AidKey::Clear,
    }
}

/// The parts of the screen operator input must never change: for every field attribute its
/// attribute bits without MDT, for every character in a protected field its EBCDIC code.
/// Unprotected positions are `None`.
fn protected_snapshot(ps: &PresentationSpace) -> Vec<Option<u8>> {
    let cells = screen_cells(ps);
    let governing = governing_attributes(ps, &cells);
    cells
        .iter()
        .zip(governing)
        .map(|(cell, governing)| {
            if let Some(fa) = cell.field_attribute() {
                return Some(fa.with_modified(false).raw_bits());
            }
            governing
                .filter(|fa| fa.is_protected())
                .map(|_| cell.raw_ebcdic())
        })
        .collect()
}

/// `true` if `input` may legitimately rewrite protected cells: Clear erases the screen, and
/// an AID in SSCP-LU mode may scroll it.
fn may_rewrite_screen(kb: &VirtualKeyboard, input: KeyInput) -> bool {
    matches!(input, KeyInput::Aid(AidKey::Clear))
        || (kb.host_mode() == HostMode::SscpLu && matches!(input, KeyInput::Aid(_)))
}

/// Submits one key and checks the protected-field rule for it.
fn submit_checked(kb: &mut VirtualKeyboard, ps: &mut PresentationSpace, input: KeyInput) {
    let exempt = may_rewrite_screen(kb, input);
    let before = protected_snapshot(ps);
    // Refused keys (locked, protected, numeric, unmappable) are expected results.
    let _ = kb.submit(ps, input, &CP037);
    if !exempt {
        assert_eq!(
            before,
            protected_snapshot(ps),
            "operator input {input:?} changed a protected field or field attribute"
        );
    }
    assert_addresses_in_bounds(ps);
}

fn check(kb: &VirtualKeyboard, ps: &PresentationSpace) {
    assert_addresses_in_bounds(ps);
    assert!(kb.typeahead_len() <= MAX_TYPEAHEAD);
}

fuzz_target!(|input: Input| {
    let model = model_from_selector(input.model);
    let mut ps = PresentationSpace::new(model);
    let _ = DataStreamParser::process(&input.screen, &mut ps);
    let mut kb = match input.options {
        None => VirtualKeyboard::new(),
        Some((numeric_lock, blank_fill)) => VirtualKeyboard::with_options(KeyboardOptions {
            numeric_lock,
            blank_fill,
        }),
    };

    for op in input.ops.into_iter().take(MAX_OPS) {
        match op {
            Op::Char(ch) => submit_checked(&mut kb, &mut ps, KeyInput::Char(ch)),
            Op::Action(i) => submit_checked(&mut kb, &mut ps, KeyInput::Action(action_key(i))),
            Op::MoveCursor { row, col } => submit_checked(
                &mut kb,
                &mut ps,
                KeyInput::Action(ActionKey::MoveCursor { row, col }),
            ),
            Op::Aid(i) => submit_checked(&mut kb, &mut ps, KeyInput::Aid(aid_key(i))),
            Op::SysReq => submit_checked(&mut kb, &mut ps, KeyInput::SysReq),
            Op::Paste(text) => {
                let before = protected_snapshot(&ps);
                let _ = kb.paste(&mut ps, &text, &CP037);
                assert_eq!(
                    before,
                    protected_snapshot(&ps),
                    "paste changed a protected field or field attribute"
                );
            }
            Op::HostRecord(record) => {
                let result = DataStreamParser::process(&record, &mut ps);
                if let Some(wcc) = result.wcc {
                    kb.handle_wcc(&mut ps, wcc);
                } else if result.screen_written {
                    kb.host_write(result.restore_keyboard);
                }
            }
            Op::HostWrite(restore) => kb.host_write(restore),
            Op::HostReset => kb.host_reset(),
            Op::Reset => kb.reset(),
            Op::EnterInhibit => kb.enter_inhibit(),
            Op::NotAvailable => kb.not_available(),
            Op::SetHostMode(i) => kb.set_host_mode(
                HOST_MODES
                    .get(usize::from(i) % HOST_MODES.len())
                    .copied()
                    .unwrap_or_default(),
            ),
            Op::Disconnected => kb.disconnected(),
            Op::Connected => kb.connected(),
            Op::Entered3270(tn3270e) => kb.entered_3270(tn3270e),
            Op::Unbound => kb.unbound(),
        }
        check(&kb, &ps);

        // Typeahead replay (`x3270` `run_ta`): stops once a key locks the keyboard again.
        let mut replayed = 0;
        while let Some(queued) = kb.pop_typeahead() {
            submit_checked(&mut kb, &mut ps, queued);
            check(&kb, &ps);
            replayed += 1;
            assert!(
                replayed <= MAX_TYPEAHEAD,
                "typeahead replay does not terminate"
            );
        }
    }
    let _ = assert_safe_view(&ps, &CP037);
});
