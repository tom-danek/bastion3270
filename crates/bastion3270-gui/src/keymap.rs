//! IBM 3270 Hardware Keyboard Mapping and On-Screen Keypad Toolbar.
//!
//! Translates `egui::Key`, `egui::Modifiers`, and text input events into deterministic
//! [`GuiKeyAction`] commands (`AidKey`, `ActionKey`, printable characters, and UI zoom).

use bastion3270_core::{ActionKey, AidKey, AttentionKey};
use egui::{Key, Modifiers};
use serde::{Deserialize, Serialize};

/// Key layout presets, the same as the web client's (`keymap.js`):
///
/// * `x3270` — x3270 / wc3270: Enter is the Enter AID, Shift+Enter / Ctrl+Enter New Line, Esc
///   Reset, End End-of-field, Shift+End Erase EOF, `PageUp` / `PageDown` PF7 / PF8;
/// * `pcomm` — IBM Personal Communications' default 3270 layout: Enter is New Line, Esc / Shift+Esc
///   Attn / `SysReq`, Alt+Insert / Alt+Home / `Shift+PageUp` PA1 / PA2 / PA3, End Erase EOF,
///   Shift+End / Alt+End Erase Field / Erase Input, Shift+Insert / Shift+Home Dup / Field Mark.
///   egui reports neither which Ctrl key was pressed nor the Pause key, so the desktop client
///   takes Ctrl+Enter for PCOMM's Right Ctrl (Enter AID), Ctrl+R for Left Ctrl (Reset) and
///   Ctrl+L for Pause (Clear).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KeyboardPreset {
    /// x3270 / wc3270.
    #[default]
    #[serde(rename = "x3270")]
    X3270,
    /// IBM Personal Communications.
    #[serde(rename = "pcomm")]
    Pcomm,
}

impl KeyboardPreset {
    /// All presets for UI selection.
    pub const ALL: [Self; 2] = [Self::X3270, Self::Pcomm];

    /// Human-readable name for the UI (as in the web client).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::X3270 => "x3270 / wc3270",
            Self::Pcomm => "IBM Personal Communications",
        }
    }
}

/// High-level action produced by keyboard translation or the on-screen 3270 keypad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuiKeyAction {
    /// Transmit a 3270 Attention Identification (AID) key (`Enter`, `PF1`..`PF24`, `PA1`..`PA3`, `Clear`).
    Aid(AidKey),
    /// Perform a local virtual keyboard navigation, editing, or operator reset action.
    Action(ActionKey),
    /// Press Attn or `SysReq`.
    Attention(AttentionKey),
    /// Insert a printable character at the current cursor position.
    Char(char),
    /// Increase terminal font size.
    ZoomIn,
    /// Decrease terminal font size.
    ZoomOut,
    /// Reset terminal font size to 100%.
    ZoomReset,
}

/// Translates a pressed `egui::Key` + `egui::Modifiers` into an optional [`GuiKeyAction`]
/// with the key layout `preset` (see [`KeyboardPreset`]).
///
/// Besides the preset, the desktop client keeps its own shortcuts: Ctrl+R Reset, Ctrl+L Clear,
/// Ctrl+E Erase EOF, Ctrl+U Erase Input, Alt+1 / Alt+2 / Alt+3 PA1 / PA2 / PA3, Alt+C Clear,
/// Ctrl+Plus / Ctrl+Minus / Ctrl+0 zoom.
#[must_use]
pub fn translate_key_event(
    key: Key,
    modifiers: Modifiers,
    preset: KeyboardPreset,
) -> Option<GuiKeyAction> {
    let ctrl = modifiers.ctrl || modifiers.command;
    let shift = modifiers.shift;
    let alt = modifiers.alt;
    let pcomm = preset == KeyboardPreset::Pcomm;
    let aid = |a: AidKey| Some(GuiKeyAction::Aid(a));
    let action = |a: ActionKey| Some(GuiKeyAction::Action(a));

    // F1..F12 -> PF1..PF12, Shift+F1..F12 -> PF13..PF24 (both presets)
    if let Some(pf_base) = function_key_number(key) {
        let pf_num = if shift {
            pf_base.saturating_add(12)
        } else {
            pf_base
        };
        return AidKey::pf(pf_num).map(GuiKeyAction::Aid);
    }

    if ctrl && !alt {
        return match key {
            // PCOMM's Right Ctrl; in the x3270 preset Ctrl+Enter is New Line, as Shift+Enter.
            Key::Enter if pcomm => aid(AidKey::Enter),
            Key::Enter => action(ActionKey::Newline),
            Key::R => action(ActionKey::Reset),
            Key::L => aid(AidKey::Clear),
            Key::E => action(ActionKey::EraseEof),
            Key::U => action(ActionKey::EraseInput),
            Key::Plus | Key::Equals => Some(GuiKeyAction::ZoomIn),
            Key::Minus => Some(GuiKeyAction::ZoomOut),
            Key::Num0 => Some(GuiKeyAction::ZoomReset),
            _ => None,
        };
    }

    if alt && !ctrl {
        match key {
            Key::Num1 => return aid(AidKey::PA1),
            Key::Num2 => return aid(AidKey::PA2),
            Key::Num3 => return aid(AidKey::PA3),
            Key::C => return aid(AidKey::Clear),
            Key::Insert if pcomm => return aid(AidKey::PA1),
            Key::Home if pcomm => return aid(AidKey::PA2),
            Key::End if pcomm => return action(ActionKey::EraseInput),
            _ => {}
        }
    }

    if let PresetKey::Preset(preset_action) = preset_key(key, shift, preset) {
        return preset_action;
    }

    match key {
        Key::Tab => action(if shift {
            ActionKey::BackTab
        } else {
            ActionKey::Tab
        }),
        Key::Home => action(ActionKey::Home),
        Key::Insert => action(ActionKey::ToggleInsert),
        Key::ArrowLeft => action(ActionKey::Left),
        Key::ArrowRight => action(ActionKey::Right),
        Key::ArrowUp => action(ActionKey::Up),
        Key::ArrowDown => action(ActionKey::Down),
        Key::Backspace => action(ActionKey::Backspace),
        Key::Delete => action(ActionKey::Delete),
        _ => None,
    }
}

/// What a key means in a preset.
enum PresetKey {
    /// The key means the same in both presets (handled by [`translate_key_event`]).
    Common,
    /// The preset's meaning; `None`: the key does nothing in this preset.
    Preset(Option<GuiKeyAction>),
}

/// One of two values by the Shift key.
const fn by_shift<T: Copy>(shift: bool, on_shift: T, plain: T) -> T {
    if shift {
        on_shift
    } else {
        plain
    }
}

/// The keys whose meaning depends on the preset.
fn preset_key(key: Key, shift: bool, preset: KeyboardPreset) -> PresetKey {
    let aid = |a: AidKey| PresetKey::Preset(Some(GuiKeyAction::Aid(a)));
    let action = |a: ActionKey| PresetKey::Preset(Some(GuiKeyAction::Action(a)));
    match (preset, key) {
        (KeyboardPreset::Pcomm, Key::Enter) => action(ActionKey::Newline),
        (KeyboardPreset::Pcomm, Key::Escape) => PresetKey::Preset(Some(GuiKeyAction::Attention(
            by_shift(shift, AttentionKey::SysReq, AttentionKey::Attn),
        ))),
        (KeyboardPreset::Pcomm, Key::Insert) if shift => action(ActionKey::Dup),
        (KeyboardPreset::Pcomm, Key::Home) if shift => action(ActionKey::FieldMark),
        (KeyboardPreset::Pcomm, Key::PageUp) if shift => aid(AidKey::PA3),
        (KeyboardPreset::Pcomm, Key::PageUp | Key::PageDown) => PresetKey::Preset(None),
        (KeyboardPreset::Pcomm, Key::End) => {
            action(by_shift(shift, ActionKey::EraseField, ActionKey::EraseEof))
        }
        (KeyboardPreset::X3270, Key::Enter) if shift => action(ActionKey::Newline),
        (KeyboardPreset::X3270, Key::Enter) => aid(AidKey::Enter),
        (KeyboardPreset::X3270, Key::Escape) => action(ActionKey::Reset),
        // As wc3270: End = FieldEnd, Shift+End = EraseEOF, PageUp / PageDown = PF7 / PF8.
        (KeyboardPreset::X3270, Key::End) => {
            action(by_shift(shift, ActionKey::EraseEof, ActionKey::FieldEnd))
        }
        (KeyboardPreset::X3270, Key::PageUp) => aid(AidKey::PF7),
        (KeyboardPreset::X3270, Key::PageDown) => aid(AidKey::PF8),
        _ => PresetKey::Common,
    }
}

/// Filters and translates `egui::Event::Text` into printable [`GuiKeyAction::Char`] events.
///
/// Control characters (such as `\r`, `\n`, `\t`, `\x08`, `\x7f`) are ignored because they
/// are already handled deterministically via [`translate_key_event`].
#[must_use]
pub fn translate_text_input(text: &str) -> Vec<GuiKeyAction> {
    let mut actions = Vec::with_capacity(text.len());
    for ch in text.chars() {
        if !ch.is_control() {
            actions.push(GuiKeyAction::Char(ch));
        }
    }
    actions
}

const fn function_key_number(key: Key) -> Option<u8> {
    match key {
        Key::F1 => Some(1),
        Key::F2 => Some(2),
        Key::F3 => Some(3),
        Key::F4 => Some(4),
        Key::F5 => Some(5),
        Key::F6 => Some(6),
        Key::F7 => Some(7),
        Key::F8 => Some(8),
        Key::F9 => Some(9),
        Key::F10 => Some(10),
        Key::F11 => Some(11),
        Key::F12 => Some(12),
        Key::F13 => Some(13),
        Key::F14 => Some(14),
        Key::F15 => Some(15),
        Key::F16 => Some(16),
        Key::F17 => Some(17),
        Key::F18 => Some(18),
        Key::F19 => Some(19),
        Key::F20 => Some(20),
        Key::F21 => Some(21),
        Key::F22 => Some(22),
        Key::F23 => Some(23),
        Key::F24 => Some(24),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pf1_through_pf24_mapping() {
        let no_mod = Modifiers::NONE;
        let shift_mod = Modifiers {
            shift: true,
            ..Modifiers::NONE
        };

        assert_eq!(
            translate_key_event(Key::F1, no_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Aid(AidKey::PF1))
        );
        assert_eq!(
            translate_key_event(Key::F3, no_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Aid(AidKey::PF3))
        );
        assert_eq!(
            translate_key_event(Key::F12, no_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Aid(AidKey::PF12))
        );

        // Shift + F1..F12 -> PF13..PF24
        assert_eq!(
            translate_key_event(Key::F1, shift_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Aid(AidKey::PF13))
        );
        assert_eq!(
            translate_key_event(Key::F12, shift_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Aid(AidKey::PF24))
        );
    }

    #[test]
    fn test_enter_modes_and_ctrl_shortcuts() {
        let no_mod = Modifiers::NONE;
        let shift_mod = Modifiers {
            shift: true,
            ..Modifiers::NONE
        };
        let ctrl_mod = Modifiers {
            ctrl: true,
            ..Modifiers::NONE
        };

        // x3270 preset
        assert_eq!(
            translate_key_event(Key::Enter, no_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Aid(AidKey::Enter))
        );
        assert_eq!(
            translate_key_event(Key::Enter, shift_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Action(ActionKey::Newline))
        );

        // PCOMM preset (Ctrl+Enter stands for Right Ctrl)
        assert_eq!(
            translate_key_event(Key::Enter, no_mod, KeyboardPreset::Pcomm),
            Some(GuiKeyAction::Action(ActionKey::Newline))
        );
        assert_eq!(
            translate_key_event(Key::Enter, ctrl_mod, KeyboardPreset::Pcomm),
            Some(GuiKeyAction::Aid(AidKey::Enter))
        );

        // Operator shortcuts
        assert_eq!(
            translate_key_event(Key::Escape, no_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Action(ActionKey::Reset))
        );
        assert_eq!(
            translate_key_event(Key::R, ctrl_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Action(ActionKey::Reset))
        );
        assert_eq!(
            translate_key_event(Key::L, ctrl_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Aid(AidKey::Clear))
        );
        assert_eq!(
            translate_key_event(Key::E, ctrl_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Action(ActionKey::EraseEof))
        );
        assert_eq!(
            translate_key_event(Key::U, ctrl_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Action(ActionKey::EraseInput))
        );
    }

    #[test]
    fn test_navigation_and_text_filtering() {
        let no_mod = Modifiers::NONE;
        let shift_mod = Modifiers {
            shift: true,
            ..Modifiers::NONE
        };

        assert_eq!(
            translate_key_event(Key::Tab, no_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Action(ActionKey::Tab))
        );
        assert_eq!(
            translate_key_event(Key::Tab, shift_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Action(ActionKey::BackTab))
        );
        assert_eq!(
            translate_key_event(Key::Backspace, no_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Action(ActionKey::Backspace))
        );
        assert_eq!(
            translate_key_event(Key::Delete, no_mod, KeyboardPreset::X3270),
            Some(GuiKeyAction::Action(ActionKey::Delete))
        );

        let chars = translate_text_input("HERC01\n\t\r");
        assert_eq!(
            chars,
            vec![
                GuiKeyAction::Char('H'),
                GuiKeyAction::Char('E'),
                GuiKeyAction::Char('R'),
                GuiKeyAction::Char('C'),
                GuiKeyAction::Char('0'),
                GuiKeyAction::Char('1'),
            ]
        );
    }

    #[test]
    fn test_pcomm_preset_and_x3270_page_keys() {
        let m = |shift: bool, alt: bool| Modifiers {
            shift,
            alt,
            ..Modifiers::NONE
        };
        let p = KeyboardPreset::Pcomm;
        let x = KeyboardPreset::X3270;
        let t = translate_key_event;
        assert_eq!(
            t(Key::Escape, m(false, false), p),
            Some(GuiKeyAction::Attention(AttentionKey::Attn))
        );
        assert_eq!(
            t(Key::Escape, m(true, false), p),
            Some(GuiKeyAction::Attention(AttentionKey::SysReq))
        );
        assert_eq!(
            t(Key::Insert, m(false, true), p),
            Some(GuiKeyAction::Aid(AidKey::PA1))
        );
        assert_eq!(
            t(Key::Home, m(false, true), p),
            Some(GuiKeyAction::Aid(AidKey::PA2))
        );
        assert_eq!(
            t(Key::PageUp, m(true, false), p),
            Some(GuiKeyAction::Aid(AidKey::PA3))
        );
        assert_eq!(t(Key::PageDown, m(false, false), p), None);
        assert_eq!(
            t(Key::End, m(false, false), p),
            Some(GuiKeyAction::Action(ActionKey::EraseEof))
        );
        assert_eq!(
            t(Key::End, m(true, false), p),
            Some(GuiKeyAction::Action(ActionKey::EraseField))
        );
        assert_eq!(
            t(Key::End, m(false, true), p),
            Some(GuiKeyAction::Action(ActionKey::EraseInput))
        );
        assert_eq!(
            t(Key::Insert, m(true, false), p),
            Some(GuiKeyAction::Action(ActionKey::Dup))
        );
        assert_eq!(
            t(Key::Home, m(true, false), p),
            Some(GuiKeyAction::Action(ActionKey::FieldMark))
        );
        // x3270 / wc3270: PageUp / PageDown are PF7 / PF8, End is End-of-field.
        assert_eq!(
            t(Key::PageUp, m(false, false), x),
            Some(GuiKeyAction::Aid(AidKey::PF7))
        );
        assert_eq!(
            t(Key::PageDown, m(false, false), x),
            Some(GuiKeyAction::Aid(AidKey::PF8))
        );
        assert_eq!(
            t(Key::End, m(false, false), x),
            Some(GuiKeyAction::Action(ActionKey::FieldEnd))
        );
    }
}
