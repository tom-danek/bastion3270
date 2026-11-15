//! WebSocket wire protocol (`bastion3270.v1`, JSON text frames).
//!
//! **Browser → server** ([`ClientMessage`]) carries *only intents*: keystrokes, actions, AID keys.
//! The browser never sends field contents or attributes, so it cannot overwrite a `Protected`
//! field — the server-side `bastion3270-core` keyboard validates every keystroke.
//!
//! **Server → browser** ([`ServerMessage`]) carries *only* a projection of [`SafeScreenView`]:
//! row texts (hidden fields already blank) plus run-length-encoded style runs.
//!
//! ```text
//! → {"type":"open","profile":"hercules"}
//! ← {"type":"session","session_id":"…","resume_token":"…","profile":"hercules"}
//! ← {"type":"frame","seq":1,"screen":{…},"status":{…},"alarm":false}
//! → {"type":"key","ch":"A"}
//! → {"type":"aid","aid":"enter"}
//! → {"type":"attention","key":"attn"}
//! ```

use bastion3270_core::{
    ActionKey, AidKey, AttentionKey, CodePageId, Color3270, HostMode, KeyboardState, SafeCell,
    SafeScreenView,
};
use bastion3270_net::profile::{ConnectionProfile, ProfileTerminalModel};
use serde::{Deserialize, Serialize};

use crate::gateway::Snapshot;

/// Messages sent by the browser.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientMessage {
    /// Open a new session on a whitelisted profile (must be the first message).
    Open {
        /// Profile id.
        profile: String,
        /// The user's session choices (model, screen size, code page ...); validated by the
        /// gateway, never connection settings.
        #[serde(default)]
        options: crate::gateway::SessionOptions,
    },
    /// Open a session to a target the user entered (must be the first message); the gateway
    /// checks it against its `[custom_connections]` policy.
    OpenCustom {
        /// Host, port, TLS.
        target: crate::custom::CustomTarget,
        /// The user's session choices, as with `open`.
        #[serde(default)]
        options: crate::gateway::SessionOptions,
    },
    /// Re-attach to an existing session (must be the first message).
    Resume {
        /// Session id from a previous `session` message.
        session_id: String,
        /// Resume token from the same message.
        token: String,
    },
    /// Type one character.
    Key {
        /// The character.
        ch: char,
    },
    /// Paste text (checked by the DLP policy, length-limited).
    Text {
        /// Text to type.
        text: String,
    },
    /// Navigation / editing key.
    Action {
        /// Action name (see [`parse_action`]).
        action: String,
    },
    /// Move the cursor (mouse click).
    MoveCursor {
        /// 0-based row.
        row: u16,
        /// 0-based column.
        col: u16,
    },
    /// AID key.
    Aid {
        /// AID name (see [`parse_aid`]).
        aid: String,
    },
    /// Attn or `SysReq` key.
    Attention {
        /// Key name (see [`parse_attention`]).
        key: String,
    },
    /// The user prints the screen: audited, and refused when the profile does not allow the
    /// screen to leave the page (the copy policy).
    Print,
    /// Switch blank fill on or off for the rest of the session (operator preference).
    BlankFill {
        /// On or off.
        on: bool,
    },
    /// End the mainframe session.
    Disconnect,
}

/// Messages sent by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Session established / resumed.
    Session {
        /// Session id.
        session_id: String,
        /// Resume token for the next reconnect. Every `open` and every `resume` issues a new
        /// one; the token just used is no longer valid.
        resume_token: String,
        /// Profile id.
        profile: String,
    },
    /// Screen and status update.
    Frame {
        /// Snapshot sequence number.
        seq: u64,
        /// Screen, omitted if unchanged since the previous frame.
        #[serde(skip_serializing_if = "Option::is_none")]
        screen: Option<WireScreen>,
        /// Status line (OIA).
        status: WireStatus,
        /// Ring the bell.
        alarm: bool,
    },
    /// Recoverable error (the connection stays open).
    Error {
        /// Stable code (`bad_request`, `dlp_denied`, `rate_limited`, …).
        code: String,
        /// Human-readable message.
        message: String,
    },
    /// The WebSocket is about to close.
    Closed {
        /// Reason: `user`, `host_disconnected`, `taken_over`, `server_shutdown`,
        /// `rate_limited`; when the gateway ends the session itself `idle` (no operator input),
        /// `lifetime` (maximum session lifetime), `identity_expired` or `ended` (any other).
        reason: String,
    },
}

/// Screen projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WireScreen {
    /// Rows.
    pub rows: u16,
    /// Columns.
    pub cols: u16,
    /// Cursor `[row, col]`, 0-based.
    pub cursor: [u16; 2],
    /// Formatted screen (has fields).
    pub formatted: bool,
    /// One string per row, exactly `cols` characters each.
    pub text: Vec<String>,
    /// Style runs over the linear cell index.
    pub runs: Vec<StyleRun>,
    /// DLP: may the client offer copy.
    pub copy_allowed: bool,
}

/// A run of consecutive cells with identical style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StyleRun {
    /// First linear cell index.
    pub s: u32,
    /// Number of cells.
    pub n: u32,
    /// Foreground: `0` = default, otherwise the 3270 color byte `0xF0..=0xFF`.
    pub fg: u8,
    /// Background, same encoding.
    pub bg: u8,
    /// Highlighting flags: bit 0 blink, bit 1 reverse video, bit 2 underscore, bit 3 intensify.
    pub hl: u8,
    /// Bit 0 = protected, bit 1 = field attribute marker.
    pub f: u8,
}

/// OIA status.
// One JSON flag per OIA indicator; independent values, not a state machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WireStatus {
    /// `connecting`, `negotiating`, `connected`, `disconnected`, `error`.
    pub state: &'static str,
    /// Error text, if `state == "error"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// OIA keyboard indicator (`""`, `X SYSTEM`, `X PROTECTED`, …).
    pub keyboard: &'static str,
    /// Keyboard locked.
    pub locked: bool,
    /// TLS transport.
    pub tls: bool,
    /// TN3270E negotiated.
    pub tn3270e: bool,
    /// Host-assigned LU.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lu: Option<String>,
    /// Host mode: `negotiating`, `unbound`, `3270`, `sscp-lu`, `nvt`.
    pub mode: &'static str,
    /// Insert mode is on.
    pub insert: bool,
    /// NVT text from the host (printable ASCII, bounded), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Terminal model of the session: `2`..`5` or `dynamic` (the screen's current size is in
    /// the frame's `screen`).
    pub model: &'static str,
    /// Host code page of the session (canonical name, e.g. `cp1047`).
    pub codepage: &'static str,
}

/// Builds the screen projection.
#[must_use]
pub fn wire_screen(view: &SafeScreenView, copy_allowed: bool) -> WireScreen {
    let cols = usize::from(view.cols());
    let cells = view.cells();
    let text = if cols == 0 {
        Vec::new()
    } else {
        cells
            .chunks(cols)
            .map(|row| row.iter().map(|c| printable(c.ch)).collect())
            .collect()
    };

    let mut runs: Vec<StyleRun> = Vec::new();
    for (i, cell) in cells.iter().enumerate() {
        let (fg, bg, hl, f) = style_of(cell);
        let idx = u32::try_from(i).unwrap_or(u32::MAX);
        match runs.last_mut() {
            Some(r) if r.fg == fg && r.bg == bg && r.hl == hl && r.f == f => {
                r.n = r.n.saturating_add(1);
            }
            _ => runs.push(StyleRun {
                s: idx,
                n: 1,
                fg,
                bg,
                hl,
                f,
            }),
        }
    }

    WireScreen {
        rows: view.rows(),
        cols: view.cols(),
        cursor: [view.cursor_row(), view.cursor_col()],
        formatted: view.is_formatted(),
        text,
        runs,
        copy_allowed,
    }
}

/// What the browser sees when the host connection ended with an error.
pub const HOST_ERROR: &str = "the connection to the host ended with an error";

/// Builds the OIA status.
#[must_use]
pub fn wire_status(snap: &Snapshot, connection: &ConnectionProfile) -> WireStatus {
    use bastion3270_net::SessionState as S;
    let (state, error) = match &snap.state {
        S::Connecting => ("connecting", None),
        S::Negotiating => ("negotiating", None),
        S::Connected3270 => ("connected", None),
        S::Disconnected => ("disconnected", None),
        // The detail (it may name hosts, certificates or files) is recorded server-side with
        // the session's `Closed` audit event; the browser gets a fixed text.
        S::Error(_) => ("error", Some(HOST_ERROR.to_owned())),
    };
    WireStatus {
        state,
        error,
        keyboard: snap.keyboard.oia_indicator(),
        locked: snap.keyboard != KeyboardState::Unlocked,
        tls: snap.is_tls,
        tn3270e: snap.is_tn3270e,
        lu: snap.lu.clone(),
        mode: match snap.host_mode {
            HostMode::Negotiating => "negotiating",
            HostMode::Unbound => "unbound",
            HostMode::Data3270 => "3270",
            HostMode::SscpLu => "sscp-lu",
            HostMode::Nvt => "nvt",
        },
        insert: snap.insert_mode,
        banner: snap.banner.clone(),
        model: match connection.terminal_model {
            ProfileTerminalModel::Model2 => "2",
            ProfileTerminalModel::Model3 => "3",
            ProfileTerminalModel::Model4 => "4",
            ProfileTerminalModel::Model5 => "5",
            ProfileTerminalModel::Dynamic { .. } => "dynamic",
        },
        // The profile was validated when the session opened, so the name is known.
        codepage: CodePageId::from_name(&connection.codepage).map_or("", CodePageId::name),
    }
}

/// Replaces control characters with spaces so the client can render text verbatim.
fn printable(ch: char) -> char {
    if ch.is_control() {
        ' '
    } else {
        ch
    }
}

fn style_of(cell: &SafeCell) -> (u8, u8, u8, u8) {
    // Highlighting flags: blink 1, reverse video 2, underscore 4, intensify 8.
    let hl = cell.highlight.bits();
    let f = u8::from(cell.protected) | (u8::from(cell.is_field_marker) << 1);
    (color(cell.foreground), color(cell.background), hl, f)
}

const fn color(c: Color3270) -> u8 {
    c.to_xa_byte()
}

/// Parses an AID name: `enter`, `clear`, `pf1`..`pf24`, `pa1`..`pa3`.
#[must_use]
pub fn parse_aid(name: &str) -> Option<AidKey> {
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "enter" => Some(AidKey::Enter),
        "clear" => Some(AidKey::Clear),
        _ => {
            if let Some(n) = lower.strip_prefix("pf") {
                AidKey::pf(n.parse().ok()?)
            } else if let Some(n) = lower.strip_prefix("pa") {
                AidKey::pa(n.parse().ok()?)
            } else {
                None
            }
        }
    }
}

/// Parses an attention key name: `attn` or `sysreq`.
#[must_use]
pub fn parse_attention(name: &str) -> Option<AttentionKey> {
    match name.to_ascii_lowercase().as_str() {
        "attn" => Some(AttentionKey::Attn),
        "sysreq" => Some(AttentionKey::SysReq),
        _ => None,
    }
}

/// Parses an action name (`tab`, `backtab`, `home`, `newline`, `left`, `right`, `up`, `down`,
/// `erase_eof`, `erase_input`, `field_end`, `toggle_insert`, `backspace`, `delete`, `reset`).
#[must_use]
pub fn parse_action(name: &str) -> Option<ActionKey> {
    Some(match name {
        "tab" => ActionKey::Tab,
        "backtab" => ActionKey::BackTab,
        "home" => ActionKey::Home,
        "newline" => ActionKey::Newline,
        "left" => ActionKey::Left,
        "right" => ActionKey::Right,
        "up" => ActionKey::Up,
        "down" => ActionKey::Down,
        "erase_eof" => ActionKey::EraseEof,
        "erase_input" => ActionKey::EraseInput,
        "field_end" => ActionKey::FieldEnd,
        "toggle_insert" => ActionKey::ToggleInsert,
        "backspace" => ActionKey::Backspace,
        "delete" => ActionKey::Delete,
        "reset" => ActionKey::Reset,
        "dup" => ActionKey::Dup,
        "field_mark" => ActionKey::FieldMark,
        "erase_field" => ActionKey::EraseField,
        _ => return None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_host_error_details_are_not_sent_to_the_browser() {
        let snap = crate::gateway::Snapshot {
            seq: 0,
            view: SafeScreenView::default(),
            state: bastion3270_net::SessionState::Error(
                "TLS error: certificate not valid for name \"lpar1.internal\"".to_owned(),
            ),
            keyboard: KeyboardState::Unlocked,
            is_tls: true,
            is_tn3270e: true,
            lu: None,
            alarm_seq: 0,
            last_error: None,
            host_mode: HostMode::Data3270,
            insert_mode: false,
            banner: None,
        };
        let connection = ConnectionProfile {
            terminal_model: ProfileTerminalModel::Dynamic {
                rows: 62,
                cols: 160,
            },
            codepage: "german-euro".into(),
            ..ConnectionProfile::default()
        };
        let status = wire_status(&snap, &connection);
        assert_eq!(status.state, "error");
        assert_eq!(status.error.as_deref(), Some(HOST_ERROR));
        // The session's model and code page (canonical name) for the status line.
        assert_eq!((status.model, status.codepage), ("dynamic", "cp1141"));
    }

    #[test]
    fn test_parse_client_messages() {
        let m: ClientMessage = serde_json::from_str(r#"{"type":"key","ch":"A"}"#).unwrap();
        assert_eq!(m, ClientMessage::Key { ch: 'A' });
        let m: ClientMessage =
            serde_json::from_str(r#"{"type":"move_cursor","row":3,"col":7}"#).unwrap();
        assert_eq!(m, ClientMessage::MoveCursor { row: 3, col: 7 });
        let m: ClientMessage =
            serde_json::from_str(r#"{"type":"attention","key":"attn"}"#).unwrap();
        assert_eq!(
            m,
            ClientMessage::Attention {
                key: "attn".to_string()
            }
        );
        assert!(serde_json::from_str::<ClientMessage>(r#"{"type":"key","ch":"AB"}"#).is_err());
        assert!(serde_json::from_str::<ClientMessage>(r#"{"type":"raw","bytes":[1]}"#).is_err());
        assert!(serde_json::from_str::<ClientMessage>(
            r#"{"type":"open","profile":"x","host":"10.0.0.1"}"#
        )
        .is_err());
    }

    #[test]
    fn test_parse_aid_and_action_names() {
        assert_eq!(parse_aid("enter"), Some(AidKey::Enter));
        assert_eq!(parse_aid("PF24"), Some(AidKey::PF24));
        assert_eq!(parse_aid("pa3"), Some(AidKey::PA3));
        assert_eq!(parse_attention("attn"), Some(AttentionKey::Attn));
        assert_eq!(parse_attention("SysReq"), Some(AttentionKey::SysReq));
        assert_eq!(parse_attention("pa1"), None);
        assert_eq!(parse_aid("pf25"), None);
        assert_eq!(parse_aid("pf"), None);
        assert_eq!(parse_action("erase_eof"), Some(ActionKey::EraseEof));
        assert_eq!(parse_action("field_end"), Some(ActionKey::FieldEnd));
        assert_eq!(parse_action("toggle_insert"), Some(ActionKey::ToggleInsert));
        assert_eq!(parse_action("dup"), Some(ActionKey::Dup));
        assert_eq!(parse_action("field_mark"), Some(ActionKey::FieldMark));
        assert_eq!(parse_action("erase_field"), Some(ActionKey::EraseField));
        assert_eq!(parse_action("format_c"), None);
    }

    #[test]
    fn test_wire_screen_rle_and_rows() {
        let mut cells = vec![SafeCell::BLANK; 2 * 3];
        cells[0].ch = 'H';
        cells[1].ch = 'I';
        cells[3].protected = true;
        cells[3].is_field_marker = true;
        cells[4].foreground = Color3270::Red;
        cells[5].ch = '\u{7}';
        let view = SafeScreenView::new(2, 3, 1, 2, true, cells).unwrap();
        let w = wire_screen(&view, true);
        assert_eq!(w.text, vec!["HI ".to_owned(), "   ".to_owned()]);
        assert_eq!(w.cursor, [1, 2]);
        assert_eq!(w.runs.len(), 4);
        assert_eq!((w.runs[0].s, w.runs[0].n), (0, 3));
        assert_eq!(w.runs[1].f, 0b11);
        assert_eq!(w.runs[2].fg, 0xF2);
        let total: u32 = w.runs.iter().map(|r| r.n).sum();
        assert_eq!(total, 6);
    }
}
