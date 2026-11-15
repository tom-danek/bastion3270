//! IBM 3270 Operator Information Area (OIA) Status Bar Model and Renderer.
//!
//! Reference: IBM 3270 Information Display System & `x3270` status line (row N+1).
//! Displays:
//! - `4A` / `4B` / `4-` Online & System Connection indicator
//! - Security indicator (`TLS 1.2/1.3` vs `PLAIN TCP` vs `OFFLINE`)
//! - Protocol & Logical Unit (`TN3270E LU:...` or `TN3270`)
//! - Keyboard Lock / Error Indicator (`X SYSTEM`, `X PROTECTED`, `X NUMERIC`, `READY`)
//! - Terminal Model & Dimensions (`24x80`, `32x80`, `43x80`, `27x132`, etc.)
//! - 1-based Cursor Coordinates (`RRR/CCC`, e.g. `001/001`..`024/080`)

use bastion3270_core::KeyboardState;
use bastion3270_net::{ProfileTerminalModel, SessionState, SessionStatus};
use egui::{Color32, RichText, Ui};

/// Pure, deterministically testable snapshot of the Operator Information Area (OIA) line.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct OiaStatusModel {
    /// Session lifecycle state (`Connecting`, `Negotiating`, `Connected3270`, `Disconnected`, `Error`).
    pub session_state: SessionState,
    /// Virtual keyboard state (`Unlocked`, `TimeWait`, `Protected`, `Numeric`, etc.).
    pub keyboard_state: KeyboardState,
    /// 0-based cursor row.
    pub cursor_row: u16,
    /// 0-based cursor column.
    pub cursor_col: u16,
    /// Screen row count.
    pub rows: u16,
    /// Screen column count.
    pub cols: u16,
    /// Whether the current presentation space is formatted with 3270 fields.
    pub is_formatted: bool,
    /// Active terminal model configuration.
    pub terminal_model: ProfileTerminalModel,
    /// Assigned Logical Unit (LU) name, if any.
    pub assigned_lu: Option<String>,
    /// `true` if negotiated in TN3270E mode.
    pub is_tn3270e: bool,
    /// `true` if transport is TLS encrypted.
    pub is_tls: bool,
    /// Active EBCDIC code page identifier (e.g. `"cp037"`, `"ibm870"`).
    pub codepage: String,
    /// Visual bell / audible alarm active indicator.
    pub alarm_active: bool,
    /// Insert mode is on (`INS` indicator, `x3270` OIA insert mode).
    pub insert_mode: bool,
}

impl Default for OiaStatusModel {
    fn default() -> Self {
        Self {
            session_state: SessionState::Disconnected,
            keyboard_state: KeyboardState::Unlocked,
            cursor_row: 0,
            cursor_col: 0,
            rows: 24,
            cols: 80,
            is_formatted: false,
            terminal_model: ProfileTerminalModel::Model2,
            assigned_lu: None,
            is_tn3270e: false,
            is_tls: false,
            codepage: "cp037".to_string(),
            alarm_active: false,
            insert_mode: false,
        }
    }
}

impl OiaStatusModel {
    /// Updates the OIA model from a [`SessionStatus`] snapshot and screen dimensions.
    pub fn apply_session_status(&mut self, status: &SessionStatus, rows: u16, cols: u16) {
        self.session_state = status.state.clone();
        self.keyboard_state = status.keyboard_state;
        self.cursor_row = status.cursor_row;
        self.cursor_col = status.cursor_col;
        self.rows = rows;
        self.cols = cols;
        self.is_formatted = status.is_formatted;
        self.terminal_model = status.terminal_model;
        self.assigned_lu.clone_from(&status.assigned_lu);
        self.is_tn3270e = status.is_tn3270e;
        self.is_tls = status.is_tls;
    }

    /// Returns the classic IBM 3270 system connection code (`4A`, `4B`, or `4-`).
    #[must_use]
    pub const fn connection_code(&self) -> &'static str {
        match self.session_state {
            SessionState::Connected3270 => "4A",
            SessionState::Connecting | SessionState::Negotiating => "4B",
            SessionState::Disconnected | SessionState::Error(_) => "4-",
        }
    }

    /// Formats 0-based `(cursor_row, cursor_col)` into the standard 1-based `RRR/CCC` string
    /// (e.g., `(0, 0)` -> `"001/001"`, `(23, 79)` -> `"024/080"`).
    #[must_use]
    pub fn cursor_rc_text(&self) -> String {
        format_cursor_rc(self.cursor_row, self.cursor_col)
    }

    /// Returns the transport security badge text (`"TLS 🔒"`, `"TCP"`, or `"OFFLINE"`).
    #[must_use]
    pub const fn security_badge(&self) -> &'static str {
        match self.session_state {
            SessionState::Connecting | SessionState::Negotiating | SessionState::Connected3270 => {
                if self.is_tls {
                    "TLS 🔒"
                } else {
                    "TCP"
                }
            }
            SessionState::Disconnected | SessionState::Error(_) => "OFFLINE",
        }
    }

    /// Returns the protocol & LU badge (e.g. `"TN3270E [LU01]"` or `"TN3270"`).
    #[must_use]
    pub fn protocol_badge(&self) -> String {
        if !matches!(self.session_state, SessionState::Connected3270) {
            return match &self.session_state {
                SessionState::Connecting => "CONNECTING...".to_string(),
                SessionState::Negotiating => "NEGOTIATING...".to_string(),
                SessionState::Disconnected => "DISCONNECTED".to_string(),
                SessionState::Error(err) => format!("ERR: {err}"),
                SessionState::Connected3270 => String::new(),
            };
        }
        let proto = if self.is_tn3270e { "TN3270E" } else { "TN3270" };
        match &self.assigned_lu {
            Some(lu) if !lu.is_empty() => format!("{proto} [{lu}]"),
            _ => proto.to_string(),
        }
    }

    /// Returns the OIA keyboard status text (`"READY"` when unlocked, or `X SYSTEM`, `X PROTECTED`, etc.).
    #[must_use]
    pub fn keyboard_badge(&self) -> &'static str {
        let ind = self.keyboard_state.oia_indicator();
        if ind.is_empty() {
            "READY"
        } else {
            ind
        }
    }

    /// Returns the color associated with the current keyboard lock state.
    #[must_use]
    pub const fn keyboard_badge_color(&self) -> Color32 {
        match self.keyboard_state {
            KeyboardState::Unlocked => Color32::from_rgb(0x2E, 0xEB, 0x5A),
            KeyboardState::NotConnected => Color32::from_rgb(0x9A, 0x9A, 0x9A),
            // Waiting for the host.
            KeyboardState::TimeWait
            | KeyboardState::SystemLock
            | KeyboardState::AwaitingFirst
            | KeyboardState::Inhibit => Color32::from_rgb(0xFF, 0xEA, 0x55),
            // Operator errors and unavailable functions.
            KeyboardState::Protected
            | KeyboardState::Numeric
            | KeyboardState::Overflow
            | KeyboardState::NotAvailable => Color32::from_rgb(0xFF, 0x55, 0x55),
        }
    }

    /// Returns short label for the configured terminal model (`"M2"`, `"M3"`, `"M4"`, `"M5"`, or `"DYN(RxC)"`).
    #[must_use]
    pub fn model_badge(&self) -> String {
        match self.terminal_model {
            ProfileTerminalModel::Model2 => "M2".to_string(),
            ProfileTerminalModel::Model3 => "M3".to_string(),
            ProfileTerminalModel::Model4 => "M4".to_string(),
            ProfileTerminalModel::Model5 => "M5".to_string(),
            ProfileTerminalModel::Dynamic { rows, cols } => format!("DYN({rows}×{cols})"),
        }
    }

    /// Returns screen geometry & formatting indicator (e.g., `"M4 43×80 FMT CP037"`).
    #[must_use]
    pub fn geometry_badge(&self) -> String {
        let fmt_tag = if self.is_formatted { "FMT" } else { "UNFMT" };
        let cp = self.codepage.to_ascii_uppercase();
        format!(
            "{} {}×{} {} {}",
            self.model_badge(),
            self.rows,
            self.cols,
            fmt_tag,
            cp
        )
    }

    /// Formats a complete single-line plain-text summary of the OIA status line (useful for logs/tests).
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "{} | {} | {} | {} | {} | {}",
            self.connection_code(),
            self.security_badge(),
            self.protocol_badge(),
            self.keyboard_badge(),
            self.geometry_badge(),
            self.cursor_rc_text()
        )
    }
}

/// Formats 0-based `(row, col)` into 1-based `RRR/CCC` OIA coordinates.
#[must_use]
pub fn format_cursor_rc(row: u16, col: u16) -> String {
    let r1 = row.saturating_add(1);
    let c1 = col.saturating_add(1);
    format!("{r1:03}/{c1:03}")
}

/// Renders the Operator Information Area (OIA) bottom status bar inside an `egui::Ui`.
pub fn render_oia_bar(ui: &mut Ui, oia: &OiaStatusModel) {
    ui.horizontal(|ui| {
        // 1. 4A / 4B / 4- indicator
        let conn_color = match oia.session_state {
            SessionState::Connected3270 => Color32::from_rgb(0x00, 0xE5, 0xFF),
            SessionState::Connecting | SessionState::Negotiating => {
                Color32::from_rgb(0xFF, 0xEA, 0x55)
            }
            SessionState::Disconnected => Color32::from_rgb(0x88, 0x92, 0xA0),
            SessionState::Error(_) => Color32::from_rgb(0xFF, 0x55, 0x55),
        };
        ui.label(
            RichText::new(format!(" {} ", oia.connection_code()))
                .monospace()
                .strong()
                .color(conn_color),
        );
        ui.separator();

        // 2. TLS / TCP badge
        let sec_color = if oia.is_tls && matches!(oia.session_state, SessionState::Connected3270) {
            Color32::from_rgb(0x2E, 0xEB, 0x5A)
        } else if matches!(oia.session_state, SessionState::Connected3270) {
            Color32::from_rgb(0xFF, 0xB8, 0x1C)
        } else {
            Color32::from_rgb(0x88, 0x92, 0xA0)
        };
        ui.label(
            RichText::new(oia.security_badge())
                .monospace()
                .strong()
                .color(sec_color),
        );
        ui.separator();

        // 3. Protocol & LU
        ui.label(
            RichText::new(oia.protocol_badge())
                .monospace()
                .color(Color32::from_rgb(0xD8, 0xDE, 0xE9)),
        );
        ui.separator();

        // 4. Keyboard Lock / Error Indicator (X SYSTEM, X PROTECTED, READY)
        ui.label(
            RichText::new(format!(" {} ", oia.keyboard_badge()))
                .monospace()
                .strong()
                .color(oia.keyboard_badge_color()),
        );

        if oia.insert_mode {
            ui.separator();
            ui.label(
                RichText::new(" INS ")
                    .monospace()
                    .strong()
                    .color(Color32::from_rgb(0xD8, 0xDE, 0xE9)),
            );
        }

        if oia.alarm_active {
            ui.separator();
            ui.label(
                RichText::new("🔔 ALARM")
                    .monospace()
                    .strong()
                    .color(Color32::from_rgb(0xFF, 0x4D, 0x4D)),
            );
        }

        // Right-aligned geometry and RRR/CCC cursor position
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(format!(" {} ", oia.cursor_rc_text()))
                    .monospace()
                    .strong()
                    .color(Color32::from_rgb(0x00, 0xE5, 0xFF)),
            );
            ui.separator();
            ui.label(
                RichText::new(oia.geometry_badge())
                    .monospace()
                    .color(Color32::from_rgb(0xA4, 0xB0, 0xBE)),
            );
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_cursor_rc_1_based() {
        assert_eq!(format_cursor_rc(0, 0), "001/001");
        assert_eq!(format_cursor_rc(23, 79), "024/080");
        assert_eq!(format_cursor_rc(42, 131), "043/132");
    }

    #[test]
    fn test_oia_badges_and_states() {
        let mut oia = OiaStatusModel::default();
        assert_eq!(oia.connection_code(), "4-");
        assert_eq!(oia.security_badge(), "OFFLINE");
        assert_eq!(oia.keyboard_badge(), "READY");
        assert_eq!(oia.cursor_rc_text(), "001/001");

        let status = SessionStatus {
            state: SessionState::Connected3270,
            keyboard_state: KeyboardState::Protected,
            cursor_row: 5,
            cursor_col: 19,
            is_formatted: true,
            terminal_model: ProfileTerminalModel::Model4,
            assigned_lu: Some("TCP00042".to_string()),
            is_tn3270e: true,
            is_tls: true,
        };
        oia.apply_session_status(&status, 43, 80);

        assert_eq!(oia.connection_code(), "4A");
        assert_eq!(oia.security_badge(), "TLS 🔒");
        assert_eq!(oia.protocol_badge(), "TN3270E [TCP00042]");
        assert_eq!(oia.keyboard_badge(), "X PROTECTED");
        assert_eq!(oia.cursor_rc_text(), "006/020");
        assert!(oia.geometry_badge().contains("43×80 FMT"));
    }
}
