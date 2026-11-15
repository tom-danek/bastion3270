//! # bastion3270-gui
//!
//! Native cross-platform (Windows, Linux, macOS) IBM 3278/3279 TN3270/TN3270E graphical client
//! built with `egui` and `eframe`.
//!
//! ## Modules
//! - [`theme`]: 16-color IBM 3279 palette, 3278 Green / Amber phosphor modes, extended attributes, and zoom.
//! - [`oia`]: Operator Information Area (OIA) bottom status bar model and `RRR/CCC` coordinate formatter.
//! - [`keymap`]: Hardware keyboard interception (`PF1`–`PF24`, `PA1`–`PA3`, `Clear`, `Reset`, `Enter`, navigation).
//! - [`message`]: Message line above the OIA bar (info, warning, error).
//! - [`canvas`]: Monospace terminal grid geometry, cell renderer, crosshair cursor, and mouse click hit-testing.
//! - [`profiles`]: saved profiles (`SavedProfile`, `ProfileCatalog`) with TOML persistence.
//! - [`profile_manager`]: the profile manager window and its working copy (Save / Cancel).
//! - [`storage`]: Per-user file locations (profiles, log) and the automatically saved profile catalog.
//! - [`bridge`]: Non-blocking asynchronous Tokio runtime bridge for [`bastion3270_net::SessionCoordinator`].
//! - [`icon`]: the application icon (the same as the web client's) and the application id.
//! - [`app`]: Top-level [`Bastion3270GuiApp`] implementing [`eframe::App`].

#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod app;
pub mod bridge;
pub mod canvas;
pub mod icon;
pub mod keymap;
pub mod message;
pub mod oia;
pub mod profile_manager;
pub mod profiles;
pub mod selection;
pub mod storage;
pub mod theme;

pub use app::{Bastion3270GuiApp, UntrustedCertificate};
pub use bridge::GuiSessionBridge;
pub use canvas::{render_terminal_canvas, CanvasInteraction, GridMetrics};
pub use keymap::{translate_key_event, translate_text_input, GuiKeyAction, KeyboardPreset};
pub use oia::{format_cursor_rc, render_oia_bar, OiaStatusModel};
pub use profile_manager::{ManagerAction, ProfileManager};
pub use profiles::{ProfileCatalog, SavedProfile};
pub use theme::{CellVisualStyle, CursorStyle, TerminalColorScheme, TerminalTheme};
