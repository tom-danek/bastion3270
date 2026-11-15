//! The application icon: the same drawing as the web client's (source
//! `crates/bastion3270-server/web/icon.svg`), so both clients look like one product.
//!
//! The icon is set at runtime on every window: Windows shows it in the title bar and the
//! taskbar, macOS in the Dock, Linux under X11 in the title bar and the task switcher. Wayland
//! has no window icon: a compositor takes it only from an installed `.desktop` file named after
//! [`APP_ID`], which the plain archive does not install.

use std::sync::Arc;

use egui::IconData;

/// The application's id: the Wayland `app_id` and the X11 `WM_CLASS` (the desktop groups the
/// client's windows by it).
pub const APP_ID: &str = "bastion3270";

/// The icon as PNG, 512 × 512 pixels.
const ICON_PNG: &[u8] = include_bytes!("../../bastion3270-server/web/icon-512.png");

/// The decoded icon, or `None` (with a warning) if it cannot be decoded.
#[must_use]
pub fn app_icon() -> Option<Arc<IconData>> {
    match eframe::icon_data::from_png_bytes(ICON_PNG) {
        Ok(icon) => Some(Arc::new(icon)),
        Err(err) => {
            tracing::warn!(%err, "the application icon cannot be decoded");
            None
        }
    }
}
