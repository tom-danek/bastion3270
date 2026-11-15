//! The application icon is usable on every platform's taskbar and Dock.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use bastion3270_gui::icon::app_icon;

/// Square, large enough for a Dock or a high-DPI taskbar, and with transparent corners (the
/// rounded square, not a black box).
#[test]
fn test_the_application_icon_is_a_square_rgba_image_with_transparent_corners() {
    let icon = app_icon().expect("the icon decodes");
    assert_eq!(icon.width, icon.height);
    assert!(icon.width >= 256, "{} px", icon.width);
    assert_eq!(icon.rgba.len(), (icon.width * icon.height * 4) as usize);
    let alpha_at = |x: u32, y: u32| icon.rgba[((y * icon.width + x) * 4 + 3) as usize];
    assert_eq!(alpha_at(0, 0), 0, "top-left corner is transparent");
    assert_eq!(
        alpha_at(icon.width / 2, icon.height / 2),
        255,
        "the middle is opaque"
    );
}
