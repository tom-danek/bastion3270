//! Every character the desktop client puts on screen must exist in its fonts.
//!
//! The client uses egui's bundled fonts on every platform (no system fonts), so a symbol
//! outside them is drawn as an empty box ("tofu") on Windows, macOS and Linux alike. This test
//! reads the client's sources, collects every non-ASCII character of every string literal
//! (button labels, status badges, messages) and checks it against the fonts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;

use egui::{FontFamily, FontId};

/// The client's sources; a new module with user-visible text belongs here.
const SOURCES: &[(&str, &str)] = &[
    ("app.rs", include_str!("../src/app.rs")),
    ("bridge.rs", include_str!("../src/bridge.rs")),
    ("canvas.rs", include_str!("../src/canvas.rs")),
    ("keymap.rs", include_str!("../src/keymap.rs")),
    ("main.rs", include_str!("../src/main.rs")),
    ("message.rs", include_str!("../src/message.rs")),
    ("oia.rs", include_str!("../src/oia.rs")),
    (
        "profile_manager.rs",
        include_str!("../src/profile_manager.rs"),
    ),
    ("profiles.rs", include_str!("../src/profiles.rs")),
    ("selection.rs", include_str!("../src/selection.rs")),
    ("storage.rs", include_str!("../src/storage.rs")),
    ("theme.rs", include_str!("../src/theme.rs")),
];

/// Non-ASCII characters inside string literals of `source` (comments are skipped).
fn literal_chars(source: &str) -> BTreeSet<char> {
    let mut found = BTreeSet::new();
    let mut chars = source.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            match c {
                '\\' => {
                    chars.next();
                }
                '"' => in_string = false,
                c if !c.is_ascii() => {
                    found.insert(c);
                }
                _ => {}
            }
        } else if c == '/' && chars.peek() == Some(&'/') {
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
        } else if c == '"' {
            in_string = true;
        }
    }
    found
}

#[test]
fn test_every_character_in_the_client_texts_has_a_glyph() {
    let ctx = egui::Context::default();
    // One pass loads the fonts; its texture upload is not needed without a renderer.
    let mut output = ctx.run_ui(egui::RawInput::default(), |_| {});
    output.textures_delta.clear();
    let mut missing = Vec::new();
    for (file, source) in SOURCES {
        for c in literal_chars(source) {
            for family in [FontFamily::Proportional, FontFamily::Monospace] {
                let font = FontId::new(14.0, family.clone());
                if !ctx.fonts_mut(|f| f.has_glyph(&font, c)) {
                    missing.push(format!("{file}: {c:?} (U+{:04X}) in {family:?}", c as u32));
                }
            }
        }
    }
    assert!(missing.is_empty(), "drawn as empty boxes: {missing:#?}");
}

#[test]
fn test_literal_chars_reads_strings_but_not_comments() {
    let source = "// → arrow\nlet a = \"⏹ Stop \\\" ✓\"; /* x */ let b = 'é';";
    assert_eq!(literal_chars(source), BTreeSet::from(['⏹', '✓']));
}
