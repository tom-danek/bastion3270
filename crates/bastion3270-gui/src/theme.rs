//! IBM 3278/3279 Terminal Color Schemes, Extended Attribute Styling, and Zoom Metrics.

use bastion3270_core::{Color3270, Highlight3270, SafeCell};
use egui::Color32;
use serde::{Deserialize, Serialize};

/// Minimum allowed terminal font size in points.
pub const MIN_FONT_SIZE_PT: f32 = 10.0;
/// Default terminal font size in points.
pub const DEFAULT_FONT_SIZE_PT: f32 = 16.0;
/// Maximum allowed terminal font size in points.
pub const MAX_FONT_SIZE_PT: f32 = 36.0;
/// Font zoom step in points.
pub const FONT_ZOOM_STEP_PT: f32 = 2.0;

/// Visual color scheme of the 3270 CRT display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TerminalColorScheme {
    /// Authentic 16-color IBM 3279 Color Display Station palette.
    #[default]
    Classic3279,
    /// Light background; the colours stay distinguishable, black and white text turn dark
    /// (the web client's `light` theme).
    Light,
    /// Monochrome IBM 3278 P1 green phosphor CRT.
    GreenPhosphor3278,
    /// Monochrome amber phosphor CRT.
    AmberPhosphor,
}

impl TerminalColorScheme {
    /// Returns all available color schemes for UI combo-boxes.
    pub const ALL: [Self; 4] = [
        Self::Classic3279,
        Self::Light,
        Self::GreenPhosphor3278,
        Self::AmberPhosphor,
    ];

    /// Human-readable label for the UI.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Classic3279 => "Classic (dark)",
            Self::Light => "Light",
            Self::GreenPhosphor3278 => "Green screen",
            Self::AmberPhosphor => "Amber screen",
        }
    }
}

/// Visual shape of the 3270 operator cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CursorStyle {
    /// Classic filled translucent/inverted block cursor.
    #[default]
    Block,
    /// Bottom underscore cursor (`_`).
    Underscore,
    /// Left vertical bar cursor (`|`).
    VerticalBar,
}

impl CursorStyle {
    /// All cursor styles for UI combo-boxes.
    pub const ALL: [Self; 3] = [Self::Block, Self::Underscore, Self::VerticalBar];

    /// Human-readable label for the UI.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Block => "Block",
            Self::Underscore => "Underscore",
            Self::VerticalBar => "Vertical Bar",
        }
    }
}

/// Resolved visual styling for a single rendered terminal cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellVisualStyle {
    /// Resolved foreground glyph color.
    pub fg: Color32,
    /// Resolved cell background fill color.
    pub bg: Color32,
    /// Whether an underline stroke should be drawn beneath the cell.
    pub underline: bool,
    /// Whether this cell is currently in the hidden phase of a blink cycle.
    pub blink_hidden: bool,
}

/// Complete visual configuration for the terminal canvas and OIA bar.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalTheme {
    /// Active CRT color palette.
    pub color_scheme: TerminalColorScheme,
    /// Active cursor shape.
    pub cursor_style: CursorStyle,
    /// Whether to draw full-screen horizontal and vertical crosshair lines at the cursor.
    #[serde(default)]
    pub crosshair_enabled: bool,
    /// Whether to visually highlight unprotected (editable) input fields with a subtle
    /// background tint and baseline guide so blank input fields are clearly visible.
    #[serde(default)]
    pub highlight_input_fields: bool,
    /// Monospace font size in points (`10.0..=36.0`).
    pub font_size_pt: f32,
}

impl Default for TerminalTheme {
    fn default() -> Self {
        Self {
            color_scheme: TerminalColorScheme::Classic3279,
            cursor_style: CursorStyle::Block,
            crosshair_enabled: false,
            highlight_input_fields: false,
            font_size_pt: DEFAULT_FONT_SIZE_PT,
        }
    }
}

impl TerminalTheme {
    /// Increases the terminal font size by [`FONT_ZOOM_STEP_PT`], clamped to [`MAX_FONT_SIZE_PT`].
    pub fn zoom_in(&mut self) {
        self.font_size_pt = (self.font_size_pt + FONT_ZOOM_STEP_PT).min(MAX_FONT_SIZE_PT);
    }

    /// Decreases the terminal font size by [`FONT_ZOOM_STEP_PT`], clamped to [`MIN_FONT_SIZE_PT`].
    pub fn zoom_out(&mut self) {
        self.font_size_pt = (self.font_size_pt - FONT_ZOOM_STEP_PT).max(MIN_FONT_SIZE_PT);
    }

    /// Resets the terminal font size to [`DEFAULT_FONT_SIZE_PT`].
    pub fn reset_zoom(&mut self) {
        self.font_size_pt = DEFAULT_FONT_SIZE_PT;
    }

    /// Returns the current zoom percentage relative to [`DEFAULT_FONT_SIZE_PT`].
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn zoom_percent(&self) -> u16 {
        ((self.font_size_pt / DEFAULT_FONT_SIZE_PT) * 100.0).round() as u16
    }

    /// Base CRT screen background color.
    #[must_use]
    pub const fn screen_bg(&self) -> Color32 {
        match self.color_scheme {
            TerminalColorScheme::Classic3279 => Color32::from_rgb(0x0A, 0x0E, 0x14),
            TerminalColorScheme::Light => Color32::from_rgb(0xFB, 0xFB, 0xF7),
            TerminalColorScheme::GreenPhosphor3278 => Color32::from_rgb(0x05, 0x12, 0x05),
            TerminalColorScheme::AmberPhosphor => Color32::from_rgb(0x14, 0x0C, 0x02),
        }
    }

    /// Primary cursor highlight color.
    #[must_use]
    pub const fn cursor_color(&self) -> Color32 {
        match self.color_scheme {
            TerminalColorScheme::Classic3279 => Color32::from_rgb(0x00, 0xE5, 0xFF),
            TerminalColorScheme::Light => Color32::from_rgb(0x00, 0x77, 0xAA),
            TerminalColorScheme::GreenPhosphor3278 => Color32::from_rgb(0x33, 0xFF, 0x33),
            TerminalColorScheme::AmberPhosphor => Color32::from_rgb(0xFF, 0xB8, 0x00),
        }
    }

    /// Subtle crosshair ruler stroke color.
    #[must_use]
    pub const fn crosshair_color(&self) -> Color32 {
        match self.color_scheme {
            TerminalColorScheme::Classic3279 => {
                Color32::from_rgba_premultiplied(0x00, 0x90, 0xB0, 0x70)
            }
            TerminalColorScheme::Light => Color32::from_rgba_premultiplied(0x00, 0x50, 0x70, 0x50),
            TerminalColorScheme::GreenPhosphor3278 => {
                Color32::from_rgba_premultiplied(0x20, 0x90, 0x20, 0x70)
            }
            TerminalColorScheme::AmberPhosphor => {
                Color32::from_rgba_premultiplied(0x95, 0x68, 0x00, 0x70)
            }
        }
    }

    /// Subtle background fill tint for unprotected (editable) input fields when
    /// [`Self::highlight_input_fields`] is enabled.
    #[must_use]
    pub const fn input_field_bg_tint(&self) -> Color32 {
        match self.color_scheme {
            TerminalColorScheme::Classic3279 => Color32::from_rgb(0x11, 0x22, 0x19),
            TerminalColorScheme::Light => Color32::from_rgb(0xE8, 0xF2, 0xEA),
            TerminalColorScheme::GreenPhosphor3278 => Color32::from_rgb(0x0D, 0x26, 0x0D),
            TerminalColorScheme::AmberPhosphor => Color32::from_rgb(0x28, 0x1A, 0x05),
        }
    }

    /// Subtle baseline underline color for unprotected (editable) input fields when
    /// [`Self::highlight_input_fields`] is enabled.
    #[must_use]
    pub const fn input_field_underline_color(&self) -> Color32 {
        match self.color_scheme {
            TerminalColorScheme::Classic3279 => {
                Color32::from_rgba_premultiplied(0x1E, 0x7A, 0x38, 0x80)
            }
            TerminalColorScheme::Light => Color32::from_rgba_premultiplied(0x17, 0x3E, 0x19, 0x80),
            TerminalColorScheme::GreenPhosphor3278 => {
                Color32::from_rgba_premultiplied(0x20, 0x80, 0x20, 0x80)
            }
            TerminalColorScheme::AmberPhosphor => {
                Color32::from_rgba_premultiplied(0x8A, 0x5A, 0x08, 0x80)
            }
        }
    }

    /// Maps an IBM [`Color3270`] value to an RGB [`Color32`] in the active scheme.
    #[must_use]
    pub const fn resolve_color3270(&self, color: Color3270, protected: bool) -> Color32 {
        match self.color_scheme {
            TerminalColorScheme::Classic3279 => match color {
                Color3270::Default => {
                    if protected {
                        Color32::from_rgb(0x5C, 0xB8, 0xFF) // Protected default: Cyan/Light Blue
                    } else {
                        Color32::from_rgb(0x2E, 0xEB, 0x5A) // Unprotected default: 3279 Green
                    }
                }
                Color3270::NeutralBlack | Color3270::Black => Color32::from_rgb(0x0A, 0x0E, 0x14),
                Color3270::Blue => Color32::from_rgb(0x42, 0x99, 0xFF),
                Color3270::Red => Color32::from_rgb(0xFF, 0x4D, 0x4D),
                Color3270::Pink => Color32::from_rgb(0xFF, 0x79, 0xC6),
                Color3270::Green => Color32::from_rgb(0x2E, 0xEB, 0x5A),
                Color3270::Turquoise => Color32::from_rgb(0x00, 0xE5, 0xFF),
                Color3270::Yellow => Color32::from_rgb(0xFF, 0xEA, 0x55),
                Color3270::NeutralWhite | Color3270::White => Color32::from_rgb(0xF8, 0xF8, 0xF2),
                Color3270::DeepBlue => Color32::from_rgb(0x1E, 0x5A, 0xD7),
                Color3270::Orange => Color32::from_rgb(0xFF, 0x9E, 0x3B),
                Color3270::Purple => Color32::from_rgb(0xBD, 0x93, 0xF9),
                Color3270::PaleGreen => Color32::from_rgb(0x8A, 0xFF, 0x80),
                Color3270::PaleTurquoise => Color32::from_rgb(0x8B, 0xE9, 0xFD),
                Color3270::Grey => Color32::from_rgb(0x94, 0x9C, 0xA8),
            },
            // The web client's `light` palette (screen.js).
            TerminalColorScheme::Light => match color {
                Color3270::Default => {
                    if protected {
                        Color32::from_rgb(0x1F, 0x5F, 0xBF)
                    } else {
                        Color32::from_rgb(0x2E, 0x7D, 0x32)
                    }
                }
                Color3270::NeutralBlack
                | Color3270::Black
                | Color3270::NeutralWhite
                | Color3270::White => Color32::from_rgb(0x11, 0x11, 0x11),
                Color3270::Blue => Color32::from_rgb(0x1F, 0x5F, 0xBF),
                Color3270::Red => Color32::from_rgb(0xC6, 0x28, 0x28),
                Color3270::Pink => Color32::from_rgb(0xAD, 0x14, 0x57),
                Color3270::Green => Color32::from_rgb(0x2E, 0x7D, 0x32),
                Color3270::Turquoise => Color32::from_rgb(0x00, 0x83, 0x8F),
                Color3270::Yellow => Color32::from_rgb(0x8A, 0x6D, 0x00),
                Color3270::DeepBlue => Color32::from_rgb(0x1A, 0x3F, 0x9E),
                Color3270::Orange => Color32::from_rgb(0xC2, 0x5A, 0x00),
                Color3270::Purple => Color32::from_rgb(0x6A, 0x1B, 0x9A),
                Color3270::PaleGreen => Color32::from_rgb(0x38, 0x8E, 0x3C),
                Color3270::PaleTurquoise => Color32::from_rgb(0x00, 0x69, 0x5C),
                Color3270::Grey => Color32::from_rgb(0x55, 0x55, 0x55),
            },
            TerminalColorScheme::GreenPhosphor3278 => match color {
                Color3270::NeutralBlack | Color3270::Black => Color32::from_rgb(0x05, 0x12, 0x05),
                Color3270::Red | Color3270::NeutralWhite | Color3270::White | Color3270::Yellow => {
                    // High-intensity phosphor
                    Color32::from_rgb(0xB8, 0xFF, 0xB8)
                }
                Color3270::Blue | Color3270::DeepBlue | Color3270::Grey => {
                    // Protected normal intensity phosphor
                    Color32::from_rgb(0x24, 0xC8, 0x24)
                }
                _ => {
                    if protected {
                        Color32::from_rgb(0x28, 0xD8, 0x28)
                    } else {
                        Color32::from_rgb(0x45, 0xFF, 0x45)
                    }
                }
            },
            TerminalColorScheme::AmberPhosphor => match color {
                Color3270::NeutralBlack | Color3270::Black => Color32::from_rgb(0x14, 0x0C, 0x02),
                Color3270::Red | Color3270::NeutralWhite | Color3270::White | Color3270::Yellow => {
                    // High-intensity amber
                    Color32::from_rgb(0xFF, 0xE2, 0x8A)
                }
                Color3270::Blue | Color3270::DeepBlue | Color3270::Grey => {
                    Color32::from_rgb(0xD4, 0x88, 0x00)
                }
                _ => {
                    if protected {
                        Color32::from_rgb(0xE0, 0x96, 0x00)
                    } else {
                        Color32::from_rgb(0xFF, 0xB8, 0x1C)
                    }
                }
            },
        }
    }

    /// Resolves foreground, background, underline, and blink state for a [`SafeCell`].
    #[must_use]
    pub const fn resolve_cell_style(
        &self,
        cell: &SafeCell,
        blink_phase_off: bool,
    ) -> CellVisualStyle {
        let glyph_rgb = self.resolve_color3270(cell.foreground, cell.protected);
        let fill_rgb = match cell.background {
            Color3270::Default | Color3270::NeutralBlack | Color3270::Black => self.screen_bg(),
            other => self.resolve_color3270(other, false),
        };

        let (fg, bg) = if cell.highlight.contains(Highlight3270::REVERSE_VIDEO) {
            (fill_rgb, glyph_rgb)
        } else {
            (glyph_rgb, fill_rgb)
        };

        let underline = cell.highlight.contains(Highlight3270::UNDERSCORE);
        let blink_hidden = cell.highlight.contains(Highlight3270::BLINK) && blink_phase_off;

        CellVisualStyle {
            fg,
            bg,
            underline,
            blink_hidden,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bastion3270_core::CharacterSet;

    #[test]
    fn test_zoom_clamping_and_reset() {
        let mut theme = TerminalTheme::default();
        assert_eq!(theme.zoom_percent(), 100);

        for _ in 0..30 {
            theme.zoom_in();
        }
        assert!((theme.font_size_pt - MAX_FONT_SIZE_PT).abs() < f32::EPSILON);

        for _ in 0..30 {
            theme.zoom_out();
        }
        assert!((theme.font_size_pt - MIN_FONT_SIZE_PT).abs() < f32::EPSILON);

        theme.reset_zoom();
        assert!((theme.font_size_pt - DEFAULT_FONT_SIZE_PT).abs() < f32::EPSILON);
        assert_eq!(theme.zoom_percent(), 100);
    }

    #[test]
    fn test_all_color3270_variants_resolve_distinctly_from_bg() {
        let colors = [
            Color3270::Default,
            Color3270::Blue,
            Color3270::Red,
            Color3270::Pink,
            Color3270::Green,
            Color3270::Turquoise,
            Color3270::Yellow,
            Color3270::NeutralWhite,
            Color3270::DeepBlue,
            Color3270::Orange,
            Color3270::Purple,
            Color3270::PaleGreen,
            Color3270::PaleTurquoise,
            Color3270::Grey,
            Color3270::White,
        ];

        for scheme in TerminalColorScheme::ALL {
            let theme = TerminalTheme {
                color_scheme: scheme,
                ..TerminalTheme::default()
            };
            let bg = theme.screen_bg();
            for &c in &colors {
                let resolved = theme.resolve_color3270(c, false);
                assert_ne!(
                    resolved, bg,
                    "foreground color {c:?} in {scheme:?} must contrast with bg"
                );
            }
        }
    }

    #[test]
    fn test_reverse_video_and_underscore_and_blink_resolution() {
        let theme = TerminalTheme::default();
        let cell_rev = SafeCell {
            ch: 'A',
            foreground: Color3270::Yellow,
            background: Color3270::Default,
            highlight: Highlight3270::REVERSE_VIDEO,
            charset: CharacterSet::Base,
            protected: false,
            is_field_marker: false,
        };
        let style_rev = theme.resolve_cell_style(&cell_rev, false);
        assert_eq!(style_rev.fg, theme.screen_bg());
        assert_eq!(
            style_rev.bg,
            theme.resolve_color3270(Color3270::Yellow, false)
        );
        assert!(!style_rev.underline);

        let cell_und = SafeCell {
            highlight: Highlight3270::UNDERSCORE,
            ..cell_rev
        };
        let style_und = theme.resolve_cell_style(&cell_und, false);
        assert!(style_und.underline);

        let cell_blink = SafeCell {
            highlight: Highlight3270::BLINK,
            ..cell_rev
        };
        assert!(!theme.resolve_cell_style(&cell_blink, false).blink_hidden);
        assert!(theme.resolve_cell_style(&cell_blink, true).blink_hidden);
    }
}
