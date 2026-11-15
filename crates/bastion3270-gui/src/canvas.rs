//! IBM 3270 Terminal Grid Geometry, Hit-Testing, Crosshair Ruler, and `egui` Canvas Renderer.

use crate::selection::Selection;
use bastion3270_core::{ActionKey, SafeScreenView};
use egui::{Align2, Color32, FontFamily, FontId, Pos2, Rect, Sense, Stroke, StrokeKind, Ui, Vec2};

use crate::theme::{CursorStyle, TerminalTheme};

/// Monospace character aspect ratio (`width / height`) fallback when font metrics are unavailable.
pub const DEFAULT_CHAR_ASPECT_RATIO: f32 = 0.6;
/// Line height multiplier relative to font size in points.
pub const LINE_HEIGHT_MULTIPLIER: f32 = 1.25;

/// Deterministic pixel geometry of the 3270 character grid.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GridMetrics {
    /// Top-left pixel origin X of row 0, col 0.
    pub origin_x: f32,
    /// Top-left pixel origin Y of row 0, col 0.
    pub origin_y: f32,
    /// Width of a single character cell in pixels.
    pub cell_width: f32,
    /// Height of a single character cell in pixels.
    pub cell_height: f32,
    /// Number of terminal rows.
    pub rows: u16,
    /// Number of terminal columns.
    pub cols: u16,
}

impl GridMetrics {
    /// Computes deterministic [`GridMetrics`] from an origin, cell dimensions, and grid size.
    #[must_use]
    pub const fn new(
        origin_x: f32,
        origin_y: f32,
        cell_width: f32,
        cell_height: f32,
        rows: u16,
        cols: u16,
    ) -> Self {
        Self {
            origin_x,
            origin_y,
            cell_width,
            cell_height,
            rows,
            cols,
        }
    }

    /// Computes [`GridMetrics`] directly from font size in points (`font_size_pt`).
    #[must_use]
    pub fn from_font_size(
        origin_x: f32,
        origin_y: f32,
        font_size_pt: f32,
        rows: u16,
        cols: u16,
    ) -> Self {
        let cell_width = (font_size_pt * DEFAULT_CHAR_ASPECT_RATIO).round().max(6.0);
        let cell_height = (font_size_pt * LINE_HEIGHT_MULTIPLIER).round().max(12.0);
        Self::new(origin_x, origin_y, cell_width, cell_height, rows, cols)
    }

    /// Total width of the character grid in pixels.
    #[must_use]
    pub fn total_width(&self) -> f32 {
        self.cell_width * f32::from(self.cols)
    }

    /// Total height of the character grid in pixels.
    #[must_use]
    pub fn total_height(&self) -> f32 {
        self.cell_height * f32::from(self.rows)
    }

    /// Bounding [`Rect`] of the entire terminal grid.
    #[must_use]
    pub fn grid_rect(&self) -> Rect {
        Rect::from_min_size(
            Pos2::new(self.origin_x, self.origin_y),
            Vec2::new(self.total_width(), self.total_height()),
        )
    }

    /// Bounding [`Rect`] of a specific 0-based `(row, col)` cell.
    #[must_use]
    pub fn cell_rect(&self, row: u16, col: u16) -> Rect {
        let x = self.origin_x + f32::from(col) * self.cell_width;
        let y = self.origin_y + f32::from(row) * self.cell_height;
        Rect::from_min_size(
            Pos2::new(x, y),
            Vec2::new(self.cell_width, self.cell_height),
        )
    }

    /// Converts a pixel position `(px, py)` into a 0-based `(row, col)` cell coordinate,
    /// or returns `None` if the point lies outside the terminal grid.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn hit_test(&self, px: f32, py: f32) -> Option<(u16, u16)> {
        if self.rows == 0 || self.cols == 0 || self.cell_width <= 0.0 || self.cell_height <= 0.0 {
            return None;
        }
        let rel_x = px - self.origin_x;
        let rel_y = py - self.origin_y;
        if rel_x < 0.0 || rel_y < 0.0 {
            return None;
        }
        let col_f = (rel_x / self.cell_width).floor();
        let row_f = (rel_y / self.cell_height).floor();
        if col_f >= f32::from(self.cols) || row_f >= f32::from(self.rows) {
            return None;
        }
        Some((row_f as u16, col_f as u16))
    }
}

/// Output returned after rendering the terminal canvas for one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanvasInteraction {
    /// If the user clicked inside the terminal grid, contains [`ActionKey::MoveCursor`]
    /// for the clicked `(row, col)` cell.
    pub clicked_cursor_move: Option<ActionKey>,
    /// Whether the terminal canvas currently holds keyboard focus.
    pub has_focus: bool,
    /// The cell where a mouse drag (selection) started this frame.
    pub drag_started_at: Option<(u16, u16)>,
    /// The cell under the pointer while a drag is in progress.
    pub dragged_to: Option<(u16, u16)>,
}

/// Persistent `egui::Id` of the 3270 terminal canvas widget so it can hold permanent
/// keyboard focus and lock `Tab` / `Shift+Tab` inside the terminal.
pub const TERMINAL_CANVAS_ID: &str = "bastion3270_terminal_canvas";

/// Renders the Zero-Trust [`SafeScreenView`] onto an `egui::Ui` canvas.
///
/// Supports:
/// - All IBM 3279 16-color attributes and monochrome 3278 Green / Amber phosphor modes.
/// - Extended attributes (`ReverseVideo`, `Underscore`, `Blink`).
/// - Optional full-screen horizontal & vertical **Crosshair cursor** (`x3270` style).
/// - Active operator cursor (`Block`, `Underscore`, `VerticalBar`).
/// - Mouse click-to-position-cursor (`ActionKey::MoveCursor { row, col }`).
/// - Mouse drag to select a rectangle (`selection` is highlighted).
#[allow(clippy::too_many_lines)]
pub fn render_terminal_canvas(
    ui: &mut Ui,
    screen: &SafeScreenView,
    theme: &TerminalTheme,
    blink_phase_off: bool,
    selection: Option<Selection>,
) -> CanvasInteraction {
    let font_id = FontId::new(theme.font_size_pt, FontFamily::Monospace);

    // Measure actual monospace glyph advance from egui font definitions when available
    let glyph_width = ui
        .fonts_mut(|f| f.glyph_width(&font_id, 'M'))
        .max(theme.font_size_pt * DEFAULT_CHAR_ASPECT_RATIO);
    let cell_width = glyph_width.ceil().max(6.0);
    let cell_height = (theme.font_size_pt * LINE_HEIGHT_MULTIPLIER)
        .ceil()
        .max(12.0);

    let rows = screen.rows().max(1);
    let cols = screen.cols().max(1);
    let desired_size = Vec2::new(
        cell_width * f32::from(cols) + 8.0,
        cell_height * f32::from(rows) + 8.0,
    );

    let canvas_id = egui::Id::unique(TERMINAL_CANVAS_ID);
    let (_, rect) = ui.allocate_space(desired_size);
    let response = ui.interact(rect, canvas_id, Sense::click_and_drag());
    let painter = ui.painter_at(rect);

    // When the canvas is clicked, focus the terminal canvas so any open text edit
    // in the Profile Manager relinquishes keyboard focus.
    if response.clicked() {
        ui.ctx().memory_mut(|m| m.request_focus(canvas_id));
    }
    let screen_bg = theme.screen_bg();
    painter.rect_filled(rect, 2.0, screen_bg);

    // Center the terminal grid inside the allocated canvas rect
    let grid_w = cell_width * f32::from(cols);
    let grid_h = cell_height * f32::from(rows);
    let origin_x = (rect.min.x + ((rect.width() - grid_w) * 0.5).max(4.0)).floor();
    let origin_y = (rect.min.y + ((rect.height() - grid_h) * 0.5).max(4.0)).floor();

    let metrics = GridMetrics::new(origin_x, origin_y, cell_width, cell_height, rows, cols);
    let grid_rect = metrics.grid_rect();

    // Subtle bezel border around the active 3270 display area
    painter.rect_stroke(
        grid_rect.expand(2.0),
        2.0,
        Stroke::new(1.0_f32, Color32::from_rgb(0x28, 0x34, 0x44)),
        StrokeKind::Outside,
    );

    // 1. Render cells (background fill, character glyph, and underline)
    let is_formatted = screen.is_formatted();
    let input_bg_tint = theme.input_field_bg_tint();
    let input_underline_color = theme.input_field_underline_color();
    let mut char_buf = [0u8; 4];
    for row in 0..rows {
        for col in 0..cols {
            let Some(cell) = screen.cell_at(row, col) else {
                continue;
            };
            let style = theme.resolve_cell_style(cell, blink_phase_off);
            let cell_rect = metrics.cell_rect(row, col);

            let is_editable_cell = is_formatted && !cell.protected && !cell.is_field_marker;

            if style.bg != screen_bg {
                painter.rect_filled(cell_rect, 0.0, style.bg);
            } else if theme.highlight_input_fields && is_editable_cell {
                painter.rect_filled(cell_rect, 0.0, input_bg_tint);
            }

            if !cell.is_blank() && !cell.is_field_marker && !style.blink_hidden {
                let s = cell.ch.encode_utf8(&mut char_buf);
                painter.text(
                    cell_rect.center(),
                    Align2::CENTER_CENTER,
                    s,
                    font_id.clone(),
                    style.fg,
                );
            }

            if style.underline && !cell.is_field_marker {
                let y = cell_rect.max.y - 1.5;
                painter.line_segment(
                    [Pos2::new(cell_rect.min.x, y), Pos2::new(cell_rect.max.x, y)],
                    Stroke::new(1.2_f32, style.fg),
                );
            } else if theme.highlight_input_fields && is_editable_cell {
                let y = cell_rect.max.y - 1.0;
                painter.line_segment(
                    [Pos2::new(cell_rect.min.x, y), Pos2::new(cell_rect.max.x, y)],
                    Stroke::new(1.0_f32, input_underline_color),
                );
            }
        }
    }

    // 2. Render optional Crosshair Cursor (full-width horizontal + full-height vertical ruler lines)
    let cursor_row = screen.cursor_row().min(rows.saturating_sub(1));
    let cursor_col = screen.cursor_col().min(cols.saturating_sub(1));
    let cursor_rect = metrics.cell_rect(cursor_row, cursor_col);

    if theme.crosshair_enabled {
        let ch_color = theme.crosshair_color();
        let stroke = Stroke::new(1.0_f32, ch_color);

        // Horizontal line along the bottom of the cursor row
        let hy = cursor_rect.max.y - 0.5;
        painter.line_segment(
            [
                Pos2::new(grid_rect.min.x, hy),
                Pos2::new(grid_rect.max.x, hy),
            ],
            stroke,
        );

        // Vertical line along the left edge of the cursor column
        let vx = cursor_rect.min.x + 0.5;
        painter.line_segment(
            [
                Pos2::new(vx, grid_rect.min.y),
                Pos2::new(vx, grid_rect.max.y),
            ],
            stroke,
        );
    }

    // 3. Render active operator cursor at (cursor_row, cursor_col)
    let cur_color = theme.cursor_color();
    match theme.cursor_style {
        CursorStyle::Block => {
            let fill =
                Color32::from_rgba_unmultiplied(cur_color.r(), cur_color.g(), cur_color.b(), 90);
            painter.rect_filled(cursor_rect, 1.0, fill);
            painter.rect_stroke(
                cursor_rect,
                1.0,
                Stroke::new(1.5_f32, cur_color),
                StrokeKind::Inside,
            );
        }
        CursorStyle::Underscore => {
            let under_rect = Rect::from_min_max(
                Pos2::new(
                    cursor_rect.min.x,
                    (cursor_rect.max.y - 3.0).max(cursor_rect.min.y),
                ),
                cursor_rect.max,
            );
            painter.rect_filled(under_rect, 0.5, cur_color);
        }
        CursorStyle::VerticalBar => {
            let bar_rect = Rect::from_min_max(
                cursor_rect.min,
                Pos2::new(
                    (cursor_rect.min.x + 2.5).min(cursor_rect.max.x),
                    cursor_rect.max.y,
                ),
            );
            painter.rect_filled(bar_rect, 0.5, cur_color);
        }
    }

    // 4. Selection highlight (over the text, translucent, like a text editor)
    if let Some(sel) = selection {
        let tint = Color32::from_rgba_unmultiplied(0x5A, 0x8C, 0xFF, 0x60);
        let rect = metrics.cell_rect(sel.r0, sel.c0).union(metrics.cell_rect(
            sel.r1.min(rows.saturating_sub(1)),
            sel.c1.min(cols.saturating_sub(1)),
        ));
        painter.rect_filled(rect, 0.0, tint);
    }

    // 5. Mouse: a click positions the cursor, a drag selects a rectangle
    let cell_under_pointer = response
        .interact_pointer_pos()
        .and_then(|pos| metrics.hit_test(pos.x, pos.y));
    let clicked_cursor_move = cell_under_pointer
        .filter(|_| response.clicked())
        .map(|(row, col)| ActionKey::MoveCursor { row, col });
    // The drag starts where the button went down, not where the pointer is when egui decides
    // that the movement is a drag.
    let drag_started_at = response
        .drag_started()
        .then(|| ui.input(|i| i.pointer.press_origin()))
        .flatten()
        .and_then(|pos| metrics.hit_test(pos.x, pos.y));
    let dragged_to = cell_under_pointer.filter(|_| response.dragged());
    if response.clicked() || response.drag_started() {
        tracing::debug!(
            target: "bastion3270_gui::canvas",
            pointer = ?response.interact_pointer_pos(),
            grid = ?metrics.grid_rect(),
            cell = ?cell_under_pointer,
            clicked = response.clicked(),
            drag = response.drag_started(),
            "mouse on the terminal"
        );
    }

    CanvasInteraction {
        clicked_cursor_move,
        has_focus: ui.ctx().memory(|m| m.has_focus(canvas_id)),
        drag_started_at,
        dragged_to,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grid_metrics_and_hit_testing() {
        let m = GridMetrics::new(10.0, 20.0, 10.0, 20.0, 24, 80);
        assert!((m.total_width() - 800.0).abs() < f32::EPSILON);
        assert!((m.total_height() - 480.0).abs() < f32::EPSILON);

        // Top-left cell (0, 0)
        assert_eq!(m.hit_test(10.0, 20.0), Some((0, 0)));
        assert_eq!(m.hit_test(19.9, 39.9), Some((0, 0)));

        // Cell (1, 2)
        assert_eq!(m.hit_test(35.0, 45.0), Some((1, 2)));

        // Bottom-right cell (23, 79)
        assert_eq!(m.hit_test(809.9, 499.9), Some((23, 79)));

        // Out-of-bounds clicks return None
        assert_eq!(m.hit_test(9.9, 20.0), None);
        assert_eq!(m.hit_test(10.0, 19.9), None);
        assert_eq!(m.hit_test(810.0, 20.0), None);
        assert_eq!(m.hit_test(10.0, 500.0), None);
    }

    #[test]
    fn test_headless_egui_render_terminal_canvas() {
        let ctx = egui::Context::default();
        let screen = SafeScreenView::empty(24, 80);
        let theme = TerminalTheme::default();

        ctx.run_ui(egui::RawInput::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                let interaction = render_terminal_canvas(ui, &screen, &theme, false, None);
                assert_eq!(interaction.clicked_cursor_move, None);
            });
        })
        .drop_without_applying_deltas();
    }

    /// A mouse click on a cell is reported as `MoveCursor` to that cell (x3270: a click moves
    /// the cursor). Runs real pointer events through egui, frame by frame.
    #[test]
    fn test_click_on_a_cell_moves_the_cursor() {
        use egui::{Event, PointerButton, RawInput};
        let ctx = egui::Context::default();
        let screen = SafeScreenView::empty(24, 80);
        let theme = TerminalTheme::default();
        let grid_origin = std::cell::Cell::new(Pos2::ZERO);
        let frame = |events: Vec<Event>| {
            let mut input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(1400.0, 900.0))),
                ..RawInput::default()
            };
            input.events = events;
            let mut result = None;
            ctx.run_ui(input, |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    grid_origin.set(ui.cursor().min);
                    result = Some(render_terminal_canvas(ui, &screen, &theme, false, None));
                });
            })
            .drop_without_applying_deltas();
            result.and_then(|r| r.clicked_cursor_move)
        };
        assert_eq!(frame(Vec::new()), None, "layout frame");
        // Somewhere inside the grid (a few cells right and down from its top-left corner).
        let at = grid_origin.get() + Vec2::new(60.0, 60.0);
        let press = |pressed| Event::PointerButton {
            pos: at,
            button: PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        let _ = frame(vec![Event::PointerMoved(at), press(true)]);
        let moved = frame(vec![press(false)]);
        assert!(
            matches!(moved, Some(ActionKey::MoveCursor { .. })),
            "the click must move the cursor: {moved:?}"
        );
    }
}
