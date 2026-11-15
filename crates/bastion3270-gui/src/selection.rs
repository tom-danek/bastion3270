//! Rectangular selection of screen cells and its clipboard text (as in the web client and
//! x3270's rectangular selection).

use bastion3270_core::SafeScreenView;

/// A rectangle of cells, inclusive, normalised so that `r0 <= r1` and `c0 <= c1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    /// First row.
    pub r0: u16,
    /// First column.
    pub c0: u16,
    /// Last row.
    pub r1: u16,
    /// Last column.
    pub c1: u16,
}

impl Selection {
    /// The rectangle between the cell where the drag started and the current cell.
    #[must_use]
    pub fn between(anchor: (u16, u16), point: (u16, u16)) -> Self {
        Self {
            r0: anchor.0.min(point.0),
            r1: anchor.0.max(point.0),
            c0: anchor.1.min(point.1),
            c1: anchor.1.max(point.1),
        }
    }

    /// `true` if `(row, col)` lies inside.
    #[must_use]
    pub const fn contains(&self, row: u16, col: u16) -> bool {
        row >= self.r0 && row <= self.r1 && col >= self.c0 && col <= self.c1
    }
}

/// Clipboard text of `selection`, or of the whole screen when `None`: one line per row,
/// trailing blanks removed. The text comes from the masked view, so hidden fields are blank.
#[must_use]
pub fn selection_text(screen: &SafeScreenView, selection: Option<Selection>) -> String {
    let all = Selection {
        r0: 0,
        c0: 0,
        r1: screen.rows().saturating_sub(1),
        c1: screen.cols().saturating_sub(1),
    };
    let sel = selection.unwrap_or(all);
    (sel.r0..=sel.r1.min(all.r1))
        .filter_map(|row| screen.row_text(row))
        .map(|text| {
            let picked: String = text
                .chars()
                .skip(usize::from(sel.c0))
                .take(usize::from(sel.c1.saturating_sub(sel.c0)).saturating_add(1))
                .collect();
            picked.trim_end().to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bastion3270_core::{PresentationSpace, TerminalModel, CP037};

    fn screen(lines: &[&str]) -> SafeScreenView {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        for (row, line) in lines.iter().enumerate() {
            for (col, ch) in line.chars().enumerate() {
                let addr = bastion3270_core::BufferAddress::from_row_col(
                    u16::try_from(row).unwrap(),
                    u16::try_from(col).unwrap(),
                    24,
                    80,
                )
                .unwrap();
                let byte = bastion3270_core::CodePage::char_to_ebcdic(&CP037, ch).unwrap();
                ps.write_char(addr, byte, bastion3270_core::ExtendedAttributes::DEFAULT)
                    .unwrap();
            }
        }
        ps.to_safe_view(&CP037)
    }

    #[test]
    fn test_rectangle_text_and_whole_screen() {
        let s = screen(&["HELLO WORLD", "  SECOND ROW", "THIRD"]);
        let sel = Selection::between((1, 8), (0, 2)); // dragged up and left
        assert_eq!(
            sel,
            Selection {
                r0: 0,
                c0: 2,
                r1: 1,
                c1: 8
            }
        );
        assert_eq!(selection_text(&s, Some(sel)), "LLO WOR\nSECOND");
        let all = selection_text(&s, None);
        assert!(
            all.starts_with("HELLO WORLD\n  SECOND ROW\nTHIRD\n"),
            "{all:?}"
        );
        assert_eq!(all.matches('\n').count(), 23, "24 rows");
    }
}
