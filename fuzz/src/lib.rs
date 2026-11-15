//! Shared helpers for the libFuzzer targets in `fuzz_targets/`.
//!
//! The targets decode their raw input with these helpers so that seeds stay readable
//! (a selector byte followed by length-prefixed records or chunks) and so that every target
//! checks the same invariants in the same way.

use bastion3270_core::address::BufferAddress;
use bastion3270_core::{Cell, FieldAttribute, PresentationSpace, SafeScreenView, TerminalModel};

/// Dynamic (`IBM-DYNAMIC`) screen sizes chosen by the model selector: the minimum, common
/// ISPF sizes and the largest shapes that still fit the 14-bit address space.
const DYNAMIC_SIZES: [(u16, u16); 4] = [(24, 80), (62, 160), (64, 255), (128, 128)];

/// Maps the low three bits of `selector` to a terminal model: `0..=3` are the fixed models
/// 2 to 5, `4..=7` a dynamic model of one of [`DYNAMIC_SIZES`].
pub fn model_from_selector(selector: u8) -> TerminalModel {
    match selector & 0x07 {
        0 => TerminalModel::Model2,
        1 => TerminalModel::Model3,
        2 => TerminalModel::Model4,
        3 => TerminalModel::Model5,
        n => {
            let (rows, cols) = DYNAMIC_SIZES
                .get(usize::from(n - 4))
                .copied()
                .unwrap_or((24, 80));
            TerminalModel::new_dynamic(rows, cols).unwrap_or(TerminalModel::Model2)
        }
    }
}

/// Splits `data` into records, each preceded by a big-endian `u16` length.
///
/// A length of `0` means "the rest of the input", so a single record is written as
/// `00 00 <record>`. A length longer than the remaining input takes what is left.
pub fn split_records(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while let [hi, lo, rest @ ..] = data {
        let len = usize::from(u16::from_be_bytes([*hi, *lo]));
        let take = if len == 0 {
            rest.len()
        } else {
            len.min(rest.len())
        };
        let (record, tail) = rest.split_at(take);
        out.push(record);
        data = tail;
    }
    out
}

/// Asserts that a presentation space keeps its cursor and buffer address on the screen.
pub fn assert_addresses_in_bounds(ps: &PresentationSpace) {
    let cap = ps.capacity();
    assert_eq!(
        cap,
        usize::from(ps.rows()) * usize::from(ps.cols()),
        "capacity must be rows x cols"
    );
    assert!(
        ps.cursor_addr().as_usize() < cap,
        "cursor outside the screen"
    );
    assert!(
        ps.buffer_addr().as_usize() < cap,
        "buffer address outside the screen"
    );
}

/// Projects `ps` into a [`SafeScreenView`] and asserts its documented zero-trust guarantees
/// (`SafeCell`):
///
/// 1. a field attribute position is rendered as `' '`, marked as field marker and protected;
/// 2. every character governed by a non-display field attribute is rendered as `' '`.
///
/// The view must also have the dimensions and cursor of the presentation space.
pub fn assert_safe_view(
    ps: &PresentationSpace,
    codepage: &dyn bastion3270_core::CodePage,
) -> SafeScreenView {
    let view = SafeScreenView::from_presentation_space(ps, codepage);
    let cap = ps.capacity();
    assert_eq!(view.rows(), ps.rows());
    assert_eq!(view.cols(), ps.cols());
    assert_eq!(view.capacity(), cap);
    assert_eq!(view.cells().len(), cap);
    assert!(view.cursor_row() < view.rows() && view.cursor_col() < view.cols());
    assert_eq!(
        view.cursor_position(),
        ps.cursor_addr().to_row_col(ps.cols())
    );

    let cells = screen_cells(ps);
    let governing = governing_attributes(ps, &cells);
    for (idx, (cell, governing)) in cells.iter().zip(&governing).enumerate() {
        let Some(safe) = view.cells().get(idx) else {
            panic!("no safe cell at address {idx} below capacity {cap}");
        };
        if cell.is_field_attribute() {
            assert_eq!(safe.ch, ' ', "field attribute rendered as a character");
            assert!(safe.is_field_marker && safe.protected);
        } else if governing.is_some_and(FieldAttribute::is_non_display) {
            assert_eq!(
                safe.ch, ' ',
                "non-display field content leaked at address {idx}"
            );
        }
    }
    view
}

/// Copies every cell of the presentation space, in buffer order.
pub fn screen_cells(ps: &PresentationSpace) -> Vec<Cell> {
    let cap = ps.capacity();
    (0..cap)
        .map(|idx| {
            let Some(cell) = BufferAddress::new(idx, cap).ok().and_then(|a| ps.cell(a)) else {
                panic!("no cell at address {idx} below capacity {cap}");
            };
            *cell
        })
        .collect()
}

/// The field attribute governing every position (for an attribute position, the attribute
/// itself), or `None` on an unformatted screen.
///
/// Equivalent to `PresentationSpace::governing_field` per position (`x3270`
/// `get_field_attribute`: the nearest attribute at or before the position, wrapping at the
/// start of the buffer), but computed in one pass so the harness stays linear on large
/// screens. Also asserts that the screen is formatted exactly when it holds an attribute.
pub fn governing_attributes(ps: &PresentationSpace, cells: &[Cell]) -> Vec<Option<FieldAttribute>> {
    let last = cells.iter().rev().find_map(Cell::field_attribute);
    assert_eq!(
        ps.is_formatted(),
        last.is_some(),
        "formatted flag disagrees with the field attributes on the screen"
    );
    let mut current = last;
    cells
        .iter()
        .map(|cell| {
            if let Some(fa) = cell.field_attribute() {
                current = Some(fa);
            }
            current
        })
        .collect()
}
