//! Screen operations whose cost the host controls must stay linear in the screen size.
//!
//! A host chooses the screen size (up to 16,384 cells with `IBM-DYNAMIC`) and how many fields
//! it defines. Looking up the governing field walks back through the buffer to the previous
//! attribute (`x3270` `find_field_attribute`), so any per-cell loop that repeats that lookup is
//! quadratic on a large screen with few fields: one record could then cost the gateway
//! hundreds of milliseconds of CPU per session. `x3270` carries the current attribute forward
//! instead (`ctlr_write` `ORDER_EUA`, `screen_disp`); these tests pin the same for the
//! projection to the safe view, `Erase Unprotected to Address` and `Repeat to Address` over
//! many attributes.
//!
//! The budget is generous for an unoptimised build on a slow CI runner (a linear pass takes
//! a few milliseconds there), while a quadratic implementation takes seconds.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::{Duration, Instant};

use bastion3270_core::address::BufferAddress;
use bastion3270_core::ebcdic::CP037;
use bastion3270_core::{DataStreamParser, PresentationSpace, SafeScreenView, TerminalModel};

/// Upper bound for one operation on the largest screen.
const BUDGET: Duration = Duration::from_millis(250);

/// The largest dynamic screen: 64 x 255 = 16,320 cells.
fn large_model() -> TerminalModel {
    TerminalModel::new_dynamic(64, 255).unwrap()
}

/// `SBA` to `addr` on a screen of `cap` cells (14-bit address).
fn sba(addr: usize, cap: usize) -> Vec<u8> {
    let bytes = BufferAddress::new(addr, cap)
        .unwrap()
        .encode_for_capacity(cap)
        .unwrap();
    vec![0x11, bytes[0], bytes[1]]
}

/// A large screen with a single unprotected field at address 1 (`EWA`, `SBA`, `SF`), the
/// rest of the buffer filled with characters.
fn sparse_screen() -> PresentationSpace {
    let mut ps = PresentationSpace::new(large_model());
    let cap = large_model().alternate_capacity();
    let mut record = vec![0x7E, 0xC3];
    record.extend(sba(1, cap));
    record.extend([0x1D, 0x40]);
    // RA to address 0 with 'A': fills every data position of the field.
    record.extend([0x3C, 0x00, 0x00, 0xC1]);
    let result = DataStreamParser::process(&record, &mut ps);
    assert!(result.rejected.is_none());
    assert_eq!(ps.capacity(), cap);
    ps
}

fn assert_within_budget(what: &str, elapsed: Duration) {
    assert!(
        elapsed < BUDGET,
        "{what} took {elapsed:?} on a 16,320-cell screen (budget {BUDGET:?}): not linear"
    );
}

#[test]
fn projecting_a_large_sparse_screen_is_linear() {
    let ps = sparse_screen();
    let start = Instant::now();
    let view = SafeScreenView::from_presentation_space(&ps, &CP037);
    assert_within_budget("the safe view projection", start.elapsed());
    assert_eq!(view.cells().len(), ps.capacity());
    assert_eq!(view.cells()[2].ch, 'A');
}

#[test]
fn erase_unprotected_to_address_over_a_large_sparse_screen_is_linear() {
    let mut ps = sparse_screen();
    let cap = ps.capacity();
    // W, SBA to 2, EUA to 1: erases every data position of the field, wrapping once.
    let mut record = vec![0xF1, 0xC3];
    record.extend(sba(2, cap));
    let stop = BufferAddress::new(1, cap)
        .unwrap()
        .encode_for_capacity(cap)
        .unwrap();
    record.extend([0x12, stop[0], stop[1]]);

    let start = Instant::now();
    let result = DataStreamParser::process(&record, &mut ps);
    assert_within_budget("EUA", start.elapsed());
    assert!(result.rejected.is_none());
    assert_eq!(
        ps.cell(BufferAddress::new(2, cap).unwrap())
            .unwrap()
            .raw_ebcdic(),
        0x00
    );
    assert_eq!(ps.cell(BufferAddress::ZERO).unwrap().raw_ebcdic(), 0x00);
}

#[test]
fn repeating_over_many_attributes_is_linear() {
    let model = large_model();
    let cap = model.alternate_capacity();
    let half = cap / 2;
    // EWA, then an attribute in every cell of the second half.
    let mut fields = vec![0x7E, 0xC3];
    fields.extend(sba(half, cap));
    for _ in half..cap {
        fields.extend([0x1D, 0x40]);
    }
    // W, SBA to the second half, RA to address 0: overwrites every attribute in turn.
    let mut repeat = vec![0xF1, 0xC3];
    repeat.extend(sba(half, cap));
    repeat.extend([0x3C, 0x00, 0x00, 0xC1]);

    // Three rounds, so the quadratic cost stands well clear of the budget.
    let mut elapsed = Duration::ZERO;
    for _ in 0..3 {
        let mut ps = PresentationSpace::new(model);
        assert!(DataStreamParser::process(&fields, &mut ps)
            .rejected
            .is_none());
        assert!(ps.is_formatted());

        let start = Instant::now();
        let result = DataStreamParser::process(&repeat, &mut ps);
        elapsed += start.elapsed();
        assert!(result.rejected.is_none());
        assert!(!ps.is_formatted(), "the last attribute is gone");
    }
    assert_within_budget("RA over 8,160 attributes (three rounds)", elapsed);
}
