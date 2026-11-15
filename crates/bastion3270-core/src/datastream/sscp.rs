//! SSCP-LU data: the unformatted, line-oriented text the SNA control point (for example the
//! VTAM USS logon screen) exchanges with the terminal before an application binds the session.
//!
//! Follows `x3270` `ctlr.c` `ctlr_write_sscp_lu` (output) and the SSCP-LU path of
//! `ctlr_read_modified` (input, see [`crate::datastream::response::build_sscp_read`]).

use crate::address::BufferAddress;
use crate::datastream::order::{FC_NL, ORDER_GE, ORDER_IC, ORDER_SBA, ORDER_SF};
use crate::ebcdic::EBC_NULL;
use crate::field::{CharacterSet, ExtendedAttributes};
use crate::screen::{PresentationSpace, ScreenError};

/// EBCDIC space.
const EBC_SPACE: u8 = 0x40;

/// Writes SSCP-LU data to the screen as plain text from the buffer address.
///
/// * `NL` fills the rest of the row with nulls and moves to the next row.
/// * `SF` (and its attribute byte) is shown as a space: SSCP-LU data has no fields, but some
///   hosts send one anyway.
/// * `IC` is ignored; `SBA` and its address are skipped.
/// * `GE x` shows `x` from the APL set (a space for `x <= 0x40`).
/// * Every other byte is stored as it is.
///
/// Writing past the end of the screen scrolls it up one row and continues on the last row.
/// Afterwards the cursor and the SSCP-LU input start are where the output ended.
///
/// # Errors
///
/// Returns [`ScreenError`] only if a computed address is outside the screen, which cannot
/// happen for a consistent presentation space.
pub fn write_sscp_lu(ps: &mut PresentationSpace, data: &[u8]) -> Result<(), ScreenError> {
    let mut bytes = data.iter().copied();
    while let Some(byte) = bytes.next() {
        match byte {
            FC_NL => {
                let cols = ps.cols_nonzero();
                let row = ps.buffer_addr().as_usize() / cols;
                while ps.buffer_addr().as_usize() / cols == row {
                    ps.write_char(ps.buffer_addr(), EBC_NULL, ExtendedAttributes::DEFAULT)?;
                    ps.advance_buffer_addr();
                    if ps.buffer_addr() == BufferAddress::ZERO {
                        break;
                    }
                }
                scroll_if_wrapped(ps)?;
            }
            ORDER_SF => {
                let _attribute = bytes.next();
                put(ps, EBC_SPACE, ExtendedAttributes::DEFAULT)?;
            }
            ORDER_IC => {}
            ORDER_SBA => {
                let _address = (bytes.next(), bytes.next());
            }
            ORDER_GE => {
                let Some(ch) = bytes.next() else { break };
                let ch = if ch <= EBC_SPACE { EBC_SPACE } else { ch };
                let xa = ExtendedAttributes {
                    charset: CharacterSet::Apl,
                    ..ExtendedAttributes::DEFAULT
                };
                put(ps, ch, xa)?;
            }
            other => put(ps, other, ExtendedAttributes::DEFAULT)?,
        }
    }
    let end = ps.buffer_addr();
    ps.set_cursor_addr(end)?;
    ps.set_sscp_start(end)
}

/// Stores one character at the buffer address and advances it.
fn put(ps: &mut PresentationSpace, ch: u8, xa: ExtendedAttributes) -> Result<(), ScreenError> {
    ps.write_char(ps.buffer_addr(), ch, xa)?;
    ps.advance_buffer_addr();
    scroll_if_wrapped(ps)
}

/// After the buffer address wrapped to 0: scroll up one row and continue on the last row.
fn scroll_if_wrapped(ps: &mut PresentationSpace) -> Result<(), ScreenError> {
    if ps.buffer_addr() == BufferAddress::ZERO {
        ps.scroll_up();
        let last = ps.last_row_start();
        ps.set_buffer_addr(last)?;
    }
    Ok(())
}
