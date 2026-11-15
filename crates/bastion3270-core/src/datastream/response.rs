//! Inbound 3270 Response Stream Builders (Read Buffer and Read Modified).
//!
//! Generates outbound byte streams sent from the terminal back to the host in response
//! to `ReadBuffer`, `ReadModified`, and `ReadModifiedAll` commands or AID key triggers.

use crate::address::BufferAddress;
use crate::datastream::order::{ORDER_GE, ORDER_SA, ORDER_SBA, ORDER_SF, ORDER_SFE};
use crate::field::{
    CharacterSet, Color3270, ExtendedAttributes, Highlight3270, XA_3270, XA_BACKGROUND, XA_CHARSET,
    XA_FOREGROUND, XA_HIGHLIGHTING,
};
use crate::screen::{Cell, PresentationSpace, ReplyMode};

/// Short-read AID codes that transmit only the AID byte itself without cursor address or field data.
pub const AID_CLEAR: u8 = 0x6D;
pub const AID_PA1: u8 = 0x6C;
pub const AID_PA2: u8 = 0x6E;
pub const AID_PA3: u8 = 0x6B;
/// AID of the System Request key in plain TN3270 (`x3270` `AID_SYSREQ`).
pub const AID_SYSREQ: u8 = 0xF0;

/// Prefix of a *test request* read: `SOH % / STX` in EBCDIC (`x3270` `ctlr_read_modified`,
/// case `AID_SYSREQ`).
pub const TEST_REQUEST_HEADER: [u8; 4] = [0x01, 0x6C, 0x61, 0x02];

/// Returns `true` if `aid_byte` is a short-read AID (PA1, PA2, PA3, or Clear).
pub const fn is_short_read_aid(aid_byte: u8) -> bool {
    matches!(aid_byte, AID_CLEAR | AID_PA1 | AID_PA2 | AID_PA3)
}

/// AID sent when no AID key is pending (`x3270` `AID_NO`).
pub const AID_NO: u8 = 0x60;

/// Builds the reply to a host [`Command::ReadBuffer`](crate::datastream::Command::ReadBuffer)
/// with AID `0x60` (no AID); see [`build_read_buffer_with_aid`].
pub fn build_read_buffer(ps: &PresentationSpace) -> Vec<u8> {
    build_read_buffer_with_aid(ps, AID_NO)
}

/// Builds a Read Buffer reply (`x3270` `ctlr_read_buffer`): AID, cursor address, then every
/// buffer position.
///
/// Field attributes are sent as `SF <attr>` in [`ReplyMode::Field`], otherwise as
/// `SFE` with the 3270 attribute and every non-default extended attribute. In
/// [`ReplyMode::Character`] the listed character attributes are reported with `SA` orders
/// when they change. APL / graphic-escape characters are prefixed with `GE`.
///
/// `aid_byte` is the current AID for a host Read Buffer, or
/// [`AID_READ_PARTITION`](crate::datastream::AID_READ_PARTITION) when the read was requested
/// by a WSF *Read Partition*.
pub fn build_read_buffer_with_aid(ps: &PresentationSpace, aid_byte: u8) -> Vec<u8> {
    let cap = ps.capacity();
    let mode = ps.reply_mode();
    let mut out = Vec::with_capacity(cap.saturating_add(3));
    out.push(aid_byte);
    out.extend_from_slice(&encoded_cursor(ps));

    let mut sa = SaState::default();
    let mut field_cs = ps
        .governing_field(BufferAddress::ZERO)
        .map_or(CharacterSet::Base, |(_, _, xa)| xa.charset);
    for idx in 0..cap {
        let Some(cell) = BufferAddress::new(idx, cap).ok().and_then(|a| ps.cell(a)) else {
            continue;
        };
        let xa = cell.extended();
        if let Some(fa) = cell.field_attribute() {
            field_cs = xa.charset;
            if mode == ReplyMode::Field {
                out.extend_from_slice(&[ORDER_SF, fa.to_wire_byte()]);
            } else {
                let mut pairs = vec![(XA_3270, fa.to_wire_byte())];
                for (kind, value) in [
                    (XA_FOREGROUND, xa.foreground.to_xa_byte()),
                    (XA_BACKGROUND, xa.background.to_xa_byte()),
                    (XA_HIGHLIGHTING, highlight_byte(xa.highlight)),
                    (XA_CHARSET, xa.charset.to_xa_byte()),
                ] {
                    if value != 0 {
                        pairs.push((kind, value));
                    }
                }
                out.push(ORDER_SFE);
                out.push(u8::try_from(pairs.len()).unwrap_or(1));
                for (kind, value) in pairs {
                    out.extend_from_slice(&[kind, value]);
                }
            }
        } else {
            sa.insert(mode, xa, &mut out);
            if needs_ge(xa.charset, field_cs) {
                out.push(ORDER_GE);
            }
            out.push(cell.raw_ebcdic());
        }
    }
    out
}

/// Builds a Read Modified / Read Modified All reply, or the inbound record of an AID key
/// (`x3270` `ctlr_read_modified`).
///
/// * `AID_SYSREQ` starts with [`TEST_REQUEST_HEADER`] instead of AID and cursor address.
/// * A short-read AID (PA1–PA3, Clear) sends only the AID byte, unless `read_all`: Read
///   Modified All differs from Read Modified **only** here.
/// * Otherwise the AID and cursor address are followed by the *modified* fields
///   (`SBA <first data position>` + non-null characters); an unformatted screen sends every
///   non-null character. In [`ReplyMode::Character`] the listed character attributes are
///   reported with `SA` orders (a character without its own attribute inherits the field's),
///   and APL / graphic-escape characters are prefixed with `GE`.
pub fn build_read_modified(ps: &PresentationSpace, aid_byte: u8, read_all: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if aid_byte == AID_SYSREQ {
        out.extend_from_slice(&TEST_REQUEST_HEADER);
    } else {
        out.push(aid_byte);
        if !read_all && is_short_read_aid(aid_byte) {
            return out;
        }
        out.extend_from_slice(&encoded_cursor(ps));
    }
    push_modified_data(ps, &mut out);
    out
}

/// Longest SSCP-LU input `x3270` sends for one Enter (`ctlr_read_modified`).
pub const SSCP_READ_MAX: usize = 255;

/// Builds the SSCP-LU reply to the Enter key (`x3270` `ctlr_read_modified` in SSCP-LU
/// mode): no AID and no cursor address, just the non-null characters from the SSCP-LU
/// input start, at most [`SSCP_READ_MAX`], ending where the screen wraps.
pub fn build_sscp_read(ps: &PresentationSpace) -> Vec<u8> {
    let mut out = Vec::new();
    push_unformatted_data(ps, ps.sscp_start(), Some(SSCP_READ_MAX), &mut out);
    out
}

/// Appends the non-null characters of an unformatted screen from `start` up to the end of
/// the screen (no wrap), with `SA` orders in character reply mode and `GE` for APL
/// characters; stops after `limit` characters if given.
fn push_unformatted_data(
    ps: &PresentationSpace,
    start: BufferAddress,
    limit: Option<usize>,
    out: &mut Vec<u8>,
) {
    let cap = ps.capacity();
    let mode = ps.reply_mode();
    let mut sa = SaState::default();
    let mut count = 0usize;
    for idx in start.as_usize()..cap {
        if limit.is_some_and(|max| count >= max) {
            break;
        }
        let Some(cell) = BufferAddress::new(idx, cap).ok().and_then(|a| ps.cell(a)) else {
            continue;
        };
        let ebcdic = cell.raw_ebcdic();
        if ebcdic != 0x00 {
            let xa = cell.extended();
            sa.insert(mode, xa, out);
            if xa.charset == CharacterSet::Apl {
                out.push(ORDER_GE);
            }
            out.push(ebcdic);
            count = count.saturating_add(1);
        }
    }
}

/// Builds the inbound *test request* read sent by the System Request key in plain TN3270
/// (`x3270` `ctlr_read_modified` with `AID_SYSREQ`).
pub fn build_test_request(ps: &PresentationSpace) -> Vec<u8> {
    build_read_modified(ps, AID_SYSREQ, false)
}

fn encoded_cursor(ps: &PresentationSpace) -> [u8; 2] {
    ps.cursor_addr()
        .encode_for_capacity(ps.capacity())
        .unwrap_or([0x40, 0x40])
}

/// Appends the field data of a Read Modified.
fn push_modified_data(ps: &PresentationSpace, out: &mut Vec<u8>) {
    let cap = ps.capacity();
    let mode = ps.reply_mode();
    let mut sa = SaState::default();

    if !ps.is_formatted() {
        push_unformatted_data(ps, BufferAddress::ZERO, None, out);
        return;
    }

    for idx in 0..cap {
        let Ok(addr) = BufferAddress::new(idx, cap) else {
            continue;
        };
        let Some(fa) = ps.cell(addr).and_then(Cell::field_attribute) else {
            continue;
        };
        if !fa.is_modified() {
            continue;
        }
        let field_xa = ps
            .cell(addr)
            .map_or(ExtendedAttributes::DEFAULT, Cell::extended);
        let first_data_addr = addr.next_wrapped(cap);
        let [a1, a2] = first_data_addr
            .encode_for_capacity(cap)
            .unwrap_or([0x40, 0x40]);
        out.extend_from_slice(&[ORDER_SBA, a1, a2]);

        // Field characters up to the next field attribute.
        let mut curr = first_data_addr;
        loop {
            if let Some(data_cell) = ps.cell(curr) {
                if data_cell.is_field_attribute() {
                    break;
                }
                let b = data_cell.raw_ebcdic();
                if b != 0x00 {
                    let xa = inherit(data_cell.extended(), field_xa);
                    sa.insert(mode, xa, out);
                    if needs_ge(data_cell.extended().charset, field_xa.charset) {
                        out.push(ORDER_GE);
                    }
                    out.push(b);
                }
            }
            curr = curr.next_wrapped(cap);
            if curr == first_data_addr {
                break;
            }
        }
    }
}

/// `true` if a character must be sent with a `GE` prefix: it is in the APL set, or it uses
/// the default set of a field whose set is APL (`x3270` `ctlr_read_buffer` /
/// `ctlr_read_modified`).
fn needs_ge(cell_cs: CharacterSet, field_cs: CharacterSet) -> bool {
    cell_cs == CharacterSet::Apl || (cell_cs == CharacterSet::Base && field_cs == CharacterSet::Apl)
}

/// Character attributes with the field's attributes filling in the defaults.
fn inherit(cell: ExtendedAttributes, field: ExtendedAttributes) -> ExtendedAttributes {
    ExtendedAttributes {
        foreground: if cell.foreground == Color3270::Default {
            field.foreground
        } else {
            cell.foreground
        },
        background: if cell.background == Color3270::Default {
            field.background
        } else {
            cell.background
        },
        highlight: if cell.highlight.is_default() {
            field.highlight
        } else {
            cell.highlight
        },
        charset: if cell.charset == CharacterSet::Base {
            field.charset
        } else {
            cell.charset
        },
    }
}

/// Highlighting as reported to the host: `0x00` for none, else `X'F0' | flags`.
const fn highlight_byte(h: Highlight3270) -> u8 {
    h.to_xa_byte()
}

/// Last attribute values reported by `SA` in character reply mode (`x3270` `insert_sa`,
/// `prev_fg` / `prev_bg` / `prev_gr` / `prev_cs`).
#[derive(Default)]
struct SaState {
    foreground: u8,
    background: u8,
    highlight: u8,
    charset: u8,
}

impl SaState {
    fn insert(&mut self, mode: ReplyMode, xa: ExtendedAttributes, out: &mut Vec<u8>) {
        let ReplyMode::Character(attrs) = mode else {
            return;
        };
        if attrs.foreground() {
            Self::insert1(
                XA_FOREGROUND,
                xa.foreground.to_xa_byte(),
                &mut self.foreground,
                out,
            );
        }
        if attrs.background() {
            Self::insert1(
                XA_BACKGROUND,
                xa.background.to_xa_byte(),
                &mut self.background,
                out,
            );
        }
        if attrs.highlight() {
            Self::insert1(
                XA_HIGHLIGHTING,
                highlight_byte(xa.highlight),
                &mut self.highlight,
                out,
            );
        }
        if attrs.charset() {
            Self::insert1(XA_CHARSET, xa.charset.to_xa_byte(), &mut self.charset, out);
        }
    }

    fn insert1(kind: u8, value: u8, prev: &mut u8, out: &mut Vec<u8>) {
        if value != *prev {
            *prev = value;
            out.extend_from_slice(&[ORDER_SA, kind, value]);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::ebcdic::{CodePage, CP037};
    use crate::field::{ExtendedAttributes, FieldAttribute, FieldIntensity};
    use crate::model::TerminalModel;

    #[test]
    fn test_short_read_aids() {
        let ps = PresentationSpace::new(TerminalModel::Model2);
        assert_eq!(build_read_modified(&ps, AID_CLEAR, false), vec![AID_CLEAR]);
        assert_eq!(build_read_modified(&ps, AID_PA1, false), vec![AID_PA1]);
        assert_eq!(build_read_modified(&ps, AID_PA2, false), vec![AID_PA2]);
        assert_eq!(build_read_modified(&ps, AID_PA3, false), vec![AID_PA3]);
    }

    #[test]
    fn test_read_buffer_structure() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();

        let fa_addr = BufferAddress::new(0, cap).unwrap();
        let fa = FieldAttribute::new(true, false, FieldIntensity::NormalNonDetectable, false);
        ps.place_field(fa_addr, fa, ExtendedAttributes::DEFAULT)
            .unwrap();

        let data_addr = BufferAddress::new(1, cap).unwrap();
        let ebcdic_a = CP037.char_to_ebcdic('A').unwrap();
        ps.write_char(data_addr, ebcdic_a, ExtendedAttributes::DEFAULT)
            .unwrap();

        let stream = build_read_buffer(&ps);
        assert_eq!(stream[0], 0x60); // AID
        assert_eq!(stream[3], ORDER_SF);
        assert_eq!(stream[4], fa.to_wire_byte());
        assert_eq!(stream[5], ebcdic_a);
        // cap + 3 header bytes + 1 extra byte because ORDER_SF is 2 bytes for 1 cell
        assert_eq!(stream.len(), cap + 3 + 1);
    }

    /// `x3270` `ctlr_read_modified(AID_SYSREQ)`: `SOH % / STX`, no AID or cursor, then the
    /// modified fields exactly as in a Read Modified.
    #[test]
    fn test_request_replaces_aid_and_cursor_with_header() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();
        assert_eq!(build_test_request(&ps), TEST_REQUEST_HEADER.to_vec());

        let fa_addr = BufferAddress::new(10, cap).unwrap();
        let fa = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, true);
        ps.place_field(fa_addr, fa, ExtendedAttributes::DEFAULT)
            .unwrap();
        let c_a = CP037.char_to_ebcdic('A').unwrap();
        ps.write_char(
            BufferAddress::new(11, cap).unwrap(),
            c_a,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();

        let rm = build_read_modified(&ps, 0x7D, false);
        let tr = build_test_request(&ps);
        assert_eq!(&tr[..4], &TEST_REQUEST_HEADER);
        assert_eq!(&tr[4..], &rm[3..], "field data identical to Read Modified");
        assert_eq!(tr[4], ORDER_SBA);
        assert!(tr.contains(&c_a));
    }

    #[test]
    fn test_read_modified_null_suppression() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let cap = ps.capacity();

        // Field 1: MDT=1, contains "A", null, "B"
        let fa1_addr = BufferAddress::new(10, cap).unwrap();
        let fa1 = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, true);
        ps.place_field(fa1_addr, fa1, ExtendedAttributes::DEFAULT)
            .unwrap();

        let c_a = CP037.char_to_ebcdic('A').unwrap();
        let c_b = CP037.char_to_ebcdic('B').unwrap();

        ps.write_char(
            BufferAddress::new(11, cap).unwrap(),
            c_a,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
        ps.write_char(
            BufferAddress::new(12, cap).unwrap(),
            0x00,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();
        ps.write_char(
            BufferAddress::new(13, cap).unwrap(),
            c_b,
            ExtendedAttributes::DEFAULT,
        )
        .unwrap();

        // Field 2: at cell 20, MDT=0 (unmodified)
        let fa2_addr = BufferAddress::new(20, cap).unwrap();
        let fa2 = FieldAttribute::new(false, false, FieldIntensity::NormalNonDetectable, false);
        ps.place_field(fa2_addr, fa2, ExtendedAttributes::DEFAULT)
            .unwrap();

        // Read modified with Enter AID (0x7D)
        let stream = build_read_modified(&ps, 0x7D, false);

        assert_eq!(stream[0], 0x7D); // AID
                                     // Next 2 bytes are cursor address
        assert_eq!(stream[3], ORDER_SBA);
        // SBA address should be cell 11 (first data cell)
        let [exp_a1, exp_a2] = BufferAddress::new(11, cap)
            .unwrap()
            .encode_for_capacity(cap)
            .unwrap();
        assert_eq!(stream[4], exp_a1);
        assert_eq!(stream[5], exp_a2);
        // Data bytes: 'A' and 'B', null (0x00) is suppressed
        assert_eq!(stream[6], c_a);
        assert_eq!(stream[7], c_b);
        assert_eq!(stream.len(), 8);
    }
}
