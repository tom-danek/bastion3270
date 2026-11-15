//! Write Structured Field (WSF) Query Reply Engine and Builder.
//!
//! Handles inbound `SF_READ_PART (0x01)` (Query and Query List) and constructs
//! IBM 3270 standard structured field Query Replies framed with `AID_SF (0x88)`.
//!
//! Complies strictly with IBM GA23-0059 and reference `x3270` (`Common/sf.c`).

use crate::ebcdic::CodePage;
use crate::model::TerminalModel;
use core::fmt;

// Protocol Constants
/// AID code identifying an inbound Structured Field reply (`0x88`).
pub const AID_SF: u8 = 0x88;
/// Structured Field ID for Read Partition (`0x01`).
pub const SF_READ_PART: u8 = 0x01;
/// Structured Field ID for Query Reply (`0x81`).
pub const SFID_QREPLY: u8 = 0x81;

/// Read Partition Query type (`0x02`).
pub const SF_RP_QUERY: u8 = 0x02;
/// Read Partition Query List type (`0x03`).
pub const SF_RP_QLIST: u8 = 0x03;

/// Query List request type: List of specific QCODEs (`0x00`).
pub const SF_RPQ_LIST: u8 = 0x00;
/// Query List request type: Equivalent List (`0x40`).
pub const SF_RPQ_EQUIV: u8 = 0x40;
/// Query List request type: All supported QCODEs (`0x80`).
pub const SF_RPQ_ALL: u8 = 0x80;

/// Query Reply QCODE: Summary (`0x80`).
pub const QR_SUMMARY: u8 = 0x80;
/// Query Reply QCODE: Usable Area (`0x81`).
pub const QR_USABLE_AREA: u8 = 0x81;
/// Query Reply QCODE: Alphanumeric Partitions (`0x84`).
pub const QR_ALPHA_PART: u8 = 0x84;
/// Query Reply QCODE: Character Sets (`0x85`).
pub const QR_CHARSETS: u8 = 0x85;
/// Query Reply QCODE: Color (`0x86`).
pub const QR_COLOR: u8 = 0x86;
/// Query Reply QCODE: Highlighting (`0x87`).
pub const QR_HIGHLIGHTING: u8 = 0x87;
/// Query Reply QCODE: Reply Modes (`0x88`).
pub const QR_REPLY_MODES: u8 = 0x88;
/// Query Reply QCODE: RPQ Names (`0xA1`).
pub const QR_RPQNAMES: u8 = 0xA1;
/// Query Reply QCODE: Implicit Partition (`0xA6`).
pub const QR_IMP_PART: u8 = 0xA6;
/// Query Reply QCODE: Null / Unsupported (`0xFF`).
pub const QR_NULL: u8 = 0xFF;

/// Highlighting attribute: Default (`0x00`).
pub const XAH_DEFAULT: u8 = 0x00;
/// Highlighting attribute: Normal (`0xF0`).
pub const XAH_NORMAL: u8 = 0xF0;
/// Highlighting attribute: Blink (`0xF1`).
pub const XAH_BLINK: u8 = 0xF1;
/// Highlighting attribute: Reverse Video (`0xF2`).
pub const XAH_REVERSE: u8 = 0xF2;
/// Highlighting attribute: Underscore (`0xF4`).
pub const XAH_UNDERSCORE: u8 = 0xF4;
/// Highlighting attribute: Intensify (`0xF8`).
pub const XAH_INTENSIFY: u8 = 0xF8;

/// Reply mode: Field mode (`0x00`).
pub const SF_SRM_FIELD: u8 = 0x00;
/// Reply mode: Extended field mode (`0x01`).
pub const SF_SRM_XFIELD: u8 = 0x01;
/// Reply mode: Character mode (`0x02`).
pub const SF_SRM_CHAR: u8 = 0x02;

/// Standard sequence of supported query replies in canonical order (`x3270` `sf.c`
/// `replies[]`). Distributed Data Management (`0x95`) is not reported: it announces IND$FILE
/// file transfer, which this terminal does not offer; DBCS-Asia (`0x91`) only exists on DBCS
/// terminals.
pub const SUPPORTED_QUERY_CODES: [u8; 9] = [
    QR_SUMMARY,
    QR_USABLE_AREA,
    QR_ALPHA_PART,
    QR_CHARSETS,
    QR_COLOR,
    QR_HIGHLIGHTING,
    QR_REPLY_MODES,
    QR_RPQNAMES,
    QR_IMP_PART,
];

/// Program name reported in the RPQ Names query reply.
const RPQ_PROGRAM_NAME: &str = "bastion3270";

/// Errors returned by the WSF parser or builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsfError {
    /// Inbound structured field was shorter than required minimum.
    TruncatedField {
        /// Number of bytes expected.
        expected: usize,
        /// Number of bytes available.
        available: usize,
    },
    /// Invalid partition ID for query (expected 0xFF).
    InvalidPartition {
        /// Expected partition ID (`0xFF`).
        expected: u8,
        /// Encountered partition ID.
        actual: u8,
    },
    /// Unsupported Read Partition query type (expected 0x02 or 0x03).
    InvalidQueryType(u8),
    /// Unsupported Query List request type (expected 0x00, 0x40, or 0x80).
    InvalidRequestType(u8),
    /// Structured field length header exceeds remaining data or is malformed.
    InvalidStructuredFieldLength {
        /// Length declared in header.
        length: usize,
        /// Length actually available in buffer.
        available: usize,
    },
}

impl fmt::Display for WsfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedField { expected, available } => write!(
                f,
                "WSF field truncated: expected at least {expected} bytes, but only {available} available"
            ),
            Self::InvalidPartition { expected, actual } => write!(
                f,
                "invalid partition ID 0x{actual:02X} for query (expected 0x{expected:02X})"
            ),
            Self::InvalidQueryType(q) => write!(
                f,
                "unsupported Read Partition query type 0x{q:02X} (expected 0x02 or 0x03)"
            ),
            Self::InvalidRequestType(r) => write!(
                f,
                "unsupported Query List request type 0x{r:02X}"
            ),
            Self::InvalidStructuredFieldLength { length, available } => write!(
                f,
                "invalid structured field length {length} (available {available} bytes)"
            ),
        }
    }
}

impl std::error::Error for WsfError {}

/// Parsed representation of an inbound `SF_READ_PART` query request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryRequest {
    /// Standard Query (0x02): emit all supported replies.
    QueryAll,
    /// Query List (0x03, `request_type` 0x00): emit requested codes in canonical order.
    QueryList(Vec<u8>),
    /// Query List Equivalent (0x03, `request_type` 0x40): emit all supported replies.
    QueryListEquivalent,
    /// Query List All (0x03, `request_type` 0x80): emit all supported replies.
    QueryListAll,
}

/// Parses an inbound `SF_READ_PART` structured field record.
///
/// Accepts the structured field bytes either starting with the 2-byte length header
/// (`[len_hi, len_lo, 0x01, partition, type, ...]`) or starting directly with the
/// SFID byte `0x01` (`[0x01, partition, type, ...]`).
///
/// # Errors
/// Returns [`WsfError`] if the field is truncated, targets a partition other than `0xFF`,
/// or specifies an unrecognized query or request type.
pub fn parse_read_partition(field: &[u8]) -> Result<QueryRequest, WsfError> {
    // Normalize: strip 2-byte length if present and field starts with length + SF_READ_PART
    let payload =
        if let (Some(&b0), Some(&b1), Some(&b2)) = (field.first(), field.get(1), field.get(2)) {
            let len = (usize::from(b0) << 8) | usize::from(b1);
            if len >= 3 && b2 == SF_READ_PART {
                field.get(2..).unwrap_or(field)
            } else {
                field
            }
        } else {
            field
        };

    let Some(&sf_id) = payload.first() else {
        return Err(WsfError::TruncatedField {
            expected: 3,
            available: payload.len(),
        });
    };

    if sf_id != SF_READ_PART {
        return Err(WsfError::InvalidQueryType(sf_id));
    }

    let Some(&partition) = payload.get(1) else {
        return Err(WsfError::TruncatedField {
            expected: 2,
            available: payload.len(),
        });
    };

    if partition != 0xFF {
        return Err(WsfError::InvalidPartition {
            expected: 0xFF,
            actual: partition,
        });
    }

    let Some(&query_type) = payload.get(2) else {
        return Err(WsfError::TruncatedField {
            expected: 3,
            available: payload.len(),
        });
    };

    match query_type {
        SF_RP_QUERY => Ok(QueryRequest::QueryAll),
        SF_RP_QLIST => {
            let Some(&req_type) = payload.get(3) else {
                return Err(WsfError::TruncatedField {
                    expected: 4,
                    available: payload.len(),
                });
            };
            match req_type {
                SF_RPQ_LIST => {
                    let mut qcodes = Vec::new();
                    if let Some(codes_slice) = payload.get(4..) {
                        qcodes.extend_from_slice(codes_slice);
                    }
                    Ok(QueryRequest::QueryList(qcodes))
                }
                SF_RPQ_EQUIV => Ok(QueryRequest::QueryListEquivalent),
                SF_RPQ_ALL => Ok(QueryRequest::QueryListAll),
                other => Err(WsfError::InvalidRequestType(other)),
            }
        }
        other => Err(WsfError::InvalidQueryType(other)),
    }
}

/// Builder for IBM 3270 Query Reply structured field sequences.
#[derive(Debug, Clone)]
pub struct QueryReplyBuilder<'a> {
    model: TerminalModel,
    codepage: &'a dyn CodePage,
    color_3279: bool,
}

impl<'a> QueryReplyBuilder<'a> {
    /// Creates a new [`QueryReplyBuilder`] for the given model and host code page.
    ///
    /// By default, 3279 color capability is enabled.
    #[must_use]
    pub fn new(model: TerminalModel, codepage: &'a dyn CodePage) -> Self {
        Self {
            model,
            codepage,
            color_3279: true,
        }
    }

    /// Configures 3279 color capability (`true` for color, `false` for monochrome 3278).
    #[must_use]
    pub fn with_color(mut self, color: bool) -> Self {
        self.color_3279 = color;
        self
    }

    /// Handles an inbound `SF_READ_PART` structured field record and builds the complete
    /// Query Reply envelope prefixed with `AID_SF (0x88)`.
    ///
    /// # Errors
    /// Returns [`WsfError`] if parsing the inbound field fails.
    pub fn handle_read_partition(&self, field: &[u8]) -> Result<Vec<u8>, WsfError> {
        let request = parse_read_partition(field)?;
        Ok(self.build_from_request(&request))
    }

    /// Builds the complete Query Reply envelope for the given [`QueryRequest`].
    #[must_use]
    pub fn build_from_request(&self, request: &QueryRequest) -> Vec<u8> {
        match request {
            QueryRequest::QueryAll
            | QueryRequest::QueryListAll
            | QueryRequest::QueryListEquivalent => self.build_all(),
            QueryRequest::QueryList(qcodes) => self.build_list(qcodes),
        }
    }

    /// Emits all supported Query Replies in standard canonical order, prefixed with `AID_SF (0x88)`.
    #[must_use]
    pub fn build_all(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(AID_SF);
        for &code in &SUPPORTED_QUERY_CODES {
            self.append_query_reply(&mut out, code);
        }
        out
    }

    /// Emits Query Replies for requested QCODEs in canonical order, prefixed with `AID_SF (0x88)`.
    ///
    /// If no requested QCODE matches a supported reply, emits a single `QR_NULL (0xFF)`.
    #[must_use]
    pub fn build_list(&self, requested_codes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(AID_SF);

        if requested_codes.is_empty() {
            Self::append_structured_field(&mut out, QR_NULL, &[]);
            return out;
        }

        let mut matched_count: usize = 0;
        for &code in &SUPPORTED_QUERY_CODES {
            let requested = requested_codes.contains(&code);
            if requested {
                self.append_query_reply(&mut out, code);
                matched_count = matched_count.saturating_add(1);
            }
        }

        if matched_count == 0 {
            Self::append_structured_field(&mut out, QR_NULL, &[]);
        }

        out
    }

    /// Appends the single Query Reply for `qcode` into `out`.
    fn append_query_reply(&self, out: &mut Vec<u8>, qcode: u8) {
        match qcode {
            QR_SUMMARY => self.append_summary(out),
            QR_USABLE_AREA => self.append_usable_area(out),
            QR_ALPHA_PART => self.append_alpha_part(out),
            QR_CHARSETS => self.append_charsets(out),
            QR_COLOR => self.append_color(out),
            QR_HIGHLIGHTING => self.append_highlighting(out),
            QR_REPLY_MODES => self.append_reply_modes(out),
            QR_RPQNAMES => self.append_rpq_names(out),
            QR_IMP_PART => self.append_implicit_partition(out),
            QR_NULL => Self::append_null(out),
            _ => {}
        }
    }

    /// Helper to wrap payload in `[len_hi, len_lo, 0x81, qcode, ...payload]`.
    #[allow(clippy::cast_possible_truncation)]
    fn append_structured_field(out: &mut Vec<u8>, qcode: u8, payload: &[u8]) {
        let total_len = payload.len().saturating_add(4);
        let len_u16 = total_len as u16;
        out.push((len_u16 >> 8) as u8);
        out.push((len_u16 & 0xFF) as u8);
        out.push(SFID_QREPLY);
        out.push(qcode);
        out.extend_from_slice(payload);
    }

    /// Query Reply Summary (0x80)
    pub fn append_summary(&self, out: &mut Vec<u8>) {
        Self::append_structured_field(out, QR_SUMMARY, &SUPPORTED_QUERY_CODES);
    }

    /// Query Reply Usable Area (0x81)
    #[allow(clippy::cast_possible_truncation)]
    pub fn append_usable_area(&self, out: &mut Vec<u8>) {
        let (rows, cols) = self.model.alternate_dimensions();
        let cap = (rows as usize).saturating_mul(cols as usize) as u16;

        let mut payload = Vec::with_capacity(19);
        payload.push(0x01); // 12/14-bit addressing supported
        payload.push(0x00); // flags 2
        payload.push((cols >> 8) as u8);
        payload.push((cols & 0xFF) as u8);
        payload.push((rows >> 8) as u8);
        payload.push((rows & 0xFF) as u8);
        payload.push(0x01); // units = mm
        payload.extend_from_slice(&[0x00, 0x0A, 0x02, 0xE5]); // Xr (10.725 dots/mm)
        payload.extend_from_slice(&[0x00, 0x02, 0x00, 0x6F]); // Yr (2.433 dots/mm)
        payload.push(0x09); // AW = 9 dots
        payload.push(0x0C); // AH = 12 dots
        payload.push((cap >> 8) as u8);
        payload.push((cap & 0xFF) as u8);

        Self::append_structured_field(out, QR_USABLE_AREA, &payload);
    }

    /// Query Reply Alphanumeric Partitions (0x84)
    #[allow(clippy::cast_possible_truncation)]
    pub fn append_alpha_part(&self, out: &mut Vec<u8>) {
        let (rows, cols) = self.model.alternate_dimensions();
        let cap = (rows as usize).saturating_mul(cols as usize) as u16;

        let payload = vec![0x00, (cap >> 8) as u8, (cap & 0xFF) as u8, 0x00];

        Self::append_structured_field(out, QR_ALPHA_PART, &payload);
    }

    /// Query Reply Character Sets (0x85)
    pub fn append_charsets(&self, out: &mut Vec<u8>) {
        let cgcsgid = self.codepage.cgcsgid();

        let mut payload = Vec::with_capacity(23);
        payload.push(0x82); // GE present, CGCSGID present
        payload.push(0x00); // flags 2
        payload.push(0x09); // SDW = 9
        payload.push(0x0C); // SDH = 12
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Load PS format
        payload.push(0x07); // DL = 7 bytes descriptor length

        // Set 0: Base Character Set
        payload.push(0x00); // SET ID = 0
        payload.push(0x10); // FLAGS: non-loadable, single-plane, single-byte, no compare
        payload.push(0x00); // LCID = 0
        payload.push((cgcsgid >> 24) as u8);
        payload.push(((cgcsgid >> 16) & 0xFF) as u8);
        payload.push(((cgcsgid >> 8) & 0xFF) as u8);
        payload.push((cgcsgid & 0xFF) as u8);

        // Set 1: APL2 Character Set
        payload.push(0x01); // SET ID = 1
        payload.push(0x00); // FLAGS
        payload.push(0xF1); // LCID = 0xF1
        payload.extend_from_slice(&[0x03, 0xC3, 0x01, 0x36]); // CGCSGID 3179 APL2

        Self::append_structured_field(out, QR_CHARSETS, &payload);
    }

    /// Query Reply Color (0x86)
    pub fn append_color(&self, out: &mut Vec<u8>) {
        let mut payload = Vec::with_capacity(34);
        payload.push(0x00); // flags
        payload.push(0x10); // 16 colors
        payload.push(0x00); // default color attr
        payload.push(0xF4); // default color = Green (0xF4)

        // 15 color attribute pairs: 0xF1..=0xFF
        for code in 0xF1..=0xFF_u8 {
            payload.push(code);
            if self.color_3279 {
                payload.push(code);
            } else {
                payload.push(0x00);
            }
        }

        Self::append_structured_field(out, QR_COLOR, &payload);
    }

    /// Query Reply Highlighting (0x87)
    pub fn append_highlighting(&self, out: &mut Vec<u8>) {
        let payload = [
            0x05, // 5 pairs
            XAH_DEFAULT,
            XAH_NORMAL, // 0x00, 0xF0
            XAH_BLINK,
            XAH_BLINK, // 0xF1, 0xF1
            XAH_REVERSE,
            XAH_REVERSE, // 0xF2, 0xF2
            XAH_UNDERSCORE,
            XAH_UNDERSCORE, // 0xF4, 0xF4
            XAH_INTENSIFY,
            XAH_INTENSIFY, // 0xF8, 0xF8
        ];
        Self::append_structured_field(out, QR_HIGHLIGHTING, &payload);
    }

    /// Query Reply Reply Modes (0x88)
    pub fn append_reply_modes(&self, out: &mut Vec<u8>) {
        let payload = [SF_SRM_FIELD, SF_SRM_XFIELD, SF_SRM_CHAR];
        Self::append_structured_field(out, QR_REPLY_MODES, &payload);
    }

    /// Query Reply RPQ Names (0xA1), as `x3270` `do_qr_rpqnames` with no optional terms:
    /// device type 0 and model 0 ("all"), then a length byte and the program name in EBCDIC.
    /// The optional self-defining terms of `x3270` (user name, IP address, time stamp, time
    /// zone, version) are not sent, so no operator or workstation data reaches the host.
    pub fn append_rpq_names(&self, out: &mut Vec<u8>) {
        let name: Vec<u8> = RPQ_PROGRAM_NAME
            .chars()
            .filter_map(|c| self.codepage.char_to_ebcdic(c))
            .collect();
        let mut payload = Vec::with_capacity(name.len().saturating_add(9));
        payload.extend_from_slice(&[0, 0, 0, 0]); // device type: all
        payload.extend_from_slice(&[0, 0, 0, 0]); // model: all
                                                  // Length of the RPQ name data, including this byte.
        payload.push(u8::try_from(name.len().saturating_add(1)).unwrap_or(u8::MAX));
        payload.extend_from_slice(&name);
        Self::append_structured_field(out, QR_RPQNAMES, &payload);
    }

    /// Query Reply Implicit Partition (0xA6)
    pub fn append_implicit_partition(&self, out: &mut Vec<u8>) {
        let (alt_rows, alt_cols) = self.model.alternate_dimensions();
        let (def_rows, def_cols) = (24_u16, 80_u16);

        let mut payload = Vec::with_capacity(13);
        payload.extend_from_slice(&[0x00, 0x00]); // reserved
        payload.push(0x0B); // length of display size
        payload.push(0x01); // implicit partition size
        payload.push(0x00); // reserved
        payload.push((def_cols >> 8) as u8);
        payload.push((def_cols & 0xFF) as u8);
        payload.push((def_rows >> 8) as u8);
        payload.push((def_rows & 0xFF) as u8);
        payload.push((alt_cols >> 8) as u8);
        payload.push((alt_cols & 0xFF) as u8);
        payload.push((alt_rows >> 8) as u8);
        payload.push((alt_rows & 0xFF) as u8);

        Self::append_structured_field(out, QR_IMP_PART, &payload);
    }

    /// Query Reply Null (0xFF)
    pub fn append_null(out: &mut Vec<u8>) {
        Self::append_structured_field(out, QR_NULL, &[]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebcdic::CP037;

    #[test]
    fn test_parse_read_partition_query_all() {
        let raw = [0x00, 0x04, 0x01, 0xFF, 0x02];
        assert_eq!(parse_read_partition(&raw), Ok(QueryRequest::QueryAll));
    }

    #[test]
    fn test_parse_read_partition_query_list() {
        let raw = [0x01, 0xFF, 0x03, 0x00, 0x81, 0x86];
        assert_eq!(
            parse_read_partition(&raw),
            Ok(QueryRequest::QueryList(vec![0x81, 0x86]))
        );
    }

    #[test]
    fn test_query_reply_summary_and_null() {
        let builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);
        let resp = builder.build_list(&[0x99]); // unsupported code
        assert_eq!(resp, vec![AID_SF, 0x00, 0x04, 0x81, 0xFF]);
    }
}
