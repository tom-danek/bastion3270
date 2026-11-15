//! TN3270E protocol structures, header serialization, and BIND image parsing (RFC 2355).

use crate::ebcdic::{CodePage, CP037};
use crate::model::{BindSizes, ScreenSize, TerminalModel};
use crate::telnet::TelnetError;

/// Size of the standard TN3270E transmission header in bytes.
pub const EH_SIZE: usize = 5;

/// BIND RU opcode in SNA data stream.
pub const BIND_RU: u8 = 0x31;

/// Offsets into SNA BIND RU.
pub const BIND_OFF_RD: usize = 20;
pub const BIND_OFF_CD: usize = 21;
pub const BIND_OFF_RA: usize = 22;
pub const BIND_OFF_CA: usize = 23;
pub const BIND_OFF_SSIZE: usize = 24;
pub const BIND_OFF_PLU_NAME_LEN: usize = 27;
pub const BIND_OFF_PLU_NAME: usize = 28;

/// TN3270E Header Data Types (RFC 2355 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tn3270eDataType {
    /// 3270 display data stream (0x00).
    Data3270 = 0x00,
    /// SCS printer data stream (0x01).
    ScsData = 0x01,
    /// Response to previous transmission (0x02).
    Response = 0x02,
    /// SNA BIND RU image (0x03).
    BindImage = 0x03,
    /// SNA UNBIND RU image (0x04).
    Unbind = 0x04,
    /// NVT ASCII data stream (0x05).
    NvtData = 0x05,
    /// Request to send data (0x06).
    Request = 0x06,
    /// SSCP-LU session data (0x07).
    SscpLuData = 0x07,
    /// Print End of Job (0x08).
    PrintEoj = 0x08,
    /// Bid request (0x09).
    Bid = 0x09,
}

impl Tn3270eDataType {
    /// Decodes a raw byte code into [`Tn3270eDataType`].
    ///
    /// # Errors
    /// Returns [`TelnetError::InvalidDataType`] if `val` is not a recognized data type.
    pub const fn from_u8(val: u8) -> Result<Self, TelnetError> {
        match val {
            0x00 => Ok(Self::Data3270),
            0x01 => Ok(Self::ScsData),
            0x02 => Ok(Self::Response),
            0x03 => Ok(Self::BindImage),
            0x04 => Ok(Self::Unbind),
            0x05 => Ok(Self::NvtData),
            0x06 => Ok(Self::Request),
            0x07 => Ok(Self::SscpLuData),
            0x08 => Ok(Self::PrintEoj),
            0x09 => Ok(Self::Bid),
            other => Err(TelnetError::InvalidDataType(other)),
        }
    }

    /// Converts this data type to its raw byte representation.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

// Header Request Flags (RFC 2355 §8)
/// Request flag: Error condition cleared (0x00).
pub const TN3270E_RQF_ERR_COND_CLEARED: u8 = 0x00;
/// Request flag: Send data (0x01).
pub const TN3270E_RQF_SEND_DATA: u8 = 0x01;
/// Request flag: Keyboard restore (0x02).
pub const TN3270E_RQF_KEYBOARD_RESTORE: u8 = 0x02;
/// Request flag: Signal (0x04).
pub const TN3270E_RQF_SIGNAL: u8 = 0x04;

// Header Response Flags - Host to Client (RFC 2355 §8)
/// Response flag: No response requested (0x00).
pub const TN3270E_RSF_NO_RESPONSE: u8 = 0x00;
/// Response flag: Error response requested (0x01).
pub const TN3270E_RSF_ERROR_RESPONSE: u8 = 0x01;
/// Response flag: Always response requested (0x02).
pub const TN3270E_RSF_ALWAYS_RESPONSE: u8 = 0x02;

// Header Response Flags - Client to Host in RESPONSE data type (RFC 2355 §8)
/// Response flag: Positive response (0x00).
pub const TN3270E_RSF_POSITIVE_RESPONSE: u8 = 0x00;
/// Response flag: Negative response (0x01).
pub const TN3270E_RSF_NEGATIVE_RESPONSE: u8 = 0x01;
/// Response flag: SNA sense data included (0x02).
pub const TN3270E_RSF_SNA_SENSE: u8 = 0x02;

// Header Response Codes (Payload Byte)
/// Positive response code: Device End (0x00).
pub const TN3270E_POS_DEVICE_END: u8 = 0x00;
/// Negative response code: Command Reject (0x00).
pub const TN3270E_NEG_COMMAND_REJECT: u8 = 0x00;
/// Negative response code: Intervention Required (0x01).
pub const TN3270E_NEG_INTERVENTION_REQUIRED: u8 = 0x01;
/// Negative response code: Operation Check (0x02).
pub const TN3270E_NEG_OPERATION_CHECK: u8 = 0x02;
/// Negative response code: Component Disconnected (0x03).
pub const TN3270E_NEG_COMPONENT_DISCONNECTED: u8 = 0x03;

// TN3270E Subnegotiation Operations (RFC 2355 §4–§5)
/// TN3270E operation: ASSOCIATE (0).
pub const TN3270E_OP_ASSOCIATE: u8 = 0;
/// TN3270E operation: CONNECT (1).
pub const TN3270E_OP_CONNECT: u8 = 1;
/// TN3270E operation: DEVICE-TYPE (2).
pub const TN3270E_OP_DEVICE_TYPE: u8 = 2;
/// TN3270E operation: FUNCTIONS (3).
pub const TN3270E_OP_FUNCTIONS: u8 = 3;
/// TN3270E operation: IS (4).
pub const TN3270E_OP_IS: u8 = 4;
/// TN3270E operation: REASON (5).
pub const TN3270E_OP_REASON: u8 = 5;
/// TN3270E operation: REJECT (6).
pub const TN3270E_OP_REJECT: u8 = 6;
/// TN3270E operation: REQUEST (7).
pub const TN3270E_OP_REQUEST: u8 = 7;
/// TN3270E operation: SEND (8).
pub const TN3270E_OP_SEND: u8 = 8;

// TN3270E Functions (RFC 2355 §5)
/// TN3270E function: BIND-IMAGE (0).
pub const TN3270E_FUNC_BIND_IMAGE: u8 = 0;
/// TN3270E function: DATA-STREAM-CTL (1).
pub const TN3270E_FUNC_DATA_STREAM_CTL: u8 = 1;
/// TN3270E function: RESPONSES (2).
pub const TN3270E_FUNC_RESPONSES: u8 = 2;
/// TN3270E function: SCS-CTL-CODES (3).
pub const TN3270E_FUNC_SCS_CTL_CODES: u8 = 3;
/// TN3270E function: SYSREQ (4).
pub const TN3270E_FUNC_SYSREQ: u8 = 4;

/// Represents negotiated TN3270E functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tn3270eFunctions {
    /// BIND-IMAGE function supported.
    pub bind_image: bool,
    /// RESPONSES function supported.
    pub responses: bool,
    /// SYSREQ function supported.
    pub sysreq: bool,
}

impl Tn3270eFunctions {
    /// The functions this client asks for at the start of every TN3270E negotiation
    /// (`x3270` `tn3270e_init`): BIND-IMAGE, RESPONSES and SYSREQ.
    pub const REQUESTED: Self = Self {
        bind_image: true,
        responses: true,
        sysreq: true,
    };

    /// Decodes the function list of a `FUNCTIONS REQUEST` / `FUNCTIONS IS` subnegotiation.
    ///
    /// Returns the functions this client knows, and `true` as the second value if the list
    /// also named a function it cannot perform (DATA-STREAM-CTL, SCS-CTL-CODES, an unknown
    /// code, ...). Such a list is never a subset of what the client requested.
    #[must_use]
    pub fn decode(codes: &[u8]) -> (Self, bool) {
        let mut funcs = Self::default();
        let mut foreign = false;
        for &code in codes {
            match code {
                TN3270E_FUNC_BIND_IMAGE => funcs.bind_image = true,
                TN3270E_FUNC_RESPONSES => funcs.responses = true,
                TN3270E_FUNC_SYSREQ => funcs.sysreq = true,
                _ => foreign = true,
            }
        }
        (funcs, foreign)
    }

    /// Encodes the set as a function list in ascending code order, as `x3270`
    /// `tn3270e_subneg_send` does.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        [
            (self.bind_image, TN3270E_FUNC_BIND_IMAGE),
            (self.responses, TN3270E_FUNC_RESPONSES),
            (self.sysreq, TN3270E_FUNC_SYSREQ),
        ]
        .into_iter()
        .filter_map(|(on, code)| on.then_some(code))
        .collect()
    }

    /// `true` if every function in `self` is also in `other` (`x3270` `b8_none_added`).
    #[must_use]
    pub const fn is_subset_of(self, other: Self) -> bool {
        (!self.bind_image || other.bind_image)
            && (!self.responses || other.responses)
            && (!self.sysreq || other.sysreq)
    }

    /// The functions present in both sets (`x3270` `b8_and`).
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self {
            bind_image: self.bind_image && other.bind_image,
            responses: self.responses && other.responses,
            sysreq: self.sysreq && other.sysreq,
        }
    }
}

// TN3270E DEVICE-TYPE REJECT reason codes (RFC 2355 §7.1).
/// Reject reason: CONN-PARTNER (0).
pub const TN3270E_REASON_CONN_PARTNER: u8 = 0;
/// Reject reason: DEVICE-IN-USE (1).
pub const TN3270E_REASON_DEVICE_IN_USE: u8 = 1;
/// Reject reason: INV-ASSOCIATE (2).
pub const TN3270E_REASON_INV_ASSOCIATE: u8 = 2;
/// Reject reason: INV-NAME (3).
pub const TN3270E_REASON_INV_NAME: u8 = 3;
/// Reject reason: INV-DEVICE-TYPE (4).
pub const TN3270E_REASON_INV_DEVICE_TYPE: u8 = 4;
/// Reject reason: TYPE-NAME-ERROR (5).
pub const TN3270E_REASON_TYPE_NAME_ERROR: u8 = 5;
/// Reject reason: UNKNOWN-ERROR (6).
pub const TN3270E_REASON_UNKNOWN_ERROR: u8 = 6;
/// Reject reason: UNSUPPORTED-REQ (7).
pub const TN3270E_REASON_UNSUPPORTED_REQ: u8 = 7;

/// Why the client abandoned TN3270E and fell back to plain TN3270 (`x3270` `backoff_tn3270e`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tn3270eBackoff {
    /// The host answered `DEVICE-TYPE REJECT` with the given reason code.
    DeviceTypeRejected {
        /// RFC 2355 reason code (`TN3270E_REASON_*`).
        reason: Option<u8>,
    },
    /// The host's `FUNCTIONS IS` named functions the client never requested.
    FunctionsAdded,
}

impl core::fmt::Display for Tn3270eBackoff {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DeviceTypeRejected { reason } => {
                let name = match reason {
                    Some(TN3270E_REASON_CONN_PARTNER) => "CONN-PARTNER",
                    Some(TN3270E_REASON_DEVICE_IN_USE) => "DEVICE-IN-USE",
                    Some(TN3270E_REASON_INV_ASSOCIATE) => "INV-ASSOCIATE",
                    Some(TN3270E_REASON_INV_NAME) => "INV-NAME",
                    Some(TN3270E_REASON_INV_DEVICE_TYPE) => "INV-DEVICE-TYPE",
                    Some(TN3270E_REASON_TYPE_NAME_ERROR) => "TYPE-NAME-ERROR",
                    Some(TN3270E_REASON_UNKNOWN_ERROR) => "UNKNOWN-ERROR",
                    Some(TN3270E_REASON_UNSUPPORTED_REQ) => "UNSUPPORTED-REQ",
                    Some(_) => "unknown reason",
                    None => "no reason given",
                };
                write!(f, "host rejected the TN3270E device type ({name})")
            }
            Self::FunctionsAdded => {
                write!(f, "host added TN3270E functions that were not requested")
            }
        }
    }
}

/// 5-byte TN3270E Transmission Header (RFC 2355 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tn3270eHeader {
    /// Data type code.
    pub data_type: Tn3270eDataType,
    /// Request flag.
    pub request_flag: u8,
    /// Response flag.
    pub response_flag: u8,
    /// 16-bit sequence number (big-endian).
    pub seq_number: u16,
}

impl Tn3270eHeader {
    /// Parses a 5-byte TN3270E header from the start of `slice`.
    ///
    /// # Errors
    /// Returns [`TelnetError::TruncatedHeader`] if `slice.len() < 5`, or
    /// [`TelnetError::InvalidDataType`] if the first byte is unknown.
    pub fn parse(slice: &[u8]) -> Result<Self, TelnetError> {
        let b0 = slice.first().copied().ok_or(TelnetError::TruncatedHeader {
            needed: 5,
            available: slice.len(),
        })?;
        let b1 = slice.get(1).copied().ok_or(TelnetError::TruncatedHeader {
            needed: 5,
            available: slice.len(),
        })?;
        let b2 = slice.get(2).copied().ok_or(TelnetError::TruncatedHeader {
            needed: 5,
            available: slice.len(),
        })?;
        let b3 = slice.get(3).copied().ok_or(TelnetError::TruncatedHeader {
            needed: 5,
            available: slice.len(),
        })?;
        let b4 = slice.get(4).copied().ok_or(TelnetError::TruncatedHeader {
            needed: 5,
            available: slice.len(),
        })?;

        let data_type = Tn3270eDataType::from_u8(b0)?;
        let seq_number = u16::from_be_bytes([b3, b4]);

        Ok(Self {
            data_type,
            request_flag: b1,
            response_flag: b2,
            seq_number,
        })
    }

    /// Serializes this header into a 5-byte big-endian array.
    #[inline]
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 5] {
        let [s0, s1] = self.seq_number.to_be_bytes();
        [
            self.data_type.as_u8(),
            self.request_flag,
            self.response_flag,
            s0,
            s1,
        ]
    }
}

/// Extracted screen geometry and session metadata from an SNA BIND RU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindImageInfo {
    /// Screen sizes requested by the BIND; `None` if the BIND carries no (or an unknown)
    /// screen size byte, in which case the current sizes stay (`x3270` `bind_state = 0`).
    pub sizes: Option<BindSizes>,
    /// Primary Logical Unit name, if extracted from the BIND RU.
    pub plu_name: Option<String>,
}

/// Longest PLU name `x3270` takes from a BIND (`process_bind`).
const MAX_PLU_NAME: usize = 8;

impl BindImageInfo {
    /// Parses screen sizes and PLU name from an SNA BIND RU, following `x3270`
    /// `process_bind()`. The screen size byte (offset 24) selects:
    ///
    /// | Byte          | Default size | Alternate size      |
    /// | :------------ | :----------- | :------------------ |
    /// | `0x00`/`0x02` | 24x80        | 24x80               |
    /// | `0x03`        | 24x80        | the model size      |
    /// | `0x7E`        | RD x CD      | RD x CD             |
    /// | `0x7F`        | RD x CD      | RA x CA             |
    ///
    /// The sizes are not validated here; [`crate::PresentationSpace::apply_bind`] rejects
    /// sizes the terminal cannot show.
    ///
    /// # Errors
    /// Returns [`TelnetError::InvalidBindRu`] if the buffer is empty or the opcode is not `0x31`.
    pub fn parse(ru: &[u8], model: TerminalModel) -> Result<Self, TelnetError> {
        let first = ru
            .first()
            .copied()
            .ok_or(TelnetError::InvalidBindRu("empty BIND RU"))?;
        if first != BIND_RU {
            return Err(TelnetError::InvalidBindRu(
                "invalid BIND RU opcode (expected 0x31)",
            ));
        }

        let size_at = |r: usize, c: usize| -> Option<ScreenSize> {
            Some(ScreenSize::new(
                u16::from(*ru.get(r)?),
                u16::from(*ru.get(c)?),
            ))
        };
        let sizes = match ru.get(BIND_OFF_SSIZE) {
            Some(0x00 | 0x02) => Some(BindSizes {
                default: ScreenSize::DEFAULT,
                alternate: ScreenSize::DEFAULT,
            }),
            Some(0x03) => Some(BindSizes {
                default: ScreenSize::DEFAULT,
                alternate: model.max_size(),
            }),
            Some(0x7E) => size_at(BIND_OFF_RD, BIND_OFF_CD).map(|size| BindSizes {
                default: size,
                alternate: size,
            }),
            Some(0x7F) => size_at(BIND_OFF_RD, BIND_OFF_CD)
                .zip(size_at(BIND_OFF_RA, BIND_OFF_CA))
                .map(|(default, alternate)| BindSizes { default, alternate }),
            _ => None,
        };

        Ok(Self {
            sizes,
            plu_name: Self::plu_name(ru),
        })
    }

    /// The PLU name: present only if the RU extends beyond it (`x3270`:
    /// `buflen > BIND_OFF_PLU_NAME + namelen`), at most 8 bytes, EBCDIC.
    fn plu_name(ru: &[u8]) -> Option<String> {
        let nlen = usize::from(*ru.get(BIND_OFF_PLU_NAME_LEN)?);
        if nlen == 0 || ru.len() <= BIND_OFF_PLU_NAME.checked_add(nlen)? {
            return None;
        }
        let name_end = BIND_OFF_PLU_NAME.checked_add(nlen.min(MAX_PLU_NAME))?;
        let name_bytes = ru.get(BIND_OFF_PLU_NAME..name_end)?;
        let name: String = name_bytes
            .iter()
            .filter_map(|&ebc| CP037.ebcdic_to_char(ebc))
            .collect();
        let trimmed = name.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tn3270e_header_roundtrip() {
        let hdr = Tn3270eHeader {
            data_type: Tn3270eDataType::Data3270,
            request_flag: TN3270E_RQF_SEND_DATA,
            response_flag: TN3270E_RSF_ALWAYS_RESPONSE,
            seq_number: 0x1234,
        };
        let bytes = hdr.to_bytes();
        assert_eq!(bytes, [0x00, 0x01, 0x02, 0x12, 0x34]);

        assert_eq!(Tn3270eHeader::parse(&bytes), Ok(hdr));
    }

    #[test]
    fn test_bind_image_info_ssize_03() {
        let mut ru = vec![0x00; 35];
        if let Some(first) = ru.first_mut() {
            *first = BIND_RU;
        }
        if let Some(ssize) = ru.get_mut(BIND_OFF_SSIZE) {
            *ssize = 0x03;
        }
        // PLU name length 4: "CICS" in EBCDIC CP037: [0xC3, 0xC9, 0xC3, 0xE2]
        if let Some(nl) = ru.get_mut(BIND_OFF_PLU_NAME_LEN) {
            *nl = 4;
        }
        if let Some(slice) = ru.get_mut(BIND_OFF_PLU_NAME..BIND_OFF_PLU_NAME + 4) {
            slice.copy_from_slice(&[0xC3, 0xC9, 0xC3, 0xE2]);
        }

        assert_eq!(
            BindImageInfo::parse(&ru, TerminalModel::Model4),
            Ok(BindImageInfo {
                sizes: Some(BindSizes {
                    default: ScreenSize::new(24, 80),
                    alternate: ScreenSize::new(43, 80),
                }),
                plu_name: Some("CICS".to_string()),
            })
        );
    }
}
