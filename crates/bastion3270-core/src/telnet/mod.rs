//! Telnet and TN3270E protocol state engine adhering to RFC 854, RFC 885, RFC 1091, and RFC 2355.
//!
//! Provides pure-Rust, deterministic byte-stream parsing, option negotiation, IAC escaping,
//! TN3270E header validation, response generation, and 3270 record framing.

pub mod iac;
pub mod state_machine;
pub mod tn3270e;

use core::fmt;

pub use iac::{
    escape_iac, format_do, format_dont, format_will, format_wont, TelnetOption, AO, AYT, BREAK, DM,
    DO, DONT, EC, EL, EOR, GA, IAC, IP, NOP, SB, SE, TELOPT_BINARY, TELOPT_ECHO, TELOPT_EOR,
    TELOPT_SGA, TELOPT_TM, TELOPT_TN3270E, TELOPT_TTYPE, TELQUAL_IS, TELQUAL_SEND, WILL, WONT,
};
pub use state_machine::{
    AttentionRoute, SessionSubmode, TelnetState, TelnetStateMachine, MAX_OUTBOUND_QUEUE_BYTES,
    MAX_RECORD_BYTES, MAX_SUBNEG_BYTES,
};
pub use tn3270e::{
    BindImageInfo, Tn3270eBackoff, Tn3270eDataType, Tn3270eFunctions, Tn3270eHeader, BIND_RU,
    EH_SIZE, TN3270E_FUNC_BIND_IMAGE, TN3270E_FUNC_DATA_STREAM_CTL, TN3270E_FUNC_RESPONSES,
    TN3270E_FUNC_SCS_CTL_CODES, TN3270E_FUNC_SYSREQ, TN3270E_NEG_COMMAND_REJECT,
    TN3270E_NEG_COMPONENT_DISCONNECTED, TN3270E_NEG_INTERVENTION_REQUIRED,
    TN3270E_NEG_OPERATION_CHECK, TN3270E_OP_ASSOCIATE, TN3270E_OP_CONNECT, TN3270E_OP_DEVICE_TYPE,
    TN3270E_OP_FUNCTIONS, TN3270E_OP_IS, TN3270E_OP_REASON, TN3270E_OP_REJECT, TN3270E_OP_REQUEST,
    TN3270E_OP_SEND, TN3270E_POS_DEVICE_END, TN3270E_REASON_CONN_PARTNER,
    TN3270E_REASON_DEVICE_IN_USE, TN3270E_REASON_INV_ASSOCIATE, TN3270E_REASON_INV_DEVICE_TYPE,
    TN3270E_REASON_INV_NAME, TN3270E_REASON_TYPE_NAME_ERROR, TN3270E_REASON_UNKNOWN_ERROR,
    TN3270E_REASON_UNSUPPORTED_REQ, TN3270E_RQF_ERR_COND_CLEARED, TN3270E_RQF_KEYBOARD_RESTORE,
    TN3270E_RQF_SEND_DATA, TN3270E_RQF_SIGNAL, TN3270E_RSF_ALWAYS_RESPONSE,
    TN3270E_RSF_ERROR_RESPONSE, TN3270E_RSF_NEGATIVE_RESPONSE, TN3270E_RSF_NO_RESPONSE,
    TN3270E_RSF_POSITIVE_RESPONSE, TN3270E_RSF_SNA_SENSE,
};

/// What the host is currently exchanging with the terminal (`x3270` connection states
/// `CONNECTED_3270` / `CONNECTED_TN3270E`, `CONNECTED_SSCP`, `CONNECTED_E_NVT`,
/// `CONNECTED_UNBOUND`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostMode {
    /// No 3270 mode yet (negotiation in progress, or plain NVT).
    #[default]
    Negotiating,
    /// TN3270E without a BIND yet: no data flows until the host binds the session.
    Unbound,
    /// 3270 data stream (plain TN3270, or a TN3270E session in 3270 mode).
    Data3270,
    /// SSCP-LU data: unformatted text from the SNA control point (for example the VTAM USS
    /// logon screen).
    SscpLu,
    /// TN3270E NVT data: line-mode ASCII text.
    Nvt,
}

/// High-level events emitted by the [`TelnetStateMachine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelnetEvent {
    /// In traditional TN3270 mode, a complete 3270 data record terminated by `IAC EOR`.
    DataRecord(Vec<u8>),
    /// In TN3270E mode, a complete frame with peeled 5-byte header and data payload.
    Tn3270eRecord {
        /// Peeled 5-byte TN3270E transmission header.
        header: Tn3270eHeader,
        /// Remaining data stream payload.
        payload: Vec<u8>,
    },
    /// Host initiated session binding with SNA BIND RU parameters.
    BindImage(BindImageInfo),
    /// Host initiated session unbinding with reason code.
    Unbind(u8),
    /// The connection entered a 3270 mode: TN3270E once its functions are agreed, or plain
    /// TN3270 once BINARY, EOR and TERMINAL-TYPE are in effect. Reported again when the mode
    /// changes, e.g. when the host negotiates TN3270E off and plain TN3270 takes over.
    NegotiationComplete {
        /// True if TN3270E enhancements were negotiated; false if fallen back to basic TN3270.
        tn3270e: bool,
        /// Agreed TN3270E functions.
        functions: Tn3270eFunctions,
        /// Host-assigned Logical Unit name, if any.
        assigned_lu: Option<String>,
    },
    /// NVT (line-mode ASCII) text arrived: before a 3270 mode is in effect, or as TN3270E
    /// NVT-DATA.
    NvtData {
        /// The text bytes as received.
        data: Vec<u8>,
        /// Sequence number of a TN3270E NVT-DATA record that asked for ALWAYS-RESPONSE; the
        /// session owes it a positive response (`x3270` `process_eor`).
        ack: Option<u16>,
    },
    /// TN3270E SSCP-LU data arrived (no response is ever owed for it).
    SscpLuData(Vec<u8>),
    /// A TN3270E record switched the host mode (`x3270` `check_in3270` after
    /// `process_eor`); reported just before the record that caused it.
    HostModeChanged(HostMode),
    /// A received record was dropped (malformed TN3270E header, unknown data type, invalid
    /// BIND image, or larger than the record limit). The session continues; the error says why.
    RecordDiscarded(TelnetError),
    /// The client abandoned TN3270E (sent `WONT TN3270E`) and continues with plain TN3270
    /// negotiation; the reason says why.
    Tn3270eBackoff(Tn3270eBackoff),
}

/// Errors returned by the Telnet and TN3270E state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelnetError {
    /// TN3270E header had fewer bytes than required 5 bytes.
    TruncatedHeader {
        /// Number of bytes needed.
        needed: usize,
        /// Number of bytes available.
        available: usize,
    },
    /// Unrecognized TN3270E header data type code.
    InvalidDataType(u8),
    /// Unrecognized TN3270E subnegotiation operation code.
    InvalidOperation(u8),
    /// An incoming data record exceeded maximum allowed frame size (64 KiB).
    FrameTooLarge {
        /// Encountered byte count.
        size: usize,
        /// Maximum allowed limit.
        max: usize,
    },
    /// Subnegotiation payload exceeded allowed capacity (1 KiB).
    SubnegotiationTooLarge {
        /// Encountered byte count.
        size: usize,
        /// Maximum allowed limit.
        max: usize,
    },
    /// Outbound response queue exceeded allowed capacity (128 KiB).
    OutboundQueueFull {
        /// Total bytes needed.
        size: usize,
        /// Maximum allowed limit.
        max: usize,
    },
    /// Malformed or invalid subnegotiation payload.
    InvalidSubnegotiation(&'static str),
    /// SNA BIND RU parsing failure.
    InvalidBindRu(&'static str),
    /// A TN3270E record whose data type (code given) needs a function that was not negotiated
    /// (BIND-IMAGE / UNBIND without BIND-IMAGE, BID without CONTENTION-RESOLUTION).
    FunctionNotNegotiated(u8),
    /// An end of record arrived while no 3270 mode is in effect (NVT or negotiation still in
    /// progress); the record is dropped (`x3270` "EOR received when not in 3270 mode").
    NotIn3270Mode,
}

impl fmt::Display for TelnetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { needed, available } => {
                write!(
                    f,
                    "truncated TN3270E header: needed {needed} bytes, got {available}"
                )
            }
            Self::InvalidDataType(dt) => write!(f, "invalid TN3270E data type code: 0x{dt:02X}"),
            Self::InvalidOperation(op) => write!(f, "invalid TN3270E operation code: {op}"),
            Self::FrameTooLarge { size, max } => {
                write!(
                    f,
                    "frame exceeded maximum allowed size: {size} > {max} bytes"
                )
            }
            Self::SubnegotiationTooLarge { size, max } => {
                write!(
                    f,
                    "subnegotiation buffer exceeded limit: {size} > {max} bytes"
                )
            }
            Self::OutboundQueueFull { size, max } => {
                write!(f, "outbound queue exceeded capacity: {size} > {max} bytes")
            }
            Self::InvalidSubnegotiation(msg) => write!(f, "invalid subnegotiation: {msg}"),
            Self::InvalidBindRu(msg) => write!(f, "invalid BIND image RU: {msg}"),
            Self::FunctionNotNegotiated(dt) => write!(
                f,
                "TN3270E data type 0x{dt:02X} needs a function that was not negotiated"
            ),
            Self::NotIn3270Mode => write!(f, "end of record received when not in 3270 mode"),
        }
    }
}

impl std::error::Error for TelnetError {}
