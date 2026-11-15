//! # bastion3270-core
//!
//! Pure-Rust implementation of the IBM 3270 Data Stream, TN3270/TN3270E
//! state machine, modular EBCDIC code pages, and Zero-Trust `SafeCell` / `PresentationSpace`.
//!
//! ## Core Design Principles
//! - **Zero-Panic & Memory Safe:** Forbids `unsafe`, `.unwrap()`, `.expect()`, and unchecked slice
//!   indexing. Every fallible operation returns a typed `Result`.
//! - **Zero-Trust Screen Projection:** `NonDisplay` (hidden/password) fields are masked inside
//!   [`screen::PresentationSpace::safe_cell_at`] before leaving the core engine.

// Silent integer wrap-around in a protocol parser is a logic error: every arithmetic operation
// must state its overflow semantics (`checked_*`, `saturating_*`, `wrapping_*` or `NonZero`).
#![deny(clippy::arithmetic_side_effects)]

pub mod address;
pub mod datastream;
pub mod ebcdic;
pub mod field;
pub mod keyboard;
pub mod model;
pub mod safe_view;
pub mod screen;
pub mod telnet;
pub mod wsf;

pub use address::{AddressError, BufferAddress, CODE_TABLE};
pub use datastream::{
    command::Command,
    order::{
        is_format_control, is_order, FC_CR, FC_DUP, FC_EM, FC_EO, FC_FF, FC_FM, FC_LF, FC_NL,
        FC_NULL, FC_SUB, ORDER_EUA, ORDER_GE, ORDER_IC, ORDER_MF, ORDER_PT, ORDER_RA, ORDER_SA,
        ORDER_SBA, ORDER_SF, ORDER_SFE,
    },
    parser::DataStreamParser,
    reader::ByteReader,
    response::{build_read_buffer, build_read_modified, is_short_read_aid},
    wcc::WriteControlCharacter,
    CommandResult, DatastreamError,
};
pub use ebcdic::{apl_to_char, CodePage, CodePageId, EncodingError, StaticCodePage, CP037, IBM870};
pub use field::{
    CharacterSet, Color3270, ExtendedAttributes, FieldAttribute, FieldIntensity, Highlight3270,
};
pub use keyboard::{
    ActionKey, AidKey, AttentionKey, KeyInput, KeyOutcome, KeyboardError, KeyboardLock,
    KeyboardOptions, KeyboardState, LockReason, OperatorError, PasteEnd, PasteOutcome,
    VirtualKeyboard,
};
pub use model::{BindSizes, ModelError, ScreenSize, TerminalModel};
pub use safe_view::{SafeCell, SafeScreenView, SafeViewError};
pub use screen::{
    BindSizeError, Cell, CharacterReplyAttrs, PresentationSpace, ReplyMode, ScreenError,
};
pub use telnet::{
    AttentionRoute, BindImageInfo, HostMode, SessionSubmode, TelnetError, TelnetEvent,
    TelnetOption, TelnetState, TelnetStateMachine, Tn3270eDataType, Tn3270eFunctions,
    Tn3270eHeader,
};
pub use wsf::{
    parse_read_partition, QueryReplyBuilder, QueryRequest, WsfError, AID_SF, QR_ALPHA_PART,
    QR_CHARSETS, QR_COLOR, QR_HIGHLIGHTING, QR_IMP_PART, QR_NULL, QR_REPLY_MODES, QR_SUMMARY,
    QR_USABLE_AREA, SFID_QREPLY, SF_READ_PART,
};
