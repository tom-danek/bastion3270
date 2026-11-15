//! # bastion3270-net
//!
//! Asynchronous TCP and TLS 1.2/1.3 (AT-TLS) transport and session layer for connecting
//! IBM z/OS mainframes and Hercules emulators with `bastion3270-core`.
//!
//! ## Core Architecture
//! - [`error`]: Typed error hierarchy ([`NetError`]) and [`Result`] alias adhering to the
//!   workspace zero-panic policy.
//! - [`profile`]: Connection profile schema ([`ConnectionProfile`]), TOML serialization/deserialization,
//!   precedence-based `BASTION3270_*` environment variable overrides, and fluent builder.
//! - [`transport`]: Asynchronous TCP and TLS 1.2/1.3 transport streams, timeout guards, and
//!   custom CA certificate store loader.
//! - `session`: Session coordinator actor bridging network streams with `bastion3270-core`
//!   state machines, bounded backpressure channels, autonomous TN3270E responses, WSF Query Replies,
//!   and Zero-Trust [`bastion3270_core::SafeScreenView`] projection.

#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
// Silent integer wrap-around (or an `Instant + Duration` overflow panic) is a logic error: every
// arithmetic operation must state its overflow semantics.
#![deny(clippy::arithmetic_side_effects)]

pub mod error;
pub mod profile;
pub mod transport;

pub mod session;

// Primary re-exports
pub use error::{NetError, Result};
pub use profile::{ConnectionProfile, ConnectionProfileBuilder, ProfileTerminalModel, TlsMode};
pub use session::{
    SessionCommand, SessionCoordinator, SessionEvent, SessionHandle, SessionState, SessionStatus,
};
pub use transport::TransportStream;
