//! Connection profile configuration and corporate defaults.
//!
//! Provides the [`ConnectionProfile`] struct, TOML serialization/deserialization,
//! `BASTION3270_*` environment variable overrides, and [`ConnectionProfileBuilder`].

pub mod builder;
pub mod config;

pub use builder::ConnectionProfileBuilder;
pub use config::{
    is_lu_name, ConnectionProfile, ProfileTerminalModel, TlsMode, DEFAULT_CHANNEL_CAPACITY,
    DEFAULT_CODEPAGE, DEFAULT_COLOR_3279, DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_EXTENDED,
    DEFAULT_HOST, DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_NEGOTIATION_TIMEOUT_MS, DEFAULT_PORT,
    DEFAULT_WRITE_TIMEOUT_MS, MAX_CHANNEL_CAPACITY,
};
