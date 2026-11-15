//! Helpers shared by the gateway integration tests (each test file compiles its own copy, so
//! helpers a file does not use are not dead code there).
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

pub mod browser;
pub mod gateway;
pub mod mock_host;
