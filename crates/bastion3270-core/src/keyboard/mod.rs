//! IBM 3270 Virtual Keyboard and Operator Information Area (OIA) status machine.
//!
//! Provides deterministic keyboard editing, cursor navigation, protected field enforcement,
//! numeric entry validation, auto-skip jump navigation, and Read Modified AID generation.

pub mod engine;
pub mod key;
pub mod lock;
pub mod oia;

pub use engine::{
    KeyInput, KeyOutcome, KeyboardError, KeyboardOptions, PasteEnd, PasteOutcome, VirtualKeyboard,
    MAX_TYPEAHEAD,
};
pub use key::{ActionKey, AidKey, AttentionKey};
pub use lock::{KeyboardLock, LockReason, OperatorError};
pub use oia::KeyboardState;
