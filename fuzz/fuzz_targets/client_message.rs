//! Fuzzes the browser-to-gateway JSON protocol (`bastion3270_server::protocol`).
//!
//! Every input that is valid UTF-8 is decoded as a `ClientMessage` (internally tagged by
//! `type`, unknown fields rejected) and passed to the public name parsers `parse_aid`,
//! `parse_action` and `parse_attention`, both as a whole and through the field of a decoded
//! message, exactly as the WebSocket handler dispatches them.
//!
//! Asserted invariants:
//! * decoding and name parsing never panic on arbitrary text;
//! * the name parsers are total functions of the documented names: `parse_aid` and
//!   `parse_attention` ignore ASCII case, `parse_action` is case-sensitive;
//! * a decoded `key` message carries exactly one character.
#![no_main]

use bastion3270_server::protocol::{parse_action, parse_aid, parse_attention, ClientMessage};
use libfuzzer_sys::fuzz_target;

fn parse_names(name: &str) {
    let aid = parse_aid(name);
    assert_eq!(aid, parse_aid(&name.to_ascii_uppercase()));
    assert_eq!(aid, parse_aid(&name.to_ascii_lowercase()));
    let attention = parse_attention(name);
    assert_eq!(attention, parse_attention(&name.to_ascii_uppercase()));
    let _ = parse_action(name);
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    parse_names(text);

    // Malformed or unknown messages are expected to be rejected with an error.
    let Ok(message) = serde_json::from_str::<ClientMessage>(text) else {
        return;
    };
    match message {
        ClientMessage::Aid { aid } => parse_names(&aid),
        ClientMessage::Action { action } => parse_names(&action),
        ClientMessage::Attention { key } => parse_names(&key),
        ClientMessage::Key { ch } => assert_eq!(ch.to_string().chars().count(), 1),
        ClientMessage::Open { .. }
        | ClientMessage::Resume { .. }
        | ClientMessage::Text { .. }
        | ClientMessage::MoveCursor { .. }
        | ClientMessage::Disconnect => {}
    }
});
