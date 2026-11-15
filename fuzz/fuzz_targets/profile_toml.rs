//! Fuzzes the TOML loader of `bastion3270_net::ConnectionProfile`
//! (`ConnectionProfile::from_toml_str`, which parses and then validates).
//!
//! Asserted invariants for every profile the loader accepts:
//! * validation already guarantees a supported terminal model and code page, so
//!   `core_terminal_model`, `core_codepage`, `terminal_type_string` and `terminal_type_name`
//!   succeed, and the terminal type string equals the core model's `TERMINAL-TYPE` name
//!   (RFC 1091, RFC 2355 §7);
//! * a model that needs the extended data stream is only accepted with `extended = true`;
//! * `keyboard_options` reflects the profile switches;
//! * the profile survives a round trip through `to_toml_string` and `from_toml_str`.
#![no_main]

use bastion3270_net::ConnectionProfile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Invalid TOML and invalid profiles are expected to be rejected with an error.
    let Ok(profile) = ConnectionProfile::from_toml_str(text) else {
        return;
    };

    let model = match profile.core_terminal_model() {
        Ok(model) => model,
        Err(e) => panic!("validated profile has no terminal model: {e}"),
    };
    assert!(!model.requires_extended() || profile.extended);
    assert!(
        profile.core_codepage().is_ok(),
        "validated profile has no code page"
    );
    let type_string = match profile.terminal_type_string() {
        Ok(s) => s,
        Err(e) => panic!("validated profile has no terminal type: {e}"),
    };
    assert_eq!(
        type_string,
        model.terminal_type_name(profile.color_3279, profile.extended)
    );
    assert_eq!(
        profile.terminal_type_name().ok(),
        Some(type_string.as_str())
    );

    let options = profile.keyboard_options();
    assert_eq!(options.numeric_lock, profile.numeric_lock);
    assert_eq!(options.blank_fill, profile.blank_fill);

    let serialized = match profile.to_toml_string() {
        Ok(s) => s,
        Err(e) => panic!("validated profile cannot be serialized: {e}"),
    };
    match ConnectionProfile::from_toml_str(&serialized) {
        Ok(again) => assert_eq!(again, profile, "profile changed in a TOML round trip"),
        Err(e) => panic!("serialized profile is rejected again: {e}\n{serialized}"),
    }
});
