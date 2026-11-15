//! Adversarial empirical verification suite for `ConnectionProfile`, TOML parsing, and ENV overrides.
//!
//! Validates:
//! 1. Boundary conditions and corner cases in TOML parsing (malformed syntax, empty strings, large payloads).
//! 2. Port boundaries (port 0, negative ports, port > 65535, port 1, port 65535).
//! 3. Dynamic terminal models (0x0, 0x80, 80x0, 255x255, 62x160, 200x100, 14-bit cell limit boundary).
//! 4. Case-insensitive `TlsMode` variants ("true", "1", "enabled", "false", "0", "disabled", unrecognized strings).
//! 5. Environment variable overrides with invalid values and graceful `Err(NetError::Config)` rejection.
//! 6. Zero panics across all inputs, builders, and edge conditions.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use bastion3270_core::TerminalModel;
use bastion3270_net::error::NetError;
use bastion3270_net::profile::{ConnectionProfile, ProfileTerminalModel, TlsMode};

/// Parses a profile TOML for a test that is not about TLS: the required `tls_mode` is added
/// unless the text sets it.
fn parse(toml: &str) -> Result<ConnectionProfile, NetError> {
    if toml.contains("tls_mode") {
        ConnectionProfile::from_toml_str(toml)
    } else {
        ConnectionProfile::from_toml_str(&format!("tls_mode = \"disabled\"\n{toml}"))
    }
}

// =========================================================================
// 1. TOML Syntax Edge Cases, Malformed Inputs, and Payload Stress
// =========================================================================

#[test]
fn test_toml_syntax_malformed_and_resilience() {
    // 1a. Unclosed table header
    let res = parse("[unclosed_table");
    assert!(matches!(res, Err(NetError::Config(_))));

    // 1b. Double equals syntax error
    let res = parse("host = = '127.0.0.1'");
    assert!(matches!(res, Err(NetError::Config(_))));

    // 1c. Unclosed string
    let res = parse("host = \"unclosed string");
    assert!(matches!(res, Err(NetError::Config(_))));

    // 1d. Repeated keys (duplicate key error in TOML)
    let res = parse("port = 3270\nport = 3271");
    assert!(matches!(res, Err(NetError::Config(_))));

    // 1e. Type mismatch: port as string
    let res = parse("port = '3270'");
    assert!(matches!(res, Err(NetError::Config(_))));

    // 1f. Type mismatch: port as float
    let res = parse("port = 3270.5");
    assert!(matches!(res, Err(NetError::Config(_))));

    // 1g. Type mismatch: host as integer
    let res = parse("host = 127001");
    assert!(matches!(res, Err(NetError::Config(_))));

    // 1h. Type mismatch: color_3279 as string in TOML
    let res = parse("color_3279 = 'true'");
    assert!(matches!(res, Err(NetError::Config(_))));

    // 1i. Type mismatch: channel_capacity as negative integer
    let res = parse("channel_capacity = -1");
    assert!(matches!(res, Err(NetError::Config(_))));

    // 1j. Completely empty string -> valid defaults
    let empty = parse("").expect("empty toml should parse defaults");
    assert_eq!(empty, ConnectionProfile::default());

    // 1k. Whitespace only string (spaces, tabs, newlines, CRLF) -> valid defaults
    let ws = parse("   \n\r\n\t   \n  ").expect("valid whitespace toml should parse defaults");
    assert_eq!(ws, ConnectionProfile::default());

    // 1k-2. Bare carriage return (invalid in TOML specification) -> graceful NetError::Config
    let bare_cr = parse("   \n\r\t   \n  ");
    assert!(matches!(bare_cr, Err(NetError::Config(_))));

    // 1l. 100 KB large string host in TOML
    let huge_host = "a".repeat(100_000);
    let toml_huge = format!("host = '{huge_host}'");
    let prof_huge = parse(&toml_huge).expect("large host should parse without panic");
    assert_eq!(prof_huge.host.len(), 100_000);

    // 1m. 1 MB comment payload in TOML
    let huge_comment = format!("# {}\nport = 3270\n", "X".repeat(1_000_000));
    let prof_comm = parse(&huge_comment).expect("1MB comment should parse without panic");
    assert_eq!(prof_comm.port, 3270);

    // 1n. Unsupported codepage string (100KB) -> returns graceful NetError::Config
    let huge_cp = "c".repeat(100_000);
    let toml_bad_cp = format!("codepage = '{huge_cp}'");
    let res = parse(&toml_bad_cp);
    assert!(matches!(res, Err(NetError::Config(_))));
}

// =========================================================================
// 2. Port Boundaries (Port 0, Negative, > 65535, Port 1, Port 65535)
// =========================================================================

#[test]
fn test_port_boundary_conditions() {
    // 2a. Port 0 in TOML -> rejected by validate()
    let res = parse("port = 0");
    match res {
        Err(NetError::Config(msg)) => {
            assert!(msg.contains("cannot be 0"), "unexpected error: {msg}");
        }
        other => panic!("expected Err(NetError::Config), got {other:?}"),
    }

    // 2b. Port 1 in TOML (minimum valid TCP port)
    let prof = parse("port = 1").expect("port 1 is valid");
    assert_eq!(prof.port, 1);

    // 2c. Port 65535 in TOML (maximum valid TCP port)
    let prof = parse("port = 65535").expect("port 65535 is valid");
    assert_eq!(prof.port, 65535);

    // 2d. Negative ports in TOML (-1, -3270, -65535) -> rejected by deserializer
    for neg_port in ["-1", "-3270", "-65535", "-100000"] {
        let toml = format!("port = {neg_port}");
        let res = parse(&toml);
        assert!(
            matches!(res, Err(NetError::Config(_))),
            "port {neg_port} should be rejected"
        );
    }

    // 2e. Overflow ports in TOML (65536, 70000, 4294967295, 18446744073709551615)
    for over_port in [
        "65536",
        "70000",
        "4294967295",
        "18446744073709551615",
        "999999999999999999999999999999",
    ] {
        let toml = format!("port = {over_port}");
        let res = parse(&toml);
        assert!(
            matches!(res, Err(NetError::Config(_))),
            "port {over_port} should be rejected"
        );
    }

    // 2f. Builder port validations
    let res_b0 = ConnectionProfile::builder().port(0).build();
    assert!(matches!(res_b0, Err(NetError::Config(_))));

    let prof_b1 = ConnectionProfile::builder()
        .port(1)
        .build()
        .expect("builder port 1");
    assert_eq!(prof_b1.port, 1);

    let prof_b65535 = ConnectionProfile::builder()
        .port(65535)
        .build()
        .expect("builder port 65535");
    assert_eq!(prof_b65535.port, 65535);

    // 2g. ENV override port tests
    let test_env_port = |val: &str| -> Result<ConnectionProfile, NetError> {
        let mut prof = ConnectionProfile::default();
        let mut map = HashMap::new();
        map.insert("BASTION3270_PORT".to_string(), val.to_string());
        prof.apply_env_lookup(&|k| map.get(k).cloned())?;
        prof.validate()?;
        Ok(prof)
    };

    // Valid ENV ports
    assert_eq!(test_env_port("1").unwrap().port, 1);
    assert_eq!(test_env_port("65535").unwrap().port, 65535);
    assert_eq!(test_env_port(" 3270 ").unwrap().port, 3270);

    // Invalid ENV ports
    assert!(matches!(test_env_port("0"), Err(NetError::Config(_))));
    assert!(matches!(test_env_port("-1"), Err(NetError::Config(_))));
    assert!(matches!(test_env_port("65536"), Err(NetError::Config(_))));
    assert!(matches!(test_env_port("70000"), Err(NetError::Config(_))));
    assert!(matches!(test_env_port("abc"), Err(NetError::Config(_))));
    assert!(matches!(test_env_port(""), Err(NetError::Config(_))));
    assert!(matches!(test_env_port("   "), Err(NetError::Config(_))));
    assert!(matches!(test_env_port("3270a"), Err(NetError::Config(_))));
}

// =========================================================================
// 3. Dynamic Terminal Models & 14-Bit Buffer Cell Limit (16,384)
// =========================================================================

#[test]
fn test_dynamic_terminal_model_boundary_cases() {
    // 3a. ProfileTerminalModel::from_str - Rejection of zero dimensions
    assert!(ProfileTerminalModel::from_str("0x0").is_err());
    assert!(ProfileTerminalModel::from_str("dynamic:0x0").is_err());
    assert!(ProfileTerminalModel::from_str("dynamic 0x0").is_err());
    assert!(ProfileTerminalModel::from_str("0x80").is_err());
    assert!(ProfileTerminalModel::from_str("dynamic:0x80").is_err());
    assert!(ProfileTerminalModel::from_str("80x0").is_err());
    assert!(ProfileTerminalModel::from_str("dynamic:80x0").is_err());

    // 3b. ProfileTerminalModel::from_str - Limit checks (16,384 cells)
    // 255x255 = 65,025 cells (> 16,384)
    let res_255 = ProfileTerminalModel::from_str("255x255");
    assert!(res_255.is_err());
    let err_msg = res_255.unwrap_err();
    assert!(err_msg.contains("exceed 14-bit limit"));

    // 200x100 = 20,000 cells (> 16,384)
    let res_200 = ProfileTerminalModel::from_str("dynamic:200x100");
    assert!(res_200.is_err());
    assert!(res_200.unwrap_err().contains("exceed 14-bit limit"));

    // 62x160 = 9,920 cells (<= 16,384) -> Valid z/OS ISPF Dynamic model
    let model_62 = ProfileTerminalModel::from_str("dynamic:62x160").expect("62x160 is valid");
    assert_eq!(
        model_62,
        ProfileTerminalModel::Dynamic {
            rows: 62,
            cols: 160
        }
    );
    let core_model: TerminalModel = model_62.try_into().expect("convert to core");
    assert_eq!(core_model.dimensions(), (62, 160));
    assert_eq!(core_model.alternate_capacity(), 9920);
    assert_eq!(core_model.terminal_type_name(true, true), "IBM-DYNAMIC");

    // Boundary edge: 1x1 = 1 cell
    let model_1 = ProfileTerminalModel::from_str("dynamic:1x1").expect("1x1 is valid");
    assert_eq!(model_1, ProfileTerminalModel::Dynamic { rows: 1, cols: 1 });

    // Boundary edge: 128x128 = 16,384 cells (exact limit)
    let model_max = ProfileTerminalModel::from_str("dynamic:128x128").expect("128x128 is valid");
    assert_eq!(
        model_max,
        ProfileTerminalModel::Dynamic {
            rows: 128,
            cols: 128
        }
    );
    let core_max: TerminalModel = model_max.try_into().expect("convert to core");
    assert_eq!(core_max.alternate_capacity(), 16384);

    // Boundary edge: 128x129 = 16,512 cells (> 16,384 limit)
    assert!(ProfileTerminalModel::from_str("dynamic:128x129").is_err());

    // 3c. Malformed dynamic string variants
    assert!(ProfileTerminalModel::from_str("dynamic:256x80").is_err()); // u8 overflow
    assert!(ProfileTerminalModel::from_str("dynamic:80x256").is_err()); // u8 overflow
    assert!(ProfileTerminalModel::from_str("dynamic:-1x80").is_err());
    assert!(ProfileTerminalModel::from_str("dynamic:").is_err());
    assert!(ProfileTerminalModel::from_str("dynamic:62").is_err());
    assert!(ProfileTerminalModel::from_str("dynamic:62x").is_err());
    assert!(ProfileTerminalModel::from_str("dynamic:x160").is_err());
    assert!(ProfileTerminalModel::from_str("dynamic:62x160x40").is_err());
    assert!(ProfileTerminalModel::from_str("dynamic:abcxdef").is_err());

    // 3d. TOML table deserialization for dynamic models
    let toml_zero_r = "terminal_model = { rows = 0, cols = 80 }";
    assert!(matches!(parse(toml_zero_r), Err(NetError::Config(_))));

    let toml_zero_c = "terminal_model = { rows = 24, cols = 0 }";
    assert!(matches!(parse(toml_zero_c), Err(NetError::Config(_))));

    let toml_200_100 = "terminal_model = { rows = 200, cols = 100 }";
    assert!(matches!(parse(toml_200_100), Err(NetError::Config(_))));

    let toml_255_255 = "terminal_model = { rows = 255, cols = 255 }";
    assert!(matches!(parse(toml_255_255), Err(NetError::Config(_))));

    let toml_valid_map = "terminal_model = { rows = 62, cols = 160 }";
    let prof_map = parse(toml_valid_map).expect("valid map should parse");
    assert_eq!(
        prof_map.terminal_model,
        ProfileTerminalModel::Dynamic {
            rows: 62,
            cols: 160
        }
    );

    // 3e. Direct construction & validation guard
    let invalid_prof = ConnectionProfile {
        terminal_model: ProfileTerminalModel::Dynamic { rows: 0, cols: 0 },
        ..Default::default()
    };
    assert!(matches!(invalid_prof.validate(), Err(NetError::Config(_))));

    // 3f. ENV override with dynamic models
    let test_env_model = |val: &str| -> Result<ConnectionProfile, NetError> {
        let mut prof = ConnectionProfile::default();
        let mut map = HashMap::new();
        map.insert("BASTION3270_TERMINAL_MODEL".to_string(), val.to_string());
        prof.apply_env_lookup(&|k| map.get(k).cloned())?;
        prof.validate()?;
        Ok(prof)
    };

    assert!(matches!(
        test_env_model("dynamic:0x0"),
        Err(NetError::Config(_))
    ));
    assert!(matches!(
        test_env_model("dynamic:0x80"),
        Err(NetError::Config(_))
    ));
    assert!(matches!(
        test_env_model("dynamic:200x100"),
        Err(NetError::Config(_))
    ));
    assert!(matches!(
        test_env_model("dynamic:255x255"),
        Err(NetError::Config(_))
    ));
    assert!(matches!(
        test_env_model("unknown_model_xyz"),
        Err(NetError::Config(_))
    ));

    let valid_env_model = test_env_model("dynamic:62x160").expect("valid env dynamic");
    assert_eq!(
        valid_env_model.terminal_model,
        ProfileTerminalModel::Dynamic {
            rows: 62,
            cols: 160
        }
    );
    assert_eq!(
        valid_env_model.terminal_type_string().unwrap(),
        "IBM-DYNAMIC"
    );
}

// =========================================================================
// 4. Case-Insensitive TlsMode Variants & Ser/De
// =========================================================================

#[test]
fn test_tls_mode_case_insensitivity_and_variants() {
    // 4a. Enabled variants
    let enabled_strings = [
        "true",
        "TRUE",
        "True",
        "tRuE",
        "1",
        "enabled",
        "ENABLED",
        "Enabled",
        "EnAbLeD",
        "yes",
        "YES",
        "Yes",
        "on",
        "ON",
        "On",
        "tls",
        "TLS",
        "Tls",
        "  true  ",
        "  enabled  ",
        " 1 ",
    ];

    for s in enabled_strings {
        let mode = s
            .parse::<TlsMode>()
            .unwrap_or_else(|e| panic!("failed to parse '{s}': {e}"));
        assert_eq!(
            mode,
            TlsMode::Enabled,
            "string '{s}' should parse to Enabled"
        );
        assert!(mode.is_enabled());
    }

    // 4b. Disabled variants
    let disabled_strings = [
        "false",
        "FALSE",
        "False",
        "fAlSe",
        "0",
        "disabled",
        "DISABLED",
        "Disabled",
        "DiSaBlEd",
        "no",
        "NO",
        "No",
        "off",
        "OFF",
        "Off",
        "none",
        "NONE",
        "None",
        "plain",
        "PLAIN",
        "Plain",
        "  false  ",
        "  disabled  ",
        " 0 ",
    ];

    for s in disabled_strings {
        let mode = s
            .parse::<TlsMode>()
            .unwrap_or_else(|e| panic!("failed to parse '{s}': {e}"));
        assert_eq!(
            mode,
            TlsMode::Disabled,
            "string '{s}' should parse to Disabled"
        );
        assert!(!mode.is_enabled());
    }

    // 4c. Unrecognized strings (must return Err)
    let invalid_strings = [
        "unrecognized",
        "maybe",
        "",
        "   ",
        "2",
        "-1",
        "enable",
        "disable",
        "ssl",
        "true1",
        "false0",
        "null",
        "undefined",
        "{}",
        "[]",
    ];

    for s in invalid_strings {
        assert!(
            s.parse::<TlsMode>().is_err(),
            "string '{s}' should not parse to TlsMode"
        );
    }

    // 4d. TOML parsing of TlsMode (boolean and string representations)
    let toml_cases = [
        ("tls_mode = true", TlsMode::Enabled),
        ("tls_mode = false", TlsMode::Disabled),
        ("tls_mode = 'true'", TlsMode::Enabled),
        ("tls_mode = 'TRUE'", TlsMode::Enabled),
        ("tls_mode = '1'", TlsMode::Enabled),
        ("tls_mode = 'enabled'", TlsMode::Enabled),
        ("tls_mode = 'ENABLED'", TlsMode::Enabled),
        ("tls_mode = 'false'", TlsMode::Disabled),
        ("tls_mode = 'FALSE'", TlsMode::Disabled),
        ("tls_mode = '0'", TlsMode::Disabled),
        ("tls_mode = 'disabled'", TlsMode::Disabled),
        ("tls_mode = 'DISABLED'", TlsMode::Disabled),
    ];

    for (toml_str, expected) in toml_cases {
        let prof =
            parse(toml_str).unwrap_or_else(|e| panic!("failed to parse TOML '{toml_str}': {e}"));
        assert_eq!(prof.tls_mode, expected, "case: {toml_str}");
    }

    // TOML unrecognized TlsMode string
    let res = parse("tls_mode = 'unrecognized'");
    assert!(matches!(res, Err(NetError::Config(_))));

    // 4e. ENV override for TlsMode (both BASTION3270_TLS and BASTION3270_TLS_MODE)
    let test_env_tls = |key: &str, val: &str| -> Result<ConnectionProfile, NetError> {
        let mut prof = ConnectionProfile::default();
        let mut map = HashMap::new();
        map.insert(key.to_string(), val.to_string());
        prof.apply_env_lookup(&|k| map.get(k).cloned())?;
        prof.validate()?;
        Ok(prof)
    };

    assert_eq!(
        test_env_tls("BASTION3270_TLS", "ENABLED").unwrap().tls_mode,
        TlsMode::Enabled
    );
    assert_eq!(
        test_env_tls("BASTION3270_TLS_MODE", "1").unwrap().tls_mode,
        TlsMode::Enabled
    );
    assert_eq!(
        test_env_tls("BASTION3270_TLS", "DISABLED")
            .unwrap()
            .tls_mode,
        TlsMode::Disabled
    );
    assert_eq!(
        test_env_tls("BASTION3270_TLS_MODE", "0").unwrap().tls_mode,
        TlsMode::Disabled
    );
    assert!(matches!(
        test_env_tls("BASTION3270_TLS", "unrecognized"),
        Err(NetError::Config(_))
    ));
    assert!(matches!(
        test_env_tls("BASTION3270_TLS_MODE", "invalid"),
        Err(NetError::Config(_))
    ));
}

// =========================================================================
// 5. Environment Variable Overrides with Invalid Values (Zero Panics)
// =========================================================================

#[test]
fn test_env_overrides_invalid_values_graceful_rejection() {
    let test_invalid_env = |key: &str, val: &str| {
        let mut prof = ConnectionProfile::default();
        let mut map = HashMap::new();
        map.insert(key.to_string(), val.to_string());
        let res = prof.apply_env_lookup(&|k| map.get(k).cloned());
        let final_res = res.and_then(|()| prof.validate());
        assert!(
            matches!(final_res, Err(NetError::Config(_))),
            "Expected Err(NetError::Config) for {key}='{val}', got {final_res:?}"
        );
    };

    // Port invalid values
    test_invalid_env("BASTION3270_PORT", "0");
    test_invalid_env("BASTION3270_PORT", "-1");
    test_invalid_env("BASTION3270_PORT", "65536");
    test_invalid_env("BASTION3270_PORT", "not_a_number");
    test_invalid_env("BASTION3270_PORT", "");

    // TLS invalid values
    test_invalid_env("BASTION3270_TLS", "bogus");
    test_invalid_env("BASTION3270_TLS_MODE", "not_a_mode");

    // Terminal Model invalid values
    test_invalid_env("BASTION3270_TERMINAL_MODEL", "bogus_model");
    test_invalid_env("BASTION3270_TERMINAL_MODEL", "dynamic:0x0");
    test_invalid_env("BASTION3270_TERMINAL_MODEL", "dynamic:200x100");
    test_invalid_env("BASTION3270_TERMINAL_MODEL", "dynamic:255x255");
    test_invalid_env("BASTION3270_TERMINAL_MODEL", "dynamic:bad");

    // Color invalid values
    test_invalid_env("BASTION3270_COLOR", "invalid_bool");
    test_invalid_env("BASTION3270_COLOR", "2");
    test_invalid_env("BASTION3270_COLOR", "-1");
    test_invalid_env("BASTION3270_COLOR", "");

    // Extended invalid values
    test_invalid_env("BASTION3270_EXTENDED", "invalid_bool");
    test_invalid_env("BASTION3270_EXTENDED", "maybe");
    test_invalid_env("BASTION3270_EXTENDED", "");

    // Codepage invalid values
    test_invalid_env("BASTION3270_CODEPAGE", "invalid_codepage");
    test_invalid_env("BASTION3270_CODEPAGE", "utf-8");
    test_invalid_env("BASTION3270_CODEPAGE", "iso-8859-1");

    // Connect timeout invalid values
    test_invalid_env("BASTION3270_CONNECT_TIMEOUT_MS", "0");
    test_invalid_env("BASTION3270_CONNECT_TIMEOUT_MS", "-10");
    test_invalid_env("BASTION3270_CONNECT_TIMEOUT_MS", "not_number");
    test_invalid_env("BASTION3270_CONNECT_TIMEOUT", "0");
    test_invalid_env("BASTION3270_CONNECT_TIMEOUT", "-50");
    test_invalid_env("BASTION3270_CONNECT_TIMEOUT", "abc");

    // Idle timeout invalid values
    test_invalid_env("BASTION3270_IDLE_TIMEOUT_MS", "0");
    test_invalid_env("BASTION3270_IDLE_TIMEOUT_MS", "-10");
    test_invalid_env("BASTION3270_IDLE_TIMEOUT_MS", "not_number");
    test_invalid_env("BASTION3270_IDLE_TIMEOUT", "0");
    test_invalid_env("BASTION3270_IDLE_TIMEOUT", "-50");
    test_invalid_env("BASTION3270_IDLE_TIMEOUT", "xyz");

    // Channel capacity invalid values
    test_invalid_env("BASTION3270_CHANNEL_CAPACITY", "0");
    test_invalid_env("BASTION3270_CHANNEL_CAPACITY", "-1");
    test_invalid_env("BASTION3270_CHANNEL_CAPACITY", "not_number");
    test_invalid_env("BASTION3270_CHANNEL_CAPACITY", "");
}

// =========================================================================
// 6. Security Paths, LU Name, and Whitespace Handling
// =========================================================================

#[test]
fn test_env_security_and_paths_whitespace_handling() {
    let mut prof = ConnectionProfile {
        ca_cert: Some(PathBuf::from("/existing/ca.pem")),
        client_cert: Some(PathBuf::from("/existing/client.pem")),
        client_key: Some(PathBuf::from("/existing/client.key")),
        lu_name: Some("EXISTING_LU".to_string()),
        ..Default::default()
    };

    // Setting whitespace-only values in ENV must clear them to None
    let mut map = HashMap::new();
    map.insert("BASTION3270_CA_CERT".to_string(), "   ".to_string());
    map.insert("BASTION3270_CLIENT_CERT".to_string(), "  \t ".to_string());
    map.insert("BASTION3270_CLIENT_KEY".to_string(), String::new());
    map.insert("BASTION3270_LU_NAME".to_string(), "   ".to_string());

    prof.apply_env_lookup(&|k| map.get(k).cloned()).unwrap();
    assert!(prof.ca_cert.is_none());
    assert!(prof.client_cert.is_none());
    assert!(prof.client_key.is_none());
    assert!(prof.lu_name.is_none());

    // Setting valid non-empty strings
    let mut map2 = HashMap::new();
    map2.insert("BASTION3270_CA_CERT".to_string(), "/new/ca.crt".to_string());
    map2.insert(
        "BASTION3270_CLIENT_CERT".to_string(),
        "/new/client.crt".to_string(),
    );
    map2.insert(
        "BASTION3270_CLIENT_KEY".to_string(),
        "/new/client.key".to_string(),
    );
    map2.insert("BASTION3270_LU_NAME".to_string(), "NEWLU01".to_string());

    prof.apply_env_lookup(&|k| map2.get(k).cloned()).unwrap();
    assert_eq!(prof.ca_cert, Some(PathBuf::from("/new/ca.crt")));
    assert_eq!(prof.client_cert, Some(PathBuf::from("/new/client.crt")));
    assert_eq!(prof.client_key, Some(PathBuf::from("/new/client.key")));
    assert_eq!(prof.lu_name, Some("NEWLU01".to_string()));
}

// =========================================================================
// 7. Builder Boundary Validations
// =========================================================================

#[test]
fn test_builder_all_boundary_validations() {
    // Empty host
    let res = ConnectionProfile::builder().host("").build();
    assert!(matches!(res, Err(NetError::Config(_))));

    // Whitespace host
    let res = ConnectionProfile::builder().host("   \t  ").build();
    assert!(matches!(res, Err(NetError::Config(_))));

    // Port 0
    let res = ConnectionProfile::builder().port(0).build();
    assert!(matches!(res, Err(NetError::Config(_))));

    // Channel capacity 0
    let res = ConnectionProfile::builder().channel_capacity(0).build();
    assert!(matches!(res, Err(NetError::Config(_))));

    // Connect timeout 0
    let res = ConnectionProfile::builder().connect_timeout_ms(0).build();
    assert!(matches!(res, Err(NetError::Config(_))));

    // Idle timeout 0
    let res = ConnectionProfile::builder().idle_timeout_ms(0).build();
    assert!(matches!(res, Err(NetError::Config(_))));

    // Unsupported codepage
    let res = ConnectionProfile::builder().codepage("cp1252").build();
    assert!(matches!(res, Err(NetError::Config(_))));

    // Dynamic 0x0 model
    let res = ConnectionProfile::builder()
        .terminal_model(ProfileTerminalModel::Dynamic { rows: 0, cols: 0 })
        .build();
    assert!(matches!(res, Err(NetError::Config(_))));

    // Dynamic 200x100 model (> 16384 cells)
    let res = ConnectionProfile::builder()
        .terminal_model(ProfileTerminalModel::Dynamic {
            rows: 200,
            cols: 100,
        })
        .build();
    assert!(matches!(res, Err(NetError::Config(_))));
}

// =========================================================================
// 8. Standard Terminal Models & Terminal-Type Names
// =========================================================================

#[test]
fn test_standard_terminal_models_and_type_names() {
    let cases = [
        (ProfileTerminalModel::Model2, false, false, "IBM-3278-2"),
        (ProfileTerminalModel::Model2, true, false, "IBM-3279-2"),
        (ProfileTerminalModel::Model2, false, true, "IBM-3278-2-E"),
        (ProfileTerminalModel::Model2, true, true, "IBM-3279-2-E"),
        (ProfileTerminalModel::Model3, false, false, "IBM-3278-3"),
        (ProfileTerminalModel::Model3, true, false, "IBM-3279-3"),
        (ProfileTerminalModel::Model3, false, true, "IBM-3278-3-E"),
        (ProfileTerminalModel::Model3, true, true, "IBM-3279-3-E"),
        (ProfileTerminalModel::Model4, false, false, "IBM-3278-4"),
        (ProfileTerminalModel::Model4, true, false, "IBM-3278-4"),
        (ProfileTerminalModel::Model4, false, true, "IBM-3278-4-E"),
        (ProfileTerminalModel::Model4, true, true, "IBM-3278-4-E"),
        (ProfileTerminalModel::Model5, false, false, "IBM-3278-5"),
        (ProfileTerminalModel::Model5, true, false, "IBM-3278-5"),
        (ProfileTerminalModel::Model5, false, true, "IBM-3278-5-E"),
        (ProfileTerminalModel::Model5, true, true, "IBM-3278-5-E"),
        (
            ProfileTerminalModel::Dynamic {
                rows: 62,
                cols: 160,
            },
            true,
            true,
            "IBM-DYNAMIC",
        ),
    ];

    for (model, color, ext, expected_name) in cases {
        let prof = ConnectionProfile::builder()
            .terminal_model(model)
            .color_3279(color)
            .extended(ext)
            .build()
            .unwrap();

        assert_eq!(
            prof.terminal_type_string().unwrap(),
            expected_name,
            "failed for {model:?}, color={color}, ext={ext}"
        );
        assert_eq!(
            prof.terminal_type_name().unwrap(),
            expected_name,
            "failed for {model:?}, color={color}, ext={ext}"
        );
    }
}

// =========================================================================
// 9. EBCDIC CodePage Resolution & Casing
// =========================================================================

#[test]
fn test_codepage_resolution_and_casing() {
    // Valid supported codepages (case-insensitive in ENV / core mapping)
    for cp in ["cp037", "CP037", "cp870", "CP870", "ibm870", "IBM870"] {
        let mut prof = ConnectionProfile::default();
        let mut map = HashMap::new();
        map.insert("BASTION3270_CODEPAGE".to_string(), cp.to_string());
        prof.apply_env_lookup(&|k| map.get(k).cloned()).unwrap();
        assert!(prof.validate().is_ok(), "codepage {cp} should validate");
        let core_cp = prof.core_codepage();
        assert!(core_cp.is_ok(), "core_codepage should resolve for {cp}");
    }

    // Unsupported codepages
    for bad_cp in [
        "utf-8",
        "ascii",
        "cp1252",
        "iso-8859-1",
        "ebcdic",
        "",
        "cp999",
    ] {
        let prof = ConnectionProfile {
            codepage: bad_cp.to_string(),
            ..Default::default()
        };
        assert!(
            matches!(prof.validate(), Err(NetError::Config(_))),
            "unsupported codepage '{bad_cp}' should fail validation"
        );
        assert!(
            matches!(prof.core_codepage(), Err(NetError::Config(_))),
            "unsupported codepage '{bad_cp}' should fail core resolution"
        );
    }
}

// =========================================================================
// 10. Dynamic Terminal Model Case Insensitivity & TOML Roundtrip
// =========================================================================

#[test]
fn test_dynamic_terminal_model_casing_and_roundtrip() {
    let variations = [
        "dynamic:62x160",
        "DYNAMIC:62X160",
        "Dynamic:62x160",
        "dynamic 62x160",
        "DYNAMIC 62X160",
        "62x160",
        "62X160",
        "  62x160  ",
    ];

    for s in variations {
        let model = s
            .parse::<ProfileTerminalModel>()
            .unwrap_or_else(|e| panic!("failed to parse '{s}': {e}"));
        assert_eq!(
            model,
            ProfileTerminalModel::Dynamic {
                rows: 62,
                cols: 160
            },
            "variation '{s}' failed"
        );
    }

    // TOML roundtrip for Dynamic model
    let prof_dyn = ConnectionProfile::builder()
        .terminal_model(ProfileTerminalModel::Dynamic {
            rows: 62,
            cols: 160,
        })
        .build()
        .unwrap();

    let toml = prof_dyn.to_toml_string().expect("to_toml_string");
    let back = parse(&toml).expect("from_toml_str");
    assert_eq!(prof_dyn, back);
    assert_eq!(
        back.terminal_model,
        ProfileTerminalModel::Dynamic {
            rows: 62,
            cols: 160
        }
    );
}

// =========================================================================
// 11. Empirical Stress & Fuzz Generator: Zero Panics Under Hostile Inputs
// =========================================================================

#[test]
fn test_fuzz_stress_zero_panics() {
    // Deterministic pseudo-random generator (LCG)
    struct SimpleRng(u64);
    impl SimpleRng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (self.0 >> 32) as u32
        }
        fn choose<'a>(&mut self, slice: &'a [&'a str]) -> &'a str {
            let idx = (self.next_u32() as usize) % slice.len();
            slice[idx]
        }
    }

    let mut rng = SimpleRng(0xDEAD_BEEF_CAFE_BABE);

    let repeat_host = "a".repeat(1000);
    let host_tokens = [
        "127.0.0.1",
        "localhost",
        "ibm.z.corp",
        "",
        "   ",
        "\0",
        "\r\n",
        ":::1",
        "256.256.256.256",
        "huge-name-",
        repeat_host.as_str(),
    ];
    let port_tokens = [
        "3270", "0", "-1", "65535", "65536", "99999", "abc", "", "   ", "23", "992",
    ];
    let tls_tokens = [
        "true", "false", "1", "0", "enabled", "disabled", "bogus", "", "   ", "TLS", "none",
    ];
    let model_tokens = [
        "Model2",
        "Model3",
        "Model4",
        "Model5",
        "2",
        "3",
        "4",
        "5",
        "dynamic:62x160",
        "dynamic:0x0",
        "dynamic:200x100",
        "dynamic:255x255",
        "dynamic:80x0",
        "dynamic:0x80",
        "dynamic:128x128",
        "dynamic:128x129",
        "garbage",
        "",
        "   ",
        "dynamic:",
        "dynamic:foo",
    ];
    let cp_tokens = [
        "cp037", "CP037", "cp870", "CP870", "ibm870", "invalid", "", "utf-8", "latin1",
    ];

    // 11a. Fuzz 2,000 TOML payloads
    for _ in 0..2_000 {
        let host_val = rng.choose(&host_tokens);
        let port_val = rng.choose(&port_tokens);
        let tls_val = rng.choose(&tls_tokens);
        let model_val = rng.choose(&model_tokens);
        let cp_val = rng.choose(&cp_tokens);

        let toml_payload = format!(
            "host = \"{}\"\nport = {}\ntls_mode = \"{}\"\nterminal_model = \"{}\"\ncodepage = \"{}\"\n",
            host_val.replace('"', "\\\""),
            port_val,
            tls_val,
            model_val,
            cp_val
        );

        // Must never panic! It either succeeds or returns Err(NetError::Config).
        let _ = parse(&toml_payload);
    }

    // 11b. Fuzz 2,000 ENV overrides
    for _ in 0..2_000 {
        let host_val = rng.choose(&host_tokens);
        let port_val = rng.choose(&port_tokens);
        let tls_val = rng.choose(&tls_tokens);
        let model_val = rng.choose(&model_tokens);
        let cp_val = rng.choose(&cp_tokens);

        let mut env_map = HashMap::new();
        env_map.insert("BASTION3270_HOST".to_string(), host_val.to_string());
        env_map.insert("BASTION3270_PORT".to_string(), port_val.to_string());
        env_map.insert("BASTION3270_TLS".to_string(), tls_val.to_string());
        env_map.insert(
            "BASTION3270_TERMINAL_MODEL".to_string(),
            model_val.to_string(),
        );
        env_map.insert("BASTION3270_CODEPAGE".to_string(), cp_val.to_string());

        let mut prof = ConnectionProfile::default();
        let res = prof.apply_env_lookup(&|k| env_map.get(k).cloned());
        if res.is_ok() {
            let _ = prof.validate();
            let _ = prof.core_terminal_model();
            let _ = prof.terminal_type_string();
            let _ = prof.core_codepage();
        }
    }
}

/// A misspelt key is an error, never silently replaced by the default (a profile file of
/// the desktop client or a gateway profile).
#[test]
fn test_unknown_connection_keys_are_rejected() {
    let typo = "host = \"zos1.example.com\"\ntls_mode = \"enabled\"\naccept_hostnme = \"zos1\"\n";
    let err = ConnectionProfile::from_toml_str(typo)
        .unwrap_err()
        .to_string();
    assert!(err.contains("accept_hostnme"), "{err}");
}
