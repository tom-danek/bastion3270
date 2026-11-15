//! Integration test suite for `ConnectionProfile`, TOML parsing, and ENV overrides.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::HashMap;
use std::path::PathBuf;

use bastion3270_core::TerminalModel;
use bastion3270_net::error::NetError;
use bastion3270_net::profile::{
    ConnectionProfile, ProfileTerminalModel, TlsMode, DEFAULT_CHANNEL_CAPACITY, DEFAULT_CODEPAGE,
    DEFAULT_COLOR_3279, DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_EXTENDED, DEFAULT_HOST,
    DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_PORT,
};

/// Parses a profile TOML for a test that is not about TLS: the required `tls_mode` is added
/// unless the text sets it.
fn parse(toml: &str) -> Result<ConnectionProfile, NetError> {
    if toml.contains("tls_mode") {
        ConnectionProfile::from_toml_str(toml)
    } else {
        ConnectionProfile::from_toml_str(&format!("tls_mode = \"disabled\"\n{toml}"))
    }
}

#[test]
fn test_default_profile_values() {
    let profile = ConnectionProfile::default();
    assert_eq!(profile.host, DEFAULT_HOST);
    assert_eq!(profile.port, DEFAULT_PORT);
    assert_eq!(profile.tls_mode, TlsMode::Disabled);
    assert!(profile.ca_cert.is_none());
    assert!(profile.client_cert.is_none());
    assert!(profile.client_key.is_none());
    assert!(profile.lu_name.is_none());
    assert_eq!(profile.terminal_model, ProfileTerminalModel::Model2);
    assert_eq!(profile.color_3279, DEFAULT_COLOR_3279);
    assert_eq!(profile.extended, DEFAULT_EXTENDED);
    assert_eq!(profile.codepage, DEFAULT_CODEPAGE);
    assert_eq!(profile.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT_MS);
    assert_eq!(profile.idle_timeout_ms, DEFAULT_IDLE_TIMEOUT_MS);
    assert_eq!(profile.channel_capacity, DEFAULT_CHANNEL_CAPACITY);

    assert!(profile.validate().is_ok());
    assert_eq!(
        profile.core_terminal_model().unwrap(),
        TerminalModel::Model2
    );
    assert_eq!(profile.terminal_type_string().unwrap(), "IBM-3279-2-E");
    assert_eq!(profile.terminal_type_name().unwrap(), "IBM-3279-2-E");
    assert!(profile.core_codepage().is_ok());
}

#[test]
fn test_toml_full_profile_parsing() {
    let toml = r#"
        host = "zos.corp.bank.com"
        port = 992
        tls_mode = "enabled"
        ca_cert = "/etc/ssl/certs/corp_ca.pem"
        lu_name = "LUZOS01"
        terminal_model = "Model4"
        color_3279 = false
        extended = true
        codepage = "cp870"
        connect_timeout_ms = 15000
        idle_timeout_ms = 120000
        channel_capacity = 256
    "#;

    let profile = parse(toml).expect("parsing should succeed");
    assert_eq!(profile.host, "zos.corp.bank.com");
    assert_eq!(profile.port, 992);
    assert_eq!(profile.tls_mode, TlsMode::Enabled);
    assert_eq!(
        profile.ca_cert,
        Some(PathBuf::from("/etc/ssl/certs/corp_ca.pem"))
    );
    assert_eq!(profile.lu_name, Some("LUZOS01".to_string()));
    assert_eq!(profile.terminal_model, ProfileTerminalModel::Model4);
    assert!(!profile.color_3279);
    assert!(profile.extended);
    assert_eq!(profile.codepage, "cp870");
    assert_eq!(profile.connect_timeout_ms, 15_000);
    assert_eq!(profile.idle_timeout_ms, 120_000);
    assert_eq!(profile.channel_capacity, 256);

    assert_eq!(
        profile.core_terminal_model().unwrap(),
        TerminalModel::Model4
    );
    assert_eq!(profile.terminal_type_string().unwrap(), "IBM-3278-4-E");
    assert_eq!(profile.terminal_type_name().unwrap(), "IBM-3278-4-E");
}

#[test]
fn test_toml_partial_and_empty_profile() {
    let empty_profile = parse("").expect("empty toml should parse defaults");
    assert_eq!(empty_profile, ConnectionProfile::default());

    let partial_toml = r#"
        host = "hercules.local"
        port = 3271
    "#;
    let partial = parse(partial_toml).expect("partial toml should parse");
    assert_eq!(partial.host, "hercules.local");
    assert_eq!(partial.port, 3271);
    assert_eq!(partial.terminal_model, ProfileTerminalModel::Model2);
    assert_eq!(partial.channel_capacity, 128);
}

#[test]
fn test_toml_roundtrip() {
    let original = ConnectionProfile {
        host: "zos.test".to_string(),
        port: 992,
        tls_mode: TlsMode::Enabled,
        ca_cert: Some(PathBuf::from("/ca.pem")),
        accept_hostname: Some("zos1.bank.example".to_string()),
        pinned_cert_sha256: Some("ab".repeat(32)),
        client_cert: None,
        client_key: None,
        lu_name: Some("MYLU".to_string()),
        terminal_model: ProfileTerminalModel::Model5,
        color_3279: true,
        extended: true,
        codepage: "cp037".to_string(),
        numeric_lock: true,
        blank_fill: false,
        connect_timeout_ms: 8_000,
        idle_timeout_ms: 45_000,
        write_timeout_ms: 7_000,
        negotiation_timeout_ms: 9_000,
        channel_capacity: 64,
    };

    let serialized = original
        .to_toml_string()
        .expect("serialization should succeed");
    let deserialized = parse(&serialized).expect("deserialization should succeed");
    assert_eq!(original, deserialized);
}

#[test]
fn test_dynamic_terminal_model_parsing_and_mapping() {
    let toml = r#"
        terminal_model = "dynamic:62x160"
    "#;
    let profile = parse(toml).expect("dynamic model should parse");
    assert_eq!(
        profile.terminal_model,
        ProfileTerminalModel::Dynamic {
            rows: 62,
            cols: 160
        }
    );
    let core_model = profile.core_terminal_model().unwrap();
    assert_eq!(core_model.dimensions(), (62, 160));
    assert_eq!(profile.terminal_type_string().unwrap(), "IBM-DYNAMIC");

    // Dynamic model map deserialization
    let toml_map = r"
        terminal_model = { rows = 43, cols = 80 }
    ";
    let profile_map = parse(toml_map).expect("dynamic map model should parse");
    assert_eq!(
        profile_map.terminal_model,
        ProfileTerminalModel::Dynamic { rows: 43, cols: 80 }
    );
}

#[test]
fn test_validation_errors() {
    // Port 0
    let res = parse("port = 0");
    assert!(matches!(res, Err(NetError::Config(_))));

    // Empty host
    let res = parse("host = ''");
    assert!(matches!(res, Err(NetError::Config(_))));

    // Channel capacity 0
    let res = parse("channel_capacity = 0");
    assert!(matches!(res, Err(NetError::Config(_))));

    // Timeout 0
    let res = parse("connect_timeout_ms = 0");
    assert!(matches!(res, Err(NetError::Config(_))));

    let res = parse("idle_timeout_ms = 0");
    assert!(matches!(res, Err(NetError::Config(_))));

    // Unsupported codepage
    let res = parse("codepage = 'invalid_cp'");
    assert!(matches!(res, Err(NetError::Config(_))));

    // Dynamic model zero rows
    let res = parse("terminal_model = 'dynamic:0x80'");
    assert!(matches!(res, Err(NetError::Config(_))));

    // Dynamic model exceeding 16384 cells (200x100 = 20000)
    let res = parse("terminal_model = 'dynamic:200x100'");
    assert!(matches!(res, Err(NetError::Config(_))));
}

#[test]
fn test_builder_fluent_api() {
    let profile = ConnectionProfile::builder()
        .host("main.host.net")
        .port(23)
        .with_tls(true)
        .ca_cert("/path/to/ca.pem")
        .lu_name("LU01")
        .terminal_model(ProfileTerminalModel::Model3)
        .color_3279(false)
        .extended(false)
        .codepage("cp870")
        .connect_timeout_ms(5_000)
        .idle_timeout_ms(30_000)
        .channel_capacity(64)
        .build()
        .expect("builder build should succeed");

    assert_eq!(profile.host, "main.host.net");
    assert_eq!(profile.port, 23);
    assert_eq!(profile.tls_mode, TlsMode::Enabled);
    assert_eq!(profile.ca_cert, Some(PathBuf::from("/path/to/ca.pem")));
    assert_eq!(profile.lu_name, Some("LU01".to_string()));
    assert_eq!(profile.terminal_model, ProfileTerminalModel::Model3);
    assert_eq!(profile.terminal_type_string().unwrap(), "IBM-3278-3");

    // Test clear helpers
    let cleared = ConnectionProfile::builder()
        .ca_cert("/ca.pem")
        .clear_ca_cert()
        .client_cert("/cert.pem")
        .clear_client_cert()
        .client_key("/key.pem")
        .clear_client_key()
        .lu_name("LU")
        .clear_lu_name()
        .build()
        .expect("build should succeed");
    assert!(cleared.ca_cert.is_none());
    assert!(cleared.client_cert.is_none());
    assert!(cleared.client_key.is_none());
    assert!(cleared.lu_name.is_none());

    // Invalid builder parameter should return error
    let invalid = ConnectionProfile::builder().port(0).build();
    assert!(matches!(invalid, Err(NetError::Config(_))));
}

#[test]
fn test_env_overrides_lookup() {
    let mut profile = ConnectionProfile::default();
    let mut env = HashMap::new();
    env.insert("BASTION3270_HOST".to_string(), "env.zos.corp".to_string());
    env.insert("BASTION3270_PORT".to_string(), "993".to_string());
    env.insert("BASTION3270_TLS".to_string(), "true".to_string());
    env.insert("BASTION3270_CA_CERT".to_string(), "/pki/ca.crt".to_string());
    env.insert(
        "BASTION3270_CLIENT_CERT".to_string(),
        "/pki/client.crt".to_string(),
    );
    env.insert(
        "BASTION3270_CLIENT_KEY".to_string(),
        "/pki/client.key".to_string(),
    );
    env.insert("BASTION3270_LU_NAME".to_string(), "ENVLU02".to_string());
    env.insert(
        "BASTION3270_TERMINAL_MODEL".to_string(),
        "Model5".to_string(),
    );
    env.insert("BASTION3270_COLOR".to_string(), "0".to_string());
    env.insert("BASTION3270_EXTENDED".to_string(), "1".to_string());
    env.insert("BASTION3270_CODEPAGE".to_string(), "CP870".to_string());
    env.insert(
        "BASTION3270_CONNECT_TIMEOUT_MS".to_string(),
        "20000".to_string(),
    );
    env.insert(
        "BASTION3270_IDLE_TIMEOUT_MS".to_string(),
        "90000".to_string(),
    );
    env.insert(
        "BASTION3270_CHANNEL_CAPACITY".to_string(),
        "512".to_string(),
    );

    profile
        .apply_env_lookup(&|k| env.get(k).cloned())
        .expect("env lookup should succeed");
    profile.validate().expect("profile should be valid");

    assert_eq!(profile.host, "env.zos.corp");
    assert_eq!(profile.port, 993);
    assert_eq!(profile.tls_mode, TlsMode::Enabled);
    assert_eq!(profile.ca_cert, Some(PathBuf::from("/pki/ca.crt")));
    assert_eq!(profile.client_cert, Some(PathBuf::from("/pki/client.crt")));
    assert_eq!(profile.client_key, Some(PathBuf::from("/pki/client.key")));
    assert_eq!(profile.lu_name, Some("ENVLU02".to_string()));
    assert_eq!(profile.terminal_model, ProfileTerminalModel::Model5);
    assert!(!profile.color_3279);
    assert!(profile.extended);
    assert_eq!(profile.codepage, "cp870");
    assert_eq!(profile.connect_timeout_ms, 20_000);
    assert_eq!(profile.idle_timeout_ms, 90_000);
    assert_eq!(profile.channel_capacity, 512);

    assert_eq!(profile.terminal_type_string().unwrap(), "IBM-3278-5-E");
}

#[test]
fn test_env_precedence_over_toml() {
    let toml = r#"
        host = "toml.host.com"
        port = 3270
        codepage = "cp037"
    "#;
    let mut profile = parse(toml).unwrap();
    assert_eq!(profile.host, "toml.host.com");
    assert_eq!(profile.port, 3270);

    let mut env = HashMap::new();
    env.insert("BASTION3270_HOST".to_string(), "env.host.com".to_string());
    env.insert("BASTION3270_PORT".to_string(), "3279".to_string());

    profile.apply_env_lookup(&|k| env.get(k).cloned()).unwrap();
    assert_eq!(profile.host, "env.host.com"); // ENV overrides TOML
    assert_eq!(profile.port, 3279); // ENV overrides TOML
    assert_eq!(profile.codepage, "cp037"); // TOML preserved when env not set
}

#[test]
fn test_tls_mode_parsing_and_serialization() {
    assert_eq!("enabled".parse::<TlsMode>().unwrap(), TlsMode::Enabled);
    assert_eq!("true".parse::<TlsMode>().unwrap(), TlsMode::Enabled);
    assert_eq!("1".parse::<TlsMode>().unwrap(), TlsMode::Enabled);
    assert_eq!("disabled".parse::<TlsMode>().unwrap(), TlsMode::Disabled);
    assert_eq!("false".parse::<TlsMode>().unwrap(), TlsMode::Disabled);
    assert_eq!("0".parse::<TlsMode>().unwrap(), TlsMode::Disabled);
    assert!("invalid".parse::<TlsMode>().is_err());

    assert_eq!(TlsMode::Enabled.to_string(), "enabled");
    assert_eq!(TlsMode::Disabled.to_string(), "disabled");
}

#[test]
fn test_model_conversions() {
    let core_m2 = TerminalModel::Model2;
    let prof_m2: ProfileTerminalModel = core_m2.into();
    assert_eq!(prof_m2, ProfileTerminalModel::Model2);

    let core_dyn = TerminalModel::new_dynamic(60, 120).unwrap();
    let prof_dyn: ProfileTerminalModel = core_dyn.into();
    assert_eq!(
        prof_dyn,
        ProfileTerminalModel::Dynamic {
            rows: 60,
            cols: 120
        }
    );

    let converted_back: TerminalModel = prof_dyn.try_into().unwrap();
    assert_eq!(converted_back.dimensions(), (60, 120));
}

#[test]
fn test_dynamic_model_needs_the_extended_data_stream() {
    // x3270 `oversize_init`: an oversize screen exists only with the extended data stream.
    let dynamic = ProfileTerminalModel::Dynamic {
        rows: 62,
        cols: 160,
    };
    let err = ConnectionProfile::builder()
        .terminal_model(dynamic)
        .extended(false)
        .build()
        .unwrap_err();
    assert!(matches!(err, NetError::Config(msg) if msg.contains("extended")));
    assert!(ConnectionProfile::builder()
        .terminal_model(dynamic)
        .extended(true)
        .build()
        .is_ok());
}

/// Settings that would not take effect are refused (no silent degradation): half a client
/// certificate configuration, a client certificate or a CA certificate on a plain-TCP profile.
#[test]
fn test_settings_without_effect_are_refused() {
    let base = "host = \"zos\"\nport = 992\n";
    for (extra, field) in [
        (
            "tls_mode = \"enabled\"\nclient_cert = \"/c.pem\"",
            "client_key",
        ),
        (
            "tls_mode = \"enabled\"\nclient_key = \"/c.key\"",
            "client_cert",
        ),
        (
            "tls_mode = \"disabled\"\nclient_cert = \"/c.pem\"\nclient_key = \"/c.key\"",
            "disabled",
        ),
        ("tls_mode = \"disabled\"\nca_cert = \"/ca.pem\"", "ca_cert"),
    ] {
        let err = parse(&format!("{base}{extra}")).expect_err("must be refused");
        assert!(err.to_string().contains(field), "{field}: {err}");
    }
    assert!(parse(&format!(
        "{base}tls_mode = \"enabled\"\nca_cert = \"/ca.pem\""
    ))
    .is_ok());
}

/// `tls_mode` has no default in a profile file: a profile that forgets it must not silently
/// connect in clear text.
#[test]
fn test_tls_mode_is_required_in_a_profile_file() {
    let err = ConnectionProfile::from_toml_str("host = \"zos\"\nport = 992")
        .expect_err("a profile without tls_mode must be refused");
    assert!(err.to_string().contains("tls_mode"), "{err}");
    for mode in ["enabled", "disabled"] {
        assert!(ConnectionProfile::from_toml_str(&format!(
            "host = \"zos\"\nport = 992\ntls_mode = \"{mode}\""
        ))
        .is_ok());
    }
}

/// Every built-in code page is accepted by name, number or x3270 alias; an unknown one is
/// refused with the list of supported names (not a stale subset).
#[test]
fn test_profile_accepts_every_built_in_code_page() {
    use bastion3270_core::CodePageId;
    use bastion3270_net::profile::ConnectionProfile;
    let with_codepage = |name: &str| ConnectionProfile {
        host: "127.0.0.1".into(),
        codepage: name.into(),
        ..ConnectionProfile::default()
    };
    for name in ["cp1047", "1141", "german-euro", "ibm500", "uk", "bracket"] {
        let profile = with_codepage(name);
        profile.validate().unwrap_or_else(|e| panic!("{name}: {e}"));
        let id = CodePageId::from_name(name).unwrap();
        assert_eq!(profile.core_codepage().unwrap().name(), id.name());
    }
    let err = with_codepage("cp9999").validate().unwrap_err().to_string();
    assert!(
        err.contains("cp9999") && err.contains("cp1047") && err.contains("cp1160"),
        "{err}"
    );
}

/// The LU name goes into the TN3270E negotiation as it is: only SNA names are accepted, so no
/// control byte (e.g. IAC) can be sent to the host through it.
#[test]
fn test_profile_lu_name_must_be_an_sna_name() {
    use bastion3270_net::profile::{is_lu_name, ConnectionProfile};
    for good in ["A", "LU3270A", "TSO0001", "@LU#$01", "tsolu01"] {
        assert!(is_lu_name(good), "{good}");
    }
    for bad in [
        "",
        "123ABC",
        "TOOLONG99",
        "LU 01",
        "LU\u{ff}",
        "LU-01",
        "LUÄ",
        "a\n",
    ] {
        assert!(!is_lu_name(bad), "{bad:?}");
        let profile = ConnectionProfile {
            host: "127.0.0.1".into(),
            lu_name: Some(bad.into()),
            ..ConnectionProfile::default()
        };
        assert!(profile.validate().is_err(), "{bad:?}");
    }
}
