//! Adversarial empirical verification suite for `NetError` and crate root architecture.
//!
//! Validates:
//! 1. All 8 variants and their query predicates (8x8 exclusivity matrix).
//! 2. Error source chaining and dynamic downcasting (`Io` and `Tls` return source, others return None).
//! 3. All 13 `From` conversions preserving context across `bastion3270-core`, `toml`, `tokio`, and `std`.
//! 4. Question-mark `?` propagation with the `Result<T>` alias.
//! 5. Adversarial input resilience (1MB strings, null bytes, format specifiers, Unicode).
//! 6. Concurrency and thread safety (`Send + Sync + 'static` across threads and Tokio tasks).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::unnecessary_literal_unwrap
)]

use bastion3270_net::{NetError, Result};
use std::error::Error;

// =========================================================================
// 1. Predicate Exclusivity Matrix (8x8 = 64 assertions)
// =========================================================================

#[test]
fn test_predicate_exclusivity_matrix() {
    let variants: Vec<(&'static str, NetError)> = vec![
        (
            "Io",
            NetError::Io(std::io::Error::other("adversarial socket disconnect")),
        ),
        ("Tls", NetError::Tls(rustls::Error::HandshakeNotComplete)),
        ("Config", NetError::config("missing LU name")),
        (
            "InvalidCertificate",
            NetError::invalid_certificate("corrupt ASN.1 DER payload"),
        ),
        ("ConnectTimeout", NetError::ConnectTimeout),
        ("IdleTimeout", NetError::IdleTimeout),
        (
            "Protocol",
            NetError::protocol("unexpected IAC SB terminating sequence"),
        ),
        (
            "Channel",
            NetError::channel("backpressure bounded queue full"),
        ),
    ];

    for (name, err) in &variants {
        let is_io = err.is_io();
        let is_tls = err.is_tls();
        let is_cfg = err.is_config();
        let is_cert = err.is_invalid_certificate();
        let is_conn_to = err.is_connect_timeout();
        let is_idle_to = err.is_idle_timeout();
        let is_proto = err.is_protocol();
        let is_chan = err.is_channel();

        let count = [
            is_io, is_tls, is_cfg, is_cert, is_conn_to, is_idle_to, is_proto, is_chan,
        ]
        .iter()
        .filter(|&&b| b)
        .count();

        assert_eq!(
            count, 1,
            "Variant {name} must have exactly one predicate returning true! Predicates: io={is_io}, tls={is_tls}, config={is_cfg}, cert={is_cert}, conn_to={is_conn_to}, idle_to={is_idle_to}, proto={is_proto}, chan={is_chan}"
        );

        match *name {
            "Io" => assert!(is_io),
            "Tls" => assert!(is_tls),
            "Config" => assert!(is_cfg),
            "InvalidCertificate" => assert!(is_cert),
            "ConnectTimeout" => assert!(is_conn_to),
            "IdleTimeout" => assert!(is_idle_to),
            "Protocol" => assert!(is_proto),
            "Channel" => assert!(is_chan),
            other => panic!("Unexpected variant in test: {other}"),
        }
    }
}

// =========================================================================
// 2. Source Chaining & Dynamic Downcasting
// =========================================================================

#[test]
fn test_error_source_chaining_and_downcast() {
    // 2a. std::io::Error
    let custom_io = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "peer reset TCP");
    let net_io = NetError::Io(custom_io);
    let src = net_io.source().expect("Io must provide source");
    let downcasted = src
        .downcast_ref::<std::io::Error>()
        .expect("downcast to std::io::Error");
    assert_eq!(downcasted.kind(), std::io::ErrorKind::ConnectionAborted);
    assert!(downcasted.to_string().contains("peer reset TCP"));

    // 2b. rustls::Error
    let rustls_err = rustls::Error::AlertReceived(rustls::AlertDescription::BadCertificate);
    let net_tls = NetError::Tls(rustls_err);
    let src = net_tls.source().expect("Tls must provide source");
    let downcasted = src
        .downcast_ref::<rustls::Error>()
        .expect("downcast to rustls::Error");
    assert!(matches!(
        downcasted,
        rustls::Error::AlertReceived(rustls::AlertDescription::BadCertificate)
    ));

    // 2c. All non-chained variants must strictly return None
    assert!(NetError::Config("test".into()).source().is_none());
    assert!(NetError::InvalidCertificate("test".into())
        .source()
        .is_none());
    assert!(NetError::ConnectTimeout.source().is_none());
    assert!(NetError::IdleTimeout.source().is_none());
    assert!(NetError::Protocol("test".into()).source().is_none());
    assert!(NetError::Channel("test".into()).source().is_none());
}

// =========================================================================
// 3. All 13 From Conversions: Context Preservation
// =========================================================================

#[test]
fn test_all_13_from_conversions_preserve_context() {
    // 1. std::io::Error -> Io
    let io_raw = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "cannot bind socket");
    let net_err: NetError = io_raw.into();
    assert!(net_err.is_io());
    assert!(format!("{net_err}").contains("I/O error: cannot bind socket"));

    // 2. rustls::Error -> Tls
    let tls_raw = rustls::Error::General("tls issue".into());
    let net_err: NetError = tls_raw.into();
    assert!(net_err.is_tls());
    assert!(format!("{net_err}").contains("TLS error:"));
    assert!(format!("{net_err}").contains("tls issue"));

    // 3. toml::de::Error -> Config
    let bad_toml = "[section\nunclosed = 1";
    let de_err = toml::from_str::<toml::Value>(bad_toml).unwrap_err();
    let net_err: NetError = de_err.into();
    assert!(net_err.is_config());
    let msg = format!("{net_err}");
    assert!(msg.starts_with("configuration error: TOML deserialization error:"));

    // 4. toml::ser::Error -> Config
    // Induce a serialization error: a TOML document must be a table, a bare string is not.
    let ser_err = toml::to_string("not a table").unwrap_err();
    let net_err: NetError = ser_err.into();
    assert!(net_err.is_config());
    let msg = format!("{net_err}");
    assert!(msg.starts_with("configuration error: TOML serialization error:"));

    // 5. bastion3270_core::TelnetError -> Protocol
    let telnet_err = bastion3270_core::TelnetError::FrameTooLarge {
        size: 70000,
        max: 65536,
    };
    let net_err: NetError = telnet_err.into();
    assert!(net_err.is_protocol());
    let msg = format!("{net_err}");
    assert!(msg.contains("protocol error: telnet protocol error:"));
    assert!(msg.contains("70000 > 65536 bytes"));

    // 6. bastion3270_core::DatastreamError -> Protocol
    let ds_err = bastion3270_core::DatastreamError::UnexpectedEof {
        expected: "order parameters",
        needed: 4,
        remaining: 1,
    };
    let net_err: NetError = ds_err.into();
    assert!(net_err.is_protocol());
    let msg = format!("{net_err}");
    assert!(msg.contains("protocol error: 3270 datastream error:"));
    assert!(msg.contains("unexpected EOF reading order parameters"));

    // 7. bastion3270_core::KeyboardError -> Protocol
    let kbd_err = bastion3270_core::KeyboardError::NumericField;
    let net_err: NetError = kbd_err.into();
    assert!(net_err.is_protocol());
    let msg = format!("{net_err}");
    assert!(msg.contains("protocol error: virtual keyboard error:"));
    assert!(msg.contains("cannot insert non-numeric character"));

    // 8. bastion3270_core::WsfError -> Protocol
    let wsf_err = bastion3270_core::WsfError::InvalidPartition {
        expected: 0xFF,
        actual: 0x42,
    };
    let net_err: NetError = wsf_err.into();
    assert!(net_err.is_protocol());
    let msg = format!("{net_err}");
    assert!(msg.contains("protocol error: structured field error:"));
    assert!(msg.contains("invalid partition ID 0x42 for query (expected 0xFF)"));

    // 9. bastion3270_core::ModelError -> Config
    let model_err = bastion3270_core::ModelError::InvalidDimension {
        rows: 300,
        cols: 80,
    };
    let net_err: NetError = model_err.into();
    assert!(net_err.is_config());
    let msg = format!("{net_err}");
    assert!(msg.contains("configuration error: terminal model error:"));
    assert!(msg.contains("invalid 3270 screen dimensions 300x80"));

    // 10. bastion3270_core::SafeViewError -> Protocol
    let sv_err = bastion3270_core::SafeViewError::DimensionMismatch {
        rows: 24,
        cols: 80,
        expected_cells: 1920,
        actual_cells: 1000,
    };
    let net_err: NetError = sv_err.into();
    assert!(net_err.is_protocol());
    let msg = format!("{net_err}");
    assert!(msg.contains("protocol error: safe view error:"));
    assert!(msg.contains("cell vector length 1000 does not match 24x80"));

    // 11. bastion3270_core::ScreenError -> Protocol
    let screen_err = bastion3270_core::ScreenError::InvalidAddress(
        bastion3270_core::AddressError::OutOfBounds {
            address: 2000,
            capacity: 1920,
        },
    );
    let net_err: NetError = screen_err.into();
    assert!(net_err.is_protocol());
    let msg = format!("{net_err}");
    assert!(msg.contains("protocol error: screen error:"));
    assert!(msg.contains("3270 buffer address 2000 is out of bounds for screen capacity 1920"));

    // 12. tokio::sync::oneshot::error::RecvError -> Channel
    let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    drop(tx);
    let recv_err = rx.blocking_recv().unwrap_err();
    let net_err: NetError = recv_err.into();
    assert!(net_err.is_channel());
    let msg = format!("{net_err}");
    assert!(
        msg.contains("channel communication error: oneshot channel receive error: channel closed")
    );

    // 13. tokio::sync::mpsc::error::SendError<T> -> Channel
    let (mpsc_tx, mpsc_rx) = tokio::sync::mpsc::channel::<String>(1);
    drop(mpsc_rx);
    let send_err = mpsc_tx.blocking_send("payload".to_string()).unwrap_err();
    let net_err: NetError = send_err.into();
    assert!(net_err.is_channel());
    let msg = format!("{net_err}");
    assert_eq!(
        msg,
        "channel communication error: mpsc channel closed: receiver dropped"
    );
}

// =========================================================================
// 4. Result<T> Alias and ? Operator Chaining
// =========================================================================

#[test]
fn test_result_alias_and_question_mark_propagation() {
    fn trigger_io() -> Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        ))?;
        Ok(())
    }

    fn trigger_tls() -> Result<()> {
        Err(rustls::Error::HandshakeNotComplete)?;
        Ok(())
    }

    fn trigger_toml_de() -> Result<()> {
        let err = toml::from_str::<toml::Value>("[bad").unwrap_err();
        Err(err)?;
        Ok(())
    }

    fn trigger_telnet() -> Result<()> {
        Err(bastion3270_core::TelnetError::InvalidDataType(0xFE))?;
        Ok(())
    }

    fn trigger_datastream() -> Result<()> {
        Err(bastion3270_core::DatastreamError::EmptyStream)?;
        Ok(())
    }

    fn trigger_keyboard() -> Result<()> {
        Err(bastion3270_core::KeyboardError::ProtectedField)?;
        Ok(())
    }

    fn trigger_wsf() -> Result<()> {
        Err(bastion3270_core::WsfError::InvalidQueryType(0x01))?;
        Ok(())
    }

    fn trigger_model() -> Result<()> {
        Err(bastion3270_core::ModelError::InvalidDimension { rows: 0, cols: 0 })?;
        Ok(())
    }

    fn trigger_safe_view() -> Result<()> {
        Err(bastion3270_core::SafeViewError::CursorOutOfBounds {
            cursor_row: 99,
            cursor_col: 99,
            rows: 24,
            cols: 80,
        })?;
        Ok(())
    }

    fn trigger_screen() -> Result<()> {
        Err(bastion3270_core::ScreenError::InvalidAddress(
            bastion3270_core::AddressError::OutOfBounds {
                address: 9999,
                capacity: 1920,
            },
        ))?;
        Ok(())
    }

    assert!(trigger_io().unwrap_err().is_io());
    assert!(trigger_tls().unwrap_err().is_tls());
    assert!(trigger_toml_de().unwrap_err().is_config());
    assert!(trigger_telnet().unwrap_err().is_protocol());
    assert!(trigger_datastream().unwrap_err().is_protocol());
    assert!(trigger_keyboard().unwrap_err().is_protocol());
    assert!(trigger_wsf().unwrap_err().is_protocol());
    assert!(trigger_model().unwrap_err().is_config());
    assert!(trigger_safe_view().unwrap_err().is_protocol());
    assert!(trigger_screen().unwrap_err().is_protocol());
}

// =========================================================================
// 5. Adversarial Input Stress Testing (No Panics)
// =========================================================================

#[test]
fn test_adversarial_input_resilience() {
    // 5a. 1 Megabyte string inside error message
    let huge_str = "A".repeat(1_000_000);
    let cfg_err = NetError::config(&huge_str);
    assert!(cfg_err.is_config());
    let formatted = format!("{cfg_err}");
    assert!(formatted.starts_with("configuration error: AAAAA"));
    assert_eq!(formatted.len(), 1_000_000 + "configuration error: ".len());

    // 5b. Null bytes and control characters
    let dirty_str = "malformed\0\x01\x02payload\r\n\t--inject{}";
    let proto_err = NetError::protocol(dirty_str);
    let disp = format!("{proto_err}");
    assert!(disp.contains("malformed\0\x01\x02payload\r\n\t--inject{}"));

    // 5c. Unicode stress test: RTL, emoji, surrogate pairs, zero-width joiners
    let unicode_stress = "⚠️ IBM z/OS 3270: 👨‍👩‍👧‍👦 \u{200B}\u{FEFF} مرحبا بالعالم 漢字";
    let cert_err = NetError::invalid_certificate(unicode_stress);
    let disp = format!("{cert_err}");
    assert!(disp.contains(unicode_stress));

    // 5d. Empty strings
    let empty_cfg = NetError::config("");
    assert_eq!(format!("{empty_cfg}"), "configuration error: ");

    let empty_proto = NetError::protocol("");
    assert_eq!(format!("{empty_proto}"), "protocol error: ");

    let empty_chan = NetError::channel("");
    assert_eq!(format!("{empty_chan}"), "channel communication error: ");

    let empty_cert = NetError::invalid_certificate("");
    assert_eq!(format!("{empty_cert}"), "invalid certificate: ");

    // 5e. Format string specifiers inside error payload (must NOT cause format injection)
    let specifier_payload = "{0} {:?} {:#?} %s %d %x {err}";
    let spec_err = NetError::config(specifier_payload);
    assert_eq!(
        format!("{spec_err}"),
        format!("configuration error: {specifier_payload}")
    );
}

// =========================================================================
// 6. Concurrency, Send + Sync, and Tokio Task Handoff
// =========================================================================

#[test]
fn test_send_sync_across_threads_and_tokio() {
    fn assert_send_sync<T: Send + Sync + 'static + Unpin>() {}
    assert_send_sync::<NetError>();

    // Send across std::thread
    let err = NetError::ConnectTimeout;
    let handle = std::thread::spawn(move || {
        assert!(err.is_connect_timeout());
        format!("{err}")
    });
    let result = handle.join().expect("thread join");
    assert_eq!(
        result,
        "connection timed out during connect or TLS handshake"
    );

    // Send across Tokio tasks via mpsc channel
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime build");

    rt.block_on(async {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<NetError>(4);

        tokio::spawn(async move {
            tx.send(NetError::IdleTimeout).await.expect("send");
            tx.send(NetError::config("worker thread failure"))
                .await
                .expect("send");
        });

        let e1 = rx.recv().await.expect("recv e1");
        assert!(e1.is_idle_timeout());

        let e2 = rx.recv().await.expect("recv e2");
        assert!(e2.is_config());
    });
}

// =========================================================================
// 7. Exhaustive Variant Coverage for all Domain Errors
// =========================================================================

#[test]
fn test_exhaustive_domain_error_variants_conversion() {
    // 7a. TelnetError variants
    let telnet_variants = vec![
        bastion3270_core::TelnetError::TruncatedHeader {
            needed: 5,
            available: 3,
        },
        bastion3270_core::TelnetError::InvalidDataType(0x99),
        bastion3270_core::TelnetError::InvalidOperation(0x88),
        bastion3270_core::TelnetError::FrameTooLarge {
            size: 100000,
            max: 65536,
        },
        bastion3270_core::TelnetError::SubnegotiationTooLarge {
            size: 2048,
            max: 1024,
        },
        bastion3270_core::TelnetError::OutboundQueueFull {
            size: 200000,
            max: 131072,
        },
        bastion3270_core::TelnetError::InvalidSubnegotiation("corrupt SB"),
        bastion3270_core::TelnetError::InvalidBindRu("invalid presentation space size"),
    ];
    for t_err in telnet_variants {
        let expected_fragment = format!("{t_err}");
        let net_err: NetError = t_err.into();
        assert!(net_err.is_protocol());
        let disp = format!("{net_err}");
        assert!(
            disp.contains(&expected_fragment),
            "Display '{disp}' should contain '{expected_fragment}'"
        );
    }

    // 7b. DatastreamError variants
    let ds_variants = vec![
        bastion3270_core::DatastreamError::EmptyStream,
        bastion3270_core::DatastreamError::UnknownCommand(0xEE),
        bastion3270_core::DatastreamError::UnexpectedEof {
            expected: "SBA address",
            needed: 2,
            remaining: 1,
        },
        bastion3270_core::DatastreamError::InvalidAddress(
            bastion3270_core::AddressError::OutOfBounds {
                address: 5000,
                capacity: 1920,
            },
        ),
        bastion3270_core::DatastreamError::InvalidStructuredFieldLength {
            length: 100,
            remaining: 10,
        },
        bastion3270_core::DatastreamError::Screen(bastion3270_core::ScreenError::InvalidAddress(
            bastion3270_core::AddressError::OutOfBounds {
                address: 9999,
                capacity: 1920,
            },
        )),
    ];
    for ds_err in ds_variants {
        let expected_fragment = format!("{ds_err}");
        let net_err: NetError = ds_err.into();
        assert!(net_err.is_protocol());
        let disp = format!("{net_err}");
        assert!(
            disp.contains(&expected_fragment),
            "Display '{disp}' should contain '{expected_fragment}'"
        );
    }

    // 7c. KeyboardError variants
    let kbd_variants = vec![
        bastion3270_core::KeyboardError::Locked(bastion3270_core::KeyboardState::TimeWait),
        bastion3270_core::KeyboardError::ProtectedField,
        bastion3270_core::KeyboardError::NumericField,
        bastion3270_core::KeyboardError::Encoding(
            bastion3270_core::EncodingError::UnmappableChar {
                ch: '§',
                codepage: "cp037",
            },
        ),
        bastion3270_core::KeyboardError::Screen(bastion3270_core::ScreenError::InvalidAddress(
            bastion3270_core::AddressError::OutOfBounds {
                address: 4000,
                capacity: 1920,
            },
        )),
    ];
    for k_err in kbd_variants {
        let expected_fragment = format!("{k_err}");
        let net_err: NetError = k_err.into();
        assert!(net_err.is_protocol());
        let disp = format!("{net_err}");
        assert!(
            disp.contains(&expected_fragment),
            "Display '{disp}' should contain '{expected_fragment}'"
        );
    }

    // 7d. WsfError variants
    let wsf_variants = vec![
        bastion3270_core::WsfError::TruncatedField {
            expected: 8,
            available: 2,
        },
        bastion3270_core::WsfError::InvalidPartition {
            expected: 0xFF,
            actual: 0x01,
        },
        bastion3270_core::WsfError::InvalidQueryType(0x55),
        bastion3270_core::WsfError::InvalidRequestType(0x10),
        bastion3270_core::WsfError::InvalidStructuredFieldLength {
            length: 50,
            available: 12,
        },
    ];
    for w_err in wsf_variants {
        let expected_fragment = format!("{w_err}");
        let net_err: NetError = w_err.into();
        assert!(net_err.is_protocol());
        let disp = format!("{net_err}");
        assert!(
            disp.contains(&expected_fragment),
            "Display '{disp}' should contain '{expected_fragment}'"
        );
    }

    // 7e. ModelError variants
    let model_variants = vec![
        bastion3270_core::ModelError::InvalidDimension { rows: 0, cols: 80 },
        bastion3270_core::ModelError::CapacityExceeded {
            rows: 255,
            cols: 255,
            total_cells: 65025,
        },
    ];
    for m_err in model_variants {
        let expected_fragment = format!("{m_err}");
        let net_err: NetError = m_err.into();
        assert!(net_err.is_config());
        let disp = format!("{net_err}");
        assert!(
            disp.contains(&expected_fragment),
            "Display '{disp}' should contain '{expected_fragment}'"
        );
    }

    // 7f. SafeViewError variants
    let sv_variants = vec![
        bastion3270_core::SafeViewError::DimensionMismatch {
            rows: 24,
            cols: 80,
            expected_cells: 1920,
            actual_cells: 0,
        },
        bastion3270_core::SafeViewError::CursorOutOfBounds {
            cursor_row: 25,
            cursor_col: 81,
            rows: 24,
            cols: 80,
        },
    ];
    for sv_err in sv_variants {
        let expected_fragment = format!("{sv_err}");
        let net_err: NetError = sv_err.into();
        assert!(net_err.is_protocol());
        let disp = format!("{net_err}");
        assert!(
            disp.contains(&expected_fragment),
            "Display '{disp}' should contain '{expected_fragment}'"
        );
    }
}

// =========================================================================
// 8. Multiple std::io::ErrorKind and rustls::Error Variants
// =========================================================================

#[test]
fn test_io_kinds_and_rustls_variants() {
    let io_kinds = [
        std::io::ErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::NotConnected,
        std::io::ErrorKind::AddrInUse,
        std::io::ErrorKind::AddrNotAvailable,
        std::io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::AlreadyExists,
        std::io::ErrorKind::WouldBlock,
        std::io::ErrorKind::InvalidInput,
        std::io::ErrorKind::InvalidData,
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::WriteZero,
        std::io::ErrorKind::Interrupted,
        std::io::ErrorKind::Unsupported,
        std::io::ErrorKind::UnexpectedEof,
        std::io::ErrorKind::OutOfMemory,
        std::io::ErrorKind::Other,
    ];

    for kind in io_kinds {
        let io_err = std::io::Error::new(kind, format!("simulated kind {kind:?}"));
        let net_err: NetError = io_err.into();
        assert!(net_err.is_io());
        assert!(net_err.source().is_some());
        assert!(format!("{net_err}").contains(&format!("simulated kind {kind:?}")));
    }

    let rustls_errors = [
        rustls::Error::HandshakeNotComplete,
        rustls::Error::General("general failure".into()),
        rustls::Error::AlertReceived(rustls::AlertDescription::AccessDenied),
        rustls::Error::AlertReceived(rustls::AlertDescription::CertificateRevoked),
        rustls::Error::AlertReceived(rustls::AlertDescription::UnknownCA),
        rustls::Error::NoApplicationProtocol,
    ];

    for r_err in rustls_errors {
        let net_err: NetError = r_err.into();
        assert!(net_err.is_tls());
        assert!(net_err.source().is_some());
        assert!(format!("{net_err}").starts_with("TLS error:"));
    }
}

// =========================================================================
// 9. SendError<T> with diverse generic types
// =========================================================================

#[test]
fn test_mpsc_send_error_generic_types() {
    // 9a. SendError<Vec<u8>>
    let (tx1, rx1) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    drop(rx1);
    let err1: NetError = tx1.blocking_send(vec![1, 2, 3]).unwrap_err().into();
    assert!(err1.is_channel());
    assert_eq!(
        format!("{err1}"),
        "channel communication error: mpsc channel closed: receiver dropped"
    );

    // 9b. SendError<u64>
    let (tx2, rx2) = tokio::sync::mpsc::channel::<u64>(1);
    drop(rx2);
    let err2: NetError = tx2.blocking_send(42).unwrap_err().into();
    assert!(err2.is_channel());

    // 9c. SendError<()>
    let (tx3, rx3) = tokio::sync::mpsc::channel::<()>(1);
    drop(rx3);
    let err3: NetError = tx3.blocking_send(()).unwrap_err().into();
    assert!(err3.is_channel());
}

// =========================================================================
// 10. String Type Polymorphism for Helper Constructors
// =========================================================================

#[test]
fn test_constructor_string_polymorphism() {
    // &str
    let e1 = NetError::config("str slice");
    assert_eq!(format!("{e1}"), "configuration error: str slice");

    // String
    let e2 = NetError::invalid_certificate(String::from("owned string"));
    assert_eq!(format!("{e2}"), "invalid certificate: owned string");

    // Box<str>
    let e3 = NetError::protocol(String::from("boxed str").into_boxed_str());
    assert_eq!(format!("{e3}"), "protocol error: boxed str");

    // Cow<'static, str>
    let cow: std::borrow::Cow<'static, str> = std::borrow::Cow::Borrowed("cow string");
    let e4 = NetError::channel(cow);
    assert_eq!(format!("{e4}"), "channel communication error: cow string");
}

// =========================================================================
// 11. Result<T, E> Type Alias Flexibility
// =========================================================================

#[test]
fn test_result_type_alias_two_type_params() {
    // Default E = NetError
    let res1: Result<i32> = Ok(100);
    assert_eq!(res1.unwrap(), 100);

    // Explicit custom E
    #[derive(Debug, PartialEq, Eq)]
    struct CustomError(usize);
    let res2: Result<i32, CustomError> = Err(CustomError(404));
    assert_eq!(res2.unwrap_err(), CustomError(404));
}
