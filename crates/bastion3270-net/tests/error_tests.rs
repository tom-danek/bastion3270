//! Integration tests for `NetError` hierarchy and Display/Error traits.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use bastion3270_net::{NetError, Result};
use std::error::Error;

#[test]
fn test_net_error_variants() {
    let err = NetError::ConnectTimeout;
    assert!(err.is_connect_timeout());
    assert!(!err.is_idle_timeout());
    assert_eq!(
        format!("{err}"),
        "connection timed out during connect or TLS handshake"
    );
    assert!(err.source().is_none());

    let err = NetError::IdleTimeout;
    assert!(err.is_idle_timeout());
    assert_eq!(
        format!("{err}"),
        "connection timed out due to host inactivity (idle timeout)"
    );

    let err = NetError::config("invalid terminal model");
    assert!(err.is_config());
    assert_eq!(
        format!("{err}"),
        "configuration error: invalid terminal model"
    );

    let err = NetError::invalid_certificate("failed to parse PEM");
    assert!(err.is_invalid_certificate());
    assert_eq!(format!("{err}"), "invalid certificate: failed to parse PEM");

    let err = NetError::protocol("outbound buffer overflow");
    assert!(err.is_protocol());
    assert_eq!(format!("{err}"), "protocol error: outbound buffer overflow");

    let err = NetError::channel("backpressure queue dropped");
    assert!(err.is_channel());
    assert_eq!(
        format!("{err}"),
        "channel communication error: backpressure queue dropped"
    );
}

#[test]
fn test_io_error_wrapping() {
    let io = std::io::Error::new(std::io::ErrorKind::TimedOut, "socket timeout");
    let net_err: NetError = io.into();
    assert!(net_err.is_io());
    assert!(net_err.source().is_some());
    assert!(format!("{net_err}").contains("I/O error: socket timeout"));
}

#[test]
fn test_tls_error_wrapping() {
    let tls = rustls::Error::HandshakeNotComplete;
    let net_err: NetError = tls.into();
    assert!(net_err.is_tls());
    assert!(net_err.source().is_some());
    assert!(format!("{net_err}").contains("TLS error:"));
}

#[test]
fn test_result_type_alias() {
    #[allow(clippy::unnecessary_wraps)]
    fn succeed() -> Result<u32> {
        Ok(42)
    }

    fn fail() -> Result<u32> {
        Err(NetError::ConnectTimeout)
    }

    assert_eq!(succeed().unwrap(), 42);
    assert!(fail().unwrap_err().is_connect_timeout());
}

#[test]
fn test_core_error_conversions() {
    let telnet: NetError = bastion3270_core::TelnetError::InvalidDataType(0xFF).into();
    assert!(telnet.is_protocol());
    assert!(format!("{telnet}").contains("telnet protocol error"));

    let datastream: NetError = bastion3270_core::DatastreamError::UnknownCommand(0x05).into();
    assert!(datastream.is_protocol());
    assert!(format!("{datastream}").contains("3270 datastream error"));

    let keyboard: NetError = bastion3270_core::KeyboardError::ProtectedField.into();
    assert!(keyboard.is_protocol());
    assert!(format!("{keyboard}").contains("virtual keyboard error"));

    let wsf: NetError = bastion3270_core::WsfError::TruncatedField {
        expected: 4,
        available: 2,
    }
    .into();
    assert!(wsf.is_protocol());
    assert!(format!("{wsf}").contains("structured field error"));

    let model: NetError =
        bastion3270_core::ModelError::InvalidDimension { rows: 0, cols: 0 }.into();
    assert!(model.is_config());
    assert!(format!("{model}").contains("terminal model error"));

    let safe_view: NetError = bastion3270_core::SafeViewError::CursorOutOfBounds {
        cursor_row: 100,
        cursor_col: 100,
        rows: 24,
        cols: 80,
    }
    .into();
    assert!(safe_view.is_protocol());
    assert!(format!("{safe_view}").contains("safe view error"));

    let screen: NetError = bastion3270_core::ScreenError::InvalidAddress(
        bastion3270_core::AddressError::OutOfBounds {
            address: 9999,
            capacity: 1920,
        },
    )
    .into();
    assert!(screen.is_protocol());
    assert!(format!("{screen}").contains("screen error"));
}

#[test]
fn test_channel_error_conversions() {
    let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
    drop(tx);
    let recv_err = rx.blocking_recv().unwrap_err();
    let net_err: NetError = recv_err.into();
    assert!(net_err.is_channel());
    assert!(format!("{net_err}").contains("oneshot channel receive error"));

    let (mpsc_tx, mpsc_rx) = tokio::sync::mpsc::channel::<i32>(1);
    drop(mpsc_rx);
    let send_err = mpsc_tx.blocking_send(10).unwrap_err();
    let net_err: NetError = send_err.into();
    assert!(net_err.is_channel());
    assert!(format!("{net_err}").contains("mpsc channel closed"));
}
