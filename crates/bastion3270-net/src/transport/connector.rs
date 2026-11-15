//! High-level transport connection entry point.
//!
//! Provides the primary [`connect`] function that translates a [`ConnectionProfile`]
//! into an active, validated [`TransportStream`].

use std::time::Duration;

use crate::error::Result;
use crate::profile::{ConnectionProfile, TlsMode};
use crate::transport::stream::TransportStream;
use crate::transport::tcp::{self, IdleTimeoutStream};
use crate::transport::tls;
use crate::transport::trust::HostTrust;

/// Establishes an asynchronous network transport stream based on the provided [`ConnectionProfile`].
///
/// # Behavior
/// 1. Validates the profile configuration against corporate rules ([`ConnectionProfile::validate`]).
/// 2. Applies the configured `connect_timeout_ms` deadline across the entire connection process:
///    - For plain TCP: DNS resolution and the TCP 3-way handshake must complete within the deadline.
///    - For TLS: DNS resolution, TCP handshake, and the TLS handshake must complete within the deadline.
/// 3. Returns [`NetError::ConnectTimeout`](crate::error::NetError::ConnectTimeout) if the deadline expires.
/// 4. Returns [`NetError::Io`](crate::error::NetError::Io) if an OS-level network failure occurs (e.g. connection refused).
/// 5. Returns [`NetError::InvalidCertificate`](crate::error::NetError::InvalidCertificate) or
///    [`NetError::Tls`](crate::error::NetError::Tls) if TLS certificate loading or handshake fails.
///
/// # Errors
/// Returns [`NetError`](crate::error::NetError) if profile validation, DNS resolution, TCP connection,
/// or TLS handshake fails.
pub async fn connect(profile: &ConnectionProfile) -> Result<TransportStream> {
    connect_with_trust(profile, &HostTrust::system()).await
}

/// [`connect`] with the application's trust anchors for the host's certificate (e.g. the
/// Mozilla roots, the system store and the gateway's CA files).
///
/// # Errors
/// As [`connect`].
pub async fn connect_with_trust(
    profile: &ConnectionProfile,
    trust: &HostTrust,
) -> Result<TransportStream> {
    profile.validate()?;

    let timeout_duration = Duration::from_millis(profile.connect_timeout_ms);

    match profile.tls_mode {
        TlsMode::Disabled => {
            let tcp_stream =
                tcp::connect_tcp(&profile.host, profile.port, timeout_duration).await?;
            Ok(TransportStream::Plain(tcp_stream))
        }
        TlsMode::Enabled => {
            let tls_stream = tls::connect_tls_with_trust(profile, trust, timeout_duration).await?;
            Ok(TransportStream::Tls(tls_stream))
        }
    }
}

/// Establishes a connection and wraps it in an [`IdleTimeoutStream`] initialized with `profile.idle_timeout_ms`.
///
/// # Errors
/// Returns [`NetError`](crate::error::NetError) if connection establishment fails.
pub async fn connect_with_idle_timeout(
    profile: &ConnectionProfile,
) -> Result<IdleTimeoutStream<TransportStream>> {
    let stream = connect(profile).await?;
    let idle_timeout = Duration::from_millis(profile.idle_timeout_ms);
    Ok(IdleTimeoutStream::new(stream, idle_timeout))
}
