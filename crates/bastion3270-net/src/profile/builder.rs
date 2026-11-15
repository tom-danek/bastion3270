//! Fluent builder for programmatically constructing a [`ConnectionProfile`].

use std::path::PathBuf;

use super::config::{ConnectionProfile, ProfileTerminalModel, TlsMode};
use crate::error::NetError;

/// Fluent builder for programmatically configuring a [`ConnectionProfile`].
#[derive(Debug, Clone)]
pub struct ConnectionProfileBuilder {
    profile: ConnectionProfile,
}

impl Default for ConnectionProfileBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionProfileBuilder {
    /// Creates a new builder initialized with default corporate settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            profile: ConnectionProfile::default(),
        }
    }

    /// Sets the target mainframe hostname or IP address.
    #[must_use]
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.profile.host = host.into();
        self
    }

    /// Sets the target TCP port.
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.profile.port = port;
        self
    }

    /// Sets the TLS encryption mode.
    #[must_use]
    pub fn tls_mode(mut self, mode: TlsMode) -> Self {
        self.profile.tls_mode = mode;
        self
    }

    /// Convenience helper to set TLS enabled (`true`) or disabled (`false`).
    #[must_use]
    pub fn with_tls(mut self, enabled: bool) -> Self {
        self.profile.tls_mode = if enabled {
            TlsMode::Enabled
        } else {
            TlsMode::Disabled
        };
        self
    }

    /// Adds a CA certificate file (PEM or DER; roots or intermediates) to the trusted ones.
    #[must_use]
    pub fn ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.profile.ca_cert = Some(path.into());
        self
    }

    /// Clears the CA certificate path (the Mozilla roots and the system store remain).
    #[must_use]
    pub fn clear_ca_cert(mut self) -> Self {
        self.profile.ca_cert = None;
        self
    }

    /// Sets the name the host's certificate must match instead of the host (x3270
    /// `acceptHostname`).
    #[must_use]
    pub fn accept_hostname(mut self, name: impl Into<String>) -> Self {
        self.profile.accept_hostname = Some(name.into());
        self
    }

    /// Trusts exactly the host certificate with this SHA-256 (64 hex digits).
    #[must_use]
    pub fn pinned_cert_sha256(mut self, fingerprint: impl Into<String>) -> Self {
        self.profile.pinned_cert_sha256 = Some(fingerprint.into());
        self
    }

    /// Sets the path to client certificate file for mTLS authentication.
    #[must_use]
    pub fn client_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.profile.client_cert = Some(path.into());
        self
    }

    /// Clears the client certificate path.
    #[must_use]
    pub fn clear_client_cert(mut self) -> Self {
        self.profile.client_cert = None;
        self
    }

    /// Sets the path to client private key file for mTLS authentication.
    #[must_use]
    pub fn client_key(mut self, path: impl Into<PathBuf>) -> Self {
        self.profile.client_key = Some(path.into());
        self
    }

    /// Clears the client private key path.
    #[must_use]
    pub fn clear_client_key(mut self) -> Self {
        self.profile.client_key = None;
        self
    }

    /// Sets the requested SNA Logical Unit (LU) name or pool name.
    #[must_use]
    pub fn lu_name(mut self, lu: impl Into<String>) -> Self {
        self.profile.lu_name = Some(lu.into());
        self
    }

    /// Clears the requested LU name (reverting to host dynamic allocation).
    #[must_use]
    pub fn clear_lu_name(mut self) -> Self {
        self.profile.lu_name = None;
        self
    }

    /// Sets the terminal display model.
    #[must_use]
    pub fn terminal_model(mut self, model: ProfileTerminalModel) -> Self {
        self.profile.terminal_model = model;
        self
    }

    /// Sets whether 3279 color capability is enabled.
    #[must_use]
    pub fn color_3279(mut self, color: bool) -> Self {
        self.profile.color_3279 = color;
        self
    }

    /// Sets whether extended data stream attributes (-E) are enabled.
    #[must_use]
    pub fn extended(mut self, extended: bool) -> Self {
        self.profile.extended = extended;
        self
    }

    /// Sets numeric lock (`x3270` `numericLock`).
    #[must_use]
    pub const fn numeric_lock(mut self, on: bool) -> Self {
        self.profile.numeric_lock = on;
        self
    }

    /// Sets blank fill (`x3270` `blankFill`).
    #[must_use]
    pub const fn blank_fill(mut self, on: bool) -> Self {
        self.profile.blank_fill = on;
        self
    }

    /// Sets the EBCDIC host code page name (e.g. `"cp037"` or `"cp870"`).
    #[must_use]
    pub fn codepage(mut self, codepage: impl Into<String>) -> Self {
        self.profile.codepage = codepage.into();
        self
    }

    /// Sets the connection timeout in milliseconds.
    #[must_use]
    pub fn connect_timeout_ms(mut self, ms: u64) -> Self {
        self.profile.connect_timeout_ms = ms;
        self
    }

    /// Sets the idle silence timeout in milliseconds.
    #[must_use]
    pub fn idle_timeout_ms(mut self, ms: u64) -> Self {
        self.profile.idle_timeout_ms = ms;
        self
    }

    /// Sets the deadline for one write to the host in milliseconds.
    #[must_use]
    pub fn write_timeout_ms(mut self, ms: u64) -> Self {
        self.profile.write_timeout_ms = ms;
        self
    }

    /// Sets the deadline from connect to completed Telnet negotiation in milliseconds.
    #[must_use]
    pub fn negotiation_timeout_ms(mut self, ms: u64) -> Self {
        self.profile.negotiation_timeout_ms = ms;
        self
    }

    /// Sets the bounded channel capacity for async backpressure.
    #[must_use]
    pub fn channel_capacity(mut self, cap: usize) -> Self {
        self.profile.channel_capacity = cap;
        self
    }

    /// Applies environment variable overrides with `BASTION3270_*` prefix to this builder.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if an environment variable has an invalid value.
    pub fn with_env_overrides(mut self) -> Result<Self, NetError> {
        self.profile.apply_env_overrides()?;
        Ok(self)
    }

    /// Applies environment overrides using a custom lookup closure.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if an environment variable has an invalid value.
    pub fn with_env_lookup<F>(mut self, lookup: &F) -> Result<Self, NetError>
    where
        F: Fn(&str) -> Option<String>,
    {
        self.profile.apply_env_lookup(lookup)?;
        Ok(self)
    }

    /// Validates and constructs the finalized [`ConnectionProfile`].
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if validation fails.
    pub fn build(self) -> Result<ConnectionProfile, NetError> {
        self.profile.validate()?;
        Ok(self.profile)
    }
}
