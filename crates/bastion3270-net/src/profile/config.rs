//! [`ConnectionProfile`] data model, TOML deserialization, validation, and ENV overrides.

use core::fmt;
use core::str::FromStr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rustls_pki_types::ServerName;

use crate::error::NetError;
use crate::transport::certificate::parse_sha256_hex;

/// Corporate default mainframe host (local Hercules emulator).
pub const DEFAULT_HOST: &str = "127.0.0.1";
/// Corporate default TCP port (standard TN3270 port).
pub const DEFAULT_PORT: u16 = 3270;
/// Corporate default for 3279 color mode (enabled).
pub const DEFAULT_COLOR_3279: bool = true;
/// Corporate default for extended data stream attributes (enabled).
pub const DEFAULT_EXTENDED: bool = true;
/// Corporate default EBCDIC code page (IBM US / Canada standard).
pub const DEFAULT_CODEPAGE: &str = "cp037";
/// Corporate default connection timeout in milliseconds (10 seconds).
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
/// Corporate default inactivity silence timeout in milliseconds (60 seconds).
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
/// Default deadline for one write to the host in milliseconds (30 seconds).
pub const DEFAULT_WRITE_TIMEOUT_MS: u64 = 30_000;
/// Default deadline from connect to completed Telnet negotiation in milliseconds (30 seconds).
pub const DEFAULT_NEGOTIATION_TIMEOUT_MS: u64 = 30_000;
/// Corporate default bounded channel capacity for backpressure.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 128;
/// Largest accepted channel capacity (tokio's bounded channel has an upper limit; a session
/// never needs more than a few dozen queued commands).
pub const MAX_CHANNEL_CAPACITY: usize = 4096;

fn default_host() -> String {
    DEFAULT_HOST.to_string()
}

const fn default_port() -> u16 {
    DEFAULT_PORT
}

const fn default_model() -> ProfileTerminalModel {
    ProfileTerminalModel::Model2
}

const fn default_color() -> bool {
    DEFAULT_COLOR_3279
}

const fn default_extended() -> bool {
    DEFAULT_EXTENDED
}

const fn default_numeric_lock() -> bool {
    bastion3270_core::KeyboardOptions::DEFAULT.numeric_lock
}

const fn default_blank_fill() -> bool {
    bastion3270_core::KeyboardOptions::DEFAULT.blank_fill
}

/// `true` for an SNA LU (or LU pool) name: 1 to 8 characters `A`-`Z` (either case), `0`-`9`,
/// `@`, `#`, `$`, the first not a digit.
#[must_use]
pub fn is_lu_name(name: &str) -> bool {
    let valid = |c: char| c.is_ascii_alphanumeric() || matches!(c, '@' | '#' | '$');
    (1..=8).contains(&name.len())
        && name.chars().all(valid)
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

fn default_codepage() -> String {
    DEFAULT_CODEPAGE.to_string()
}

const fn default_connect_timeout() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_MS
}

const fn default_idle_timeout() -> u64 {
    DEFAULT_IDLE_TIMEOUT_MS
}

const fn default_write_timeout() -> u64 {
    DEFAULT_WRITE_TIMEOUT_MS
}

const fn default_negotiation_timeout() -> u64 {
    DEFAULT_NEGOTIATION_TIMEOUT_MS
}

const fn default_channel_capacity() -> usize {
    DEFAULT_CHANNEL_CAPACITY
}

/// Encryption mode for the 3270 network transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMode {
    /// Unencrypted plain TCP (standard for local Hercules emulator on port 3270).
    #[default]
    Disabled,
    /// Encrypted TLS 1.2 or 1.3 (AT-TLS on IBM z/OS on port 992 or custom port).
    Enabled,
}

impl TlsMode {
    /// Returns `true` if TLS encryption is enabled.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

impl fmt::Display for TlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Enabled => write!(f, "enabled"),
        }
    }
}

impl FromStr for TlsMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "enabled" | "yes" | "on" | "tls" => Ok(Self::Enabled),
            "0" | "false" | "disabled" | "no" | "off" | "none" | "plain" => Ok(Self::Disabled),
            other => Err(format!(
                "invalid TLS mode '{other}': expected 'enabled'/'true'/'1' or 'disabled'/'false'/'0'"
            )),
        }
    }
}

impl Serialize for TlsMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Disabled => serializer.serialize_str("disabled"),
            Self::Enabled => serializer.serialize_str("enabled"),
        }
    }
}

impl<'de> Deserialize<'de> for TlsMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TlsModeVisitor;

        impl serde::de::Visitor<'_> for TlsModeVisitor {
            type Value = TlsMode;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a boolean (true/false) or string ('disabled'/'enabled')")
            }

            fn visit_bool<E>(self, v: bool) -> Result<TlsMode, E>
            where
                E: serde::de::Error,
            {
                Ok(if v {
                    TlsMode::Enabled
                } else {
                    TlsMode::Disabled
                })
            }

            fn visit_str<E>(self, v: &str) -> Result<TlsMode, E>
            where
                E: serde::de::Error,
            {
                v.parse::<TlsMode>().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(TlsModeVisitor)
    }
}

/// IBM 3270 terminal display model configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProfileTerminalModel {
    /// Model 2: 24 rows × 80 columns (1,920 cells).
    #[default]
    Model2,
    /// Model 3: 32 rows × 80 columns (2,560 cells).
    Model3,
    /// Model 4: 43 rows × 80 columns (3,440 cells).
    Model4,
    /// Model 5: 27 rows × 132 columns (3,564 cells).
    Model5,
    /// Dynamic (`IBM-DYNAMIC`): custom rows and columns (e.g. 62×160 for z/OS ISPF).
    Dynamic {
        /// Screen rows (1..=255).
        rows: u8,
        /// Screen columns (1..=255).
        cols: u8,
    },
}

impl FromStr for ProfileTerminalModel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let lower = trimmed.to_ascii_lowercase();

        match lower.as_str() {
            "2" | "model2" | "model-2" | "ibm-3278-2" | "ibm-3279-2" => Ok(Self::Model2),
            "3" | "model3" | "model-3" | "ibm-3278-3" | "ibm-3279-3" => Ok(Self::Model3),
            "4" | "model4" | "model-4" | "ibm-3278-4" | "ibm-3279-4" => Ok(Self::Model4),
            "5" | "model5" | "model-5" | "ibm-3278-5" | "ibm-3279-5" => Ok(Self::Model5),
            _ => {
                let dim_str = if let Some(stripped) = lower.strip_prefix("dynamic:") {
                    stripped
                } else if let Some(stripped) = lower.strip_prefix("dynamic ") {
                    stripped
                } else {
                    lower.as_str()
                };

                if let Some((r_str, c_str)) = dim_str.split_once('x') {
                    let r = r_str
                        .trim()
                        .parse::<u8>()
                        .map_err(|e| format!("invalid rows in dynamic model '{trimmed}': {e}"))?;
                    let c = c_str
                        .trim()
                        .parse::<u8>()
                        .map_err(|e| format!("invalid cols in dynamic model '{trimmed}': {e}"))?;

                    if r == 0 || c == 0 {
                        return Err(format!(
                            "dynamic dimensions {r}x{c} must be non-zero (1..=255)"
                        ));
                    }
                    let total = usize::from(r).saturating_mul(usize::from(c));
                    if total > bastion3270_core::model::MAX_BUFFER_CELLS_14BIT {
                        return Err(format!(
                            "dynamic dimensions {r}x{c} ({total} cells) exceed 14-bit limit of {}",
                            bastion3270_core::model::MAX_BUFFER_CELLS_14BIT
                        ));
                    }
                    Ok(Self::Dynamic { rows: r, cols: c })
                } else {
                    Err(format!(
                        "unknown terminal model '{trimmed}': expected 'Model2' ('2'), 'Model3' ('3'), 'Model4' ('4'), 'Model5' ('5'), or 'dynamic:ROWSxCOLS'"
                    ))
                }
            }
        }
    }
}

impl fmt::Display for ProfileTerminalModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model2 => write!(f, "Model2"),
            Self::Model3 => write!(f, "Model3"),
            Self::Model4 => write!(f, "Model4"),
            Self::Model5 => write!(f, "Model5"),
            Self::Dynamic { rows, cols } => write!(f, "dynamic:{rows}x{cols}"),
        }
    }
}

impl Serialize for ProfileTerminalModel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Model2 => serializer.serialize_str("Model2"),
            Self::Model3 => serializer.serialize_str("Model3"),
            Self::Model4 => serializer.serialize_str("Model4"),
            Self::Model5 => serializer.serialize_str("Model5"),
            Self::Dynamic { rows, cols } => {
                let s = format!("dynamic:{rows}x{cols}");
                serializer.serialize_str(&s)
            }
        }
    }
}

impl<'de> Deserialize<'de> for ProfileTerminalModel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ModelVisitor;

        impl<'de> serde::de::Visitor<'de> for ModelVisitor {
            type Value = ProfileTerminalModel;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a terminal model string like 'Model2', '4', 'dynamic:62x160' or a map with rows and cols")
            }

            fn visit_str<E>(self, v: &str) -> Result<ProfileTerminalModel, E>
            where
                E: serde::de::Error,
            {
                v.parse::<ProfileTerminalModel>().map_err(E::custom)
            }

            fn visit_map<M>(self, mut map: M) -> Result<ProfileTerminalModel, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut rows: Option<u8> = None;
                let mut cols: Option<u8> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.to_ascii_lowercase().as_str() {
                        "rows" => {
                            rows = Some(map.next_value()?);
                        }
                        "cols" | "columns" => {
                            cols = Some(map.next_value()?);
                        }
                        "dynamic" => {
                            #[derive(Deserialize)]
                            struct SubDims {
                                rows: u8,
                                cols: u8,
                            }
                            let sub: SubDims = map.next_value()?;
                            rows = Some(sub.rows);
                            cols = Some(sub.cols);
                        }
                        _ => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                match (rows, cols) {
                    (Some(r), Some(c)) => {
                        let total = usize::from(r).saturating_mul(usize::from(c));
                        if r == 0 || c == 0 {
                            return Err(serde::de::Error::custom(format!(
                                "dynamic dimensions {r}x{c} must be non-zero"
                            )));
                        }
                        if total > bastion3270_core::model::MAX_BUFFER_CELLS_14BIT {
                            return Err(serde::de::Error::custom(format!(
                                "dynamic dimensions {r}x{c} ({total} cells) exceed 14-bit limit"
                            )));
                        }
                        Ok(ProfileTerminalModel::Dynamic { rows: r, cols: c })
                    }
                    _ => Err(serde::de::Error::custom(
                        "expected map with 'rows' and 'cols' fields for dynamic terminal model",
                    )),
                }
            }
        }

        deserializer.deserialize_any(ModelVisitor)
    }
}

impl TryFrom<ProfileTerminalModel> for bastion3270_core::TerminalModel {
    type Error = NetError;

    fn try_from(m: ProfileTerminalModel) -> Result<Self, Self::Error> {
        match m {
            ProfileTerminalModel::Model2 => Ok(Self::Model2),
            ProfileTerminalModel::Model3 => Ok(Self::Model3),
            ProfileTerminalModel::Model4 => Ok(Self::Model4),
            ProfileTerminalModel::Model5 => Ok(Self::Model5),
            ProfileTerminalModel::Dynamic { rows, cols } => {
                Self::new_dynamic(u16::from(rows), u16::from(cols)).map_err(|e| {
                    NetError::Config(format!("invalid dynamic terminal model {rows}x{cols}: {e}"))
                })
            }
        }
    }
}

impl From<bastion3270_core::TerminalModel> for ProfileTerminalModel {
    fn from(m: bastion3270_core::TerminalModel) -> Self {
        match m {
            bastion3270_core::TerminalModel::Model2 => Self::Model2,
            bastion3270_core::TerminalModel::Model3 => Self::Model3,
            bastion3270_core::TerminalModel::Model4 => Self::Model4,
            bastion3270_core::TerminalModel::Model5 => Self::Model5,
            bastion3270_core::TerminalModel::Dynamic { rows, cols } => Self::Dynamic {
                rows: u8::try_from(rows).unwrap_or(u8::MAX),
                cols: u8::try_from(cols).unwrap_or(u8::MAX),
            },
        }
    }
}

/// Complete configuration profile for establishing a 3270 connection.
///
/// A misspelt key is an error (`deny_unknown_fields`): it must stop the start instead of
/// leaving the setting at its default.
// The booleans are independent configuration switches (one TOML key each), not a state.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionProfile {
    /// Target mainframe hostname or IP address.
    #[serde(default = "default_host")]
    pub host: String,

    /// Target TCP port (e.g. 3270 for plain Hercules, 992 or 23 for TLS).
    #[serde(default = "default_port")]
    pub port: u16,

    /// TLS encryption mode (`disabled` for plain TCP, `enabled` for TLS 1.2/1.3).
    ///
    /// Required in a profile file, without a default: a profile that forgets it must not
    /// silently send passwords and screens in clear text. (Profiles built in code start from
    /// [`TlsMode::Disabled`] through [`ConnectionProfile::default`].)
    pub tls_mode: TlsMode,

    /// Optional CA certificate file (PEM or DER; roots or intermediates) trusted **in
    /// addition** to the Mozilla roots and the operating system's store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<PathBuf>,

    /// The name the host's certificate must match instead of `host` (x3270
    /// `acceptHostname`), e.g. when connecting by IP address to a certificate issued for a
    /// host name. A DNS name or an IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_hostname: Option<String>,

    /// SHA-256 (64 hex digits) of one host certificate trusted as it is, without its CA, name
    /// or dates being checked — like an SSH host key. Set by the desktop client when the user
    /// trusts a refused certificate; the gateway does not accept it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_cert_sha256: Option<String>,

    /// PEM file with the client certificate (and intermediates) the gateway presents to the
    /// host for mutual TLS. Requires [`ConnectionProfile::client_key`] and TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<PathBuf>,

    /// PEM file with the private key of [`ConnectionProfile::client_cert`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key: Option<PathBuf>,

    /// Optional SNA Logical Unit (LU) name or LU pool name requested from host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lu_name: Option<String>,

    /// Terminal display model (e.g. Model2 = 24x80, Model4 = 43x80, Dynamic).
    #[serde(default = "default_model")]
    pub terminal_model: ProfileTerminalModel,

    /// Whether to enable 3279 color mode (`true`) or 3278 monochrome (`false`).
    #[serde(default = "default_color")]
    pub color_3279: bool,

    /// Whether to enable extended data stream attributes (`true` appends `-E` suffix).
    #[serde(default = "default_extended")]
    pub extended: bool,

    /// EBCDIC host code page (e.g. `"cp037"` or `"cp870"`).
    #[serde(default = "default_codepage")]
    pub codepage: String,

    /// Only digits, `+`, `-`, `.` and `,` may be typed into numeric fields (`x3270`
    /// `numericLock`; default off, the host validates numeric fields).
    #[serde(default = "default_numeric_lock")]
    pub numeric_lock: bool,

    /// Typing after empty positions of a field turns them into spaces, so the host receives
    /// the text where it was typed (`x3270` `blankFill`; default on).
    #[serde(default = "default_blank_fill")]
    pub blank_fill: bool,

    /// Connection deadline for TCP connect and TLS handshake in milliseconds.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,

    /// Inactivity silence threshold for detecting dead connections in milliseconds.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_ms: u64,

    /// Deadline for one write (and flush) to the host in milliseconds. A host that stops
    /// reading ends the session instead of blocking it.
    #[serde(default = "default_write_timeout")]
    pub write_timeout_ms: u64,

    /// Deadline from connect until the Telnet negotiation is complete, in milliseconds. Host
    /// traffic before that does not extend it.
    #[serde(default = "default_negotiation_timeout")]
    pub negotiation_timeout_ms: u64,

    /// Bounded capacity for async channels (backpressure buffer bound).
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
}

impl Default for ConnectionProfile {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            tls_mode: TlsMode::Disabled,
            ca_cert: None,
            accept_hostname: None,
            pinned_cert_sha256: None,
            client_cert: None,
            client_key: None,
            lu_name: None,
            terminal_model: default_model(),
            color_3279: default_color(),
            extended: default_extended(),
            codepage: default_codepage(),
            numeric_lock: default_numeric_lock(),
            blank_fill: default_blank_fill(),
            connect_timeout_ms: default_connect_timeout(),
            idle_timeout_ms: default_idle_timeout(),
            write_timeout_ms: default_write_timeout(),
            negotiation_timeout_ms: default_negotiation_timeout(),
            channel_capacity: default_channel_capacity(),
        }
    }
}

impl ConnectionProfile {
    /// Validates all configuration parameters against architectural limits.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if any parameter violates architectural limits.
    pub fn validate(&self) -> Result<(), NetError> {
        if self.host.trim().is_empty() {
            return Err(NetError::Config(
                "profile 'host' must not be empty".to_string(),
            ));
        }
        if self.port == 0 {
            return Err(NetError::Config(
                "profile 'port' must be in 1..=65535, cannot be 0".to_string(),
            ));
        }
        // The LU name goes into the TN3270E negotiation as it is (`CONNECT <name>`, RFC 2355
        // §7.1): only an SNA name is accepted, so no other byte can reach the host there.
        if let Some(lu) = &self.lu_name {
            if !is_lu_name(lu) {
                return Err(NetError::Config(
                    "profile 'lu_name' must be an SNA name: 1 to 8 letters, digits, @, # or $, \
                     not starting with a digit"
                        .to_string(),
                ));
            }
        }
        // No silent degradation: settings that would not take effect are refused.
        if self.client_cert.is_some() != self.client_key.is_some() {
            return Err(NetError::Config(
                "profile 'client_cert' and 'client_key' must be set together (mutual TLS)"
                    .to_string(),
            ));
        }
        if self.client_cert.is_some() && self.tls_mode == TlsMode::Disabled {
            return Err(NetError::Config(
                "profile 'client_cert' is set but tls_mode = \"disabled\": the connection would \
                 not use it"
                    .to_string(),
            ));
        }
        if self.ca_cert.is_some() && self.tls_mode == TlsMode::Disabled {
            return Err(NetError::Config(
                "profile 'ca_cert' is set but tls_mode = \"disabled\": the connection would not \
                 use it"
                    .to_string(),
            ));
        }
        self.validate_certificate_checks()?;
        if self.channel_capacity == 0 || self.channel_capacity > MAX_CHANNEL_CAPACITY {
            return Err(NetError::Config(format!(
                "profile 'channel_capacity' must be between 1 and {MAX_CHANNEL_CAPACITY}"
            )));
        }
        if self.connect_timeout_ms == 0 {
            return Err(NetError::Config(
                "profile 'connect_timeout_ms' must be > 0".to_string(),
            ));
        }
        if self.idle_timeout_ms == 0 {
            return Err(NetError::Config(
                "profile 'idle_timeout_ms' must be > 0".to_string(),
            ));
        }
        if self.write_timeout_ms == 0 {
            return Err(NetError::Config(
                "profile 'write_timeout_ms' must be > 0".to_string(),
            ));
        }
        if self.negotiation_timeout_ms == 0 {
            return Err(NetError::Config(
                "profile 'negotiation_timeout_ms' must be > 0".to_string(),
            ));
        }

        // Validate code page supported by bastion3270-core
        self.core_codepage()?;

        // Validate terminal model
        let model = self.core_terminal_model()?;
        if model.requires_extended() && !self.extended {
            return Err(NetError::Config(
                "profile 'terminal_model' Dynamic needs 'extended = true' (IBM-DYNAMIC uses the \
                 extended data stream)"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// `accept_hostname` and `pinned_cert_sha256`: only with TLS, and well formed.
    fn validate_certificate_checks(&self) -> Result<(), NetError> {
        if let Some(name) = &self.accept_hostname {
            if self.tls_mode == TlsMode::Disabled {
                return Err(NetError::Config(
                    "profile 'accept_hostname' is set but tls_mode = \"disabled\": the \
                     connection would not use it"
                        .to_string(),
                ));
            }
            if ServerName::try_from(name.as_str()).is_err() {
                return Err(NetError::Config(
                    "profile 'accept_hostname' must be a DNS name or an IP address".to_string(),
                ));
            }
        }
        if let Some(pin) = &self.pinned_cert_sha256 {
            if self.tls_mode == TlsMode::Disabled {
                return Err(NetError::Config(
                    "profile 'pinned_cert_sha256' is set but tls_mode = \"disabled\": the \
                     connection would not use it"
                        .to_string(),
                ));
            }
            if parse_sha256_hex(pin).is_none() {
                return Err(NetError::Config(
                    "profile 'pinned_cert_sha256' must be 64 hex digits".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Deserializes a [`ConnectionProfile`] from a TOML string, applying defaults and validation.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if parsing or validation fails.
    pub fn from_toml_str(s: &str) -> Result<Self, NetError> {
        let profile: Self = toml::from_str(s)
            .map_err(|e| NetError::Config(format!("failed to parse TOML profile: {e}")))?;
        profile.validate()?;
        Ok(profile)
    }

    /// Reads and deserializes a [`ConnectionProfile`] from a `.toml` file.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if reading, parsing, or validation fails.
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, NetError> {
        let path_ref = path.as_ref();
        let content = std::fs::read_to_string(path_ref).map_err(|e| {
            NetError::Config(format!(
                "failed to read profile file '{}': {e}",
                path_ref.display()
            ))
        })?;
        Self::from_toml_str(&content)
    }

    /// Serializes this profile to a formatted TOML string.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if serialization fails.
    pub fn to_toml_string(&self) -> Result<String, NetError> {
        toml::to_string_pretty(self)
            .map_err(|e| NetError::Config(format!("failed to serialize profile to TOML: {e}")))
    }

    /// Applies environment variable overrides with `BASTION3270_*` prefix.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if an environment variable value is invalid.
    pub fn apply_env_overrides(&mut self) -> Result<(), NetError> {
        self.apply_env_lookup(&|k| std::env::var(k).ok())
    }

    /// Applies environment overrides using a custom key-lookup closure.
    ///
    /// This method allows deterministic, thread-safe testing without mutating global
    /// process environment variables.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if a value cannot be parsed.
    pub fn apply_env_lookup<F>(&mut self, lookup: &F) -> Result<(), NetError>
    where
        F: Fn(&str) -> Option<String>,
    {
        self.apply_env_network(lookup)?;
        self.apply_env_security(lookup);
        self.apply_env_terminal(lookup)?;
        self.apply_env_timeouts(lookup)?;
        Ok(())
    }

    fn apply_env_network<F>(&mut self, lookup: &F) -> Result<(), NetError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(val) = lookup("BASTION3270_HOST") {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                self.host = trimmed.to_string();
            }
        }

        if let Some(val) = lookup("BASTION3270_PORT") {
            let p = val.trim().parse::<u16>().map_err(|e| {
                NetError::Config(format!("invalid value for BASTION3270_PORT '{val}': {e}"))
            })?;
            self.port = p;
        }

        let tls_val = lookup("BASTION3270_TLS").or_else(|| lookup("BASTION3270_TLS_MODE"));
        if let Some(val) = tls_val {
            let mode = val.parse::<TlsMode>().map_err(|e| {
                NetError::Config(format!("invalid value for BASTION3270_TLS '{val}': {e}"))
            })?;
            self.tls_mode = mode;
        }

        Ok(())
    }

    fn apply_env_security<F>(&mut self, lookup: &F)
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(val) = lookup("BASTION3270_CA_CERT") {
            let trimmed = val.trim();
            self.ca_cert = if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            };
        }

        if let Some(val) = lookup("BASTION3270_ACCEPT_HOSTNAME") {
            let trimmed = val.trim();
            self.accept_hostname = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }

        if let Some(val) = lookup("BASTION3270_CLIENT_CERT") {
            let trimmed = val.trim();
            self.client_cert = if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            };
        }

        if let Some(val) = lookup("BASTION3270_CLIENT_KEY") {
            let trimmed = val.trim();
            self.client_key = if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            };
        }
    }

    fn apply_env_terminal<F>(&mut self, lookup: &F) -> Result<(), NetError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(val) = lookup("BASTION3270_LU_NAME") {
            let trimmed = val.trim();
            self.lu_name = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }

        if let Some(val) = lookup("BASTION3270_TERMINAL_MODEL") {
            let model = val.parse::<ProfileTerminalModel>().map_err(|e| {
                NetError::Config(format!(
                    "invalid value for BASTION3270_TERMINAL_MODEL '{val}': {e}"
                ))
            })?;
            self.terminal_model = model;
        }

        if let Some(val) = lookup("BASTION3270_COLOR") {
            let b = parse_loose_bool(&val).map_err(|e| {
                NetError::Config(format!("invalid value for BASTION3270_COLOR '{val}': {e}"))
            })?;
            self.color_3279 = b;
        }

        if let Some(val) = lookup("BASTION3270_EXTENDED") {
            let b = parse_loose_bool(&val).map_err(|e| {
                NetError::Config(format!(
                    "invalid value for BASTION3270_EXTENDED '{val}': {e}"
                ))
            })?;
            self.extended = b;
        }

        if let Some(val) = lookup("BASTION3270_CODEPAGE") {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                self.codepage = trimmed.to_lowercase();
            }
        }

        if let Some(val) = lookup("BASTION3270_NUMERIC_LOCK") {
            self.numeric_lock = parse_loose_bool(&val).map_err(|e| {
                NetError::Config(format!(
                    "invalid value for BASTION3270_NUMERIC_LOCK '{val}': {e}"
                ))
            })?;
        }

        if let Some(val) = lookup("BASTION3270_BLANK_FILL") {
            self.blank_fill = parse_loose_bool(&val).map_err(|e| {
                NetError::Config(format!(
                    "invalid value for BASTION3270_BLANK_FILL '{val}': {e}"
                ))
            })?;
        }

        Ok(())
    }

    fn apply_env_timeouts<F>(&mut self, lookup: &F) -> Result<(), NetError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let conn_timeout = lookup("BASTION3270_CONNECT_TIMEOUT_MS")
            .or_else(|| lookup("BASTION3270_CONNECT_TIMEOUT"));
        if let Some(val) = conn_timeout {
            let ms = val.trim().parse::<u64>().map_err(|e| {
                NetError::Config(format!(
                    "invalid value for BASTION3270_CONNECT_TIMEOUT_MS '{val}': {e}"
                ))
            })?;
            self.connect_timeout_ms = ms;
        }

        let idle_timeout =
            lookup("BASTION3270_IDLE_TIMEOUT_MS").or_else(|| lookup("BASTION3270_IDLE_TIMEOUT"));
        if let Some(val) = idle_timeout {
            let ms = val.trim().parse::<u64>().map_err(|e| {
                NetError::Config(format!(
                    "invalid value for BASTION3270_IDLE_TIMEOUT_MS '{val}': {e}"
                ))
            })?;
            self.idle_timeout_ms = ms;
        }

        if let Some(val) = lookup("BASTION3270_CHANNEL_CAPACITY") {
            let cap = val.trim().parse::<usize>().map_err(|e| {
                NetError::Config(format!(
                    "invalid value for BASTION3270_CHANNEL_CAPACITY '{val}': {e}"
                ))
            })?;
            self.channel_capacity = cap;
        }

        Ok(())
    }

    /// Constructs a [`ConnectionProfile`] starting with corporate defaults, overridden by environment variables.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if environment overrides or validation fails.
    pub fn from_env() -> Result<Self, NetError> {
        let mut profile = Self::default();
        profile.apply_env_overrides()?;
        profile.validate()?;
        Ok(profile)
    }

    /// Maps the profile's [`ProfileTerminalModel`] to [`bastion3270_core::TerminalModel`].
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if dynamic dimensions cannot be mapped.
    pub fn core_terminal_model(&self) -> Result<bastion3270_core::TerminalModel, NetError> {
        self.terminal_model.try_into()
    }

    /// The operator keyboard switches of this profile (numeric lock, blank fill).
    #[must_use]
    pub const fn keyboard_options(&self) -> bastion3270_core::KeyboardOptions {
        bastion3270_core::KeyboardOptions {
            numeric_lock: self.numeric_lock,
            blank_fill: self.blank_fill,
        }
    }

    /// Resolves the configured code page name into a static [`bastion3270_core::CodePage`] reference.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if the code page is unsupported.
    pub fn core_codepage(&self) -> Result<&'static dyn bastion3270_core::CodePage, NetError> {
        let id =
            bastion3270_core::ebcdic::CodePageId::from_name(&self.codepage).ok_or_else(|| {
                let supported: Vec<&str> = bastion3270_core::ebcdic::CodePageId::ALL
                    .iter()
                    .map(|id| id.name())
                    .collect();
                NetError::Config(format!(
                    "unsupported EBCDIC code page '{}' (supported: {}, or their numbers and x3270 \
                 aliases)",
                    self.codepage,
                    supported.join(", ")
                ))
            })?;
        Ok(id.codepage())
    }

    /// Computes the canonical Telnet / TN3270E `TERMINAL-TYPE` string for this profile.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if the terminal model cannot be mapped.
    pub fn terminal_type_string(&self) -> Result<String, NetError> {
        let model = self.core_terminal_model()?;
        Ok(model
            .terminal_type_name(self.color_3279, self.extended)
            .to_string())
    }

    /// Computes the canonical Telnet / TN3270E `TERMINAL-TYPE` static name for this profile.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if the terminal model cannot be mapped.
    pub fn terminal_type_name(&self) -> Result<&'static str, NetError> {
        let model = self.core_terminal_model()?;
        Ok(model.terminal_type_name(self.color_3279, self.extended))
    }

    /// Creates a fluent [`ConnectionProfileBuilder`] initialized with default corporate settings.
    #[must_use]
    pub fn builder() -> super::builder::ConnectionProfileBuilder {
        super::builder::ConnectionProfileBuilder::new()
    }
}

fn parse_loose_bool(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!(
            "expected boolean ('true'/'false'/'1'/'0'), got '{other}'"
        )),
    }
}
