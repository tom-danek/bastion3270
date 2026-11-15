//! Server configuration (`bastion3270-server.toml`), suitable for a Kubernetes `ConfigMap`.
//!
//! The configuration defines the **LPAR whitelist**: a browser user can never type an arbitrary
//! host/port (SSRF protection). They can only pick one of the
//! [`GatewayProfile`]s below, identified by its short `id`.
//!
//! ```toml
//! [server]
//! bind = "0.0.0.0:8080"
//!
//! [limits]
//! max_sessions = 500
//!
//! [auth]
//! mode = "none"
//!
//! [[profiles]]
//! id = "hercules"
//! name = "Hercules MVS 3.8j (TK4-)"
//!
//! [profiles.connection]
//! host = "hercules"
//! port = 3270
//! ```

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use bastion3270_net::{ConnectionProfile, TlsMode};
use serde::{Deserialize, Serialize};

use crate::error::{Result, ServerError};

/// Root of `bastion3270-server.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// HTTP listener settings.
    #[serde(default)]
    pub server: ListenerConfig,
    /// Resource governance limits (`DoS` protection).
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Built-in authentication settings (`none` / `static-token`).
    #[serde(default)]
    pub auth: AuthConfig,
    /// Whitelisted mainframe targets.
    #[serde(default)]
    pub profiles: Vec<GatewayProfile>,
    /// Connections users define themselves (host, port, TLS); enabled by default.
    #[serde(default)]
    pub custom_connections: crate::custom::CustomConnectionsConfig,
    /// Trust in the hosts' certificates, for every profile and custom connection.
    #[serde(default)]
    pub host_tls: HostTlsConfig,
}

/// Trust in the hosts' TLS certificates (`[host_tls]`).
///
/// The Mozilla roots and the operating system's store are always trusted (a `scratch`
/// container has no system store). `ca_certs` adds the organisation's CAs once for every
/// profile and every custom connection; a profile's own `ca_cert` adds to these.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostTlsConfig {
    /// CA certificate files (PEM or DER; roots, or intermediates a host does not send).
    #[serde(default)]
    pub ca_certs: Vec<PathBuf>,
}

impl HostTlsConfig {
    /// Loads the trust anchors (reads every file).
    ///
    /// # Errors
    /// [`ServerError::Config`] if a file cannot be read or holds no usable certificate.
    pub fn trust(&self) -> Result<bastion3270_net::transport::HostTrust> {
        bastion3270_net::transport::HostTrust::with_ca_files(&self.ca_certs)
            .map_err(|e| ServerError::Config(format!("host_tls.ca_certs: {e}")))
    }
}

/// HTTP / WebSocket listener settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Socket address to bind (`0.0.0.0:8080` inside a container).
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    /// Allowed browser `Origin` values for the WebSocket upgrade (CSWSH protection).
    ///
    /// Empty list = same-origin only: the `Origin` host must equal the `Host` header.
    /// Requests without an `Origin` header (non-browser API clients) are accepted.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Address ranges of reverse proxies (the ingress) whose `X-Forwarded-For` and
    /// `X-Forwarded-Proto` are believed: the audit then records the browser's address, and the
    /// same-origin check also compares the scheme. Empty: the headers are ignored.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Address of a separate listener serving Prometheus metrics at `GET /metrics` (e.g.
    /// `0.0.0.0:9090`, reachable only from the monitoring system). Unset: no metrics endpoint.
    #[serde(default)]
    pub metrics_bind: Option<SocketAddr>,
    /// Serve HTTPS / WSS instead of plain HTTP, e.g. so the hop from the ingress to the pod is
    /// encrypted (and, with `client_ca`, authenticated) too.
    #[serde(default)]
    pub tls: Option<ListenerTls>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            allowed_origins: Vec::new(),
            trusted_proxies: Vec::new(),
            metrics_bind: None,
            tls: None,
        }
    }
}

/// TLS for the gateway's own listener (`[server.tls]`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerTls {
    /// PEM file with the server certificate, followed by its intermediate certificates.
    pub cert: PathBuf,
    /// PEM file with the private key of `cert`.
    pub key: PathBuf,
    /// PEM file with the CA certificates that sign client certificates. When set, a client
    /// (the ingress) must present a certificate signed by one of them (mutual TLS).
    #[serde(default)]
    pub client_ca: Option<PathBuf>,
}

/// The checks of one `[[profiles]]` entry that do not depend on the others.
fn validate_profile(p: &GatewayProfile) -> Result<()> {
    let cfg_err = |m: String| Err(ServerError::Config(m));
    if p.id == crate::custom::CUSTOM_PROFILE_ID {
        return cfg_err(format!(
            "profile id '{}' is reserved for connections users define themselves",
            p.id
        ));
    }
    if p.name.trim().is_empty() {
        return cfg_err(format!("profile '{}' has an empty name", p.id));
    }
    for pattern in p.allowed_lu_names.iter().flatten() {
        let name = pattern.strip_suffix('*').unwrap_or(pattern);
        let prefix_only = pattern.ends_with('*') && name.is_empty();
        if !prefix_only && !bastion3270_net::profile::is_lu_name(name) {
            return cfg_err(format!(
                "profile '{}': allowed_lu_names entry '{pattern}' must be an SNA name \
                 (1 to 8 letters, digits, @ # $), optionally ending in '*'",
                p.id
            ));
        }
    }
    p.connection
        .validate()
        .map_err(|e| ServerError::Config(format!("profile '{}': {e}", p.id)))?;
    // In the gateway only the administrator's CAs decide; a pinned certificate is a
    // desktop user's decision.
    if p.connection.pinned_cert_sha256.is_some() {
        return cfg_err(format!(
            "profile '{}': pinned_cert_sha256 is a desktop setting; trust the host's \
             CA instead (ca_cert, or [host_tls] ca_certs)",
            p.id
        ));
    }
    Ok(())
}

fn default_bind() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8080))
}

/// Upper bound for `max_connections` and `max_pending_handshakes` (far above what one process
/// can serve, and below the limits of the semaphores that enforce them).
const MAX_CONNECTION_LIMIT: usize = 1_000_000;

/// Resource governance limits (denial-of-service protection).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    /// Maximum concurrent mainframe sessions served by this process (pod).
    pub max_sessions: usize,
    /// Maximum concurrent sessions owned by a single identity.
    pub max_sessions_per_identity: usize,
    /// How long a session survives without an attached browser (F5 / Wi-Fi drop), in seconds.
    pub detach_grace_secs: u64,
    /// How often the reaper scans for expired sessions, in seconds.
    pub reaper_interval_secs: u64,
    /// Maximum size of one inbound WebSocket message in bytes.
    pub max_ws_message_bytes: usize,
    /// Maximum number of characters in one paste (`text`) message.
    pub max_paste_chars: usize,
    /// Maximum inbound WebSocket messages per second per connection (flood protection).
    pub max_messages_per_second: u32,
    /// Maximum concurrent HTTP connections that have not (yet) become a WebSocket; further
    /// connections are closed right after accept.
    pub max_connections: usize,
    /// Maximum WebSocket connections waiting for their first (`open` / `resume`) message; further
    /// upgrades are refused with 503.
    pub max_pending_handshakes: usize,
    /// Time a client has to send a complete HTTP request head, also between requests on a
    /// keep-alive connection (slow-loris protection), in seconds.
    pub header_read_timeout_secs: u64,
    /// Interval of the server's WebSocket pings, in seconds. A browser that sends nothing
    /// (not even the automatic pong) for two intervals is detached.
    pub ping_interval_secs: u64,
    /// Maximum age of a session in seconds, however active it is; then it is closed.
    pub max_session_lifetime_secs: u64,
    /// A session without operator input (keys, paste, AIDs) for this many seconds is closed,
    /// even with a browser attached.
    pub idle_timeout_secs: u64,
    /// Session tabs the web client offers in one browser page (1..=16); the sessions of an
    /// identity are still limited by `max_sessions_per_identity`.
    pub max_tabs_per_page: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_sessions: 500,
            max_sessions_per_identity: 4,
            detach_grace_secs: 300,
            reaper_interval_secs: 15,
            max_ws_message_bytes: 16 * 1024,
            max_paste_chars: 2048,
            max_messages_per_second: 200,
            max_connections: 1024,
            max_pending_handshakes: 64,
            header_read_timeout_secs: 10,
            ping_interval_secs: 25,
            max_session_lifetime_secs: 12 * 3600,
            // NIST SP 800-63B (AAL2): 30 minutes of inactivity, 12 hours overall.
            idle_timeout_secs: 30 * 60,
            max_tabs_per_page: 4,
        }
    }
}

/// Built-in authentication mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMode {
    /// No gateway authentication — the user logs on at the RACF/TSO screen.
    #[default]
    None,
    /// Static bearer tokens (SHA-256 hashes stored in configuration).
    StaticToken,
}

/// Built-in authentication configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Selected mode.
    #[serde(default)]
    pub mode: AuthMode,
    /// Token table used by [`AuthMode::StaticToken`].
    #[serde(default)]
    pub tokens: Vec<StaticTokenEntry>,
}

/// One static bearer token. Only the SHA-256 hash is stored, so the `ConfigMap` itself
/// does not contain a usable credential.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticTokenEntry {
    /// Identity name shown in audit logs.
    pub subject: String,
    /// Lower-case hex SHA-256 of the token (`printf %s "$TOKEN" | sha256sum`).
    pub sha256: String,
    /// Profile ids this token may open. Empty = all profiles.
    #[serde(default)]
    pub profiles: Vec<String>,
}

/// One whitelisted mainframe target.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayProfile {
    /// Short stable identifier used by the browser (`[a-z0-9_-]{1,64}`).
    pub id: String,
    /// Human readable name.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: String,
    /// Static DLP switch: may the user paste text into this session?
    #[serde(default = "default_true")]
    pub allow_paste: bool,
    /// Static DLP switch: may the web client offer copy of the screen?
    #[serde(default = "default_true")]
    pub allow_copy: bool,
    /// Default key layout of the web client for this profile; each user may switch it.
    #[serde(default)]
    pub keyboard: KeyboardPreset,
    /// LU names a user may request for this profile: exact names or prefixes ending in `*`
    /// (`["TSO0*", "CICS01"]`). Absent: any valid LU name; empty: none (the LU of the
    /// connection settings, or the host's choice).
    #[serde(default)]
    pub allowed_lu_names: Option<Vec<String>>,
    /// Built by the gateway for a user-defined connection (never from the configuration).
    #[serde(skip)]
    pub custom: bool,
    /// Connection parameters (never sent to the browser).
    pub connection: ConnectionProfile,
}

const fn default_true() -> bool {
    true
}

impl GatewayProfile {
    /// The id an identity's profile list is checked against: the profile's own, or
    /// [`crate::custom::CUSTOM_PROFILE_ID`] for a user-defined connection.
    #[must_use]
    pub fn permission_id(&self) -> &str {
        if self.custom {
            crate::custom::CUSTOM_PROFILE_ID
        } else {
            &self.id
        }
    }
}

/// Key layouts of the web client: which key is Enter, Reset, Clear, PA1 ...
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyboardPreset {
    /// x3270 / wc3270: Enter is Enter, Shift+Enter is New Line.
    #[default]
    X3270,
    /// The default 3270 layout of IBM Personal Communications: Right Ctrl is Enter, Enter is
    /// New Line, Left Ctrl is Reset, Pause is Clear.
    Pcomm,
}

/// Public, browser-safe description of a profile (no host, port or certificates).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicProfile {
    /// Profile id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Default key layout.
    pub keyboard: KeyboardPreset,
    /// LU names the user may request (`None`: any valid name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lu_names: Option<Vec<String>>,
}

impl From<&GatewayProfile> for PublicProfile {
    fn from(p: &GatewayProfile) -> Self {
        Self {
            id: p.id.clone(),
            name: p.name.clone(),
            description: p.description.clone(),
            keyboard: p.keyboard,
            lu_names: p.allowed_lu_names.clone(),
        }
    }
}

impl ServerConfig {
    /// Parses and validates a TOML document.
    ///
    /// # Errors
    /// Returns [`ServerError::Config`] on syntax errors or failed validation.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(s).map_err(|e| ServerError::Config(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reads, parses and validates a TOML file, then applies `BASTION3270_SERVER_*` overrides.
    ///
    /// # Errors
    /// Returns [`ServerError::Io`] if the file cannot be read, or [`ServerError::Config`].
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())?;
        let mut cfg: Self =
            toml::from_str(&text).map_err(|e| ServerError::Config(e.to_string()))?;
        cfg.apply_env_lookup(&|k| std::env::var(k).ok())?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Applies environment overrides through an injectable lookup (testable without
    /// touching the real process environment).
    ///
    /// Supported: `BASTION3270_SERVER_BIND`.
    ///
    /// # Errors
    /// Returns [`ServerError::Config`] if an override value is malformed.
    pub fn apply_env_lookup<F>(&mut self, lookup: &F) -> Result<()>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(bind) = lookup("BASTION3270_SERVER_BIND") {
            self.server.bind = bind.parse().map_err(|_| {
                ServerError::Config(format!(
                    "BASTION3270_SERVER_BIND: invalid socket address '{bind}'"
                ))
            })?;
        }
        Ok(())
    }

    /// Validates the whole configuration.
    ///
    /// # Errors
    /// Returns [`ServerError::Config`] describing the first violation found.
    pub fn validate(&self) -> Result<()> {
        let cfg_err = |m: String| Err(ServerError::Config(m));

        for range in &self.server.trusted_proxies {
            range
                .parse::<crate::forwarded::Cidr>()
                .map_err(|e| ServerError::Config(format!("server.trusted_proxies: {e}")))?;
        }
        if self.profiles.is_empty() {
            return cfg_err("at least one [[profiles]] entry is required".into());
        }
        let mut ids = HashSet::new();
        for p in &self.profiles {
            if !is_valid_id(&p.id) {
                return cfg_err(format!(
                    "profile id '{}' must match [a-z0-9_-]{{1,64}}",
                    p.id
                ));
            }
            if !ids.insert(p.id.as_str()) {
                return cfg_err(format!("duplicate profile id '{}'", p.id));
            }
            validate_profile(p)?;
        }

        let l = &self.limits;
        if l.max_sessions == 0
            || l.max_sessions_per_identity == 0
            || l.reaper_interval_secs == 0
            || l.max_ws_message_bytes < 256
            || l.max_messages_per_second == 0
            || l.header_read_timeout_secs == 0
            || l.ping_interval_secs == 0
            || l.max_session_lifetime_secs == 0
            || l.idle_timeout_secs == 0
            || !(1..=MAX_CONNECTION_LIMIT).contains(&l.max_connections)
            || !(1..=MAX_CONNECTION_LIMIT).contains(&l.max_pending_handshakes)
            || !(1..=16).contains(&l.max_tabs_per_page)
        {
            return cfg_err(
                "limits: max_sessions, max_sessions_per_identity, reaper_interval_secs, \
                 max_messages_per_second, header_read_timeout_secs, ping_interval_secs, \
                 max_session_lifetime_secs and idle_timeout_secs must be > 0; max_connections and max_pending_handshakes \
                 between 1 and 1000000; max_tabs_per_page between 1 and 16; \
                 max_ws_message_bytes must be >= 256"
                    .into(),
            );
        }

        if let Err(e) = self.custom_connections.validate() {
            return cfg_err(e);
        }

        if self.auth.mode == AuthMode::StaticToken && self.auth.tokens.is_empty() {
            return cfg_err(
                "auth.mode = \"static-token\" requires at least one [[auth.tokens]]".into(),
            );
        }
        let mut digests = HashSet::new();
        for t in &self.auth.tokens {
            // Two entries with one digest would make the first one's subject and profiles
            // unreachable (and which one wins an accident of order).
            if !digests.insert(t.sha256.to_ascii_lowercase()) {
                return cfg_err(format!(
                    "auth.tokens '{}': the same token digest appears twice",
                    t.subject
                ));
            }
            if t.subject.trim().is_empty() {
                return cfg_err("auth.tokens: subject must not be empty".into());
            }
            if t.sha256.len() != 64 || !t.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return cfg_err(format!(
                    "auth.tokens '{}': sha256 must be 64 hex characters",
                    t.subject
                ));
            }
            if let Some(unknown) = t.profiles.iter().find(|id| !ids.contains(id.as_str())) {
                return cfg_err(format!(
                    "auth.tokens '{}': unknown profile id '{unknown}'",
                    t.subject
                ));
            }
        }
        Ok(())
    }

    /// Settings that are valid but unsafe for production, as one sentence each. Printed by
    /// `--check-config` and logged as warnings at startup.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.auth.mode == AuthMode::None {
            out.push(
                "auth.mode = \"none\": every user is anonymous and shares one identity (per-identity \
                 limits do not apply); use it only in a lab or behind an authenticating proxy"
                    .to_owned(),
            );
        }
        out.extend(self.custom_connections.warning());
        for p in &self.profiles {
            if p.connection.tls_mode == TlsMode::Disabled {
                out.push(format!(
                    "profile '{}': tls_mode = \"disabled\": passwords and screens travel to the \
                     host in clear text",
                    p.id
                ));
            }
        }
        out
    }

    /// Finds a whitelisted profile by id.
    #[must_use]
    pub fn profile(&self, id: &str) -> Option<&GatewayProfile> {
        self.profiles.iter().find(|p| p.id == id)
    }
}

/// `[a-z0-9_-]{1,64}`
pub(crate) fn is_valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [[profiles]]
        id = "hercules"
        name = "Hercules"
        [profiles.connection]
        tls_mode = "disabled"
        host = "127.0.0.1"
        port = 3270
    "#;

    #[test]
    fn test_minimal_config_uses_safe_defaults() {
        let cfg = ServerConfig::from_toml_str(MINIMAL).unwrap();
        assert_eq!(cfg.server.bind, default_bind());
        assert_eq!(cfg.auth.mode, AuthMode::None);
        assert_eq!(cfg.limits, LimitsConfig::default());
        let p = cfg.profile("hercules").unwrap();
        assert!(p.allow_paste && p.allow_copy);
        assert!(cfg.profile("missing").is_none());
    }

    /// Two entries with one digest: the first one's subject and profiles would be unreachable.
    #[test]
    fn test_duplicate_token_digests_are_refused() {
        let d = "b".repeat(64);
        let cfg = format!(
            "[auth]\nmode = \"static-token\"\n\
             [[auth.tokens]]\nsubject = \"a\"\nsha256 = \"{d}\"\n\
             [[auth.tokens]]\nsubject = \"b\"\nsha256 = \"{}\"\n{MINIMAL}",
            d.to_uppercase()
        );
        let err = ServerConfig::from_toml_str(&cfg).unwrap_err();
        assert!(err.to_string().contains("twice"), "{err}");
    }

    #[test]
    fn test_unsafe_settings_are_reported_as_warnings() {
        let cfg = ServerConfig::from_toml_str(MINIMAL).unwrap();
        let warnings = cfg.warnings();
        assert_eq!(warnings.len(), 3, "{warnings:?}");
        assert!(warnings[0].starts_with("auth.mode = \"none\""));
        // Custom connections are on by default and reach any target until restricted.
        assert!(warnings[1].starts_with("custom_connections: users may connect to any host"));
        assert!(warnings[2].starts_with("profile 'hercules': tls_mode"));

        let hash = "a".repeat(64);
        let tls = MINIMAL.replace("tls_mode = \"disabled\"", "tls_mode = \"enabled\"");
        let safe = format!(
            "[custom_connections]\nallowed_targets = [\"10.0.0.0/8:992\"]\n\
             [auth]\nmode = \"static-token\"\n[[auth.tokens]]\nsubject = \"u\"\nsha256 = \"{hash}\"\n{tls}"
        );
        let none: [String; 0] = [];
        assert_eq!(ServerConfig::from_toml_str(&safe).unwrap().warnings(), none);
    }

    #[test]
    fn test_rejects_empty_profiles_and_bad_ids() {
        assert!(ServerConfig::from_toml_str("").is_err());
        let bad = MINIMAL.replace("\"hercules\"", "\"../etc\"");
        assert!(ServerConfig::from_toml_str(&bad).is_err());
        let dup = format!("{MINIMAL}{MINIMAL}");
        assert!(ServerConfig::from_toml_str(&dup).is_err());
    }

    /// In the gateway only the administrator's CAs decide which host certificates are trusted.
    #[test]
    fn test_pinned_host_certificates_are_a_desktop_setting() {
        let tls = MINIMAL.replace("tls_mode = \"disabled\"", "tls_mode = \"enabled\"");
        let pinned = tls.replace(
            "port = 3270",
            &format!("port = 992\npinned_cert_sha256 = \"{}\"", "ab".repeat(32)),
        );
        let err = ServerConfig::from_toml_str(&pinned).unwrap_err();
        assert!(err.to_string().contains("desktop setting"), "{err}");

        let accept = tls.replace(
            "port = 3270",
            "port = 992\naccept_hostname = \"zos1.example\"",
        );
        assert!(ServerConfig::from_toml_str(&accept).is_ok());
    }

    #[test]
    fn test_host_ca_files_are_loaded_once_for_all_profiles() {
        let cfg = ServerConfig::from_toml_str(MINIMAL).unwrap();
        assert_eq!(cfg.host_tls, HostTlsConfig::default());
        assert_eq!(cfg.host_tls.trust().unwrap().summary().configured, 0);

        let missing = format!("[host_tls]\nca_certs = [\"/nonexistent/bank-ca.pem\"]\n{MINIMAL}");
        let cfg = ServerConfig::from_toml_str(&missing).unwrap();
        let err = cfg.host_tls.trust().unwrap_err();
        assert!(
            err.to_string()
                .starts_with("configuration error: host_tls.ca_certs"),
            "{err}"
        );

        let typo = format!("[host_tls]\nca_cert = []\n{MINIMAL}");
        assert!(ServerConfig::from_toml_str(&typo).is_err());
    }

    #[test]
    fn test_rejects_a_typo_in_a_profile_connection() {
        // A misspelt connection key must stop the start, not fall back to the default.
        let typo = MINIMAL.replace("port = 3270", "port = 3270\n        conect_timeout_ms = 5");
        let err = ServerConfig::from_toml_str(&typo).unwrap_err().to_string();
        assert!(err.contains("conect_timeout_ms"), "{err}");
    }

    #[test]
    fn test_rejects_unknown_fields() {
        let typo = format!("[server]\nbindd = \"0.0.0.0:1\"\n{MINIMAL}");
        assert!(ServerConfig::from_toml_str(&typo).is_err());
    }

    #[test]
    fn test_static_token_validation() {
        let no_tokens = format!("[auth]\nmode = \"static-token\"\n{MINIMAL}");
        assert!(ServerConfig::from_toml_str(&no_tokens).is_err());

        let bad_hash = format!(
            "[auth]\nmode = \"static-token\"\n[[auth.tokens]]\nsubject = \"a\"\nsha256 = \"xyz\"\n{MINIMAL}"
        );
        assert!(ServerConfig::from_toml_str(&bad_hash).is_err());

        let unknown_profile = format!(
            "[auth]\nmode = \"static-token\"\n[[auth.tokens]]\nsubject = \"a\"\nsha256 = \"{}\"\nprofiles = [\"nope\"]\n{MINIMAL}",
            "a".repeat(64)
        );
        assert!(ServerConfig::from_toml_str(&unknown_profile).is_err());

        let ok = format!(
            "[auth]\nmode = \"static-token\"\n[[auth.tokens]]\nsubject = \"a\"\nsha256 = \"{}\"\nprofiles = [\"hercules\"]\n{MINIMAL}",
            "a".repeat(64)
        );
        assert!(ServerConfig::from_toml_str(&ok).is_ok());
    }

    #[test]
    fn test_env_override_bind() {
        let mut cfg = ServerConfig::from_toml_str(MINIMAL).unwrap();
        cfg.apply_env_lookup(&|k| {
            (k == "BASTION3270_SERVER_BIND").then(|| "127.0.0.1:9999".into())
        })
        .unwrap();
        assert_eq!(cfg.server.bind.port(), 9999);
        assert!(cfg
            .apply_env_lookup(&|_| Some("not-an-address".into()))
            .is_err());
    }

    #[test]
    fn test_public_profile_hides_connection_details() {
        let cfg = ServerConfig::from_toml_str(MINIMAL).unwrap();
        let public = PublicProfile::from(cfg.profile("hercules").unwrap());
        let json: serde_json::Value = serde_json::to_value(&public).unwrap();
        // Only the browser-safe fields; no host, port or TLS settings in any form.
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["description", "id", "keyboard", "name"]);
        let text = json.to_string();
        assert!(!text.contains("127.0.0.1"));
        assert!(!text.contains(":3270") && !text.contains("\"port\""));
    }

    #[test]
    fn test_allowed_lu_names_must_be_sna_names_or_prefixes() {
        let with = |list: &str| {
            let toml = MINIMAL.replacen(
                "id = \"hercules\"",
                &format!("id = \"hercules\"\nallowed_lu_names = {list}"),
                1,
            );
            assert!(toml.contains("allowed_lu_names"));
            ServerConfig::from_toml_str(&toml)
        };
        assert!(with(r#"["TSO0*", "CICS01", "*"]"#).is_ok());
        assert!(with("[]").is_ok());
        for bad in [
            r#"["TSO 1"]"#,
            r#"["9ABC"]"#,
            r#"["TOOLONGNAME*"]"#,
            r#"["A*B"]"#,
        ] {
            assert!(with(bad).is_err(), "{bad}");
        }
    }
}
