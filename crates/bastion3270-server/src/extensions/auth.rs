//! Extension point **A — [`AuthProvider`]**: who is the user, which LPAR profiles may they open,
//! and (optionally) which mainframe credentials should the gateway type in on their behalf.
//!
//! Default implementations: [`NoAuthProvider`] (RACF/TSO logon screen) and
//! [`StaticTokenProvider`] (bearer tokens).

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use async_trait::async_trait;
use axum::http::{header, HeaderMap};
use bastion3270_core::{ActionKey, AidKey};
use sha2::{Digest, Sha256};

use crate::config::{AuthConfig, GatewayProfile};
use crate::secret::Secret;

/// WebSocket sub-protocol the gateway speaks. Browsers must offer it.
pub const WS_PROTOCOL: &str = "bastion3270.v1";

/// Prefix of the optional bearer-token sub-protocol entry.
///
/// The browser `WebSocket` API cannot set an `Authorization` header, so the web client sends
/// `Sec-WebSocket-Protocol: bastion3270.v1, bastion3270.bearer.<token>` instead.
pub const WS_BEARER_PREFIX: &str = "bastion3270.bearer.";

/// Which whitelisted profiles an identity may open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileAccess {
    /// Every profile from the server configuration.
    All,
    /// Only the listed profile ids.
    Only(BTreeSet<String>),
}

impl ProfileAccess {
    /// Returns `true` if the profile `id` is permitted.
    #[must_use]
    pub fn allows(&self, id: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(set) => set.contains(id),
        }
    }
}

/// The authenticated (or anonymous) user behind a browser session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    /// Stable subject (token subject, `"anonymous"`, or what an identity provider returns).
    /// Used for ownership checks on session resume, for per-identity limits and for audit
    /// records. A provider for several issuers must make it unique across them, e.g.
    /// `"<issuer>|<sub>"`: two users with the same `sub` at different issuers must never
    /// share a subject.
    pub subject: String,
    /// Optional display name for UIs.
    pub display_name: Option<String>,
    /// `true` if the gateway verified a credential (anything except [`NoAuthProvider`]).
    pub authenticated: bool,
    /// Profiles this identity may open.
    pub profiles: ProfileAccess,
    /// Free-form attributes for custom policies (groups, `racf_id`, department, …).
    pub attributes: BTreeMap<String, String>,
    /// When the authentication stops being valid (e.g. the `exp` of an identity provider's
    /// token). The gateway closes the session's mainframe connection then, attached or not;
    /// the user authenticates again for a new one. `None`: valid for the session's lifetime.
    pub expires_at: Option<SystemTime>,
}

impl SessionIdentity {
    /// Anonymous identity with access to every profile.
    #[must_use]
    pub fn anonymous() -> Self {
        Self {
            subject: "anonymous".to_owned(),
            display_name: None,
            authenticated: false,
            profiles: ProfileAccess::All,
            attributes: BTreeMap::new(),
            expires_at: None,
        }
    }
}

/// Authentication failures. Mapped to HTTP 401 / 403 / 503.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No credential was presented (HTTP 401).
    MissingCredentials,
    /// The credential was presented but is invalid or expired (HTTP 401).
    InvalidCredentials,
    /// Authenticated but not allowed (HTTP 403).
    Forbidden(String),
    /// The identity provider is unreachable (HTTP 503).
    Unavailable(String),
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingCredentials => f.write_str("missing credentials"),
            Self::InvalidCredentials => f.write_str("invalid credentials"),
            Self::Forbidden(m) => write!(f, "forbidden: {m}"),
            Self::Unavailable(m) => write!(f, "identity provider unavailable: {m}"),
        }
    }
}

impl AuthError {
    /// What the browser is told: a fixed text per kind. The text of `Forbidden` and
    /// `Unavailable` comes from an identity provider and may name internal systems; it goes
    /// to the audit record only (the [`Display`] form).
    ///
    /// [`Display`]: core::fmt::Display
    #[must_use]
    pub const fn public_message(&self) -> &'static str {
        match self {
            Self::MissingCredentials => "missing credentials",
            Self::InvalidCredentials => "invalid credentials",
            Self::Forbidden(_) => "access denied",
            Self::Unavailable(_) => "the identity provider is unavailable",
        }
    }
}

impl std::error::Error for AuthError {}

/// One step of a server-side auto-logon script.
///
/// The script runs **inside the gateway**; secrets never travel to the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogonStep {
    /// Type text at the cursor (user id, password, `PassTicket`).
    Text(Secret),
    /// Press a navigation / editing key.
    Action(ActionKey),
    /// Press an AID key (usually `Enter`).
    Aid(AidKey),
    /// Wait until the host answers the previous AID and unlocks the keyboard.
    WaitForUnlock,
}

/// Mainframe credentials resolved by an [`AuthProvider`] for automatic logon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainframeAutoLogon {
    /// Audit-safe description, e.g. `"RACF PassTicket for HERC01 / TSO"`. Must not contain secrets.
    pub description: String,
    /// Script executed once the first formatted, unlocked screen arrives.
    pub steps: Vec<LogonStep>,
}

/// Extension trait: authenticates the HTTP request that opens a WebSocket and optionally
/// supplies mainframe credentials for single sign-on.
///
/// # Why `#[async_trait]`?
/// Native `async fn` in traits is stable, but such traits are not *dyn-compatible*
/// (cannot be used as `Arc<dyn AuthProvider>`). The `async_trait` macro rewrites each method to
/// return `Pin<Box<dyn Future + Send>>`, which makes runtime plug-ins from other crates
/// possible without generics leaking through the whole server.
#[async_trait]
pub trait AuthProvider: Send + Sync + core::fmt::Debug + 'static {
    /// Short name for logs and `/api/config` (e.g. `"none"`, `"static-token"`, `"oidc"`).
    fn name(&self) -> &'static str;

    /// `true` if the web client must obtain a credential before connecting.
    fn requires_credentials(&self) -> bool;

    /// Verifies the request headers and returns the identity with its allowed profiles.
    ///
    /// # Errors
    /// Returns [`AuthError`] when the request is not authenticated / authorised.
    async fn authenticate(&self, headers: &HeaderMap) -> Result<SessionIdentity, AuthError>;

    /// Optional SSO hook called right before the TN3270 connection is opened.
    ///
    /// The default returns `Ok(None)`: the user logs on manually at the RACF/TSO screen.
    /// An implementation may return a server-side [`MainframeAutoLogon`] script.
    ///
    /// # Errors
    /// Returns [`AuthError`] if credentials cannot be produced (the session is not opened).
    async fn resolve_mainframe_credentials(
        &self,
        _identity: &SessionIdentity,
        _profile: &GatewayProfile,
    ) -> Result<Option<MainframeAutoLogon>, AuthError> {
        Ok(None)
    }
}

/// Default: no gateway authentication. Every caller is [`SessionIdentity::anonymous`] and
/// can open any **whitelisted** profile; the mainframe logon screen remains the gate.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAuthProvider;

#[async_trait]
impl AuthProvider for NoAuthProvider {
    fn name(&self) -> &'static str {
        "none"
    }

    fn requires_credentials(&self) -> bool {
        false
    }

    async fn authenticate(&self, _headers: &HeaderMap) -> Result<SessionIdentity, AuthError> {
        Ok(SessionIdentity::anonymous())
    }
}

/// One entry of the [`StaticTokenProvider`] table.
#[derive(Debug, Clone)]
struct TokenEntry {
    subject: String,
    digest: [u8; 32],
    profiles: ProfileAccess,
}

/// Static bearer tokens for small teams / lab deployments.
///
/// Accepts `Authorization: Bearer <token>` (REST, CLI) or the WebSocket sub-protocol entry
/// `bastion3270.bearer.<token>` (browser). Only SHA-256 digests are kept in memory, and the
/// comparison runs in constant time over **all** entries to avoid timing side channels.
#[derive(Debug, Clone)]
pub struct StaticTokenProvider {
    entries: Vec<TokenEntry>,
}

impl StaticTokenProvider {
    /// Builds the provider from `[auth]` configuration. Entries with malformed hashes are
    /// rejected earlier by [`ServerConfig::validate`](crate::ServerConfig::validate).
    #[must_use]
    pub fn from_config(cfg: &AuthConfig) -> Self {
        let entries = cfg
            .tokens
            .iter()
            .filter_map(|t| {
                Some(TokenEntry {
                    subject: t.subject.clone(),
                    digest: decode_hex32(&t.sha256)?,
                    profiles: if t.profiles.is_empty() {
                        ProfileAccess::All
                    } else {
                        ProfileAccess::Only(t.profiles.iter().cloned().collect())
                    },
                })
            })
            .collect();
        Self { entries }
    }
}

#[async_trait]
impl AuthProvider for StaticTokenProvider {
    fn name(&self) -> &'static str {
        "static-token"
    }

    fn requires_credentials(&self) -> bool {
        true
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<SessionIdentity, AuthError> {
        let token = extract_bearer(headers).ok_or(AuthError::MissingCredentials)?;
        let presented = sha256(token.expose().as_bytes());

        // Constant-time scan: always visit every entry, never break early.
        let mut matched: Option<&TokenEntry> = None;
        for entry in &self.entries {
            if constant_time_eq(&entry.digest, &presented) {
                matched = Some(entry);
            }
        }

        let entry = matched.ok_or(AuthError::InvalidCredentials)?;
        Ok(SessionIdentity {
            subject: entry.subject.clone(),
            display_name: None,
            authenticated: true,
            profiles: entry.profiles.clone(),
            attributes: BTreeMap::new(),
            expires_at: None,
        })
    }
}

/// Extracts a bearer token from `Authorization` or from the WebSocket sub-protocol list.
#[must_use]
pub fn extract_bearer(headers: &HeaderMap) -> Option<Secret> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = value.strip_prefix("Bearer ") {
            let token = token.trim();
            if !token.is_empty() {
                return Some(Secret::new(token));
            }
        }
    }
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .find_map(|p| p.strip_prefix(WS_BEARER_PREFIX))
        .filter(|t| !t.is_empty())
        .map(Secret::new)
}

/// SHA-256 helper.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Compares two digests without data-dependent early exit.
#[must_use]
pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Shortest accepted static token, in characters. A static token is stored as a plain SHA-256
/// digest (fast to compute), which is safe only for high-entropy secrets: 32 random hex
/// characters are 128 bits, beyond offline guessing even with the digest.
pub const MIN_TOKEN_CHARS: usize = 32;

/// A new static token: 256 bits from the operating system's CSPRNG, hex encoded. `None` if the
/// OS cannot provide randomness.
#[must_use]
pub fn generate_token() -> Option<Secret> {
    let mut bytes = zeroize::Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut()).ok()?;
    Some(Secret::new(encode_hex(bytes.as_ref())))
}

/// Checks a static token chosen by an operator: long enough for a plain digest, and made of
/// characters a browser can send (the token travels as a WebSocket sub-protocol name, which
/// must be an HTTP token, RFC 9110 §5.6.2).
///
/// # Errors
/// A sentence saying what is wrong (never the token itself).
pub fn check_token_strength(token: &str) -> Result<(), String> {
    const SEPARATORS: &[u8] = b"!#$%&'*+-.^_`|~";
    if token.chars().count() < MIN_TOKEN_CHARS {
        return Err(format!(
            "the token is shorter than {MIN_TOKEN_CHARS} characters (use --generate-token)"
        ));
    }
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || SEPARATORS.contains(&b))
    {
        return Err(
            "the token contains characters a browser cannot send (letters, digits and \
             !#$%&'*+-.^_`|~ only)"
                .to_owned(),
        );
    }
    Ok(())
}

/// Lower-case hex encoding (used for digests in logs and resume tokens).
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(
            HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'),
        ));
        out.push(char::from(
            HEX.get(usize::from(b & 0x0F)).copied().unwrap_or(b'0'),
        ));
    }
    out
}

/// Decodes exactly 64 hex characters into 32 bytes.
#[must_use]
pub fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    // `as_chunks::<2>()` yields `&[[u8; 2]]`: the pair length is a compile-time fact,
    // so destructuring `[hi, lo]` needs no bounds-checked `.get()`.
    let (pairs, _) = bytes.as_chunks::<2>();
    for (slot, &[hi, lo]) in out.iter_mut().zip(pairs) {
        let hi = char::from(hi).to_digit(16)?;
        let lo = char::from(lo).to_digit(16)?;
        *slot = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::StaticTokenEntry;
    use axum::http::HeaderValue;

    fn provider() -> StaticTokenProvider {
        StaticTokenProvider::from_config(&AuthConfig {
            mode: crate::config::AuthMode::StaticToken,
            tokens: vec![StaticTokenEntry {
                subject: "sysprog".into(),
                sha256: encode_hex(&sha256(b"s3cret-token")),
                profiles: vec!["hercules".into()],
            }],
        })
    }

    #[test]
    fn test_hex_roundtrip() {
        let d = sha256(b"abc");
        assert_eq!(decode_hex32(&encode_hex(&d)), Some(d));
        assert_eq!(decode_hex32("zz"), None);
        assert_eq!(decode_hex32(&"g".repeat(64)), None);
    }

    #[tokio::test]
    async fn test_static_token_via_authorization_header() {
        let p = provider();
        let mut h = HeaderMap::new();
        assert_eq!(p.authenticate(&h).await, Err(AuthError::MissingCredentials));

        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        assert_eq!(p.authenticate(&h).await, Err(AuthError::InvalidCredentials));

        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer s3cret-token"),
        );
        let id = p.authenticate(&h).await.unwrap();
        assert_eq!(id.subject, "sysprog");
        assert!(id.authenticated);
        assert!(id.profiles.allows("hercules"));
        assert!(!id.profiles.allows("prod"));
    }

    #[tokio::test]
    async fn test_static_token_via_websocket_subprotocol() {
        let mut h = HeaderMap::new();
        h.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("bastion3270.v1, bastion3270.bearer.s3cret-token"),
        );
        assert_eq!(
            provider().authenticate(&h).await.unwrap().subject,
            "sysprog"
        );
    }

    #[tokio::test]
    async fn test_no_auth_is_anonymous_and_has_no_sso() {
        let p = NoAuthProvider;
        let id = p.authenticate(&HeaderMap::new()).await.unwrap();
        assert!(!id.authenticated);
        assert!(id.profiles.allows("anything"));
        let profile = GatewayProfile {
            id: "x".into(),
            name: "x".into(),
            description: String::new(),
            allow_paste: true,
            allow_copy: true,
            keyboard: crate::config::KeyboardPreset::default(),
            allowed_lu_names: None,
            custom: false,
            connection: bastion3270_net::ConnectionProfile::default(),
        };
        assert_eq!(
            p.resolve_mainframe_credentials(&id, &profile).await,
            Ok(None)
        );
    }

    #[test]
    fn test_generated_tokens_are_strong_and_accepted() {
        let a = super::generate_token().unwrap();
        let b = super::generate_token().unwrap();
        assert_ne!(a.expose(), b.expose());
        assert_eq!(a.expose().len(), 64);
        assert_eq!(super::check_token_strength(a.expose()), Ok(()));
    }

    #[test]
    fn test_weak_or_unsendable_tokens_are_refused() {
        assert!(super::check_token_strength("lab-token-1").is_err());
        assert!(super::check_token_strength(&"a".repeat(31)).is_err());
        assert!(super::check_token_strength(&"a".repeat(32)).is_ok());
        let spaced = format!("{} {}", "a".repeat(20), "b".repeat(20));
        assert!(super::check_token_strength(&spaced).is_err());
        let err = super::check_token_strength("Qz7xW").unwrap_err();
        assert!(!err.contains("Qz7xW"), "the token is never echoed: {err}");
    }
}
