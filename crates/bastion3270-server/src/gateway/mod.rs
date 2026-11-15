//! Server-side session management: opening, resuming, closing and reaping
//! [`GatewaySession`]s, with limits and audit hooks applied in one place.

mod autologon;
mod options;
mod session;
mod throttle;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bastion3270_net::transport::HostTrust;
use bastion3270_net::{SessionCoordinator, SessionState};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tracing::Instrument as _;

pub use options::{ModelChoice, SessionOptions, MAX_DYNAMIC, MIN_DYNAMIC};
use session::{spawn_event_pump, SessionSlot, SlotCounts};
pub use session::{GatewaySession, SessionId, Snapshot};

use crate::config::{GatewayProfile, ServerConfig};
use crate::custom::{CustomTarget, CUSTOM_PROFILE_ID};
use crate::extensions::auth::{encode_hex, AuthError, SessionIdentity};
use crate::extensions::{Extensions, SessionAuditEvent, SessionAuditKind};
use crate::metrics::Metrics;
use crate::secret::Secret;

/// Why a session could not be opened or resumed. Each variant maps to a stable wire `code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// The profile id is not in the whitelist.
    UnknownProfile,
    /// The identity may not open this profile.
    Forbidden,
    /// Capacity limit reached.
    LimitExceeded(String),
    /// SSO hook failed.
    Auth(AuthError),
    /// TCP/TLS connect or Telnet setup failed.
    Connect(String),
    /// Session store refused the session.
    Store(String),
    /// The operating system could not provide randomness for the resume token.
    Random,
    /// Resume: unknown id, wrong owner, wrong token or already ended (deliberately
    /// indistinguishable, so ids cannot be probed).
    NotFound,
    /// The gateway is shutting down (e.g. a pod being replaced): no new or resumed sessions.
    ShuttingDown,
    /// The user's session choices are invalid (model, screen size, code page).
    InvalidOptions(String),
}

impl OpenError {
    /// Stable machine-readable code for the web client.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownProfile => "unknown_profile",
            Self::Forbidden => "forbidden",
            Self::LimitExceeded(_) => "limit_exceeded",
            Self::Auth(_) => "auth_failed",
            Self::Connect(_) => "connect_failed",
            Self::Store(_) => "store_failed",
            Self::Random => "internal_error",
            Self::NotFound => "session_not_found",
            Self::ShuttingDown => "shutting_down",
            Self::InvalidOptions(_) => "invalid_options",
        }
    }
}

impl core::fmt::Display for OpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownProfile => f.write_str("unknown profile"),
            Self::Forbidden => f.write_str("profile not permitted for this identity"),
            Self::LimitExceeded(m) => f.write_str(m),
            // Sent to the browser: the details (host names, certificate names, file paths)
            // stay in the server's audit record, see [`OpenError::detail`].
            Self::Connect(_) => f.write_str("could not connect to the host"),
            Self::Store(_) => f.write_str("the session could not be stored"),
            Self::Random => f.write_str("internal error"),
            Self::Auth(e) => f.write_str(e.public_message()),
            Self::NotFound => f.write_str("session not found or expired"),
            Self::ShuttingDown => f.write_str("the gateway is restarting; try again shortly"),
            Self::InvalidOptions(m) => write!(f, "invalid session settings: {m}"),
        }
    }
}

impl OpenError {
    /// The full description for server-side records (audit, logs); [`Display`] is what the
    /// browser sees.
    ///
    /// [`Display`]: core::fmt::Display
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Connect(m) => format!("could not connect to the host: {m}"),
            Self::Store(m) => format!("the session could not be stored: {m}"),
            Self::Auth(e) => e.to_string(),
            Self::Random => "the operating system random source failed".to_owned(),
            other => other.to_string(),
        }
    }
}

/// The session manager shared by all HTTP / WebSocket handlers (`Arc<Gateway>`).
#[derive(Debug)]
pub struct Gateway {
    config: Arc<ServerConfig>,
    ext: Extensions,
    counts: Arc<Mutex<SlotCounts>>,
    handshakes: Arc<Semaphore>,
    throttle: throttle::FailureThrottle,
    metrics: Metrics,
    /// `true` from the start of [`Gateway::shutdown`]: no new or resumed sessions.
    stopping: watch::Sender<bool>,
    /// Open WebSocket tasks ([`Gateway::track_socket`]): a shutdown waits until every browser
    /// was told its session ended.
    sockets: watch::Sender<usize>,
    /// Trust anchors for the hosts' certificates (`[host_tls]`), loaded once.
    host_trust: std::sync::OnceLock<core::result::Result<HostTrust, String>>,
}

/// Longest wait of a shutdown for the browsers to be told (inside Kubernetes'
/// `terminationGracePeriodSeconds`, 30 s in `deploy/k8s`, together with the HTTP drain).
const SOCKET_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Holds one place in [`Gateway::track_socket`] while a WebSocket task runs.
#[derive(Debug)]
pub(crate) struct SocketGuard<'a>(&'a watch::Sender<usize>);

impl Drop for SocketGuard<'_> {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n = n.saturating_sub(1));
    }
}

impl Gateway {
    /// Creates a gateway.
    #[must_use]
    pub fn new(config: ServerConfig, ext: Extensions) -> Self {
        Self {
            handshakes: Arc::new(Semaphore::new(config.limits.max_pending_handshakes)),
            throttle: throttle::FailureThrottle::new(Instant::now()),
            metrics: Metrics::default(),
            config: Arc::new(config),
            ext,
            counts: Arc::new(Mutex::new(SlotCounts::default())),
            stopping: watch::Sender::new(false),
            sockets: watch::Sender::new(0),
            host_trust: std::sync::OnceLock::new(),
        }
    }

    /// The trust anchors for the hosts' certificates: the Mozilla roots, the system store and
    /// `[host_tls] ca_certs`. Loaded on first use (the server loads them before it listens,
    /// so a bad file stops the start); a failure is kept and refuses every TLS session.
    ///
    /// # Errors
    /// The reason the CA files could not be loaded.
    pub fn host_trust(&self) -> core::result::Result<&HostTrust, String> {
        self.host_trust
            .get_or_init(|| self.config.host_tls.trust().map_err(|e| e.to_string()))
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Counts a WebSocket task until the guard is dropped (also on cancellation).
    pub(crate) fn track_socket(&self) -> SocketGuard<'_> {
        self.sockets.send_modify(|n| *n = n.saturating_add(1));
        SocketGuard(&self.sockets)
    }

    /// `true` once a shutdown has begun.
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        *self.stopping.borrow()
    }

    /// Resolves when a shutdown begins.
    pub(crate) async fn stopping(&self) {
        let mut rx = self.stopping.subscribe();
        let _ = rx.wait_for(|stopping| *stopping).await;
    }

    /// Operational metrics of this gateway.
    #[must_use]
    pub const fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Live sessions split into attached and detached (for the metrics scrape).
    pub async fn session_states(&self) -> crate::metrics::Live {
        let mut live = crate::metrics::Live::default();
        for session in self.ext.store.sessions().await {
            if session.is_attached() {
                live.attached += 1;
            } else {
                live.detached += 1;
            }
        }
        live
    }

    /// Reserves one of the `max_pending_handshakes` places for a WebSocket that has not sent
    /// its first message yet; `None` when all are taken. Dropping the permit frees the place.
    #[must_use]
    pub fn try_begin_handshake(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.handshakes).try_acquire_owned().ok()
    }

    /// Server configuration.
    #[must_use]
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Installed extensions.
    #[must_use]
    pub const fn extensions(&self) -> &Extensions {
        &self.ext
    }

    /// Number of live sessions (including ones still connecting).
    #[must_use]
    pub fn live_sessions(&self) -> usize {
        self.counts.lock().map_or(usize::MAX, |c| c.total)
    }

    /// Emits a session audit event.
    pub fn audit(
        &self,
        session: Option<&GatewaySession>,
        identity: Option<&SessionIdentity>,
        peer: Option<SocketAddr>,
        kind: SessionAuditKind,
    ) {
        if kind.is_failure() {
            let (record, suppressed) =
                self.throttle
                    .admit(kind.name(), peer.map(|p| p.ip()), Instant::now());
            self.report_suppressed(suppressed);
            if !record {
                return;
            }
        }
        let event = SessionAuditEvent {
            at: SystemTime::now(),
            session_id: session.map(GatewaySession::id),
            subject: session
                .map(|s| s.identity().subject.clone())
                .or_else(|| identity.map(|i| i.subject.clone())),
            profile_id: session.map(|s| s.profile().id.clone()),
            peer,
            kind,
        };
        self.metrics.audit_events.inc(event.kind.name());
        self.ext.audit.on_session_event(&event);
    }

    /// One `AuditSuppressed` record per kind and source that the throttle held back.
    fn report_suppressed(&self, suppressed: Vec<throttle::Suppressed>) {
        for s in suppressed {
            self.ext.audit.on_session_event(&SessionAuditEvent {
                at: SystemTime::now(),
                session_id: None,
                subject: None,
                profile_id: None,
                peer: s.source.map(|ip| SocketAddr::new(ip, 0)),
                kind: SessionAuditKind::AuditSuppressed {
                    event: s.kind.to_owned(),
                    count: s.count,
                },
            });
        }
    }

    /// Opens a new mainframe session for `identity` on the whitelisted profile `profile_id`.
    ///
    /// Returns the session and its one-time-displayed resume token.
    ///
    /// # Errors
    /// See [`OpenError`].
    pub async fn open_session(
        &self,
        identity: &SessionIdentity,
        profile_id: &str,
        options: &SessionOptions,
        peer: Option<SocketAddr>,
    ) -> Result<(Arc<GatewaySession>, Secret), OpenError> {
        let profile = self
            .config
            .profile(profile_id)
            .cloned()
            .ok_or(OpenError::UnknownProfile)
            .and_then(|p| {
                if identity.profiles.allows(&p.id) {
                    Ok(p)
                } else {
                    Err(OpenError::Forbidden)
                }
            });
        self.open_audited(identity, profile_id, profile, options, peer)
            .await
    }

    /// Opens a session to a target the user entered (host, port, TLS), if the gateway's
    /// `[custom_connections]` policy allows it and the identity may use custom connections
    /// (profile id `custom`). The session's profile id is `custom:<host>:<port>`.
    ///
    /// # Errors
    /// [`OpenError::InvalidOptions`] when the policy refuses the target, otherwise as
    /// [`Gateway::open_session`].
    pub async fn open_custom_session(
        &self,
        identity: &SessionIdentity,
        target: &CustomTarget,
        options: &SessionOptions,
        peer: Option<SocketAddr>,
    ) -> Result<(Arc<GatewaySession>, Secret), OpenError> {
        let profile = if identity.profiles.allows(CUSTOM_PROFILE_ID) {
            self.config
                .custom_connections
                .profile_for(target)
                .map_err(OpenError::InvalidOptions)
        } else {
            Err(OpenError::Forbidden)
        };
        // Only a well-formed target is echoed into the audit record.
        let label = profile
            .as_ref()
            .map_or_else(|_| CUSTOM_PROFILE_ID.to_owned(), |p| p.id.clone());
        self.open_audited(identity, &label, profile, options, peer)
            .await
    }

    /// Opens with an already resolved profile; metrics and audit for both kinds of open.
    async fn open_audited(
        &self,
        identity: &SessionIdentity,
        profile_id: &str,
        profile: Result<GatewayProfile, OpenError>,
        options: &SessionOptions,
        peer: Option<SocketAddr>,
    ) -> Result<(Arc<GatewaySession>, Secret), OpenError> {
        let result = match profile {
            Ok(profile) => self.open_inner(identity, profile, options).await,
            Err(e) => Err(e),
        };
        self.metrics
            .sessions_opened
            .inc(result.as_ref().map_or_else(OpenError::code, |_| "ok"));
        match &result {
            Ok((session, _)) => self.audit(Some(session), None, peer, SessionAuditKind::Opened),
            // The profile was found before connecting, so its id is a whitelisted one.
            Err(err @ OpenError::Connect(_)) => self.audit(
                None,
                Some(identity),
                peer,
                SessionAuditKind::ConnectFailed {
                    reason: format!("open '{profile_id}': {}", err.detail()),
                },
            ),
            Err(err) => self.audit(
                None,
                Some(identity),
                peer,
                SessionAuditKind::PolicyDenied {
                    // The id comes from the client: only a well-formed one is echoed.
                    reason: if crate::config::is_valid_id(profile_id)
                        || profile_id.starts_with(CUSTOM_PROFILE_ID)
                    {
                        format!("open '{profile_id}': {}", err.detail())
                    } else {
                        format!("open <invalid profile id>: {}", err.detail())
                    },
                },
            ),
        }
        result
    }

    async fn open_inner(
        &self,
        identity: &SessionIdentity,
        mut profile: GatewayProfile,
        options: &SessionOptions,
    ) -> Result<(Arc<GatewaySession>, Secret), OpenError> {
        if self.is_stopping() {
            return Err(OpenError::ShuttingDown);
        }
        // The user's choices change a copy of the profile; the result must still be a valid
        // connection profile (checked before any capacity is taken or anything connects).
        options
            .apply(&mut profile.connection, profile.allowed_lu_names.as_deref())
            .map_err(OpenError::InvalidOptions)?;
        profile
            .connection
            .validate()
            .map_err(|e| OpenError::InvalidOptions(e.to_string()))?;

        // Reserve capacity *before* the expensive connect. If anything below fails, the slot
        // is dropped and released automatically (RAII).
        // Without authentication all users share one subject, so a per-identity limit would
        // let one user lock out everyone: anonymous sessions only count against the total.
        let limits = &self.config.limits;
        let per_identity = if identity.authenticated {
            limits.max_sessions_per_identity
        } else {
            usize::MAX
        };
        let slot = SessionSlot::try_reserve(
            &self.counts,
            &identity.subject,
            limits.max_sessions,
            per_identity,
        )
        .map_err(|e| {
            self.metrics.limit_rejections.inc(e.limit());
            OpenError::LimitExceeded(e.to_string())
        })?;

        let autologon = self
            .ext
            .auth
            .resolve_mainframe_credentials(identity, &profile)
            .await
            .map_err(OpenError::Auth)?;

        // The session id exists before the connection, so the network layer's log lines carry
        // it (span `session`); the audit trail uses the same id.
        let connect_started = Instant::now();
        let id = SessionId::random();
        let span = tracing::info_span!("session", session = %id, profile = %profile.id);
        let trust = self.host_trust().map_err(OpenError::Connect)?;
        let (handle, events, _join) =
            SessionCoordinator::connect_with_trust(profile.connection.clone(), trust)
                .instrument(span)
                .await
                .map_err(|e| OpenError::Connect(e.to_string()))?;

        let status = handle
            .query_status()
            .await
            .map_err(|e| OpenError::Connect(e.to_string()))?;
        let view = handle
            .query_screen()
            .await
            .map_err(|e| OpenError::Connect(e.to_string()))?;
        self.metrics.host_connect.observe(connect_started.elapsed());

        let (tx, rx) = watch::channel(Snapshot {
            seq: 0,
            view,
            state: status.state,
            keyboard: status.keyboard_state,
            is_tls: status.is_tls,
            is_tn3270e: status.is_tn3270e,
            lu: status.assigned_lu,
            alarm_seq: 0,
            last_error: None,
            host_mode: bastion3270_core::HostMode::default(),
            insert_mode: false,
            banner: None,
        });
        spawn_event_pump(events, tx);

        // Dropping `handle` on this error ends the host connection again.
        let token = new_resume_token().ok_or(OpenError::Random)?;
        let session = Arc::new(GatewaySession::new(
            id,
            &token,
            identity.clone(),
            profile,
            handle,
            rx,
            slot,
        ));

        if let Err(e) = self.ext.store.insert(Arc::clone(&session)).await {
            session.terminate().await;
            return Err(OpenError::Store(e));
        }

        if let Some(logon) = autologon {
            self.spawn_autologon(Arc::clone(&session), logon);
        }

        Ok((session, token))
    }

    fn spawn_autologon(
        &self,
        session: Arc<GatewaySession>,
        logon: crate::extensions::MainframeAutoLogon,
    ) {
        let audit = Arc::clone(&self.ext.audit);
        // Held before the session is handed to the browser, released when the script ends.
        session.hold_input(true);
        tokio::spawn(async move {
            let description = logon.description.clone();
            let success =
                autologon::run(session.handle().clone(), session.subscribe(), logon).await;
            session.hold_input(false);
            audit.on_session_event(&SessionAuditEvent {
                at: SystemTime::now(),
                session_id: Some(session.id()),
                subject: Some(session.identity().subject.clone()),
                profile_id: Some(session.profile().id.clone()),
                peer: None,
                kind: SessionAuditKind::AutoLogon {
                    description,
                    success,
                },
            });
        });
    }

    /// Re-attaches to an existing session (browser refresh / reconnect). Returns the session
    /// and its **new** resume token: every token resumes at most once, so a token that leaked
    /// (shared workstation, screenshot, storage dump) stops working after the next resume.
    ///
    /// # Errors
    /// [`OpenError::NotFound`] for every failure (unknown id, wrong owner, profile no longer
    /// allowed, wrong token, ended); every failure is audited the same way.
    pub async fn resume_session(
        &self,
        identity: &SessionIdentity,
        session_id: &str,
        token: &str,
        peer: Option<SocketAddr>,
    ) -> Result<(Arc<GatewaySession>, Secret), OpenError> {
        if self.is_stopping() {
            return Err(OpenError::ShuttingDown);
        }
        let session = match session_id.parse::<SessionId>() {
            Ok(id) => self.ext.store.get(&id).await,
            Err(_) => None,
        };
        let next = new_resume_token().ok_or(OpenError::Random)?;
        let resumed = session.filter(|session| {
            // All checks are evaluated before the token exchange decides (no short-circuit
            // timing difference between them).
            let allowed = session.identity().subject == identity.subject
                && identity.profiles.allows(session.profile().permission_id())
                && !session.is_terminal();
            session.exchange_resume_token(token, allowed, &next)
        });
        let Some(session) = resumed else {
            self.audit(
                None,
                Some(identity),
                peer,
                SessionAuditKind::PolicyDenied {
                    reason: "resume rejected".to_owned(),
                },
            );
            return Err(OpenError::NotFound);
        };
        self.metrics.sessions_resumed.inc();
        self.audit(Some(&session), None, peer, SessionAuditKind::Resumed);
        Ok((session, next))
    }

    /// Closes every session of `subject` (the user was disabled, logged out at the identity
    /// provider, or an administrator ended their sessions). Returns how many were closed; each
    /// is audited as `Closed` with `reason`.
    pub async fn close_sessions_for(&self, subject: &str, reason: &str) -> usize {
        let mut closed = 0;
        for session in self.ext.store.sessions().await {
            if session.identity().subject == subject {
                self.close_session(&session.id(), reason).await;
                closed += 1;
            }
        }
        closed
    }

    /// Removes and disconnects a session. Audits `Closed` exactly once with `reason`; an
    /// attached browser gets [`browser_close_reason`] of it.
    pub async fn close_session(&self, id: &SessionId, reason: &str) {
        if let Some(session) = self.ext.store.remove(id).await {
            session.terminate_for(browser_close_reason(reason)).await;
            self.metrics
                .sessions_closed
                .inc(Metrics::close_reason(reason));
            self.audit(
                Some(&session),
                None,
                None,
                SessionAuditKind::Closed {
                    reason: reason.to_owned(),
                },
            );
        }
    }

    /// One reaper pass: drops ended sessions, sessions detached longer than the grace period,
    /// sessions older than the maximum lifetime (attached or not: activity does not extend it,
    /// so a session cannot be kept alive forever) and sessions without operator input for the
    /// inactivity timeout (an unattended open tab).
    pub async fn reap_once(&self) {
        let limits = &self.config.limits;
        let grace = Duration::from_secs(limits.detach_grace_secs);
        let lifetime = Duration::from_secs(limits.max_session_lifetime_secs);
        let idle = Duration::from_secs(limits.idle_timeout_secs);
        self.report_suppressed(self.throttle.flush(Instant::now()));
        for session in self.ext.store.sessions().await {
            let snap_state = session.snapshot().state;
            if snap_state.is_terminal() {
                self.close_session(&session.id(), &closed_reason(&snap_state))
                    .await;
            } else if session.detached_for().is_some_and(|d| d >= grace) {
                self.close_session(&session.id(), "expired").await;
            } else if session.age() >= lifetime {
                self.close_session(&session.id(), "lifetime").await;
            } else if session.idle_for() >= idle {
                self.close_session(&session.id(), "idle").await;
            } else if session
                .identity()
                .expires_at
                .is_some_and(|at| at <= SystemTime::now())
            {
                self.close_session(&session.id(), "identity_expired").await;
            }
        }
    }

    /// Spawns the periodic reaper task.
    pub fn spawn_reaper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let gw = Arc::clone(self);
        let every = Duration::from_secs(self.config.limits.reaper_interval_secs);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                gw.reap_once().await;
            }
        })
    }

    /// Graceful shutdown (SIGTERM of a pod being replaced): refuses new and resumed sessions,
    /// disconnects every session, and waits (at most [`SOCKET_DRAIN_TIMEOUT`]) until every
    /// attached browser was told (`closed`, reason `server_shutdown`) and its socket closed.
    /// Without the wait the process could exit while the closing messages are still unsent.
    pub async fn shutdown(&self) {
        self.stopping.send_replace(true);
        // Repeated until the sockets are gone: a session whose opening was already past the
        // `stopping` check is stored after the first pass and closed by a later one.
        let deadline = Instant::now() + SOCKET_DRAIN_TIMEOUT;
        let mut open = self.sockets.subscribe();
        loop {
            for session in self.ext.store.sessions().await {
                self.close_session(&session.id(), "server shutdown").await;
            }
            if *open.borrow_and_update() == 0 {
                return;
            }
            if Instant::now() >= deadline {
                tracing::warn!(
                    target: "bastion3270::server",
                    sockets = *open.borrow(),
                    "shutdown: browsers still connected after the drain timeout"
                );
                return;
            }
            let _ = tokio::time::timeout(Duration::from_millis(200), open.changed()).await;
        }
    }
}

/// Audit reason for a terminal session state.
#[must_use]
pub fn closed_reason(state: &SessionState) -> String {
    match state {
        SessionState::Error(msg) => format!("error: {msg}"),
        _ => "host disconnected".to_owned(),
    }
}

/// The `closed` reason a browser gets when a session is closed for `reason` (the audited
/// reason). A fixed set of codes: the browser can explain each, and a reason that a custom
/// binary passes to [`Gateway::close_sessions_for`] (free text) never reaches the page.
#[must_use]
pub fn browser_close_reason(reason: &str) -> &'static str {
    match Metrics::close_reason(reason) {
        "user" => "user",
        "idle" => "idle",
        "lifetime" => "lifetime",
        "identity_expired" => "identity_expired",
        "shutdown" => "server_shutdown",
        "host" | "host_error" => "host_disconnected",
        _ => "ended",
    }
}

/// 256 bits from the operating system's CSPRNG, hex encoded. `None` if the OS cannot provide
/// randomness (then no session is opened: a guessable token must never be issued).
fn new_resume_token() -> Option<Secret> {
    let mut bytes = zeroize::Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut()).ok()?;
    Some(Secret::new(encode_hex(bytes.as_ref())))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use std::collections::HashSet;

    /// Resume tokens carry 256 bits from the OS CSPRNG (64 hex digits) and do not repeat.
    #[test]
    fn test_resume_tokens_are_256_random_bits() {
        let tokens: HashSet<String> = (0..1000)
            .map(|_| super::new_resume_token().unwrap().expose().to_owned())
            .collect();
        assert_eq!(tokens.len(), 1000);
        for t in &tokens {
            assert_eq!(t.len(), 64);
            assert!(t.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        // Every hex digit position varies (a UUID has fixed version / variant digits).
        for i in 0..64 {
            let digits: HashSet<u8> = tokens.iter().map(|t| t.as_bytes()[i]).collect();
            assert!(digits.len() > 1, "digit {i} never changes");
        }
    }

    /// The browser learns why the gateway closed a session, from a fixed set of codes; host
    /// errors stay `host_disconnected` (their text names internal systems) and a custom
    /// binary's free-text reason becomes `ended`.
    #[test]
    fn test_browser_close_reasons_are_fixed_codes() {
        for (audited, browser) in [
            ("idle", "idle"),
            ("lifetime", "lifetime"),
            ("identity_expired", "identity_expired"),
            ("user", "user"),
            ("server shutdown", "server_shutdown"),
            ("host disconnected", "host_disconnected"),
            ("error: TLS alert from lpar1.internal", "host_disconnected"),
            ("expired", "ended"),
            ("disabled in the directory by J. Smith", "ended"),
        ] {
            assert_eq!(super::browser_close_reason(audited), browser, "{audited}");
        }
    }
}
