//! [`GatewaySession`] — one live mainframe session owned by the gateway, independent of any
//! browser tab. A browser *attaches* to it; closing the tab only *detaches*.
//!
//! ## Why a `tokio::sync::watch` channel?
//! The `SessionCoordinator` emits a stream of events. The gateway folds them into a single
//! latest [`Snapshot`] stored in a `watch` channel:
//! * a slow browser never builds up a queue — it simply skips intermediate screens and always
//!   renders the newest one (natural backpressure, constant memory per session);
//! * a re-attached browser (after F5) immediately gets the current screen.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use bastion3270_core::{HostMode, KeyboardState, SafeScreenView};
use bastion3270_net::{SessionEvent, SessionHandle, SessionState};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use crate::config::GatewayProfile;
use crate::extensions::auth::{constant_time_eq, sha256, SessionIdentity};
use crate::secret::Secret;

/// Opaque, random session identifier (UUID v4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(Uuid);

impl SessionId {
    /// Generates a new random id.
    #[must_use]
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }

    /// Underlying UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for SessionId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

/// Latest known state of a session, folded from [`SessionEvent`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Monotonic counter, incremented on every change.
    pub seq: u64,
    /// Masked screen.
    pub view: SafeScreenView,
    /// Lifecycle state.
    pub state: SessionState,
    /// OIA keyboard state.
    pub keyboard: KeyboardState,
    /// Transport is TLS.
    pub is_tls: bool,
    /// TN3270E negotiated.
    pub is_tn3270e: bool,
    /// Host-assigned LU name.
    pub lu: Option<String>,
    /// Incremented on every host alarm (the client beeps when it changes).
    pub alarm_seq: u64,
    /// Last error or warning reported by the session layer.
    pub last_error: Option<String>,
    /// What the host exchanges with the terminal (3270, SSCP-LU, NVT, unbound).
    pub host_mode: HostMode,
    /// Insert mode is on.
    pub insert_mode: bool,
    /// NVT text from the host (for example a banner before the 3270 session starts), reduced
    /// to printable ASCII and bounded; cleared when 3270 or SSCP-LU data takes over.
    pub banner: Option<String>,
}

/// Longest NVT banner kept for the browser, in characters.
const MAX_BANNER_CHARS: usize = 480;

/// Appends NVT text to the banner: printable ASCII only (line ends and tabs become spaces,
/// other control bytes and escape sequences' bytes are dropped), whitespace collapsed, and
/// only the last [`MAX_BANNER_CHARS`] characters kept. Returns `true` if the banner changed.
fn append_banner(banner: &mut Option<String>, bytes: &[u8]) -> bool {
    let mut text = banner.clone().unwrap_or_default();
    for &b in bytes {
        let ch = match b {
            0x20..=0x7E => char::from(b),
            b'\r' | b'\n' | b'\t' => ' ',
            _ => continue,
        };
        if ch == ' ' && (text.is_empty() || text.ends_with(' ')) {
            continue;
        }
        text.push(ch);
    }
    let excess = text.chars().count().saturating_sub(MAX_BANNER_CHARS);
    if excess > 0 {
        text = text.chars().skip(excess).collect();
    }
    let new = (!text.trim().is_empty()).then(|| text.trim_end().to_string());
    let changed = new != *banner;
    *banner = new;
    changed
}

impl Snapshot {
    /// Applies one event; returns `true` if anything visible changed.
    fn apply(&mut self, event: SessionEvent) -> bool {
        match event {
            SessionEvent::StateChanged(state) => self.state = state,
            SessionEvent::NegotiationComplete {
                is_tn3270e,
                assigned_lu,
            } => {
                self.is_tn3270e = is_tn3270e;
                self.lu = assigned_lu;
            }
            SessionEvent::ScreenUpdated(view) => self.view = view,
            SessionEvent::KeyboardStateChanged(kb) => self.keyboard = kb,
            SessionEvent::Alarm => self.alarm_seq = self.alarm_seq.wrapping_add(1),
            SessionEvent::Error(msg) => self.last_error = Some(msg),
            SessionEvent::Disconnected => {
                if !self.state.is_terminal() {
                    self.state = SessionState::Disconnected;
                }
            }
            SessionEvent::InsertModeChanged(on) => self.insert_mode = on,
            SessionEvent::HostModeChanged(mode) => {
                self.host_mode = mode;
                if matches!(mode, HostMode::Data3270 | HostMode::SscpLu) {
                    self.banner = None;
                }
            }
            SessionEvent::NvtData(data) => {
                if !append_banner(&mut self.banner, &data) {
                    return false;
                }
            }
            // Warnings are diagnostics only; they never reach the browser.
            SessionEvent::Warning(_) => return false,
        }
        self.seq = self.seq.wrapping_add(1);
        true
    }
}

/// Folds the coordinator's event stream into the `watch` channel until the session ends.
pub(crate) fn spawn_event_pump(
    mut events: mpsc::Receiver<SessionEvent>,
    tx: watch::Sender<Snapshot>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            tx.send_if_modified(|snap| snap.apply(event));
        }
        // Event channel closed = coordinator task finished.
        tx.send_if_modified(|snap| {
            if snap.state.is_terminal() {
                false
            } else {
                snap.state = SessionState::Disconnected;
                snap.seq = snap.seq.wrapping_add(1);
                true
            }
        });
    })
}

/// Live-session counters shared by all [`SessionSlot`]s of one gateway.
#[derive(Debug, Default)]
pub(crate) struct SlotCounts {
    pub(crate) total: usize,
    pub(crate) per_subject: HashMap<String, usize>,
}

/// RAII capacity reservation. Created *before* connecting to the mainframe and owned by the
/// [`GatewaySession`]; when the last `Arc<GatewaySession>` is dropped (or connecting fails),
/// `Drop` returns the slot. Counting therefore never drifts, even on early `?` returns.
#[derive(Debug)]
pub(crate) struct SessionSlot {
    counts: Arc<Mutex<SlotCounts>>,
    subject: String,
}

impl SessionSlot {
    /// Tries to reserve one slot under the given limits.
    pub(crate) fn try_reserve(
        counts: &Arc<Mutex<SlotCounts>>,
        subject: &str,
        max_total: usize,
        max_per_subject: usize,
    ) -> Result<Self, SlotError> {
        let mut c = counts.lock().map_err(|_| SlotError::Poisoned)?;
        if c.total >= max_total {
            return Err(SlotError::Total { max: max_total });
        }
        let mine = c.per_subject.get(subject).copied().unwrap_or(0);
        if mine >= max_per_subject {
            return Err(SlotError::PerSubject {
                mine,
                max: max_per_subject,
            });
        }
        c.total += 1;
        c.per_subject.insert(subject.to_owned(), mine + 1);
        Ok(Self {
            counts: Arc::clone(counts),
            subject: subject.to_owned(),
        })
    }
}

/// Why no slot was reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotError {
    /// The gateway is at `max_sessions`.
    Total { max: usize },
    /// The identity is at `max_sessions_per_identity`.
    PerSubject { mine: usize, max: usize },
    /// The counter lock was poisoned (a panic elsewhere); refuse rather than guess.
    Poisoned,
}

impl SlotError {
    /// The limit's name in metrics.
    pub(crate) const fn limit(self) -> &'static str {
        match self {
            Self::Total { .. } | Self::Poisoned => "sessions",
            Self::PerSubject { .. } => "sessions_per_identity",
        }
    }
}

impl fmt::Display for SlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Total { max } => write!(f, "gateway is at capacity ({max} sessions)"),
            Self::PerSubject { mine, max } => {
                write!(f, "identity already has {mine} sessions (limit {max})")
            }
            Self::Poisoned => f.write_str("slot counter lock poisoned"),
        }
    }
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        if let Ok(mut c) = self.counts.lock() {
            c.total = c.total.saturating_sub(1);
            if let Some(n) = c.per_subject.get_mut(&self.subject) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    c.per_subject.remove(&self.subject);
                }
            }
        }
    }
}

/// A live mainframe session held by the gateway.
#[derive(Debug)]
pub struct GatewaySession {
    id: SessionId,
    /// SHA-256 of the current resume token; replaced on every successful resume.
    resume_digest: Mutex<[u8; 32]>,
    identity: SessionIdentity,
    profile: GatewayProfile,
    created_at: SystemTime,
    /// Monotonic start, for the maximum lifetime (the wall clock may jump).
    started: Instant,
    handle: SessionHandle,
    snapshot_rx: watch::Receiver<Snapshot>,
    attach_tx: watch::Sender<u64>,
    detached_since: Mutex<Option<Instant>>,
    /// Last operator input (keys, paste, AIDs; not pings), for the inactivity timeout.
    last_input: Mutex<Instant>,
    /// Set while the gateway types an auto-logon: browser input is refused meanwhile, so it
    /// cannot move the cursor between the script's steps.
    input_held: AtomicBool,
    /// The `closed` reason for the browser when the gateway itself ends the session (inactivity,
    /// lifetime, …); set before the host connection is dropped. Unset when the host ends it.
    closed_by_gateway: OnceLock<&'static str>,
    _slot: SessionSlot,
}

impl GatewaySession {
    pub(crate) fn new(
        id: SessionId,
        resume_token: &Secret,
        identity: SessionIdentity,
        profile: GatewayProfile,
        handle: SessionHandle,
        snapshot_rx: watch::Receiver<Snapshot>,
        slot: SessionSlot,
    ) -> Self {
        let (attach_tx, _) = watch::channel(0);
        Self {
            id,
            // Only the digest is kept: a heap dump of the gateway does not reveal resume tokens.
            resume_digest: Mutex::new(sha256(resume_token.expose().as_bytes())),
            identity,
            profile,
            created_at: SystemTime::now(),
            started: Instant::now(),
            handle,
            snapshot_rx,
            attach_tx,
            detached_since: Mutex::new(Some(Instant::now())),
            last_input: Mutex::new(Instant::now()),
            input_held: AtomicBool::new(false),
            closed_by_gateway: OnceLock::new(),
            _slot: slot,
        }
    }

    /// `true` while browser input is refused (an auto-logon is running).
    #[must_use]
    pub fn input_held(&self) -> bool {
        self.input_held.load(Ordering::Acquire)
    }

    pub(crate) fn hold_input(&self, held: bool) {
        self.input_held.store(held, Ordering::Release);
    }

    /// Session id.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// Owner identity.
    #[must_use]
    pub const fn identity(&self) -> &SessionIdentity {
        &self.identity
    }

    /// Profile the session was opened with.
    #[must_use]
    pub const fn profile(&self) -> &GatewayProfile {
        &self.profile
    }

    /// Creation time.
    #[must_use]
    pub const fn created_at(&self) -> SystemTime {
        self.created_at
    }

    /// Time since the session was opened.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.started.elapsed()
    }

    /// Time since the operator last typed or pressed a key in this session.
    #[must_use]
    pub fn idle_for(&self) -> Duration {
        self.last_input
            .lock()
            .map_or(Duration::ZERO, |t| t.elapsed())
    }

    /// Records operator input (resets the inactivity timeout).
    pub(crate) fn touch(&self) {
        if let Ok(mut t) = self.last_input.lock() {
            *t = Instant::now();
        }
    }

    /// Handle for sending input to the mainframe session.
    #[must_use]
    pub const fn handle(&self) -> &SessionHandle {
        &self.handle
    }

    /// Clone of the latest snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot_rx.borrow().clone()
    }

    /// New subscription to snapshot changes.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Snapshot> {
        self.snapshot_rx.clone()
    }

    /// `true` once the mainframe session has ended.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.snapshot_rx.borrow().state.is_terminal()
    }

    /// Exchanges a resume token for `next`: if `presented` is the current token (constant-time
    /// check) and `allowed`, `next` becomes the only valid token and `true` is returned. The
    /// check and the replacement happen under one lock, so a token resumes at most once even
    /// when two browsers present it at the same time.
    #[must_use]
    pub fn exchange_resume_token(&self, presented: &str, allowed: bool, next: &Secret) -> bool {
        let presented = sha256(presented.as_bytes());
        let Ok(mut digest) = self.resume_digest.lock() else {
            return false;
        };
        if !(constant_time_eq(&digest, &presented) && allowed) {
            return false;
        }
        *digest = sha256(next.expose().as_bytes());
        true
    }

    /// Attaches a browser. Returns its *generation* and a receiver that changes when another
    /// browser takes the session over (only one tab may drive a terminal at a time).
    pub(crate) fn attach(&self) -> (u64, watch::Receiver<u64>) {
        let mut generation = 0;
        self.attach_tx.send_modify(|g| {
            *g = g.wrapping_add(1);
            generation = *g;
        });
        if let Ok(mut d) = self.detached_since.lock() {
            *d = None;
        }
        (generation, self.attach_tx.subscribe())
    }

    /// Detaches the browser with the given generation (no-op if it was already replaced).
    pub(crate) fn detach(&self, generation: u64) {
        if *self.attach_tx.borrow() == generation {
            if let Ok(mut d) = self.detached_since.lock() {
                *d = Some(Instant::now());
            }
        }
    }

    /// `true` while a browser is attached.
    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.detached_since.lock().is_ok_and(|d| d.is_none())
    }

    /// How long the session has been without a browser (`None` while attached).
    #[must_use]
    pub fn detached_for(&self) -> Option<Duration> {
        self.detached_since
            .lock()
            .ok()
            .and_then(|d| d.map(|since| since.elapsed()))
    }

    /// Asks the mainframe session to disconnect. Attached browsers observe the terminal state.
    pub async fn terminate(&self) {
        let _ = self.handle.disconnect().await;
    }

    /// Ends the session for the gateway's own reason: an attached browser is told `reason` (a
    /// `closed` code) instead of `host_disconnected`. The first reason wins.
    pub(crate) async fn terminate_for(&self, reason: &'static str) {
        let _ = self.closed_by_gateway.set(reason);
        self.terminate().await;
    }

    /// The `closed` reason if the gateway ended the session ([`Self::terminate_for`]).
    #[must_use]
    pub fn closed_by_gateway(&self) -> Option<&'static str> {
        self.closed_by_gateway.get().copied()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn snapshot() -> Snapshot {
        Snapshot {
            seq: 0,
            view: SafeScreenView::empty(24, 80),
            state: SessionState::Negotiating,
            keyboard: KeyboardState::Unlocked,
            is_tls: false,
            is_tn3270e: false,
            lu: None,
            alarm_seq: 0,
            last_error: None,
            host_mode: HostMode::Negotiating,
            insert_mode: false,
            banner: None,
        }
    }

    #[test]
    fn test_nvt_banner_is_printable_bounded_and_cleared_by_3270_data() {
        let mut s = snapshot();
        assert!(s.apply(SessionEvent::NvtData(
            b"Welcome\r\n\x1b[1mHOST\x07  ready".to_vec()
        )));
        assert_eq!(s.banner.as_deref(), Some("Welcome [1mHOST ready"));
        assert!(!s.apply(SessionEvent::NvtData(b"\x00\x01".to_vec())));
        assert!(s.apply(SessionEvent::NvtData(vec![b'x'; 2000])));
        assert_eq!(s.banner.as_ref().map(String::len), Some(MAX_BANNER_CHARS));
        assert!(s.apply(SessionEvent::HostModeChanged(HostMode::Data3270)));
        assert_eq!(s.banner, None);
    }

    #[test]
    fn test_snapshot_apply_folds_events() {
        let mut s = snapshot();
        assert!(s.apply(SessionEvent::StateChanged(SessionState::Connected3270)));
        assert!(s.apply(SessionEvent::KeyboardStateChanged(KeyboardState::TimeWait)));
        assert!(s.apply(SessionEvent::Alarm));
        assert!(!s.apply(SessionEvent::Warning("w".into())));
        assert_eq!(s.seq, 3);
        assert_eq!(s.alarm_seq, 1);
        assert_eq!(s.keyboard, KeyboardState::TimeWait);
        assert!(s.apply(SessionEvent::Disconnected));
        assert_eq!(s.state, SessionState::Disconnected);
    }

    #[test]
    fn test_session_slots_enforce_limits_and_release_on_drop() {
        let counts = Arc::new(Mutex::new(SlotCounts::default()));
        let a1 = SessionSlot::try_reserve(&counts, "alice", 3, 2).unwrap();
        let a2 = SessionSlot::try_reserve(&counts, "alice", 3, 2).unwrap();
        assert!(SessionSlot::try_reserve(&counts, "alice", 3, 2).is_err());
        let b1 = SessionSlot::try_reserve(&counts, "bob", 3, 2).unwrap();
        assert!(SessionSlot::try_reserve(&counts, "carol", 3, 2).is_err());
        drop(a1);
        assert!(SessionSlot::try_reserve(&counts, "carol", 3, 2).is_ok());
        drop((a2, b1));
        let c = counts.lock().unwrap();
        assert_eq!(c.total, 0);
        assert!(c.per_subject.is_empty());
    }

    #[test]
    fn test_session_id_roundtrip() {
        let id = SessionId::random();
        assert_eq!(id.to_string().parse::<SessionId>().unwrap(), id);
        assert!("not-a-uuid".parse::<SessionId>().is_err());
    }
}
