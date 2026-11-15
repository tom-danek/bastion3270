//! Extension point **B — [`AuditSink`]**: who connected where, and which AID key was pressed on
//! which (masked) screen.
//!
//! Default implementation: [`StdoutAuditSink`] — structured `tracing` records on stdout
//! (`kubectl logs`).
//!
//! **Zero-Trust guarantee:** the sink only ever receives a [`SafeScreenView`], in which
//! `Non-display` fields (passwords) were already blanked by `bastion3270-core`. There is no API
//! through which a sink could obtain the raw presentation space.

use std::net::SocketAddr;
use std::time::SystemTime;

use bastion3270_core::{AidKey, SafeScreenView};
use sha2::{Digest, Sha256};

use crate::extensions::auth::encode_hex;
use crate::gateway::SessionId;

/// What happened to a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAuditKind {
    /// Authentication of an HTTP / WebSocket request failed.
    AuthFailed {
        /// Reason (never contains the presented credential).
        reason: String,
    },
    /// A request was refused by policy (profile not allowed, limits, DLP).
    PolicyDenied {
        /// Reason.
        reason: String,
    },
    /// A new mainframe session was opened.
    Opened,
    /// A browser re-attached to an existing session (F5 / reconnect).
    Resumed,
    /// The browser detached; the session waits for the grace period.
    Detached,
    /// A server-side auto-logon script was executed.
    AutoLogon {
        /// Audit-safe description from [`MainframeAutoLogon`](crate::MainframeAutoLogon).
        description: String,
        /// `true` if all steps completed.
        success: bool,
    },
    /// The session ended.
    Closed {
        /// Reason (`user`, `host`, `expired`, `terminated`, error text …).
        reason: String,
    },
    /// A credential was verified (only for authenticated identities).
    AuthSucceeded {
        /// The [`AuthProvider`](crate::AuthProvider) that verified it.
        provider: String,
    },
    /// The connection to the mainframe could not be established (TCP, TLS, negotiation).
    ConnectFailed {
        /// Full error, for the server-side record only.
        reason: String,
    },
    /// Failure records of one kind from one source that were not written because the source
    /// exceeded the per-minute cap (a flood); the count of the ones left out.
    AuditSuppressed {
        /// The event name that was suppressed (e.g. `auth_failed`).
        event: String,
        /// How many records were left out.
        count: u32,
    },
    /// The user printed the screen (or saved it as PDF) from the browser.
    ScreenPrinted {
        /// SHA-256 (hex) of the masked screen that was printed (as in the AID record).
        screen_sha256: String,
    },
    /// The browser sent messages that were refused (malformed, unknown key names, out of
    /// range). One record per connection, so a flood cannot flood the audit trail.
    MessagesRejected {
        /// Why the first one was refused (a fixed text, never the message content).
        first: String,
        /// How many were refused on this connection.
        count: u32,
    },
}

impl SessionAuditKind {
    /// Stable event name for log fields and SIEM rules.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::AuthFailed { .. } => "auth_failed",
            Self::PolicyDenied { .. } => "policy_denied",
            Self::Opened => "opened",
            Self::Resumed => "resumed",
            Self::Detached => "detached",
            Self::AutoLogon { .. } => "auto_logon",
            Self::Closed { .. } => "closed",
            Self::AuthSucceeded { .. } => "auth_succeeded",
            Self::ConnectFailed { .. } => "connect_failed",
            Self::MessagesRejected { .. } => "messages_rejected",
            Self::AuditSuppressed { .. } => "audit_suppressed",
            Self::ScreenPrinted { .. } => "screen_printed",
        }
    }

    /// `true` for the failures an unauthenticated caller can provoke at will; those are capped
    /// per source in the audit trail.
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(
            self,
            Self::AuthFailed { .. }
                | Self::PolicyDenied { .. }
                | Self::ConnectFailed { .. }
                | Self::MessagesRejected { .. }
        )
    }

    /// The free-text part of the event, if it has one.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::AuthFailed { reason }
            | Self::PolicyDenied { reason }
            | Self::Closed { reason }
            | Self::ConnectFailed { reason } => Some(reason),
            Self::AutoLogon { description, .. } => Some(description),
            Self::AuthSucceeded { provider } => Some(provider),
            Self::MessagesRejected { first, .. } => Some(first),
            Self::AuditSuppressed { event, .. } => Some(event),
            Self::ScreenPrinted { screen_sha256 } => Some(screen_sha256),
            Self::Opened | Self::Resumed | Self::Detached => None,
        }
    }
}

/// Session lifecycle audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuditEvent {
    /// Wall-clock time of the event.
    pub at: SystemTime,
    /// Session, if one exists yet.
    pub session_id: Option<SessionId>,
    /// Identity subject, if known.
    pub subject: Option<String>,
    /// Profile id, if known.
    pub profile_id: Option<String>,
    /// Remote peer address of the HTTP connection.
    pub peer: Option<SocketAddr>,
    /// Event kind.
    pub kind: SessionAuditKind,
}

/// Record of one AID transmission (`Enter`, `PF3`, …).
#[derive(Debug, Clone, Copy)]
pub struct AidAuditRecord<'a> {
    /// Wall-clock time.
    pub at: SystemTime,
    /// Session id.
    pub session_id: SessionId,
    /// Identity subject.
    pub subject: &'a str,
    /// Profile id.
    pub profile_id: &'a str,
    /// AID key pressed.
    pub aid: AidKey,
    /// Masked screen at the moment of the AID (what the user saw and submitted).
    pub screen: &'a SafeScreenView,
    /// [`masked_screen_digest`] of `screen` — lets a SIEM correlate screens without storing them.
    pub screen_sha256: [u8; 32],
}

/// Extension trait receiving audit records.
///
/// Methods are **synchronous and must not block**: they run on the hot path of a WebSocket
/// task. A network-backed sink (SIEM) should push into its own bounded channel and ship
/// records from a background task.
pub trait AuditSink: Send + Sync + core::fmt::Debug + 'static {
    /// Session lifecycle event.
    fn on_session_event(&self, event: &SessionAuditEvent);

    /// AID key submitted to the host.
    fn on_aid_submitted(&self, record: &AidAuditRecord<'_>);
}

/// Default sink: one structured `tracing` record per event on target `bastion3270::audit`.
///
/// AID records contain only the screen digest, never screen content.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdoutAuditSink;

impl AuditSink for StdoutAuditSink {
    fn on_session_event(&self, e: &SessionAuditEvent) {
        let session = e.session_id.map(|id| id.to_string());
        let peer = e.peer.map(|p| p.to_string());
        // One field per item (not a Debug dump), so a log pipeline can index and alert on
        // them; text values are escaped by the formatter (no line injection).
        let (success, count) = match &e.kind {
            SessionAuditKind::AutoLogon { success, .. } => (Some(*success), None),
            SessionAuditKind::MessagesRejected { count, .. }
            | SessionAuditKind::AuditSuppressed { count, .. } => (None, Some(*count)),
            _ => (None, None),
        };
        tracing::info!(
            target: "bastion3270::audit",
            event = e.kind.name(),
            reason = e.kind.reason().unwrap_or("-"),
            success,
            count,
            session = session.as_deref().unwrap_or("-"),
            subject = e.subject.as_deref().unwrap_or("-"),
            profile = e.profile_id.as_deref().unwrap_or("-"),
            peer = peer.as_deref().unwrap_or("-"),
            "session event"
        );
    }

    fn on_aid_submitted(&self, r: &AidAuditRecord<'_>) {
        tracing::info!(
            target: "bastion3270::audit",
            session = %r.session_id,
            subject = r.subject,
            profile = r.profile_id,
            aid = %r.aid,
            screen_sha256 = %encode_hex(&r.screen_sha256),
            "aid submitted"
        );
    }
}

/// SHA-256 over the *masked* screen (dimensions, cursor and visible characters).
///
/// Hidden fields are already blanks in a [`SafeScreenView`], therefore two screens that differ
/// only in a typed password produce the **same** digest — the digest cannot be used to brute
/// force a password.
#[must_use]
pub fn masked_screen_digest(view: &SafeScreenView) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(view.rows().to_be_bytes());
    h.update(view.cols().to_be_bytes());
    h.update(view.cursor_row().to_be_bytes());
    h.update(view.cursor_col().to_be_bytes());
    let mut buf = [0u8; 4];
    for cell in view.cells() {
        h.update(cell.ch.encode_utf8(&mut buf).as_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use bastion3270_core::SafeCell;

    #[test]
    fn test_digest_depends_on_visible_content_only() {
        let a = SafeScreenView::empty(2, 4);
        let mut cells = vec![SafeCell::BLANK; 8];
        cells[0].ch = 'X';
        let b = SafeScreenView::new(2, 4, 0, 0, false, cells).unwrap();
        assert_ne!(masked_screen_digest(&a), masked_screen_digest(&b));
        assert_eq!(masked_screen_digest(&a), masked_screen_digest(&a.clone()));
    }

    /// Log fields are a stable name plus the free text, not a Debug dump of the kind.
    #[test]
    fn test_event_names_and_reasons_for_log_fields() {
        let rejected = super::SessionAuditKind::MessagesRejected {
            first: "malformed message".into(),
            count: 3,
        };
        assert_eq!(rejected.name(), "messages_rejected");
        assert_eq!(rejected.reason(), Some("malformed message"));
        assert_eq!(super::SessionAuditKind::Opened.name(), "opened");
        assert_eq!(super::SessionAuditKind::Opened.reason(), None);
        let failed = super::SessionAuditKind::ConnectFailed {
            reason: "tls".into(),
        };
        assert_eq!(
            (failed.name(), failed.reason()),
            ("connect_failed", Some("tls"))
        );
    }
}
