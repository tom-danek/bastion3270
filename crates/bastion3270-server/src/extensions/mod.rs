//! # Extension points
//!
//! Every place where a deployment may need different behaviour is a *trait*, and this crate
//! ships a simple default implementation of each:
//!
//! | Trait             | Default implementation    |
//! | :---------------- | :------------------------ |
//! | [`AuthProvider`]  | [`NoAuthProvider`], [`StaticTokenProvider`] |
//! | [`AuditSink`]     | [`StdoutAuditSink`]       |
//! | [`DlpPolicy`]     | [`StaticDlpPolicy`]       |
//! | [`SessionStore`]  | [`InMemorySessionStore`]  |
//!
//! There is no conditional compilation: a custom binary depends on this crate and injects its
//! own implementations:
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use bastion3270_server::{Extensions, Server, ServerConfig, StdoutAuditSink};
//! # async fn demo(config: ServerConfig) -> bastion3270_server::Result<()> {
//! let extensions = Extensions::defaults(&config)
//!     .with_build_label("my-gateway")
//!     .with_audit(Arc::new(StdoutAuditSink)); // or your own `AuditSink`
//! Server::new(config, extensions).serve(std::future::pending()).await
//! # }
//! ```

pub mod audit;
pub mod auth;
pub mod dlp;
pub mod store;

use std::borrow::Cow;
use std::sync::Arc;

pub use audit::{
    masked_screen_digest, AidAuditRecord, AuditSink, SessionAuditEvent, SessionAuditKind,
    StdoutAuditSink,
};
pub use auth::{
    AuthError, AuthProvider, LogonStep, MainframeAutoLogon, NoAuthProvider, ProfileAccess,
    SessionIdentity, StaticTokenProvider,
};
pub use dlp::{DlpContext, DlpDecision, DlpPolicy, StaticDlpPolicy};
pub use store::{InMemorySessionStore, SessionStore};

use crate::config::{AuthMode, ServerConfig};

/// The set of plug-ins a server runs with.
///
/// `Arc<dyn Trait>` = *dynamic dispatch*: the concrete type is chosen at runtime (by the
/// binary that builds the server), at the cost of one pointer indirection per call — negligible
/// compared to a network round-trip to a mainframe. Generic parameters (`Server<A, S, D, T>`)
/// would avoid that indirection, but would leak four type parameters into every public type.
#[derive(Debug, Clone)]
pub struct Extensions {
    /// Build label exposed by `/api/config` and `/healthz` (default `"bastion3270-server"`).
    pub build_label: Cow<'static, str>,
    /// Authentication provider.
    pub auth: Arc<dyn AuthProvider>,
    /// Audit sink.
    pub audit: Arc<dyn AuditSink>,
    /// DLP policy.
    pub dlp: Arc<dyn DlpPolicy>,
    /// Session store.
    pub store: Arc<dyn SessionStore>,
}

impl Extensions {
    /// Default implementations derived from configuration (`auth.mode`).
    #[must_use]
    pub fn defaults(config: &ServerConfig) -> Self {
        let auth: Arc<dyn AuthProvider> = match config.auth.mode {
            AuthMode::None => Arc::new(NoAuthProvider),
            AuthMode::StaticToken => Arc::new(StaticTokenProvider::from_config(&config.auth)),
        };
        Self {
            build_label: Cow::Borrowed("bastion3270-server"),
            auth,
            audit: Arc::new(StdoutAuditSink),
            dlp: Arc::new(StaticDlpPolicy),
            store: Arc::new(InMemorySessionStore::new()),
        }
    }

    /// Replaces the build label.
    #[must_use]
    pub fn with_build_label(mut self, label: impl Into<Cow<'static, str>>) -> Self {
        self.build_label = label.into();
        self
    }

    /// Replaces the authentication provider.
    #[must_use]
    pub fn with_auth(mut self, auth: Arc<dyn AuthProvider>) -> Self {
        self.auth = auth;
        self
    }

    /// Replaces the audit sink.
    #[must_use]
    pub fn with_audit(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = audit;
        self
    }

    /// Replaces the DLP policy.
    #[must_use]
    pub fn with_dlp(mut self, dlp: Arc<dyn DlpPolicy>) -> Self {
        self.dlp = dlp;
        self
    }

    /// Replaces the session store.
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.store = store;
        self
    }
}
