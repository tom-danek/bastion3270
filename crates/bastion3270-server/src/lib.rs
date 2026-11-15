//! # bastion3270-server — zero-trust web gateway
//!
//! Runs the complete `bastion3270-core` 3270 state machine **on the server** and exposes it to a
//! thin HTML5 canvas client over WebSocket. The browser receives only a masked
//! [`SafeScreenView`](bastion3270_core::SafeScreenView) projection and sends only keystrokes.
//!
//! ## Library *and* binary
//! * `src/main.rs` — the `bastion3270-server` binary, ~100 lines.
//! * this library — everything else, so that a custom binary can depend on it
//!   and plug in its own [`AuthProvider`], [`AuditSink`], [`DlpPolicy`] and [`SessionStore`]
//!   (see [`extensions`]).
//!
//! ## Modules
//! - [`config`]: `bastion3270-server.toml` (LPAR whitelist, limits, auth).
//! - [`extensions`]: extension traits and their default implementations.
//! - [`gateway`]: server-side session lifecycle (open / resume / reap), limits, audit.
//! - [`protocol`]: JSON WebSocket protocol `bastion3270.v1`.
//! - [`http`]: routes, security headers, Kubernetes probes, WebSocket upgrade.

#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod config;
pub mod custom;
pub mod error;
pub mod extensions;
pub mod forwarded;
pub mod gateway;
pub mod http;
mod listener;
pub mod metrics;
pub mod protocol;
pub mod secret;
pub mod tls;
mod ws;

use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpListener;

pub use config::{GatewayProfile, KeyboardPreset, ServerConfig};
pub use error::{Result, ServerError};
pub use extensions::{
    AidAuditRecord, AuditSink, AuthError, AuthProvider, DlpContext, DlpDecision, DlpPolicy,
    Extensions, InMemorySessionStore, LogonStep, MainframeAutoLogon, NoAuthProvider, ProfileAccess,
    SessionAuditEvent, SessionAuditKind, SessionIdentity, SessionStore, StaticDlpPolicy,
    StaticTokenProvider, StdoutAuditSink,
};
pub use gateway::{Gateway, GatewaySession, SessionId};
pub use secret::Secret;

/// Concurrent connections of the metrics listener (one or two scrapers).
const METRICS_CONNECTIONS: usize = 16;

/// `GET /metrics` in the Prometheus text format.
fn metrics_router(gateway: Arc<Gateway>) -> axum::Router {
    use axum::http::header;
    use axum::response::IntoResponse;
    axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let gw = Arc::clone(&gateway);
            async move {
                let live = gw.session_states().await;
                let body = gw.metrics().render(live, env!("CARGO_PKG_VERSION"));
                (
                    [(
                        header::CONTENT_TYPE,
                        "text/plain; version=0.0.4; charset=utf-8",
                    )],
                    body,
                )
                    .into_response()
            }
        }),
    )
}

/// The assembled server: configuration + extensions.
#[derive(Debug)]
pub struct Server {
    gateway: Arc<Gateway>,
}

impl Server {
    /// Creates a server.
    #[must_use]
    pub fn new(config: ServerConfig, extensions: Extensions) -> Self {
        Self {
            gateway: Arc::new(Gateway::new(config, extensions)),
        }
    }

    /// The session manager, for a custom binary that needs it next to the server: e.g. an
    /// administration endpoint or an identity provider's logout notification calling
    /// [`Gateway::close_sessions_for`].
    #[must_use]
    pub fn gateway(&self) -> Arc<Gateway> {
        Arc::clone(&self.gateway)
    }

    /// Binds `config.server.bind` and serves until `shutdown` completes.
    ///
    /// # Errors
    /// Returns [`ServerError::Io`] if the socket cannot be bound or serving fails.
    pub async fn serve<F>(self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind(self.gateway.config().server.bind).await?;
        self.serve_with_listener(listener, shutdown).await
    }

    /// Serves on an already bound listener (tests bind `127.0.0.1:0`).
    ///
    /// Shutdown sequence (Kubernetes `SIGTERM`): `/readyz` turns 503 → all mainframe sessions
    /// are disconnected and audited → the HTTP server stops.
    ///
    /// # Errors
    /// Returns [`ServerError::Io`] if serving fails.
    pub async fn serve_with_listener<F>(self, listener: TcpListener, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let gateway = self.gateway;
        // Certificate problems stop the start here, before anything runs.
        let tls = match &gateway.config().server.tls {
            Some(cfg) => Some(tls::acceptor(cfg)?),
            None => None,
        };
        let trust = gateway.host_trust().map_err(ServerError::Config)?.summary();
        tracing::info!(
            target: "bastion3270::server",
            mozilla = trust.mozilla,
            system = trust.system,
            configured = trust.configured,
            "trusted CAs for host certificates"
        );
        let reaper = gateway.spawn_reaper();
        let state = http::AppState::new(Arc::clone(&gateway));
        let app = http::router(state.clone());

        tracing::info!(
            target: "bastion3270::server",
            addr = ?listener.local_addr().ok(),
            build = %gateway.extensions().build_label,
            auth = gateway.extensions().auth.name(),
            profiles = gateway.config().profiles.len(),
            "bastion3270-server listening"
        );
        for warning in gateway.config().warnings() {
            tracing::warn!(target: "bastion3270::server", "{warning}");
        }

        let drain = async move {
            shutdown.await;
            tracing::info!(target: "bastion3270::server", "shutdown requested; draining sessions");
            state.begin_shutdown();
            state.gateway().shutdown().await;
        };

        let limits = &gateway.config().limits;
        let (max_connections, header_timeout) = (
            limits.max_connections,
            std::time::Duration::from_secs(limits.header_read_timeout_secs),
        );
        // Prometheus metrics on their own listener, never on the browser-facing port.
        let metrics = match gateway.config().server.metrics_bind {
            Some(addr) => {
                let metrics_listener = TcpListener::bind(addr).await?;
                tracing::info!(target: "bastion3270::server", %addr, "metrics listening");
                Some(tokio::spawn(listener::serve(
                    metrics_listener,
                    metrics_router(Arc::clone(&gateway)),
                    METRICS_CONNECTIONS,
                    header_timeout,
                    None,
                    || {},
                    std::future::pending(),
                )))
            }
            None => None,
        };
        let on_limit = {
            let gw = Arc::clone(&gateway);
            move || gw.metrics().limit_rejections.inc("connections")
        };
        let result = listener::serve(
            listener,
            app,
            max_connections,
            header_timeout,
            tls,
            on_limit,
            drain,
        )
        .await;
        if let Some(task) = metrics {
            task.abort();
        }

        reaper.abort();
        result.map_err(ServerError::Io)
    }
}
