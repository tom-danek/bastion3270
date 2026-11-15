//! HTTP routes: static web client, REST helpers, Kubernetes probes and the WebSocket upgrade.
//!
//! | Route            | Purpose |
//! | :--------------- | :------ |
//! | `GET /`          | Thin HTML5 canvas client (embedded in the binary) |
//! | `GET /manifest.webmanifest` | Web application manifest: lets a browser install the client |
//! | `GET /healthz`   | Liveness probe (process is alive) |
//! | `GET /readyz`    | Readiness probe (not shutting down, below capacity) |
//! | `GET /api/config`| Build label and auth mode for the web client |
//! | `GET /api/profiles` | Profiles the caller may open (auth required) |
//! | `GET /ws`        | WebSocket upgrade (`bastion3270.v1`) |

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::config::PublicProfile;
use crate::extensions::auth::WS_PROTOCOL;
use crate::extensions::{AuthError, SessionAuditKind, SessionIdentity};
use crate::forwarded::{client_view, Cidr, ClientView};
use crate::gateway::Gateway;

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const KEYMAP_JS: &str = include_str!("../web/keymap.js");
const SCREEN_JS: &str = include_str!("../web/screen.js");
const I18N_JS: &str = include_str!("../web/i18n.js");
const STATUS_JS: &str = include_str!("../web/status.js");
const STYLE_CSS: &str = include_str!("../web/style.css");
const MANIFEST: &str = include_str!("../web/manifest.webmanifest");
const ICON_192: &[u8] = include_bytes!("../web/icon-192.png");
const ICON_512: &[u8] = include_bytes!("../web/icon-512.png");

/// Content Security Policy for the web client: no inline scripts, no third-party origins,
/// no framing (click-jacking), WebSocket only to the same origin. `manifest-src` lets the
/// browser read the web application manifest; its icons fall under `img-src`.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                   connect-src 'self'; img-src 'self' data:; manifest-src 'self'; \
                   base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Shared state of all handlers.
#[derive(Debug, Clone)]
pub struct AppState {
    gateway: Arc<Gateway>,
    shutting_down: Arc<AtomicBool>,
    trusted_proxies: Arc<[Cidr]>,
}

impl AppState {
    /// Wraps a gateway.
    #[must_use]
    pub fn new(gateway: Arc<Gateway>) -> Self {
        // Validated with the configuration; an entry that does not parse cannot occur here.
        let trusted_proxies = gateway
            .config()
            .server
            .trusted_proxies
            .iter()
            .filter_map(|c| c.parse().ok())
            .collect();
        Self {
            gateway,
            shutting_down: Arc::new(AtomicBool::new(false)),
            trusted_proxies,
        }
    }

    /// The browser's address and scheme for a request from `peer` (see [`client_view`]).
    #[must_use]
    pub fn client(&self, peer: Option<SocketAddr>, headers: &HeaderMap) -> ClientView {
        let tls = self.gateway.config().server.tls.is_some();
        client_view(peer, headers, &self.trusted_proxies, tls)
    }

    /// The gateway.
    #[must_use]
    pub const fn gateway(&self) -> &Arc<Gateway> {
        &self.gateway
    }

    /// Marks the server as draining: `/readyz` returns 503 so Kubernetes stops routing.
    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }
}

/// Builds the router. Public so a custom binary can `.merge()` extra routes onto it.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/keymap.js", get(keymap_js))
        .route("/screen.js", get(screen_js))
        .route("/i18n.js", get(i18n_js))
        .route("/status.js", get(status_js))
        .route("/style.css", get(style_css))
        .route("/manifest.webmanifest", get(manifest))
        .route("/icon-192.png", get(icon_192))
        .route("/icon-512.png", get(icon_512))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/api/config", get(api_config))
        .route("/api/profiles", get(api_profiles))
        .route("/ws", get(ws_upgrade))
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
}

async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // Isolation from other origins: no shared browsing context group with a page that opens
    // the client (window.opener), no embedding of our responses by other sites.
    h.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    res
}

/// Browser features the terminal never uses (copy and paste work through clipboard events,
/// which this policy does not affect).
const PERMISSIONS_POLICY: &str = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), \
     serial=(), hid=(), bluetooth=(), display-capture=(), clipboard-read=()";

fn asset(content_type: &'static str, body: impl IntoResponse) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

async fn index() -> Response {
    asset("text/html; charset=utf-8", INDEX_HTML)
}

async fn app_js() -> Response {
    asset("text/javascript; charset=utf-8", APP_JS)
}

async fn keymap_js() -> Response {
    asset("text/javascript; charset=utf-8", KEYMAP_JS)
}

async fn screen_js() -> Response {
    asset("text/javascript; charset=utf-8", SCREEN_JS)
}

async fn i18n_js() -> Response {
    asset("text/javascript; charset=utf-8", I18N_JS)
}

async fn status_js() -> Response {
    asset("text/javascript; charset=utf-8", STATUS_JS)
}

async fn style_css() -> Response {
    asset("text/css; charset=utf-8", STYLE_CSS)
}

async fn manifest() -> Response {
    asset("application/manifest+json", MANIFEST)
}

async fn icon_192() -> Response {
    asset("image/png", ICON_192)
}

async fn icon_512() -> Response {
    asset("image/png", ICON_512)
}

async fn healthz() -> Response {
    // Liveness only; unauthenticated, so no build or version.
    Json(json!({ "status": "ok" })).into_response()
}

async fn readyz(State(app): State<AppState>) -> Response {
    let gw = &app.gateway;
    let live = gw.live_sessions();
    let max = gw.config().limits.max_sessions;
    if app.shutting_down.load(Ordering::SeqCst) {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "draining" })),
        )
            .into_response()
    } else if live >= max {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "full" })),
        )
            .into_response()
    } else {
        // No session count: the probe is unauthenticated (gateway load is for metrics).
        Json(json!({ "status": "ready" })).into_response()
    }
}

async fn api_config(State(app): State<AppState>) -> Response {
    let ext = app.gateway.extensions();
    // Read before login: nothing that helps an attacker pick an exploit (no version or build;
    // those come with the authenticated profile list).
    Json(json!({
        "auth": ext.auth.name(),
        "auth_required": ext.auth.requires_credentials(),
        "protocol": WS_PROTOCOL,
        // How long a browser may try to resume after losing the connection.
        "resume_grace_secs": app.gateway.config().limits.detach_grace_secs,
        // Session tabs the web client offers in one page.
        "max_tabs": app.gateway.config().limits.max_tabs_per_page,
    }))
    .into_response()
}

/// Audits a verified credential (not the anonymous identity, which verifies nothing).
fn audit_success(gw: &Gateway, identity: &SessionIdentity, peer: Option<SocketAddr>) {
    if identity.authenticated {
        gw.audit(
            None,
            Some(identity),
            peer,
            SessionAuditKind::AuthSucceeded {
                provider: gw.extensions().auth.name().to_owned(),
            },
        );
    }
}

fn auth_error_response(err: &AuthError) -> Response {
    let status = match err {
        AuthError::MissingCredentials | AuthError::InvalidCredentials => StatusCode::UNAUTHORIZED,
        AuthError::Forbidden(_) => StatusCode::FORBIDDEN,
        AuthError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, Json(json!({ "error": err.public_message() }))).into_response()
}

async fn api_profiles(
    State(app): State<AppState>,
    Peer(peer): Peer,
    headers: HeaderMap,
) -> Response {
    let gw = &app.gateway;
    let peer = app.client(peer, &headers).addr;
    match gw.extensions().auth.authenticate(&headers).await {
        Ok(identity) => {
            audit_success(gw, &identity, peer);
            let list: Vec<PublicProfile> = gw
                .config()
                .profiles
                .iter()
                .filter(|p| identity.profiles.allows(&p.id))
                .map(PublicProfile::from)
                .collect();
            let ext = gw.extensions();
            Json(json!({
                "subject": identity.subject,
                "profiles": list,
                "build": ext.build_label,
                "version": env!("CARGO_PKG_VERSION"),
                // What a user may choose for a session (validated again on `open`).
                "choices": {
                    "codepages": bastion3270_core::CodePageId::ALL
                        .iter()
                        .map(|id| json!({ "name": id.name(), "label": id.label() }))
                        .collect::<Vec<_>>(),
                    "min_dynamic": crate::gateway::MIN_DYNAMIC,
                    "max_dynamic": crate::gateway::MAX_DYNAMIC,
                },
                // Connections users define themselves: offered at all, plain allowed,
                // restricted to an allow-list (the gateway checks every open anyway).
                "custom_connections": {
                    "enabled": gw.config().custom_connections.enabled
                        && identity.profiles.allows(crate::custom::CUSTOM_PROFILE_ID),
                    "allow_plain": gw.config().custom_connections.allow_plain,
                    "restricted": gw.config().custom_connections.allowed_targets.is_some(),
                },
            }))
            .into_response()
        }
        Err(err) => {
            gw.audit(
                None,
                None,
                peer,
                SessionAuditKind::AuthFailed {
                    reason: err.to_string(),
                },
            );
            auth_error_response(&err)
        }
    }
}

async fn ws_upgrade(
    State(app): State<AppState>,
    Peer(peer): Peer,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let gw = Arc::clone(&app.gateway);
    let client = app.client(peer, &headers);
    let peer = client.addr;

    if !origin_allowed(&headers, &gw.config().server.allowed_origins, client.scheme) {
        gw.audit(
            None,
            None,
            peer,
            SessionAuditKind::PolicyDenied {
                reason: "websocket origin not allowed".to_owned(),
            },
        );
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }

    let identity = match gw.extensions().auth.authenticate(&headers).await {
        Ok(identity) => {
            audit_success(&gw, &identity, peer);
            identity
        }
        Err(err) => {
            gw.audit(
                None,
                None,
                peer,
                SessionAuditKind::AuthFailed {
                    reason: err.to_string(),
                },
            );
            return auth_error_response(&err);
        }
    };

    // Bound the sockets that may sit in the handshake (up to its timeout) without a session.
    let Some(handshake) = gw.try_begin_handshake() else {
        gw.metrics().limit_rejections.inc("pending_handshakes");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many pending connections",
        )
            .into_response();
    };

    let max = gw.config().limits.max_ws_message_bytes;
    ws.protocols([WS_PROTOCOL])
        .max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| crate::ws::run(socket, gw, identity, peer, handshake))
}

/// Cross-Site WebSocket Hijacking protection.
///
/// * no `Origin` header → non-browser client → allowed (it must still authenticate);
/// * explicit allow-list configured → exact match required;
/// * otherwise → the `Origin` authority must equal the `Host` header (same origin), and when the
///   scheme the browser used is known (`scheme`), the `Origin` scheme must be that one too.
#[must_use]
pub fn origin_allowed(headers: &HeaderMap, allowed: &[String], scheme: Option<&str>) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    if !allowed.is_empty() {
        return allowed.iter().any(|a| a.eq_ignore_ascii_case(origin));
    }
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    origin
        .split_once("://")
        .is_some_and(|(origin_scheme, authority)| {
            authority.eq_ignore_ascii_case(host)
                && scheme.is_none_or(|s| origin_scheme.eq_ignore_ascii_case(s))
        })
}

/// Remote peer address, if the server was started with connect-info (absent in unit tests).
#[derive(Debug, Clone, Copy)]
pub struct Peer(pub Option<SocketAddr>);

impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl core::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        // Nothing to await: hand back an already-completed future.
        std::future::ready(Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ci.0),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(origin: Option<&'static str>, host: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static(host));
        if let Some(o) = origin {
            h.insert(header::ORIGIN, HeaderValue::from_static(o));
        }
        h
    }

    #[test]
    fn test_origin_policy() {
        assert!(origin_allowed(&headers(None, "gw:8080"), &[], None));
        assert!(origin_allowed(
            &headers(Some("http://gw:8080"), "gw:8080"),
            &[],
            None
        ));
        assert!(!origin_allowed(
            &headers(Some("https://evil.example"), "gw:8080"),
            &[],
            None
        ));
        let allow = vec!["https://tn3270.bank.example".to_owned()];
        assert!(origin_allowed(
            &headers(Some("https://tn3270.bank.example"), "gw:8080"),
            &allow,
            None
        ));
        assert!(!origin_allowed(
            &headers(Some("http://gw:8080"), "gw:8080"),
            &allow,
            None
        ));
        // Known browser scheme (trusted proxy or own TLS listener): it must match too.
        let h = headers(Some("http://gw:8080"), "gw:8080");
        assert!(
            !origin_allowed(&h, &[], Some("https")),
            "http page for an https gateway"
        );
        let h = headers(Some("https://gw:8080"), "gw:8080");
        assert!(origin_allowed(&h, &[], Some("https")));
    }
}
