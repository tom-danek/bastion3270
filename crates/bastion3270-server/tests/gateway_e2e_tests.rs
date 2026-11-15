//! Hermetic end-to-end tests: WebSocket client → `bastion3270-server` → TN3270E → mock mainframe.
//!
//! The custom `AuditSink`, `DlpPolicy` and `AuthProvider` used here are exactly how a custom
//! binary plugs its own implementations into the gateway — these tests prove the seam works.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::http::HeaderMap;
use bastion3270_core::{AidKey, SafeScreenView};
use bastion3270_server::extensions::masked_screen_digest;
use bastion3270_server::{
    AidAuditRecord, AuditSink, AuthError, AuthProvider, DlpContext, DlpDecision, DlpPolicy,
    Extensions, GatewayProfile, LogonStep, MainframeAutoLogon, Secret, Server, ServerConfig,
    SessionAuditEvent, SessionAuditKind, SessionIdentity,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

mod common;

use common::gateway::start;
use common::mock_host::{host_receives, spawn_mock_host};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

const T: Duration = Duration::from_secs(5);

/// EBCDIC "SECRET".
const SECRET_EBCDIC: [u8; 6] = [0xE2, 0xC5, 0xC3, 0xD9, 0xC5, 0xE3];
/// EBCDIC "HERC01".
const HERC01_EBCDIC: [u8; 6] = [0xC8, 0xC5, 0xD9, 0xC3, 0xF0, 0xF1];

// ─── Gateway helpers ────────────────────────────────────────────────────────────────

fn config(host_port: u16, extra: &str) -> ServerConfig {
    ServerConfig::from_toml_str(&format!(
        r#"
        {extra}

        [[profiles]]
        id = "hercules"
        name = "Mock Hercules"
        [profiles.connection]
        tls_mode = "disabled"
        host = "127.0.0.1"
        port = {host_port}
        terminal_model = "Model2"
        idle_timeout_ms = 600000

        [[profiles]]
        id = "nopaste"
        name = "No paste"
        allow_paste = false
        allow_copy = false
        [profiles.connection]
        tls_mode = "disabled"
        host = "127.0.0.1"
        port = {host_port}
        terminal_model = "Model2"
        idle_timeout_ms = 600000
        "#
    ))
    .unwrap()
}

async fn ws_connect(addr: SocketAddr, protocols: &str) -> Result<Ws, String> {
    let mut req = format!("ws://{addr}/ws").into_client_request().unwrap();
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_str(protocols).unwrap(),
    );
    tokio_tungstenite::connect_async(req)
        .await
        .map(|(ws, _)| ws)
        .map_err(|e| e.to_string())
}

async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::Text(v.to_string().into())).await.unwrap();
}

async fn recv(ws: &mut Ws) -> Value {
    tokio::time::timeout(T, async {
        loop {
            match ws.next().await.expect("socket closed").expect("ws error") {
                Message::Text(t) => return serde_json::from_str(t.as_str()).unwrap(),
                Message::Close(_) => return json!({"type": "__close__"}),
                _ => {}
            }
        }
    })
    .await
    .expect("timed out waiting for server message")
}

/// Receives messages until `pred` matches; returns the match. Collects every screen text seen.
async fn recv_until(ws: &mut Ws, seen: &mut Vec<String>, pred: impl Fn(&Value) -> bool) -> Value {
    loop {
        let m = recv(ws).await;
        if let Some(rows) = m["screen"]["text"].as_array() {
            seen.extend(rows.iter().map(|r| r.as_str().unwrap().to_owned()));
        }
        if pred(&m) {
            return m;
        }
        assert_ne!(m["type"], "__close__", "socket closed while waiting");
    }
}

fn row0(frame: &Value) -> String {
    frame["screen"]["text"][0]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// Opens a session and waits for the first frame showing the logon screen.
async fn open(addr: SocketAddr, profile: &str) -> (Ws, String, String) {
    let mut ws = ws_connect(addr, "bastion3270.v1").await.unwrap();
    send(&mut ws, json!({"type": "open", "profile": profile})).await;
    let s = recv(&mut ws).await;
    assert_eq!(s["type"], "session", "unexpected: {s}");
    let id = s["session_id"].as_str().unwrap().to_owned();
    let token = s["resume_token"].as_str().unwrap().to_owned();
    let mut seen = Vec::new();
    recv_until(&mut ws, &mut seen, |m| row0(m).contains("PASS:")).await;
    (ws, id, token)
}

// ─── Custom plug-ins used by the tests ───────────────────────────────────────────

/// One AID record as seen by the audit sink.
#[derive(Debug, Clone)]
struct SeenAid {
    aid: AidKey,
    screen_text: String,
    digest: [u8; 32],
    recomputed: [u8; 32],
}

#[derive(Debug, Default)]
struct RecordingAudit {
    events: Mutex<Vec<SessionAuditKind>>,
    aids: Mutex<Vec<SeenAid>>,
}

impl AuditSink for RecordingAudit {
    fn on_session_event(&self, event: &SessionAuditEvent) {
        self.events.lock().unwrap().push(event.kind.clone());
    }
    fn on_aid_submitted(&self, r: &AidAuditRecord<'_>) {
        self.aids.lock().unwrap().push(SeenAid {
            aid: r.aid,
            screen_text: r.screen.to_plain_text(),
            digest: r.screen_sha256,
            recomputed: masked_screen_digest(r.screen),
        });
    }
}

#[derive(Debug)]
struct DenyCardNumbers;

impl DlpPolicy for DenyCardNumbers {
    fn check_paste(&self, _ctx: &DlpContext<'_>, text: &str) -> DlpDecision {
        if text.chars().filter(char::is_ascii_digit).count() >= 13 {
            DlpDecision::Deny {
                reason: "looks like a card number".into(),
            }
        } else {
            DlpDecision::Allow
        }
    }
    fn copy_allowed(&self, _ctx: &DlpContext<'_>, _screen: &SafeScreenView) -> bool {
        true
    }
}

#[derive(Debug)]
struct PassTicketLikeAuth;

#[async_trait]
impl AuthProvider for PassTicketLikeAuth {
    fn name(&self) -> &'static str {
        "test-sso"
    }
    fn requires_credentials(&self) -> bool {
        false
    }
    async fn authenticate(&self, _headers: &HeaderMap) -> Result<SessionIdentity, AuthError> {
        let mut id = SessionIdentity::anonymous();
        id.subject = "alice@bank.example".into();
        id.authenticated = true;
        Ok(id)
    }
    async fn resolve_mainframe_credentials(
        &self,
        _identity: &SessionIdentity,
        _profile: &GatewayProfile,
    ) -> Result<Option<MainframeAutoLogon>, AuthError> {
        Ok(Some(MainframeAutoLogon {
            description: "test PassTicket for HERC01".into(),
            steps: vec![
                LogonStep::Text(Secret::new("HERC01")),
                LogonStep::Aid(AidKey::Enter),
            ],
        }))
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_e2e_password_never_reaches_browser_or_audit_but_reaches_host() {
    let (port, mut host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(config(port, ""), |e| e.with_audit(audit_dyn)).await;

    let (mut ws, _, _) = open(srv.addr, "hercules").await;
    let mut seen = Vec::new();
    for ch in "SECRET".chars() {
        send(&mut ws, json!({"type": "key", "ch": ch.to_string()})).await;
    }
    // Cursor advances 8 → 14 while typing; wait for that frame.
    recv_until(&mut ws, &mut seen, |m| {
        m["screen"]["cursor"] == json!([0, 14])
    })
    .await;
    send(&mut ws, json!({"type": "aid", "aid": "enter"})).await;
    let locked = recv_until(&mut ws, &mut seen, |m| m["status"]["keyboard"] == "X Wait").await;
    assert_eq!(locked["status"]["tn3270e"], true);
    assert_eq!(locked["status"]["lu"], "LUTEST01");

    // 1. The browser never saw the password.
    assert!(
        seen.iter().all(|row| !row.contains("SECRET")),
        "password leaked to browser"
    );
    // 2. The mainframe received it (EBCDIC) with AID Enter (0x7D) after the 5-byte header.
    let rec = host_receives(&mut host_rx, &SECRET_EBCDIC).await;
    assert_eq!(rec[5], 0x7D);
    // 3. The audit sink got the AID with a masked screen and a correct digest.
    let aids = audit.aids.lock().unwrap().clone();
    assert_eq!(aids.len(), 1);
    let seen = &aids[0];
    assert_eq!(seen.aid, AidKey::Enter);
    assert!(seen.screen_text.contains("PASS:") && !seen.screen_text.contains("SECRET"));
    assert_eq!(seen.digest, seen.recomputed);
    assert!(audit
        .events
        .lock()
        .unwrap()
        .contains(&SessionAuditKind::Opened));
}

#[tokio::test]
async fn test_e2e_protected_field_write_is_blocked_server_side() {
    let (port, _host_rx) = spawn_mock_host().await;
    let srv = start(config(port, ""), |e| e).await;
    let (mut ws, _, _) = open(srv.addr, "hercules").await;
    let mut seen = Vec::new();

    send(&mut ws, json!({"type": "move_cursor", "row": 0, "col": 2})).await;
    recv_until(&mut ws, &mut seen, |m| {
        m["screen"]["cursor"] == json!([0, 2])
    })
    .await;
    send(&mut ws, json!({"type": "key", "ch": "X"})).await;
    let f = recv_until(&mut ws, &mut seen, |m| {
        m["status"]["keyboard"] == "X PROTECTED"
    })
    .await;
    assert_eq!(f["status"]["locked"], true);
    assert!(
        seen.iter().all(|r| !r.contains('X')),
        "protected field was modified"
    );

    // Out-of-range cursor and unknown names are rejected without touching the session.
    send(
        &mut ws,
        json!({"type": "move_cursor", "row": 999, "col": 0}),
    )
    .await;
    assert_eq!(recv(&mut ws).await["code"], "bad_request");
    send(&mut ws, json!({"type": "aid", "aid": "pf99"})).await;
    assert_eq!(recv(&mut ws).await["code"], "bad_request");
    send(&mut ws, json!({"type": "key", "ch": "\u{0007}"})).await;
    assert_eq!(recv(&mut ws).await["code"], "bad_request");
}

#[tokio::test]
async fn test_e2e_resume_after_reconnect_and_takeover() {
    let (port, _host_rx) = spawn_mock_host().await;
    let srv = start(config(port, ""), |e| e).await;
    let (mut ws1, id, token) = open(srv.addr, "hercules").await;
    let mut seen = Vec::new();

    send(&mut ws1, json!({"type": "key", "ch": "A"})).await;
    recv_until(&mut ws1, &mut seen, |m| {
        m["screen"]["cursor"] == json!([0, 9])
    })
    .await;
    ws1.close(None).await.unwrap();
    drop(ws1);

    // Wrong token → indistinguishable "not found".
    let mut bad = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(
        &mut bad,
        json!({"type": "resume", "session_id": id, "token": "0".repeat(64)}),
    )
    .await;
    assert_eq!(recv(&mut bad).await["code"], "session_not_found");

    // Correct token → same session, cursor still where we left it, and a new token.
    let mut ws2 = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(
        &mut ws2,
        json!({"type": "resume", "session_id": id, "token": token}),
    )
    .await;
    let s = recv(&mut ws2).await;
    assert_eq!(s["type"], "session");
    assert_eq!(s["session_id"], id.as_str());
    let token2 = s["resume_token"].as_str().unwrap().to_owned();
    assert_ne!(token2, token, "every resume issues a new token");
    let f = recv_until(&mut ws2, &mut seen, |m| m["type"] == "frame").await;
    assert_eq!(f["screen"]["cursor"], json!([0, 9]));
    assert_eq!(f["alarm"], false);

    // The used token resumes no more (a leaked copy is worthless after the owner's resume).
    let mut stale = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(
        &mut stale,
        json!({"type": "resume", "session_id": id, "token": token}),
    )
    .await;
    assert_eq!(recv(&mut stale).await["code"], "session_not_found");

    // A second tab with the current token takes over; the first one is told so.
    let mut ws3 = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(
        &mut ws3,
        json!({"type": "resume", "session_id": id, "token": token2}),
    )
    .await;
    let s = recv(&mut ws3).await;
    assert_eq!(s["type"], "session");
    let token3 = s["resume_token"].as_str().unwrap().to_owned();
    let closed = recv_until(&mut ws2, &mut seen, |m| m["type"] == "closed").await;
    assert_eq!(closed["reason"], "taken_over");

    // Explicit disconnect ends the session for good.
    send(&mut ws3, json!({"type": "disconnect"})).await;
    let closed = recv_until(&mut ws3, &mut seen, |m| m["type"] == "closed").await;
    assert_eq!(closed["reason"], "user");
    let mut ws4 = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(
        &mut ws4,
        json!({"type": "resume", "session_id": id, "token": token3}),
    )
    .await;
    assert_eq!(recv(&mut ws4).await["code"], "session_not_found");
}

#[tokio::test]
async fn test_e2e_whitelist_and_protocol_validation() {
    let (port, _host_rx) = spawn_mock_host().await;
    let srv = start(config(port, ""), |e| e).await;

    let mut ws = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(&mut ws, json!({"type": "open", "profile": "prod-lpar"})).await;
    assert_eq!(recv(&mut ws).await["code"], "unknown_profile");

    // SSRF attempt: extra host/port fields are rejected by `deny_unknown_fields`.
    let mut ws = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(
        &mut ws,
        json!({"type": "open", "profile": "hercules", "host": "10.0.0.1", "port": 22}),
    )
    .await;
    assert_eq!(recv(&mut ws).await["code"], "bad_request");

    let mut ws = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(&mut ws, json!({"type": "key", "ch": "A"})).await;
    assert_eq!(recv(&mut ws).await["code"], "bad_request");

    // Cross-site WebSocket hijacking: foreign Origin is refused at the HTTP upgrade.
    let mut req = format!("ws://{}/ws", srv.addr)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Origin", HeaderValue::from_static("https://evil.example"));
    let err = tokio_tungstenite::connect_async(req).await.unwrap_err();
    assert!(err.to_string().contains("403"), "{err}");
}

#[tokio::test]
async fn test_e2e_static_token_auth() {
    let (port, _host_rx) = spawn_mock_host().await;
    let hash = bastion3270_server::extensions::auth::encode_hex(
        &bastion3270_server::extensions::auth::sha256(b"lab-token-1"),
    );
    let extra = format!(
        "[auth]\nmode = \"static-token\"\n[[auth.tokens]]\nsubject = \"sysprog\"\nsha256 = \"{hash}\"\nprofiles = [\"hercules\"]"
    );
    let srv = start(config(port, &extra), |e| e).await;

    let err = ws_connect(srv.addr, "bastion3270.v1").await.unwrap_err();
    assert!(err.contains("401"), "{err}");
    let err = ws_connect(srv.addr, "bastion3270.v1, bastion3270.bearer.wrong")
        .await
        .unwrap_err();
    assert!(err.contains("401"), "{err}");

    // Valid token, but the token is limited to "hercules".
    let mut ws = ws_connect(srv.addr, "bastion3270.v1, bastion3270.bearer.lab-token-1")
        .await
        .unwrap();
    send(&mut ws, json!({"type": "open", "profile": "nopaste"})).await;
    assert_eq!(recv(&mut ws).await["code"], "forbidden");

    let mut ws = ws_connect(srv.addr, "bastion3270.v1, bastion3270.bearer.lab-token-1")
        .await
        .unwrap();
    send(&mut ws, json!({"type": "open", "profile": "hercules"})).await;
    assert_eq!(recv(&mut ws).await["type"], "session");
}

#[tokio::test]
async fn test_e2e_limits_per_identity_and_release() {
    let (port, _host_rx) = spawn_mock_host().await;
    let hash = bastion3270_server::extensions::auth::encode_hex(
        &bastion3270_server::extensions::auth::sha256(b"lab-token-1"),
    );
    let srv = start(
        config(
            port,
            &format!(
                "[limits]\nmax_sessions_per_identity = 1\n[auth]\nmode = \"static-token\"\n\
                 [[auth.tokens]]\nsubject = \"sysprog\"\nsha256 = \"{hash}\""
            ),
        ),
        |e| e,
    )
    .await;
    let protocols = "bastion3270.v1, bastion3270.bearer.lab-token-1";

    let mut ws1 = ws_connect(srv.addr, protocols).await.unwrap();
    send(&mut ws1, json!({"type": "open", "profile": "hercules"})).await;
    assert_eq!(recv(&mut ws1).await["type"], "session");
    let mut ws2 = ws_connect(srv.addr, protocols).await.unwrap();
    send(&mut ws2, json!({"type": "open", "profile": "hercules"})).await;
    assert_eq!(recv(&mut ws2).await["code"], "limit_exceeded");

    send(&mut ws1, json!({"type": "disconnect"})).await;
    let mut seen = Vec::new();
    recv_until(&mut ws1, &mut seen, |m| m["type"] == "closed").await;

    // The RAII slot was released → a new session can be opened.
    let mut ws3 = ws_connect(srv.addr, protocols).await.unwrap();
    send(&mut ws3, json!({"type": "open", "profile": "hercules"})).await;
    assert_eq!(recv(&mut ws3).await["type"], "session");
}

/// Without authentication every user shares the anonymous identity, so a per-identity limit
/// would let one user lock out everyone. Anonymous sessions are bounded by `max_sessions`.
#[tokio::test]
async fn test_e2e_anonymous_sessions_are_bounded_by_the_gateway_limit_only() {
    let (port, _host_rx) = spawn_mock_host().await;
    let srv = start(
        config(
            port,
            "[limits]\nmax_sessions = 2\nmax_sessions_per_identity = 1",
        ),
        |e| e,
    )
    .await;

    let (_ws1, _, _) = open(srv.addr, "hercules").await;
    let (_ws2, _, _) = open(srv.addr, "hercules").await;
    let mut ws3 = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(&mut ws3, json!({"type": "open", "profile": "hercules"})).await;
    let reply = recv(&mut ws3).await;
    assert_eq!(reply["code"], "limit_exceeded");
    assert!(
        reply["message"]
            .as_str()
            .unwrap_or_default()
            .contains("capacity"),
        "the gateway limit, not the identity limit: {reply}"
    );
}

#[tokio::test]
async fn test_e2e_dlp_paste_policies() {
    let (port, mut host_rx) = spawn_mock_host().await;
    let srv = start(config(port, "[limits]\nmax_paste_chars = 32"), |e| {
        e.with_dlp(Arc::new(DenyCardNumbers))
    })
    .await;

    let (mut ws, _, _) = open(srv.addr, "hercules").await;
    send(
        &mut ws,
        json!({"type": "text", "text": "4111 1111 1111 1111"}),
    )
    .await;
    let e = recv(&mut ws).await;
    assert_eq!(e["code"], "dlp_denied");
    send(&mut ws, json!({"type": "text", "text": "x".repeat(33)})).await;
    assert_eq!(recv(&mut ws).await["code"], "paste_too_long");

    send(&mut ws, json!({"type": "text", "text": "SECRET"})).await;
    let mut seen = Vec::new();
    recv_until(&mut ws, &mut seen, |m| {
        m["screen"]["cursor"] == json!([0, 14])
    })
    .await;
    send(&mut ws, json!({"type": "aid", "aid": "enter"})).await;
    host_receives(&mut host_rx, &SECRET_EBCDIC).await;
}

#[tokio::test]
async fn test_e2e_static_dlp_copy_flag_and_paste_switch() {
    let (port, _host_rx) = spawn_mock_host().await;
    let srv = start(config(port, ""), |e| e).await;
    let mut ws = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(&mut ws, json!({"type": "open", "profile": "nopaste"})).await;
    assert_eq!(recv(&mut ws).await["type"], "session");
    let mut seen = Vec::new();
    let f = recv_until(&mut ws, &mut seen, |m| row0(m).contains("PASS:")).await;
    assert_eq!(f["screen"]["copy_allowed"], false);
    send(&mut ws, json!({"type": "text", "text": "abc"})).await;
    assert_eq!(recv(&mut ws).await["code"], "dlp_denied");
}

#[tokio::test]
async fn test_e2e_server_side_autologon_from_auth_provider() {
    let (port, mut host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(config(port, ""), |e| {
        e.with_auth(Arc::new(PassTicketLikeAuth))
            .with_audit(audit_dyn)
    })
    .await;

    let mut ws = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(&mut ws, json!({"type": "open", "profile": "hercules"})).await;
    assert_eq!(recv(&mut ws).await["type"], "session");

    // The gateway typed the credential itself; the browser sent nothing.
    let rec = host_receives(&mut host_rx, &HERC01_EBCDIC).await;
    assert_eq!(rec[5], 0x7D);
    let mut seen = Vec::new();
    recv_until(&mut ws, &mut seen, |m| m["status"]["keyboard"] == "X Wait").await;
    assert!(seen.iter().all(|r| !r.contains("HERC01")));

    tokio::time::timeout(T, async {
        loop {
            let ok = audit.events.lock().unwrap().iter().any(|k| {
                matches!(k, SessionAuditKind::AutoLogon { success: true, description } if description.contains("HERC01"))
            });
            if ok {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("auto-logon audit event");
}

#[tokio::test]
async fn test_e2e_graceful_shutdown_closes_sessions() {
    let (port, _host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let mut srv = start(config(port, ""), |e| e.with_audit(audit_dyn)).await;
    let (mut ws, _, _) = open(srv.addr, "hercules").await;

    srv.shutdown.take().unwrap().send(()).unwrap();
    let mut seen = Vec::new();
    let closed = recv_until(&mut ws, &mut seen, |m| m["type"] == "closed").await;
    // The gateway, not the host, ended the session: the browser may reconnect.
    assert_eq!(closed["reason"], "server_shutdown");
    drop(ws);
    tokio::time::timeout(T, srv.join)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(audit
        .events
        .lock()
        .unwrap()
        .contains(&SessionAuditKind::Closed {
            reason: "server shutdown".into()
        }));
}

/// A pod being replaced: SIGTERM → `serve` returns → `main` returns and the runtime is dropped,
/// which cancels every task still running. Every attached browser must have been told before
/// that (`closed` / `server_shutdown`), so the gateway runs in its own runtime here, dropped
/// as soon as `serve` returns, like the binary's. New sessions are refused while draining.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_e2e_shutdown_tells_every_browser_before_the_process_ends() {
    const SESSIONS: usize = 30;
    let (port, _host_rx) = spawn_mock_host().await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let server = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            listener.set_nonblocking(true).unwrap();
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let cfg = config(port, "[limits]\nmax_sessions = 64");
            let ext = Extensions::defaults(&cfg);
            Server::new(cfg, ext)
                .serve_with_listener(listener, async move {
                    let _ = tokio::task::spawn_blocking(move || stop_rx.recv()).await;
                })
                .await
                .unwrap();
        });
        // `runtime` is dropped here: whatever was not sent by now is lost, as in `main`.
    });

    let mut sockets = Vec::new();
    for _ in 0..SESSIONS {
        sockets.push(open(addr, "hercules").await.0);
    }
    stop_tx.send(()).unwrap();
    tokio::task::spawn_blocking(move || server.join().unwrap())
        .await
        .unwrap();

    // The process is gone; only what it sent before is in the sockets' buffers.
    let (mut told, mut told_shutdown) = (0, 0);
    for ws in &mut sockets {
        let mut seen = Vec::new();
        let reason = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match ws.next().await {
                    Some(Ok(Message::Text(t))) => {
                        let m: Value = serde_json::from_str(t.as_str()).unwrap();
                        if m["type"] == "closed" {
                            return m["reason"].as_str().map(str::to_owned);
                        }
                        if let Some(rows) = m["screen"]["text"].as_array() {
                            seen.extend(rows.iter().map(|r| r.as_str().unwrap().to_owned()));
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => return None,
                }
            }
        })
        .await
        .ok()
        .flatten();
        told += usize::from(reason.is_some());
        told_shutdown += usize::from(reason.as_deref() == Some("server_shutdown"));
    }
    assert_eq!(told, SESSIONS, "browsers told before the process ended");
    assert_eq!(told_shutdown, SESSIONS, "reason server_shutdown");
}

/// Reads until the peer closes the connection; `true` if that happened within `within`.
async fn closed_within(tcp: &mut TcpStream, within: Duration) -> bool {
    use tokio::io::AsyncReadExt;
    let mut buf = [0_u8; 1024];
    tokio::time::timeout(within, async {
        loop {
            match tcp.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await
    .is_ok()
}

/// Slow-loris: a client that sends a request head byte by byte, or keeps a keep-alive
/// connection idle, must be disconnected after the header read timeout instead of holding a
/// connection (and its file descriptor) forever.
#[tokio::test]
async fn test_e2e_slow_and_idle_http_connections_are_closed() {
    use tokio::io::AsyncWriteExt;
    let (port, _host_rx) = spawn_mock_host().await;
    let srv = start(
        config(port, "[limits]\nheader_read_timeout_secs = 1"),
        |e| e,
    )
    .await;

    let mut slow = TcpStream::connect(srv.addr).await.unwrap();
    slow.write_all(b"GET /healthz HTTP/1.1\r\nHost: gw\r\n")
        .await
        .unwrap();
    assert!(
        closed_within(&mut slow, Duration::from_secs(4)).await,
        "an incomplete request head must not keep the connection open"
    );

    let mut idle = TcpStream::connect(srv.addr).await.unwrap();
    idle.write_all(b"GET /healthz HTTP/1.1\r\nHost: gw\r\n\r\n")
        .await
        .unwrap();
    assert!(
        closed_within(&mut idle, Duration::from_secs(4)).await,
        "an idle keep-alive connection must be closed"
    );
}

/// Connections beyond `max_connections` are closed right after accept; WebSocket connections waiting for
/// their first message beyond `max_pending_handshakes` are refused.
#[tokio::test]
async fn test_e2e_connection_and_handshake_limits() {
    let (port, _host_rx) = spawn_mock_host().await;
    let srv = start(config(port, "[limits]\nmax_connections = 2"), |e| e).await;
    let _a = TcpStream::connect(srv.addr).await.unwrap();
    let _b = TcpStream::connect(srv.addr).await.unwrap();
    let mut c = TcpStream::connect(srv.addr).await.unwrap();
    assert!(
        closed_within(&mut c, Duration::from_secs(2)).await,
        "the connection over the limit must be closed"
    );

    let srv = start(config(port, "[limits]\nmax_pending_handshakes = 1"), |e| e).await;
    let _waiting = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    let refused = ws_connect(srv.addr, "bastion3270.v1").await;
    assert!(
        refused.as_ref().is_err_and(|e| e.contains("503")),
        "a second socket in the handshake must be refused: {refused:?}"
    );
}

/// Resume re-checks the profile right of the presenting credential: a credential of the same
/// subject that may no longer open the profile cannot re-attach to a session on it.
#[tokio::test]
async fn test_e2e_resume_rechecks_the_profile_right() {
    let (port, _host_rx) = spawn_mock_host().await;
    let digest = |t: &[u8]| {
        bastion3270_server::extensions::auth::encode_hex(
            &bastion3270_server::extensions::auth::sha256(t),
        )
    };
    let (all, limited) = (digest(b"token-all"), digest(b"token-limited"));
    let srv = start(
        config(
            port,
            &format!(
                "[auth]\nmode = \"static-token\"\n\
                 [[auth.tokens]]\nsubject = \"alice\"\nsha256 = \"{all}\"\n\
                 [[auth.tokens]]\nsubject = \"alice\"\nsha256 = \"{limited}\"\nprofiles = [\"hercules\"]"
            ),
        ),
        |e| e,
    )
    .await;

    let mut ws = ws_connect(srv.addr, "bastion3270.v1, bastion3270.bearer.token-all")
        .await
        .unwrap();
    send(&mut ws, json!({"type": "open", "profile": "nopaste"})).await;
    let s = recv(&mut ws).await;
    assert_eq!(s["type"], "session");
    let (id, token) = (s["session_id"].clone(), s["resume_token"].clone());
    ws.close(None).await.unwrap();

    let mut other = ws_connect(srv.addr, "bastion3270.v1, bastion3270.bearer.token-limited")
        .await
        .unwrap();
    send(
        &mut other,
        json!({"type": "resume", "session_id": id, "token": token}),
    )
    .await;
    assert_eq!(recv(&mut other).await["code"], "session_not_found");
}

/// A malformed profile id from the client is not echoed into the audit trail (log flooding,
/// line injection into custom sinks).
#[tokio::test]
async fn test_e2e_malformed_profile_id_is_not_echoed_into_the_audit() {
    let (port, _host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(config(port, ""), |e| e.with_audit(audit_dyn)).await;

    let hostile = format!("x\nFORGED RECORD {}", "A".repeat(4000));
    let mut ws = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(&mut ws, json!({"type": "open", "profile": hostile})).await;
    assert_eq!(recv(&mut ws).await["code"], "unknown_profile");

    let events = audit.events.lock().unwrap();
    let reason = events
        .iter()
        .find_map(|e| match e {
            SessionAuditKind::PolicyDenied { reason } => Some(reason.clone()),
            _ => None,
        })
        .expect("the failed open is audited");
    assert!(
        !reason.contains('\n') && !reason.contains("FORGED"),
        "{reason}"
    );
    assert!(reason.len() < 200, "{reason}");
}

/// A browser that is gone without closing its socket (sleeping laptop, half-open TCP) must
/// not keep its session "attached" forever: with no frame at all (not even the automatic
/// pong) for two ping intervals, the session is detached and the grace period applies.
#[tokio::test]
async fn test_e2e_unresponsive_browser_is_detached() {
    let (port, _host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(config(port, "[limits]\nping_interval_secs = 1"), |e| {
        e.with_audit(audit_dyn)
    })
    .await;

    // Open, then never read again: tungstenite answers pings only while it is polled.
    let (_ws, _, _) = open(srv.addr, "hercules").await;
    let detached = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if audit
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, SessionAuditKind::Detached))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(detached.is_ok(), "the silent browser must be detached");
}

/// Connect errors can name internal hosts, certificate names and file paths: the browser gets
/// a fixed text, the detail stays in the server-side audit record.
#[tokio::test]
async fn test_e2e_connect_error_details_stay_on_the_server() {
    // A port nobody listens on (bound, then released).
    let closed_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(config(closed_port, ""), |e| e.with_audit(audit_dyn)).await;

    let mut ws = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(&mut ws, json!({"type": "open", "profile": "hercules"})).await;
    let reply = recv(&mut ws).await;
    assert_eq!(reply["code"], "connect_failed");
    assert_eq!(reply["message"], "could not connect to the host");

    let events = audit.events.lock().unwrap();
    let detailed = events.iter().any(|e| {
        matches!(e, SessionAuditKind::ConnectFailed { reason }
            if reason.starts_with("open 'hercules': could not connect to the host: "))
    });
    assert!(detailed, "the audit keeps the detail: {events:?}");
}

/// `USER: ` (protected) followed by a **visible** unprotected field with the cursor in it.
const VISIBLE_FIELD_SCREEN: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x01, // TN3270E header (3270-DATA)
    0x05, 0xC3, // Erase/Write, WCC restore keyboard
    0x1D, 0x20, 0xE4, 0xE2, 0xC5, 0xD9, 0x7A, 0x40, // SF protected + "USER: "
    0x1D, 0x00, 0x13, // SF unprotected normal (visible) + IC
    0xFF, 0xEF, // IAC EOR
];

/// The logon panel with a keyboard that stays locked (WCC without "restore keyboard").
const LOCKED_SCREEN: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x01, // TN3270E header (3270-DATA)
    0x05, 0x40, // Erase/Write, WCC without restore
    0x1D, 0x20, 0xD7, 0xC1, 0xE2, 0xE2, 0x7A, 0x40, // SF protected + "PASS: "
    0x1D, 0x0C, 0x13, // SF unprotected non-display + IC
    0xFF, 0xEF, // IAC EOR
];

/// If the panel is not what the auto-logon script expects (here the cursor sits in a visible
/// field), the secret is not typed: it would be shown to the browser and sent to the host in a
/// field where it does not belong.
#[tokio::test]
async fn test_e2e_autologon_never_types_a_secret_into_a_visible_field() {
    let mut host = common::mock_host::spawn(VISIBLE_FIELD_SCREEN, |_| None).await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(config(host.port, ""), |e| {
        e.with_auth(Arc::new(PassTicketLikeAuth))
            .with_audit(audit_dyn)
    })
    .await;

    let mut ws = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(&mut ws, json!({"type": "open", "profile": "hercules"})).await;
    assert_eq!(recv(&mut ws).await["type"], "session");

    tokio::time::timeout(T, async {
        loop {
            let failed = audit
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|k| matches!(k, SessionAuditKind::AutoLogon { success: false, .. }));
            if failed {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the auto-logon must fail");

    let mut seen = Vec::new();
    send(&mut ws, json!({"type": "aid", "aid": "enter"})).await;
    let frame = recv_until(&mut ws, &mut seen, |m| m["type"] == "frame").await;
    assert!(!frame.to_string().contains("HERC01"));
    while let Ok(bytes) = host.received.try_recv() {
        assert!(
            !bytes
                .windows(HERC01_EBCDIC.len())
                .any(|w| w == HERC01_EBCDIC),
            "the secret reached the host"
        );
    }
}

/// While the gateway runs an auto-logon, browser input is refused, so it cannot move the
/// cursor (or type) between the script's steps.
#[tokio::test]
async fn test_e2e_browser_input_is_held_during_autologon() {
    let host = common::mock_host::spawn(LOCKED_SCREEN, |_| None).await;
    let srv = start(config(host.port, ""), |e| {
        e.with_auth(Arc::new(PassTicketLikeAuth))
    })
    .await;

    let mut ws = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(&mut ws, json!({"type": "open", "profile": "hercules"})).await;
    assert_eq!(recv(&mut ws).await["type"], "session");

    // The script waits for an unlocked keyboard that never comes.
    send(&mut ws, json!({"type": "action", "action": "tab"})).await;
    let mut seen = Vec::new();
    let err = recv_until(&mut ws, &mut seen, |m| m["type"] == "error").await;
    assert_eq!(err["code"], "input_held");
}

/// Control frames count against the message rate limit: a ping flood costs the gateway a
/// pong and a wake-up per frame, like any other message.
#[tokio::test]
async fn test_e2e_ping_flood_is_rate_limited() {
    let (port, _host_rx) = spawn_mock_host().await;
    let srv = start(
        config(port, "[limits]\nmax_messages_per_second = 20"),
        |e| e,
    )
    .await;
    let (mut ws, _, _) = open(srv.addr, "hercules").await;
    for _ in 0..100 {
        if ws.send(Message::Ping(Vec::new().into())).await.is_err() {
            break;
        }
    }
    let mut seen = Vec::new();
    let closed = recv_until(&mut ws, &mut seen, |m| m["type"] == "closed").await;
    assert_eq!(closed["reason"], "rate_limited");
}

/// A session is closed when it reaches its maximum lifetime, even while a browser is attached
/// and active; the browser is told why (not that the host ended it).
#[tokio::test]
async fn test_e2e_session_is_closed_at_its_maximum_lifetime() {
    let (port, _host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(
        config(
            port,
            "[limits]\nmax_session_lifetime_secs = 1\nreaper_interval_secs = 1",
        ),
        |e| e.with_audit(audit_dyn),
    )
    .await;
    let (mut ws, _, _) = open(srv.addr, "hercules").await;
    send(&mut ws, json!({"type": "key", "ch": "A"})).await; // activity does not extend it

    let mut seen = Vec::new();
    let closed = recv_until(&mut ws, &mut seen, |m| m["type"] == "closed").await;
    assert_eq!(closed["reason"], "lifetime");
    let closed_for_lifetime = audit
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, SessionAuditKind::Closed { reason } if reason == "lifetime"));
    assert!(closed_for_lifetime);
}

/// An identity provider whose errors name internal systems.
#[derive(Debug)]
struct ChattyFailingAuth;

#[async_trait]
impl AuthProvider for ChattyFailingAuth {
    fn name(&self) -> &'static str {
        "chatty"
    }
    fn requires_credentials(&self) -> bool {
        false
    }
    async fn authenticate(&self, _headers: &HeaderMap) -> Result<SessionIdentity, AuthError> {
        Err(AuthError::Unavailable(
            "https://idp.corp.internal:8443/token timed out".into(),
        ))
    }
}

/// Texts from an identity provider can name internal systems: the browser gets a fixed text,
/// the audit record keeps the detail.
#[tokio::test]
async fn test_e2e_identity_provider_errors_stay_on_the_server() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (port, _host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(config(port, ""), |e| {
        e.with_auth(Arc::new(ChattyFailingAuth))
            .with_audit(audit_dyn)
    })
    .await;

    let refused = ws_connect(srv.addr, "bastion3270.v1").await;
    let text = format!("{refused:?}");
    assert!(text.contains("503") && !text.contains("idp.corp"), "{text}");

    let mut tcp = TcpStream::connect(srv.addr).await.unwrap();
    tcp.write_all(b"GET /api/profiles HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    tcp.read_to_string(&mut body).await.unwrap();
    assert!(
        body.contains("the identity provider is unavailable"),
        "{body}"
    );
    assert!(!body.contains("idp.corp"), "{body}");

    let kept = audit.events.lock().unwrap().iter().any(
        |e| matches!(e, SessionAuditKind::AuthFailed { reason } if reason.contains("idp.corp")),
    );
    assert!(kept, "the audit keeps the detail");
}

/// An unattended open tab: the session is closed after the inactivity timeout without operator
/// input, although the browser stays attached; input keeps it open.
#[tokio::test]
async fn test_e2e_session_without_operator_input_is_closed() {
    let (port, _host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(
        config(
            port,
            "[limits]\nidle_timeout_secs = 2\nreaper_interval_secs = 1\nping_interval_secs = 1",
        ),
        |e| e.with_audit(audit_dyn),
    )
    .await;
    let (mut ws, _, _) = open(srv.addr, "hercules").await;
    let closed_for_idle = || {
        audit
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, SessionAuditKind::Closed { reason } if reason == "idle"))
    };

    // Typing every half second for 3 s keeps the session (longer than the timeout).
    let mut seen = Vec::new();
    for _ in 0..6 {
        send(&mut ws, json!({"type": "action", "action": "home"})).await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        while let Ok(Some(Ok(_))) = tokio::time::timeout_at(deadline, ws.next()).await {}
    }
    assert!(!closed_for_idle(), "input keeps the session open");

    // Then only the automatic pongs: closed for inactivity, and the browser is told so.
    let closed = recv_until(&mut ws, &mut seen, |m| m["type"] == "closed").await;
    assert_eq!(closed["reason"], "idle");
    assert!(closed_for_idle());
}

/// Refused messages are not operator input: a client that keeps sending messages the gateway
/// rejects (unknown action, cursor off the screen, control character) does not keep a session
/// alive past the inactivity timeout.
#[tokio::test]
async fn test_e2e_refused_messages_do_not_count_as_operator_input() {
    let (port, _host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(
        config(
            port,
            "[limits]\nidle_timeout_secs = 2\nreaper_interval_secs = 1\nping_interval_secs = 1",
        ),
        |e| e.with_audit(audit_dyn),
    )
    .await;
    let (mut ws, _, _) = open(srv.addr, "hercules").await;
    let refused = [
        json!({"type": "action", "action": "no-such-action"}),
        json!({"type": "move_cursor", "row": 999, "col": 0}),
        json!({"type": "key", "ch": "\u{7}"}),
    ];
    let mut closed = false;
    'outer: for i in 0..12 {
        send(&mut ws, refused[i % refused.len()].clone()).await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        while let Ok(Some(Ok(msg))) = tokio::time::timeout_at(deadline, ws.next()).await {
            if let Message::Text(t) = msg {
                let m: Value = serde_json::from_str(t.as_str()).unwrap();
                if m["type"] == "closed" {
                    closed = true;
                    break 'outer;
                }
            }
        }
    }
    assert!(closed, "refused messages kept the session open for 6 s");
    assert!(audit
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, SessionAuditKind::Closed { reason } if reason == "idle")));
}

/// A custom binary can end every session of one identity (user disabled, logout at the
/// identity provider): the sessions close and are audited with the given reason. The browser
/// gets the neutral `ended`: the reason is the custom binary's own text.
#[tokio::test]
async fn test_e2e_sessions_of_one_identity_can_be_closed() {
    let (port, _host_rx) = spawn_mock_host().await;
    let srv = start(config(port, ""), |e| e).await;
    let (mut a, _, _) = open(srv.addr, "hercules").await;
    let (mut b, _, _) = open(srv.addr, "hercules").await;

    assert_eq!(
        srv.gateway
            .close_sessions_for("somebody-else", "admin")
            .await,
        0
    );
    assert_eq!(
        srv.gateway.close_sessions_for("anonymous", "admin").await,
        2
    );
    let mut seen = Vec::new();
    for ws in [&mut a, &mut b] {
        let closed = recv_until(ws, &mut seen, |m| m["type"] == "closed").await;
        assert_eq!(closed["reason"], "ended");
    }
    assert_eq!(srv.gateway.live_sessions(), 0);
}

/// An identity provider whose authentication expires soon.
#[derive(Debug)]
struct ShortLivedAuth;

#[async_trait]
impl AuthProvider for ShortLivedAuth {
    fn name(&self) -> &'static str {
        "short-lived"
    }
    fn requires_credentials(&self) -> bool {
        false
    }
    async fn authenticate(&self, _headers: &HeaderMap) -> Result<SessionIdentity, AuthError> {
        let mut id = SessionIdentity::anonymous();
        id.subject = "alice".into();
        id.authenticated = true;
        id.expires_at = Some(std::time::SystemTime::now() + Duration::from_secs(1));
        Ok(id)
    }
}

/// When the authentication expires (an identity provider token's `exp`), the session is
/// closed although it is attached and in use.
#[tokio::test]
async fn test_e2e_session_ends_when_the_identity_expires() {
    let (port, _host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(config(port, "[limits]\nreaper_interval_secs = 1"), |e| {
        e.with_auth(Arc::new(ShortLivedAuth)).with_audit(audit_dyn)
    })
    .await;
    let (mut ws, _, _) = open(srv.addr, "hercules").await;
    let mut seen = Vec::new();
    let closed = recv_until(&mut ws, &mut seen, |m| m["type"] == "closed").await;
    assert_eq!(closed["reason"], "identity_expired");
    let expired =
        audit.events.lock().unwrap().iter().any(
            |e| matches!(e, SessionAuditKind::Closed { reason } if reason == "identity_expired"),
        );
    assert!(expired);
}

/// Refused browser messages (malformed, unknown key names, smuggled fields) are audited, once
/// per connection with a count, so a flood of them cannot flood the audit trail. A verified
/// credential is audited too.
#[tokio::test]
async fn test_e2e_rejected_messages_and_verified_credentials_are_audited() {
    let (port, _host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let hash = bastion3270_server::extensions::auth::encode_hex(
        &bastion3270_server::extensions::auth::sha256(b"lab-token-1"),
    );
    let srv = start(
        config(
            port,
            &format!(
                "[auth]\nmode = \"static-token\"\n[[auth.tokens]]\nsubject = \"op\"\nsha256 = \"{hash}\""
            ),
        ),
        |e| e.with_audit(audit_dyn),
    )
    .await;
    let mut ws = ws_connect(srv.addr, "bastion3270.v1, bastion3270.bearer.lab-token-1")
        .await
        .unwrap();
    send(&mut ws, json!({"type": "open", "profile": "hercules"})).await;
    assert_eq!(recv(&mut ws).await["type"], "session");

    ws.send(Message::Text("{not json".into())).await.unwrap();
    send(&mut ws, json!({"type": "action", "action": "format-c"})).await;
    send(
        &mut ws,
        json!({"type": "key", "ch": "A", "host": "10.0.0.1"}),
    )
    .await;
    send(&mut ws, json!({"type": "disconnect"})).await;
    let mut seen = Vec::new();
    recv_until(&mut ws, &mut seen, |m| m["type"] == "closed").await;

    let events = audit.events.lock().unwrap();
    let rejected: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            SessionAuditKind::MessagesRejected { first, count } => Some((first.clone(), *count)),
            _ => None,
        })
        .collect();
    assert_eq!(rejected, vec![("malformed message".to_owned(), 3)]);
    assert!(events.iter().any(
        |e| matches!(e, SessionAuditKind::AuthSucceeded { provider } if provider == "static-token")
    ));
}

/// Records the peer of every session event.
#[derive(Debug, Default)]
struct PeerAudit(Mutex<Vec<(&'static str, Option<SocketAddr>)>>);

impl AuditSink for PeerAudit {
    fn on_session_event(&self, e: &SessionAuditEvent) {
        self.0.lock().unwrap().push((e.kind.name(), e.peer));
    }
    fn on_aid_submitted(&self, _r: &AidAuditRecord<'_>) {}
}

async fn ws_connect_via_proxy(addr: SocketAddr, origin: &str) -> Result<Ws, String> {
    let mut req = format!("ws://{addr}/ws").into_client_request().unwrap();
    let h = req.headers_mut();
    h.insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static("bastion3270.v1"),
    );
    h.insert("Origin", HeaderValue::from_str(origin).unwrap());
    h.insert(
        "X-Forwarded-For",
        HeaderValue::from_static("6.6.6.6, 203.0.113.9"),
    );
    h.insert("X-Forwarded-Proto", HeaderValue::from_static("https"));
    tokio_tungstenite::connect_async(req)
        .await
        .map(|(ws, _)| ws)
        .map_err(|e| e.to_string())
}

/// Behind a trusted proxy the audit records the browser's address (not the proxy's), and the
/// same-origin check compares the scheme the browser used; from an untrusted peer the
/// forwarded headers are ignored.
#[tokio::test]
async fn test_e2e_trusted_proxy_headers_give_client_address_and_scheme() {
    let (port, _host_rx) = spawn_mock_host().await;
    let audit = Arc::new(PeerAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(
        config(port, "[server]\ntrusted_proxies = [\"127.0.0.0/8\"]"),
        |e| e.with_audit(audit_dyn),
    )
    .await;
    let host = srv.addr.to_string();

    // The browser page was https, the Origin says http: refused (scheme downgrade).
    let refused = ws_connect_via_proxy(srv.addr, &format!("http://{host}")).await;
    assert!(refused.is_err_and(|e| e.contains("403")));

    let mut ws = ws_connect_via_proxy(srv.addr, &format!("https://{host}"))
        .await
        .unwrap();
    send(&mut ws, json!({"type": "open", "profile": "hercules"})).await;
    assert_eq!(recv(&mut ws).await["type"], "session");
    let browser: SocketAddr = "203.0.113.9:0".parse().unwrap();
    assert!(
        audit.0.lock().unwrap().contains(&("opened", Some(browser))),
        "{:?}",
        audit.0.lock().unwrap()
    );

    // Same headers, proxy not trusted: ignored (the TCP peer is recorded, no scheme check).
    let audit = Arc::new(PeerAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(config(port, ""), |e| e.with_audit(audit_dyn)).await;
    let mut ws = ws_connect_via_proxy(srv.addr, &format!("http://{}", srv.addr))
        .await
        .unwrap();
    send(&mut ws, json!({"type": "open", "profile": "hercules"})).await;
    assert_eq!(recv(&mut ws).await["type"], "session");
    let recorded = audit.0.lock().unwrap().clone();
    assert!(
        recorded
            .iter()
            .any(|(k, p)| *k == "opened" && p.is_some_and(|p| p.ip().is_loopback())),
        "{recorded:?}"
    );
}

/// A flood of failures from one source (here: a cross-site page retrying the WebSocket) is
/// capped in the audit trail; the rest is reported as one summary when the window ends.
#[tokio::test]
async fn test_e2e_failure_flood_is_capped_in_the_audit() {
    let (port, _host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let srv = start(config(port, ""), |e| e.with_audit(audit_dyn)).await;
    for _ in 0..30 {
        let mut req = format!("ws://{}/ws", srv.addr)
            .into_client_request()
            .unwrap();
        req.headers_mut()
            .insert("Origin", HeaderValue::from_static("https://evil.example"));
        assert!(tokio_tungstenite::connect_async(req).await.is_err());
    }
    let denied = audit
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, SessionAuditKind::PolicyDenied { .. }))
        .count();
    assert_eq!(denied, 20);
}

/// GET `path` over plain HTTP; the whole response.
async fn http_get(addr: SocketAddr, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    tcp.read_to_string(&mut out).await.unwrap();
    out
}

/// Metrics count what happened (open, AID, frames, close) on their own listener, carry no
/// personal data, and are not served on the browser-facing port.
#[tokio::test]
async fn test_e2e_metrics_on_their_own_listener() {
    let (port, _host_rx) = spawn_mock_host().await;
    let metrics_addr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let hash = bastion3270_server::extensions::auth::encode_hex(
        &bastion3270_server::extensions::auth::sha256(b"lab-token-1"),
    );
    let srv = start(
        config(
            port,
            &format!(
                "[server]\nmetrics_bind = \"{metrics_addr}\"\n[auth]\nmode = \"static-token\"\n\
                 [[auth.tokens]]\nsubject = \"alice.secret@bank\"\nsha256 = \"{hash}\""
            ),
        ),
        |e| e,
    )
    .await;
    let mut ws = ws_connect(srv.addr, "bastion3270.v1, bastion3270.bearer.lab-token-1")
        .await
        .unwrap();
    send(&mut ws, json!({"type": "open", "profile": "hercules"})).await;
    assert_eq!(recv(&mut ws).await["type"], "session");
    send(&mut ws, json!({"type": "aid", "aid": "enter"})).await;
    send(&mut ws, json!({"type": "disconnect"})).await;
    let mut seen = Vec::new();
    recv_until(&mut ws, &mut seen, |m| m["type"] == "closed").await;

    let text = http_get(metrics_addr, "/metrics").await;
    assert!(text.contains("text/plain; version=0.0.4"), "{text}");
    for line in [
        "bastion3270_sessions_opened_total{result=\"ok\"} 1",
        "bastion3270_sessions_closed_total{reason=\"user\"} 1",
        "bastion3270_aids_total 1",
        "bastion3270_host_connect_seconds_count 1",
        "bastion3270_audit_events_total{event=\"opened\"} 1",
        "bastion3270_sessions{state=\"attached\"} 0",
    ] {
        assert!(text.contains(line), "missing {line}:\n{text}");
    }
    assert!(
        !text.contains("bastion3270_frames_sent_total 0"),
        "frames were sent"
    );
    assert!(
        !text.contains("alice") && !text.contains("127.0.0.1"),
        "no personal data"
    );

    let main = http_get(srv.addr, "/metrics").await;
    assert!(
        main.starts_with("HTTP/1.1 404"),
        "not on the browser port: {main}"
    );
}

/// The user's session choices shape the session (here a dynamic 30 x 100 screen, shown at the
/// host's first Erase/Write Alternate, and another code page); invalid choices and attempts to pass connection settings are refused before
/// anything connects to the host.
#[tokio::test]
async fn test_e2e_session_choices_are_applied_and_validated() {
    // A dynamic screen uses its alternate size once the host writes with Erase/Write
    // Alternate, as ISPF does: TN3270E header, EWA (X'7E'), WCC (restore keyboard), IAC EOR.
    static EWA_SCREEN: [u8; 9] = [0x00, 0x00, 0x00, 0x00, 0x01, 0x7E, 0xC2, 0xFF, 0xEF];
    let host = common::mock_host::spawn(&EWA_SCREEN, |_| None).await;
    let srv = start(config(host.port, ""), |e| e).await;

    let mut ws = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
    send(
        &mut ws,
        json!({"type": "open", "profile": "hercules",
               "options": {"model": "dynamic", "rows": 30, "cols": 100, "codepage": "cp1047"}}),
    )
    .await;
    assert_eq!(recv(&mut ws).await["type"], "session");
    let mut seen = Vec::new();
    // The first frames may show the screen before the host's write (24 x 80).
    let frame = recv_until(&mut ws, &mut seen, |m| {
        m["type"] == "frame" && m["screen"]["rows"] == json!(30)
    })
    .await;
    assert_eq!(
        (&frame["screen"]["rows"], &frame["screen"]["cols"]),
        (&json!(30), &json!(100))
    );
    assert_eq!(host.connection_count(), 1);

    for options in [
        json!({"model": "dynamic", "rows": 70, "cols": 160}),
        json!({"codepage": "cp9999"}),
        json!({"host": "10.0.0.1"}),
    ] {
        let mut ws = ws_connect(srv.addr, "bastion3270.v1").await.unwrap();
        send(
            &mut ws,
            json!({"type": "open", "profile": "hercules", "options": options}),
        )
        .await;
        let reply = recv(&mut ws).await;
        assert_eq!(reply["type"], "error", "{options}: {reply}");
        let code = reply["code"].as_str().unwrap();
        assert!(
            code == "invalid_options" || code == "bad_request",
            "{options}: {reply}"
        );
    }
    assert_eq!(
        host.connection_count(),
        1,
        "no connection for refused choices"
    );
}

/// Records the profile id of every session event (custom sessions name their target there).
#[derive(Debug, Default)]
struct ProfileIds(Mutex<Vec<Option<String>>>);

impl AuditSink for ProfileIds {
    fn on_session_event(&self, event: &SessionAuditEvent) {
        self.0.lock().unwrap().push(event.profile_id.clone());
    }
    fn on_aid_submitted(&self, _: &AidAuditRecord<'_>) {}
}

/// Opens a custom connection and returns the first reply.
async fn open_custom(addr: SocketAddr, target: Value) -> Value {
    let mut ws = ws_connect(addr, "bastion3270.v1").await.unwrap();
    send(&mut ws, json!({"type": "open_custom", "target": target})).await;
    recv(&mut ws).await
}

/// A connection the user defines (host, port, TLS) is allowed by default and audited with
/// its target; the gateway refuses it when the administrator disabled custom connections or
/// the target is not on the allow-list, before anything connects.
#[tokio::test]
async fn test_e2e_custom_connections_follow_the_gateway_policy() {
    let host = common::mock_host::spawn(common::mock_host::LOGON_SCREEN, |_| None).await;
    let target = json!({"host": "127.0.0.1", "port": host.port, "tls": false});

    let ids = Arc::new(ProfileIds::default());
    let sink: Arc<dyn AuditSink> = ids.clone();
    let open = start(config(host.port, ""), |e| e.with_audit(sink)).await;
    let reply = open_custom(open.addr, target.clone()).await;
    assert_eq!(reply["type"], "session", "{reply}");
    assert_eq!(host.connection_count(), 1);
    let expected = format!("custom:127.0.0.1:{}", host.port);
    assert!(
        ids.0
            .lock()
            .unwrap()
            .iter()
            .any(|id| id.as_deref() == Some(expected.as_str())),
        "the audit names the target"
    );

    for policy in [
        "[custom_connections]\nenabled = false".to_owned(),
        "[custom_connections]\nallowed_targets = [\"10.0.0.0/8\"]".to_owned(),
        "[custom_connections]\nallow_plain = false".to_owned(),
    ] {
        let srv = start(config(host.port, &policy), |e| e).await;
        let reply = open_custom(srv.addr, target.clone()).await;
        assert_eq!(reply["type"], "error", "{policy}: {reply}");
        assert_eq!(reply["code"], "invalid_options", "{policy}: {reply}");
    }
    // Fields the gateway does not know are refused, not ignored.
    let reply = open_custom(
        open.addr,
        json!({"host": "127.0.0.1", "port": host.port, "tls": false, "ca_cert": "/etc/x"}),
    )
    .await;
    assert_eq!(reply["code"], "bad_request", "{reply}");
    assert_eq!(
        host.connection_count(),
        1,
        "nothing refused reached the host"
    );
}

/// A TLS front of `backend` (as AT-TLS on z/OS) with a host certificate for `localhost`
/// issued by a new internal CA; returns the port and the CA in PEM.
async fn tls_front(backend: u16) -> (u16, String) {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    };
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Bank Internal CA");
    ca.distinguished_name = dn;
    let ca_pem = ca.self_signed(&ca_key).unwrap().pem();
    let host_key = KeyPair::generate().unwrap();
    let host = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&host_key, &Issuer::from_params(&ca, &ca_key))
        .unwrap();

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![host.der().clone()],
        rustls_pki_types::PrivateKeyDer::try_from(host_key.serialize_der()).unwrap(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    if let Ok(mut plain) = TcpStream::connect(("127.0.0.1", backend)).await {
                        let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
                    }
                }
            });
        }
    });
    (port, ca_pem)
}

/// A bank's internal CA in `[host_tls] ca_certs` is trusted for custom connections, which
/// cannot name a CA themselves; without it the connection is refused and the audit record
/// says why (the browser gets the fixed text).
#[tokio::test]
async fn test_e2e_gateway_cas_are_trusted_for_custom_connections() {
    let host = common::mock_host::spawn(common::mock_host::LOGON_SCREEN, |_| None).await;
    let (tls_port, ca_pem) = tls_front(host.port).await;
    let target = json!({"host": "localhost", "port": tls_port, "tls": true});

    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let untrusted = start(config(host.port, ""), |e| e.with_audit(audit_dyn)).await;
    let reply = open_custom(untrusted.addr, target.clone()).await;
    assert_eq!(reply["code"], "connect_failed", "{reply}");
    assert!(!reply.to_string().contains("Bank Internal CA"), "{reply}");
    let reason = audit
        .events
        .lock()
        .unwrap()
        .iter()
        .find_map(|e| match e {
            SessionAuditKind::ConnectFailed { reason } => Some(reason.clone()),
            _ => None,
        })
        .expect("the refusal is audited");
    assert!(
        reason.contains("not trusted") && reason.contains("issuer 'CN=Bank Internal CA'"),
        "{reason}"
    );

    let ca_file = std::env::temp_dir().join(format!("bastion3270_e2e_ca_{tls_port}.pem"));
    std::fs::write(&ca_file, &ca_pem).unwrap();
    let extra = format!(
        "[host_tls]\nca_certs = [{:?}]",
        ca_file.display().to_string()
    );
    let trusted = start(config(host.port, &extra), |e| e).await;
    let reply = open_custom(trusted.addr, target).await;
    let _ = std::fs::remove_file(&ca_file);
    assert_eq!(reply["type"], "session", "{reply}");
}

/// Printing is audited with the digest of the masked screen; a profile that does not allow
/// copying refuses it (`print_denied`) and audits the refusal.
#[tokio::test]
async fn test_e2e_printing_is_audited_and_follows_the_copy_policy() {
    let (port, _host_rx) = spawn_mock_host().await;
    let audit = Arc::new(RecordingAudit::default());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let cfg = format!(
        "[[profiles]]\nid = \"nocopy\"\nname = \"No copy\"\nallow_copy = false\n\
         [profiles.connection]\ntls_mode = \"disabled\"\nhost = \"127.0.0.1\"\nport = {port}\n"
    );
    let mut toml_cfg = config(port, "");
    toml_cfg
        .profiles
        .extend(ServerConfig::from_toml_str(&cfg).unwrap().profiles);
    let srv = start(toml_cfg, |e| e.with_audit(audit_dyn)).await;

    let (mut ws, _, _) = open(srv.addr, "hercules").await;
    send(&mut ws, json!({"type": "print"})).await;
    let printed = tokio::time::timeout(T, async {
        loop {
            if let Some(SessionAuditKind::ScreenPrinted { screen_sha256 }) = audit
                .events
                .lock()
                .unwrap()
                .iter()
                .find(|e| matches!(e, SessionAuditKind::ScreenPrinted { .. }))
                .cloned()
            {
                return screen_sha256;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(printed.len(), 64, "hex SHA-256");

    let (mut ws, _, _) = open(srv.addr, "nocopy").await;
    send(&mut ws, json!({"type": "print"})).await;
    let mut seen = Vec::new();
    let refused = recv_until(&mut ws, &mut seen, |m| m["type"] == "error").await;
    assert_eq!(refused["code"], "print_denied");
    assert!(audit.events.lock().unwrap().iter().any(|e| matches!(
        e,
        SessionAuditKind::PolicyDenied { reason } if reason.starts_with("print:")
    )));
}
