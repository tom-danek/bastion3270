//! One WebSocket connection = one attached browser tab.
//!
//! ```text
//!            ┌─────────── tokio::select! ────────────┐
//! browser ──►│ socket.recv()   → validate → SessionHandle (keystrokes only)
//! browser ◄──│ snapshot.changed() → SafeScreenView projection
//!            │ attach.changed()   → another tab took over → close
//!            │ ping tick          → keep proxies / ingress from idling out
//!            └───────────────────────────────────────┘
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use axum::extract::ws::{Message, WebSocket};
use bastion3270_core::{ActionKey, AidKey, KeyboardState, SafeScreenView};
use tokio::sync::OwnedSemaphorePermit;

use crate::extensions::{
    masked_screen_digest, AidAuditRecord, DlpContext, DlpDecision, SessionAuditKind,
    SessionIdentity,
};
use crate::gateway::{closed_reason, Gateway, GatewaySession, OpenError, Snapshot};
use crate::protocol::{
    parse_action, parse_aid, parse_attention, wire_screen, wire_status, ClientMessage,
    ServerMessage,
};
use crate::secret::Secret;

/// Time allowed for the first (`open` / `resume`) message.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for one message to the browser. A browser that stops reading (zero TCP
/// window) would otherwise block the attached loop, and with it the liveness check below.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Fixed-window message rate limiter.
#[derive(Debug)]
struct RateLimiter {
    window_start: Instant,
    count: u32,
    max_per_second: u32,
}

impl RateLimiter {
    fn new(max_per_second: u32) -> Self {
        Self {
            window_start: Instant::now(),
            count: 0,
            max_per_second,
        }
    }

    fn allow(&mut self) -> bool {
        if self.window_start.elapsed() >= Duration::from_secs(1) {
            self.window_start = Instant::now();
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.count <= self.max_per_second
    }
}

/// How the attach loop ended.
#[derive(Debug)]
enum Exit {
    /// Browser went away; session keeps running for the grace period.
    Detached,
    /// Browser exceeded the message rate.
    RateLimited,
    /// User pressed "disconnect".
    UserClosed,
    /// Mainframe session ended.
    HostEnded(String),
    /// Another tab attached to the same session.
    TakenOver,
}

/// Result of handling one input message.
enum Flow {
    Continue,
    Disconnect,
    /// The message was refused (the browser was told); the fixed reason is audited.
    Rejected(&'static str),
}

/// Messages refused on one connection: audited once, when the connection ends, so a flood of
/// bad messages cannot flood the audit trail.
#[derive(Debug, Default)]
struct Rejections {
    first: Option<&'static str>,
    count: u32,
}

impl Rejections {
    fn note(&mut self, reason: &'static str) {
        self.first.get_or_insert(reason);
        self.count = self.count.saturating_add(1);
    }

    /// One audit record for the connection, if anything was refused.
    fn audit(&self, gw: &Gateway, session: &GatewaySession, peer: Option<SocketAddr>) {
        if let Some(first) = self.first {
            gw.audit(
                Some(session),
                None,
                peer,
                SessionAuditKind::MessagesRejected {
                    first: first.to_owned(),
                    count: self.count,
                },
            );
        }
    }
}

/// Sends one message within [`SEND_TIMEOUT`]; `false` if the browser is gone or too slow.
async fn send(socket: &mut WebSocket, msg: &ServerMessage) -> bool {
    match serde_json::to_string(msg) {
        Ok(json) => send_frame(socket, Message::Text(json.into())).await,
        Err(_) => false,
    }
}

/// Sends one WebSocket frame within [`SEND_TIMEOUT`].
async fn send_frame(socket: &mut WebSocket, frame: Message) -> bool {
    matches!(
        tokio::time::timeout(SEND_TIMEOUT, socket.send(frame)).await,
        Ok(Ok(()))
    )
}

async fn send_error(socket: &mut WebSocket, code: &str, message: impl Into<String>) -> bool {
    send(
        socket,
        &ServerMessage::Error {
            code: code.to_owned(),
            message: message.into(),
        },
    )
    .await
}

async fn close_with(socket: &mut WebSocket, reason: &str) {
    let _ = send(
        socket,
        &ServerMessage::Closed {
            reason: reason.to_owned(),
        },
    )
    .await;
    let _ = send_frame(socket, Message::Close(None)).await;
}

/// Reads the next text message, skipping control frames. `None` = socket closed.
async fn next_text(socket: &mut WebSocket) -> Option<String> {
    loop {
        match socket.recv().await? {
            Ok(Message::Text(t)) => return Some(t.as_str().to_owned()),
            Ok(Message::Ping(_) | Message::Pong(_)) => {}
            Ok(Message::Binary(_)) => return Some(String::new()),
            Ok(Message::Close(_)) | Err(_) => return None,
        }
    }
}

/// Waits for the first message (`open` or `resume`) and acts on it. `None`: the socket was
/// already answered and closed (timeout, shutdown, bad first message).
async fn handshake_message(
    socket: &mut WebSocket,
    gw: &Gateway,
    identity: &SessionIdentity,
    peer: Option<SocketAddr>,
) -> Option<Result<(Arc<GatewaySession>, Secret), OpenError>> {
    let first = tokio::select! {
        first = tokio::time::timeout(HANDSHAKE_TIMEOUT, next_text(socket)) => first,
        // A socket still waiting for its first message must not hold up a shutdown.
        () = gw.stopping() => {
            close_with(socket, OpenError::ShuttingDown.code()).await;
            return None;
        }
    };
    let Ok(Some(first)) = first else {
        close_with(socket, "handshake_timeout").await;
        return None;
    };
    match serde_json::from_str::<ClientMessage>(&first) {
        Ok(ClientMessage::Open { profile, options }) => {
            Some(gw.open_session(identity, &profile, &options, peer).await)
        }
        Ok(ClientMessage::OpenCustom { target, options }) => Some(
            gw.open_custom_session(identity, &target, &options, peer)
                .await,
        ),
        Ok(ClientMessage::Resume { session_id, token }) => {
            Some(gw.resume_session(identity, &session_id, &token, peer).await)
        }
        _ => {
            let _ = send_error(
                socket,
                "bad_request",
                "first message must be open or resume",
            )
            .await;
            close_with(socket, "bad_request").await;
            gw.audit(
                None,
                Some(identity),
                peer,
                SessionAuditKind::MessagesRejected {
                    first: "first message must be open or resume".to_owned(),
                    count: 1,
                },
            );
            None
        }
    }
}

/// Entry point after the HTTP upgrade. `identity` was authenticated on the HTTP request.
pub(crate) async fn run(
    mut socket: WebSocket,
    gw: Arc<Gateway>,
    identity: SessionIdentity,
    peer: Option<SocketAddr>,
    handshake: OwnedSemaphorePermit,
) {
    let _connection = gw.metrics().ws_connection();
    let _tracked = gw.track_socket();
    // ── 1. Handshake: `open` or `resume` ────────────────────────────────────────────
    let Some(opened) = handshake_message(&mut socket, &gw, &identity, peer).await else {
        return;
    };

    // The handshake is over: free its place for the next socket.
    drop(handshake);
    let (session, resume_token) = match opened {
        Ok(v) => v,
        Err(err) => {
            let _ = send_error(&mut socket, err.code(), err.to_string()).await;
            close_with(&mut socket, err.code()).await;
            return;
        }
    };

    if !send(
        &mut socket,
        &ServerMessage::Session {
            session_id: session.id().to_string(),
            resume_token: resume_token.expose().to_owned(),
            profile: session.profile().id.clone(),
        },
    )
    .await
    {
        return;
    }

    // ── 2. Attach loop ──────────────────────────────────────────────────────────────
    let (generation, attach_rx) = session.attach();
    let mut rejections = Rejections::default();
    let exit = attach_loop(
        &mut socket,
        &gw,
        &session,
        generation,
        attach_rx,
        &mut rejections,
    )
    .await;
    rejections.audit(&gw, &session, peer);

    // ── 3. Teardown ─────────────────────────────────────────────────────────────────
    match exit {
        Exit::Detached => {
            session.detach(generation);
            gw.audit(Some(&session), None, peer, SessionAuditKind::Detached);
        }
        Exit::RateLimited => {
            gw.metrics().limit_rejections.inc("message_rate");
            close_with(&mut socket, "rate_limited").await;
            session.detach(generation);
            gw.audit(
                Some(&session),
                None,
                peer,
                SessionAuditKind::PolicyDenied {
                    reason: "websocket message rate exceeded".to_owned(),
                },
            );
        }
        Exit::UserClosed => {
            gw.close_session(&session.id(), "user").await;
            close_with(&mut socket, "user").await;
        }
        // Ended by the gateway's own shutdown, not by the host: the browser may reconnect.
        Exit::HostEnded(_) if gw.is_stopping() => close_with(&mut socket, "server_shutdown").await,
        Exit::HostEnded(reason) => {
            if let Some(why) = session.closed_by_gateway() {
                // The gateway ended it (inactivity, lifetime, …) and audited it: say why.
                close_with(&mut socket, why).await;
            } else {
                close_with(&mut socket, "host_disconnected").await;
                gw.close_session(&session.id(), &reason).await;
            }
        }
        Exit::TakenOver => close_with(&mut socket, "taken_over").await,
    }
}

async fn attach_loop(
    socket: &mut WebSocket,
    gw: &Gateway,
    session: &GatewaySession,
    generation: u64,
    mut attach_rx: tokio::sync::watch::Receiver<u64>,
    rejections: &mut Rejections,
) -> Exit {
    let limits = &gw.config().limits;
    let mut limiter = RateLimiter::new(limits.max_messages_per_second);
    let mut snap_rx = session.subscribe();
    snap_rx.mark_changed(); // send the current screen immediately
    let mut last_view: Option<SafeScreenView> = None;
    let mut last_alarm = session.snapshot().alarm_seq; // a resumed tab must not beep
                                                       // Browsers answer pings by themselves: a browser that sends nothing at all for two ping
                                                       // intervals is gone (sleeping laptop, half-open connection) and the session is detached,
                                                       // so the grace period and the reaper apply.
    let ping_interval = Duration::from_secs(limits.ping_interval_secs);
    let mut ping = tokio::time::interval(ping_interval);
    ping.tick().await;
    let mut last_heard = Instant::now();
    // An AID that the host has not answered yet: when it was pressed, and whether the keyboard
    // has been seen locked since (X Wait). The answer is the first frame with the keyboard
    // unlocked again, which is what the operator waits for (local echo of keys typed just
    // before the AID does not count).
    let mut pending_aid: Option<(Instant, bool)> = None;
    let metrics = gw.metrics();

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                last_heard = Instant::now();
                let text = match incoming {
                    None | Some(Err(_) | Ok(Message::Close(_))) => return Exit::Detached,
                    // Control frames cost a reply (pong) and a wake-up too: they count.
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                        if !limiter.allow() { return Exit::RateLimited; }
                        continue;
                    }
                    Some(Ok(Message::Binary(_))) => {
                        if !limiter.allow() { return Exit::RateLimited; }
                        let _ = send_error(socket, "bad_request", "binary frames are not supported").await;
                        rejections.note("binary frame");
                        continue;
                    }
                    Some(Ok(Message::Text(t))) => t,
                };
                if !limiter.allow() {
                    return Exit::RateLimited;
                }
                metrics.ws_messages.inc();
                let flow = if let Ok(msg) = serde_json::from_str::<ClientMessage>(text.as_str()) {
                    if matches!(msg, ClientMessage::Aid { .. }) {
                        pending_aid = Some((Instant::now(), false));
                    }
                    handle_input(socket, gw, session, msg).await
                } else {
                    let _ = send_error(socket, "bad_request", "malformed message").await;
                    Flow::Rejected("malformed message")
                };
                match flow {
                    Flow::Disconnect => return Exit::UserClosed,
                    Flow::Rejected(reason) => rejections.note(reason),
                    Flow::Continue => {}
                }
            }

            changed = snap_rx.changed() => {
                if changed.is_err() {
                    return Exit::HostEnded("host disconnected".to_owned());
                }
                let snap = snap_rx.borrow_and_update().clone();
                let frame = build_frame(gw, session, &snap, &mut last_view, &mut last_alarm);
                if !send(socket, &frame).await {
                    return Exit::Detached;
                }
                metrics.frames_sent.inc();
                if let Some((pressed, seen_locked)) = pending_aid {
                    if snap.keyboard != KeyboardState::Unlocked {
                        pending_aid = Some((pressed, true));
                    } else if seen_locked {
                        metrics.aid_response.observe(pressed.elapsed());
                        pending_aid = None;
                    }
                }
                if snap.state.is_terminal() {
                    return Exit::HostEnded(closed_reason(&snap.state));
                }
            }

            res = attach_rx.changed() => {
                if res.is_err() || *attach_rx.borrow_and_update() != generation {
                    return Exit::TakenOver;
                }
            }

            _ = ping.tick() => {
                if last_heard.elapsed() > ping_interval.saturating_mul(2)
                    || !send_frame(socket, Message::Ping(Vec::new().into())).await
                {
                    return Exit::Detached;
                }
            }
        }
    }
}

fn build_frame(
    gw: &Gateway,
    session: &GatewaySession,
    snap: &Snapshot,
    last_view: &mut Option<SafeScreenView>,
    last_alarm: &mut u64,
) -> ServerMessage {
    let screen = if last_view.as_ref() == Some(&snap.view) {
        None
    } else {
        let ctx = DlpContext {
            identity: session.identity(),
            profile: session.profile(),
        };
        let copy_allowed = gw.extensions().dlp.copy_allowed(&ctx, &snap.view);
        *last_view = Some(snap.view.clone());
        Some(wire_screen(&snap.view, copy_allowed))
    };
    let alarm = snap.alarm_seq != *last_alarm;
    *last_alarm = snap.alarm_seq;
    ServerMessage::Frame {
        seq: snap.seq,
        screen,
        status: wire_status(snap, &session.profile().connection),
        alarm,
    }
}

/// Audits an AID key together with the masked screen it was pressed on, then sends it.
async fn submit_aid(gw: &Gateway, session: &GatewaySession, key: AidKey) {
    gw.metrics().aids.inc();
    let snap = session.snapshot();
    gw.extensions().audit.on_aid_submitted(&AidAuditRecord {
        at: SystemTime::now(),
        session_id: session.id(),
        subject: &session.identity().subject,
        profile_id: &session.profile().id,
        aid: key,
        screen: &snap.view,
        screen_sha256: masked_screen_digest(&snap.view),
    });
    let _ = session.handle().press_aid(key).await;
}

/// The user prints the screen: printing takes it out of the page like a copy, so the copy
/// policy decides; both outcomes are audited (the printed screen by its masked digest).
async fn print_screen(socket: &mut WebSocket, gw: &Gateway, session: &GatewaySession) {
    let snap = session.snapshot();
    let ctx = DlpContext {
        identity: session.identity(),
        profile: session.profile(),
    };
    let kind = if gw.extensions().dlp.copy_allowed(&ctx, &snap.view) {
        SessionAuditKind::ScreenPrinted {
            screen_sha256: crate::extensions::auth::encode_hex(&masked_screen_digest(&snap.view)),
        }
    } else {
        let _ = send_error(socket, "print_denied", "printing is not allowed").await;
        SessionAuditKind::PolicyDenied {
            reason: "print: copying the screen is not allowed".to_owned(),
        }
    };
    gw.audit(Some(session), None, None, kind);
}

async fn handle_input(
    socket: &mut WebSocket,
    gw: &Gateway,
    session: &GatewaySession,
    msg: ClientMessage,
) -> Flow {
    let handle = session.handle();
    if session.input_held() && !matches!(msg, ClientMessage::Disconnect) {
        let _ = send_error(
            socket,
            "input_held",
            "the gateway is logging on; input is held",
        )
        .await;
        return Flow::Continue;
    }
    // Keystroke errors (protected / numeric field, locked keyboard) are *not* reported here:
    // the core locks the keyboard (X PROTECTED / X NUMERIC) and the next frame shows it.
    match msg {
        ClientMessage::Key { ch } => {
            if ch.is_control() {
                let _ = send_error(socket, "bad_request", "control characters are not keys").await;
                return Flow::Rejected("control character");
            }
            let _ = handle.send_key(ch).await;
        }
        ClientMessage::Text { text } => {
            let max = gw.config().limits.max_paste_chars;
            if text.chars().count() > max {
                let _ = send_error(
                    socket,
                    "paste_too_long",
                    format!("paste exceeds {max} characters"),
                )
                .await;
                return Flow::Continue;
            }
            let ctx = DlpContext {
                identity: session.identity(),
                profile: session.profile(),
            };
            if let DlpDecision::Deny { reason } = gw.extensions().dlp.check_paste(&ctx, &text) {
                gw.audit(
                    Some(session),
                    None,
                    None,
                    SessionAuditKind::PolicyDenied {
                        reason: format!("dlp paste: {reason}"),
                    },
                );
                let _ = send_error(socket, "dlp_denied", reason).await;
                return Flow::Continue;
            }
            // The paste rules (margin, no wrap, skipped characters) live in the core.
            let _ = handle.paste(&text).await;
        }
        ClientMessage::Action { action } => {
            let Some(a) = parse_action(&action) else {
                let _ =
                    send_error(socket, "bad_request", format!("unknown action '{action}'")).await;
                return Flow::Rejected("unknown action");
            };
            let _ = handle.send_action(a).await;
        }
        ClientMessage::MoveCursor { row, col } => {
            let view = &session.snapshot().view;
            if row >= view.rows() || col >= view.cols() {
                let _ = send_error(socket, "bad_request", "cursor position out of range").await;
                return Flow::Rejected("cursor position out of range");
            }
            let _ = handle.send_action(ActionKey::MoveCursor { row, col }).await;
        }
        ClientMessage::Aid { aid } => {
            let Some(key) = parse_aid(&aid) else {
                let _ = send_error(socket, "bad_request", format!("unknown aid '{aid}'")).await;
                return Flow::Rejected("unknown aid");
            };
            submit_aid(gw, session, key).await;
        }
        ClientMessage::Attention { key } => {
            let Some(k) = parse_attention(&key) else {
                let _ = send_error(
                    socket,
                    "bad_request",
                    format!("unknown attention key '{key}'"),
                )
                .await;
                return Flow::Rejected("unknown attention key");
            };
            let _ = handle.press_attention(k).await;
        }
        ClientMessage::BlankFill { on } => {
            let _ = handle.set_blank_fill(on).await;
        }
        ClientMessage::Print => print_screen(socket, gw, session).await,
        ClientMessage::Disconnect => return Flow::Disconnect,
        ClientMessage::Open { .. }
        | ClientMessage::OpenCustom { .. }
        | ClientMessage::Resume { .. } => {
            let _ = send_error(socket, "bad_request", "session already established").await;
            return Flow::Rejected("second open or resume");
        }
    }
    // Only input that reached the session is operator activity for the inactivity timeout:
    // a refused message (above: returned early) must not keep an unattended session alive.
    // Keystrokes the core refuses (protected field, locked keyboard) still count: an operator
    // pressed them.
    session.touch();
    Flow::Continue
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_blocks_burst() {
        let mut r = RateLimiter::new(3);
        assert!(r.allow() && r.allow() && r.allow());
        assert!(!r.allow());
    }
}
