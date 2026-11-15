//! Simulated browsers: one WebSocket session each (WSS with a TLS connector).

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::stats::Stats;

/// A byte stream to the gateway: plain TCP or TLS over TCP.
trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

type Ws = WebSocketStream<Box<dyn Io>>;

/// Longest wait for any single answer from the gateway.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(30);

/// One simulated operator.
#[derive(Debug, Clone)]
pub struct Browser {
    pub(crate) gateway: SocketAddr,
    pub(crate) profile: String,
    pub(crate) think: Duration,
    pub(crate) reopen: bool,
    pub(crate) stop_at: Instant,
    pub(crate) stats: Arc<Stats>,
    pub(crate) phase: Duration,
    pub(crate) tls: Option<Arc<ClientConfig>>,
}

/// Why a session ended before the run did.
#[derive(Debug)]
enum End {
    /// The gateway ended it with a `closed` message; its reason.
    Closed(String),
    /// Anything else, counted as a failure (`timeout`, `dropped`, `send`, `bad_json`).
    Failed(&'static str),
}

impl Browser {
    /// Opens a session and works until `stop_at`: type a few characters, press Enter, wait for
    /// the answering screen (measured), think, repeat. Ends the session with `disconnect`.
    /// Every earlier end is counted: by the gateway's reason ([`Stats::end`]) or as a failure.
    /// With `reopen`, a session the gateway ended is opened again.
    pub async fn run(self) {
        loop {
            let Some(mut ws) = self.open().await else {
                return;
            };
            self.stats.opened.fetch_add(1, Ordering::Relaxed);
            self.stats.active.fetch_add(1, Ordering::Relaxed);
            let end = self.work(&mut ws).await;
            self.stats.active.fetch_sub(1, Ordering::Relaxed);
            match end {
                None => return,
                Some(End::Closed(reason)) => {
                    self.stats.end(&reason);
                    if !self.reopen || Instant::now() >= self.stop_at {
                        return;
                    }
                }
                Some(End::Failed(why)) => {
                    self.stats.fail(why);
                    return;
                }
            }
        }
    }

    /// The operator's work in one session; `None` when it lasted until `stop_at`.
    async fn work(&self, ws: &mut Ws) -> Option<End> {
        let mut panel = None;
        if let Err(end) = self.idle(ws, &mut panel, self.phase).await {
            return Some(end);
        }
        while Instant::now() < self.stop_at {
            if let Err(end) = self.action(ws, &mut panel).await {
                return Some(end);
            }
            if let Err(end) = self.idle(ws, &mut panel, self.think).await {
                return Some(end);
            }
        }
        let _ = send(ws, &json!({"type": "disconnect"})).await;
        let _ = ws.close(None).await;
        None
    }

    /// Waits `pause` while reading what the gateway sends, as a browser does while its
    /// operator thinks: frames update the last panel, and a `closed` ends the session at once
    /// (not unnoticed until the next key is sent into a closed connection).
    async fn idle(&self, ws: &mut Ws, panel: &mut Option<u64>, pause: Duration) -> Result<(), End> {
        let until = Instant::now() + pause;
        loop {
            match next_json(ws, &self.stats, until).await {
                Ok(None) => return Ok(()),
                Ok(Some(m)) => {
                    if let Some(counter) = frame_panel(&m) {
                        *panel = Some(counter);
                    }
                    closed(&m)?;
                }
                Err(why) => return Err(End::Failed(why)),
            }
        }
    }

    async fn open(&self) -> Option<Ws> {
        let scheme = if self.tls.is_some() { "wss" } else { "ws" };
        let mut req = format!("{scheme}://{}/ws", self.gateway)
            .into_client_request()
            .ok()?;
        req.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("bastion3270.v1"),
        );
        let Some(stream) = self.connect().await else {
            self.stats.fail("connect");
            return None;
        };
        let Ok((mut ws, _)) = tokio_tungstenite::client_async(req, stream).await else {
            self.stats.fail("handshake");
            return None;
        };
        if !send(&mut ws, &json!({"type": "open", "profile": self.profile})).await {
            self.stats.fail("send");
            return None;
        }
        match next_json(&mut ws, &self.stats, Instant::now() + ANSWER_TIMEOUT).await {
            Ok(Some(m)) if field(&m, "type") == "session" => Some(ws),
            Ok(None) => {
                self.stats.fail("timeout");
                None
            }
            Ok(Some(m)) => {
                self.stats
                    .fail(field(&m, "code").as_str().unwrap_or("unexpected"));
                None
            }
            Err(why) => {
                self.stats.fail(why);
                None
            }
        }
    }

    /// TCP (Nagle off, as browsers do for WebSocket connections), then TLS if configured.
    async fn connect(&self) -> Option<Box<dyn Io>> {
        let tcp = tokio::net::TcpStream::connect(self.gateway).await.ok()?;
        tcp.set_nodelay(true).ok()?;
        match &self.tls {
            None => Some(Box::new(tcp)),
            Some(config) => {
                let name = ServerName::from(self.gateway.ip());
                let stream = TlsConnector::from(Arc::clone(config))
                    .connect(name, tcp)
                    .await;
                if stream.is_err() {
                    self.stats.fail("tls");
                }
                Some(Box::new(stream.ok()?))
            }
        }
    }

    /// One operator action. `panel` is the counter of the last host panel seen: the answer to
    /// the Enter is the panel with a different counter (frames in between carry status or the
    /// local echo of the typed keys).
    async fn action(&self, ws: &mut Ws, panel: &mut Option<u64>) -> Result<(), End> {
        for ch in ["3", "."] {
            if !send(ws, &json!({"type": "key", "ch": ch})).await {
                return Err(End::Failed("send"));
            }
        }
        let pressed = Instant::now();
        if !send(ws, &json!({"type": "aid", "aid": "enter"})).await {
            return Err(End::Failed("send"));
        }
        let until = pressed + ANSWER_TIMEOUT;
        loop {
            match next_json(ws, &self.stats, until).await {
                Ok(None) => return Err(End::Failed("timeout")),
                Ok(Some(m)) => {
                    closed(&m)?;
                    let Some(counter) = frame_panel(&m) else {
                        continue;
                    };
                    let answered = panel.is_some_and(|before| before != counter);
                    *panel = Some(counter);
                    if answered {
                        self.stats.latency(pressed.elapsed());
                        return Ok(());
                    }
                }
                Err(why) => return Err(End::Failed(why)),
            }
        }
    }
}

/// `Err` with the gateway's reason if `m` is a `closed` message.
fn closed(m: &Value) -> Result<(), End> {
    if field(m, "type") == "closed" {
        let reason = field(m, "reason").as_str().unwrap_or("unknown");
        return Err(End::Closed(reason.to_owned()));
    }
    Ok(())
}

/// The panel counter of a `frame` message with a host panel.
fn frame_panel(m: &Value) -> Option<u64> {
    if field(m, "type") == "frame" {
        panel_counter(field(m, "screen"))
    } else {
        None
    }
}

/// `v[key]`, or `null` (without the panicking-index path the lints forbid).
fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&Value::Null)
}

/// The counter `#nnnnnn` in the title row of a host panel (see [`crate::host::panel`]).
fn panel_counter(screen: &Value) -> Option<u64> {
    let row = field(screen, "text").as_array()?.get(2)?.as_str()?;
    let digits = row.split_once('#')?.1.get(..6)?;
    digits.parse().ok()
}

async fn send(ws: &mut Ws, v: &Value) -> bool {
    ws.send(Message::Text(v.to_string().into())).await.is_ok()
}

/// The next JSON message, `None` if none came before `until`, or why the connection cannot
/// deliver one: `dropped` (it ended without a `closed` message) or `bad_json`.
async fn next_json(
    ws: &mut Ws,
    stats: &Stats,
    until: Instant,
) -> Result<Option<Value>, &'static str> {
    loop {
        let msg = match tokio::time::timeout_at(until.into(), ws.next()).await {
            Err(_) => return Ok(None),
            Ok(None | Some(Err(_))) => return Err("dropped"),
            Ok(Some(Ok(msg))) => msg,
        };
        match msg {
            Message::Text(t) => {
                stats.frames.fetch_add(1, Ordering::Relaxed);
                return serde_json::from_str(t.as_str())
                    .map(Some)
                    .map_err(|_| "bad_json");
            }
            Message::Close(_) => return Err("dropped"),
            _ => {}
        }
    }
}
