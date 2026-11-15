//! Non-blocking bridge between the synchronous `egui` render thread and the async `tokio`
//! [`SessionCoordinator`](bastion3270_net::SessionCoordinator) actor.

use std::sync::{Arc, Mutex};

use bastion3270_core::{ActionKey, AidKey, AttentionKey};
use bastion3270_net::transport::CertificateRejection;
use bastion3270_net::{
    ConnectionProfile, NetError, SessionCoordinator, SessionEvent, SessionHandle, SessionState,
};
use tokio::runtime::{Builder, Handle, Runtime};
use tokio::sync::mpsc;

/// Manages the background Tokio runtime and active [`SessionHandle`] for the GUI.
#[derive(Debug)]
pub struct GuiSessionBridge {
    /// Owned Tokio runtime when running as a standalone desktop binary (`None` if attached to an existing runtime).
    owned_runtime: Option<Runtime>,
    /// Handle to the active Tokio runtime.
    rt_handle: Handle,
    /// Shared slot containing the active [`SessionHandle`] once TCP/TLS connect succeeds.
    active_handle: Arc<Mutex<Option<SessionHandle>>>,
    /// Receiver for [`SessionEvent`] notifications forwarded from the background session task.
    event_rx: Option<mpsc::Receiver<SessionEvent>>,
    /// The host certificate the last connection attempt refused, for the trust dialog.
    refused_certificate: Arc<Mutex<Option<CertificateRejection>>>,
}

impl GuiSessionBridge {
    /// Creates a new [`GuiSessionBridge`], attaching to the current Tokio runtime if one is active,
    /// or building a dedicated background multi-thread Tokio runtime otherwise.
    ///
    /// # Errors
    /// Returns [`NetError::Io`] if the Tokio runtime cannot be initialized.
    pub fn new() -> Result<Self, NetError> {
        if let Ok(handle) = Handle::try_current() {
            Ok(Self {
                owned_runtime: None,
                rt_handle: handle,
                active_handle: Arc::new(Mutex::new(None)),
                event_rx: None,
                refused_certificate: Arc::default(),
            })
        } else {
            let rt = Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("bastion3270-gui-io")
                .enable_all()
                .build()
                .map_err(NetError::Io)?;
            let handle = rt.handle().clone();
            Ok(Self {
                owned_runtime: Some(rt),
                rt_handle: handle,
                active_handle: Arc::new(Mutex::new(None)),
                event_rx: None,
                refused_certificate: Arc::default(),
            })
        }
    }

    /// Attaches an already-spawned [`SessionHandle`] and [`SessionEvent`] receiver directly
    /// (ideal for deterministic in-process loopback testing).
    pub fn attach_session(
        &mut self,
        handle: SessionHandle,
        event_rx: mpsc::Receiver<SessionEvent>,
    ) {
        if let Ok(mut guard) = self.active_handle.lock() {
            *guard = Some(handle);
        }
        self.event_rx = Some(event_rx);
    }

    /// Initiates an asynchronous connection to the given [`ConnectionProfile`] without blocking
    /// the GUI thread.
    ///
    /// Any previous active session is gracefully disconnected first.
    pub fn connect(&mut self, profile: ConnectionProfile) {
        self.disconnect();

        let cap = profile.channel_capacity.max(64);
        let (gui_evt_tx, gui_evt_rx) = mpsc::channel(cap);
        self.event_rx = Some(gui_evt_rx);

        let handle_slot = Arc::clone(&self.active_handle);
        let refused_slot = Arc::clone(&self.refused_certificate);
        if let Ok(mut refused) = refused_slot.lock() {
            *refused = None;
        }

        self.rt_handle.spawn(async move {
            let _ = gui_evt_tx
                .send(SessionEvent::StateChanged(SessionState::Connecting))
                .await;

            match SessionCoordinator::connect(profile).await {
                Ok((handle, mut net_evt_rx, _join_handle)) => {
                    if let Ok(mut guard) = handle_slot.lock() {
                        *guard = Some(handle);
                    }
                    while let Some(evt) = net_evt_rx.recv().await {
                        if gui_evt_tx.send(evt).await.is_err() {
                            break;
                        }
                    }
                    if let Ok(mut guard) = handle_slot.lock() {
                        *guard = None;
                    }
                }
                Err(err) => {
                    // Kept before the error event, so the app finds it when it sees the error.
                    if let NetError::UntrustedCertificate(rejection) = &err {
                        if let Ok(mut refused) = refused_slot.lock() {
                            *refused = Some((**rejection).clone());
                        }
                    }
                    let msg = err.to_string();
                    let _ = gui_evt_tx
                        .send(SessionEvent::StateChanged(SessionState::Error(msg.clone())))
                        .await;
                    let _ = gui_evt_tx.send(SessionEvent::Error(msg)).await;
                }
            }
        });
    }

    /// The host certificate the last connection attempt refused (once).
    pub fn take_refused_certificate(&self) -> Option<CertificateRejection> {
        self.refused_certificate
            .lock()
            .ok()
            .and_then(|mut refused| refused.take())
    }

    /// Returns `true` if there is currently an open [`SessionHandle`].
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.active_handle
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(SessionHandle::is_open))
            .unwrap_or(false)
    }

    /// Returns a clone of the active [`SessionHandle`], if connected.
    #[must_use]
    pub fn session_handle(&self) -> Option<SessionHandle> {
        self.active_handle.lock().ok().and_then(|g| g.clone())
    }

    /// Non-blockingly drains all pending [`SessionEvent`]s accumulated since the last frame.
    pub fn poll_events(&mut self) -> Vec<SessionEvent> {
        let mut events = Vec::new();
        if let Some(rx) = &mut self.event_rx {
            while let Ok(evt) = rx.try_recv() {
                events.push(evt);
            }
        }
        events
    }

    /// Asynchronously sends a single character keystroke to the active session.
    pub fn send_char(&self, ch: char) {
        if let Some(handle) = self.session_handle() {
            self.rt_handle.spawn(async move {
                if let Err(err) = handle.send_key(ch).await {
                    tracing::debug!(target: "bastion3270_gui::bridge", %err, "key not applied");
                }
            });
        }
    }

    /// Pastes text with the operator paste rules of the core (margin, no wrap into protected
    /// fields, unmappable characters skipped).
    pub fn paste(&self, text: String) {
        if let Some(handle) = self.session_handle() {
            self.rt_handle.spawn(async move {
                if let Err(err) = handle.paste(&text).await {
                    tracing::debug!(target: "bastion3270_gui::bridge", %err, "paste not applied");
                }
            });
        }
    }

    /// Asynchronously sends a navigation, editing, or operator reset [`ActionKey`] to the active session.
    pub fn send_action(&self, action: ActionKey) {
        if let Some(handle) = self.session_handle() {
            self.rt_handle.spawn(async move {
                match handle.send_action(action).await {
                    Ok(()) => tracing::debug!(target: "bastion3270_gui::bridge", ?action, "action"),
                    Err(err) => {
                        tracing::debug!(target: "bastion3270_gui::bridge", ?action, %err, "action not applied");
                    }
                }
            });
        }
    }

    /// Asynchronously sends an [`AidKey`] (`Enter`, `PF1`..`PF24`, `PA1`..`PA3`, `Clear`) to the active session.
    pub fn press_aid(&self, aid: AidKey) {
        if let Some(handle) = self.session_handle() {
            self.rt_handle.spawn(async move {
                let _ = handle.press_aid(aid).await;
            });
        }
    }

    /// Asynchronously presses Attn or `SysReq` on the active session.
    pub fn press_attention(&self, key: AttentionKey) {
        if let Some(handle) = self.session_handle() {
            self.rt_handle.spawn(async move {
                let _ = handle.press_attention(key).await;
            });
        }
    }

    /// Gracefully disconnects the active session, if any.
    pub fn disconnect(&mut self) {
        let maybe_handle = self.active_handle.lock().ok().and_then(|mut g| g.take());
        if let Some(handle) = maybe_handle {
            self.rt_handle.spawn(async move {
                let _ = handle.disconnect().await;
            });
        }
    }
}

impl Drop for GuiSessionBridge {
    fn drop(&mut self) {
        self.disconnect();
        if let Some(rt) = self.owned_runtime.take() {
            rt.shutdown_background();
        }
    }
}
