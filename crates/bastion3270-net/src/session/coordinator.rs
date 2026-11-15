//! Async session coordinator actor driving network I/O, deterministic state machines,
//! backpressure channels, autonomous responses, and Zero-Trust screen projection.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::Instrument as _;

use bastion3270_core::datastream::build_read_modified;
use bastion3270_core::datastream::parser::DataStreamParser;
use bastion3270_core::datastream::response::AID_PA1;
use bastion3270_core::datastream::sscp::write_sscp_lu;
use bastion3270_core::datastream::{
    Command, DatastreamError, ReadPartitionRequest, RejectKind, AID_READ_PARTITION,
};
use bastion3270_core::ebcdic::CodePage;
use bastion3270_core::keyboard::{
    ActionKey, AidKey, AttentionKey, KeyInput, KeyOutcome, KeyboardError, PasteEnd, PasteOutcome,
    VirtualKeyboard,
};
use bastion3270_core::safe_view::SafeScreenView;
use bastion3270_core::screen::PresentationSpace;
use bastion3270_core::telnet::iac::{BREAK, IAC};
use bastion3270_core::telnet::state_machine::{AttentionRoute, TelnetStateMachine};
use bastion3270_core::telnet::tn3270e::{
    Tn3270eDataType, TN3270E_NEG_COMMAND_REJECT, TN3270E_NEG_OPERATION_CHECK,
    TN3270E_RQF_KEYBOARD_RESTORE, TN3270E_RSF_ALWAYS_RESPONSE, TN3270E_RSF_NO_RESPONSE,
};
use bastion3270_core::telnet::TelnetEvent;
use bastion3270_core::telnet::{BindImageInfo, HostMode, Tn3270eHeader};
use bastion3270_core::wsf::QueryReplyBuilder;

use crate::error::{NetError, Result};
use crate::profile::ConnectionProfile;
use crate::session::command::{SessionCommand, SessionStatus};
use crate::session::event::SessionEvent;
use crate::session::handle::SessionHandle;
use crate::session::state::SessionState;
use crate::transport::{self, TransportStream};

/// Network chunk read buffer size (8 KiB).
const NETWORK_BUFFER_SIZE: usize = 8_192;

/// How long the actor waits for room in a full event channel before it drops the event.
const EVENT_SEND_DEADLINE: Duration = Duration::from_millis(50);

/// Central session coordinator actor bridging transport streams with `bastion3270-core`.
#[derive(Debug)]
pub struct SessionCoordinator {
    profile: ConnectionProfile,
    stream: Option<TransportStream>,
    command_rx: mpsc::Receiver<SessionCommand>,
    event_tx: mpsc::Sender<SessionEvent>,
    state: SessionState,
    telnet: TelnetStateMachine,
    presentation_space: PresentationSpace,
    keyboard: VirtualKeyboard,
    wsf_builder: QueryReplyBuilder<'static>,
    is_tls: bool,
    /// Sequence number and response flag of the TN3270E record being processed while the
    /// host still expects a response to it (x3270 `response_required`).
    pending_response: Option<(u16, u8)>,
    /// Insert mode as last reported to subscribers.
    reported_insert_mode: bool,
    /// Set when an event was dropped because the subscriber did not read in time; the
    /// session loop then re-sends the current state once the channel has room again.
    resync_pending: bool,
}

/// What happened to one inbound 3270 record.
#[derive(Debug, Default)]
struct RecordOutcome {
    /// Set if the record was rejected or aborted part-way.
    rejected: Option<DatastreamError>,
}

impl SessionCoordinator {
    /// Creates a new [`SessionCoordinator`] instance initialized from profile and transport stream.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if terminal model or code page configuration is invalid.
    pub fn new(
        profile: ConnectionProfile,
        stream: TransportStream,
        command_rx: mpsc::Receiver<SessionCommand>,
        event_tx: mpsc::Sender<SessionEvent>,
    ) -> Result<Self> {
        profile.validate()?;

        let core_model = profile.core_terminal_model()?;
        let codepage = profile.core_codepage()?;
        let is_tls = stream.is_tls();

        let telnet = TelnetStateMachine::new(
            core_model,
            profile.color_3279,
            profile.extended,
            profile.lu_name.clone(),
        );
        let presentation_space = PresentationSpace::new(core_model);
        let mut keyboard = VirtualKeyboard::with_options(profile.keyboard_options());
        keyboard.disconnected();
        let wsf_builder =
            QueryReplyBuilder::new(core_model, codepage).with_color(profile.color_3279);

        Ok(Self {
            profile,
            stream: Some(stream),
            command_rx,
            event_tx,
            state: SessionState::Connecting,
            telnet,
            presentation_space,
            keyboard,
            wsf_builder,
            is_tls,
            pending_response: None,
            reported_insert_mode: false,
            resync_pending: false,
        })
    }

    /// Spawns the [`SessionCoordinator`] actor on a background tokio task.
    ///
    /// Returns a [`SessionHandle`], a bounded [`SessionEvent`] receiver, and the task [`JoinHandle`].
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if profile configuration is invalid.
    pub fn spawn(
        profile: ConnectionProfile,
        stream: TransportStream,
    ) -> Result<(
        SessionHandle,
        mpsc::Receiver<SessionEvent>,
        JoinHandle<Result<()>>,
    )> {
        let cap = profile.channel_capacity;
        let (cmd_tx, cmd_rx) = mpsc::channel(cap);
        let (evt_tx, evt_rx) = mpsc::channel(cap);

        let coordinator = Self::new(profile, stream, cmd_rx, evt_tx)?;
        let handle = SessionHandle::new(cmd_tx);

        // The task carries the caller's span (e.g. the gateway's `session` span), so every log
        // line of this session can be attributed to it among many parallel sessions.
        let join_handle = tokio::spawn(async move { coordinator.run().await }.in_current_span());

        Ok((handle, evt_rx, join_handle))
    }

    /// Establishes a transport connection based on the profile, then spawns the coordinator actor.
    ///
    /// # Errors
    /// Returns [`NetError`] if connection establishment or coordinator initialization fails.
    pub async fn connect(
        profile: ConnectionProfile,
    ) -> Result<(
        SessionHandle,
        mpsc::Receiver<SessionEvent>,
        JoinHandle<Result<()>>,
    )> {
        let stream = transport::connect(&profile).await?;
        Self::spawn(profile, stream)
    }

    /// [`SessionCoordinator::connect`] with the application's trust anchors for the host's
    /// certificate ([`HostTrust`](crate::transport::HostTrust)).
    ///
    /// # Errors
    /// Returns [`NetError`] if connection establishment or coordinator initialization fails.
    pub async fn connect_with_trust(
        profile: ConnectionProfile,
        trust: &crate::transport::HostTrust,
    ) -> Result<(
        SessionHandle,
        mpsc::Receiver<SessionEvent>,
        JoinHandle<Result<()>>,
    )> {
        let stream = transport::connect_with_trust(&profile, trust).await?;
        Self::spawn(profile, stream)
    }

    /// Returns the current lifecycle state of the session coordinator.
    #[must_use]
    pub const fn state(&self) -> &SessionState {
        &self.state
    }

    /// Returns a reference to the active [`PresentationSpace`].
    #[must_use]
    pub const fn presentation_space(&self) -> &PresentationSpace {
        &self.presentation_space
    }

    /// Returns a reference to the active [`VirtualKeyboard`].
    #[must_use]
    pub const fn keyboard(&self) -> &VirtualKeyboard {
        &self.keyboard
    }

    /// Returns a reference to the active [`TelnetStateMachine`].
    #[must_use]
    pub const fn telnet(&self) -> &TelnetStateMachine {
        &self.telnet
    }

    /// Returns a reference to the active [`ConnectionProfile`].
    #[must_use]
    pub const fn profile(&self) -> &ConnectionProfile {
        &self.profile
    }

    /// Returns `true` if the underlying transport connection is TLS encrypted.
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        self.is_tls
    }

    /// Runs the asynchronous actor event loop using `tokio::select!`.
    ///
    /// # Event Loop Structure
    /// - **Branch 1:** Inbound network packets from mainframe.
    /// - **Branch 2:** User commands from UI / CLI channel.
    /// - **Branch 3:** Negotiation deadline (until the Telnet negotiation is complete).
    /// - **Branch 4:** Idle silence timeout guard.
    ///
    /// # Errors
    /// Returns [`NetError`] if an unrecoverable I/O or protocol error occurs.
    pub async fn run(mut self) -> Result<()> {
        let stream = self.stream.take().ok_or_else(|| {
            NetError::protocol("SessionCoordinator::run called without active stream")
        })?;

        let (mut reader, mut writer) = stream.into_split();

        // 1. Initial State Transition: Negotiating. The keyboard stays locked until the host
        //    writes the first screen (x3270 `kybd_connect`).
        self.transition_state(SessionState::Negotiating).await;
        self.keyboard.connected();
        self.emit_keyboard_state().await;

        // 2. Telnet negotiation is purely reactive (as in x3270): the client sends nothing
        //    until the host asks, so the loop below starts by reading.

        let mut net_buf = [0u8; NETWORK_BUFFER_SIZE];
        let idle_timeout = Duration::from_millis(self.profile.idle_timeout_ms);
        let mut last_activity = tokio::time::Instant::now();
        // Host traffic does not extend this one: a host trickling bytes cannot keep a
        // session negotiating forever. A timeout too large to represent as an `Instant`
        // (`checked_add` is `None`) never expires; plain `+` would panic on it.
        let negotiation_deadline =
            last_activity.checked_add(Duration::from_millis(self.profile.negotiation_timeout_ms));

        let codepage = self.profile.core_codepage()?;

        // A clone used only to wait for room in the event channel (branch 5): a permit
        // borrowed from `self.event_tx` would keep `self` borrowed in every other branch.
        let resync_tx = self.event_tx.clone();

        let run_result: Result<()> = loop {
            let idle_deadline = last_activity.checked_add(idle_timeout);

            tokio::select! {
                // ─── Branch 1: Inbound Network Data ─────────────────────────────
                read_res = reader.read(&mut net_buf) => {
                    match read_res {
                        Ok(0) => {
                            // Clean EOF from remote host
                            tracing::info!(target: "bastion3270_net::session", "remote host closed connection (EOF)");
                            break Ok(());
                        }
                        Ok(n) => {
                            last_activity = tokio::time::Instant::now();
                            let Some(chunk) = net_buf.get(..n) else {
                                break Err(NetError::protocol("read buffer bounds overflow"));
                            };

                            if let Err(err) = self.handle_network_chunk(chunk, &mut writer, codepage).await {
                                break Err(err);
                            }
                        }
                        Err(io_err) => {
                            tracing::error!(target: "bastion3270_net::session", %io_err, "network read error");
                            break Err(NetError::Io(io_err));
                        }
                    }
                }

                // ─── Branch 2: User Commands ────────────────────────────────────
                cmd_opt = self.command_rx.recv() => {
                    let Some(cmd) = cmd_opt else {
                        // All handles dropped; graceful shutdown
                        tracing::debug!(target: "bastion3270_net::session", "all command handles dropped; shutting down");
                        break Ok(());
                    };

                    // Local operator activity also counts as session activity
                    last_activity = tokio::time::Instant::now();

                    if !self.handle_command(cmd, &mut writer, codepage).await {
                        break Ok(());
                    }
                }

                // ─── Branch 3: Negotiation Deadline ─────────────────────────────
                () = tokio::time::sleep_until(negotiation_deadline.unwrap_or(last_activity)),
                    if self.state == SessionState::Negotiating && negotiation_deadline.is_some() =>
                {
                    tracing::warn!(
                        target: "bastion3270_net::session",
                        timeout_ms = self.profile.negotiation_timeout_ms,
                        "Telnet negotiation did not complete in time"
                    );
                    break Err(NetError::NegotiationTimeout);
                }

                // ─── Branch 4: Inactivity Silence Timeout ─────────────────────────
                () = tokio::time::sleep_until(idle_deadline.unwrap_or(last_activity)),
                    if self.profile.idle_timeout_ms > 0 && idle_deadline.is_some() =>
                {
                    tracing::warn!(
                        target: "bastion3270_net::session",
                        timeout_ms = self.profile.idle_timeout_ms,
                        "session idle silence timeout expired without host packets"
                    );
                    break Err(NetError::IdleTimeout);
                }

                // ─── Branch 5: Re-send the current state after dropped events ───
                // Waits for room in the channel; the permit is released at once (the actor
                // is the only sender, so the slot stays free for the snapshot's first event).
                open = async { resync_tx.reserve().await.is_ok() }, if self.resync_pending => {
                    self.resync_pending = false;
                    if open {
                        self.emit_state_snapshot(codepage).await;
                    }
                }
            }
        };

        // 3. Final State Termination and Shutdown
        self.finalize_session(run_result, &mut writer).await
    }

    async fn handle_network_chunk(
        &mut self,
        chunk: &[u8],
        writer: &mut WriteHalf<TransportStream>,
        codepage: &'static dyn CodePage,
    ) -> Result<()> {
        let events = self.telnet.process_inbound(chunk).map_err(NetError::from)?;

        // Immediately flush any outbound negotiation responses generated by state machine
        self.flush_outbound_negotiation(writer).await?;

        for event in events {
            match event {
                TelnetEvent::NegotiationComplete {
                    tn3270e,
                    functions,
                    assigned_lu,
                } => {
                    self.transition_state(SessionState::Connected3270).await;
                    self.emit_event(SessionEvent::NegotiationComplete {
                        is_tn3270e: tn3270e,
                        assigned_lu,
                    })
                    .await;
                    self.keyboard.entered_3270(tn3270e);
                    let mode = if tn3270e && functions.bind_image {
                        HostMode::Unbound
                    } else {
                        HostMode::Data3270
                    };
                    self.keyboard.set_host_mode(mode);
                    self.emit_keyboard_state().await;
                    self.emit_event(SessionEvent::HostModeChanged(mode)).await;
                    self.run_typeahead(writer, codepage).await?;
                }
                TelnetEvent::DataRecord(record) => {
                    // Plain TN3270 has no negative response: a rejected record is logged and
                    // the session continues (x3270 `process_eor()`).
                    let outcome = self
                        .execute_3270_record(&record, false, writer, codepage)
                        .await?;
                    if let Some(err) = &outcome.rejected {
                        tracing::warn!(target: "bastion3270_net::session", %err, "3270 record rejected");
                    }
                }
                TelnetEvent::Tn3270eRecord { header, payload } => {
                    self.handle_tn3270e_record(header, &payload, writer, codepage)
                        .await?;
                }
                TelnetEvent::SscpLuData(data) => {
                    self.handle_sscp_lu(&data, writer, codepage).await?;
                }
                TelnetEvent::HostModeChanged(mode) => {
                    tracing::debug!(target: "bastion3270_net::session", ?mode, "host mode changed");
                    self.keyboard.set_host_mode(mode);
                    self.emit_keyboard_state().await;
                    self.emit_event(SessionEvent::HostModeChanged(mode)).await;
                }
                TelnetEvent::NvtData { data, ack } => {
                    // `x3270` `process_eor` NVT-DATA: positive response only for
                    // ALWAYS-RESPONSE.
                    if let Some(seq) = ack {
                        let resp = self
                            .telnet
                            .frame_positive_response(seq)
                            .map_err(NetError::from)?;
                        self.write_host(writer, &resp).await?;
                    }
                    self.emit_event(SessionEvent::NvtData(data)).await;
                }
                TelnetEvent::BindImage(bind) => self.handle_bind(&bind, codepage).await,
                TelnetEvent::RecordDiscarded(err) => {
                    tracing::warn!(target: "bastion3270_net::session", %err, "inbound record discarded");
                }
                TelnetEvent::Tn3270eBackoff(why) => {
                    tracing::warn!(target: "bastion3270_net::session", %why, "falling back from TN3270E to TN3270");
                }
                TelnetEvent::Unbind(reason) => self.handle_unbind(reason, codepage).await,
            }
        }

        Ok(())
    }

    /// A TN3270E record other than BIND, UNBIND, NVT or SSCP-LU data (`x3270` `process_eor`).
    async fn handle_tn3270e_record(
        &mut self,
        header: Tn3270eHeader,
        payload: &[u8],
        writer: &mut WriteHalf<TransportStream>,
        codepage: &'static dyn CodePage,
    ) -> Result<()> {
        if header.data_type == Tn3270eDataType::Data3270 {
            // TN3270E KEYBOARD-RESTORE request flag (x3270 `process_ds` →
            // `restore_keyboard`).
            let restore = header.request_flag & TN3270E_RQF_KEYBOARD_RESTORE != 0;
            // The response the host asked for (x3270 `response_required`).
            // ALWAYS-RESPONSE is satisfied by a positive response sent *before*
            // the first reply data (`net_output`); see `send_record`.
            self.pending_response = (header.response_flag != TN3270E_RSF_NO_RESPONSE)
                .then_some((header.seq_number, header.response_flag));
            let outcome = self
                .execute_3270_record(payload, restore, writer, codepage)
                .await?;
            let pending = self.pending_response.take();

            // RFC 2355 §10.4 / x3270 `process_eor()`: a rejected record gets a
            // negative response while a response is still owed; a successful one
            // without output gets its positive response now. The session
            // continues either way.
            if let Some(err) = &outcome.rejected {
                tracing::warn!(target: "bastion3270_net::session", %err, "3270 record rejected");
                if let Some((seq, _)) = pending {
                    let reason = match err.reject_kind() {
                        RejectKind::CommandReject => TN3270E_NEG_COMMAND_REJECT,
                        RejectKind::OperationCheck => TN3270E_NEG_OPERATION_CHECK,
                    };
                    let neg = self
                        .telnet
                        .frame_negative_response(seq, reason)
                        .map_err(NetError::from)?;
                    self.write_host(writer, &neg).await?;
                }
            } else if let Some((seq, TN3270E_RSF_ALWAYS_RESPONSE)) = pending {
                let resp = self
                    .telnet
                    .frame_positive_response(seq)
                    .map_err(NetError::from)?;
                self.write_host(writer, &resp).await?;
            }
        } else {
            // SCS, REQUEST, RESPONSE and other types are not for a display terminal; x3270
            // `process_eor` ignores them without a response.
            tracing::debug!(target: "bastion3270_net::session", data_type = ?header.data_type, "TN3270E record ignored");
        }
        Ok(())
    }

    /// SSCP-LU data (`x3270` `ctlr_write_sscp_lu`): shown as unformatted text, then the
    /// keyboard is reset. No response is ever sent for it.
    async fn handle_sscp_lu(
        &mut self,
        data: &[u8],
        writer: &mut WriteHalf<TransportStream>,
        codepage: &'static dyn CodePage,
    ) -> Result<()> {
        if let Err(err) = write_sscp_lu(&mut self.presentation_space, data) {
            tracing::warn!(target: "bastion3270_net::session", %err, "SSCP-LU data not shown");
        }
        self.keyboard.host_reset();
        self.emit_screen(codepage).await;
        self.emit_keyboard_state().await;
        self.run_typeahead(writer, codepage).await
    }

    /// BIND (`x3270` `process_bind`): takes the BIND screen sizes (if valid) and erases to the
    /// default size. The keyboard follows the mode change reported just before
    /// ([`TelnetEvent::HostModeChanged`]).
    async fn handle_bind(&mut self, bind: &BindImageInfo, codepage: &'static dyn CodePage) {
        if let Err(err) = self.presentation_space.apply_bind(bind.sizes) {
            tracing::warn!(target: "bastion3270_net::session", %err, "BIND screen size ignored");
            self.emit_event(SessionEvent::Warning(err.to_string()))
                .await;
        }
        self.emit_screen(codepage).await;
    }

    /// UNBIND (`x3270` `process_eor`): back to the model sizes, screen erased; the keyboard
    /// waits for the next BIND (mode change to unbound).
    ///
    /// Not a warning: a normal UNBIND is part of every logon (the VTAM / USS session ends, the
    /// application binds); `x3270` only traces it. The operator sees the mode change in the OIA.
    async fn handle_unbind(&mut self, reason: u8, codepage: &'static dyn CodePage) {
        tracing::debug!(
            target: "bastion3270_net::session",
            reason = unbind_reason(reason),
            code = reason,
            "UNBIND"
        );
        self.presentation_space.unbind();
        self.emit_screen(codepage).await;
    }

    /// Executes one 3270 record and sends the replies it requires.
    ///
    /// Data stream errors are not fatal: whatever was applied before the error stays applied
    /// and is shown, and the rejection is returned for the caller to report to the host.
    /// Only I/O errors (the connection itself failing) end the session.
    async fn execute_3270_record(
        &mut self,
        record: &[u8],
        keyboard_restore: bool,
        writer: &mut WriteHalf<TransportStream>,
        codepage: &'static dyn CodePage,
    ) -> Result<RecordOutcome> {
        let mut outcome = RecordOutcome::default();
        if record.is_empty() {
            return Ok(outcome);
        }

        let cmd_res = DataStreamParser::process(record, &mut self.presentation_space);
        outcome.rejected.clone_from(&cmd_res.rejected);

        // Side-effects from WCC
        if cmd_res.sound_alarm {
            self.emit_event(SessionEvent::Alarm).await;
        }

        // Host-side keyboard rules: every Write ends the AID wait (with WCC restore it resets
        // the keyboard), Erase All Unprotected and the TN3270E KEYBOARD-RESTORE flag restore it
        // (x3270 `ctlr_write`, `ctlr_erase_all_unprotected`, `restore_keyboard`).
        match cmd_res.command {
            _ if cmd_res.screen_written => self.keyboard.host_write(cmd_res.restore_keyboard),
            _ => {}
        }
        if keyboard_restore {
            self.keyboard.host_reset();
        }

        // Autonomous replies to WSF Read Partition (Query, Query List, RB / RM / RMA).
        if cmd_res.command == Command::WriteStructuredField {
            for request in &cmd_res.read_partition {
                let reply = match request {
                    // Validated by the parser; invalid queries were rejected there.
                    ReadPartitionRequest::Query(query) => {
                        self.wsf_builder.build_from_request(query)
                    }
                    ReadPartitionRequest::ReadBuffer => {
                        bastion3270_core::datastream::build_read_buffer_with_aid(
                            &self.presentation_space,
                            AID_READ_PARTITION,
                        )
                    }
                    ReadPartitionRequest::ReadModified { all } => {
                        bastion3270_core::datastream::build_read_modified(
                            &self.presentation_space,
                            AID_READ_PARTITION,
                            *all,
                        )
                    }
                };
                self.send_record(writer, &reply).await?;
                if matches!(request, ReadPartitionRequest::Query(_)) {
                    // x3270 `query_reply_end`: input waits for the next host write.
                    self.keyboard.enter_inhibit();
                }
            }
        } else if cmd_res.requires_inbound_reply && cmd_res.command == Command::ReadBuffer {
            // x3270 `process_ds`: answered with the current AID.
            let rb_bytes = bastion3270_core::datastream::build_read_buffer_with_aid(
                &self.presentation_space,
                self.keyboard.current_aid(),
            );
            self.send_record(writer, &rb_bytes).await?;
        } else if cmd_res.requires_inbound_reply
            && (cmd_res.command == Command::ReadModified
                || cmd_res.command == Command::ReadModifiedAll)
        {
            let all = cmd_res.command == Command::ReadModifiedAll;
            // x3270 `process_ds`: answered with the current AID (a short read after PA / Clear).
            let rm_bytes = bastion3270_core::datastream::build_read_modified(
                &self.presentation_space,
                self.keyboard.current_aid(),
                all,
            );
            self.send_record(writer, &rm_bytes).await?;
        }

        // Screen updated: project SafeScreenView and emit event
        let safe_view = SafeScreenView::from_presentation_space(&self.presentation_space, codepage);
        self.emit_event(SessionEvent::ScreenUpdated(safe_view))
            .await;
        self.emit_keyboard_state().await;

        // Keys typed while the host was busy run now (x3270 `ps_process`).
        self.run_typeahead(writer, codepage).await?;

        Ok(outcome)
    }

    /// Runs one operator input through the keyboard (lock policy and typeahead, see
    /// [`VirtualKeyboard::submit`]) and sends what it produces. Input dropped because the
    /// keyboard is locked rings the bell, as in x3270 (`enq_xta`), so nothing is lost silently.
    /// Types a secret only while the cursor is in an unprotected non-display field and the
    /// keyboard is unlocked (so nothing is queued for later, when the cursor may be elsewhere).
    /// Checked before every character: a field shorter than the secret would otherwise let
    /// auto-skip carry the rest into the next, possibly visible, field.
    async fn handle_secret(
        &mut self,
        text: &str,
        writer: &mut WriteHalf<TransportStream>,
        codepage: &'static dyn CodePage,
    ) -> Result<()> {
        for ch in text.chars() {
            let cursor = self.presentation_space.cursor_addr();
            if self.keyboard.is_locked() || !self.presentation_space.is_hidden_input(cursor) {
                return Err(NetError::protocol(
                    "secret refused: the cursor is not in an unprotected non-display field",
                ));
            }
            self.handle_key_input(KeyInput::Char(ch), writer, codepage)
                .await?;
        }
        Ok(())
    }

    async fn handle_key_input(
        &mut self,
        input: KeyInput,
        writer: &mut WriteHalf<TransportStream>,
        codepage: &'static dyn CodePage,
    ) -> Result<()> {
        let res = self
            .keyboard
            .submit(&mut self.presentation_space, input, codepage);
        self.emit_keyboard_state().await;
        match res {
            Ok(KeyOutcome::Applied) => {
                self.emit_screen(codepage).await;
                Ok(())
            }
            Ok(KeyOutcome::Queued) => Ok(()),
            Ok(KeyOutcome::Transmit(bytes)) => {
                if input == KeyInput::Aid(AidKey::Clear) {
                    // Clear erased the screen locally.
                    self.emit_screen(codepage).await;
                }
                self.send_record(writer, &bytes).await
            }
            Err(err) => {
                let mouse = matches!(input, KeyInput::Action(ActionKey::MoveCursor { .. }));
                if matches!(err, KeyboardError::Locked(_)) && !mouse {
                    self.emit_event(SessionEvent::Alarm).await;
                }
                Err(NetError::from(err))
            }
        }
    }

    /// Executes one operator command; `false` ends the session (disconnect requested).
    async fn handle_command(
        &mut self,
        cmd: SessionCommand,
        writer: &mut WriteHalf<TransportStream>,
        codepage: &'static dyn CodePage,
    ) -> bool {
        match cmd {
            SessionCommand::InputChar { ch, respond_to } => {
                let res = self
                    .handle_key_input(KeyInput::Char(ch), writer, codepage)
                    .await;
                if let Some(resp) = respond_to {
                    let _ = resp.send(res);
                }
            }
            SessionCommand::InputSecret { text, respond_to } => {
                let res = self.handle_secret(text.expose(), writer, codepage).await;
                if let Some(resp) = respond_to {
                    let _ = resp.send(res);
                }
            }
            SessionCommand::Paste { text, respond_to } => {
                let res = self.handle_paste(&text, codepage).await;
                if let Some(resp) = respond_to {
                    let _ = resp.send(res);
                }
            }
            SessionCommand::InputAction { action, respond_to } => {
                let res = self
                    .handle_key_input(KeyInput::Action(action), writer, codepage)
                    .await;
                if let Some(resp) = respond_to {
                    let _ = resp.send(res);
                }
            }
            SessionCommand::PressAid { aid, respond_to } => {
                let res = self
                    .handle_key_input(KeyInput::Aid(aid), writer, codepage)
                    .await;
                if let Some(resp) = respond_to {
                    let _ = resp.send(res);
                }
            }
            SessionCommand::PressAttention { key, respond_to } => {
                let res = self.handle_attention(key, writer, codepage).await;
                if let Some(resp) = respond_to {
                    let _ = resp.send(res);
                }
            }
            SessionCommand::QueryScreen { respond_to } => {
                let safe_view =
                    SafeScreenView::from_presentation_space(&self.presentation_space, codepage);
                let _ = respond_to.send(safe_view);
            }
            SessionCommand::QueryStatus { respond_to } => {
                let status = self.build_status();
                let _ = respond_to.send(status);
            }
            SessionCommand::SetBlankFill(on) => self.keyboard.set_blank_fill(on),
            SessionCommand::Disconnect => {
                tracing::info!(target: "bastion3270_net::session", "client requested disconnect");
                return false;
            }
        }
        true
    }

    /// An operator paste ([`VirtualKeyboard::paste`]); a refused character sounds the alarm.
    async fn handle_paste(
        &mut self,
        text: &str,
        codepage: &'static dyn CodePage,
    ) -> Result<PasteOutcome> {
        let res = self
            .keyboard
            .paste(&mut self.presentation_space, text, codepage);
        self.emit_keyboard_state().await;
        self.emit_screen(codepage).await;
        match res {
            Ok(outcome) => {
                if matches!(outcome.end, PasteEnd::Rejected(_)) {
                    self.emit_event(SessionEvent::Alarm).await;
                }
                Ok(outcome)
            }
            Err(err) => {
                self.emit_event(SessionEvent::Alarm).await;
                Err(NetError::from(err))
            }
        }
    }

    /// Replays queued typeahead keys while the keyboard is unlocked (x3270 `run_ta`); stops by
    /// itself when an AID locks the keyboard again. Only I/O errors are returned.
    async fn run_typeahead(
        &mut self,
        writer: &mut WriteHalf<TransportStream>,
        codepage: &'static dyn CodePage,
    ) -> Result<()> {
        while let Some(input) = self.keyboard.pop_typeahead() {
            match self.handle_key_input(input, writer, codepage).await {
                Err(NetError::Io(err)) => return Err(NetError::Io(err)),
                Err(err) => {
                    tracing::debug!(target: "bastion3270_net::session", %err, "typeahead key rejected");
                }
                Ok(()) => {}
            }
        }
        Ok(())
    }

    /// Sends one inbound 3270 record. If the host record being processed asked for
    /// ALWAYS-RESPONSE, the positive response goes out first and the request is satisfied
    /// (x3270 `net_output`).
    async fn send_record(
        &mut self,
        writer: &mut WriteHalf<TransportStream>,
        record: &[u8],
    ) -> Result<()> {
        if let Some((seq, TN3270E_RSF_ALWAYS_RESPONSE)) = self.pending_response {
            self.pending_response = None;
            let ack = self
                .telnet
                .frame_positive_response(seq)
                .map_err(NetError::from)?;
            self.write_host(writer, &ack).await?;
        }
        let framed = self
            .telnet
            .frame_outbound_3270(record)
            .map_err(NetError::from)?;
        self.write_host(writer, &framed).await?;
        Ok(())
    }

    async fn emit_screen(&mut self, codepage: &'static dyn CodePage) {
        let safe_view = SafeScreenView::from_presentation_space(&self.presentation_space, codepage);
        self.emit_event(SessionEvent::ScreenUpdated(safe_view))
            .await;
    }

    async fn emit_keyboard_state(&mut self) {
        self.emit_event(SessionEvent::KeyboardStateChanged(self.keyboard.state()))
            .await;
        let insert = self.keyboard.insert_mode();
        if insert != self.reported_insert_mode {
            self.reported_insert_mode = insert;
            self.emit_event(SessionEvent::InsertModeChanged(insert))
                .await;
        }
    }

    /// Sends Attn or `SysReq` the way the current connection mode requires (`x3270`
    /// `Attn_action`, `SysReq_action`); the decision is made by the Telnet state machine.
    async fn handle_attention(
        &mut self,
        key: AttentionKey,
        writer: &mut WriteHalf<TransportStream>,
        codepage: &'static dyn CodePage,
    ) -> Result<()> {
        let wire = match self.telnet.attention_route(key) {
            AttentionRoute::TelnetCommand(cmd) => vec![IAC, cmd],
            AttentionRoute::Pa1ThenBreak => {
                // Attn ignores the keyboard lock: it exists to interrupt a host that is busy.
                let read = build_read_modified(&self.presentation_space, AID_PA1, false);
                let mut wire = self
                    .telnet
                    .frame_outbound_3270(&read)
                    .map_err(NetError::from)?;
                wire.extend_from_slice(&[IAC, BREAK]);
                wire
            }
            AttentionRoute::TestRequest => {
                return self
                    .handle_key_input(KeyInput::SysReq, writer, codepage)
                    .await;
            }
            AttentionRoute::NotAvailable => {
                self.keyboard.not_available();
                self.emit_keyboard_state().await;
                return Ok(());
            }
            AttentionRoute::Ignored => {
                tracing::debug!(target: "bastion3270_net::session", ?key, "attention key has no effect in the current mode");
                return Ok(());
            }
        };
        self.write_host(writer, &wire).await?;
        Ok(())
    }

    fn build_status(&self) -> SessionStatus {
        let (cursor_row, cursor_col) = self
            .presentation_space
            .cursor_addr()
            .to_row_col(self.presentation_space.cols());

        SessionStatus {
            state: self.state.clone(),
            keyboard_state: self.keyboard.state(),
            cursor_row,
            cursor_col,
            is_formatted: self.presentation_space.is_formatted(),
            terminal_model: self.profile.terminal_model,
            assigned_lu: self.telnet.assigned_lu().map(String::from),
            is_tn3270e: self.telnet.is_tn3270e(),
            is_tls: self.is_tls,
        }
    }

    /// Sends one event to the subscriber. If the bounded channel stays full for 50 ms the
    /// event is dropped, so a stalled subscriber cannot stall the host connection; the
    /// session is marked for a resync, and the session loop re-sends the current state
    /// ([`Self::emit_state_snapshot`]) as soon as the subscriber reads again. Every state
    /// event carries a full value (latest wins), so the subscriber ends up consistent; only
    /// transient events (alarm, warning, NVT text) dropped in that window are lost.
    async fn emit_event(&mut self, event: SessionEvent) {
        if let Err(mpsc::error::TrySendError::Full(evt)) = self.event_tx.try_send(event) {
            if tokio::time::timeout(EVENT_SEND_DEADLINE, self.event_tx.send(evt))
                .await
                .is_err()
            {
                if !self.resync_pending {
                    tracing::warn!(
                        target: "bastion3270_net::session",
                        "event channel full for more than 50 ms; dropping events until the subscriber reads again"
                    );
                }
                self.resync_pending = true;
            }
        }
    }

    /// Re-sends every state the subscriber tracks, with its current value: lifecycle,
    /// negotiation result, host mode, screen, keyboard and insert mode.
    async fn emit_state_snapshot(&mut self, codepage: &'static dyn CodePage) {
        self.emit_event(SessionEvent::StateChanged(self.state.clone()))
            .await;
        if self.state == SessionState::Connected3270 {
            self.emit_event(SessionEvent::NegotiationComplete {
                is_tn3270e: self.telnet.is_tn3270e(),
                assigned_lu: self.telnet.assigned_lu().map(String::from),
            })
            .await;
            self.emit_event(SessionEvent::HostModeChanged(self.telnet.host_mode()))
                .await;
        }
        self.emit_screen(codepage).await;
        self.emit_event(SessionEvent::KeyboardStateChanged(self.keyboard.state()))
            .await;
        self.reported_insert_mode = self.keyboard.insert_mode();
        self.emit_event(SessionEvent::InsertModeChanged(self.reported_insert_mode))
            .await;
    }

    async fn transition_state(&mut self, next_state: SessionState) {
        self.state = next_state.clone();
        self.emit_event(SessionEvent::StateChanged(next_state))
            .await;
    }

    /// Deadline for one write to the host.
    const fn write_timeout(&self) -> Duration {
        Duration::from_millis(self.profile.write_timeout_ms)
    }

    /// Writes `bytes` to the host and flushes, within the write deadline. Every write to the
    /// host goes through here: the session loop awaits writes inline, so a host that stops
    /// reading (zero TCP window) would otherwise block the loop — and its idle timeout and
    /// disconnect command — forever.
    async fn write_host(
        &self,
        writer: &mut WriteHalf<TransportStream>,
        bytes: &[u8],
    ) -> Result<()> {
        let write = async {
            writer.write_all(bytes).await?;
            writer.flush().await
        };
        match tokio::time::timeout(self.write_timeout(), write).await {
            Ok(result) => result.map_err(NetError::Io),
            Err(_) => Err(NetError::WriteTimeout),
        }
    }

    async fn flush_outbound_negotiation(
        &mut self,
        writer: &mut WriteHalf<TransportStream>,
    ) -> Result<()> {
        let outbound = self.telnet.take_outbound();
        if !outbound.is_empty() {
            self.write_host(writer, &outbound).await?;
        }
        Ok(())
    }

    async fn finalize_session(
        &mut self,
        result: Result<()>,
        writer: &mut WriteHalf<TransportStream>,
    ) -> Result<()> {
        // Attempt a clean transport shutdown, bounded like every other write.
        let _ = tokio::time::timeout(self.write_timeout(), writer.shutdown()).await;
        self.keyboard.disconnected();
        self.emit_keyboard_state().await;

        match result {
            Ok(()) => {
                self.transition_state(SessionState::Disconnected).await;
                self.emit_event(SessionEvent::Disconnected).await;
                Ok(())
            }
            Err(err) => {
                let err_str = err.to_string();
                self.transition_state(SessionState::Error(err_str.clone()))
                    .await;
                self.emit_event(SessionEvent::Error(err_str)).await;
                Err(err)
            }
        }
    }
}

/// The UNBIND reason as text (`x3270` `telnet.c` `unbind_reason`).
const fn unbind_reason(reason: u8) -> &'static str {
    match reason {
        0x01 => "normal",
        0x02 => "BIND forthcoming",
        0x07 => "virtual route inoperative",
        0x08 => "route extension inoperative",
        0x09 => "hierarchical reset",
        0x0A => "SSCP gone",
        0x0B => "virtual route deactivated",
        0x0C => "unrecoverable LU failure",
        0x0E => "recoverable LU failure",
        0x0F => "cleanup",
        0xFE => "bad sense code or user-supplied sense code",
        _ => "unknown",
    }
}
