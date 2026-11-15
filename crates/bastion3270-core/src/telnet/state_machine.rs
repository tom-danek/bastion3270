//! 8-State RFC 854 byte processor, option negotiation, and RFC 2355 response framing engine.

use crate::keyboard::AttentionKey;
use crate::model::TerminalModel;
use crate::telnet::iac::{
    format_do, format_dont, format_will, format_wont, AO, DO, DONT, EOR, IAC, IP, SB, SE,
    TELOPT_BINARY, TELOPT_ECHO, TELOPT_EOR, TELOPT_SGA, TELOPT_TN3270E, TELOPT_TTYPE, TELQUAL_IS,
    TELQUAL_SEND, WILL, WONT,
};
use crate::telnet::tn3270e::{
    BindImageInfo, Tn3270eBackoff, Tn3270eDataType, Tn3270eFunctions, Tn3270eHeader, EH_SIZE,
    TN3270E_OP_CONNECT, TN3270E_OP_DEVICE_TYPE, TN3270E_OP_FUNCTIONS, TN3270E_OP_IS,
    TN3270E_OP_REJECT, TN3270E_OP_REQUEST, TN3270E_OP_SEND, TN3270E_POS_DEVICE_END,
    TN3270E_RSF_ALWAYS_RESPONSE, TN3270E_RSF_NEGATIVE_RESPONSE, TN3270E_RSF_NO_RESPONSE,
    TN3270E_RSF_POSITIVE_RESPONSE,
};
use crate::telnet::{HostMode, TelnetError, TelnetEvent};

/// Maximum size of an incoming record buffer (64 KiB) before returning [`TelnetError::FrameTooLarge`].
pub const MAX_RECORD_BYTES: usize = 65_536;

/// Maximum size of an incoming subnegotiation buffer (1 KiB).
pub const MAX_SUBNEG_BYTES: usize = 1_024;

/// Maximum size of the outbound queue (128 KiB).
pub const MAX_OUTBOUND_QUEUE_BYTES: usize = 131_072;

/// The 8 states of the RFC 854 Telnet byte parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TelnetState {
    /// Normal data stream byte accumulation.
    #[default]
    Data,
    /// Preceding byte was `IAC` (0xFF).
    Iac,
    /// Expecting option code following `WILL`.
    Will,
    /// Expecting option code following `WONT`.
    Wont,
    /// Expecting option code following `DO`.
    Do,
    /// Expecting option code following `DONT`.
    Dont,
    /// Accumulating subnegotiation parameter bytes.
    Subnegotiation,
    /// Preceding byte inside subnegotiation was `IAC`.
    SubnegotiationIac,
}

/// Internal session mode of the Telnet / TN3270E connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionSubmode {
    /// Initial disconnected / unnegotiated state.
    #[default]
    Init,
    /// TERMINAL-TYPE answered, waiting for BINARY / EOR or TN3270E.
    TtypeNegotiated,
    /// TN3270E device type negotiation in progress.
    Tn3270eNegotiatingDeviceType,
    /// TN3270E functions negotiation in progress.
    Tn3270eNegotiatingFunctions,
    /// TN3270E active but unbound (awaiting BIND-IMAGE RU).
    Tn3270eUnbound,
    /// TN3270E active and bound (ready for 3270 data).
    Tn3270eActive,
    /// TN3270E in SSCP-LU mode: the host sent SSCP-LU data (`x3270` `E_SSCP`).
    Tn3270eSscpLu,
    /// TN3270E in NVT mode: the host sent NVT data (`x3270` `E_NVT`).
    Tn3270eNvt,
    /// Traditional TN3270 active (no TN3270E headers).
    Tn3270Active,
}

impl SessionSubmode {
    /// `true` for the submodes that only exist while TN3270E is (being) negotiated.
    const fn is_tn3270e(self) -> bool {
        matches!(
            self,
            Self::Tn3270eNegotiatingDeviceType
                | Self::Tn3270eNegotiatingFunctions
                | Self::Tn3270eUnbound
                | Self::Tn3270eActive
                | Self::Tn3270eSscpLu
                | Self::Tn3270eNvt
        )
    }
}

/// State of the Telnet options on one side of the connection, indexed by option code
/// (`x3270` `myopts` / `hisopts`).
#[derive(Debug, Clone)]
struct OptionFlags([bool; 256]);

impl OptionFlags {
    const fn new() -> Self {
        Self([false; 256])
    }

    fn is_on(&self, opt: u8) -> bool {
        self.0.get(usize::from(opt)).copied().unwrap_or(false)
    }

    fn set(&mut self, opt: u8, on: bool) {
        if let Some(flag) = self.0.get_mut(usize::from(opt)) {
            *flag = on;
        }
    }
}

/// Options the client agrees to perform when the host sends `DO` (`x3270` `TNS_DO`).
const fn client_supports(opt: u8) -> bool {
    matches!(
        opt,
        TELOPT_BINARY | TELOPT_EOR | TELOPT_TTYPE | TELOPT_SGA | TELOPT_TN3270E
    )
}

/// Options the client lets the host perform when the host sends `WILL` (`x3270` `TNS_WILL`).
const fn host_may_perform(opt: u8) -> bool {
    matches!(
        opt,
        TELOPT_BINARY | TELOPT_EOR | TELOPT_TTYPE | TELOPT_SGA | TELOPT_ECHO | TELOPT_TN3270E
    )
}

/// How an [`AttentionKey`] is carried in the current connection mode (`x3270` `Attn_action`,
/// `SysReq_action`, `net_interrupt`, `net_abort`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttentionRoute {
    /// Send this Telnet command on its own: `IAC IP` for Attn on a bound TN3270E session,
    /// `IAC AO` for `SysReq` when the SYSREQ function was negotiated (RFC 2355 §10.5).
    TelnetCommand(u8),
    /// Plain TN3270 Attn: a short Read Modified with AID PA1, followed by `IAC BREAK`
    /// (what PCOMM does; `x3270` `Attn_action`).
    Pa1ThenBreak,
    /// Plain TN3270 `SysReq`: a *test request* read (`x3270` `key_AID(AID_SYSREQ)`).
    TestRequest,
    /// The function is not available now (Attn on a TN3270E session without a BIND): the
    /// keyboard shows `X -f` until `Reset`.
    NotAvailable,
    /// The key has no meaning in the current state (not in 3270 mode, or `SysReq` on a
    /// TN3270E session without the SYSREQ function or without an active 3270 session).
    Ignored,
}

/// The 3270 mode the connection is in, as last reported through
/// [`TelnetEvent::NegotiationComplete`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode3270 {
    /// Not (yet) in 3270 mode.
    None,
    /// Plain TN3270 (RFC 1576).
    Tn3270,
    /// TN3270E (RFC 2355).
    Tn3270e,
}

/// Pure, deterministic Telnet & TN3270E protocol state machine.
///
/// Option negotiation is purely reactive, as in `x3270`: the client never offers an option
/// on its own, it answers the host's `DO` / `WILL` requests. After every change of an option
/// or of the TN3270E state, [`Self::check_mode`] recomputes the 3270 mode (the counterpart of
/// `x3270` `check_in3270`), so entering and leaving TN3270E always goes through one place.
#[allow(clippy::struct_excessive_bools)] // independent protocol and configuration flags
#[derive(Debug)]
pub struct TelnetStateMachine {
    state: TelnetState,
    submode: SessionSubmode,
    /// Options the client performs (`x3270` `myopts`).
    my_opts: OptionFlags,
    /// Options the host performs (`x3270` `hisopts`).
    his_opts: OptionFlags,
    /// Mode last reported to the session layer.
    mode: Mode3270,
    // TN3270E state (`x3270` `tn3270e_init`)
    tn3270e_negotiated: bool,
    /// Requested functions while negotiating, agreed functions afterwards (`x3270` `e_funcs`).
    functions: Tn3270eFunctions,
    bound: bool,
    // Configuration
    model: TerminalModel,
    color_3279: bool,
    extended: bool,
    requested_lu: Option<String>,
    assigned_lu: Option<String>,
    // Client-to-host sequence number (15-bit, 0..=32767)
    xmit_seq: u16,
    // Buffers adhering to strict capacity bounds
    record_buffer: Vec<u8>,
    /// Bytes of the current record dropped because it exceeded [`MAX_RECORD_BYTES`]; while
    /// non-zero, input is discarded until the next `IAC EOR` (resynchronisation).
    oversize_bytes: usize,
    subneg_buffer: Vec<u8>,
    outbound_queue: Vec<u8>,
}

impl TelnetStateMachine {
    /// Creates a new [`TelnetStateMachine`] configured with terminal model, color, and optional LU.
    #[must_use]
    pub fn new(
        model: TerminalModel,
        color_3279: bool,
        extended: bool,
        requested_lu: Option<String>,
    ) -> Self {
        Self {
            state: TelnetState::Data,
            submode: SessionSubmode::Init,
            my_opts: OptionFlags::new(),
            his_opts: OptionFlags::new(),
            mode: Mode3270::None,
            tn3270e_negotiated: false,
            functions: Tn3270eFunctions::REQUESTED,
            bound: false,
            model,
            color_3279,
            extended,
            requested_lu,
            assigned_lu: None,
            xmit_seq: 0,
            record_buffer: Vec::with_capacity(4096),
            oversize_bytes: 0,
            subneg_buffer: Vec::with_capacity(256),
            outbound_queue: Vec::with_capacity(1024),
        }
    }

    /// Returns the current parser state.
    #[must_use]
    pub const fn state(&self) -> TelnetState {
        self.state
    }

    /// Returns the current session submode.
    #[must_use]
    pub const fn submode(&self) -> SessionSubmode {
        self.submode
    }

    /// What the host is currently exchanging with the terminal (`x3270` `check_in3270`).
    #[must_use]
    pub const fn host_mode(&self) -> HostMode {
        match self.submode {
            SessionSubmode::Tn3270Active | SessionSubmode::Tn3270eActive => HostMode::Data3270,
            SessionSubmode::Tn3270eSscpLu => HostMode::SscpLu,
            SessionSubmode::Tn3270eNvt => HostMode::Nvt,
            SessionSubmode::Tn3270eUnbound => HostMode::Unbound,
            SessionSubmode::Init
            | SessionSubmode::TtypeNegotiated
            | SessionSubmode::Tn3270eNegotiatingDeviceType
            | SessionSubmode::Tn3270eNegotiatingFunctions => HostMode::Negotiating,
        }
    }

    /// Returns `true` if TN3270E negotiation has completed successfully.
    #[must_use]
    pub const fn is_tn3270e(&self) -> bool {
        self.tn3270e_negotiated
    }

    /// Returns `true` if session is currently bound by an SNA BIND RU.
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        self.bound
    }

    /// Returns the currently assigned LU name, if any.
    #[must_use]
    pub fn assigned_lu(&self) -> Option<&str> {
        self.assigned_lu.as_deref()
    }

    /// Returns the requested LU name, if any.
    #[must_use]
    pub fn requested_lu(&self) -> Option<&str> {
        self.requested_lu.as_deref()
    }

    /// Returns the TN3270E functions: the requested set while negotiating, the agreed set once
    /// [`Self::is_tn3270e`] is `true`.
    #[must_use]
    pub const fn functions(&self) -> Tn3270eFunctions {
        self.functions
    }

    /// Returns configured terminal model.
    #[must_use]
    pub const fn model(&self) -> TerminalModel {
        self.model
    }

    /// Returns `true` if 3279 color is configured.
    #[must_use]
    pub const fn color_3279(&self) -> bool {
        self.color_3279
    }

    /// Returns `true` if extended attributes are configured.
    #[must_use]
    pub const fn extended(&self) -> bool {
        self.extended
    }

    /// Returns number of queued outbound bytes.
    #[must_use]
    pub fn outbound_queue_len(&self) -> usize {
        self.outbound_queue.len()
    }

    /// Drains and returns all queued outbound network bytes.
    pub fn take_outbound(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outbound_queue)
    }

    /// Decides how `key` must be sent in the current mode (`x3270` `Attn_action`,
    /// `SysReq_action`).
    #[must_use]
    pub fn attention_route(&self, key: AttentionKey) -> AttentionRoute {
        match key {
            AttentionKey::Attn if self.in_e() => {
                // `net_bound()`: Attn needs an SNA session the host has bound.
                if self.tn3270e_negotiated && self.functions.bind_image && self.bound {
                    AttentionRoute::TelnetCommand(IP)
                } else {
                    AttentionRoute::NotAvailable
                }
            }
            AttentionKey::SysReq if self.in_e() => {
                // `net_abort()`: only with SYSREQ, and only in 3270 (or SSCP-LU) mode.
                if self.tn3270e_negotiated
                    && self.functions.sysreq
                    && matches!(
                        self.submode,
                        SessionSubmode::Tn3270eActive | SessionSubmode::Tn3270eSscpLu
                    )
                {
                    AttentionRoute::TelnetCommand(AO)
                } else {
                    AttentionRoute::Ignored
                }
            }
            AttentionKey::Attn if self.mode == Mode3270::Tn3270 => AttentionRoute::Pa1ThenBreak,
            AttentionKey::SysReq if self.mode == Mode3270::Tn3270 => AttentionRoute::TestRequest,
            AttentionKey::Attn | AttentionKey::SysReq => AttentionRoute::Ignored,
        }
    }

    /// `true` while the client performs TN3270E, i.e. records carry the 5-byte TN3270E header
    /// (`x3270` `IN_E`: from `WILL TN3270E` until the option is negotiated off).
    fn in_e(&self) -> bool {
        self.my_opts.is_on(TELOPT_TN3270E)
    }

    /// Recomputes the 3270 mode after an option or TN3270E state change (`x3270`
    /// `check_in3270`) and reports entering a 3270 mode as
    /// [`TelnetEvent::NegotiationComplete`].
    ///
    /// * TN3270E is in effect while the client performs the TN3270E option; it is complete once
    ///   the functions are agreed.
    /// * Otherwise plain TN3270 is in effect once the client performs BINARY, EOR and
    ///   TERMINAL-TYPE and the host performs BINARY and EOR.
    /// * When TN3270E has been negotiated off, its state (functions, BIND, sequence numbers,
    ///   assigned LU) is cleared, so later records are framed and parsed without the TN3270E
    ///   header.
    fn check_mode(&mut self) -> Option<TelnetEvent> {
        if !self.in_e() && (self.tn3270e_negotiated || self.submode.is_tn3270e()) {
            self.reset_tn3270e();
        }

        let mode = if self.in_e() {
            if self.tn3270e_negotiated {
                Mode3270::Tn3270e
            } else {
                Mode3270::None
            }
        } else if self.my_opts.is_on(TELOPT_BINARY)
            && self.my_opts.is_on(TELOPT_EOR)
            && self.my_opts.is_on(TELOPT_TTYPE)
            && self.his_opts.is_on(TELOPT_BINARY)
            && self.his_opts.is_on(TELOPT_EOR)
        {
            self.submode = SessionSubmode::Tn3270Active;
            self.bound = true;
            Mode3270::Tn3270
        } else {
            if self.submode == SessionSubmode::Tn3270Active {
                self.submode = SessionSubmode::TtypeNegotiated;
                self.bound = false;
            }
            Mode3270::None
        };

        if mode == self.mode {
            return None;
        }
        self.mode = mode;
        match mode {
            Mode3270::None => None,
            Mode3270::Tn3270 => Some(TelnetEvent::NegotiationComplete {
                tn3270e: false,
                functions: Tn3270eFunctions::default(),
                assigned_lu: None,
            }),
            Mode3270::Tn3270e => Some(TelnetEvent::NegotiationComplete {
                tn3270e: true,
                functions: self.functions,
                assigned_lu: self.assigned_lu.clone(),
            }),
        }
    }

    /// Clears all TN3270E state (`x3270` `tn3270e_init`).
    fn reset_tn3270e(&mut self) {
        self.tn3270e_negotiated = false;
        self.functions = Tn3270eFunctions::REQUESTED;
        self.bound = false;
        self.xmit_seq = 0;
        self.assigned_lu = None;
        if self.submode.is_tn3270e() {
            self.submode = SessionSubmode::Init;
        }
    }

    /// Abandons TN3270E (`x3270` `backoff_tn3270e`): tells the host `WONT TN3270E` and falls
    /// back to plain TN3270 negotiation.
    fn backoff_tn3270e(&mut self, why: Tn3270eBackoff) -> Result<TelnetEvent, TelnetError> {
        self.queue_bytes(&format_wont(TELOPT_TN3270E))?;
        self.my_opts.set(TELOPT_TN3270E, false);
        self.reset_tn3270e();
        Ok(TelnetEvent::Tn3270eBackoff(why))
    }

    /// Ingests an incoming slice of network bytes, drives the 8-state parser,
    /// and returns any completed high-level events.
    ///
    /// # Errors
    /// Returns [`TelnetError`] if the subnegotiation or outbound queue limits are exceeded.
    /// Problems with an individual record (oversized, malformed TN3270E header, unknown data
    /// type, invalid BIND image) are not errors: the record is dropped and reported as
    /// [`TelnetEvent::RecordDiscarded`].
    pub fn process_inbound(&mut self, chunk: &[u8]) -> Result<Vec<TelnetEvent>, TelnetError> {
        let mut events = Vec::new();
        // NVT text of this chunk; reported before the next Telnet command and at the end.
        let mut nvt = Vec::new();

        for &byte in chunk {
            match self.state {
                TelnetState::Data => {
                    if byte == IAC {
                        self.state = TelnetState::Iac;
                    } else {
                        self.data_byte(byte, &mut nvt);
                    }
                }
                TelnetState::Iac => {
                    if byte != IAC {
                        Self::flush_nvt(&mut nvt, &mut events);
                    }
                    match byte {
                        IAC => {
                            // Doubled IAC collapses to literal 0xFF
                            self.data_byte(IAC, &mut nvt);
                            self.state = TelnetState::Data;
                        }
                        EOR => {
                            // End of record: process accumulated frame. A mode change the
                            // record causes is reported before the record itself.
                            let before = self.host_mode();
                            let event = self.process_eor();
                            let after = self.host_mode();
                            if after != before {
                                events.push(TelnetEvent::HostModeChanged(after));
                            }
                            if let Some(e) = event {
                                events.push(e);
                            }
                            self.record_buffer.clear();
                            self.state = TelnetState::Data;
                        }
                        WILL => self.state = TelnetState::Will,
                        WONT => self.state = TelnetState::Wont,
                        DO => self.state = TelnetState::Do,
                        DONT => self.state = TelnetState::Dont,
                        SB => {
                            self.subneg_buffer.clear();
                            self.state = TelnetState::Subnegotiation;
                        }
                        _ => {
                            // Other Telnet commands (NOP, GA, DM, etc.) ignored
                            self.state = TelnetState::Data;
                        }
                    }
                }
                TelnetState::Will => {
                    self.handle_will(byte)?;
                    self.state = TelnetState::Data;
                    events.extend(self.check_mode());
                }
                TelnetState::Wont => {
                    self.handle_wont(byte)?;
                    self.state = TelnetState::Data;
                    events.extend(self.check_mode());
                }
                TelnetState::Do => {
                    self.handle_do(byte)?;
                    self.state = TelnetState::Data;
                    events.extend(self.check_mode());
                }
                TelnetState::Dont => {
                    self.handle_dont(byte)?;
                    self.state = TelnetState::Data;
                    events.extend(self.check_mode());
                }
                TelnetState::Subnegotiation => {
                    if byte == IAC {
                        self.state = TelnetState::SubnegotiationIac;
                    } else {
                        self.push_subneg_byte(byte)?;
                    }
                }
                TelnetState::SubnegotiationIac => {
                    if byte == SE {
                        events.extend(self.handle_subnegotiation()?);
                        events.extend(self.check_mode());
                        self.subneg_buffer.clear();
                        self.state = TelnetState::Data;
                    } else if byte == IAC {
                        // Doubled IAC inside subnegotiation
                        self.push_subneg_byte(IAC)?;
                        self.state = TelnetState::Subnegotiation;
                    } else {
                        self.state = TelnetState::Subnegotiation;
                    }
                }
            }
        }

        Self::flush_nvt(&mut nvt, &mut events);
        Ok(events)
    }

    fn push_subneg_byte(&mut self, byte: u8) -> Result<(), TelnetError> {
        if self.subneg_buffer.len() >= MAX_SUBNEG_BYTES {
            return Err(TelnetError::SubnegotiationTooLarge {
                size: self.subneg_buffer.len().saturating_add(1),
                max: MAX_SUBNEG_BYTES,
            });
        }
        self.subneg_buffer.push(byte);
        Ok(())
    }

    fn queue_bytes(&mut self, bytes: &[u8]) -> Result<(), TelnetError> {
        let needed = self.outbound_queue.len().saturating_add(bytes.len());
        if needed > MAX_OUTBOUND_QUEUE_BYTES {
            return Err(TelnetError::OutboundQueueFull {
                size: needed,
                max: MAX_OUTBOUND_QUEUE_BYTES,
            });
        }
        self.outbound_queue.extend_from_slice(bytes);
        Ok(())
    }

    /// Host asks the client to perform an option (`x3270` `TNS_DO`). A supported option is
    /// acknowledged once with `WILL`; anything else is refused with `WONT`.
    fn handle_do(&mut self, opt: u8) -> Result<(), TelnetError> {
        if !client_supports(opt) {
            return self.queue_bytes(&format_wont(opt));
        }
        if !self.my_opts.is_on(opt) {
            self.my_opts.set(opt, true);
            self.queue_bytes(&format_will(opt))?;
        }
        Ok(())
    }

    /// Host tells the client to stop performing an option (`x3270` `TNS_DONT`). Only an
    /// option that is on is acknowledged, so a repeated `DONT` causes no loop.
    fn handle_dont(&mut self, opt: u8) -> Result<(), TelnetError> {
        if self.my_opts.is_on(opt) {
            self.my_opts.set(opt, false);
            self.queue_bytes(&format_wont(opt))?;
        }
        Ok(())
    }

    /// Host offers to perform an option (`x3270` `TNS_WILL`). An acceptable option is
    /// acknowledged once with `DO`; anything else is refused with `DONT`. When the host starts
    /// doing EOR, the client volunteers EOR too.
    fn handle_will(&mut self, opt: u8) -> Result<(), TelnetError> {
        if !host_may_perform(opt) {
            return self.queue_bytes(&format_dont(opt));
        }
        if !self.his_opts.is_on(opt) {
            self.his_opts.set(opt, true);
            self.queue_bytes(&format_do(opt))?;
            if opt == TELOPT_EOR && !self.my_opts.is_on(TELOPT_EOR) {
                self.my_opts.set(TELOPT_EOR, true);
                self.queue_bytes(&format_will(TELOPT_EOR))?;
            }
        }
        Ok(())
    }

    /// Host stops performing an option (`x3270` `TNS_WONT`). An option that was on is
    /// acknowledged with `DONT`. A host that answers `WONT TN3270E` where it should send
    /// `DONT TN3270E` also turns off the client side of TN3270E.
    fn handle_wont(&mut self, opt: u8) -> Result<(), TelnetError> {
        if self.his_opts.is_on(opt) {
            self.his_opts.set(opt, false);
            self.queue_bytes(&format_dont(opt))?;
        } else if opt == TELOPT_TN3270E && self.my_opts.is_on(TELOPT_TN3270E) {
            self.my_opts.set(TELOPT_TN3270E, false);
            self.queue_bytes(&format_wont(TELOPT_TN3270E))?;
        }
        Ok(())
    }

    fn handle_subnegotiation(&mut self) -> Result<Option<TelnetEvent>, TelnetError> {
        let Some(opt) = self.subneg_buffer.first().copied() else {
            return Ok(None);
        };

        match opt {
            TELOPT_TTYPE => {
                if self.subneg_buffer.get(1).copied() == Some(TELQUAL_SEND) {
                    let mut termtype = self
                        .model
                        .terminal_type_name(self.color_3279, self.extended)
                        .to_string();
                    if let Some(ref lu) = self.requested_lu {
                        termtype.push('@');
                        termtype.push_str(lu);
                    }
                    let mut resp = Vec::with_capacity(6_usize.saturating_add(termtype.len()));
                    resp.extend_from_slice(&[IAC, SB, TELOPT_TTYPE, TELQUAL_IS]);
                    resp.extend_from_slice(termtype.as_bytes());
                    resp.extend_from_slice(&[IAC, SE]);
                    self.queue_bytes(&resp)?;
                    if !self.submode.is_tn3270e() {
                        self.submode = SessionSubmode::TtypeNegotiated;
                    }
                }
            }
            // TN3270E subnegotiation only counts while the client performs TN3270E.
            TELOPT_TN3270E if self.in_e() => {
                return self.handle_tn3270e_subneg();
            }
            _ => {}
        }

        Ok(None)
    }

    /// Sends a TN3270E `FUNCTIONS REQUEST` / `FUNCTIONS IS` with `funcs` (`x3270`
    /// `tn3270e_subneg_send`).
    fn send_functions(&mut self, op: u8, funcs: Tn3270eFunctions) -> Result<(), TelnetError> {
        let mut msg = vec![IAC, SB, TELOPT_TN3270E, TN3270E_OP_FUNCTIONS, op];
        msg.extend(funcs.encode());
        msg.extend_from_slice(&[IAC, SE]);
        self.queue_bytes(&msg)
    }

    /// Sends the TN3270E `DEVICE-TYPE REQUEST` (`x3270` `tn3270e_request`). The device type
    /// is always a 3278, as RFC 2355 requires.
    fn send_device_type_request(&mut self) -> Result<(), TelnetError> {
        let termtype = self.model.terminal_type_name(false, self.extended);
        let mut msg = Vec::with_capacity(32);
        msg.extend_from_slice(&[
            IAC,
            SB,
            TELOPT_TN3270E,
            TN3270E_OP_DEVICE_TYPE,
            TN3270E_OP_REQUEST,
        ]);
        msg.extend_from_slice(termtype.as_bytes());
        if let Some(ref lu) = self.requested_lu {
            msg.push(TN3270E_OP_CONNECT);
            msg.extend_from_slice(lu.as_bytes());
        }
        msg.extend_from_slice(&[IAC, SE]);
        self.queue_bytes(&msg)
    }

    /// TN3270E subnegotiation (`x3270` `tn3270e_negotiate`, RFC 2355 §7).
    fn handle_tn3270e_subneg(&mut self) -> Result<Option<TelnetEvent>, TelnetError> {
        let op = self.subneg_buffer.get(1).copied();
        let qualifier = self.subneg_buffer.get(2).copied();

        match (op, qualifier) {
            (Some(TN3270E_OP_SEND), Some(TN3270E_OP_DEVICE_TYPE)) => {
                self.send_device_type_request()?;
                self.submode = SessionSubmode::Tn3270eNegotiatingDeviceType;
            }
            (Some(TN3270E_OP_DEVICE_TYPE), Some(TN3270E_OP_IS)) => {
                // IS <device-type> [CONNECT <device-name>]
                let rest = self.subneg_buffer.get(3..).unwrap_or(&[]);
                self.assigned_lu = rest
                    .iter()
                    .position(|&b| b == TN3270E_OP_CONNECT)
                    .and_then(|pos| rest.get(pos.saturating_add(1)..))
                    .and_then(|lu| core::str::from_utf8(lu).ok())
                    .map(str::trim)
                    .filter(|lu| !lu.is_empty())
                    .map(str::to_string);

                // Tell the host what we can do.
                self.send_functions(TN3270E_OP_REQUEST, self.functions)?;
                self.submode = SessionSubmode::Tn3270eNegotiatingFunctions;
            }
            (Some(TN3270E_OP_DEVICE_TYPE), Some(TN3270E_OP_REJECT)) => {
                // REJECT REASON <code>. With at most one LU configured there is nothing else
                // to try, so the client always backs off to plain TN3270.
                let reason = self.subneg_buffer.get(4).copied();
                return self
                    .backoff_tn3270e(Tn3270eBackoff::DeviceTypeRejected { reason })
                    .map(Some);
            }
            (Some(TN3270E_OP_FUNCTIONS), Some(TN3270E_OP_REQUEST)) => {
                // The host proposes a function set.
                let (wanted, foreign) =
                    Tn3270eFunctions::decode(self.subneg_buffer.get(3..).unwrap_or(&[]));
                if !foreign && wanted.is_subset_of(self.functions) {
                    // What we want, or less: accept it. Negotiation is complete.
                    self.functions = wanted;
                    self.send_functions(TN3270E_OP_IS, wanted)?;
                    self.complete_tn3270e();
                } else {
                    // Something we cannot do: request the common subset.
                    self.functions = self.functions.intersection(wanted);
                    self.send_functions(TN3270E_OP_REQUEST, self.functions)?;
                }
            }
            (Some(TN3270E_OP_FUNCTIONS), Some(TN3270E_OP_IS)) => {
                // The host accepts our last request, or a subset of it.
                let (agreed, foreign) =
                    Tn3270eFunctions::decode(self.subneg_buffer.get(3..).unwrap_or(&[]));
                if foreign || !agreed.is_subset_of(self.functions) {
                    return self
                        .backoff_tn3270e(Tn3270eBackoff::FunctionsAdded)
                        .map(Some);
                }
                self.functions = agreed;
                self.complete_tn3270e();
            }
            _ => {}
        }

        Ok(None)
    }

    /// Marks TN3270E negotiation complete. Without BIND-IMAGE the session is in 3270 mode
    /// straight away; with it, 3270 data waits for the host's BIND.
    fn complete_tn3270e(&mut self) {
        self.tn3270e_negotiated = true;
        if self.functions.bind_image {
            self.submode = SessionSubmode::Tn3270eUnbound;
            self.bound = false;
        } else {
            self.submode = SessionSubmode::Tn3270eActive;
            self.bound = true;
        }
    }

    /// Appends a byte to the current record, enforcing [`MAX_RECORD_BYTES`].
    ///
    /// An oversized record is not fatal: its bytes are dropped (memory stays bounded) and the
    /// record is reported as discarded at its `IAC EOR`, after which normal processing resumes.
    fn push_record_byte(&mut self, byte: u8) {
        if self.oversize_bytes > 0 || self.record_buffer.len() >= MAX_RECORD_BYTES {
            if self.oversize_bytes == 0 {
                self.oversize_bytes = self.record_buffer.len();
                self.record_buffer.clear();
                self.record_buffer.shrink_to(4096);
            }
            self.oversize_bytes = self.oversize_bytes.saturating_add(1);
        } else {
            self.record_buffer.push(byte);
        }
    }

    /// A data byte: NVT text while no 3270 mode is in effect and TN3270E is not being
    /// negotiated, otherwise part of the current record (`x3270` `telnet_fsm`: `IN_NVT &&
    /// !IN_E` → `nvt_process`, else `store3270in`). NVT text therefore never ends up in
    /// front of the first 3270 record.
    fn data_byte(&mut self, byte: u8, nvt: &mut Vec<u8>) {
        if self.mode == Mode3270::None && !self.in_e() {
            if nvt.len() < MAX_RECORD_BYTES {
                nvt.push(byte);
            }
        } else {
            self.push_record_byte(byte);
        }
    }

    /// Reports collected NVT text as one event.
    fn flush_nvt(nvt: &mut Vec<u8>, events: &mut Vec<TelnetEvent>) {
        if !nvt.is_empty() {
            events.push(TelnetEvent::NvtData {
                data: core::mem::take(nvt),
                ack: None,
            });
        }
    }

    /// Handles a complete record at `IAC EOR`.
    ///
    /// Record-level problems never end the session (`x3270` `process_eor()` ignores unknown
    /// data types and invalid BIND images); they are reported as
    /// [`TelnetEvent::RecordDiscarded`] so the session layer can log them.
    fn process_eor(&mut self) -> Option<TelnetEvent> {
        if self.oversize_bytes > 0 {
            let size = self.oversize_bytes;
            self.oversize_bytes = 0;
            return Some(TelnetEvent::RecordDiscarded(TelnetError::FrameTooLarge {
                size,
                max: MAX_RECORD_BYTES,
            }));
        }
        if self.mode == Mode3270::None {
            // NVT or negotiation in progress (`x3270` `telnet_fsm`: only `IN_3270 || (IN_E
            // && tn3270e_negotiated)` processes a record).
            return Some(TelnetEvent::RecordDiscarded(TelnetError::NotIn3270Mode));
        }
        if self.record_buffer.is_empty() {
            return None;
        }

        if !self.in_e() {
            return Some(TelnetEvent::DataRecord(self.record_buffer.clone()));
        }

        // In TN3270E, peel 5-byte header
        let header = match Tn3270eHeader::parse(&self.record_buffer) {
            Ok(header) => header,
            Err(err) => return Some(TelnetEvent::RecordDiscarded(err)),
        };
        let payload = self.record_buffer.get(EH_SIZE..).unwrap_or(&[]).to_vec();

        match header.data_type {
            Tn3270eDataType::Data3270 => {
                if self.functions.bind_image && !self.bound {
                    // Ignore 3270 data while unbound
                    None
                } else {
                    // `x3270` `process_eor`: 3270 data puts the session in 3270 mode (for
                    // example after SSCP-LU data).
                    self.submode = SessionSubmode::Tn3270eActive;
                    Some(TelnetEvent::Tn3270eRecord { header, payload })
                }
            }
            // BIND and UNBIND only exist with the BIND-IMAGE function, BID only with
            // CONTENTION-RESOLUTION, which this client never requests (`x3270` `process_eor`).
            Tn3270eDataType::BindImage | Tn3270eDataType::Unbind if !self.functions.bind_image => {
                Some(TelnetEvent::RecordDiscarded(
                    TelnetError::FunctionNotNegotiated(header.data_type.as_u8()),
                ))
            }
            Tn3270eDataType::Bid => Some(TelnetEvent::RecordDiscarded(
                TelnetError::FunctionNotNegotiated(header.data_type.as_u8()),
            )),
            Tn3270eDataType::BindImage => match BindImageInfo::parse(&payload, self.model) {
                Ok(info) => {
                    self.bound = true;
                    self.submode = SessionSubmode::Tn3270eActive;
                    Some(TelnetEvent::BindImage(info))
                }
                Err(err) => {
                    // `x3270` `process_eor`: a malformed BIND still binds the session (3270
                    // data is accepted from now on) but changes neither screen nor submode.
                    self.bound = true;
                    Some(TelnetEvent::RecordDiscarded(err))
                }
            },
            Tn3270eDataType::Unbind => {
                let reason = payload.first().copied().unwrap_or(0);
                self.bound = false;
                self.submode = SessionSubmode::Tn3270eUnbound;
                Some(TelnetEvent::Unbind(reason))
            }
            Tn3270eDataType::NvtData => {
                self.submode = SessionSubmode::Tn3270eNvt;
                let ack = (header.response_flag == TN3270E_RSF_ALWAYS_RESPONSE)
                    .then_some(header.seq_number);
                Some(TelnetEvent::NvtData { data: payload, ack })
            }
            // Accepted bound or not (`x3270` `process_eor`).
            Tn3270eDataType::SscpLuData => {
                self.submode = SessionSubmode::Tn3270eSscpLu;
                Some(TelnetEvent::SscpLuData(payload))
            }
            _ => Some(TelnetEvent::Tn3270eRecord { header, payload }),
        }
    }

    /// Frames an outbound 3270 datastream record.
    ///
    /// Prepends the 5-byte header (if in TN3270E mode), escapes IAC bytes (`0xFF -> 0xFF 0xFF`),
    /// and appends `IAC EOR` (`0xFF 0xEF`).
    ///
    /// # Errors
    /// Returns [`TelnetError`] if framing fails.
    pub fn frame_outbound_3270(&mut self, record: &[u8]) -> Result<Vec<u8>, TelnetError> {
        let mut out = Vec::with_capacity(EH_SIZE.saturating_add(record.len()).saturating_add(16));

        if self.in_e() {
            // `x3270` `net_output`: SSCP-LU input goes out as SSCP-LU data.
            let data_type = if self.submode == SessionSubmode::Tn3270eSscpLu {
                Tn3270eDataType::SscpLuData
            } else {
                Tn3270eDataType::Data3270
            };
            let header = Tn3270eHeader {
                data_type,
                request_flag: 0x00,
                response_flag: TN3270E_RSF_NO_RESPONSE,
                seq_number: self.xmit_seq,
            };
            if self.functions.responses {
                self.xmit_seq = (self.xmit_seq.saturating_add(1)) & 0x7FFF;
            }
            for &b in &header.to_bytes() {
                out.push(b);
                if b == IAC {
                    out.push(IAC);
                }
            }
        }

        for &b in record {
            out.push(b);
            if b == IAC {
                out.push(IAC);
            }
        }

        out.push(IAC);
        out.push(EOR);
        Ok(out)
    }

    /// Frames a TN3270E POSITIVE-RESPONSE (`DEVICE_END 0x00`) with escaped IACs and trailing `IAC EOR`.
    ///
    /// # Errors
    /// Returns [`TelnetError`] if framing fails.
    pub fn frame_positive_response(&self, seq_number: u16) -> Result<Vec<u8>, TelnetError> {
        let [s0, s1] = seq_number.to_be_bytes();
        let raw = [
            Tn3270eDataType::Response.as_u8(),
            0x00,
            TN3270E_RSF_POSITIVE_RESPONSE,
            s0,
            s1,
            TN3270E_POS_DEVICE_END,
        ];
        let mut out = Vec::with_capacity(12);
        for &b in &raw {
            out.push(b);
            if b == IAC {
                out.push(IAC);
            }
        }
        out.push(IAC);
        out.push(EOR);
        Ok(out)
    }

    /// Frames a TN3270E NEGATIVE-RESPONSE with reason code, escaped IACs, and trailing `IAC EOR`.
    ///
    /// # Errors
    /// Returns [`TelnetError`] if framing fails.
    pub fn frame_negative_response(
        &self,
        seq_number: u16,
        reason: u8,
    ) -> Result<Vec<u8>, TelnetError> {
        let [s0, s1] = seq_number.to_be_bytes();
        let raw = [
            Tn3270eDataType::Response.as_u8(),
            0x00,
            TN3270E_RSF_NEGATIVE_RESPONSE,
            s0,
            s1,
            reason,
        ];
        let mut out = Vec::with_capacity(12);
        for &b in &raw {
            out.push(b);
            if b == IAC {
                out.push(IAC);
            }
        }
        out.push(IAC);
        out.push(EOR);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replays the exact wire sequence captured live from Hercules MVS 3.8j TK4-
    /// (classic TN3270, no TN3270E) and verifies the client handshake byte-for-byte.
    #[test]
    fn test_classic_tn3270_hercules_handshake() {
        let mut sm = TelnetStateMachine::new(TerminalModel::Model2, false, false, None);

        // The client offers nothing on its own (x3270 is purely reactive).
        assert_eq!(sm.take_outbound(), Vec::<u8>::new());

        // Host: DO TTYPE -> WILL TTYPE; a repeated DO is not answered again (no loop).
        assert_eq!(sm.process_inbound(&[IAC, DO, TELOPT_TTYPE]), Ok(vec![]));
        assert_eq!(sm.take_outbound(), vec![IAC, WILL, TELOPT_TTYPE]);
        assert_eq!(sm.process_inbound(&[IAC, DO, TELOPT_TTYPE]), Ok(vec![]));
        assert_eq!(sm.take_outbound(), Vec::<u8>::new());

        // Host: SB TTYPE SEND -> client answers IS IBM-3278-2.
        assert_eq!(
            sm.process_inbound(&[IAC, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE]),
            Ok(vec![])
        );
        let mut expected = vec![IAC, SB, TELOPT_TTYPE, TELQUAL_IS];
        expected.extend_from_slice(b"IBM-3278-2");
        expected.extend_from_slice(&[IAC, SE]);
        assert_eq!(sm.take_outbound(), expected);

        // Host: DO EOR, WILL EOR -> not complete yet (BINARY missing).
        assert_eq!(
            sm.process_inbound(&[IAC, DO, TELOPT_EOR, IAC, WILL, TELOPT_EOR]),
            Ok(vec![])
        );
        assert_eq!(
            sm.take_outbound(),
            vec![IAC, WILL, TELOPT_EOR, IAC, DO, TELOPT_EOR]
        );

        // Host: DO BINARY, WILL BINARY -> classic negotiation complete.
        let events = sm.process_inbound(&[IAC, DO, TELOPT_BINARY, IAC, WILL, TELOPT_BINARY]);
        assert_eq!(
            events,
            Ok(vec![TelnetEvent::NegotiationComplete {
                tn3270e: false,
                functions: Tn3270eFunctions::default(),
                assigned_lu: None,
            }])
        );
        assert_eq!(sm.submode(), SessionSubmode::Tn3270Active);
        assert!(!sm.is_tn3270e());

        // Subsequent 3270 record is delivered without TN3270E header.
        assert_eq!(
            sm.process_inbound(&[0xF5, 0x42, IAC, EOR]),
            Ok(vec![TelnetEvent::DataRecord(vec![0xF5, 0x42])])
        );
    }

    /// Negotiates plain TN3270 (TTYPE, BINARY and EOR both ways).
    #[allow(clippy::unwrap_used)]
    fn plain_tn3270() -> TelnetStateMachine {
        let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
        let evs = sm
            .process_inbound(&[
                IAC,
                DO,
                TELOPT_TTYPE,
                IAC,
                DO,
                TELOPT_BINARY,
                IAC,
                WILL,
                TELOPT_BINARY,
                IAC,
                DO,
                TELOPT_EOR,
                IAC,
                WILL,
                TELOPT_EOR,
            ])
            .unwrap();
        assert!(evs
            .iter()
            .any(|e| matches!(e, TelnetEvent::NegotiationComplete { .. })));
        sm
    }

    #[test]
    fn test_iac_doubling_on_receive() {
        let mut sm = plain_tn3270();
        let input = [0xC1, IAC, IAC, 0xC2, IAC, EOR];
        assert_eq!(
            sm.process_inbound(&input),
            Ok(vec![TelnetEvent::DataRecord(vec![0xC1, 0xFF, 0xC2])])
        );
    }

    #[test]
    fn test_nvt_text_before_3270_mode_is_not_part_of_the_first_record() {
        let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
        // A banner before negotiation, with an escaped 0xFF: NVT text.
        assert_eq!(
            sm.process_inbound(b"Welcome\r\n"),
            Ok(vec![TelnetEvent::NvtData {
                data: b"Welcome\r\n".to_vec(),
                ack: None,
            }])
        );
        // An end of record while not in 3270 mode is dropped.
        assert_eq!(
            sm.process_inbound(&[b'x', IAC, EOR]),
            Ok(vec![
                TelnetEvent::NvtData {
                    data: b"x".to_vec(),
                    ack: None,
                },
                TelnetEvent::RecordDiscarded(TelnetError::NotIn3270Mode),
            ])
        );
        // Once in 3270 mode the first record holds only its own bytes.
        let mut sm = plain_tn3270();
        assert_eq!(
            sm.process_inbound(&[0xF5, 0xC3, IAC, EOR]),
            Ok(vec![TelnetEvent::DataRecord(vec![0xF5, 0xC3])])
        );
    }

    #[test]
    fn test_positive_response_iac_escaping() {
        let sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
        // Sequence number 0xFF12 has 0xFF in hi byte
        assert_eq!(
            sm.frame_positive_response(0xFF12),
            Ok(vec![0x02, 0x00, 0x00, 0xFF, 0xFF, 0x12, 0x00, 0xFF, 0xEF])
        );
    }
}
