//! Text traces of recorded host traffic, shared by the recording proxy
//! (`examples/record_proxy.rs`) and the replay tests (`tests/recorded_host_replay.rs`).
//!
//! # Format (`# bastion3270 trace v1`)
//!
//! ```text
//! # bastion3270 trace v1
//! # target: <host:port>
//! # profile: terminal_model = "Model4"      (TOML lines of the client's connection profile)
//! 12 < fffd28                              (ms since start, direction, bytes as hex)
//! 15 > fffb28
//! ```
//!
//! `<` is host → client, `>` is client → host. Each line is one read from the socket, so
//! records may be split or merged across lines exactly as TCP delivered them.
//!
//! # Redaction
//!
//! Client → host data is redacted while recording ([`OutboundRedactor`]): Telnet commands and
//! subnegotiations, the TN3270E header, the AID, the cursor address, buffer addresses (`SBA`)
//! and structured-field replies are kept; every other byte of a 3270 record (typed field
//! contents, passwords) and all SSCP-LU, NVT and SCS data become `0x00`. The length never
//! changes, so the trace stays a faithful picture of the record structure.
#![allow(dead_code, unreachable_pub)]

use std::fmt::Write as _;
use std::time::Instant;

use bastion3270_core::datastream::sscp::write_sscp_lu;
use bastion3270_core::SafeScreenView;
use bastion3270_core::{
    AidKey, CodePage, DataStreamParser, PresentationSpace, TelnetEvent, TelnetStateMachine,
    Tn3270eDataType,
};
use bastion3270_net::ConnectionProfile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// First line of every trace.
pub const MAGIC: &str = "# bastion3270 trace v1";

const IAC: u8 = 0xFF;
const SE: u8 = 0xF0;
const SB: u8 = 0xFA;
const EOR: u8 = 0xEF;
const SBA: u8 = 0x11;
/// AIDs of inbound records that carry no operator data and are kept whole: structured field
/// (query replies), no AID, read partition.
const AID_SF: u8 = 0x88;
const AID_NO: u8 = 0x60;
const AID_READ_PARTITION: u8 = 0x61;

/// Direction of one recorded read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Host → client (`<`).
    FromHost,
    /// Client → host (`>`).
    ToHost,
}

/// One read from the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub ms: u64,
    pub dir: Direction,
    pub bytes: Vec<u8>,
}

/// A parsed trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {
    /// The `# profile:` lines joined as TOML (the client's connection settings).
    pub profile_toml: String,
    pub chunks: Vec<Chunk>,
}

impl Trace {
    /// The client's connection profile, pointed at `host:port`.
    pub fn profile(&self, host: &str, port: u16) -> Result<ConnectionProfile, String> {
        // The replay always talks to a local mock host over plain TCP, whatever the recorded
        // client used towards the real host.
        let toml = format!(
            "host = {host:?}\nport = {port}\ntls_mode = \"disabled\"\n{}",
            self.profile_toml
        );
        ConnectionProfile::from_toml_str(&toml).map_err(|e| e.to_string())
    }
}

/// The header of a new trace.
pub fn header(target: &str, profile_toml_lines: &[String]) -> String {
    let mut out = format!("{MAGIC}\n# target: {target}\n");
    for line in profile_toml_lines {
        let _ = writeln!(out, "# profile: {line}");
    }
    out
}

/// One trace line for `chunk`.
pub fn line(chunk: &Chunk) -> String {
    let dir = match chunk.dir {
        Direction::FromHost => '<',
        Direction::ToHost => '>',
    };
    let mut out = format!("{} {dir} ", chunk.ms);
    for b in &chunk.bytes {
        let _ = write!(out, "{b:02x}");
    }
    out.push('\n');
    out
}

/// Parses a trace.
pub fn parse(text: &str) -> Result<Trace, String> {
    let mut lines = text.lines();
    if lines.next() != Some(MAGIC) {
        return Err(format!("not a trace (first line must be {MAGIC:?})"));
    }
    let mut profile_toml = String::new();
    let mut chunks = Vec::new();
    for (n, raw) in lines.enumerate() {
        let n = n + 2;
        let l = raw.trim();
        if l.is_empty() {
            continue;
        }
        if let Some(rest) = l.strip_prefix("# profile:") {
            profile_toml.push_str(rest.trim());
            profile_toml.push('\n');
            continue;
        }
        if l.starts_with('#') {
            continue;
        }
        let mut parts = l.split_whitespace();
        let (Some(ms), Some(dir), Some(hex), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(format!("line {n}: expected `<ms> <dir> <hex>`"));
        };
        let ms = ms.parse().map_err(|e| format!("line {n}: {e}"))?;
        let dir = match dir {
            "<" => Direction::FromHost,
            ">" => Direction::ToHost,
            other => return Err(format!("line {n}: direction {other:?}")),
        };
        let bytes = decode_hex(hex).ok_or_else(|| format!("line {n}: bad hex"))?;
        chunks.push(Chunk { ms, dir, bytes });
    }
    Ok(Trace {
        profile_toml,
        chunks,
    })
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Replaces every occurrence of `from` by `to` in `bytes`. Both must have the same, non-zero
/// length (a redaction never changes lengths); otherwise nothing is replaced.
pub fn replace_all(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    if from.is_empty() || from.len() != to.len() {
        return;
    }
    let mut i = 0;
    while let Some(window) = bytes.get_mut(i..i + from.len()) {
        if window == from {
            window.copy_from_slice(to);
            i += from.len();
        } else {
            i += 1;
        }
    }
}

/// `(text, replacement)` pairs in the host code page, both of the same length.
pub type Redactions = Vec<(Vec<u8>, Vec<u8>)>;

/// Applies [`Redactions`] to one direction of a stream that arrives in arbitrary pieces.
///
/// A text may be split across two reads (a host writes `Z1` in one TCP segment and `2345`
/// in the next), so a redaction applied to each read alone would miss it. The redactor holds
/// back the longest end of the data that is the beginning of some text and decides on it
/// together with the next piece. Lengths never change: everything fed in comes out again,
/// in order, after [`TextRedactor::finish`].
#[derive(Debug, Default)]
pub struct TextRedactor {
    redactions: Redactions,
    pending: Vec<u8>,
}

impl TextRedactor {
    pub fn new(redactions: Redactions) -> Self {
        Self {
            redactions,
            pending: Vec::new(),
        }
    }

    /// Redacts `bytes` and returns what is certain now; may hold back a few bytes.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(bytes);
        for (text, replacement) in &self.redactions {
            replace_all(&mut self.pending, text, replacement);
        }
        let held = self.partial_match_len();
        let ready = self.pending.len() - held;
        let rest = self.pending.split_off(ready);
        std::mem::replace(&mut self.pending, rest)
    }

    /// The bytes still held back (at the end of the stream).
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }

    /// Length of the longest end of `pending` that is a proper beginning of some text.
    fn partial_match_len(&self) -> usize {
        let longest = self
            .redactions
            .iter()
            .map(|(t, _)| t.len())
            .max()
            .unwrap_or(0);
        (1..longest.min(self.pending.len() + 1))
            .rev()
            .find(|&n| {
                let tail = self
                    .pending
                    .get(self.pending.len() - n..)
                    .unwrap_or_default();
                self.redactions
                    .iter()
                    .any(|(t, _)| t.len() > n && t.starts_with(tail))
            })
            .unwrap_or(0)
    }
}

/// Copies both directions between `client` and `host` until either side closes, and sends
/// every read to `tx` (client data redacted with an [`OutboundRedactor`], then `redactions`
/// applied to both directions). `start` is the time origin of the chunk timestamps.
pub async fn pump(
    client: TcpStream,
    host: TcpStream,
    start: Instant,
    tx: mpsc::UnboundedSender<Chunk>,
    redactions: Redactions,
) {
    let (client_rd, client_wr) = client.into_split();
    let (host_rd, host_wr) = host.into_split();
    let to_host = copy(
        client_rd,
        host_wr,
        Direction::ToHost,
        start,
        tx.clone(),
        redactions.clone(),
    );
    let to_client = copy(
        host_rd,
        client_wr,
        Direction::FromHost,
        start,
        tx,
        redactions,
    );
    tokio::join!(to_host, to_client);
}

/// One direction of [`pump`].
async fn copy(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    dir: Direction,
    start: Instant,
    tx: mpsc::UnboundedSender<Chunk>,
    redactions: Redactions,
) {
    let mut redactor = OutboundRedactor::default();
    let mut text = TextRedactor::new(redactions);
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let Some(data) = buf.get(..n) else { break };
        if to.write_all(data).await.is_err() {
            break;
        }
        let bytes = match dir {
            Direction::ToHost => text.feed(&redactor.redact(data)),
            Direction::FromHost => text.feed(data),
        };
        send(&tx, start, dir, bytes);
    }
    send(&tx, start, dir, text.finish());
    let _ = to.shutdown().await;
}

/// Sends a non-empty piece of the trace.
fn send(tx: &mpsc::UnboundedSender<Chunk>, start: Instant, dir: Direction, bytes: Vec<u8>) {
    if !bytes.is_empty() {
        let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let _ = tx.send(Chunk { ms, dir, bytes });
    }
}

/// Applies `redactions` once more to a recorded trace, for instance one recorded with a
/// redaction that missed a text, or to replace another text. Chunk boundaries and timestamps
/// stay as recorded, except that a text split across two chunks moves to the later one.
pub fn redact_trace(trace: &Trace, redactions: &Redactions) -> Vec<Chunk> {
    let mut out: Vec<Chunk> = Vec::new();
    let mut to_host = (TextRedactor::new(redactions.clone()), None);
    let mut from_host = (TextRedactor::new(redactions.clone()), None);
    for chunk in &trace.chunks {
        let (redactor, last_ms) = match chunk.dir {
            Direction::ToHost => &mut to_host,
            Direction::FromHost => &mut from_host,
        };
        *last_ms = Some(chunk.ms);
        let bytes = redactor.feed(&chunk.bytes);
        if !bytes.is_empty() {
            out.push(Chunk {
                bytes,
                ..chunk.clone()
            });
        }
    }
    for (dir, (mut redactor, last_ms)) in [
        (Direction::ToHost, to_host),
        (Direction::FromHost, from_host),
    ] {
        let bytes = redactor.finish();
        if let (false, Some(ms)) = (bytes.is_empty(), last_ms) {
            out.push(Chunk { ms, dir, bytes });
        }
    }
    out
}

// ─── Telnet units of a client stream ────────────────────────────────────────────────

/// One Telnet unit of a client → host stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unit {
    /// A Telnet command or subnegotiation, raw (`IAC ...`).
    Command(Vec<u8>),
    /// A data record up to `IAC EOR`, unescaped.
    Record(Vec<u8>),
}

impl Unit {
    /// What the unit is, independent of redacted contents: commands compare exactly, records
    /// by TN3270E data type and AID.
    pub fn kind(&self) -> String {
        match self {
            Self::Command(bytes) => format!("telnet {}", hex(bytes)),
            Self::Record(r) => match r.first() {
                Some(&dt) if dt <= 0x09 && r.len() >= 5 => match r.get(5) {
                    Some(aid) if dt == 0x00 => format!("3270-DATA aid {aid:02x}"),
                    _ => format!("TN3270E type {dt:02x}"),
                },
                Some(aid) => format!("3270 aid {aid:02x}"),
                None => "empty record".to_owned(),
            },
        }
    }

    /// The operator AID of a 3270 record (what a key press produces), if any.
    pub fn operator_aid(&self) -> Option<AidKey> {
        AidKey::from_byte(*self.data_3270()?.first()?)
    }

    /// The bytes of a 3270 record after the TN3270E header, if it is 3270 data.
    pub fn data_3270(&self) -> Option<&[u8]> {
        let Self::Record(r) = self else { return None };
        match r.first() {
            Some(&0x00) => r.get(5..),
            Some(&dt) if dt <= 0x09 => None,
            _ => Some(r),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Splits a client → host byte stream into Telnet [`Unit`]s (stateful across reads).
#[derive(Debug)]
pub struct UnitSplitter {
    state: TelnetState,
    command: Vec<u8>,
    record: Vec<u8>,
}

impl Default for UnitSplitter {
    fn default() -> Self {
        Self {
            state: TelnetState::Data,
            command: Vec::new(),
            record: Vec::new(),
        }
    }
}

impl UnitSplitter {
    /// The units completed by `bytes`.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Unit> {
        let mut out = Vec::new();
        for &b in bytes {
            self.state = match (self.state, b) {
                (TelnetState::Data, IAC) => TelnetState::Iac,
                (TelnetState::Data, _) => {
                    self.record.push(b);
                    TelnetState::Data
                }
                (TelnetState::Iac, IAC) => {
                    self.record.push(IAC);
                    TelnetState::Data
                }
                (TelnetState::Iac, EOR) => {
                    out.push(Unit::Record(std::mem::take(&mut self.record)));
                    TelnetState::Data
                }
                (TelnetState::Iac, SB) => {
                    self.command = vec![IAC, SB];
                    TelnetState::Sb
                }
                (TelnetState::Iac, 0xFB..=0xFE) => {
                    self.command = vec![IAC, b];
                    TelnetState::Option
                }
                (TelnetState::Iac, _) => {
                    out.push(Unit::Command(vec![IAC, b]));
                    TelnetState::Data
                }
                (TelnetState::Option, _) => {
                    self.command.push(b);
                    out.push(Unit::Command(std::mem::take(&mut self.command)));
                    TelnetState::Data
                }
                (TelnetState::Sb, _) => {
                    self.command.push(b);
                    if b == IAC {
                        TelnetState::SbIac
                    } else {
                        TelnetState::Sb
                    }
                }
                (TelnetState::SbIac, _) => {
                    self.command.push(b);
                    if b == SE {
                        out.push(Unit::Command(std::mem::take(&mut self.command)));
                        TelnetState::Data
                    } else {
                        TelnetState::Sb
                    }
                }
            };
        }
        out
    }
}

// ─── Record-time redaction of client → host data ────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TelnetState {
    Data,
    Iac,
    /// After `IAC WILL/WONT/DO/DONT`: the option byte.
    Option,
    Sb,
    SbIac,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Record {
    /// No byte of the current record seen yet.
    Start,
    /// TN3270E record with this data type (header of 5 bytes).
    Tn3270e(u8),
    /// Plain TN3270 3270 data.
    Plain,
    /// Not a 3270 record (NVT text without TN3270E): everything is redacted.
    Opaque,
}

/// Redacts a client → host byte stream as it is read (see the module docs). Stateful: records
/// and Telnet sequences may be split across reads.
#[derive(Debug)]
pub struct OutboundRedactor {
    telnet: TelnetState,
    record: Record,
    /// Logical (unescaped) index of the next data byte in the current record.
    pos: usize,
    /// The record is a structured-field reply: kept whole.
    keep_record: bool,
    /// Address bytes still to keep after an `SBA`.
    keep_next: u8,
    /// The command byte of the current `IAC WILL/WONT/DO/DONT` sequence.
    command: u8,
    /// The client agreed to TN3270E (`IAC WILL TN3270E`): records start with the 5-byte header.
    tn3270e: bool,
    /// The client agreed to end-of-record framing (`IAC WILL EOR`): 3270 records.
    eor: bool,
}

impl Default for OutboundRedactor {
    fn default() -> Self {
        Self {
            telnet: TelnetState::Data,
            record: Record::Start,
            pos: 0,
            keep_record: false,
            keep_next: 0,
            command: 0,
            tn3270e: false,
            eor: false,
        }
    }
}

const WILL: u8 = 0xFB;
const WONT: u8 = 0xFC;
const TELOPT_EOR: u8 = 0x19;
const TELOPT_TN3270E: u8 = 0x28;

/// `true` for bytes that start a client 3270 record.
fn is_inbound_aid(b: u8) -> bool {
    AidKey::from_byte(b).is_some() || matches!(b, AID_SF | AID_NO | AID_READ_PARTITION)
}

impl OutboundRedactor {
    /// The redacted form of `raw` (same length).
    pub fn redact(&mut self, raw: &[u8]) -> Vec<u8> {
        raw.iter().map(|&b| self.byte(b)).collect()
    }

    fn byte(&mut self, b: u8) -> u8 {
        match self.telnet {
            TelnetState::Data if b == IAC => {
                self.telnet = TelnetState::Iac;
                b
            }
            TelnetState::Data => self.data_byte(b),
            TelnetState::Iac => {
                self.telnet = match b {
                    IAC => {
                        // An escaped 0xFF data byte: kept as is (both bytes), counted once.
                        self.pos += 1;
                        TelnetState::Data
                    }
                    EOR => {
                        self.end_record();
                        TelnetState::Data
                    }
                    SB => TelnetState::Sb,
                    0xFB..=0xFE => {
                        self.command = b;
                        TelnetState::Option
                    }
                    _ => TelnetState::Data,
                };
                b
            }
            TelnetState::Option => {
                match (self.command, b) {
                    (WILL, TELOPT_TN3270E) => self.tn3270e = true,
                    (WONT, TELOPT_TN3270E) => self.tn3270e = false, // fallback to TN3270
                    (WILL, TELOPT_EOR) => self.eor = true,
                    (WONT, TELOPT_EOR) => self.eor = false,
                    _ => {}
                }
                self.telnet = TelnetState::Data;
                b
            }
            TelnetState::Sb => {
                if b == IAC {
                    self.telnet = TelnetState::SbIac;
                }
                b
            }
            TelnetState::SbIac => {
                self.telnet = if b == SE {
                    TelnetState::Data
                } else {
                    TelnetState::Sb
                };
                b
            }
        }
    }

    fn end_record(&mut self) {
        self.record = Record::Start;
        self.pos = 0;
        self.keep_record = false;
        self.keep_next = 0;
    }

    fn data_byte(&mut self, b: u8) -> u8 {
        let p = self.pos;
        self.pos += 1;
        if self.record == Record::Start {
            // Only data the client framed as 3270 records is parsed; anything else (NVT text
            // before or without 3270 mode) is redacted whole.
            self.record = if self.tn3270e && b <= 0x09 {
                Record::Tn3270e(b)
            } else if self.eor && !self.tn3270e && is_inbound_aid(b) {
                Record::Plain
            } else {
                Record::Opaque
            };
        }
        let q = match self.record {
            Record::Start | Record::Opaque => return 0x00,
            Record::Tn3270e(_) if p < 5 => return b,
            // RESPONSE / REQUEST and other control types carry no operator data.
            Record::Tn3270e(dt) if dt != 0x00 && !matches!(dt, 0x01 | 0x05 | 0x07) => return b,
            Record::Tn3270e(dt) if dt != 0x00 => return 0x00, // SCS, NVT, SSCP-LU data
            Record::Tn3270e(_) => p - 5,
            Record::Plain => p,
        };
        match q {
            0 => {
                if !is_inbound_aid(b) {
                    self.record = Record::Opaque;
                    return 0x00;
                }
                self.keep_record = b == AID_SF;
                b
            }
            _ if self.keep_record => b,
            1 | 2 => b, // cursor address
            _ if self.keep_next > 0 => {
                self.keep_next -= 1;
                b
            }
            _ if b == SBA => {
                self.keep_next = 2;
                b
            }
            _ => 0x00,
        }
    }
}

// ─── Core replay ────────────────────────────────────────────────────────────────────

/// The result of replaying the host side of a trace through the core.
#[derive(Debug, Default)]
pub struct CoreReplay {
    /// One snapshot per host record that changed the screen (see [`snapshot`]).
    pub snapshots: Vec<String>,
    /// Everything the core rejected or discarded (must be empty for a good trace).
    pub problems: Vec<String>,
}

/// Replays the host → client chunks through the Telnet state machine and the data stream
/// parser, making the same core calls as the session coordinator
/// (`SessionCoordinator::handle_network_chunk` in `src/session/coordinator.rs`): 3270 data →
/// `DataStreamParser::process`, SSCP-LU data → `write_sscp_lu`, BIND → `apply_bind`,
/// UNBIND → `unbind`. Client replies are not needed: the host's writes are recorded.
pub fn replay_core(trace: &Trace) -> Result<CoreReplay, String> {
    let profile = trace.profile("127.0.0.1", 23)?;
    let model = profile.core_terminal_model().map_err(|e| e.to_string())?;
    let codepage = profile.core_codepage().map_err(|e| e.to_string())?;
    let mut telnet = TelnetStateMachine::new(
        model,
        profile.color_3279,
        profile.extended,
        profile.lu_name.clone(),
    );
    let mut ps = PresentationSpace::new(model);
    let mut out = CoreReplay::default();
    let mut record_no = 0_usize;

    for chunk in trace.chunks.iter().filter(|c| c.dir == Direction::FromHost) {
        let events = telnet
            .process_inbound(&chunk.bytes)
            .map_err(|e| format!("Telnet error at {} ms: {e}", chunk.ms))?;
        let _ = telnet.take_outbound();
        for event in events {
            let label = match event {
                TelnetEvent::DataRecord(record) => {
                    apply_3270(&record, &mut ps, &mut out, record_no)
                }
                TelnetEvent::Tn3270eRecord { header, payload } => {
                    if header.data_type != Tn3270eDataType::Data3270 {
                        continue;
                    }
                    apply_3270(&payload, &mut ps, &mut out, record_no)
                }
                TelnetEvent::SscpLuData(data) => {
                    if let Err(e) = write_sscp_lu(&mut ps, &data) {
                        out.problems
                            .push(format!("record {record_no}: SSCP-LU data: {e}"));
                    }
                    "SSCP-LU data"
                }
                TelnetEvent::BindImage(bind) => {
                    if let Err(e) = ps.apply_bind(bind.sizes) {
                        out.problems.push(format!("record {record_no}: BIND: {e}"));
                    }
                    "BIND"
                }
                TelnetEvent::Unbind(_) => {
                    ps.unbind();
                    "UNBIND"
                }
                TelnetEvent::RecordDiscarded(e) => {
                    out.problems
                        .push(format!("record {record_no}: discarded: {e}"));
                    continue;
                }
                _ => continue,
            };
            out.snapshots
                .push(snapshot(record_no, label, &ps, codepage));
            record_no += 1;
        }
    }
    Ok(out)
}

/// Applies one 3270 record like the session coordinator does; returns the snapshot label
/// (with `alarm` when the WCC sounded the alarm, which a client turns into a beep).
fn apply_3270(
    record: &[u8],
    ps: &mut PresentationSpace,
    out: &mut CoreReplay,
    record_no: usize,
) -> &'static str {
    let result = DataStreamParser::process(record, ps);
    if let Some(err) = result.rejected {
        out.problems
            .push(format!("record {record_no}: rejected: {err}"));
    }
    let cap = ps.capacity();
    if ps.cursor_addr().as_usize() >= cap || ps.buffer_addr().as_usize() >= cap {
        out.problems
            .push(format!("record {record_no}: address outside the screen"));
    }
    if result.sound_alarm {
        "3270 data, alarm"
    } else {
        "3270 data"
    }
}

/// A screen as text: a header line (record number, what it was) and [`screen_text`].
pub fn snapshot(
    record_no: usize,
    label: &str,
    ps: &PresentationSpace,
    codepage: &dyn CodePage,
) -> String {
    format!(
        "== record {record_no}: {label}\n{}",
        screen_text(&ps.to_safe_view(codepage))
    )
}

/// The Zero-Trust projection as text: size, cursor and formatted state, then the rows with
/// trailing blanks removed.
pub fn screen_text(view: &SafeScreenView) -> String {
    let (row, col) = view.cursor_position();
    let formatted = if view.is_formatted() {
        ", formatted"
    } else {
        ""
    };
    let mut out = format!(
        "{}x{}, cursor {row},{col}{formatted}\n",
        view.rows(),
        view.cols()
    );
    for line in view.cells().chunks(usize::from(view.cols()).max(1)) {
        let text: String = line.iter().map(|c| c.ch).collect();
        out.push_str(text.trim_end());
        out.push('\n');
    }
    out
}
