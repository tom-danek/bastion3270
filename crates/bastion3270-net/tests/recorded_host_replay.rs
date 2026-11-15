//! Replay of recorded host traffic (traces written by `examples/record_proxy.rs`).
//!
//! * Hermetic tests (always run): the record-time redaction, and a scripted host session that
//!   is recorded through the real session stack and then replayed at both levels below.
//! * Corpus tests (ignored): every trace of a local corpus of recorded host traffic — not part
//!   of the repository — is replayed and compared with its golden screens.
//!
//! Replay levels:
//! 1. **Core:** the host side of the trace through the Telnet state machine and the data stream
//!    parser; a screen snapshot after every host record is compared with the golden file.
//! 2. **Session:** a host that replays the trace to the real `SessionCoordinator`, pressing the
//!    recorded operator AIDs; the client's units (Telnet commands, record kinds) must match the
//!    recording and the final screen must match the core replay.
//!
//! ```text
//! BASTION3270_HOST_CORPUS=<dir> cargo test -p bastion3270-net --test recorded_host_replay -- --ignored
//! BASTION3270_UPDATE_GOLDEN=1 ...   # rewrite the golden files, then review them with `git diff`
//! ```
//! The corpus directory holds `traces/<name>.trc` and `golden/<name>.txt`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use bastion3270_core::{AidKey, SafeScreenView};
use bastion3270_net::{SessionCoordinator, SessionEvent};
use common::trace::{self, Chunk, Direction, OutboundRedactor, Trace, Unit, UnitSplitter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const T: Duration = Duration::from_secs(5);
/// EBCDIC "SECRET".
const SECRET: [u8; 6] = [0xE2, 0xC5, 0xC3, 0xD9, 0xC5, 0xE3];
const IAC_EOR: [u8; 2] = [0xFF, 0xEF];

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ─── Redaction ──────────────────────────────────────────────────────────────────────

/// Client negotiation that switches the redactor to TN3270E record parsing.
const WILL_TN3270E: [u8; 3] = [0xFF, 0xFB, 0x28];

fn redact_whole_and_bytewise(input: &[u8]) -> Vec<u8> {
    let whole = OutboundRedactor::default().redact(input);
    let mut split = OutboundRedactor::default();
    let bytewise: Vec<u8> = input.iter().flat_map(|b| split.redact(&[*b])).collect();
    assert_eq!(
        whole, bytewise,
        "redaction must not depend on how reads are split"
    );
    assert_eq!(whole.len(), input.len(), "redaction must keep the length");
    whole
}

#[test]
fn typed_field_data_is_redacted_and_the_record_structure_is_kept() {
    let mut input = WILL_TN3270E.to_vec();
    // TN3270E header, AID Enter, cursor, SBA + "SECRET", SBA + "SECRET", IAC EOR.
    let record_start = input.len();
    input.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x7D, 0x40, 0x4B]);
    input.extend([0x11, 0x40, 0x4A]);
    input.extend(SECRET);
    input.extend([0x11, 0xC1, 0x50]);
    input.extend(SECRET);
    input.extend(IAC_EOR);

    let out = redact_whole_and_bytewise(&input);
    assert!(!contains(&out, &SECRET), "typed data left in the trace");
    let mut expected = input.clone();
    for i in (record_start + 11..record_start + 17).chain(record_start + 20..record_start + 26) {
        expected[i] = 0x00;
    }
    assert_eq!(
        out, expected,
        "header, AID, cursor and SBA addresses are kept"
    );
}

#[test]
fn negotiation_and_structured_field_replies_are_kept() {
    let mut input = WILL_TN3270E.to_vec();
    input.extend([0xFF, 0xFA, 0x28, 0x02, 0x07]);
    input.extend(b"IBM-3278-2-E");
    input.extend([0xFF, 0xF0]);
    // Query reply (AID 0x88) with an escaped 0xFF byte inside.
    input.extend([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x00, 0x06, 0x81, 0x80, 0xFF, 0xFF,
    ]);
    input.extend(IAC_EOR);
    assert_eq!(redact_whole_and_bytewise(&input), input);
}

#[test]
fn sscp_lu_nvt_and_unframed_data_are_redacted_whole() {
    // SSCP-LU data in TN3270E: the header stays, the typed logon command goes.
    let mut input = WILL_TN3270E.to_vec();
    input.extend([0x07, 0x00, 0x00, 0x00, 0x01]);
    input.extend(SECRET);
    input.extend(IAC_EOR);
    let out = redact_whole_and_bytewise(&input);
    assert_eq!(&out[..8], &input[..8]);
    assert!(out[8..14].iter().all(|b| *b == 0));

    // Before any 3270 negotiation (NVT): nothing is parsed, everything typed goes. `J` (0x4A)
    // would be an AID and TAB (0x09) a TN3270E data type if the stream were trusted.
    let typed = b"J\tsecret\r\n";
    assert!(redact_whole_and_bytewise(typed).iter().all(|b| *b == 0));
}

#[test]
fn plain_tn3270_records_are_parsed_after_end_of_record_is_agreed() {
    let mut input = vec![0xFF, 0xFB, 0x19]; // IAC WILL EOR
    input.extend([0x7D, 0x40, 0x4B, 0x11, 0x40, 0x4A]);
    input.extend(SECRET);
    input.extend(IAC_EOR);
    let out = redact_whole_and_bytewise(&input);
    assert_eq!(&out[..9], &input[..9]);
    assert!(!contains(&out, &SECRET));
}

#[test]
fn trace_lines_round_trip_and_redaction_texts_keep_lengths() {
    let chunks = vec![
        Chunk {
            ms: 0,
            dir: Direction::FromHost,
            bytes: vec![0xFF, 0xFD, 0x28],
        },
        Chunk {
            ms: 7,
            dir: Direction::ToHost,
            bytes: vec![0xFF, 0xFB, 0x28],
        },
    ];
    let mut text = trace::header("host:23", &["terminal_model = \"Model4\"".to_owned()]);
    for c in &chunks {
        text.push_str(&trace::line(c));
    }
    let parsed = trace::parse(&text).unwrap();
    assert_eq!(parsed.chunks, chunks);
    assert_eq!(parsed.profile_toml, "terminal_model = \"Model4\"\n");
    assert!(trace::parse("not a trace").is_err());

    let mut bytes = b"..USER01..USER01".to_vec();
    trace::replace_all(&mut bytes, b"USER01", b"XXXXXX");
    assert_eq!(bytes, b"..XXXXXX..XXXXXX");
    trace::replace_all(&mut bytes, b"XX", b"Y"); // different lengths: refused
    assert_eq!(bytes, b"..XXXXXX..XXXXXX");
}

/// A host may write a user id across two TCP reads; the redaction must still catch it,
/// wherever the split falls, without changing the length or the order of the stream.
#[test]
fn a_text_split_across_reads_is_redacted() {
    let stream = b"Userid ===> USER01 ..USER0";
    let expected = b"Userid ===> XXXXXX ..USER0";
    for split in 0..=stream.len() {
        let (a, b) = stream.split_at(split);
        let mut redactor = trace::TextRedactor::new(vec![(b"USER01".to_vec(), b"XXXXXX".to_vec())]);
        let mut out = redactor.feed(a);
        out.extend(redactor.feed(b));
        out.extend(redactor.finish());
        assert_eq!(out, expected, "split at {split}");
    }

    // Only a beginning of the text is held back, so a record end is never delayed.
    let mut redactor = trace::TextRedactor::new(vec![(b"USER01".to_vec(), b"XXXXXX".to_vec())]);
    assert_eq!(redactor.feed(b"abc\xff\xef"), b"abc\xff\xef");
    assert_eq!(redactor.feed(b"xUSE"), b"x");
    assert_eq!(redactor.feed(b"R02"), b"USER02");
}

/// Redacting a recorded trace again fixes a text split across two chunks of one direction
/// and leaves the other direction and the chunk order alone.
#[test]
fn a_recorded_trace_can_be_redacted_again() {
    let chunk = |ms, dir, bytes: &[u8]| Chunk {
        ms,
        dir,
        bytes: bytes.to_vec(),
    };
    let recorded = Trace {
        profile_toml: String::new(),
        chunks: vec![
            chunk(1, Direction::FromHost, b"id US"),
            chunk(2, Direction::ToHost, b"ER01"),
            chunk(3, Direction::FromHost, b"ER01 ok"),
            chunk(4, Direction::FromHost, b" US"),
        ],
    };
    let redactions = vec![(b"USER01".to_vec(), b"XXXXXX".to_vec())];
    assert_eq!(
        trace::redact_trace(&recorded, &redactions),
        vec![
            chunk(1, Direction::FromHost, b"id "),
            chunk(2, Direction::ToHost, b"ER01"),
            chunk(3, Direction::FromHost, b"XXXXXX ok"),
            chunk(4, Direction::FromHost, b" "),
            chunk(4, Direction::FromHost, b"US"),
        ]
    );
}

// ─── Session replay ─────────────────────────────────────────────────────────────────

/// What a session replay saw.
struct SessionReplay {
    expected: Vec<String>,
    got: Vec<String>,
    query_replies: Vec<Vec<u8>>,
    final_screen: SafeScreenView,
}

/// Reads client units from `sock` until `got` has `n` of them. When the client stays silent
/// and the next expected unit is an operator AID, asks for that key to be pressed.
async fn read_client_units(
    sock: &mut TcpStream,
    splitter: &mut UnitSplitter,
    got: &mut Vec<Unit>,
    expected: &[Unit],
    n: usize,
    press: &mpsc::UnboundedSender<AidKey>,
    pressed: &mut usize,
) -> Result<(), String> {
    let deadline = Instant::now() + T;
    let mut buf = vec![0_u8; 16 * 1024]; // on the heap: keeps the future small
    while got.len() < n {
        match tokio::time::timeout(Duration::from_millis(300), sock.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => return Err("client closed the connection".into()),
            Ok(Ok(len)) => got.extend(splitter.feed(&buf[..len])),
            Err(_) => {
                let next = got.len();
                if let Some(aid) = expected.get(next).and_then(Unit::operator_aid) {
                    if *pressed <= next {
                        let _ = press.send(aid);
                        *pressed = next + 1;
                    }
                }
                if Instant::now() > deadline {
                    return Err(format!(
                        "client sent {} units, expected {}; next expected: {}",
                        got.len(),
                        n,
                        expected.get(next).map_or("-".into(), Unit::kind)
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Replays `trace` to the real session stack (see the module docs).
async fn replay_session(trace: &Trace) -> SessionReplay {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let profile = trace.profile("127.0.0.1", port).unwrap();
    let (press_tx, mut press_rx) = mpsc::unbounded_channel::<AidKey>();

    let chunks = trace.chunks.clone();
    let host = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let (mut expected_split, mut got_split) =
            (UnitSplitter::default(), UnitSplitter::default());
        let (mut expected, mut got) = (Vec::new(), Vec::new());
        let mut pressed = 0;
        for chunk in &chunks {
            match chunk.dir {
                Direction::ToHost => expected.extend(expected_split.feed(&chunk.bytes)),
                Direction::FromHost => {
                    let n = expected.len();
                    read_client_units(
                        &mut sock,
                        &mut got_split,
                        &mut got,
                        &expected,
                        n,
                        &press_tx,
                        &mut pressed,
                    )
                    .await?;
                    sock.write_all(&chunk.bytes)
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        let n = expected.len();
        read_client_units(
            &mut sock,
            &mut got_split,
            &mut got,
            &expected,
            n,
            &press_tx,
            &mut pressed,
        )
        .await?;
        Ok::<_, String>((expected, got, sock))
    });

    let (handle, mut events, _join) = SessionCoordinator::connect(profile).await.unwrap();
    let drain = tokio::spawn(async move { while events.recv().await.is_some() {} });
    let presser = {
        let handle = handle.clone();
        tokio::spawn(async move {
            while let Some(aid) = press_rx.recv().await {
                let _ = handle.press_aid(aid).await;
            }
        })
    };

    let (expected, got, _sock) = tokio::time::timeout(Duration::from_secs(60), host)
        .await
        .expect("replay finished")
        .unwrap()
        .unwrap_or_else(|e| panic!("session replay: {e}"));
    // The last host record may still be in flight inside the session.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let final_screen = handle.query_screen().await.unwrap();
    let _ = handle.disconnect().await;
    presser.abort();
    drain.abort();

    SessionReplay {
        expected: expected.iter().map(Unit::kind).collect(),
        got: got.iter().map(Unit::kind).collect(),
        query_replies: got
            .iter()
            .filter_map(Unit::data_3270)
            .filter(|d| d.first() == Some(&0x88))
            .map(<[u8]>::to_vec)
            .collect(),
        final_screen,
    }
}

/// `true` if `reply` is AID 0x88 followed by structured fields that end exactly at its end.
fn well_formed_structured_fields(reply: &[u8]) -> bool {
    let mut i = 1;
    while i < reply.len() {
        let Some(len) = reply
            .get(i..i + 2)
            .map(|l| usize::from(l[0]) << 8 | usize::from(l[1]))
        else {
            return false;
        };
        if len < 3 {
            return false;
        }
        i += len;
    }
    i == reply.len()
}

/// The screen part of the last core snapshot (without its `== record` line).
fn last_core_screen(snapshots: &[String]) -> &str {
    let last = snapshots.last().expect("at least one screen");
    last.split_once('\n').map_or("", |(_, screen)| screen)
}

fn check_session_replay(
    name: &str,
    replay: &SessionReplay,
    core: &trace::CoreReplay,
) -> Vec<String> {
    let mut failures = Vec::new();
    if replay.expected != replay.got {
        failures.push(format!(
            "{name}: client units differ from the recording\n  recorded: {:?}\n  replayed: {:?}",
            replay.expected, replay.got
        ));
    }
    for reply in &replay.query_replies {
        if !well_formed_structured_fields(reply) {
            failures.push(format!("{name}: malformed query reply {reply:02x?}"));
        }
    }
    let screen = trace::screen_text(&replay.final_screen);
    if screen != last_core_screen(&core.snapshots) {
        failures.push(format!(
            "{name}: final session screen differs from the core replay\n--- session\n{screen}--- core\n{}",
            last_core_screen(&core.snapshots)
        ));
    }
    failures
}

// ─── Hermetic end to end: record a scripted session, replay it ─────────────────────

/// One read from `s`, appended to `received`; returns the number of bytes (0 = closed).
async fn read_into(s: &mut TcpStream, received: &mut Vec<u8>) -> usize {
    let mut buf = [0_u8; 4096];
    let n = s.read(&mut buf).await.unwrap_or(0);
    received.extend_from_slice(&buf[..n]);
    n
}

/// Plays a z/OS-like TN3270E host: negotiation, a logon screen with a non-display field, a
/// Read Partition Query, and a welcome screen after Enter. Returns everything it received.
async fn scripted_host(listener: TcpListener) -> Vec<u8> {
    let (mut s, _) = listener.accept().await.unwrap();
    let mut received = Vec::new();
    s.write_all(&[0xFF, 0xFD, 0x28]).await.unwrap();
    read_into(&mut s, &mut received).await;
    s.write_all(&[0xFF, 0xFA, 0x28, 0x08, 0x02, 0xFF, 0xF0])
        .await
        .unwrap();
    read_into(&mut s, &mut received).await;
    let mut confirm = vec![0xFF, 0xFA, 0x28, 0x02, 0x04];
    confirm.extend_from_slice(b"IBM-3278-2-E\x01LUTEST01");
    confirm.extend_from_slice(&[0xFF, 0xF0]);
    s.write_all(&confirm).await.unwrap();
    read_into(&mut s, &mut received).await;
    s.write_all(&[0xFF, 0xFA, 0x28, 0x03, 0x04, 0x02, 0xFF, 0xF0])
        .await
        .unwrap();
    // Read Partition Query (WSF), as z/OS sends before the first screen; partition 0xFF is
    // escaped (IAC IAC) in the Telnet stream.
    s.write_all(&[
        0x00, 0x00, 0x00, 0x00, 0x02, 0xF3, 0x00, 0x05, 0x01, 0xFF, 0xFF, 0x02, 0xFF, 0xEF,
    ])
    .await
    .unwrap();
    // The query reply; it inhibits the keyboard until the next host write (x3270
    // `query_reply_end`), which the logon screen is.
    read_into(&mut s, &mut received).await;
    // Logon screen: SF protected "PASS: ", SF unprotected non-display, IC.
    let mut logon = vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3, 0x1D, 0x60];
    logon.extend([0xD7, 0xC1, 0xE2, 0xE2, 0x7A, 0x40, 0x1D, 0x4C, 0x13]);
    logon.extend(IAC_EOR);
    s.write_all(&logon).await.unwrap();
    // Wait for Enter, then the welcome screen.
    let mut units = UnitSplitter::default();
    'enter: loop {
        let before = received.len();
        if read_into(&mut s, &mut received).await == 0 {
            break;
        }
        for unit in units.feed(&received[before..]) {
            if unit.operator_aid() == Some(AidKey::Enter) {
                break 'enter;
            }
        }
    }
    let mut welcome = vec![0x00, 0x00, 0x00, 0x00, 0x03, 0x05, 0xC3, 0x1D, 0x60];
    welcome.extend([0xE6, 0xC5, 0xD3, 0xC3, 0xD6, 0xD4, 0xC5]); // WELCOME
    welcome.extend(IAC_EOR);
    s.write_all(&welcome).await.unwrap();
    // Keep the connection until the client goes.
    while read_into(&mut s, &mut received).await > 0 {}
    received
}

async fn wait_for_screen(events: &mut mpsc::Receiver<SessionEvent>, needle: &str) {
    tokio::time::timeout(T, async {
        while let Some(event) = events.recv().await {
            if let SessionEvent::ScreenUpdated(view) = event {
                if trace::screen_text(&view).contains(needle) {
                    return;
                }
            }
        }
        panic!("session ended before {needle:?}");
    })
    .await
    .unwrap_or_else(|_| panic!("screen never showed {needle:?}"));
}

/// Records a scripted session through the real coordinator (exactly as the proxy does),
/// checks the password never reached the trace, then replays the trace at both levels.
#[tokio::test]
async fn a_recorded_session_replays_through_the_core_and_the_session() {
    let host_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host_addr = host_listener.local_addr().unwrap();
    let host = tokio::spawn(scripted_host(host_listener));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let recorder = tokio::spawn(async move {
        let (client, _) = proxy.accept().await.unwrap();
        let host = TcpStream::connect(host_addr).await.unwrap();
        trace::pump(client, host, Instant::now(), tx, Vec::new()).await;
    });

    let profile_lines = vec![
        "terminal_model = \"Model2\"".to_owned(),
        "color_3279 = true".to_owned(),
        "extended = true".to_owned(),
        "codepage = \"cp037\"".to_owned(),
    ];
    let mut text = trace::header("scripted", &profile_lines);
    let header_only = trace::parse(&text).unwrap();
    let (handle, mut events, _join) =
        SessionCoordinator::connect(header_only.profile("127.0.0.1", proxy_port).unwrap())
            .await
            .unwrap();
    wait_for_screen(&mut events, "PASS:").await;
    handle.send_string("SECRET").await.unwrap();
    handle.press_aid(AidKey::Enter).await.unwrap();
    wait_for_screen(&mut events, "WELCOME").await;
    handle.disconnect().await.unwrap();
    let received_by_host = tokio::time::timeout(T, host).await.unwrap().unwrap();
    tokio::time::timeout(T, recorder).await.unwrap().unwrap();

    while let Ok(chunk) = rx.try_recv() {
        text.push_str(&trace::line(&chunk));
    }
    let trace = trace::parse(&text).unwrap();
    assert!(
        contains(&received_by_host, &SECRET),
        "the host got the password"
    );
    for chunk in &trace.chunks {
        assert!(
            !contains(&chunk.bytes, &SECRET),
            "password in the trace: {chunk:?}"
        );
    }

    let core = trace::replay_core(&trace).unwrap();
    assert!(core.problems.is_empty(), "{:?}", core.problems);
    assert!(core.snapshots.iter().any(|s| s.contains("PASS:")));
    assert!(core.snapshots.last().unwrap().contains("WELCOME"));

    let session = replay_session(&trace).await;
    assert!(
        session
            .expected
            .iter()
            .any(|k| k.starts_with("3270-DATA aid 88")),
        "the recording holds our query reply: {:?}",
        session.expected
    );
    let failures = check_session_replay("scripted", &session, &core);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ─── Local corpus ───────────────────────────────────────────────────────────────────

fn corpus_dir() -> Option<PathBuf> {
    let Some(dir) = std::env::var_os("BASTION3270_HOST_CORPUS").map(PathBuf::from) else {
        eprintln!("BASTION3270_HOST_CORPUS is not set — skipped");
        return None;
    };
    if dir.join("traces").is_dir() {
        Some(dir)
    } else {
        eprintln!(
            "no corpus of recorded host traffic at {} — skipped",
            dir.display()
        );
        None
    }
}

fn corpus_traces(dir: &std::path::Path) -> Vec<(String, Trace)> {
    let mut paths: Vec<_> = std::fs::read_dir(dir.join("traces"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "trc"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&p).unwrap();
            let trace = trace::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            (name, trace)
        })
        .collect()
}

#[test]
#[ignore = "needs the local corpus of recorded host traffic (see the module docs)"]
fn recorded_traces_replay_through_the_core() {
    let Some(dir) = corpus_dir() else { return };
    let update = std::env::var_os("BASTION3270_UPDATE_GOLDEN").is_some();
    let mut failures = Vec::new();
    for (name, trace) in corpus_traces(&dir) {
        let replay = match trace::replay_core(&trace) {
            Ok(replay) => replay,
            Err(e) => {
                failures.push(format!("{name}: {e}"));
                continue;
            }
        };
        failures.extend(replay.problems.iter().map(|p| format!("{name}: {p}")));
        let screens = replay.snapshots.join("\n");
        let golden = dir.join("golden").join(format!("{name}.txt"));
        if update {
            std::fs::create_dir_all(dir.join("golden")).unwrap();
            std::fs::write(&golden, &screens).unwrap();
            eprintln!("{name}: {} screens written", replay.snapshots.len());
        } else {
            match std::fs::read_to_string(&golden) {
                Ok(expected) if expected == screens => {}
                Ok(_) => failures.push(format!(
                    "{name}: screens differ from {} (BASTION3270_UPDATE_GOLDEN=1 rewrites it)",
                    golden.display()
                )),
                Err(_) => failures.push(format!("{name}: no golden file {}", golden.display())),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
#[ignore = "needs the local corpus of recorded host traffic (see the module docs)"]
async fn recorded_logon_replays_through_the_session() {
    let Some(dir) = corpus_dir() else { return };
    let Some((name, trace)) = corpus_traces(&dir).into_iter().find(|(n, _)| n == "logon") else {
        eprintln!("no traces/logon.trc in the corpus — skipped");
        return;
    };
    let core = trace::replay_core(&trace).unwrap();
    let session = replay_session(&trace).await;
    let failures = check_session_replay(&name, &session, &core);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
