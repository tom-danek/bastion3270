//! Records TN3270 / TN3270E traffic between a client and a host as a text trace, for
//! regression tests that replay real host data streams.
//!
//! ```text
//! # record: point a client profile at the listen address, use the terminal, then stop (Ctrl+C)
//! cargo run -p bastion3270-net --example record_proxy -- record \
//!     --listen 127.0.0.1:3271 --target <host:port> --out logon.trc \
//!     --model Model4 [--no-color] [--no-extended] [--codepage cp037] [--lu NAME] \
//!     [--redact USERID=XXXXXX]...
//!
//! # review: print every host screen of a trace
//! cargo run -p bastion3270-net --example record_proxy -- dump logon.trc
//!
//! # redact a recorded trace once more into a new file
//! cargo run -p bastion3270-net --example record_proxy -- redact logon.trc logon-new.trc \
//!     --redact USERID=XXXXXX...
//! ```
//!
//! What the client sends is redacted before it is written (typed field contents and passwords
//! become `0x00`, see `tests/common/trace.rs`); `--redact` additionally replaces a text (user
//! id, name) in both directions with a placeholder of the same length. The `--model` and
//! related flags must match the client profile: the replay uses them to negotiate like the
//! client did. Plain TCP only (put TLS termination in front if the host needs it).

use std::error::Error;
use std::time::Instant;

use bastion3270_core::CodePage;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

#[path = "../tests/common/trace.rs"]
mod trace;

use trace::{Chunk, Redactions};

type BoxError = Box<dyn Error + Send + Sync>;

struct RecordArgs {
    listen: String,
    target: String,
    out: String,
    profile_lines: Vec<String>,
    redact: Vec<(String, String)>,
}

fn usage() -> BoxError {
    "usage: record_proxy record --listen ADDR --target HOST:PORT --out FILE --model MODEL \
     [--no-color] [--no-extended] [--codepage CP] [--lu NAME] [--redact TEXT=REPLACEMENT]... \
     | record_proxy dump FILE \
     | record_proxy redact FILE NEW_FILE [--redact TEXT=REPLACEMENT]..."
        .into()
}

fn parse_record_args(mut args: impl Iterator<Item = String>) -> Result<RecordArgs, BoxError> {
    let (mut listen, mut target, mut out, mut model) = (None, None, None, None);
    let (mut color, mut extended, mut codepage, mut lu) = (true, true, "cp037".to_owned(), None);
    let mut redact = Vec::new();
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(usage);
        match flag.as_str() {
            "--listen" => listen = Some(value()?),
            "--target" => target = Some(value()?),
            "--out" => out = Some(value()?),
            "--model" => model = Some(value()?),
            "--codepage" => codepage = value()?,
            "--lu" => lu = Some(value()?),
            "--no-color" => color = false,
            "--no-extended" => extended = false,
            "--redact" => redact.push(redact_pair(&value()?)?),
            _ => return Err(usage()),
        }
    }
    let mut profile_lines = vec![
        format!("terminal_model = {:?}", model.ok_or_else(usage)?),
        format!("color_3279 = {color}"),
        format!("extended = {extended}"),
        format!("codepage = {codepage:?}"),
    ];
    if let Some(lu) = lu {
        profile_lines.push(format!("lu_name = {lu:?}"));
    }
    Ok(RecordArgs {
        listen: listen.ok_or_else(usage)?,
        target: target.ok_or_else(usage)?,
        out: out.ok_or_else(usage)?,
        profile_lines,
        redact,
    })
}

/// Parses one `--redact TEXT=REPLACEMENT` value.
fn redact_pair(pair: &str) -> Result<(String, String), BoxError> {
    let (text, replacement) = pair.split_once('=').ok_or_else(usage)?;
    if text.chars().count() != replacement.chars().count() || text.is_empty() {
        return Err(format!("--redact {pair}: both sides need the same length").into());
    }
    Ok((text.to_owned(), replacement.to_owned()))
}

/// The `--redact` pairs encoded in the profile's code page.
fn encode_redactions(
    pairs: &[(String, String)],
    codepage: &dyn CodePage,
) -> Result<Redactions, BoxError> {
    let encode = |s: &str| -> Result<Vec<u8>, BoxError> {
        s.chars()
            .map(|c| {
                codepage
                    .char_to_ebcdic(c)
                    .ok_or_else(|| format!("--redact {s:?}: {c:?} is not in the code page").into())
            })
            .collect()
    };
    pairs
        .iter()
        .map(|(from, to)| Ok((encode(from)?, encode(to)?)))
        .collect()
}

async fn record(args: RecordArgs) -> Result<(), BoxError> {
    let header = trace::header(&args.target, &args.profile_lines);
    // Validate the profile lines the replay will use.
    let parsed = trace::parse(&header)?;
    let profile = parsed.profile("127.0.0.1", 23)?;
    let redactions = encode_redactions(&args.redact, profile.core_codepage()?)?;

    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&args.out)
        .await
        .map_err(|e| format!("{}: {e} (the proxy never overwrites a trace)", args.out))?;
    file.write_all(header.as_bytes()).await?;

    let listener = TcpListener::bind(&args.listen).await?;
    eprintln!(
        "recording {} -> {} into {}",
        args.listen, args.target, args.out
    );
    let start = Instant::now();
    let (tx, mut rx) = mpsc::unbounded_channel::<Chunk>();

    let writer = tokio::spawn(async move {
        while let Some(chunk) = rx.recv().await {
            if file
                .write_all(trace::line(&chunk).as_bytes())
                .await
                .is_err()
                || file.flush().await.is_err()
            {
                eprintln!("cannot write the trace");
                return;
            }
        }
    });

    let serve = async {
        loop {
            let (client, peer) = listener.accept().await?;
            eprintln!("client {peer} connected");
            let host = TcpStream::connect(&args.target).await?;
            trace::pump(client, host, start, tx.clone(), redactions.clone()).await;
            eprintln!("client {peer} disconnected");
        }
        #[allow(unreachable_code)]
        Ok::<(), BoxError>(())
    };
    tokio::select! {
        result = serve => result?,
        _ = tokio::signal::ctrl_c() => eprintln!("stopped"),
    }
    drop(tx);
    let _ = writer.await;
    Ok(())
}

/// Prints every host screen of a trace and what the core rejected.
fn dump(path: &str) -> Result<(), BoxError> {
    let text = std::fs::read_to_string(path)?;
    let replay = trace::replay_core(&trace::parse(&text)?)?;
    for snapshot in &replay.snapshots {
        println!("{snapshot}");
    }
    for problem in &replay.problems {
        println!("PROBLEM: {problem}");
    }
    println!(
        "{} screens, {} problems",
        replay.snapshots.len(),
        replay.problems.len()
    );
    Ok(())
}

/// Writes `input` with the redactions applied once more to the new file `output`.
fn redact(
    input: &str,
    output: &str,
    mut args: impl Iterator<Item = String>,
) -> Result<(), BoxError> {
    let mut pairs = Vec::new();
    while let Some(flag) = args.next() {
        match (flag.as_str(), args.next()) {
            ("--redact", Some(pair)) => pairs.push(redact_pair(&pair)?),
            _ => return Err(usage()),
        }
    }
    let text = std::fs::read_to_string(input)?;
    let parsed = trace::parse(&text)?;
    let profile = parsed.profile("127.0.0.1", 23)?;
    let redactions = encode_redactions(&pairs, profile.core_codepage()?)?;
    let mut out: String =
        text.lines()
            .take_while(|l| l.starts_with('#'))
            .fold(String::new(), |mut acc, l| {
                acc.push_str(l);
                acc.push('\n');
                acc
            });
    for chunk in trace::redact_trace(&parsed, &redactions) {
        out.push_str(&trace::line(&chunk));
    }
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .map_err(|e| format!("{output}: {e} (never overwritten)"))?;
    std::io::Write::write_all(&mut file, out.as_bytes())?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("record") => record(parse_record_args(args)?).await,
        Some("dump") => dump(&args.next().ok_or_else(usage)?),
        Some("redact") => {
            let input = args.next().ok_or_else(usage)?;
            let output = args.next().ok_or_else(usage)?;
            redact(&input, &output, args)
        }
        _ => Err(usage()),
    }
}
