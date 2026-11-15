//! `hercules_probe` — minimal headless TN3270(E) probe for live hosts.
//!
//! Connects to a mainframe (default: local Hercules MVS 3.8j TK4- on `127.0.0.1:3270`),
//! waits for the first formatted screen, prints the Zero-Trust [`SafeScreenView`]
//! (Non-display fields masked) together with session status, and disconnects cleanly.
//!
//! # Usage
//! ```text
//! cargo run -p bastion3270-net --example hercules_probe                 # defaults + BASTION3270_* env
//! cargo run -p bastion3270-net --example hercules_probe -- profile.toml # TOML profile + env overrides
//! BASTION3270_HOST=10.0.0.5 BASTION3270_PORT=992 BASTION3270_TLS=enabled \
//!     cargo run -p bastion3270-net --example hercules_probe
//! ```
//!
//! Optional env `BASTION3270_PROBE_WAIT_MS` (default `3000`) controls how long the probe keeps
//! collecting screen updates after the first one before printing the final screen.
//!
//! Exit codes: `0` success, `1` connection / protocol failure, `2` configuration error.

use std::process::ExitCode;
use std::time::Duration;

use bastion3270_core::safe_view::SafeScreenView;
use bastion3270_net::{ConnectionProfile, NetError, SessionCoordinator, SessionEvent};

/// Hard upper bound for the whole probe, regardless of host behaviour.
const OVERALL_DEADLINE: Duration = Duration::from_secs(30);

fn load_profile() -> Result<ConnectionProfile, NetError> {
    match std::env::args().nth(1) {
        Some(path) => {
            let mut profile = ConnectionProfile::from_toml_file(&path)?;
            profile.apply_env_overrides()?;
            profile.validate()?;
            Ok(profile)
        }
        None => ConnectionProfile::from_env(),
    }
}

fn settle_window() -> Duration {
    let ms = std::env::var("BASTION3270_PROBE_WAIT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3_000);
    Duration::from_millis(ms)
}

fn print_screen(view: &SafeScreenView) {
    let cols = usize::from(view.cols());
    let border = "-".repeat(cols);
    println!("+{border}+");
    for row in 0..view.rows() {
        let text = view.row_text(row).unwrap_or_default();
        println!("|{text:<cols$}|");
    }
    println!("+{border}+");
}

async fn run(profile: ConnectionProfile) -> Result<(), NetError> {
    println!(
        "bastion3270 probe → {}:{} (tls: {:?}, model: {:?}, codepage: {})",
        profile.host, profile.port, profile.tls_mode, profile.terminal_model, profile.codepage
    );

    let (handle, mut events, join) = SessionCoordinator::connect(profile).await?;
    let settle = settle_window();

    // Phase 1: wait for the first screen. Phase 2: keep absorbing updates until the host
    // has been quiet for `settle` (TK4- typically paints the logo in several writes).
    let mut last_screen: Option<SafeScreenView> = None;
    loop {
        let next = if last_screen.is_some() {
            tokio::time::timeout(settle, events.recv()).await
        } else {
            Ok(events.recv().await)
        };

        match next {
            Err(_quiet) => break,
            Ok(None) => break,
            Ok(Some(event)) => match event {
                SessionEvent::NegotiationComplete {
                    is_tn3270e,
                    assigned_lu,
                } => {
                    println!(
                        "negotiated: {} (LU: {})",
                        if is_tn3270e { "TN3270E" } else { "TN3270" },
                        assigned_lu.as_deref().unwrap_or("-")
                    );
                }
                SessionEvent::ScreenUpdated(view) => last_screen = Some(view),
                SessionEvent::NvtData(data) => {
                    println!("NVT: {}", String::from_utf8_lossy(&data).trim_end());
                }
                SessionEvent::Warning(msg) => eprintln!("warning: {msg}"),
                SessionEvent::Error(msg) => eprintln!("session error: {msg}"),
                SessionEvent::Disconnected => break,
                SessionEvent::HostModeChanged(mode) => eprintln!("host mode: {mode:?}"),
                SessionEvent::StateChanged(_)
                | SessionEvent::KeyboardStateChanged(_)
                | SessionEvent::InsertModeChanged(_)
                | SessionEvent::Alarm => {}
            },
        }
    }

    if let Some(view) = &last_screen {
        print_screen(view);
    } else {
        eprintln!("no 3270 screen received from host");
    }

    if handle.is_open() {
        if let Ok(status) = handle.query_status().await {
            println!(
                "status: state={:?} keyboard={:?} cursor=({},{}) tn3270e={} tls={} formatted={}",
                status.state,
                status.keyboard_state,
                status.cursor_row,
                status.cursor_col,
                status.is_tn3270e,
                status.is_tls,
                status.is_formatted
            );
        }
        let _ = handle.disconnect().await;
    }

    let outcome = join
        .await
        .map_err(|e| NetError::protocol(format!("session task join failure: {e}")))?;

    match (outcome, last_screen) {
        (Ok(()), Some(_)) => Ok(()),
        (Ok(()), None) => Err(NetError::protocol(
            "host closed session before sending a screen",
        )),
        (Err(err), _) => Err(err),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let profile = match load_profile() {
        Ok(p) => p,
        Err(err) => {
            eprintln!("configuration error: {err}");
            return ExitCode::from(2);
        }
    };

    match tokio::time::timeout(OVERALL_DEADLINE, run(profile)).await {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(err)) => {
            eprintln!("probe failed: {err}");
            ExitCode::from(1)
        }
        Err(_) => {
            eprintln!("probe failed: overall deadline of {OVERALL_DEADLINE:?} exceeded");
            ExitCode::from(1)
        }
    }
}
