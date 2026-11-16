//! Native desktop entry point for `bastion3270-gui`.
//!
//! ```text
//! bastion3270-gui [--profiles <file>]
//! ```
//!
//! Profiles and the diagnostics log live in the per-user directories of the platform
//! (see [`bastion3270_gui::storage`]); `--profiles` uses another catalog file instead.

// Release builds on Windows are GUI applications: no console window opens next to the client.
// Diagnostics then go only to the log file. Debug builds keep the console for development.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;

use bastion3270_gui::icon;
use bastion3270_gui::storage::{open_log, AppDirs, ProfileStore, LOG_FILE, PROFILES_FILE};
use bastion3270_gui::Bastion3270GuiApp;
use tracing_subscriber::fmt::writer::{BoxMakeWriter, MakeWriterExt};

const USAGE: &str = "usage: bastion3270-gui [--profiles <file>]";

fn main() -> ExitCode {
    let dirs = AppDirs::from_env();
    let log_path = dirs.as_ref().map(|d| d.logs.join(LOG_FILE));
    let log_error = init_logging(log_path.as_deref());
    if let Some(err) = &log_error {
        tracing::warn!(%err, "diagnostics log file not available, logging to stderr only");
    }

    let profiles_path = match profiles_arg(std::env::args_os().skip(1)) {
        Ok(Some(path)) => Some(path),
        Ok(None) => dirs.as_ref().map(|d| d.config.join(PROFILES_FILE)),
        Err(msg) => {
            tracing::error!("{msg}");
            eprintln!("{msg}\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let app = match Bastion3270GuiApp::new() {
        Ok(app) => app,
        Err(err) => {
            tracing::error!(%err, "failed to initialize the bastion3270-gui runtime");
            return ExitCode::from(1);
        }
    };
    let app = if let Some(path) = profiles_path {
        let opened = ProfileStore::open(path);
        if let Some(notice) = &opened.notice {
            tracing::warn!(target: "bastion3270_gui::profiles", "{notice}");
        }
        app.with_profiles(opened, log_path.filter(|_| log_error.is_none()))
    } else {
        tracing::warn!("no per-user directory in the environment; profiles are not saved");
        app
    };

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("bastion3270 — TN3270/TN3270E Client")
        .with_app_id(icon::APP_ID)
        .with_inner_size([1024.0, 680.0])
        .with_min_inner_size([400.0, 280.0]);
    if let Some(icon) = icon::app_icon() {
        viewport = viewport.with_icon(icon);
    }

    let native_options = eframe::NativeOptions {
        viewport,
        ..eframe::NativeOptions::default()
    };

    match eframe::run_native(
        "bastion3270",
        native_options,
        Box::new(|_cc| Ok(Box::new(app))),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(%err, "bastion3270-gui exited with an error");
            ExitCode::from(1)
        }
    }
}

/// Diagnostics go to stderr and, when it can be opened, to the log file of this run.
/// The level comes from `RUST_LOG` (default `warn`; `RUST_LOG=bastion3270_gui=debug` shows
/// mouse and clipboard handling). Returns why the log file is not used, if it is not.
fn init_logging(log_path: Option<&std::path::Path>) -> Option<String> {
    let (writer, error) = match log_path.map(open_log) {
        Some(Ok(file)) => (
            BoxMakeWriter::new(std::io::stderr.and(Mutex::new(file))),
            None,
        ),
        Some(Err(err)) => (BoxMakeWriter::new(std::io::stderr), Some(err.to_string())),
        None => (
            BoxMakeWriter::new(std::io::stderr),
            Some("no per-user directory in the environment".to_string()),
        ),
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        // Plain text: the same lines go to a file, where colour codes would be noise.
        .with_ansi(false)
        .with_writer(writer)
        .init();
    error
}

/// The `--profiles <file>` argument, if given. Anything else is an error, never ignored.
fn profiles_arg(mut args: impl Iterator<Item = OsString>) -> Result<Option<PathBuf>, String> {
    let mut path = None;
    while let Some(arg) = args.next() {
        if arg == "--profiles" {
            match args.next() {
                Some(value) if path.is_none() => path = Some(PathBuf::from(value)),
                Some(_) => return Err("--profiles given more than once".to_string()),
                None => return Err("--profiles needs a file name".to_string()),
            }
        } else {
            return Err(format!("unknown argument {}", arg.to_string_lossy()));
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> std::vec::IntoIter<OsString> {
        list.iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn profiles_argument_is_parsed_and_anything_else_refused() {
        assert_eq!(profiles_arg(args(&[])), Ok(None));
        assert_eq!(
            profiles_arg(args(&["--profiles", "team.toml"])),
            Ok(Some(PathBuf::from("team.toml")))
        );
        assert!(profiles_arg(args(&["--profiles"])).is_err());
        assert!(profiles_arg(args(&["--profiles", "a", "--profiles", "b"])).is_err());
        assert!(profiles_arg(args(&["team.toml"])).is_err());
    }
}
