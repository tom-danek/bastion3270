//! Where the desktop client keeps its files: the profile catalog and the diagnostics log.
//!
//! The locations follow each platform's convention for per-user application data, so the
//! client behaves the same however it was started (double click, shortcut, terminal) — the
//! working directory never matters:
//!
//! | Platform | Profiles | Log |
//! | :--- | :--- | :--- |
//! | Linux and other Unix | `$XDG_CONFIG_HOME/bastion3270/` (`~/.config/…`) | `$XDG_STATE_HOME/bastion3270/` (`~/.local/state/…`) |
//! | Windows | `%APPDATA%\bastion3270\` | `%LOCALAPPDATA%\bastion3270\logs\` |
//! | macOS | `~/Library/Application Support/bastion3270/` | `~/Library/Logs/bastion3270/` |
//!
//! The directories are read from the environment (XDG Base Directory Specification on Unix,
//! the `APPDATA` / `LOCALAPPDATA` variables Windows sets for every user session). Only absolute
//! values count: the XDG specification says relative ones are invalid, and a relative path
//! would again depend on the working directory.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bastion3270_net::NetError;

use crate::profiles::ProfileCatalog;

/// Directory name under every platform's base directory.
const APP_DIR: &str = "bastion3270";
/// File name of the profile catalog.
pub const PROFILES_FILE: &str = "profiles.toml";
/// File name of the diagnostics log of the current run (the previous run is kept as `.1`).
pub const LOG_FILE: &str = "bastion3270-gui.log";

/// Directory convention to follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux and every other Unix: XDG Base Directory Specification.
    Unix,
    /// macOS: `~/Library`.
    MacOs,
    /// Windows: `%APPDATA%` and `%LOCALAPPDATA%`.
    Windows,
}

impl Platform {
    /// The platform this binary was built for.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Unix
        }
    }
}

/// Per-user directories of the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDirs {
    /// Directory of the profile catalog.
    pub config: PathBuf,
    /// Directory of the diagnostics log.
    pub logs: PathBuf,
}

impl AppDirs {
    /// Directories of the current user on the current platform, or `None` when the
    /// environment does not name them (e.g. no `HOME`).
    #[must_use]
    pub fn from_env() -> Option<Self> {
        Self::resolve(Platform::current(), |key| std::env::var_os(key))
    }

    /// Directories for `platform`, reading environment variables through `env`.
    #[must_use]
    pub fn resolve(platform: Platform, env: impl Fn(&str) -> Option<OsString>) -> Option<Self> {
        let var = |key: &str| env(key).map(PathBuf::from).filter(|p| p.is_absolute());
        match platform {
            Platform::Windows => Some(Self {
                config: var("APPDATA")?.join(APP_DIR),
                logs: var("LOCALAPPDATA")?.join(APP_DIR).join("logs"),
            }),
            Platform::MacOs => {
                let library = var("HOME")?.join("Library");
                Some(Self {
                    config: library.join("Application Support").join(APP_DIR),
                    logs: library.join("Logs").join(APP_DIR),
                })
            }
            Platform::Unix => {
                let home = var("HOME");
                let config =
                    var("XDG_CONFIG_HOME").or_else(|| Some(home.as_ref()?.join(".config")));
                let state = var("XDG_STATE_HOME")
                    .or_else(|| Some(home.as_ref()?.join(".local").join("state")));
                Some(Self {
                    config: config?.join(APP_DIR),
                    logs: state?.join(APP_DIR),
                })
            }
        }
    }
}

/// Opens the log file of this run, keeping the previous run's log as `<name>.1`.
///
/// # Errors
/// Returns the I/O error if the directory or the file cannot be created.
pub fn open_log(path: &Path) -> io::Result<fs::File> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    match fs::rename(path, append_suffix(path, ".1")) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        _ => {}
    }
    fs::File::create(path)
}

/// `path` with `suffix` appended to the whole file name (`profiles.toml` → `profiles.toml.1`).
fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// The profile catalog file and whether the client may write it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileStore {
    path: PathBuf,
    /// Why changes are not written, if they are not.
    read_only: Option<String>,
}

/// Result of [`ProfileStore::open`]: the store, the catalog to start with and, when the file
/// could not be used, a message for the user.
#[derive(Debug)]
pub struct OpenedProfiles {
    /// Where changes are saved.
    pub store: ProfileStore,
    /// The catalog to start with.
    pub catalog: ProfileCatalog,
    /// What went wrong with the file, if anything (shown to the user and logged).
    pub notice: Option<String>,
}

impl ProfileStore {
    /// Loads the catalog from `path`.
    ///
    /// * Missing file (first start): the built-in profiles; the file is created on the first
    ///   change.
    /// * Invalid file: it is never overwritten. It is renamed to
    ///   `<name>.invalid-<unix seconds>` so the user can repair it, and the client starts with
    ///   the built-in profiles. If it cannot be renamed, changes are not saved at all.
    /// * Unreadable file (e.g. permissions): built-in profiles, changes are not saved.
    #[must_use]
    pub fn open(path: PathBuf) -> OpenedProfiles {
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Self::opened(path, None, ProfileCatalog::new(), None);
            }
            Err(err) => {
                let notice = format!("cannot read {}: {err}", path.display());
                return Self::opened(
                    path,
                    Some(notice.clone()),
                    ProfileCatalog::new(),
                    Some(notice),
                );
            }
        };
        match ProfileCatalog::from_toml_str(&text) {
            Ok(catalog) => Self::opened(path, None, catalog, None),
            Err(err) => {
                let secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let aside = append_suffix(&path, &format!(".invalid-{secs}"));
                match fs::rename(&path, &aside) {
                    Ok(()) => {
                        let notice = format!(
                            "{} is invalid ({err}); it was moved to {} and the built-in profiles are used",
                            path.display(),
                            aside.display()
                        );
                        Self::opened(path, None, ProfileCatalog::new(), Some(notice))
                    }
                    Err(rename_err) => {
                        let notice = format!(
                            "{} is invalid ({err}) and could not be moved aside ({rename_err}); changes are not saved",
                            path.display()
                        );
                        Self::opened(
                            path,
                            Some(notice.clone()),
                            ProfileCatalog::new(),
                            Some(notice),
                        )
                    }
                }
            }
        }
    }

    fn opened(
        path: PathBuf,
        read_only: Option<String>,
        catalog: ProfileCatalog,
        notice: Option<String>,
    ) -> OpenedProfiles {
        OpenedProfiles {
            store: Self { path, read_only },
            catalog,
            notice,
        }
    }

    /// Path of the catalog file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes `catalog` atomically: to a temporary file next to the target, then renamed over
    /// it, so a crash or a full disk never leaves a half-written catalog. Only a catalog that
    /// loads again is written (every profile valid).
    ///
    /// # Errors
    /// [`NetError::Config`] if the store is read-only or a profile is invalid,
    /// [`NetError::Io`] if the file cannot be written.
    pub fn save(&self, catalog: &ProfileCatalog) -> Result<(), NetError> {
        if let Some(reason) = &self.read_only {
            return Err(NetError::Config(format!(
                "profiles are not saved: {reason}"
            )));
        }
        let text = catalog.to_toml_string()?;
        ProfileCatalog::from_toml_str(&text)?;
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(NetError::Io)?;
        }
        let tmp = append_suffix(&self.path, ".tmp");
        fs::write(&tmp, text).map_err(NetError::Io)?;
        fs::rename(&tmp, &self.path).map_err(NetError::Io)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    /// A fresh, empty directory for one test (emptied again at the start of the next run).
    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("bastion3270-gui-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An absolute path on the host running the test (`C:\a\b` on Windows, `/a/b`
    /// elsewhere): what counts as absolute depends on the host, not on the platform under test.
    fn abs(parts: &[&str]) -> PathBuf {
        let root = if cfg!(windows) { "C:\\" } else { "/" };
        parts
            .iter()
            .fold(PathBuf::from(root), |p, part| p.join(part))
    }

    fn env_of(vars: Vec<(&'static str, PathBuf)>) -> impl Fn(&str) -> Option<OsString> {
        move |key| {
            vars.iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.clone().into_os_string())
        }
    }

    #[test]
    fn directories_follow_each_platform_convention() {
        let win = AppDirs::resolve(
            Platform::Windows,
            env_of(vec![
                ("APPDATA", abs(&["u", "Roaming"])),
                ("LOCALAPPDATA", abs(&["u", "Local"])),
            ]),
        );
        assert_eq!(
            win,
            Some(AppDirs {
                config: abs(&["u", "Roaming", "bastion3270"]),
                logs: abs(&["u", "Local", "bastion3270", "logs"]),
            })
        );
        let mac = AppDirs::resolve(
            Platform::MacOs,
            env_of(vec![("HOME", abs(&["Users", "op"]))]),
        );
        assert_eq!(
            mac,
            Some(AppDirs {
                config: abs(&[
                    "Users",
                    "op",
                    "Library",
                    "Application Support",
                    "bastion3270"
                ]),
                logs: abs(&["Users", "op", "Library", "Logs", "bastion3270"]),
            })
        );
        let unix = AppDirs::resolve(Platform::Unix, env_of(vec![("HOME", abs(&["home", "op"]))]));
        assert_eq!(
            unix,
            Some(AppDirs {
                config: abs(&["home", "op", ".config", "bastion3270"]),
                logs: abs(&["home", "op", ".local", "state", "bastion3270"]),
            })
        );
    }

    #[test]
    fn xdg_variables_win_over_home_and_relative_values_are_ignored() {
        let dirs = AppDirs::resolve(
            Platform::Unix,
            env_of(vec![
                ("HOME", abs(&["home", "op"])),
                ("XDG_CONFIG_HOME", abs(&["cfg"])),
                ("XDG_STATE_HOME", PathBuf::from("relative").join("state")),
            ]),
        );
        assert_eq!(
            dirs,
            Some(AppDirs {
                config: abs(&["cfg", "bastion3270"]),
                logs: abs(&["home", "op", ".local", "state", "bastion3270"]),
            })
        );
        // Nothing absolute to build on: no directories rather than the working directory.
        assert_eq!(
            AppDirs::resolve(Platform::Unix, env_of(vec![("HOME", PathBuf::from("op"))])),
            None
        );
        assert_eq!(
            AppDirs::resolve(Platform::Windows, env_of(vec![("APPDATA", abs(&["r"]))])),
            None
        );
    }

    #[test]
    fn first_start_uses_built_in_profiles_and_saves_on_change() {
        let dir = scratch("first-start");
        let path = dir.as_path().join("sub").join(PROFILES_FILE);
        let opened = ProfileStore::open(path.clone());
        assert!(opened.notice.is_none());
        assert_eq!(opened.catalog, ProfileCatalog::new());
        assert!(!path.exists(), "nothing is written before a change");

        let mut catalog = opened.catalog;
        catalog.duplicate_selected();
        opened.store.save(&catalog).unwrap();
        assert_eq!(ProfileStore::open(path).catalog, catalog);
    }

    #[test]
    fn invalid_file_is_moved_aside_never_overwritten() {
        let dir = scratch("invalid-file");
        let path = dir.as_path().join(PROFILES_FILE);
        fs::write(&path, "selected_index = \"not a number\"\n").unwrap();

        let opened = ProfileStore::open(path.clone());
        assert!(opened.notice.as_deref().unwrap_or("").contains("invalid"));
        assert_eq!(opened.catalog, ProfileCatalog::new());
        let aside: Vec<_> = fs::read_dir(dir.as_path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("profiles.toml.invalid-"))
            .collect();
        assert_eq!(aside.len(), 1, "the user's file is kept: {aside:?}");

        // Saving now writes a fresh file; the moved-aside one is untouched.
        opened.store.save(&opened.catalog).unwrap();
        let kept = fs::read_to_string(dir.as_path().join(&aside[0])).unwrap();
        assert_eq!(kept, "selected_index = \"not a number\"\n");
    }

    #[test]
    fn invalid_catalog_is_not_saved() {
        let dir = scratch("invalid-catalog");
        let path = dir.as_path().join(PROFILES_FILE);
        let opened = ProfileStore::open(path.clone());
        let mut catalog = opened.catalog;
        if let Some(p) = catalog.selected_mut() {
            p.connection.host.clear();
        }
        assert!(opened.store.save(&catalog).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn log_of_the_previous_run_is_kept() {
        let dir = scratch("log-rotation");
        let path = dir.as_path().join("logs").join(LOG_FILE);
        drop(open_log(&path).unwrap());
        fs::write(&path, "run 1").unwrap();
        open_log(&path).unwrap();
        assert_eq!(
            fs::read_to_string(append_suffix(&path, ".1")).unwrap(),
            "run 1"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "");
    }
}
