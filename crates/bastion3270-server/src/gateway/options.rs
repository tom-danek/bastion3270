//! Session choices a user may make in the browser (`open` message): terminal model, screen
//! size, code page, LU name and the initial blank fill. Numeric lock is the administrator's
//! (profile) setting and not among them.
//!
//! Zero-Trust: these are *choices*, not configuration. Host, port, TLS, certificates and the
//! profile's policies are not among them and cannot be (`deny_unknown_fields`); every value is
//! validated here and again by the connection profile before anything connects.

use bastion3270_core::CodePageId;
use bastion3270_net::profile::{ConnectionProfile, ProfileTerminalModel};
use serde::Deserialize;

/// Smallest dynamic screen (a Model 2 screen: the host must be able to show its panels).
pub const MIN_DYNAMIC: (u16, u16) = (24, 80);
/// Largest dynamic screen the gateway accepts: bounds the memory of a session and the frames
/// sent to the browser (the benchmarks in `benches/` measure 62 × 160).
pub const MAX_DYNAMIC: (u16, u16) = (62, 160);

/// Terminal model choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum ModelChoice {
    /// 24 × 80.
    #[serde(rename = "2")]
    Model2,
    /// 32 × 80.
    #[serde(rename = "3")]
    Model3,
    /// 43 × 80.
    #[serde(rename = "4")]
    Model4,
    /// 27 × 132.
    #[serde(rename = "5")]
    Model5,
    /// `rows` × `cols` within [`MIN_DYNAMIC`]..=[`MAX_DYNAMIC`].
    #[serde(rename = "dynamic")]
    Dynamic,
}

/// The user's choices for a new session; every field is optional (the profile's value is
/// kept when a field is absent).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionOptions {
    /// Terminal model.
    #[serde(default)]
    pub model: Option<ModelChoice>,
    /// Rows of a dynamic screen (only with `model = "dynamic"`).
    #[serde(default)]
    pub rows: Option<u16>,
    /// Columns of a dynamic screen (only with `model = "dynamic"`).
    #[serde(default)]
    pub cols: Option<u16>,
    /// Host code page by name, number or x3270 alias (`cp1141`, `1047`, `german-euro`).
    #[serde(default)]
    pub codepage: Option<String>,
    /// Typing after empty field positions turns them into spaces (x3270 `blankFill`).
    #[serde(default)]
    pub blank_fill: Option<bool>,
    /// LU (or LU pool) name to request from the host; empty: the profile's / the host's choice.
    #[serde(default)]
    pub lu_name: Option<String>,
}

/// `true` if `name` matches one of the profile's `allowed_lu_names` (exact, or a prefix
/// ending in `*`), case-insensitively.
fn lu_allowed(name: &str, allowed: &[String]) -> bool {
    allowed
        .iter()
        .any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => name
                .get(..prefix.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(prefix)),
            None => name.eq_ignore_ascii_case(pattern),
        })
}

impl SessionOptions {
    /// Applies the choices to a copy of a profile's connection settings; `allowed_lu` is the
    /// profile's `allowed_lu_names` (`None`: any valid LU name).
    ///
    /// # Errors
    /// A description for the user (no configuration detail) when a choice is invalid.
    pub fn apply(
        &self,
        connection: &mut ConnectionProfile,
        allowed_lu: Option<&[String]>,
    ) -> Result<(), String> {
        match (self.model, self.rows, self.cols) {
            (Some(ModelChoice::Dynamic), Some(rows), Some(cols)) => {
                let (min, max) = (MIN_DYNAMIC, MAX_DYNAMIC);
                if !(min.0..=max.0).contains(&rows) || !(min.1..=max.1).contains(&cols) {
                    return Err(format!(
                        "screen size {rows} x {cols} outside {} x {} .. {} x {}",
                        min.0, min.1, max.0, max.1
                    ));
                }
                let (Ok(rows), Ok(cols)) = (u8::try_from(rows), u8::try_from(cols)) else {
                    return Err("screen size out of range".to_owned());
                };
                connection.terminal_model = ProfileTerminalModel::Dynamic { rows, cols };
            }
            (Some(ModelChoice::Dynamic), _, _) => {
                return Err("a dynamic screen needs rows and cols".to_owned());
            }
            (Some(model), None, None) => {
                connection.terminal_model = match model {
                    ModelChoice::Model2 => ProfileTerminalModel::Model2,
                    ModelChoice::Model3 => ProfileTerminalModel::Model3,
                    ModelChoice::Model4 => ProfileTerminalModel::Model4,
                    ModelChoice::Model5 | ModelChoice::Dynamic => ProfileTerminalModel::Model5,
                };
            }
            (None, None, None) => {}
            _ => return Err("rows and cols belong to a dynamic screen".to_owned()),
        }
        if let Some(name) = &self.codepage {
            let id = CodePageId::from_name(name).ok_or_else(|| {
                format!(
                    "unknown code page '{}'",
                    name.chars().take(32).collect::<String>()
                )
            })?;
            id.name().clone_into(&mut connection.codepage);
        }
        if let Some(on) = self.blank_fill {
            connection.blank_fill = on;
        }
        if let Some(lu) = self
            .lu_name
            .as_deref()
            .map(str::trim)
            .filter(|lu| !lu.is_empty())
        {
            if !bastion3270_net::profile::is_lu_name(lu) {
                return Err("an LU name has 1 to 8 letters, digits, @ # $".to_owned());
            }
            let lu = lu.to_ascii_uppercase();
            if allowed_lu.is_some_and(|allowed| !lu_allowed(&lu, allowed)) {
                return Err(format!("LU {lu} is not allowed for this system"));
            }
            connection.lu_name = Some(lu);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn apply(json: &str) -> Result<ConnectionProfile, String> {
        let options: SessionOptions = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let mut connection = ConnectionProfile::default();
        options.apply(&mut connection, None).map(|()| connection)
    }

    #[test]
    fn choices_change_only_what_they_name() {
        let base = ConnectionProfile::default();
        assert_eq!(apply("{}").unwrap(), base);
        let c = apply(r#"{"model": "4", "codepage": "german-euro", "blank_fill": false}"#).unwrap();
        assert_eq!(c.terminal_model, ProfileTerminalModel::Model4);
        assert_eq!(c.codepage, "cp1141");
        assert!(!c.blank_fill);
        assert_eq!(
            (c.host, c.port, c.tls_mode),
            (base.host, base.port, base.tls_mode)
        );
        let d = apply(r#"{"model": "dynamic", "rows": 62, "cols": 160}"#).unwrap();
        assert_eq!(
            d.terminal_model,
            ProfileTerminalModel::Dynamic {
                rows: 62,
                cols: 160
            }
        );
    }

    #[test]
    fn invalid_or_foreign_choices_are_refused() {
        for bad in [
            r#"{"model": "dynamic", "rows": 63, "cols": 160}"#,
            r#"{"model": "dynamic", "rows": 24, "cols": 79}"#,
            r#"{"model": "dynamic", "rows": 30}"#,
            r#"{"model": "2", "rows": 30, "cols": 90}"#,
            r#"{"rows": 30, "cols": 90}"#,
            r#"{"model": "6"}"#,
            r#"{"codepage": "cp9999"}"#,
            // Connection settings are not choices.
            r#"{"host": "evil.example"}"#,
            r#"{"port": 23}"#,
            r#"{"tls_mode": "disabled"}"#,
            // The administrator's setting.
            r#"{"numeric_lock": true}"#,
        ] {
            assert!(apply(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn lu_names_are_checked_and_may_be_restricted_per_profile() {
        let lu = |json: &str, allowed: Option<&[String]>| {
            let options: SessionOptions = serde_json::from_str(json).unwrap();
            let mut connection = ConnectionProfile::default();
            options
                .apply(&mut connection, allowed)
                .map(|()| connection.lu_name)
        };
        // Any valid name without a restriction; upper-cased; empty means "not chosen".
        assert_eq!(
            lu(r#"{"lu_name": "tso0001"}"#, None),
            Ok(Some("TSO0001".into()))
        );
        assert_eq!(lu(r#"{"lu_name": "  "}"#, None), Ok(None));
        for bad in [
            r#"{"lu_name": "LU 1"}"#,
            r#"{"lu_name": "9LU"}"#,
            r#"{"lu_name": "TOOLONG99"}"#,
        ] {
            assert!(lu(bad, None).is_err(), "{bad}");
        }
        let allowed = ["TSO0*".to_owned(), "CICS01".to_owned()];
        assert_eq!(
            lu(r#"{"lu_name": "TSO0042"}"#, Some(&allowed)),
            Ok(Some("TSO0042".into()))
        );
        assert_eq!(
            lu(r#"{"lu_name": "cics01"}"#, Some(&allowed)),
            Ok(Some("CICS01".into()))
        );
        assert!(lu(r#"{"lu_name": "CICS02"}"#, Some(&allowed)).is_err());
        assert!(lu(r#"{"lu_name": "TSO1001"}"#, Some(&allowed)).is_err());
        // An empty list allows none.
        assert!(lu(r#"{"lu_name": "TSO0001"}"#, Some(&[])).is_err());
    }
}
