//! Saved profiles (`SavedProfile`, `ProfileCatalog`) with TOML persistence.
//!
//! A fresh installation has one built-in profile, the local Hercules MVS 3.8j (TK4-) of the
//! quick start; users add their own systems in the profile manager.

use std::path::Path;

use bastion3270_net::{ConnectionProfile, NetError, ProfileTerminalModel, TlsMode};
use serde::{Deserialize, Serialize};

use crate::keymap::KeyboardPreset;
use crate::theme::{CursorStyle, TerminalColorScheme};

/// A named desktop session profile combining a network [`ConnectionProfile`] with UI preferences.
///
/// In a profile file `name` and `connection` are required, the rest has a default, and a
/// misspelt key is an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedProfile {
    /// Human-readable profile name shown in the session selector.
    pub name: String,
    /// Optional notes / description (e.g. LPAR, environment).
    #[serde(default)]
    pub description: String,
    /// Underlying network, TLS, model, and codepage configuration.
    pub connection: ConnectionProfile,
    /// Preferred CRT color scheme for this profile.
    #[serde(default)]
    pub color_scheme: TerminalColorScheme,
    /// Preferred cursor style.
    #[serde(default)]
    pub cursor_style: CursorStyle,
    /// Whether crosshair cursor lines are enabled by default for this profile.
    #[serde(default)]
    pub crosshair_enabled: bool,
    /// Whether unprotected (editable) input fields are visually highlighted on the canvas.
    #[serde(default)]
    pub highlight_input_fields: bool,
    /// Key layout (the same presets as the web client).
    #[serde(default)]
    pub keyboard: KeyboardPreset,
}

impl Default for SavedProfile {
    fn default() -> Self {
        Self::hercules_tk4_preset()
    }
}

impl SavedProfile {
    /// Built-in preset for the local Hercules MVS 3.8j (TK4-) container (`127.0.0.1:3270`, plain TCP).
    #[must_use]
    pub fn hercules_tk4_preset() -> Self {
        Self {
            name: "Hercules MVS 3.8j (TK4-)".to_string(),
            description: "Local MVS 3.8j Turnkey 4- emulator on 127.0.0.1:3270".to_string(),
            connection: ConnectionProfile {
                host: "127.0.0.1".to_string(),
                port: 3270,
                tls_mode: TlsMode::Disabled,
                terminal_model: ProfileTerminalModel::Model2,
                color_3279: true,
                extended: true,
                codepage: "cp037".to_string(),
                ..ConnectionProfile::default()
            },
            color_scheme: TerminalColorScheme::Classic3279,
            cursor_style: CursorStyle::Block,
            crosshair_enabled: false,
            highlight_input_fields: false,
            keyboard: KeyboardPreset::X3270,
        }
    }

    /// Validates both the profile metadata and the underlying [`ConnectionProfile`].
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if the profile name is blank or the connection settings are invalid.
    pub fn validate(&self) -> Result<(), NetError> {
        if self.name.trim().is_empty() {
            return Err(NetError::Config(
                "profile name must not be empty".to_string(),
            ));
        }
        self.connection.validate()
    }
}

/// Collection of saved connection profiles with an active selection index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCatalog {
    profiles: Vec<SavedProfile>,
    #[serde(default)]
    selected_index: usize,
}

impl Default for ProfileCatalog {
    fn default() -> Self {
        Self {
            profiles: vec![SavedProfile::hercules_tk4_preset()],
            selected_index: 0,
        }
    }
}

impl ProfileCatalog {
    /// Creates a new [`ProfileCatalog`] with the built-in profile.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A catalog of `profiles` with the one at `selected` chosen (the first one if `selected`
    /// is out of range).
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if there is no profile or one is not valid.
    pub fn from_profiles(profiles: Vec<SavedProfile>, selected: usize) -> Result<Self, NetError> {
        if profiles.is_empty() {
            return Err(NetError::Config(
                "profile catalog must contain at least one profile".to_string(),
            ));
        }
        for profile in &profiles {
            profile.validate()?;
        }
        let selected_index = if selected < profiles.len() {
            selected
        } else {
            0
        };
        Ok(Self {
            profiles,
            selected_index,
        })
    }

    /// Returns a slice of all saved profiles.
    #[must_use]
    pub fn profiles(&self) -> &[SavedProfile] {
        &self.profiles
    }

    /// Returns the number of profiles in the catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Returns `true` if the catalog contains no profiles.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Returns the currently selected profile index.
    #[must_use]
    pub const fn selected_index(&self) -> usize {
        self.selected_index
    }

    /// Selects a profile by index if within bounds, returning `true` on success.
    pub fn select(&mut self, index: usize) -> bool {
        if index < self.profiles.len() {
            self.selected_index = index;
            true
        } else {
            false
        }
    }

    /// Returns a reference to the currently selected [`SavedProfile`].
    #[must_use]
    pub fn selected(&self) -> Option<&SavedProfile> {
        self.profiles.get(self.selected_index)
    }

    /// Returns a mutable reference to the currently selected [`SavedProfile`].
    pub fn selected_mut(&mut self) -> Option<&mut SavedProfile> {
        self.profiles.get_mut(self.selected_index)
    }

    /// Validates and adds a new [`SavedProfile`] to the catalog, selecting it.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if validation fails.
    pub fn add_profile(&mut self, profile: SavedProfile) -> Result<usize, NetError> {
        profile.validate()?;
        self.profiles.push(profile);
        let new_idx = self.profiles.len().saturating_sub(1);
        self.selected_index = new_idx;
        Ok(new_idx)
    }

    /// Duplicates the currently selected profile with `" (Copy)"` appended to its name.
    pub fn duplicate_selected(&mut self) -> Option<usize> {
        let mut copy = self.selected()?.clone();
        copy.name = format!("{} (Copy)", copy.name);
        self.profiles.push(copy);
        let new_idx = self.profiles.len().saturating_sub(1);
        self.selected_index = new_idx;
        Some(new_idx)
    }

    /// Removes the profile at `index`, keeping at least 1 profile in the catalog.
    /// Returns `true` if removed.
    pub fn remove_profile(&mut self, index: usize) -> bool {
        if self.profiles.len() <= 1 || index >= self.profiles.len() {
            return false;
        }
        self.profiles.remove(index);
        if self.selected_index >= self.profiles.len() {
            self.selected_index = self.profiles.len().saturating_sub(1);
        }
        true
    }

    /// Serializes the entire [`ProfileCatalog`] to a TOML string.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if serialization fails.
    pub fn to_toml_string(&self) -> Result<String, NetError> {
        toml::to_string_pretty(self)
            .map_err(|e| NetError::Config(format!("failed to serialize profile catalog: {e}")))
    }

    /// Deserializes a [`ProfileCatalog`] from a TOML string and validates all profiles.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if parsing fails or any profile is invalid.
    pub fn from_toml_str(s: &str) -> Result<Self, NetError> {
        let mut catalog: Self = toml::from_str(s)
            .map_err(|e| NetError::Config(format!("failed to parse profile catalog TOML: {e}")))?;
        if catalog.profiles.is_empty() {
            return Err(NetError::Config(
                "profile catalog must contain at least one profile".to_string(),
            ));
        }
        for profile in &catalog.profiles {
            profile.validate()?;
        }
        if catalog.selected_index >= catalog.profiles.len() {
            catalog.selected_index = 0;
        }
        Ok(catalog)
    }

    /// Saves the catalog to a TOML file on disk.
    ///
    /// # Errors
    /// Returns [`NetError`] on serialization or file I/O failure.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), NetError> {
        let content = self.to_toml_string()?;
        std::fs::write(path, content).map_err(NetError::Io)
    }

    /// Loads a catalog from a TOML file on disk.
    ///
    /// # Errors
    /// Returns [`NetError`] on file I/O or TOML validation failure.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, NetError> {
        let content = std::fs::read_to_string(path).map_err(NetError::Io)?;
        Self::from_toml_str(&content)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_a_fresh_catalog_has_the_hercules_profile() {
        let catalog = ProfileCatalog::new();
        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog.profiles()[0].connection.host, "127.0.0.1");
        for p in catalog.profiles() {
            assert!(p.validate().is_ok());
        }
    }

    #[test]
    fn test_catalog_crud_and_toml_roundtrip() {
        let mut catalog = ProfileCatalog::new();
        assert_eq!(catalog.selected_index(), 0);

        // Duplicate selected
        assert_eq!(catalog.duplicate_selected(), Some(1));
        assert_eq!(catalog.duplicate_selected(), Some(2));
        assert_eq!(catalog.duplicate_selected(), Some(3));
        assert_eq!(catalog.len(), 4);
        assert_eq!(catalog.selected_index(), 3);

        // Serialize and deserialize
        let toml_str = catalog.to_toml_string().unwrap_or_default();
        assert_ne!(toml_str, "");

        let restored = ProfileCatalog::from_toml_str(&toml_str);
        assert_eq!(restored.ok(), Some(catalog.clone()));

        // Remove down to 1 profile; last one cannot be removed
        assert!(catalog.remove_profile(3));
        assert!(catalog.remove_profile(2));
        assert!(catalog.remove_profile(1));
        assert_eq!(catalog.len(), 1);
        assert!(!catalog.remove_profile(0));
    }

    /// A profile file is checked like the gateway configuration: a misspelt key or a profile
    /// without a name is an error (the file is kept aside), not a profile that silently takes
    /// the built-in Hercules values.
    #[test]
    fn test_profile_files_reject_typos_and_profiles_without_name() {
        let profile = |body: &str| {
            format!(
                "selected_index = 0\n[[profiles]]\n{body}\n[profiles.connection]\n\
                 host = \"zos1.example.com\"\ntls_mode = \"enabled\"\n"
            )
        };
        let typo = ProfileCatalog::from_toml_str(&profile("name = \"Z\"\ncolr_scheme = \"light\""));
        assert!(
            typo.as_ref()
                .is_err_and(|e| e.to_string().contains("colr_scheme")),
            "{typo:?}"
        );
        let unnamed = ProfileCatalog::from_toml_str(&profile("description = \"x\""));
        assert!(
            unnamed
                .as_ref()
                .is_err_and(|e| e.to_string().contains("name")),
            "{unnamed:?}"
        );
        let catalog = ProfileCatalog::from_toml_str(&profile("name = \"Z\"")).unwrap();
        let only = &catalog.profiles()[0];
        assert_eq!(
            only.description, "",
            "no description: empty, not the Hercules one"
        );
        assert_eq!(only.keyboard, KeyboardPreset::X3270);
        assert_eq!(only.color_scheme, TerminalColorScheme::Classic3279);
    }
}
