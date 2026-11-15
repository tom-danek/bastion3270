//! The profile manager: a window of its own with the list of profiles and a form.
//!
//! The manager edits a **working copy** of the profiles. Nothing reaches the
//! [`ProfileCatalog`] (and the profile file) before **Save**, and **Cancel** drops the copy.
//! The profile shown in the form is chosen in the manager's own list; the profile the main
//! window connects with stays as it is.
//!
//! The window is an `egui` *viewport*: a native window on Windows, macOS and Linux. Where a
//! second window is not possible (and in tests, which run without a windowing backend), `egui`
//! draws the same content as a window inside the main one.

use std::path::PathBuf;

use bastion3270_core::CodePageId;
use bastion3270_net::{NetError, ProfileTerminalModel, TlsMode};
use egui::{Align, Color32, Layout, Panel, RichText, ScrollArea, TextEdit, Ui};

use crate::keymap::KeyboardPreset;
use crate::profiles::{ProfileCatalog, SavedProfile};
use crate::theme::{CursorStyle, TerminalColorScheme};

/// Width of the text fields of the form.
const FIELD_WIDTH: f32 = 320.0;
/// Width of the label column, the same in every section so the fields line up.
const LABEL_WIDTH: f32 = 130.0;
/// Colour of the reason why the profiles cannot be saved.
const PROBLEM_COLOR: Color32 = Color32::from_rgb(0xFF, 0x6B, 0x6B);

/// What the user decided in the manager window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerAction {
    /// Write the working copy to the catalog and close the window.
    Save,
    /// Drop the working copy and close the window.
    Cancel,
}

/// One profile of the working copy.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    profile: SavedProfile,
    /// Its index in the catalog when the manager opened; `None` for a profile created here.
    origin: Option<usize>,
}

/// The working copy of the profiles while the manager window is open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileManager {
    entries: Vec<Entry>,
    /// The entry shown in the form.
    selected: usize,
    /// The file named for import and export.
    pub file_path: String,
    /// How the last import or export ended, shown under the buttons.
    pub file_result: Option<Result<String, String>>,
}

impl ProfileManager {
    /// The `egui` identity of the manager window.
    #[must_use]
    pub fn viewport_id() -> egui::ViewportId {
        egui::ViewportId::from_hash_of("bastion3270_profile_manager")
    }

    /// A working copy of `catalog`, showing the profile that is selected there.
    #[must_use]
    pub fn open(catalog: &ProfileCatalog) -> Self {
        Self {
            entries: catalog
                .profiles()
                .iter()
                .enumerate()
                .map(|(index, profile)| Entry {
                    profile: profile.clone(),
                    origin: Some(index),
                })
                .collect(),
            selected: catalog.selected_index(),
            file_path: String::new(),
            file_result: None,
        }
    }

    /// The profiles of the working copy, in the order of the list.
    pub fn profiles(&self) -> impl Iterator<Item = &SavedProfile> {
        self.entries.iter().map(|e| &e.profile)
    }

    /// Index of the profile shown in the form.
    #[must_use]
    pub const fn selected_index(&self) -> usize {
        self.selected
    }

    /// Shows the profile at `index` in the form; `false` if there is none.
    pub fn select(&mut self, index: usize) -> bool {
        let exists = index < self.entries.len();
        if exists {
            self.selected = index;
        }
        exists
    }

    /// The profile shown in the form.
    pub fn selected_mut(&mut self) -> Option<&mut SavedProfile> {
        self.entries.get_mut(self.selected).map(|e| &mut e.profile)
    }

    /// Appends an empty profile and shows it. It has no host yet, so it cannot be saved
    /// before the user fills one in ([`Self::problem`]).
    pub fn add_new(&mut self) {
        let mut profile = SavedProfile::hercules_tk4_preset();
        "New profile".clone_into(&mut profile.name);
        profile.description.clear();
        profile.connection.host.clear();
        self.push(profile);
    }

    /// Appends a copy of the profile in the form and shows it.
    pub fn duplicate_selected(&mut self) {
        if let Some(mut copy) = self.entries.get(self.selected).map(|e| e.profile.clone()) {
            copy.name = format!("{} (Copy)", copy.name);
            self.push(copy);
        }
    }

    fn push(&mut self, profile: SavedProfile) {
        self.entries.push(Entry {
            profile,
            origin: None,
        });
        self.selected = self.entries.len().saturating_sub(1);
    }

    /// Removes the profile in the form; the last profile stays (`false`).
    pub fn remove_selected(&mut self) -> bool {
        if self.entries.len() <= 1 || self.selected >= self.entries.len() {
            return false;
        }
        self.entries.remove(self.selected);
        self.selected = self.selected.min(self.entries.len().saturating_sub(1));
        true
    }

    /// `true` if saving would change `catalog`.
    #[must_use]
    pub fn differs_from(&self, catalog: &ProfileCatalog) -> bool {
        self.entries.len() != catalog.len()
            || self.entries.iter().zip(catalog.profiles()).enumerate().any(
                |(index, (entry, saved))| entry.origin != Some(index) || entry.profile != *saved,
            )
    }

    /// Why the working copy cannot be saved: the first profile that is not valid.
    #[must_use]
    pub fn problem(&self) -> Option<String> {
        self.entries.iter().find_map(|entry| {
            let err = entry.profile.validate().err()?;
            let reason = match err {
                NetError::Config(reason) => reason,
                other => other.to_string(),
            };
            // The texts are written for a profile file ("profile 'host' must not be empty").
            let reason = reason.strip_prefix("profile ").unwrap_or(&reason);
            Some(format!("{}: {reason}", display_name(&entry.profile)))
        })
    }

    /// The catalog that **Save** produces. The profile `catalog` has selected (the one the
    /// main window connects with) stays selected wherever it moved; if it was deleted, the
    /// first profile is.
    ///
    /// # Errors
    /// Returns [`NetError::Config`] if a profile is not valid.
    pub fn to_catalog(&self, catalog: &ProfileCatalog) -> Result<ProfileCatalog, NetError> {
        let selected = self
            .entries
            .iter()
            .position(|e| e.origin == Some(catalog.selected_index()))
            .unwrap_or(0);
        ProfileCatalog::from_profiles(self.profiles().cloned().collect(), selected)
    }

    /// Applies `change` to the working copy of the catalog's profile `index`: a setting the
    /// main window stores in a profile while the manager is open must survive its **Save**.
    pub(crate) fn mirror(&mut self, index: usize, change: impl FnOnce(&mut SavedProfile)) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.origin == Some(index)) {
            change(&mut entry.profile);
        }
    }

    /// Replaces the working copy with the profiles of the file [`Self::file_path`].
    pub fn import_file(&mut self) {
        let path = self.file_path.trim().to_owned();
        self.file_result = Some(match ProfileCatalog::load_from_file(&path) {
            Ok(catalog) => {
                self.entries = catalog
                    .profiles()
                    .iter()
                    .map(|profile| Entry {
                        profile: profile.clone(),
                        origin: None,
                    })
                    .collect();
                self.selected = catalog.selected_index();
                Ok(format!(
                    "Imported {} profiles; Save keeps them.",
                    self.entries.len()
                ))
            }
            Err(err) => Err(format!("Import failed: {err}")),
        });
    }

    /// Writes the working copy to the file [`Self::file_path`].
    pub fn export_file(&mut self) {
        let path = self.file_path.trim().to_owned();
        let written = ProfileCatalog::from_profiles(self.profiles().cloned().collect(), 0)
            .and_then(|catalog| catalog.save_to_file(&path));
        self.file_result = Some(match written {
            Ok(()) => Ok(format!("Exported to {path}")),
            Err(err) => Err(format!("Export failed: {err}")),
        });
    }

    /// Draws the manager: the buttons at the bottom, the list on the left, the form of the
    /// chosen profile in the rest. `unsaved` says whether the working copy differs from the
    /// catalog. Returns what the user decided in this frame.
    pub fn ui(&mut self, ui: &mut Ui, unsaved: bool) -> Option<ManagerAction> {
        let mut action = None;
        let problem = self.problem();

        Panel::bottom("profile_manager_buttons").show(ui, |ui| {
            ui.add_space(4.0);
            // One row: the buttons at the right end, the state of the working copy in the
            // space left of them.
            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Cancel").clicked() {
                        action = Some(ManagerAction::Cancel);
                    }
                    let can_save = unsaved && problem.is_none();
                    if ui
                        .add_enabled(can_save, egui::Button::new("Save"))
                        .clicked()
                    {
                        action = Some(ManagerAction::Save);
                    }
                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                        if let Some(problem) = &problem {
                            ui.add(
                                egui::Label::new(RichText::new(problem).color(PROBLEM_COLOR))
                                    .truncate(),
                            );
                        } else if unsaved {
                            ui.weak("Unsaved changes");
                        }
                    });
                });
            });
            ui.add_space(4.0);
        });

        Panel::left("profile_manager_list")
            .resizable(false)
            .default_size(250.0)
            .show(ui, |ui| self.list_ui(ui));

        egui::CentralPanel::default().show(ui, |ui| {
            ScrollArea::vertical()
                .id_salt("profile_manager_form")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if let Some(profile) = self.selected_mut() {
                        profile_form(ui, profile);
                    }
                });
        });
        action
    }

    /// The list of profiles with its buttons, and import / export of the whole list.
    fn list_ui(&mut self, ui: &mut Ui) {
        ui.add_space(4.0);
        ui.heading("Profiles");
        ui.horizontal(|ui| {
            if ui.button("New").clicked() {
                self.add_new();
            }
            if ui.button("Duplicate").clicked() {
                self.duplicate_selected();
            }
            if ui
                .add_enabled(self.entries.len() > 1, egui::Button::new("Delete"))
                .clicked()
            {
                self.remove_selected();
            }
        });
        ui.separator();

        Panel::bottom("profile_manager_files").show(ui, |ui| {
            ui.collapsing("Import / export", |ui| {
                ui.label("Import replaces the list; export writes a copy.");
                ui.add(TextEdit::singleline(&mut self.file_path).hint_text("path to a .toml file"));
                let has_path = !self.file_path.trim().is_empty();
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(has_path, egui::Button::new("Import"))
                        .clicked()
                    {
                        self.import_file();
                    }
                    if ui
                        .add_enabled(has_path, egui::Button::new("Export"))
                        .clicked()
                    {
                        self.export_file();
                    }
                });
                match &self.file_result {
                    Some(Ok(done)) => {
                        ui.add(egui::Label::new(done.as_str()).wrap());
                    }
                    Some(Err(failed)) => {
                        ui.add(egui::Label::new(RichText::new(failed).color(PROBLEM_COLOR)).wrap());
                    }
                    None => {}
                }
            });
        });

        let mut chosen = None;
        ScrollArea::vertical()
            .id_salt("profile_manager_list_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.with_layout(Layout::top_down_justified(Align::LEFT), |ui| {
                    for (index, entry) in self.entries.iter().enumerate() {
                        let profile = &entry.profile;
                        if ui
                            .selectable_label(index == self.selected, display_name(profile))
                            .clicked()
                        {
                            chosen = Some(index);
                        }
                        let host = profile.connection.host.trim();
                        let target = if host.is_empty() {
                            "no host yet".to_owned()
                        } else {
                            format!("{host}:{}", profile.connection.port)
                        };
                        ui.label(RichText::new(target).small().weak());
                        ui.add_space(4.0);
                    }
                });
            });
        if let Some(index) = chosen {
            self.select(index);
        }
    }
}

/// The name of a profile in the list and in messages.
fn display_name(profile: &SavedProfile) -> &str {
    let name = profile.name.trim();
    if name.is_empty() {
        "(no name)"
    } else {
        name
    }
}

/// A section of the form: a title, then a two-column grid of labels and fields.
fn section(ui: &mut Ui, title: &str, fields: impl FnOnce(&mut Ui)) {
    ui.add_space(10.0);
    ui.label(RichText::new(title).strong());
    ui.separator();
    egui::Grid::new(title)
        .num_columns(2)
        .min_col_width(LABEL_WIDTH)
        .spacing([16.0, 8.0])
        .show(ui, fields);
}

/// A text field whose empty content means "not set".
fn optional_text(ui: &mut Ui, value: &mut Option<String>) {
    let mut text = value.clone().unwrap_or_default();
    if ui
        .add(TextEdit::singleline(&mut text).desired_width(FIELD_WIDTH))
        .changed()
    {
        let trimmed = text.trim();
        *value = (!trimmed.is_empty()).then(|| trimmed.to_owned());
    }
}

/// The form of one profile.
#[allow(clippy::too_many_lines)]
fn profile_form(ui: &mut Ui, profile: &mut SavedProfile) {
    section(ui, "Profile", |ui| {
        ui.label("Name");
        ui.add(TextEdit::singleline(&mut profile.name).desired_width(FIELD_WIDTH));
        ui.end_row();
        ui.label("Description");
        ui.add(TextEdit::singleline(&mut profile.description).desired_width(FIELD_WIDTH));
        ui.end_row();
    });

    let connection = &mut profile.connection;
    section(ui, "Connection", |ui| {
        ui.label("Host");
        ui.add(TextEdit::singleline(&mut connection.host).desired_width(FIELD_WIDTH));
        ui.end_row();

        ui.label("Port");
        let mut port = u32::from(connection.port);
        if ui
            .add(egui::DragValue::new(&mut port).range(1..=65535))
            .changed()
        {
            if let Ok(port) = u16::try_from(port) {
                connection.port = port;
            }
        }
        ui.end_row();

        ui.label("LU name")
            .on_hover_text("Optional: the LU the host should assign to this terminal");
        optional_text(ui, &mut connection.lu_name);
        ui.end_row();
    });

    section(ui, "Encryption", |ui| {
        ui.label("TLS");
        let mut tls = matches!(connection.tls_mode, TlsMode::Enabled);
        if ui
            .checkbox(&mut tls, "Encrypt the connection (TLS 1.2 / 1.3)")
            .changed()
        {
            connection.tls_mode = if tls {
                TlsMode::Enabled
            } else {
                TlsMode::Disabled
            };
        }
        ui.end_row();
        if !tls {
            return;
        }

        ui.label("Additional CA").on_hover_text(
            "Optional: a CA certificate file (PEM / DER), trusted in addition to the system's \
             certificate store and the Mozilla roots",
        );
        let mut ca = connection
            .ca_cert
            .as_ref()
            .map_or_else(String::new, |p| p.display().to_string());
        if ui
            .add(TextEdit::singleline(&mut ca).desired_width(FIELD_WIDTH))
            .changed()
        {
            let trimmed = ca.trim();
            connection.ca_cert = (!trimmed.is_empty()).then(|| PathBuf::from(trimmed));
        }
        ui.end_row();

        ui.label("Certificate name").on_hover_text(
            "Optional: the name the host's certificate is issued for, when it differs from \
             the host (e.g. connecting by IP address)",
        );
        optional_text(ui, &mut connection.accept_hostname);
        ui.end_row();

        if let Some(pin) = connection.pinned_cert_sha256.clone() {
            ui.label("Trusted certificate");
            ui.horizontal(|ui| {
                let short: String = pin.chars().take(16).collect();
                ui.label(format!("SHA-256 {short}…"))
                    .on_hover_text(pin.as_str());
                if ui.small_button("Forget").clicked() {
                    connection.pinned_cert_sha256 = None;
                }
            });
            ui.end_row();
        }
    });

    section(ui, "Terminal", |ui| {
        ui.label("Model");
        let models = [
            (ProfileTerminalModel::Model2, "Model 2 (24×80)"),
            (ProfileTerminalModel::Model3, "Model 3 (32×80)"),
            (ProfileTerminalModel::Model4, "Model 4 (43×80)"),
            (ProfileTerminalModel::Model5, "Model 5 (27×132)"),
            (
                ProfileTerminalModel::Dynamic {
                    rows: 62,
                    cols: 160,
                },
                "Dynamic (62×160)",
            ),
        ];
        let current = match connection.terminal_model {
            ProfileTerminalModel::Model2 => "Model 2 (24×80)",
            ProfileTerminalModel::Model3 => "Model 3 (32×80)",
            ProfileTerminalModel::Model4 => "Model 4 (43×80)",
            ProfileTerminalModel::Model5 => "Model 5 (27×132)",
            ProfileTerminalModel::Dynamic { .. } => "Dynamic (custom)",
        };
        egui::ComboBox::from_id_salt("profile_manager_model")
            .selected_text(current)
            .show_ui(ui, |ui| {
                for (model, label) in models {
                    ui.selectable_value(&mut connection.terminal_model, model, label);
                }
            });
        ui.end_row();

        // Every built-in code page; an alias in the profile is shown as the code page it
        // resolves to.
        ui.label("Code page");
        let current = CodePageId::from_name(&connection.codepage);
        egui::ComboBox::from_id_salt("profile_manager_codepage")
            .selected_text(current.map_or_else(
                || connection.codepage.to_ascii_uppercase(),
                CodePageId::label,
            ))
            .show_ui(ui, |ui| {
                for &id in CodePageId::ALL {
                    if ui
                        .selectable_label(current == Some(id), id.label())
                        .clicked()
                    {
                        id.name().clone_into(&mut connection.codepage);
                    }
                }
            });
        ui.end_row();
    });

    section(ui, "Appearance and keyboard", |ui| {
        ui.label("Colours");
        egui::ComboBox::from_id_salt("profile_manager_colours")
            .selected_text(profile.color_scheme.label())
            .show_ui(ui, |ui| {
                for scheme in TerminalColorScheme::ALL {
                    ui.selectable_value(&mut profile.color_scheme, scheme, scheme.label());
                }
            });
        ui.end_row();

        ui.label("Cursor");
        egui::ComboBox::from_id_salt("profile_manager_cursor")
            .selected_text(profile.cursor_style.label())
            .show_ui(ui, |ui| {
                for style in CursorStyle::ALL {
                    ui.selectable_value(&mut profile.cursor_style, style, style.label());
                }
            });
        ui.end_row();

        ui.label("Crosshair");
        ui.checkbox(&mut profile.crosshair_enabled, "Show the crosshair ruler");
        ui.end_row();

        ui.label("Input fields");
        ui.checkbox(
            &mut profile.highlight_input_fields,
            "Highlight input fields",
        );
        ui.end_row();

        ui.label("Keyboard");
        egui::ComboBox::from_id_salt("profile_manager_keyboard")
            .selected_text(profile.keyboard.label())
            .show_ui(ui, |ui| {
                for preset in KeyboardPreset::ALL {
                    ui.selectable_value(&mut profile.keyboard, preset, preset.label());
                }
            });
        ui.end_row();
    });
}
