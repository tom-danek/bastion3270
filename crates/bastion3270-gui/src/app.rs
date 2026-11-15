//! Main `Bastion3270GuiApp` Desktop Application State, Panels, Keypad Toolbar, and `eframe::App` Implementation.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use bastion3270_core::{ActionKey, AidKey, AttentionKey, KeyboardState, SafeScreenView};
use bastion3270_net::{ProfileTerminalModel, SessionEvent, SessionState, TlsMode};
use egui::{
    Color32, Context, Event, Key, KeyboardShortcut, Modifiers, Panel, RichText, ScrollArea, Ui,
};

use crate::selection::{selection_text, Selection};
use bastion3270_net::transport::CertificateRejection;

use crate::bridge::GuiSessionBridge;
use crate::canvas::{render_terminal_canvas, TERMINAL_CANVAS_ID};
use crate::keymap::{translate_key_event, translate_text_input, GuiKeyAction, KeyboardPreset};
use crate::message::{MessageLevel, StatusMessage};
use crate::oia::{render_oia_bar, OiaStatusModel};
use crate::profile_manager::{ManagerAction, ProfileManager};
use crate::profiles::{ProfileCatalog, SavedProfile};
use crate::storage::{OpenedProfiles, ProfileStore};
use crate::theme::{TerminalColorScheme, TerminalTheme};

/// Duration for which the visual bell / alarm banner stays highlighted in the OIA bar.
const ALARM_FLASH_DURATION: Duration = Duration::from_secs(2);
/// Period of the 3270 blink attribute cycle (`500 ms` on, `500 ms` off).
const BLINK_HALF_PERIOD: Duration = Duration::from_millis(500);
/// Quiet time after the last change of the catalog before it is written (a burst of View menu
/// changes is one write).
const PROFILE_AUTOSAVE_DELAY: Duration = Duration::from_secs(1);

/// Complete desktop application state for `bastion3270-gui`.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct Bastion3270GuiApp {
    /// Saved connection profiles and active selection.
    pub catalog: ProfileCatalog,
    /// Visual theme (color scheme, cursor style, crosshair, zoom).
    pub theme: TerminalTheme,
    /// Active `Enter` vs `Ctrl+Enter` keyboard mode.
    pub keyboard: KeyboardPreset,
    /// Zero-Trust snapshot of the current 3270 screen.
    pub screen: SafeScreenView,
    /// Operator Information Area (OIA) bottom status bar state.
    pub oia: OiaStatusModel,
    /// Non-blocking async bridge to the background Tokio runtime and `SessionCoordinator`.
    pub bridge: GuiSessionBridge,
    /// The profile manager window with its working copy of the profiles, while it is open.
    pub profile_manager: Option<ProfileManager>,
    /// Whether the on-screen 3270 Keypad toolbar (`PF1`..`PF24`, `PA1`..`PA3`, `Clear`, `Reset`) is shown.
    pub show_keypad_bar: bool,
    ///Whether `PF13`..`PF24` bank is shown on the keypad toolbar instead of `PF1`..`PF12`.
    pub keypad_shift_pf13_24: bool,
    /// Message line above the OIA bar (client messages; the session state is in the OIA).
    pub status_message: Option<StatusMessage>,
    /// Whether the Help → About window is open.
    pub show_about: bool,
    /// Where the catalog is saved; `None` keeps it in memory only.
    profile_store: Option<ProfileStore>,
    /// The catalog as last written, to notice changes.
    saved_catalog: ProfileCatalog,
    /// When the catalog first differed from [`Self::saved_catalog`].
    profiles_changed_at: Option<Instant>,
    /// Why the last automatic save failed, if it did.
    profile_save_error: Option<String>,
    /// Diagnostics log of this run, shown in Help, About.
    log_path: Option<PathBuf>,
    /// Timestamp when the last audible/visual alarm (`WCC sound_alarm`) was triggered.
    alarm_until: Option<Instant>,
    /// Start instant used to compute the 500ms blink phase.
    start_instant: Instant,
    /// Rectangle selected with the mouse (copied by Ctrl+C), cleared by a new screen.
    pub selection: Option<Selection>,
    /// Cell where the current mouse drag started.
    drag_anchor: Option<(u16, u16)>,
    /// A host certificate the last connection refused: the trust dialog is open.
    pub untrusted_certificate: Option<UntrustedCertificate>,
}

/// The trust dialog: which profile's connection refused which certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedCertificate {
    /// Name of the profile the connection was opened with.
    pub profile_name: String,
    /// Why the certificate was refused, and what it says.
    pub rejection: CertificateRejection,
}

impl Bastion3270GuiApp {
    /// Creates a new [`Bastion3270GuiApp`] with default profiles and an initialized Tokio bridge.
    /// Profiles are kept in memory only until [`Self::with_profiles`] attaches a file.
    ///
    /// # Errors
    /// Returns [`bastion3270_net::NetError`] if the background Tokio runtime cannot be created.
    pub fn new() -> Result<Self, bastion3270_net::NetError> {
        let catalog = ProfileCatalog::new();
        let bridge = GuiSessionBridge::new()?;
        let mut app = Self {
            saved_catalog: catalog.clone(),
            catalog,
            theme: TerminalTheme::default(),
            keyboard: KeyboardPreset::default(),
            screen: SafeScreenView::empty(24, 80),
            oia: OiaStatusModel::default(),
            bridge,
            profile_manager: None,
            show_keypad_bar: true,
            keypad_shift_pf13_24: false,
            status_message: None,
            show_about: false,
            profile_store: None,
            profiles_changed_at: None,
            profile_save_error: None,
            log_path: None,
            alarm_until: None,
            start_instant: Instant::now(),
            selection: None,
            drag_anchor: None,
            untrusted_certificate: None,
        };
        app.sync_preferences_from_selected_profile();
        Ok(app)
    }

    /// Starts with the catalog loaded from a file and saves it back there: what the profile
    /// manager saves, and what the main window stores in a profile (View menu, a trusted
    /// certificate). See [`ProfileStore`]; `log_path` is only displayed.
    #[must_use]
    pub fn with_profiles(mut self, opened: OpenedProfiles, log_path: Option<PathBuf>) -> Self {
        self.saved_catalog = opened.catalog.clone();
        self.catalog = opened.catalog;
        self.profile_store = Some(opened.store);
        self.status_message = opened.notice.map(StatusMessage::warning);
        self.log_path = log_path;
        self.sync_preferences_from_selected_profile();
        self
    }

    /// Removes an informational message (e.g. "Connecting…") once it no longer applies;
    /// warnings and errors stay.
    fn clear_info_message(&mut self) {
        if self
            .status_message
            .as_ref()
            .is_some_and(|m| m.level() == MessageLevel::Info)
        {
            self.status_message = None;
        }
    }

    /// Stores a setting of the main window in the selected profile. While the profile manager
    /// is open, its working copy of that profile gets the same change, so the manager's Save
    /// does not undo it.
    fn update_selected_profile(&mut self, change: impl Fn(&mut SavedProfile)) {
        let index = self.catalog.selected_index();
        if let Some(profile) = self.catalog.selected_mut() {
            change(profile);
        }
        if let Some(manager) = &mut self.profile_manager {
            manager.mirror(index, change);
        }
    }

    /// Sets the colour scheme for the session and the selected profile.
    pub fn set_color_scheme(&mut self, scheme: TerminalColorScheme) {
        self.theme.color_scheme = scheme;
        self.update_selected_profile(|p| p.color_scheme = scheme);
    }

    /// Shows or hides the crosshair ruler for the session and the selected profile.
    pub fn set_crosshair(&mut self, on: bool) {
        self.theme.crosshair_enabled = on;
        self.update_selected_profile(|p| p.crosshair_enabled = on);
    }

    /// Highlights input fields (or not) for the session and the selected profile.
    pub fn set_highlight_input_fields(&mut self, on: bool) {
        self.theme.highlight_input_fields = on;
        self.update_selected_profile(|p| p.highlight_input_fields = on);
    }

    /// Opens the profile manager with a working copy of the profiles (no effect if it is
    /// open already).
    pub fn open_profile_manager(&mut self) {
        if self.profile_manager.is_none() {
            self.profile_manager = Some(ProfileManager::open(&self.catalog));
        }
    }

    /// The manager's **Save**: its working copy becomes the catalog, is written to the profile
    /// file, and the window closes. Returns `false` (and keeps the window open) if a profile is
    /// not valid; the window names it.
    pub fn save_profile_manager(&mut self) -> bool {
        let Some(manager) = &self.profile_manager else {
            return false;
        };
        let Ok(catalog) = manager.to_catalog(&self.catalog) else {
            return false;
        };
        self.catalog = catalog;
        self.profile_manager = None;
        self.sync_preferences_from_selected_profile();
        self.autosave_profiles(true);
        if self.oia.session_state.is_active() || self.bridge.is_connected() {
            self.status_message = Some(StatusMessage::info(
                "Profiles saved. Connection settings apply to the next connection.",
            ));
        }
        true
    }

    /// The manager's **Cancel**: drops its working copy and closes the window.
    pub fn cancel_profile_manager(&mut self) {
        self.profile_manager = None;
    }

    /// Writes the catalog once it has been unchanged for [`PROFILE_AUTOSAVE_DELAY`]
    /// (or at once with `now`), so a burst of edits is one write.
    fn autosave_profiles(&mut self, now: bool) {
        if self.profile_store.is_none() || self.catalog == self.saved_catalog {
            self.profiles_changed_at = None;
            return;
        }
        let changed_at = *self.profiles_changed_at.get_or_insert_with(Instant::now);
        if !now && changed_at.elapsed() < PROFILE_AUTOSAVE_DELAY {
            return;
        }
        let Some(store) = &self.profile_store else {
            return;
        };
        match store.save(&self.catalog) {
            Ok(()) => {
                self.saved_catalog = self.catalog.clone();
                self.profiles_changed_at = None;
                if let Some(err) = self.profile_save_error.take() {
                    if self
                        .status_message
                        .as_ref()
                        .is_some_and(|m| m.text() == err)
                    {
                        self.status_message = None;
                    }
                }
            }
            Err(err) => {
                let err = format!("Profiles not saved: {err}");
                // Reported once per distinct reason, not on every retry (a dismissed message
                // stays dismissed).
                if self.profile_save_error.as_deref() != Some(err.as_str()) {
                    tracing::warn!(target: "bastion3270_gui::profiles", "{err}");
                    self.status_message = Some(StatusMessage::warning(err.clone()));
                }
                self.profile_save_error = Some(err);
                // Retry after the next quiet period (the user may be fixing the profile).
                self.profiles_changed_at = Some(Instant::now());
            }
        }
    }

    /// Synchronizes theme, crosshair, cursor style, enter mode, and OIA metadata from the
    /// currently selected [`SavedProfile`](crate::profiles::SavedProfile).
    pub fn sync_preferences_from_selected_profile(&mut self) {
        if let Some(selected) = self.catalog.selected() {
            self.theme.color_scheme = selected.color_scheme;
            self.theme.cursor_style = selected.cursor_style;
            self.theme.crosshair_enabled = selected.crosshair_enabled;
            self.theme.highlight_input_fields = selected.highlight_input_fields;
            self.keyboard = selected.keyboard;
            self.oia.terminal_model = selected.connection.terminal_model;
            self.oia.codepage.clone_from(&selected.connection.codepage);
            self.oia.is_tls = matches!(selected.connection.tls_mode, TlsMode::Enabled);

            // When disconnected, reflect the configured profile geometry immediately in the
            // canvas and OIA bar so the user sees changes to the terminal model right away.
            if !self.oia.session_state.is_active() && !self.bridge.is_connected() {
                let (rows, cols) = Self::dimensions_for_model(selected.connection.terminal_model);
                if self.screen.rows() != rows || self.screen.cols() != cols {
                    self.screen = SafeScreenView::empty(rows, cols);
                }
                self.oia.rows = rows;
                self.oia.cols = cols;
            }
        }
    }

    const fn dimensions_for_model(model: ProfileTerminalModel) -> (u16, u16) {
        match model {
            ProfileTerminalModel::Model2 => (24, 80),
            ProfileTerminalModel::Model3 => (32, 80),
            ProfileTerminalModel::Model4 => (43, 80),
            ProfileTerminalModel::Model5 => (27, 132),
            ProfileTerminalModel::Dynamic { rows, cols } => (rows as u16, cols as u16),
        }
    }

    /// Initiates a connection using the currently selected profile.
    pub fn connect_selected_profile(&mut self) {
        self.sync_preferences_from_selected_profile();
        if let Some(selected) = self.catalog.selected().cloned() {
            match selected.validate() {
                Ok(()) => {
                    let (rows, cols) =
                        Self::dimensions_for_model(selected.connection.terminal_model);
                    self.screen = SafeScreenView::empty(rows, cols);
                    self.oia.rows = rows;
                    self.oia.cols = cols;
                    self.oia.cursor_row = 0;
                    self.oia.cursor_col = 0;
                    self.oia.session_state = SessionState::Connecting;
                    self.oia.keyboard_state = KeyboardState::Unlocked;
                    self.status_message = Some(StatusMessage::info(format!(
                        "Connecting to {}:{} ({})...",
                        selected.connection.host, selected.connection.port, selected.name
                    )));
                    self.bridge.connect(selected.connection);
                }
                Err(err) => {
                    self.status_message =
                        Some(StatusMessage::error(format!("Profile error: {err}")));
                }
            }
        }
    }

    /// Trusts the refused certificate of the trust dialog for its profile (stores its SHA-256 as
    /// `pinned_cert_sha256`, saved with the profiles) and connects again.
    pub fn trust_refused_certificate(&mut self) {
        let Some(prompt) = self.untrusted_certificate.take() else {
            return;
        };
        // The selection changed meanwhile: never pin a certificate to another profile.
        if self.catalog.selected().map(|p| p.name.as_str()) != Some(prompt.profile_name.as_str()) {
            return;
        }
        let pin = prompt.rejection.certificate.sha256_hex();
        self.update_selected_profile(|p| p.connection.pinned_cert_sha256 = Some(pin.clone()));
        self.connect_selected_profile();
    }

    /// Disconnects the active session.
    pub fn disconnect_session(&mut self) {
        self.bridge.disconnect();
        self.oia.session_state = SessionState::Disconnected;
        self.oia.keyboard_state = KeyboardState::Unlocked;
        self.clear_info_message();
    }

    /// Drains all pending [`SessionEvent`]s from the background bridge and updates
    /// [`Self::screen`] and [`Self::oia`].
    ///
    /// Returns the number of events processed.
    pub fn process_session_events(&mut self) -> usize {
        let events = self.bridge.poll_events();
        let count = events.len();
        for event in events {
            match event {
                SessionEvent::StateChanged(state) => {
                    self.oia.session_state = state;
                }
                SessionEvent::NegotiationComplete {
                    is_tn3270e,
                    assigned_lu,
                } => {
                    self.oia.is_tn3270e = is_tn3270e;
                    self.oia.assigned_lu = assigned_lu;
                    self.oia.session_state = SessionState::Connected3270;
                    self.clear_info_message();
                }
                SessionEvent::ScreenUpdated(view) => {
                    // A new screen invalidates the selection (it may no longer match).
                    if self.drag_anchor.is_none() {
                        self.selection = None;
                    }
                    self.oia.rows = view.rows();
                    self.oia.cols = view.cols();
                    self.oia.cursor_row = view.cursor_row();
                    self.oia.cursor_col = view.cursor_col();
                    self.oia.is_formatted = view.is_formatted();
                    self.screen = view;
                }
                SessionEvent::KeyboardStateChanged(kb_state) => {
                    self.oia.keyboard_state = kb_state;
                }
                SessionEvent::Alarm => {
                    self.alarm_until = Some(Instant::now() + ALARM_FLASH_DURATION);
                    self.oia.alarm_active = true;
                }
                SessionEvent::NvtData(bytes) => {
                    let banner = String::from_utf8_lossy(&bytes).trim().to_string();
                    if !banner.is_empty() {
                        self.status_message = Some(StatusMessage::info(format!("NVT: {banner}")));
                    }
                }
                SessionEvent::InsertModeChanged(on) => {
                    self.oia.insert_mode = on;
                }
                // The keyboard indicator already shows what the mode allows (`X -f` in NVT).
                SessionEvent::HostModeChanged(_) => {}
                SessionEvent::Warning(msg) => {
                    self.status_message = Some(StatusMessage::warning(msg));
                }
                // Shown by the OIA bar (`ERR: …`); a "Connecting…" note is out of date.
                SessionEvent::Error(err) => {
                    self.oia.session_state = SessionState::Error(err);
                    self.clear_info_message();
                }
                SessionEvent::Disconnected => {
                    self.oia.session_state = SessionState::Disconnected;
                    self.clear_info_message();
                }
            }
        }

        if let Some(rejection) = self.bridge.take_refused_certificate() {
            if let Some(profile) = self.catalog.selected() {
                self.untrusted_certificate = Some(UntrustedCertificate {
                    profile_name: profile.name.clone(),
                    rejection,
                });
            }
        }

        // Expire visual alarm indicator after ALARM_FLASH_DURATION
        if let Some(deadline) = self.alarm_until {
            if Instant::now() >= deadline {
                self.alarm_until = None;
                self.oia.alarm_active = false;
            }
        }

        count
    }

    /// Executes a [`GuiKeyAction`] (from hardware keyboard or on-screen 3270 keypad).
    pub fn apply_key_action(&mut self, action: GuiKeyAction) {
        match action {
            GuiKeyAction::Aid(aid) => {
                self.bridge.press_aid(aid);
            }
            GuiKeyAction::Action(act) => {
                self.bridge.send_action(act);
            }
            GuiKeyAction::Attention(key) => {
                self.bridge.press_attention(key);
            }
            GuiKeyAction::Char(ch) => {
                self.bridge.send_char(ch);
            }
            GuiKeyAction::ZoomIn => {
                self.theme.zoom_in();
            }
            GuiKeyAction::ZoomOut => {
                self.theme.zoom_out();
            }
            GuiKeyAction::ZoomReset => {
                self.theme.reset_zoom();
            }
        }
    }

    /// Renders the complete GUI into the root `egui::Ui` of one frame.
    ///
    /// Pending session events are drained first, so the frame always shows the latest screen.
    /// (`eframe` also drains them in `App::logic`, which keeps running while the window is
    /// hidden; draining an empty queue here is a no-op.)
    pub fn render_ui(&mut self, ui: &mut Ui) {
        self.process_session_events();
        // `Context` is a cheap reference-counted handle. Cloning it releases the shared borrow
        // of `ui`, which the panels below need mutably.
        let ctx = ui.ctx().clone();
        let ctx = &ctx;

        // Intercept hardware keyboard input (especially Tab / Shift+Tab, Enter, PF keys, and text)
        // BEFORE rendering any GUI buttons or panels so `egui`'s built-in widget focus navigation
        // does not steal `Tab` to cycle focus across toolbar/keypad buttons.
        // The profile manager is a window of its own with its own keyboard input. Only where it
        // is drawn inside this window (no second window possible) does a text field of it get
        // the keys instead of the terminal.
        let canvas_id = egui::Id::unique(TERMINAL_CANVAS_ID);
        let profile_text_input_focused =
            self.profile_manager.is_some() && ctx.egui_wants_keyboard_input();
        if !profile_text_input_focused {
            self.capture_keyboard_events(ctx);
        }

        // Menu bar, then the toolbar with the actions used all the time
        Panel::top("bastion3270_menu_bar").show(ui, |ui| {
            self.render_menu_bar(ui);
        });
        Panel::top("bastion3270_top_toolbar").show(ui, |ui| {
            self.render_top_toolbar(ui);
        });

        // Optional 3270 function keypad toolbar
        if self.show_keypad_bar {
            Panel::top("bastion3270_keypad_bar").show(ui, |ui| {
                self.render_keypad_bar(ui);
            });
        }

        // Bottom Operator Information Area (OIA) status bar
        Panel::bottom("bastion3270_oia_bar").show(ui, |ui| {
            render_oia_bar(ui, &self.oia);
        });

        // Message line just above the OIA bar (panels added later sit further inside)
        if self
            .status_message
            .as_ref()
            .is_some_and(|m| m.is_expired(Instant::now()))
        {
            self.status_message = None;
        }
        if self.status_message.is_some() {
            Panel::bottom("bastion3270_message_line").show(ui, |ui| {
                self.render_message_line(ui);
            });
        }

        self.render_windows(ctx);
        self.render_profile_manager(ctx);

        // Central Terminal Canvas
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(self.theme.screen_bg())
                    .inner_margin(6.0),
            )
            .show(ui, |ui| {
                let blink_off =
                    (self.start_instant.elapsed().as_millis() / BLINK_HALF_PERIOD.as_millis()) % 2
                        == 1;

                ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let interaction = render_terminal_canvas(
                            ui,
                            &self.screen,
                            &self.theme,
                            blink_off,
                            self.selection,
                        );

                        if let Some(move_act) = interaction.clicked_cursor_move {
                            self.selection = None;
                            self.drag_anchor = None;
                            self.apply_key_action(GuiKeyAction::Action(move_act));
                        }
                        if let Some(anchor) = interaction.drag_started_at {
                            self.drag_anchor = Some(anchor);
                            self.selection = Some(Selection::between(anchor, anchor));
                        }
                        if let (Some(anchor), Some(point)) =
                            (self.drag_anchor, interaction.dragged_to)
                        {
                            self.selection = Some(Selection::between(anchor, point));
                        }
                        if ui.input(|i| i.pointer.any_released()) {
                            self.drag_anchor = None;
                        }
                    });
            });

        // Keep keyboard focus locked onto the 3270 terminal canvas (with `lock_focus = true` for
        // `Tab` / `Shift+Tab`) whenever no text edit box in the Profile Manager holds focus.
        // Because `egui` processes `Tab` focus movement inside `Context::begin_pass` before
        // `render_ui` runs, locking `Tab` on `canvas_id` at the end of frame N guarantees that
        // pressing `Tab` in frame N+1 never moves focus to the top toolbar ComboBox or buttons
        // (zero visual flicker!).
        let profile_text_input_focused_after =
            self.profile_manager.is_some() && ctx.egui_wants_keyboard_input();
        if !profile_text_input_focused_after {
            let tab_filter = egui::EventFilter {
                tab: true,
                horizontal_arrows: true,
                vertical_arrows: true,
                escape: true,
            };
            ctx.memory_mut(|m| {
                m.request_focus(canvas_id);
                m.set_focus_lock_filter(canvas_id, tab_filter);
            });
        }
    }

    fn capture_keyboard_events(&mut self, ctx: &Context) {
        let mut actions = Vec::new();
        let keyboard = self.keyboard;
        let mut copy = false;
        let mut pastes = Vec::new();

        // Explicitly consume Tab and Shift+Tab from egui::InputState so egui's internal
        // focus navigation does not cycle focus across toolbar/keypad buttons.
        ctx.input_mut(|input| {
            if input.consume_key(egui::Modifiers::SHIFT, egui::Key::Tab) {
                actions.push(GuiKeyAction::Action(ActionKey::BackTab));
            } else if input.consume_key(egui::Modifiers::NONE, egui::Key::Tab) {
                actions.push(GuiKeyAction::Action(ActionKey::Tab));
            }

            for event in &input.events {
                match event {
                    Event::Key {
                        key,
                        pressed: true,
                        modifiers,
                        ..
                    } => {
                        if *key != egui::Key::Tab {
                            if let Some(act) = translate_key_event(*key, *modifiers, keyboard) {
                                actions.push(act);
                            }
                        }
                    }
                    Event::Text(text)
                        if !input.modifiers.ctrl
                            && !input.modifiers.command
                            && !input.modifiers.alt =>
                    {
                        actions.extend(translate_text_input(text));
                    }
                    // Ctrl+C / Ctrl+X (the platform's copy keys): the terminal has nothing to
                    // cut, both copy the selection, or the whole screen without one.
                    Event::Copy | Event::Cut => copy = true,
                    // Ctrl+V: the clipboard text goes through the core's paste rules.
                    Event::Paste(text) => pastes.push(text.clone()),
                    _ => {}
                }
            }
        });

        for act in actions {
            self.apply_key_action(act);
        }
        if copy {
            let text = selection_text(&self.screen, self.selection);
            tracing::debug!(target: "bastion3270_gui::clipboard", chars = text.chars().count(), "copy");
            ctx.copy_text(text);
        }
        for text in pastes {
            tracing::debug!(target: "bastion3270_gui::clipboard", chars = text.chars().count(), "paste");
            self.bridge.paste(text);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn render_top_toolbar(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("bastion3270").strong().monospace());
            ui.separator();

            // Profile selector ComboBox
            let current_name = self
                .catalog
                .selected()
                .map_or_else(|| "Select Profile".to_string(), |p| p.name.clone());

            let mut selected_idx = self.catalog.selected_index();
            let mut changed = false;
            egui::ComboBox::from_id_salt("profile_selector_combo")
                .selected_text(current_name)
                .width(210.0)
                .show_ui(ui, |ui| {
                    for (idx, p) in self.catalog.profiles().iter().enumerate() {
                        if ui
                            .selectable_value(
                                &mut selected_idx,
                                idx,
                                format!("{} ({}:{})", p.name, p.connection.host, p.connection.port),
                            )
                            .changed()
                        {
                            changed = true;
                        }
                    }
                });
            if changed && self.catalog.select(selected_idx) {
                self.sync_preferences_from_selected_profile();
            }
            if ui
                .button("Profiles…")
                .on_hover_text("Add, edit and delete profiles")
                .clicked()
            {
                self.show_profile_manager(ui.ctx());
            }

            // Connect / Disconnect button
            let is_active = self.oia.session_state.is_active() || self.bridge.is_connected();
            if is_active {
                if ui
                    .button(
                        RichText::new("⏹ Disconnect").color(Color32::from_rgb(0xFF, 0x6B, 0x6B)),
                    )
                    .clicked()
                {
                    self.disconnect_session();
                }
            } else if ui
                .button(
                    RichText::new("▶ Connect")
                        .strong()
                        .color(Color32::from_rgb(0x2E, 0xEB, 0x5A)),
                )
                .clicked()
            {
                self.connect_selected_profile();
            }
        });
    }

    /// Menu bar: everything that is not needed all the time.
    ///
    /// Shortcuts are only shown where they really work in the terminal (see `keymap`); the
    /// copy and paste entries go through the same clipboard events as the keyboard.
    fn render_menu_bar(&mut self, ui: &mut Ui) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("Session", |ui| self.render_session_menu(ui));
            ui.menu_button("Edit", Self::render_edit_menu);
            ui.menu_button("View", |ui| self.render_view_menu(ui));
            ui.menu_button("Help", |ui| {
                if ui.button("About bastion3270").clicked() {
                    self.show_about = true;
                }
            });
        });
    }

    /// Session menu: connect, choose the profile (only while disconnected), quit.
    fn render_session_menu(&mut self, ui: &mut Ui) {
        let is_active = self.oia.session_state.is_active() || self.bridge.is_connected();
        if ui
            .add_enabled(!is_active, egui::Button::new("Connect"))
            .clicked()
        {
            self.connect_selected_profile();
        }
        if ui
            .add_enabled(is_active, egui::Button::new("Disconnect"))
            .clicked()
        {
            self.disconnect_session();
        }
        ui.separator();
        ui.add_enabled_ui(!is_active, |ui| {
            let mut selected = self.catalog.selected_index();
            let names: Vec<String> = self
                .catalog
                .profiles()
                .iter()
                .map(|p| p.name.clone())
                .collect();
            for (idx, name) in names.into_iter().enumerate() {
                if ui.radio_value(&mut selected, idx, name).clicked()
                    && self.catalog.select(selected)
                {
                    self.sync_preferences_from_selected_profile();
                }
            }
        });
        if ui.button("Profiles…").clicked() {
            self.show_profile_manager(ui.ctx());
        }
        ui.separator();
        if ui.button("Quit").clicked() {
            ui.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    /// Edit menu: the same clipboard events as the keyboard shortcuts.
    fn render_edit_menu(ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let shortcut = |modifiers, key| ctx.format_shortcut(&KeyboardShortcut::new(modifiers, key));
        if ui
            .add(egui::Button::new("Copy").shortcut_text(shortcut(Modifiers::COMMAND, Key::C)))
            .on_hover_text("Selection, or the whole screen without one")
            .clicked()
        {
            ui.send_viewport_cmd(egui::ViewportCommand::RequestCopy);
        }
        if ui
            .add(egui::Button::new("Paste").shortcut_text(shortcut(Modifiers::COMMAND, Key::V)))
            .clicked()
        {
            ui.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
        }
    }

    /// View menu: appearance settings (saved in the selected profile) and zoom.
    fn render_view_menu(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let shortcut = |modifiers, key| ctx.format_shortcut(&KeyboardShortcut::new(modifiers, key));
        ui.menu_button("Color Scheme", |ui| {
            let mut scheme = self.theme.color_scheme;
            for s in TerminalColorScheme::ALL {
                if ui.radio_value(&mut scheme, s, s.label()).clicked() {
                    self.set_color_scheme(scheme);
                }
            }
        });
        let mut crosshair = self.theme.crosshair_enabled;
        if ui.checkbox(&mut crosshair, "Crosshair").changed() {
            self.set_crosshair(crosshair);
        }
        let mut highlight = self.theme.highlight_input_fields;
        if ui
            .checkbox(&mut highlight, "Highlight Input Fields")
            .on_hover_text("Highlight editable (unprotected) 3270 input fields")
            .changed()
        {
            self.set_highlight_input_fields(highlight);
        }
        ui.checkbox(&mut self.show_keypad_bar, "Keypad");
        ui.separator();
        if ui
            .add(
                egui::Button::new("Zoom In")
                    .shortcut_text(shortcut(Modifiers::COMMAND, Key::Equals)),
            )
            .clicked()
        {
            self.theme.zoom_in();
        }
        if ui
            .add(
                egui::Button::new("Zoom Out")
                    .shortcut_text(shortcut(Modifiers::COMMAND, Key::Minus)),
            )
            .clicked()
        {
            self.theme.zoom_out();
        }
        if ui
            .add(
                egui::Button::new(format!("Reset Zoom ({}%)", self.theme.zoom_percent()))
                    .shortcut_text(shortcut(Modifiers::COMMAND, Key::Num0)),
            )
            .clicked()
        {
            self.theme.reset_zoom();
        }
    }

    /// Message line above the OIA bar, with a button to dismiss the message.
    fn render_message_line(&mut self, ui: &mut Ui) {
        let Some(message) = &self.status_message else {
            return;
        };
        let (icon, color) = match message.level() {
            MessageLevel::Info => ("ℹ", Color32::from_rgb(0xA4, 0xB0, 0xBE)),
            MessageLevel::Warning => ("⚠", Color32::from_rgb(0xFF, 0xEA, 0x55)),
            MessageLevel::Error => ("✖", Color32::from_rgb(0xFF, 0x6B, 0x6B)),
        };
        let text = format!("{icon} {}", message.text());
        let mut dismiss = false;
        ui.horizontal(|ui| {
            if ui.small_button("×").on_hover_text("Dismiss").clicked() {
                dismiss = true;
            }
            ui.add(egui::Label::new(RichText::new(text).color(color)).wrap());
        });
        if dismiss {
            self.status_message = None;
        }
    }

    /// Opens the profile manager, or brings its window to the front if it is open.
    fn show_profile_manager(&mut self, ctx: &Context) {
        if self.profile_manager.is_some() {
            ctx.send_viewport_cmd_to(ProfileManager::viewport_id(), egui::ViewportCommand::Focus);
        }
        self.open_profile_manager();
    }

    /// The profile manager in a window of its own (see [`ProfileManager`]), and what the user
    /// decided there. Closing the window is Cancel.
    fn render_profile_manager(&mut self, ctx: &Context) {
        // Taken out of `self` for the frame: the window's closure edits the working copy
        // while `self.catalog` is read.
        let Some(mut manager) = self.profile_manager.take() else {
            return;
        };
        let unsaved = manager.differs_from(&self.catalog);
        let mut window = egui::ViewportBuilder::default()
            .with_title("Profiles — bastion3270")
            .with_app_id(crate::icon::APP_ID)
            .with_inner_size([860.0, 640.0])
            .with_min_inner_size([680.0, 420.0]);
        if let Some(icon) = crate::icon::app_icon() {
            window = window.with_icon(icon);
        }
        let action =
            ctx.show_viewport_immediate(ProfileManager::viewport_id(), window, |ui, class| {
                let closed = class != egui::ViewportClass::EmbeddedWindow
                    && ui.input(|i| i.viewport().close_requested());
                let action = manager.ui(ui, unsaved);
                if closed {
                    Some(ManagerAction::Cancel)
                } else {
                    action
                }
            });
        self.profile_manager = Some(manager);
        match action {
            Some(ManagerAction::Save) => {
                self.save_profile_manager();
            }
            Some(ManagerAction::Cancel) => self.cancel_profile_manager(),
            None => {}
        }
    }

    /// The floating windows that are open (About, the certificate trust dialog).
    fn render_windows(&mut self, ctx: &Context) {
        if self.show_about {
            self.render_about_window(ctx);
        }
        if self.untrusted_certificate.is_some() {
            self.render_untrusted_certificate_window(ctx);
        }
    }

    /// The host's certificate was refused: what it says, why, and the choice to trust it.
    fn render_untrusted_certificate_window(&mut self, ctx: &Context) {
        // A copy: the window's closure must not borrow `self` while the buttons decide.
        let Some(prompt) = self.untrusted_certificate.clone() else {
            return;
        };
        let (rejection, profile_name) = (&prompt.rejection, &prompt.profile_name);
        let cert = &rejection.certificate;
        let mut open = true;
        let (mut trust, mut cancel) = (false, false);
        egui::Window::new("Host certificate not trusted")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new(format!("The certificate is {}.", rejection.problem)).strong(),
                );
                ui.label(rejection.problem.hint());
                ui.separator();
                egui::Grid::new("untrusted_certificate_details")
                    .num_columns(2)
                    .show(ui, |ui| {
                        for (label, value) in [
                            ("Subject", cert.subject.clone()),
                            ("Issuer", cert.issuer.clone()),
                            ("Valid from", cert.not_before.clone()),
                            ("Valid until", cert.not_after.clone()),
                            ("Names", cert.names.join(", ")),
                        ] {
                            ui.label(label);
                            ui.label(value);
                            ui.end_row();
                        }
                    });
                ui.label("SHA-256:");
                ui.monospace(fingerprint_groups(&cert.sha256_hex()));
                ui.separator();
                ui.label(format!(
                    "Compare the SHA-256 with the one your mainframe team gives you. Trusting \
                     it accepts exactly this certificate for the profile '{profile_name}', \
                     until the host's certificate changes."
                ));
                ui.horizontal(|ui| {
                    if ui.button("Trust this certificate").clicked() {
                        trust = true;
                    }
                    cancel = ui.button("Cancel").clicked();
                });
            });
        if trust {
            self.trust_refused_certificate();
        } else if cancel || !open {
            self.untrusted_certificate = None;
        }
    }

    /// Help → About: version, licence and where the client keeps its files.
    fn render_about_window(&mut self, ctx: &Context) {
        let mut open = self.show_about;
        egui::Window::new("About bastion3270")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new(format!("bastion3270 {}", env!("CARGO_PKG_VERSION"))).strong(),
                );
                ui.label("TN3270 / TN3270E client for IBM z/OS");
                ui.label(format!("License: {}", env!("CARGO_PKG_LICENSE")));
                ui.hyperlink(env!("CARGO_PKG_REPOSITORY"));
                ui.separator();
                match &self.profile_store {
                    Some(store) => {
                        ui.label(format!("Profiles: {}", store.path().display()));
                    }
                    None => {
                        ui.label("Profiles: not saved (start with --profiles <file>)");
                    }
                }
                match &self.log_path {
                    Some(log) => ui.label(format!("Log: {}", log.display())),
                    None => ui.label("Log: stderr only"),
                };
            });
        self.show_about = open;
    }

    fn render_keypad_bar(&mut self, ui: &mut Ui) {
        let mut clicked_action: Option<GuiKeyAction> = None;

        ui.horizontal_wrapped(|ui| {
            // Bank selector PF1..PF12 vs PF13..PF24
            let bank_label = if self.keypad_shift_pf13_24 {
                "PF13–24"
            } else {
                "PF1–12"
            };
            if ui
                .selectable_label(self.keypad_shift_pf13_24, bank_label)
                .on_hover_text("Switch between PF1–PF12 and PF13–PF24")
                .clicked()
            {
                self.keypad_shift_pf13_24 = !self.keypad_shift_pf13_24;
            }
            ui.separator();

            let base: u8 = if self.keypad_shift_pf13_24 { 13 } else { 1 };
            for offset in 0..12u8 {
                let pf_num = base.saturating_add(offset);
                if let Some(aid) = AidKey::pf(pf_num) {
                    if ui.small_button(format!("PF{pf_num}")).clicked() {
                        clicked_action = Some(GuiKeyAction::Aid(aid));
                    }
                }
            }

            ui.separator();
            for pa_num in 1..=3u8 {
                if let Some(aid) = AidKey::pa(pa_num) {
                    if ui.small_button(format!("PA{pa_num}")).clicked() {
                        clicked_action = Some(GuiKeyAction::Aid(aid));
                    }
                }
            }

            ui.separator();
            if ui.small_button("Clear").clicked() {
                clicked_action = Some(GuiKeyAction::Aid(AidKey::Clear));
            }
            if ui
                .small_button(RichText::new("Reset").color(Color32::from_rgb(0xFF, 0x9E, 0x3B)))
                .on_hover_text("Unlock X PROTECTED / X NUMERIC operator lock (Esc / Ctrl+R)")
                .clicked()
            {
                clicked_action = Some(GuiKeyAction::Action(ActionKey::Reset));
            }
            if ui.small_button("Erase EOF").clicked() {
                clicked_action = Some(GuiKeyAction::Action(ActionKey::EraseEof));
            }
            if ui.small_button("Erase Inp").clicked() {
                clicked_action = Some(GuiKeyAction::Action(ActionKey::EraseInput));
            }
            if ui.small_button("Home").clicked() {
                clicked_action = Some(GuiKeyAction::Action(ActionKey::Home));
            }
            ui.separator();
            if ui
                .small_button("Attn")
                .on_hover_text("Interrupt the running host program")
                .clicked()
            {
                clicked_action = Some(GuiKeyAction::Attention(AttentionKey::Attn));
            }
            if ui
                .small_button("SysReq")
                .on_hover_text("System Request")
                .clicked()
            {
                clicked_action = Some(GuiKeyAction::Attention(AttentionKey::SysReq));
            }
            if ui
                .small_button(
                    RichText::new("↩ Enter")
                        .strong()
                        .color(Color32::from_rgb(0x2E, 0xEB, 0x5A)),
                )
                .clicked()
            {
                clicked_action = Some(GuiKeyAction::Aid(AidKey::Enter));
            }
        });

        if let Some(act) = clicked_action {
            self.apply_key_action(act);
        }
    }
}

impl eframe::App for Bastion3270GuiApp {
    /// Runs before every [`Self::ui`] call and also while the window is minimized or occluded
    /// (when `eframe` skips `ui`), so host output is drained even when nothing is drawn and the
    /// bounded session channel never stalls the connection.
    fn logic(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // The light screen theme gets light window chrome too (as in the web client).
        let wanted = if self.theme.color_scheme == TerminalColorScheme::Light {
            egui::Theme::Light
        } else {
            egui::Theme::Dark
        };
        if ctx.theme() != wanted {
            ctx.set_theme(wanted);
        }
        self.process_session_events();
        self.autosave_profiles(false);
        // Request continuous repaint at ~20Hz while connected or blinking so incoming mainframe
        // screens and cursor blink update smoothly even without mouse movement.
        ctx.request_repaint_after(Duration::from_millis(50));
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.render_ui(ui);
    }

    /// Writes pending profile edits when the window closes (no quiet period to wait for).
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.autosave_profiles(true);
    }
}

/// A fingerprint in groups of four hex digits, so it can be compared by eye.
fn fingerprint_groups(hex: &str) -> String {
    hex.as_bytes()
        .chunks(4)
        .filter_map(|group| std::str::from_utf8(group).ok())
        .collect::<Vec<_>>()
        .join(" ")
}
