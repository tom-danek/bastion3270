//! The profile manager: a window of its own that edits a working copy of the profiles.
//!
//! Nothing reaches the catalog or the profile file before **Save**; **Cancel** drops the
//! working copy. The profile chosen in the main window (the one **Connect** uses) is
//! independent of the profile being edited.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use bastion3270_gui::storage::ProfileStore;
use bastion3270_gui::{Bastion3270GuiApp, ProfileCatalog, SavedProfile, TerminalColorScheme};
use bastion3270_net::ProfileTerminalModel;
use egui::{Event, RawInput};

/// An app with the profiles "LPAR A", "LPAR B" and "LPAR C".
fn app_with_three_profiles() -> Bastion3270GuiApp {
    let profiles = ["LPAR A", "LPAR B", "LPAR C"]
        .into_iter()
        .map(|name| {
            let mut profile = SavedProfile::hercules_tk4_preset();
            name.clone_into(&mut profile.name);
            profile
        })
        .collect();
    let mut app = Bastion3270GuiApp::new().unwrap();
    app.catalog = ProfileCatalog::from_profiles(profiles, 0).unwrap();
    app
}

fn names(app: &Bastion3270GuiApp) -> Vec<String> {
    app.catalog
        .profiles()
        .iter()
        .map(|p| p.name.clone())
        .collect()
}

/// An app whose catalog is stored in a fresh file; returns the file's path too.
fn app_with_profile_file(tag: &str) -> (Bastion3270GuiApp, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "bastion3270-profile-manager-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("profiles.toml");
    let app = Bastion3270GuiApp::new()
        .unwrap()
        .with_profiles(ProfileStore::open(path.clone()), None);
    (app, path)
}

#[test]
fn test_edits_reach_the_catalog_and_the_file_only_with_save() {
    let (mut app, path) = app_with_profile_file("save");
    let before = app.catalog.clone();
    let file_before = std::fs::read_to_string(&path).ok();

    app.open_profile_manager();
    let manager = app.profile_manager.as_mut().expect("manager open");
    assert!(!manager.differs_from(&before));
    manager.selected_mut().unwrap().connection.host = "zos1.example.com".to_owned();
    manager.selected_mut().unwrap().connection.terminal_model = ProfileTerminalModel::Model4;
    assert!(manager.differs_from(&before));

    // Not saved yet: the catalog, the session's settings and the file are as before.
    assert_eq!(app.catalog, before);
    assert_eq!(app.oia.rows, 24);
    assert_eq!(std::fs::read_to_string(&path).ok(), file_before);

    assert!(app.save_profile_manager());
    assert!(app.profile_manager.is_none(), "Save closes the window");
    let saved = app.catalog.selected().unwrap();
    assert_eq!(saved.connection.host, "zos1.example.com");
    // The selected profile's settings apply at once while no session is open.
    assert_eq!((app.oia.rows, app.oia.cols), (43, 80));
    let file = std::fs::read_to_string(&path).expect("profile file written by Save");
    assert!(file.contains("zos1.example.com"), "{file}");
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn test_cancel_drops_every_change() {
    let (mut app, path) = app_with_profile_file("cancel");
    let before = app.catalog.clone();
    let file_before = std::fs::read_to_string(&path).ok();

    app.open_profile_manager();
    let manager = app.profile_manager.as_mut().unwrap();
    manager.selected_mut().unwrap().name = "Renamed".to_owned();
    manager.add_new();
    manager.select(0);
    assert!(manager.remove_selected());

    app.cancel_profile_manager();
    assert!(app.profile_manager.is_none());
    assert_eq!(app.catalog, before);
    assert_eq!(std::fs::read_to_string(&path).ok(), file_before);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// Choosing a profile to edit does not change the profile the main window connects with,
/// and that choice follows its profile when others are added or deleted.
#[test]
fn test_the_edited_profile_is_independent_of_the_connect_profile() {
    let mut app = app_with_three_profiles();
    assert!(app.catalog.select(1));
    let connect_with = app.catalog.selected().unwrap().name.clone();

    app.open_profile_manager();
    let manager = app.profile_manager.as_mut().unwrap();
    assert_eq!(manager.selected_index(), 1, "opens on the current profile");
    manager.select(2);
    manager.selected_mut().unwrap().description = "edited".to_owned();
    assert_eq!(app.catalog.selected_index(), 1);

    // Delete the first profile: the connect profile moves to index 0 with its name.
    let manager = app.profile_manager.as_mut().unwrap();
    manager.select(0);
    assert!(manager.remove_selected());
    assert!(app.save_profile_manager());
    assert_eq!(app.catalog.selected().unwrap().name, connect_with);
    assert_eq!(app.catalog.selected_index(), 0);
    assert_eq!(app.catalog.profiles()[1].description, "edited");

    // Delete the connect profile itself: the first remaining profile is chosen.
    app.open_profile_manager();
    let manager = app.profile_manager.as_mut().unwrap();
    manager.select(0);
    assert!(manager.remove_selected());
    assert!(app.save_profile_manager());
    assert_eq!(app.catalog.selected_index(), 0);
    assert_eq!(app.catalog.len(), 1);

    // The last profile cannot be deleted.
    app.open_profile_manager();
    assert!(!app.profile_manager.as_mut().unwrap().remove_selected());
}

#[test]
fn test_new_and_duplicated_profiles() {
    let mut app = Bastion3270GuiApp::new().unwrap();
    let count = app.catalog.len();
    app.open_profile_manager();
    let manager = app.profile_manager.as_mut().unwrap();

    manager.select(0);
    manager.duplicate_selected();
    assert_eq!(manager.selected_index(), count, "the copy is selected");
    let copy = manager.selected_mut().unwrap().name.clone();
    assert!(copy.ends_with("(Copy)"), "{copy}");

    // A new profile has no host yet: Save is refused and the window says why.
    manager.add_new();
    assert_eq!(manager.selected_index(), count + 1);
    let problem = manager.problem().expect("a profile without a host");
    assert!(problem.contains("host"), "{problem}");
    assert!(
        !app.save_profile_manager(),
        "an invalid profile is not saved"
    );
    assert!(app.profile_manager.is_some(), "the window stays open");
    assert_eq!(app.catalog.len(), count);

    let manager = app.profile_manager.as_mut().unwrap();
    let new = manager.selected_mut().unwrap();
    new.name = "Test LPAR".to_owned();
    new.connection.host = "lpar.example.com".to_owned();
    assert_eq!(manager.problem(), None);
    assert!(app.save_profile_manager());
    assert_eq!(names(&app)[count..], [copy, "Test LPAR".to_owned()]);
}

/// A view setting changed in the main window while the manager is open (stored in the
/// profile at once) is not undone by a later Save of the manager.
#[test]
fn test_main_window_settings_survive_a_save_of_the_open_manager() {
    let mut app = Bastion3270GuiApp::new().unwrap();
    app.open_profile_manager();
    app.profile_manager
        .as_mut()
        .unwrap()
        .selected_mut()
        .unwrap()
        .description = "edited in the manager".to_owned();

    let scheme = TerminalColorScheme::ALL[1];
    app.set_color_scheme(scheme);
    app.set_crosshair(true);
    assert_eq!(app.catalog.selected().unwrap().color_scheme, scheme);

    assert!(app.save_profile_manager());
    let profile = app.catalog.selected().unwrap();
    assert_eq!(profile.description, "edited in the manager");
    assert_eq!(profile.color_scheme, scheme);
    assert!(profile.crosshair_enabled);
}

#[test]
fn test_import_and_export_work_on_the_working_copy() {
    let mut app = Bastion3270GuiApp::new().unwrap();
    let before = app.catalog.clone();
    let dir = std::env::temp_dir().join(format!("bastion3270-pm-file-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("export.toml");

    app.open_profile_manager();
    let manager = app.profile_manager.as_mut().unwrap();
    manager.selected_mut().unwrap().name = "Exported".to_owned();
    manager.file_path = file.display().to_string();
    manager.export_file();
    assert!(manager.file_result.as_ref().unwrap().is_ok());
    app.cancel_profile_manager();

    app.open_profile_manager();
    let manager = app.profile_manager.as_mut().unwrap();
    manager.file_path = file.display().to_string();
    manager.import_file();
    assert!(manager.file_result.as_ref().unwrap().is_ok());
    assert!(manager.differs_from(&before));
    assert_eq!(
        app.catalog, before,
        "an import is saved with Save, as every change"
    );
    assert!(app.save_profile_manager());
    assert_eq!(names(&app)[0], "Exported");

    app.open_profile_manager();
    let manager = app.profile_manager.as_mut().unwrap();
    manager.file_path = dir.join("missing.toml").display().to_string();
    manager.import_file();
    assert!(manager.file_result.as_ref().unwrap().is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every text painted in one frame, and where (the middle of its first line).
fn painted_texts(shapes: &[egui::epaint::ClippedShape]) -> Vec<(String, egui::Pos2)> {
    fn collect(shape: &egui::Shape, out: &mut Vec<(String, egui::Pos2)>) {
        match shape {
            egui::Shape::Text(text) => {
                let rect = text.galley.rect.translate(text.pos.to_vec2());
                out.push((text.galley.text().to_owned(), rect.center()));
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect(s, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    for clipped in shapes {
        collect(&clipped.shape, &mut out);
    }
    out
}

/// Without a windowing backend (and where a platform cannot open a second window) the
/// manager is drawn as a window inside the main one. Its list, form and buttons render, and
/// the Cancel button closes it.
#[test]
fn test_the_manager_window_renders_and_cancel_closes_it() {
    let mut app = app_with_three_profiles();
    app.open_profile_manager();
    app.profile_manager
        .as_mut()
        .unwrap()
        .selected_mut()
        .unwrap()
        .description = "not saved".to_owned();

    let ctx = egui::Context::default();
    let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1400.0, 900.0));
    let frame = |app: &mut Bastion3270GuiApp, events: Vec<Event>| {
        let input = RawInput {
            screen_rect: Some(screen),
            events,
            ..RawInput::default()
        };
        let mut output = ctx.run_ui(input, |ui| app.render_ui(ui));
        output.textures_delta.clear();
        painted_texts(&output.shapes)
    };
    frame(&mut app, Vec::new());
    let texts = frame(&mut app, Vec::new());
    let all: String = texts
        .iter()
        .map(|(t, _)| t.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for expected in [
        "Profiles",
        "LPAR B",
        "LPAR C",
        "New",
        "Duplicate",
        "Delete",
        "Host",
        "Code page",
        "Keyboard",
        "Unsaved changes",
        "Save",
        "Cancel",
    ] {
        assert!(all.contains(expected), "{expected:?} is painted:\n{all}");
    }

    let (_, cancel) = texts
        .iter()
        .find(|(t, _)| t == "Cancel")
        .expect("Cancel button");
    let press = |pressed| Event::PointerButton {
        pos: *cancel,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::NONE,
    };
    frame(&mut app, vec![Event::PointerMoved(*cancel)]);
    frame(&mut app, vec![press(true)]);
    frame(&mut app, vec![press(false)]);
    assert!(app.profile_manager.is_none(), "Cancel closed the manager");
    assert_eq!(
        app.catalog.selected().unwrap().description,
        "Local MVS 3.8j Turnkey 4- emulator on 127.0.0.1:3270"
    );
}
