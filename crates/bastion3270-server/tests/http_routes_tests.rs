//! HTTP route tests through `tower::ServiceExt::oneshot` (no socket needed).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use bastion3270_server::http::{router, AppState};
use bastion3270_server::{Extensions, Gateway, ServerConfig};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

fn app(extra: &str) -> (axum::Router, AppState) {
    let cfg = ServerConfig::from_toml_str(&format!(
        "{extra}\n[[profiles]]\nid = \"hercules\"\nname = \"Hercules\"\ndescription = \"lab\"\n\
         [profiles.connection]\ntls_mode = \"disabled\"\nhost = \"10.1.2.3\"\nport = 3270\n\
         [[profiles]]\nid = \"prod\"\nname = \"Prod\"\n[profiles.connection]\ntls_mode = \"disabled\"\nhost = \"10.9.9.9\"\n"
    ))
    .unwrap();
    let ext = Extensions::defaults(&cfg);
    let state = AppState::new(Arc::new(Gateway::new(cfg, ext)));
    (router(state.clone()), state)
}

async fn get(
    app: &axum::Router,
    uri: &str,
    auth: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let (status, headers, body) = get_bytes(app, uri, auth).await;
    (status, headers, String::from_utf8(body).unwrap())
}

/// As [`get`], for a body that is not text (an image).
async fn get_bytes(
    app: &axum::Router,
    uri: &str,
    auth: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut req = Request::builder().uri(uri);
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body.to_vec())
}

#[tokio::test]
async fn test_static_client_and_security_headers() {
    let (app, _) = app("");
    let (status, h, body) = get(&app, "/", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<canvas id=\"screen\""));
    assert!(h[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .contains("frame-ancestors 'none'"));
    assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(h["cross-origin-opener-policy"], "same-origin");
    assert_eq!(h["cross-origin-resource-policy"], "same-origin");
    assert!(h["permissions-policy"]
        .to_str()
        .unwrap()
        .contains("camera=()"));

    let (status, h, body) = get(&app, "/app.js", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/javascript"));
    assert!(body.contains("bastion3270.v1"));
}

/// The page loads `app.js` as an ES module; every module it imports must be served as
/// JavaScript with the same security headers (a module served as `text/plain` or 404 breaks the
/// whole client, and browsers enforce the MIME type for modules).
#[tokio::test]
async fn test_every_imported_module_is_served_as_javascript() {
    let (app, _) = app("");
    let (_, _, index) = get(&app, "/", None).await;
    assert!(index.contains(r#"<script type="module" src="/app.js">"#));

    let (_, _, app_js) = get(&app, "/app.js", None).await;
    // Every `… from "./x.js"`, also of an import statement spread over several lines.
    let imports: Vec<&str> = app_js
        .split("from \"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .collect();
    for expected in ["./i18n.js", "./keymap.js", "./screen.js", "./status.js"] {
        assert!(imports.contains(&expected), "{expected} in {imports:?}");
    }
    for module in imports {
        let path = module.trim_start_matches('.');
        let (status, h, body) = get(&app, path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(
            h[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/javascript"),
            "{path}"
        );
        assert!(h.contains_key(header::CONTENT_SECURITY_POLICY), "{path}");
        assert!(body.contains("export "), "{path}");
    }
}

/// A browser offers to install the client as an application when the page links a manifest
/// that it may load (CSP `manifest-src`) and that names the application, its start URL, a
/// window mode and icons of 192 and 512 pixels. Every icon must really be served as a PNG of
/// the size the manifest declares, or the browser drops it.
#[tokio::test]
async fn test_the_client_can_be_installed_as_a_web_application() {
    let (app, _) = app("");
    let (_, h, index) = get(&app, "/", None).await;
    assert!(index.contains(r#"<link rel="manifest" href="/manifest.webmanifest""#));
    assert!(index.contains(r#"<meta name="theme-color""#));
    let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("manifest-src 'self'"), "{csp}");
    assert!(csp.contains("img-src 'self'"), "{csp}");

    let (status, h, body) = get(&app, "/manifest.webmanifest", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h[header::CONTENT_TYPE], "application/manifest+json");
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    let manifest: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(manifest["name"], "bastion3270");
    assert_eq!(manifest["start_url"], "/");
    assert_eq!(manifest["scope"], "/");
    assert_eq!(manifest["display"], "standalone");

    let mut sizes = Vec::new();
    for icon in manifest["icons"].as_array().unwrap() {
        let path = icon["src"].as_str().unwrap();
        assert_eq!(icon["type"], "image/png", "{path}");
        let (status, h, png) = get_bytes(&app, path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(h[header::CONTENT_TYPE], "image/png", "{path}");
        // The PNG signature, then the IHDR chunk: width and height as big-endian u32.
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "{path}");
        let width = u32::from_be_bytes(png[16..20].try_into().unwrap());
        let height = u32::from_be_bytes(png[20..24].try_into().unwrap());
        assert_eq!(icon["sizes"], format!("{width}x{height}"), "{path}");
        sizes.push(width);
    }
    sizes.sort_unstable();
    assert_eq!(sizes, [192, 512]);
    assert!(index.contains(r#"<link rel="icon" type="image/png" href="/icon-192.png">"#));
}

#[tokio::test]
async fn test_probes_and_draining() {
    let (app, state) = app("");
    let (status, _, body) = get(&app, "/healthz", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body, r#"{"status":"ok"}"#,
        "no build or version on an open probe"
    );

    let (status, _, body) = get(&app, "/readyz", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("sessions"),
        "no load figures on an open probe: {body}"
    );
    state.begin_shutdown();
    let (status, _, body) = get(&app, "/readyz", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("draining"));
}

#[tokio::test]
async fn test_api_config_and_profiles_hide_hosts() {
    let (app, _) = app("");
    let (_, _, body) = get(&app, "/api/config", None).await;
    let cfg: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(cfg["auth"], "none");
    assert_eq!(cfg["auth_required"], false);
    assert!(
        cfg.get("version").is_none() && cfg.get("build").is_none(),
        "read before login: no version or build: {cfg}"
    );

    let (status, _, body) = get(&app, "/api/profiles", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("hercules") && body.contains("prod"));
    assert!(!body.contains("10.1.2.3") && !body.contains("10.9.9.9"));
    let list: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(list["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn test_api_profiles_with_static_token() {
    let hash = bastion3270_server::extensions::auth::encode_hex(
        &bastion3270_server::extensions::auth::sha256(b"t0k"),
    );
    let (app, _) = app(&format!(
        "[auth]\nmode = \"static-token\"\n[[auth.tokens]]\nsubject = \"dev\"\nsha256 = \"{hash}\"\nprofiles = [\"hercules\"]\n"
    ));
    let (status, _, _) = get(&app, "/api/profiles", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = get(&app, "/api/profiles", Some("Bearer nope")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _, body) = get(&app, "/api/profiles", Some("Bearer t0k")).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["subject"], "dev");
    let ids: Vec<&str> = v["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["hercules"]);
}
