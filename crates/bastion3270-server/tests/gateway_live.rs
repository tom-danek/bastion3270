//! Live test: browser protocol → gateway → real Hercules MVS 3.8j.
//!
//! Ignored by default so `cargo test` stays hermetic.
//!
//! ```text
//! # in-process gateway → Hercules on 127.0.0.1:3270 (BASTION3270_HOST / BASTION3270_PORT override)
//! cargo test -p bastion3270-server --test gateway_live -- --ignored --nocapture
//!
//! # against a running gateway container (profile id "hercules")
//! BASTION3270_GATEWAY_ADDR=127.0.0.1:18080 cargo test -p bastion3270-server --test gateway_live -- --ignored --nocapture
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::Duration;

use bastion3270_net::ConnectionProfile;
use bastion3270_server::{Extensions, GatewayProfile, Server, ServerConfig};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

async fn gateway_addr() -> String {
    if let Ok(addr) = std::env::var("BASTION3270_GATEWAY_ADDR") {
        return addr;
    }
    let mut connection = ConnectionProfile::from_env().expect("profile from env");
    connection.idle_timeout_ms = 600_000;
    let config = ServerConfig {
        profiles: vec![GatewayProfile {
            id: "hercules".into(),
            name: "Hercules".into(),
            description: String::new(),
            allow_paste: true,
            allow_copy: true,
            keyboard: bastion3270_server::KeyboardPreset::default(),
            allowed_lu_names: None,
            custom: false,
            connection,
        }],
        ..ServerConfig::default()
    };
    config.validate().expect("valid config");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ext = Extensions::defaults(&config);
    tokio::spawn(Server::new(config, ext).serve_with_listener(listener, std::future::pending()));
    addr.to_string()
}

#[tokio::test]
#[ignore = "requires a live TN3270 host (Hercules TK4- on 127.0.0.1:3270)"]
async fn live_gateway_renders_hercules_logon_screen() {
    let addr = gateway_addr().await;
    let mut req = format!("ws://{addr}/ws").into_client_request().unwrap();
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static("bastion3270.v1"),
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .expect("ws connect");
    ws.send(Message::Text(
        json!({"type":"open","profile":"hercules"})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();

    let mut session = None;
    let mut screen: Option<Value> = None;
    let mut status: Option<Value> = None;
    let collect = async {
        while let Some(Ok(msg)) = ws.next().await {
            let Message::Text(t) = msg else { continue };
            let m: Value = serde_json::from_str(t.as_str()).unwrap();
            match m["type"].as_str() {
                Some("session") => session = Some(m),
                Some("frame") => {
                    status = Some(m["status"].clone());
                    if !m["screen"].is_null() {
                        screen = Some(m["screen"].clone());
                    }
                    let painted = screen.as_ref().is_some_and(|s| {
                        s["text"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|r| !r.as_str().unwrap().trim().is_empty())
                    });
                    if painted && m["status"]["state"] == "connected" {
                        return;
                    }
                }
                Some("error" | "closed") => panic!("gateway refused: {m}"),
                _ => {}
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(20), collect)
        .await
        .expect("painted screen within 20 s");

    // Let VTAM finish its write before we leave (see bastion3270-net hercules_live).
    let settle = tokio::time::Instant::now() + Duration::from_millis(2500);
    while let Ok(Some(Ok(Message::Text(t)))) = tokio::time::timeout_at(settle, ws.next()).await {
        let m: Value = serde_json::from_str(t.as_str()).unwrap();
        if !m["screen"].is_null() {
            screen = Some(m["screen"].clone());
        }
    }

    let session = session.expect("session message");
    assert!(session["resume_token"]
        .as_str()
        .is_some_and(|t| t.len() == 64));
    let screen = screen.unwrap();
    for row in screen["text"].as_array().unwrap() {
        println!("{}", row.as_str().unwrap().trim_end());
    }
    println!("status: {}", status.unwrap());

    ws.send(Message::Text(
        json!({"type":"disconnect"}).to_string().into(),
    ))
    .await
    .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(Message::Text(t))) = ws.next().await {
            let m: Value = serde_json::from_str(t.as_str()).unwrap();
            if m["type"] == "closed" {
                return m;
            }
        }
        panic!("socket ended without closed message");
    })
    .await
    .unwrap();
    assert_eq!(closed["reason"], "user");
}
