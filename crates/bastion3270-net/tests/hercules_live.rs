//! Live integration test against a real TN3270 host.
//!
//! Ignored by default so `cargo test` stays hermetic. Run against the local Hercules
//! MVS 3.8j TK4- container (see `docker/docker-compose.yml`):
//!
//! ```text
//! cargo test -p bastion3270-net --test hercules_live -- --ignored --nocapture
//! ```
//!
//! Target is configurable through the usual `BASTION3270_*` environment overrides
//! (defaults: `127.0.0.1:3270`, plain TCP, Model 2, CP037).

#![allow(clippy::expect_used, clippy::panic)]

use std::time::Duration;

use bastion3270_net::{ConnectionProfile, SessionCoordinator, SessionEvent, SessionState};

#[tokio::test]
#[ignore = "requires a live TN3270 host (Hercules TK4- on 127.0.0.1:3270)"]
async fn live_hercules_connect_render_and_disconnect() {
    let profile = ConnectionProfile::from_env().expect("valid profile from env");

    let (handle, mut events, join) = tokio::time::timeout(
        Duration::from_secs(10),
        SessionCoordinator::connect(profile),
    )
    .await
    .expect("connect within 10 s")
    .expect("transport + coordinator start");

    let mut negotiated = false;
    let mut screen = None;

    // Wait for initial screen, then keep absorbing updates for 2500ms so VTAM NETSOL
    // completes its channel write (`Logon ===>`) before we disconnect, preventing
    // `IST800I TERM CUU0C0 HAS BEEN RELEASED BY NETSOL DUE TO I/O ERROR`.
    let collect = async {
        while let Some(event) = events.recv().await {
            match event {
                SessionEvent::NegotiationComplete { .. } => negotiated = true,
                SessionEvent::ScreenUpdated(view) => {
                    if !view.to_plain_text_trimmed().trim().is_empty() {
                        screen = Some(view);
                        break;
                    }
                }
                SessionEvent::Error(msg) => panic!("session error: {msg}"),
                SessionEvent::Disconnected => break,
                _ => {}
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_millis(2500);
        while let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.recv()).await {
            match event {
                SessionEvent::ScreenUpdated(view) => {
                    screen = Some(view);
                }
                SessionEvent::Error(msg) => panic!("session error during settle: {msg}"),
                _ => {}
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(15), collect)
        .await
        .expect("first non-empty screen within 15 s");

    assert!(negotiated, "Telnet/TN3270(E) negotiation must complete");
    let view = screen.expect("host must paint a non-empty screen");
    println!("{}", view.to_plain_text_trimmed());

    let status = handle.query_status().await.expect("status query");
    assert_eq!(status.state, SessionState::Connected3270);

    handle.disconnect().await.expect("disconnect");
    let outcome = join.await.expect("join coordinator task");
    assert!(outcome.is_ok(), "clean shutdown expected: {outcome:?}");
}
