//! A short load run against an in-process gateway: keeps the tool working, and checks the
//! gateway's metrics see the operator round trips.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use bastion3270_loadgen::{gateway_config, host, run, tls, GatewayTls, LoadConfig};
use bastion3270_server::{Extensions, Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_load_run_completes_without_failures() {
    let hosts = Arc::new(host::HostStats::default());
    let host_addr = host::spawn(
        "127.0.0.1:0".parse().unwrap(),
        Duration::from_millis(5),
        Arc::clone(&hosts),
        None,
    )
    .await
    .unwrap();
    let metrics_addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway = listener.local_addr().unwrap();
    let cfg = ServerConfig::from_toml_str(&gateway_config(
        host_addr,
        8,
        gateway,
        metrics_addr,
        GatewayTls::default(),
    ))
    .unwrap();
    let ext = Extensions::defaults(&cfg);
    tokio::spawn(Server::new(cfg, ext).serve_with_listener(listener, std::future::pending()));

    let report = run(
        LoadConfig {
            gateway,
            profile: "load".into(),
            sessions: 8,
            ramp: Duration::from_millis(400),
            duration: Duration::from_secs(2),
            think: Duration::from_millis(200),
            reopen: false,
            tls: None,
        },
        Duration::from_secs(1),
        |_| {},
    )
    .await;
    assert_eq!(report.opened, 8, "{report}");
    assert!(report.failed.is_empty(), "{report}");
    assert!(
        report.actions >= 8,
        "every session made round trips: {report}"
    );
    assert_eq!(report.active, 0, "all sessions ended");

    let mut tcp = TcpStream::connect(metrics_addr).await.unwrap();
    tcp.write_all(b"GET /metrics HTTP/1.1\r\nHost: m\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut text = String::new();
    tcp.read_to_string(&mut text).await.unwrap();
    let count: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix("bastion3270_aid_response_seconds_count "))
        .and_then(|v| v.parse().ok())
        .unwrap();
    assert!(
        count >= report.actions / 2,
        "gateway saw the round trips: {count} vs {report}"
    );
}

/// The production path: TLS towards the simulated hosts and WSS on the gateway's own listener,
/// with the throw-away PKI of `bastion3270-loadgen certs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_load_run_over_tls_on_both_sides_completes_without_failures() {
    let pki = std::env::temp_dir().join(format!("bastion3270-loadgen-pki-{}", std::process::id()));
    tls::write_test_pki(&pki).unwrap();
    let (ca, cert, key) = (
        pki.join(tls::CA_FILE),
        pki.join(tls::CERT_FILE),
        pki.join(tls::KEY_FILE),
    );

    let hosts = Arc::new(host::HostStats::default());
    let host_addr = host::spawn(
        "127.0.0.1:0".parse().unwrap(),
        Duration::from_millis(5),
        Arc::clone(&hosts),
        Some(tls::acceptor(&cert, &key).unwrap()),
    )
    .await
    .unwrap();
    let metrics_addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway = listener.local_addr().unwrap();
    let toml = gateway_config(
        host_addr,
        4,
        gateway,
        metrics_addr,
        GatewayTls {
            host_ca: Some(&ca),
            listener: Some((&cert, &key)),
        },
    );
    assert!(toml.contains("[server.tls]") && toml.contains("tls_mode = \"enabled\""));
    let cfg = ServerConfig::from_toml_str(&toml).unwrap();
    let ext = Extensions::defaults(&cfg);
    tokio::spawn(Server::new(cfg, ext).serve_with_listener(listener, std::future::pending()));

    let report = run(
        LoadConfig {
            gateway,
            profile: "load".into(),
            sessions: 4,
            ramp: Duration::from_millis(200),
            duration: Duration::from_secs(2),
            think: Duration::from_millis(200),
            reopen: false,
            tls: Some(tls::client_config(&ca).unwrap()),
        },
        Duration::from_secs(1),
        |_| {},
    )
    .await;
    let _ = std::fs::remove_dir_all(&pki);
    assert_eq!(report.opened, 4, "{report}");
    assert!(report.failed.is_empty(), "{report}");
    assert!(
        report.actions >= 4,
        "every session made round trips: {report}"
    );
    assert!(
        hosts.connections.load(std::sync::atomic::Ordering::Relaxed) >= 4,
        "the gateway reached the hosts over TLS"
    );
}

/// Starts simulated hosts and a gateway whose sessions live one second (the reaper looks every
/// second), and returns the gateway's address.
async fn gateway_with_short_session_lifetime(sessions: usize) -> std::net::SocketAddr {
    let hosts = Arc::new(host::HostStats::default());
    let host_addr = host::spawn(
        "127.0.0.1:0".parse().unwrap(),
        Duration::from_millis(5),
        hosts,
        None,
    )
    .await
    .unwrap();
    let metrics_addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway = listener.local_addr().unwrap();
    let toml = gateway_config(
        host_addr,
        sessions,
        gateway,
        metrics_addr,
        GatewayTls::default(),
    )
    .replace(
        "[limits]\n",
        "[limits]\nmax_session_lifetime_secs = 1\nreaper_interval_secs = 1\n",
    );
    let cfg = ServerConfig::from_toml_str(&toml).unwrap();
    let ext = Extensions::defaults(&cfg);
    tokio::spawn(Server::new(cfg, ext).serve_with_listener(listener, std::future::pending()));
    gateway
}

fn short_run(gateway: std::net::SocketAddr, sessions: usize, reopen: bool) -> LoadConfig {
    LoadConfig {
        gateway,
        profile: "load".into(),
        sessions,
        ramp: Duration::from_millis(200),
        duration: Duration::from_millis(4500),
        // Longer than the session lifetime: the gateway ends most sessions while their
        // operator thinks, so the browser must notice an end while it waits.
        think: Duration::from_millis(1500),
        reopen,
        tls: None,
    }
}

/// Every session the gateway ends is reported with the gateway's reason, also when it ends
/// while the operator is thinking (a soak once lost 981 of 1000 ended sessions that way).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_session_the_gateway_ends_is_reported_with_its_reason() {
    let gateway = gateway_with_short_session_lifetime(6).await;
    let report = run(short_run(gateway, 6, false), Duration::from_secs(1), |_| {}).await;
    assert_eq!(report.opened, 6, "{report}");
    assert!(report.failed.is_empty(), "{report}");
    assert_eq!(
        report.ended.get("lifetime").copied(),
        Some(6),
        "each session ended by its lifetime, counted once: {report}"
    );
    assert_eq!(report.ended.values().sum::<u64>(), 6, "{report}");
    assert_eq!(report.active, 0, "{report}");
}

/// With `reopen`, a session the gateway ends is opened again, as an operator logs on again:
/// a soak can run longer than the session lifetime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reopen_opens_a_new_session_after_the_gateway_ended_one() {
    let gateway = gateway_with_short_session_lifetime(4).await;
    let report = run(short_run(gateway, 4, true), Duration::from_secs(1), |_| {}).await;
    assert!(report.failed.is_empty(), "{report}");
    let ended = report.ended.get("lifetime").copied().unwrap_or(0);
    assert!(ended >= 4, "every first session ended: {report}");
    // A session that ends after the run's end is not opened again.
    assert!(
        report.opened >= 8 && report.opened <= 4 + ended,
        "a new session for every session ended during the run: {report}"
    );
    assert_eq!(report.active, 0, "{report}");
}
