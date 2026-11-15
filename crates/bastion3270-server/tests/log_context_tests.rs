//! Log context of the network layer, in its own test binary: scoped `tracing` subscribers and
//! other tests registering the same callsites in parallel threads can disable a span for the
//! scoped subscriber (callsite interest is cached process-wide), so this check runs alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bastion3270_server::{Extensions, Gateway, ServerConfig, SessionIdentity};

fn config(host_port: u16) -> ServerConfig {
    ServerConfig::from_toml_str(&format!(
        r#"
        [[profiles]]
        id = "hercules"
        name = "Mock host"
        [profiles.connection]
        tls_mode = "disabled"
        host = "127.0.0.1"
        port = {host_port}
        "#
    ))
    .unwrap()
}

/// Log output captured in memory.
#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The network layer's log lines carry the session id (span `session`), so among many
/// parallel sessions a host error can be attributed to its session and audit records.
#[tokio::test]
async fn network_log_lines_carry_the_session() {
    let log = CapturedLog::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // A host that accepts and hangs up at once.
    let host = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = host.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = host.accept().await;
    });
    let cfg = config(port);
    let ext = Extensions::defaults(&cfg);
    let gw = Gateway::new(cfg, ext);
    let _ = gw
        .open_session(
            &SessionIdentity::anonymous(),
            "hercules",
            &bastion3270_server::gateway::SessionOptions::default(),
            None,
        )
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let line = text
        .lines()
        .find(|l| l.contains("bastion3270_net::session"))
        .unwrap_or_else(|| panic!("no network log line in:\n{text}"));
    assert!(
        line.contains("session{session=") && line.contains("profile=hercules"),
        "{line}"
    );
}
