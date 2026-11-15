//! The gateway's own TLS listener (`[server.tls]`): HTTPS, optionally with client
//! certificates (mutual TLS) for the hop from an ingress to the pod.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bastion3270_server::{Extensions, Server, ServerConfig};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

/// A CA, a server certificate for 127.0.0.1 and a client certificate, all as PEM files in a
/// fresh directory.
struct Pki {
    dir: PathBuf,
    ca_der: CertificateDer<'static>,
    client_cert: CertificateDer<'static>,
    client_key: PrivateKeyDer<'static>,
}

impl Pki {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("bastion3270-tls-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let srv_key = KeyPair::generate().unwrap();
        let srv = CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .signed_by(&srv_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .unwrap();
        let cli_key = KeyPair::generate().unwrap();
        let cli = CertificateParams::new(vec!["ingress".into()])
            .unwrap()
            .signed_by(&cli_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .unwrap();

        std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
        std::fs::write(dir.join("server.pem"), srv.pem()).unwrap();
        std::fs::write(dir.join("server.key"), srv_key.serialize_pem()).unwrap();
        Self {
            dir,
            ca_der: ca.der().clone(),
            client_cert: cli.der().clone(),
            client_key: PrivateKeyDer::try_from(cli_key.serialize_der()).unwrap(),
        }
    }

    fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }
}

fn config(tls: &str) -> ServerConfig {
    ServerConfig::from_toml_str(&format!(
        r#"
        [server.tls]
        {tls}

        [[profiles]]
        id = "lab"
        name = "Lab"
        [profiles.connection]
        tls_mode = "disabled"
        host = "127.0.0.1"
        port = 3270
        "#
    ))
    .unwrap()
}

fn toml_path(p: &Path) -> String {
    format!("{:?}", p.display().to_string())
}

/// Starts the gateway on an ephemeral port; returns its address and the serving task.
async fn start(
    cfg: ServerConfig,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<bastion3270_server::Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ext = Extensions::defaults(&cfg);
    let join =
        tokio::spawn(Server::new(cfg, ext).serve_with_listener(listener, std::future::pending()));
    (addr, join)
}

/// GET /healthz over TLS; `Err` if the handshake or the request fails.
async fn get_healthz(addr: std::net::SocketAddr, client: ClientConfig) -> Result<String, String> {
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let name = ServerName::try_from("127.0.0.1").unwrap();
    let mut tls = TlsConnector::from(Arc::new(client))
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    tls.write_all(b"GET /healthz HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| e.to_string())?;
    let mut out = String::new();
    tls.read_to_string(&mut out)
        .await
        .map_err(|e| e.to_string())?;
    Ok(out)
}

fn client(pki: &Pki, with_cert: bool) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca_der.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    if with_cert {
        builder
            .with_client_auth_cert(vec![pki.client_cert.clone()], pki.client_key.clone_key())
            .unwrap()
    } else {
        builder.with_no_client_auth()
    }
}

#[tokio::test]
async fn https_is_served_and_plain_http_is_not() {
    let pki = Pki::new("https");
    let (addr, _join) = start(config(&format!(
        "cert = {}\nkey = {}",
        toml_path(&pki.path("server.pem")),
        toml_path(&pki.path("server.key"))
    )))
    .await;

    let reply = get_healthz(addr, client(&pki, false)).await.unwrap();
    assert!(
        reply.starts_with("HTTP/1.1 200") && reply.contains(r#"{"status":"ok"}"#),
        "{reply}"
    );

    // Plain HTTP on the TLS port gets no HTTP answer.
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"GET /healthz HTTP/1.1\r\nHost: gw\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), tcp.read_to_end(&mut buf)).await;
    assert!(
        !String::from_utf8_lossy(&buf).contains("200"),
        "plain HTTP must not be served"
    );
}

#[tokio::test]
async fn with_a_client_ca_only_clients_with_a_certificate_are_served() {
    let pki = Pki::new("mtls");
    let (addr, _join) = start(config(&format!(
        "cert = {}\nkey = {}\nclient_ca = {}",
        toml_path(&pki.path("server.pem")),
        toml_path(&pki.path("server.key")),
        toml_path(&pki.path("ca.pem"))
    )))
    .await;

    assert!(
        get_healthz(addr, client(&pki, false)).await.is_err(),
        "no client certificate"
    );
    let reply = get_healthz(addr, client(&pki, true)).await.unwrap();
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
}

#[tokio::test]
async fn invalid_certificate_files_stop_the_start() {
    let pki = Pki::new("bad");
    std::fs::write(pki.path("broken.key"), "not a key").unwrap();
    let (_, join) = start(config(&format!(
        "cert = {}\nkey = {}",
        toml_path(&pki.path("server.pem")),
        toml_path(&pki.path("broken.key"))
    )))
    .await;
    let err = tokio::time::timeout(Duration::from_secs(5), join)
        .await
        .expect("the start must fail, not hang")
        .unwrap()
        .expect_err("a broken key must stop the start");
    assert!(err.to_string().contains("broken.key"), "{err}");
}
