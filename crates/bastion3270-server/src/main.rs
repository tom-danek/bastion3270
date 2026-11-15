//! `bastion3270-server` binary.
//!
//! Deliberately thin: load configuration, pick the default [`Extensions`], serve.
//! A custom binary looks the same, only with `.with_auth(...)` etc.
//!
//! ```text
//! bastion3270-server [--config PATH]      serve (default /etc/bastion3270/bastion3270-server.toml
//!                                      or $BASTION3270_SERVER_CONFIG)
//! bastion3270-server --check-config PATH  validate configuration and exit
//! bastion3270-server --generate-token     print a new random token and its SHA-256 for [[auth.tokens]]
//! bastion3270-server --hash-token         read a token on stdin, print its SHA-256 for [[auth.tokens]]
//! bastion3270-server --healthcheck ADDR   GET http://ADDR/healthz (container HEALTHCHECK, no curl needed)
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

use bastion3270_server::extensions::auth::{self, check_token_strength, encode_hex, sha256};
use bastion3270_server::{Extensions, Server, ServerConfig};
use tracing_subscriber::EnvFilter;

/// `println!` without its panic: a closed stdout (`... | head -1`) must not crash the binary.
macro_rules! out {
    ($($arg:tt)*) => {{
        let _ = writeln!(std::io::stdout(), $($arg)*);
    }};
}

/// `eprintln!` without its panic.
macro_rules! err_out {
    ($($arg:tt)*) => {{
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

const DEFAULT_CONFIG: &str = "/etc/bastion3270/bastion3270-server.toml";

const USAGE: &str = "\
bastion3270-server [--config PATH]      serve (default /etc/bastion3270/bastion3270-server.toml or $BASTION3270_SERVER_CONFIG)
bastion3270-server --check-config PATH  validate configuration and exit
bastion3270-server --generate-token     print a new random token and its SHA-256 for [[auth.tokens]]
bastion3270-server --hash-token         read a token on stdin, print its SHA-256 for [[auth.tokens]]
bastion3270-server --healthcheck ADDR   GET http://ADDR/healthz (container HEALTHCHECK)
bastion3270-server --version";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).map(String::as_str);

    match arg(0) {
        Some("--help" | "-h") => {
            out!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("--version" | "-V") => {
            out!("bastion3270-server {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--hash-token") => hash_token(),
        Some("--generate-token") => generate_token(),
        Some("--healthcheck") => healthcheck(arg(1).unwrap_or("127.0.0.1:8080")),
        Some("--check-config") => match load_config(arg(1)) {
            Ok(cfg) => {
                if let Some(tls) = &cfg.server.tls {
                    if let Err(e) = bastion3270_server::tls::acceptor(tls) {
                        err_out!("{e}");
                        return ExitCode::from(2);
                    }
                }
                if let Err(e) = cfg.host_tls.trust() {
                    err_out!("{e}");
                    return ExitCode::from(2);
                }
                out!(
                    "configuration OK: {} profile(s), auth = {:?}",
                    cfg.profiles.len(),
                    cfg.auth.mode
                );
                for warning in cfg.warnings() {
                    out!("warning: {warning}");
                }
                ExitCode::SUCCESS
            }
            Err(code) => code,
        },
        Some("--config") => run(arg(1)),
        None => run(None),
        Some(other) => {
            err_out!("unknown argument '{other}', see --help");
            ExitCode::from(2)
        }
    }
}

fn load_config(path: Option<&str>) -> Result<ServerConfig, ExitCode> {
    let path = path
        .map(str::to_owned)
        .or_else(|| std::env::var("BASTION3270_SERVER_CONFIG").ok())
        .unwrap_or_else(|| DEFAULT_CONFIG.to_owned());
    ServerConfig::from_toml_file(&path).map_err(|e| {
        err_out!("failed to load '{path}': {e}");
        ExitCode::from(2)
    })
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("BASTION3270_LOG_FORMAT").is_ok_and(|v| v == "json");
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}

fn run(config_path: Option<&str>) -> ExitCode {
    init_tracing();
    let config = match load_config(config_path) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("bastion3270-server")
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            err_out!("failed to start tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let extensions = Extensions::defaults(&config);
    match runtime.block_on(Server::new(config, extensions).serve(shutdown_signal())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(target: "bastion3270::server", error = %e, "server failed");
            ExitCode::FAILURE
        }
    }
}

/// Resolves on Ctrl+C or (on Unix) `SIGTERM` — what Kubernetes sends before killing a pod.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
}

fn hash_token() -> ExitCode {
    let mut input = zeroize::Zeroizing::new(String::new());
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return ExitCode::FAILURE;
    }
    let token = input.trim_end_matches(['\r', '\n']);
    if let Err(why) = check_token_strength(token) {
        err_out!("refused: {why}");
        return ExitCode::from(2);
    }
    out!("{}", encode_hex(&sha256(token.as_bytes())));
    ExitCode::SUCCESS
}

fn generate_token() -> ExitCode {
    let Some(token) = auth::generate_token() else {
        err_out!("the operating system random source failed");
        return ExitCode::FAILURE;
    };
    out!(
        "token  = {}   (give to the user once; not stored)",
        token.expose()
    );
    out!(
        "sha256 = \"{}\"   (for [[auth.tokens]])",
        encode_hex(&sha256(token.expose().as_bytes()))
    );
    ExitCode::SUCCESS
}

/// Minimal blocking HTTP/1.1 GET — the runtime image has no shell or curl.
fn healthcheck(addr: &str) -> ExitCode {
    let attempt = || -> std::io::Result<bool> {
        let sock = addr
            .parse()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad address"))?;
        let mut s = TcpStream::connect_timeout(&sock, Duration::from_secs(2))?;
        s.set_read_timeout(Some(Duration::from_secs(2)))?;
        write!(
            s,
            "GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
        )?;
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf)?;
        Ok(buf.get(..n).is_some_and(|b| b.starts_with(b"HTTP/1.1 200")))
    };
    match attempt() {
        Ok(true) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}
