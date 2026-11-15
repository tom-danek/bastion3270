//! `bastion3270-loadgen` — load and soak tests of the gateway.
//!
//! ```text
//! # 1. simulated hosts (one listener serves any number of sessions)
//! bastion3270-loadgen host --listen 127.0.0.1:3270 --delay-ms 20
//! # 2. a gateway configuration for the test, then start the gateway (release build) with it
//! bastion3270-loadgen config --host 127.0.0.1:3270 --sessions 2000 > /tmp/load.toml
//! bastion3270-server --config /tmp/load.toml &
//! # 3. the load: ramp up, keep busy, report (and sample the gateway process)
//! bastion3270-loadgen run --gateway 127.0.0.1:8080 --sessions 2000 --ramp-s 60 \
//!     --duration-s 300 --think-ms 2000 --gateway-pid $!
//! ```
//! A soak test is a `run` with a long `--duration-s`; the samples show the memory trend. The
//! gateway ends sessions after `limits.max_session_lifetime_secs` (12 h by default): with
//! `--reopen` an ended session is opened again, so the run can be longer.
//!
//! The production path with TLS on both sides (host connection and the gateway's listener):
//! ```text
//! bastion3270-loadgen certs --out /tmp/pki
//! bastion3270-loadgen host --listen 127.0.0.1:3270 --tls-cert /tmp/pki/server.pem \
//!     --tls-key /tmp/pki/server.key
//! bastion3270-loadgen config --host 127.0.0.1:3270 --sessions 2000 --host-ca /tmp/pki/ca.pem \
//!     --listener-cert /tmp/pki/server.pem --listener-key /tmp/pki/server.key > /tmp/load.toml
//! bastion3270-loadgen run --gateway 127.0.0.1:8080 --sessions 2000 --tls-ca /tmp/pki/ca.pem
//! ```

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bastion3270_loadgen::{host, proc, run, tls, GatewayTls, LoadConfig};

const USAGE: &str = "\
bastion3270-loadgen certs  --out DIR
bastion3270-loadgen host   --listen ADDR [--delay-ms N] [--tls-cert FILE --tls-key FILE]
bastion3270-loadgen config --host ADDR --sessions N [--bind ADDR] [--metrics ADDR]
                           [--host-ca FILE] [--listener-cert FILE --listener-key FILE]
bastion3270-loadgen run    --gateway ADDR --sessions N [--ramp-s N] [--duration-s N]
                           [--think-ms N] [--sample-s N] [--gateway-pid PID] [--profile ID]
                           [--tls-ca FILE] [--reopen]";

/// The command line: `--name value` pairs after the subcommand.
struct Args(Vec<String>);

impl Args {
    fn flag(&self, name: &str) -> Option<String> {
        self.0
            .iter()
            .position(|a| a == name)
            .and_then(|i| self.0.get(i.saturating_add(1)))
            .cloned()
    }

    fn num(&self, name: &str, default: u64) -> u64 {
        self.flag(name)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// A switch without a value.
    fn has(&self, name: &str) -> bool {
        self.0.iter().any(|a| a == name)
    }

    fn addr(&self, name: &str) -> Option<SocketAddr> {
        self.flag(name).and_then(|v| v.parse().ok())
    }

    fn path(&self, name: &str) -> Option<PathBuf> {
        self.flag(name).map(PathBuf::from)
    }
}

fn main() -> ExitCode {
    let args = Args(std::env::args().skip(1).collect());
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        return ExitCode::FAILURE;
    };
    match args.0.first().map(String::as_str) {
        Some("certs") => certs(&args),
        Some("host") => runtime.block_on(hosts(&args)),
        Some("config") => config(&args),
        Some("run") => runtime.block_on(load_command(&args)),
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    println!("{USAGE}");
    ExitCode::from(2)
}

/// `certs`: a throw-away CA and server certificate for TLS runs.
fn certs(args: &Args) -> ExitCode {
    let Some(out) = args.path("--out") else {
        return usage();
    };
    match tls::write_test_pki(&out) {
        Ok(()) => {
            eprintln!(
                "test CA and server certificate for 127.0.0.1 in {}",
                out.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("certs: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `host`: simulated hosts until Ctrl+C.
async fn hosts(args: &Args) -> ExitCode {
    let Some(listen) = args.addr("--listen") else {
        return usage();
    };
    let delay = Duration::from_millis(args.num("--delay-ms", 20));
    let acceptor = match (args.path("--tls-cert"), args.path("--tls-key")) {
        (Some(cert), Some(key)) => match tls::acceptor(&cert, &key) {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("host TLS: {e}");
                return ExitCode::FAILURE;
            }
        },
        (None, None) => None,
        _ => return usage(),
    };
    let stats = Arc::new(host::HostStats::default());
    match host::spawn(listen, delay, Arc::clone(&stats), acceptor).await {
        Ok(bound) => eprintln!("simulated hosts on {bound}"),
        Err(e) => {
            eprintln!("bind {listen}: {e}");
            return ExitCode::FAILURE;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
    ExitCode::SUCCESS
}

/// `config`: a gateway configuration for the test on stdout.
fn config(args: &Args) -> ExitCode {
    let (Some(host), Some(sessions)) = (args.addr("--host"), args.flag("--sessions")) else {
        return usage();
    };
    let bind = args
        .addr("--bind")
        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 8080)));
    let metrics = args
        .addr("--metrics")
        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 9090)));
    let host_ca = args.path("--host-ca");
    let (cert, key) = (args.path("--listener-cert"), args.path("--listener-key"));
    if cert.is_some() != key.is_some() {
        return usage();
    }
    let tls = GatewayTls {
        host_ca: host_ca.as_deref(),
        listener: cert.as_deref().zip(key.as_deref()),
    };
    println!(
        "{}",
        bastion3270_loadgen::gateway_config(
            host,
            sessions.parse().unwrap_or(1000),
            bind,
            metrics,
            tls
        )
    );
    ExitCode::SUCCESS
}

/// `run`: parses the options, then [`load`].
async fn load_command(args: &Args) -> ExitCode {
    let Some(gateway) = args.addr("--gateway") else {
        return usage();
    };
    let tls = match args.path("--tls-ca").map(|ca| tls::client_config(&ca)) {
        None => None,
        Some(Ok(c)) => Some(c),
        Some(Err(e)) => {
            eprintln!("browser TLS: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cfg = LoadConfig {
        gateway,
        profile: args.flag("--profile").unwrap_or_else(|| "load".to_owned()),
        sessions: usize::try_from(args.num("--sessions", 100)).unwrap_or(100),
        ramp: Duration::from_secs(args.num("--ramp-s", 30)),
        duration: Duration::from_secs(args.num("--duration-s", 60)),
        think: Duration::from_millis(args.num("--think-ms", 2000)),
        reopen: args.has("--reopen"),
        tls,
    };
    let pid = args
        .flag("--gateway-pid")
        .and_then(|p| p.parse::<u32>().ok());
    let every = Duration::from_secs(args.num("--sample-s", 10));
    load(cfg, pid, every).await
}

/// The `run` command: load, progress lines, final report (and the gateway's memory).
async fn load(cfg: LoadConfig, pid: Option<u32>, every: Duration) -> ExitCode {
    check_open_files(cfg.sessions);
    let reopen = cfg.reopen;
    let idle = pid.and_then(proc::sample);
    let mut last = pid.and_then(proc::sample).map(|s| (Instant::now(), s));
    let report = run(cfg, every, |r| {
        let mut line = r.to_string();
        if let Some(now) = pid.and_then(proc::sample) {
            let now = (Instant::now(), now);
            let cores = last.map_or(0.0, |l| proc::cpu_cores(l, now));
            let _ = write!(
                line,
                " | gateway rss={}MiB fds={} cpu={cores:.2} cores",
                now.1.rss_kib / 1024,
                now.1.fds
            );
            last = Some(now);
        }
        println!("{line}");
    })
    .await;
    println!("final: {report}");
    if let (Some(idle), Some(end)) = (idle, last) {
        let per_session = end
            .1
            .rss_kib
            .saturating_sub(idle.rss_kib)
            .checked_div(report.opened.max(1))
            .unwrap_or(0);
        println!(
            "gateway rss idle={}MiB end={}MiB (~{per_session} KiB per session, at the last sample)",
            idle.rss_kib / 1024,
            end.1.rss_kib / 1024
        );
    }
    // A session the gateway ended is expected only when the run reopens ended sessions.
    if report.failed.values().sum::<u64>() > 0 || (!reopen && !report.ended.is_empty()) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Every session needs two sockets in this process (browser) or one each in host and browser.
fn check_open_files(sessions: usize) {
    if let Some(limit) = proc::open_files_limit() {
        let needed = u64::try_from(sessions)
            .unwrap_or(u64::MAX)
            .saturating_mul(2)
            .saturating_add(64);
        if limit < needed {
            eprintln!(
                "warning: open files limit {limit} < {needed} needed for {sessions} sessions \
                 (raise it with `ulimit -n {needed}` in this shell and the gateway's)"
            );
        }
    }
}
