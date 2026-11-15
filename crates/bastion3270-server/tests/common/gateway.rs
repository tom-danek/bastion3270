//! Runs the real gateway (`Server`) in-process on an ephemeral `127.0.0.1` port.

use std::net::SocketAddr;

use std::sync::Arc;

use bastion3270_server::{Extensions, Gateway, Server, ServerConfig};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// A running gateway: its address, the shutdown trigger and the serving task.
pub struct Running {
    pub addr: SocketAddr,
    pub shutdown: Option<oneshot::Sender<()>>,
    /// The running session manager (what a custom binary gets from `Server::gateway`).
    pub gateway: Arc<Gateway>,
    pub join: tokio::task::JoinHandle<bastion3270_server::Result<()>>,
}

/// Starts the gateway with `cfg` and the default extensions, adjusted by `customize`.
pub async fn start(cfg: ServerConfig, customize: impl FnOnce(Extensions) -> Extensions) -> Running {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ext = customize(Extensions::defaults(&cfg));
    let (tx, rx) = oneshot::channel::<()>();
    let server = Server::new(cfg, ext);
    let gateway = server.gateway();
    let join = tokio::spawn(server.serve_with_listener(listener, async move {
        let _ = rx.await;
    }));
    Running {
        addr,
        shutdown: Some(tx),
        gateway,
        join,
    }
}
