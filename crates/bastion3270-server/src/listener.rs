//! HTTP/1 accept loop with connection-level limits.
//!
//! `axum::serve` builds its hyper connection without a timer, and hyper then silently disables
//! its header read timeout. A client could open many connections and send a header byte now
//! and then (slow-loris) or keep idle keep-alive connections open, exhausting file descriptors
//! and tasks for every user of the pod. This loop serves the same router, but each connection
//! * has a timer, so a request head (and the wait for the next one on a keep-alive connection)
//!   must arrive within `header_read_timeout_secs`;
//! * holds one of `max_connections` permits until it ends or becomes a WebSocket; a
//!   connection beyond the limit is closed right after accept.
//!
//! With `[server.tls]`, every connection first completes a TLS handshake (bounded by the same
//! timeout); then the same HTTP/1 handling applies.
//!
//! Upgraded WebSocket connections are bounded elsewhere: by the handshake places
//! (`max_pending_handshakes`) and by `max_sessions`.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::Router;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt as _;

/// How long open HTTP connections get to finish after shutdown was requested.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Serves `router` on `listener` until `shutdown` completes, then lets open connections
/// finish (bounded by [`DRAIN_TIMEOUT`]).
pub(crate) async fn serve<F>(
    listener: TcpListener,
    router: Router,
    max_connections: usize,
    header_read_timeout: Duration,
    tls: Option<TlsAcceptor>,
    on_limit: impl Fn() + Send,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let permits = Arc::new(Semaphore::new(max_connections));
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        let (tcp, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                // Per-connection errors (e.g. the peer reset before accept) and descriptor
                // exhaustion must not stop the listener.
                Err(err) => {
                    tracing::warn!(target: "bastion3270::server", %err, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        configure(&tcp);
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            tracing::warn!(
                target: "bastion3270::server",
                max_connections,
                "connection limit reached; closing a new connection"
            );
            on_limit();
            drop(tcp);
            continue;
        };
        let conn = Connection {
            router: router.clone(),
            peer,
            header_read_timeout,
            stop: stop_rx.clone(),
        };
        let tls = tls.clone();
        tokio::spawn(async move {
            match tls {
                None => conn.serve(tcp).await,
                // The TLS handshake is bounded like a request head: a client that opens the
                // connection and never finishes the handshake is dropped.
                Some(acceptor) => {
                    if let Ok(Ok(stream)) =
                        tokio::time::timeout(header_read_timeout, acceptor.accept(tcp)).await
                    {
                        conn.serve(stream).await;
                    }
                }
            }
            drop(permit);
        });
    }

    // Stop accepting, ask every connection to finish, wait until all permits are back.
    let _ = stop_tx.send(true);
    let all = u32::try_from(max_connections).unwrap_or(u32::MAX);
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, permits.acquire_many(all)).await;
    Ok(())
}

/// One accepted connection (plain TCP or after the TLS handshake).
struct Connection {
    router: Router,
    peer: SocketAddr,
    header_read_timeout: Duration,
    stop: watch::Receiver<bool>,
}

impl Connection {
    async fn serve<I>(mut self, io: I)
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (router, peer) = (self.router, self.peer);
        let service = service_fn(move |mut req: Request<Incoming>| {
            req.extensions_mut().insert(ConnectInfo(peer));
            router.clone().oneshot(req)
        });
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(self.header_read_timeout)
            .serve_connection(TokioIo::new(io), service)
            .with_upgrades();
        let mut conn = std::pin::pin!(conn);
        tokio::select! {
            _ = conn.as_mut() => {}
            // The `watch::Ref` must not live across the await below (it is a lock guard).
            () = async { drop(self.stop.wait_for(|stop| *stop).await) } => {
                conn.as_mut().graceful_shutdown();
                let _ = conn.await;
            }
        }
    }
}

/// Socket options of an accepted connection. Interactive traffic: a frame must not wait for
/// the ACK of the previous one (Nagle's algorithm with delayed ACKs added up to 40 ms to a
/// share of the frames under load).
fn configure(tcp: &tokio::net::TcpStream) {
    if let Err(err) = tcp.set_nodelay(true) {
        tracing::debug!(target: "bastion3270::server", %err, "TCP_NODELAY not set");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[tokio::test]
    async fn test_accepted_connections_disable_nagle() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        assert!(
            !server.nodelay().unwrap(),
            "the default would delay small frames"
        );
        super::configure(&server);
        assert!(server.nodelay().unwrap());
    }
}
