//! Asynchronous network transport layer (Plain TCP, TLS 1.2/1.3, Timeouts, [`TransportStream`]).

pub mod certificate;
pub mod connector;
pub mod ecdsa;
pub mod stream;
pub mod tcp;
pub mod tls;
pub mod trust;

pub use certificate::{CertProblem, CertificateRejection, PeerCertificate};
pub use connector::{connect, connect_with_idle_timeout, connect_with_trust};
pub use stream::{TlsSessionInfo, TransportStream};
pub use tcp::{
    connect_tcp, connect_tcp_stream, read_with_idle_timeout, IdleTimeoutDetector, IdleTimeoutStream,
};
pub use tls::{
    connect_tls, connect_tls_handshake, connect_tls_with_trust, create_tls_client_config,
    load_ca_cert_store, load_ca_cert_store as load_root_certs, load_default_root_store,
    parse_server_name, read_ca_certs,
};
pub use trust::{HostTrust, TrustSummary};
