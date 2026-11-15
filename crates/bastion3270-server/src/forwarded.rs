//! The browser's address and scheme behind a reverse proxy (ingress).
//!
//! Behind an ingress every connection comes from the ingress, so the audit trail would only
//! show its address, and the gateway cannot tell whether the browser used `https`. Proxies
//! report both in `X-Forwarded-For` / `X-Forwarded-Proto`, but anybody can send those headers:
//! they are believed only from the addresses listed in `server.trusted_proxies`.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use axum::http::HeaderMap;

/// An address range, `10.0.0.0/8` or `fd00::/8` (a bare address is a single host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = s.split_once('/').unwrap_or((s, ""));
        let net: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| format!("'{s}' is not an address range (e.g. 10.0.0.0/8)"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = if prefix.is_empty() {
            max
        } else {
            prefix
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("'{s}': prefix length must be 0..={max}"))?
        };
        Ok(Self { net, prefix })
    }
}

impl Cidr {
    /// `true` if `ip` lies in the range. An IPv4-mapped IPv6 address counts as IPv4.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 @ IpAddr::V4(_) => v4,
        };
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// What the gateway knows about the browser side of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientView {
    /// The browser's address (from a trusted proxy's `X-Forwarded-For`, port 0), else the TCP
    /// peer.
    pub addr: Option<SocketAddr>,
    /// `https` / `http` as the browser used it, if known: from a trusted proxy's
    /// `X-Forwarded-Proto`, or `https` on the gateway's own TLS listener.
    pub scheme: Option<&'static str>,
}

/// Works out the browser's address and scheme. Forwarded headers count only when the TCP peer
/// is a trusted proxy; the client is the rightmost `X-Forwarded-For` entry that is not itself
/// a trusted proxy (entries to its left are whatever the client claimed).
///
/// `X-Forwarded-Proto` has no per-hop addresses, so its last value is used: the trusted proxy
/// must set it (overwrite or append), as ingress controllers do. A value passed through from
/// the client could only make the same-origin check stricter, never weaker: the `Origin`
/// authority must still be the gateway's own.
#[must_use]
pub fn client_view(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted: &[Cidr],
    tls_listener: bool,
) -> ClientView {
    let own_scheme = tls_listener.then_some("https");
    let from_proxy = peer.is_some_and(|p| trusted.iter().any(|c| c.contains(p.ip())));
    if !from_proxy {
        return ClientView {
            addr: peer,
            scheme: own_scheme,
        };
    }
    let header = |name: &str| {
        headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .collect::<Vec<_>>()
    };
    let forwarded_for = header("x-forwarded-for");
    let client_ip = forwarded_for
        .iter()
        .rev()
        .filter_map(|entry| entry.parse::<IpAddr>().ok())
        .find(|ip| !trusted.iter().any(|c| c.contains(*ip)));
    let scheme = match header("x-forwarded-proto").last().copied() {
        Some(p) if p.eq_ignore_ascii_case("https") => Some("https"),
        Some(p) if p.eq_ignore_ascii_case("http") => Some("http"),
        _ => own_scheme,
    };
    ClientView {
        addr: client_ip.map(|ip| SocketAddr::new(ip, 0)).or(peer),
        scheme,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn cidrs(list: &[&str]) -> Vec<Cidr> {
        list.iter().map(|c| c.parse().unwrap()).collect()
    }

    #[test]
    fn test_cidr_parsing_and_matching() {
        let net: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(net.contains("10.20.30.40".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        assert!(
            net.contains("::ffff:10.1.1.1".parse().unwrap()),
            "IPv4-mapped"
        );
        let host: Cidr = "192.0.2.7".parse().unwrap();
        assert!(host.contains("192.0.2.7".parse().unwrap()));
        assert!(!host.contains("192.0.2.8".parse().unwrap()));
        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("203.0.113.1".parse().unwrap()));
        let v6: Cidr = "fd00::/8".parse().unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        for bad in ["10.0.0.0/33", "fd00::/129", "nonsense", "10.0.0.0/x"] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
    }

    fn headers(xff: &str, proto: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(xff).unwrap());
        h.insert("x-forwarded-proto", HeaderValue::from_str(proto).unwrap());
        h
    }

    #[test]
    fn test_forwarded_headers_count_only_from_trusted_proxies() {
        let ingress: SocketAddr = "10.1.0.5:44321".parse().unwrap();
        let trusted = cidrs(&["10.1.0.0/16"]);
        // A spoofed entry on the left is ignored: the proxy appends what it saw.
        let h = headers("6.6.6.6, 203.0.113.9", "https");
        let v = client_view(Some(ingress), &h, &trusted, false);
        assert_eq!(v.addr, Some("203.0.113.9:0".parse().unwrap()));
        assert_eq!(v.scheme, Some("https"));

        // Chained trusted proxies are skipped.
        let h = headers("203.0.113.9, 10.1.0.7", "http");
        let v = client_view(Some(ingress), &h, &trusted, false);
        assert_eq!(v.addr, Some("203.0.113.9:0".parse().unwrap()));
        assert_eq!(v.scheme, Some("http"));

        // From anybody else the headers are ignored.
        let stranger: SocketAddr = "198.51.100.1:5000".parse().unwrap();
        let v = client_view(Some(stranger), &h, &trusted, false);
        assert_eq!(v.addr, Some(stranger));
        assert_eq!(v.scheme, None);
        let v = client_view(Some(stranger), &h, &trusted, true);
        assert_eq!(v.scheme, Some("https"), "own TLS listener");
    }
}
