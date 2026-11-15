//! Connections the user defines in the browser (host, port, TLS) instead of choosing a
//! configured profile.
//!
//! The gateway decides, not the browser: every request is checked against
//! [`CustomConnectionsConfig`] (enabled, plain connections allowed, the optional allow-list of
//! targets) before anything connects. The session then runs like one of a configured profile,
//! with a profile built here (`custom:<host>:<port>`, so the audit names the target).
//!
//! Without an allow-list any host and port can be reached from the gateway's network position
//! (server-side request forgery); [`CustomConnectionsConfig::warning`] says so at startup, and in
//! Kubernetes the `NetworkPolicy` egress rules still limit the reachable targets.

use std::net::IpAddr;

use bastion3270_net::profile::{ConnectionProfile, TlsMode};
use serde::Deserialize;

use crate::config::{GatewayProfile, KeyboardPreset};

/// The profile id an identity's profile list must contain to use custom connections (when
/// the list is restricted at all).
pub const CUSTOM_PROFILE_ID: &str = "custom";

/// `[custom_connections]`: may users connect to targets of their own?
// The booleans are independent configuration switches (one TOML key each), not a state.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CustomConnectionsConfig {
    /// Offer "New connection" (default `true`).
    pub enabled: bool,
    /// Allow connections without TLS (default `true`).
    pub allow_plain: bool,
    /// Targets a user may connect to: `host`, `*.domain`, an IP address or CIDR range, or `*`,
    /// each optionally followed by `:port` or `:port,port` (`["10.20.0.0/16:23,992",
    /// "*.zos.example.com:992"]`). Absent: any target.
    pub allowed_targets: Option<Vec<String>>,
    /// Paste into custom sessions (default `true`).
    pub allow_paste: bool,
    /// Copy from custom sessions (default `true`).
    pub allow_copy: bool,
}

impl Default for CustomConnectionsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_plain: true,
            allowed_targets: None,
            allow_paste: true,
            allow_copy: true,
        }
    }
}

/// A target the browser asks for.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomTarget {
    /// Host name or IP address.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Connect with TLS (certificate verification is always on).
    pub tls: bool,
}

/// One parsed `allowed_targets` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetRule {
    host: HostRule,
    /// `None`: any port.
    ports: Option<Vec<u16>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostRule {
    Any,
    /// Exact name, lower case.
    Name(String),
    /// `*.suffix`: any name ending in `.suffix` (lower case, without the dot).
    Suffix(String),
    /// An address range (a single address is a /32 or /128).
    Net(IpAddr, u8),
}

/// `true` for a host name the gateway will try to resolve: letters, digits, `-` and `.`,
/// 1..=253 characters, labels of 1..=63; or an IP address.
fn is_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    (1..=253).contains(&host.len())
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn parse_rule(entry: &str) -> Option<TargetRule> {
    // IPv6 needs brackets when a port follows: "[fd00::/8]:992".
    let (host, ports) = if let Some(rest) = entry.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        (host, after.strip_prefix(':'))
    } else if entry.matches(':').count() > 1 {
        (entry, None) // a bare IPv6 address or range
    } else {
        match entry.split_once(':') {
            Some((host, ports)) => (host, Some(ports)),
            None => (entry, None),
        }
    };
    let ports = match ports {
        None | Some("*") => None,
        Some(list) => Some(
            list.split(',')
                .map(|p| p.trim().parse::<u16>().ok().filter(|p| *p != 0))
                .collect::<Option<Vec<u16>>>()?,
        ),
    };
    let host = host.trim();
    let host = if host == "*" {
        HostRule::Any
    } else if let Some(suffix) = host.strip_prefix("*.") {
        if !is_host(suffix) || suffix.parse::<IpAddr>().is_ok() {
            return None;
        }
        HostRule::Suffix(suffix.to_ascii_lowercase())
    } else if let Some((addr, bits)) = host.split_once('/') {
        let addr: IpAddr = addr.parse().ok()?;
        let bits: u8 = bits.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return None;
        }
        HostRule::Net(addr, bits)
    } else if let Ok(addr) = host.parse::<IpAddr>() {
        HostRule::Net(addr, if addr.is_ipv4() { 32 } else { 128 })
    } else if is_host(host) {
        HostRule::Name(host.to_ascii_lowercase())
    } else {
        return None;
    };
    Some(TargetRule { host, ports })
}

fn in_net(addr: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

impl TargetRule {
    /// Names are compared as typed (the gateway's DNS decides where they lead); address
    /// ranges match only a target given as an address.
    fn matches(&self, host: &str, port: u16) -> bool {
        if self
            .ports
            .as_ref()
            .is_some_and(|ports| !ports.contains(&port))
        {
            return false;
        }
        let host = host.to_ascii_lowercase();
        match &self.host {
            HostRule::Any => true,
            HostRule::Name(name) => *name == host,
            HostRule::Suffix(suffix) => host
                .strip_suffix(suffix.as_str())
                .is_some_and(|start| start.ends_with('.') && start.len() > 1),
            HostRule::Net(net, bits) => host.parse().is_ok_and(|a| in_net(a, *net, *bits)),
        }
    }
}

impl CustomConnectionsConfig {
    /// Checks the `allowed_targets` entries.
    ///
    /// # Errors
    /// The first entry that is not a valid target rule.
    pub fn validate(&self) -> Result<(), String> {
        for entry in self.allowed_targets.iter().flatten() {
            if parse_rule(entry).is_none() {
                return Err(format!(
                    "custom_connections.allowed_targets: '{entry}' is not a host, *.domain, IP \
                     address / range or *, optionally with :port[,port]"
                ));
            }
        }
        Ok(())
    }

    /// The startup warning while custom connections reach any target.
    #[must_use]
    pub fn warning(&self) -> Option<String> {
        (self.enabled && self.allowed_targets.is_none()).then(|| {
            "custom_connections: users may connect to any host and port from the gateway's \
             network position; restrict with allowed_targets or set enabled = false"
                .to_owned()
        })
    }

    /// Checks a requested target against this policy and builds the profile its session runs
    /// with.
    ///
    /// # Errors
    /// A description for the user when the target is not allowed or not valid.
    pub fn profile_for(&self, target: &CustomTarget) -> Result<GatewayProfile, String> {
        if !self.enabled {
            return Err("this gateway does not allow connections of your own".to_owned());
        }
        let host = target.host.trim();
        if !is_host(host) {
            return Err("the host must be a host name or an IP address".to_owned());
        }
        if target.port == 0 {
            return Err("the port must be between 1 and 65535".to_owned());
        }
        if !target.tls && !self.allow_plain {
            return Err("this gateway allows only connections with TLS".to_owned());
        }
        if let Some(entries) = &self.allowed_targets {
            let allowed = entries
                .iter()
                .filter_map(|e| parse_rule(e))
                .any(|rule| rule.matches(host, target.port));
            if !allowed {
                return Err(format!(
                    "{host}:{} is not among the targets this gateway allows",
                    target.port
                ));
            }
        }
        Ok(GatewayProfile {
            id: format!("{CUSTOM_PROFILE_ID}:{host}:{}", target.port),
            name: format!("{host}:{}", target.port),
            description: String::new(),
            allow_paste: self.allow_paste,
            allow_copy: self.allow_copy,
            keyboard: KeyboardPreset::default(),
            allowed_lu_names: None,
            custom: true,
            connection: ConnectionProfile {
                host: host.to_owned(),
                port: target.port,
                tls_mode: if target.tls {
                    TlsMode::Enabled
                } else {
                    TlsMode::Disabled
                },
                ..ConnectionProfile::default()
            },
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn target(host: &str, port: u16, tls: bool) -> CustomTarget {
        CustomTarget {
            host: host.to_owned(),
            port,
            tls,
        }
    }

    fn policy(targets: &[&str]) -> CustomConnectionsConfig {
        CustomConnectionsConfig {
            allowed_targets: Some(targets.iter().map(|t| (*t).to_owned()).collect()),
            ..CustomConnectionsConfig::default()
        }
    }

    #[test]
    fn by_default_any_valid_target_is_allowed_with_a_warning() {
        let cfg = CustomConnectionsConfig::default();
        assert!(cfg.warning().is_some());
        let p = cfg
            .profile_for(&target("zos.example.com", 992, true))
            .unwrap();
        assert_eq!(p.id, "custom:zos.example.com:992");
        assert!(p.custom);
        assert_eq!(p.connection.tls_mode, TlsMode::Enabled);
        assert!(cfg.profile_for(&target("10.1.2.3", 23, false)).is_ok());
        for bad in ["", "host name", "evil.com/path", "a..b", "-x.com", "x:23"] {
            assert!(cfg.profile_for(&target(bad, 23, true)).is_err(), "{bad:?}");
        }
        assert!(cfg.profile_for(&target("host", 0, true)).is_err());
    }

    #[test]
    fn the_administrator_can_disable_restrict_and_require_tls() {
        let off = CustomConnectionsConfig {
            enabled: false,
            ..CustomConnectionsConfig::default()
        };
        assert!(off.warning().is_none());
        assert!(off.profile_for(&target("zos", 992, true)).is_err());

        let tls_only = CustomConnectionsConfig {
            allow_plain: false,
            ..CustomConnectionsConfig::default()
        };
        assert!(tls_only.profile_for(&target("zos", 23, false)).is_err());
        assert!(tls_only.profile_for(&target("zos", 992, true)).is_ok());

        let cfg = policy(&[
            "10.20.0.0/16:23,992",
            "*.zos.example.com:992",
            "lab",
            "[fd00::/8]",
        ]);
        assert!(cfg.validate().is_ok());
        assert!(cfg.warning().is_none());
        let ok = |h: &str, p: u16| cfg.profile_for(&target(h, p, true)).is_ok();
        assert!(ok("10.20.3.4", 992) && ok("10.20.3.4", 23));
        assert!(!ok("10.20.3.4", 3270) && !ok("10.21.0.1", 992));
        assert!(ok("lpar1.zos.example.com", 992) && ok("LPAR1.ZOS.example.com", 992));
        assert!(!ok("zos.example.com", 992) && !ok("evilzos.example.com", 992));
        assert!(ok("lab", 3270) && !ok("lab2", 3270));
        assert!(ok("fd00::5", 23) && !ok("fe80::1", 23));
        // Names do not match address ranges and the other way round.
        assert!(!ok("ten.twenty", 992));
    }

    #[test]
    fn invalid_rules_are_refused() {
        for bad in [
            "",
            "10.0.0.0/33",
            "*.10.0.0.1",
            "host:0",
            "host:abc",
            "bad host",
            "a:1:2",
        ] {
            assert!(policy(&[bad]).validate().is_err(), "{bad:?}");
        }
        for good in [
            "*",
            "*:992",
            "host",
            "10.0.0.1",
            "[::1]:23",
            "::1",
            "*.example.com",
        ] {
            assert!(policy(&[good]).validate().is_ok(), "{good:?}");
        }
    }
}
