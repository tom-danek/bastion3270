//! Why a host's certificate was refused, and what the certificate says.
//!
//! A refused certificate becomes [`NetError::UntrustedCertificate`](crate::error::NetError)
//! with a [`CertificateRejection`]: the reason ([`CertProblem`]) and the certificate's details
//! ([`PeerCertificate`]: subject, issuer, validity, names, SHA-256). The desktop client shows
//! them so the user can ask for the right CA or trust the certificate; the gateway writes them
//! to its audit record. A certificate carries no secret, so the details may be logged.
//!
//! The module also holds the common-name check of x3270 (`sio_openssl.c`, `check_cert_name`)
//! for host certificates without a subject alternative name.

use core::fmt;
use std::net::IpAddr;

use rustls::CertificateError;
use rustls_pki_types::ServerName;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;

/// What was wrong with the host's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertProblem {
    /// The chain does not lead to a trusted CA (an internal CA that is not trusted, a
    /// self-signed certificate, an intermediate the host did not send, or a CA with the
    /// name of a trusted one but another key).
    UnknownIssuer,
    /// The certificate is not issued for the name that was checked.
    NameMismatch {
        /// The name the certificate had to match (`accept_hostname` or the host).
        expected: String,
    },
    /// The certificate (or one in its chain) has expired.
    Expired,
    /// The certificate (or one in its chain) is not valid yet.
    NotYetValid,
    /// Signed with an algorithm that is not accepted any more (e.g. SHA-1).
    UnsupportedAlgorithm,
    /// Any other reason, in the words of the TLS library.
    Other(String),
}

impl CertProblem {
    /// Classifies a certificate error of the TLS library; `expected` is the checked name.
    #[must_use]
    pub fn from_tls_error(error: &rustls::Error, expected: &ServerName<'_>) -> Self {
        let rustls::Error::InvalidCertificate(cert_error) = error else {
            return Self::Other(error.to_string());
        };
        match cert_error {
            // A bad signature on a chain to a trusted name: a CA of that name signed it, but not
            // the trusted one (e.g. a CA generated again under the same name).
            CertificateError::UnknownIssuer | CertificateError::BadSignature => Self::UnknownIssuer,
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                Self::NameMismatch {
                    expected: expected.to_str().into_owned(),
                }
            }
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => Self::Expired,
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                Self::NotYetValid
            }
            CertificateError::UnsupportedSignatureAlgorithmContext { .. }
            | CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
                Self::UnsupportedAlgorithm
            }
            other => Self::Other(other.to_string()),
        }
    }

    /// What the user or the administrator can do about it.
    #[must_use]
    pub const fn hint(&self) -> &'static str {
        match self {
            Self::UnknownIssuer => {
                "trust the issuing CA: install it in the system's certificate store or set \
                 ca_cert (add a missing intermediate the same way)"
            }
            Self::NameMismatch { .. } => {
                "connect by a name the certificate lists, or set accept_hostname to one of them"
            }
            Self::Expired | Self::NotYetValid => {
                "check the clock of this computer; otherwise the host needs a valid certificate"
            }
            Self::UnsupportedAlgorithm => {
                "the host needs a certificate signed with SHA-256 or stronger"
            }
            Self::Other(_) => "the host needs a valid certificate",
        }
    }
}

impl fmt::Display for CertProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownIssuer => {
                f.write_str("issued by a certificate authority that is not trusted")
            }
            Self::NameMismatch { expected } => write!(f, "not issued for '{expected}'"),
            Self::Expired => f.write_str("expired"),
            Self::NotYetValid => f.write_str("not valid yet"),
            Self::UnsupportedAlgorithm => {
                f.write_str("signed with an algorithm no longer accepted")
            }
            Self::Other(text) => f.write_str(text),
        }
    }
}

/// The details of a host certificate, for the user and the audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCertificate {
    /// Subject distinguished name (`CN=…, O=…`).
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Start of the validity period.
    pub not_before: String,
    /// End of the validity period.
    pub not_after: String,
    /// Subject alternative names (`DNS:…`, `IP:…`).
    pub names: Vec<String>,
    /// SHA-256 of the DER encoding: what a desktop profile pins (`pinned_cert_sha256`).
    pub sha256: [u8; 32],
}

impl PeerCertificate {
    /// Reads the details of a DER certificate. A certificate that cannot be parsed still has a
    /// fingerprint; its other fields say so.
    #[must_use]
    pub fn from_der(der: &[u8]) -> Self {
        let sha256 = sha256(der);
        let Ok((_, cert)) = X509Certificate::from_der(der) else {
            let unreadable = "(unreadable)".to_owned();
            return Self {
                subject: unreadable.clone(),
                issuer: unreadable.clone(),
                not_before: unreadable.clone(),
                not_after: unreadable,
                names: Vec::new(),
                sha256,
            };
        };
        let names = match cert.subject_alternative_name() {
            Ok(Some(san)) => san
                .value
                .general_names
                .iter()
                .filter_map(general_name_text)
                .collect(),
            _ => Vec::new(),
        };
        Self {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            not_before: cert.validity().not_before.to_string(),
            not_after: cert.validity().not_after.to_string(),
            names,
            sha256,
        }
    }

    /// The fingerprint as 64 lowercase hex digits, the form of `pinned_cert_sha256`.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        hex(&self.sha256)
    }
}

impl fmt::Display for PeerCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "subject '{}', issuer '{}', valid {} to {}",
            self.subject, self.issuer, self.not_before, self.not_after
        )?;
        if !self.names.is_empty() {
            write!(f, ", names {}", self.names.join(" "))?;
        }
        write!(f, ", SHA-256 {}", self.sha256_hex())
    }
}

/// A refused host certificate: why, and what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRejection {
    /// The reason.
    pub problem: CertProblem,
    /// The host's (end-entity) certificate.
    pub certificate: PeerCertificate,
}

impl fmt::Display for CertificateRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the host's certificate is {} ({}); {}",
            self.problem,
            self.certificate,
            self.problem.hint()
        )
    }
}

/// SHA-256 of `der`.
#[must_use]
pub fn sha256(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// Parses a fingerprint of 64 hex digits (either case); `None` for anything else.
#[must_use]
pub fn parse_sha256_hex(text: &str) -> Option<[u8; 32]> {
    // `from_str_radix` alone would also take a sign (`+f`): only hex digits pass.
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (slot, pair) in out.iter_mut().zip(pairs) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn general_name_text(name: &GeneralName<'_>) -> Option<String> {
    match name {
        GeneralName::DNSName(dns) => Some(format!("DNS:{dns}")),
        GeneralName::IPAddress(raw) => ip_from_bytes(raw).map(|ip| format!("IP:{ip}")),
        _ => None,
    }
}

fn ip_from_bytes(raw: &[u8]) -> Option<IpAddr> {
    if let Ok(v4) = <[u8; 4]>::try_from(raw) {
        return Some(IpAddr::from(v4));
    }
    <[u8; 16]>::try_from(raw).ok().map(IpAddr::from)
}

/// Does the certificate's common name match `name`, for a certificate **without** DNS or IP
/// subject alternative names?
///
/// x3270 checks the common name of every host certificate (`sio_openssl.c`,
/// `check_cert_name`), so z/OS certificates created without `ALTNAME` work there. RFC 6125
/// §6.4.4 allows the common name only when no subject alternative name of a supported type is
/// present; a certificate with such names is never matched by its common name here.
#[must_use]
pub fn common_name_matches(der: &[u8], name: &ServerName<'_>) -> bool {
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return false;
    };
    match cert.subject_alternative_name() {
        Ok(None) => {}
        Ok(Some(san)) => {
            let has_names = san
                .value
                .general_names
                .iter()
                .any(|n| matches!(n, GeneralName::DNSName(_) | GeneralName::IPAddress(_)));
            if has_names {
                return false;
            }
        }
        // A malformed or duplicated extension: no fallback.
        Err(_) => return false,
    }
    let matched = cert
        .subject()
        .iter_common_name()
        .filter_map(|cn| cn.as_str().ok())
        .any(|cn| name_matches(cn, name));
    matched
}

/// `pattern` (a common name) against the checked name: case-insensitive DNS names with a
/// wildcard only as the whole leftmost label (`*.example.com`, as x3270 `hostname_matches`),
/// IP addresses by value.
fn name_matches(pattern: &str, name: &ServerName<'_>) -> bool {
    match name {
        ServerName::DnsName(dns) => dns_matches(pattern, dns.as_ref()),
        ServerName::IpAddress(ip) => pattern
            .parse::<IpAddr>()
            .is_ok_and(|cn_ip| cn_ip == IpAddr::from(*ip)),
        _ => false,
    }
}

fn dns_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    let host = host.trim_end_matches('.');
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // The wildcard stands for exactly one non-empty label.
        return match host.split_once('.') {
            Some((label, rest)) => {
                !label.is_empty() && !suffix.is_empty() && rest.eq_ignore_ascii_case(suffix)
            }
            None => false,
        };
    }
    !pattern.is_empty() && pattern.eq_ignore_ascii_case(host)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    fn cert(cn: &str, sans: Vec<SanType>) -> Vec<u8> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.subject_alt_names = sans;
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn dns(name: &str) -> ServerName<'static> {
        ServerName::try_from(name.to_owned()).unwrap()
    }

    #[test]
    fn common_name_is_used_only_without_alternative_names() {
        let cn_only = cert("zos1.bank.example", vec![]);
        assert!(common_name_matches(&cn_only, &dns("zos1.bank.example")));
        assert!(common_name_matches(&cn_only, &dns("ZOS1.Bank.Example")));
        assert!(!common_name_matches(&cn_only, &dns("zos2.bank.example")));

        // With a DNS SAN the common name is never a fallback (RFC 6125 §6.4.4).
        let with_san = cert(
            "zos1.bank.example",
            vec![SanType::DnsName("other.bank.example".try_into().unwrap())],
        );
        assert!(!common_name_matches(&with_san, &dns("zos1.bank.example")));
    }

    #[test]
    fn common_name_wildcard_covers_one_label() {
        let wildcard = cert("*.bank.example", vec![]);
        assert!(common_name_matches(&wildcard, &dns("zos1.bank.example")));
        assert!(!common_name_matches(&wildcard, &dns("a.zos1.bank.example")));
        assert!(!common_name_matches(&wildcard, &dns("bank.example")));
    }

    #[test]
    fn common_name_with_an_address() {
        let by_ip = cert("10.1.2.3", vec![]);
        assert!(common_name_matches(&by_ip, &dns("10.1.2.3")));
        assert!(!common_name_matches(&by_ip, &dns("10.1.2.4")));
        assert!(!common_name_matches(&by_ip, &dns("zos1.bank.example")));
    }

    #[test]
    fn details_of_a_certificate() {
        let der = cert(
            "zos1.bank.example",
            vec![
                SanType::DnsName("zos1.bank.example".try_into().unwrap()),
                SanType::IpAddress("10.1.2.3".parse().unwrap()),
            ],
        );
        let peer = PeerCertificate::from_der(&der);
        assert_eq!(peer.subject, "CN=zos1.bank.example");
        assert_eq!(peer.issuer, "CN=zos1.bank.example");
        assert_eq!(peer.names, ["DNS:zos1.bank.example", "IP:10.1.2.3"]);
        assert_eq!(peer.sha256, sha256(&der));
        assert_eq!(parse_sha256_hex(&peer.sha256_hex()), Some(peer.sha256));

        let garbage = PeerCertificate::from_der(b"not a certificate");
        assert_eq!(garbage.subject, "(unreadable)");
    }

    #[test]
    fn fingerprint_parsing_is_strict() {
        let hex64 = "AB".repeat(32);
        assert_eq!(parse_sha256_hex(&hex64), Some([0xab; 32]));
        assert_eq!(parse_sha256_hex(&"ab".repeat(31)), None);
        assert_eq!(parse_sha256_hex(&format!("{}zz", "ab".repeat(31))), None);
        assert_eq!(parse_sha256_hex(&"ab:".repeat(32)), None);
    }

    #[test]
    fn problems_from_tls_errors() {
        let name = dns("zos1.bank.example");
        let classify =
            |e| CertProblem::from_tls_error(&rustls::Error::InvalidCertificate(e), &name);
        assert_eq!(
            classify(CertificateError::UnknownIssuer),
            CertProblem::UnknownIssuer
        );
        assert_eq!(
            classify(CertificateError::NotValidForName),
            CertProblem::NameMismatch {
                expected: "zos1.bank.example".into()
            }
        );
        assert_eq!(classify(CertificateError::Expired), CertProblem::Expired);
        assert_eq!(
            classify(CertificateError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: vec![],
                supported_algorithms: vec![],
            }),
            CertProblem::UnsupportedAlgorithm
        );
    }
}
