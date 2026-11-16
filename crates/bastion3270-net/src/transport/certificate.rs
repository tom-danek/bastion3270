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
use rustls_pki_types::{ServerName, UnixTime};
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;

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
            // the trusted one (e.g. a CA generated again under the same name, or switched from
            // RSA to ECC so its public key type or curve no longer matches the signature).
            CertificateError::UnknownIssuer
            | CertificateError::BadSignature
            | CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
                Self::UnknownIssuer
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                Self::NameMismatch {
                    expected: expected.to_str().into_owned(),
                }
            }
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => Self::Expired,
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                Self::NotYetValid
            }
            CertificateError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id,
                ..
            } => {
                if is_strong_ecc_signature(signature_algorithm_id) {
                    Self::UnknownIssuer
                } else {
                    Self::UnsupportedAlgorithm
                }
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
    /// Serial number in colon-separated hex (`01:23:…`).
    pub serial: String,
    /// Public key algorithm and size or curve (e.g. `ECC (P-256 / secp256r1, 256 bits)` or `RSA (2048 bits)`).
    pub public_key: String,
    /// Signature algorithm used to sign the certificate (e.g. `ECDSA with SHA-384`).
    pub signature_algorithm: String,
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
                serial: unreadable.clone(),
                public_key: unreadable.clone(),
                signature_algorithm: unreadable.clone(),
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
            serial: cert.raw_serial_as_string(),
            public_key: describe_public_key(&cert),
            signature_algorithm: describe_signature_algorithm(&cert),
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

/// Checks that `der` is valid at `now` (`not_before <= now <= not_after`).
///
/// Used when a certificate is trusted directly from the system store or `ca_cert` (where
/// `webpki` would otherwise treat it only as an issuing CA).
///
/// # Errors
/// Returns [`CertificateError::BadEncoding`], [`CertificateError::NotValidYet`], or
/// [`CertificateError::Expired`] wrapped in [`rustls::Error::InvalidCertificate`].
pub fn check_cert_validity(der: &[u8], now: UnixTime) -> core::result::Result<(), rustls::Error> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
    let validity = cert.validity();
    let Ok(now_secs) = i64::try_from(now.as_secs()) else {
        return Err(rustls::Error::InvalidCertificate(CertificateError::Expired));
    };
    if now_secs < validity.not_before.timestamp() {
        return Err(rustls::Error::InvalidCertificate(
            CertificateError::NotValidYet,
        ));
    }
    if now_secs > validity.not_after.timestamp() {
        return Err(rustls::Error::InvalidCertificate(CertificateError::Expired));
    }
    Ok(())
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

/// Does `alg_id` (DER `AlgorithmIdentifier` content) name an ECC signature with SHA-256 or
/// stronger (e.g. `ecdsa-with-SHA512`, `ecdsa-with-SHA256`/`384` with explicit parameters,
/// `ecdsa-with-sha3-*`, or `Ed448`) that `ring` does not verify in chains, rather than an
/// obsolete digest like SHA-1 or MD5?
fn is_strong_ecc_signature(alg_id: &[u8]) -> bool {
    // 1.2.840.10045.4.3.{2,3,4}: ecdsa-with-SHA256 / SHA384 / SHA512 (RFC 5758).
    const ECDSA_SHA2_PREFIX: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03];
    // 2.16.840.1.101.3.4.3.{10,11,12}: id-ecdsa-with-sha3-256 / 384 / 512.
    const ECDSA_SHA3_PREFIX: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
    // 1.3.101.113: id-Ed448 (RFC 8410).
    const ED448_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x71];

    if let Some(&digest) = alg_id
        .strip_prefix(ECDSA_SHA2_PREFIX)
        .and_then(|rest| rest.first())
    {
        return matches!(digest, 0x02..=0x04);
    }
    if let Some(&digest) = alg_id
        .strip_prefix(ECDSA_SHA3_PREFIX)
        .and_then(|rest| rest.first())
    {
        return matches!(digest, 0x0a..=0x0c);
    }
    alg_id.starts_with(ED448_OID)
}

/// Human-readable public key type and size or curve (e.g. `ECC (P-256 / secp256r1, 256 bits)`
/// or `RSA (2048 bits)`).
fn describe_public_key(cert: &X509Certificate<'_>) -> String {
    let spki = cert.public_key();
    let alg_oid = spki.algorithm.algorithm.to_id_string();
    match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => format!("RSA ({} bits)", rsa.key_size()),
        Ok(PublicKey::EC(_)) => {
            let curve_oid = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|any| any.as_oid().ok())
                .map(|oid| oid.to_id_string());
            match curve_oid.as_deref() {
                Some("1.2.840.10045.3.1.7") => "ECC (P-256 / secp256r1, 256 bits)".to_owned(),
                Some("1.3.132.0.34") => "ECC (P-384 / secp384r1, 384 bits)".to_owned(),
                Some("1.3.132.0.35") => "ECC (P-521 / secp521r1, 521 bits)".to_owned(),
                Some("1.3.36.3.3.2.8.1.1.7") => "ECC (brainpoolP256r1, 256 bits)".to_owned(),
                Some("1.3.36.3.3.2.8.1.1.11") => "ECC (brainpoolP384r1, 384 bits)".to_owned(),
                Some("1.3.36.3.3.2.8.1.1.13") => "ECC (brainpoolP512r1, 512 bits)".to_owned(),
                Some(other) => format!("ECC ({other})"),
                None => "ECC".to_owned(),
            }
        }
        Ok(PublicKey::DSA(_)) => "DSA".to_owned(),
        _ => match alg_oid.as_str() {
            "1.3.101.112" => "Ed25519 (256 bits)".to_owned(),
            "1.3.101.113" => "Ed448 (448 bits)".to_owned(),
            _ => alg_oid,
        },
    }
}

/// Human-readable signature algorithm of the certificate.
fn describe_signature_algorithm(cert: &X509Certificate<'_>) -> String {
    let oid = cert.signature_algorithm.algorithm.to_id_string();
    match oid.as_str() {
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256".to_owned(),
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384".to_owned(),
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512".to_owned(),
        "1.2.840.10045.4.3.1" => "ECDSA with SHA-224".to_owned(),
        "1.2.840.10045.4.1" => "ECDSA with SHA-1".to_owned(),
        "1.2.840.113549.1.1.11" => "RSA PKCS#1 v1.5 with SHA-256".to_owned(),
        "1.2.840.113549.1.1.12" => "RSA PKCS#1 v1.5 with SHA-384".to_owned(),
        "1.2.840.113549.1.1.13" => "RSA PKCS#1 v1.5 with SHA-512".to_owned(),
        "1.2.840.113549.1.1.10" => "RSA-PSS".to_owned(),
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => "RSA PKCS#1 v1.5 with SHA-1".to_owned(),
        "1.2.840.113549.1.1.4" | "1.3.14.3.2.3" => "RSA PKCS#1 v1.5 with MD5".to_owned(),
        "1.3.101.112" => "Ed25519".to_owned(),
        "1.3.101.113" => "Ed448".to_owned(),
        _ => oid,
    }
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
        assert_ne!(peer.serial, "");
        assert_eq!(peer.public_key, "ECC (P-256 / secp256r1, 256 bits)");
        assert_eq!(peer.signature_algorithm, "ECDSA with SHA-256");
        assert_eq!(peer.names, ["DNS:zos1.bank.example", "IP:10.1.2.3"]);
        assert_eq!(peer.sha256, sha256(&der));
        assert_eq!(parse_sha256_hex(&peer.sha256_hex()), Some(peer.sha256));

        let garbage = PeerCertificate::from_der(b"not a certificate");
        assert_eq!(garbage.subject, "(unreadable)");
        assert_eq!(garbage.public_key, "(unreadable)");
        assert_eq!(garbage.signature_algorithm, "(unreadable)");
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
        // An ECC certificate whose issuer name matches an older RSA CA in the trust store, or
        // signed with ECDSA-SHA512 (1.2.840.10045.4.3.4), is untrusted rather than weak.
        assert_eq!(
            classify(
                CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                    signature_algorithm_id: vec![],
                    public_key_algorithm_id: vec![],
                }
            ),
            CertProblem::UnknownIssuer
        );
        assert_eq!(
            classify(CertificateError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: vec![
                    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04
                ],
                supported_algorithms: vec![],
            }),
            CertProblem::UnknownIssuer
        );
    }
}
