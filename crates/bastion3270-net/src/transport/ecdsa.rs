//! Additional ECDSA X.509 certificate signature verifiers (`ecdsa-with-SHA512` and `secp521r1`).
//!
//! `rustls` with the `ring` provider verifies `ecdsa-with-SHA256` and `ecdsa-with-SHA384` on
//! NIST P-256 and P-384, but omits `ecdsa-with-SHA512` (OID `1.2.840.10045.4.3.4`, RFC 5758 §3.2)
//! and NIST P-521 (`secp521r1`, OID `1.3.132.0.35`, RFC 5480 §2.1.1.1). Corporate and mainframe
//! PKIs frequently sign P-384 or P-521 certificates with `ecdsa-with-SHA512`.
//!
//! This module implements [`SignatureVerificationAlgorithm`] for those combinations in safe,
//! panic-free Rust so [`verify_server_cert_signed_by_trust_anchor`](rustls::client::verify_server_cert_signed_by_trust_anchor)
//! can validate such certificate chains from the system store or `ca_cert`.

// `BigUint` arithmetic is arbitrary-precision (no integer wrap-around), all moduli (`p`, `n`) are
// fixed NIST primes > 2^255 (never zero), and `mod_sub` checks `a >= b` before subtracting.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    clippy::similar_names
)]

use rustls_pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_parser::num_bigint::BigUint;

/// `ecdsa-with-SHA512` (`1.2.840.10045.4.3.4`) without parameters (RFC 5758 §3.2).
const ALG_ECDSA_SHA512: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04]);

/// `ecdsa-with-SHA512` (`1.2.840.10045.4.3.4`) with explicit ASN.1 NULL parameters (`05 00`).
const ALG_ECDSA_SHA512_WITH_NULL: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x05, 0x00,
]);

/// `id-ecPublicKey` (`1.2.840.10045.2.1`) with curve `secp521r1` (`1.3.132.0.35`).
const ALG_ECDSA_P521: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
]);

/// Additional ECDSA verification algorithms not provided by `webpki::ring`.
pub static EXTRA_ECDSA_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    &EcdsaVerifier {
        public_key_alg_id: alg_id::ECDSA_P256,
        signature_alg_id: ALG_ECDSA_SHA512,
        curve: CurveId::P256,
        hash: HashId::Sha512,
    },
    &EcdsaVerifier {
        public_key_alg_id: alg_id::ECDSA_P256,
        signature_alg_id: ALG_ECDSA_SHA512_WITH_NULL,
        curve: CurveId::P256,
        hash: HashId::Sha512,
    },
    &EcdsaVerifier {
        public_key_alg_id: alg_id::ECDSA_P384,
        signature_alg_id: ALG_ECDSA_SHA512,
        curve: CurveId::P384,
        hash: HashId::Sha512,
    },
    &EcdsaVerifier {
        public_key_alg_id: alg_id::ECDSA_P384,
        signature_alg_id: ALG_ECDSA_SHA512_WITH_NULL,
        curve: CurveId::P384,
        hash: HashId::Sha512,
    },
    &EcdsaVerifier {
        public_key_alg_id: ALG_ECDSA_P521,
        signature_alg_id: alg_id::ECDSA_SHA256,
        curve: CurveId::P521,
        hash: HashId::Sha256,
    },
    &EcdsaVerifier {
        public_key_alg_id: ALG_ECDSA_P521,
        signature_alg_id: alg_id::ECDSA_SHA384,
        curve: CurveId::P521,
        hash: HashId::Sha384,
    },
    &EcdsaVerifier {
        public_key_alg_id: ALG_ECDSA_P521,
        signature_alg_id: ALG_ECDSA_SHA512,
        curve: CurveId::P521,
        hash: HashId::Sha512,
    },
    &EcdsaVerifier {
        public_key_alg_id: ALG_ECDSA_P521,
        signature_alg_id: ALG_ECDSA_SHA512_WITH_NULL,
        curve: CurveId::P521,
        hash: HashId::Sha512,
    },
];

/// Returns `base` (e.g. `ring`'s `signature_verification_algorithms.all`) extended with
/// [`EXTRA_ECDSA_ALGS`].
#[must_use]
pub fn extended_verification_algorithms(
    base: &[&'static dyn SignatureVerificationAlgorithm],
) -> Vec<&'static dyn SignatureVerificationAlgorithm> {
    let mut all = Vec::with_capacity(base.len().saturating_add(EXTRA_ECDSA_ALGS.len()));
    all.extend_from_slice(base);
    all.extend_from_slice(EXTRA_ECDSA_ALGS);
    all
}

#[derive(Debug, Clone, Copy)]
enum CurveId {
    P256,
    P384,
    P521,
}

#[derive(Debug, Clone, Copy)]
enum HashId {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug)]
struct EcdsaVerifier {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    curve: CurveId,
    hash: HashId,
}

impl SignatureVerificationAlgorithm for EcdsaVerifier {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let params = CurveParams::for_curve(self.curve);
        let (qx, qy) = parse_uncompressed_point(public_key, &params).ok_or(InvalidSignature)?;
        let (r, s) = parse_der_ecdsa_signature(signature).ok_or(InvalidSignature)?;

        let one = BigUint::from(1u32);
        if r < one || r >= params.n || s < one || s >= params.n {
            return Err(InvalidSignature);
        }

        let e = digest_scalar(self.hash, message, params.order_bits, &params.n);
        let two = BigUint::from(2u32);
        let w = s.modpow(&(&params.n - &two), &params.n);
        let u1 = (&e * &w) % &params.n;
        let u2 = (&r * &w) % &params.n;

        let g = Point::Jacobian {
            x: params.gx.clone(),
            y: params.gy.clone(),
            z: one.clone(),
        };
        let q = Point::Jacobian {
            x: qx,
            y: qy,
            z: one,
        };

        let p1 = scalar_mul(&g, &u1, &params.p);
        let p2 = scalar_mul(&q, &u2, &params.p);
        let sum = point_add(&p1, &p2, &params.p);
        let x_aff = affine_x(&sum, &params.p).ok_or(InvalidSignature)?;

        if (x_aff % &params.n) == r {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }
}

struct CurveParams {
    coord_len: usize,
    order_bits: usize,
    p: BigUint,
    n: BigUint,
    b: BigUint,
    gx: BigUint,
    gy: BigUint,
}

impl CurveParams {
    fn for_curve(curve: CurveId) -> Self {
        match curve {
            CurveId::P256 => Self::p256(),
            CurveId::P384 => Self::p384(),
            CurveId::P521 => Self::p521(),
        }
    }

    fn p256() -> Self {
        Self {
            coord_len: 32,
            order_bits: 256,
            p: BigUint::from_bytes_be(&[
                0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            ]),
            n: BigUint::from_bytes_be(&[
                0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
                0xfc, 0x63, 0x25, 0x51,
            ]),
            b: BigUint::from_bytes_be(&[
                0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98,
                0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e,
                0x27, 0xd2, 0x60, 0x4b,
            ]),
            gx: BigUint::from_bytes_be(&[
                0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
                0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
                0xd8, 0x98, 0xc2, 0x96,
            ]),
            gy: BigUint::from_bytes_be(&[
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
                0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
                0x37, 0xbf, 0x51, 0xf5,
            ]),
        }
    }

    fn p384() -> Self {
        Self {
            coord_len: 48,
            order_bits: 384,
            p: BigUint::from_bytes_be(&[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            ]),
            n: BigUint::from_bytes_be(&[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81,
                0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec,
                0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
            ]),
            b: BigUint::from_bytes_be(&[
                0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8,
                0x2d, 0x19, 0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8f,
                0x50, 0x13, 0x87, 0x5a, 0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85,
                0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef,
            ]),
            gx: BigUint::from_bytes_be(&[
                0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20,
                0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7, 0x41, 0xe0,
                0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54,
                0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
            ]),
            gy: BigUint::from_bytes_be(&[
                0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92,
                0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9, 0xda, 0x31, 0x13,
                0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43,
                0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
            ]),
        }
    }

    fn p521() -> Self {
        Self {
            coord_len: 66,
            order_bits: 521,
            p: BigUint::from_bytes_be(&[
                0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ]),
            n: BigUint::from_bytes_be(&[
                0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b,
                0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c,
                0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09,
            ]),
            b: BigUint::from_bytes_be(&[
                0x00, 0x51, 0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c, 0x9a, 0x1f, 0x92, 0x9a, 0x21, 0xa0,
                0xb6, 0x85, 0x40, 0xee, 0xa2, 0xda, 0x72, 0x5b, 0x99, 0xb3, 0x15, 0xf3, 0xb8, 0xb4,
                0x89, 0x91, 0x8e, 0xf1, 0x09, 0xe1, 0x56, 0x19, 0x39, 0x51, 0xec, 0x7e, 0x93, 0x7b,
                0x16, 0x52, 0xc0, 0xbd, 0x3b, 0xb1, 0xbf, 0x07, 0x35, 0x73, 0xdf, 0x88, 0x3d, 0x2c,
                0x34, 0xf1, 0xef, 0x45, 0x1f, 0xd4, 0x6b, 0x50, 0x3f, 0x00,
            ]),
            gx: BigUint::from_bytes_be(&[
                0x00, 0xc6, 0x85, 0x8e, 0x06, 0xb7, 0x04, 0x04, 0xe9, 0xcd, 0x9e, 0x3e, 0xcb, 0x66,
                0x23, 0x95, 0xb4, 0x42, 0x9c, 0x64, 0x81, 0x39, 0x05, 0x3f, 0xb5, 0x21, 0xf8, 0x28,
                0xaf, 0x60, 0x6b, 0x4d, 0x3d, 0xba, 0xa1, 0x4b, 0x5e, 0x77, 0xef, 0xe7, 0x59, 0x28,
                0xfe, 0x1d, 0xc1, 0x27, 0xa2, 0xff, 0xa8, 0xde, 0x33, 0x48, 0xb3, 0xc1, 0x85, 0x6a,
                0x42, 0x9b, 0xf9, 0x7e, 0x7e, 0x31, 0xc2, 0xe5, 0xbd, 0x66,
            ]),
            gy: BigUint::from_bytes_be(&[
                0x01, 0x18, 0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b, 0xc0, 0x04, 0x5c, 0x8a, 0x5f, 0xb4,
                0x2c, 0x7d, 0x1b, 0xd9, 0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b, 0x44, 0x68, 0x17, 0xaf,
                0xbd, 0x17, 0x27, 0x3e, 0x66, 0x2c, 0x97, 0xee, 0x72, 0x99, 0x5e, 0xf4, 0x26, 0x40,
                0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad, 0x07, 0x61, 0x35, 0x3c, 0x70, 0x86, 0xa2, 0x72,
                0xc2, 0x40, 0x88, 0xbe, 0x94, 0x76, 0x9f, 0xd1, 0x66, 0x50,
            ]),
        }
    }
}

/// Parses an uncompressed SEC1 point (`0x04 || X || Y`) and checks that it lies on the curve.
fn parse_uncompressed_point(bytes: &[u8], params: &CurveParams) -> Option<(BigUint, BigUint)> {
    let (&first, coords) = bytes.split_first()?;
    if first != 0x04 || coords.len() != params.coord_len.saturating_mul(2) {
        return None;
    }
    let (x_bytes, y_bytes) = coords.split_at_checked(params.coord_len)?;
    let x = BigUint::from_bytes_be(x_bytes);
    let y = BigUint::from_bytes_be(y_bytes);
    if x >= params.p || y >= params.p {
        return None;
    }
    // Check y^2 == x^3 - 3x + b (mod p).
    let lhs = (&y * &y) % &params.p;
    let x2 = (&x * &x) % &params.p;
    let x3 = (&x2 * &x) % &params.p;
    let three_x = (BigUint::from(3u32) * &x) % &params.p;
    let rhs = (mod_sub(&x3, &three_x, &params.p) + &params.b) % &params.p;
    if lhs == rhs {
        Some((x, y))
    } else {
        None
    }
}

/// Parses a strict ASN.1 DER `SEQUENCE { r INTEGER, s INTEGER }`.
fn parse_der_ecdsa_signature(der: &[u8]) -> Option<(BigUint, BigUint)> {
    let (seq_body, rest) = read_der_tlv(der, 0x30)?;
    if !rest.is_empty() {
        return None;
    }
    let (r_bytes, after_r) = read_der_positive_integer(seq_body)?;
    let (s_bytes, after_s) = read_der_positive_integer(after_r)?;
    if !after_s.is_empty() {
        return None;
    }
    Some((
        BigUint::from_bytes_be(r_bytes),
        BigUint::from_bytes_be(s_bytes),
    ))
}

fn read_der_tlv(input: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag != expected_tag {
        return None;
    }
    let (&len_byte, rest) = rest.split_first()?;
    let (len, content) = if len_byte < 0x80 {
        (usize::from(len_byte), rest)
    } else if len_byte == 0x81 {
        let (&b0, after) = rest.split_first()?;
        if b0 < 0x80 {
            return None;
        }
        (usize::from(b0), after)
    } else if len_byte == 0x82 {
        let (&b0, after0) = rest.split_first()?;
        let (&b1, after1) = after0.split_first()?;
        let len = (usize::from(b0) << 8) | usize::from(b1);
        if len < 0x100 {
            return None;
        }
        (len, after1)
    } else {
        return None;
    };
    content.split_at_checked(len)
}

fn read_der_positive_integer(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (bytes, rest) = read_der_tlv(input, 0x02)?;
    let (&first, tail) = bytes.split_first()?;
    // Negative INTEGER (high bit set) is invalid.
    if first & 0x80 != 0 {
        return None;
    }
    if first == 0x00 {
        let (&second, _) = tail.split_first()?;
        // Leading zero is only canonical when the next byte has its high bit set.
        if second & 0x80 == 0 {
            return None;
        }
        Some((tail, rest))
    } else {
        Some((bytes, rest))
    }
}

/// Computes the FIPS 186-4 / SEC 1 §4.1.4 message representative `e` from `hash(message)`.
fn digest_scalar(hash: HashId, message: &[u8], order_bits: usize, n: &BigUint) -> BigUint {
    let (digest_bytes, digest_bits): (Vec<u8>, usize) = match hash {
        HashId::Sha256 => (Sha256::digest(message).to_vec(), 256),
        HashId::Sha384 => (Sha384::digest(message).to_vec(), 384),
        HashId::Sha512 => (Sha512::digest(message).to_vec(), 512),
    };
    let mut e = BigUint::from_bytes_be(&digest_bytes);
    if digest_bits > order_bits {
        e >>= digest_bits.saturating_sub(order_bits);
    }
    e % n
}

#[derive(Clone)]
enum Point {
    Infinity,
    Jacobian { x: BigUint, y: BigUint, z: BigUint },
}

fn mod_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % p
    } else {
        (p - ((b - a) % p)) % p
    }
}

fn point_double(pt: &Point, p: &BigUint) -> Point {
    let Point::Jacobian { x, y, z } = pt else {
        return Point::Infinity;
    };
    let zero = BigUint::from(0u32);
    if *y == zero || *z == zero {
        return Point::Infinity;
    }
    let delta = (z * z) % p;
    let gamma = (y * y) % p;
    let beta = (x * &gamma) % p;
    let x_minus_delta = mod_sub(x, &delta, p);
    let x_plus_delta = (x + &delta) % p;
    let alpha = (BigUint::from(3u32) * x_minus_delta * x_plus_delta) % p;

    let alpha2 = (&alpha * &alpha) % p;
    let four_beta = (BigUint::from(4u32) * &beta) % p;
    let eight_beta = (BigUint::from(8u32) * &beta) % p;
    let x3 = mod_sub(&alpha2, &eight_beta, p);

    let y_plus_z = (y + z) % p;
    let y_plus_z_sq = (&y_plus_z * &y_plus_z) % p;
    let z3 = mod_sub(&mod_sub(&y_plus_z_sq, &gamma, p), &delta, p);

    let four_beta_minus_x3 = mod_sub(&four_beta, &x3, p);
    let alpha_term = (&alpha * four_beta_minus_x3) % p;
    let gamma2 = (&gamma * &gamma) % p;
    let eight_gamma2 = (BigUint::from(8u32) * gamma2) % p;
    let y3 = mod_sub(&alpha_term, &eight_gamma2, p);

    Point::Jacobian {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn point_add(p1: &Point, p2: &Point, p: &BigUint) -> Point {
    let (
        Point::Jacobian {
            x: x1,
            y: y1,
            z: z1,
        },
        Point::Jacobian {
            x: x2,
            y: y2,
            z: z2,
        },
    ) = (p1, p2)
    else {
        return match p1 {
            Point::Infinity => p2.clone(),
            Point::Jacobian { .. } => p1.clone(),
        };
    };

    let z1_sq = (z1 * z1) % p;
    let z2_sq = (z2 * z2) % p;
    let u1 = (x1 * &z2_sq) % p;
    let u2 = (x2 * &z1_sq) % p;
    let s1 = (y1 * z2 * &z2_sq) % p;
    let s2 = (y2 * z1 * &z1_sq) % p;

    if u1 == u2 {
        if s1 == s2 {
            return point_double(p1, p);
        }
        return Point::Infinity;
    }

    let h = mod_sub(&u2, &u1, p);
    let r = mod_sub(&s2, &s1, p);
    let h2 = (&h * &h) % p;
    let h3 = (&h * &h2) % p;
    let u1_h2 = (&u1 * &h2) % p;

    let r2 = (&r * &r) % p;
    let two_u1_h2 = (BigUint::from(2u32) * &u1_h2) % p;
    let x3 = mod_sub(&mod_sub(&r2, &h3, p), &two_u1_h2, p);

    let u1_h2_minus_x3 = mod_sub(&u1_h2, &x3, p);
    let r_term = (&r * u1_h2_minus_x3) % p;
    let s1_h3 = (&s1 * &h3) % p;
    let y3 = mod_sub(&r_term, &s1_h3, p);

    let z3 = (&h * z1 * z2) % p;

    Point::Jacobian {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn scalar_mul(base: &Point, k: &BigUint, p: &BigUint) -> Point {
    let mut acc = Point::Infinity;
    let bits = k.bits();
    for i in (0..bits).rev() {
        acc = point_double(&acc, p);
        if k.bit(i) {
            acc = point_add(&acc, base, p);
        }
    }
    acc
}

fn affine_x(pt: &Point, p: &BigUint) -> Option<BigUint> {
    let Point::Jacobian { x, z, .. } = pt else {
        return None;
    };
    let zero = BigUint::from(0u32);
    if *z == zero {
        return None;
    }
    let two = BigUint::from(2u32);
    let z_inv = z.modpow(&(p - &two), p);
    let z_inv2 = (&z_inv * &z_inv) % p;
    Some((x * z_inv2) % p)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn generator_points_are_on_their_curves() {
        for curve in [CurveId::P256, CurveId::P384, CurveId::P521] {
            let params = CurveParams::for_curve(curve);
            let mut uncompressed = vec![0x04];
            let gx_bytes = params.gx.to_bytes_be();
            let gy_bytes = params.gy.to_bytes_be();
            uncompressed.extend(std::iter::repeat_n(
                0u8,
                params.coord_len.saturating_sub(gx_bytes.len()),
            ));
            uncompressed.extend_from_slice(&gx_bytes);
            uncompressed.extend(std::iter::repeat_n(
                0u8,
                params.coord_len.saturating_sub(gy_bytes.len()),
            ));
            uncompressed.extend_from_slice(&gy_bytes);
            assert!(parse_uncompressed_point(&uncompressed, &params).is_some());
        }
    }

    #[test]
    fn verifies_ecdsa_p384_sha512_signature() {
        // Generate a P-384 key and deterministic test signature s = k^-1 (e + r*d) mod n.
        let params = CurveParams::for_curve(CurveId::P384);
        let d = BigUint::from(42_424_242u64);
        let k = BigUint::from(123_456_789u64);
        let g = Point::Jacobian {
            x: params.gx.clone(),
            y: params.gy.clone(),
            z: BigUint::from(1u32),
        };
        let q = scalar_mul(&g, &d, &params.p);
        let Point::Jacobian {
            x: qx_j,
            y: qy_j,
            z: qz_j,
        } = &q
        else {
            unreachable!();
        };
        let two = BigUint::from(2u32);
        let z_inv = qz_j.modpow(&(&params.p - &two), &params.p);
        let z_inv2 = (&z_inv * &z_inv) % &params.p;
        let z_inv3 = (&z_inv2 * &z_inv) % &params.p;
        let qx = (qx_j * &z_inv2) % &params.p;
        let qy = (qy_j * &z_inv3) % &params.p;

        let mut pubkey = vec![0x04];
        for coord in [&qx, &qy] {
            let bytes = coord.to_bytes_be();
            pubkey.extend(std::iter::repeat_n(
                0u8,
                params.coord_len.saturating_sub(bytes.len()),
            ));
            pubkey.extend_from_slice(&bytes);
        }

        let msg = b"zos1.example.com tbsCertificate payload";
        let e = digest_scalar(HashId::Sha512, msg, params.order_bits, &params.n);
        let kg = scalar_mul(&g, &k, &params.p);
        let r = affine_x(&kg, &params.p).unwrap() % &params.n;
        let k_inv = k.modpow(&(&params.n - &two), &params.n);
        let s = (k_inv * (&e + (&r * &d) % &params.n)) % &params.n;

        let encode_int = |val: &BigUint| {
            let mut b = val.to_bytes_be();
            if b.first().is_some_and(|&hi| hi & 0x80 != 0) {
                b.insert(0, 0x00);
            }
            let mut out = vec![0x02, u8::try_from(b.len()).unwrap()];
            out.extend_from_slice(&b);
            out
        };
        let mut seq_body = encode_int(&r);
        seq_body.extend_from_slice(&encode_int(&s));
        let mut der_sig = vec![0x30, u8::try_from(seq_body.len()).unwrap()];
        der_sig.extend_from_slice(&seq_body);

        let verifier = EcdsaVerifier {
            public_key_alg_id: alg_id::ECDSA_P384,
            signature_alg_id: ALG_ECDSA_SHA512,
            curve: CurveId::P384,
            hash: HashId::Sha512,
        };
        assert!(verifier.verify_signature(&pubkey, msg, &der_sig).is_ok());
        assert!(verifier
            .verify_signature(&pubkey, b"tampered", &der_sig)
            .is_err());
    }
}
