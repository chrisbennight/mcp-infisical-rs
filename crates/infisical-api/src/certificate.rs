use aws_lc_rs::{
    signature::{ECDSA_P521_SHA512_ASN1, UnparsedPublicKey, VerificationAlgorithm},
    unstable::signature::{ML_DSA_44, ML_DSA_65, ML_DSA_87},
};
use fips205::traits::{SerDes, Verifier};
use rustls_pki_types::CertificateDer;
use x509_parser::prelude::{FromDer, X509Certificate};

const PEM_CERTIFICATE_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const PEM_CERTIFICATE_END: &[u8] = b"-----END CERTIFICATE-----";

/// Remove one optional terminal PEM line ending while rejecting other padding.
pub(crate) fn normalize_pem(value: &str) -> Option<String> {
    let normalized = value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value);
    (!normalized.is_empty() && normalized.trim() == normalized).then(|| normalized.to_owned())
}

/// Compare a textual hexadecimal serial with one parsed X.509 certificate.
pub(crate) fn certificate_serial_matches(
    certificate: &X509Certificate<'_>,
    serial_number: &str,
) -> bool {
    let expected = certificate.raw_serial_as_string().replace(':', "");
    certificate_serial_values_match(&expected, serial_number)
}

/// Compare two validated textual hexadecimal serial representations semantically.
pub(crate) fn certificate_serial_values_match(left: &str, right: &str) -> bool {
    let left = left.trim_start_matches('0');
    let right = right.trim_start_matches('0');
    let left = if left.is_empty() { "0" } else { left };
    let right = if right.is_empty() { "0" } else { right };
    left.eq_ignore_ascii_case(right)
}

macro_rules! verify_slh_dsa_signature {
    ($module:ident, $public_key:expr, $message:expr, $signature:expr) => {{
        let public_key = <&[u8; fips205::$module::PK_LEN]>::try_from($public_key);
        let signature = <&[u8; fips205::$module::SIG_LEN]>::try_from($signature);
        match (public_key, signature) {
            (Ok(public_key), Ok(signature)) => {
                fips205::$module::PublicKey::try_from_bytes(public_key)
                    .is_ok_and(|public_key| public_key.verify($message, signature, b""))
            }
            _ => false,
        }
    }};
}

macro_rules! verify_slh_dsa_signature_by_oid {
    ($oid:expr, $public_key:expr, $message:expr, $signature:expr, {$($expected_oid:literal => $module:ident),+ $(,)?}) => {
        match $oid {
            $(
                $expected_oid => verify_slh_dsa_signature!(
                    $module,
                    $public_key,
                    $message,
                    $signature
                ),
            )+
            _ => false,
        }
    };
}

/// Validate one or more newline-separated PEM certificates as trust anchors.
pub(crate) fn is_valid_ca_certificate_bundle(value: &str) -> bool {
    certificate_bundle_der(value).is_some_and(|certificates| {
        certificates
            .into_iter()
            .all(|der| webpki::anchor_from_trusted_cert(&CertificateDer::from(der)).is_ok())
    })
}

/// Require every certificate in a PEM bundle to carry CA signing constraints.
pub(crate) fn is_valid_ca_signing_certificate_bundle(value: &str) -> bool {
    certificate_bundle_der(value).is_some_and(|certificates| {
        certificates.into_iter().all(|der| {
            webpki::anchor_from_trusted_cert(&CertificateDer::from(der.clone())).is_ok()
                && X509Certificate::from_der(&der).is_ok_and(|(remainder, certificate)| {
                    remainder.is_empty()
                        && certificate.basic_constraints().is_ok_and(|constraints| {
                            constraints.is_some_and(|value| value.value.ca)
                        })
                        && certificate.key_usage().is_ok_and(|usage| {
                            usage.is_some_and(|value| value.value.key_cert_sign())
                        })
                })
        })
    })
}

pub(crate) fn certificate_bundle_der(value: &str) -> Option<Vec<Vec<u8>>> {
    let mut remaining = value.as_bytes();
    let mut certificates = Vec::new();
    loop {
        let after_begin = remaining.strip_prefix(PEM_CERTIFICATE_BEGIN)?;
        let end_offset = after_begin
            .windows(PEM_CERTIFICATE_END.len())
            .position(|window| window == PEM_CERTIFICATE_END)?;
        let block_len = PEM_CERTIFICATE_BEGIN.len() + end_offset + PEM_CERTIFICATE_END.len();
        let block = &remaining[..block_len];
        let (label, der) = pem_rfc7468::decode_vec(block).ok()?;
        if label != "CERTIFICATE" {
            return None;
        }
        certificates.push(der);
        remaining = &remaining[block_len..];
        if remaining.is_empty() {
            return Some(certificates);
        }
        remaining = if let Some(rest) = remaining.strip_prefix(b"\r\n") {
            rest
        } else {
            remaining.strip_prefix(b"\n")?
        };
    }
}

/// Verify certificate signature families not handled by x509-parser's generic verifier.
pub(crate) fn verify_certificate_signature_with_algorithm_fallback(
    signature_oid: &str,
    public_key_oid: &str,
    public_key_curve_oid: Option<&str>,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    if signature_oid == public_key_oid
        && verify_slh_dsa_signature_by_oid!(signature_oid, public_key, message, signature, {
            "2.16.840.1.101.3.4.3.20" => slh_dsa_sha2_128s,
            "2.16.840.1.101.3.4.3.21" => slh_dsa_sha2_128f,
            "2.16.840.1.101.3.4.3.22" => slh_dsa_sha2_192s,
            "2.16.840.1.101.3.4.3.23" => slh_dsa_sha2_192f,
            "2.16.840.1.101.3.4.3.24" => slh_dsa_sha2_256s,
            "2.16.840.1.101.3.4.3.25" => slh_dsa_sha2_256f,
            "2.16.840.1.101.3.4.3.26" => slh_dsa_shake_128s,
            "2.16.840.1.101.3.4.3.27" => slh_dsa_shake_128f,
            "2.16.840.1.101.3.4.3.28" => slh_dsa_shake_192s,
            "2.16.840.1.101.3.4.3.29" => slh_dsa_shake_192f,
            "2.16.840.1.101.3.4.3.30" => slh_dsa_shake_256s,
            "2.16.840.1.101.3.4.3.31" => slh_dsa_shake_256f,
        })
    {
        return true;
    }
    let algorithm: Option<&'static dyn VerificationAlgorithm> = match signature_oid {
        "1.2.840.10045.4.3.4"
            if public_key_oid == "1.2.840.10045.2.1"
                && public_key_curve_oid == Some("1.3.132.0.35") =>
        {
            Some(&ECDSA_P521_SHA512_ASN1)
        }
        "2.16.840.1.101.3.4.3.17" if public_key_oid == signature_oid => Some(&ML_DSA_44),
        "2.16.840.1.101.3.4.3.18" if public_key_oid == signature_oid => Some(&ML_DSA_65),
        "2.16.840.1.101.3.4.3.19" if public_key_oid == signature_oid => Some(&ML_DSA_87),
        _ => None,
    };
    algorithm.is_some_and(|algorithm| {
        UnparsedPublicKey::new(algorithm, public_key)
            .verify(message, signature)
            .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use fips205::traits::{KeyGen, SerDes, Signer};

    use super::verify_certificate_signature_with_algorithm_fallback;

    #[test]
    fn slh_dsa_fallback_verifies_only_the_matching_signature() {
        const OID: &str = "2.16.840.1.101.3.4.3.21";
        let message = b"certificate tbs bytes";
        let (public_key, private_key) = fips205::slh_dsa_sha2_128f::KG::keygen_with_seeds(
            &[1; fips205::slh_dsa_sha2_128f::N],
            &[2; fips205::slh_dsa_sha2_128f::N],
            &[3; fips205::slh_dsa_sha2_128f::N],
        );
        let public_key = public_key.into_bytes();
        let signature = private_key.try_sign(message, b"", false).unwrap();
        assert!(verify_certificate_signature_with_algorithm_fallback(
            OID,
            OID,
            None,
            &public_key,
            message,
            &signature,
        ));

        let mut corrupted_signature = signature;
        corrupted_signature[0] ^= 1;
        assert!(!verify_certificate_signature_with_algorithm_fallback(
            OID,
            OID,
            None,
            &public_key,
            message,
            &corrupted_signature,
        ));
        assert!(!verify_certificate_signature_with_algorithm_fallback(
            OID,
            "2.16.840.1.101.3.4.3.20",
            None,
            &public_key,
            message,
            &signature,
        ));
    }
}
