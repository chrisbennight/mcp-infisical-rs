use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{
    signature::{ECDSA_P521_SHA512_ASN1, UnparsedPublicKey, VerificationAlgorithm},
    unstable::signature::{ML_DSA_44, ML_DSA_65, ML_DSA_87},
};
use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509CertificationRequest, parse_x509_crl};

use crate::{
    CertificateAuthorityId, CertificateAuthorityProjectId, CertificateAuthorityStatus,
    InfisicalClient, InternalCertificateAuthority, InternalCertificateAuthorityType,
    MutationOperation, ObservableReadOperation, ResourceError,
    certificate::{is_valid_ca_signing_certificate_bundle, normalize_pem},
    client::{ApiVersion, Endpoint, sealed},
    resources::{is_bounded_text, is_uuid, utc_timestamp_millis},
};

const MAX_CERTIFICATE_PEM_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATE_CHAIN_PEM_BYTES: usize = 512 * 1024;
const MAX_CSR_PEM_BYTES: usize = 16 * 1024;
const MAX_CRL_PEM_BYTES: usize = 512 * 1024;
const MAX_CA_CERTIFICATES: usize = 500;
const MAX_CA_CRLS: usize = 500;
const MAX_SERIAL_NUMBER_BYTES: usize = 128;

/// Input validation failures for internal-CA certificate operations.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CertificateAuthorityCertificateInputError {
    #[error("certificate validity timestamps must be RFC 3339 UTC timestamps")]
    InvalidValidity,
    #[error("certificate validity must end after it begins")]
    InvalidValidityOrder,
    #[error("certificate not-after must be in the future")]
    NotAfterNotFuture,
    #[error("certificate maximum path length must be between -1 and 100")]
    InvalidMaxPathLength,
    #[error("the parent certificate authority must differ from the target authority")]
    ParentMatchesTarget,
    #[error("CSR must be one bounded PKCS #10 PEM block")]
    InvalidCsr,
    #[error("certificate and chain must be bounded CA certificate PEM bundles")]
    InvalidCertificatePem,
}

/// One validated CSR retained by an internal CA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CertificateAuthorityCsr {
    /// PKCS #10 PEM document.
    pub csr: String,
}

/// Validated CA certificate material and version metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateAuthorityCertificate {
    /// PEM-encoded CA certificate.
    pub certificate: String,
    /// PEM-encoded issuer chain, or an empty string when upstream has no chain.
    pub certificate_chain: String,
    /// Bounded hexadecimal serial number.
    pub serial_number: String,
    /// Canonical CA certificate UUID.
    pub certificate_id: String,
    /// Validity start for a historical certificate when returned upstream.
    pub not_before: Option<String>,
    /// Validity end for a historical certificate when returned upstream.
    pub not_after: Option<String>,
    /// Historical basic-constraints path length when returned upstream.
    pub max_path_length: Option<i16>,
    /// Canonical parent CA UUID for an intermediate certificate.
    pub parent_ca_id: Option<String>,
    /// Monotonic CA certificate version returned by history listings.
    pub version: Option<u32>,
}

/// One CRL retained by an internal CA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CertificateAuthorityCrl {
    /// Canonical CRL UUID.
    pub id: String,
    /// PEM-encoded X.509 certificate revocation list.
    pub crl: String,
}

/// Result of signing an intermediate-CA CSR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateAuthoritySignedIntermediate {
    /// PEM-encoded signed intermediate certificate.
    pub certificate: String,
    /// PEM-encoded issuer chain.
    pub certificate_chain: String,
    /// PEM-encoded certificate for the signing CA.
    pub issuing_ca_certificate: String,
    /// Bounded hexadecimal serial number.
    pub serial_number: String,
}

/// Receipt proving that certificate material was imported into the requested CA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateAuthorityImportReceipt {
    /// Canonical target CA UUID.
    pub ca_id: String,
    /// Stable upstream success message.
    pub message: String,
}

/// Complete validated input for generating a root or intermediate CA certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthorityCertificateGeneration {
    not_before: String,
    not_after: String,
    max_path_length: i16,
    parent_ca_id: Option<CertificateAuthorityId>,
}

impl CertificateAuthorityCertificateGeneration {
    /// Validate explicit certificate dates, path length, and optional parent CA.
    ///
    /// # Errors
    ///
    /// Returns an error when the certificate constraints are incoherent.
    pub fn new(
        target_ca_id: &CertificateAuthorityId,
        not_before: impl Into<String>,
        not_after: impl Into<String>,
        max_path_length: i16,
        parent_ca_id: Option<CertificateAuthorityId>,
    ) -> Result<Self, CertificateAuthorityCertificateInputError> {
        let not_before = not_before.into();
        let not_after = not_after.into();
        validate_validity(Some(&not_before), &not_after)?;
        validate_path_length(max_path_length)?;
        if parent_ca_id.as_ref() == Some(target_ca_id) {
            return Err(CertificateAuthorityCertificateInputError::ParentMatchesTarget);
        }
        Ok(Self {
            not_before,
            not_after,
            max_path_length,
            parent_ca_id,
        })
    }
}

/// Complete validated input for renewing the active CA certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthorityCertificateRenewal {
    not_after: String,
}

impl CertificateAuthorityCertificateRenewal {
    /// Validate a future renewal boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when `not_after` is not a future RFC 3339 UTC timestamp.
    pub fn new(
        not_after: impl Into<String>,
    ) -> Result<Self, CertificateAuthorityCertificateInputError> {
        let not_after = not_after.into();
        validate_validity(None, &not_after)?;
        Ok(Self { not_after })
    }
}

/// Complete validated input for signing an intermediate-CA CSR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthoritySigningRequest {
    csr: String,
    not_before: Option<String>,
    not_after: String,
    max_path_length: i16,
}

impl CertificateAuthoritySigningRequest {
    /// Validate a bounded PKCS #10 request and resulting certificate constraints.
    ///
    /// # Errors
    ///
    /// Returns an error when the CSR or certificate constraints are invalid.
    pub fn new(
        csr: impl Into<String>,
        not_before: Option<String>,
        not_after: impl Into<String>,
        max_path_length: i16,
    ) -> Result<Self, CertificateAuthorityCertificateInputError> {
        let csr = csr.into();
        let csr =
            normalize_pem(&csr).ok_or(CertificateAuthorityCertificateInputError::InvalidCsr)?;
        let not_after = not_after.into();
        if !is_valid_csr(&csr) {
            return Err(CertificateAuthorityCertificateInputError::InvalidCsr);
        }
        validate_validity(not_before.as_deref(), &not_after)?;
        validate_path_length(max_path_length)?;
        Ok(Self {
            csr,
            not_before,
            not_after,
            max_path_length,
        })
    }
}

/// Complete validated certificate material imported into an internal CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthorityCertificateImport {
    certificate: String,
    certificate_chain: String,
}

impl CertificateAuthorityCertificateImport {
    /// Validate one CA certificate and its non-empty issuer chain.
    ///
    /// # Errors
    ///
    /// Returns an error when either PEM value violates the bounded CA contract.
    pub fn new(
        certificate: impl Into<String>,
        certificate_chain: impl Into<String>,
    ) -> Result<Self, CertificateAuthorityCertificateInputError> {
        let certificate = certificate.into();
        let certificate = normalize_pem(&certificate)
            .ok_or(CertificateAuthorityCertificateInputError::InvalidCertificatePem)?;
        let certificate_chain = certificate_chain.into();
        let certificate_chain = normalize_pem(&certificate_chain)
            .ok_or(CertificateAuthorityCertificateInputError::InvalidCertificatePem)?;
        if !is_valid_single_certificate(&certificate)
            || !is_valid_certificate_chain(&certificate_chain)
        {
            return Err(CertificateAuthorityCertificateInputError::InvalidCertificatePem);
        }
        Ok(Self {
            certificate,
            certificate_chain,
        })
    }
}

fn validate_validity(
    not_before: Option<&str>,
    not_after: &str,
) -> Result<(), CertificateAuthorityCertificateInputError> {
    let before = not_before
        .map(|value| {
            utc_timestamp_millis(value)
                .ok_or(CertificateAuthorityCertificateInputError::InvalidValidity)
        })
        .transpose()?;
    let after = utc_timestamp_millis(not_after)
        .ok_or(CertificateAuthorityCertificateInputError::InvalidValidity)?;
    if before.is_some_and(|before| after <= before) {
        return Err(CertificateAuthorityCertificateInputError::InvalidValidityOrder);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .and_then(|millis| utc_timestamp_millis("1970-01-01T00:00:00Z")?.checked_add(millis))
        .ok_or(CertificateAuthorityCertificateInputError::InvalidValidity)?;
    if after <= now {
        return Err(CertificateAuthorityCertificateInputError::NotAfterNotFuture);
    }
    Ok(())
}

fn validate_path_length(value: i16) -> Result<(), CertificateAuthorityCertificateInputError> {
    if !(-1..=100).contains(&value) {
        return Err(CertificateAuthorityCertificateInputError::InvalidMaxPathLength);
    }
    Ok(())
}

fn is_valid_single_certificate(value: &str) -> bool {
    is_bounded_pem(value, MAX_CERTIFICATE_PEM_BYTES)
        && value.matches("-----BEGIN CERTIFICATE-----").count() == 1
        && value.matches("-----END CERTIFICATE-----").count() == 1
        && is_valid_ca_signing_certificate_bundle(value)
}

fn is_bounded_pem(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && value.trim() == value
}

fn is_within_collection_limit(length: usize, maximum: usize) -> bool {
    length <= maximum
}

fn has_active_certificate(
    status: CertificateAuthorityStatus,
    active_certificate_id: Option<&str>,
) -> bool {
    status == CertificateAuthorityStatus::Active && active_certificate_id.is_some()
}

fn awaits_initial_certificate(authority: &InternalCertificateAuthority) -> bool {
    authority.status == CertificateAuthorityStatus::PendingCertificate
        && authority.configuration.active_ca_certificate_id.is_none()
}

fn is_valid_certificate_chain(value: &str) -> bool {
    is_bounded_pem(value, MAX_CERTIFICATE_CHAIN_PEM_BYTES)
        && is_valid_ca_signing_certificate_bundle(value)
}

pub(crate) fn is_valid_csr(value: &str) -> bool {
    if !is_bounded_pem(value, MAX_CSR_PEM_BYTES) {
        return false;
    }
    pem_rfc7468::decode_vec(value.as_bytes()).is_ok_and(|(label, der)| {
        matches!(label, "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST")
            && X509CertificationRequest::from_der(&der).is_ok_and(|(remainder, request)| {
                remainder.is_empty() && verify_csr_signature(&request)
            })
    })
}

fn verify_csr_signature(request: &X509CertificationRequest<'_>) -> bool {
    if request.signature_value.unused_bits != 0 {
        return false;
    }
    let signature_oid = request.signature_algorithm.algorithm.to_id_string();
    let public_key = &request.certification_request_info.subject_pki;
    let public_key_oid = public_key.algorithm.algorithm.to_id_string();
    let post_quantum_algorithm: Option<&'static dyn VerificationAlgorithm> =
        match signature_oid.as_str() {
            "2.16.840.1.101.3.4.3.17" => Some(&ML_DSA_44),
            "2.16.840.1.101.3.4.3.18" => Some(&ML_DSA_65),
            "2.16.840.1.101.3.4.3.19" => Some(&ML_DSA_87),
            _ => None,
        };
    if let Some(algorithm) = post_quantum_algorithm {
        if signature_oid != public_key_oid {
            return false;
        }
        return verify_csr_with_algorithm(request, algorithm, public_key.raw);
    }
    if signature_oid == "1.2.840.10045.4.3.4" {
        return verify_csr_with_algorithm(
            request,
            &ECDSA_P521_SHA512_ASN1,
            &public_key.subject_public_key.data,
        );
    }
    request.verify_signature().is_ok()
}

fn verify_csr_with_algorithm(
    request: &X509CertificationRequest<'_>,
    algorithm: &'static dyn VerificationAlgorithm,
    public_key: &[u8],
) -> bool {
    UnparsedPublicKey::new(algorithm, public_key)
        .verify(
            request.certification_request_info.raw,
            &request.signature_value.data,
        )
        .is_ok()
}

fn is_valid_crl(value: &str) -> bool {
    is_bounded_pem(value, MAX_CRL_PEM_BYTES)
        && pem_rfc7468::decode_vec(value.as_bytes()).is_ok_and(|(label, der)| {
            label == "X509 CRL"
                && parse_x509_crl(&der).is_ok_and(|(remainder, _)| remainder.is_empty())
        })
}

#[derive(Serialize)]
struct CaTarget {
    #[serde(skip_serializing)]
    ca_id: CertificateAuthorityId,
}

#[derive(Serialize)]
struct CaCertificateTarget {
    #[serde(skip_serializing)]
    ca_id: CertificateAuthorityId,
    #[serde(skip_serializing)]
    certificate_id: CertificateAuthorityId,
}

#[derive(Deserialize)]
struct CsrWire {
    csr: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateWire {
    certificate: String,
    certificate_chain: String,
    serial_number: String,
    #[serde(rename = "certId")]
    certificate_id: String,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
    #[serde(default)]
    max_path_length: Option<i16>,
    #[serde(default)]
    parent_ca_id: Option<String>,
    #[serde(default)]
    version: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedIntermediateWire {
    certificate: String,
    certificate_chain: String,
    issuing_ca_certificate: String,
    serial_number: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportReceiptWire {
    message: String,
    ca_id: String,
}

#[derive(Deserialize)]
struct CrlWire {
    id: String,
    crl: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerateCertificateRequest {
    #[serde(skip_serializing)]
    ca_id: CertificateAuthorityId,
    not_before: String,
    not_after: String,
    max_path_length: i16,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_ca_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RenewCertificateRequest {
    #[serde(skip_serializing)]
    ca_id: CertificateAuthorityId,
    #[serde(rename = "type")]
    renewal_type: &'static str,
    not_after: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignIntermediateRequest {
    #[serde(skip_serializing)]
    ca_id: CertificateAuthorityId,
    csr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<String>,
    not_after: String,
    max_path_length: i16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportCertificateRequest {
    #[serde(skip_serializing)]
    ca_id: CertificateAuthorityId,
    certificate: String,
    certificate_chain: String,
}

macro_rules! ca_read {
    ($operation:ident, $query:ty, $output:ty, $suffix:expr) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl ObservableReadOperation for $operation {
            type Query = $query;
            type Output = $output;

            fn endpoint(query: &Self::Query) -> Endpoint {
                let mut segments = vec![
                    "cert-manager".to_owned(),
                    "ca".to_owned(),
                    "internal".to_owned(),
                    query.ca_id.as_str().to_owned(),
                ];
                segments.extend(($suffix)(query));
                Endpoint::from_segments(ApiVersion::V1, segments)
            }
        }
    };
}

ca_read!(GetCaCsr, CaTarget, CsrWire, |_query: &CaTarget| vec![
    "csr".to_owned()
]);
ca_read!(
    ListCaCertificates,
    CaTarget,
    Vec<CertificateWire>,
    |_query: &CaTarget| vec!["ca-certificates".to_owned()]
);
ca_read!(
    GetCurrentCaCertificate,
    CaTarget,
    CertificateWire,
    |_query: &CaTarget| vec!["certificate".to_owned()]
);
ca_read!(
    GetCaCertificateVersion,
    CaCertificateTarget,
    CertificateWire,
    |query: &CaCertificateTarget| vec![
        "certificate".to_owned(),
        query.certificate_id.as_str().to_owned()
    ]
);
ca_read!(
    ListCaCrls,
    CaTarget,
    Vec<CrlWire>,
    |_query: &CaTarget| vec!["crls".to_owned()]
);

macro_rules! ca_mutation {
    ($operation:ident, $input:ty, $output:ty, $suffix:expr) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl MutationOperation for $operation {
            type Input = $input;
            type Output = $output;

            fn method() -> Method {
                Method::POST
            }

            fn endpoint(input: &Self::Input) -> Endpoint {
                Endpoint::from_segments(
                    ApiVersion::V1,
                    [
                        "cert-manager",
                        "ca",
                        "internal",
                        input.ca_id.as_str(),
                        $suffix,
                    ],
                )
            }
        }
    };
}

ca_mutation!(
    GenerateCaCertificate,
    GenerateCertificateRequest,
    CertificateWire,
    "certificate"
);
ca_mutation!(
    RenewCaCertificate,
    RenewCertificateRequest,
    CertificateWire,
    "renew"
);
ca_mutation!(
    SignIntermediateCa,
    SignIntermediateRequest,
    SignedIntermediateWire,
    "sign-intermediate"
);
ca_mutation!(
    ImportCaCertificate,
    ImportCertificateRequest,
    ImportReceiptWire,
    "import-certificate"
);

fn certificate_from_wire(
    wire: CertificateWire,
) -> Result<CertificateAuthorityCertificate, ResourceError> {
    let certificate = normalize_pem(&wire.certificate)
        .ok_or(ResourceError::InvalidCertificateAuthorityResponse)?;
    let certificate_chain = if wire.certificate_chain.is_empty() {
        String::new()
    } else {
        normalize_pem(&wire.certificate_chain)
            .ok_or(ResourceError::InvalidCertificateAuthorityResponse)?
    };
    if !is_valid_single_certificate(&certificate)
        || (!certificate_chain.is_empty() && !is_valid_certificate_chain(&certificate_chain))
        || !is_bounded_text(&wire.serial_number, MAX_SERIAL_NUMBER_BYTES)
        || !wire
            .serial_number
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ResourceError::InvalidCertificateAuthorityResponse);
    }
    let certificate_id = CertificateAuthorityId::new(wire.certificate_id)
        .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
    let not_before = wire.not_before;
    let not_after = wire.not_after;
    if not_before
        .as_deref()
        .is_some_and(|value| utc_timestamp_millis(value).is_none())
        || not_after
            .as_deref()
            .is_some_and(|value| utc_timestamp_millis(value).is_none())
        || not_before
            .as_deref()
            .zip(not_after.as_deref())
            .is_some_and(|(before, after)| {
                utc_timestamp_millis(before) >= utc_timestamp_millis(after)
            })
        || wire
            .max_path_length
            .is_some_and(|value| !(-1..=100).contains(&value))
        || wire.version == Some(0)
    {
        return Err(ResourceError::InvalidCertificateAuthorityResponse);
    }
    let parent_ca_id = wire
        .parent_ca_id
        .map(CertificateAuthorityId::new)
        .transpose()
        .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?
        .map(|id| id.as_str().to_owned());
    Ok(CertificateAuthorityCertificate {
        certificate,
        certificate_chain,
        serial_number: wire.serial_number,
        certificate_id: certificate_id.as_str().to_owned(),
        not_before,
        not_after,
        max_path_length: wire.max_path_length,
        parent_ca_id,
        version: wire.version,
    })
}

fn signed_intermediate_from_wire(
    wire: SignedIntermediateWire,
) -> Result<CertificateAuthoritySignedIntermediate, ResourceError> {
    let certificate = normalize_pem(&wire.certificate)
        .ok_or(ResourceError::InvalidCertificateAuthorityResponse)?;
    let certificate_chain = normalize_pem(&wire.certificate_chain)
        .ok_or(ResourceError::InvalidCertificateAuthorityResponse)?;
    let issuing_ca_certificate = normalize_pem(&wire.issuing_ca_certificate)
        .ok_or(ResourceError::InvalidCertificateAuthorityResponse)?;
    if !is_valid_single_certificate(&certificate)
        || !is_valid_certificate_chain(&certificate_chain)
        || !is_valid_single_certificate(&issuing_ca_certificate)
        || !is_bounded_text(&wire.serial_number, MAX_SERIAL_NUMBER_BYTES)
        || !wire
            .serial_number
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ResourceError::InvalidCertificateAuthorityResponse);
    }
    Ok(CertificateAuthoritySignedIntermediate {
        certificate,
        certificate_chain,
        issuing_ca_certificate,
        serial_number: wire.serial_number,
    })
}

fn crl_from_wire(wire: &CrlWire) -> Result<CertificateAuthorityCrl, ResourceError> {
    let crl = normalize_pem(&wire.crl).ok_or(ResourceError::InvalidCertificateAuthorityResponse)?;
    if !is_uuid(&wire.id) || !is_valid_crl(&crl) {
        return Err(ResourceError::InvalidCertificateAuthorityResponse);
    }
    Ok(CertificateAuthorityCrl {
        id: wire.id.to_ascii_lowercase(),
        crl,
    })
}

fn import_receipt_from_wire(
    wire: ImportReceiptWire,
    ca_id: &CertificateAuthorityId,
) -> Result<CertificateAuthorityImportReceipt, ResourceError> {
    let response_ca_id = CertificateAuthorityId::new(wire.ca_id)
        .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
    if &response_ca_id != ca_id || wire.message != "Successfully imported certificate to CA" {
        return Err(ResourceError::InvalidCertificateAuthorityResponse);
    }
    Ok(CertificateAuthorityImportReceipt {
        ca_id: response_ca_id.as_str().to_owned(),
        message: wire.message,
    })
}

impl InfisicalClient {
    async fn ensure_internal_ca_scope(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
    ) -> Result<InternalCertificateAuthority, ResourceError> {
        self.get_internal_certificate_authority(project_id, ca_id)
            .await
    }

    /// Retrieve the bounded CSR for one exact internal CA.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or bounded-response error.
    pub async fn get_internal_ca_csr(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
    ) -> Result<CertificateAuthorityCsr, ResourceError> {
        self.ensure_internal_ca_scope(project_id, ca_id).await?;
        let response = self
            .execute_observable_read::<GetCaCsr>(&CaTarget {
                ca_id: ca_id.clone(),
            })
            .await?;
        let csr = normalize_pem(&response.csr)
            .ok_or(ResourceError::InvalidCertificateAuthorityResponse)?;
        if !is_valid_csr(&csr) {
            return Err(ResourceError::InvalidCertificateAuthorityResponse);
        }
        Ok(CertificateAuthorityCsr { csr })
    }

    /// List the bounded certificate history for one exact internal CA.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or bounded-response error.
    pub async fn list_internal_ca_certificates(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
    ) -> Result<Vec<CertificateAuthorityCertificate>, ResourceError> {
        self.ensure_internal_ca_scope(project_id, ca_id).await?;
        let response = self
            .execute_observable_read::<ListCaCertificates>(&CaTarget {
                ca_id: ca_id.clone(),
            })
            .await?;
        if !is_within_collection_limit(response.len(), MAX_CA_CERTIFICATES) {
            return Err(ResourceError::InvalidCertificateAuthorityResponse);
        }
        let certificates = response
            .into_iter()
            .map(certificate_from_wire)
            .collect::<Result<Vec<_>, _>>()?;
        if certificates
            .iter()
            .any(|certificate| certificate.version.is_none())
            || certificates
                .iter()
                .map(|certificate| certificate.certificate_id.as_str())
                .collect::<HashSet<_>>()
                .len()
                != certificates.len()
            || certificates
                .iter()
                .filter_map(|certificate| certificate.version)
                .collect::<HashSet<_>>()
                .len()
                != certificates.len()
        {
            return Err(ResourceError::InvalidCertificateAuthorityResponse);
        }
        Ok(certificates)
    }

    /// Retrieve the active certificate for one exact internal CA.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or bounded-response error.
    pub async fn get_internal_ca_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
    ) -> Result<CertificateAuthorityCertificate, ResourceError> {
        let authority = self.ensure_internal_ca_scope(project_id, ca_id).await?;
        let response = self
            .execute_observable_read::<GetCurrentCaCertificate>(&CaTarget {
                ca_id: ca_id.clone(),
            })
            .await?;
        let certificate = certificate_from_wire(response)?;
        if authority.configuration.active_ca_certificate_id.as_deref()
            != Some(certificate.certificate_id.as_str())
        {
            return Err(ResourceError::InvalidCertificateAuthorityScope);
        }
        Ok(certificate)
    }

    /// Retrieve one historical certificate for one exact internal CA.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or certificate-identity error.
    pub async fn get_internal_ca_certificate_version(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
        certificate_id: &CertificateAuthorityId,
    ) -> Result<CertificateAuthorityCertificate, ResourceError> {
        self.ensure_internal_ca_scope(project_id, ca_id).await?;
        let response = self
            .execute_observable_read::<GetCaCertificateVersion>(&CaCertificateTarget {
                ca_id: ca_id.clone(),
                certificate_id: certificate_id.clone(),
            })
            .await?;
        let certificate = certificate_from_wire(response)?;
        if certificate.certificate_id != certificate_id.as_str() {
            return Err(ResourceError::InvalidCertificateAuthorityScope);
        }
        Ok(certificate)
    }

    /// List bounded PEM CRLs for one exact internal CA.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or bounded-response error.
    pub async fn list_internal_ca_crls(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
    ) -> Result<Vec<CertificateAuthorityCrl>, ResourceError> {
        self.ensure_internal_ca_scope(project_id, ca_id).await?;
        let response = self
            .execute_observable_read::<ListCaCrls>(&CaTarget {
                ca_id: ca_id.clone(),
            })
            .await?;
        if !is_within_collection_limit(response.len(), MAX_CA_CRLS) {
            return Err(ResourceError::InvalidCertificateAuthorityResponse);
        }
        let crls = response
            .iter()
            .map(crl_from_wire)
            .collect::<Result<Vec<_>, _>>()?;
        if crls
            .iter()
            .map(|crl| crl.id.as_str())
            .collect::<HashSet<_>>()
            .len()
            != crls.len()
        {
            return Err(ResourceError::InvalidCertificateAuthorityResponse);
        }
        Ok(crls)
    }

    /// Generate and install a root or intermediate certificate exactly once after scope preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or bounded-response error.
    pub async fn generate_internal_ca_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
        generation: CertificateAuthorityCertificateGeneration,
        confirm: bool,
    ) -> Result<CertificateAuthorityCertificate, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateAuthorityCertificateMutationNotConfirmed);
        }
        let target = self.ensure_internal_ca_scope(project_id, ca_id).await?;
        if !awaits_initial_certificate(&target) {
            return Err(ResourceError::InvalidCertificateAuthorityCertificateState);
        }
        match (
            target.configuration.ca_type,
            generation.parent_ca_id.as_ref(),
        ) {
            (InternalCertificateAuthorityType::Root, None) => {}
            (InternalCertificateAuthorityType::Intermediate, Some(parent_ca_id)) => {
                let parent = self
                    .ensure_internal_ca_scope(project_id, parent_ca_id)
                    .await?;
                if !has_active_certificate(
                    parent.status,
                    parent.configuration.active_ca_certificate_id.as_deref(),
                ) {
                    return Err(ResourceError::InvalidCertificateAuthorityCertificateState);
                }
            }
            _ => return Err(ResourceError::InvalidCertificateAuthorityCertificateState),
        }
        let response = self
            .execute_mutation::<GenerateCaCertificate>(&GenerateCertificateRequest {
                ca_id: ca_id.clone(),
                not_before: generation.not_before,
                not_after: generation.not_after,
                max_path_length: generation.max_path_length,
                parent_ca_id: generation.parent_ca_id.map(|id| id.as_str().to_owned()),
            })
            .await?;
        certificate_from_wire(response)
    }

    /// Renew the active certificate exactly once after scope preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or bounded-response error.
    pub async fn renew_internal_ca_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
        renewal: CertificateAuthorityCertificateRenewal,
        confirm: bool,
    ) -> Result<CertificateAuthorityCertificate, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateAuthorityCertificateMutationNotConfirmed);
        }
        let authority = self.ensure_internal_ca_scope(project_id, ca_id).await?;
        if !has_active_certificate(
            authority.status,
            authority.configuration.active_ca_certificate_id.as_deref(),
        ) {
            return Err(ResourceError::InvalidCertificateAuthorityCertificateState);
        }
        let response = self
            .execute_mutation::<RenewCaCertificate>(&RenewCertificateRequest {
                ca_id: ca_id.clone(),
                renewal_type: "existing",
                not_after: renewal.not_after,
            })
            .await?;
        certificate_from_wire(response)
    }

    /// Sign an intermediate CSR exactly once after signer scope preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or bounded-response error.
    pub async fn sign_internal_ca_intermediate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
        request: CertificateAuthoritySigningRequest,
        confirm: bool,
    ) -> Result<CertificateAuthoritySignedIntermediate, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateAuthorityCertificateMutationNotConfirmed);
        }
        let authority = self.ensure_internal_ca_scope(project_id, ca_id).await?;
        if !has_active_certificate(
            authority.status,
            authority.configuration.active_ca_certificate_id.as_deref(),
        ) {
            return Err(ResourceError::InvalidCertificateAuthorityCertificateState);
        }
        let response = self
            .execute_mutation::<SignIntermediateCa>(&SignIntermediateRequest {
                ca_id: ca_id.clone(),
                csr: request.csr,
                not_before: request.not_before,
                not_after: request.not_after,
                max_path_length: request.max_path_length,
            })
            .await?;
        signed_intermediate_from_wire(response)
    }

    /// Import CA certificate material exactly once after target scope preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-identity error.
    pub async fn import_internal_ca_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
        import: CertificateAuthorityCertificateImport,
        confirm: bool,
    ) -> Result<CertificateAuthorityImportReceipt, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateAuthorityCertificateMutationNotConfirmed);
        }
        let authority = self.ensure_internal_ca_scope(project_id, ca_id).await?;
        if !awaits_initial_certificate(&authority) {
            return Err(ResourceError::InvalidCertificateAuthorityCertificateState);
        }
        let response = self
            .execute_mutation::<ImportCaCertificate>(&ImportCertificateRequest {
                ca_id: ca_id.clone(),
                certificate: import.certificate,
                certificate_chain: import.certificate_chain,
            })
            .await?;
        import_receipt_from_wire(response, ca_id)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    use super::*;
    use crate::test_support::{CA_CERT, mount_login, settings};

    const PROJECT_ID: &str = "22222222-2222-4222-8222-222222222222";
    const CA_ID: &str = "11111111-1111-4111-8111-111111111111";
    const PARENT_CA_ID: &str = "33333333-3333-4333-8333-333333333333";
    const CERTIFICATE_ID: &str = "44444444-4444-4444-8444-444444444444";
    const CRL_ID: &str = "55555555-5555-4555-8555-555555555555";

    fn csr_fixture() -> &'static str {
        include_str!("../test-fixtures/ca-csr.txt")
            .strip_suffix('\n')
            .expect("CSR fixture must have one final line feed")
    }

    fn ml_dsa_csr_fixture() -> &'static str {
        include_str!("../test-fixtures/ml-dsa-44-csr.txt")
            .strip_suffix('\n')
            .expect("ML-DSA CSR fixture must have one final line feed")
    }

    fn ml_dsa_65_csr_fixture() -> &'static str {
        include_str!("../test-fixtures/ml-dsa-65-csr.txt")
            .strip_suffix('\n')
            .expect("ML-DSA-65 CSR fixture must have one final line feed")
    }

    fn ml_dsa_87_csr_fixture() -> &'static str {
        include_str!("../test-fixtures/ml-dsa-87-csr.txt")
            .strip_suffix('\n')
            .expect("ML-DSA-87 CSR fixture must have one final line feed")
    }

    fn p521_csr_fixture() -> &'static str {
        include_str!("../test-fixtures/p521-csr.txt")
            .strip_suffix('\n')
            .expect("P-521 CSR fixture must have one final line feed")
    }

    fn end_entity_certificate_fixture() -> &'static str {
        include_str!("../test-fixtures/end-entity-cert.txt")
            .strip_suffix('\n')
            .expect("end-entity certificate fixture must have one final line feed")
    }

    fn ca_without_key_cert_sign_fixture() -> &'static str {
        include_str!("../test-fixtures/ca-without-keycertsign.txt")
            .strip_suffix('\n')
            .expect("CA certificate fixture must have one final line feed")
    }

    fn corrupt_pem_signature(value: &str) -> String {
        let (label, mut der) = pem_rfc7468::decode_vec(value.as_bytes()).unwrap();
        *der.last_mut().expect("fixture DER must be non-empty") ^= 1;
        pem_rfc7468::encode_string(label, pem_rfc7468::LineEnding::LF, &der)
            .unwrap()
            .strip_suffix('\n')
            .unwrap()
            .to_owned()
    }

    fn append_der_trailing_data(value: &str) -> String {
        let (label, mut der) = pem_rfc7468::decode_vec(value.as_bytes()).unwrap();
        der.push(0);
        pem_rfc7468::encode_string(label, pem_rfc7468::LineEnding::LF, &der)
            .unwrap()
            .strip_suffix('\n')
            .unwrap()
            .to_owned()
    }

    fn crl_fixture() -> &'static str {
        include_str!("../test-fixtures/ca-crl.txt")
            .strip_suffix('\n')
            .expect("CRL fixture must have one final line feed")
    }

    fn ca_value(ca_id: &str) -> serde_json::Value {
        let ca_type = if ca_id == CA_ID {
            "intermediate"
        } else {
            "root"
        };
        json!({
            "id": ca_id,
            "projectId": PROJECT_ID,
            "name": "root-ca",
            "type": "internal",
            "status": "active",
            "enableDirectIssuance": false,
            "configuration": {
                "type": ca_type,
                "commonName": "Root CA",
                "keyAlgorithm": "RSA_2048",
                "activeCaCertId": CERTIFICATE_ID,
                "crlDistributionPointUrls": [],
                "disableManagedCrlDistributionPointUrl": false
            }
        })
    }

    fn pending_ca_value(ca_id: &str) -> serde_json::Value {
        let mut authority = ca_value(ca_id);
        authority["status"] = json!("pending-certificate");
        authority["configuration"]["activeCaCertId"] = serde_json::Value::Null;
        authority
    }

    fn certificate_value() -> serde_json::Value {
        json!({
            "certificate": format!("{CA_CERT}\n"),
            "certificateChain": format!("{CA_CERT}\r\n"),
            "serialNumber": "01ab",
            "certId": CERTIFICATE_ID
        })
    }

    fn certificate_wire() -> CertificateWire {
        serde_json::from_value(certificate_value()).expect("valid certificate wire fixture")
    }

    fn signed_intermediate_wire() -> SignedIntermediateWire {
        serde_json::from_value(json!({
            "certificate": CA_CERT,
            "certificateChain": CA_CERT,
            "issuingCaCertificate": CA_CERT,
            "serialNumber": "02cd"
        }))
        .expect("valid signed intermediate wire fixture")
    }

    async fn mount_scope(server: &MockServer, ca_id: &str, count: u64) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/cert-manager/ca/internal/{ca_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(ca_value(ca_id)))
            .expect(count)
            .mount(server)
            .await;
    }

    async fn mount_scope_response(server: &MockServer, response: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/cert-manager/ca/internal/{CA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_ca_crls(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/crls"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    json!([{ "id": CRL_ID, "crl": format!("{}\n", crl_fixture()) }]),
                ),
            )
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_initial_certificate_mutations(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/certificate"
            )))
            .and(body_json(json!({
                "notBefore": "2036-01-01T00:00:00Z",
                "notAfter": "2037-01-01T00:00:00Z",
                "maxPathLength": 0,
                "parentCaId": PARENT_CA_ID
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(certificate_value()))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/import-certificate"
            )))
            .and(body_json(
                json!({ "certificate": CA_CERT, "certificateChain": CA_CERT }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "Successfully imported certificate to CA",
                "caId": CA_ID.to_ascii_uppercase()
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_active_certificate_mutations(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/renew"
            )))
            .and(body_json(
                json!({ "type": "existing", "notAfter": "2038-01-01T00:00:00Z" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(certificate_value()))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/sign-intermediate"
            )))
            .and(body_json(
                json!({ "csr": csr_fixture(), "notAfter": "2039-01-01T00:00:00Z", "maxPathLength": -1 }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": CA_CERT,
                "certificateChain": CA_CERT,
                "issuingCaCertificate": CA_CERT,
                "serialNumber": "02cd"
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[test]
    fn certificate_operation_inputs_reject_ambiguous_or_unbounded_values() {
        let ca_id = CertificateAuthorityId::new(CA_ID).unwrap();
        assert_eq!(
            CertificateAuthorityCertificateGeneration::new(
                &ca_id,
                "2036-01-02T00:00:00Z",
                "2036-01-01T00:00:00Z",
                0,
                None,
            )
            .unwrap_err(),
            CertificateAuthorityCertificateInputError::InvalidValidityOrder
        );
        assert_eq!(
            CertificateAuthorityCertificateGeneration::new(
                &ca_id,
                "2036-01-01T00:00:00Z",
                "2037-01-01T00:00:00Z",
                101,
                None,
            )
            .unwrap_err(),
            CertificateAuthorityCertificateInputError::InvalidMaxPathLength
        );
        assert_eq!(
            CertificateAuthorityCertificateGeneration::new(
                &ca_id,
                "2036-01-01T00:00:00Z",
                "2037-01-01T00:00:00Z",
                0,
                Some(ca_id.clone()),
            )
            .unwrap_err(),
            CertificateAuthorityCertificateInputError::ParentMatchesTarget
        );
        assert_eq!(
            CertificateAuthoritySigningRequest::new("not a CSR", None, "2037-01-01T00:00:00Z", 0,)
                .unwrap_err(),
            CertificateAuthorityCertificateInputError::InvalidCsr
        );
        assert_eq!(
            CertificateAuthorityCertificateImport::new(CA_CERT, "not a chain").unwrap_err(),
            CertificateAuthorityCertificateInputError::InvalidCertificatePem
        );
        assert_eq!(
            CertificateAuthorityCertificateImport::new(end_entity_certificate_fixture(), CA_CERT)
                .unwrap_err(),
            CertificateAuthorityCertificateInputError::InvalidCertificatePem
        );
        assert_eq!(
            CertificateAuthorityCertificateImport::new(CA_CERT, end_entity_certificate_fixture())
                .unwrap_err(),
            CertificateAuthorityCertificateInputError::InvalidCertificatePem
        );

        let import = CertificateAuthorityCertificateImport::new(
            format!("{CA_CERT}\n"),
            format!("{CA_CERT}\r\n"),
        )
        .unwrap();
        assert_eq!(import.certificate, CA_CERT);
        assert_eq!(import.certificate_chain, CA_CERT);
        let signing = CertificateAuthoritySigningRequest::new(
            format!("{}\n", csr_fixture()),
            None,
            "2037-01-01T00:00:00Z",
            0,
        )
        .unwrap();
        assert_eq!(signing.csr, csr_fixture());
    }

    #[test]
    fn pki_pem_values_require_semantic_der_and_exact_framing() {
        assert!(is_bounded_pem(&"x".repeat(16 * 1024), MAX_CSR_PEM_BYTES));
        assert!(!is_bounded_pem(
            &"x".repeat(16 * 1024 + 1),
            MAX_CSR_PEM_BYTES
        ));
        for (maximum, expected) in [
            (MAX_CERTIFICATE_PEM_BYTES, 64 * 1024),
            (MAX_CERTIFICATE_CHAIN_PEM_BYTES, 512 * 1024),
            (MAX_CRL_PEM_BYTES, 512 * 1024),
        ] {
            assert!(is_bounded_pem(&"x".repeat(expected), maximum));
            assert!(!is_bounded_pem(&"x".repeat(expected + 1), maximum));
        }
        assert!(!is_bounded_pem("", MAX_CSR_PEM_BYTES));
        assert!(!is_bounded_pem(" padded", MAX_CSR_PEM_BYTES));
        assert_eq!(normalize_pem("document\n").as_deref(), Some("document"));
        assert_eq!(normalize_pem("document\r\n").as_deref(), Some("document"));
        assert_eq!(normalize_pem(""), None);
        assert_eq!(normalize_pem(" padded "), None);
        assert_eq!(normalize_pem("document\n\n"), None);
        assert!(is_valid_csr(csr_fixture()));
        assert!(is_valid_csr(p521_csr_fixture()));
        assert!(!is_valid_csr(&corrupt_pem_signature(p521_csr_fixture())));
        for csr in [
            ml_dsa_csr_fixture(),
            ml_dsa_65_csr_fixture(),
            ml_dsa_87_csr_fixture(),
        ] {
            assert!(is_valid_csr(csr));
            assert!(!is_valid_csr(&corrupt_pem_signature(csr)));
        }
        assert!(is_valid_csr(
            &csr_fixture().replace("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")
        ));
        assert!(!is_valid_csr(&corrupt_pem_signature(csr_fixture())));
        assert!(!is_valid_csr(&append_der_trailing_data(csr_fixture())));
        assert!(!is_valid_csr(
            "-----BEGIN CERTIFICATE REQUEST-----\nAQID\n-----END CERTIFICATE REQUEST-----"
        ));
        assert!(is_valid_crl(crl_fixture()));
        assert!(!is_valid_crl(
            "-----BEGIN X509 CRL-----\nAQID\n-----END X509 CRL-----"
        ));
        assert!(is_valid_single_certificate(CA_CERT));
        assert!(!is_valid_single_certificate(
            end_entity_certificate_fixture()
        ));
        assert!(!is_valid_single_certificate(
            ca_without_key_cert_sign_fixture()
        ));
        assert!(!is_valid_single_certificate(&format!(
            "{CA_CERT}\n{CA_CERT}"
        )));
        assert!(!is_valid_single_certificate(&format!(
            "{CA_CERT}\n-----END CERTIFICATE-----"
        )));
    }

    #[test]
    fn pki_collection_and_active_certificate_boundaries_are_exact() {
        assert!(is_within_collection_limit(500, MAX_CA_CERTIFICATES));
        assert!(!is_within_collection_limit(501, MAX_CA_CERTIFICATES));
        assert!(is_within_collection_limit(500, MAX_CA_CRLS));
        assert!(!is_within_collection_limit(501, MAX_CA_CRLS));
        assert!(has_active_certificate(
            CertificateAuthorityStatus::Active,
            Some(CERTIFICATE_ID)
        ));
        assert!(!has_active_certificate(
            CertificateAuthorityStatus::Disabled,
            Some(CERTIFICATE_ID)
        ));
        assert!(!has_active_certificate(
            CertificateAuthorityStatus::Active,
            None
        ));
    }

    #[test]
    fn certificate_wire_fields_fail_independently() {
        let mut invalid = Vec::new();

        let mut wire = certificate_wire();
        wire.certificate = "not a certificate".into();
        invalid.push(wire);
        let mut wire = certificate_wire();
        wire.certificate_chain = "not a chain".into();
        invalid.push(wire);
        let mut wire = certificate_wire();
        wire.serial_number.clear();
        invalid.push(wire);
        let mut wire = certificate_wire();
        wire.serial_number = "not-hex".into();
        invalid.push(wire);
        let mut wire = certificate_wire();
        wire.not_before = Some("not-a-time".into());
        invalid.push(wire);
        let mut wire = certificate_wire();
        wire.not_after = Some("not-a-time".into());
        invalid.push(wire);
        let mut wire = certificate_wire();
        wire.not_before = Some("2037-01-01T00:00:00Z".into());
        wire.not_after = Some("2036-01-01T00:00:00Z".into());
        invalid.push(wire);
        let mut wire = certificate_wire();
        wire.max_path_length = Some(101);
        invalid.push(wire);
        let mut wire = certificate_wire();
        wire.version = Some(0);
        invalid.push(wire);
        let mut wire = certificate_wire();
        wire.certificate_id = "not-a-uuid".into();
        invalid.push(wire);
        let mut wire = certificate_wire();
        wire.parent_ca_id = Some("not-a-uuid".into());
        invalid.push(wire);

        for wire in invalid {
            assert_eq!(
                certificate_from_wire(wire).unwrap_err(),
                ResourceError::InvalidCertificateAuthorityResponse
            );
        }

        let mut maximum_serial = certificate_wire();
        maximum_serial.serial_number = "a".repeat(MAX_SERIAL_NUMBER_BYTES);
        assert!(certificate_from_wire(maximum_serial).is_ok());
        let mut oversized_serial = certificate_wire();
        oversized_serial.serial_number = "a".repeat(MAX_SERIAL_NUMBER_BYTES + 1);
        assert_eq!(
            certificate_from_wire(oversized_serial).unwrap_err(),
            ResourceError::InvalidCertificateAuthorityResponse
        );
    }

    #[test]
    fn signed_intermediate_wire_fields_fail_independently() {
        let mut invalid = Vec::new();

        let mut wire = signed_intermediate_wire();
        wire.certificate = "not a certificate".into();
        invalid.push(wire);
        let mut wire = signed_intermediate_wire();
        wire.certificate_chain = "not a chain".into();
        invalid.push(wire);
        let mut wire = signed_intermediate_wire();
        wire.issuing_ca_certificate = "not a certificate".into();
        invalid.push(wire);
        let mut wire = signed_intermediate_wire();
        wire.serial_number.clear();
        invalid.push(wire);
        let mut wire = signed_intermediate_wire();
        wire.serial_number = "not-hex".into();
        invalid.push(wire);

        for wire in invalid {
            assert_eq!(
                signed_intermediate_from_wire(wire).unwrap_err(),
                ResourceError::InvalidCertificateAuthorityResponse
            );
        }
    }

    #[test]
    fn crl_and_import_receipt_fields_fail_independently() {
        let crl = crl_from_wire(&CrlWire {
            id: CRL_ID.to_ascii_uppercase(),
            crl: crl_fixture().into(),
        })
        .unwrap();
        assert_eq!(crl.id, CRL_ID);
        for wire in [
            CrlWire {
                id: "not-a-uuid".into(),
                crl: crl_fixture().into(),
            },
            CrlWire {
                id: CRL_ID.into(),
                crl: "not a CRL".into(),
            },
        ] {
            assert_eq!(
                crl_from_wire(&wire).unwrap_err(),
                ResourceError::InvalidCertificateAuthorityResponse
            );
        }

        let ca_id = CertificateAuthorityId::new(CA_ID).unwrap();
        let receipt = import_receipt_from_wire(
            ImportReceiptWire {
                message: "Successfully imported certificate to CA".into(),
                ca_id: CA_ID.to_ascii_uppercase(),
            },
            &ca_id,
        )
        .unwrap();
        assert_eq!(receipt.ca_id, CA_ID);
        for wire in [
            ImportReceiptWire {
                message: "Successfully imported certificate to CA".into(),
                ca_id: PARENT_CA_ID.into(),
            },
            ImportReceiptWire {
                message: "unexpected message".into(),
                ca_id: CA_ID.into(),
            },
        ] {
            assert_eq!(
                import_receipt_from_wire(wire, &ca_id).unwrap_err(),
                ResourceError::InvalidCertificateAuthorityResponse
            );
        }
    }

    #[tokio::test]
    async fn internal_ca_certificate_reads_dispatch_every_pinned_route() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-certificate-read-token").await;
        mount_scope(&server, CA_ID, 5).await;

        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/csr"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "csr": format!("{}\n", csr_fixture()) })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut historical = certificate_value();
        historical["version"] = json!(1);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/ca-certificates"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([historical])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/certificate"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(certificate_value()))
            .expect(1)
            .mount(&server)
            .await;
        let mut version = certificate_value();
        version["notBefore"] = json!("2036-01-01T00:00:00Z");
        version["notAfter"] = json!("2037-01-01T00:00:00Z");
        version["maxPathLength"] = json!(0);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/certificate/{CERTIFICATE_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(version))
            .expect(1)
            .mount(&server)
            .await;
        mount_ca_crls(&server).await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let ca_id = CertificateAuthorityId::new(CA_ID).unwrap();
        assert_eq!(
            client
                .get_internal_ca_csr(&project_id, &ca_id)
                .await
                .unwrap()
                .csr,
            csr_fixture()
        );
        assert_eq!(
            client
                .list_internal_ca_certificates(&project_id, &ca_id)
                .await
                .unwrap()[0]
                .version,
            Some(1)
        );
        assert_eq!(
            client
                .get_internal_ca_certificate(&project_id, &ca_id)
                .await
                .unwrap()
                .certificate_id,
            CERTIFICATE_ID
        );
        assert_eq!(
            client
                .get_internal_ca_certificate_version(
                    &project_id,
                    &ca_id,
                    &CertificateAuthorityId::new(CERTIFICATE_ID).unwrap()
                )
                .await
                .unwrap()
                .max_path_length,
            Some(0)
        );
        assert_eq!(
            client
                .list_internal_ca_crls(&project_id, &ca_id)
                .await
                .unwrap()[0]
                .id,
            CRL_ID
        );
    }

    #[tokio::test]
    async fn certificate_history_rejects_duplicate_versions() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-history-version-token").await;
        mount_scope(&server, CA_ID, 1).await;
        let mut first = certificate_value();
        first["version"] = json!(1);
        let mut second = certificate_value();
        second["certId"] = json!("66666666-6666-4666-8666-666666666666");
        second["version"] = json!(1);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/ca-certificates"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([first, second])))
            .expect(1)
            .mount(&server)
            .await;

        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .list_internal_ca_certificates(
                &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                &CertificateAuthorityId::new(CA_ID).unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, ResourceError::InvalidCertificateAuthorityResponse);
    }

    #[tokio::test]
    async fn certificate_history_rejects_duplicate_certificate_ids() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-history-certificate-id-token").await;
        mount_scope(&server, CA_ID, 1).await;
        let mut first = certificate_value();
        first["version"] = json!(1);
        let mut second = certificate_value();
        second["version"] = json!(2);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/ca-certificates"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([first, second])))
            .expect(1)
            .mount(&server)
            .await;

        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .list_internal_ca_certificates(
                &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                &CertificateAuthorityId::new(CA_ID).unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, ResourceError::InvalidCertificateAuthorityResponse);
    }

    #[tokio::test]
    async fn certificate_history_requires_a_version_on_every_entry() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-history-required-version-token").await;
        mount_scope(&server, CA_ID, 1).await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/ca-certificates"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([certificate_value()])))
            .expect(1)
            .mount(&server)
            .await;

        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .list_internal_ca_certificates(
                &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                &CertificateAuthorityId::new(CA_ID).unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, ResourceError::InvalidCertificateAuthorityResponse);
    }

    #[tokio::test]
    async fn certificate_mutations_require_confirmation_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let ca_id = CertificateAuthorityId::new(CA_ID).unwrap();

        let generation = CertificateAuthorityCertificateGeneration::new(
            &ca_id,
            "2036-01-01T00:00:00Z",
            "2037-01-01T00:00:00Z",
            0,
            None,
        )
        .unwrap();
        assert_eq!(
            client
                .generate_internal_ca_certificate(&project_id, &ca_id, generation, false)
                .await
                .unwrap_err(),
            ResourceError::CertificateAuthorityCertificateMutationNotConfirmed
        );
        assert_eq!(
            client
                .renew_internal_ca_certificate(
                    &project_id,
                    &ca_id,
                    CertificateAuthorityCertificateRenewal::new("2037-01-01T00:00:00Z").unwrap(),
                    false
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateAuthorityCertificateMutationNotConfirmed
        );
        assert_eq!(
            client
                .sign_internal_ca_intermediate(
                    &project_id,
                    &ca_id,
                    CertificateAuthoritySigningRequest::new(
                        csr_fixture(),
                        None,
                        "2037-01-01T00:00:00Z",
                        0,
                    )
                    .unwrap(),
                    false
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateAuthorityCertificateMutationNotConfirmed
        );
        assert_eq!(
            client
                .import_internal_ca_certificate(
                    &project_id,
                    &ca_id,
                    CertificateAuthorityCertificateImport::new(CA_CERT, CA_CERT).unwrap(),
                    false
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateAuthorityCertificateMutationNotConfirmed
        );
    }

    #[tokio::test]
    async fn certificate_state_preflights_block_unsupported_mutations() {
        let root_server = MockServer::start().await;
        mount_login(&root_server, "ca-root-state-token").await;
        let mut root = ca_value(CA_ID);
        root["configuration"]["type"] = json!("root");
        mount_scope_response(&root_server, root).await;
        let root_client = InfisicalClient::new(settings(&root_server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let ca_id = CertificateAuthorityId::new(CA_ID).unwrap();
        let generation = CertificateAuthorityCertificateGeneration::new(
            &ca_id,
            "2036-01-01T00:00:00Z",
            "2037-01-01T00:00:00Z",
            0,
            Some(CertificateAuthorityId::new(PARENT_CA_ID).unwrap()),
        )
        .unwrap();
        assert_eq!(
            root_client
                .generate_internal_ca_certificate(&project_id, &ca_id, generation, true)
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateAuthorityCertificateState
        );

        let import_server = MockServer::start().await;
        mount_login(&import_server, "ca-import-state-token").await;
        mount_scope(&import_server, CA_ID, 1).await;
        let import_client = InfisicalClient::new(settings(&import_server)).unwrap();
        assert_eq!(
            import_client
                .import_internal_ca_certificate(
                    &project_id,
                    &ca_id,
                    CertificateAuthorityCertificateImport::new(CA_CERT, CA_CERT).unwrap(),
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateAuthorityCertificateState
        );

        let incoherent_server = MockServer::start().await;
        mount_login(&incoherent_server, "ca-incoherent-state-token").await;
        let mut incoherent = ca_value(CA_ID);
        incoherent["status"] = json!("pending-certificate");
        mount_scope_response(&incoherent_server, incoherent).await;
        let incoherent_client = InfisicalClient::new(settings(&incoherent_server)).unwrap();
        assert_eq!(
            incoherent_client
                .import_internal_ca_certificate(
                    &project_id,
                    &ca_id,
                    CertificateAuthorityCertificateImport::new(CA_CERT, CA_CERT).unwrap(),
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateAuthorityCertificateState
        );

        let disabled_server = MockServer::start().await;
        mount_login(&disabled_server, "ca-disabled-state-token").await;
        let mut disabled = ca_value(CA_ID);
        disabled["status"] = json!("disabled");
        mount_scope_response(&disabled_server, disabled).await;
        let disabled_client = InfisicalClient::new(settings(&disabled_server)).unwrap();
        assert_eq!(
            disabled_client
                .renew_internal_ca_certificate(
                    &project_id,
                    &ca_id,
                    CertificateAuthorityCertificateRenewal::new("2038-01-01T00:00:00Z").unwrap(),
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateAuthorityCertificateState
        );
    }

    #[tokio::test]
    async fn root_certificate_generation_uses_the_body_without_a_parent() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-root-generation-token").await;
        let mut root = ca_value(CA_ID);
        root["configuration"]["type"] = json!("root");
        root["status"] = json!("pending-certificate");
        root["configuration"]["activeCaCertId"] = serde_json::Value::Null;
        mount_scope_response(&server, root).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{CA_ID}/certificate"
            )))
            .and(body_json(json!({
                "notBefore": "2036-01-01T00:00:00Z",
                "notAfter": "2037-01-01T00:00:00Z",
                "maxPathLength": 1
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(certificate_value()))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let ca_id = CertificateAuthorityId::new(CA_ID).unwrap();
        let generated = client
            .generate_internal_ca_certificate(
                &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                &ca_id,
                CertificateAuthorityCertificateGeneration::new(
                    &ca_id,
                    "2036-01-01T00:00:00Z",
                    "2037-01-01T00:00:00Z",
                    1,
                    None,
                )
                .unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(generated.certificate_id, CERTIFICATE_ID);
    }

    #[tokio::test]
    async fn certificate_mutations_preflight_scope_and_send_each_body_once() {
        let initial_server = MockServer::start().await;
        mount_login(&initial_server, "ca-certificate-initial-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/cert-manager/ca/internal/{CA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(pending_ca_value(CA_ID)))
            .expect(2)
            .mount(&initial_server)
            .await;
        mount_scope(&initial_server, PARENT_CA_ID, 1).await;
        mount_initial_certificate_mutations(&initial_server).await;

        let initial_client = InfisicalClient::new(settings(&initial_server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let ca_id = CertificateAuthorityId::new(CA_ID).unwrap();
        let generated = initial_client
            .generate_internal_ca_certificate(
                &project_id,
                &ca_id,
                CertificateAuthorityCertificateGeneration::new(
                    &ca_id,
                    "2036-01-01T00:00:00Z",
                    "2037-01-01T00:00:00Z",
                    0,
                    Some(CertificateAuthorityId::new(PARENT_CA_ID).unwrap()),
                )
                .unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(generated.certificate_id, CERTIFICATE_ID);
        assert_eq!(
            initial_client
                .import_internal_ca_certificate(
                    &project_id,
                    &ca_id,
                    CertificateAuthorityCertificateImport::new(CA_CERT, CA_CERT).unwrap(),
                    true
                )
                .await
                .unwrap()
                .ca_id,
            CA_ID
        );

        let active_server = MockServer::start().await;
        mount_login(&active_server, "ca-certificate-active-token").await;
        mount_scope(&active_server, CA_ID, 2).await;
        mount_active_certificate_mutations(&active_server).await;
        let active_client = InfisicalClient::new(settings(&active_server)).unwrap();
        assert_eq!(
            active_client
                .renew_internal_ca_certificate(
                    &project_id,
                    &ca_id,
                    CertificateAuthorityCertificateRenewal::new("2038-01-01T00:00:00Z").unwrap(),
                    true
                )
                .await
                .unwrap()
                .serial_number,
            "01ab"
        );
        assert_eq!(
            active_client
                .sign_internal_ca_intermediate(
                    &project_id,
                    &ca_id,
                    CertificateAuthoritySigningRequest::new(
                        csr_fixture(),
                        None,
                        "2039-01-01T00:00:00Z",
                        -1,
                    )
                    .unwrap(),
                    true
                )
                .await
                .unwrap()
                .serial_number,
            "02cd"
        );
    }
}
