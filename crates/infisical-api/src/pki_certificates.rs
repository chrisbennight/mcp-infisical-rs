use std::collections::HashSet;

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;
use x509_parser::{
    prelude::{FromDer, X509Certificate},
    public_key::PublicKey,
    time::ASN1Time,
};

use crate::{
    ApiErrorKind, CertificateAuthorityId, CertificateAuthorityProjectId, CertificateKeyAlgorithm,
    CertificateRequestId, ClientError, InfisicalClient, MAX_PAGE_SIZE, MutationOperation,
    ObservableReadBodyOperation, ObservableReadOperation, Page, PageRequest, ResourceError,
    SecretValue,
    certificate::{
        certificate_bundle_der, certificate_serial_matches, certificate_serial_values_match,
        normalize_pem,
    },
    client::{ApiVersion, DeserializedSecret, Endpoint, sealed},
    pki_certificate_profiles::{
        certificate_chain_belongs_to_leaf, certificate_chain_is_linked_to_leaf,
        certificate_signature_is_valid, private_key_matches_certificate,
    },
    pki_certificate_requests::certificate_subject_values_match,
    resources::{is_bounded_text, is_uuid, utc_timestamp_millis},
};

const MAX_CERTIFICATE_SEARCH_BYTES: usize = 255;
const MAX_CERTIFICATE_FRIENDLY_NAME_BYTES: usize = 255;
const MAX_CERTIFICATE_TEXT_BYTES: usize = 2_048;
const MAX_SERIAL_NUMBER_BYTES: usize = 128;
const MAX_ALTERNATIVE_NAMES_BYTES: usize = 16 * 1_024;
const MAX_FILTER_VALUES: usize = 100;
const MAX_CERTIFICATE_PEM_BYTES: usize = 64 * 1_024;
const MAX_CERTIFICATE_CHAIN_PEM_BYTES: usize = 512 * 1_024;
const MAX_CERTIFICATE_LIFECYCLE_MATERIAL_BYTES: usize = 96 * 1_024;

/// Input validation failures for project certificate inventory.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CertificateInputError {
    #[error("certificate ID must be a UUID")]
    InvalidId,
    #[error("certificate search must be trimmed, control-free, and at most 255 bytes")]
    InvalidSearch,
    #[error("certificate inventory filters must contain bounded unique values")]
    InvalidFilter,
    #[error("certificate sort order requires a sort field")]
    InvalidSort,
    #[error("certificate renewal lead time must be between 1 and 30 days")]
    InvalidRenewBeforeDays,
    #[error("certificate import material must be bounded, well-formed, and internally consistent")]
    InvalidImportMaterial,
    #[error("certificate import metadata must be bounded and use canonical identifiers")]
    InvalidImportMetadata,
}

/// Canonical certificate UUID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct CertificateId(String);

impl CertificateId {
    /// Validate one exact certificate identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, CertificateInputError> {
        let value = value.into();
        if !is_uuid(&value) {
            return Err(CertificateInputError::InvalidId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Borrow the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Certificate lifecycle state returned by project inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CertificateStatus {
    Active,
    Expired,
    Revoked,
}

/// RFC 5280 CRL reason accepted by Infisical's certificate revocation route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CertificateRevocationReason {
    #[serde(rename = "UNSPECIFIED")]
    Unspecified,
    #[serde(rename = "KEY_COMPROMISE")]
    KeyCompromise,
    #[serde(rename = "CA_COMPROMISE")]
    CaCompromise,
    #[serde(rename = "AFFILIATION_CHANGED")]
    AffiliationChanged,
    #[serde(rename = "SUPERSEDED")]
    Superseded,
    #[serde(rename = "CESSATION_OF_OPERATION")]
    CessationOfOperation,
    #[serde(rename = "CERTIFICATE_HOLD")]
    CertificateHold,
    #[serde(rename = "PRIVILEGE_WITHDRAWN")]
    PrivilegeWithdrawn,
    #[serde(rename = "A_A_COMPROMISE")]
    AaCompromise,
}

/// Exact automatic-renewal configuration change supported by the pinned route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateRenewalConfigurationChange {
    RenewBeforeDays(CertificateRenewBeforeDays),
    Disable,
}

/// Validated automatic-renewal lead time accepted by the pinned route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateRenewBeforeDays(u8);

impl CertificateRenewBeforeDays {
    /// Validate an automatic-renewal lead time.
    ///
    /// # Errors
    ///
    /// Returns an error unless the lead time is within the pinned inclusive range.
    pub fn new(days: u8) -> Result<Self, CertificateInputError> {
        if !(1..=30).contains(&days) {
            return Err(CertificateInputError::InvalidRenewBeforeDays);
        }
        Ok(Self(days))
    }

    const fn get(self) -> u8 {
        self.0
    }
}

impl CertificateRenewalConfigurationChange {
    /// Validate an automatic-renewal lead time.
    ///
    /// # Errors
    ///
    /// Returns an error unless the lead time is within the pinned inclusive range.
    pub fn renew_before_days(days: u8) -> Result<Self, CertificateInputError> {
        CertificateRenewBeforeDays::new(days).map(Self::RenewBeforeDays)
    }
}

/// Validated material returned by a managed-key certificate renewal.
#[derive(Debug)]
pub struct RenewedCertificate {
    pub project_id: String,
    pub previous_certificate_id: String,
    pub certificate_id: String,
    pub request_id: String,
    pub serial_number: String,
    pub certificate: String,
    pub issuing_ca_certificate: String,
    pub certificate_chain: String,
    pub private_key: SecretValue,
}

/// Public certificate and issuer-chain material bound to one inventory record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePublicMaterial {
    pub project_id: String,
    pub certificate_id: String,
    pub serial_number: String,
    pub certificate: String,
    pub certificate_chain: String,
}

/// Confirmed certificate bundle whose optional private key remains redacted.
#[derive(Debug)]
pub struct CertificateBundle {
    pub project_id: String,
    pub certificate_id: String,
    pub serial_number: String,
    pub certificate: String,
    pub certificate_chain: String,
    pub private_key: Option<SecretValue>,
}

/// Confirmed private key bound to one project-owned certificate.
#[derive(Debug)]
pub struct CertificatePrivateKey {
    pub project_id: String,
    pub certificate_id: String,
    pub serial_number: String,
    pub private_key: SecretValue,
}

/// Validated certificate material and optional inventory placement for one import.
#[derive(Debug)]
pub struct CertificateImport {
    certificate: SecretValue,
    private_key: Option<SecretValue>,
    certificate_chain: Option<SecretValue>,
    friendly_name: Option<String>,
    pki_collection_id: Option<String>,
    application_id: Option<String>,
}

impl CertificateImport {
    /// Validate imported PEM material and its optional inventory metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when material is malformed, mismatched, or exceeds a bound.
    pub fn new(
        certificate: SecretValue,
        private_key: Option<SecretValue>,
        certificate_chain: Option<SecretValue>,
        friendly_name: Option<String>,
        pki_collection_id: Option<String>,
        application_id: Option<String>,
    ) -> Result<Self, CertificateInputError> {
        let normalized_certificate = normalize_lifecycle_certificate(certificate.expose_secret())
            .ok_or(CertificateInputError::InvalidImportMaterial)?;
        // The normalized copy is now the sole retained leaf value; zeroize the
        // uploaded source before performing the remaining validation work.
        drop(certificate);
        let certificate_der = certificate_bundle_der(&normalized_certificate)
            .and_then(|mut values| (values.len() == 1).then(|| values.pop()).flatten())
            .ok_or(CertificateInputError::InvalidImportMaterial)?;
        let (remainder, parsed) = X509Certificate::from_der(&certificate_der)
            .map_err(|_| CertificateInputError::InvalidImportMaterial)?;
        if !remainder.is_empty() {
            return Err(CertificateInputError::InvalidImportMaterial);
        }
        let certificate_chain = certificate_chain
            .map(|value| {
                let chain = normalize_lifecycle_chain(value.expose_secret())
                    .filter(|chain| !chain.is_empty())
                    .ok_or(CertificateInputError::InvalidImportMaterial)?;
                if !certificate_chain_is_linked_to_leaf(&parsed, &chain) {
                    return Err(CertificateInputError::InvalidImportMaterial);
                }
                Ok(SecretValue::new(chain))
            })
            .transpose()?;
        let private_key = private_key
            .map(|value| {
                let key = normalize_lifecycle_pem(value.expose_secret(), MAX_CERTIFICATE_PEM_BYTES)
                    .filter(|key| private_key_matches_certificate(&parsed, key))
                    .ok_or(CertificateInputError::InvalidImportMaterial)?;
                Ok(SecretValue::new(key))
            })
            .transpose()?;
        let aggregate = normalized_certificate.len()
            + certificate_chain
                .as_ref()
                .map_or(0, |value| value.expose_secret().len())
            + private_key
                .as_ref()
                .map_or(0, |value| value.expose_secret().len());
        if aggregate > MAX_CERTIFICATE_LIFECYCLE_MATERIAL_BYTES
            || friendly_name.as_deref().is_some_and(|value| {
                value.is_empty() || !valid_text(value, MAX_CERTIFICATE_FRIENDLY_NAME_BYTES)
            })
            || pki_collection_id
                .as_deref()
                .is_some_and(|value| !is_uuid(value))
            || application_id
                .as_deref()
                .is_some_and(|value| !is_uuid(value))
        {
            return Err(CertificateInputError::InvalidImportMetadata);
        }
        Ok(Self {
            certificate: SecretValue::new(normalized_certificate),
            private_key,
            certificate_chain,
            friendly_name,
            pki_collection_id: pki_collection_id.map(|value| value.to_ascii_lowercase()),
            application_id: application_id.map(|value| value.to_ascii_lowercase()),
        })
    }
}

/// Sanitized certificate revocation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRevocation {
    pub project_id: String,
    pub certificate_id: String,
    pub serial_number: String,
    pub reason: CertificateRevocationReason,
    pub revoked_at: String,
}

/// Durable automatic-renewal configuration reflected by Infisical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRenewalConfiguration {
    pub project_id: String,
    pub certificate_id: String,
    pub enabled: bool,
    pub renew_before_days: Option<u8>,
}

/// Supported certificate inventory sort field from the pinned search route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CertificateInventorySort {
    NotAfter,
    NotBefore,
    CreatedAt,
    CommonName,
    KeyAlgorithm,
    Status,
}

/// Sort direction for project certificate inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CertificateInventorySortOrder {
    Asc,
    Desc,
}

/// One bounded project-scoped certificate search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateListRequest {
    project_id: CertificateAuthorityProjectId,
    page: PageRequest,
    search: Option<String>,
    status: Option<CertificateStatus>,
    profile_ids: Option<Vec<String>>,
    ca_ids: Option<Vec<String>>,
    application_ids: Option<Vec<String>>,
    key_algorithms: Option<Vec<CertificateKeyAlgorithm>>,
    sort_by: Option<CertificateInventorySort>,
    sort_order: Option<CertificateInventorySortOrder>,
}

impl CertificateListRequest {
    /// Validate pagination, text, identifier filters, and sorting before search.
    ///
    /// # Errors
    ///
    /// Returns an error for ambiguous text, duplicate or oversized filters, or
    /// a sort direction without a field.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: CertificateAuthorityProjectId,
        page: PageRequest,
        search: Option<String>,
        status: Option<CertificateStatus>,
        profile_ids: Option<Vec<String>>,
        ca_ids: Option<Vec<String>>,
        application_ids: Option<Vec<String>>,
        key_algorithms: Option<Vec<CertificateKeyAlgorithm>>,
        sort_by: Option<CertificateInventorySort>,
        sort_order: Option<CertificateInventorySortOrder>,
    ) -> Result<Self, CertificateInputError> {
        if search.as_deref().is_some_and(|value| {
            !is_bounded_text(value, MAX_CERTIFICATE_SEARCH_BYTES) || value != value.trim()
        }) {
            return Err(CertificateInputError::InvalidSearch);
        }
        let profile_ids = normalize_uuid_filters(profile_ids)?;
        let ca_ids = normalize_uuid_filters(ca_ids)?;
        let application_ids = normalize_uuid_filters(application_ids)?;
        validate_unique_filter(key_algorithms.as_deref())?;
        if sort_order.is_some() && sort_by.is_none() {
            return Err(CertificateInputError::InvalidSort);
        }
        Ok(Self {
            project_id,
            page,
            search,
            status,
            profile_ids,
            ca_ids,
            application_ids,
            key_algorithms,
            sort_by,
            sort_order,
        })
    }
}

/// Sanitized metadata for one Certificate Manager certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    /// Canonical certificate UUID.
    pub id: String,
    /// Owning Certificate Manager project UUID.
    pub project_id: String,
    /// Bounded display name assigned to the certificate.
    pub friendly_name: String,
    /// Bounded X.509 subject common name.
    pub common_name: String,
    /// Current lifecycle state reported by Infisical.
    pub status: CertificateStatus,
    /// Bounded certificate serial-number representation.
    pub serial_number: String,
    /// Canonical UTC validity start.
    pub not_before: String,
    /// Canonical UTC validity end.
    pub not_after: String,
    /// Canonical UTC revocation time for a revoked certificate.
    pub revoked_at: Option<String>,
    /// RFC 5280 CRL reason code when Infisical records one.
    pub revocation_reason: Option<u8>,
    /// Bounded subject-alternative-name representation when present.
    pub alternative_names: Option<String>,
    /// Unique bounded X.509 key-usage names when present.
    pub key_usages: Option<Vec<String>>,
    /// Unique bounded X.509 extended-key-usage names when present.
    pub extended_key_usages: Option<Vec<String>>,
    /// Typed public-key algorithm when Infisical records one.
    pub key_algorithm: Option<CertificateKeyAlgorithm>,
    /// Bounded signature-algorithm name when present.
    pub signature_algorithm: Option<String>,
    /// Whether the certificate asserts certificate-authority basic constraints.
    pub is_ca: Option<bool>,
    /// Related certificate-authority UUID when present.
    pub ca_id: Option<String>,
    /// Related certificate-profile UUID when present.
    pub profile_id: Option<String>,
    /// Related application UUID when present.
    pub application_id: Option<String>,
    /// Bounded related certificate-authority display name when present.
    pub ca_name: Option<String>,
    /// Bounded related certificate-profile display name when present.
    pub profile_name: Option<String>,
    /// Bounded enrollment-family name when present.
    pub enrollment_type: Option<String>,
    /// Bounded related application display name when present.
    pub application_name: Option<String>,
    /// Whether Infisical reports stored private-key material for this certificate.
    pub has_private_key: bool,
    /// Canonical UTC creation timestamp.
    pub created_at: String,
    /// Canonical UTC last-update timestamp.
    pub updated_at: String,
}

fn normalize_uuid_filters(
    values: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, CertificateInputError> {
    let Some(values) = values else {
        return Ok(None);
    };
    if values.is_empty()
        || values.len() > MAX_FILTER_VALUES
        || values.iter().any(|value| !is_uuid(value))
    {
        return Err(CertificateInputError::InvalidFilter);
    }
    let values = values
        .into_iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if values.iter().collect::<HashSet<_>>().len() != values.len() {
        return Err(CertificateInputError::InvalidFilter);
    }
    Ok(Some(values))
}

fn validate_unique_filter<T>(values: Option<&[T]>) -> Result<(), CertificateInputError>
where
    T: Eq + std::hash::Hash,
{
    if values.is_some_and(|values| {
        values.is_empty()
            || values.len() > MAX_FILTER_VALUES
            || values.iter().collect::<HashSet<_>>().len() != values.len()
    }) {
        return Err(CertificateInputError::InvalidFilter);
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchCertificatesRequest {
    #[serde(skip_serializing)]
    project_id: CertificateAuthorityProjectId,
    offset: u32,
    limit: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    search: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<CertificateStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    application_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "keyAlgorithm")]
    key_algorithms: Option<Vec<CertificateKeyAlgorithm>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sort_by: Option<CertificateInventorySort>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sort_order: Option<CertificateInventorySortOrder>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchCertificatesResponse {
    certificates: Vec<CertificateWire>,
    total_count: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateWire {
    id: String,
    project_id: String,
    friendly_name: String,
    common_name: String,
    status: CertificateStatus,
    serial_number: String,
    not_before: String,
    not_after: String,
    #[serde(default)]
    revoked_at: Option<String>,
    #[serde(default)]
    revocation_reason: Option<u8>,
    #[serde(default)]
    alt_names: Option<String>,
    #[serde(default)]
    key_usages: Option<Vec<String>>,
    #[serde(default)]
    extended_key_usages: Option<Vec<String>>,
    #[serde(default)]
    key_algorithm: Option<CertificateKeyAlgorithm>,
    #[serde(default)]
    signature_algorithm: Option<String>,
    #[serde(default, rename = "isCA")]
    is_ca: Option<bool>,
    #[serde(default)]
    ca_id: Option<String>,
    #[serde(default)]
    profile_id: Option<String>,
    #[serde(default)]
    application_id: Option<String>,
    #[serde(default)]
    ca_name: Option<String>,
    #[serde(default)]
    profile_name: Option<String>,
    #[serde(default)]
    enrollment_type: Option<String>,
    #[serde(default)]
    application_name: Option<String>,
    has_private_key: bool,
    created_at: String,
    updated_at: String,
}

struct SearchCertificates;
impl sealed::Sealed for SearchCertificates {}
impl ObservableReadBodyOperation for SearchCertificates {
    type Input = SearchCertificatesRequest;
    type Output = SearchCertificatesResponse;

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects",
                input.project_id.as_str(),
                "certificates",
                "search",
            ],
        )
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RenewCertificateRequest {
    #[serde(skip_serializing)]
    certificate_id: CertificateId,
    remove_roots_from_chain: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenewCertificateResponse {
    certificate: String,
    issuing_ca_certificate: String,
    certificate_chain: String,
    #[serde(deserialize_with = "deserialize_secret")]
    private_key: SecretValue,
    serial_number: String,
    certificate_id: String,
    certificate_request_id: String,
}

fn deserialize_secret<'de, D>(deserializer: D) -> Result<SecretValue, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(SecretValue::new)
}

fn serialize_secret<S>(value: &SecretValue, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.expose_secret())
}

#[allow(clippy::ref_option)]
fn serialize_optional_secret<S>(
    value: &Option<SecretValue>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(value) => serializer.serialize_some(value.expose_secret()),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_secret<'de, D>(deserializer: D) -> Result<Option<SecretValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(SecretValue::new))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportCertificateRequest {
    project_id: CertificateAuthorityProjectId,
    #[serde(serialize_with = "serialize_secret")]
    certificate_pem: SecretValue,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_secret"
    )]
    private_key_pem: Option<SecretValue>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_secret"
    )]
    chain_pem: Option<SecretValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    friendly_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pki_collection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    application_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportCertificateResponse {
    certificate: String,
    serial_number: String,
    #[serde(default)]
    certificate_chain: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    private_key: Option<SecretValue>,
}

#[derive(Serialize)]
struct CertificateMaterialQuery {
    #[serde(skip_serializing)]
    certificate_id: CertificateId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificatePublicMaterialResponse {
    certificate: String,
    #[serde(default)]
    certificate_chain: Option<String>,
    serial_number: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateBundleResponse {
    certificate: String,
    #[serde(default)]
    certificate_chain: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    private_key: Option<SecretValue>,
    serial_number: String,
}

#[derive(Serialize)]
struct RevokeCertificateRequest {
    #[serde(skip_serializing)]
    certificate_id: CertificateId,
    #[serde(rename = "revocationReason")]
    reason: CertificateRevocationReason,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeCertificateResponse {
    message: String,
    serial_number: String,
    revoked_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateCertificateConfigRequest {
    #[serde(skip_serializing)]
    certificate_id: CertificateId,
    #[serde(skip_serializing_if = "Option::is_none")]
    renew_before_days: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enable_auto_renewal: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateCertificateConfigResponse {
    message: String,
    #[serde(default)]
    renew_before_days: Option<u8>,
}

#[derive(Serialize)]
struct DeleteCertificateRequest {
    #[serde(skip_serializing)]
    certificate_id: CertificateId,
}

#[derive(Deserialize)]
struct DeleteCertificateResponse {
    certificate: CertificateWire,
}

struct RenewCertificate;
impl sealed::Sealed for RenewCertificate {}
impl MutationOperation for RenewCertificate {
    type Input = RenewCertificateRequest;
    type Output = RenewCertificateResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "cert-manager",
                "certificates",
                input.certificate_id.as_str(),
                "renew",
            ],
        )
    }
}

struct RevokeCertificate;
impl sealed::Sealed for RevokeCertificate {}
impl MutationOperation for RevokeCertificate {
    type Input = RevokeCertificateRequest;
    type Output = RevokeCertificateResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "cert-manager",
                "certificates",
                input.certificate_id.as_str(),
                "revoke",
            ],
        )
    }
}

struct UpdateCertificateConfig;
impl sealed::Sealed for UpdateCertificateConfig {}
impl MutationOperation for UpdateCertificateConfig {
    type Input = UpdateCertificateConfigRequest;
    type Output = UpdateCertificateConfigResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "cert-manager",
                "certificates",
                input.certificate_id.as_str(),
                "config",
            ],
        )
    }
}

struct DeleteCertificate;
impl sealed::Sealed for DeleteCertificate {}
impl MutationOperation for DeleteCertificate {
    type Input = DeleteCertificateRequest;
    type Output = DeleteCertificateResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "cert-manager",
                "certificates",
                input.certificate_id.as_str(),
            ],
        )
    }
}

struct ImportCertificate;
impl sealed::Sealed for ImportCertificate {}
impl MutationOperation for ImportCertificate {
    type Input = ImportCertificateRequest;
    type Output = ImportCertificateResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["cert-manager", "certificates", "import-certificate"],
        )
    }
}

macro_rules! certificate_material_read {
    ($operation:ident, $output:ty, $suffix:literal) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl ObservableReadOperation for $operation {
            type Query = CertificateMaterialQuery;
            type Output = $output;

            fn endpoint(query: &Self::Query) -> Endpoint {
                Endpoint::from_segments(
                    ApiVersion::V1,
                    [
                        "cert-manager",
                        "certificates",
                        query.certificate_id.as_str(),
                        $suffix,
                    ],
                )
            }
        }
    };
}

certificate_material_read!(
    GetCertificatePublicMaterial,
    CertificatePublicMaterialResponse,
    "certificate"
);
certificate_material_read!(GetCertificatePrivateKey, DeserializedSecret, "private-key");
certificate_material_read!(GetCertificateBundle, CertificateBundleResponse, "bundle");

fn certificate_from_wire(
    wire: CertificateWire,
    project_id: &CertificateAuthorityProjectId,
) -> Result<Certificate, ResourceError> {
    let id = CertificateId::new(wire.id)
        .map_err(|_| ResourceError::InvalidCertificateInventoryResponse)?;
    if wire.project_id != project_id.as_str()
        || wire
            .ca_id
            .as_deref()
            .is_some_and(|value| CertificateAuthorityId::new(value.to_owned()).is_err())
        || wire
            .profile_id
            .as_deref()
            .is_some_and(|value| !is_uuid(value))
        || wire
            .application_id
            .as_deref()
            .is_some_and(|value| !is_uuid(value))
        || wire.serial_number.is_empty()
        || wire.serial_number.len() > MAX_SERIAL_NUMBER_BYTES
        || !valid_text(&wire.serial_number, MAX_SERIAL_NUMBER_BYTES)
        || !valid_text(&wire.friendly_name, MAX_CERTIFICATE_TEXT_BYTES)
        || !valid_text(&wire.common_name, MAX_CERTIFICATE_TEXT_BYTES)
        || wire
            .alt_names
            .as_deref()
            .is_some_and(|value| !valid_text(value, MAX_ALTERNATIVE_NAMES_BYTES))
        || utc_timestamp_millis(&wire.not_before).is_none()
        || utc_timestamp_millis(&wire.not_after).is_none()
        || utc_timestamp_millis(&wire.not_after) <= utc_timestamp_millis(&wire.not_before)
        || wire
            .revoked_at
            .as_deref()
            .is_some_and(|value| utc_timestamp_millis(value).is_none())
        || utc_timestamp_millis(&wire.created_at).is_none()
        || utc_timestamp_millis(&wire.updated_at).is_none()
        || utc_timestamp_millis(&wire.updated_at) < utc_timestamp_millis(&wire.created_at)
        || (wire.status == CertificateStatus::Revoked) != wire.revoked_at.is_some()
        || wire
            .revocation_reason
            .is_some_and(|reason| !matches!(reason, 0..=6 | 8..=10))
        || !valid_optional_text(wire.signature_algorithm.as_deref())
        || !valid_optional_text(wire.ca_name.as_deref())
        || !valid_optional_text(wire.profile_name.as_deref())
        || !valid_optional_text(wire.enrollment_type.as_deref())
        || !valid_optional_text(wire.application_name.as_deref())
        || !valid_usage_values(wire.key_usages.as_deref())
        || !valid_usage_values(wire.extended_key_usages.as_deref())
    {
        return Err(ResourceError::InvalidCertificateInventoryResponse);
    }
    Ok(Certificate {
        id: id.as_str().to_owned(),
        project_id: project_id.as_str().to_owned(),
        friendly_name: wire.friendly_name,
        common_name: wire.common_name,
        status: wire.status,
        serial_number: wire.serial_number,
        not_before: wire.not_before,
        not_after: wire.not_after,
        revoked_at: wire.revoked_at,
        revocation_reason: wire.revocation_reason,
        alternative_names: wire.alt_names,
        key_usages: wire.key_usages,
        extended_key_usages: wire.extended_key_usages,
        key_algorithm: wire.key_algorithm,
        signature_algorithm: wire.signature_algorithm,
        is_ca: wire.is_ca,
        ca_id: wire.ca_id,
        profile_id: wire.profile_id,
        application_id: wire.application_id,
        ca_name: wire.ca_name,
        profile_name: wire.profile_name,
        enrollment_type: wire.enrollment_type,
        application_name: wire.application_name,
        has_private_key: wire.has_private_key,
        created_at: wire.created_at,
        updated_at: wire.updated_at,
    })
}

fn valid_text(value: &str, maximum: usize) -> bool {
    value.len() <= maximum && value.trim() == value && !value.chars().any(char::is_control)
}

fn valid_optional_text(value: Option<&str>) -> bool {
    value.is_none_or(|value| !value.is_empty() && valid_text(value, MAX_CERTIFICATE_TEXT_BYTES))
}

fn valid_usage_values(values: Option<&[String]>) -> bool {
    values.is_none_or(|values| {
        values.len() <= MAX_FILTER_VALUES
            && values
                .iter()
                .all(|value| !value.is_empty() && valid_text(value, MAX_CERTIFICATE_TEXT_BYTES))
            && values.iter().collect::<HashSet<_>>().len() == values.len()
    })
}

fn validate_page(page: PageRequest, returned: usize, total: u64) -> Result<(), ResourceError> {
    if returned > usize::from(page.limit()) {
        return Err(ResourceError::InvalidCertificateInventoryResponse);
    }
    let returned =
        u64::try_from(returned).map_err(|_| ResourceError::InvalidCertificateInventoryResponse)?;
    let end = u64::from(page.offset())
        .checked_add(returned)
        .ok_or(ResourceError::InvalidCertificateInventoryResponse)?;
    let consistent = if returned == 0 {
        u64::from(page.offset()) >= total
    } else if returned < u64::from(page.limit()) {
        end == total
    } else {
        end <= total
    };
    if !consistent {
        return Err(ResourceError::InvalidCertificateInventoryResponse);
    }
    Ok(())
}

fn certificate_matches_request(
    certificate: &Certificate,
    request: &CertificateListRequest,
) -> bool {
    if request
        .status
        .is_some_and(|status| certificate.status != status)
        || request.profile_ids.as_ref().is_some_and(|ids| {
            certificate
                .profile_id
                .as_ref()
                .is_none_or(|id| !ids.contains(id))
        })
        || request.ca_ids.as_ref().is_some_and(|ids| {
            certificate
                .ca_id
                .as_ref()
                .is_none_or(|id| !ids.contains(id))
        })
        || request.application_ids.as_ref().is_some_and(|ids| {
            certificate
                .application_id
                .as_ref()
                .is_none_or(|id| !ids.contains(id))
        })
        || request.key_algorithms.as_ref().is_some_and(|algorithms| {
            certificate
                .key_algorithm
                .is_none_or(|algorithm| !algorithms.contains(&algorithm))
        })
    {
        return false;
    }
    request.search.as_deref().is_none_or(|search| {
        let search = search.to_lowercase();
        certificate.id.to_lowercase().contains(&search)
            || certificate.serial_number.to_lowercase().contains(&search)
            || certificate.common_name.to_lowercase().contains(&search)
            || certificate
                .alternative_names
                .as_deref()
                .is_some_and(|value| value.to_lowercase().contains(&search))
    })
}

fn certificate_is_end_entity(certificate: &Certificate) -> bool {
    certificate.is_ca == Some(false)
}

fn certificate_supports_managed_renewal(certificate: &Certificate) -> bool {
    certificate.status == CertificateStatus::Active
        && certificate_is_end_entity(certificate)
        && certificate.has_private_key
        && certificate.profile_id.is_some()
        && certificate.enrollment_type.as_deref() == Some("api")
}

fn certificate_supports_renewal_configuration(certificate: &Certificate) -> bool {
    certificate.status == CertificateStatus::Active
        && certificate_is_end_entity(certificate)
        && certificate.has_private_key
        && certificate.profile_id.is_some()
        && certificate.enrollment_type.as_deref() == Some("api")
}

fn normalize_lifecycle_pem(value: &str, maximum: usize) -> Option<String> {
    (!value.is_empty() && value.len() <= maximum)
        .then(|| normalize_pem(value))
        .flatten()
}

fn normalize_lifecycle_certificate(value: &str) -> Option<String> {
    let value = normalize_lifecycle_pem(value, MAX_CERTIFICATE_PEM_BYTES)?;
    let values = certificate_bundle_der(&value)?;
    (values.len() == 1
        && X509Certificate::from_der(&values[0]).is_ok_and(|(remainder, _)| remainder.is_empty()))
    .then_some(value)
}

fn normalize_lifecycle_chain(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some(String::new());
    }
    let value = normalize_lifecycle_pem(value, MAX_CERTIFICATE_CHAIN_PEM_BYTES)?;
    let values = certificate_bundle_der(&value)?;
    (!values.is_empty()
        && values.iter().all(|der| {
            X509Certificate::from_der(der).is_ok_and(|(remainder, _)| remainder.is_empty())
        }))
    .then_some(value)
}

fn lifecycle_chain_ends_in_self_signed_root(value: &str) -> bool {
    let Some(der) = certificate_bundle_der(value).and_then(|values| values.into_iter().last())
    else {
        return false;
    };
    X509Certificate::from_der(&der).is_ok_and(|(remainder, certificate)| {
        remainder.is_empty()
            && certificate.issuer() == certificate.subject()
            && certificate_signature_is_valid(&certificate, &certificate)
    })
}

fn lifecycle_issuer_matches_leaf(
    leaf: &X509Certificate<'_>,
    issuing_certificate: &str,
    chain: &str,
    validation_time: ASN1Time,
) -> bool {
    if issuing_certificate.is_empty() {
        return chain.is_empty()
            && leaf.issuer() == leaf.subject()
            && certificate_signature_is_valid(leaf, leaf);
    }
    let Some(issuer_der) = certificate_bundle_der(issuing_certificate)
        .and_then(|mut values| (values.len() == 1).then(|| values.pop()).flatten())
    else {
        return false;
    };
    let Ok((remainder, issuer)) = X509Certificate::from_der(&issuer_der) else {
        return false;
    };
    if !remainder.is_empty()
        || !issuer.validity().is_valid_at(validation_time)
        || !issuer.is_ca()
        || !issuer
            .key_usage()
            .is_ok_and(|usage| usage.is_none_or(|usage| usage.value.key_cert_sign()))
        || leaf.issuer() != issuer.subject()
        || !certificate_signature_is_valid(leaf, &issuer)
    {
        return false;
    }
    chain.is_empty()
        || certificate_bundle_der(chain)
            .and_then(|values| values.into_iter().next())
            .as_deref()
            == Some(issuer_der.as_slice())
}

fn lifecycle_certificate_is_end_entity(certificate: &X509Certificate<'_>) -> bool {
    certificate
        .basic_constraints()
        .is_ok_and(|constraints| constraints.is_none_or(|value| !value.value.ca))
        && certificate
            .key_usage()
            .is_ok_and(|usage| usage.is_none_or(|value| !value.value.key_cert_sign()))
}

fn lifecycle_certificate_key_algorithm_matches(
    certificate: &X509Certificate<'_>,
    expected: Option<CertificateKeyAlgorithm>,
) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let public_key = certificate.public_key();
    match expected {
        CertificateKeyAlgorithm::Rsa2048
        | CertificateKeyAlgorithm::Rsa3072
        | CertificateKeyAlgorithm::Rsa4096 => {
            let expected_bits = match expected {
                CertificateKeyAlgorithm::Rsa2048 => 2_048,
                CertificateKeyAlgorithm::Rsa3072 => 3_072,
                CertificateKeyAlgorithm::Rsa4096 => 4_096,
                _ => unreachable!(),
            };
            public_key.parsed().is_ok_and(
                |key| matches!(key, PublicKey::RSA(key) if key.key_size() == expected_bits),
            )
        }
        CertificateKeyAlgorithm::EcPrime256v1
        | CertificateKeyAlgorithm::EcSecp384r1
        | CertificateKeyAlgorithm::EcSecp521r1 => {
            let (expected_curve, expected_bytes) = match expected {
                CertificateKeyAlgorithm::EcPrime256v1 => ("1.2.840.10045.3.1.7", 65),
                CertificateKeyAlgorithm::EcSecp384r1 => ("1.3.132.0.34", 97),
                CertificateKeyAlgorithm::EcSecp521r1 => ("1.3.132.0.35", 133),
                _ => unreachable!(),
            };
            let curve = public_key
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.as_oid().ok())
                .map(|oid| oid.to_id_string());
            curve.as_deref() == Some(expected_curve)
                && public_key.parsed().is_ok_and(
                    |key| matches!(key, PublicKey::EC(point) if point.data().len() == expected_bytes && point.data().first() == Some(&4)),
                )
        }
        algorithm => {
            let expected_oid = match algorithm {
                CertificateKeyAlgorithm::MlDsa44 => "2.16.840.1.101.3.4.3.17",
                CertificateKeyAlgorithm::MlDsa65 => "2.16.840.1.101.3.4.3.18",
                CertificateKeyAlgorithm::MlDsa87 => "2.16.840.1.101.3.4.3.19",
                CertificateKeyAlgorithm::SlhDsaSha2_128s => "2.16.840.1.101.3.4.3.20",
                CertificateKeyAlgorithm::SlhDsaSha2_128f => "2.16.840.1.101.3.4.3.21",
                CertificateKeyAlgorithm::SlhDsaSha2_192s => "2.16.840.1.101.3.4.3.22",
                CertificateKeyAlgorithm::SlhDsaSha2_192f => "2.16.840.1.101.3.4.3.23",
                CertificateKeyAlgorithm::SlhDsaSha2_256s => "2.16.840.1.101.3.4.3.24",
                CertificateKeyAlgorithm::SlhDsaSha2_256f => "2.16.840.1.101.3.4.3.25",
                CertificateKeyAlgorithm::SlhDsaShake128s => "2.16.840.1.101.3.4.3.26",
                CertificateKeyAlgorithm::SlhDsaShake128f => "2.16.840.1.101.3.4.3.27",
                CertificateKeyAlgorithm::SlhDsaShake192s => "2.16.840.1.101.3.4.3.28",
                CertificateKeyAlgorithm::SlhDsaShake192f => "2.16.840.1.101.3.4.3.29",
                CertificateKeyAlgorithm::SlhDsaShake256s => "2.16.840.1.101.3.4.3.30",
                CertificateKeyAlgorithm::SlhDsaShake256f => "2.16.840.1.101.3.4.3.31",
                _ => unreachable!(),
            };
            public_key.algorithm.algorithm.to_id_string() == expected_oid
                && public_key.algorithm.parameters.is_none()
        }
    }
}

fn lifecycle_certificate_key_usages_match(
    certificate: &X509Certificate<'_>,
    expected: Option<&[String]>,
) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let Ok(extension) = certificate.key_usage() else {
        return false;
    };
    let mut actual = HashSet::new();
    if let Some(extension) = extension {
        let usage = extension.value;
        if usage.flags & !0x01ff != 0 {
            return false;
        }
        for (present, name) in [
            (usage.digital_signature(), "digitalSignature"),
            (usage.key_encipherment(), "keyEncipherment"),
            (usage.non_repudiation(), "nonRepudiation"),
            (usage.data_encipherment(), "dataEncipherment"),
            (usage.key_agreement(), "keyAgreement"),
            (usage.key_cert_sign(), "keyCertSign"),
            (usage.crl_sign(), "cRLSign"),
            (usage.encipher_only(), "encipherOnly"),
            (usage.decipher_only(), "decipherOnly"),
        ] {
            if present {
                actual.insert(name);
            }
        }
    }
    actual == expected.iter().map(String::as_str).collect::<HashSet<_>>()
}

fn lifecycle_certificate_extended_key_usages_match(
    certificate: &X509Certificate<'_>,
    expected: Option<&[String]>,
) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let Ok(extension) = certificate.extended_key_usage() else {
        return false;
    };
    let mut actual = HashSet::new();
    if let Some(extension) = extension {
        let usage = extension.value;
        if usage.any || !usage.other.is_empty() {
            return false;
        }
        for (present, name) in [
            (usage.client_auth, "clientAuth"),
            (usage.server_auth, "serverAuth"),
            (usage.code_signing, "codeSigning"),
            (usage.email_protection, "emailProtection"),
            (usage.ocsp_signing, "ocspSigning"),
            (usage.time_stamping, "timeStamping"),
        ] {
            if present {
                actual.insert(name);
            }
        }
    }
    actual == expected.iter().map(String::as_str).collect::<HashSet<_>>()
}

fn renewed_certificate_from_wire(
    wire: RenewCertificateResponse,
    project_id: &CertificateAuthorityProjectId,
    before: &Certificate,
    remove_roots_from_chain: bool,
) -> Result<RenewedCertificate, ResourceError> {
    let certificate_id = CertificateId::new(wire.certificate_id)
        .map_err(|_| ResourceError::InvalidCertificateLifecycleResponse)?;
    let request_id = CertificateRequestId::new(wire.certificate_request_id)
        .map_err(|_| ResourceError::InvalidCertificateLifecycleResponse)?;
    if certificate_id.as_str() == before.id
        || certificate_serial_values_match(&wire.serial_number, &before.serial_number)
        || wire.serial_number.is_empty()
        || wire.serial_number.len() > MAX_SERIAL_NUMBER_BYTES
        || !wire
            .serial_number
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ResourceError::InvalidCertificateLifecycleResponse);
    }
    let certificate = normalize_lifecycle_certificate(&wire.certificate)
        .ok_or(ResourceError::InvalidCertificateLifecycleResponse)?;
    let issuing_ca_certificate = if wire.issuing_ca_certificate.is_empty() {
        String::new()
    } else {
        normalize_lifecycle_certificate(&wire.issuing_ca_certificate)
            .ok_or(ResourceError::InvalidCertificateLifecycleResponse)?
    };
    let certificate_chain = normalize_lifecycle_chain(&wire.certificate_chain)
        .ok_or(ResourceError::InvalidCertificateLifecycleResponse)?;
    let private_key =
        normalize_lifecycle_pem(wire.private_key.expose_secret(), MAX_CERTIFICATE_PEM_BYTES)
            .map(SecretValue::new)
            .ok_or(ResourceError::InvalidCertificateLifecycleResponse)?;
    let total = [
        certificate.len(),
        issuing_ca_certificate.len(),
        certificate_chain.len(),
        private_key.expose_secret().len(),
    ]
    .into_iter()
    .try_fold(0_usize, usize::checked_add);
    let certificate_der = certificate_bundle_der(&certificate)
        .and_then(|mut values| (values.len() == 1).then(|| values.pop()).flatten())
        .ok_or(ResourceError::InvalidCertificateLifecycleResponse)?;
    let (remainder, parsed) = X509Certificate::from_der(&certificate_der)
        .map_err(|_| ResourceError::InvalidCertificateLifecycleResponse)?;
    let validation_time = ASN1Time::now();
    if !remainder.is_empty()
        || total.is_none_or(|total| total > MAX_CERTIFICATE_LIFECYCLE_MATERIAL_BYTES)
        || !parsed.validity().is_valid_at(validation_time)
        || !certificate_serial_matches(&parsed, &wire.serial_number)
        || !lifecycle_certificate_is_end_entity(&parsed)
        || !lifecycle_certificate_key_algorithm_matches(&parsed, before.key_algorithm)
        || !lifecycle_certificate_key_usages_match(&parsed, before.key_usages.as_deref())
        || !lifecycle_certificate_extended_key_usages_match(
            &parsed,
            before.extended_key_usages.as_deref(),
        )
        || !certificate_subject_values_match(
            &parsed,
            Some(before.common_name.as_str()),
            before.alternative_names.as_deref(),
        )
        || !private_key_matches_certificate(&parsed, private_key.expose_secret())
        || !(certificate_chain_belongs_to_leaf(&parsed, &certificate_chain, validation_time)
            || (remove_roots_from_chain && certificate_chain.is_empty()))
        || (before.ca_id.is_some() && issuing_ca_certificate.is_empty())
        || (remove_roots_from_chain && lifecycle_chain_ends_in_self_signed_root(&certificate_chain))
        || !lifecycle_issuer_matches_leaf(
            &parsed,
            &issuing_ca_certificate,
            &certificate_chain,
            validation_time,
        )
    {
        return Err(ResourceError::InvalidCertificateLifecycleResponse);
    }
    Ok(RenewedCertificate {
        project_id: project_id.as_str().to_owned(),
        previous_certificate_id: before.id.clone(),
        certificate_id: certificate_id.as_str().to_owned(),
        request_id: request_id.as_str().to_owned(),
        serial_number: wire.serial_number,
        certificate,
        issuing_ca_certificate,
        certificate_chain,
        private_key,
    })
}

fn renewed_inventory_matches_source(
    before: &Certificate,
    after: &Certificate,
    renewed: &RenewedCertificate,
) -> bool {
    after.id == renewed.certificate_id
        && after.project_id == before.project_id
        && after.status == CertificateStatus::Active
        && certificate_is_end_entity(after)
        && after.has_private_key
        && after.ca_id == before.ca_id
        && after.profile_id == before.profile_id
        && certificate_serial_values_match(&after.serial_number, &renewed.serial_number)
}

fn public_material_from_wire(
    wire: CertificatePublicMaterialResponse,
    project_id: &CertificateAuthorityProjectId,
    before: &Certificate,
) -> Result<CertificatePublicMaterial, ResourceError> {
    let certificate = normalize_lifecycle_certificate(&wire.certificate)
        .ok_or(ResourceError::InvalidCertificateMaterialResponse)?;
    let certificate_chain = match wire.certificate_chain {
        Some(value) if !value.is_empty() => normalize_lifecycle_chain(&value)
            .ok_or(ResourceError::InvalidCertificateMaterialResponse)?,
        Some(_) | None => String::new(),
    };
    let certificate_der = certificate_bundle_der(&certificate)
        .and_then(|mut values| (values.len() == 1).then(|| values.pop()).flatten())
        .ok_or(ResourceError::InvalidCertificateMaterialResponse)?;
    let (remainder, parsed) = X509Certificate::from_der(&certificate_der)
        .map_err(|_| ResourceError::InvalidCertificateMaterialResponse)?;
    let parsed_is_ca = parsed
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|constraints| constraints.value.ca);
    if !remainder.is_empty()
        || wire.serial_number.is_empty()
        || wire.serial_number.len() > MAX_SERIAL_NUMBER_BYTES
        || !certificate_serial_matches(&parsed, &wire.serial_number)
        || !certificate_serial_values_match(&wire.serial_number, &before.serial_number)
        || !certificate_subject_values_match(
            &parsed,
            Some(before.common_name.as_str()),
            before.alternative_names.as_deref(),
        )
        || before
            .is_ca
            .is_some_and(|expected| expected != parsed_is_ca)
        || (!certificate_chain.is_empty()
            && !certificate_chain_is_linked_to_leaf(&parsed, &certificate_chain))
    {
        return Err(ResourceError::InvalidCertificateMaterialResponse);
    }
    Ok(CertificatePublicMaterial {
        project_id: project_id.as_str().to_owned(),
        certificate_id: before.id.clone(),
        serial_number: wire.serial_number,
        certificate,
        certificate_chain,
    })
}

fn bundle_from_wire(
    wire: CertificateBundleResponse,
    project_id: &CertificateAuthorityProjectId,
    before: &Certificate,
) -> Result<CertificateBundle, ResourceError> {
    let public = public_material_from_wire(
        CertificatePublicMaterialResponse {
            certificate: wire.certificate,
            certificate_chain: wire.certificate_chain,
            serial_number: wire.serial_number,
        },
        project_id,
        before,
    )?;
    let private_key = wire
        .private_key
        .map(|value| {
            let normalized =
                normalize_lifecycle_pem(value.expose_secret(), MAX_CERTIFICATE_PEM_BYTES)
                    .ok_or(ResourceError::InvalidCertificateMaterialResponse)?;
            let certificate_der = certificate_bundle_der(&public.certificate)
                .and_then(|mut values| (values.len() == 1).then(|| values.pop()).flatten())
                .ok_or(ResourceError::InvalidCertificateMaterialResponse)?;
            let (remainder, parsed) = X509Certificate::from_der(&certificate_der)
                .map_err(|_| ResourceError::InvalidCertificateMaterialResponse)?;
            if !remainder.is_empty() || !private_key_matches_certificate(&parsed, &normalized) {
                return Err(ResourceError::InvalidCertificateMaterialResponse);
            }
            Ok(SecretValue::new(normalized))
        })
        .transpose()?;
    if before.has_private_key != private_key.is_some() {
        return Err(ResourceError::InvalidCertificateMaterialResponse);
    }
    Ok(CertificateBundle {
        project_id: public.project_id,
        certificate_id: public.certificate_id,
        serial_number: public.serial_number,
        certificate: public.certificate,
        certificate_chain: public.certificate_chain,
        private_key,
    })
}

fn import_response_matches_request(
    wire: &ImportCertificateResponse,
    request: &ImportCertificateRequest,
) -> bool {
    let Some(certificate) = normalize_lifecycle_certificate(&wire.certificate) else {
        return false;
    };
    let certificate_chain = match wire.certificate_chain.as_deref() {
        Some(value) if !value.is_empty() => {
            let Some(normalized) = normalize_lifecycle_chain(value) else {
                return false;
            };
            Some(normalized)
        }
        Some(_) | None => Some(String::new()),
    };
    let private_key = match wire.private_key.as_ref() {
        Some(value) if !value.expose_secret().is_empty() => {
            let Some(normalized) =
                normalize_lifecycle_pem(value.expose_secret(), MAX_CERTIFICATE_PEM_BYTES)
            else {
                return false;
            };
            Some(normalized)
        }
        Some(_) | None => None,
    };
    let certificate_der = certificate_bundle_der(&certificate)
        .and_then(|mut values| (values.len() == 1).then(|| values.pop()).flatten());
    let serial_matches = certificate_der.as_deref().is_some_and(|der| {
        X509Certificate::from_der(der).is_ok_and(|(remainder, parsed)| {
            remainder.is_empty() && certificate_serial_matches(&parsed, &wire.serial_number)
        })
    });
    certificate == request.certificate_pem.expose_secret()
        && certificate_chain.as_deref().unwrap_or_default()
            == request
                .chain_pem
                .as_ref()
                .map_or("", SecretValue::expose_secret)
        && private_key.as_deref()
            == request
                .private_key_pem
                .as_ref()
                .map(SecretValue::expose_secret)
        && serial_matches
}

fn imported_inventory_matches_request(
    certificate: &Certificate,
    request: &ImportCertificateRequest,
    serial_number: &str,
) -> bool {
    let Some(certificate_der) = certificate_bundle_der(request.certificate_pem.expose_secret())
        .and_then(|mut values| (values.len() == 1).then(|| values.pop()).flatten())
    else {
        return false;
    };
    let Ok((remainder, parsed)) = X509Certificate::from_der(&certificate_der) else {
        return false;
    };
    remainder.is_empty()
        && certificate.status == CertificateStatus::Active
        && certificate_serial_values_match(&certificate.serial_number, serial_number)
        && certificate.has_private_key == request.private_key_pem.is_some()
        && certificate.application_id == request.application_id
        && request
            .friendly_name
            .as_ref()
            .is_none_or(|name| certificate.friendly_name == *name)
        && certificate_subject_values_match(
            &parsed,
            Some(certificate.common_name.as_str()),
            certificate.alternative_names.as_deref(),
        )
}

fn imported_certificate_serial(request: &ImportCertificateRequest) -> Option<String> {
    let certificate_der = certificate_bundle_der(request.certificate_pem.expose_secret())
        .and_then(|mut values| (values.len() == 1).then(|| values.pop()).flatten())?;
    let (remainder, parsed) = X509Certificate::from_der(&certificate_der).ok()?;
    if !remainder.is_empty() {
        return None;
    }
    let serial = parsed.raw_serial_as_string().replace(':', "");
    let serial = serial.trim_start_matches('0');
    Some(if serial.is_empty() {
        "0".to_owned()
    } else {
        serial.to_ascii_uppercase()
    })
}

fn lifecycle_unknown(error: ClientError, unknown: ResourceError) -> ResourceError {
    match error {
        ClientError::Transport(_)
        | ClientError::ResponseTooLarge { .. }
        | ClientError::InvalidMutationResponse => unknown,
        ClientError::Api(ref failure) if failure.kind() == ApiErrorKind::Server => unknown,
        other => ResourceError::Client(other),
    }
}

impl InfisicalClient {
    /// Search one bounded page of sanitized certificate metadata in a project.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, filter, response-contract, or pagination error.
    pub async fn list_certificates(
        &self,
        request: CertificateListRequest,
    ) -> Result<Page<Certificate>, ResourceError> {
        let response = self
            .execute_observable_read_body::<SearchCertificates>(&SearchCertificatesRequest {
                project_id: request.project_id.clone(),
                offset: request.page.offset(),
                limit: request.page.limit(),
                search: request.search.clone(),
                status: request.status,
                profile_ids: request.profile_ids.clone(),
                ca_ids: request.ca_ids.clone(),
                application_ids: request.application_ids.clone(),
                key_algorithms: request.key_algorithms.clone(),
                sort_by: request.sort_by,
                sort_order: request.sort_order,
            })
            .await?;
        validate_page(
            request.page,
            response.certificates.len(),
            response.total_count,
        )?;
        let certificates = response
            .certificates
            .into_iter()
            .map(|wire| certificate_from_wire(wire, &request.project_id))
            .collect::<Result<Vec<_>, _>>()?;
        if certificates
            .iter()
            .map(|certificate| certificate.id.as_str())
            .collect::<HashSet<_>>()
            .len()
            != certificates.len()
            || certificates
                .iter()
                .any(|certificate| !certificate_matches_request(certificate, &request))
        {
            return Err(ResourceError::InvalidCertificateInventoryResponse);
        }
        Ok(Page::new(
            request.page,
            certificates,
            Some(response.total_count),
        )?)
    }

    /// Retrieve one exact certificate as sanitized project-scoped metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or response-contract error when the exact
    /// certificate is absent or the search response is not bound to the target.
    pub async fn get_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        certificate_id: &CertificateId,
    ) -> Result<Certificate, ResourceError> {
        let mut next = Some(PageRequest::new(0, 100)?);
        let mut expected_total = None;
        let mut seen_ids = HashSet::new();
        while let Some(page_request) = next {
            let request = CertificateListRequest::new(
                project_id.clone(),
                page_request,
                Some(certificate_id.as_str().to_owned()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .map_err(|_| ResourceError::InvalidCertificateInventoryResponse)?;
            let page = self.list_certificates(request).await?;
            let total = page
                .total
                .ok_or(ResourceError::InvalidCertificateInventoryResponse)?;
            if expected_total.is_some_and(|expected| expected != total) {
                return Err(ResourceError::InvalidCertificateInventoryResponse);
            }
            expected_total = Some(total);
            for certificate in page.items {
                if !seen_ids.insert(certificate.id.clone()) {
                    return Err(ResourceError::InvalidCertificateInventoryResponse);
                }
                if certificate.id == certificate_id.as_str() {
                    return Ok(certificate);
                }
            }
            next = page.next;
        }
        Err(ResourceError::InvalidCertificateInventoryScope)
    }

    async fn certificates_by_serial(
        &self,
        project_id: &CertificateAuthorityProjectId,
        serial_number: &str,
    ) -> Result<Vec<Certificate>, ResourceError> {
        let request = CertificateListRequest::new(
            project_id.clone(),
            PageRequest::new(0, MAX_PAGE_SIZE)?,
            Some(serial_number.to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .map_err(|_| ResourceError::InvalidCertificateInventoryResponse)?;
        let page = self.list_certificates(request).await?;
        if page.next.is_some() {
            return Err(ResourceError::InvalidCertificateInventoryScope);
        }
        Ok(page
            .items
            .into_iter()
            .filter(|certificate| {
                certificate_serial_values_match(&certificate.serial_number, serial_number)
            })
            .collect())
    }

    /// Import one validated certificate and optional private material exactly once.
    ///
    /// # Errors
    ///
    /// Returns a typed confirmation, project scope, upstream, or unknown-outcome error.
    pub async fn import_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        certificate_import: CertificateImport,
        confirm: bool,
    ) -> Result<Certificate, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateImportNotConfirmed);
        }
        let request = ImportCertificateRequest {
            project_id: project_id.clone(),
            certificate_pem: certificate_import.certificate,
            private_key_pem: certificate_import.private_key,
            chain_pem: certificate_import.certificate_chain,
            friendly_name: certificate_import.friendly_name,
            pki_collection_id: certificate_import.pki_collection_id,
            application_id: certificate_import.application_id,
        };
        let requested_serial = imported_certificate_serial(&request)
            .ok_or(ResourceError::InvalidCertificateMaterialResponse)?;
        let existing_ids = self
            .certificates_by_serial(project_id, &requested_serial)
            .await?
            .into_iter()
            .map(|certificate| certificate.id)
            .collect::<HashSet<_>>();
        let response = self
            .execute_mutation::<ImportCertificate>(&request)
            .await
            .map_err(|error| {
                lifecycle_unknown(error, ResourceError::CertificateImportOutcomeUnknown)
            })?;
        if !import_response_matches_request(&response, &request) {
            return Err(ResourceError::CertificateImportOutcomeUnknown);
        }
        let mut imported = self
            .certificates_by_serial(project_id, &requested_serial)
            .await
            .map_err(|_| ResourceError::CertificateImportOutcomeUnknown)?
            .into_iter()
            .filter(|certificate| {
                !existing_ids.contains(&certificate.id)
                    && imported_inventory_matches_request(
                        certificate,
                        &request,
                        &response.serial_number,
                    )
            })
            .collect::<Vec<_>>();
        if imported.len() != 1 {
            return Err(ResourceError::CertificateImportOutcomeUnknown);
        }
        imported
            .pop()
            .ok_or(ResourceError::CertificateImportOutcomeUnknown)
    }

    /// Retrieve public certificate and issuer-chain material for one project record.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or response-contract error.
    pub async fn get_certificate_public_material(
        &self,
        project_id: &CertificateAuthorityProjectId,
        certificate_id: &CertificateId,
    ) -> Result<CertificatePublicMaterial, ResourceError> {
        let before = self.get_certificate(project_id, certificate_id).await?;
        let response = self
            .execute_observable_read::<GetCertificatePublicMaterial>(&CertificateMaterialQuery {
                certificate_id: certificate_id.clone(),
            })
            .await?;
        public_material_from_wire(response, project_id, &before)
    }

    /// Reveal one complete certificate bundle after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, typed client, scope, or response-contract error.
    pub async fn reveal_certificate_bundle(
        &self,
        project_id: &CertificateAuthorityProjectId,
        certificate_id: &CertificateId,
        confirm: bool,
    ) -> Result<CertificateBundle, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateMaterialRevealNotConfirmed);
        }
        let before = self.get_certificate(project_id, certificate_id).await?;
        let response = self
            .execute_observable_read::<GetCertificateBundle>(&CertificateMaterialQuery {
                certificate_id: certificate_id.clone(),
            })
            .await?;
        bundle_from_wire(response, project_id, &before)
    }

    /// Reveal one certificate private key after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, typed client, scope, custody, or response-contract error.
    pub async fn reveal_certificate_private_key(
        &self,
        project_id: &CertificateAuthorityProjectId,
        certificate_id: &CertificateId,
        confirm: bool,
    ) -> Result<CertificatePrivateKey, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateMaterialRevealNotConfirmed);
        }
        let before = self.get_certificate(project_id, certificate_id).await?;
        if !before.has_private_key {
            return Err(ResourceError::CertificatePrivateKeyUnavailable);
        }
        let public_response = self
            .execute_observable_read::<GetCertificatePublicMaterial>(&CertificateMaterialQuery {
                certificate_id: certificate_id.clone(),
            })
            .await?;
        let public = public_material_from_wire(public_response, project_id, &before)?;
        let response = self
            .execute_observable_read::<GetCertificatePrivateKey>(&CertificateMaterialQuery {
                certificate_id: certificate_id.clone(),
            })
            .await?;
        let private_key =
            normalize_lifecycle_pem(response.0.expose_secret(), MAX_CERTIFICATE_PEM_BYTES)
                .ok_or(ResourceError::InvalidCertificateMaterialResponse)?;
        let certificate_der = certificate_bundle_der(&public.certificate)
            .and_then(|mut values| (values.len() == 1).then(|| values.pop()).flatten())
            .ok_or(ResourceError::InvalidCertificateMaterialResponse)?;
        let (remainder, parsed) = X509Certificate::from_der(&certificate_der)
            .map_err(|_| ResourceError::InvalidCertificateMaterialResponse)?;
        if !remainder.is_empty() || !private_key_matches_certificate(&parsed, &private_key) {
            return Err(ResourceError::InvalidCertificateMaterialResponse);
        }
        Ok(CertificatePrivateKey {
            project_id: project_id.as_str().to_owned(),
            certificate_id: certificate_id.as_str().to_owned(),
            serial_number: public.serial_number,
            private_key: SecretValue::new(private_key),
        })
    }

    /// Renew one active API-enrolled managed-key certificate exactly once.
    ///
    /// # Errors
    ///
    /// Returns a typed confirmation, scope, state, upstream, or unknown-outcome error.
    pub async fn renew_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        certificate_id: &CertificateId,
        remove_roots_from_chain: bool,
        confirm: bool,
    ) -> Result<RenewedCertificate, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateRenewalNotConfirmed);
        }
        let before = self.get_certificate(project_id, certificate_id).await?;
        if !certificate_supports_managed_renewal(&before) {
            return Err(ResourceError::InvalidCertificateLifecycleState);
        }
        let response = self
            .execute_mutation::<RenewCertificate>(&RenewCertificateRequest {
                certificate_id: certificate_id.clone(),
                remove_roots_from_chain,
            })
            .await
            .map_err(|error| {
                lifecycle_unknown(error, ResourceError::CertificateRenewalOutcomeUnknown)
            })?;
        let renewed =
            renewed_certificate_from_wire(response, project_id, &before, remove_roots_from_chain)
                .map_err(|_| ResourceError::CertificateRenewalOutcomeUnknown)?;
        let renewed_id = CertificateId::new(renewed.certificate_id.clone())
            .map_err(|_| ResourceError::CertificateRenewalOutcomeUnknown)?;
        let after = self
            .get_certificate(project_id, &renewed_id)
            .await
            .map_err(|_| ResourceError::CertificateRenewalOutcomeUnknown)?;
        if !renewed_inventory_matches_source(&before, &after, &renewed) {
            return Err(ResourceError::CertificateRenewalOutcomeUnknown);
        }
        Ok(renewed)
    }

    /// Revoke one active project-owned certificate exactly once.
    ///
    /// # Errors
    ///
    /// Returns a typed confirmation, scope, state, upstream, or unknown-outcome error.
    pub async fn revoke_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        certificate_id: &CertificateId,
        reason: CertificateRevocationReason,
        confirm: bool,
    ) -> Result<CertificateRevocation, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateRevocationNotConfirmed);
        }
        let before = self.get_certificate(project_id, certificate_id).await?;
        if before.status != CertificateStatus::Active || !certificate_is_end_entity(&before) {
            return Err(ResourceError::InvalidCertificateLifecycleState);
        }
        let response = self
            .execute_mutation::<RevokeCertificate>(&RevokeCertificateRequest {
                certificate_id: certificate_id.clone(),
                reason,
            })
            .await
            .map_err(|error| {
                lifecycle_unknown(error, ResourceError::CertificateRevocationOutcomeUnknown)
            })?;
        if !valid_text(&response.message, MAX_CERTIFICATE_TEXT_BYTES)
            || response.message.is_empty()
            || response.serial_number != before.serial_number
            || utc_timestamp_millis(&response.revoked_at).is_none()
        {
            return Err(ResourceError::CertificateRevocationOutcomeUnknown);
        }
        Ok(CertificateRevocation {
            project_id: project_id.as_str().to_owned(),
            certificate_id: certificate_id.as_str().to_owned(),
            serial_number: response.serial_number,
            reason,
            revoked_at: response.revoked_at,
        })
    }

    /// Change the automatic-renewal configuration of one eligible certificate.
    ///
    /// # Errors
    ///
    /// Returns a typed scope, state, upstream, or unknown-outcome error.
    pub async fn update_certificate_renewal_configuration(
        &self,
        project_id: &CertificateAuthorityProjectId,
        certificate_id: &CertificateId,
        change: CertificateRenewalConfigurationChange,
    ) -> Result<CertificateRenewalConfiguration, ResourceError> {
        let before = self.get_certificate(project_id, certificate_id).await?;
        if !certificate_supports_renewal_configuration(&before) {
            return Err(ResourceError::InvalidCertificateLifecycleState);
        }
        let (renew_before_days, enable_auto_renewal) = match change {
            CertificateRenewalConfigurationChange::RenewBeforeDays(days) => {
                (Some(days.get()), None)
            }
            CertificateRenewalConfigurationChange::Disable => (None, Some(false)),
        };
        let response = self
            .execute_mutation::<UpdateCertificateConfig>(&UpdateCertificateConfigRequest {
                certificate_id: certificate_id.clone(),
                renew_before_days,
                enable_auto_renewal,
            })
            .await
            .map_err(|error| {
                lifecycle_unknown(
                    error,
                    ResourceError::CertificateRenewalConfigurationOutcomeUnknown,
                )
            })?;
        if response.message.is_empty()
            || !valid_text(&response.message, MAX_CERTIFICATE_TEXT_BYTES)
            || response.renew_before_days != renew_before_days
        {
            return Err(ResourceError::CertificateRenewalConfigurationOutcomeUnknown);
        }
        Ok(CertificateRenewalConfiguration {
            project_id: project_id.as_str().to_owned(),
            certificate_id: certificate_id.as_str().to_owned(),
            enabled: renew_before_days.is_some(),
            renew_before_days,
        })
    }

    /// Permanently delete one exact project-owned certificate.
    ///
    /// # Errors
    ///
    /// Returns a typed confirmation, scope, upstream, or unknown-outcome error.
    pub async fn delete_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        certificate_id: &CertificateId,
        confirm: bool,
    ) -> Result<Certificate, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateDeletionNotConfirmed);
        }
        let before = self.get_certificate(project_id, certificate_id).await?;
        if !certificate_is_end_entity(&before) {
            return Err(ResourceError::InvalidCertificateLifecycleState);
        }
        let response = self
            .execute_mutation::<DeleteCertificate>(&DeleteCertificateRequest {
                certificate_id: certificate_id.clone(),
            })
            .await
            .map_err(|error| {
                lifecycle_unknown(error, ResourceError::CertificateDeletionOutcomeUnknown)
            })?;
        let deleted = certificate_from_wire(response.certificate, project_id)
            .map_err(|_| ResourceError::CertificateDeletionOutcomeUnknown)?;
        if deleted.id != before.id
            || deleted.serial_number != before.serial_number
            || deleted.status != before.status
        {
            return Err(ResourceError::CertificateDeletionOutcomeUnknown);
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };
    use x509_parser::{
        prelude::{FromDer, X509Certificate},
        time::ASN1Time,
    };

    use super::{
        CertificateId, CertificateImport, CertificateInputError, CertificateInventorySort,
        CertificateInventorySortOrder, CertificateListRequest,
        CertificateRenewalConfigurationChange, CertificateRevocationReason, CertificateStatus,
        ImportCertificateRequest, ImportCertificateResponse, import_response_matches_request,
        lifecycle_certificate_key_algorithm_matches, lifecycle_chain_ends_in_self_signed_root,
        lifecycle_issuer_matches_leaf,
    };
    use crate::{
        CertificateAuthorityProjectId, CertificateKeyAlgorithm, InfisicalClient, PageRequest,
        ResourceError, SecretValue,
        certificate::certificate_bundle_der,
        pki_certificate_profiles::certificate_chain_belongs_to_leaf,
        test_support::{mount_login, settings},
    };

    const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const CERTIFICATE_ID: &str = "22222222-2222-4222-8222-222222222222";
    const PROFILE_ID: &str = "33333333-3333-4333-8333-333333333333";
    const CA_ID: &str = "44444444-4444-4444-8444-444444444444";
    const APPLICATION_ID: &str = "55555555-5555-4555-8555-555555555555";

    fn project_id() -> CertificateAuthorityProjectId {
        CertificateAuthorityProjectId::new(PROJECT_ID).unwrap()
    }

    fn certificate_value(project_id: &str) -> Value {
        json!({
            "id": CERTIFICATE_ID,
            "projectId": project_id,
            "friendlyName": "api.example.test",
            "commonName": "api.example.test",
            "status": "active",
            "serialNumber": "01AB",
            "notBefore": "2026-07-21T12:00:00.000Z",
            "notAfter": "2027-07-21T12:00:00.000Z",
            "revokedAt": null,
            "revocationReason": null,
            "altNames": "api.example.test",
            "keyUsages": ["digitalSignature"],
            "extendedKeyUsages": ["serverAuth"],
            "keyAlgorithm": "RSA_2048",
            "signatureAlgorithm": "RSA-SHA256",
            "isCA": false,
            "caId": CA_ID,
            "profileId": PROFILE_ID,
            "applicationId": APPLICATION_ID,
            "caName": "issuing-ca",
            "profileName": "server-certificates",
            "enrollmentType": "api",
            "applicationName": "public-api",
            "hasPrivateKey": true,
            "createdAt": "2026-07-21T12:00:00.000Z",
            "updatedAt": "2026-07-21T12:00:01.000Z"
        })
    }

    fn renewable_certificate_value() -> Value {
        let mut certificate = certificate_value(PROJECT_ID);
        certificate["commonName"] = json!("certificate-profile.example");
        certificate["altNames"] = Value::Null;
        certificate["keyAlgorithm"] = Value::Null;
        certificate["extendedKeyUsages"] = json!([]);
        certificate
    }

    fn imported_certificate_value(has_private_key: bool) -> Value {
        let mut certificate = certificate_value(PROJECT_ID);
        certificate["friendlyName"] = json!("imported-certificate");
        certificate["commonName"] = json!("certificate-profile.example");
        certificate["serialNumber"] = json!("A1B2");
        certificate["altNames"] = Value::Null;
        certificate["caId"] = Value::Null;
        certificate["profileId"] = Value::Null;
        certificate["applicationId"] = Value::Null;
        certificate["caName"] = Value::Null;
        certificate["profileName"] = Value::Null;
        certificate["enrollmentType"] = Value::Null;
        certificate["applicationName"] = Value::Null;
        certificate["hasPrivateKey"] = json!(has_private_key);
        certificate
    }

    async fn mount_import_inventory_sequence(
        server: &MockServer,
        before: Vec<Value>,
        after: Vec<Value>,
    ) {
        let calls = Arc::new(AtomicUsize::new(0));
        let responses = Arc::new([before, after]);
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{PROJECT_ID}/certificates/search"
            )))
            .and(body_json(json!({
                "offset": 0,
                "limit": 100,
                "search": "A1B2"
            })))
            .respond_with(move |_: &wiremock::Request| {
                let index = calls.fetch_add(1, Ordering::SeqCst).min(1);
                ResponseTemplate::new(200).set_body_json(json!({
                    "certificates": responses[index],
                    "totalCount": responses[index].len()
                }))
            })
            .expect(2)
            .mount(server)
            .await;
    }

    #[test]
    fn renewal_lead_time_rejects_values_outside_the_pinned_range() {
        assert_eq!(
            CertificateRenewalConfigurationChange::renew_before_days(0),
            Err(CertificateInputError::InvalidRenewBeforeDays)
        );
        assert_eq!(
            CertificateRenewalConfigurationChange::renew_before_days(31),
            Err(CertificateInputError::InvalidRenewBeforeDays)
        );
    }

    fn certificate_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-cert.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn san_certificate_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-san-issued-cert.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn self_signed_san_certificate_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-san-cert.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn san_issuer_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-san-issuer-cert.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn ca_certificate_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-ca-cert.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn issuer_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-issuer-cert.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn private_key_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-private-key.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn certificate_import(has_private_key: bool) -> CertificateImport {
        CertificateImport::new(
            SecretValue::new(certificate_fixture()),
            has_private_key.then(|| SecretValue::new(private_key_fixture())),
            Some(SecretValue::new(issuer_fixture())),
            Some("imported-certificate".into()),
            None,
            None,
        )
        .unwrap()
    }

    async fn mount_certificate_preflight(server: &MockServer, certificate: Value) {
        mount_certificate_preflight_count(server, certificate, 1).await;
    }

    async fn mount_certificate_preflight_count(
        server: &MockServer,
        certificate: Value,
        expected_calls: u64,
    ) {
        mount_certificate_lookup(server, CERTIFICATE_ID, certificate, expected_calls).await;
    }

    async fn mount_certificate_lookup(
        server: &MockServer,
        certificate_id: &str,
        certificate: Value,
        expected_calls: u64,
    ) {
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{PROJECT_ID}/certificates/search"
            )))
            .and(body_json(json!({
                "offset": 0,
                "limit": 100,
                "search": certificate_id
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [certificate],
                "totalCount": 1
            })))
            .expect(expected_calls)
            .mount(server)
            .await;
    }

    #[test]
    fn search_inputs_reject_ambiguous_and_duplicate_filters() {
        assert_eq!(
            CertificateListRequest::new(
                project_id(),
                PageRequest::new(0, 25).unwrap(),
                Some(" untrimmed".into()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            CertificateInputError::InvalidSearch
        );
        assert_eq!(
            CertificateListRequest::new(
                project_id(),
                PageRequest::new(0, 25).unwrap(),
                None,
                None,
                Some(vec![PROFILE_ID.into(), PROFILE_ID.into()]),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            CertificateInputError::InvalidFilter
        );
        assert_eq!(
            CertificateListRequest::new(
                project_id(),
                PageRequest::new(0, 25).unwrap(),
                None,
                None,
                Some(vec![
                    "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".into(),
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                ]),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            CertificateInputError::InvalidFilter
        );
        assert_eq!(
            CertificateListRequest::new(
                project_id(),
                PageRequest::new(0, 25).unwrap(),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(CertificateInventorySortOrder::Asc),
            )
            .unwrap_err(),
            CertificateInputError::InvalidSort
        );
    }

    #[tokio::test]
    async fn project_search_is_bounded_filtered_and_sanitized() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-search-token").await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{PROJECT_ID}/certificates/search"
            )))
            .and(body_json(json!({
                "offset": 0,
                "limit": 25,
                "search": "api.example.test",
                "status": "active",
                "profileIds": [PROFILE_ID],
                "caIds": [CA_ID],
                "applicationIds": [APPLICATION_ID],
                "keyAlgorithm": ["RSA_2048"],
                "sortBy": "notAfter",
                "sortOrder": "asc"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [certificate_value(PROJECT_ID)],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;

        let request = CertificateListRequest::new(
            project_id(),
            PageRequest::new(0, 25).unwrap(),
            Some("api.example.test".into()),
            Some(CertificateStatus::Active),
            Some(vec![PROFILE_ID.into()]),
            Some(vec![CA_ID.into()]),
            Some(vec![APPLICATION_ID.into()]),
            Some(vec![CertificateKeyAlgorithm::Rsa2048]),
            Some(CertificateInventorySort::NotAfter),
            Some(CertificateInventorySortOrder::Asc),
        )
        .unwrap();
        let page = InfisicalClient::new(settings(&server))
            .unwrap()
            .list_certificates(request)
            .await
            .unwrap();
        assert_eq!(page.total, Some(1));
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].project_id, PROJECT_ID);
        assert!(page.items[0].has_private_key);
        let output = serde_json::to_value(&page.items[0]).unwrap();
        assert!(output.get("certificate").is_none());
        assert!(output.get("privateKey").is_none());
        assert!(output.get("certificateChain").is_none());
    }

    #[tokio::test]
    async fn exact_lookup_requires_an_exact_project_bound_match() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-exact-token").await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{PROJECT_ID}/certificates/search"
            )))
            .and(body_json(json!({
                "offset": 0,
                "limit": 100,
                "search": CERTIFICATE_ID
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [certificate_value(PROJECT_ID)],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;

        let certificate = InfisicalClient::new(settings(&server))
            .unwrap()
            .get_certificate(&project_id(), &CertificateId::new(CERTIFICATE_ID).unwrap())
            .await
            .unwrap();
        assert_eq!(certificate.id, CERTIFICATE_ID);
        assert_eq!(certificate.profile_id.as_deref(), Some(PROFILE_ID));
    }

    #[tokio::test]
    async fn exact_lookup_follows_the_validated_search_continuation() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-exact-page-token").await;
        let decoys = (0..100)
            .map(|index| {
                let mut value = certificate_value(PROJECT_ID);
                value["id"] = json!(format!("00000000-0000-4000-8000-{index:012}"));
                value["commonName"] = json!(CERTIFICATE_ID);
                value
            })
            .collect::<Vec<_>>();
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{PROJECT_ID}/certificates/search"
            )))
            .and(body_json(json!({
                "offset": 0,
                "limit": 100,
                "search": CERTIFICATE_ID
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": decoys,
                "totalCount": 101
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{PROJECT_ID}/certificates/search"
            )))
            .and(body_json(json!({
                "offset": 100,
                "limit": 100,
                "search": CERTIFICATE_ID
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [certificate_value(PROJECT_ID)],
                "totalCount": 101
            })))
            .expect(1)
            .mount(&server)
            .await;

        let certificate = InfisicalClient::new(settings(&server))
            .unwrap()
            .get_certificate(&project_id(), &CertificateId::new(CERTIFICATE_ID).unwrap())
            .await
            .unwrap();
        assert_eq!(certificate.id, CERTIFICATE_ID);
        assert!(certificate.has_private_key);
    }

    #[test]
    fn certificate_import_validates_material_and_metadata_before_io() {
        assert!(
            CertificateImport::new(
                SecretValue::new(certificate_fixture()),
                Some(SecretValue::new(private_key_fixture())),
                Some(SecretValue::new(issuer_fixture())),
                Some("imported-certificate".into()),
                None,
                None,
            )
            .is_ok()
        );
        assert_eq!(
            CertificateImport::new(
                SecretValue::new(certificate_fixture()),
                Some(SecretValue::new("not a private key")),
                Some(SecretValue::new(issuer_fixture())),
                None,
                None,
                None,
            )
            .unwrap_err(),
            CertificateInputError::InvalidImportMaterial
        );
        assert_eq!(
            CertificateImport::new(
                SecretValue::new(certificate_fixture()),
                Some(SecretValue::new(private_key_fixture())),
                Some(SecretValue::new(ca_certificate_fixture())),
                None,
                None,
                None,
            )
            .unwrap_err(),
            CertificateInputError::InvalidImportMaterial
        );
    }

    #[test]
    fn import_response_rejects_unexpected_malformed_material() {
        let request = ImportCertificateRequest {
            project_id: project_id(),
            certificate_pem: SecretValue::new(certificate_fixture()),
            private_key_pem: None,
            chain_pem: None,
            friendly_name: Some("imported-certificate".into()),
            pki_collection_id: None,
            application_id: None,
        };
        let mut response = ImportCertificateResponse {
            certificate: certificate_fixture().into(),
            serial_number: "A1B2".into(),
            certificate_chain: Some("not a certificate chain".into()),
            private_key: None,
        };
        assert!(!import_response_matches_request(&response, &request));

        response.certificate_chain = None;
        response.private_key = Some(SecretValue::new("not a private key"));
        assert!(!import_response_matches_request(&response, &request));
    }

    #[tokio::test]
    async fn import_is_confirmed_scoped_once_and_reconciled_by_serial() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-import-token").await;
        mount_import_inventory_sequence(
            &server,
            Vec::new(),
            vec![imported_certificate_value(true)],
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificates/import-certificate"))
            .and(body_json(json!({
                "projectId": PROJECT_ID,
                "certificatePem": certificate_fixture(),
                "privateKeyPem": private_key_fixture(),
                "chainPem": issuer_fixture(),
                "friendlyName": "imported-certificate"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate_fixture(),
                "privateKey": private_key_fixture(),
                "certificateChain": issuer_fixture(),
                "serialNumber": "A1B2"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let imported = InfisicalClient::new(settings(&server))
            .unwrap()
            .import_certificate(&project_id(), certificate_import(true), true)
            .await
            .unwrap();
        assert_eq!(imported.id, CERTIFICATE_ID);
        assert_eq!(imported.serial_number, "A1B2");
        assert!(imported.has_private_key);
    }

    #[tokio::test]
    async fn import_reconciliation_returns_only_a_new_matching_record() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-import-new-id-token").await;
        let existing = imported_certificate_value(true);
        let mut created = existing.clone();
        created["id"] = json!("66666666-6666-4666-8666-666666666666");
        mount_import_inventory_sequence(&server, vec![existing.clone()], vec![existing, created])
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificates/import-certificate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate_fixture(),
                "privateKey": private_key_fixture(),
                "certificateChain": issuer_fixture(),
                "serialNumber": "A1B2"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let imported = InfisicalClient::new(settings(&server))
            .unwrap()
            .import_certificate(&project_id(), certificate_import(true), true)
            .await
            .unwrap();

        assert_eq!(imported.id, "66666666-6666-4666-8666-666666666666");
    }

    #[tokio::test]
    async fn import_reconciliation_does_not_report_a_preexisting_match() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-import-existing-id-token").await;
        let existing = imported_certificate_value(true);
        mount_import_inventory_sequence(&server, vec![existing.clone()], vec![existing]).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificates/import-certificate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate_fixture(),
                "privateKey": private_key_fixture(),
                "certificateChain": issuer_fixture(),
                "serialNumber": "A1B2"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .import_certificate(&project_id(), certificate_import(true), true)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            ResourceError::CertificateImportOutcomeUnknown
        ));
    }

    #[tokio::test]
    async fn import_refuses_an_incomplete_serial_search_before_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-import-broad-search-token").await;
        let certificates = (0..100)
            .map(|index| {
                let mut certificate = imported_certificate_value(true);
                certificate["id"] = json!(format!("00000000-0000-4000-8000-{index:012x}"));
                certificate
            })
            .collect::<Vec<_>>();
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{PROJECT_ID}/certificates/search"
            )))
            .and(body_json(json!({
                "offset": 0,
                "limit": 100,
                "search": "A1B2"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": certificates,
                "totalCount": 101
            })))
            .expect(1)
            .mount(&server)
            .await;

        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .import_certificate(&project_id(), certificate_import(true), true)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            ResourceError::InvalidCertificateInventoryScope
        ));
    }

    #[tokio::test]
    async fn import_confirmation_precedes_authentication_and_upload() {
        let server = MockServer::start().await;
        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .import_certificate(&project_id(), certificate_import(true), false)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ResourceError::CertificateImportNotConfirmed
        ));
    }

    #[tokio::test]
    async fn public_certificate_material_is_bound_to_inventory() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-material-token").await;
        mount_certificate_preflight(&server, imported_certificate_value(true)).await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/certificate"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate_fixture(),
                "certificateChain": issuer_fixture(),
                "serialNumber": "A1B2"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let material = InfisicalClient::new(settings(&server))
            .unwrap()
            .get_certificate_public_material(
                &project_id(),
                &CertificateId::new(CERTIFICATE_ID).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(material.certificate, certificate_fixture());
        assert_eq!(material.certificate_chain, issuer_fixture());
        assert_eq!(material.serial_number, "A1B2");
    }

    #[tokio::test]
    async fn confirmed_bundle_and_private_key_are_correlated_to_the_leaf() {
        let bundle_server = MockServer::start().await;
        mount_login(&bundle_server, "certificate-bundle-token").await;
        mount_certificate_preflight(&bundle_server, imported_certificate_value(true)).await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/bundle"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate_fixture(),
                "certificateChain": issuer_fixture(),
                "privateKey": private_key_fixture(),
                "serialNumber": "A1B2"
            })))
            .expect(1)
            .mount(&bundle_server)
            .await;
        let bundle = InfisicalClient::new(settings(&bundle_server))
            .unwrap()
            .reveal_certificate_bundle(
                &project_id(),
                &CertificateId::new(CERTIFICATE_ID).unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(bundle.serial_number, "A1B2");
        assert_eq!(
            bundle.private_key.unwrap().expose_secret(),
            private_key_fixture()
        );

        let key_server = MockServer::start().await;
        mount_login(&key_server, "certificate-private-key-token").await;
        mount_certificate_preflight(&key_server, imported_certificate_value(true)).await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/certificate"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate_fixture(),
                "certificateChain": issuer_fixture(),
                "serialNumber": "A1B2"
            })))
            .expect(1)
            .mount(&key_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/private-key"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(private_key_fixture()))
            .expect(1)
            .mount(&key_server)
            .await;
        let private_key = InfisicalClient::new(settings(&key_server))
            .unwrap()
            .reveal_certificate_private_key(
                &project_id(),
                &CertificateId::new(CERTIFICATE_ID).unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(private_key.serial_number, "A1B2");
        assert_eq!(
            private_key.private_key.expose_secret(),
            private_key_fixture()
        );
    }

    #[tokio::test]
    async fn search_rejects_cross_project_and_filter_mismatches() {
        for body in [certificate_value("99999999-9999-4999-8999-999999999999"), {
            let mut value = certificate_value(PROJECT_ID);
            value["status"] = json!("revoked");
            value["revokedAt"] = json!("2026-08-01T12:00:00.000Z");
            value["revocationReason"] = json!(1);
            value
        }] {
            let server = MockServer::start().await;
            mount_login(&server, "certificate-invalid-token").await;
            Mock::given(method("POST"))
                .and(path(format!(
                    "/api/v1/projects/{PROJECT_ID}/certificates/search"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "certificates": [body],
                    "totalCount": 1
                })))
                .expect(1)
                .mount(&server)
                .await;
            let request = CertificateListRequest::new(
                project_id(),
                PageRequest::new(0, 25).unwrap(),
                None,
                Some(CertificateStatus::Active),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            assert!(matches!(
                InfisicalClient::new(settings(&server))
                    .unwrap()
                    .list_certificates(request)
                    .await,
                Err(ResourceError::InvalidCertificateInventoryResponse)
            ));
        }
    }

    #[tokio::test]
    async fn search_post_is_not_replayed_after_authentication_rejection() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-rejected-token").await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{PROJECT_ID}/certificates/search"
            )))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;
        let request = CertificateListRequest::new(
            project_id(),
            PageRequest::new(0, 25).unwrap(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .list_certificates(request)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn renewal_preflights_managed_state_and_validates_returned_material() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-renew-token").await;
        let mut before = renewable_certificate_value();
        before["altNames"] = json!(
            "certificate-profile.example,192.0.2.10,service@example.com,spiffe://example/service"
        );
        before["keyUsages"] = json!([]);
        mount_certificate_preflight(&server, before).await;
        let renewed_id = "66666666-6666-4666-8666-666666666666";
        let request_id = "77777777-7777-4777-8777-777777777777";
        let mut after = renewable_certificate_value();
        after["id"] = json!(renewed_id);
        after["serialNumber"] = json!("A1B3");
        after["altNames"] = json!(
            "certificate-profile.example,192.0.2.10,service@example.com,spiffe://example/service"
        );
        after["keyUsages"] = json!([]);
        mount_certificate_lookup(&server, renewed_id, after, 1).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/renew"
            )))
            .and(body_json(json!({ "removeRootsFromChain": false })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": san_certificate_fixture(),
                "issuingCaCertificate": san_issuer_fixture(),
                "certificateChain": san_issuer_fixture(),
                "privateKey": private_key_fixture(),
                "serialNumber": "A1B3",
                "certificateId": renewed_id,
                "certificateRequestId": request_id
            })))
            .expect(1)
            .mount(&server)
            .await;
        let renewed = InfisicalClient::new(settings(&server))
            .unwrap()
            .renew_certificate(
                &project_id(),
                &CertificateId::new(CERTIFICATE_ID).unwrap(),
                false,
                true,
            )
            .await
            .unwrap();
        assert_eq!(renewed.previous_certificate_id, CERTIFICATE_ID);
        assert_eq!(renewed.certificate_id, renewed_id);
        assert_eq!(renewed.request_id, request_id);
        assert!(!format!("{renewed:?}").contains(private_key_fixture()));
    }

    #[tokio::test]
    async fn renewal_reconciles_the_returned_certificate_to_the_source_hierarchy() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-renew-reconciliation-token").await;
        mount_certificate_preflight(&server, renewable_certificate_value()).await;
        let renewed_id = "66666666-6666-4666-8666-666666666666";
        let mut after = renewable_certificate_value();
        after["id"] = json!(renewed_id);
        after["serialNumber"] = json!("A1B2");
        after["caId"] = json!("88888888-8888-4888-8888-888888888888");
        mount_certificate_lookup(&server, renewed_id, after, 1).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/renew"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate_fixture(),
                "issuingCaCertificate": issuer_fixture(),
                "certificateChain": issuer_fixture(),
                "privateKey": private_key_fixture(),
                "serialNumber": "A1B2",
                "certificateId": renewed_id,
                "certificateRequestId": "77777777-7777-4777-8777-777777777777"
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .renew_certificate(
                    &project_id(),
                    &CertificateId::new(CERTIFICATE_ID).unwrap(),
                    false,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateRenewalOutcomeUnknown
        );
    }

    #[tokio::test]
    async fn renewal_rejects_a_self_signed_leaf_for_a_ca_bound_source() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-renew-self-signed-token").await;
        let mut before = renewable_certificate_value();
        before["altNames"] = json!(
            "certificate-profile.example,192.0.2.10,service@example.com,spiffe://example/service"
        );
        before["keyUsages"] = json!([]);
        mount_certificate_preflight(&server, before).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/renew"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": self_signed_san_certificate_fixture(),
                "issuingCaCertificate": "",
                "certificateChain": "",
                "privateKey": private_key_fixture(),
                "serialNumber": "A1B3",
                "certificateId": "66666666-6666-4666-8666-666666666666",
                "certificateRequestId": "77777777-7777-4777-8777-777777777777"
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .renew_certificate(
                    &project_id(),
                    &CertificateId::new(CERTIFICATE_ID).unwrap(),
                    false,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateRenewalOutcomeUnknown
        );
    }

    #[test]
    fn renewal_chain_validation_checks_one_explicit_validity_time() {
        let leaf_der = certificate_bundle_der(certificate_fixture()).unwrap();
        let (_, leaf) = X509Certificate::from_der(&leaf_der[0]).unwrap();
        let issuer_der = certificate_bundle_der(issuer_fixture()).unwrap();
        let (_, issuer) = X509Certificate::from_der(&issuer_der[0]).unwrap();
        let before_leaf =
            ASN1Time::from_timestamp(leaf.validity().not_before.timestamp() - 1).unwrap();
        let after_issuer =
            ASN1Time::from_timestamp(issuer.validity().not_after.timestamp() + 1).unwrap();

        assert!(!certificate_chain_belongs_to_leaf(
            &leaf,
            issuer_fixture(),
            before_leaf
        ));
        assert!(!lifecycle_issuer_matches_leaf(
            &leaf,
            issuer_fixture(),
            issuer_fixture(),
            after_issuer
        ));
    }

    #[test]
    fn lifecycle_key_algorithm_validation_matches_the_certificate_spki() {
        let der = certificate_bundle_der(
            include_str!("../test-fixtures/end-entity-cert.txt")
                .strip_suffix('\n')
                .unwrap(),
        )
        .unwrap()
        .remove(0);
        let (remainder, certificate) = X509Certificate::from_der(&der).unwrap();
        assert!(remainder.is_empty());
        assert!(lifecycle_certificate_key_algorithm_matches(
            &certificate,
            Some(CertificateKeyAlgorithm::Rsa2048)
        ));
        assert!(!lifecycle_certificate_key_algorithm_matches(
            &certificate,
            Some(CertificateKeyAlgorithm::Rsa3072)
        ));
    }

    #[tokio::test]
    async fn renewal_rejects_key_algorithm_or_usage_drift_as_unknown_outcome() {
        for (field, value) in [
            ("keyAlgorithm", json!("RSA_2048")),
            ("keyUsages", json!(["keyEncipherment"])),
            ("extendedKeyUsages", json!(["serverAuth"])),
        ] {
            let server = MockServer::start().await;
            mount_login(&server, "certificate-renew-cryptographic-contract-token").await;
            let mut before = renewable_certificate_value();
            before[field] = value;
            mount_certificate_preflight(&server, before).await;
            Mock::given(method("POST"))
                .and(path(format!(
                    "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/renew"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "certificate": certificate_fixture(),
                    "issuingCaCertificate": issuer_fixture(),
                    "certificateChain": issuer_fixture(),
                    "privateKey": private_key_fixture(),
                    "serialNumber": "A1B2",
                    "certificateId": "66666666-6666-4666-8666-666666666666",
                    "certificateRequestId": "77777777-7777-4777-8777-777777777777"
                })))
                .expect(1)
                .mount(&server)
                .await;
            assert_eq!(
                InfisicalClient::new(settings(&server))
                    .unwrap()
                    .renew_certificate(
                        &project_id(),
                        &CertificateId::new(CERTIFICATE_ID).unwrap(),
                        false,
                        true,
                    )
                    .await
                    .unwrap_err(),
                ResourceError::CertificateRenewalOutcomeUnknown,
                "field {field} drift was accepted"
            );
        }
    }

    #[test]
    fn lifecycle_chain_root_detection_distinguishes_terminal_certificate_kind() {
        assert!(lifecycle_chain_ends_in_self_signed_root(issuer_fixture()));
        assert!(!lifecycle_chain_ends_in_self_signed_root(
            certificate_fixture()
        ));
    }

    #[tokio::test]
    async fn renewal_root_removal_rejects_a_returned_root_as_unknown_outcome() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-renew-root-token").await;
        mount_certificate_preflight(&server, renewable_certificate_value()).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/renew"
            )))
            .and(body_json(json!({ "removeRootsFromChain": true })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate_fixture(),
                "issuingCaCertificate": issuer_fixture(),
                "certificateChain": issuer_fixture(),
                "privateKey": private_key_fixture(),
                "serialNumber": "A1B2",
                "certificateId": "66666666-6666-4666-8666-666666666666",
                "certificateRequestId": "77777777-7777-4777-8777-777777777777"
            })))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .renew_certificate(
                    &project_id(),
                    &CertificateId::new(CERTIFICATE_ID).unwrap(),
                    true,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateRenewalOutcomeUnknown
        );
    }

    #[tokio::test]
    async fn renewal_rejects_subject_alternative_name_drift_as_unknown_outcome() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-renew-identity-token").await;
        let mut before = renewable_certificate_value();
        before["altNames"] = json!("other.example.test");
        mount_certificate_preflight(&server, before).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/renew"
            )))
            .and(body_json(json!({ "removeRootsFromChain": false })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate_fixture(),
                "issuingCaCertificate": issuer_fixture(),
                "certificateChain": issuer_fixture(),
                "privateKey": private_key_fixture(),
                "serialNumber": "A1B2",
                "certificateId": "66666666-6666-4666-8666-666666666666",
                "certificateRequestId": "77777777-7777-4777-8777-777777777777"
            })))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .renew_certificate(
                    &project_id(),
                    &CertificateId::new(CERTIFICATE_ID).unwrap(),
                    false,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateRenewalOutcomeUnknown
        );
    }

    #[tokio::test]
    async fn renewal_rejects_a_semantically_unchanged_serial_as_unknown_outcome() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-renew-serial-token").await;
        let mut before = renewable_certificate_value();
        before["serialNumber"] = json!("00a1b2");
        mount_certificate_preflight(&server, before).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/renew"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate_fixture(),
                "issuingCaCertificate": issuer_fixture(),
                "certificateChain": issuer_fixture(),
                "privateKey": private_key_fixture(),
                "serialNumber": "A1B2",
                "certificateId": "66666666-6666-4666-8666-666666666666",
                "certificateRequestId": "77777777-7777-4777-8777-777777777777"
            })))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .renew_certificate(
                    &project_id(),
                    &CertificateId::new(CERTIFICATE_ID).unwrap(),
                    false,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateRenewalOutcomeUnknown
        );
    }

    #[tokio::test]
    async fn renewal_rejects_a_ca_capable_leaf_as_unknown_outcome() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-renew-ca-token").await;
        mount_certificate_preflight(&server, renewable_certificate_value()).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/renew"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": ca_certificate_fixture(),
                "issuingCaCertificate": "",
                "certificateChain": "",
                "privateKey": private_key_fixture(),
                "serialNumber": "A1B2",
                "certificateId": "66666666-6666-4666-8666-666666666666",
                "certificateRequestId": "77777777-7777-4777-8777-777777777777"
            })))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .renew_certificate(
                    &project_id(),
                    &CertificateId::new(CERTIFICATE_ID).unwrap(),
                    false,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateRenewalOutcomeUnknown
        );
    }

    #[tokio::test]
    async fn revocation_uses_the_rfc_reason_and_checks_the_exact_serial() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-revoke-token").await;
        mount_certificate_preflight(&server, certificate_value(PROJECT_ID)).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/revoke"
            )))
            .and(body_json(json!({ "revocationReason": "KEY_COMPROMISE" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "Successfully revoked certificate",
                "serialNumber": "01AB",
                "revokedAt": "2026-08-25T02:00:00.000Z"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let receipt = InfisicalClient::new(settings(&server))
            .unwrap()
            .revoke_certificate(
                &project_id(),
                &CertificateId::new(CERTIFICATE_ID).unwrap(),
                CertificateRevocationReason::KeyCompromise,
                true,
            )
            .await
            .unwrap();
        assert_eq!(receipt.serial_number, "01AB");
        assert_eq!(receipt.reason, CertificateRevocationReason::KeyCompromise);
    }

    #[tokio::test]
    async fn renewal_configuration_sends_one_closed_change() {
        for (change, body, response, enabled, days) in [
            (
                CertificateRenewalConfigurationChange::renew_before_days(14).unwrap(),
                json!({ "renewBeforeDays": 14 }),
                json!({
                    "message": "Certificate configuration updated successfully",
                    "renewBeforeDays": 14
                }),
                true,
                Some(14),
            ),
            (
                CertificateRenewalConfigurationChange::Disable,
                json!({ "enableAutoRenewal": false }),
                json!({ "message": "Auto-renewal disabled successfully" }),
                false,
                None,
            ),
        ] {
            let server = MockServer::start().await;
            mount_login(&server, "certificate-config-token").await;
            mount_certificate_preflight(&server, certificate_value(PROJECT_ID)).await;
            Mock::given(method("PATCH"))
                .and(path(format!(
                    "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/config"
                )))
                .and(body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
            let config = InfisicalClient::new(settings(&server))
                .unwrap()
                .update_certificate_renewal_configuration(
                    &project_id(),
                    &CertificateId::new(CERTIFICATE_ID).unwrap(),
                    change,
                )
                .await
                .unwrap();
            assert_eq!(config.enabled, enabled);
            assert_eq!(config.renew_before_days, days);
        }
    }

    #[tokio::test]
    async fn deletion_preflights_scope_and_returns_the_removed_certificate() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-delete-token").await;
        mount_certificate_preflight(&server, certificate_value(PROJECT_ID)).await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate_value(PROJECT_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;
        let deleted = InfisicalClient::new(settings(&server))
            .unwrap()
            .delete_certificate(
                &project_id(),
                &CertificateId::new(CERTIFICATE_ID).unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(deleted.id, CERTIFICATE_ID);
    }

    #[tokio::test]
    async fn lifecycle_server_errors_report_operation_specific_unknown_outcomes() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-lifecycle-server-error-token").await;
        mount_certificate_preflight_count(&server, renewable_certificate_value(), 4).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/renew"
            )))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/revoke"
            )))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/config"
            )))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}"
            )))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let certificate_id = CertificateId::new(CERTIFICATE_ID).unwrap();
        assert_eq!(
            client
                .renew_certificate(&project_id(), &certificate_id, false, true)
                .await
                .unwrap_err(),
            ResourceError::CertificateRenewalOutcomeUnknown
        );
        assert_eq!(
            client
                .revoke_certificate(
                    &project_id(),
                    &certificate_id,
                    CertificateRevocationReason::KeyCompromise,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateRevocationOutcomeUnknown
        );
        assert_eq!(
            client
                .update_certificate_renewal_configuration(
                    &project_id(),
                    &certificate_id,
                    CertificateRenewalConfigurationChange::renew_before_days(14).unwrap(),
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateRenewalConfigurationOutcomeUnknown
        );
        assert_eq!(
            client
                .delete_certificate(&project_id(), &certificate_id, true)
                .await
                .unwrap_err(),
            ResourceError::CertificateDeletionOutcomeUnknown
        );
    }

    #[tokio::test]
    async fn renewal_contract_failure_reports_unknown_outcome() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-renew-contract-token").await;
        mount_certificate_preflight(&server, renewable_certificate_value()).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/renew"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate_fixture(),
                "issuingCaCertificate": issuer_fixture(),
                "certificateChain": issuer_fixture(),
                "privateKey": private_key_fixture(),
                "serialNumber": "01AB",
                "certificateId": CERTIFICATE_ID,
                "certificateRequestId": "77777777-7777-4777-8777-777777777777"
            })))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .renew_certificate(
                    &project_id(),
                    &CertificateId::new(CERTIFICATE_ID).unwrap(),
                    false,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateRenewalOutcomeUnknown
        );
    }

    #[tokio::test]
    async fn revocation_contract_failure_reports_unknown_outcome() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-revoke-contract-token").await;
        mount_certificate_preflight(&server, certificate_value(PROJECT_ID)).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/revoke"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "Successfully revoked certificate",
                "serialNumber": "FFFF",
                "revokedAt": "2026-08-25T02:00:00.000Z"
            })))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .revoke_certificate(
                    &project_id(),
                    &CertificateId::new(CERTIFICATE_ID).unwrap(),
                    CertificateRevocationReason::KeyCompromise,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateRevocationOutcomeUnknown
        );
    }

    #[tokio::test]
    async fn renewal_configuration_contract_failure_reports_unknown_outcome() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-config-contract-token").await;
        mount_certificate_preflight(&server, certificate_value(PROJECT_ID)).await;
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}/config"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "Certificate configuration updated successfully",
                "renewBeforeDays": 7
            })))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .update_certificate_renewal_configuration(
                    &project_id(),
                    &CertificateId::new(CERTIFICATE_ID).unwrap(),
                    CertificateRenewalConfigurationChange::renew_before_days(14).unwrap(),
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateRenewalConfigurationOutcomeUnknown
        );
    }

    #[tokio::test]
    async fn deletion_contract_failure_reports_unknown_outcome() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-delete-contract-token").await;
        mount_certificate_preflight(&server, certificate_value(PROJECT_ID)).await;
        let mut wrong_certificate = certificate_value(PROJECT_ID);
        wrong_certificate["id"] = json!("88888888-8888-4888-8888-888888888888");
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{CERTIFICATE_ID}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "certificate": wrong_certificate })),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .delete_certificate(
                    &project_id(),
                    &CertificateId::new(CERTIFICATE_ID).unwrap(),
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateDeletionOutcomeUnknown
        );
    }

    #[tokio::test]
    async fn confirmed_lifecycle_operations_reject_an_invalid_source_state_before_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-state-token").await;
        let mut revoked = certificate_value(PROJECT_ID);
        revoked["status"] = json!("revoked");
        revoked["revokedAt"] = json!("2026-08-25T02:00:00.000Z");
        revoked["revocationReason"] = json!(1);
        mount_certificate_preflight(&server, revoked).await;
        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .revoke_certificate(
                    &project_id(),
                    &CertificateId::new(CERTIFICATE_ID).unwrap(),
                    CertificateRevocationReason::Superseded,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateLifecycleState
        );
    }

    #[tokio::test]
    async fn end_entity_lifecycle_preflights_reject_ca_certificates_before_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-ca-state-token").await;
        let mut ca_certificate = renewable_certificate_value();
        ca_certificate["isCA"] = json!(true);
        mount_certificate_preflight_count(&server, ca_certificate, 4).await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let certificate_id = CertificateId::new(CERTIFICATE_ID).unwrap();
        assert_eq!(
            client
                .renew_certificate(&project_id(), &certificate_id, false, true)
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateLifecycleState
        );
        assert_eq!(
            client
                .update_certificate_renewal_configuration(
                    &project_id(),
                    &certificate_id,
                    CertificateRenewalConfigurationChange::renew_before_days(14).unwrap(),
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateLifecycleState
        );
        assert_eq!(
            client
                .revoke_certificate(
                    &project_id(),
                    &certificate_id,
                    CertificateRevocationReason::Superseded,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateLifecycleState
        );
        assert_eq!(
            client
                .delete_certificate(&project_id(), &certificate_id, true)
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateLifecycleState
        );
    }

    #[tokio::test]
    async fn revocation_and_deletion_require_affirmative_end_entity_inventory() {
        let server = MockServer::start().await;
        mount_login(&server, "certificate-unclassified-state-token").await;
        let mut unclassified = renewable_certificate_value();
        unclassified.as_object_mut().unwrap().remove("isCA");
        mount_certificate_preflight_count(&server, unclassified, 2).await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let certificate_id = CertificateId::new(CERTIFICATE_ID).unwrap();
        assert_eq!(
            client
                .revoke_certificate(
                    &project_id(),
                    &certificate_id,
                    CertificateRevocationReason::Superseded,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateLifecycleState
        );
        assert_eq!(
            client
                .delete_certificate(&project_id(), &certificate_id, true)
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateLifecycleState
        );
    }

    #[tokio::test]
    async fn lifecycle_confirmations_fail_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let certificate_id = CertificateId::new(CERTIFICATE_ID).unwrap();
        assert_eq!(
            client
                .renew_certificate(&project_id(), &certificate_id, false, false)
                .await
                .unwrap_err(),
            ResourceError::CertificateRenewalNotConfirmed
        );
        assert_eq!(
            client
                .revoke_certificate(
                    &project_id(),
                    &certificate_id,
                    CertificateRevocationReason::Unspecified,
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::CertificateRevocationNotConfirmed
        );
        assert_eq!(
            client
                .delete_certificate(&project_id(), &certificate_id, false)
                .await
                .unwrap_err(),
            ResourceError::CertificateDeletionNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
