use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::{
    InfisicalClient, MutationOperation, ObservableReadOperation, ProjectId, ResourceError,
    client::{ApiVersion, Endpoint, sealed},
    resources::{is_bounded_text, is_uuid, utc_timestamp_millis},
};

const MAX_CA_NAME_BYTES: usize = 64;
const MAX_CA_SUBJECT_FIELD_BYTES: usize = 256;
const MAX_CA_DN_BYTES: usize = 2_048;
const MAX_CA_SERIAL_BYTES: usize = 128;
const MAX_CA_LIST_ENTRIES: usize = 500;
const MAX_CRL_DISTRIBUTION_POINT_URLS: usize = 4;
const MAX_CRL_DISTRIBUTION_POINT_URL_BYTES: usize = 2_048;
const CERTIFICATE_MANAGER_PROJECT_TYPE: &str = "cert-manager";

/// Input validation failures for the pinned certificate-authority contract.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CertificateAuthorityInputError {
    #[error("Certificate Manager project ID must be a UUID")]
    InvalidProjectId,
    #[error("certificate-authority ID must be a UUID")]
    InvalidId,
    #[error(
        "certificate-authority name must contain 1 to 64 lowercase letters or numbers separated by single hyphens"
    )]
    InvalidName,
    #[error(
        "certificate-authority subject fields must be trimmed, control-free, and at most 256 bytes each"
    )]
    InvalidSubject,
    #[error("certificate-authority subject must contain at least one non-empty field")]
    EmptySubject,
    #[error("certificate-authority country must be empty or two uppercase ASCII letters")]
    InvalidCountry,
    #[error("certificate-authority validity timestamps must be RFC 3339 UTC timestamps")]
    InvalidValidity,
    #[error("certificate-authority not-before requires not-after")]
    IncompleteValidity,
    #[error("certificate-authority validity must end after it begins")]
    InvalidValidityOrder,
    #[error("certificate-authority not-after must be in the future")]
    NotAfterNotFuture,
    #[error("intermediate certificate-authority creation cannot include root validity fields")]
    InvalidIntermediateConfiguration,
    #[error("certificate-authority maximum path length must be between -1 and 100")]
    InvalidMaxPathLength,
    #[error("SLH-DSA is not supported for internal certificate-authority creation")]
    UnsupportedKeyAlgorithm,
    #[error(
        "CRL distribution points must contain at most four unique HTTP(S) URLs of at most 2048 bytes"
    )]
    InvalidCrlDistributionPoints,
    #[error("certificate-authority update must change at least one field")]
    EmptyChange,
}

/// A validated certificate-authority identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct CertificateAuthorityId(String);

impl CertificateAuthorityId {
    /// Validate a UUID before it reaches a certificate-authority URL path.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, CertificateAuthorityInputError> {
        let value = value.into();
        if !is_uuid(&value) {
            return Err(CertificateAuthorityInputError::InvalidId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated UUID identifying one Certificate Manager project.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct CertificateAuthorityProjectId(ProjectId);

impl CertificateAuthorityProjectId {
    /// Validate the UUID-only project contract used by Certificate Manager.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, CertificateAuthorityInputError> {
        let value = value.into();
        if !is_uuid(&value) {
            return Err(CertificateAuthorityInputError::InvalidProjectId);
        }
        ProjectId::new(value.to_ascii_lowercase())
            .map(Self)
            .map_err(|_| CertificateAuthorityInputError::InvalidProjectId)
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn as_project_id(&self) -> &ProjectId {
        &self.0
    }
}

/// A validated lowercase certificate-authority slug.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct CertificateAuthorityName(String);

impl CertificateAuthorityName {
    /// Validate the pinned CA name contract.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or non-canonical slug.
    pub fn new(value: impl Into<String>) -> Result<Self, CertificateAuthorityInputError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_CA_NAME_BYTES
            || !value.split('-').all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
        {
            return Err(CertificateAuthorityInputError::InvalidName);
        }
        Ok(Self(value))
    }

    /// Borrow the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed provider family returned by the pinned general CA inventory route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum CertificateAuthorityType {
    #[serde(rename = "internal")]
    Internal,
    #[serde(rename = "acme")]
    Acme,
    #[serde(rename = "azure-ad-cs")]
    AzureAdCs,
    #[serde(rename = "aws-pca")]
    AwsPca,
    #[serde(rename = "digicert")]
    DigiCert,
    #[serde(rename = "aws-acm-public-ca")]
    AwsAcmPublicCa,
    #[serde(rename = "venafi-tpp")]
    VenafiTpp,
    #[serde(rename = "godaddy")]
    GoDaddy,
}

/// Lifecycle state of a certificate authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CertificateAuthorityStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "disabled")]
    Disabled,
    #[serde(rename = "pending-certificate")]
    PendingCertificate,
}

/// Internal CA hierarchy role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum InternalCertificateAuthorityType {
    #[serde(rename = "root")]
    Root,
    #[serde(rename = "intermediate")]
    Intermediate,
}

/// Key algorithms accepted or returned by the pinned internal-CA API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[allow(clippy::enum_variant_names)]
pub enum CertificateKeyAlgorithm {
    #[serde(rename = "RSA_2048")]
    Rsa2048,
    #[serde(rename = "RSA_3072")]
    Rsa3072,
    #[serde(rename = "RSA_4096")]
    Rsa4096,
    #[serde(rename = "EC_prime256v1")]
    EcPrime256v1,
    #[serde(rename = "EC_secp384r1")]
    EcSecp384r1,
    #[serde(rename = "EC_secp521r1")]
    EcSecp521r1,
    #[serde(rename = "ML-DSA-44")]
    MlDsa44,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,
    #[serde(rename = "SLH-DSA-SHA2-128f")]
    SlhDsaSha2_128f,
    #[serde(rename = "SLH-DSA-SHA2-128s")]
    SlhDsaSha2_128s,
    #[serde(rename = "SLH-DSA-SHA2-192f")]
    SlhDsaSha2_192f,
    #[serde(rename = "SLH-DSA-SHA2-192s")]
    SlhDsaSha2_192s,
    #[serde(rename = "SLH-DSA-SHA2-256f")]
    SlhDsaSha2_256f,
    #[serde(rename = "SLH-DSA-SHA2-256s")]
    SlhDsaSha2_256s,
    #[serde(rename = "SLH-DSA-SHAKE-128f")]
    SlhDsaShake128f,
    #[serde(rename = "SLH-DSA-SHAKE-128s")]
    SlhDsaShake128s,
    #[serde(rename = "SLH-DSA-SHAKE-192f")]
    SlhDsaShake192f,
    #[serde(rename = "SLH-DSA-SHAKE-192s")]
    SlhDsaShake192s,
    #[serde(rename = "SLH-DSA-SHAKE-256f")]
    SlhDsaShake256f,
    #[serde(rename = "SLH-DSA-SHAKE-256s")]
    SlhDsaShake256s,
}

impl CertificateKeyAlgorithm {
    const fn supports_internal_creation(self) -> bool {
        !matches!(
            self,
            Self::SlhDsaSha2_128f
                | Self::SlhDsaSha2_128s
                | Self::SlhDsaSha2_192f
                | Self::SlhDsaSha2_192s
                | Self::SlhDsaSha2_256f
                | Self::SlhDsaSha2_256s
                | Self::SlhDsaShake128f
                | Self::SlhDsaShake128s
                | Self::SlhDsaShake192f
                | Self::SlhDsaShake192s
                | Self::SlhDsaShake256f
                | Self::SlhDsaShake256s
        )
    }
}

/// Value-free metadata shared by every pinned CA provider family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateAuthoritySummary {
    /// Canonical CA UUID.
    pub id: String,
    /// Owning Certificate Manager project ID.
    pub project_id: String,
    /// Canonical project-local CA name.
    pub name: String,
    /// Closed provider family.
    #[serde(rename = "type")]
    pub ca_type: CertificateAuthorityType,
    /// Current lifecycle state.
    pub status: CertificateAuthorityStatus,
    /// Whether certificate issuance may bypass certificate profiles.
    pub enable_direct_issuance: bool,
}

/// Validated subject fields used to construct an internal CA distinguished name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateAuthoritySubject {
    /// Common name component.
    pub common_name: String,
    /// Organization component.
    pub organization: String,
    /// Organizational-unit component.
    pub organizational_unit: String,
    /// Two-letter uppercase country component, or an empty string.
    pub country: String,
    /// Province or state component.
    pub province: String,
    /// Locality component.
    pub locality: String,
}

impl CertificateAuthoritySubject {
    /// Validate bounded subject components and require at least one value.
    ///
    /// # Errors
    ///
    /// Returns an error for ambiguous or unusable distinguished-name input.
    pub fn new(
        common_name: impl Into<String>,
        organization: impl Into<String>,
        organizational_unit: impl Into<String>,
        country: impl Into<String>,
        province: impl Into<String>,
        locality: impl Into<String>,
    ) -> Result<Self, CertificateAuthorityInputError> {
        let subject = Self {
            common_name: common_name.into(),
            organization: organization.into(),
            organizational_unit: organizational_unit.into(),
            country: country.into(),
            province: province.into(),
            locality: locality.into(),
        };
        let fields = [
            subject.common_name.as_str(),
            subject.organization.as_str(),
            subject.organizational_unit.as_str(),
            subject.country.as_str(),
            subject.province.as_str(),
            subject.locality.as_str(),
        ];
        if fields.iter().any(|field| {
            field.len() > MAX_CA_SUBJECT_FIELD_BYTES
                || field.trim() != *field
                || field.chars().any(char::is_control)
        }) {
            return Err(CertificateAuthorityInputError::InvalidSubject);
        }
        if fields.iter().all(|field| field.is_empty()) {
            return Err(CertificateAuthorityInputError::EmptySubject);
        }
        if !subject.country.is_empty()
            && (subject.country.len() != 2
                || !subject
                    .country
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase()))
        {
            return Err(CertificateAuthorityInputError::InvalidCountry);
        }
        Ok(subject)
    }
}

/// Complete typed configuration returned for one internal CA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InternalCertificateAuthorityConfiguration {
    /// Root or intermediate hierarchy role.
    #[serde(rename = "type")]
    pub ca_type: InternalCertificateAuthorityType,
    /// Validated subject components.
    pub subject: CertificateAuthoritySubject,
    /// Upstream-rendered distinguished name when present.
    pub distinguished_name: Option<String>,
    /// Certificate validity start when a certificate is installed.
    pub not_before: Option<String>,
    /// Certificate validity end when a certificate is installed.
    pub not_after: Option<String>,
    /// Basic-constraints path-length limit when configured.
    pub max_path_length: Option<i16>,
    /// Private-key algorithm retained by Infisical.
    pub key_algorithm: CertificateKeyAlgorithm,
    /// Parent CA UUID for an installed intermediate certificate.
    pub parent_ca_id: Option<String>,
    /// Hexadecimal active-certificate serial number.
    pub serial_number: Option<String>,
    /// Active CA certificate UUID when installed.
    pub active_ca_certificate_id: Option<String>,
    /// Additional CRL distribution-point URLs.
    pub crl_distribution_point_urls: Vec<String>,
    /// Whether Infisical omits its managed CRL distribution point.
    pub disable_managed_crl_distribution_point_url: bool,
}

/// One exact internal certificate authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InternalCertificateAuthority {
    /// Canonical CA UUID.
    pub id: String,
    /// Owning Certificate Manager project ID.
    pub project_id: String,
    /// Canonical project-local CA name.
    pub name: String,
    /// Current lifecycle state.
    pub status: CertificateAuthorityStatus,
    /// Whether certificate issuance may bypass certificate profiles.
    pub enable_direct_issuance: bool,
    /// Typed internal-provider configuration.
    pub configuration: InternalCertificateAuthorityConfiguration,
}

/// Complete input for creating one internal CA and its encrypted private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalCertificateAuthorityCreation {
    name: CertificateAuthorityName,
    ca_type: InternalCertificateAuthorityType,
    subject: CertificateAuthoritySubject,
    not_before: Option<String>,
    not_after: Option<String>,
    max_path_length: Option<i16>,
    key_algorithm: CertificateKeyAlgorithm,
    crl_distribution_point_urls: Vec<String>,
    disable_managed_crl_distribution_point_url: bool,
}

impl InternalCertificateAuthorityCreation {
    /// Validate a complete internal-CA creation contract.
    ///
    /// # Errors
    ///
    /// Returns an error when hierarchy, validity, key, or CRL settings are incoherent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: CertificateAuthorityName,
        ca_type: InternalCertificateAuthorityType,
        subject: CertificateAuthoritySubject,
        not_before: Option<String>,
        not_after: Option<String>,
        max_path_length: Option<i16>,
        key_algorithm: CertificateKeyAlgorithm,
        crl_distribution_point_urls: Vec<String>,
        disable_managed_crl_distribution_point_url: bool,
    ) -> Result<Self, CertificateAuthorityInputError> {
        if !key_algorithm.supports_internal_creation() {
            return Err(CertificateAuthorityInputError::UnsupportedKeyAlgorithm);
        }
        if not_before.is_some() && not_after.is_none() {
            return Err(CertificateAuthorityInputError::IncompleteValidity);
        }
        validate_validity(not_before.as_deref(), not_after.as_deref())?;
        if let Some(not_after) = not_after.as_deref() {
            let not_after = utc_timestamp_millis(not_after)
                .ok_or(CertificateAuthorityInputError::InvalidValidity)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|duration| i64::try_from(duration.as_millis()).ok())
                .and_then(|unix_millis| {
                    utc_timestamp_millis("1970-01-01T00:00:00Z")?.checked_add(unix_millis)
                })
                .ok_or(CertificateAuthorityInputError::InvalidValidity)?;
            if not_after <= now {
                return Err(CertificateAuthorityInputError::NotAfterNotFuture);
            }
        }
        if ca_type == InternalCertificateAuthorityType::Intermediate
            && (not_before.is_some() || not_after.is_some() || max_path_length.is_some())
        {
            return Err(CertificateAuthorityInputError::InvalidIntermediateConfiguration);
        }
        validate_max_path_length(max_path_length)?;
        validate_distribution_points(&crl_distribution_point_urls)?;
        Ok(Self {
            name,
            ca_type,
            subject,
            not_before,
            not_after,
            max_path_length,
            key_algorithm,
            crl_distribution_point_urls,
            disable_managed_crl_distribution_point_url,
        })
    }

    fn expected_status(&self) -> CertificateAuthorityStatus {
        if self.ca_type == InternalCertificateAuthorityType::Root && self.not_after.is_some() {
            CertificateAuthorityStatus::Active
        } else {
            CertificateAuthorityStatus::PendingCertificate
        }
    }
}

/// Exact mutable fields supported by the pinned internal-CA update route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalCertificateAuthorityChange {
    name: Option<CertificateAuthorityName>,
    status: Option<CertificateAuthorityStatus>,
    crl_distribution_point_urls: Option<Vec<String>>,
    disable_managed_crl_distribution_point_url: Option<bool>,
}

impl InternalCertificateAuthorityChange {
    /// Validate a non-empty complete replacement of selected mutable fields.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty update or invalid distribution points.
    pub fn new(
        name: Option<CertificateAuthorityName>,
        status: Option<CertificateAuthorityStatus>,
        crl_distribution_point_urls: Option<Vec<String>>,
        disable_managed_crl_distribution_point_url: Option<bool>,
    ) -> Result<Self, CertificateAuthorityInputError> {
        if name.is_none()
            && status.is_none()
            && crl_distribution_point_urls.is_none()
            && disable_managed_crl_distribution_point_url.is_none()
        {
            return Err(CertificateAuthorityInputError::EmptyChange);
        }
        if let Some(urls) = crl_distribution_point_urls.as_ref() {
            validate_distribution_points(urls)?;
        }
        Ok(Self {
            name,
            status,
            crl_distribution_point_urls,
            disable_managed_crl_distribution_point_url,
        })
    }
}

fn validate_validity(
    not_before: Option<&str>,
    not_after: Option<&str>,
) -> Result<(), CertificateAuthorityInputError> {
    let before = not_before
        .map(|value| {
            utc_timestamp_millis(value).ok_or(CertificateAuthorityInputError::InvalidValidity)
        })
        .transpose()?;
    let after = not_after
        .map(|value| {
            utc_timestamp_millis(value).ok_or(CertificateAuthorityInputError::InvalidValidity)
        })
        .transpose()?;
    if before.is_some_and(|before| after.is_some_and(|after| after <= before)) {
        return Err(CertificateAuthorityInputError::InvalidValidityOrder);
    }
    Ok(())
}

fn normalized_timestamp_millis(value: Option<&str>) -> Option<i64> {
    value.and_then(utc_timestamp_millis)
}

fn validate_max_path_length(
    max_path_length: Option<i16>,
) -> Result<(), CertificateAuthorityInputError> {
    if max_path_length.is_some_and(|value| !(-1..=100).contains(&value)) {
        return Err(CertificateAuthorityInputError::InvalidMaxPathLength);
    }
    Ok(())
}

fn validate_distribution_points(urls: &[String]) -> Result<(), CertificateAuthorityInputError> {
    if urls.len() > MAX_CRL_DISTRIBUTION_POINT_URLS {
        return Err(CertificateAuthorityInputError::InvalidCrlDistributionPoints);
    }
    let mut normalized = HashSet::with_capacity(urls.len());
    for value in urls {
        if value.is_empty()
            || value.len() > MAX_CRL_DISTRIBUTION_POINT_URL_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(CertificateAuthorityInputError::InvalidCrlDistributionPoints);
        }
        let url = Url::parse(value)
            .map_err(|_| CertificateAuthorityInputError::InvalidCrlDistributionPoints)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || !normalized.insert(url.to_string())
        {
            return Err(CertificateAuthorityInputError::InvalidCrlDistributionPoints);
        }
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectCaQuery {
    project_id: String,
}

#[derive(Serialize)]
struct ExactCaQuery {
    #[serde(skip_serializing)]
    ca_id: CertificateAuthorityId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneralCertificateAuthorityResponse {
    certificate_authorities: Vec<CertificateAuthoritySummaryWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateAuthoritySummaryWire {
    id: String,
    project_id: String,
    name: String,
    #[serde(rename = "type")]
    ca_type: CertificateAuthorityType,
    status: CertificateAuthorityStatus,
    enable_direct_issuance: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InternalCertificateAuthorityWire {
    id: String,
    project_id: String,
    name: String,
    #[serde(rename = "type")]
    ca_type: CertificateAuthorityType,
    status: CertificateAuthorityStatus,
    enable_direct_issuance: bool,
    configuration: InternalCertificateAuthorityConfigurationWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InternalCertificateAuthorityConfigurationWire {
    #[serde(rename = "type")]
    ca_type: InternalCertificateAuthorityType,
    #[serde(default)]
    common_name: String,
    #[serde(default)]
    organization: String,
    #[serde(default, rename = "ou")]
    organizational_unit: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    province: String,
    #[serde(default)]
    locality: String,
    #[serde(default, rename = "dn")]
    distinguished_name: Option<String>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
    #[serde(default)]
    max_path_length: Option<i16>,
    key_algorithm: CertificateKeyAlgorithm,
    #[serde(default)]
    parent_ca_id: Option<String>,
    #[serde(default)]
    serial_number: Option<String>,
    #[serde(default)]
    active_ca_cert_id: Option<String>,
    #[serde(default)]
    crl_distribution_point_urls: Vec<String>,
    #[serde(default)]
    disable_managed_crl_distribution_point_url: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateInternalCertificateAuthorityRequest {
    name: String,
    project_id: String,
    status: CertificateAuthorityStatus,
    configuration: CreateInternalCertificateAuthorityConfiguration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateInternalCertificateAuthorityConfiguration {
    #[serde(rename = "type")]
    ca_type: InternalCertificateAuthorityType,
    common_name: String,
    organization: String,
    #[serde(rename = "ou")]
    organizational_unit: String,
    country: String,
    province: String,
    locality: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_path_length: Option<i16>,
    key_algorithm: CertificateKeyAlgorithm,
    crl_distribution_point_urls: Vec<String>,
    disable_managed_crl_distribution_point_url: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateInternalCertificateAuthorityRequest {
    #[serde(skip_serializing)]
    ca_id: CertificateAuthorityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<CertificateAuthorityStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    configuration: Option<UpdateInternalCertificateAuthorityConfiguration>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateInternalCertificateAuthorityConfiguration {
    #[serde(skip_serializing_if = "Option::is_none")]
    crl_distribution_point_urls: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disable_managed_crl_distribution_point_url: Option<bool>,
}

#[derive(Serialize)]
struct DeleteInternalCertificateAuthorityRequest {
    #[serde(skip_serializing)]
    ca_id: CertificateAuthorityId,
}

struct ListCertificateAuthorities;
impl sealed::Sealed for ListCertificateAuthorities {}
impl ObservableReadOperation for ListCertificateAuthorities {
    type Query = ProjectCaQuery;
    type Output = GeneralCertificateAuthorityResponse;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "cert-manager/ca")
    }
}

struct ListInternalCertificateAuthorities;
impl sealed::Sealed for ListInternalCertificateAuthorities {}
impl ObservableReadOperation for ListInternalCertificateAuthorities {
    type Query = ProjectCaQuery;
    type Output = Vec<InternalCertificateAuthorityWire>;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "cert-manager/ca/internal")
    }
}

struct GetInternalCertificateAuthority;
impl sealed::Sealed for GetInternalCertificateAuthority {}
impl ObservableReadOperation for GetInternalCertificateAuthority {
    type Query = ExactCaQuery;
    type Output = InternalCertificateAuthorityWire;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["cert-manager", "ca", "internal", query.ca_id.as_str()],
        )
    }
}

macro_rules! internal_ca_mutation {
    ($operation:ident, $input:ty, $method:expr, $suffix:expr) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl MutationOperation for $operation {
            type Input = $input;
            type Output = InternalCertificateAuthorityWire;

            fn method() -> Method {
                $method
            }

            fn endpoint(input: &Self::Input) -> Endpoint {
                let mut segments = vec![
                    "cert-manager".to_owned(),
                    "ca".to_owned(),
                    "internal".to_owned(),
                ];
                segments.extend(($suffix)(input));
                Endpoint::from_segments(ApiVersion::V1, segments)
            }
        }
    };
}

internal_ca_mutation!(
    CreateInternalCertificateAuthority,
    CreateInternalCertificateAuthorityRequest,
    Method::POST,
    |_input: &CreateInternalCertificateAuthorityRequest| Vec::<String>::new()
);
internal_ca_mutation!(
    UpdateInternalCertificateAuthority,
    UpdateInternalCertificateAuthorityRequest,
    Method::PATCH,
    |input: &UpdateInternalCertificateAuthorityRequest| vec![input.ca_id.as_str().to_owned()]
);
internal_ca_mutation!(
    DeleteInternalCertificateAuthority,
    DeleteInternalCertificateAuthorityRequest,
    Method::DELETE,
    |input: &DeleteInternalCertificateAuthorityRequest| vec![input.ca_id.as_str().to_owned()]
);

fn summary_from_wire(
    wire: CertificateAuthoritySummaryWire,
    project_id: &CertificateAuthorityProjectId,
) -> Result<CertificateAuthoritySummary, ResourceError> {
    let id = CertificateAuthorityId::new(wire.id)
        .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
    let name = CertificateAuthorityName::new(wire.name)
        .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
    let response_project_id = CertificateAuthorityProjectId::new(wire.project_id)
        .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
    if &response_project_id != project_id {
        return Err(ResourceError::InvalidCertificateAuthorityScope);
    }
    Ok(CertificateAuthoritySummary {
        id: id.as_str().to_owned(),
        project_id: response_project_id.as_str().to_owned(),
        name: name.as_str().to_owned(),
        ca_type: wire.ca_type,
        status: wire.status,
        enable_direct_issuance: wire.enable_direct_issuance,
    })
}

fn internal_ca_from_wire(
    wire: InternalCertificateAuthorityWire,
    project_id: &CertificateAuthorityProjectId,
    expected_id: Option<&CertificateAuthorityId>,
) -> Result<InternalCertificateAuthority, ResourceError> {
    if wire.ca_type != CertificateAuthorityType::Internal {
        return Err(ResourceError::InvalidCertificateAuthorityResponse);
    }
    let id = CertificateAuthorityId::new(wire.id)
        .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
    let name = CertificateAuthorityName::new(wire.name)
        .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
    let response_project_id = CertificateAuthorityProjectId::new(wire.project_id)
        .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
    if &response_project_id != project_id || expected_id.is_some_and(|expected| expected != &id) {
        return Err(ResourceError::InvalidCertificateAuthorityScope);
    }
    let subject = CertificateAuthoritySubject::new(
        wire.configuration.common_name,
        wire.configuration.organization,
        wire.configuration.organizational_unit,
        wire.configuration.country,
        wire.configuration.province,
        wire.configuration.locality,
    )
    .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
    validate_validity(
        wire.configuration.not_before.as_deref(),
        wire.configuration.not_after.as_deref(),
    )
    .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
    validate_max_path_length(wire.configuration.max_path_length)
        .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
    validate_distribution_points(&wire.configuration.crl_distribution_point_urls)
        .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
    if wire
        .configuration
        .distinguished_name
        .as_deref()
        .is_some_and(|value| !is_bounded_text(value, MAX_CA_DN_BYTES))
        || wire
            .configuration
            .serial_number
            .as_deref()
            .is_some_and(|value| {
                !is_bounded_text(value, MAX_CA_SERIAL_BYTES)
                    || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        || wire
            .configuration
            .parent_ca_id
            .as_deref()
            .is_some_and(|value| !is_uuid(value))
        || wire
            .configuration
            .active_ca_cert_id
            .as_deref()
            .is_some_and(|value| !is_uuid(value))
    {
        return Err(ResourceError::InvalidCertificateAuthorityResponse);
    }
    Ok(InternalCertificateAuthority {
        id: id.as_str().to_owned(),
        project_id: response_project_id.as_str().to_owned(),
        name: name.as_str().to_owned(),
        status: wire.status,
        enable_direct_issuance: wire.enable_direct_issuance,
        configuration: InternalCertificateAuthorityConfiguration {
            ca_type: wire.configuration.ca_type,
            subject,
            distinguished_name: wire.configuration.distinguished_name,
            not_before: wire.configuration.not_before,
            not_after: wire.configuration.not_after,
            max_path_length: wire.configuration.max_path_length,
            key_algorithm: wire.configuration.key_algorithm,
            parent_ca_id: wire.configuration.parent_ca_id,
            serial_number: wire.configuration.serial_number,
            active_ca_certificate_id: wire.configuration.active_ca_cert_id,
            crl_distribution_point_urls: wire.configuration.crl_distribution_point_urls,
            disable_managed_crl_distribution_point_url: wire
                .configuration
                .disable_managed_crl_distribution_point_url,
        },
    })
}

fn created_internal_ca_from_wire(
    wire: InternalCertificateAuthorityWire,
    project_id: &CertificateAuthorityProjectId,
    creation: &InternalCertificateAuthorityCreation,
) -> Result<InternalCertificateAuthority, ResourceError> {
    let authority = internal_ca_from_wire(wire, project_id, None)?;
    let expected_status = creation.expected_status();
    if authority.name != creation.name.as_str()
        || authority.status != expected_status
        || authority.enable_direct_issuance
        || authority.configuration.ca_type != creation.ca_type
        || authority.configuration.subject != creation.subject
        || normalized_timestamp_millis(authority.configuration.not_after.as_deref())
            != normalized_timestamp_millis(creation.not_after.as_deref())
        || authority.configuration.not_before.is_some() != creation.not_after.is_some()
        || creation.not_before.as_ref().is_some_and(|not_before| {
            normalized_timestamp_millis(authority.configuration.not_before.as_deref())
                != utc_timestamp_millis(not_before)
        })
        || authority.configuration.max_path_length != creation.max_path_length
        || authority.configuration.key_algorithm != creation.key_algorithm
        || authority.configuration.parent_ca_id.is_some()
        || authority.configuration.serial_number.is_some() != creation.not_after.is_some()
        || authority.configuration.active_ca_certificate_id.is_some()
            != creation.not_after.is_some()
        || authority.configuration.crl_distribution_point_urls
            != creation.crl_distribution_point_urls
        || authority
            .configuration
            .disable_managed_crl_distribution_point_url
            != creation.disable_managed_crl_distribution_point_url
    {
        return Err(ResourceError::InvalidCertificateAuthorityResponse);
    }
    Ok(authority)
}

fn updated_internal_ca_from_wire(
    wire: InternalCertificateAuthorityWire,
    project_id: &CertificateAuthorityProjectId,
    ca_id: &CertificateAuthorityId,
    before: &InternalCertificateAuthority,
    change: &InternalCertificateAuthorityChange,
) -> Result<InternalCertificateAuthority, ResourceError> {
    let authority = internal_ca_from_wire(wire, project_id, Some(ca_id))?;
    let mut expected = before.clone();
    if let Some(name) = change.name.as_ref() {
        name.as_str().clone_into(&mut expected.name);
    }
    if let Some(status) = change.status {
        expected.status = status;
    }
    if let Some(urls) = change.crl_distribution_point_urls.as_ref() {
        expected
            .configuration
            .crl_distribution_point_urls
            .clone_from(urls);
    }
    if let Some(disable) = change.disable_managed_crl_distribution_point_url {
        expected
            .configuration
            .disable_managed_crl_distribution_point_url = disable;
    }
    if authority != expected {
        return Err(ResourceError::InvalidCertificateAuthorityResponse);
    }
    Ok(authority)
}

impl InfisicalClient {
    pub(crate) async fn ensure_certificate_manager_project(
        &self,
        project_id: &CertificateAuthorityProjectId,
    ) -> Result<(), ResourceError> {
        let project = self.get_project(project_id.as_project_id()).await?;
        let Some(project) = project.as_ref() else {
            return Err(ResourceError::InvalidCertificateAuthorityScope);
        };
        let response_project_id = CertificateAuthorityProjectId::new(project.id.as_str())
            .map_err(|_| ResourceError::InvalidCertificateAuthorityResponse)?;
        if &response_project_id != project_id {
            return Err(ResourceError::InvalidCertificateAuthorityScope);
        }
        if project.project_type != CERTIFICATE_MANAGER_PROJECT_TYPE {
            return Err(ResourceError::InvalidCertificateAuthorityProjectKind);
        }
        Ok(())
    }

    /// List bounded, value-free metadata for every pinned CA provider family.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or bounded-response error.
    pub async fn list_certificate_authorities(
        &self,
        project_id: &CertificateAuthorityProjectId,
    ) -> Result<Vec<CertificateAuthoritySummary>, ResourceError> {
        let response = self
            .execute_observable_read::<ListCertificateAuthorities>(&ProjectCaQuery {
                project_id: project_id.as_str().to_owned(),
            })
            .await?;
        if response.certificate_authorities.len() > MAX_CA_LIST_ENTRIES {
            return Err(ResourceError::InvalidCertificateAuthorityResponse);
        }
        let authorities = response
            .certificate_authorities
            .into_iter()
            .map(|authority| summary_from_wire(authority, project_id))
            .collect::<Result<Vec<_>, _>>()?;
        if authorities
            .iter()
            .map(|authority| authority.id.as_str())
            .collect::<HashSet<_>>()
            .len()
            != authorities.len()
        {
            return Err(ResourceError::InvalidCertificateAuthorityResponse);
        }
        Ok(authorities)
    }

    /// List all bounded internal CAs in one exact Certificate Manager project.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or bounded-response error.
    pub async fn list_internal_certificate_authorities(
        &self,
        project_id: &CertificateAuthorityProjectId,
    ) -> Result<Vec<InternalCertificateAuthority>, ResourceError> {
        let response = self
            .execute_observable_read::<ListInternalCertificateAuthorities>(&ProjectCaQuery {
                project_id: project_id.as_str().to_owned(),
            })
            .await?;
        if response.len() > MAX_CA_LIST_ENTRIES {
            return Err(ResourceError::InvalidCertificateAuthorityResponse);
        }
        let authorities = response
            .into_iter()
            .map(|authority| internal_ca_from_wire(authority, project_id, None))
            .collect::<Result<Vec<_>, _>>()?;
        if authorities
            .iter()
            .map(|authority| authority.id.as_str())
            .collect::<HashSet<_>>()
            .len()
            != authorities.len()
        {
            return Err(ResourceError::InvalidCertificateAuthorityResponse);
        }
        Ok(authorities)
    }

    /// Get one exact internal CA and prove its project ownership.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or response-contract error.
    pub async fn get_internal_certificate_authority(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
    ) -> Result<InternalCertificateAuthority, ResourceError> {
        let response = self
            .execute_observable_read::<GetInternalCertificateAuthority>(&ExactCaQuery {
                ca_id: ca_id.clone(),
            })
            .await?;
        internal_ca_from_wire(response, project_id, Some(ca_id))
    }

    /// Create one encrypted internal-CA private key after project preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn create_internal_certificate_authority(
        &self,
        project_id: &CertificateAuthorityProjectId,
        creation: InternalCertificateAuthorityCreation,
        confirm: bool,
    ) -> Result<InternalCertificateAuthority, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateAuthorityCreateNotConfirmed);
        }
        self.ensure_certificate_manager_project(project_id).await?;
        let expected_status = creation.expected_status();
        let request = CreateInternalCertificateAuthorityRequest {
            name: creation.name.as_str().to_owned(),
            project_id: project_id.as_str().to_owned(),
            status: expected_status,
            configuration: CreateInternalCertificateAuthorityConfiguration {
                ca_type: creation.ca_type,
                common_name: creation.subject.common_name.clone(),
                organization: creation.subject.organization.clone(),
                organizational_unit: creation.subject.organizational_unit.clone(),
                country: creation.subject.country.clone(),
                province: creation.subject.province.clone(),
                locality: creation.subject.locality.clone(),
                not_before: creation.not_before.clone(),
                not_after: creation.not_after.clone(),
                max_path_length: creation.max_path_length,
                key_algorithm: creation.key_algorithm,
                crl_distribution_point_urls: creation.crl_distribution_point_urls.clone(),
                disable_managed_crl_distribution_point_url: creation
                    .disable_managed_crl_distribution_point_url,
            },
        };
        let response = self
            .execute_mutation::<CreateInternalCertificateAuthority>(&request)
            .await?;
        created_internal_ca_from_wire(response, project_id, &creation)
    }

    /// Update one exact internal CA after confirmation and scope preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    pub async fn update_internal_certificate_authority(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
        change: InternalCertificateAuthorityChange,
        confirm: bool,
    ) -> Result<InternalCertificateAuthority, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateAuthorityUpdateNotConfirmed);
        }
        let before = self
            .get_internal_certificate_authority(project_id, ca_id)
            .await?;
        let request = UpdateInternalCertificateAuthorityRequest {
            ca_id: ca_id.clone(),
            name: change.name.as_ref().map(|name| name.as_str().to_owned()),
            status: change.status,
            configuration: (change.crl_distribution_point_urls.is_some()
                || change.disable_managed_crl_distribution_point_url.is_some())
            .then(|| UpdateInternalCertificateAuthorityConfiguration {
                crl_distribution_point_urls: change.crl_distribution_point_urls.clone(),
                disable_managed_crl_distribution_point_url: change
                    .disable_managed_crl_distribution_point_url,
            }),
        };
        let response = self
            .execute_mutation::<UpdateInternalCertificateAuthority>(&request)
            .await?;
        updated_internal_ca_from_wire(response, project_id, ca_id, &before, &change)
    }

    /// Delete one exact internal CA after confirmation and scope preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    pub async fn delete_internal_certificate_authority(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
        confirm: bool,
    ) -> Result<InternalCertificateAuthority, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateAuthorityDeleteNotConfirmed);
        }
        let before = self
            .get_internal_certificate_authority(project_id, ca_id)
            .await?;
        let response = self
            .execute_mutation::<DeleteInternalCertificateAuthority>(
                &DeleteInternalCertificateAuthorityRequest {
                    ca_id: ca_id.clone(),
                },
            )
            .await?;
        let deleted = internal_ca_from_wire(response, project_id, Some(ca_id))?;
        if deleted != before {
            return Err(ResourceError::InvalidCertificateAuthorityResponse);
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path, query_param},
    };

    use super::*;
    use crate::{
        InfisicalClient,
        test_support::{mount_login, settings},
    };

    const PROJECT_ID: &str = "22222222-2222-4222-8222-222222222222";
    const CA_ID: &str = "11111111-1111-4111-8111-111111111111";
    type ResponseMutation = (&'static str, fn(&mut serde_json::Value));

    fn subject() -> CertificateAuthoritySubject {
        CertificateAuthoritySubject::new("Root CA", "Example", "Security", "US", "TX", "Austin")
            .unwrap()
    }

    fn internal_ca_value(
        name: &str,
        status: &str,
        urls: &[&str],
        disabled: bool,
    ) -> serde_json::Value {
        json!({
            "id": CA_ID,
            "projectId": PROJECT_ID,
            "name": name,
            "type": "internal",
            "status": status,
            "enableDirectIssuance": false,
            "configuration": {
                "type": "root",
                "commonName": "Root CA",
                "organization": "Example",
                "ou": "Security",
                "country": "US",
                "province": "TX",
                "locality": "Austin",
                "dn": "C=US,O=Example,OU=Security,ST=TX,CN=Root CA,L=Austin",
                "notBefore": "2026-01-01T00:00:00Z",
                "notAfter": "2036-01-01T00:00:00Z",
                "maxPathLength": 2,
                "keyAlgorithm": "RSA_2048",
                "serialNumber": "01ab",
                "activeCaCertId": "22222222-2222-4222-8222-222222222222",
                "crlDistributionPointUrls": urls,
                "disableManagedCrlDistributionPointUrl": disabled,
                "encryptedPrivateKey": "must-never-cross"
            }
        })
    }

    fn bounded_ca_id(index: usize) -> String {
        format!("00000000-0000-4000-8000-{index:012x}")
    }

    #[test]
    fn creation_rejects_ignored_validity_fields_and_unsafe_urls() {
        assert_eq!(
            CertificateAuthorityProjectId::new("project_123").unwrap_err(),
            CertificateAuthorityInputError::InvalidProjectId
        );
        assert_eq!(
            InternalCertificateAuthorityCreation::new(
                CertificateAuthorityName::new("root-ca").unwrap(),
                InternalCertificateAuthorityType::Root,
                subject(),
                Some("2026-01-01T00:00:00Z".to_owned()),
                None,
                None,
                CertificateKeyAlgorithm::Rsa2048,
                vec![],
                false,
            )
            .unwrap_err(),
            CertificateAuthorityInputError::IncompleteValidity
        );
        assert_eq!(
            InternalCertificateAuthorityCreation::new(
                CertificateAuthorityName::new("expired-root-ca").unwrap(),
                InternalCertificateAuthorityType::Root,
                subject(),
                None,
                Some("2000-01-01T00:00:00Z".to_owned()),
                None,
                CertificateKeyAlgorithm::Rsa2048,
                vec![],
                false,
            )
            .unwrap_err(),
            CertificateAuthorityInputError::NotAfterNotFuture
        );
        let name = CertificateAuthorityName::new("intermediate-ca").unwrap();
        assert_eq!(
            InternalCertificateAuthorityCreation::new(
                name,
                InternalCertificateAuthorityType::Intermediate,
                subject(),
                None,
                Some("2036-01-01T00:00:00Z".to_owned()),
                None,
                CertificateKeyAlgorithm::Rsa2048,
                vec![],
                false,
            )
            .unwrap_err(),
            CertificateAuthorityInputError::InvalidIntermediateConfiguration
        );
        assert_eq!(
            validate_distribution_points(&["https://user:secret@example.test/crl".to_owned()])
                .unwrap_err(),
            CertificateAuthorityInputError::InvalidCrlDistributionPoints
        );

        assert_eq!(
            InternalCertificateAuthorityCreation::new(
                CertificateAuthorityName::new("unsupported-root-ca").unwrap(),
                InternalCertificateAuthorityType::Root,
                subject(),
                None,
                None,
                None,
                CertificateKeyAlgorithm::SlhDsaSha2_128f,
                vec![],
                false,
            )
            .unwrap_err(),
            CertificateAuthorityInputError::UnsupportedKeyAlgorithm
        );

        let pending_root = InternalCertificateAuthorityCreation::new(
            CertificateAuthorityName::new("pending-root-ca").unwrap(),
            InternalCertificateAuthorityType::Root,
            subject(),
            None,
            None,
            None,
            CertificateKeyAlgorithm::Rsa2048,
            vec![],
            false,
        )
        .unwrap();
        assert_eq!(
            pending_root.expected_status(),
            CertificateAuthorityStatus::PendingCertificate
        );
    }

    #[test]
    fn validity_path_length_and_distribution_point_boundaries_are_enforced() {
        assert_eq!(
            validate_validity(Some("not-a-timestamp"), Some("2036-01-01T00:00:00Z")),
            Err(CertificateAuthorityInputError::InvalidValidity)
        );
        assert_eq!(
            validate_validity(Some("2036-01-01T00:00:00Z"), Some("2035-01-01T00:00:00Z")),
            Err(CertificateAuthorityInputError::InvalidValidityOrder)
        );

        assert!(validate_max_path_length(Some(-1)).is_ok());
        for value in [-2, 101] {
            assert_eq!(
                validate_max_path_length(Some(value)),
                Err(CertificateAuthorityInputError::InvalidMaxPathLength),
                "accepted path length {value}"
            );
        }

        let maximum_urls = (0..MAX_CRL_DISTRIBUTION_POINT_URLS)
            .map(|index| format!("https://pki.example.test/{index}.crl"))
            .collect::<Vec<_>>();
        assert!(validate_distribution_points(&maximum_urls).is_ok());
        let mut too_many_urls = maximum_urls;
        too_many_urls.push("https://pki.example.test/overflow.crl".to_owned());
        assert_eq!(
            validate_distribution_points(&too_many_urls),
            Err(CertificateAuthorityInputError::InvalidCrlDistributionPoints)
        );

        let invalid_cases = [
            vec![String::new()],
            vec![format!(
                "https://pki.example.test/{}",
                "a".repeat(MAX_CRL_DISTRIBUTION_POINT_URL_BYTES)
            )],
            vec![" https://pki.example.test/root.crl".to_owned()],
            vec!["https://pki.example.test/root\n.crl".to_owned()],
            vec!["ftp://pki.example.test/root.crl".to_owned()],
            vec!["https://user@pki.example.test/root.crl".to_owned()],
            vec!["https://:secret@pki.example.test/root.crl".to_owned()],
            vec!["https://pki.example.test/root.crl#fragment".to_owned()],
            vec![
                "https://pki.example.test/root.crl".to_owned(),
                "https://pki.example.test/root.crl".to_owned(),
            ],
        ];
        for urls in invalid_cases {
            assert_eq!(
                validate_distribution_points(&urls),
                Err(CertificateAuthorityInputError::InvalidCrlDistributionPoints),
                "accepted invalid distribution points {urls:?}"
            );
        }
    }

    #[test]
    fn internal_ca_response_rejects_each_scope_and_metadata_violation() {
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let expected_id = CertificateAuthorityId::new(CA_ID).unwrap();

        let mut wrong_project = internal_ca_value("root-ca", "active", &[], false);
        wrong_project["projectId"] = json!("33333333-3333-4333-8333-333333333333");
        assert_eq!(
            internal_ca_from_wire(
                serde_json::from_value(wrong_project).unwrap(),
                &project_id,
                None,
            )
            .unwrap_err(),
            ResourceError::InvalidCertificateAuthorityScope
        );

        let other_id = CertificateAuthorityId::new("33333333-3333-4333-8333-333333333333").unwrap();
        assert_eq!(
            internal_ca_from_wire(
                serde_json::from_value(internal_ca_value("root-ca", "active", &[], false)).unwrap(),
                &project_id,
                Some(&other_id),
            )
            .unwrap_err(),
            ResourceError::InvalidCertificateAuthorityScope
        );

        let metadata_cases: [ResponseMutation; 4] = [
            ("non-hex serial", |value| {
                value["configuration"]["serialNumber"] = json!("not-hex");
            }),
            ("overlong serial", |value| {
                value["configuration"]["serialNumber"] = json!("a".repeat(MAX_CA_SERIAL_BYTES + 1));
            }),
            ("invalid parent CA ID", |value| {
                value["configuration"]["parentCaId"] = json!("not-a-uuid");
            }),
            ("invalid active certificate ID", |value| {
                value["configuration"]["activeCaCertId"] = json!("not-a-uuid");
            }),
        ];
        for (field, mutate) in metadata_cases {
            let mut response = internal_ca_value("root-ca", "active", &[], false);
            mutate(&mut response);
            assert_eq!(
                internal_ca_from_wire(
                    serde_json::from_value(response).unwrap(),
                    &project_id,
                    Some(&expected_id),
                )
                .unwrap_err(),
                ResourceError::InvalidCertificateAuthorityResponse,
                "accepted invalid {field}"
            );
        }
    }

    #[test]
    fn ca_identifiers_and_timestamps_compare_semantically() {
        const CANONICAL_PROJECT_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        const CANONICAL_CA_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let project_id =
            CertificateAuthorityProjectId::new(CANONICAL_PROJECT_ID.to_ascii_uppercase()).unwrap();
        let ca_id = CertificateAuthorityId::new(CANONICAL_CA_ID.to_ascii_uppercase()).unwrap();
        assert_eq!(project_id.as_str(), CANONICAL_PROJECT_ID);
        assert_eq!(ca_id.as_str(), CANONICAL_CA_ID);

        let summary: CertificateAuthoritySummaryWire = serde_json::from_value(json!({
            "id": CANONICAL_CA_ID.to_ascii_uppercase(),
            "projectId": CANONICAL_PROJECT_ID.to_ascii_uppercase(),
            "name": "root-ca",
            "type": "internal",
            "status": "active",
            "enableDirectIssuance": false
        }))
        .unwrap();
        let summary = summary_from_wire(summary, &project_id).unwrap();
        assert_eq!(summary.id, CANONICAL_CA_ID);
        assert_eq!(summary.project_id, CANONICAL_PROJECT_ID);

        let creation = InternalCertificateAuthorityCreation::new(
            CertificateAuthorityName::new("root-ca").unwrap(),
            InternalCertificateAuthorityType::Root,
            subject(),
            Some("2026-01-01T00:00:00Z".to_owned()),
            Some("2036-01-01T00:00:00Z".to_owned()),
            Some(2),
            CertificateKeyAlgorithm::Rsa2048,
            vec![],
            false,
        )
        .unwrap();
        let mut response = internal_ca_value("root-ca", "active", &[], false);
        response["id"] = json!(CANONICAL_CA_ID.to_ascii_uppercase());
        response["projectId"] = json!(CANONICAL_PROJECT_ID.to_ascii_uppercase());
        response["configuration"]["notBefore"] = json!("2026-01-01T00:00:00.000Z");
        response["configuration"]["notAfter"] = json!("2036-01-01T00:00:00.000Z");
        let authority = created_internal_ca_from_wire(
            serde_json::from_value(response).unwrap(),
            &project_id,
            &creation,
        )
        .unwrap();
        assert_eq!(authority.id, CANONICAL_CA_ID);
        assert_eq!(authority.project_id, CANONICAL_PROJECT_ID);
    }

    #[test]
    fn created_ca_response_must_reflect_every_requested_and_derived_field() {
        let creation = InternalCertificateAuthorityCreation::new(
            CertificateAuthorityName::new("root-ca").unwrap(),
            InternalCertificateAuthorityType::Root,
            subject(),
            Some("2026-01-01T00:00:00Z".to_owned()),
            Some("2036-01-01T00:00:00Z".to_owned()),
            Some(2),
            CertificateKeyAlgorithm::Rsa2048,
            vec!["https://pki.example.test/root.crl".to_owned()],
            false,
        )
        .unwrap();
        let valid = internal_ca_value(
            "root-ca",
            "active",
            &["https://pki.example.test/root.crl"],
            false,
        );
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let parsed = serde_json::from_value(valid.clone()).unwrap();
        assert!(created_internal_ca_from_wire(parsed, &project_id, &creation).is_ok());

        let cases: [ResponseMutation; 14] = [
            ("name", |value| value["name"] = json!("other-ca")),
            ("status", |value| value["status"] = json!("disabled")),
            ("direct issuance", |value| {
                value["enableDirectIssuance"] = json!(true);
            }),
            ("hierarchy type", |value| {
                value["configuration"]["type"] = json!("intermediate");
            }),
            ("subject", |value| {
                value["configuration"]["commonName"] = json!("Other Root");
            }),
            ("not before", |value| {
                value["configuration"]["notBefore"] = json!("2027-01-01T00:00:00Z");
            }),
            ("not after", |value| {
                value["configuration"]["notAfter"] = json!("2037-01-01T00:00:00Z");
            }),
            ("path length", |value| {
                value["configuration"]["maxPathLength"] = json!(1);
            }),
            ("key algorithm", |value| {
                value["configuration"]["keyAlgorithm"] = json!("RSA_3072");
            }),
            ("parent", |value| {
                value["configuration"]["parentCaId"] = json!(CA_ID);
            }),
            ("serial", |value| {
                value["configuration"]["serialNumber"] = serde_json::Value::Null;
            }),
            ("active certificate", |value| {
                value["configuration"]["activeCaCertId"] = serde_json::Value::Null;
            }),
            ("distribution points", |value| {
                value["configuration"]["crlDistributionPointUrls"] = json!([]);
            }),
            ("managed distribution point", |value| {
                value["configuration"]["disableManagedCrlDistributionPointUrl"] = json!(true);
            }),
        ];
        for (field, mutate) in cases {
            let mut response = valid.clone();
            mutate(&mut response);
            let parsed = serde_json::from_value(response).unwrap();
            assert_eq!(
                created_internal_ca_from_wire(parsed, &project_id, &creation).unwrap_err(),
                ResourceError::InvalidCertificateAuthorityResponse,
                "accepted drifted {field}"
            );
        }
    }

    #[tokio::test]
    async fn general_inventory_drops_provider_configuration() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-inventory-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/ca"))
            .and(query_param("projectId", PROJECT_ID))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateAuthorities": [{
                    "id": CA_ID,
                    "projectId": PROJECT_ID,
                    "name": "external-ca",
                    "type": "digicert",
                    "status": "active",
                    "enableDirectIssuance": true,
                    "configuration": { "apiKey": "provider-secret-canary" }
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let authorities = InfisicalClient::new(settings(&server))
            .unwrap()
            .list_certificate_authorities(&CertificateAuthorityProjectId::new(PROJECT_ID).unwrap())
            .await
            .unwrap();
        let serialized = serde_json::to_string(&authorities).unwrap();
        assert_eq!(authorities.len(), 1);
        assert!(!serialized.contains("provider-secret-canary"));
        assert!(!serialized.contains("configuration"));
    }

    #[tokio::test]
    async fn internal_ca_reads_use_exact_audited_routes_and_drop_private_material() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-read-token").await;
        let response = internal_ca_value("root-ca", "active", &[], false);
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/ca/internal"))
            .and(query_param("projectId", PROJECT_ID))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([response.clone()])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/cert-manager/ca/internal/{CA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let authorities = client
            .list_internal_certificate_authorities(&project_id)
            .await
            .unwrap();
        assert_eq!(authorities.len(), 1);
        let authority = client
            .get_internal_certificate_authority(
                &project_id,
                &CertificateAuthorityId::new(CA_ID).unwrap(),
            )
            .await
            .unwrap();
        let serialized = serde_json::to_string(&authority).unwrap();
        assert_eq!(authority.id, CA_ID);
        assert!(!serialized.contains("must-never-cross"));
        assert!(!serialized.contains("encryptedPrivateKey"));
    }

    #[tokio::test]
    async fn ca_collections_accept_the_exact_response_limit() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-bounds-token").await;
        let general = (0..MAX_CA_LIST_ENTRIES)
            .map(|index| {
                json!({
                    "id": bounded_ca_id(index),
                    "projectId": PROJECT_ID,
                    "name": format!("ca-{index}"),
                    "type": "internal",
                    "status": "active",
                    "enableDirectIssuance": false
                })
            })
            .collect::<Vec<_>>();
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/ca"))
            .and(query_param("projectId", PROJECT_ID))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateAuthorities": general
            })))
            .expect(1)
            .mount(&server)
            .await;

        let internal = (0..MAX_CA_LIST_ENTRIES)
            .map(|index| {
                let mut authority =
                    internal_ca_value(&format!("internal-ca-{index}"), "active", &[], false);
                authority["id"] = json!(bounded_ca_id(index));
                authority
            })
            .collect::<Vec<_>>();
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/ca/internal"))
            .and(query_param("projectId", PROJECT_ID))
            .respond_with(ResponseTemplate::new(200).set_body_json(internal))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        assert_eq!(
            client
                .list_certificate_authorities(&project_id)
                .await
                .unwrap()
                .len(),
            MAX_CA_LIST_ENTRIES
        );
        assert_eq!(
            client
                .list_internal_certificate_authorities(&project_id)
                .await
                .unwrap()
                .len(),
            MAX_CA_LIST_ENTRIES
        );
    }

    #[tokio::test]
    async fn create_validates_project_then_sends_one_typed_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-create-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{PROJECT_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": {
                    "id": PROJECT_ID,
                    "name": "Certificates",
                    "slug": "certificates",
                    "type": "cert-manager",
                    "orgId": "org_123",
                    "description": null,
                    "environments": []
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/ca/internal"))
            .and(body_json(json!({
                "name": "root-ca",
                "projectId": PROJECT_ID,
                "status": "active",
                "configuration": {
                    "type": "root",
                    "commonName": "Root CA",
                    "organization": "Example",
                    "ou": "Security",
                    "country": "US",
                    "province": "TX",
                    "locality": "Austin",
                    "notBefore": "2026-01-01T00:00:00Z",
                    "notAfter": "2036-01-01T00:00:00Z",
                    "maxPathLength": 2,
                    "keyAlgorithm": "RSA_2048",
                    "crlDistributionPointUrls": ["https://pki.example.test/root.crl"],
                    "disableManagedCrlDistributionPointUrl": false
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(internal_ca_value(
                "root-ca",
                "active",
                &["https://pki.example.test/root.crl"],
                false,
            )))
            .expect(1)
            .mount(&server)
            .await;

        let creation = InternalCertificateAuthorityCreation::new(
            CertificateAuthorityName::new("root-ca").unwrap(),
            InternalCertificateAuthorityType::Root,
            subject(),
            Some("2026-01-01T00:00:00Z".to_owned()),
            Some("2036-01-01T00:00:00Z".to_owned()),
            Some(2),
            CertificateKeyAlgorithm::Rsa2048,
            vec!["https://pki.example.test/root.crl".to_owned()],
            false,
        )
        .unwrap();
        let created = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_internal_certificate_authority(
                &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                creation,
                true,
            )
            .await
            .unwrap();
        assert_eq!(created.id, CA_ID);
        assert_eq!(created.status, CertificateAuthorityStatus::Active);
    }

    #[tokio::test]
    async fn create_rejects_non_certificate_manager_project_before_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-wrong-project-kind-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{PROJECT_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": {
                    "id": PROJECT_ID,
                    "name": "Secrets",
                    "slug": "secrets",
                    "type": "secret-manager",
                    "orgId": "org_123",
                    "description": null,
                    "environments": []
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let creation = InternalCertificateAuthorityCreation::new(
            CertificateAuthorityName::new("root-ca").unwrap(),
            InternalCertificateAuthorityType::Root,
            subject(),
            None,
            None,
            None,
            CertificateKeyAlgorithm::Rsa2048,
            vec![],
            false,
        )
        .unwrap();
        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_internal_certificate_authority(
                &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                creation,
                true,
            )
            .await
            .unwrap_err();
        assert_eq!(error, ResourceError::InvalidCertificateAuthorityProjectKind);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method != "POST" || request.url.path().contains("/auth/"))
        );
    }

    #[tokio::test]
    async fn update_preflights_scope_sends_one_exact_patch_and_rejects_other_drift() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-update-token").await;
        let before = internal_ca_value("root-ca", "active", &[], false);
        let after = internal_ca_value(
            "renamed-ca",
            "disabled",
            &["https://pki.example.test/root.crl"],
            true,
        );
        let exact_path = format!("/api/v1/cert-manager/ca/internal/{CA_ID}");
        Mock::given(method("GET"))
            .and(path(exact_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(before.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(exact_path))
            .and(body_json(json!({
                "name": "renamed-ca",
                "status": "disabled",
                "configuration": {
                    "crlDistributionPointUrls": ["https://pki.example.test/root.crl"],
                    "disableManagedCrlDistributionPointUrl": true
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(after.clone()))
            .expect(1)
            .mount(&server)
            .await;

        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let ca_id = CertificateAuthorityId::new(CA_ID).unwrap();
        let change = InternalCertificateAuthorityChange::new(
            Some(CertificateAuthorityName::new("renamed-ca").unwrap()),
            Some(CertificateAuthorityStatus::Disabled),
            Some(vec!["https://pki.example.test/root.crl".to_owned()]),
            Some(true),
        )
        .unwrap();
        let updated = InfisicalClient::new(settings(&server))
            .unwrap()
            .update_internal_certificate_authority(&project_id, &ca_id, change.clone(), true)
            .await
            .unwrap();
        assert_eq!(updated.name, "renamed-ca");

        let before = internal_ca_from_wire(
            serde_json::from_value(before).unwrap(),
            &project_id,
            Some(&ca_id),
        )
        .unwrap();
        let mut drifted = after;
        drifted["configuration"]["organization"] = json!("Unexpected");
        assert_eq!(
            updated_internal_ca_from_wire(
                serde_json::from_value(drifted).unwrap(),
                &project_id,
                &ca_id,
                &before,
                &change,
            )
            .unwrap_err(),
            ResourceError::InvalidCertificateAuthorityResponse
        );
    }

    #[tokio::test]
    async fn update_serializes_a_single_configuration_field() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-update-config-token").await;
        let before = internal_ca_value("root-ca", "active", &[], false);
        let after = internal_ca_value(
            "root-ca",
            "active",
            &["https://pki.example.test/root.crl"],
            false,
        );
        let exact_path = format!("/api/v1/cert-manager/ca/internal/{CA_ID}");
        Mock::given(method("GET"))
            .and(path(exact_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(before))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(exact_path))
            .and(body_json(json!({
                "configuration": {
                    "crlDistributionPointUrls": ["https://pki.example.test/root.crl"]
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(after))
            .expect(1)
            .mount(&server)
            .await;

        let updated = InfisicalClient::new(settings(&server))
            .unwrap()
            .update_internal_certificate_authority(
                &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                &CertificateAuthorityId::new(CA_ID).unwrap(),
                InternalCertificateAuthorityChange::new(
                    None,
                    None,
                    Some(vec!["https://pki.example.test/root.crl".to_owned()]),
                    None,
                )
                .unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(
            updated.configuration.crl_distribution_point_urls,
            ["https://pki.example.test/root.crl"]
        );
    }

    #[tokio::test]
    async fn delete_preflights_scope_and_returns_the_exact_deleted_authority() {
        let server = MockServer::start().await;
        mount_login(&server, "ca-delete-token").await;
        let response = internal_ca_value("root-ca", "active", &[], false);
        let exact_path = format!("/api/v1/cert-manager/ca/internal/{CA_ID}");
        Mock::given(method("GET"))
            .and(path(exact_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(response.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(exact_path))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;

        let deleted = InfisicalClient::new(settings(&server))
            .unwrap()
            .delete_internal_certificate_authority(
                &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                &CertificateAuthorityId::new(CA_ID).unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(deleted.id, CA_ID);
    }

    #[tokio::test]
    async fn confirmation_failure_makes_no_upstream_request() {
        let server = MockServer::start().await;
        let creation = InternalCertificateAuthorityCreation::new(
            CertificateAuthorityName::new("root-ca").unwrap(),
            InternalCertificateAuthorityType::Root,
            subject(),
            None,
            None,
            None,
            CertificateKeyAlgorithm::Rsa2048,
            vec![],
            false,
        )
        .unwrap();
        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_internal_certificate_authority(
                &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                creation,
                false,
            )
            .await
            .unwrap_err();
        assert_eq!(error, ResourceError::CertificateAuthorityCreateNotConfirmed);
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
