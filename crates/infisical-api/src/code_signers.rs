use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;
use x509_parser::{
    prelude::{FromDer, X509Certificate},
    public_key::PublicKey,
    x509::SubjectPublicKeyInfo,
};
use zeroize::Zeroizing;

use crate::{
    Certificate, CertificateAuthorityId, CertificateAuthorityProjectId, CertificateAuthorityStatus,
    CertificateId, CertificateKeyAlgorithm, CertificateStatus, InfisicalClient, MutationOperation,
    ObservableReadOperation, Page, PageRequest, ResourceError, SecretValue,
    certificate::{certificate_bundle_der, certificate_serial_matches, normalize_pem},
    client::{ApiVersion, Endpoint, sealed},
    resources::{is_bounded_text, is_uuid, utc_timestamp_millis},
};

const MAX_SIGNER_NAME_BYTES: usize = 64;
const MAX_SIGNER_DESCRIPTION_BYTES: usize = 256;
const MAX_SIGNER_TEXT_BYTES: usize = 256;
const MAX_SIGNER_FAILURE_BYTES: usize = 1_024;
const MAX_SIGNER_SEARCH_BYTES: usize = 255;
const MAX_SIGNER_DATA_BYTES: usize = 128;
const MAX_SIGNATURE_BYTES: usize = 4_096;
const MAX_PUBLIC_KEY_BYTES: usize = 8_192;
const MAX_CERTIFICATE_PEM_BYTES: usize = 64 * 1024;
const MAX_SERIAL_NUMBER_BYTES: usize = 128;
const MAX_CLIENT_TOOL_BYTES: usize = 128;
const MAX_CLIENT_HOSTNAME_BYTES: usize = 256;
const MAX_CLIENT_IP_BYTES: usize = 64;
const MAX_CERTIFICATE_TTL_DAYS: u16 = 3_650;

/// Input validation failures for the pinned code-signer contract.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CodeSignerInputError {
    #[error("code-signer ID must be a UUID")]
    InvalidId,
    #[error("code-signer certificate ID must be a UUID")]
    InvalidCertificateId,
    #[error("code-signer name must contain 1 to 64 lowercase letters, numbers, or hyphens")]
    InvalidName,
    #[error("code-signer description must be trimmed, control-free, and at most 256 bytes")]
    InvalidDescription,
    #[error("code-signer text fields must be trimmed, control-free, and at most 256 bytes")]
    InvalidText,
    #[error("code-signer search must be trimmed, control-free, and at most 255 bytes")]
    InvalidSearch,
    #[error("code-signer certificate TTL must be between 1 and 3650 days")]
    InvalidCertificateTtl,
    #[error(
        "code-signer renew-before days must be between 1 and 30 and less than the certificate TTL"
    )]
    InvalidRenewBefore,
    #[error("code signers support only RSA 2048/3072/4096 and ECDSA P-256/P-384/P-521 keys")]
    UnsupportedKeyAlgorithm,
    #[error("code-signer update must change at least one field")]
    EmptyChange,
    #[error("code-signing data must be canonical base64 containing at most 128 decoded bytes")]
    InvalidSigningData,
    #[error("code-signing digest length does not match the selected algorithm")]
    InvalidDigest,
    #[error("code-signing client metadata is empty, untrimmed, control-bearing, or oversized")]
    InvalidClientMetadata,
}

macro_rules! uuid_id {
    ($name:ident, $error:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validate a UUID before it reaches a code-signing route.
            ///
            /// # Errors
            ///
            /// Returns an error when the value is not a UUID.
            pub fn new(value: impl Into<String>) -> Result<Self, CodeSignerInputError> {
                let value = value.into();
                if !is_uuid(&value) {
                    return Err($error);
                }
                Ok(Self(value.to_ascii_lowercase()))
            }

            /// Borrow the canonical identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

uuid_id!(CodeSignerId, CodeSignerInputError::InvalidId);
uuid_id!(
    CodeSignerCertificateId,
    CodeSignerInputError::InvalidCertificateId
);

/// Validated project-local code-signer name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct CodeSignerName(String);

impl CodeSignerName {
    /// Validate the exact public signer slug grammar.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, or non-canonical values.
    pub fn new(value: impl Into<String>) -> Result<Self, CodeSignerInputError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_SIGNER_NAME_BYTES
            || value.starts_with('-')
            || value.ends_with('-')
            || value.split('-').any(str::is_empty)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(CodeSignerInputError::InvalidName);
        }
        Ok(Self(value))
    }

    /// Borrow the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lifecycle state returned by the pinned code-signer API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CodeSignerStatus {
    Pending,
    Active,
    Failed,
    Disabled,
    Expired,
}

/// User-selectable signer state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CodeSignerDesiredStatus {
    Active,
    Disabled,
}

/// Supported code-signing algorithms for RSA and ECDSA signer certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[allow(clippy::enum_variant_names)]
pub enum CodeSigningAlgorithm {
    #[serde(rename = "RSASSA_PSS_SHA_512")]
    RsaPssSha512,
    #[serde(rename = "RSASSA_PSS_SHA_384")]
    RsaPssSha384,
    #[serde(rename = "RSASSA_PSS_SHA_256")]
    RsaPssSha256,
    #[serde(rename = "RSASSA_PKCS1_V1_5_SHA_512")]
    RsaPkcs1V15Sha512,
    #[serde(rename = "RSASSA_PKCS1_V1_5_SHA_384")]
    RsaPkcs1V15Sha384,
    #[serde(rename = "RSASSA_PKCS1_V1_5_SHA_256")]
    RsaPkcs1V15Sha256,
    #[serde(rename = "ECDSA_SHA_512")]
    EcdsaSha512,
    #[serde(rename = "ECDSA_SHA_384")]
    EcdsaSha384,
    #[serde(rename = "ECDSA_SHA_256")]
    EcdsaSha256,
}

impl CodeSigningAlgorithm {
    fn supports_key(self, key_algorithm: CertificateKeyAlgorithm) -> bool {
        match key_algorithm {
            CertificateKeyAlgorithm::Rsa2048
            | CertificateKeyAlgorithm::Rsa3072
            | CertificateKeyAlgorithm::Rsa4096 => matches!(
                self,
                Self::RsaPssSha512
                    | Self::RsaPssSha384
                    | Self::RsaPssSha256
                    | Self::RsaPkcs1V15Sha512
                    | Self::RsaPkcs1V15Sha384
                    | Self::RsaPkcs1V15Sha256
            ),
            CertificateKeyAlgorithm::EcPrime256v1
            | CertificateKeyAlgorithm::EcSecp384r1
            | CertificateKeyAlgorithm::EcSecp521r1 => {
                matches!(
                    self,
                    Self::EcdsaSha512 | Self::EcdsaSha384 | Self::EcdsaSha256
                )
            }
            _ => false,
        }
    }

    const fn digest_bytes(self) -> Option<usize> {
        match self {
            Self::RsaPkcs1V15Sha512 | Self::EcdsaSha512 => Some(64),
            Self::RsaPkcs1V15Sha384 | Self::EcdsaSha384 => Some(48),
            Self::RsaPkcs1V15Sha256 | Self::EcdsaSha256 => Some(32),
            Self::RsaPssSha512 | Self::RsaPssSha384 | Self::RsaPssSha256 => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum CodeSignerPublicKeyFamily {
    #[serde(rename = "RSA_4096")]
    Rsa,
    #[serde(rename = "ECC_NIST_P256")]
    EccNistP256,
    #[serde(rename = "ECC_NIST_P384")]
    EccNistP384,
    #[serde(rename = "ECC_NIST_P521")]
    EccNistP521,
}

/// Existing certificate or internal CA used to create one signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeSignerCertificateSource {
    Existing {
        certificate_id: CodeSignerCertificateId,
    },
    InternalCertificateAuthority {
        ca_id: CertificateAuthorityId,
        common_name: String,
        certificate_ttl_days: u16,
        certificate_renew_before_days: Option<u8>,
        key_algorithm: CertificateKeyAlgorithm,
    },
}

impl CodeSignerCertificateSource {
    /// Build an internal-CA signer source after validating its subject and key settings.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid subject, TTL, renewal, or key-algorithm values.
    pub fn internal_ca(
        ca_id: CertificateAuthorityId,
        common_name: impl Into<String>,
        certificate_ttl_days: u16,
        certificate_renew_before_days: Option<u8>,
        key_algorithm: CertificateKeyAlgorithm,
    ) -> Result<Self, CodeSignerInputError> {
        let common_name = common_name.into();
        validate_text(&common_name)?;
        validate_certificate_settings(
            certificate_ttl_days,
            certificate_renew_before_days,
            key_algorithm,
        )?;
        Ok(Self::InternalCertificateAuthority {
            ca_id,
            common_name,
            certificate_ttl_days,
            certificate_renew_before_days,
            key_algorithm,
        })
    }
}

/// Validated code-signer creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignerCreation {
    name: CodeSignerName,
    description: Option<String>,
    source: CodeSignerCertificateSource,
}

impl CodeSignerCreation {
    /// Bind signer metadata to one validated certificate source.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid description.
    pub fn new(
        name: CodeSignerName,
        description: Option<String>,
        source: CodeSignerCertificateSource,
    ) -> Result<Self, CodeSignerInputError> {
        validate_description(description.as_deref())?;
        Ok(Self {
            name,
            description,
            source,
        })
    }
}

/// Optional-description update that distinguishes omission from clearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeSignerDescriptionChange {
    Set(String),
    Clear,
}

/// Optional renew-before update that distinguishes omission from clearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeSignerRenewBeforeChange {
    Set(u8),
    Clear,
}

/// Non-empty code-signer metadata change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignerChange {
    name: Option<CodeSignerName>,
    description: Option<CodeSignerDescriptionChange>,
    certificate_renew_before_days: Option<CodeSignerRenewBeforeChange>,
}

impl CodeSignerChange {
    /// Validate one non-empty signer change.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid values or a no-op request.
    pub fn new(
        name: Option<CodeSignerName>,
        description: Option<CodeSignerDescriptionChange>,
        certificate_renew_before_days: Option<CodeSignerRenewBeforeChange>,
    ) -> Result<Self, CodeSignerInputError> {
        if let Some(CodeSignerDescriptionChange::Set(value)) = description.as_ref() {
            validate_description(Some(value))?;
        }
        if let Some(CodeSignerRenewBeforeChange::Set(value)) = certificate_renew_before_days
            && !(1..=30).contains(&value)
        {
            return Err(CodeSignerInputError::InvalidRenewBefore);
        }
        if name.is_none() && description.is_none() && certificate_renew_before_days.is_none() {
            return Err(CodeSignerInputError::EmptyChange);
        }
        Ok(Self {
            name,
            description,
            certificate_renew_before_days,
        })
    }
}

/// Optional subject changes accepted only while a signer is pending or failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignerCertificateReissue {
    pub ca_id: CertificateAuthorityId,
    pub common_name: Option<String>,
    pub certificate_ttl_days: Option<u16>,
}

impl CodeSignerCertificateReissue {
    /// Validate a signer certificate-reissue request.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid optional subject or TTL values.
    pub fn new(
        ca_id: CertificateAuthorityId,
        common_name: Option<String>,
        certificate_ttl_days: Option<u16>,
    ) -> Result<Self, CodeSignerInputError> {
        if let Some(common_name) = common_name.as_deref() {
            validate_text(common_name)?;
        }
        if certificate_ttl_days
            .is_some_and(|value| !(1..=MAX_CERTIFICATE_TTL_DAYS).contains(&value))
        {
            return Err(CodeSignerInputError::InvalidCertificateTtl);
        }
        Ok(Self {
            ca_id,
            common_name,
            certificate_ttl_days,
        })
    }
}

/// One bounded page request for signer inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignerListRequest {
    pub project_id: CertificateAuthorityProjectId,
    pub page: PageRequest,
    pub search: Option<String>,
}

impl CodeSignerListRequest {
    /// Validate one bounded signer list request.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid search string.
    pub fn new(
        project_id: CertificateAuthorityProjectId,
        page: PageRequest,
        search: Option<String>,
    ) -> Result<Self, CodeSignerInputError> {
        if search.as_deref().is_some_and(|value| {
            value.is_empty()
                || value.trim() != value
                || value.len() > MAX_SIGNER_SEARCH_BYTES
                || value.chars().any(char::is_control)
        }) {
            return Err(CodeSignerInputError::InvalidSearch);
        }
        Ok(Self {
            project_id,
            page,
            search,
        })
    }
}

/// Sensitive base64 data submitted for signing.
#[derive(Debug)]
pub struct CodeSigningData(SecretValue, usize);

impl CodeSigningData {
    /// Validate and redact bounded code-signing data.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, malformed, non-canonical, or oversized base64.
    pub fn new(value: SecretValue) -> Result<Self, CodeSignerInputError> {
        let decoded_len =
            decode_canonical_secret_base64(value.expose_secret(), MAX_SIGNER_DATA_BYTES)
                .map_err(|()| CodeSignerInputError::InvalidSigningData)?;
        Ok(Self(value, decoded_len))
    }
}

/// Optional non-secret client attribution recorded in Infisical's signing audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeSigningClientMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_ip: Option<String>,
}

impl CodeSigningClientMetadata {
    /// Validate non-empty bounded client attribution.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, untrimmed, control-bearing, or oversized fields.
    pub fn new(
        tool: Option<String>,
        hostname: Option<String>,
        reported_ip: Option<String>,
    ) -> Result<Self, CodeSignerInputError> {
        let fields = [
            (tool.as_deref(), MAX_CLIENT_TOOL_BYTES),
            (hostname.as_deref(), MAX_CLIENT_HOSTNAME_BYTES),
            (reported_ip.as_deref(), MAX_CLIENT_IP_BYTES),
        ];
        if fields.iter().any(|(value, max)| {
            value.is_some_and(|value| {
                value.is_empty()
                    || value.trim() != value
                    || value.len() > *max
                    || value.chars().any(char::is_control)
            })
        }) || fields.iter().all(|(value, _)| value.is_none())
        {
            return Err(CodeSignerInputError::InvalidClientMetadata);
        }
        Ok(Self {
            tool,
            hostname,
            reported_ip,
        })
    }
}

/// Sanitized code-signer metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSigner {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: CodeSignerStatus,
    pub certificate_id: Option<String>,
    pub approval_policy_id: Option<String>,
    pub last_signed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub ca_id: Option<String>,
    pub common_name: Option<String>,
    pub certificate_ttl_days: Option<u16>,
    pub certificate_renew_before_days: Option<u8>,
    pub certificate_failure_reason: Option<String>,
    pub key_algorithm: CertificateKeyAlgorithm,
    pub certificate_common_name: Option<String>,
    pub certificate_serial_number: Option<String>,
    pub certificate_not_before: Option<String>,
    pub certificate_not_after: Option<String>,
    pub certificate_key_algorithm: Option<CertificateKeyAlgorithm>,
    pub certificate_status: Option<String>,
    pub certificate_ca_id: Option<String>,
    pub approval_policy_name: Option<String>,
}

/// Exported signer leaf certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerCertificate {
    pub signer_id: String,
    pub signer_name: String,
    pub serial_number: String,
    pub certificate_pem: String,
}

/// DER `SubjectPublicKeyInfo` returned as base64 for one signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerPublicKey {
    pub signer_id: String,
    pub signer_name: String,
    pub algorithm: CertificateKeyAlgorithm,
    pub public_key: String,
}

/// Signature produced by one exact code signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerSignature {
    pub signer_id: String,
    pub signing_algorithm: CodeSigningAlgorithm,
    pub signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListSignersQuery {
    project_id: String,
    offset: u32,
    limit: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    search: Option<String>,
}

#[derive(Serialize)]
struct SignerIdQuery {
    #[serde(skip_serializing)]
    signer_id: CodeSignerId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSignerRequest {
    project_id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    common_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate_ttl_days: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate_renew_before_days: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_algorithm: Option<CertificateKeyAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateSignerRequest {
    #[serde(skip_serializing)]
    signer_id: CodeSignerId,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<NullableString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate_renew_before_days: Option<NullableU8>,
}

enum NullableString {
    Value(String),
    Null,
}

impl Serialize for NullableString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Value(value) => value.serialize(serializer),
            Self::Null => serializer.serialize_none(),
        }
    }
}

enum NullableU8 {
    Value(u8),
    Null,
}

impl Serialize for NullableU8 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Value(value) => value.serialize(serializer),
            Self::Null => serializer.serialize_none(),
        }
    }
}

#[derive(Serialize)]
struct DeleteSignerRequest {
    #[serde(skip_serializing)]
    signer_id: CodeSignerId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateSignerStatusRequest {
    #[serde(skip_serializing)]
    signer_id: CodeSignerId,
    status: CodeSignerDesiredStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReissueSignerCertificateRequest {
    #[serde(skip_serializing)]
    signer_id: CodeSignerId,
    ca_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    common_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate_ttl_days: Option<u16>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignRequest {
    #[serde(skip_serializing)]
    signer_id: CodeSignerId,
    #[serde(serialize_with = "serialize_secret")]
    data: SecretValue,
    signing_algorithm: CodeSigningAlgorithm,
    is_digest: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_metadata: Option<CodeSigningClientMetadata>,
}

fn serialize_secret<S>(value: &SecretValue, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.expose_secret())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListSignersResponse {
    signers: Vec<CodeSignerWire>,
    total_count: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CodeSignerWire {
    id: String,
    project_id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    status: CodeSignerStatus,
    #[serde(default)]
    certificate_id: Option<String>,
    #[serde(default)]
    approval_policy_id: Option<String>,
    #[serde(default)]
    last_signed_at: Option<String>,
    created_at: String,
    updated_at: String,
    #[serde(default)]
    ca_id: Option<String>,
    #[serde(default)]
    common_name: Option<String>,
    #[serde(default)]
    certificate_ttl_days: Option<u16>,
    #[serde(default)]
    certificate_renew_before_days: Option<u8>,
    #[serde(default)]
    certificate_failure_reason: Option<String>,
    key_algorithm: CertificateKeyAlgorithm,
    #[serde(default)]
    certificate_common_name: Option<String>,
    #[serde(default)]
    certificate_serial_number: Option<String>,
    #[serde(default)]
    certificate_not_before: Option<String>,
    #[serde(default)]
    certificate_not_after: Option<String>,
    #[serde(default)]
    certificate_key_algorithm: Option<CertificateKeyAlgorithm>,
    #[serde(default)]
    certificate_status: Option<String>,
    #[serde(default)]
    certificate_ca_id: Option<String>,
    #[serde(default)]
    approval_policy_name: Option<String>,
}

struct ExistingSignerCertificateBinding {
    certificate_id: CodeSignerCertificateId,
    key_algorithm: CertificateKeyAlgorithm,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportCertificateWire {
    certificate_pem: String,
    serial_number: String,
    signer_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyWire {
    public_key: String,
    algorithm: CodeSignerPublicKeyFamily,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureWire {
    signature: String,
    signing_algorithm: CodeSigningAlgorithm,
    signer_id: String,
}

macro_rules! signer_read {
    ($operation:ident, $query:ty, $output:ty, $segments:expr) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl ObservableReadOperation for $operation {
            type Query = $query;
            type Output = $output;

            fn endpoint(query: &Self::Query) -> Endpoint {
                Endpoint::from_segments(ApiVersion::V1, ($segments)(query))
            }
        }
    };
}

signer_read!(
    ListSigners,
    ListSignersQuery,
    ListSignersResponse,
    |_query: &ListSignersQuery| ["cert-manager".to_owned(), "signers".to_owned()]
);
signer_read!(
    GetSigner,
    SignerIdQuery,
    CodeSignerWire,
    |query: &SignerIdQuery| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        query.signer_id.as_str().to_owned()
    ]
);
signer_read!(
    GetSignerPublicKey,
    SignerIdQuery,
    PublicKeyWire,
    |query: &SignerIdQuery| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        query.signer_id.as_str().to_owned(),
        "public-key".to_owned()
    ]
);
signer_read!(
    ExportSignerCertificate,
    SignerIdQuery,
    ExportCertificateWire,
    |query: &SignerIdQuery| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        query.signer_id.as_str().to_owned(),
        "certificate".to_owned()
    ]
);
macro_rules! signer_mutation {
    ($operation:ident, $input:ty, $output:ty, $method:expr, $segments:expr) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl MutationOperation for $operation {
            type Input = $input;
            type Output = $output;

            fn method() -> Method {
                $method
            }

            fn endpoint(input: &Self::Input) -> Endpoint {
                Endpoint::from_segments(ApiVersion::V1, ($segments)(input))
            }
        }
    };
}

signer_mutation!(
    CreateSigner,
    CreateSignerRequest,
    CodeSignerWire,
    Method::POST,
    |_input: &CreateSignerRequest| ["cert-manager".to_owned(), "signers".to_owned()]
);
signer_mutation!(
    UpdateSigner,
    UpdateSignerRequest,
    CodeSignerWire,
    Method::PATCH,
    |input: &UpdateSignerRequest| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned()
    ]
);
signer_mutation!(
    DeleteSigner,
    DeleteSignerRequest,
    CodeSignerWire,
    Method::DELETE,
    |input: &DeleteSignerRequest| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned()
    ]
);
signer_mutation!(
    UpdateSignerStatus,
    UpdateSignerStatusRequest,
    CodeSignerWire,
    Method::PATCH,
    |input: &UpdateSignerStatusRequest| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned(),
        "status".to_owned()
    ]
);
signer_mutation!(
    ReissueSignerCertificate,
    ReissueSignerCertificateRequest,
    CodeSignerWire,
    Method::POST,
    |input: &ReissueSignerCertificateRequest| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned(),
        "certificate".to_owned(),
        "reissue".to_owned()
    ]
);
signer_mutation!(
    SignData,
    SignRequest,
    SignatureWire,
    Method::POST,
    |input: &SignRequest| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned(),
        "sign".to_owned()
    ]
);

fn validate_description(value: Option<&str>) -> Result<(), CodeSignerInputError> {
    if value.is_some_and(|value| {
        value.trim() != value
            || value.len() > MAX_SIGNER_DESCRIPTION_BYTES
            || value.chars().any(char::is_control)
    }) {
        return Err(CodeSignerInputError::InvalidDescription);
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), CodeSignerInputError> {
    if value.trim() != value
        || !is_bounded_text(value, MAX_SIGNER_TEXT_BYTES)
        || value.chars().any(char::is_control)
    {
        return Err(CodeSignerInputError::InvalidText);
    }
    Ok(())
}

fn supported_code_signer_key_algorithm(value: CertificateKeyAlgorithm) -> bool {
    matches!(
        value,
        CertificateKeyAlgorithm::Rsa2048
            | CertificateKeyAlgorithm::Rsa3072
            | CertificateKeyAlgorithm::Rsa4096
            | CertificateKeyAlgorithm::EcPrime256v1
            | CertificateKeyAlgorithm::EcSecp384r1
            | CertificateKeyAlgorithm::EcSecp521r1
    )
}

fn validate_certificate_settings(
    certificate_ttl_days: u16,
    certificate_renew_before_days: Option<u8>,
    key_algorithm: CertificateKeyAlgorithm,
) -> Result<(), CodeSignerInputError> {
    if !(1..=MAX_CERTIFICATE_TTL_DAYS).contains(&certificate_ttl_days) {
        return Err(CodeSignerInputError::InvalidCertificateTtl);
    }
    if certificate_renew_before_days
        .is_some_and(|value| !(1..=30).contains(&value) || u16::from(value) >= certificate_ttl_days)
    {
        return Err(CodeSignerInputError::InvalidRenewBefore);
    }
    if !supported_code_signer_key_algorithm(key_algorithm) {
        return Err(CodeSignerInputError::UnsupportedKeyAlgorithm);
    }
    Ok(())
}

fn decode_canonical_base64(
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<Vec<u8>, ()> {
    let decoded = STANDARD.decode(value).map_err(|_| ())?;
    if (!allow_empty && decoded.is_empty())
        || decoded.len() > max_bytes
        || STANDARD.encode(&decoded) != value
    {
        return Err(());
    }
    Ok(decoded)
}

fn decode_canonical_secret_base64(value: &str, max_bytes: usize) -> Result<usize, ()> {
    let decoded = Zeroizing::new(STANDARD.decode(value).map_err(|_| ())?);
    if decoded.is_empty() || decoded.len() > max_bytes {
        return Err(());
    }
    let encoded = Zeroizing::new(STANDARD.encode(decoded.as_slice()));
    if encoded.as_str() != value {
        return Err(());
    }
    Ok(decoded.len())
}

fn valid_timestamp(value: &str) -> bool {
    utc_timestamp_millis(value).is_some()
}

fn current_timestamp_millis() -> Option<i64> {
    const UNIX_EPOCH_FROM_YEAR_ONE_MILLIS: i64 = 62_135_596_800_000;
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(elapsed.as_millis())
        .ok()?
        .checked_add(UNIX_EPOCH_FROM_YEAR_ONE_MILLIS)
}

fn valid_optional_uuid(value: Option<&str>) -> bool {
    value.is_none_or(is_uuid)
}

fn signer_from_wire(
    wire: CodeSignerWire,
    expected_project: &CertificateAuthorityProjectId,
    expected_id: Option<&CodeSignerId>,
) -> Result<CodeSigner, ResourceError> {
    let id = CodeSignerId::new(&wire.id).map_err(|_| ResourceError::InvalidCodeSignerResponse)?;
    if wire.project_id != expected_project.as_str()
        || expected_id.is_some_and(|expected| expected != &id)
        || CodeSignerName::new(&wire.name).is_err()
        || validate_description(wire.description.as_deref()).is_err()
        || !valid_optional_uuid(wire.certificate_id.as_deref())
        || !valid_optional_uuid(wire.approval_policy_id.as_deref())
        || !valid_optional_uuid(wire.ca_id.as_deref())
        || !valid_optional_uuid(wire.certificate_ca_id.as_deref())
        || wire
            .last_signed_at
            .as_deref()
            .is_some_and(|value| !valid_timestamp(value))
        || !valid_timestamp(&wire.created_at)
        || !valid_timestamp(&wire.updated_at)
        || wire
            .common_name
            .as_deref()
            .is_some_and(|value| validate_text(value).is_err())
        || wire
            .certificate_common_name
            .as_deref()
            .is_some_and(|value| validate_text(value).is_err())
        || wire
            .certificate_ttl_days
            .is_some_and(|value| !(1..=MAX_CERTIFICATE_TTL_DAYS).contains(&value))
        || wire
            .certificate_renew_before_days
            .is_some_and(|value| !(1..=30).contains(&value))
        || wire
            .certificate_failure_reason
            .as_deref()
            .is_some_and(|value| !is_bounded_text(value, MAX_SIGNER_FAILURE_BYTES))
        || !supported_code_signer_key_algorithm(wire.key_algorithm)
        || wire
            .certificate_key_algorithm
            .is_some_and(|value| !supported_code_signer_key_algorithm(value))
        || wire
            .certificate_serial_number
            .as_deref()
            .is_some_and(|value| !valid_serial(value))
        || wire
            .certificate_not_before
            .as_deref()
            .is_some_and(|value| !valid_timestamp(value))
        || wire
            .certificate_not_after
            .as_deref()
            .is_some_and(|value| !valid_timestamp(value))
        || wire
            .certificate_status
            .as_deref()
            .is_some_and(|value| !matches!(value, "active" | "expired" | "revoked"))
        || wire
            .approval_policy_name
            .as_deref()
            .is_some_and(|value| !is_bounded_text(value, MAX_SIGNER_TEXT_BYTES))
    {
        return Err(ResourceError::InvalidCodeSignerResponse);
    }
    if let (Some(renew), Some(ttl)) = (
        wire.certificate_renew_before_days,
        wire.certificate_ttl_days,
    ) && u16::from(renew) >= ttl
    {
        return Err(ResourceError::InvalidCodeSignerResponse);
    }
    Ok(CodeSigner {
        id: id.as_str().to_owned(),
        project_id: wire.project_id,
        name: wire.name,
        description: wire.description,
        status: wire.status,
        certificate_id: wire.certificate_id,
        approval_policy_id: wire.approval_policy_id,
        last_signed_at: wire.last_signed_at,
        created_at: wire.created_at,
        updated_at: wire.updated_at,
        ca_id: wire.ca_id,
        common_name: wire.common_name,
        certificate_ttl_days: wire.certificate_ttl_days,
        certificate_renew_before_days: wire.certificate_renew_before_days,
        certificate_failure_reason: wire.certificate_failure_reason,
        key_algorithm: wire.key_algorithm,
        certificate_common_name: wire.certificate_common_name,
        certificate_serial_number: wire.certificate_serial_number,
        certificate_not_before: wire.certificate_not_before,
        certificate_not_after: wire.certificate_not_after,
        certificate_key_algorithm: wire.certificate_key_algorithm,
        certificate_status: wire.certificate_status,
        certificate_ca_id: wire.certificate_ca_id,
        approval_policy_name: wire.approval_policy_name,
    })
}

fn valid_serial(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SERIAL_NUMBER_BYTES
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn existing_signer_certificate_is_usable(
    certificate: &Certificate,
    project_id: &CertificateAuthorityProjectId,
    certificate_id: &CodeSignerCertificateId,
    now: Option<i64>,
) -> bool {
    let Some(not_before) = utc_timestamp_millis(&certificate.not_before) else {
        return false;
    };
    let Some(not_after) = utc_timestamp_millis(&certificate.not_after) else {
        return false;
    };
    let Some(now) = now else {
        return false;
    };
    certificate.id == certificate_id.as_str()
        && certificate.project_id == project_id.as_str()
        && certificate.status == CertificateStatus::Active
        && certificate.has_private_key
        && not_before <= now
        && not_after > now
        && certificate.is_ca == Some(false)
        && certificate
            .key_algorithm
            .is_some_and(supported_code_signer_key_algorithm)
        && certificate
            .extended_key_usages
            .as_ref()
            .is_some_and(|usages| usages.iter().any(|usage| usage == "codeSigning"))
}

fn internal_signer_ca_is_usable(status: CertificateAuthorityStatus) -> bool {
    status == CertificateAuthorityStatus::Active
}

fn signer_page_from_wire(
    response: ListSignersResponse,
    request: &CodeSignerListRequest,
) -> Result<Page<CodeSigner>, ResourceError> {
    let returned = u32::try_from(response.signers.len())
        .map_err(|_| ResourceError::InvalidCodeSignerResponse)?;
    let returned_end = request
        .page
        .offset()
        .checked_add(returned)
        .ok_or(ResourceError::InvalidCodeSignerResponse)?;
    let pagination_is_incoherent = if returned == 0 {
        request.page.offset() < response.total_count
    } else {
        returned_end > response.total_count
            || (returned < u32::from(request.page.limit()) && returned_end != response.total_count)
    };
    if response.signers.len() > usize::from(request.page.limit()) || pagination_is_incoherent {
        return Err(ResourceError::InvalidCodeSignerResponse);
    }
    let signers = response
        .signers
        .into_iter()
        .map(|wire| signer_from_wire(wire, &request.project_id, None))
        .collect::<Result<Vec<_>, _>>()?;
    if signers
        .iter()
        .map(|signer| &signer.id)
        .collect::<HashSet<_>>()
        .len()
        != signers.len()
        || request.search.as_ref().is_some_and(|search| {
            let search = search.to_lowercase();
            signers.iter().any(|signer| {
                !signer.name.to_lowercase().contains(&search)
                    && !signer
                        .certificate_common_name
                        .as_ref()
                        .is_some_and(|name| name.to_lowercase().contains(&search))
            })
        })
    {
        return Err(ResourceError::InvalidCodeSignerScope);
    }
    Ok(Page::new(
        request.page,
        signers,
        Some(u64::from(response.total_count)),
    )?)
}

fn created_signer_matches(
    signer: &CodeSigner,
    request: &CreateSignerRequest,
    existing_certificate: Option<&ExistingSignerCertificateBinding>,
    expected_name: &str,
    expected_description: Option<&str>,
) -> bool {
    signer.name == expected_name
        && signer.description.as_deref() == expected_description
        && signer.status == CodeSignerStatus::Active
        && request
            .certificate_id
            .as_ref()
            .is_none_or(|certificate_id| signer.certificate_id.as_ref() == Some(certificate_id))
        && request.ca_id.as_ref() == signer.ca_id.as_ref()
        && request.common_name == signer.common_name
        && request.certificate_ttl_days == signer.certificate_ttl_days
        && request.certificate_renew_before_days == signer.certificate_renew_before_days
        && request
            .key_algorithm
            .is_none_or(|value| signer.key_algorithm == value)
        && match (
            request.certificate_id.as_deref(),
            request.ca_id.as_deref(),
            request.common_name.as_deref(),
            existing_certificate,
        ) {
            (Some(certificate_id), None, None, Some(binding)) => {
                certificate_id == binding.certificate_id.as_str()
                    && existing_certificate_matches(signer, binding)
            }
            (None, Some(ca_id), Some(common_name), None) => {
                internal_certificate_matches(signer, ca_id, common_name)
            }
            _ => false,
        }
        && signer.certificate_id.is_some()
}

fn existing_certificate_matches(
    signer: &CodeSigner,
    binding: &ExistingSignerCertificateBinding,
) -> bool {
    signer.certificate_id.as_deref() == Some(binding.certificate_id.as_str())
        && signer.certificate_status.as_deref() == Some("active")
        && signer.key_algorithm == binding.key_algorithm
        && signer.certificate_key_algorithm == Some(binding.key_algorithm)
}

fn internal_certificate_matches(
    signer: &CodeSigner,
    expected_ca_id: &str,
    expected_common_name: &str,
) -> bool {
    signer.certificate_status.as_deref() == Some("active")
        && signer.certificate_key_algorithm == Some(signer.key_algorithm)
        && signer.certificate_ca_id.as_deref() == Some(expected_ca_id)
        && signer.certificate_common_name.as_deref() == Some(expected_common_name)
}

fn updated_signer_matches(
    signer: &CodeSigner,
    before: &CodeSigner,
    request: &UpdateSignerRequest,
) -> bool {
    request
        .name
        .as_ref()
        .map_or_else(|| signer.name == before.name, |name| &signer.name == name)
        && request.description.as_ref().map_or_else(
            || signer.description == before.description,
            |description| match description {
                NullableString::Value(value) => signer.description.as_ref() == Some(value),
                NullableString::Null => signer.description.is_none(),
            },
        )
        && request.certificate_renew_before_days.as_ref().map_or_else(
            || signer.certificate_renew_before_days == before.certificate_renew_before_days,
            |renew| match renew {
                NullableU8::Value(value) => signer.certificate_renew_before_days == Some(*value),
                NullableU8::Null => signer.certificate_renew_before_days.is_none(),
            },
        )
        && signer.status == before.status
        && signer.certificate_id == before.certificate_id
        && signer.ca_id == before.ca_id
        && signer.key_algorithm == before.key_algorithm
}

fn renew_before_fits(renew_before_days: Option<u8>, certificate_ttl_days: Option<u16>) -> bool {
    match (renew_before_days, certificate_ttl_days) {
        (Some(renew), Some(ttl)) => u16::from(renew) < ttl,
        _ => true,
    }
}

fn status_transition_is_allowed(before: &CodeSigner, desired: CodeSignerDesiredStatus) -> bool {
    let expected = match desired {
        CodeSignerDesiredStatus::Active => CodeSignerStatus::Active,
        CodeSignerDesiredStatus::Disabled => CodeSignerStatus::Disabled,
    };
    before.status != expected
        && (desired != CodeSignerDesiredStatus::Active
            || (before.status == CodeSignerStatus::Disabled && before.certificate_id.is_some()))
}

fn status_updated_signer_matches(
    signer: &CodeSigner,
    before: &CodeSigner,
    expected: CodeSignerStatus,
) -> bool {
    signer.status == expected
        && signer.certificate_id == before.certificate_id
        && signer.ca_id == before.ca_id
        && signer.key_algorithm == before.key_algorithm
}

fn reissued_signer_matches(
    signer: &CodeSigner,
    before: &CodeSigner,
    request: &ReissueSignerCertificateRequest,
    expected_common_name: Option<&str>,
    expected_ttl: u16,
) -> bool {
    signer.status == CodeSignerStatus::Active
        && signer.ca_id.as_deref() == Some(request.ca_id.as_str())
        && expected_common_name.is_some_and(|common_name| {
            internal_certificate_matches(signer, &request.ca_id, common_name)
        })
        && signer.common_name.as_deref() == expected_common_name
        && signer.certificate_ttl_days == Some(expected_ttl)
        && signer.certificate_id.is_some()
        && signer.certificate_id != before.certificate_id
        && signer.key_algorithm == before.key_algorithm
}

fn reissue_changes_are_allowed(
    status: CodeSignerStatus,
    changes_common_name: bool,
    changes_ttl: bool,
) -> bool {
    matches!(status, CodeSignerStatus::Pending | CodeSignerStatus::Failed)
        || (!changes_common_name && !changes_ttl)
}

fn reissue_expectations(
    before: &CodeSigner,
    reissue: &CodeSignerCertificateReissue,
) -> Result<(String, u16), ResourceError> {
    if !reissue_changes_are_allowed(
        before.status,
        reissue.common_name.is_some(),
        reissue.certificate_ttl_days.is_some(),
    ) {
        return Err(ResourceError::InvalidCodeSignerCertificateState);
    }
    let common_name = reissue
        .common_name
        .as_ref()
        .or(before.common_name.as_ref())
        .cloned()
        .ok_or(ResourceError::InvalidCodeSignerCertificateState)?;
    let certificate_ttl_days = reissue
        .certificate_ttl_days
        .or(before.certificate_ttl_days)
        .unwrap_or(365);
    if !renew_before_fits(
        before.certificate_renew_before_days,
        Some(certificate_ttl_days),
    ) {
        return Err(ResourceError::InvalidCodeSignerCertificateState);
    }
    Ok((common_name, certificate_ttl_days))
}

fn validate_reissued_signer(
    signer: &CodeSigner,
    before: &CodeSigner,
    request: &ReissueSignerCertificateRequest,
    expected_common_name: &str,
    expected_ttl: u16,
) -> Result<(), ResourceError> {
    reissued_signer_matches(
        signer,
        before,
        request,
        Some(expected_common_name),
        expected_ttl,
    )
    .then_some(())
    .ok_or(ResourceError::InvalidCodeSignerResponse)
}

fn exported_certificate_metadata_matches(
    is_ca: bool,
    serial_number: &str,
    signer_name: &str,
    expected_signer_name: &str,
) -> bool {
    !is_ca && valid_serial(serial_number) && signer_name == expected_signer_name
}

fn exported_certificate_matches_signer(
    certificate: &X509Certificate<'_>,
    response: &ExportCertificateWire,
    signer: &CodeSigner,
) -> bool {
    exported_certificate_metadata_matches(
        certificate.is_ca(),
        &response.serial_number,
        &response.signer_name,
        &signer.name,
    ) && certificate_serial_matches(certificate, &response.serial_number)
        && signer
            .certificate_serial_number
            .as_deref()
            .is_some_and(|serial| certificate_serial_matches(certificate, serial))
}

fn validated_exported_certificate(
    response: &ExportCertificateWire,
    signer: &CodeSigner,
) -> Result<(String, Vec<u8>), ResourceError> {
    let normalized = normalize_pem(&response.certificate_pem)
        .filter(|pem| pem.len() <= MAX_CERTIFICATE_PEM_BYTES)
        .ok_or(ResourceError::InvalidCodeSignerResponse)?;
    let certificates = certificate_bundle_der(&normalized)
        .filter(|certificates| certificates.len() == 1)
        .ok_or(ResourceError::InvalidCodeSignerResponse)?;
    let (remainder, certificate) = X509Certificate::from_der(&certificates[0])
        .map_err(|_| ResourceError::InvalidCodeSignerResponse)?;
    if !remainder.is_empty() || !exported_certificate_matches_signer(&certificate, response, signer)
    {
        return Err(ResourceError::InvalidCodeSignerResponse);
    }
    Ok((normalized, certificate.public_key().raw.to_vec()))
}

fn public_key_family_matches(
    key_algorithm: CertificateKeyAlgorithm,
    public_key_algorithm: CodeSignerPublicKeyFamily,
) -> bool {
    match key_algorithm {
        CertificateKeyAlgorithm::Rsa2048
        | CertificateKeyAlgorithm::Rsa3072
        | CertificateKeyAlgorithm::Rsa4096 => {
            public_key_algorithm == CodeSignerPublicKeyFamily::Rsa
        }
        CertificateKeyAlgorithm::EcPrime256v1 => {
            public_key_algorithm == CodeSignerPublicKeyFamily::EccNistP256
        }
        CertificateKeyAlgorithm::EcSecp384r1 => {
            public_key_algorithm == CodeSignerPublicKeyFamily::EccNistP384
        }
        CertificateKeyAlgorithm::EcSecp521r1 => {
            public_key_algorithm == CodeSignerPublicKeyFamily::EccNistP521
        }
        _ => false,
    }
}

fn valid_public_key_spki(der: &[u8], key_algorithm: CertificateKeyAlgorithm) -> bool {
    let Ok((remainder, spki)) = SubjectPublicKeyInfo::from_der(der) else {
        return false;
    };
    if !remainder.is_empty() {
        return false;
    }
    match (key_algorithm, spki.parsed()) {
        (algorithm, Ok(PublicKey::RSA(key))) => {
            let Some(expected_key_size) = valid_public_key_spki_rsa_size(algorithm) else {
                return false;
            };
            valid_public_key_spki_rsa_parameters(
                key.key_size(),
                expected_key_size,
                key.try_exponent().ok(),
            )
        }
        (algorithm, Ok(PublicKey::EC(point))) => {
            let Some(expected) = valid_public_key_spki_ec_parameters(algorithm) else {
                return false;
            };
            let curve_oid = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.as_oid().ok())
                .map(|oid| oid.to_id_string());
            curve_oid.as_deref() == Some(expected.0)
                && point.data().len() == expected.1
                && point.data().first() == Some(&4)
        }
        _ => false,
    }
}

const fn valid_public_key_spki_rsa_size(algorithm: CertificateKeyAlgorithm) -> Option<usize> {
    match algorithm {
        CertificateKeyAlgorithm::Rsa2048 => Some(2_048),
        CertificateKeyAlgorithm::Rsa3072 => Some(3_072),
        CertificateKeyAlgorithm::Rsa4096 => Some(4_096),
        _ => None,
    }
}

const fn valid_public_key_spki_ec_parameters(
    algorithm: CertificateKeyAlgorithm,
) -> Option<(&'static str, usize)> {
    match algorithm {
        CertificateKeyAlgorithm::EcPrime256v1 => Some(("1.2.840.10045.3.1.7", 65)),
        CertificateKeyAlgorithm::EcSecp384r1 => Some(("1.3.132.0.34", 97)),
        CertificateKeyAlgorithm::EcSecp521r1 => Some(("1.3.132.0.35", 133)),
        _ => None,
    }
}

fn valid_public_key_spki_rsa_parameters(
    key_size: usize,
    expected_key_size: usize,
    exponent: Option<u64>,
) -> bool {
    key_size == expected_key_size
        && exponent.is_some_and(|exponent| exponent >= 3 && exponent % 2 == 1)
}

fn validate_public_key_response(
    signer: &CodeSigner,
    response: &PublicKeyWire,
    public_key: &[u8],
) -> Result<(), ResourceError> {
    if !public_key_family_matches(signer.key_algorithm, response.algorithm)
        || !valid_public_key_spki(public_key, signer.key_algorithm)
    {
        return Err(ResourceError::InvalidCodeSignerResponse);
    }
    Ok(())
}

fn signer_can_sign(
    signer: &CodeSigner,
    signing_algorithm: CodeSigningAlgorithm,
    now: Option<i64>,
) -> bool {
    let Some(not_before) = signer
        .certificate_not_before
        .as_deref()
        .and_then(utc_timestamp_millis)
    else {
        return false;
    };
    let Some(not_after) = signer
        .certificate_not_after
        .as_deref()
        .and_then(utc_timestamp_millis)
    else {
        return false;
    };
    let Some(now) = now else {
        return false;
    };
    signer.status == CodeSignerStatus::Active
        && signer.certificate_id.is_some()
        && signer.certificate_status.as_deref() == Some("active")
        && not_before <= now
        && not_after > now
        && signer.certificate_key_algorithm == Some(signer.key_algorithm)
        && signing_algorithm.supports_key(signer.key_algorithm)
}

fn signing_input_is_valid(
    decoded_data_bytes: usize,
    signing_algorithm: CodeSigningAlgorithm,
    is_digest: bool,
) -> bool {
    !is_digest || signing_algorithm.digest_bytes() == Some(decoded_data_bytes)
}

fn signature_matches(
    response: &SignatureWire,
    signer_id: &CodeSignerId,
    signing_algorithm: CodeSigningAlgorithm,
) -> bool {
    response.signer_id == signer_id.as_str()
        && response.signing_algorithm == signing_algorithm
        && decode_canonical_base64(&response.signature, MAX_SIGNATURE_BYTES, false).is_ok()
}

impl InfisicalClient {
    async fn preflight_existing_signer_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        certificate_id: &CodeSignerCertificateId,
    ) -> Result<ExistingSignerCertificateBinding, ResourceError> {
        let inventory_id = CertificateId::new(certificate_id.as_str().to_owned())
            .map_err(|_| ResourceError::InvalidCodeSignerCertificateState)?;
        let certificate = self.get_certificate(project_id, &inventory_id).await?;
        if !certificate.has_private_key {
            return Err(ResourceError::MissingCodeSignerCertificatePrivateKey);
        }
        if !existing_signer_certificate_is_usable(
            &certificate,
            project_id,
            certificate_id,
            current_timestamp_millis(),
        ) {
            return Err(ResourceError::InvalidCodeSignerCertificateState);
        }
        let key_algorithm = certificate
            .key_algorithm
            .ok_or(ResourceError::InvalidCodeSignerCertificateState)?;
        Ok(ExistingSignerCertificateBinding {
            certificate_id: certificate_id.clone(),
            key_algorithm,
        })
    }

    async fn preflight_internal_signer_ca(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
    ) -> Result<(), ResourceError> {
        let ca = self
            .get_internal_certificate_authority(project_id, ca_id)
            .await?;
        if !internal_signer_ca_is_usable(ca.status) {
            return Err(ResourceError::InvalidCodeSignerCertificateState);
        }
        Ok(())
    }

    /// List one bounded page of code signers in a Certificate Manager project.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, response-contract, or pagination error.
    pub async fn list_code_signers(
        &self,
        request: CodeSignerListRequest,
    ) -> Result<Page<CodeSigner>, ResourceError> {
        let response = self
            .execute_observable_read::<ListSigners>(&ListSignersQuery {
                project_id: request.project_id.as_str().to_owned(),
                offset: request.page.offset(),
                limit: request.page.limit(),
                search: request.search.clone(),
            })
            .await?;
        signer_page_from_wire(response, &request)
    }

    /// Get one exact code signer after proving project ownership.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or response-contract error.
    pub async fn get_code_signer(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
    ) -> Result<CodeSigner, ResourceError> {
        let response = self
            .execute_observable_read::<GetSigner>(&SignerIdQuery {
                signer_id: signer_id.clone(),
            })
            .await?;
        signer_from_wire(response, project_id, Some(signer_id))
    }

    /// Create one code signer from an existing certificate or enabled internal CA.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, state, typed client, or response-contract error.
    pub async fn create_code_signer(
        &self,
        project_id: &CertificateAuthorityProjectId,
        creation: CodeSignerCreation,
        confirm: bool,
    ) -> Result<CodeSigner, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSignerCreateNotConfirmed);
        }
        self.ensure_certificate_manager_project(project_id).await?;
        let expected_name = creation.name.as_str().to_owned();
        let expected_description = creation.description.clone();
        let (request, existing_certificate) = match creation.source {
            CodeSignerCertificateSource::Existing { certificate_id } => {
                let binding = self
                    .preflight_existing_signer_certificate(project_id, &certificate_id)
                    .await?;
                (
                    CreateSignerRequest {
                        project_id: project_id.as_str().to_owned(),
                        name: creation.name.as_str().to_owned(),
                        description: creation.description,
                        ca_id: None,
                        common_name: None,
                        certificate_ttl_days: None,
                        certificate_renew_before_days: None,
                        key_algorithm: None,
                        certificate_id: Some(certificate_id.as_str().to_owned()),
                    },
                    Some(binding),
                )
            }
            CodeSignerCertificateSource::InternalCertificateAuthority {
                ca_id,
                common_name,
                certificate_ttl_days,
                certificate_renew_before_days,
                key_algorithm,
            } => {
                self.preflight_internal_signer_ca(project_id, &ca_id)
                    .await?;
                (
                    CreateSignerRequest {
                        project_id: project_id.as_str().to_owned(),
                        name: creation.name.as_str().to_owned(),
                        description: creation.description,
                        ca_id: Some(ca_id.as_str().to_owned()),
                        common_name: Some(common_name),
                        certificate_ttl_days: Some(certificate_ttl_days),
                        certificate_renew_before_days,
                        key_algorithm: Some(key_algorithm),
                        certificate_id: None,
                    },
                    None,
                )
            }
        };
        let response = self.execute_mutation::<CreateSigner>(&request).await?;
        let signer = signer_from_wire(response, project_id, None)?;
        if !created_signer_matches(
            &signer,
            &request,
            existing_certificate.as_ref(),
            &expected_name,
            expected_description.as_deref(),
        ) {
            return Err(ResourceError::InvalidCodeSignerResponse);
        }
        Ok(signer)
    }

    /// Apply one non-empty metadata or renewal-window change.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, state, typed client, or response-contract error.
    pub async fn update_code_signer(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        change: CodeSignerChange,
        confirm: bool,
    ) -> Result<CodeSigner, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSignerUpdateNotConfirmed);
        }
        let before = self.get_code_signer(project_id, signer_id).await?;
        let requested_renew = match change.certificate_renew_before_days {
            Some(CodeSignerRenewBeforeChange::Set(value)) => Some(value),
            Some(CodeSignerRenewBeforeChange::Clear) | None => None,
        };
        if !renew_before_fits(requested_renew, before.certificate_ttl_days) {
            return Err(ResourceError::InvalidCodeSignerCertificateState);
        }
        let request = UpdateSignerRequest {
            signer_id: signer_id.clone(),
            name: change.name.map(|name| name.as_str().to_owned()),
            description: change.description.map(|description| match description {
                CodeSignerDescriptionChange::Set(value) => NullableString::Value(value),
                CodeSignerDescriptionChange::Clear => NullableString::Null,
            }),
            certificate_renew_before_days: change.certificate_renew_before_days.map(|value| {
                match value {
                    CodeSignerRenewBeforeChange::Set(value) => NullableU8::Value(value),
                    CodeSignerRenewBeforeChange::Clear => NullableU8::Null,
                }
            }),
        };
        let response = self.execute_mutation::<UpdateSigner>(&request).await?;
        let signer = signer_from_wire(response, project_id, Some(signer_id))?;
        if !updated_signer_matches(&signer, &before, &request) {
            return Err(ResourceError::InvalidCodeSignerResponse);
        }
        Ok(signer)
    }

    /// Permanently delete one exact signer after confirmation and ownership preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    pub async fn delete_code_signer(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        confirm: bool,
    ) -> Result<CodeSigner, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSignerDeleteNotConfirmed);
        }
        self.get_code_signer(project_id, signer_id).await?;
        let response = self
            .execute_mutation::<DeleteSigner>(&DeleteSignerRequest {
                signer_id: signer_id.clone(),
            })
            .await?;
        signer_from_wire(response, project_id, Some(signer_id))
    }

    /// Enable or disable one signer after confirmation and ownership preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, state, typed client, or response-contract error.
    pub async fn update_code_signer_status(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        status: CodeSignerDesiredStatus,
        confirm: bool,
    ) -> Result<CodeSigner, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSignerStatusUpdateNotConfirmed);
        }
        let before = self.get_code_signer(project_id, signer_id).await?;
        let expected = match status {
            CodeSignerDesiredStatus::Active => CodeSignerStatus::Active,
            CodeSignerDesiredStatus::Disabled => CodeSignerStatus::Disabled,
        };
        if !status_transition_is_allowed(&before, status) {
            return Err(ResourceError::InvalidCodeSignerState);
        }
        let response = self
            .execute_mutation::<UpdateSignerStatus>(&UpdateSignerStatusRequest {
                signer_id: signer_id.clone(),
                status,
            })
            .await?;
        let signer = signer_from_wire(response, project_id, Some(signer_id))?;
        if !status_updated_signer_matches(&signer, &before, expected) {
            return Err(ResourceError::InvalidCodeSignerResponse);
        }
        Ok(signer)
    }

    /// Reissue one signer certificate from an enabled internal CA.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, state, typed client, or response-contract error.
    pub async fn reissue_code_signer_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        reissue: CodeSignerCertificateReissue,
        confirm: bool,
    ) -> Result<CodeSigner, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSignerCertificateMutationNotConfirmed);
        }
        let before = self.get_code_signer(project_id, signer_id).await?;
        self.preflight_internal_signer_ca(project_id, &reissue.ca_id)
            .await?;
        let (expected_common_name, expected_ttl) = reissue_expectations(&before, &reissue)?;
        let request = ReissueSignerCertificateRequest {
            signer_id: signer_id.clone(),
            ca_id: reissue.ca_id.as_str().to_owned(),
            common_name: reissue.common_name,
            certificate_ttl_days: reissue.certificate_ttl_days,
        };
        let response = self
            .execute_mutation::<ReissueSignerCertificate>(&request)
            .await?;
        let signer = signer_from_wire(response, project_id, Some(signer_id))?;
        validate_reissued_signer(
            &signer,
            &before,
            &request,
            &expected_common_name,
            expected_ttl,
        )?;
        Ok(signer)
    }

    /// Export the public leaf certificate for one exact signer.
    ///
    /// # Errors
    ///
    /// Returns a scope, state, typed client, or certificate-contract error.
    pub async fn export_code_signer_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
    ) -> Result<CodeSignerCertificate, ResourceError> {
        let signer = self.get_code_signer(project_id, signer_id).await?;
        if signer.certificate_id.is_none() {
            return Err(ResourceError::InvalidCodeSignerCertificateState);
        }
        let response = self
            .execute_observable_read::<ExportSignerCertificate>(&SignerIdQuery {
                signer_id: signer_id.clone(),
            })
            .await?;
        let (normalized, _) = validated_exported_certificate(&response, &signer)?;
        Ok(CodeSignerCertificate {
            signer_id: signer.id,
            signer_name: response.signer_name,
            serial_number: response.serial_number,
            certificate_pem: normalized,
        })
    }

    /// Get one signer's base64 DER `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    ///
    /// Returns a scope, state, typed client, or bounded-response error.
    pub async fn get_code_signer_public_key(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
    ) -> Result<CodeSignerPublicKey, ResourceError> {
        let signer = self.get_code_signer(project_id, signer_id).await?;
        if signer.certificate_id.is_none() {
            return Err(ResourceError::InvalidCodeSignerCertificateState);
        }
        let response = self
            .execute_observable_read::<GetSignerPublicKey>(&SignerIdQuery {
                signer_id: signer_id.clone(),
            })
            .await?;
        let public_key = decode_canonical_base64(&response.public_key, MAX_PUBLIC_KEY_BYTES, false)
            .map_err(|()| ResourceError::InvalidCodeSignerResponse)?;
        validate_public_key_response(&signer, &response, &public_key)?;
        let certificate_response = self
            .execute_observable_read::<ExportSignerCertificate>(&SignerIdQuery {
                signer_id: signer_id.clone(),
            })
            .await?;
        let (_, certificate_public_key) =
            validated_exported_certificate(&certificate_response, &signer)?;
        if public_key != certificate_public_key {
            return Err(ResourceError::InvalidCodeSignerResponse);
        }
        Ok(CodeSignerPublicKey {
            signer_id: signer.id,
            signer_name: signer.name,
            algorithm: signer.key_algorithm,
            public_key: response.public_key,
        })
    }

    /// Sign bounded base64 data with one exact active signer.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, state, typed client, or reflected-response error.
    #[allow(clippy::too_many_arguments)]
    pub async fn code_signer_sign(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        data: CodeSigningData,
        signing_algorithm: CodeSigningAlgorithm,
        is_digest: bool,
        client_metadata: Option<CodeSigningClientMetadata>,
        confirm: bool,
    ) -> Result<CodeSignerSignature, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSigningNotConfirmed);
        }
        if !signing_input_is_valid(data.1, signing_algorithm, is_digest) {
            return Err(ResourceError::InvalidCodeSigningInput);
        }
        let signer = self.get_code_signer(project_id, signer_id).await?;
        if !signer_can_sign(&signer, signing_algorithm, current_timestamp_millis()) {
            return Err(ResourceError::InvalidCodeSignerState);
        }
        let response = self
            .execute_mutation::<SignData>(&SignRequest {
                signer_id: signer_id.clone(),
                data: data.0,
                signing_algorithm,
                is_digest,
                client_metadata,
            })
            .await?;
        if !signature_matches(&response, signer_id, signing_algorithm) {
            return Err(ResourceError::InvalidCodeSignerResponse);
        }
        Ok(CodeSignerSignature {
            signer_id: response.signer_id,
            signing_algorithm: response.signing_algorithm,
            signature: response.signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path, query_param},
    };
    use x509_parser::{
        prelude::{FromDer, X509Certificate, X509CertificationRequest},
        x509::SubjectPublicKeyInfo,
    };

    use super::{
        CodeSigner, CodeSignerCertificateId, CodeSignerCertificateReissue,
        CodeSignerCertificateSource, CodeSignerChange, CodeSignerCreation,
        CodeSignerDescriptionChange, CodeSignerDesiredStatus, CodeSignerId, CodeSignerListRequest,
        CodeSignerName, CodeSignerPublicKeyFamily, CodeSignerRenewBeforeChange, CodeSignerStatus,
        CodeSignerWire, CodeSigningAlgorithm, CodeSigningData, CreateSignerRequest,
        ExistingSignerCertificateBinding, ExportCertificateWire, ListSignersResponse,
        NullableString, NullableU8, PublicKeyWire, ReissueSignerCertificateRequest, SignatureWire,
        UpdateSignerRequest, created_signer_matches, current_timestamp_millis,
        decode_canonical_base64, decode_canonical_secret_base64,
        existing_signer_certificate_is_usable, exported_certificate_matches_signer,
        exported_certificate_metadata_matches, internal_signer_ca_is_usable,
        public_key_family_matches, reissue_changes_are_allowed, reissue_expectations,
        reissued_signer_matches, renew_before_fits, signature_matches, signer_can_sign,
        signer_from_wire, signer_page_from_wire, signing_input_is_valid,
        status_transition_is_allowed, status_updated_signer_matches,
        supported_code_signer_key_algorithm, updated_signer_matches, valid_optional_uuid,
        valid_public_key_spki, valid_public_key_spki_ec_parameters,
        valid_public_key_spki_rsa_parameters, valid_public_key_spki_rsa_size, valid_serial,
        valid_timestamp, validate_certificate_settings, validate_description,
        validate_public_key_response, validate_reissued_signer, validate_text,
        validated_exported_certificate,
    };
    use crate::{
        Certificate, CertificateAuthorityId, CertificateAuthorityProjectId,
        CertificateAuthorityStatus, CertificateKeyAlgorithm, CertificateStatus, InfisicalClient,
        PageRequest, ResourceError, SecretValue,
        certificate::certificate_bundle_der,
        resources::utc_timestamp_millis,
        test_support::{mount_login, settings},
    };

    const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const SIGNER_ID: &str = "22222222-2222-4222-8222-222222222222";
    const CERTIFICATE_ID: &str = "33333333-3333-4333-8333-333333333333";
    const POLICY_ID: &str = "44444444-4444-4444-8444-444444444444";
    const CA_ID: &str = "55555555-5555-4555-8555-555555555555";
    const CREATED_AT: &str = "2026-07-20T12:00:00.000Z";
    const NOT_AFTER: &str = "2036-07-20T12:00:00.000Z";
    const LEAF_SERIAL: &str = "53D112612118759DA8F4154E67C467098521A0C5";
    const LEAF_CERTIFICATE: &str = include_str!("../test-fixtures/end-entity-cert.txt");
    const CA_CERTIFICATE: &str = include_str!("../test-fixtures/ca-cert.txt");
    const RSA_PUBLIC_KEY: &str = include_str!("../test-fixtures/rsa-2048-public-key-spki.base64");
    const RSA_1024_PUBLIC_KEY: &str =
        include_str!("../test-fixtures/rsa-1024-public-key-spki.base64");
    const P521_CSR: &str = include_str!("../test-fixtures/p521-csr.txt");

    fn project_id() -> CertificateAuthorityProjectId {
        CertificateAuthorityProjectId::new(PROJECT_ID).unwrap()
    }

    fn signer_id() -> CodeSignerId {
        CodeSignerId::new(SIGNER_ID).unwrap()
    }

    fn signer_value(description: Option<&str>, status: &str) -> serde_json::Value {
        json!({
            "id": SIGNER_ID,
            "projectId": PROJECT_ID,
            "name": "release-signer",
            "description": description,
            "status": status,
            "certificateId": CERTIFICATE_ID,
            "approvalPolicyId": POLICY_ID,
            "lastSignedAt": null,
            "createdAt": CREATED_AT,
            "updatedAt": CREATED_AT,
            "caId": null,
            "commonName": null,
            "certificateTtlDays": null,
            "certificateRenewBeforeDays": null,
            "certificateFailureReason": null,
            "keyAlgorithm": "RSA_2048",
            "certificateCommonName": "release.example.test",
            "certificateSerialNumber": LEAF_SERIAL,
            "certificateNotBefore": CREATED_AT,
            "certificateNotAfter": NOT_AFTER,
            "certificateKeyAlgorithm": "RSA_2048",
            "certificateStatus": "active",
            "certificateCaId": null,
            "approvalPolicyName": "signer:22222222-2222-4222-8222-222222222222"
        })
    }

    fn signer_wire(value: Value) -> CodeSignerWire {
        serde_json::from_value(value).unwrap()
    }

    fn valid_signer() -> CodeSigner {
        signer_from_wire(
            signer_wire(signer_value(None, "active")),
            &project_id(),
            None,
        )
        .unwrap()
    }

    fn existing_certificate() -> Certificate {
        Certificate {
            id: CERTIFICATE_ID.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            friendly_name: "release.example.test".to_owned(),
            common_name: "release.example.test".to_owned(),
            status: CertificateStatus::Active,
            serial_number: LEAF_SERIAL.to_owned(),
            not_before: CREATED_AT.to_owned(),
            not_after: NOT_AFTER.to_owned(),
            revoked_at: None,
            revocation_reason: None,
            alternative_names: None,
            key_usages: Some(vec!["digitalSignature".to_owned()]),
            key_algorithm: Some(CertificateKeyAlgorithm::Rsa2048),
            extended_key_usages: Some(vec!["codeSigning".to_owned()]),
            signature_algorithm: None,
            is_ca: Some(false),
            ca_id: None,
            profile_id: None,
            application_id: None,
            ca_name: None,
            profile_name: None,
            enrollment_type: None,
            application_name: None,
            has_private_key: true,
            created_at: CREATED_AT.to_owned(),
            updated_at: CREATED_AT.to_owned(),
        }
    }

    fn existing_certificate_inventory_value(key_algorithm: &str, has_private_key: bool) -> Value {
        json!({
            "id": CERTIFICATE_ID,
            "projectId": PROJECT_ID,
            "friendlyName": "release.example.test",
            "commonName": "release.example.test",
            "status": "active",
            "serialNumber": LEAF_SERIAL,
            "notBefore": CREATED_AT,
            "notAfter": NOT_AFTER,
            "keyAlgorithm": key_algorithm,
            "extendedKeyUsages": ["codeSigning"],
            "isCA": false,
            "hasPrivateKey": has_private_key,
            "createdAt": CREATED_AT,
            "updatedAt": CREATED_AT
        })
    }

    fn existing_signer_request() -> CreateSignerRequest {
        CreateSignerRequest {
            project_id: PROJECT_ID.to_owned(),
            name: "release-signer".to_owned(),
            description: None,
            ca_id: None,
            common_name: None,
            certificate_ttl_days: None,
            certificate_renew_before_days: None,
            key_algorithm: None,
            certificate_id: Some(CERTIFICATE_ID.to_owned()),
        }
    }

    fn existing_certificate_binding() -> ExistingSignerCertificateBinding {
        ExistingSignerCertificateBinding {
            certificate_id: CodeSignerCertificateId::new(CERTIFICATE_ID).unwrap(),
            key_algorithm: CertificateKeyAlgorithm::Rsa2048,
        }
    }

    fn internal_certificate_binding_mutations() -> [fn(&mut CodeSigner); 8] {
        [
            |value| value.certificate_status = None,
            |value| value.certificate_status = Some("revoked".to_owned()),
            |value| value.certificate_key_algorithm = None,
            |value| {
                value.certificate_key_algorithm = Some(CertificateKeyAlgorithm::Rsa3072);
            },
            |value| value.certificate_ca_id = None,
            |value| {
                value.certificate_ca_id = Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned());
            },
            |value| value.certificate_common_name = None,
            |value| value.certificate_common_name = Some("other.example.test".to_owned()),
        ]
    }

    fn signature_wire() -> SignatureWire {
        SignatureWire {
            signature: "AQID".to_owned(),
            signing_algorithm: CodeSigningAlgorithm::RsaPkcs1V15Sha256,
            signer_id: SIGNER_ID.to_owned(),
        }
    }

    fn internal_ca_value(status: &str) -> Value {
        json!({
            "id": CA_ID,
            "projectId": PROJECT_ID,
            "name": "signing-ca",
            "type": "internal",
            "status": status,
            "enableDirectIssuance": false,
            "configuration": {
                "type": "root",
                "commonName": "Signing CA",
                "organization": "Example",
                "ou": "Security",
                "country": "US",
                "province": "TX",
                "locality": "Austin",
                "dn": "C=US,O=Example,OU=Security,ST=TX,CN=Signing CA,L=Austin",
                "notBefore": CREATED_AT,
                "notAfter": NOT_AFTER,
                "maxPathLength": 2,
                "keyAlgorithm": "RSA_2048",
                "serialNumber": "01ab",
                "activeCaCertId": CERTIFICATE_ID,
                "crlDistributionPointUrls": [],
                "disableManagedCrlDistributionPointUrl": false
            }
        })
    }

    async fn mount_project(server: &MockServer) {
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
            .mount(server)
            .await;
    }

    #[test]
    fn signer_inputs_are_closed_bounded_and_redacted() {
        assert!(CodeSignerName::new("release-signer").is_ok());
        assert!(CodeSignerName::new("Release Signer").is_err());
        assert!(CodeSignerName::new("release--signer").is_err());
        assert!(CodeSigningData::new(SecretValue::new("AQID")).is_ok());
        assert!(CodeSigningData::new(SecretValue::new("AQID\n")).is_err());
        let data = CodeSigningData::new(SecretValue::new("AQID")).unwrap();
        assert!(!format!("{data:?}").contains("AQID"));
        assert!(
            CodeSignerChange::new(None, None, Some(CodeSignerRenewBeforeChange::Set(31))).is_err()
        );
        assert!(CodeSignerChange::new(None, None, None).is_err());
        assert!(
            CodeSignerCertificateSource::internal_ca(
                crate::CertificateAuthorityId::new("55555555-5555-4555-8555-555555555555").unwrap(),
                "release.example.test",
                30,
                Some(30),
                CertificateKeyAlgorithm::Rsa2048,
            )
            .is_err()
        );
    }

    #[test]
    fn signing_algorithms_bind_exact_key_families_and_digest_lengths() {
        let rsa_algorithms = [
            CodeSigningAlgorithm::RsaPssSha512,
            CodeSigningAlgorithm::RsaPssSha384,
            CodeSigningAlgorithm::RsaPssSha256,
            CodeSigningAlgorithm::RsaPkcs1V15Sha512,
            CodeSigningAlgorithm::RsaPkcs1V15Sha384,
            CodeSigningAlgorithm::RsaPkcs1V15Sha256,
        ];
        let ecdsa_algorithms = [
            CodeSigningAlgorithm::EcdsaSha512,
            CodeSigningAlgorithm::EcdsaSha384,
            CodeSigningAlgorithm::EcdsaSha256,
        ];
        for algorithm in rsa_algorithms {
            assert!(algorithm.supports_key(CertificateKeyAlgorithm::Rsa2048));
            assert!(!algorithm.supports_key(CertificateKeyAlgorithm::EcPrime256v1));
            assert!(!algorithm.supports_key(CertificateKeyAlgorithm::MlDsa44));
        }
        for algorithm in ecdsa_algorithms {
            assert!(algorithm.supports_key(CertificateKeyAlgorithm::EcPrime256v1));
            assert!(!algorithm.supports_key(CertificateKeyAlgorithm::Rsa2048));
            assert!(!algorithm.supports_key(CertificateKeyAlgorithm::MlDsa44));
        }
        for (algorithm, expected) in [
            (CodeSigningAlgorithm::RsaPkcs1V15Sha512, Some(64)),
            (CodeSigningAlgorithm::EcdsaSha512, Some(64)),
            (CodeSigningAlgorithm::RsaPkcs1V15Sha384, Some(48)),
            (CodeSigningAlgorithm::EcdsaSha384, Some(48)),
            (CodeSigningAlgorithm::RsaPkcs1V15Sha256, Some(32)),
            (CodeSigningAlgorithm::EcdsaSha256, Some(32)),
            (CodeSigningAlgorithm::RsaPssSha512, None),
            (CodeSigningAlgorithm::RsaPssSha384, None),
            (CodeSigningAlgorithm::RsaPssSha256, None),
        ] {
            assert_eq!(algorithm.digest_bytes(), expected, "{algorithm:?}");
        }
    }

    #[test]
    fn signer_scalar_validators_enforce_every_independent_boundary() {
        assert!(validate_description(None).is_ok());
        assert!(validate_description(Some("")).is_ok());
        assert!(validate_description(Some(&"d".repeat(256))).is_ok());
        for invalid in [
            " leading".to_owned(),
            "trailing ".to_owned(),
            "d".repeat(257),
            "line\nbreak".to_owned(),
        ] {
            assert!(validate_description(Some(&invalid)).is_err(), "{invalid:?}");
        }

        assert!(validate_text("x").is_ok());
        assert!(validate_text(&"x".repeat(256)).is_ok());
        for invalid in [
            String::new(),
            " leading".to_owned(),
            "x".repeat(257),
            "line\nbreak".to_owned(),
        ] {
            assert!(validate_text(&invalid).is_err(), "{invalid:?}");
        }

        for supported in [
            CertificateKeyAlgorithm::Rsa2048,
            CertificateKeyAlgorithm::Rsa3072,
            CertificateKeyAlgorithm::Rsa4096,
            CertificateKeyAlgorithm::EcPrime256v1,
            CertificateKeyAlgorithm::EcSecp384r1,
            CertificateKeyAlgorithm::EcSecp521r1,
        ] {
            assert!(supported_code_signer_key_algorithm(supported));
            assert!(validate_certificate_settings(365, Some(30), supported).is_ok());
        }
        assert!(!supported_code_signer_key_algorithm(
            CertificateKeyAlgorithm::MlDsa44
        ));
        for (ttl, renew, key) in [
            (0, None, CertificateKeyAlgorithm::Rsa2048),
            (3_651, None, CertificateKeyAlgorithm::Rsa2048),
            (365, Some(0), CertificateKeyAlgorithm::Rsa2048),
            (365, Some(31), CertificateKeyAlgorithm::Rsa2048),
            (30, Some(30), CertificateKeyAlgorithm::Rsa2048),
            (365, None, CertificateKeyAlgorithm::MlDsa44),
        ] {
            assert!(validate_certificate_settings(ttl, renew, key).is_err());
        }

        assert_eq!(decode_canonical_base64("", 1, true), Ok(Vec::new()));
        assert_eq!(decode_canonical_base64("AQ==", 1, false), Ok(vec![1]));
        assert!(decode_canonical_base64("", 1, false).is_err());
        assert!(decode_canonical_base64("AQ==", 0, false).is_err());
        assert!(decode_canonical_base64("not-base64", 128, false).is_err());
        assert!(decode_canonical_base64("AB==", 128, false).is_err());

        assert!(valid_timestamp(CREATED_AT));
        assert!(!valid_timestamp("not-a-timestamp"));
        assert!(current_timestamp_millis().is_some_and(|value| value > 63_000_000_000_000));
        assert!(valid_optional_uuid(None));
        assert!(valid_optional_uuid(Some(SIGNER_ID)));
        assert!(!valid_optional_uuid(Some("not-a-uuid")));

        assert!(valid_serial("01ab"));
        assert!(!valid_serial(""));
        assert!(!valid_serial("0g"));
        assert!(!valid_serial(&"a".repeat(129)));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn signer_wire_validation_rejects_each_independent_field() {
        let invalid_fields = [
            ("id", json!("not-a-uuid")),
            ("projectId", json!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")),
            ("name", json!("Invalid Name")),
            ("description", json!(" leading")),
            ("certificateId", json!("not-a-uuid")),
            ("approvalPolicyId", json!("not-a-uuid")),
            ("caId", json!("not-a-uuid")),
            ("certificateCaId", json!("not-a-uuid")),
            ("lastSignedAt", json!("not-a-timestamp")),
            ("createdAt", json!("not-a-timestamp")),
            ("updatedAt", json!("not-a-timestamp")),
            ("commonName", json!("")),
            ("certificateCommonName", json!("")),
            ("certificateTtlDays", json!(0)),
            ("certificateRenewBeforeDays", json!(0)),
            ("certificateFailureReason", json!("")),
            ("keyAlgorithm", json!("ML-DSA-44")),
            ("certificateKeyAlgorithm", json!("ML-DSA-44")),
            ("certificateSerialNumber", json!("0g")),
            ("certificateNotBefore", json!("not-a-timestamp")),
            ("certificateNotAfter", json!("not-a-timestamp")),
            ("certificateStatus", json!("unknown")),
            ("approvalPolicyName", json!("")),
        ];
        for (field, invalid) in invalid_fields {
            let mut value = signer_value(None, "active");
            value[field] = invalid;
            assert!(
                matches!(
                    signer_from_wire(signer_wire(value), &project_id(), None),
                    Err(ResourceError::InvalidCodeSignerResponse)
                ),
                "{field}"
            );
        }

        for (field, invalid) in [
            ("certificateTtlDays", json!(3_651)),
            ("certificateRenewBeforeDays", json!(31)),
            ("certificateSerialNumber", json!("a".repeat(129))),
            ("approvalPolicyName", json!("a".repeat(257))),
        ] {
            let mut value = signer_value(None, "active");
            value[field] = invalid;
            assert!(
                signer_from_wire(signer_wire(value), &project_id(), None).is_err(),
                "{field}"
            );
        }

        let mut invalid_renewal = signer_value(None, "active");
        invalid_renewal["certificateTtlDays"] = json!(30);
        invalid_renewal["certificateRenewBeforeDays"] = json!(30);
        assert!(signer_from_wire(signer_wire(invalid_renewal), &project_id(), None).is_err());

        let other_id = CodeSignerId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        assert!(
            signer_from_wire(
                signer_wire(signer_value(None, "active")),
                &project_id(),
                Some(&other_id),
            )
            .is_err()
        );
    }

    #[test]
    fn certificate_preflight_helpers_require_every_usable_state_invariant() {
        let now = utc_timestamp_millis(CREATED_AT).unwrap();
        let certificate_id = CodeSignerCertificateId::new(CERTIFICATE_ID).unwrap();
        let certificate = existing_certificate();
        assert!(existing_signer_certificate_is_usable(
            &certificate,
            &project_id(),
            &certificate_id,
            Some(now),
        ));
        assert!(!existing_signer_certificate_is_usable(
            &certificate,
            &project_id(),
            &certificate_id,
            None,
        ));

        let mutations: [fn(&mut Certificate); 12] = [
            |wire| wire.id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            |wire| wire.project_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            |wire| wire.status = CertificateStatus::Revoked,
            |wire| wire.has_private_key = false,
            |wire| wire.not_before = NOT_AFTER.to_owned(),
            |wire| wire.not_after = CREATED_AT.to_owned(),
            |wire| wire.not_after = "not-a-timestamp".to_owned(),
            |wire| wire.is_ca = Some(true),
            |wire| wire.is_ca = None,
            |wire| wire.key_algorithm = None,
            |wire| wire.key_algorithm = Some(CertificateKeyAlgorithm::MlDsa44),
            |wire| wire.extended_key_usages = Some(vec!["serverAuth".to_owned()]),
        ];
        for mutate in mutations {
            let mut changed = existing_certificate();
            mutate(&mut changed);
            assert!(!existing_signer_certificate_is_usable(
                &changed,
                &project_id(),
                &certificate_id,
                Some(now),
            ));
        }
        let mut missing_usages = existing_certificate();
        missing_usages.extended_key_usages = None;
        assert!(!existing_signer_certificate_is_usable(
            &missing_usages,
            &project_id(),
            &certificate_id,
            Some(now),
        ));
        assert!(internal_signer_ca_is_usable(
            CertificateAuthorityStatus::Active
        ));
        for status in [
            CertificateAuthorityStatus::PendingCertificate,
            CertificateAuthorityStatus::Disabled,
        ] {
            assert!(!internal_signer_ca_is_usable(status));
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn signer_page_contract_enforces_bounds_uniqueness_and_search() {
        let request = |limit, search: Option<&str>| {
            CodeSignerListRequest::new(
                project_id(),
                PageRequest::new(0, limit).unwrap(),
                search.map(str::to_owned),
            )
            .unwrap()
        };
        let second_signer = || {
            let mut value = signer_value(None, "active");
            value["id"] = json!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
            value["name"] = json!("other-signer");
            value["certificateCommonName"] = json!("other.example.test");
            signer_wire(value)
        };

        for response in [
            ListSignersResponse {
                signers: vec![signer_wire(signer_value(None, "active"))],
                total_count: 1,
            },
            ListSignersResponse {
                signers: vec![signer_wire(signer_value(None, "active")), second_signer()],
                total_count: 2,
            },
        ] {
            assert!(signer_page_from_wire(response, &request(2, None)).is_ok());
        }

        let page_with_more = signer_page_from_wire(
            ListSignersResponse {
                signers: vec![signer_wire(signer_value(None, "active"))],
                total_count: 2,
            },
            &request(1, None),
        )
        .unwrap();
        assert_eq!(page_with_more.next.unwrap().offset(), 1);
        assert!(
            signer_page_from_wire(
                ListSignersResponse {
                    signers: vec![signer_wire(signer_value(None, "active"))],
                    total_count: 2,
                },
                &request(2, None),
            )
            .is_err()
        );
        assert!(
            signer_page_from_wire(
                ListSignersResponse {
                    signers: Vec::new(),
                    total_count: 1,
                },
                &request(2, None),
            )
            .is_err()
        );

        assert!(
            signer_page_from_wire(
                ListSignersResponse {
                    signers: vec![signer_wire(signer_value(None, "active")), second_signer(),],
                    total_count: 2,
                },
                &request(1, None),
            )
            .is_err()
        );
        assert!(
            signer_page_from_wire(
                ListSignersResponse {
                    signers: vec![signer_wire(signer_value(None, "active"))],
                    total_count: 0,
                },
                &request(2, None),
            )
            .is_err()
        );
        assert!(
            signer_page_from_wire(
                ListSignersResponse {
                    signers: vec![
                        signer_wire(signer_value(None, "active")),
                        signer_wire(signer_value(None, "active")),
                    ],
                    total_count: 2,
                },
                &request(2, None),
            )
            .is_err()
        );
        assert!(
            signer_page_from_wire(
                ListSignersResponse {
                    signers: vec![signer_wire(signer_value(None, "active"))],
                    total_count: 1,
                },
                &request(2, Some("absent")),
            )
            .is_err()
        );
        assert!(
            signer_page_from_wire(
                ListSignersResponse {
                    signers: vec![signer_wire(signer_value(None, "active"))],
                    total_count: 1,
                },
                &request(2, Some("release-signer")),
            )
            .is_ok()
        );
        assert!(
            signer_page_from_wire(
                ListSignersResponse {
                    signers: vec![signer_wire(signer_value(None, "active"))],
                    total_count: 1,
                },
                &request(2, Some("example.test")),
            )
            .is_ok()
        );

        let terminal_request =
            CodeSignerListRequest::new(project_id(), PageRequest::new(1, 2).unwrap(), None)
                .unwrap();
        assert!(
            signer_page_from_wire(
                ListSignersResponse {
                    signers: Vec::new(),
                    total_count: 1,
                },
                &terminal_request,
            )
            .is_ok()
        );
        let offset_request =
            CodeSignerListRequest::new(project_id(), PageRequest::new(20, 2).unwrap(), None)
                .unwrap();
        assert!(
            signer_page_from_wire(
                ListSignersResponse {
                    signers: vec![signer_wire(signer_value(None, "active"))],
                    total_count: 1,
                },
                &offset_request,
            )
            .is_err()
        );
        assert!(
            signer_page_from_wire(
                ListSignersResponse {
                    signers: Vec::new(),
                    total_count: 1,
                },
                &offset_request,
            )
            .is_ok()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn signer_mutation_helpers_bind_every_requested_and_stable_field() {
        let existing_request = existing_signer_request();
        let existing_binding = existing_certificate_binding();
        let signer = valid_signer();
        assert!(created_signer_matches(
            &signer,
            &existing_request,
            Some(&existing_binding),
            "release-signer",
            None,
        ));
        let mut policy_free_signer = signer.clone();
        policy_free_signer.approval_policy_id = None;
        assert!(created_signer_matches(
            &policy_free_signer,
            &existing_request,
            Some(&existing_binding),
            "release-signer",
            None,
        ));
        let create_mutations: [fn(&mut CodeSigner); 8] = [
            |value| value.name = "other-signer".to_owned(),
            |value| value.description = Some("other".to_owned()),
            |value| value.status = CodeSignerStatus::Disabled,
            |value| value.certificate_id = None,
            |value| value.ca_id = Some(CA_ID.to_owned()),
            |value| value.common_name = Some("other.example.test".to_owned()),
            |value| value.certificate_ttl_days = Some(30),
            |value| value.certificate_renew_before_days = Some(10),
        ];
        for mutate in create_mutations {
            let mut changed = signer.clone();
            mutate(&mut changed);
            assert!(!created_signer_matches(
                &changed,
                &existing_request,
                Some(&existing_binding),
                "release-signer",
                None,
            ));
        }
        let existing_certificate_mutations: [fn(&mut CodeSigner); 5] = [
            |value| value.certificate_status = None,
            |value| value.certificate_status = Some("revoked".to_owned()),
            |value| value.certificate_key_algorithm = None,
            |value| {
                value.certificate_key_algorithm = Some(CertificateKeyAlgorithm::Rsa3072);
            },
            |value| value.key_algorithm = CertificateKeyAlgorithm::Rsa3072,
        ];
        for mutate in existing_certificate_mutations {
            let mut changed = signer.clone();
            mutate(&mut changed);
            assert!(!created_signer_matches(
                &changed,
                &existing_request,
                Some(&existing_binding),
                "release-signer",
                None,
            ));
        }

        let internal_request = CreateSignerRequest {
            project_id: PROJECT_ID.to_owned(),
            name: "release-signer".to_owned(),
            description: Some("release artifacts".to_owned()),
            ca_id: Some(CA_ID.to_owned()),
            common_name: Some("release.example.test".to_owned()),
            certificate_ttl_days: Some(365),
            certificate_renew_before_days: Some(30),
            key_algorithm: Some(CertificateKeyAlgorithm::Rsa2048),
            certificate_id: None,
        };
        let mut internal_signer = signer.clone();
        internal_signer.description = Some("release artifacts".to_owned());
        internal_signer.ca_id = Some(CA_ID.to_owned());
        internal_signer.common_name = Some("release.example.test".to_owned());
        internal_signer.certificate_ttl_days = Some(365);
        internal_signer.certificate_renew_before_days = Some(30);
        internal_signer.certificate_ca_id = Some(CA_ID.to_owned());
        assert!(created_signer_matches(
            &internal_signer,
            &internal_request,
            None,
            "release-signer",
            Some("release artifacts"),
        ));
        let mut wrong_internal_key = internal_signer.clone();
        wrong_internal_key.key_algorithm = CertificateKeyAlgorithm::Rsa3072;
        assert!(!created_signer_matches(
            &wrong_internal_key,
            &internal_request,
            None,
            "release-signer",
            Some("release artifacts"),
        ));
        for mutate in internal_certificate_binding_mutations() {
            let mut changed = internal_signer.clone();
            mutate(&mut changed);
            assert!(!created_signer_matches(
                &changed,
                &internal_request,
                None,
                "release-signer",
                Some("release artifacts"),
            ));
        }

        let before = signer.clone();
        let update_request = UpdateSignerRequest {
            signer_id: signer_id(),
            name: Some("renamed-signer".to_owned()),
            description: Some(NullableString::Value("release artifacts".to_owned())),
            certificate_renew_before_days: Some(NullableU8::Value(20)),
        };
        let mut updated = before.clone();
        updated.name = "renamed-signer".to_owned();
        updated.description = Some("release artifacts".to_owned());
        updated.certificate_renew_before_days = Some(20);
        assert!(updated_signer_matches(&updated, &before, &update_request));
        let update_mutations: [fn(&mut CodeSigner); 7] = [
            |value| value.name = "wrong-signer".to_owned(),
            |value| value.description = None,
            |value| value.certificate_renew_before_days = Some(19),
            |value| value.status = CodeSignerStatus::Disabled,
            |value| value.certificate_id = None,
            |value| value.ca_id = Some(CA_ID.to_owned()),
            |value| value.key_algorithm = CertificateKeyAlgorithm::Rsa3072,
        ];
        for mutate in update_mutations {
            let mut changed = updated.clone();
            mutate(&mut changed);
            assert!(!updated_signer_matches(&changed, &before, &update_request));
        }
        let clear_request = UpdateSignerRequest {
            signer_id: signer_id(),
            name: None,
            description: Some(NullableString::Null),
            certificate_renew_before_days: Some(NullableU8::Null),
        };
        let mut clear_before = before.clone();
        clear_before.description = Some("release artifacts".to_owned());
        clear_before.certificate_renew_before_days = Some(20);
        let mut cleared = clear_before.clone();
        cleared.description = None;
        cleared.certificate_renew_before_days = None;
        assert!(updated_signer_matches(
            &cleared,
            &clear_before,
            &clear_request
        ));
        assert!(!updated_signer_matches(
            &clear_before,
            &clear_before,
            &clear_request
        ));

        let description_only_request = UpdateSignerRequest {
            signer_id: signer_id(),
            name: None,
            description: Some(NullableString::Value("release artifacts".to_owned())),
            certificate_renew_before_days: None,
        };
        let mut description_only_result = before.clone();
        description_only_result.description = Some("release artifacts".to_owned());
        assert!(updated_signer_matches(
            &description_only_result,
            &before,
            &description_only_request,
        ));
        for mutate in [
            |value: &mut CodeSigner| value.name = "renamed-signer".to_owned(),
            |value: &mut CodeSigner| value.status = CodeSignerStatus::Disabled,
            |value: &mut CodeSigner| value.certificate_renew_before_days = Some(20),
        ] {
            let mut changed = description_only_result.clone();
            mutate(&mut changed);
            assert!(!updated_signer_matches(
                &changed,
                &before,
                &description_only_request,
            ));
        }

        let name_only_request = UpdateSignerRequest {
            signer_id: signer_id(),
            name: Some("renamed-signer".to_owned()),
            description: None,
            certificate_renew_before_days: None,
        };
        let mut name_only_result = before.clone();
        name_only_result.name = "renamed-signer".to_owned();
        assert!(updated_signer_matches(
            &name_only_result,
            &before,
            &name_only_request,
        ));
        let mut changed_description = name_only_result;
        changed_description.description = Some("unexpected".to_owned());
        assert!(!updated_signer_matches(
            &changed_description,
            &before,
            &name_only_request,
        ));

        assert!(renew_before_fits(Some(30), Some(31)));
        assert!(!renew_before_fits(Some(30), Some(30)));
        assert!(renew_before_fits(None, Some(30)));
        assert!(renew_before_fits(Some(30), None));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn signer_status_and_reissue_helpers_enforce_every_transition_and_result() {
        let active = valid_signer();
        let mut disabled = active.clone();
        disabled.status = CodeSignerStatus::Disabled;
        assert!(status_transition_is_allowed(
            &active,
            CodeSignerDesiredStatus::Disabled
        ));
        assert!(status_transition_is_allowed(
            &disabled,
            CodeSignerDesiredStatus::Active
        ));
        assert!(!status_transition_is_allowed(
            &active,
            CodeSignerDesiredStatus::Active
        ));
        assert!(!status_transition_is_allowed(
            &disabled,
            CodeSignerDesiredStatus::Disabled
        ));
        let mut pending = active.clone();
        pending.status = CodeSignerStatus::Pending;
        assert!(!status_transition_is_allowed(
            &pending,
            CodeSignerDesiredStatus::Active
        ));
        disabled.certificate_id = None;
        assert!(!status_transition_is_allowed(
            &disabled,
            CodeSignerDesiredStatus::Active
        ));

        let mut status_result = active.clone();
        status_result.status = CodeSignerStatus::Disabled;
        assert!(status_updated_signer_matches(
            &status_result,
            &active,
            CodeSignerStatus::Disabled,
        ));
        for mutate in [
            |value: &mut CodeSigner| value.status = CodeSignerStatus::Active,
            |value: &mut CodeSigner| value.certificate_id = None,
            |value: &mut CodeSigner| value.ca_id = Some(CA_ID.to_owned()),
            |value: &mut CodeSigner| value.key_algorithm = CertificateKeyAlgorithm::Rsa3072,
        ] {
            let mut changed = status_result.clone();
            mutate(&mut changed);
            assert!(!status_updated_signer_matches(
                &changed,
                &active,
                CodeSignerStatus::Disabled,
            ));
        }

        assert!(reissue_changes_are_allowed(
            CodeSignerStatus::Pending,
            true,
            true,
        ));
        assert!(reissue_changes_are_allowed(
            CodeSignerStatus::Failed,
            true,
            true,
        ));
        assert!(reissue_changes_are_allowed(
            CodeSignerStatus::Active,
            false,
            false,
        ));
        assert!(!reissue_changes_are_allowed(
            CodeSignerStatus::Active,
            true,
            false,
        ));
        assert!(!reissue_changes_are_allowed(
            CodeSignerStatus::Active,
            false,
            true,
        ));

        let no_changes = CodeSignerCertificateReissue::new(
            CertificateAuthorityId::new(CA_ID).unwrap(),
            None,
            None,
        )
        .unwrap();
        let mut configured = active.clone();
        configured.common_name = Some("release.example.test".to_owned());
        configured.certificate_ttl_days = Some(365);
        assert_eq!(
            reissue_expectations(&configured, &no_changes).unwrap(),
            ("release.example.test".to_owned(), 365)
        );
        assert!(reissue_expectations(&active, &no_changes).is_err());
        let mut invalid_renewal = configured.clone();
        invalid_renewal.certificate_renew_before_days = Some(30);
        invalid_renewal.certificate_ttl_days = Some(30);
        assert!(reissue_expectations(&invalid_renewal, &no_changes).is_err());
        let resubject = CodeSignerCertificateReissue::new(
            CertificateAuthorityId::new(CA_ID).unwrap(),
            Some("new.example.test".to_owned()),
            Some(30),
        )
        .unwrap();
        assert!(reissue_expectations(&active, &resubject).is_err());
        let mut failed = active.clone();
        failed.status = CodeSignerStatus::Failed;
        assert_eq!(
            reissue_expectations(&failed, &resubject).unwrap(),
            ("new.example.test".to_owned(), 30)
        );

        let request = ReissueSignerCertificateRequest {
            signer_id: signer_id(),
            ca_id: CA_ID.to_owned(),
            common_name: Some("release.example.test".to_owned()),
            certificate_ttl_days: Some(365),
        };
        let mut reissued = active.clone();
        reissued.ca_id = Some(CA_ID.to_owned());
        reissued.common_name = Some("release.example.test".to_owned());
        reissued.certificate_ttl_days = Some(365);
        reissued.certificate_id = Some("66666666-6666-4666-8666-666666666666".to_owned());
        reissued.certificate_ca_id = Some(CA_ID.to_owned());
        assert!(reissued_signer_matches(
            &reissued,
            &active,
            &request,
            Some("release.example.test"),
            365,
        ));
        assert!(
            validate_reissued_signer(&reissued, &active, &request, "release.example.test", 365,)
                .is_ok()
        );
        let reissue_mutations: [fn(&mut CodeSigner); 7] = [
            |value| value.status = CodeSignerStatus::Disabled,
            |value| value.ca_id = Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned()),
            |value| value.common_name = Some("wrong.example.test".to_owned()),
            |value| value.certificate_ttl_days = Some(364),
            |value| value.certificate_id = None,
            |value| value.certificate_id = Some(CERTIFICATE_ID.to_owned()),
            |value| value.key_algorithm = CertificateKeyAlgorithm::Rsa3072,
        ];
        for mutate in reissue_mutations {
            let mut changed = reissued.clone();
            mutate(&mut changed);
            assert!(!reissued_signer_matches(
                &changed,
                &active,
                &request,
                Some("release.example.test"),
                365,
            ));
            assert!(
                validate_reissued_signer(&changed, &active, &request, "release.example.test", 365,)
                    .is_err()
            );
        }
        for mutate in internal_certificate_binding_mutations() {
            let mut changed = reissued.clone();
            mutate(&mut changed);
            assert!(!reissued_signer_matches(
                &changed,
                &active,
                &request,
                Some("release.example.test"),
                365,
            ));
            assert!(
                validate_reissued_signer(&changed, &active, &request, "release.example.test", 365,)
                    .is_err()
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn signer_cryptographic_helpers_fail_closed_on_each_independent_drift() {
        assert!(exported_certificate_metadata_matches(
            false,
            "01ab",
            "release-signer",
            "release-signer",
        ));
        assert!(!exported_certificate_metadata_matches(
            true,
            "01ab",
            "release-signer",
            "release-signer",
        ));
        assert!(!exported_certificate_metadata_matches(
            false,
            "not-hex",
            "release-signer",
            "release-signer",
        ));
        assert!(!exported_certificate_metadata_matches(
            false,
            "01ab",
            "wrong-signer",
            "release-signer",
        ));

        let certificate_der = certificate_bundle_der(LEAF_CERTIFICATE.trim_end()).unwrap();
        let (_, certificate) = X509Certificate::from_der(&certificate_der[0]).unwrap();
        let response = ExportCertificateWire {
            certificate_pem: LEAF_CERTIFICATE.trim_end().to_owned(),
            serial_number: LEAF_SERIAL.to_owned(),
            signer_name: "release-signer".to_owned(),
        };
        let signer = valid_signer();
        assert!(exported_certificate_matches_signer(
            &certificate,
            &response,
            &signer,
        ));
        let (normalized, certificate_public_key) =
            validated_exported_certificate(&response, &signer).unwrap();
        assert_eq!(normalized, LEAF_CERTIFICATE.trim_end());
        assert_eq!(certificate_public_key, certificate.public_key().raw);
        let mut certificate_with_trailing_der = certificate_der[0].clone();
        certificate_with_trailing_der.push(0);
        let certificate_with_trailing_der = pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            &certificate_with_trailing_der,
        )
        .unwrap();
        assert!(
            validated_exported_certificate(
                &ExportCertificateWire {
                    certificate_pem: certificate_with_trailing_der,
                    serial_number: LEAF_SERIAL.to_owned(),
                    signer_name: "release-signer".to_owned(),
                },
                &signer,
            )
            .is_err()
        );
        let wrong_serial = ExportCertificateWire {
            serial_number: "01ab".to_owned(),
            ..response
        };
        assert!(!exported_certificate_matches_signer(
            &certificate,
            &wrong_serial,
            &signer,
        ));
        let mut missing_preflight_serial = signer.clone();
        missing_preflight_serial.certificate_serial_number = None;
        assert!(!exported_certificate_matches_signer(
            &certificate,
            &ExportCertificateWire {
                certificate_pem: LEAF_CERTIFICATE.trim_end().to_owned(),
                serial_number: LEAF_SERIAL.to_owned(),
                signer_name: "release-signer".to_owned(),
            },
            &missing_preflight_serial,
        ));

        let rsa_public_key = super::STANDARD.decode(RSA_PUBLIC_KEY.trim_end()).unwrap();
        assert_eq!(certificate_public_key, rsa_public_key);
        assert_eq!(
            decode_canonical_secret_base64("AQID", super::MAX_SIGNER_DATA_BYTES),
            Ok(3),
        );
        assert!(decode_canonical_secret_base64("AQI", super::MAX_SIGNER_DATA_BYTES).is_err());
        assert!(decode_canonical_secret_base64("", super::MAX_SIGNER_DATA_BYTES).is_err());
        let maximum_signing_data = super::STANDARD.encode([0_u8; super::MAX_SIGNER_DATA_BYTES]);
        assert_eq!(
            decode_canonical_secret_base64(&maximum_signing_data, super::MAX_SIGNER_DATA_BYTES,),
            Ok(super::MAX_SIGNER_DATA_BYTES),
        );
        let oversized_signing_data =
            super::STANDARD.encode([0_u8; super::MAX_SIGNER_DATA_BYTES + 1]);
        assert!(
            decode_canonical_secret_base64(&oversized_signing_data, super::MAX_SIGNER_DATA_BYTES,)
                .is_err()
        );
        assert!(valid_public_key_spki(
            &rsa_public_key,
            CertificateKeyAlgorithm::Rsa2048,
        ));
        assert!(!valid_public_key_spki(
            &rsa_public_key,
            CertificateKeyAlgorithm::Rsa3072,
        ));
        assert!(!valid_public_key_spki(
            &rsa_public_key,
            CertificateKeyAlgorithm::EcPrime256v1,
        ));
        let mut trailing_data = rsa_public_key.clone();
        trailing_data.push(0);
        assert!(!valid_public_key_spki(
            &trailing_data,
            CertificateKeyAlgorithm::Rsa2048,
        ));
        assert!(!valid_public_key_spki(
            b"not-der",
            CertificateKeyAlgorithm::Rsa2048,
        ));
        let rsa_1024 = super::STANDARD
            .decode(RSA_1024_PUBLIC_KEY.trim_end())
            .unwrap();
        assert!(!valid_public_key_spki(
            &rsa_1024,
            CertificateKeyAlgorithm::Rsa2048,
        ));
        assert!(valid_public_key_spki_rsa_parameters(
            2_048,
            2_048,
            Some(65_537),
        ));
        assert!(!valid_public_key_spki_rsa_parameters(
            1_024,
            2_048,
            Some(65_537),
        ));
        assert!(!valid_public_key_spki_rsa_parameters(
            2_048,
            3_072,
            Some(65_537),
        ));
        assert!(!valid_public_key_spki_rsa_parameters(2_048, 2_048, None,));
        assert!(!valid_public_key_spki_rsa_parameters(2_048, 2_048, Some(1),));
        assert!(!valid_public_key_spki_rsa_parameters(2_048, 2_048, Some(4),));
        for (algorithm, expected) in [
            (CertificateKeyAlgorithm::Rsa2048, 2_048),
            (CertificateKeyAlgorithm::Rsa3072, 3_072),
            (CertificateKeyAlgorithm::Rsa4096, 4_096),
        ] {
            assert_eq!(valid_public_key_spki_rsa_size(algorithm), Some(expected));
        }
        assert_eq!(
            valid_public_key_spki_rsa_size(CertificateKeyAlgorithm::EcPrime256v1),
            None,
        );
        for (algorithm, expected) in [
            (
                CertificateKeyAlgorithm::EcPrime256v1,
                ("1.2.840.10045.3.1.7", 65),
            ),
            (CertificateKeyAlgorithm::EcSecp384r1, ("1.3.132.0.34", 97)),
            (CertificateKeyAlgorithm::EcSecp521r1, ("1.3.132.0.35", 133)),
        ] {
            assert_eq!(
                valid_public_key_spki_ec_parameters(algorithm),
                Some(expected),
            );
        }
        assert_eq!(
            valid_public_key_spki_ec_parameters(CertificateKeyAlgorithm::Rsa2048),
            None,
        );

        let (_, p521_csr_der) = pem_rfc7468::decode_vec(P521_CSR.as_bytes()).unwrap();
        let (_, p521_csr) = X509CertificationRequest::from_der(&p521_csr_der).unwrap();
        let p521_public_key = p521_csr.certification_request_info.subject_pki.raw;
        assert!(valid_public_key_spki(
            p521_public_key,
            CertificateKeyAlgorithm::EcSecp521r1,
        ));
        assert!(!valid_public_key_spki(
            p521_public_key,
            CertificateKeyAlgorithm::EcSecp384r1,
        ));
        let (_, spki) = SubjectPublicKeyInfo::from_der(p521_public_key).unwrap();
        let point_offset = p521_public_key
            .windows(spki.subject_public_key.data.len())
            .position(|window| window == spki.subject_public_key.data.as_ref())
            .unwrap();
        let mut wrong_point_form = p521_public_key.to_vec();
        wrong_point_form[point_offset] = 2;
        assert!(!valid_public_key_spki(
            &wrong_point_form,
            CertificateKeyAlgorithm::EcSecp521r1,
        ));

        let public_key_response = PublicKeyWire {
            public_key: RSA_PUBLIC_KEY.trim_end().to_owned(),
            algorithm: CodeSignerPublicKeyFamily::Rsa,
        };
        assert!(
            validate_public_key_response(&signer, &public_key_response, &rsa_public_key,).is_ok()
        );
        let mut wrong_signer_family = signer.clone();
        wrong_signer_family.key_algorithm = CertificateKeyAlgorithm::EcPrime256v1;
        assert!(
            validate_public_key_response(
                &wrong_signer_family,
                &public_key_response,
                &rsa_public_key,
            )
            .is_err()
        );
        assert!(validate_public_key_response(&signer, &public_key_response, b"not-der").is_err());

        for (key, public_key) in [
            (
                CertificateKeyAlgorithm::Rsa2048,
                CodeSignerPublicKeyFamily::Rsa,
            ),
            (
                CertificateKeyAlgorithm::Rsa3072,
                CodeSignerPublicKeyFamily::Rsa,
            ),
            (
                CertificateKeyAlgorithm::Rsa4096,
                CodeSignerPublicKeyFamily::Rsa,
            ),
            (
                CertificateKeyAlgorithm::EcPrime256v1,
                CodeSignerPublicKeyFamily::EccNistP256,
            ),
            (
                CertificateKeyAlgorithm::EcSecp384r1,
                CodeSignerPublicKeyFamily::EccNistP384,
            ),
            (
                CertificateKeyAlgorithm::EcSecp521r1,
                CodeSignerPublicKeyFamily::EccNistP521,
            ),
        ] {
            assert!(public_key_family_matches(key, public_key));
            assert!(
                !public_key_family_matches(key, CodeSignerPublicKeyFamily::EccNistP256)
                    || key == CertificateKeyAlgorithm::EcPrime256v1
            );
        }
        assert!(!public_key_family_matches(
            CertificateKeyAlgorithm::MlDsa44,
            CodeSignerPublicKeyFamily::Rsa,
        ));

        assert!(signing_input_is_valid(
            3,
            CodeSigningAlgorithm::RsaPkcs1V15Sha256,
            false,
        ));
        assert!(signing_input_is_valid(
            32,
            CodeSigningAlgorithm::RsaPkcs1V15Sha256,
            true,
        ));
        assert!(!signing_input_is_valid(
            31,
            CodeSigningAlgorithm::RsaPkcs1V15Sha256,
            true,
        ));
        assert!(!signing_input_is_valid(
            32,
            CodeSigningAlgorithm::RsaPssSha256,
            true,
        ));

        let now = utc_timestamp_millis(CREATED_AT).unwrap();
        assert!(signer_can_sign(
            &signer,
            CodeSigningAlgorithm::RsaPkcs1V15Sha256,
            Some(now),
        ));
        assert!(!signer_can_sign(
            &signer,
            CodeSigningAlgorithm::RsaPkcs1V15Sha256,
            None,
        ));
        let sign_state_mutations: [fn(&mut CodeSigner); 10] = [
            |value| value.status = CodeSignerStatus::Disabled,
            |value| value.certificate_id = None,
            |value| value.certificate_status = Some("revoked".to_owned()),
            |value| value.certificate_status = None,
            |value| value.certificate_not_before = None,
            |value| value.certificate_not_before = Some(NOT_AFTER.to_owned()),
            |value| value.certificate_not_after = None,
            |value| value.certificate_key_algorithm = None,
            |value| {
                value.certificate_key_algorithm = Some(CertificateKeyAlgorithm::Rsa3072);
            },
            |value| value.key_algorithm = CertificateKeyAlgorithm::EcPrime256v1,
        ];
        for mutate in sign_state_mutations {
            let mut changed = signer.clone();
            mutate(&mut changed);
            assert!(!signer_can_sign(
                &changed,
                CodeSigningAlgorithm::RsaPkcs1V15Sha256,
                Some(now),
            ));
        }
        let mut expired = signer.clone();
        expired.certificate_not_after = Some(CREATED_AT.to_owned());
        assert!(!signer_can_sign(
            &expired,
            CodeSigningAlgorithm::RsaPkcs1V15Sha256,
            Some(now),
        ));

        let signature = SignatureWire {
            signature: "AQID".to_owned(),
            signing_algorithm: CodeSigningAlgorithm::RsaPkcs1V15Sha256,
            signer_id: SIGNER_ID.to_owned(),
        };
        assert!(signature_matches(
            &signature,
            &signer_id(),
            CodeSigningAlgorithm::RsaPkcs1V15Sha256,
        ));
        for changed in [
            SignatureWire {
                signer_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                ..signature_wire()
            },
            SignatureWire {
                signing_algorithm: CodeSigningAlgorithm::RsaPkcs1V15Sha384,
                ..signature_wire()
            },
            SignatureWire {
                signature: "not-base64".to_owned(),
                ..signature_wire()
            },
        ] {
            assert!(!signature_matches(
                &changed,
                &signer_id(),
                CodeSigningAlgorithm::RsaPkcs1V15Sha256,
            ));
        }
    }

    #[tokio::test]
    async fn confirmations_fail_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let source = CodeSignerCertificateSource::Existing {
            certificate_id: CodeSignerCertificateId::new(CERTIFICATE_ID).unwrap(),
        };
        let creation =
            CodeSignerCreation::new(CodeSignerName::new("release-signer").unwrap(), None, source)
                .unwrap();
        assert!(matches!(
            client
                .create_code_signer(&project_id(), creation, false)
                .await,
            Err(ResourceError::CodeSignerCreateNotConfirmed)
        ));
        let change =
            CodeSignerChange::new(None, Some(CodeSignerDescriptionChange::Clear), None).unwrap();
        assert!(matches!(
            client
                .update_code_signer(&project_id(), &signer_id(), change, false)
                .await,
            Err(ResourceError::CodeSignerUpdateNotConfirmed)
        ));
        assert!(matches!(
            client
                .delete_code_signer(&project_id(), &signer_id(), false)
                .await,
            Err(ResourceError::CodeSignerDeleteNotConfirmed)
        ));
        assert!(matches!(
            client
                .update_code_signer_status(
                    &project_id(),
                    &signer_id(),
                    CodeSignerDesiredStatus::Disabled,
                    false,
                )
                .await,
            Err(ResourceError::CodeSignerStatusUpdateNotConfirmed)
        ));
        let reissue = CodeSignerCertificateReissue::new(
            CertificateAuthorityId::new(CA_ID).unwrap(),
            None,
            None,
        )
        .unwrap();
        assert!(matches!(
            client
                .reissue_code_signer_certificate(&project_id(), &signer_id(), reissue, false,)
                .await,
            Err(ResourceError::CodeSignerCertificateMutationNotConfirmed)
        ));
        assert!(matches!(
            client
                .code_signer_sign(
                    &project_id(),
                    &signer_id(),
                    CodeSigningData::new(SecretValue::new("AQID")).unwrap(),
                    CodeSigningAlgorithm::RsaPkcs1V15Sha256,
                    false,
                    None,
                    false,
                )
                .await,
            Err(ResourceError::CodeSigningNotConfirmed)
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn internal_ca_preflight_rejects_a_non_active_authority() {
        let server = MockServer::start().await;
        mount_login(&server, "signer-ca-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/cert-manager/ca/internal/{CA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(internal_ca_value("disabled")))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert!(matches!(
            client
                .preflight_internal_signer_ca(
                    &project_id(),
                    &CertificateAuthorityId::new(CA_ID).unwrap(),
                )
                .await,
            Err(ResourceError::InvalidCodeSignerCertificateState)
        ));
    }

    #[tokio::test]
    async fn existing_certificate_preflight_rejects_an_unsupported_key_before_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "signer-certificate-token").await;
        mount_project(&server).await;
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
                "certificates": [existing_certificate_inventory_value("ML-DSA-44", true)],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/signers"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let creation = CodeSignerCreation::new(
            CodeSignerName::new("release-signer").unwrap(),
            None,
            CodeSignerCertificateSource::Existing {
                certificate_id: CodeSignerCertificateId::new(CERTIFICATE_ID).unwrap(),
            },
        )
        .unwrap();
        assert!(matches!(
            client
                .create_code_signer(&project_id(), creation, true)
                .await,
            Err(ResourceError::InvalidCodeSignerCertificateState)
        ));
    }

    #[tokio::test]
    async fn existing_certificate_preflight_requires_infisical_private_key_custody() {
        let server = MockServer::start().await;
        mount_login(&server, "signer-custody-token").await;
        mount_project(&server).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{PROJECT_ID}/certificates/search"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [existing_certificate_inventory_value("RSA_2048", false)],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/signers"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let creation = CodeSignerCreation::new(
            CodeSignerName::new("release-signer").unwrap(),
            None,
            CodeSignerCertificateSource::Existing {
                certificate_id: CodeSignerCertificateId::new(CERTIFICATE_ID).unwrap(),
            },
        )
        .unwrap();
        let error = client
            .create_code_signer(&project_id(), creation, true)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "code-signer creation requires a certificate whose private key is stored in Infisical"
        );
        assert!(matches!(
            error,
            ResourceError::MissingCodeSignerCertificatePrivateKey
        ));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn lifecycle_and_cryptographic_routes_are_exact_and_reflected() {
        let server = MockServer::start().await;
        mount_login(&server, "signer-token").await;
        mount_project(&server).await;
        let mut created_signer = signer_value(None, "active");
        created_signer["approvalPolicyId"] = Value::Null;
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
                "certificates": [existing_certificate_inventory_value("RSA_2048", true)],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/signers"))
            .and(body_json(json!({
                "projectId": PROJECT_ID,
                "name": "release-signer",
                "certificateId": CERTIFICATE_ID
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(created_signer))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/signers"))
            .and(query_param("projectId", PROJECT_ID))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "20"))
            .and(query_param("search", "release"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signers": [signer_value(None, "active")],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/cert-manager/signers/{SIGNER_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(signer_value(None, "active")))
            .expect(6)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/cert-manager/signers/{SIGNER_ID}")))
            .and(body_json(json!({"description": "release artifacts"})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(signer_value(Some("release artifacts"), "active")),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/status"
            )))
            .and(body_json(json!({"status": "disabled"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(signer_value(None, "disabled")))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/certificate"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePem": LEAF_CERTIFICATE.trim_end(),
                "serialNumber": LEAF_SERIAL,
                "signerName": "release-signer"
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/public-key"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "publicKey": RSA_PUBLIC_KEY.trim_end(),
                "algorithm": "RSA_4096"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/sign"
            )))
            .and(body_json(json!({
                "data": "AQID",
                "signingAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
                "isDigest": false
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signature": "BAUG",
                "signingAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
                "signerId": SIGNER_ID
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/cert-manager/signers/{SIGNER_ID}")))
            .and(body_json(json!({})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(signer_value(Some("changed concurrently"), "active")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let creation = CodeSignerCreation::new(
            CodeSignerName::new("release-signer").unwrap(),
            None,
            CodeSignerCertificateSource::Existing {
                certificate_id: CodeSignerCertificateId::new(CERTIFICATE_ID).unwrap(),
            },
        )
        .unwrap();
        client
            .create_code_signer(&project_id(), creation, true)
            .await
            .unwrap();
        let page = client
            .list_code_signers(
                CodeSignerListRequest::new(
                    project_id(),
                    PageRequest::new(0, 20).unwrap(),
                    Some("release".to_owned()),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        let change = CodeSignerChange::new(
            None,
            Some(CodeSignerDescriptionChange::Set(
                "release artifacts".to_owned(),
            )),
            None,
        )
        .unwrap();
        client
            .update_code_signer(&project_id(), &signer_id(), change, true)
            .await
            .unwrap();
        client
            .update_code_signer_status(
                &project_id(),
                &signer_id(),
                CodeSignerDesiredStatus::Disabled,
                true,
            )
            .await
            .unwrap();
        let certificate = client
            .export_code_signer_certificate(&project_id(), &signer_id())
            .await
            .unwrap();
        assert_eq!(certificate.signer_id, SIGNER_ID);
        let public_key = client
            .get_code_signer_public_key(&project_id(), &signer_id())
            .await
            .unwrap();
        assert_eq!(public_key.public_key, RSA_PUBLIC_KEY.trim_end());
        assert_eq!(public_key.algorithm, CertificateKeyAlgorithm::Rsa2048);
        let signature = client
            .code_signer_sign(
                &project_id(),
                &signer_id(),
                CodeSigningData::new(SecretValue::new("AQID")).unwrap(),
                CodeSigningAlgorithm::RsaPkcs1V15Sha256,
                false,
                None,
                true,
            )
            .await
            .unwrap();
        assert_eq!(signature.signature, "BAUG");
        let deleted = client
            .delete_code_signer(&project_id(), &signer_id(), true)
            .await
            .unwrap();
        assert_eq!(deleted.description.as_deref(), Some("changed concurrently"));
    }

    #[tokio::test]
    async fn public_key_read_rejects_a_different_valid_same_family_key() {
        let server = MockServer::start().await;
        mount_login(&server, "signer-token").await;
        let ca_der = certificate_bundle_der(CA_CERTIFICATE.trim_end()).unwrap();
        let (_, ca_certificate) = X509Certificate::from_der(&ca_der[0]).unwrap();
        let other_rsa_public_key = super::STANDARD.encode(ca_certificate.public_key().raw);
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/cert-manager/signers/{SIGNER_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(signer_value(None, "active")))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/public-key"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "publicKey": other_rsa_public_key,
                "algorithm": "RSA_4096"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/certificate"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePem": LEAF_CERTIFICATE.trim_end(),
                "serialNumber": LEAF_SERIAL,
                "signerName": "release-signer"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert!(matches!(
            client
                .get_code_signer_public_key(&project_id(), &signer_id())
                .await,
            Err(ResourceError::InvalidCodeSignerResponse)
        ));
    }

    #[tokio::test]
    async fn signer_and_signature_rebinding_rejects_upstream_drift() {
        let server = MockServer::start().await;
        mount_login(&server, "signer-token").await;
        let mut wrong_project = signer_value(None, "active");
        wrong_project["projectId"] = json!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/cert-manager/signers/{SIGNER_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(wrong_project))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert!(matches!(
            client.get_code_signer(&project_id(), &signer_id()).await,
            Err(ResourceError::InvalidCodeSignerResponse)
        ));
    }
}
