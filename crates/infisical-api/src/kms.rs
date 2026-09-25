use std::collections::{HashMap, HashSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::{StreamExt, stream};
use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

#[cfg(test)]
mod preflight_tests;

use crate::{
    InfisicalClient, MutationOperation, ObservableReadOperation, Page, PageRequest, ProjectId,
    ResourceError, SecretValue,
    client::{ApiVersion, DeserializedSecret, Endpoint, sealed},
    resources::{is_bounded_text, is_uuid},
};

/// Maximum decoded data accepted by one MCP KMS operation.
///
/// Infisical accepts one MiB, but the server's one-MiB MCP ingress envelope also
/// contains JSON and base64 expansion. This narrower bound remains usable while
/// ensuring one request always fits the authenticated ingress contract.
pub const MAX_KMS_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_KMS_CIPHERTEXT_BYTES: usize = MAX_KMS_PAYLOAD_BYTES + 1024;
const MAX_KMS_SIGNATURE_BYTES: usize = 8192;
const MAX_KMS_KEY_MATERIAL_BYTES: usize = 64 * 1024;
const MAX_KMS_PRIVATE_KEY_BYTES: usize = 256 * 1024;
const MAX_KMS_PUBLIC_KEY_BYTES: usize = 128 * 1024;
const MAX_KMS_KEY_NAME_BYTES: usize = 32;
const MAX_KMS_DESCRIPTION_BYTES: usize = 500;
const MAX_KMS_SEARCH_BYTES: usize = 256;
const KMS_IMPORT_REJECTION_MESSAGE: &str = "Infisical rejected this key import";
/// Maximum keys accepted by one import or private-key export request.
pub const MAX_KMS_BULK_KEYS: usize = 100;
const MAX_CONCURRENT_KMS_PREFLIGHTS: usize = 8;

/// Input validation failures for the closed KMS contract.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum KmsInputError {
    #[error("KMS key ID must be a UUID")]
    InvalidKeyId,
    #[error(
        "KMS key name must contain 1 to 32 lowercase letters or numbers separated by single hyphens"
    )]
    InvalidKeyName,
    #[error(
        "KMS key description must contain at most 500 bytes without surrounding whitespace or control characters"
    )]
    InvalidDescription,
    #[error("KMS key usage and algorithm do not match")]
    AlgorithmUsageMismatch,
    #[error("KMS key material was validated for a different algorithm")]
    KeyMaterialAlgorithmMismatch,
    #[error("KMS key update must change at least one field")]
    EmptyChange,
    #[error("KMS data must use canonical padded base64")]
    InvalidBase64,
    #[error("KMS data exceeds the local authenticated-ingress bound")]
    PayloadTooLarge,
    #[error("KMS signing algorithm is incompatible with the selected key algorithm")]
    SigningAlgorithmMismatch,
    #[error("KMS digest mode or decoded digest length is incompatible with the signing algorithm")]
    InvalidDigest,
    #[error("KMS key material must not be empty")]
    EmptyKeyMaterial,
    #[error("KMS bulk requests must contain between 1 and 100 keys")]
    InvalidBulkSize,
    #[error("KMS bulk requests must not contain duplicate key IDs or names")]
    DuplicateBulkKey,
    #[error("KMS search text must contain at most 256 bytes without control characters")]
    InvalidSearch,
}

/// A validated Infisical KMS key identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct KmsKeyId(String);

impl KmsKeyId {
    /// Validate a UUID before it reaches a KMS URL path.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, KmsInputError> {
        let value = value.into();
        if !is_uuid(&value) {
            return Err(KmsInputError::InvalidKeyId);
        }
        Ok(Self(value))
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated lowercase Infisical KMS key name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct KmsKeyName(String);

impl KmsKeyName {
    /// Validate the pinned key-name slug contract.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or non-canonical slug.
    pub fn new(value: impl Into<String>) -> Result<Self, KmsInputError> {
        let value = value.into();
        if value.len() > MAX_KMS_KEY_NAME_BYTES
            || value.is_empty()
            || !value.split('-').all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
        {
            return Err(KmsInputError::InvalidKeyName);
        }
        Ok(Self(value))
    }

    /// Borrow the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Fixed purpose assigned to one KMS key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum KmsKeyUsage {
    /// Symmetric encryption and decryption.
    #[serde(rename = "encrypt-decrypt")]
    EncryptDecrypt,
    /// Asymmetric signing and verification.
    #[serde(rename = "sign-verify")]
    SignVerify,
}

/// Algorithms accepted by the pinned KMS key lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum KmsKeyAlgorithm {
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "RSA_4096")]
    Rsa4096,
    #[serde(rename = "ECC_NIST_P256")]
    EccNistP256,
    #[serde(rename = "ECC_NIST_P384")]
    EccNistP384,
    #[serde(rename = "ECC_NIST_P521")]
    EccNistP521,
    #[serde(rename = "ML_DSA_44")]
    MlDsa44,
    #[serde(rename = "ML_DSA_65")]
    MlDsa65,
    #[serde(rename = "ML_DSA_87")]
    MlDsa87,
}

impl KmsKeyAlgorithm {
    const fn usage(self) -> KmsKeyUsage {
        match self {
            Self::Aes256Gcm | Self::Aes128Gcm => KmsKeyUsage::EncryptDecrypt,
            Self::Rsa4096
            | Self::EccNistP256
            | Self::EccNistP384
            | Self::EccNistP521
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87 => KmsKeyUsage::SignVerify,
        }
    }

    fn signing_algorithms(self) -> &'static [KmsSigningAlgorithm] {
        match self {
            Self::Rsa4096 => &[
                KmsSigningAlgorithm::RsaPssSha512,
                KmsSigningAlgorithm::RsaPssSha384,
                KmsSigningAlgorithm::RsaPssSha256,
                KmsSigningAlgorithm::RsaPkcs1V15Sha512,
                KmsSigningAlgorithm::RsaPkcs1V15Sha384,
                KmsSigningAlgorithm::RsaPkcs1V15Sha256,
            ],
            Self::EccNistP256 | Self::EccNistP384 | Self::EccNistP521 => &[
                KmsSigningAlgorithm::EcdsaSha512,
                KmsSigningAlgorithm::EcdsaSha384,
                KmsSigningAlgorithm::EcdsaSha256,
            ],
            Self::MlDsa44 => &[KmsSigningAlgorithm::MlDsa44],
            Self::MlDsa65 => &[KmsSigningAlgorithm::MlDsa65],
            Self::MlDsa87 => &[KmsSigningAlgorithm::MlDsa87],
            Self::Aes256Gcm | Self::Aes128Gcm => &[],
        }
    }
}

/// Signature algorithms exposed by the pinned KMS signing routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[allow(clippy::enum_variant_names)]
pub enum KmsSigningAlgorithm {
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
    #[serde(rename = "ML_DSA_44")]
    MlDsa44,
    #[serde(rename = "ML_DSA_65")]
    MlDsa65,
    #[serde(rename = "ML_DSA_87")]
    MlDsa87,
}

impl KmsSigningAlgorithm {
    fn supports_key(self, key_algorithm: KmsKeyAlgorithm) -> bool {
        match key_algorithm {
            KmsKeyAlgorithm::Rsa4096 => matches!(
                self,
                Self::RsaPssSha512
                    | Self::RsaPssSha384
                    | Self::RsaPssSha256
                    | Self::RsaPkcs1V15Sha512
                    | Self::RsaPkcs1V15Sha384
                    | Self::RsaPkcs1V15Sha256
            ),
            KmsKeyAlgorithm::EccNistP256
            | KmsKeyAlgorithm::EccNistP384
            | KmsKeyAlgorithm::EccNistP521 => matches!(
                self,
                Self::EcdsaSha512 | Self::EcdsaSha384 | Self::EcdsaSha256
            ),
            KmsKeyAlgorithm::MlDsa44 => self == Self::MlDsa44,
            KmsKeyAlgorithm::MlDsa65 => self == Self::MlDsa65,
            KmsKeyAlgorithm::MlDsa87 => self == Self::MlDsa87,
            KmsKeyAlgorithm::Aes256Gcm | KmsKeyAlgorithm::Aes128Gcm => false,
        }
    }

    fn validate_key(self, key_algorithm: KmsKeyAlgorithm) -> Result<(), KmsInputError> {
        if !self.supports_key(key_algorithm) {
            return Err(KmsInputError::SigningAlgorithmMismatch);
        }
        Ok(())
    }

    const fn digest_bytes(self) -> Option<usize> {
        match self {
            Self::RsaPkcs1V15Sha512 | Self::EcdsaSha512 => Some(64),
            Self::RsaPkcs1V15Sha384 | Self::EcdsaSha384 => Some(48),
            Self::RsaPkcs1V15Sha256 | Self::EcdsaSha256 => Some(32),
            Self::RsaPssSha512
            | Self::RsaPssSha384
            | Self::RsaPssSha256
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87 => None,
        }
    }

    fn validate_digest(self, data_bytes: usize, is_digest: bool) -> Result<(), KmsInputError> {
        if !is_digest {
            return Ok(());
        }
        if self.digest_bytes() != Some(data_bytes) {
            return Err(KmsInputError::InvalidDigest);
        }
        Ok(())
    }
}

/// Value-free KMS key metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KmsKey {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub disabled: bool,
    pub project_id: String,
    pub key_usage: KmsKeyUsage,
    pub algorithm: KmsKeyAlgorithm,
    pub version: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// Validated settings for one new KMS key.
#[derive(Debug)]
pub struct KmsKeyCreation {
    name: KmsKeyName,
    description: Option<String>,
    key_usage: KmsKeyUsage,
    algorithm: KmsKeyAlgorithm,
}

impl KmsKeyCreation {
    /// Construct a key with a usage-compatible algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid description text or an algorithm mismatch.
    pub fn new(
        name: KmsKeyName,
        description: Option<String>,
        key_usage: KmsKeyUsage,
        algorithm: KmsKeyAlgorithm,
    ) -> Result<Self, KmsInputError> {
        validate_description(description.as_deref())?;
        if algorithm.usage() != key_usage {
            return Err(KmsInputError::AlgorithmUsageMismatch);
        }
        Ok(Self {
            name,
            description,
            key_usage,
            algorithm,
        })
    }
}

/// Partial KMS key metadata and status change.
#[derive(Debug)]
pub struct KmsKeyChange {
    name: Option<KmsKeyName>,
    description: Option<String>,
    disabled: Option<bool>,
}

impl KmsKeyChange {
    /// Construct a non-empty key change.
    ///
    /// `Some("")` clears the display description because the pinned API does
    /// not accept JSON null for this field.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty change or invalid description text.
    pub fn new(
        name: Option<KmsKeyName>,
        description: Option<String>,
        disabled: Option<bool>,
    ) -> Result<Self, KmsInputError> {
        validate_description(description.as_deref())?;
        if name.is_none() && description.is_none() && disabled.is_none() {
            return Err(KmsInputError::EmptyChange);
        }
        Ok(Self {
            name,
            description,
            disabled,
        })
    }
}

/// Bounded list and search coordinates for project KMS keys.
#[derive(Debug)]
pub struct KmsKeyListRequest {
    project_id: ProjectId,
    page: PageRequest,
    descending: bool,
    search: Option<String>,
}

impl KmsKeyListRequest {
    /// Construct a bounded server-side list request.
    ///
    /// # Errors
    ///
    /// Returns an error for unbounded or control-bearing search text.
    pub fn new(
        project_id: ProjectId,
        page: PageRequest,
        descending: bool,
        search: Option<String>,
    ) -> Result<Self, KmsInputError> {
        if search.as_deref().is_some_and(|value| {
            value.trim() != value
                || value.len() > MAX_KMS_SEARCH_BYTES
                || value.chars().any(char::is_control)
        }) {
            return Err(KmsInputError::InvalidSearch);
        }
        Ok(Self {
            project_id,
            page,
            descending,
            search,
        })
    }
}

/// Base64 data sent to an encrypt, sign, or verify operation.
#[derive(Debug)]
pub struct KmsData(SecretValue, usize);

impl KmsData {
    /// Validate and wrap sensitive operation data.
    ///
    /// # Errors
    ///
    /// Returns an error for non-base64 or oversized decoded data.
    pub fn new(value: SecretValue) -> Result<Self, KmsInputError> {
        let decoded_bytes = validate_base64(value.expose_secret(), MAX_KMS_PAYLOAD_BYTES, true)?;
        Ok(Self(value, decoded_bytes))
    }
}

/// Base64 ciphertext returned by Infisical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KmsCiphertext {
    pub key_id: String,
    pub ciphertext: String,
}

/// Plaintext returned only by the explicit decrypt reveal operation.
#[derive(Debug)]
pub struct KmsDecryptedData {
    pub key_id: String,
    pub plaintext: SecretValue,
}

/// Base64 key material accepted only at the import boundary.
#[derive(Debug)]
pub struct KmsKeyMaterial(SecretValue, usize, KmsKeyAlgorithm);

impl KmsKeyMaterial {
    /// Validate bounded base64 key material for the selected algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, malformed, oversized, or wrongly-sized
    /// symmetric key material.
    pub fn new(value: SecretValue, algorithm: KmsKeyAlgorithm) -> Result<Self, KmsInputError> {
        let decoded = validate_base64(value.expose_secret(), MAX_KMS_KEY_MATERIAL_BYTES, false)?;
        let valid_size = match algorithm {
            KmsKeyAlgorithm::Aes256Gcm => decoded == 32,
            KmsKeyAlgorithm::Aes128Gcm => decoded == 16,
            _ => decoded > 0,
        };
        if !valid_size {
            return Err(KmsInputError::EmptyKeyMaterial);
        }
        Ok(Self(value, decoded, algorithm))
    }
}

/// One validated key import entry.
#[derive(Debug)]
pub struct KmsBulkImportEntry {
    name: KmsKeyName,
    key_usage: KmsKeyUsage,
    algorithm: KmsKeyAlgorithm,
    key_material: KmsKeyMaterial,
}

impl KmsBulkImportEntry {
    /// Bind imported material to one key name, usage, and algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error when the usage, algorithm, or material binding disagree.
    pub fn new(
        name: KmsKeyName,
        key_usage: KmsKeyUsage,
        algorithm: KmsKeyAlgorithm,
        key_material: KmsKeyMaterial,
    ) -> Result<Self, KmsInputError> {
        if algorithm.usage() != key_usage {
            return Err(KmsInputError::AlgorithmUsageMismatch);
        }
        if algorithm != key_material.2 {
            return Err(KmsInputError::KeyMaterialAlgorithmMismatch);
        }
        Ok(Self {
            name,
            key_usage,
            algorithm,
            key_material,
        })
    }
}

/// Successfully imported key identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct KmsImportedKey {
    pub id: String,
    pub name: String,
}

/// One per-key import failure with a fixed local message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct KmsImportError {
    pub name: String,
    pub message: String,
}

/// Value-free bulk import result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KmsBulkImportResult {
    pub project_id: String,
    pub imported: Vec<KmsImportedKey>,
    pub errors: Vec<KmsImportError>,
}

/// One explicit private-key reveal.
#[derive(Debug)]
pub struct KmsPrivateKey {
    pub key_id: String,
    pub private_key: SecretValue,
}

/// One entry in an explicit bulk private-key reveal.
#[derive(Debug)]
pub struct KmsBulkPrivateKey {
    pub key_id: String,
    pub name: String,
    pub key_usage: KmsKeyUsage,
    pub algorithm: KmsKeyAlgorithm,
    pub private_key: SecretValue,
    pub public_key: Option<String>,
}

/// Public key returned for an asymmetric KMS key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KmsPublicKey {
    pub key_id: String,
    pub public_key: String,
}

/// Signing algorithms supported by one asymmetric KMS key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KmsSigningAlgorithms {
    pub key_id: String,
    pub signing_algorithms: Vec<KmsSigningAlgorithm>,
}

/// Signature produced by one exact KMS key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KmsSignature {
    pub key_id: String,
    pub signing_algorithm: KmsSigningAlgorithm,
    pub signature: String,
}

/// Signature verification result from one exact KMS key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KmsVerification {
    pub key_id: String,
    pub signing_algorithm: KmsSigningAlgorithm,
    pub signature_valid: bool,
}

fn validate_description(value: Option<&str>) -> Result<(), KmsInputError> {
    if value.is_some_and(|value| {
        value.trim() != value
            || value.len() > MAX_KMS_DESCRIPTION_BYTES
            || value.chars().any(char::is_control)
    }) {
        return Err(KmsInputError::InvalidDescription);
    }
    Ok(())
}

fn validate_base64(
    value: &str,
    max_decoded_bytes: usize,
    allow_empty: bool,
) -> Result<usize, KmsInputError> {
    if !allow_empty && value.is_empty() {
        return Err(KmsInputError::EmptyKeyMaterial);
    }
    let max_encoded_bytes = max_decoded_bytes.div_ceil(3) * 4;
    if value.len() > max_encoded_bytes {
        return Err(KmsInputError::PayloadTooLarge);
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| KmsInputError::InvalidBase64)?;
    if decoded.len() > max_decoded_bytes {
        return Err(KmsInputError::PayloadTooLarge);
    }
    if STANDARD.encode(&decoded) != value {
        return Err(KmsInputError::InvalidBase64);
    }
    Ok(decoded.len())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListKmsKeysQuery {
    project_id: String,
    offset: u32,
    limit: u16,
    order_by: KmsOrderBy,
    order_direction: KmsOrderDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    search: Option<String>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
enum KmsOrderBy {
    Name,
}

#[derive(Clone, Copy, Serialize)]
enum KmsOrderDirection {
    #[serde(rename = "asc")]
    Asc,
    #[serde(rename = "desc")]
    Desc,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListKmsKeysResponse {
    keys: Vec<KmsKeyWire>,
    total_count: u64,
}

#[derive(Serialize)]
struct GetKmsKeyQuery {
    #[serde(skip_serializing)]
    key_id: KmsKeyId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetKmsKeyByNameQuery {
    #[serde(skip_serializing)]
    key_name: KmsKeyName,
    project_id: String,
}

#[derive(Deserialize)]
struct KmsKeyResponse {
    key: KmsKeyWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KmsKeyWire {
    id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    is_disabled: bool,
    project_id: Option<String>,
    key_usage: KmsKeyUsage,
    encryption_algorithm: KmsKeyAlgorithm,
    version: u64,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateKmsKeyRequest {
    project_id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    key_usage: KmsKeyUsage,
    encryption_algorithm: KmsKeyAlgorithm,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateKmsKeyRequest {
    #[serde(skip_serializing)]
    key_id: KmsKeyId,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_disabled: Option<bool>,
}

#[derive(Serialize)]
struct DeleteKmsKeyRequest {
    #[serde(skip_serializing)]
    key_id: KmsKeyId,
}

#[derive(Serialize)]
struct KeyActionQuery {
    #[serde(skip_serializing)]
    key_id: KmsKeyId,
}

#[derive(Serialize)]
struct EncryptRequest {
    #[serde(skip_serializing)]
    key_id: KmsKeyId,
    #[serde(serialize_with = "serialize_secret")]
    plaintext: SecretValue,
}

#[derive(Deserialize)]
struct EncryptResponse {
    ciphertext: String,
}

#[derive(Serialize)]
struct DecryptRequest {
    #[serde(skip_serializing)]
    key_id: KmsKeyId,
    #[serde(serialize_with = "serialize_secret")]
    ciphertext: SecretValue,
}

#[derive(Deserialize)]
struct DecryptResponse {
    plaintext: DeserializedSecret,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyResponse {
    public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrivateKeyResponse {
    private_key: DeserializedSecret,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkImportRequest {
    project_id: String,
    keys: Vec<BulkImportEntryWire>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkImportEntryWire {
    name: String,
    key_usage: KmsKeyUsage,
    encryption_algorithm: KmsKeyAlgorithm,
    #[serde(serialize_with = "serialize_secret")]
    key_material: SecretValue,
}

#[derive(Deserialize)]
struct BulkImportResponse {
    keys: Vec<KmsImportedKeyWire>,
    errors: Vec<KmsImportErrorWire>,
}

#[derive(Deserialize)]
struct KmsImportErrorWire {
    name: String,
    message: DeserializedSecret,
}

#[derive(Deserialize)]
struct KmsImportedKeyWire {
    id: String,
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkPrivateKeyRequest {
    key_ids: Vec<String>,
}

#[derive(Deserialize)]
struct BulkPrivateKeyResponse {
    keys: Vec<BulkPrivateKeyWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkPrivateKeyWire {
    key_id: String,
    name: String,
    key_usage: KmsKeyUsage,
    algorithm: KmsKeyAlgorithm,
    private_key: DeserializedSecret,
    #[serde(default)]
    public_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningAlgorithmsResponse {
    signing_algorithms: Vec<KmsSigningAlgorithm>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignRequest {
    #[serde(skip_serializing)]
    key_id: KmsKeyId,
    signing_algorithm: KmsSigningAlgorithm,
    is_digest: bool,
    #[serde(serialize_with = "serialize_secret")]
    data: SecretValue,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignResponse {
    signature: String,
    key_id: String,
    signing_algorithm: KmsSigningAlgorithm,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest {
    #[serde(skip_serializing)]
    key_id: KmsKeyId,
    signing_algorithm: KmsSigningAlgorithm,
    is_digest: bool,
    #[serde(serialize_with = "serialize_secret")]
    data: SecretValue,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyResponse {
    signature_valid: bool,
    key_id: String,
    signing_algorithm: KmsSigningAlgorithm,
}

fn serialize_secret<S>(value: &SecretValue, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.expose_secret())
}

struct ListKmsKeys;
impl sealed::Sealed for ListKmsKeys {}
impl ObservableReadOperation for ListKmsKeys {
    type Query = ListKmsKeysQuery;
    type Output = ListKmsKeysResponse;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "kms/keys")
    }
}

struct GetKmsKey;
impl sealed::Sealed for GetKmsKey {}
impl ObservableReadOperation for GetKmsKey {
    type Query = GetKmsKeyQuery;
    type Output = KmsKeyResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["kms", "keys", query.key_id.as_str()])
    }
}

struct GetKmsKeyByName;
impl sealed::Sealed for GetKmsKeyByName {}
impl ObservableReadOperation for GetKmsKeyByName {
    type Query = GetKmsKeyByNameQuery;
    type Output = KmsKeyResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["kms", "keys", "key-name", query.key_name.as_str()],
        )
    }
}

macro_rules! kms_mutation {
    ($operation:ident, $input:ty, $output:ty, $method:expr, $suffix:expr) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl MutationOperation for $operation {
            type Input = $input;
            type Output = $output;

            fn method() -> Method {
                $method
            }

            fn endpoint(input: &Self::Input) -> Endpoint {
                let mut segments = vec!["kms".to_owned(), "keys".to_owned()];
                segments.extend(($suffix)(input));
                Endpoint::from_segments(ApiVersion::V1, segments)
            }
        }
    };
}

kms_mutation!(
    CreateKmsKey,
    CreateKmsKeyRequest,
    KmsKeyResponse,
    Method::POST,
    |_input: &CreateKmsKeyRequest| Vec::<String>::new()
);
kms_mutation!(
    UpdateKmsKey,
    UpdateKmsKeyRequest,
    KmsKeyResponse,
    Method::PATCH,
    |input: &UpdateKmsKeyRequest| vec![input.key_id.as_str().to_owned()]
);
kms_mutation!(
    DeleteKmsKey,
    DeleteKmsKeyRequest,
    KmsKeyResponse,
    Method::DELETE,
    |input: &DeleteKmsKeyRequest| vec![input.key_id.as_str().to_owned()]
);
kms_mutation!(
    Encrypt,
    EncryptRequest,
    EncryptResponse,
    Method::POST,
    |input: &EncryptRequest| vec![input.key_id.as_str().to_owned(), "encrypt".to_owned()]
);
kms_mutation!(
    Decrypt,
    DecryptRequest,
    DecryptResponse,
    Method::POST,
    |input: &DecryptRequest| vec![input.key_id.as_str().to_owned(), "decrypt".to_owned()]
);
kms_mutation!(
    BulkImport,
    BulkImportRequest,
    BulkImportResponse,
    Method::POST,
    |_input: &BulkImportRequest| vec!["bulk-import".to_owned()]
);
kms_mutation!(
    BulkPrivateKeyReveal,
    BulkPrivateKeyRequest,
    BulkPrivateKeyResponse,
    Method::POST,
    |_input: &BulkPrivateKeyRequest| vec!["bulk-export-private-keys".to_owned()]
);
kms_mutation!(
    Sign,
    SignRequest,
    SignResponse,
    Method::POST,
    |input: &SignRequest| vec![input.key_id.as_str().to_owned(), "sign".to_owned()]
);
kms_mutation!(
    Verify,
    VerifyRequest,
    VerifyResponse,
    Method::POST,
    |input: &VerifyRequest| vec![input.key_id.as_str().to_owned(), "verify".to_owned()]
);

struct GetPublicKey;
impl sealed::Sealed for GetPublicKey {}
impl ObservableReadOperation for GetPublicKey {
    type Query = KeyActionQuery;
    type Output = PublicKeyResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["kms", "keys", query.key_id.as_str(), "public-key"],
        )
    }
}

struct GetPrivateKey;
impl sealed::Sealed for GetPrivateKey {}
impl ObservableReadOperation for GetPrivateKey {
    type Query = KeyActionQuery;
    type Output = PrivateKeyResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["kms", "keys", query.key_id.as_str(), "private-key"],
        )
    }
}

struct ListSigningAlgorithms;
impl sealed::Sealed for ListSigningAlgorithms {}
impl ObservableReadOperation for ListSigningAlgorithms {
    type Query = KeyActionQuery;
    type Output = SigningAlgorithmsResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["kms", "keys", query.key_id.as_str(), "signing-algorithms"],
        )
    }
}

fn kms_key_from_wire(
    wire: KmsKeyWire,
    project_id: &ProjectId,
    expected_id: Option<&KmsKeyId>,
    expected_name: Option<&KmsKeyName>,
) -> Result<KmsKey, ResourceError> {
    let id = KmsKeyId::new(wire.id).map_err(|_| ResourceError::InvalidKmsResponse)?;
    let name = KmsKeyName::new(wire.name).map_err(|_| ResourceError::InvalidKmsResponse)?;
    validate_description(wire.description.as_deref())
        .map_err(|_| ResourceError::InvalidKmsResponse)?;
    if wire.project_id.as_deref() != Some(project_id.as_str())
        || wire.encryption_algorithm.usage() != wire.key_usage
        || expected_id.is_some_and(|expected| expected != &id)
        || expected_name.is_some_and(|expected| expected != &name)
        || wire.version == 0
        || !is_bounded_text(&wire.created_at, 128)
        || !is_bounded_text(&wire.updated_at, 128)
    {
        return Err(ResourceError::InvalidKmsResponse);
    }
    Ok(KmsKey {
        id: id.as_str().to_owned(),
        name: name.as_str().to_owned(),
        description: wire.description,
        disabled: wire.is_disabled,
        project_id: project_id.as_str().to_owned(),
        key_usage: wire.key_usage,
        algorithm: wire.encryption_algorithm,
        version: wire.version,
        created_at: wire.created_at,
        updated_at: wire.updated_at,
    })
}

fn created_kms_key_from_wire(
    wire: KmsKeyWire,
    project_id: &ProjectId,
    creation: &KmsKeyCreation,
) -> Result<KmsKey, ResourceError> {
    let key = kms_key_from_wire(wire, project_id, None, Some(&creation.name))?;
    if key.description != creation.description || key.algorithm != creation.algorithm {
        return Err(ResourceError::InvalidKmsResponse);
    }
    Ok(key)
}

fn updated_kms_key_from_wire(
    wire: KmsKeyWire,
    project_id: &ProjectId,
    key_id: &KmsKeyId,
    change: &KmsKeyChange,
) -> Result<KmsKey, ResourceError> {
    let key = kms_key_from_wire(wire, project_id, Some(key_id), change.name.as_ref())?;
    if change
        .description
        .as_ref()
        .is_some_and(|description| key.description.as_ref() != Some(description))
        || change
            .disabled
            .is_some_and(|disabled| key.disabled != disabled)
    {
        return Err(ResourceError::InvalidKmsResponse);
    }
    Ok(key)
}

impl InfisicalClient {
    async fn ensure_kms_project(&self, project_id: &ProjectId) -> Result<(), ResourceError> {
        let project = self.get_project(project_id).await?;
        if project.as_ref().map(|project| project.id.as_str()) != Some(project_id.as_str()) {
            return Err(ResourceError::InvalidKmsKeyScope);
        }
        Ok(())
    }

    async fn preflight_kms_key(
        &self,
        project_id: &ProjectId,
        key_id: &KmsKeyId,
        usage: Option<KmsKeyUsage>,
    ) -> Result<KmsKey, ResourceError> {
        let key = self.get_kms_key(project_id, key_id).await?;
        if usage.is_some_and(|usage| key.key_usage != usage) {
            return Err(ResourceError::InvalidKmsKeyUsage);
        }
        Ok(key)
    }

    async fn preflight_active_kms_key(
        &self,
        project_id: &ProjectId,
        key_id: &KmsKeyId,
        usage: Option<KmsKeyUsage>,
    ) -> Result<KmsKey, ResourceError> {
        let key = self.preflight_kms_key(project_id, key_id, usage).await?;
        if key.disabled {
            return Err(ResourceError::KmsKeyDisabled);
        }
        Ok(key)
    }

    /// List one bounded, audited page of value-free project KMS keys.
    ///
    /// # Errors
    ///
    /// Returns a typed client, response-contract, or pagination error.
    pub async fn list_kms_keys(
        &self,
        request: KmsKeyListRequest,
    ) -> Result<Page<KmsKey>, ResourceError> {
        let response = self
            .execute_observable_read::<ListKmsKeys>(&ListKmsKeysQuery {
                project_id: request.project_id.as_str().to_owned(),
                offset: request.page.offset(),
                limit: request.page.limit(),
                order_by: KmsOrderBy::Name,
                order_direction: if request.descending {
                    KmsOrderDirection::Desc
                } else {
                    KmsOrderDirection::Asc
                },
                search: request.search,
            })
            .await?;
        let returned =
            u64::try_from(response.keys.len()).map_err(|_| ResourceError::InvalidKmsResponse)?;
        let offset = u64::from(request.page.offset());
        let end = offset
            .checked_add(returned)
            .ok_or(ResourceError::InvalidKmsResponse)?;
        let returned_below_limit = response.keys.len() < usize::from(request.page.limit());
        let page_fits_total = if returned == 0 {
            offset >= response.total_count
        } else if returned_below_limit {
            end == response.total_count
        } else {
            end <= response.total_count
        };
        if response.keys.len() > usize::from(request.page.limit()) || !page_fits_total {
            return Err(ResourceError::InvalidKmsResponse);
        }
        let keys = response
            .keys
            .into_iter()
            .map(|key| kms_key_from_wire(key, &request.project_id, None, None))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Page::new(request.page, keys, Some(response.total_count))?)
    }

    /// Get one exact, audited KMS key by ID.
    ///
    /// # Errors
    ///
    /// Returns a typed client or response-contract error.
    pub async fn get_kms_key(
        &self,
        project_id: &ProjectId,
        key_id: &KmsKeyId,
    ) -> Result<KmsKey, ResourceError> {
        let response = self
            .execute_observable_read::<GetKmsKey>(&GetKmsKeyQuery {
                key_id: key_id.clone(),
            })
            .await?;
        kms_key_from_wire(response.key, project_id, Some(key_id), None)
    }

    /// Get one exact, audited KMS key by project and name.
    ///
    /// # Errors
    ///
    /// Returns a typed client or response-contract error.
    pub async fn get_kms_key_by_name(
        &self,
        project_id: &ProjectId,
        key_name: &KmsKeyName,
    ) -> Result<KmsKey, ResourceError> {
        let response = self
            .execute_observable_read::<GetKmsKeyByName>(&GetKmsKeyByNameQuery {
                key_name: key_name.clone(),
                project_id: project_id.as_str().to_owned(),
            })
            .await?;
        kms_key_from_wire(response.key, project_id, None, Some(key_name))
    }

    /// Create one project KMS key after validating its owning project.
    ///
    /// # Errors
    ///
    /// Returns a scope, typed client, or response-contract error. The mutation
    /// is sent exactly once.
    pub async fn create_kms_key(
        &self,
        project_id: &ProjectId,
        creation: KmsKeyCreation,
        confirm: bool,
    ) -> Result<KmsKey, ResourceError> {
        if !confirm {
            return Err(ResourceError::KmsOperationNotConfirmed);
        }
        self.ensure_kms_project(project_id).await?;
        let request = CreateKmsKeyRequest {
            project_id: project_id.as_str().to_owned(),
            name: creation.name.as_str().to_owned(),
            description: creation.description.clone(),
            key_usage: creation.key_usage,
            encryption_algorithm: creation.algorithm,
        };
        let response = self.execute_mutation::<CreateKmsKey>(&request).await?;
        created_kms_key_from_wire(response.key, project_id, &creation)
    }

    /// Update one exact KMS key after confirmation and scope preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    pub async fn update_kms_key(
        &self,
        project_id: &ProjectId,
        key_id: &KmsKeyId,
        change: KmsKeyChange,
        confirm: bool,
    ) -> Result<KmsKey, ResourceError> {
        if !confirm {
            return Err(ResourceError::KmsOperationNotConfirmed);
        }
        self.preflight_kms_key(project_id, key_id, None).await?;
        let request = UpdateKmsKeyRequest {
            key_id: key_id.clone(),
            name: change.name.as_ref().map(|name| name.as_str().to_owned()),
            description: change.description.clone(),
            is_disabled: change.disabled,
        };
        let response = self.execute_mutation::<UpdateKmsKey>(&request).await?;
        updated_kms_key_from_wire(response.key, project_id, key_id, &change)
    }

    /// Delete one exact KMS key after confirmation and scope preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    pub async fn delete_kms_key(
        &self,
        project_id: &ProjectId,
        key_id: &KmsKeyId,
        confirm: bool,
    ) -> Result<KmsKey, ResourceError> {
        if !confirm {
            return Err(ResourceError::KmsKeyDeletionNotConfirmed);
        }
        self.preflight_kms_key(project_id, key_id, None).await?;
        let response = self
            .execute_mutation::<DeleteKmsKey>(&DeleteKmsKeyRequest {
                key_id: key_id.clone(),
            })
            .await?;
        kms_key_from_wire(response.key, project_id, Some(key_id), None)
    }

    /// Encrypt base64 data with one exact symmetric KMS key.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, usage, typed client, or bounded-response error.
    pub async fn kms_encrypt(
        &self,
        project_id: &ProjectId,
        key_id: &KmsKeyId,
        data: KmsData,
        confirm: bool,
    ) -> Result<KmsCiphertext, ResourceError> {
        if !confirm {
            return Err(ResourceError::KmsOperationNotConfirmed);
        }
        self.preflight_active_kms_key(project_id, key_id, Some(KmsKeyUsage::EncryptDecrypt))
            .await?;
        let response = self
            .execute_mutation::<Encrypt>(&EncryptRequest {
                key_id: key_id.clone(),
                plaintext: data.0,
            })
            .await?;
        validate_base64(&response.ciphertext, MAX_KMS_CIPHERTEXT_BYTES, false)
            .map_err(|_| ResourceError::InvalidKmsResponse)?;
        Ok(KmsCiphertext {
            key_id: key_id.as_str().to_owned(),
            ciphertext: response.ciphertext,
        })
    }

    /// Decrypt one base64 ciphertext through the explicit reveal boundary.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, usage, typed client, or bounded-response error.
    pub async fn kms_decrypt(
        &self,
        project_id: &ProjectId,
        key_id: &KmsKeyId,
        ciphertext: SecretValue,
        confirm_reveal: bool,
    ) -> Result<KmsDecryptedData, ResourceError> {
        if !confirm_reveal {
            return Err(ResourceError::KmsSecretRevealNotConfirmed);
        }
        validate_base64(ciphertext.expose_secret(), MAX_KMS_CIPHERTEXT_BYTES, false)
            .map_err(|_| ResourceError::InvalidKmsCryptographicInput)?;
        self.preflight_active_kms_key(project_id, key_id, Some(KmsKeyUsage::EncryptDecrypt))
            .await?;
        let response = self
            .execute_mutation::<Decrypt>(&DecryptRequest {
                key_id: key_id.clone(),
                ciphertext,
            })
            .await?;
        validate_base64(
            response.plaintext.0.expose_secret(),
            MAX_KMS_PAYLOAD_BYTES,
            true,
        )
        .map_err(|_| ResourceError::InvalidKmsResponse)?;
        Ok(KmsDecryptedData {
            key_id: key_id.as_str().to_owned(),
            plaintext: response.plaintext.0,
        })
    }

    /// Get the public key for one exact asymmetric KMS key.
    ///
    /// # Errors
    ///
    /// Returns a scope, usage, typed client, or bounded-response error.
    pub async fn get_kms_public_key(
        &self,
        project_id: &ProjectId,
        key_id: &KmsKeyId,
    ) -> Result<KmsPublicKey, ResourceError> {
        self.preflight_active_kms_key(project_id, key_id, Some(KmsKeyUsage::SignVerify))
            .await?;
        let response = self
            .execute_observable_read::<GetPublicKey>(&KeyActionQuery {
                key_id: key_id.clone(),
            })
            .await?;
        validate_base64(&response.public_key, MAX_KMS_PUBLIC_KEY_BYTES, false)
            .map_err(|_| ResourceError::InvalidKmsResponse)?;
        Ok(KmsPublicKey {
            key_id: key_id.as_str().to_owned(),
            public_key: response.public_key,
        })
    }

    /// Reveal private key material for one exact KMS key.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or bounded-response error.
    pub async fn reveal_kms_private_key(
        &self,
        project_id: &ProjectId,
        key_id: &KmsKeyId,
        confirm_reveal: bool,
    ) -> Result<KmsPrivateKey, ResourceError> {
        if !confirm_reveal {
            return Err(ResourceError::KmsSecretRevealNotConfirmed);
        }
        self.preflight_active_kms_key(project_id, key_id, None)
            .await?;
        let response = self
            .execute_observable_read::<GetPrivateKey>(&KeyActionQuery {
                key_id: key_id.clone(),
            })
            .await?;
        validate_base64(
            response.private_key.0.expose_secret(),
            MAX_KMS_PRIVATE_KEY_BYTES,
            false,
        )
        .map_err(|_| ResourceError::InvalidKmsResponse)?;
        Ok(KmsPrivateKey {
            key_id: key_id.as_str().to_owned(),
            private_key: response.private_key.0,
        })
    }

    /// Import one to one hundred typed keys within the aggregate material bound.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, bounded-input, typed client, or response error.
    pub async fn bulk_import_kms_keys(
        &self,
        project_id: &ProjectId,
        entries: Vec<KmsBulkImportEntry>,
        confirm: bool,
    ) -> Result<KmsBulkImportResult, ResourceError> {
        if !confirm {
            return Err(ResourceError::KmsOperationNotConfirmed);
        }
        validate_bulk_import_entries(&entries).map_err(|_| ResourceError::InvalidKmsBulkRequest)?;
        let expected_names = entries
            .iter()
            .map(|entry| entry.name.as_str().to_owned())
            .collect::<HashSet<_>>();
        self.ensure_kms_project(project_id).await?;
        let response = self
            .execute_mutation::<BulkImport>(&BulkImportRequest {
                project_id: project_id.as_str().to_owned(),
                keys: entries
                    .into_iter()
                    .map(|entry| BulkImportEntryWire {
                        name: entry.name.as_str().to_owned(),
                        key_usage: entry.key_usage,
                        encryption_algorithm: entry.algorithm,
                        key_material: entry.key_material.0,
                    })
                    .collect(),
            })
            .await?;
        if response.keys.len() + response.errors.len() != expected_names.len() {
            return Err(ResourceError::InvalidKmsResponse);
        }
        let mut returned_names = HashSet::new();
        let imported = response
            .keys
            .into_iter()
            .map(|key| {
                let id = KmsKeyId::new(key.id).map_err(|_| ResourceError::InvalidKmsResponse)?;
                let name =
                    KmsKeyName::new(key.name).map_err(|_| ResourceError::InvalidKmsResponse)?;
                if !expected_names.contains(name.as_str())
                    || !returned_names.insert(name.as_str().to_owned())
                {
                    return Err(ResourceError::InvalidKmsResponse);
                }
                Ok(KmsImportedKey {
                    id: id.as_str().to_owned(),
                    name: name.as_str().to_owned(),
                })
            })
            .collect::<Result<Vec<_>, ResourceError>>()?;
        let errors = response
            .errors
            .into_iter()
            .map(|error| {
                let name =
                    KmsKeyName::new(error.name).map_err(|_| ResourceError::InvalidKmsResponse)?;
                if !expected_names.contains(name.as_str())
                    || !returned_names.insert(name.as_str().to_owned())
                {
                    return Err(ResourceError::InvalidKmsResponse);
                }
                let _redacted_upstream_message = error.message;
                Ok(KmsImportError {
                    name: name.as_str().to_owned(),
                    message: KMS_IMPORT_REJECTION_MESSAGE.to_owned(),
                })
            })
            .collect::<Result<Vec<_>, ResourceError>>()?;
        Ok(KmsBulkImportResult {
            project_id: project_id.as_str().to_owned(),
            imported,
            errors,
        })
    }

    async fn preflight_bulk_kms_keys(
        &self,
        project_id: &ProjectId,
        key_ids: &[KmsKeyId],
    ) -> Result<HashMap<String, KmsKey>, ResourceError> {
        let deadline = tokio::time::Instant::now() + self.preflight_timeout();
        let mut observed = HashMap::new();
        // Each concurrent future owns its identifier rather than borrowing the iterator.
        let mut preflights = stream::iter(key_ids.to_vec())
            .map(|key_id| async move {
                self.preflight_active_kms_key(project_id, &key_id, None)
                    .await
            })
            .buffer_unordered(MAX_CONCURRENT_KMS_PREFLIGHTS);
        loop {
            let next = tokio::time::timeout_at(deadline, preflights.next())
                .await
                .map_err(|_| ResourceError::KmsBulkPreflightTimeout {
                    validated: observed.len(),
                    requested: key_ids.len(),
                })?;
            if tokio::time::Instant::now() >= deadline {
                return Err(ResourceError::KmsBulkPreflightTimeout {
                    validated: observed.len(),
                    requested: key_ids.len(),
                });
            }
            let Some(result) = next else { break };
            let key = result.map_err(|source| ResourceError::KmsBulkPreflightFailed {
                validated: observed.len(),
                requested: key_ids.len(),
                source: Box::new(source),
            })?;
            observed.insert(key.id.clone(), key);
        }
        Ok(observed)
    }

    /// Reveal private material for exact project keys, returning the caller's order.
    ///
    /// Independent preflight reads use bounded concurrency and a shared total
    /// deadline. Every key must validate before the final bulk request is sent.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, duplicate, partial-preflight, typed client, or
    /// response error. A partial-preflight error means the bulk request was not
    /// sent; completed and cancelled reads may have created upstream access events.
    pub async fn bulk_reveal_kms_private_keys(
        &self,
        project_id: &ProjectId,
        key_ids: Vec<KmsKeyId>,
        confirm_reveal: bool,
    ) -> Result<Vec<KmsBulkPrivateKey>, ResourceError> {
        if !confirm_reveal {
            return Err(ResourceError::KmsSecretRevealNotConfirmed);
        }
        validate_bulk_key_ids(&key_ids).map_err(|_| ResourceError::InvalidKmsBulkRequest)?;
        let observed = self.preflight_bulk_kms_keys(project_id, &key_ids).await?;
        let expected = key_ids
            .iter()
            .enumerate()
            .map(|(index, key_id)| (key_id.as_str(), index))
            .collect::<HashMap<_, _>>();
        let response = self
            .execute_mutation::<BulkPrivateKeyReveal>(&BulkPrivateKeyRequest {
                key_ids: key_ids
                    .iter()
                    .map(|key_id| key_id.as_str().to_owned())
                    .collect(),
            })
            .await?;
        if response.keys.len() != key_ids.len() {
            return Err(ResourceError::InvalidKmsResponse);
        }
        let mut seen = HashSet::new();
        let mut validated = response
            .keys
            .into_iter()
            .map(|key| {
                let key_id =
                    KmsKeyId::new(key.key_id).map_err(|_| ResourceError::InvalidKmsResponse)?;
                let name =
                    KmsKeyName::new(key.name).map_err(|_| ResourceError::InvalidKmsResponse)?;
                let Some(preflight) = observed.get(key_id.as_str()) else {
                    return Err(ResourceError::InvalidKmsResponse);
                };
                let Some(&index) = expected.get(key_id.as_str()) else {
                    return Err(ResourceError::InvalidKmsResponse);
                };
                if !seen.insert(key_id.as_str().to_owned())
                    || key.algorithm.usage() != key.key_usage
                    || name.as_str() != preflight.name
                    || key.key_usage != preflight.key_usage
                    || key.algorithm != preflight.algorithm
                {
                    return Err(ResourceError::InvalidKmsResponse);
                }
                validate_base64(
                    key.private_key.0.expose_secret(),
                    MAX_KMS_PRIVATE_KEY_BYTES,
                    false,
                )
                .map_err(|_| ResourceError::InvalidKmsResponse)?;
                if let Some(public_key) = key.public_key.as_deref() {
                    validate_base64(public_key, MAX_KMS_PUBLIC_KEY_BYTES, false)
                        .map_err(|_| ResourceError::InvalidKmsResponse)?;
                }
                Ok((
                    index,
                    KmsBulkPrivateKey {
                        key_id: key_id.as_str().to_owned(),
                        name: name.as_str().to_owned(),
                        key_usage: key.key_usage,
                        algorithm: key.algorithm,
                        private_key: key.private_key.0,
                        public_key: key.public_key,
                    },
                ))
            })
            .collect::<Result<Vec<_>, ResourceError>>()?;
        validated.sort_unstable_by_key(|(index, _)| *index);
        Ok(validated.into_iter().map(|(_, key)| key).collect())
    }

    /// List signing algorithms for one exact asymmetric KMS key.
    ///
    /// # Errors
    ///
    /// Returns a scope, usage, typed client, or response-contract error.
    pub async fn list_kms_signing_algorithms(
        &self,
        project_id: &ProjectId,
        key_id: &KmsKeyId,
    ) -> Result<KmsSigningAlgorithms, ResourceError> {
        let key = self
            .preflight_active_kms_key(project_id, key_id, Some(KmsKeyUsage::SignVerify))
            .await?;
        let response = self
            .execute_observable_read::<ListSigningAlgorithms>(&KeyActionQuery {
                key_id: key_id.clone(),
            })
            .await?;
        let expected = key.algorithm.signing_algorithms();
        if expected.is_empty() || response.signing_algorithms.len() != expected.len() {
            return Err(ResourceError::InvalidKmsResponse);
        }
        let unique = response
            .signing_algorithms
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let expected = expected.iter().copied().collect::<HashSet<_>>();
        if unique != expected {
            return Err(ResourceError::InvalidKmsResponse);
        }
        Ok(KmsSigningAlgorithms {
            key_id: key_id.as_str().to_owned(),
            signing_algorithms: response.signing_algorithms,
        })
    }

    /// Sign base64 data with one exact asymmetric KMS key.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, usage, typed client, or reflected-response error.
    pub async fn kms_sign(
        &self,
        project_id: &ProjectId,
        key_id: &KmsKeyId,
        data: KmsData,
        signing_algorithm: KmsSigningAlgorithm,
        is_digest: bool,
        confirm: bool,
    ) -> Result<KmsSignature, ResourceError> {
        if !confirm {
            return Err(ResourceError::KmsOperationNotConfirmed);
        }
        signing_algorithm
            .validate_digest(data.1, is_digest)
            .map_err(|_| ResourceError::InvalidKmsCryptographicInput)?;
        let key = self
            .preflight_active_kms_key(project_id, key_id, Some(KmsKeyUsage::SignVerify))
            .await?;
        signing_algorithm
            .validate_key(key.algorithm)
            .map_err(|_| ResourceError::InvalidKmsCryptographicInput)?;
        let response = self
            .execute_mutation::<Sign>(&SignRequest {
                key_id: key_id.clone(),
                signing_algorithm,
                is_digest,
                data: data.0,
            })
            .await?;
        if response.key_id != key_id.as_str() || response.signing_algorithm != signing_algorithm {
            return Err(ResourceError::InvalidKmsResponse);
        }
        validate_base64(&response.signature, MAX_KMS_SIGNATURE_BYTES, false)
            .map_err(|_| ResourceError::InvalidKmsResponse)?;
        Ok(KmsSignature {
            key_id: response.key_id,
            signing_algorithm: response.signing_algorithm,
            signature: response.signature,
        })
    }

    /// Verify a base64 signature with one exact asymmetric KMS key.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, usage, typed client, or reflected-response error.
    #[allow(clippy::too_many_arguments)]
    pub async fn kms_verify(
        &self,
        project_id: &ProjectId,
        key_id: &KmsKeyId,
        data: KmsData,
        signature: String,
        signing_algorithm: KmsSigningAlgorithm,
        is_digest: bool,
        confirm: bool,
    ) -> Result<KmsVerification, ResourceError> {
        if !confirm {
            return Err(ResourceError::KmsOperationNotConfirmed);
        }
        validate_base64(&signature, MAX_KMS_SIGNATURE_BYTES, false)
            .map_err(|_| ResourceError::InvalidKmsCryptographicInput)?;
        signing_algorithm
            .validate_digest(data.1, is_digest)
            .map_err(|_| ResourceError::InvalidKmsCryptographicInput)?;
        let key = self
            .preflight_active_kms_key(project_id, key_id, Some(KmsKeyUsage::SignVerify))
            .await?;
        signing_algorithm
            .validate_key(key.algorithm)
            .map_err(|_| ResourceError::InvalidKmsCryptographicInput)?;
        let response = self
            .execute_mutation::<Verify>(&VerifyRequest {
                key_id: key_id.clone(),
                signing_algorithm,
                is_digest,
                data: data.0,
                signature,
            })
            .await?;
        if response.key_id != key_id.as_str() || response.signing_algorithm != signing_algorithm {
            return Err(ResourceError::InvalidKmsResponse);
        }
        Ok(KmsVerification {
            key_id: response.key_id,
            signing_algorithm: response.signing_algorithm,
            signature_valid: response.signature_valid,
        })
    }
}

fn validate_bulk_import_entries(entries: &[KmsBulkImportEntry]) -> Result<(), KmsInputError> {
    if entries.is_empty() || entries.len() > MAX_KMS_BULK_KEYS {
        return Err(KmsInputError::InvalidBulkSize);
    }
    let mut names = HashSet::new();
    if entries
        .iter()
        .any(|entry| !names.insert(entry.name.as_str()))
    {
        return Err(KmsInputError::DuplicateBulkKey);
    }
    let material_bytes = entries
        .iter()
        .try_fold(0_usize, |total, entry| {
            total.checked_add(entry.key_material.1)
        })
        .ok_or(KmsInputError::PayloadTooLarge)?;
    if material_bytes > MAX_KMS_PAYLOAD_BYTES {
        return Err(KmsInputError::PayloadTooLarge);
    }
    Ok(())
}

fn validate_bulk_key_ids(key_ids: &[KmsKeyId]) -> Result<(), KmsInputError> {
    if key_ids.is_empty() || key_ids.len() > MAX_KMS_BULK_KEYS {
        return Err(KmsInputError::InvalidBulkSize);
    }
    let mut ids = HashSet::new();
    if key_ids.iter().any(|key_id| !ids.insert(key_id.as_str())) {
        return Err(KmsInputError::DuplicateBulkKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use reqwest::Method;
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path, query_param},
    };

    use crate::{
        InfisicalClient, KmsBulkImportEntry, KmsBulkImportResult, KmsData, KmsInputError,
        KmsKeyAlgorithm, KmsKeyChange, KmsKeyCreation, KmsKeyId, KmsKeyListRequest, KmsKeyMaterial,
        KmsKeyName, KmsKeyUsage, KmsSigningAlgorithm, PageRequest, ProjectId, ResourceError,
        SecretValue,
        test_support::{mount_login, settings},
    };

    use super::{
        KMS_IMPORT_REJECTION_MESSAGE, KmsKeyWire, MAX_KMS_CIPHERTEXT_BYTES,
        MAX_KMS_KEY_MATERIAL_BYTES, MAX_KMS_PAYLOAD_BYTES, MAX_KMS_PRIVATE_KEY_BYTES,
        MAX_KMS_PUBLIC_KEY_BYTES, MAX_KMS_SIGNATURE_BYTES, created_kms_key_from_wire,
        kms_key_from_wire, updated_kms_key_from_wire, validate_base64,
        validate_bulk_import_entries, validate_bulk_key_ids, validate_description,
    };

    const KMS_SIGNING_ALGORITHM_COUNT: usize = 12;
    const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const KEY_ID: &str = "22222222-2222-4222-8222-222222222222";
    const SIGNING_KEY_ID: &str = "33333333-3333-4333-8333-333333333333";

    fn project_fixture() -> Value {
        json!({
            "project": {
                "id": PROJECT_ID,
                "name": "KMS",
                "slug": "kms",
                "type": "kms",
                "orgId": "44444444-4444-4444-8444-444444444444",
                "description": null,
                "environments": []
            }
        })
    }

    fn key_fixture(id: &str, name: &str, usage: &str, algorithm: &str) -> Value {
        json!({
            "id": id,
            "name": name,
            "description": "application key",
            "isDisabled": false,
            "orgId": "44444444-4444-4444-8444-444444444444",
            "projectId": PROJECT_ID,
            "keyUsage": usage,
            "encryptionAlgorithm": algorithm,
            "version": 1,
            "createdAt": "2026-07-20T01:02:03.000Z",
            "updatedAt": "2026-07-20T01:02:03.000Z"
        })
    }

    fn project_id() -> ProjectId {
        ProjectId::new(PROJECT_ID).unwrap()
    }

    fn key_id() -> KmsKeyId {
        KmsKeyId::new(KEY_ID).unwrap()
    }

    fn import_entry_with_material(
        name: &str,
        algorithm: KmsKeyAlgorithm,
        decoded_bytes: usize,
    ) -> KmsBulkImportEntry {
        KmsBulkImportEntry::new(
            KmsKeyName::new(name).unwrap(),
            algorithm.usage(),
            algorithm,
            KmsKeyMaterial::new(
                SecretValue::new(STANDARD.encode(vec![7_u8; decoded_bytes])),
                algorithm,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn import_entry(name: &str) -> KmsBulkImportEntry {
        import_entry_with_material(name, KmsKeyAlgorithm::Aes256Gcm, 32)
    }

    fn import_entries(count: usize) -> Vec<KmsBulkImportEntry> {
        (0..count)
            .map(|index| import_entry(&format!("key-{index}")))
            .collect()
    }

    fn key_ids(count: usize) -> Vec<KmsKeyId> {
        (0..count)
            .map(|index| {
                KmsKeyId::new(format!("00000000-0000-4000-8000-{index:012}"))
                    .expect("generated key ID must be a UUID")
            })
            .collect()
    }

    fn signing_algorithms() -> [KmsSigningAlgorithm; KMS_SIGNING_ALGORITHM_COUNT] {
        [
            KmsSigningAlgorithm::RsaPssSha512,
            KmsSigningAlgorithm::RsaPssSha384,
            KmsSigningAlgorithm::RsaPssSha256,
            KmsSigningAlgorithm::RsaPkcs1V15Sha512,
            KmsSigningAlgorithm::RsaPkcs1V15Sha384,
            KmsSigningAlgorithm::RsaPkcs1V15Sha256,
            KmsSigningAlgorithm::EcdsaSha512,
            KmsSigningAlgorithm::EcdsaSha384,
            KmsSigningAlgorithm::EcdsaSha256,
            KmsSigningAlgorithm::MlDsa44,
            KmsSigningAlgorithm::MlDsa65,
            KmsSigningAlgorithm::MlDsa87,
        ]
    }

    fn valid_key_wire() -> KmsKeyWire {
        serde_json::from_value(key_fixture(
            KEY_ID,
            "application-key",
            "encrypt-decrypt",
            "aes-256-gcm",
        ))
        .unwrap()
    }

    fn private_key_fixture(id: &str, name: &str, usage: &str, algorithm: &str) -> Value {
        json!({
            "keyId": id,
            "name": name,
            "keyUsage": usage,
            "algorithm": algorithm,
            "privateKey": STANDARD.encode("private-key"),
            "publicKey": STANDARD.encode("public-key")
        })
    }

    async fn mount_project(server: &MockServer, token: &str, count: u64) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{PROJECT_ID}")))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(project_fixture()))
            .expect(count)
            .mount(server)
            .await;
    }

    async fn mount_key(
        server: &MockServer,
        token: &str,
        id: &str,
        usage: &str,
        algorithm: &str,
        count: u64,
    ) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/kms/keys/{id}")))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "key": key_fixture(id, "application-key", usage, algorithm)
            })))
            .expect(count)
            .mount(server)
            .await;
    }

    async fn list_result(
        keys: Value,
        total_count: u64,
        offset: u32,
        limit: u16,
    ) -> Result<crate::Page<crate::KmsKey>, ResourceError> {
        let server = MockServer::start().await;
        mount_login(&server, "kms-list-contract-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/kms/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": keys,
                "totalCount": total_count
            })))
            .expect(1)
            .mount(&server)
            .await;
        InfisicalClient::new(settings(&server))
            .unwrap()
            .list_kms_keys(
                KmsKeyListRequest::new(
                    project_id(),
                    PageRequest::new(offset, limit).unwrap(),
                    false,
                    None,
                )
                .unwrap(),
            )
            .await
    }

    async fn bulk_import_result(
        names: &[&str],
        response: Value,
    ) -> Result<KmsBulkImportResult, ResourceError> {
        let server = MockServer::start().await;
        mount_login(&server, "kms-import-contract-token").await;
        mount_project(&server, "kms-import-contract-token", 1).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/kms/keys/bulk-import"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        InfisicalClient::new(settings(&server))
            .unwrap()
            .bulk_import_kms_keys(
                &project_id(),
                names.iter().map(|name| import_entry(name)).collect(),
                true,
            )
            .await
    }

    async fn bulk_reveal_result(
        preflight: &[(&str, &str, &str)],
        response: Value,
    ) -> Result<(), ResourceError> {
        let server = MockServer::start().await;
        mount_login(&server, "kms-reveal-contract-token").await;
        for (id, usage, algorithm) in preflight {
            mount_key(
                &server,
                "kms-reveal-contract-token",
                id,
                usage,
                algorithm,
                1,
            )
            .await;
        }
        Mock::given(method("POST"))
            .and(path("/api/v1/kms/keys/bulk-export-private-keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        InfisicalClient::new(settings(&server))
            .unwrap()
            .bulk_reveal_kms_private_keys(
                &project_id(),
                preflight
                    .iter()
                    .map(|(id, _, _)| KmsKeyId::new(*id).unwrap())
                    .collect(),
                true,
            )
            .await
            .map(|_| ())
    }

    async fn signing_algorithms_result(
        algorithms: Vec<KmsSigningAlgorithm>,
    ) -> Result<(), ResourceError> {
        let server = MockServer::start().await;
        mount_login(&server, "kms-algorithms-contract-token").await;
        mount_key(
            &server,
            "kms-algorithms-contract-token",
            SIGNING_KEY_ID,
            "sign-verify",
            "RSA_4096",
            1,
        )
        .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/kms/keys/{SIGNING_KEY_ID}/signing-algorithms"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signingAlgorithms": algorithms
            })))
            .expect(1)
            .mount(&server)
            .await;
        InfisicalClient::new(settings(&server))
            .unwrap()
            .list_kms_signing_algorithms(&project_id(), &KmsKeyId::new(SIGNING_KEY_ID).unwrap())
            .await
            .map(|_| ())
    }

    async fn sign_result(
        response_key_id: &str,
        response_algorithm: KmsSigningAlgorithm,
    ) -> Result<(), ResourceError> {
        let server = MockServer::start().await;
        mount_login(&server, "kms-sign-contract-token").await;
        mount_key(
            &server,
            "kms-sign-contract-token",
            SIGNING_KEY_ID,
            "sign-verify",
            "RSA_4096",
            1,
        )
        .await;
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/kms/keys/{SIGNING_KEY_ID}/sign")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signature": STANDARD.encode("signature"),
                "keyId": response_key_id,
                "signingAlgorithm": response_algorithm
            })))
            .expect(1)
            .mount(&server)
            .await;
        InfisicalClient::new(settings(&server))
            .unwrap()
            .kms_sign(
                &project_id(),
                &KmsKeyId::new(SIGNING_KEY_ID).unwrap(),
                KmsData::new(SecretValue::new(STANDARD.encode("data"))).unwrap(),
                KmsSigningAlgorithm::RsaPssSha256,
                false,
                true,
            )
            .await
            .map(|_| ())
    }

    async fn verify_result(
        response_key_id: &str,
        response_algorithm: KmsSigningAlgorithm,
    ) -> Result<(), ResourceError> {
        let server = MockServer::start().await;
        mount_login(&server, "kms-verify-contract-token").await;
        mount_key(
            &server,
            "kms-verify-contract-token",
            SIGNING_KEY_ID,
            "sign-verify",
            "RSA_4096",
            1,
        )
        .await;
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/kms/keys/{SIGNING_KEY_ID}/verify")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signatureValid": true,
                "keyId": response_key_id,
                "signingAlgorithm": response_algorithm
            })))
            .expect(1)
            .mount(&server)
            .await;
        InfisicalClient::new(settings(&server))
            .unwrap()
            .kms_verify(
                &project_id(),
                &KmsKeyId::new(SIGNING_KEY_ID).unwrap(),
                KmsData::new(SecretValue::new(STANDARD.encode("data"))).unwrap(),
                STANDARD.encode("signature"),
                KmsSigningAlgorithm::RsaPssSha256,
                false,
                true,
            )
            .await
            .map(|_| ())
    }

    #[test]
    fn kms_inputs_are_closed_bounded_and_redacted() {
        assert_eq!(
            KmsKeyId::new("not-a-uuid").unwrap_err(),
            KmsInputError::InvalidKeyId
        );
        for invalid in ["", "Application", "application--key", "-application"] {
            assert_eq!(
                KmsKeyName::new(invalid).unwrap_err(),
                KmsInputError::InvalidKeyName
            );
        }
        assert_eq!(
            KmsKeyCreation::new(
                KmsKeyName::new("application-key").unwrap(),
                None,
                KmsKeyUsage::EncryptDecrypt,
                KmsKeyAlgorithm::Rsa4096,
            )
            .unwrap_err(),
            KmsInputError::AlgorithmUsageMismatch
        );
        assert_eq!(
            KmsKeyChange::new(None, None, None).unwrap_err(),
            KmsInputError::EmptyChange
        );
        assert_eq!(
            KmsData::new(SecretValue::new("not base64")).unwrap_err(),
            KmsInputError::InvalidBase64
        );
        assert_eq!(
            KmsKeyMaterial::new(
                SecretValue::new(STANDARD.encode([0_u8; 31])),
                KmsKeyAlgorithm::Aes256Gcm,
            )
            .unwrap_err(),
            KmsInputError::EmptyKeyMaterial
        );

        let material = KmsKeyMaterial::new(
            SecretValue::new(STANDARD.encode([7_u8; 32])),
            KmsKeyAlgorithm::Aes256Gcm,
        )
        .unwrap();
        let entry = KmsBulkImportEntry::new(
            KmsKeyName::new("imported-key").unwrap(),
            KmsKeyUsage::EncryptDecrypt,
            KmsKeyAlgorithm::Aes256Gcm,
            material,
        )
        .unwrap();
        let debug = format!("{entry:?}");
        assert!(debug.contains("SecretValue([REDACTED])"));
        assert!(!debug.contains(&STANDARD.encode([7_u8; 32])));

        let rsa_material = KmsKeyMaterial::new(
            SecretValue::new(STANDARD.encode([9_u8; 32])),
            KmsKeyAlgorithm::Rsa4096,
        )
        .unwrap();
        assert_eq!(
            KmsBulkImportEntry::new(
                KmsKeyName::new("rebound-key").unwrap(),
                KmsKeyUsage::EncryptDecrypt,
                KmsKeyAlgorithm::Aes256Gcm,
                rsa_material,
            )
            .unwrap_err(),
            KmsInputError::KeyMaterialAlgorithmMismatch
        );
    }

    #[test]
    fn kms_byte_bounds_and_boundary_validation_are_exact() {
        assert_eq!(MAX_KMS_PAYLOAD_BYTES / 1024, 512);
        assert_eq!(MAX_KMS_CIPHERTEXT_BYTES - MAX_KMS_PAYLOAD_BYTES, 1024);
        assert_eq!(MAX_KMS_SIGNATURE_BYTES / 1024, 8);
        assert_eq!(MAX_KMS_KEY_MATERIAL_BYTES / 1024, 64);
        assert_eq!(MAX_KMS_PRIVATE_KEY_BYTES / 1024, 256);
        assert_eq!(MAX_KMS_PUBLIC_KEY_BYTES / 1024, 128);

        assert_eq!(validate_description(None), Ok(()));
        assert_eq!(validate_description(Some(&"a".repeat(500))), Ok(()));
        for invalid in [
            "a".repeat(501),
            " leading".to_owned(),
            "trailing ".to_owned(),
            "line\nbreak".to_owned(),
        ] {
            assert_eq!(
                validate_description(Some(&invalid)),
                Err(KmsInputError::InvalidDescription)
            );
        }

        assert_eq!(
            validate_base64("", 2, false),
            Err(KmsInputError::EmptyKeyMaterial)
        );
        assert_eq!(validate_base64("", 2, true), Ok(0));
        assert_eq!(
            validate_base64("YQ", 1, false),
            Err(KmsInputError::InvalidBase64)
        );
        assert_eq!(
            validate_base64(&STANDARD.encode([0_u8; 4]), 4, false),
            Ok(4)
        );
        assert_eq!(
            validate_base64("!!!!!!!!!!!!", 4, false),
            Err(KmsInputError::PayloadTooLarge)
        );
        assert_eq!(
            validate_base64(&STANDARD.encode([0_u8; 2]), 2, false),
            Ok(2)
        );
        assert_eq!(
            validate_base64(&STANDARD.encode([0_u8; 3]), 2, false),
            Err(KmsInputError::PayloadTooLarge)
        );
    }

    #[test]
    fn signing_key_families_and_digest_contracts_are_closed() {
        let key_algorithms = [
            KmsKeyAlgorithm::Aes256Gcm,
            KmsKeyAlgorithm::Aes128Gcm,
            KmsKeyAlgorithm::Rsa4096,
            KmsKeyAlgorithm::EccNistP256,
            KmsKeyAlgorithm::EccNistP384,
            KmsKeyAlgorithm::EccNistP521,
            KmsKeyAlgorithm::MlDsa44,
            KmsKeyAlgorithm::MlDsa65,
            KmsKeyAlgorithm::MlDsa87,
        ];
        for signing_algorithm in signing_algorithms() {
            for key_algorithm in key_algorithms {
                let expected = match key_algorithm {
                    KmsKeyAlgorithm::Rsa4096 => matches!(
                        signing_algorithm,
                        KmsSigningAlgorithm::RsaPssSha512
                            | KmsSigningAlgorithm::RsaPssSha384
                            | KmsSigningAlgorithm::RsaPssSha256
                            | KmsSigningAlgorithm::RsaPkcs1V15Sha512
                            | KmsSigningAlgorithm::RsaPkcs1V15Sha384
                            | KmsSigningAlgorithm::RsaPkcs1V15Sha256
                    ),
                    KmsKeyAlgorithm::EccNistP256
                    | KmsKeyAlgorithm::EccNistP384
                    | KmsKeyAlgorithm::EccNistP521 => matches!(
                        signing_algorithm,
                        KmsSigningAlgorithm::EcdsaSha512
                            | KmsSigningAlgorithm::EcdsaSha384
                            | KmsSigningAlgorithm::EcdsaSha256
                    ),
                    KmsKeyAlgorithm::MlDsa44 => signing_algorithm == KmsSigningAlgorithm::MlDsa44,
                    KmsKeyAlgorithm::MlDsa65 => signing_algorithm == KmsSigningAlgorithm::MlDsa65,
                    KmsKeyAlgorithm::MlDsa87 => signing_algorithm == KmsSigningAlgorithm::MlDsa87,
                    KmsKeyAlgorithm::Aes256Gcm | KmsKeyAlgorithm::Aes128Gcm => false,
                };
                assert_eq!(signing_algorithm.supports_key(key_algorithm), expected);
                assert_eq!(
                    signing_algorithm.validate_key(key_algorithm),
                    if expected {
                        Ok(())
                    } else {
                        Err(KmsInputError::SigningAlgorithmMismatch)
                    }
                );
            }

            let expected_digest_bytes = match signing_algorithm {
                KmsSigningAlgorithm::RsaPkcs1V15Sha512 | KmsSigningAlgorithm::EcdsaSha512 => {
                    Some(64)
                }
                KmsSigningAlgorithm::RsaPkcs1V15Sha384 | KmsSigningAlgorithm::EcdsaSha384 => {
                    Some(48)
                }
                KmsSigningAlgorithm::RsaPkcs1V15Sha256 | KmsSigningAlgorithm::EcdsaSha256 => {
                    Some(32)
                }
                KmsSigningAlgorithm::RsaPssSha512
                | KmsSigningAlgorithm::RsaPssSha384
                | KmsSigningAlgorithm::RsaPssSha256
                | KmsSigningAlgorithm::MlDsa44
                | KmsSigningAlgorithm::MlDsa65
                | KmsSigningAlgorithm::MlDsa87 => None,
            };
            assert_eq!(signing_algorithm.digest_bytes(), expected_digest_bytes);
            assert_eq!(signing_algorithm.validate_digest(0, false), Ok(()));
            match expected_digest_bytes {
                Some(expected_bytes) => {
                    assert_eq!(
                        signing_algorithm.validate_digest(expected_bytes, true),
                        Ok(())
                    );
                    assert_eq!(
                        signing_algorithm.validate_digest(expected_bytes - 1, true),
                        Err(KmsInputError::InvalidDigest)
                    );
                }
                None => assert_eq!(
                    signing_algorithm.validate_digest(32, true),
                    Err(KmsInputError::InvalidDigest)
                ),
            }
        }
    }

    #[test]
    fn bulk_request_boundaries_and_duplicates_are_rejected_locally() {
        assert_eq!(
            validate_bulk_import_entries(&[]),
            Err(KmsInputError::InvalidBulkSize)
        );
        assert_eq!(validate_bulk_import_entries(&import_entries(1)), Ok(()));
        assert_eq!(validate_bulk_import_entries(&import_entries(100)), Ok(()));
        let exact_material_bound = (0..8)
            .map(|index| {
                import_entry_with_material(
                    &format!("large-key-{index}"),
                    KmsKeyAlgorithm::Rsa4096,
                    MAX_KMS_KEY_MATERIAL_BYTES,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(validate_bulk_import_entries(&exact_material_bound), Ok(()));
        let over_material_bound = (0..9)
            .map(|index| {
                import_entry_with_material(
                    &format!("large-key-{index}"),
                    KmsKeyAlgorithm::Rsa4096,
                    MAX_KMS_KEY_MATERIAL_BYTES,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            validate_bulk_import_entries(&over_material_bound),
            Err(KmsInputError::PayloadTooLarge)
        );
        assert_eq!(
            validate_bulk_import_entries(&import_entries(101)),
            Err(KmsInputError::InvalidBulkSize)
        );
        assert_eq!(
            validate_bulk_import_entries(&[
                import_entry("duplicate-key"),
                import_entry("duplicate-key"),
            ]),
            Err(KmsInputError::DuplicateBulkKey)
        );

        assert_eq!(
            validate_bulk_key_ids(&[]),
            Err(KmsInputError::InvalidBulkSize)
        );
        assert_eq!(validate_bulk_key_ids(&key_ids(1)), Ok(()));
        assert_eq!(validate_bulk_key_ids(&key_ids(100)), Ok(()));
        assert_eq!(
            validate_bulk_key_ids(&key_ids(101)),
            Err(KmsInputError::InvalidBulkSize)
        );
        assert_eq!(
            validate_bulk_key_ids(&[key_id(), key_id()]),
            Err(KmsInputError::DuplicateBulkKey)
        );
    }

    #[test]
    fn key_response_metadata_invariants_fail_independently() {
        let mut missing_disabled =
            key_fixture(KEY_ID, "application-key", "encrypt-decrypt", "aes-256-gcm");
        missing_disabled
            .as_object_mut()
            .unwrap()
            .remove("isDisabled");
        assert!(serde_json::from_value::<KmsKeyWire>(missing_disabled).is_err());

        let expected_id = key_id();
        let expected_name = KmsKeyName::new("application-key").unwrap();
        assert!(
            kms_key_from_wire(
                valid_key_wire(),
                &project_id(),
                Some(&expected_id),
                Some(&expected_name),
            )
            .is_ok()
        );

        let mut invalid = valid_key_wire();
        invalid.project_id = Some("99999999-9999-4999-8999-999999999999".to_owned());
        assert_eq!(
            kms_key_from_wire(invalid, &project_id(), None, None).unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let mut invalid = valid_key_wire();
        invalid.key_usage = KmsKeyUsage::SignVerify;
        assert_eq!(
            kms_key_from_wire(invalid, &project_id(), None, None).unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let other_id = KmsKeyId::new("99999999-9999-4999-8999-999999999999").unwrap();
        assert_eq!(
            kms_key_from_wire(valid_key_wire(), &project_id(), Some(&other_id), None).unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let other_name = KmsKeyName::new("other-key").unwrap();
        assert_eq!(
            kms_key_from_wire(valid_key_wire(), &project_id(), None, Some(&other_name))
                .unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let mut invalid = valid_key_wire();
        invalid.version = 0;
        assert_eq!(
            kms_key_from_wire(invalid, &project_id(), None, None).unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let mut invalid = valid_key_wire();
        invalid.created_at.clear();
        assert_eq!(
            kms_key_from_wire(invalid, &project_id(), None, None).unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let mut invalid = valid_key_wire();
        invalid.updated_at = "invalid\nvalue".to_owned();
        assert_eq!(
            kms_key_from_wire(invalid, &project_id(), None, None).unwrap_err(),
            ResourceError::InvalidKmsResponse
        );
    }

    #[test]
    fn create_and_update_responses_reflect_every_requested_field() {
        let creation = KmsKeyCreation::new(
            KmsKeyName::new("application-key").unwrap(),
            Some("application key".to_owned()),
            KmsKeyUsage::EncryptDecrypt,
            KmsKeyAlgorithm::Aes256Gcm,
        )
        .unwrap();
        assert!(created_kms_key_from_wire(valid_key_wire(), &project_id(), &creation).is_ok());

        let mut invalid = valid_key_wire();
        invalid.description = Some("different description".to_owned());
        assert_eq!(
            created_kms_key_from_wire(invalid, &project_id(), &creation).unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let mut invalid = valid_key_wire();
        invalid.encryption_algorithm = KmsKeyAlgorithm::Aes128Gcm;
        assert_eq!(
            created_kms_key_from_wire(invalid, &project_id(), &creation).unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let change = KmsKeyChange::new(
            Some(KmsKeyName::new("renamed-key").unwrap()),
            Some("changed description".to_owned()),
            Some(true),
        )
        .unwrap();
        let mut reflected = valid_key_wire();
        reflected.name = "renamed-key".to_owned();
        reflected.description = Some("changed description".to_owned());
        reflected.is_disabled = true;
        assert!(updated_kms_key_from_wire(reflected, &project_id(), &key_id(), &change).is_ok());

        let mut invalid = valid_key_wire();
        invalid.name = "renamed-key".to_owned();
        invalid.description = Some("different description".to_owned());
        invalid.is_disabled = true;
        assert_eq!(
            updated_kms_key_from_wire(invalid, &project_id(), &key_id(), &change).unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let mut invalid = valid_key_wire();
        invalid.name = "renamed-key".to_owned();
        invalid.description = Some("changed description".to_owned());
        invalid.is_disabled = false;
        assert_eq!(
            updated_kms_key_from_wire(invalid, &project_id(), &key_id(), &change).unwrap_err(),
            ResourceError::InvalidKmsResponse
        );
    }

    #[tokio::test]
    async fn full_nonterminal_list_page_preserves_continuation() {
        let keys = json!([
            key_fixture(KEY_ID, "application-key", "encrypt-decrypt", "aes-256-gcm"),
            key_fixture(SIGNING_KEY_ID, "signing-key", "sign-verify", "RSA_4096")
        ]);
        let page = list_result(keys, 3, 0, 2).await.unwrap();

        assert_eq!(page.items.len(), 2);
        assert_eq!(page.next, Some(PageRequest::new(2, 2).unwrap()));
        assert_eq!(page.total, Some(3));
    }

    #[tokio::test]
    async fn malformed_list_pages_fail_each_pagination_invariant() {
        let too_many_keys = json!([
            key_fixture(KEY_ID, "application-key", "encrypt-decrypt", "aes-256-gcm"),
            key_fixture(
                SIGNING_KEY_ID,
                "second-key",
                "encrypt-decrypt",
                "aes-256-gcm"
            )
        ]);
        assert_eq!(
            list_result(too_many_keys, 2, 0, 1).await.unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let impossible_total = json!([key_fixture(
            KEY_ID,
            "application-key",
            "encrypt-decrypt",
            "aes-256-gcm"
        )]);
        assert_eq!(
            list_result(impossible_total, 0, 0, 1).await.unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let short_nonterminal_page = json!([key_fixture(
            KEY_ID,
            "application-key",
            "encrypt-decrypt",
            "aes-256-gcm"
        )]);
        assert_eq!(
            list_result(short_nonterminal_page, 2, 0, 2)
                .await
                .unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        assert_eq!(
            list_result(json!([]), 5, 0, 10).await.unwrap_err(),
            ResourceError::InvalidKmsResponse
        );
        let shrunken = list_result(json!([]), 5, 100, 10).await.unwrap();
        assert!(shrunken.items.is_empty());
        assert!(shrunken.next.is_none());
        assert_eq!(shrunken.total, Some(5));
    }

    #[tokio::test]
    async fn bulk_import_response_cardinality_names_and_errors_are_closed() {
        let mixed_success = json!({
            "keys": [{ "id": KEY_ID, "name": "alpha-key" }],
            "errors": [{ "name": "beta-key", "message": "not importable" }]
        });
        assert!(
            bulk_import_result(&["alpha-key", "beta-key"], mixed_success)
                .await
                .is_ok()
        );

        let unexpected_key = json!({
            "keys": [{ "id": KEY_ID, "name": "other-key" }],
            "errors": []
        });
        assert_eq!(
            bulk_import_result(&["alpha-key"], unexpected_key)
                .await
                .unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let duplicate_key = json!({
            "keys": [
                { "id": KEY_ID, "name": "alpha-key" },
                { "id": SIGNING_KEY_ID, "name": "alpha-key" }
            ],
            "errors": []
        });
        assert_eq!(
            bulk_import_result(&["alpha-key", "beta-key"], duplicate_key)
                .await
                .unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let unexpected_error = json!({
            "keys": [],
            "errors": [{ "name": "other-key", "message": "not importable" }]
        });
        assert_eq!(
            bulk_import_result(&["alpha-key"], unexpected_error)
                .await
                .unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let duplicate_result_name = json!({
            "keys": [{ "id": KEY_ID, "name": "alpha-key" }],
            "errors": [{ "name": "alpha-key", "message": "not importable" }]
        });
        assert_eq!(
            bulk_import_result(&["alpha-key", "beta-key"], duplicate_result_name)
                .await
                .unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let secret_bearing_error_message = json!({
            "keys": [],
            "errors": [{
                "name": "alpha-key",
                "message": "private-key-canary\nprovider diagnostic"
            }]
        });
        let result = bulk_import_result(&["alpha-key"], secret_bearing_error_message)
            .await
            .unwrap();
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].message, KMS_IMPORT_REJECTION_MESSAGE);
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("private-key-canary")
        );
    }

    #[tokio::test]
    async fn bulk_reveal_responses_must_match_every_preflighted_key_field() {
        let valid = json!({
            "keys": [private_key_fixture(
                KEY_ID,
                "application-key",
                "encrypt-decrypt",
                "aes-256-gcm"
            )]
        });
        assert!(
            bulk_reveal_result(&[(KEY_ID, "encrypt-decrypt", "aes-256-gcm")], valid)
                .await
                .is_ok()
        );

        assert_eq!(
            bulk_reveal_result(
                &[(KEY_ID, "encrypt-decrypt", "aes-256-gcm")],
                json!({ "keys": [] }),
            )
            .await
            .unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        let duplicate = json!({
            "keys": [
                private_key_fixture(
                    KEY_ID,
                    "application-key",
                    "encrypt-decrypt",
                    "aes-256-gcm"
                ),
                private_key_fixture(
                    KEY_ID,
                    "application-key",
                    "encrypt-decrypt",
                    "aes-256-gcm"
                )
            ]
        });
        assert_eq!(
            bulk_reveal_result(
                &[
                    (KEY_ID, "encrypt-decrypt", "aes-256-gcm"),
                    (SIGNING_KEY_ID, "encrypt-decrypt", "aes-256-gcm"),
                ],
                duplicate,
            )
            .await
            .unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        for invalid in [
            private_key_fixture(KEY_ID, "other-key", "encrypt-decrypt", "aes-256-gcm"),
            private_key_fixture(KEY_ID, "application-key", "encrypt-decrypt", "RSA_4096"),
            private_key_fixture(KEY_ID, "application-key", "encrypt-decrypt", "aes-128-gcm"),
            private_key_fixture(KEY_ID, "application-key", "sign-verify", "RSA_4096"),
        ] {
            assert_eq!(
                bulk_reveal_result(
                    &[(KEY_ID, "encrypt-decrypt", "aes-256-gcm")],
                    json!({ "keys": [invalid] }),
                )
                .await
                .unwrap_err(),
                ResourceError::InvalidKmsResponse
            );
        }
    }

    #[tokio::test]
    async fn signing_algorithm_sets_and_reflected_operation_fields_are_exact() {
        for (algorithm, expected) in [
            (KmsKeyAlgorithm::Rsa4096, 6),
            (KmsKeyAlgorithm::EccNistP256, 3),
            (KmsKeyAlgorithm::EccNistP384, 3),
            (KmsKeyAlgorithm::EccNistP521, 3),
            (KmsKeyAlgorithm::MlDsa44, 1),
            (KmsKeyAlgorithm::MlDsa65, 1),
            (KmsKeyAlgorithm::MlDsa87, 1),
            (KmsKeyAlgorithm::Aes256Gcm, 0),
            (KmsKeyAlgorithm::Aes128Gcm, 0),
        ] {
            let signing_algorithms = algorithm.signing_algorithms();
            assert_eq!(signing_algorithms.len(), expected);
            assert!(
                signing_algorithms
                    .iter()
                    .all(|signing_algorithm| signing_algorithm.supports_key(algorithm))
            );
        }
        assert_eq!(
            signing_algorithms_result(Vec::new()).await.unwrap_err(),
            ResourceError::InvalidKmsResponse
        );
        let all_algorithms = signing_algorithms();
        assert_eq!(all_algorithms.len(), KMS_SIGNING_ALGORITHM_COUNT);
        assert!(
            signing_algorithms_result(all_algorithms[..6].to_vec())
                .await
                .is_ok()
        );
        assert_eq!(
            signing_algorithms_result(all_algorithms.to_vec())
                .await
                .unwrap_err(),
            ResourceError::InvalidKmsResponse
        );

        for (response_key_id, response_algorithm) in [
            (KEY_ID, KmsSigningAlgorithm::RsaPssSha256),
            (SIGNING_KEY_ID, KmsSigningAlgorithm::EcdsaSha256),
        ] {
            assert_eq!(
                sign_result(response_key_id, response_algorithm)
                    .await
                    .unwrap_err(),
                ResourceError::InvalidKmsResponse
            );
            assert_eq!(
                verify_result(response_key_id, response_algorithm)
                    .await
                    .unwrap_err(),
                ResourceError::InvalidKmsResponse
            );
        }
    }

    #[tokio::test]
    async fn incompatible_signing_inputs_never_reach_a_cryptographic_route() {
        let digest_server = MockServer::start().await;
        let digest_client = InfisicalClient::new(settings(&digest_server)).unwrap();
        for (signing_algorithm, data_bytes) in [
            (KmsSigningAlgorithm::RsaPssSha256, 32),
            (KmsSigningAlgorithm::RsaPkcs1V15Sha256, 31),
        ] {
            assert_eq!(
                digest_client
                    .kms_verify(
                        &project_id(),
                        &KmsKeyId::new(SIGNING_KEY_ID).unwrap(),
                        KmsData::new(SecretValue::new(STANDARD.encode(vec![7_u8; data_bytes]),))
                            .unwrap(),
                        STANDARD.encode("signature"),
                        signing_algorithm,
                        true,
                        true,
                    )
                    .await
                    .unwrap_err(),
                ResourceError::InvalidKmsCryptographicInput
            );
        }
        assert!(digest_server.received_requests().await.unwrap().is_empty());

        let key_server = MockServer::start().await;
        mount_login(&key_server, "kms-signing-compatibility-token").await;
        mount_key(
            &key_server,
            "kms-signing-compatibility-token",
            SIGNING_KEY_ID,
            "sign-verify",
            "RSA_4096",
            1,
        )
        .await;
        let key_client = InfisicalClient::new(settings(&key_server)).unwrap();
        assert_eq!(
            key_client
                .kms_sign(
                    &project_id(),
                    &KmsKeyId::new(SIGNING_KEY_ID).unwrap(),
                    KmsData::new(SecretValue::new(STANDARD.encode("data"))).unwrap(),
                    KmsSigningAlgorithm::EcdsaSha256,
                    false,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidKmsCryptographicInput
        );
        assert_eq!(
            key_server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|request| request.method == Method::POST)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn list_and_exact_gets_use_audited_pinned_routes_and_validate_scope() {
        let server = MockServer::start().await;
        mount_login(&server, "kms-read-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/kms/keys"))
            .and(query_param("projectId", PROJECT_ID))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"))
            .and(query_param("orderBy", "name"))
            .and(query_param("orderDirection", "asc"))
            .and(query_param("search", "application"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": [key_fixture(KEY_ID, "application-key", "encrypt-decrypt", "aes-256-gcm")],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/kms/keys/{KEY_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "key": key_fixture(KEY_ID, "application-key", "encrypt-decrypt", "aes-256-gcm")
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/kms/keys/key-name/application-key"))
            .and(query_param("projectId", PROJECT_ID))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "key": key_fixture(KEY_ID, "application-key", "encrypt-decrypt", "aes-256-gcm")
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let list = client
            .list_kms_keys(
                KmsKeyListRequest::new(
                    project_id(),
                    PageRequest::new(0, 1).unwrap(),
                    false,
                    Some("application".to_owned()),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.items[0].id, KEY_ID);
        assert!(list.next.is_none());
        assert_eq!(
            client
                .get_kms_key(&project_id(), &key_id())
                .await
                .unwrap()
                .name,
            "application-key"
        );
        assert_eq!(
            client
                .get_kms_key_by_name(&project_id(), &KmsKeyName::new("application-key").unwrap(),)
                .await
                .unwrap()
                .id,
            KEY_ID
        );
    }

    #[tokio::test]
    async fn management_mutations_preflight_scope_and_are_never_replayed() {
        let server = MockServer::start().await;
        mount_login(&server, "kms-admin-token").await;
        mount_project(&server, "kms-admin-token", 1).await;
        mount_key(
            &server,
            "kms-admin-token",
            KEY_ID,
            "encrypt-decrypt",
            "aes-256-gcm",
            2,
        )
        .await;
        let mut updated_key = key_fixture(KEY_ID, "renamed-key", "encrypt-decrypt", "aes-256-gcm");
        updated_key["isDisabled"] = json!(true);
        Mock::given(method("POST"))
            .and(path("/api/v1/kms/keys"))
            .and(body_json(json!({
                "projectId": PROJECT_ID,
                "name": "application-key",
                "description": "application key",
                "keyUsage": "encrypt-decrypt",
                "encryptionAlgorithm": "aes-256-gcm"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "key": key_fixture(KEY_ID, "application-key", "encrypt-decrypt", "aes-256-gcm")
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/kms/keys/{KEY_ID}")))
            .and(body_json(
                json!({ "name": "renamed-key", "isDisabled": true }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "key": updated_key
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/kms/keys/{KEY_ID}")))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "key": key_fixture(KEY_ID, "application-key", "encrypt-decrypt", "aes-256-gcm")
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        client
            .create_kms_key(
                &project_id(),
                KmsKeyCreation::new(
                    KmsKeyName::new("application-key").unwrap(),
                    Some("application key".to_owned()),
                    KmsKeyUsage::EncryptDecrypt,
                    KmsKeyAlgorithm::Aes256Gcm,
                )
                .unwrap(),
                true,
            )
            .await
            .unwrap();
        let updated = client
            .update_kms_key(
                &project_id(),
                &key_id(),
                KmsKeyChange::new(
                    Some(KmsKeyName::new("renamed-key").unwrap()),
                    None,
                    Some(true),
                )
                .unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "renamed-key");
        client
            .delete_kms_key(&project_id(), &key_id(), true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn all_confirmation_failures_happen_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert_eq!(
            client
                .create_kms_key(
                    &project_id(),
                    KmsKeyCreation::new(
                        KmsKeyName::new("application-key").unwrap(),
                        None,
                        KmsKeyUsage::EncryptDecrypt,
                        KmsKeyAlgorithm::Aes256Gcm,
                    )
                    .unwrap(),
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::KmsOperationNotConfirmed
        );
        assert_eq!(
            client
                .update_kms_key(
                    &project_id(),
                    &key_id(),
                    KmsKeyChange::new(None, None, Some(true)).unwrap(),
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::KmsOperationNotConfirmed
        );
        assert_eq!(
            client
                .delete_kms_key(&project_id(), &key_id(), false)
                .await
                .unwrap_err(),
            ResourceError::KmsKeyDeletionNotConfirmed
        );
        assert_eq!(
            client
                .kms_encrypt(
                    &project_id(),
                    &key_id(),
                    KmsData::new(SecretValue::new(STANDARD.encode("plaintext"))).unwrap(),
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::KmsOperationNotConfirmed
        );
        assert_eq!(
            client
                .kms_decrypt(
                    &project_id(),
                    &key_id(),
                    SecretValue::new(STANDARD.encode("ciphertext")),
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::KmsSecretRevealNotConfirmed
        );
        assert_eq!(
            client
                .reveal_kms_private_key(&project_id(), &key_id(), false)
                .await
                .unwrap_err(),
            ResourceError::KmsSecretRevealNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn encrypt_and_decrypt_preserve_secret_and_non_replay_boundaries() {
        let server = MockServer::start().await;
        mount_login(&server, "kms-crypto-token").await;
        mount_key(
            &server,
            "kms-crypto-token",
            KEY_ID,
            "encrypt-decrypt",
            "aes-256-gcm",
            2,
        )
        .await;
        let plaintext = STANDARD.encode("plaintext-canary");
        let ciphertext = STANDARD.encode("ciphertext-canary");
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/kms/keys/{KEY_ID}/encrypt")))
            .and(body_json(json!({ "plaintext": plaintext })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ciphertext": ciphertext
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/kms/keys/{KEY_ID}/decrypt")))
            .and(body_json(json!({ "ciphertext": ciphertext })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "plaintext": plaintext
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let encrypted = client
            .kms_encrypt(
                &project_id(),
                &key_id(),
                KmsData::new(SecretValue::new(plaintext)).unwrap(),
                true,
            )
            .await
            .unwrap();
        let decrypted = client
            .kms_decrypt(
                &project_id(),
                &key_id(),
                SecretValue::new(encrypted.ciphertext),
                true,
            )
            .await
            .unwrap();
        let debug = format!("{decrypted:?}");
        assert!(debug.contains("SecretValue([REDACTED])"));
        assert!(!debug.contains("plaintext-canary"));
        assert_eq!(
            decrypted.plaintext.expose_secret(),
            STANDARD.encode("plaintext-canary")
        );
    }

    async fn mount_signing_routes(
        server: &MockServer,
        public_key: &str,
        private_key: &str,
        data: &str,
        signature: &str,
    ) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/kms/keys/{SIGNING_KEY_ID}/public-key"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "publicKey": public_key
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/kms/keys/{SIGNING_KEY_ID}/private-key"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privateKey": private_key
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/kms/keys/{SIGNING_KEY_ID}/signing-algorithms"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signingAlgorithms": [
                    "RSASSA_PSS_SHA_512",
                    "RSASSA_PSS_SHA_384",
                    "RSASSA_PSS_SHA_256",
                    "RSASSA_PKCS1_V1_5_SHA_512",
                    "RSASSA_PKCS1_V1_5_SHA_384",
                    "RSASSA_PKCS1_V1_5_SHA_256"
                ]
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/kms/keys/{SIGNING_KEY_ID}/sign")))
            .and(body_json(json!({
                "signingAlgorithm": "RSASSA_PSS_SHA_256",
                "isDigest": false,
                "data": data
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signature": signature,
                "keyId": SIGNING_KEY_ID,
                "signingAlgorithm": "RSASSA_PSS_SHA_256"
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/kms/keys/{SIGNING_KEY_ID}/verify")))
            .and(body_json(json!({
                "signingAlgorithm": "RSASSA_PSS_SHA_256",
                "isDigest": false,
                "data": data,
                "signature": signature
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signatureValid": true,
                "keyId": SIGNING_KEY_ID,
                "signingAlgorithm": "RSASSA_PSS_SHA_256"
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn signing_routes_reflect_exact_key_algorithm_and_keep_private_material_redacted() {
        let server = MockServer::start().await;
        mount_login(&server, "kms-sign-token").await;
        mount_key(
            &server,
            "kms-sign-token",
            SIGNING_KEY_ID,
            "sign-verify",
            "RSA_4096",
            5,
        )
        .await;
        let public_key = STANDARD.encode("public-key");
        let private_key = STANDARD.encode("private-key-canary");
        let data = STANDARD.encode("signed-data");
        let signature = STANDARD.encode("signature");
        mount_signing_routes(&server, &public_key, &private_key, &data, &signature).await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let signing_key_id = KmsKeyId::new(SIGNING_KEY_ID).unwrap();
        assert_eq!(
            client
                .get_kms_public_key(&project_id(), &signing_key_id)
                .await
                .unwrap()
                .public_key,
            public_key
        );
        let private = client
            .reveal_kms_private_key(&project_id(), &signing_key_id, true)
            .await
            .unwrap();
        assert!(!format!("{private:?}").contains("private-key-canary"));
        assert_eq!(
            client
                .list_kms_signing_algorithms(&project_id(), &signing_key_id)
                .await
                .unwrap()
                .signing_algorithms,
            vec![
                KmsSigningAlgorithm::RsaPssSha512,
                KmsSigningAlgorithm::RsaPssSha384,
                KmsSigningAlgorithm::RsaPssSha256,
                KmsSigningAlgorithm::RsaPkcs1V15Sha512,
                KmsSigningAlgorithm::RsaPkcs1V15Sha384,
                KmsSigningAlgorithm::RsaPkcs1V15Sha256,
            ]
        );
        let signed = client
            .kms_sign(
                &project_id(),
                &signing_key_id,
                KmsData::new(SecretValue::new(data.clone())).unwrap(),
                KmsSigningAlgorithm::RsaPssSha256,
                false,
                true,
            )
            .await
            .unwrap();
        assert_eq!(signed.signature, signature);
        assert!(
            client
                .kms_verify(
                    &project_id(),
                    &signing_key_id,
                    KmsData::new(SecretValue::new(data)).unwrap(),
                    signature,
                    KmsSigningAlgorithm::RsaPssSha256,
                    false,
                    true,
                )
                .await
                .unwrap()
                .signature_valid
        );
    }
}
