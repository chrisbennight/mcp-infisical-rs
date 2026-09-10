use std::collections::HashSet;

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair,
    RsaKeyPair,
};
use pkcs8::der::Decode;
use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};
use ssh_key::{
    EcdsaCurve, PrivateKey as ParsedSshPrivateKey, PublicKey as ParsedSshPublicKey, public::KeyData,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    InfisicalClient, MutationOperation, ObservableReadOperation, ProjectId, ResourceError,
    SecretValue,
    client::{ApiVersion, Endpoint, sealed},
    resources::{is_bounded_text, is_uuid},
};

const MAX_SSH_CA_NAME_BYTES: usize = 128;
const MAX_SSH_CA_ENTRIES: usize = 500;
const MAX_SSH_PUBLIC_KEY_BYTES: usize = 32 * 1024;
const MAX_SSH_PRIVATE_KEY_BYTES: usize = 128 * 1024;

/// Input validation failures for the pinned SSH certificate-authority contract.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SshCertificateAuthorityInputError {
    #[error("SSH project ID must be a UUID")]
    InvalidProjectId,
    #[error("SSH certificate-authority ID must be a UUID")]
    InvalidId,
    #[error("SSH certificate-authority name must be trimmed, control-free, and 1 to 128 bytes")]
    InvalidName,
    #[error("SSH public key must be a bounded supported OpenSSH public key")]
    InvalidPublicKey,
    #[error("SSH private key must be bounded, unencrypted, and use a supported key envelope")]
    InvalidPrivateKey,
    #[error("SSH public and private key algorithms must match")]
    MismatchedKeyAlgorithms,
}

/// A validated UUID identifying one SSH Access project.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SshProjectId(ProjectId);

impl SshProjectId {
    /// Validate the UUID-only project contract used by SSH Access.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, SshCertificateAuthorityInputError> {
        let value = value.into();
        if !is_uuid(&value) {
            return Err(SshCertificateAuthorityInputError::InvalidProjectId);
        }
        ProjectId::new(value.to_ascii_lowercase())
            .map(Self)
            .map_err(|_| SshCertificateAuthorityInputError::InvalidProjectId)
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A validated SSH certificate-authority identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SshCertificateAuthorityId(String);

impl SshCertificateAuthorityId {
    /// Validate a UUID before it reaches an SSH CA URL path.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, SshCertificateAuthorityInputError> {
        let value = value.into();
        if !is_uuid(&value) {
            return Err(SshCertificateAuthorityInputError::InvalidId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Key algorithms accepted by the pinned SSH CA API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SshKeyAlgorithm {
    #[serde(rename = "RSA_2048")]
    Rsa2048,
    #[serde(rename = "RSA_4096")]
    Rsa4096,
    #[serde(rename = "EC_prime256v1")]
    EcP256,
    #[serde(rename = "EC_secp384r1")]
    EcP384,
    #[serde(rename = "ED25519")]
    Ed25519,
}

/// Lifecycle state of an SSH certificate authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SshCaStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "disabled")]
    Disabled,
}

/// Origin of an SSH certificate authority's key pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SshCaKeySource {
    #[serde(rename = "internal")]
    Internal,
    #[serde(rename = "external")]
    External,
}

/// A bounded supported OpenSSH public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SshPublicKey(String);

fn rsa_modulus_bits(key: &ssh_key::public::RsaPublicKey) -> Option<usize> {
    let bytes = key.n.as_positive_bytes()?;
    let first = *bytes.first()?;
    Some((bytes.len() - 1) * 8 + (8 - first.leading_zeros() as usize))
}

fn parsed_public_key_algorithm(key: &ParsedSshPublicKey) -> Option<SshKeyAlgorithm> {
    match key.key_data() {
        KeyData::Ed25519(_) => Some(SshKeyAlgorithm::Ed25519),
        KeyData::Ecdsa(key) => match key.curve() {
            EcdsaCurve::NistP256 => Some(SshKeyAlgorithm::EcP256),
            EcdsaCurve::NistP384 => Some(SshKeyAlgorithm::EcP384),
            EcdsaCurve::NistP521 => None,
        },
        KeyData::Rsa(key) => match rsa_modulus_bits(key) {
            Some(2_048) => Some(SshKeyAlgorithm::Rsa2048),
            Some(4_096) => Some(SshKeyAlgorithm::Rsa4096),
            _ => None,
        },
        _ => None,
    }
}

impl SshPublicKey {
    /// Validate and canonicalize a supported public-key line.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported, malformed, or oversized key text.
    pub fn new(value: impl Into<String>) -> Result<Self, SshCertificateAuthorityInputError> {
        let value = value.into();
        let canonical = value.trim();
        if canonical.is_empty()
            || canonical.len() > MAX_SSH_PUBLIC_KEY_BYTES
            || canonical.chars().any(char::is_control)
        {
            return Err(SshCertificateAuthorityInputError::InvalidPublicKey);
        }
        let parsed = ParsedSshPublicKey::from_openssh(canonical)
            .map_err(|_| SshCertificateAuthorityInputError::InvalidPublicKey)?;
        if parsed_public_key_algorithm(&parsed).is_none() {
            return Err(SshCertificateAuthorityInputError::InvalidPublicKey);
        }
        parsed
            .to_openssh()
            .map(Self)
            .map_err(|_| SshCertificateAuthorityInputError::InvalidPublicKey)
    }

    /// Borrow the canonical key line.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn matches_algorithm(&self, algorithm: SshKeyAlgorithm) -> bool {
        ParsedSshPublicKey::from_openssh(&self.0)
            .ok()
            .and_then(|key| parsed_public_key_algorithm(&key))
            == Some(algorithm)
    }
}

/// Secret key material used only while creating an SSH certificate authority.
#[derive(Debug)]
pub enum SshCaKeyMaterial {
    /// Ask Infisical to generate and encrypt the key pair.
    Internal(SshKeyAlgorithm),
    /// Import a matching key pair; the private value is zeroized on drop.
    External {
        /// Public half of the imported pair.
        public_key: SshPublicKey,
        /// Private half of the imported pair.
        private_key: SecretValue,
    },
}

impl SshCaKeyMaterial {
    /// Validate an external private-key envelope before it reaches the API.
    ///
    /// Infisical performs the cryptographic pair match before persisting the CA.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or oversized private-key text.
    pub fn external(
        public_key: SshPublicKey,
        private_key: SecretValue,
    ) -> Result<Self, SshCertificateAuthorityInputError> {
        let private_algorithm = validate_private_key(private_key.expose_secret())?;
        if !public_key.matches_algorithm(private_algorithm) {
            return Err(SshCertificateAuthorityInputError::MismatchedKeyAlgorithms);
        }
        Ok(Self::External {
            public_key,
            private_key,
        })
    }
}

/// Complete input for creating an SSH certificate authority.
#[derive(Debug)]
pub struct SshCertificateAuthorityCreation {
    friendly_name: String,
    key_material: SshCaKeyMaterial,
}

impl SshCertificateAuthorityCreation {
    /// Validate the complete CA creation input.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid friendly name.
    pub fn new(
        friendly_name: impl Into<String>,
        key_material: SshCaKeyMaterial,
    ) -> Result<Self, SshCertificateAuthorityInputError> {
        let friendly_name = validate_name(friendly_name.into())?;
        Ok(Self {
            friendly_name,
            key_material,
        })
    }
}

/// Full replacement of every mutable SSH CA field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCaReplacement {
    friendly_name: String,
    status: SshCaStatus,
}

impl SshCaReplacement {
    /// Validate a complete replacement.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid friendly name.
    pub fn new(
        friendly_name: impl Into<String>,
        status: SshCaStatus,
    ) -> Result<Self, SshCertificateAuthorityInputError> {
        Ok(Self {
            friendly_name: validate_name(friendly_name.into())?,
            status,
        })
    }
}

/// Value-free SSH CA metadata returned by project inventory and deletion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshCertificateAuthoritySummary {
    /// Canonical SSH CA UUID.
    pub id: String,
    /// Canonical owning SSH project UUID.
    pub project_id: String,
    /// Bounded display name.
    pub friendly_name: String,
    /// Current lifecycle state.
    pub status: SshCaStatus,
    /// Stored key algorithm.
    pub key_algorithm: SshKeyAlgorithm,
    /// Internal or imported key origin.
    pub key_source: SshCaKeySource,
}

/// Exact SSH CA details; only public key material crosses this boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshCertificateAuthority {
    /// Canonical SSH CA UUID.
    pub id: String,
    /// Canonical owning SSH project UUID.
    pub project_id: String,
    /// Bounded display name.
    pub friendly_name: String,
    /// Current lifecycle state.
    pub status: SshCaStatus,
    /// Stored key algorithm.
    pub key_algorithm: SshKeyAlgorithm,
    /// Internal or imported key origin.
    pub key_source: SshCaKeySource,
    /// Canonical supported OpenSSH public key.
    pub public_key: SshPublicKey,
}

impl SshCertificateAuthority {
    pub(crate) fn summary(&self) -> SshCertificateAuthoritySummary {
        SshCertificateAuthoritySummary {
            id: self.id.clone(),
            project_id: self.project_id.clone(),
            friendly_name: self.friendly_name.clone(),
            status: self.status,
            key_algorithm: self.key_algorithm,
            key_source: self.key_source,
        }
    }
}

fn validate_name(value: String) -> Result<String, SshCertificateAuthorityInputError> {
    if value.trim() != value
        || value.bytes().all(|byte| byte.is_ascii_whitespace())
        || !is_bounded_text(&value, MAX_SSH_CA_NAME_BYTES)
    {
        return Err(SshCertificateAuthorityInputError::InvalidName);
    }
    Ok(value)
}

fn rsa_key_pair_algorithm(key: &RsaKeyPair) -> Option<SshKeyAlgorithm> {
    match key.public_modulus_len() * 8 {
        2_048 => Some(SshKeyAlgorithm::Rsa2048),
        4_096 => Some(SshKeyAlgorithm::Rsa4096),
        _ => None,
    }
}

fn parsed_pkcs8_private_key_algorithm(der: &[u8]) -> Option<SshKeyAlgorithm> {
    let private_key = pkcs8::PrivateKeyInfo::from_der(der).ok()?;
    match private_key.algorithm.oid.to_string().as_str() {
        "1.2.840.113549.1.1.1" => RsaKeyPair::from_pkcs8(der)
            .ok()
            .as_ref()
            .and_then(rsa_key_pair_algorithm),
        "1.2.840.10045.2.1" => {
            if EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_ASN1_SIGNING, der).is_ok() {
                Some(SshKeyAlgorithm::EcP256)
            } else if EcdsaKeyPair::from_private_key_der(&ECDSA_P384_SHA384_ASN1_SIGNING, der)
                .is_ok()
            {
                Some(SshKeyAlgorithm::EcP384)
            } else {
                None
            }
        }
        "1.3.101.112" => Ed25519KeyPair::from_pkcs8(der)
            .is_ok()
            .then_some(SshKeyAlgorithm::Ed25519),
        _ => None,
    }
}

fn private_key_text_is_bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_SSH_PRIVATE_KEY_BYTES && !value.contains('\0')
}

fn validate_private_key(value: &str) -> Result<SshKeyAlgorithm, SshCertificateAuthorityInputError> {
    let canonical = value.trim();
    if !private_key_text_is_bounded(canonical) {
        return Err(SshCertificateAuthorityInputError::InvalidPrivateKey);
    }
    if canonical.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        return ParsedSshPrivateKey::from_openssh(canonical)
            .ok()
            .filter(|key| !key.is_encrypted())
            .and_then(|key| parsed_public_key_algorithm(key.public_key()))
            .ok_or(SshCertificateAuthorityInputError::InvalidPrivateKey);
    }
    let (label, der) = pem_rfc7468::decode_vec(canonical.as_bytes())
        .map_err(|_| SshCertificateAuthorityInputError::InvalidPrivateKey)?;
    let der = Zeroizing::new(der);
    let algorithm = match label {
        "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der)
            .ok()
            .as_ref()
            .and_then(rsa_key_pair_algorithm),
        "EC PRIVATE KEY" => {
            if EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_ASN1_SIGNING, &der).is_ok() {
                Some(SshKeyAlgorithm::EcP256)
            } else if EcdsaKeyPair::from_private_key_der(&ECDSA_P384_SHA384_ASN1_SIGNING, &der)
                .is_ok()
            {
                Some(SshKeyAlgorithm::EcP384)
            } else {
                None
            }
        }
        "PRIVATE KEY" => parsed_pkcs8_private_key_algorithm(&der),
        _ => None,
    };
    algorithm.ok_or(SshCertificateAuthorityInputError::InvalidPrivateKey)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectSshQuery {
    #[serde(skip_serializing)]
    project_id: SshProjectId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExactSshCaQuery {
    #[serde(skip_serializing)]
    ca_id: SshCertificateAuthorityId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshCaWire {
    id: String,
    project_id: String,
    friendly_name: String,
    status: SshCaStatus,
    key_algorithm: SshKeyAlgorithm,
    key_source: SshCaKeySource,
    #[serde(default)]
    public_key: Option<String>,
}

#[derive(Deserialize)]
struct SshCaResponse {
    ca: SshCaWire,
}

#[derive(Deserialize)]
struct SshCaListResponse {
    cas: Vec<SshCaWire>,
}

struct SecretRequestValue(SecretValue);

impl Serialize for SecretRequestValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.expose_secret())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSshCaRequest {
    project_id: String,
    friendly_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_algorithm: Option<SshKeyAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<SecretRequestValue>,
    key_source: SshCaKeySource,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplaceSshCaRequest {
    #[serde(skip_serializing)]
    ca_id: SshCertificateAuthorityId,
    friendly_name: String,
    status: SshCaStatus,
}

#[derive(Serialize)]
struct DeleteSshCaRequest {
    #[serde(skip_serializing)]
    ca_id: SshCertificateAuthorityId,
}

struct ListSshCertificateAuthorities;
impl sealed::Sealed for ListSshCertificateAuthorities {}
impl ObservableReadOperation for ListSshCertificateAuthorities {
    type Query = ProjectSshQuery;
    type Output = SshCaListResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["projects", query.project_id.as_str(), "ssh-cas"],
        )
    }
}

struct GetSshCertificateAuthority;
impl sealed::Sealed for GetSshCertificateAuthority {}
impl ObservableReadOperation for GetSshCertificateAuthority {
    type Query = ExactSshCaQuery;
    type Output = SshCaResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["ssh", "ca", query.ca_id.as_str()])
    }
}

struct GetSshCertificateAuthorityPublicKey;
impl sealed::Sealed for GetSshCertificateAuthorityPublicKey {}
impl ObservableReadOperation for GetSshCertificateAuthorityPublicKey {
    type Query = ExactSshCaQuery;
    type Output = String;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["ssh", "ca", query.ca_id.as_str(), "public-key"],
        )
    }
}

macro_rules! ssh_ca_mutation {
    ($operation:ident, $input:ty, $method:expr) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl MutationOperation for $operation {
            type Input = $input;
            type Output = SshCaResponse;

            fn method() -> Method {
                $method
            }

            fn endpoint(input: &Self::Input) -> Endpoint {
                let mut segments = vec!["ssh".to_owned(), "ca".to_owned()];
                if let Some(id) = mutation_ca_id(input) {
                    segments.push(id.to_owned());
                }
                Endpoint::from_segments(ApiVersion::V1, segments)
            }
        }
    };
}

trait SshCaMutationTarget {
    fn ca_id(&self) -> Option<&str>;
}

fn mutation_ca_id<T: SshCaMutationTarget + ?Sized>(input: &T) -> Option<&str> {
    input.ca_id()
}

impl SshCaMutationTarget for CreateSshCaRequest {
    fn ca_id(&self) -> Option<&str> {
        None
    }
}

impl SshCaMutationTarget for ReplaceSshCaRequest {
    fn ca_id(&self) -> Option<&str> {
        Some(self.ca_id.as_str())
    }
}

impl SshCaMutationTarget for DeleteSshCaRequest {
    fn ca_id(&self) -> Option<&str> {
        Some(self.ca_id.as_str())
    }
}

ssh_ca_mutation!(
    CreateSshCertificateAuthority,
    CreateSshCaRequest,
    Method::POST
);
ssh_ca_mutation!(
    ReplaceSshCertificateAuthority,
    ReplaceSshCaRequest,
    Method::PATCH
);
ssh_ca_mutation!(
    DeleteSshCertificateAuthority,
    DeleteSshCaRequest,
    Method::DELETE
);

fn summary_from_wire(
    wire: SshCaWire,
    project_id: &SshProjectId,
    expected_id: Option<&SshCertificateAuthorityId>,
) -> Result<SshCertificateAuthoritySummary, ResourceError> {
    let id = SshCertificateAuthorityId::new(wire.id)
        .map_err(|_| ResourceError::InvalidSshCertificateAuthorityResponse)?;
    let response_project_id = SshProjectId::new(wire.project_id)
        .map_err(|_| ResourceError::InvalidSshCertificateAuthorityResponse)?;
    if &response_project_id != project_id || expected_id.is_some_and(|expected| expected != &id) {
        return Err(ResourceError::InvalidSshCertificateAuthorityScope);
    }
    if wire.public_key.is_some() {
        return Err(ResourceError::InvalidSshCertificateAuthorityResponse);
    }
    Ok(SshCertificateAuthoritySummary {
        id: id.as_str().to_owned(),
        project_id: response_project_id.as_str().to_owned(),
        friendly_name: validate_name(wire.friendly_name)
            .map_err(|_| ResourceError::InvalidSshCertificateAuthorityResponse)?,
        status: wire.status,
        key_algorithm: wire.key_algorithm,
        key_source: wire.key_source,
    })
}

fn authority_from_wire(
    wire: SshCaWire,
    project_id: &SshProjectId,
    expected_id: Option<&SshCertificateAuthorityId>,
) -> Result<SshCertificateAuthority, ResourceError> {
    let id = SshCertificateAuthorityId::new(wire.id)
        .map_err(|_| ResourceError::InvalidSshCertificateAuthorityResponse)?;
    let response_project_id = SshProjectId::new(wire.project_id)
        .map_err(|_| ResourceError::InvalidSshCertificateAuthorityResponse)?;
    if &response_project_id != project_id || expected_id.is_some_and(|expected| expected != &id) {
        return Err(ResourceError::InvalidSshCertificateAuthorityScope);
    }
    let public_key = SshPublicKey::new(
        wire.public_key
            .ok_or(ResourceError::InvalidSshCertificateAuthorityResponse)?,
    )
    .map_err(|_| ResourceError::InvalidSshCertificateAuthorityResponse)?;
    if !public_key.matches_algorithm(wire.key_algorithm) {
        return Err(ResourceError::InvalidSshCertificateAuthorityResponse);
    }
    Ok(SshCertificateAuthority {
        id: id.as_str().to_owned(),
        project_id: response_project_id.as_str().to_owned(),
        friendly_name: validate_name(wire.friendly_name)
            .map_err(|_| ResourceError::InvalidSshCertificateAuthorityResponse)?,
        status: wire.status,
        key_algorithm: wire.key_algorithm,
        key_source: wire.key_source,
        public_key,
    })
}

impl InfisicalClient {
    /// List bounded SSH CA metadata for one exact SSH Access project.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, duplicate, or bounded-response error.
    pub async fn list_ssh_certificate_authorities(
        &self,
        project_id: &SshProjectId,
    ) -> Result<Vec<SshCertificateAuthoritySummary>, ResourceError> {
        let response = self
            .execute_observable_read::<ListSshCertificateAuthorities>(&ProjectSshQuery {
                project_id: project_id.clone(),
            })
            .await?;
        if response.cas.len() > MAX_SSH_CA_ENTRIES {
            return Err(ResourceError::InvalidSshCertificateAuthorityResponse);
        }
        let authorities = response
            .cas
            .into_iter()
            .map(|wire| summary_from_wire(wire, project_id, None))
            .collect::<Result<Vec<_>, _>>()?;
        if authorities
            .iter()
            .map(|authority| authority.id.as_str())
            .collect::<HashSet<_>>()
            .len()
            != authorities.len()
        {
            return Err(ResourceError::InvalidSshCertificateAuthorityResponse);
        }
        Ok(authorities)
    }

    /// Get one exact SSH CA and prove its project ownership.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or response-contract error.
    pub async fn get_ssh_certificate_authority(
        &self,
        project_id: &SshProjectId,
        ca_id: &SshCertificateAuthorityId,
    ) -> Result<SshCertificateAuthority, ResourceError> {
        let response = self
            .execute_observable_read::<GetSshCertificateAuthority>(&ExactSshCaQuery {
                ca_id: ca_id.clone(),
            })
            .await?;
        authority_from_wire(response.ca, project_id, Some(ca_id))
    }

    /// Read the dedicated public-key route and bind it to the authenticated CA record.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or mismatched-key error.
    pub async fn get_ssh_certificate_authority_public_key(
        &self,
        project_id: &SshProjectId,
        ca_id: &SshCertificateAuthorityId,
    ) -> Result<SshPublicKey, ResourceError> {
        let authority = self
            .get_ssh_certificate_authority(project_id, ca_id)
            .await?;
        let public_key = self
            .execute_observable_read::<GetSshCertificateAuthorityPublicKey>(&ExactSshCaQuery {
                ca_id: ca_id.clone(),
            })
            .await?;
        let public_key = SshPublicKey::new(public_key)
            .map_err(|_| ResourceError::InvalidSshCertificateAuthorityResponse)?;
        if public_key != authority.public_key {
            return Err(ResourceError::InvalidSshCertificateAuthorityResponse);
        }
        Ok(public_key)
    }

    /// Create one internal or externally keyed SSH CA in one exact SSH project.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn create_ssh_certificate_authority(
        &self,
        project_id: &SshProjectId,
        creation: SshCertificateAuthorityCreation,
        confirm: bool,
    ) -> Result<SshCertificateAuthority, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshCertificateAuthorityCreateNotConfirmed);
        }
        let (key_algorithm, public_key, private_key, key_source) = match creation.key_material {
            SshCaKeyMaterial::Internal(algorithm) => {
                (Some(algorithm), None, None, SshCaKeySource::Internal)
            }
            SshCaKeyMaterial::External {
                public_key,
                private_key,
            } => (
                None,
                Some(public_key.as_str().to_owned()),
                Some(SecretRequestValue(private_key)),
                SshCaKeySource::External,
            ),
        };
        let request = CreateSshCaRequest {
            project_id: project_id.as_str().to_owned(),
            friendly_name: creation.friendly_name.clone(),
            key_algorithm,
            public_key: public_key.clone(),
            private_key,
            key_source,
        };
        let response = self
            .execute_mutation::<CreateSshCertificateAuthority>(&request)
            .await?;
        let authority = authority_from_wire(response.ca, project_id, None)?;
        if authority.friendly_name != creation.friendly_name
            || authority.status != SshCaStatus::Active
            || authority.key_source != key_source
            || key_algorithm.is_some_and(|expected| authority.key_algorithm != expected)
            || public_key
                .as_deref()
                .is_some_and(|expected| authority.public_key.as_str() != expected)
        {
            return Err(ResourceError::InvalidSshCertificateAuthorityResponse);
        }
        Ok(authority)
    }

    /// Replace every mutable SSH CA field after an exact ownership preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn replace_ssh_certificate_authority(
        &self,
        project_id: &SshProjectId,
        ca_id: &SshCertificateAuthorityId,
        replacement: &SshCaReplacement,
        confirm: bool,
    ) -> Result<SshCertificateAuthority, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshCertificateAuthorityReplaceNotConfirmed);
        }
        let before = self
            .get_ssh_certificate_authority(project_id, ca_id)
            .await?;
        let response = self
            .execute_mutation::<ReplaceSshCertificateAuthority>(&ReplaceSshCaRequest {
                ca_id: ca_id.clone(),
                friendly_name: replacement.friendly_name.clone(),
                status: replacement.status,
            })
            .await?;
        let authority = authority_from_wire(response.ca, project_id, Some(ca_id))?;
        if authority.friendly_name != replacement.friendly_name
            || authority.status != replacement.status
            || authority.key_algorithm != before.key_algorithm
            || authority.key_source != before.key_source
            || authority.public_key != before.public_key
        {
            return Err(ResourceError::InvalidSshCertificateAuthorityResponse);
        }
        Ok(authority)
    }

    /// Delete one exact SSH CA after explicit confirmation and ownership preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn delete_ssh_certificate_authority(
        &self,
        project_id: &SshProjectId,
        ca_id: &SshCertificateAuthorityId,
        confirm: bool,
    ) -> Result<SshCertificateAuthoritySummary, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshCertificateAuthorityDeleteNotConfirmed);
        }
        let before = self
            .get_ssh_certificate_authority(project_id, ca_id)
            .await?;
        let response = self
            .execute_mutation::<DeleteSshCertificateAuthority>(&DeleteSshCaRequest {
                ca_id: ca_id.clone(),
            })
            .await?;
        let deleted = summary_from_wire(response.ca, project_id, Some(ca_id))?;
        if deleted != before.summary() {
            return Err(ResourceError::InvalidSshCertificateAuthorityResponse);
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    use super::{
        MAX_SSH_PRIVATE_KEY_BYTES, SshCaKeyMaterial, SshCaReplacement, SshCaStatus,
        SshCertificateAuthorityCreation, SshCertificateAuthorityId,
        SshCertificateAuthorityInputError, SshKeyAlgorithm, SshProjectId, SshPublicKey,
        validate_private_key,
    };
    use crate::{
        InfisicalClient, ResourceError, SecretValue,
        test_support::{mount_login, settings},
    };

    const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const CA_ID: &str = "22222222-2222-4222-8222-222222222222";
    const PRIVATE_KEY_CANARY: &str = "b3BlbnNzaC1rZXktdjE";

    fn public_key() -> &'static str {
        include_str!("../test-fixtures/ssh-ed25519-public-key.txt").trim()
    }

    fn private_key() -> &'static str {
        include_str!("../test-fixtures/ssh-ed25519-private-key.txt").trim()
    }

    fn ca_json(name: &str, status: &str, include_public_key: bool) -> Value {
        let mut ca = json!({
            "id": CA_ID,
            "projectId": PROJECT_ID,
            "friendlyName": name,
            "status": status,
            "keyAlgorithm": "ED25519",
            "keySource": "internal"
        });
        if include_public_key {
            ca["publicKey"] = json!(public_key());
        }
        ca
    }

    async fn assert_ssh_ca_create_rejects_reflection_drift(response_ca: Value, external: bool) {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-ca-reflection-token").await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ssh/ca"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ca": response_ca })))
            .expect(1)
            .mount(&server)
            .await;
        let key_material = if external {
            SshCaKeyMaterial::external(
                SshPublicKey::new(public_key()).unwrap(),
                SecretValue::new(private_key()),
            )
            .unwrap()
        } else {
            SshCaKeyMaterial::Internal(SshKeyAlgorithm::Ed25519)
        };
        let result = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_ssh_certificate_authority(
                &SshProjectId::new(PROJECT_ID).unwrap(),
                SshCertificateAuthorityCreation::new("primary-ca", key_material).unwrap(),
                true,
            )
            .await;
        assert!(matches!(
            result,
            Err(ResourceError::InvalidSshCertificateAuthorityResponse)
        ));
    }

    #[test]
    fn ssh_ca_key_public_inputs_are_structurally_parsed_and_canonicalized() {
        let rsa_with_leading_zero_bits = ssh_key::public::RsaPublicKey {
            e: ssh_key::Mpint::from_positive_bytes(&[1, 0, 1]).unwrap(),
            n: ssh_key::Mpint::from_positive_bytes(&[0x40, 0]).unwrap(),
        };
        assert_eq!(
            super::rsa_modulus_bits(&rsa_with_leading_zero_bits),
            Some(15)
        );
        for (key, algorithm) in [
            (
                include_str!("../test-fixtures/ssh-ed25519-public-key.txt"),
                SshKeyAlgorithm::Ed25519,
            ),
            (
                include_str!("../test-fixtures/ssh-rsa-2048-public-key.txt"),
                SshKeyAlgorithm::Rsa2048,
            ),
            (
                include_str!("../test-fixtures/ssh-rsa-4096-public-key.txt"),
                SshKeyAlgorithm::Rsa4096,
            ),
            (
                include_str!("../test-fixtures/ssh-ecdsa-p256-public-key.txt"),
                SshKeyAlgorithm::EcP256,
            ),
            (
                include_str!("../test-fixtures/ssh-ecdsa-p384-public-key.txt"),
                SshKeyAlgorithm::EcP384,
            ),
        ] {
            assert!(SshPublicKey::new(key).unwrap().matches_algorithm(algorithm));
        }
        assert_eq!(
            SshPublicKey::new(format!("  {}  \n", public_key()))
                .unwrap()
                .as_str(),
            public_key()
        );
        for invalid in [
            "ssh-dss AQID",
            "ssh-ed25519 not-base64",
            "ssh-ed25519 AQID",
            "ssh-ed25519 AQID\ncomment",
            include_str!("../test-fixtures/ssh-rsa-3072-public-key.txt"),
        ] {
            assert_eq!(
                SshPublicKey::new(invalid).unwrap_err(),
                SshCertificateAuthorityInputError::InvalidPublicKey
            );
        }
    }

    #[test]
    fn ssh_ca_key_private_inputs_are_structurally_parsed_and_bounded() {
        assert!(!super::private_key_text_is_bounded(""));
        assert!(super::private_key_text_is_bounded("A"));
        assert!(super::private_key_text_is_bounded(
            &"A".repeat(MAX_SSH_PRIVATE_KEY_BYTES)
        ));
        assert!(!super::private_key_text_is_bounded(
            &"A".repeat(MAX_SSH_PRIVATE_KEY_BYTES + 1)
        ));
        assert!(!super::private_key_text_is_bounded("A\0B"));
        let parsed_private_key = super::ParsedSshPrivateKey::from_openssh(private_key()).unwrap();
        assert!(!parsed_private_key.is_encrypted());
        assert_eq!(
            super::parsed_public_key_algorithm(parsed_private_key.public_key()),
            Some(SshKeyAlgorithm::Ed25519)
        );
        for (key, algorithm) in [
            (
                include_str!("../test-fixtures/ssh-rsa-2048-pkcs1-private-key.txt"),
                SshKeyAlgorithm::Rsa2048,
            ),
            (
                include_str!("../test-fixtures/ssh-rsa-4096-pkcs1-private-key.txt"),
                SshKeyAlgorithm::Rsa4096,
            ),
            (
                include_str!("../test-fixtures/ssh-rsa-2048-pkcs8-private-key.txt"),
                SshKeyAlgorithm::Rsa2048,
            ),
            (
                include_str!("../test-fixtures/ssh-ecdsa-p256-sec1-private-key.txt"),
                SshKeyAlgorithm::EcP256,
            ),
            (
                include_str!("../test-fixtures/ssh-ecdsa-p384-sec1-private-key.txt"),
                SshKeyAlgorithm::EcP384,
            ),
            (
                include_str!("../test-fixtures/ssh-ecdsa-p256-pkcs8-private-key.txt"),
                SshKeyAlgorithm::EcP256,
            ),
            (
                include_str!("../test-fixtures/profile-private-key.txt"),
                SshKeyAlgorithm::Ed25519,
            ),
        ] {
            assert_eq!(validate_private_key(key), Ok(algorithm));
        }

        let oversized = format!("{}{}", private_key(), "A".repeat(MAX_SSH_PRIVATE_KEY_BYTES));
        for invalid in [
            String::new(),
            format!("{}\0", private_key()),
            include_str!("../test-fixtures/ssh-ed25519-encrypted-private-key.txt").into(),
            "-----BEGIN RSA PRIVATE KEY-----\nAQID\n-----END EC PRIVATE KEY-----".into(),
            "-----BEGIN RSA PRIVATE KEY-----\nAQID\n-----END RSA PRIVATE KEY-----".into(),
            "-----BEGIN EC PRIVATE KEY-----\nAQID\n-----END EC PRIVATE KEY-----".into(),
            "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----".into(),
            oversized,
        ] {
            assert_eq!(
                validate_private_key(&invalid),
                Err(SshCertificateAuthorityInputError::InvalidPrivateKey)
            );
        }
    }

    #[test]
    fn ssh_ca_key_material_is_typed_and_secret_redacted() {
        assert_eq!(
            SshProjectId::new("../project").unwrap_err(),
            SshCertificateAuthorityInputError::InvalidProjectId
        );
        assert_eq!(
            SshCertificateAuthorityId::new("ca/escape").unwrap_err(),
            SshCertificateAuthorityInputError::InvalidId
        );
        assert!(
            SshCertificateAuthorityCreation::new(
                " ",
                SshCaKeyMaterial::Internal(SshKeyAlgorithm::Ed25519)
            )
            .is_err()
        );
        let external = SshCaKeyMaterial::external(
            SshPublicKey::new(public_key()).unwrap(),
            SecretValue::new(private_key()),
        )
        .unwrap();
        let debug = format!("{external:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(PRIVATE_KEY_CANARY));
        assert_eq!(
            SshCaKeyMaterial::external(
                SshPublicKey::new(include_str!("../test-fixtures/ssh-rsa-2048-public-key.txt"))
                    .unwrap(),
                SecretValue::new(private_key()),
            )
            .unwrap_err(),
            SshCertificateAuthorityInputError::MismatchedKeyAlgorithms
        );
    }

    #[tokio::test]
    async fn ssh_ca_get_rejects_public_key_algorithm_drift() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-ca-algorithm-drift-token").await;
        let mut drifted = ca_json("primary-ca", "active", true);
        drifted["keyAlgorithm"] = json!("RSA_2048");
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/ca/{CA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ca": drifted })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert!(matches!(
            client
                .get_ssh_certificate_authority(
                    &SshProjectId::new(PROJECT_ID).unwrap(),
                    &SshCertificateAuthorityId::new(CA_ID).unwrap(),
                )
                .await,
            Err(ResourceError::InvalidSshCertificateAuthorityResponse)
        ));
    }

    #[tokio::test]
    async fn ssh_ca_inventory_uses_the_exact_project_route_and_rejects_scope_drift() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-ca-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{PROJECT_ID}/ssh-cas")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "cas": [ca_json("primary-ca", "active", false)]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = SshProjectId::new(PROJECT_ID).unwrap();
        let authorities = client
            .list_ssh_certificate_authorities(&project_id)
            .await
            .unwrap();
        assert_eq!(authorities.len(), 1);
        assert_eq!(authorities[0].friendly_name, "primary-ca");

        let drift_server = MockServer::start().await;
        mount_login(&drift_server, "ssh-ca-drift-token").await;
        let mut drifted = ca_json("primary-ca", "active", false);
        drifted["projectId"] = json!("33333333-3333-4333-8333-333333333333");
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{PROJECT_ID}/ssh-cas")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "cas": [drifted] })))
            .mount(&drift_server)
            .await;
        let drift_client = InfisicalClient::new(settings(&drift_server)).unwrap();
        assert!(matches!(
            drift_client
                .list_ssh_certificate_authorities(&project_id)
                .await,
            Err(ResourceError::InvalidSshCertificateAuthorityScope)
        ));
    }

    #[tokio::test]
    async fn unconfirmed_ssh_ca_mutations_fail_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = SshProjectId::new(PROJECT_ID).unwrap();
        let ca_id = SshCertificateAuthorityId::new(CA_ID).unwrap();
        let creation = SshCertificateAuthorityCreation::new(
            "primary-ca",
            SshCaKeyMaterial::Internal(SshKeyAlgorithm::Ed25519),
        )
        .unwrap();
        assert!(matches!(
            client
                .create_ssh_certificate_authority(&project_id, creation, false)
                .await,
            Err(ResourceError::SshCertificateAuthorityCreateNotConfirmed)
        ));
        assert!(matches!(
            client
                .replace_ssh_certificate_authority(
                    &project_id,
                    &ca_id,
                    &SshCaReplacement::new("renamed-ca", SshCaStatus::Disabled).unwrap(),
                    false,
                )
                .await,
            Err(ResourceError::SshCertificateAuthorityReplaceNotConfirmed)
        ));
        assert!(matches!(
            client
                .delete_ssh_certificate_authority(&project_id, &ca_id, false)
                .await,
            Err(ResourceError::SshCertificateAuthorityDeleteNotConfirmed)
        ));
    }

    #[tokio::test]
    async fn ssh_ca_creation_sends_one_exact_project_scoped_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-ca-create-token").await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ssh/ca"))
            .and(body_json(json!({
                "projectId": PROJECT_ID,
                "friendlyName": "primary-ca",
                "keyAlgorithm": "ED25519",
                "keySource": "internal"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ca": ca_json("primary-ca", "active", true)
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let authority = client
            .create_ssh_certificate_authority(
                &SshProjectId::new(PROJECT_ID).unwrap(),
                SshCertificateAuthorityCreation::new(
                    "primary-ca",
                    SshCaKeyMaterial::Internal(SshKeyAlgorithm::Ed25519),
                )
                .unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(authority.id, CA_ID);
        assert_eq!(authority.public_key.as_str(), public_key());
    }

    #[tokio::test]
    async fn ssh_ca_creation_rejects_each_reflected_field_drift() {
        let name_drift = ca_json("different-ca", "active", true);
        assert_ssh_ca_create_rejects_reflection_drift(name_drift, false).await;

        let status_drift = ca_json("primary-ca", "disabled", true);
        assert_ssh_ca_create_rejects_reflection_drift(status_drift, false).await;

        let mut source_drift = ca_json("primary-ca", "active", true);
        source_drift["keySource"] = json!("external");
        assert_ssh_ca_create_rejects_reflection_drift(source_drift, false).await;

        let mut algorithm_drift = ca_json("primary-ca", "active", true);
        algorithm_drift["keyAlgorithm"] = json!("RSA_2048");
        algorithm_drift["publicKey"] =
            json!(include_str!("../test-fixtures/ssh-rsa-2048-public-key.txt").trim());
        assert_ssh_ca_create_rejects_reflection_drift(algorithm_drift, false).await;

        let mut public_key_drift = ca_json("primary-ca", "active", true);
        public_key_drift["keySource"] = json!("external");
        public_key_drift["publicKey"] =
            json!(public_key().replace("fixture@example.test", "different@example.test"));
        assert_ssh_ca_create_rejects_reflection_drift(public_key_drift, true).await;
    }

    #[tokio::test]
    async fn external_ssh_ca_creation_transmits_the_secret_once_without_echoing_it() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-external-ca-token").await;
        let mut external_ca = ca_json("external-ca", "active", true);
        external_ca["keySource"] = json!("external");
        Mock::given(method("POST"))
            .and(path("/api/v1/ssh/ca"))
            .and(body_json(json!({
                "projectId": PROJECT_ID,
                "friendlyName": "external-ca",
                "publicKey": public_key(),
                "privateKey": private_key(),
                "keySource": "external"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ca": external_ca })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let authority = client
            .create_ssh_certificate_authority(
                &SshProjectId::new(PROJECT_ID).unwrap(),
                SshCertificateAuthorityCreation::new(
                    "external-ca",
                    SshCaKeyMaterial::external(
                        SshPublicKey::new(public_key()).unwrap(),
                        SecretValue::new(private_key()),
                    )
                    .unwrap(),
                )
                .unwrap(),
                true,
            )
            .await
            .unwrap();
        let output = serde_json::to_string(&authority).unwrap();
        assert!(output.contains(public_key()));
        assert!(!output.contains("PRIVATE KEY"));
    }

    #[tokio::test]
    async fn ssh_ca_replace_delete_and_public_key_routes_rebind_exact_results() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-ca-lifecycle-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/ca/{CA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ca": ca_json("renamed-ca", "disabled", true)
            })))
            .expect(3)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/ca/{CA_ID}/public-key")))
            .respond_with(ResponseTemplate::new(200).set_body_json(public_key()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/ssh/ca/{CA_ID}")))
            .and(body_json(json!({
                "friendlyName": "renamed-ca",
                "status": "disabled"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ca": ca_json("renamed-ca", "disabled", true)
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/ssh/ca/{CA_ID}")))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ca": ca_json("renamed-ca", "disabled", false)
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = SshProjectId::new(PROJECT_ID).unwrap();
        let ca_id = SshCertificateAuthorityId::new(CA_ID).unwrap();
        client
            .replace_ssh_certificate_authority(
                &project_id,
                &ca_id,
                &SshCaReplacement::new("renamed-ca", SshCaStatus::Disabled).unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(
            client
                .get_ssh_certificate_authority_public_key(&project_id, &ca_id)
                .await
                .unwrap()
                .as_str(),
            public_key()
        );
        let deleted = client
            .delete_ssh_certificate_authority(&project_id, &ca_id, true)
            .await
            .unwrap();
        assert_eq!(deleted.friendly_name, "renamed-ca");
        assert_eq!(deleted.status, SshCaStatus::Disabled);
    }
}
