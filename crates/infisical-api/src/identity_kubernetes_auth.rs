use std::collections::HashSet;

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use url::Url;

use crate::{
    IdentityId, InfisicalClient, MutationOperation, ReadOperation, ResourceError, SecretValue,
    TrustedIp,
    certificate::is_valid_ca_certificate_bundle,
    client::{ApiVersion, Endpoint, sealed},
};

/// Maximum access-token lifetime accepted by the pinned Kubernetes Auth route.
pub const MAX_KUBERNETES_AUTH_LIFETIME_SECONDS: u32 = 315_360_000;
/// Maximum Kubernetes API URL accepted at the MCP boundary.
pub const MAX_KUBERNETES_AUTH_HOST_BYTES: usize = 2_048;
/// Maximum PEM CA bundle accepted at the MCP boundary.
pub const MAX_KUBERNETES_AUTH_CA_CERT_BYTES: usize = 131_072;
/// Maximum token-reviewer JWT accepted at the MCP boundary.
pub const MAX_KUBERNETES_AUTH_REVIEWER_JWT_BYTES: usize = 16_384;
/// Maximum number of namespace or service-account patterns in one policy.
pub const MAX_KUBERNETES_AUTH_POLICY_PATTERNS: usize = 100;
/// Maximum size of one namespace, service-account, or glob pattern.
pub const MAX_KUBERNETES_AUTH_POLICY_PATTERN_BYTES: usize = 253;
/// Maximum Kubernetes token audience accepted at the MCP boundary.
pub const MAX_KUBERNETES_AUTH_AUDIENCE_BYTES: usize = 2_048;

/// Validation failures for Kubernetes Auth configuration.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum KubernetesAuthInputError {
    /// A token lifetime exceeded the pinned API limit.
    #[error("access-token lifetimes must not exceed 315360000 seconds")]
    InvalidTokenLifetime,
    /// The ordinary token lifetime exceeded its maximum lifetime.
    #[error("access token TTL must not exceed access token maximum TTL")]
    TokenLifetimeOrder,
    /// The Kubernetes API endpoint was not a bounded HTTPS URL supported by Infisical.
    #[error(
        "Kubernetes host must be a 1 to 2048 byte HTTPS URL containing only letters, numbers, colons, periods, hyphens, and forward slashes"
    )]
    InvalidKubernetesHost,
    /// The CA bundle was malformed, inconsistent with TLS verification, or too large.
    #[error(
        "CA certificate must be a bounded PEM certificate bundle and is required exactly when TLS verification is enabled"
    )]
    InvalidCaCertificate,
    /// The token-reviewer credential was empty, padded, control-bearing, or too large.
    #[error("token-reviewer JWT must contain 1 to 16384 non-control bytes without padding")]
    InvalidTokenReviewerJwt,
    /// A namespace or service-account policy was empty, duplicate, unbounded, or ambiguous.
    #[error(
        "namespace and service-account policies require 1 to 100 unique, comma-free patterns of at most 253 bytes"
    )]
    InvalidWorkloadPolicy,
    /// The audience did not establish one bounded exact value.
    #[error("allowed audience must contain 1 to 2048 bytes without padding or control characters")]
    InvalidAudience,
}

/// Token-review implementation configured on the machine identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum KubernetesAuthTokenReviewMode {
    /// Infisical contacts the Kubernetes `TokenReview` API directly.
    Api,
    /// Infisical contacts Kubernetes through a paid Infisical Gateway.
    Gateway,
}

/// Non-secret Kubernetes Auth configuration for one machine identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesAuthConfig {
    /// Opaque Kubernetes Auth configuration identifier.
    pub id: String,
    /// Machine identity that owns this authentication method.
    pub identity_id: String,
    /// Ordinary access-token lifetime in seconds.
    #[serde(rename = "accessTokenTTL")]
    pub access_token_ttl: u32,
    /// Maximum renewable access-token lifetime in seconds.
    #[serde(rename = "accessTokenMaxTTL")]
    pub access_token_max_ttl: u32,
    /// Maximum token uses; zero means unlimited.
    pub access_token_num_uses_limit: u32,
    /// Access-token source ranges, readable but not mutable in the community surface.
    pub access_token_trusted_ips: Vec<TrustedIp>,
    /// Token-review implementation currently configured upstream.
    pub token_review_mode: KubernetesAuthTokenReviewMode,
    /// Kubernetes API endpoint used for direct token review.
    pub kubernetes_host: Option<String>,
    /// Allowed Kubernetes namespace names or glob patterns.
    pub allowed_namespaces: Vec<String>,
    /// Allowed Kubernetes service-account names or glob patterns.
    pub allowed_names: Vec<String>,
    /// Exact Kubernetes token audience required during login.
    pub allowed_audience: Option<String>,
    /// Whether the stored Kubernetes API CA bundle is present.
    pub ca_certificate_configured: bool,
    /// Whether the stored token-reviewer credential is present.
    pub token_reviewer_jwt_configured: bool,
    /// Whether Infisical verifies the Kubernetes API TLS certificate.
    pub verify_tls_certificate: bool,
    /// Paid Infisical Gateway identifier, when an existing configuration uses one.
    pub gateway_id: Option<String>,
    /// Paid Infisical Gateway Pool identifier, when configured.
    pub gateway_pool_id: Option<String>,
    /// Infisical creation timestamp.
    pub created_at: String,
    /// Infisical update timestamp.
    pub updated_at: String,
}

/// Complete community-compatible Kubernetes Auth settings used during attachment.
#[derive(Debug)]
pub struct KubernetesAuthSettings {
    kubernetes_host: String,
    ca_cert: Option<String>,
    verify_tls_certificate: bool,
    token_reviewer_jwt: Option<SecretValue>,
    allowed_namespaces: String,
    allowed_names: String,
    allowed_audience: String,
    access_token_ttl: u32,
    access_token_max_ttl: u32,
    access_token_num_uses_limit: u32,
}

impl KubernetesAuthSettings {
    /// Validate a complete direct Kubernetes API configuration before mutation.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for any unsafe or out-of-contract value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kubernetes_host: impl Into<String>,
        ca_cert: Option<String>,
        verify_tls_certificate: bool,
        token_reviewer_jwt: Option<SecretValue>,
        allowed_namespaces: &[String],
        allowed_names: &[String],
        allowed_audience: impl Into<String>,
        access_token_ttl: u32,
        access_token_max_ttl: u32,
        access_token_num_uses_limit: u32,
    ) -> Result<Self, KubernetesAuthInputError> {
        let kubernetes_host = validate_host(kubernetes_host.into())?;
        let ca_cert = validate_ca_certificate(ca_cert, verify_tls_certificate)?;
        validate_reviewer_jwt(token_reviewer_jwt.as_ref())?;
        let allowed_namespaces = validate_patterns(allowed_namespaces)?;
        let allowed_names = validate_patterns(allowed_names)?;
        let allowed_audience = validate_audience(allowed_audience.into())?;
        validate_lifetime(access_token_ttl, access_token_max_ttl)?;
        Ok(Self {
            kubernetes_host,
            ca_cert,
            verify_tls_certificate,
            token_reviewer_jwt,
            allowed_namespaces,
            allowed_names,
            allowed_audience,
            access_token_ttl,
            access_token_max_ttl,
            access_token_num_uses_limit,
        })
    }
}

/// Treatment of the stored token-reviewer credential during a direct-review update.
#[derive(Debug)]
pub enum KubernetesTokenReviewerJwtChange {
    /// Preserve the existing credential without reading it first.
    Preserve,
    /// Replace the existing credential with one exact redacting value.
    Replace(SecretValue),
    /// Clear the stored credential.
    Clear,
}

/// One coherent Kubernetes Auth configuration change.
#[derive(Debug)]
pub enum KubernetesAuthChange {
    /// Replace both mutually constrained token lifetime fields together.
    TokenLifetime {
        /// Ordinary access-token lifetime in seconds.
        access_token_ttl: u32,
        /// Maximum renewable access-token lifetime in seconds.
        access_token_max_ttl: u32,
    },
    /// Replace the token use limit; zero means unlimited.
    AccessTokenUseLimit(u32),
    /// Replace the complete namespace, service-account, and audience policy.
    WorkloadPolicy {
        /// Comma-separated namespace patterns used by the pinned route.
        allowed_namespaces: String,
        /// Comma-separated service-account patterns used by the pinned route.
        allowed_names: String,
        /// Exact required audience.
        allowed_audience: String,
    },
    /// Replace the complete direct Kubernetes API reviewer configuration.
    DirectReviewer {
        /// Kubernetes API endpoint.
        kubernetes_host: String,
        /// Optional PEM CA bundle.
        ca_cert: Option<String>,
        /// Whether the CA bundle is used for TLS verification.
        verify_tls_certificate: bool,
        /// Explicit treatment of the stored reviewer JWT.
        token_reviewer_jwt: KubernetesTokenReviewerJwtChange,
    },
}

impl KubernetesAuthChange {
    /// Validate a complete token-lifetime change.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for an invalid lifetime or ordering.
    pub fn token_lifetime(
        access_token_ttl: u32,
        access_token_max_ttl: u32,
    ) -> Result<Self, KubernetesAuthInputError> {
        validate_lifetime(access_token_ttl, access_token_max_ttl)?;
        Ok(Self::TokenLifetime {
            access_token_ttl,
            access_token_max_ttl,
        })
    }

    /// Validate and build one complete workload policy change.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for an unsafe pattern or audience.
    pub fn workload_policy(
        allowed_namespaces: &[String],
        allowed_names: &[String],
        allowed_audience: impl Into<String>,
    ) -> Result<Self, KubernetesAuthInputError> {
        Ok(Self::WorkloadPolicy {
            allowed_namespaces: validate_patterns(allowed_namespaces)?,
            allowed_names: validate_patterns(allowed_names)?,
            allowed_audience: validate_audience(allowed_audience.into())?,
        })
    }

    /// Validate and build one complete direct-reviewer change.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for an unsafe endpoint, CA bundle, or credential.
    pub fn direct_reviewer(
        kubernetes_host: impl Into<String>,
        ca_cert: Option<String>,
        verify_tls_certificate: bool,
        token_reviewer_jwt: KubernetesTokenReviewerJwtChange,
    ) -> Result<Self, KubernetesAuthInputError> {
        let kubernetes_host = validate_host(kubernetes_host.into())?;
        let ca_cert = validate_ca_certificate(ca_cert, verify_tls_certificate)?;
        if let KubernetesTokenReviewerJwtChange::Replace(value) = &token_reviewer_jwt {
            validate_reviewer_jwt(Some(value))?;
        }
        Ok(Self::DirectReviewer {
            kubernetes_host,
            ca_cert,
            verify_tls_certificate,
            token_reviewer_jwt,
        })
    }
}

fn validate_lifetime(
    access_token_ttl: u32,
    access_token_max_ttl: u32,
) -> Result<(), KubernetesAuthInputError> {
    if access_token_ttl > MAX_KUBERNETES_AUTH_LIFETIME_SECONDS
        || access_token_max_ttl > MAX_KUBERNETES_AUTH_LIFETIME_SECONDS
    {
        return Err(KubernetesAuthInputError::InvalidTokenLifetime);
    }
    if access_token_ttl > access_token_max_ttl {
        return Err(KubernetesAuthInputError::TokenLifetimeOrder);
    }
    Ok(())
}

fn validate_host(value: String) -> Result<String, KubernetesAuthInputError> {
    if value.is_empty()
        || value.len() > MAX_KUBERNETES_AUTH_HOST_BYTES
        || value.trim() != value
        || value
            .strip_prefix("https://")
            .is_none_or(|authority| authority.is_empty() || authority.starts_with('/'))
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'/' | b'-'))
        || Url::parse(&value).is_err()
    {
        return Err(KubernetesAuthInputError::InvalidKubernetesHost);
    }
    Ok(value)
}

fn validate_ca_certificate(
    value: Option<String>,
    verify_tls_certificate: bool,
) -> Result<Option<String>, KubernetesAuthInputError> {
    if value
        .as_ref()
        .is_some_and(|certificate| certificate.len() > MAX_KUBERNETES_AUTH_CA_CERT_BYTES)
    {
        return Err(KubernetesAuthInputError::InvalidCaCertificate);
    }
    let value = value.map(|certificate| certificate.trim().to_owned());
    match (value, verify_tls_certificate) {
        (None, false) => Ok(None),
        (Some(certificate), true)
            if !certificate.is_empty()
                && !certificate.contains('\0')
                && is_valid_ca_certificate_bundle(&certificate) =>
        {
            Ok(Some(certificate))
        }
        _ => Err(KubernetesAuthInputError::InvalidCaCertificate),
    }
}

fn validate_reviewer_jwt(value: Option<&SecretValue>) -> Result<(), KubernetesAuthInputError> {
    if value.is_some_and(|value| {
        let value = value.expose_secret();
        value.is_empty()
            || value.len() > MAX_KUBERNETES_AUTH_REVIEWER_JWT_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
    }) {
        return Err(KubernetesAuthInputError::InvalidTokenReviewerJwt);
    }
    Ok(())
}

fn validate_patterns(values: &[String]) -> Result<String, KubernetesAuthInputError> {
    if values.is_empty() || values.len() > MAX_KUBERNETES_AUTH_POLICY_PATTERNS {
        return Err(KubernetesAuthInputError::InvalidWorkloadPolicy);
    }
    let mut unique = HashSet::with_capacity(values.len());
    for value in values {
        if value.is_empty()
            || value.len() > MAX_KUBERNETES_AUTH_POLICY_PATTERN_BYTES
            || value.trim() != value
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'.' | b'*' | b'?')
            })
            || !unique.insert(value.as_str())
        {
            return Err(KubernetesAuthInputError::InvalidWorkloadPolicy);
        }
    }
    Ok(values.join(","))
}

fn validate_audience(value: String) -> Result<String, KubernetesAuthInputError> {
    if value.is_empty()
        || value.len() > MAX_KUBERNETES_AUTH_AUDIENCE_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(KubernetesAuthInputError::InvalidAudience);
    }
    Ok(value)
}

#[derive(Serialize)]
struct IdentityPathQuery {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawKubernetesAuthConfig {
    id: String,
    identity_id: String,
    #[serde(rename = "accessTokenTTL")]
    access_token_ttl: u32,
    #[serde(rename = "accessTokenMaxTTL")]
    access_token_max_ttl: u32,
    access_token_num_uses_limit: u32,
    access_token_trusted_ips: Vec<TrustedIp>,
    token_review_mode: KubernetesAuthTokenReviewMode,
    kubernetes_host: Option<String>,
    allowed_namespaces: String,
    allowed_names: String,
    allowed_audience: String,
    #[serde(default)]
    ca_cert: String,
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    token_reviewer_jwt: Option<SecretValue>,
    verify_tls_certificate: bool,
    gateway_id: Option<String>,
    gateway_pool_id: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<RawKubernetesAuthConfig> for KubernetesAuthConfig {
    fn from(value: RawKubernetesAuthConfig) -> Self {
        let ca_certificate_configured = !value.ca_cert.is_empty();
        let token_reviewer_jwt_configured = value
            .token_reviewer_jwt
            .as_ref()
            .is_some_and(|credential| !credential.expose_secret().is_empty());
        Self {
            id: value.id,
            identity_id: value.identity_id,
            access_token_ttl: value.access_token_ttl,
            access_token_max_ttl: value.access_token_max_ttl,
            access_token_num_uses_limit: value.access_token_num_uses_limit,
            access_token_trusted_ips: value.access_token_trusted_ips,
            token_review_mode: value.token_review_mode,
            kubernetes_host: value.kubernetes_host,
            allowed_namespaces: split_patterns(&value.allowed_namespaces),
            allowed_names: split_patterns(&value.allowed_names),
            allowed_audience: non_empty(value.allowed_audience),
            ca_certificate_configured,
            token_reviewer_jwt_configured,
            verify_tls_certificate: value.verify_tls_certificate,
            gateway_id: value.gateway_id,
            gateway_pool_id: value.gateway_pool_id,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

fn split_patterns(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KubernetesAuthResponse {
    identity_kubernetes_auth: RawKubernetesAuthConfig,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachKubernetesAuthRequest {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
    kubernetes_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_cert: Option<String>,
    verify_tls_certificate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_reviewer_jwt: Option<SecretRequestValue>,
    token_review_mode: KubernetesAuthTokenReviewMode,
    allowed_namespaces: String,
    allowed_names: String,
    allowed_audience: String,
    #[serde(rename = "accessTokenTTL")]
    access_token_ttl: u32,
    #[serde(rename = "accessTokenMaxTTL")]
    access_token_max_ttl: u32,
    access_token_num_uses_limit: u32,
}

impl AttachKubernetesAuthRequest {
    fn new(identity_id: &IdentityId, settings: KubernetesAuthSettings) -> Self {
        Self {
            identity_id: identity_id.clone(),
            kubernetes_host: settings.kubernetes_host,
            ca_cert: settings.ca_cert,
            verify_tls_certificate: settings.verify_tls_certificate,
            token_reviewer_jwt: settings.token_reviewer_jwt.map(SecretRequestValue),
            token_review_mode: KubernetesAuthTokenReviewMode::Api,
            allowed_namespaces: settings.allowed_namespaces,
            allowed_names: settings.allowed_names,
            allowed_audience: settings.allowed_audience,
            access_token_ttl: settings.access_token_ttl,
            access_token_max_ttl: settings.access_token_max_ttl,
            access_token_num_uses_limit: settings.access_token_num_uses_limit,
        }
    }
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

enum NullableStringField {
    Value(String),
    Null,
}

impl Serialize for NullableStringField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Value(value) => serializer.serialize_str(value),
            Self::Null => serializer.serialize_none(),
        }
    }
}

enum NullableSecretField {
    Value(SecretValue),
    Null,
}

impl Serialize for NullableSecretField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Value(value) => serializer.serialize_str(value.expose_secret()),
            Self::Null => serializer.serialize_none(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateKubernetesAuthRequest {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
    #[serde(rename = "accessTokenTTL", skip_serializing_if = "Option::is_none")]
    access_token_ttl: Option<u32>,
    #[serde(rename = "accessTokenMaxTTL", skip_serializing_if = "Option::is_none")]
    access_token_max_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token_num_uses_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_namespaces: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_names: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kubernetes_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_cert: Option<NullableStringField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verify_tls_certificate: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_reviewer_jwt: Option<NullableSecretField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_review_mode: Option<KubernetesAuthTokenReviewMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway_id: Option<()>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway_pool_id: Option<()>,
}

impl UpdateKubernetesAuthRequest {
    fn change(identity_id: &IdentityId, change: KubernetesAuthChange) -> Self {
        let mut request = Self {
            identity_id: identity_id.clone(),
            access_token_ttl: None,
            access_token_max_ttl: None,
            access_token_num_uses_limit: None,
            allowed_namespaces: None,
            allowed_names: None,
            allowed_audience: None,
            kubernetes_host: None,
            ca_cert: None,
            verify_tls_certificate: None,
            token_reviewer_jwt: None,
            token_review_mode: None,
            gateway_id: None,
            gateway_pool_id: None,
        };
        match change {
            KubernetesAuthChange::TokenLifetime {
                access_token_ttl,
                access_token_max_ttl,
            } => {
                request.access_token_ttl = Some(access_token_ttl);
                request.access_token_max_ttl = Some(access_token_max_ttl);
            }
            KubernetesAuthChange::AccessTokenUseLimit(limit) => {
                request.access_token_num_uses_limit = Some(limit);
            }
            KubernetesAuthChange::WorkloadPolicy {
                allowed_namespaces,
                allowed_names,
                allowed_audience,
            } => {
                request.allowed_namespaces = Some(allowed_namespaces);
                request.allowed_names = Some(allowed_names);
                request.allowed_audience = Some(allowed_audience);
            }
            KubernetesAuthChange::DirectReviewer {
                kubernetes_host,
                ca_cert,
                verify_tls_certificate,
                token_reviewer_jwt,
            } => {
                request.kubernetes_host = Some(kubernetes_host);
                request.ca_cert = Some(match ca_cert {
                    Some(value) => NullableStringField::Value(value),
                    None => NullableStringField::Null,
                });
                request.verify_tls_certificate = Some(verify_tls_certificate);
                request.token_reviewer_jwt = match token_reviewer_jwt {
                    KubernetesTokenReviewerJwtChange::Preserve => None,
                    KubernetesTokenReviewerJwtChange::Replace(value) => {
                        Some(NullableSecretField::Value(value))
                    }
                    KubernetesTokenReviewerJwtChange::Clear => Some(NullableSecretField::Null),
                };
                request.token_review_mode = Some(KubernetesAuthTokenReviewMode::Api);
                request.gateway_id = Some(());
                request.gateway_pool_id = Some(());
            }
        }
        request
    }
}

fn deserialize_optional_secret<'de, D>(deserializer: D) -> Result<Option<SecretValue>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(SecretValue::new))
}

struct GetKubernetesAuth;
impl sealed::Sealed for GetKubernetesAuth {}
impl ReadOperation for GetKubernetesAuth {
    type Query = IdentityPathQuery;
    type Output = KubernetesAuthResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        kubernetes_auth_endpoint(&query.identity_id)
    }
}

struct AttachKubernetesAuth;
impl sealed::Sealed for AttachKubernetesAuth {}
impl MutationOperation for AttachKubernetesAuth {
    type Input = AttachKubernetesAuthRequest;
    type Output = KubernetesAuthResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        kubernetes_auth_endpoint(&input.identity_id)
    }
}

struct UpdateKubernetesAuth;
impl sealed::Sealed for UpdateKubernetesAuth {}
impl MutationOperation for UpdateKubernetesAuth {
    type Input = UpdateKubernetesAuthRequest;
    type Output = KubernetesAuthResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        kubernetes_auth_endpoint(&input.identity_id)
    }
}

struct RemoveKubernetesAuth;
impl sealed::Sealed for RemoveKubernetesAuth {}
impl MutationOperation for RemoveKubernetesAuth {
    type Input = IdentityPathQuery;
    type Output = KubernetesAuthResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        kubernetes_auth_endpoint(&input.identity_id)
    }
}

fn kubernetes_auth_endpoint(identity_id: &IdentityId) -> Endpoint {
    Endpoint::from_segments(
        ApiVersion::V1,
        [
            "auth",
            "kubernetes-auth",
            "identities",
            identity_id.as_str(),
        ],
    )
}

impl InfisicalClient {
    /// Get value-free Kubernetes Auth configuration for one machine identity.
    ///
    /// The pinned upstream route returns the stored token-reviewer JWT. This
    /// method consumes it into a redacting type and exposes only whether it is configured.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_kubernetes_auth(
        &self,
        identity_id: &IdentityId,
    ) -> Result<KubernetesAuthConfig, ResourceError> {
        let response = self
            .execute_read::<GetKubernetesAuth>(&IdentityPathQuery {
                identity_id: identity_id.clone(),
            })
            .await?;
        Ok(response.identity_kubernetes_auth.into())
    }

    /// Attach one complete community-compatible direct Kubernetes API configuration.
    ///
    /// Paid gateway routing and custom trusted-IP fields are omitted. Infisical
    /// applies its unrestricted trusted-IP defaults until that capability is available.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn attach_kubernetes_auth(
        &self,
        identity_id: &IdentityId,
        settings: KubernetesAuthSettings,
    ) -> Result<KubernetesAuthConfig, ResourceError> {
        let response = self
            .execute_mutation::<AttachKubernetesAuth>(&AttachKubernetesAuthRequest::new(
                identity_id,
                settings,
            ))
            .await?;
        Ok(response.identity_kubernetes_auth.into())
    }

    /// Apply one coherent Kubernetes Auth configuration change.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn update_kubernetes_auth(
        &self,
        identity_id: &IdentityId,
        change: KubernetesAuthChange,
    ) -> Result<KubernetesAuthConfig, ResourceError> {
        let response = self
            .execute_mutation::<UpdateKubernetesAuth>(&UpdateKubernetesAuthRequest::change(
                identity_id,
                change,
            ))
            .await?;
        Ok(response.identity_kubernetes_auth.into())
    }

    /// Remove Kubernetes Auth and revoke its derived credentials after confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn remove_kubernetes_auth(
        &self,
        identity_id: &IdentityId,
        confirm: bool,
    ) -> Result<KubernetesAuthConfig, ResourceError> {
        if !confirm {
            return Err(ResourceError::KubernetesAuthRemovalNotConfirmed);
        }
        let response = self
            .execute_mutation::<RemoveKubernetesAuth>(&IdentityPathQuery {
                identity_id: identity_id.clone(),
            })
            .await?;
        Ok(response.identity_kubernetes_auth.into())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    use crate::{
        IdentityId, InfisicalClient, KubernetesAuthChange, KubernetesAuthConfig,
        KubernetesAuthInputError, KubernetesAuthSettings, KubernetesTokenReviewerJwtChange,
        MAX_KUBERNETES_AUTH_AUDIENCE_BYTES, MAX_KUBERNETES_AUTH_CA_CERT_BYTES,
        MAX_KUBERNETES_AUTH_HOST_BYTES, MAX_KUBERNETES_AUTH_LIFETIME_SECONDS,
        MAX_KUBERNETES_AUTH_POLICY_PATTERN_BYTES, MAX_KUBERNETES_AUTH_POLICY_PATTERNS,
        MAX_KUBERNETES_AUTH_REVIEWER_JWT_BYTES, ResourceError, SecretValue,
        test_support::{CA_CERT, mount_login, settings},
    };

    use super::{RawKubernetesAuthConfig, is_valid_ca_certificate_bundle};

    const REVIEWER_JWT: &str = "reviewer.jwt.canary";
    fn config() -> Value {
        json!({
            "id": "kubernetes-auth-1",
            "identityId": "identity-1",
            "accessTokenTTL": 3600,
            "accessTokenMaxTTL": 86400,
            "accessTokenNumUsesLimit": 10,
            "accessTokenTrustedIps": [
                { "ipAddress": "0.0.0.0", "type": "ipv4", "prefix": 0 },
                { "ipAddress": "::", "type": "ipv6", "prefix": 0 }
            ],
            "tokenReviewMode": "api",
            "kubernetesHost": "https://kubernetes.default.svc",
            "allowedNamespaces": "payments,platform-*",
            "allowedNames": "api,worker-*",
            "allowedAudience": "infisical",
            "caCert": CA_CERT,
            "tokenReviewerJwt": REVIEWER_JWT,
            "verifyTlsCertificate": true,
            "gatewayId": null,
            "gatewayPoolId": null,
            "createdAt": "2026-07-19T12:00:00.000Z",
            "updatedAt": "2026-07-19T12:00:00.000Z"
        })
    }

    fn complete_settings() -> KubernetesAuthSettings {
        KubernetesAuthSettings::new(
            "https://kubernetes.default.svc",
            Some(CA_CERT.into()),
            true,
            Some(SecretValue::new(REVIEWER_JWT)),
            &["payments".into(), "platform-*".into()],
            &["api".into(), "worker-*".into()],
            "infisical",
            3600,
            86400,
            10,
        )
        .unwrap()
    }

    #[test]
    fn direct_settings_reject_ambiguous_or_unsafe_trust() {
        assert_eq!(
            KubernetesAuthSettings::new(
                "http://kubernetes.default.svc",
                None,
                false,
                None,
                &["payments".into()],
                &["api".into()],
                "infisical",
                3600,
                86400,
                0,
            )
            .unwrap_err(),
            KubernetesAuthInputError::InvalidKubernetesHost
        );
        assert_eq!(
            KubernetesAuthSettings::new(
                "https:///missing-host",
                None,
                false,
                None,
                &["payments".into()],
                &["api".into()],
                "infisical",
                3600,
                86400,
                0,
            )
            .unwrap_err(),
            KubernetesAuthInputError::InvalidKubernetesHost
        );
        assert_eq!(
            KubernetesAuthSettings::new(
                "https://kubernetes.default.svc",
                None,
                true,
                None,
                &["payments".into()],
                &["api".into()],
                "infisical",
                3600,
                86400,
                0,
            )
            .unwrap_err(),
            KubernetesAuthInputError::InvalidCaCertificate
        );
        assert_eq!(
            KubernetesAuthSettings::new(
                "https://kubernetes.default.svc",
                None,
                false,
                Some(SecretValue::new(" padded ")),
                &["payments".into()],
                &["api".into()],
                "infisical",
                3600,
                86400,
                0,
            )
            .unwrap_err(),
            KubernetesAuthInputError::InvalidTokenReviewerJwt
        );
        assert_eq!(
            KubernetesAuthChange::workload_policy(
                &["payments".into(), "payments".into()],
                &["api".into()],
                "infisical",
            )
            .unwrap_err(),
            KubernetesAuthInputError::InvalidWorkloadPolicy
        );
        assert_eq!(
            KubernetesAuthChange::workload_policy(
                &["!(payments)".into()],
                &["api".into()],
                "infisical",
            )
            .unwrap_err(),
            KubernetesAuthInputError::InvalidWorkloadPolicy
        );
        assert_eq!(
            KubernetesAuthChange::workload_policy(&["payments".into()], &["api".into()], "",)
                .unwrap_err(),
            KubernetesAuthInputError::InvalidAudience
        );
        assert_eq!(
            KubernetesAuthChange::token_lifetime(86_400, 3_600).unwrap_err(),
            KubernetesAuthInputError::TokenLifetimeOrder
        );
        let settings = complete_settings();
        assert!(settings.allowed_namespaces.contains("payments"));
        assert!(!format!("{settings:?}").contains(REVIEWER_JWT));
    }

    #[test]
    fn token_lifetime_bounds_accept_the_limit_and_reject_each_independent_overflow() {
        assert!(
            KubernetesAuthChange::token_lifetime(
                MAX_KUBERNETES_AUTH_LIFETIME_SECONDS,
                MAX_KUBERNETES_AUTH_LIFETIME_SECONDS,
            )
            .is_ok()
        );
        assert_eq!(
            KubernetesAuthChange::token_lifetime(
                MAX_KUBERNETES_AUTH_LIFETIME_SECONDS + 1,
                MAX_KUBERNETES_AUTH_LIFETIME_SECONDS,
            )
            .unwrap_err(),
            KubernetesAuthInputError::InvalidTokenLifetime
        );
        assert_eq!(
            KubernetesAuthChange::token_lifetime(
                MAX_KUBERNETES_AUTH_LIFETIME_SECONDS,
                MAX_KUBERNETES_AUTH_LIFETIME_SECONDS + 1,
            )
            .unwrap_err(),
            KubernetesAuthInputError::InvalidTokenLifetime
        );
    }

    #[test]
    fn kubernetes_host_bound_accepts_the_limit_and_rejects_one_more_byte() {
        let prefix = "https://kubernetes.default.svc/";
        let mut host_at_limit = format!(
            "{prefix}{}",
            "a".repeat(MAX_KUBERNETES_AUTH_HOST_BYTES - prefix.len())
        );
        assert_eq!(host_at_limit.len(), MAX_KUBERNETES_AUTH_HOST_BYTES);
        KubernetesAuthChange::direct_reviewer(
            &host_at_limit,
            None,
            false,
            KubernetesTokenReviewerJwtChange::Preserve,
        )
        .unwrap();

        host_at_limit.push('a');
        assert_eq!(
            KubernetesAuthChange::direct_reviewer(
                host_at_limit,
                None,
                false,
                KubernetesTokenReviewerJwtChange::Preserve,
            )
            .unwrap_err(),
            KubernetesAuthInputError::InvalidKubernetesHost
        );
        assert_eq!(
            KubernetesAuthChange::direct_reviewer(
                "https://kubernetes.default.svc:invalid",
                None,
                false,
                KubernetesTokenReviewerJwtChange::Preserve,
            )
            .unwrap_err(),
            KubernetesAuthInputError::InvalidKubernetesHost
        );
    }

    fn direct_reviewer_with_ca(
        ca_cert: String,
    ) -> Result<KubernetesAuthChange, KubernetesAuthInputError> {
        KubernetesAuthChange::direct_reviewer(
            "https://kubernetes.default.svc",
            Some(ca_cert),
            true,
            KubernetesTokenReviewerJwtChange::Preserve,
        )
    }

    #[test]
    fn ca_bundle_validation_covers_structure_certificate_der_and_size() {
        direct_reviewer_with_ca(CA_CERT.into()).unwrap();
        direct_reviewer_with_ca(format!("{CA_CERT}\n{CA_CERT}")).unwrap();
        let certificate_at_limit = format!(
            "{CA_CERT}{}",
            " ".repeat(MAX_KUBERNETES_AUTH_CA_CERT_BYTES - CA_CERT.len())
        );
        assert_eq!(
            certificate_at_limit.len(),
            MAX_KUBERNETES_AUTH_CA_CERT_BYTES
        );
        direct_reviewer_with_ca(certificate_at_limit.clone()).unwrap();

        let oversized_valid_bundle = std::iter::repeat_n(
            CA_CERT,
            MAX_KUBERNETES_AUTH_CA_CERT_BYTES / (CA_CERT.len() + 1) + 1,
        )
        .collect::<Vec<_>>()
        .join("\n");
        assert!(oversized_valid_bundle.len() > MAX_KUBERNETES_AUTH_CA_CERT_BYTES);
        assert!(is_valid_ca_certificate_bundle(&oversized_valid_bundle));
        let begin = "-----BEGIN CERTIFICATE-----";
        let end = "-----END CERTIFICATE-----";
        for invalid in [
            String::new(),
            format!("{certificate_at_limit} "),
            oversized_valid_bundle,
            format!("{begin}\0{end}"),
            format!("{end}\nY2VydA==\n{begin}"),
            format!("{begin}\nnot-base64!\n{end}"),
            format!("{begin}\nY2VydA==\n{end}"),
            format!("{CA_CERT}\nunrelated trailing material"),
        ] {
            assert_eq!(
                direct_reviewer_with_ca(invalid).unwrap_err(),
                KubernetesAuthInputError::InvalidCaCertificate
            );
        }
    }

    fn direct_reviewer_with_jwt(
        token_reviewer_jwt: String,
    ) -> Result<KubernetesAuthChange, KubernetesAuthInputError> {
        KubernetesAuthChange::direct_reviewer(
            "https://kubernetes.default.svc",
            None,
            false,
            KubernetesTokenReviewerJwtChange::Replace(SecretValue::new(token_reviewer_jwt)),
        )
    }

    #[test]
    fn reviewer_jwt_validation_covers_shape_and_size_independently() {
        direct_reviewer_with_jwt("a".repeat(MAX_KUBERNETES_AUTH_REVIEWER_JWT_BYTES)).unwrap();
        for invalid in [
            String::new(),
            "a".repeat(MAX_KUBERNETES_AUTH_REVIEWER_JWT_BYTES + 1),
            " padded ".into(),
            "line\nbreak".into(),
        ] {
            assert_eq!(
                direct_reviewer_with_jwt(invalid).unwrap_err(),
                KubernetesAuthInputError::InvalidTokenReviewerJwt
            );
        }
    }

    fn policy_with_namespaces(
        namespaces: &[String],
    ) -> Result<KubernetesAuthChange, KubernetesAuthInputError> {
        KubernetesAuthChange::workload_policy(namespaces, &["api".into()], "infisical")
    }

    #[test]
    fn workload_policy_validation_covers_cardinality_shape_and_size() {
        let exact_count = (0..MAX_KUBERNETES_AUTH_POLICY_PATTERNS)
            .map(|index| format!("ns-{index}"))
            .collect::<Vec<_>>();
        policy_with_namespaces(&exact_count).unwrap();
        let too_many = (0..=MAX_KUBERNETES_AUTH_POLICY_PATTERNS)
            .map(|index| format!("ns-{index}"))
            .collect::<Vec<_>>();
        assert_eq!(
            policy_with_namespaces(&too_many).unwrap_err(),
            KubernetesAuthInputError::InvalidWorkloadPolicy
        );

        policy_with_namespaces(&["a".repeat(MAX_KUBERNETES_AUTH_POLICY_PATTERN_BYTES)]).unwrap();
        for invalid in [
            Vec::new(),
            vec!["a".repeat(MAX_KUBERNETES_AUTH_POLICY_PATTERN_BYTES + 1)],
            vec![" padded".into()],
            vec!["api,worker".into()],
            vec!["line\nbreak".into()],
            vec!["UPPERCASE".into()],
        ] {
            assert_eq!(
                policy_with_namespaces(&invalid).unwrap_err(),
                KubernetesAuthInputError::InvalidWorkloadPolicy
            );
        }
    }

    #[test]
    fn audience_validation_covers_shape_and_size_independently() {
        KubernetesAuthChange::workload_policy(
            &["payments".into()],
            &["api".into()],
            "a".repeat(MAX_KUBERNETES_AUTH_AUDIENCE_BYTES),
        )
        .unwrap();
        for invalid in [
            "a".repeat(MAX_KUBERNETES_AUTH_AUDIENCE_BYTES + 1),
            " padded ".into(),
            "line\nbreak".into(),
        ] {
            assert_eq!(
                KubernetesAuthChange::workload_policy(
                    &["payments".into()],
                    &["api".into()],
                    invalid,
                )
                .unwrap_err(),
                KubernetesAuthInputError::InvalidAudience
            );
        }
    }

    #[test]
    fn response_mapping_preserves_present_audience_and_normalizes_empty_audience() {
        let populated = serde_json::from_value::<RawKubernetesAuthConfig>(config()).unwrap();
        let populated = KubernetesAuthConfig::from(populated);
        assert_eq!(populated.allowed_audience.as_deref(), Some("infisical"));

        let mut empty = config();
        empty["allowedAudience"] = json!("");
        let empty = serde_json::from_value::<RawKubernetesAuthConfig>(empty).unwrap();
        assert_eq!(KubernetesAuthConfig::from(empty).allowed_audience, None);
    }

    async fn mount_configuration_routes(server: &MockServer) {
        mount_login(server, "kubernetes-auth-admin").await;
        let route = "/api/v1/auth/kubernetes-auth/identities/identity-1";
        Mock::given(method("GET"))
            .and(path(route))
            .and(header("authorization", "Bearer kubernetes-auth-admin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityKubernetesAuth": config()
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(route))
            .and(header("authorization", "Bearer kubernetes-auth-admin"))
            .and(body_json(json!({
                "kubernetesHost": "https://kubernetes.default.svc",
                "caCert": CA_CERT,
                "verifyTlsCertificate": true,
                "tokenReviewerJwt": REVIEWER_JWT,
                "tokenReviewMode": "api",
                "allowedNamespaces": "payments,platform-*",
                "allowedNames": "api,worker-*",
                "allowedAudience": "infisical",
                "accessTokenTTL": 3600,
                "accessTokenMaxTTL": 86400,
                "accessTokenNumUsesLimit": 10
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityKubernetesAuth": config()
            })))
            .expect(1)
            .mount(server)
            .await;
        for body in [
            json!({ "accessTokenTTL": 1800, "accessTokenMaxTTL": 7200 }),
            json!({ "accessTokenNumUsesLimit": 20 }),
            json!({
                "allowedNamespaces": "payments,analytics",
                "allowedNames": "api,worker",
                "allowedAudience": "infisical-prod"
            }),
            json!({
                "kubernetesHost": "https://api.cluster.internal",
                "caCert": null,
                "verifyTlsCertificate": false,
                "tokenReviewMode": "api",
                "gatewayId": null,
                "gatewayPoolId": null
            }),
            json!({
                "kubernetesHost": "https://api.cluster.internal",
                "caCert": null,
                "verifyTlsCertificate": false,
                "tokenReviewerJwt": null,
                "tokenReviewMode": "api",
                "gatewayId": null,
                "gatewayPoolId": null
            }),
        ] {
            Mock::given(method("PATCH"))
                .and(path(route))
                .and(header("authorization", "Bearer kubernetes-auth-admin"))
                .and(body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "identityKubernetesAuth": config()
                })))
                .expect(1)
                .mount(server)
                .await;
        }
        Mock::given(method("DELETE"))
            .and(path(route))
            .and(header("authorization", "Bearer kubernetes-auth-admin"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityKubernetesAuth": config()
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn configuration_uses_exact_v1_contracts_without_exposing_the_reviewer_jwt() {
        let server = MockServer::start().await;
        mount_configuration_routes(&server).await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let read = client.get_kubernetes_auth(&identity_id).await.unwrap();
        assert!(read.ca_certificate_configured);
        assert!(read.token_reviewer_jwt_configured);
        assert_eq!(read.allowed_namespaces, ["payments", "platform-*"]);
        let serialized = serde_json::to_string(&read).unwrap();
        assert!(!serialized.contains(REVIEWER_JWT));
        assert!(!format!("{read:?}").contains(REVIEWER_JWT));

        client
            .attach_kubernetes_auth(&identity_id, complete_settings())
            .await
            .unwrap();
        client
            .update_kubernetes_auth(
                &identity_id,
                KubernetesAuthChange::token_lifetime(1800, 7200).unwrap(),
            )
            .await
            .unwrap();
        client
            .update_kubernetes_auth(&identity_id, KubernetesAuthChange::AccessTokenUseLimit(20))
            .await
            .unwrap();
        client
            .update_kubernetes_auth(
                &identity_id,
                KubernetesAuthChange::workload_policy(
                    &["payments".into(), "analytics".into()],
                    &["api".into(), "worker".into()],
                    "infisical-prod",
                )
                .unwrap(),
            )
            .await
            .unwrap();
        client
            .update_kubernetes_auth(
                &identity_id,
                KubernetesAuthChange::direct_reviewer(
                    "https://api.cluster.internal",
                    None,
                    false,
                    KubernetesTokenReviewerJwtChange::Preserve,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        client
            .update_kubernetes_auth(
                &identity_id,
                KubernetesAuthChange::direct_reviewer(
                    "https://api.cluster.internal",
                    None,
                    false,
                    KubernetesTokenReviewerJwtChange::Clear,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        client
            .remove_kubernetes_auth(&identity_id, true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn unconfirmed_removal_fails_before_authentication_or_mutation() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();

        assert_eq!(
            client
                .remove_kubernetes_auth(&identity_id, false)
                .await
                .unwrap_err(),
            ResourceError::KubernetesAuthRemovalNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
