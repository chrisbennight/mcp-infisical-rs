use std::fmt;

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    IdentityId, InfisicalClient, MutationOperation, Page, PageRequest, ReadOperation,
    ResourceError, SecretValue, UniversalAuthClientSecretId,
    client::{ApiVersion, Endpoint, sealed},
    resources::paginate,
};

/// Maximum token or credential lifetime accepted by the pinned Infisical API.
pub const MAX_AUTH_LIFETIME_SECONDS: u32 = 315_360_000;
/// Maximum bounded description size accepted through the MCP boundary.
pub const MAX_CLIENT_SECRET_DESCRIPTION_BYTES: usize = 1_024;

/// Validation failures for Universal Auth configuration.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum UniversalAuthInputError {
    /// A token lifetime exceeded the pinned API limit.
    #[error("token lifetimes and periods must not exceed 315360000 seconds")]
    InvalidTokenLifetime,
    /// The ordinary token lifetime exceeded its maximum lifetime.
    #[error("access token TTL must not exceed access token maximum TTL")]
    TokenLifetimeOrder,
    /// A lockout threshold was outside the pinned API range.
    #[error("lockout threshold must be between 1 and 30")]
    InvalidLockoutThreshold,
    /// A lockout duration was outside the pinned API range.
    #[error("lockout duration must be between 30 and 86400 seconds")]
    InvalidLockoutDuration,
    /// A lockout counter reset was outside the pinned API range.
    #[error("lockout counter reset must be between 5 and 3600 seconds")]
    InvalidLockoutCounterReset,
    /// A client-secret description was padded, unbounded, or control-bearing.
    #[error(
        "client-secret description must contain at most 1024 bytes without surrounding whitespace or control characters"
    )]
    InvalidClientSecretDescription,
}

/// One parsed trusted-IP record returned by Infisical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedIp {
    /// Canonical address returned by Infisical.
    pub ip_address: String,
    /// Infisical address-family label.
    #[serde(rename = "type")]
    pub address_type: String,
    /// Network prefix length.
    pub prefix: u8,
}

/// Non-secret Universal Auth configuration for one machine identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UniversalAuthConfig {
    /// Opaque Universal Auth configuration identifier.
    pub id: String,
    /// Public client identifier used with a client secret during login.
    pub client_id: String,
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
    /// Periodic-token interval in seconds; zero disables periodic tokens.
    pub access_token_period: u32,
    /// Whether repeated authentication failures cause lockout.
    pub lockout_enabled: bool,
    /// Failed attempts that trigger lockout.
    pub lockout_threshold: u8,
    /// Lockout duration in seconds.
    pub lockout_duration_seconds: u32,
    /// Failure-counter reset interval in seconds.
    pub lockout_counter_reset_seconds: u32,
    /// Client-secret source ranges, readable but not mutable in the community surface.
    pub client_secret_trusted_ips: Vec<TrustedIp>,
    /// Access-token source ranges, readable but not mutable in the community surface.
    pub access_token_trusted_ips: Vec<TrustedIp>,
}

/// Complete community-compatible Universal Auth settings used during attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniversalAuthSettings {
    access_token_ttl: u32,
    access_token_max_ttl: u32,
    access_token_num_uses_limit: u32,
    access_token_period: u32,
    lockout: UniversalAuthLockoutPolicy,
}

impl UniversalAuthSettings {
    /// Validate a complete configuration before it reaches Infisical.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for any value outside the pinned API contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        access_token_ttl: u32,
        access_token_max_ttl: u32,
        access_token_num_uses_limit: u32,
        access_token_period: u32,
        lockout_enabled: bool,
        lockout_threshold: u8,
        lockout_duration_seconds: u32,
        lockout_counter_reset_seconds: u32,
    ) -> Result<Self, UniversalAuthInputError> {
        validate_lifetime(access_token_ttl, access_token_max_ttl, access_token_period)?;
        Ok(Self {
            access_token_ttl,
            access_token_max_ttl,
            access_token_num_uses_limit,
            access_token_period,
            lockout: UniversalAuthLockoutPolicy::new(
                lockout_enabled,
                lockout_threshold,
                lockout_duration_seconds,
                lockout_counter_reset_seconds,
            )?,
        })
    }
}

impl Default for UniversalAuthSettings {
    fn default() -> Self {
        Self {
            access_token_ttl: 2_592_000,
            access_token_max_ttl: 2_592_000,
            access_token_num_uses_limit: 0,
            access_token_period: 0,
            lockout: UniversalAuthLockoutPolicy {
                enabled: true,
                threshold: 3,
                duration_seconds: 300,
                counter_reset_seconds: 30,
            },
        }
    }
}

/// Complete lockout policy, changed atomically to avoid mixed security state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniversalAuthLockoutPolicy {
    enabled: bool,
    threshold: u8,
    duration_seconds: u32,
    counter_reset_seconds: u32,
}

impl UniversalAuthLockoutPolicy {
    /// Validate one complete lockout policy.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for values outside the pinned API contract.
    pub fn new(
        enabled: bool,
        threshold: u8,
        duration_seconds: u32,
        counter_reset_seconds: u32,
    ) -> Result<Self, UniversalAuthInputError> {
        if !(1..=30).contains(&threshold) {
            return Err(UniversalAuthInputError::InvalidLockoutThreshold);
        }
        if !(30..=86_400).contains(&duration_seconds) {
            return Err(UniversalAuthInputError::InvalidLockoutDuration);
        }
        if !(5..=3_600).contains(&counter_reset_seconds) {
            return Err(UniversalAuthInputError::InvalidLockoutCounterReset);
        }
        Ok(Self {
            enabled,
            threshold,
            duration_seconds,
            counter_reset_seconds,
        })
    }
}

/// One atomic Universal Auth configuration change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UniversalAuthChange {
    /// Replace the mutually constrained token lifetime fields together.
    TokenLifetime {
        /// Ordinary token lifetime in seconds.
        access_token_ttl: u32,
        /// Maximum renewable lifetime in seconds.
        access_token_max_ttl: u32,
        /// Periodic-token interval; zero disables periodic tokens.
        access_token_period: u32,
    },
    /// Replace the token use limit; zero means unlimited.
    AccessTokenUseLimit(u32),
    /// Replace the complete lockout policy.
    Lockout(UniversalAuthLockoutPolicy),
}

impl UniversalAuthChange {
    /// Validate a complete token-lifetime change.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for an invalid lifetime or ordering.
    pub fn token_lifetime(
        access_token_ttl: u32,
        access_token_max_ttl: u32,
        access_token_period: u32,
    ) -> Result<Self, UniversalAuthInputError> {
        validate_lifetime(access_token_ttl, access_token_max_ttl, access_token_period)?;
        Ok(Self::TokenLifetime {
            access_token_ttl,
            access_token_max_ttl,
            access_token_period,
        })
    }
}

fn validate_lifetime(
    access_token_ttl: u32,
    access_token_max_ttl: u32,
    access_token_period: u32,
) -> Result<(), UniversalAuthInputError> {
    if [access_token_ttl, access_token_max_ttl, access_token_period]
        .into_iter()
        .any(|value| value > MAX_AUTH_LIFETIME_SECONDS)
    {
        return Err(UniversalAuthInputError::InvalidTokenLifetime);
    }
    if access_token_ttl > access_token_max_ttl {
        return Err(UniversalAuthInputError::TokenLifetimeOrder);
    }
    Ok(())
}

/// Non-secret metadata for one Universal Auth client secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UniversalAuthClientSecret {
    /// Opaque credential identifier.
    pub id: String,
    /// Non-secret operator description.
    pub description: String,
    /// Safe prefix used to identify the credential.
    pub client_secret_prefix: String,
    /// Uses observed by Infisical.
    pub client_secret_num_uses: u32,
    /// Maximum uses; zero means unlimited.
    pub client_secret_num_uses_limit: u32,
    /// Credential lifetime in seconds; zero means no TTL.
    #[serde(rename = "clientSecretTTL")]
    pub client_secret_ttl: u32,
    /// Whether the credential is revoked.
    pub is_client_secret_revoked: bool,
    /// Owning Universal Auth configuration identifier.
    #[serde(rename = "identityUAId")]
    pub identity_ua_id: String,
    /// Infisical creation timestamp.
    pub created_at: String,
    /// Infisical update timestamp.
    pub updated_at: String,
}

/// Validated client-secret creation options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniversalAuthClientSecretCreation {
    description: String,
    num_uses_limit: u32,
    ttl: u32,
}

impl UniversalAuthClientSecretCreation {
    /// Validate client-secret metadata and limits.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for unbounded text or lifetime.
    pub fn new(
        description: impl Into<String>,
        num_uses_limit: u32,
        ttl: u32,
    ) -> Result<Self, UniversalAuthInputError> {
        let description = description.into();
        if description.len() > MAX_CLIENT_SECRET_DESCRIPTION_BYTES
            || description.trim() != description
            || description.chars().any(char::is_control)
        {
            return Err(UniversalAuthInputError::InvalidClientSecretDescription);
        }
        if ttl > MAX_AUTH_LIFETIME_SECONDS {
            return Err(UniversalAuthInputError::InvalidTokenLifetime);
        }
        Ok(Self {
            description,
            num_uses_limit,
            ttl,
        })
    }
}

/// Newly generated credential plus its non-secret metadata.
pub struct CreatedUniversalAuthClientSecret {
    /// Credential returned once by Infisical.
    pub client_secret: SecretValue,
    /// Non-secret credential metadata.
    pub metadata: UniversalAuthClientSecret,
}

impl fmt::Debug for CreatedUniversalAuthClientSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedUniversalAuthClientSecret")
            .field("client_secret", &self.client_secret)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Result of clearing authentication lockouts for one identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UniversalAuthLockoutClear {
    /// Number of lockout records removed by Infisical.
    pub deleted: u64,
}

#[derive(Serialize)]
struct IdentityPathQuery {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UniversalAuthResponse {
    identity_universal_auth: UniversalAuthConfig,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachUniversalAuthRequest {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
    #[serde(rename = "accessTokenTTL")]
    access_token_ttl: u32,
    #[serde(rename = "accessTokenMaxTTL")]
    access_token_max_ttl: u32,
    access_token_num_uses_limit: u32,
    access_token_period: u32,
    lockout_enabled: bool,
    lockout_threshold: u8,
    lockout_duration_seconds: u32,
    lockout_counter_reset_seconds: u32,
}

impl AttachUniversalAuthRequest {
    fn new(identity_id: &IdentityId, settings: &UniversalAuthSettings) -> Self {
        Self {
            identity_id: identity_id.clone(),
            access_token_ttl: settings.access_token_ttl,
            access_token_max_ttl: settings.access_token_max_ttl,
            access_token_num_uses_limit: settings.access_token_num_uses_limit,
            access_token_period: settings.access_token_period,
            lockout_enabled: settings.lockout.enabled,
            lockout_threshold: settings.lockout.threshold,
            lockout_duration_seconds: settings.lockout.duration_seconds,
            lockout_counter_reset_seconds: settings.lockout.counter_reset_seconds,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateUniversalAuthRequest {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
    #[serde(rename = "accessTokenTTL", skip_serializing_if = "Option::is_none")]
    access_token_ttl: Option<u32>,
    #[serde(rename = "accessTokenMaxTTL", skip_serializing_if = "Option::is_none")]
    access_token_max_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token_num_uses_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token_period: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lockout_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lockout_threshold: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lockout_duration_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lockout_counter_reset_seconds: Option<u32>,
}

impl UpdateUniversalAuthRequest {
    fn change(identity_id: &IdentityId, change: UniversalAuthChange) -> Self {
        let mut request = Self {
            identity_id: identity_id.clone(),
            access_token_ttl: None,
            access_token_max_ttl: None,
            access_token_num_uses_limit: None,
            access_token_period: None,
            lockout_enabled: None,
            lockout_threshold: None,
            lockout_duration_seconds: None,
            lockout_counter_reset_seconds: None,
        };
        match change {
            UniversalAuthChange::TokenLifetime {
                access_token_ttl,
                access_token_max_ttl,
                access_token_period,
            } => {
                request.access_token_ttl = Some(access_token_ttl);
                request.access_token_max_ttl = Some(access_token_max_ttl);
                request.access_token_period = Some(access_token_period);
            }
            UniversalAuthChange::AccessTokenUseLimit(limit) => {
                request.access_token_num_uses_limit = Some(limit);
            }
            UniversalAuthChange::Lockout(policy) => {
                request.lockout_enabled = Some(policy.enabled);
                request.lockout_threshold = Some(policy.threshold);
                request.lockout_duration_seconds = Some(policy.duration_seconds);
                request.lockout_counter_reset_seconds = Some(policy.counter_reset_seconds);
            }
        }
        request
    }
}

#[derive(Serialize)]
struct ClientSecretQuery {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
    #[serde(skip_serializing)]
    client_secret_id: UniversalAuthClientSecretId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateClientSecretRequest {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
    description: String,
    num_uses_limit: u32,
    ttl: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientSecretResponse {
    client_secret_data: UniversalAuthClientSecret,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientSecretListResponse {
    client_secret_data: Vec<UniversalAuthClientSecret>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreatedClientSecretResponse {
    client_secret: String,
    client_secret_data: UniversalAuthClientSecret,
}

struct GetUniversalAuth;

impl sealed::Sealed for GetUniversalAuth {}

impl ReadOperation for GetUniversalAuth {
    type Query = IdentityPathQuery;
    type Output = UniversalAuthResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "auth",
                "universal-auth",
                "identities",
                query.identity_id.as_str(),
            ],
        )
    }
}

struct AttachUniversalAuth;

impl sealed::Sealed for AttachUniversalAuth {}

impl MutationOperation for AttachUniversalAuth {
    type Input = AttachUniversalAuthRequest;
    type Output = UniversalAuthResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        universal_auth_endpoint(&input.identity_id)
    }
}

struct UpdateUniversalAuth;

impl sealed::Sealed for UpdateUniversalAuth {}

impl MutationOperation for UpdateUniversalAuth {
    type Input = UpdateUniversalAuthRequest;
    type Output = UniversalAuthResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        universal_auth_endpoint(&input.identity_id)
    }
}

struct RemoveUniversalAuth;

impl sealed::Sealed for RemoveUniversalAuth {}

impl MutationOperation for RemoveUniversalAuth {
    type Input = IdentityPathQuery;
    type Output = UniversalAuthResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        universal_auth_endpoint(&input.identity_id)
    }
}

struct ListClientSecrets;

impl sealed::Sealed for ListClientSecrets {}

impl ReadOperation for ListClientSecrets {
    type Query = IdentityPathQuery;
    type Output = ClientSecretListResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        client_secrets_endpoint(&query.identity_id)
    }
}

struct GetClientSecret;

impl sealed::Sealed for GetClientSecret {}

impl ReadOperation for GetClientSecret {
    type Query = ClientSecretQuery;
    type Output = ClientSecretResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "auth",
                "universal-auth",
                "identities",
                query.identity_id.as_str(),
                "client-secrets",
                query.client_secret_id.as_str(),
            ],
        )
    }
}

struct CreateClientSecret;

impl sealed::Sealed for CreateClientSecret {}

impl MutationOperation for CreateClientSecret {
    type Input = CreateClientSecretRequest;
    type Output = CreatedClientSecretResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        client_secrets_endpoint(&input.identity_id)
    }
}

struct RevokeClientSecret;

impl sealed::Sealed for RevokeClientSecret {}

impl MutationOperation for RevokeClientSecret {
    type Input = ClientSecretQuery;
    type Output = ClientSecretResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "auth",
                "universal-auth",
                "identities",
                input.identity_id.as_str(),
                "client-secrets",
                input.client_secret_id.as_str(),
                "revoke",
            ],
        )
    }
}

struct ClearLockouts;

impl sealed::Sealed for ClearLockouts {}

impl MutationOperation for ClearLockouts {
    type Input = IdentityPathQuery;
    type Output = UniversalAuthLockoutClear;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "auth",
                "universal-auth",
                "identities",
                input.identity_id.as_str(),
                "clear-lockouts",
            ],
        )
    }
}

fn universal_auth_endpoint(identity_id: &IdentityId) -> Endpoint {
    Endpoint::from_segments(
        ApiVersion::V1,
        ["auth", "universal-auth", "identities", identity_id.as_str()],
    )
}

fn client_secrets_endpoint(identity_id: &IdentityId) -> Endpoint {
    Endpoint::from_segments(
        ApiVersion::V1,
        [
            "auth",
            "universal-auth",
            "identities",
            identity_id.as_str(),
            "client-secrets",
        ],
    )
}

impl InfisicalClient {
    /// Get non-secret Universal Auth configuration for one machine identity.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_universal_auth(
        &self,
        identity_id: &IdentityId,
    ) -> Result<UniversalAuthConfig, ResourceError> {
        let response = self
            .execute_read::<GetUniversalAuth>(&IdentityPathQuery {
                identity_id: identity_id.clone(),
            })
            .await?;
        Ok(response.identity_universal_auth)
    }

    /// Attach one complete community-compatible Universal Auth configuration.
    ///
    /// Trusted-IP fields are intentionally omitted so Infisical applies its
    /// defaults without implying that enterprise-only mutation is available.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn attach_universal_auth(
        &self,
        identity_id: &IdentityId,
        settings: UniversalAuthSettings,
    ) -> Result<UniversalAuthConfig, ResourceError> {
        let response = self
            .execute_mutation::<AttachUniversalAuth>(&AttachUniversalAuthRequest::new(
                identity_id,
                &settings,
            ))
            .await?;
        Ok(response.identity_universal_auth)
    }

    /// Apply one exact Universal Auth configuration change.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn update_universal_auth(
        &self,
        identity_id: &IdentityId,
        change: UniversalAuthChange,
    ) -> Result<UniversalAuthConfig, ResourceError> {
        let response = self
            .execute_mutation::<UpdateUniversalAuth>(&UpdateUniversalAuthRequest::change(
                identity_id,
                change,
            ))
            .await?;
        Ok(response.identity_universal_auth)
    }

    /// Remove Universal Auth and revoke its credentials after confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn remove_universal_auth(
        &self,
        identity_id: &IdentityId,
        confirm: bool,
    ) -> Result<UniversalAuthConfig, ResourceError> {
        if !confirm {
            return Err(ResourceError::UniversalAuthRemovalNotConfirmed);
        }
        let response = self
            .execute_mutation::<RemoveUniversalAuth>(&IdentityPathQuery {
                identity_id: identity_id.clone(),
            })
            .await?;
        Ok(response.identity_universal_auth)
    }

    /// List a bounded local page of non-secret client-secret metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_universal_auth_client_secrets(
        &self,
        identity_id: &IdentityId,
        page: PageRequest,
    ) -> Result<Page<UniversalAuthClientSecret>, ResourceError> {
        let response = self
            .execute_read::<ListClientSecrets>(&IdentityPathQuery {
                identity_id: identity_id.clone(),
            })
            .await?;
        paginate(page, response.client_secret_data)
    }

    /// Get non-secret metadata for one exact Universal Auth client secret.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_universal_auth_client_secret(
        &self,
        identity_id: &IdentityId,
        client_secret_id: &UniversalAuthClientSecretId,
    ) -> Result<UniversalAuthClientSecret, ResourceError> {
        let response = self
            .execute_read::<GetClientSecret>(&ClientSecretQuery {
                identity_id: identity_id.clone(),
                client_secret_id: client_secret_id.clone(),
            })
            .await?;
        Ok(response.client_secret_data)
    }

    /// Create a credential and return its generated secret exactly once.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn create_universal_auth_client_secret(
        &self,
        identity_id: &IdentityId,
        creation: UniversalAuthClientSecretCreation,
    ) -> Result<CreatedUniversalAuthClientSecret, ResourceError> {
        let response = self
            .execute_mutation::<CreateClientSecret>(&CreateClientSecretRequest {
                identity_id: identity_id.clone(),
                description: creation.description,
                num_uses_limit: creation.num_uses_limit,
                ttl: creation.ttl,
            })
            .await?;
        Ok(CreatedUniversalAuthClientSecret {
            client_secret: SecretValue::new(response.client_secret),
            metadata: response.client_secret_data,
        })
    }

    /// Revoke one exact client secret after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn revoke_universal_auth_client_secret(
        &self,
        identity_id: &IdentityId,
        client_secret_id: &UniversalAuthClientSecretId,
        confirm: bool,
    ) -> Result<UniversalAuthClientSecret, ResourceError> {
        if !confirm {
            return Err(ResourceError::UniversalAuthClientSecretRevocationNotConfirmed);
        }
        let response = self
            .execute_mutation::<RevokeClientSecret>(&ClientSecretQuery {
                identity_id: identity_id.clone(),
                client_secret_id: client_secret_id.clone(),
            })
            .await?;
        Ok(response.client_secret_data)
    }

    /// Clear Universal Auth lockouts after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn clear_universal_auth_lockouts(
        &self,
        identity_id: &IdentityId,
        confirm: bool,
    ) -> Result<UniversalAuthLockoutClear, ResourceError> {
        if !confirm {
            return Err(ResourceError::UniversalAuthLockoutClearNotConfirmed);
        }
        Ok(self
            .execute_mutation::<ClearLockouts>(&IdentityPathQuery {
                identity_id: identity_id.clone(),
            })
            .await?)
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
        IdentityId, InfisicalClient, PageRequest, ResourceError, UniversalAuthChange,
        UniversalAuthClientSecretCreation, UniversalAuthClientSecretId, UniversalAuthInputError,
        UniversalAuthLockoutPolicy, UniversalAuthSettings,
        test_support::{mount_login, settings},
    };

    fn config() -> Value {
        json!({
            "id": "universal-auth-1",
            "clientId": "public-client-id",
            "identityId": "identity-1",
            "accessTokenTTL": 3600,
            "accessTokenMaxTTL": 86400,
            "accessTokenNumUsesLimit": 10,
            "accessTokenPeriod": 0,
            "lockoutEnabled": true,
            "lockoutThreshold": 3,
            "lockoutDurationSeconds": 300,
            "lockoutCounterResetSeconds": 30,
            "clientSecretTrustedIps": [
                { "ipAddress": "0.0.0.0", "type": "ipv4", "prefix": 0 }
            ],
            "accessTokenTrustedIps": [
                { "ipAddress": "::", "type": "ipv6", "prefix": 0 }
            ],
            "createdAt": "2026-07-19T12:00:00.000Z",
            "updatedAt": "2026-07-19T12:00:00.000Z"
        })
    }

    fn client_secret(id: &str, revoked: bool) -> Value {
        json!({
            "id": id,
            "description": "gateway credential",
            "clientSecretPrefix": "ua.abc",
            "clientSecretNumUses": 2,
            "clientSecretNumUsesLimit": 10,
            "clientSecretTTL": 86400,
            "identityUAId": "universal-auth-1",
            "isClientSecretRevoked": revoked,
            "createdAt": "2026-07-19T12:00:00.000Z",
            "updatedAt": "2026-07-19T12:00:00.000Z"
        })
    }

    #[test]
    fn settings_reject_invalid_lifetimes_lockouts_and_descriptions() {
        assert_eq!(
            UniversalAuthSettings::new(10, 9, 0, 0, true, 3, 300, 30).unwrap_err(),
            UniversalAuthInputError::TokenLifetimeOrder
        );
        assert_eq!(
            UniversalAuthChange::token_lifetime(1, 1, 315_360_001).unwrap_err(),
            UniversalAuthInputError::InvalidTokenLifetime
        );
        assert_eq!(
            UniversalAuthLockoutPolicy::new(true, 0, 300, 30).unwrap_err(),
            UniversalAuthInputError::InvalidLockoutThreshold
        );
        assert_eq!(
            UniversalAuthLockoutPolicy::new(true, 3, 29, 30).unwrap_err(),
            UniversalAuthInputError::InvalidLockoutDuration
        );
        assert_eq!(
            UniversalAuthLockoutPolicy::new(true, 3, 300, 4).unwrap_err(),
            UniversalAuthInputError::InvalidLockoutCounterReset
        );
        assert_eq!(
            UniversalAuthClientSecretCreation::new(" padded ", 0, 0).unwrap_err(),
            UniversalAuthInputError::InvalidClientSecretDescription
        );
        assert!(UniversalAuthChange::token_lifetime(315_360_000, 315_360_000, 315_360_000).is_ok());
        assert!(UniversalAuthLockoutPolicy::new(true, 30, 86_400, 3_600).is_ok());
        assert!(UniversalAuthClientSecretCreation::new("", u32::MAX, 315_360_000).is_ok());
    }

    #[tokio::test]
    async fn universal_auth_configuration_uses_exact_v1_contracts() {
        let server = MockServer::start().await;
        mount_login(&server, "universal-admin-token").await;
        let route = "/api/v1/auth/universal-auth/identities/identity-1";
        Mock::given(method("GET"))
            .and(path(route))
            .and(header("authorization", "Bearer universal-admin-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityUniversalAuth": config()
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(route))
            .and(header("authorization", "Bearer universal-admin-token"))
            .and(body_json(json!({
                "accessTokenTTL": 3600,
                "accessTokenMaxTTL": 86400,
                "accessTokenNumUsesLimit": 10,
                "accessTokenPeriod": 0,
                "lockoutEnabled": true,
                "lockoutThreshold": 3,
                "lockoutDurationSeconds": 300,
                "lockoutCounterResetSeconds": 30
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityUniversalAuth": config()
            })))
            .expect(1)
            .mount(&server)
            .await;
        for body in [
            json!({
                "accessTokenTTL": 1800,
                "accessTokenMaxTTL": 7200,
                "accessTokenPeriod": 0
            }),
            json!({ "accessTokenNumUsesLimit": 20 }),
            json!({
                "lockoutEnabled": true,
                "lockoutThreshold": 5,
                "lockoutDurationSeconds": 600,
                "lockoutCounterResetSeconds": 60
            }),
        ] {
            Mock::given(method("PATCH"))
                .and(path(route))
                .and(header("authorization", "Bearer universal-admin-token"))
                .and(body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "identityUniversalAuth": config()
                })))
                .expect(1)
                .mount(&server)
                .await;
        }

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let read = client.get_universal_auth(&identity_id).await.unwrap();
        assert_eq!(read.client_id, "public-client-id");
        assert_eq!(read.client_secret_trusted_ips[0].address_type, "ipv4");
        client
            .attach_universal_auth(
                &identity_id,
                UniversalAuthSettings::new(3600, 86400, 10, 0, true, 3, 300, 30).unwrap(),
            )
            .await
            .unwrap();
        client
            .update_universal_auth(
                &identity_id,
                UniversalAuthChange::token_lifetime(1800, 7200, 0).unwrap(),
            )
            .await
            .unwrap();
        client
            .update_universal_auth(&identity_id, UniversalAuthChange::AccessTokenUseLimit(20))
            .await
            .unwrap();
        client
            .update_universal_auth(
                &identity_id,
                UniversalAuthChange::Lockout(
                    UniversalAuthLockoutPolicy::new(true, 5, 600, 60).unwrap(),
                ),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn destructive_configuration_actions_require_confirmation_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let client_secret_id = UniversalAuthClientSecretId::new("client-secret-1").unwrap();

        assert_eq!(
            client
                .remove_universal_auth(&identity_id, false)
                .await
                .unwrap_err(),
            ResourceError::UniversalAuthRemovalNotConfirmed
        );
        assert_eq!(
            client
                .revoke_universal_auth_client_secret(&identity_id, &client_secret_id, false,)
                .await
                .unwrap_err(),
            ResourceError::UniversalAuthClientSecretRevocationNotConfirmed
        );
        assert_eq!(
            client
                .clear_universal_auth_lockouts(&identity_id, false)
                .await
                .unwrap_err(),
            ResourceError::UniversalAuthLockoutClearNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn credential_lifecycle_bounds_metadata_and_redacts_generated_secret() {
        let server = MockServer::start().await;
        mount_login(&server, "credential-admin-token").await;
        let collection = "/api/v1/auth/universal-auth/identities/identity-1/client-secrets";
        Mock::given(method("GET"))
            .and(path(collection))
            .and(header("authorization", "Bearer credential-admin-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "clientSecretData": [
                    client_secret("client-secret-1", false),
                    client_secret("client-secret-2", false)
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{collection}/client-secret-2")))
            .and(header("authorization", "Bearer credential-admin-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "clientSecretData": client_secret("client-secret-2", false)
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(collection))
            .and(header("authorization", "Bearer credential-admin-token"))
            .and(body_json(json!({
                "description": "gateway credential",
                "numUsesLimit": 10,
                "ttl": 86400
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "clientSecret": "generated-secret-canary",
                "clientSecretData": client_secret("client-secret-3", false)
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{collection}/client-secret-2/revoke")))
            .and(header("authorization", "Bearer credential-admin-token"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "clientSecretData": client_secret("client-secret-2", true)
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let client_secret_id = UniversalAuthClientSecretId::new("client-secret-2").unwrap();
        let page = client
            .list_universal_auth_client_secrets(&identity_id, PageRequest::new(1, 1).unwrap())
            .await
            .unwrap();
        assert_eq!(page.items[0].id, "client-secret-2");
        assert_eq!(page.total, Some(2));
        assert_eq!(
            client
                .get_universal_auth_client_secret(&identity_id, &client_secret_id)
                .await
                .unwrap()
                .client_secret_prefix,
            "ua.abc"
        );
        let created = client
            .create_universal_auth_client_secret(
                &identity_id,
                UniversalAuthClientSecretCreation::new("gateway credential", 10, 86400).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            created.client_secret.expose_secret(),
            "generated-secret-canary"
        );
        let debug = format!("{created:?}");
        assert!(!debug.contains("generated-secret-canary"));
        assert!(debug.contains("SecretValue([REDACTED])"));
        assert!(debug.contains("client-secret-3"));
        assert_eq!(created.metadata.id, "client-secret-3");
        assert!(
            client
                .revoke_universal_auth_client_secret(&identity_id, &client_secret_id, true)
                .await
                .unwrap()
                .is_client_secret_revoked
        );
    }

    #[tokio::test]
    async fn confirmed_configuration_removal_and_lockout_clear_are_sent_once() {
        let server = MockServer::start().await;
        mount_login(&server, "recovery-admin-token").await;
        let route = "/api/v1/auth/universal-auth/identities/identity-1";
        Mock::given(method("DELETE"))
            .and(path(route))
            .and(header("authorization", "Bearer recovery-admin-token"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityUniversalAuth": config()
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{route}/clear-lockouts")))
            .and(header("authorization", "Bearer recovery-admin-token"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "deleted": 2 })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        client
            .remove_universal_auth(&identity_id, true)
            .await
            .unwrap();
        assert_eq!(
            client
                .clear_universal_auth_lockouts(&identity_id, true)
                .await
                .unwrap()
                .deleted,
            2
        );
    }
}
