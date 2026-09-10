use std::fmt;

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    IdentityId, InfisicalClient, MutationOperation, Page, PageRequest, ReadOperation,
    ResourceError, SecretValue, TokenAuthTokenId, TrustedIp,
    client::{ApiVersion, Endpoint, sealed},
};

/// Maximum offset accepted by the pinned Token Auth token-list route.
pub const MAX_TOKEN_AUTH_LIST_OFFSET: u32 = 100;
/// Maximum lifetime accepted by the pinned Token Auth configuration routes.
pub const MAX_TOKEN_AUTH_LIFETIME_SECONDS: u32 = 315_360_000;
/// Maximum operator label accepted at the MCP boundary.
pub const MAX_TOKEN_AUTH_TOKEN_NAME_BYTES: usize = 128;

/// Validation failures for Token Auth configuration and token metadata.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuthInputError {
    /// A token lifetime exceeded the pinned API limit.
    #[error("token lifetimes must not exceed 315360000 seconds")]
    InvalidTokenLifetime,
    /// A finite maximum lifetime was shorter than the ordinary lifetime.
    #[error("access token TTL must not exceed a non-zero access token maximum TTL")]
    TokenLifetimeOrder,
    /// A token name was padded, empty, unbounded, or control-bearing.
    #[error(
        "token name must contain 1 to 128 bytes without surrounding whitespace or control characters"
    )]
    InvalidTokenName,
    /// An organization slug was outside the pinned slug contract.
    #[error("organization slug must contain 1 to 64 lowercase words separated by single hyphens")]
    InvalidOrganizationSlug,
}

/// Non-secret Token Auth configuration for one machine identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenAuthConfig {
    /// Opaque Token Auth configuration identifier.
    pub id: String,
    /// Machine identity that owns this authentication method.
    pub identity_id: String,
    /// Ordinary access-token lifetime in seconds.
    #[serde(rename = "accessTokenTTL")]
    pub access_token_ttl: u32,
    /// Maximum renewable access-token lifetime in seconds; zero means unlimited.
    #[serde(rename = "accessTokenMaxTTL")]
    pub access_token_max_ttl: u32,
    /// Maximum token uses; zero means unlimited.
    pub access_token_num_uses_limit: u32,
    /// Periodic-token interval returned by Infisical; the pinned mutation routes do not expose it.
    pub access_token_period: u32,
    /// Access-token source ranges, readable but not mutable in the community surface.
    pub access_token_trusted_ips: Vec<TrustedIp>,
    /// Infisical creation timestamp.
    pub created_at: String,
    /// Infisical update timestamp.
    pub updated_at: String,
}

/// Complete community-compatible Token Auth settings used during attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAuthSettings {
    ttl: u32,
    max_ttl: u32,
    num_uses_limit: u32,
}

impl TokenAuthSettings {
    /// Validate a complete configuration before it reaches Infisical.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for a lifetime outside the pinned contract.
    pub fn new(
        access_token_ttl: u32,
        access_token_max_ttl: u32,
        access_token_num_uses_limit: u32,
    ) -> Result<Self, TokenAuthInputError> {
        validate_lifetime(access_token_ttl, access_token_max_ttl)?;
        Ok(Self {
            ttl: access_token_ttl,
            max_ttl: access_token_max_ttl,
            num_uses_limit: access_token_num_uses_limit,
        })
    }
}

/// One atomic Token Auth configuration change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenAuthChange {
    /// Replace both mutually constrained lifetime fields together.
    TokenLifetime {
        /// Ordinary token lifetime in seconds.
        access_token_ttl: u32,
        /// Maximum renewable lifetime; zero means unlimited.
        access_token_max_ttl: u32,
    },
    /// Replace the token use limit; zero means unlimited.
    AccessTokenUseLimit(u32),
}

impl TokenAuthChange {
    /// Validate a complete token-lifetime change.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for an invalid lifetime or ordering.
    pub fn token_lifetime(
        access_token_ttl: u32,
        access_token_max_ttl: u32,
    ) -> Result<Self, TokenAuthInputError> {
        validate_lifetime(access_token_ttl, access_token_max_ttl)?;
        Ok(Self::TokenLifetime {
            access_token_ttl,
            access_token_max_ttl,
        })
    }
}

fn validate_lifetime(
    access_token_ttl: u32,
    access_token_max_ttl: u32,
) -> Result<(), TokenAuthInputError> {
    if access_token_ttl > MAX_TOKEN_AUTH_LIFETIME_SECONDS
        || access_token_max_ttl > MAX_TOKEN_AUTH_LIFETIME_SECONDS
    {
        return Err(TokenAuthInputError::InvalidTokenLifetime);
    }
    if access_token_max_ttl > 0 && access_token_ttl > access_token_max_ttl {
        return Err(TokenAuthInputError::TokenLifetimeOrder);
    }
    Ok(())
}

/// Non-secret metadata for one Token Auth access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenAuthToken {
    /// Opaque token identifier; this is not the credential value.
    pub id: String,
    /// Owning machine identity.
    pub identity_id: String,
    /// Non-secret operator label.
    pub name: Option<String>,
    /// Authentication-method label returned by Infisical.
    pub auth_method: String,
    /// Token lifetime in seconds.
    #[serde(rename = "accessTokenTTL")]
    pub access_token_ttl: u32,
    /// Maximum renewable token lifetime in seconds.
    #[serde(rename = "accessTokenMaxTTL")]
    pub access_token_max_ttl: u32,
    /// Uses observed by Infisical.
    pub access_token_num_uses: u32,
    /// Maximum token uses; zero means unlimited.
    pub access_token_num_uses_limit: u32,
    /// Last successful use timestamp, when present.
    pub access_token_last_used_at: Option<String>,
    /// Last renewal timestamp, when present.
    pub access_token_last_renewed_at: Option<String>,
    /// Whether the token has been revoked.
    pub is_access_token_revoked: bool,
    /// Periodic-token interval in seconds.
    pub access_token_period: u32,
    /// Optional sub-organization scope.
    pub sub_organization_id: Option<String>,
    /// Infisical creation timestamp.
    pub created_at: String,
    /// Infisical update timestamp.
    pub updated_at: String,
}

/// Validated options for generating one Token Auth credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAuthTokenCreation {
    name: Option<String>,
    organization_slug: Option<String>,
}

impl TokenAuthTokenCreation {
    /// Validate optional non-secret creation metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for an unsafe label or organization slug.
    pub fn new(
        name: Option<String>,
        organization_slug: Option<String>,
    ) -> Result<Self, TokenAuthInputError> {
        if name.as_ref().is_some_and(|name| !is_valid_name(name)) {
            return Err(TokenAuthInputError::InvalidTokenName);
        }
        if organization_slug
            .as_ref()
            .is_some_and(|slug| !is_valid_slug(slug))
        {
            return Err(TokenAuthInputError::InvalidOrganizationSlug);
        }
        Ok(Self {
            name,
            organization_slug,
        })
    }
}

fn is_valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_AUTH_TOKEN_NAME_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn is_valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

/// A newly generated Token Auth credential and its value-free metadata.
pub struct CreatedTokenAuthToken {
    /// Bearer credential returned once by Infisical.
    pub access_token: SecretValue,
    /// Lifetime of the generated token in seconds.
    pub expires_in: u32,
    /// Maximum renewable lifetime of the generated token in seconds.
    pub access_token_max_ttl: u32,
    /// Non-secret token metadata.
    pub metadata: TokenAuthToken,
}

impl fmt::Debug for CreatedTokenAuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedTokenAuthToken")
            .field("access_token", &self.access_token)
            .field("expires_in", &self.expires_in)
            .field("access_token_max_ttl", &self.access_token_max_ttl)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Result returned after revoking one Token Auth token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema, Deserialize)]
pub struct TokenAuthTokenRevocation {
    /// Upstream revocation acknowledgement.
    pub message: String,
}

#[derive(Serialize)]
struct IdentityPathQuery {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
}

#[derive(Serialize)]
struct TokenPathQuery {
    #[serde(skip_serializing)]
    token_id: TokenAuthTokenId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenAuthResponse {
    identity_token_auth: TokenAuthConfig,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachTokenAuthRequest {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
    #[serde(rename = "accessTokenTTL")]
    access_token_ttl: u32,
    #[serde(rename = "accessTokenMaxTTL")]
    access_token_max_ttl: u32,
    access_token_num_uses_limit: u32,
}

impl AttachTokenAuthRequest {
    fn new(identity_id: &IdentityId, settings: &TokenAuthSettings) -> Self {
        Self {
            identity_id: identity_id.clone(),
            access_token_ttl: settings.ttl,
            access_token_max_ttl: settings.max_ttl,
            access_token_num_uses_limit: settings.num_uses_limit,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateTokenAuthRequest {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
    #[serde(rename = "accessTokenTTL", skip_serializing_if = "Option::is_none")]
    access_token_ttl: Option<u32>,
    #[serde(rename = "accessTokenMaxTTL", skip_serializing_if = "Option::is_none")]
    access_token_max_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token_num_uses_limit: Option<u32>,
}

impl UpdateTokenAuthRequest {
    fn change(identity_id: &IdentityId, change: &TokenAuthChange) -> Self {
        match change {
            TokenAuthChange::TokenLifetime {
                access_token_ttl,
                access_token_max_ttl,
            } => Self {
                identity_id: identity_id.clone(),
                access_token_ttl: Some(*access_token_ttl),
                access_token_max_ttl: Some(*access_token_max_ttl),
                access_token_num_uses_limit: None,
            },
            TokenAuthChange::AccessTokenUseLimit(limit) => Self {
                identity_id: identity_id.clone(),
                access_token_ttl: None,
                access_token_max_ttl: None,
                access_token_num_uses_limit: Some(*limit),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListTokensQuery {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
    offset: u32,
    limit: u16,
}

#[derive(Deserialize)]
struct TokenListResponse {
    tokens: Vec<TokenAuthToken>,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: TokenAuthToken,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenRequest {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_slug: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreatedTokenResponse {
    access_token: String,
    expires_in: u32,
    #[serde(rename = "accessTokenMaxTTL")]
    access_token_max_ttl: u32,
    token_data: TokenAuthToken,
}

#[derive(Serialize)]
struct UpdateTokenRequest {
    #[serde(skip_serializing)]
    token_id: TokenAuthTokenId,
    name: String,
}

struct GetTokenAuth;
impl sealed::Sealed for GetTokenAuth {}
impl ReadOperation for GetTokenAuth {
    type Query = IdentityPathQuery;
    type Output = TokenAuthResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        token_auth_endpoint(&query.identity_id)
    }
}

struct AttachTokenAuth;
impl sealed::Sealed for AttachTokenAuth {}
impl MutationOperation for AttachTokenAuth {
    type Input = AttachTokenAuthRequest;
    type Output = TokenAuthResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        token_auth_endpoint(&input.identity_id)
    }
}

struct UpdateTokenAuth;
impl sealed::Sealed for UpdateTokenAuth {}
impl MutationOperation for UpdateTokenAuth {
    type Input = UpdateTokenAuthRequest;
    type Output = TokenAuthResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        token_auth_endpoint(&input.identity_id)
    }
}

struct RemoveTokenAuth;
impl sealed::Sealed for RemoveTokenAuth {}
impl MutationOperation for RemoveTokenAuth {
    type Input = IdentityPathQuery;
    type Output = TokenAuthResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        token_auth_endpoint(&input.identity_id)
    }
}

struct ListTokens;
impl sealed::Sealed for ListTokens {}
impl ReadOperation for ListTokens {
    type Query = ListTokensQuery;
    type Output = TokenListResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "auth",
                "token-auth",
                "identities",
                query.identity_id.as_str(),
                "tokens",
            ],
        )
    }
}

struct GetToken;
impl sealed::Sealed for GetToken {}
impl ReadOperation for GetToken {
    type Query = TokenPathQuery;
    type Output = TokenResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        token_endpoint(&query.token_id)
    }
}

struct CreateToken;
impl sealed::Sealed for CreateToken {}
impl MutationOperation for CreateToken {
    type Input = CreateTokenRequest;
    type Output = CreatedTokenResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "auth",
                "token-auth",
                "identities",
                input.identity_id.as_str(),
                "tokens",
            ],
        )
    }
}

struct UpdateToken;
impl sealed::Sealed for UpdateToken {}
impl MutationOperation for UpdateToken {
    type Input = UpdateTokenRequest;
    type Output = TokenResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        token_endpoint(&input.token_id)
    }
}

struct RevokeToken;
impl sealed::Sealed for RevokeToken {}
impl MutationOperation for RevokeToken {
    type Input = TokenPathQuery;
    type Output = TokenAuthTokenRevocation;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "auth",
                "token-auth",
                "tokens",
                input.token_id.as_str(),
                "revoke",
            ],
        )
    }
}

fn token_auth_endpoint(identity_id: &IdentityId) -> Endpoint {
    Endpoint::from_segments(
        ApiVersion::V1,
        ["auth", "token-auth", "identities", identity_id.as_str()],
    )
}

fn token_endpoint(token_id: &TokenAuthTokenId) -> Endpoint {
    Endpoint::from_segments(
        ApiVersion::V1,
        ["auth", "token-auth", "tokens", token_id.as_str()],
    )
}

impl InfisicalClient {
    /// Get non-secret Token Auth configuration for one machine identity.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_token_auth(
        &self,
        identity_id: &IdentityId,
    ) -> Result<TokenAuthConfig, ResourceError> {
        let response = self
            .execute_read::<GetTokenAuth>(&IdentityPathQuery {
                identity_id: identity_id.clone(),
            })
            .await?;
        Ok(response.identity_token_auth)
    }

    /// Attach one complete community-compatible Token Auth configuration.
    ///
    /// Trusted-IP fields are omitted so Infisical applies its defaults without
    /// implying that enterprise-only mutation is available.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn attach_token_auth(
        &self,
        identity_id: &IdentityId,
        settings: TokenAuthSettings,
    ) -> Result<TokenAuthConfig, ResourceError> {
        let response = self
            .execute_mutation::<AttachTokenAuth>(&AttachTokenAuthRequest::new(
                identity_id,
                &settings,
            ))
            .await?;
        Ok(response.identity_token_auth)
    }

    /// Apply one exact Token Auth configuration change.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn update_token_auth(
        &self,
        identity_id: &IdentityId,
        change: TokenAuthChange,
    ) -> Result<TokenAuthConfig, ResourceError> {
        let response = self
            .execute_mutation::<UpdateTokenAuth>(&UpdateTokenAuthRequest::change(
                identity_id,
                &change,
            ))
            .await?;
        Ok(response.identity_token_auth)
    }

    /// Remove Token Auth and revoke its credentials after confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn remove_token_auth(
        &self,
        identity_id: &IdentityId,
        confirm: bool,
    ) -> Result<TokenAuthConfig, ResourceError> {
        if !confirm {
            return Err(ResourceError::TokenAuthRemovalNotConfirmed);
        }
        let response = self
            .execute_mutation::<RemoveTokenAuth>(&IdentityPathQuery {
                identity_id: identity_id.clone(),
            })
            .await?;
        Ok(response.identity_token_auth)
    }

    /// List one upstream-bounded page of value-free Token Auth metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error. A full page at the pinned
    /// route's maximum offset is rejected instead of returning an unusable continuation.
    pub async fn list_token_auth_tokens(
        &self,
        identity_id: &IdentityId,
        page: PageRequest,
    ) -> Result<Page<TokenAuthToken>, ResourceError> {
        if page.offset() > MAX_TOKEN_AUTH_LIST_OFFSET {
            return Err(ResourceError::TokenAuthPageOffsetLimit);
        }
        let response = self
            .execute_read::<ListTokens>(&ListTokensQuery {
                identity_id: identity_id.clone(),
                offset: page.offset(),
                limit: page.limit(),
            })
            .await?;
        let result = Page::new(page, response.tokens, None)?;
        if result
            .next
            .is_some_and(|next| next.offset() > MAX_TOKEN_AUTH_LIST_OFFSET)
        {
            return Err(ResourceError::CollectionTooLarge);
        }
        Ok(result)
    }

    /// Get value-free metadata for one exact Token Auth token.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_token_auth_token(
        &self,
        token_id: &TokenAuthTokenId,
    ) -> Result<TokenAuthToken, ResourceError> {
        let response = self
            .execute_read::<GetToken>(&TokenPathQuery {
                token_id: token_id.clone(),
            })
            .await?;
        Ok(response.token)
    }

    /// Generate a Token Auth credential and return its value exactly once.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn create_token_auth_token(
        &self,
        identity_id: &IdentityId,
        creation: TokenAuthTokenCreation,
    ) -> Result<CreatedTokenAuthToken, ResourceError> {
        let response = self
            .execute_mutation::<CreateToken>(&CreateTokenRequest {
                identity_id: identity_id.clone(),
                name: creation.name,
                organization_slug: creation.organization_slug,
            })
            .await?;
        Ok(CreatedTokenAuthToken {
            access_token: SecretValue::new(response.access_token),
            expires_in: response.expires_in,
            access_token_max_ttl: response.access_token_max_ttl,
            metadata: response.token_data,
        })
    }

    /// Replace the non-secret name of one exact Token Auth token.
    ///
    /// # Errors
    ///
    /// Returns a typed validation or client error. The mutation is sent once.
    pub async fn update_token_auth_token(
        &self,
        token_id: &TokenAuthTokenId,
        name: String,
    ) -> Result<TokenAuthToken, ResourceError> {
        if !is_valid_name(&name) {
            return Err(ResourceError::InvalidTokenAuthTokenName);
        }
        let response = self
            .execute_mutation::<UpdateToken>(&UpdateTokenRequest {
                token_id: token_id.clone(),
                name,
            })
            .await?;
        Ok(response.token)
    }

    /// Revoke one exact Token Auth credential after confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn revoke_token_auth_token(
        &self,
        token_id: &TokenAuthTokenId,
        confirm: bool,
    ) -> Result<TokenAuthTokenRevocation, ResourceError> {
        if !confirm {
            return Err(ResourceError::TokenAuthTokenRevocationNotConfirmed);
        }
        Ok(self
            .execute_mutation::<RevokeToken>(&TokenPathQuery {
                token_id: token_id.clone(),
            })
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path, query_param},
    };

    use crate::{
        IdentityId, InfisicalClient, PageRequest, ResourceError, TokenAuthChange,
        TokenAuthInputError, TokenAuthSettings, TokenAuthTokenCreation, TokenAuthTokenId,
        test_support::{mount_login, settings},
    };

    fn config() -> Value {
        json!({
            "id": "token-auth-1",
            "identityId": "identity-1",
            "accessTokenTTL": 3600,
            "accessTokenMaxTTL": 86400,
            "accessTokenNumUsesLimit": 10,
            "accessTokenPeriod": 0,
            "accessTokenTrustedIps": [
                { "ipAddress": "0.0.0.0", "type": "ipv4", "prefix": 0 },
                { "ipAddress": "::", "type": "ipv6", "prefix": 0 }
            ],
            "createdAt": "2026-07-19T12:00:00.000Z",
            "updatedAt": "2026-07-19T12:00:00.000Z"
        })
    }

    fn token(id: &str, name: &str, revoked: bool) -> Value {
        json!({
            "id": id,
            "identityId": "identity-1",
            "name": name,
            "authMethod": "token-auth",
            "accessTokenTTL": 3600,
            "accessTokenMaxTTL": 86400,
            "accessTokenNumUses": 2,
            "accessTokenNumUsesLimit": 10,
            "accessTokenLastUsedAt": "2026-07-19T12:30:00.000Z",
            "accessTokenLastRenewedAt": null,
            "isAccessTokenRevoked": revoked,
            "accessTokenPeriod": 0,
            "subOrganizationId": null,
            "createdAt": "2026-07-19T12:00:00.000Z",
            "updatedAt": "2026-07-19T12:00:00.000Z"
        })
    }

    #[test]
    fn settings_and_creation_metadata_enforce_the_pinned_contract() {
        assert_eq!(
            TokenAuthSettings::new(10, 9, 0).unwrap_err(),
            TokenAuthInputError::TokenLifetimeOrder
        );
        assert_eq!(
            TokenAuthChange::token_lifetime(315_360_001, 0).unwrap_err(),
            TokenAuthInputError::InvalidTokenLifetime
        );
        assert_eq!(
            TokenAuthTokenCreation::new(Some(" padded ".into()), None).unwrap_err(),
            TokenAuthInputError::InvalidTokenName
        );
        assert_eq!(
            TokenAuthTokenCreation::new(None, Some("Bad-Slug".into())).unwrap_err(),
            TokenAuthInputError::InvalidOrganizationSlug
        );
        assert!(TokenAuthSettings::new(315_360_000, 315_360_000, u32::MAX).is_ok());
        assert!(TokenAuthSettings::new(315_360_000, 0, 0).is_ok());
        assert!(
            TokenAuthTokenCreation::new(Some("gateway".into()), Some("child-org".into())).is_ok()
        );
    }

    #[tokio::test]
    async fn configuration_uses_exact_v1_contracts_and_coherent_updates() {
        let server = MockServer::start().await;
        mount_login(&server, "token-auth-admin").await;
        let route = "/api/v1/auth/token-auth/identities/identity-1";
        Mock::given(method("GET"))
            .and(path(route))
            .and(header("authorization", "Bearer token-auth-admin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityTokenAuth": config()
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(route))
            .and(header("authorization", "Bearer token-auth-admin"))
            .and(body_json(json!({
                "accessTokenTTL": 3600,
                "accessTokenMaxTTL": 86400,
                "accessTokenNumUsesLimit": 10
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityTokenAuth": config()
            })))
            .expect(1)
            .mount(&server)
            .await;
        for body in [
            json!({ "accessTokenTTL": 1800, "accessTokenMaxTTL": 7200 }),
            json!({ "accessTokenNumUsesLimit": 20 }),
        ] {
            Mock::given(method("PATCH"))
                .and(path(route))
                .and(header("authorization", "Bearer token-auth-admin"))
                .and(body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "identityTokenAuth": config()
                })))
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("DELETE"))
            .and(path(route))
            .and(header("authorization", "Bearer token-auth-admin"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityTokenAuth": config()
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let read = client.get_token_auth(&identity_id).await.unwrap();
        assert_eq!(read.access_token_trusted_ips[1].address_type, "ipv6");
        client
            .attach_token_auth(
                &identity_id,
                TokenAuthSettings::new(3600, 86400, 10).unwrap(),
            )
            .await
            .unwrap();
        client
            .update_token_auth(
                &identity_id,
                TokenAuthChange::token_lifetime(1800, 7200).unwrap(),
            )
            .await
            .unwrap();
        client
            .update_token_auth(&identity_id, TokenAuthChange::AccessTokenUseLimit(20))
            .await
            .unwrap();
        client.remove_token_auth(&identity_id, true).await.unwrap();
    }

    #[tokio::test]
    async fn destructive_actions_and_invalid_names_fail_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let token_id = TokenAuthTokenId::new("token-1").unwrap();

        assert_eq!(
            client
                .remove_token_auth(&identity_id, false)
                .await
                .unwrap_err(),
            ResourceError::TokenAuthRemovalNotConfirmed
        );
        assert_eq!(
            client
                .revoke_token_auth_token(&token_id, false)
                .await
                .unwrap_err(),
            ResourceError::TokenAuthTokenRevocationNotConfirmed
        );
        assert_eq!(
            client
                .update_token_auth_token(&token_id, " padded ".into())
                .await
                .unwrap_err(),
            ResourceError::InvalidTokenAuthTokenName
        );
        assert_eq!(
            client
                .list_token_auth_tokens(&identity_id, PageRequest::new(101, 1).unwrap())
                .await
                .unwrap_err(),
            ResourceError::TokenAuthPageOffsetLimit
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    async fn token_list_client(offset: u32, tokens: Vec<Value>) -> (InfisicalClient, MockServer) {
        let server = MockServer::start().await;
        mount_login(&server, "token-list-admin").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/token-auth/identities/identity-1/tokens"))
            .and(query_param("offset", offset.to_string()))
            .and(query_param("limit", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "tokens": tokens })))
            .expect(1)
            .mount(&server)
            .await;
        (InfisicalClient::new(settings(&server)).unwrap(), server)
    }

    #[tokio::test]
    async fn token_list_distinguishes_route_boundary_from_overflow() {
        let identity_id = IdentityId::new("identity-1").unwrap();

        let (client, _server) = token_list_client(100, Vec::new()).await;
        let terminal = client
            .list_token_auth_tokens(&identity_id, PageRequest::new(100, 1).unwrap())
            .await
            .unwrap();
        assert!(terminal.next.is_none());

        let (client, _server) = token_list_client(99, vec![token("token-1", "first", false)]).await;
        let final_continuation = client
            .list_token_auth_tokens(&identity_id, PageRequest::new(99, 1).unwrap())
            .await
            .unwrap();
        assert_eq!(
            final_continuation.next,
            Some(PageRequest::new(100, 1).unwrap())
        );

        let (client, _server) =
            token_list_client(100, vec![token("token-1", "first", false)]).await;
        assert_eq!(
            client
                .list_token_auth_tokens(&identity_id, PageRequest::new(100, 1).unwrap())
                .await
                .unwrap_err(),
            ResourceError::CollectionTooLarge
        );
    }

    async fn mount_token_lifecycle(server: &MockServer) {
        mount_login(server, "token-lifecycle-admin").await;
        let collection = "/api/v1/auth/token-auth/identities/identity-1/tokens";
        Mock::given(method("GET"))
            .and(path(collection))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "2"))
            .and(header("authorization", "Bearer token-lifecycle-admin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tokens": [token("token-1", "first", false), token("token-2", "second", false)]
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/token-auth/tokens/token-2"))
            .and(header("authorization", "Bearer token-lifecycle-admin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token": token("token-2", "second", false)
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(collection))
            .and(header("authorization", "Bearer token-lifecycle-admin"))
            .and(body_json(
                json!({ "name": "gateway", "organizationSlug": "child-org" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "generated-token-canary",
                "expiresIn": 3600,
                "accessTokenMaxTTL": 86400,
                "tokenType": "Bearer",
                "tokenData": token("token-3", "gateway", false)
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/auth/token-auth/tokens/token-2"))
            .and(header("authorization", "Bearer token-lifecycle-admin"))
            .and(body_json(json!({ "name": "renamed" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token": token("token-2", "renamed", false)
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/token-auth/tokens/token-2/revoke"))
            .and(header("authorization", "Bearer token-lifecycle-admin"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "Successfully revoked access token"
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn credential_lifecycle_keeps_reads_value_free_and_redacts_generated_token() {
        let server = MockServer::start().await;
        mount_token_lifecycle(&server).await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let token_id = TokenAuthTokenId::new("token-2").unwrap();
        let page = client
            .list_token_auth_tokens(&identity_id, PageRequest::new(0, 2).unwrap())
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.next, Some(PageRequest::new(2, 2).unwrap()));
        assert_eq!(
            client
                .get_token_auth_token(&token_id)
                .await
                .unwrap()
                .name
                .as_deref(),
            Some("second")
        );
        let created = client
            .create_token_auth_token(
                &identity_id,
                TokenAuthTokenCreation::new(Some("gateway".into()), Some("child-org".into()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            created.access_token.expose_secret(),
            "generated-token-canary"
        );
        let debug = format!("{created:?}");
        assert!(!debug.contains("generated-token-canary"));
        assert!(debug.contains("SecretValue([REDACTED])"));
        assert!(debug.contains("token-3"));
        assert_eq!(created.metadata.id, "token-3");
        assert_eq!(
            client
                .update_token_auth_token(&token_id, "renamed".into())
                .await
                .unwrap()
                .name
                .as_deref(),
            Some("renamed")
        );
        assert_eq!(
            client
                .revoke_token_auth_token(&token_id, true)
                .await
                .unwrap()
                .message,
            "Successfully revoked access token"
        );
    }
}
