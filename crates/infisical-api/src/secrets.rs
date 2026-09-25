use std::collections::HashSet;

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    InfisicalClient, MutationOperation, Page, PageRequest, ReadOperation, ResourceError,
    SecretName, SecretScope, SecretValue,
    client::{ApiVersion, Endpoint, sealed},
    resources::paginate,
};

/// Maximum number of secrets accepted by one bounded batch mutation.
pub const MAX_SECRET_BATCH_SIZE: usize = 50;

/// One explicitly revealed secret and its exact coordinates.
///
/// The value remains redacted through standard formatting and is intentionally
/// not serializable as part of the general API model.
#[derive(Debug)]
pub struct RevealedSecret {
    /// Opaque Infisical secret identifier.
    pub id: String,
    /// Exact secret key name.
    pub name: String,
    /// Environment containing the secret.
    pub environment: String,
    /// Current secret version.
    pub version: u64,
    /// Infisical secret type. This API currently fixes the type to `shared`.
    pub secret_type: String,
    /// Absolute secret-tree path containing the secret.
    pub secret_path: String,
    /// Secret value, exposed only by the MCP reveal response boundary.
    pub secret_value: SecretValue,
}

/// One validated name and redacting value in a batch create or update.
#[derive(Debug)]
pub struct SecretValueMutation {
    /// Exact secret name.
    pub name: SecretName,
    /// Value sent only at the reviewed Infisical request boundary.
    pub value: SecretValue,
}

impl SecretValueMutation {
    /// Pair a validated secret name with its redacting value.
    #[must_use]
    pub fn new(name: SecretName, value: SecretValue) -> Self {
        Self { name, value }
    }
}

/// Value-free identity and version metadata returned after a mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretMutationMetadata {
    /// Opaque Infisical secret identifier.
    pub id: String,
    /// Exact secret key name.
    pub name: String,
    /// Environment containing the secret.
    pub environment: String,
    /// Resulting secret version.
    pub version: u64,
    /// Infisical secret type.
    #[serde(rename = "type")]
    pub secret_type: String,
    /// Infisical creation timestamp.
    pub created_at: String,
    /// Infisical update timestamp.
    pub updated_at: String,
}

/// Value-free approval request returned by protected Infisical paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretApproval {
    /// Opaque approval-request identifier.
    pub id: String,
    /// Human-readable approval-request slug.
    pub slug: String,
    /// Current Infisical approval status.
    pub status: String,
}

/// Outcome of a secret mutation, excluding submitted and echoed values.
///
/// Every variant is internally tagged, so each serializes as a JSON object.
/// The root `type` is declared explicitly because a bare `oneOf` leaves it
/// absent, and MCP requires an `outputSchema` root of `type: "object"` —
/// a strict client rejects the entire `tools/list` response without it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[schemars(extend("type" = "object"))]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum SecretMutationReceipt {
    /// Infisical applied the mutation immediately.
    Applied {
        /// Safe metadata for the affected secret.
        secret: SecretMutationMetadata,
    },
    /// A protection policy converted the mutation into an approval request.
    ApprovalRequired {
        /// Safe metadata for the new approval request.
        approval: SecretApproval,
    },
}

/// Outcome of a bounded batch mutation, excluding every submitted or echoed value.
///
/// Declares an explicit object root for the same reason as
/// [`SecretMutationReceipt`]: an internally-tagged enum generates a bare
/// `oneOf`, and an MCP `outputSchema` root must be `type: "object"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[schemars(extend("type" = "object"))]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum SecretBatchMutationReceipt {
    /// Infisical applied the complete batch immediately.
    Applied {
        /// Safe metadata for the affected secrets.
        secrets: Vec<SecretMutationMetadata>,
    },
    /// A protection policy converted the batch into one approval request.
    ApprovalRequired {
        /// Safe metadata for the new approval request.
        approval: SecretApproval,
    },
}

/// Value-free metadata for one Infisical secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretMetadata {
    /// Opaque Infisical secret identifier.
    pub id: String,
    /// Secret key name; the corresponding value is never included.
    pub name: String,
    /// Environment slug containing the secret.
    pub environment: String,
    /// Current secret version number.
    pub version: u64,
    /// Infisical secret type, such as `shared` or `personal`.
    #[serde(rename = "type")]
    pub secret_type: String,
    /// Absolute secret-tree path reported by Infisical, when present.
    pub secret_path: Option<String>,
    /// Whether Infisical reports the value as hidden.
    pub value_hidden: bool,
    /// Operator-provided metadata; values may contain sensitive information.
    pub metadata: Vec<SecretMetadataEntry>,
    /// Tags attached to the secret.
    pub tags: Vec<SecretMetadataTag>,
}

/// Non-value key/value metadata attached to a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretMetadataEntry {
    /// Metadata key.
    pub key: String,
    /// Operator-provided metadata value, which may contain sensitive information.
    pub value: String,
    /// Whether Infisical stores this metadata entry encrypted.
    #[serde(default)]
    pub is_encrypted: bool,
}

/// Tag data embedded in a secret-metadata response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretMetadataTag {
    /// Opaque Infisical tag identifier.
    pub id: String,
    /// Human-readable tag name.
    pub name: String,
    /// Stable tag slug.
    pub slug: String,
    /// Optional display color supplied by Infisical.
    #[serde(default)]
    pub color: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListSecretMetadataQuery {
    project_id: String,
    environment: String,
    secret_path: String,
    view_secret_value: DisabledFlag,
    expand_secret_references: DisabledFlag,
    recursive: bool,
    include_personal_overrides: DisabledFlag,
    // The v4 route is camelCase; deprecated v3 routes used `include_imports`.
    #[serde(rename = "includeImports")]
    include_imports: DisabledFlag,
}

#[derive(Clone, Copy, Serialize)]
enum DisabledFlag {
    #[serde(rename = "false")]
    False,
}

#[derive(Clone, Copy, Serialize)]
enum EnabledFlag {
    #[serde(rename = "true")]
    True,
}

#[derive(Clone, Copy, Serialize)]
enum SharedSecretType {
    #[serde(rename = "shared")]
    Shared,
}

#[derive(Deserialize)]
struct ListSecretMetadataResponse {
    secrets: Vec<SecretWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretWire {
    id: String,
    environment: String,
    version: u64,
    #[serde(rename = "type")]
    secret_type: String,
    secret_key: String,
    #[serde(deserialize_with = "deserialize_secret_value")]
    secret_value: SecretValue,
    secret_value_hidden: bool,
    #[serde(default)]
    secret_path: Option<String>,
    #[serde(default)]
    secret_metadata: Vec<SecretMetadataEntry>,
    #[serde(default)]
    tags: Vec<SecretMetadataTag>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RevealSecretQuery {
    #[serde(skip_serializing)]
    secret_name: SecretName,
    project_id: String,
    environment: String,
    secret_path: String,
    #[serde(rename = "type")]
    secret_type: SharedSecretType,
    view_secret_value: EnabledFlag,
    expand_secret_references: DisabledFlag,
    #[serde(rename = "includeImports")]
    include_imports: DisabledFlag,
}

#[derive(Deserialize)]
struct RevealSecretResponse {
    secret: RevealedSecretWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevealedSecretWire {
    id: String,
    environment: String,
    version: u64,
    #[serde(rename = "type")]
    secret_type: String,
    secret_key: String,
    #[serde(deserialize_with = "deserialize_secret_value")]
    secret_value: SecretValue,
    secret_path: String,
}

impl From<RevealedSecretWire> for RevealedSecret {
    fn from(secret: RevealedSecretWire) -> Self {
        Self {
            id: secret.id,
            name: secret.secret_key,
            environment: secret.environment,
            version: secret.version,
            secret_type: secret.secret_type,
            secret_path: secret.secret_path,
            secret_value: secret.secret_value,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretMutationScope {
    project_id: String,
    environment: String,
    secret_path: String,
    #[serde(rename = "type")]
    secret_type: SharedSecretType,
}

impl From<&SecretScope> for SecretMutationScope {
    fn from(scope: &SecretScope) -> Self {
        Self {
            project_id: scope.project_id().as_str().to_owned(),
            environment: scope.environment().as_str().to_owned(),
            secret_path: scope.path().as_str().to_owned(),
            secret_type: SharedSecretType::Shared,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchSecretScope {
    project_id: String,
    environment: String,
    secret_path: String,
}

impl From<&SecretScope> for BatchSecretScope {
    fn from(scope: &SecretScope) -> Self {
        Self {
            project_id: scope.project_id().as_str().to_owned(),
            environment: scope.environment().as_str().to_owned(),
            secret_path: scope.path().as_str().to_owned(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretValueMutationRequest {
    #[serde(skip_serializing)]
    secret_name: SecretName,
    #[serde(flatten)]
    scope: SecretMutationScope,
    #[serde(serialize_with = "serialize_secret_value")]
    secret_value: SecretValue,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteSecretRequest {
    #[serde(skip_serializing)]
    secret_name: SecretName,
    #[serde(flatten)]
    scope: SecretMutationScope,
}

#[derive(Clone, Copy, Serialize)]
enum BatchUpdateMode {
    #[serde(rename = "failOnNotFound")]
    FailOnNotFound,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchSecretValueWire {
    secret_key: SecretName,
    #[serde(serialize_with = "serialize_secret_value")]
    secret_value: SecretValue,
}

impl From<SecretValueMutation> for BatchSecretValueWire {
    fn from(secret: SecretValueMutation) -> Self {
        Self {
            secret_key: secret.name,
            secret_value: secret.value,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchSecretValueMutationRequest {
    #[serde(flatten)]
    scope: BatchSecretScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<BatchUpdateMode>,
    secrets: Vec<BatchSecretValueWire>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchDeleteSecretWire {
    secret_key: SecretName,
    #[serde(rename = "type")]
    secret_type: SharedSecretType,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchDeleteSecretRequest {
    #[serde(flatten)]
    scope: BatchSecretScope,
    secrets: Vec<BatchDeleteSecretWire>,
}

fn serialize_secret_value<S>(value: &SecretValue, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.expose_secret())
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SecretMutationResponse {
    Applied { secret: SecretMutationWire },
    ApprovalRequired { approval: SecretApprovalWire },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SecretBatchMutationResponse {
    Applied { secrets: Vec<SecretMutationWire> },
    ApprovalRequired { approval: SecretApprovalWire },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretMutationWire {
    id: String,
    environment: String,
    version: u64,
    #[serde(rename = "type")]
    secret_type: String,
    secret_key: String,
    #[serde(deserialize_with = "deserialize_secret_value")]
    secret_value: SecretValue,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct SecretApprovalWire {
    id: String,
    slug: String,
    status: String,
}

impl From<SecretMutationResponse> for SecretMutationReceipt {
    fn from(response: SecretMutationResponse) -> Self {
        match response {
            SecretMutationResponse::Applied { secret } => Self::Applied {
                secret: mutation_metadata(secret),
            },
            SecretMutationResponse::ApprovalRequired { approval } => Self::ApprovalRequired {
                approval: approval.into(),
            },
        }
    }
}

impl From<SecretBatchMutationResponse> for SecretBatchMutationReceipt {
    fn from(response: SecretBatchMutationResponse) -> Self {
        match response {
            SecretBatchMutationResponse::Applied { secrets } => Self::Applied {
                secrets: secrets.into_iter().map(mutation_metadata).collect(),
            },
            SecretBatchMutationResponse::ApprovalRequired { approval } => Self::ApprovalRequired {
                approval: approval.into(),
            },
        }
    }
}

impl From<SecretApprovalWire> for SecretApproval {
    fn from(approval: SecretApprovalWire) -> Self {
        Self {
            id: approval.id,
            slug: approval.slug,
            status: approval.status,
        }
    }
}

fn mutation_metadata(secret: SecretMutationWire) -> SecretMutationMetadata {
    let SecretMutationWire {
        id,
        environment,
        version,
        secret_type,
        secret_key,
        secret_value,
        created_at,
        updated_at,
    } = secret;
    drop(secret_value);
    SecretMutationMetadata {
        id,
        name: secret_key,
        environment,
        version,
        secret_type,
        created_at,
        updated_at,
    }
}

impl From<SecretWire> for SecretMetadata {
    fn from(secret: SecretWire) -> Self {
        let SecretWire {
            id,
            environment,
            version,
            secret_type,
            secret_key,
            secret_value,
            secret_value_hidden,
            secret_path,
            secret_metadata,
            tags,
        } = secret;
        drop(secret_value);
        Self {
            id,
            name: secret_key,
            environment,
            version,
            secret_type,
            secret_path,
            value_hidden: secret_value_hidden,
            metadata: secret_metadata,
            tags,
        }
    }
}

fn deserialize_secret_value<'de, D>(deserializer: D) -> Result<SecretValue, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(SecretValue::new)
}

struct ListSecretMetadata;

impl sealed::Sealed for ListSecretMetadata {}

impl ReadOperation for ListSecretMetadata {
    type Query = ListSecretMetadataQuery;
    type Output = ListSecretMetadataResponse;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V4, "secrets")
    }
}

struct RevealSecret;

impl sealed::Sealed for RevealSecret {}

impl ReadOperation for RevealSecret {
    type Query = RevealSecretQuery;
    type Output = RevealSecretResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V4, ["secrets", query.secret_name.as_str()])
    }
}

struct CreateSecret;

impl sealed::Sealed for CreateSecret {}

impl MutationOperation for CreateSecret {
    type Input = SecretValueMutationRequest;
    type Output = SecretMutationResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V4, ["secrets", input.secret_name.as_str()])
    }
}

struct UpdateSecret;

impl sealed::Sealed for UpdateSecret {}

impl MutationOperation for UpdateSecret {
    type Input = SecretValueMutationRequest;
    type Output = SecretMutationResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V4, ["secrets", input.secret_name.as_str()])
    }
}

struct DeleteSecret;

impl sealed::Sealed for DeleteSecret {}

impl MutationOperation for DeleteSecret {
    type Input = DeleteSecretRequest;
    type Output = SecretMutationResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V4, ["secrets", input.secret_name.as_str()])
    }
}

struct CreateSecretsBatch;

impl sealed::Sealed for CreateSecretsBatch {}

impl MutationOperation for CreateSecretsBatch {
    type Input = BatchSecretValueMutationRequest;
    type Output = SecretBatchMutationResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_static(ApiVersion::V4, "secrets/batch")
    }
}

struct UpdateSecretsBatch;

impl sealed::Sealed for UpdateSecretsBatch {}

impl MutationOperation for UpdateSecretsBatch {
    type Input = BatchSecretValueMutationRequest;
    type Output = SecretBatchMutationResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_static(ApiVersion::V4, "secrets/batch")
    }
}

struct DeleteSecretsBatch;

impl sealed::Sealed for DeleteSecretsBatch {}

impl MutationOperation for DeleteSecretsBatch {
    type Input = BatchDeleteSecretRequest;
    type Output = SecretBatchMutationResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_static(ApiVersion::V4, "secrets/batch")
    }
}

impl InfisicalClient {
    /// List value-free secret metadata under an exact scope.
    ///
    /// The upstream request unconditionally disables secret values, reference
    /// expansion, personal overrides, and imports. A redacting value type still
    /// receives and immediately drops the response field required by the
    /// pinned Infisical schema.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_secret_metadata(
        &self,
        scope: &SecretScope,
        page: PageRequest,
    ) -> Result<Page<SecretMetadata>, ResourceError> {
        let response = self
            .execute_read::<ListSecretMetadata>(&ListSecretMetadataQuery {
                project_id: scope.project_id().as_str().to_owned(),
                environment: scope.environment().as_str().to_owned(),
                secret_path: scope.path().as_str().to_owned(),
                view_secret_value: DisabledFlag::False,
                expand_secret_references: DisabledFlag::False,
                recursive: scope.recursive(),
                include_personal_overrides: DisabledFlag::False,
                include_imports: DisabledFlag::False,
            })
            .await?;
        paginate(
            page,
            response
                .secrets
                .into_iter()
                .map(SecretMetadata::from)
                .collect(),
        )
    }

    /// Reveal one precisely identified current shared secret.
    ///
    /// Reference expansion and imports are unconditionally disabled. The
    /// returned value remains wrapped in [`SecretValue`].
    ///
    /// # Errors
    ///
    /// Returns a typed client error or a response error if the returned name,
    /// environment, path, or shared-secret type does not match the request.
    pub async fn reveal_secret(
        &self,
        scope: &SecretScope,
        name: &SecretName,
    ) -> Result<RevealedSecret, ResourceError> {
        let response = self
            .execute_read::<RevealSecret>(&RevealSecretQuery {
                secret_name: name.clone(),
                project_id: scope.project_id().as_str().to_owned(),
                environment: scope.environment().as_str().to_owned(),
                secret_path: scope.path().as_str().to_owned(),
                secret_type: SharedSecretType::Shared,
                view_secret_value: EnabledFlag::True,
                expand_secret_references: DisabledFlag::False,
                include_imports: DisabledFlag::False,
            })
            .await?;
        let secret = response.secret;
        if secret.secret_key != name.as_str()
            || secret.environment != scope.environment().as_str()
            || secret.secret_path != scope.path().as_str()
            || secret.secret_type != "shared"
        {
            return Err(ResourceError::InvalidSecretResponse);
        }
        Ok(secret.into())
    }

    /// Create one current shared secret without exposing Infisical's echoed value.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent exactly once.
    pub async fn create_secret(
        &self,
        scope: &SecretScope,
        name: &SecretName,
        value: SecretValue,
    ) -> Result<SecretMutationReceipt, ResourceError> {
        self.mutate_secret_value::<CreateSecret>(scope, name, value)
            .await
    }

    /// Replace one current shared secret value without exposing the echoed value.
    ///
    /// Infisical v0.160.12 does not offer an atomic version precondition for
    /// this route, so this method does not claim compare-and-swap semantics.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent exactly once.
    pub async fn update_secret(
        &self,
        scope: &SecretScope,
        name: &SecretName,
        value: SecretValue,
    ) -> Result<SecretMutationReceipt, ResourceError> {
        self.mutate_secret_value::<UpdateSecret>(scope, name, value)
            .await
    }

    async fn mutate_secret_value<O>(
        &self,
        scope: &SecretScope,
        name: &SecretName,
        value: SecretValue,
    ) -> Result<SecretMutationReceipt, ResourceError>
    where
        O: MutationOperation<Input = SecretValueMutationRequest, Output = SecretMutationResponse>,
    {
        let response = self
            .execute_mutation::<O>(&SecretValueMutationRequest {
                secret_name: name.clone(),
                scope: scope.into(),
                secret_value: value,
            })
            .await?;
        Ok(response.into())
    }

    /// Delete one precisely identified current shared secret.
    ///
    /// Infisical v0.160.12 does not offer an atomic version precondition for
    /// this route. `confirm` must be true before any upstream authentication or
    /// mutation occurs.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent exactly once.
    pub async fn delete_secret(
        &self,
        scope: &SecretScope,
        name: &SecretName,
        confirm: bool,
    ) -> Result<SecretMutationReceipt, ResourceError> {
        if !confirm {
            return Err(ResourceError::DeletionNotConfirmed);
        }
        let response = self
            .execute_mutation::<DeleteSecret>(&DeleteSecretRequest {
                secret_name: name.clone(),
                scope: scope.into(),
            })
            .await?;
        Ok(response.into())
    }

    /// Create between one and fifty current shared secrets under one exact scope.
    ///
    /// Duplicate names are rejected before authentication. Infisical's echoed
    /// values are dropped from the returned receipt.
    ///
    /// # Errors
    ///
    /// Returns a validation or typed client error. The batch is sent exactly once.
    pub async fn create_secrets_batch(
        &self,
        scope: &SecretScope,
        secrets: Vec<SecretValueMutation>,
    ) -> Result<SecretBatchMutationReceipt, ResourceError> {
        self.mutate_secret_batch::<CreateSecretsBatch>(scope, secrets, None)
            .await
    }

    /// Replace between one and fifty current shared secret values under one scope.
    ///
    /// The request forces Infisical's `failOnNotFound` mode so a miss cannot
    /// silently create a new secret. Infisical v0.160.12 exposes no atomic
    /// version precondition for this route.
    ///
    /// # Errors
    ///
    /// Returns a validation or typed client error. The batch is sent exactly once.
    pub async fn update_secrets_batch(
        &self,
        scope: &SecretScope,
        secrets: Vec<SecretValueMutation>,
    ) -> Result<SecretBatchMutationReceipt, ResourceError> {
        self.mutate_secret_batch::<UpdateSecretsBatch>(
            scope,
            secrets,
            Some(BatchUpdateMode::FailOnNotFound),
        )
        .await
    }

    async fn mutate_secret_batch<O>(
        &self,
        scope: &SecretScope,
        secrets: Vec<SecretValueMutation>,
        mode: Option<BatchUpdateMode>,
    ) -> Result<SecretBatchMutationReceipt, ResourceError>
    where
        O: MutationOperation<
                Input = BatchSecretValueMutationRequest,
                Output = SecretBatchMutationResponse,
            >,
    {
        validate_secret_batch(secrets.iter().map(|secret| &secret.name), secrets.len())?;
        let response = self
            .execute_mutation::<O>(&BatchSecretValueMutationRequest {
                scope: scope.into(),
                mode,
                secrets: secrets.into_iter().map(Into::into).collect(),
            })
            .await?;
        Ok(response.into())
    }

    /// Delete between one and fifty current shared secrets under one exact scope.
    ///
    /// Confirmation, batch bounds, and duplicate-name checks all occur before
    /// authentication or mutation. Infisical v0.160.12 exposes no atomic
    /// version precondition for this route.
    ///
    /// # Errors
    ///
    /// Returns a validation or typed client error. The batch is sent exactly once.
    pub async fn delete_secrets_batch(
        &self,
        scope: &SecretScope,
        names: Vec<SecretName>,
        confirm: bool,
    ) -> Result<SecretBatchMutationReceipt, ResourceError> {
        if !confirm {
            return Err(ResourceError::DeletionNotConfirmed);
        }
        validate_secret_batch(names.iter(), names.len())?;
        let response = self
            .execute_mutation::<DeleteSecretsBatch>(&BatchDeleteSecretRequest {
                scope: scope.into(),
                secrets: names
                    .into_iter()
                    .map(|secret_key| BatchDeleteSecretWire {
                        secret_key,
                        secret_type: SharedSecretType::Shared,
                    })
                    .collect(),
            })
            .await?;
        Ok(response.into())
    }
}

fn validate_secret_batch<'a>(
    names: impl IntoIterator<Item = &'a SecretName>,
    length: usize,
) -> Result<(), ResourceError> {
    if !(1..=MAX_SECRET_BATCH_SIZE).contains(&length) {
        return Err(ResourceError::InvalidSecretBatchSize);
    }
    let mut unique = HashSet::with_capacity(length);
    if names.into_iter().any(|name| !unique.insert(name.as_str())) {
        return Err(ResourceError::DuplicateSecretName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path, query_param},
    };

    use crate::{
        EnvironmentSlug, InfisicalClient, PageRequest, ProjectId, ResourceError, SecretName,
        SecretPath, SecretScope, SecretValue, SecretValueMutation,
        test_support::{mount_login, settings},
    };

    fn payments_scope() -> SecretScope {
        SecretScope::new(
            ProjectId::new("project-1").unwrap(),
            EnvironmentSlug::new("prod").unwrap(),
            SecretPath::new("/payments").unwrap(),
            false,
        )
    }

    fn mutation_response(name: &str, value: &str, version: u64) -> serde_json::Value {
        json!({
            "secret": {
                "id": "secret-1",
                "_id": "secret-1",
                "workspace": "project-1",
                "environment": "prod",
                "version": version,
                "type": "shared",
                "secretKey": name,
                "secretValue": value,
                "secretComment": "",
                "createdAt": "2026-07-19T12:00:00.000Z",
                "updatedAt": "2026-07-19T12:05:00.000Z",
                "secretValueHidden": true
            }
        })
    }

    fn batch_mutation_response(
        names_and_values: &[(&str, &str)],
        version: u64,
    ) -> serde_json::Value {
        json!({
            "secrets": names_and_values
                .iter()
                .enumerate()
                .map(|(index, (name, value))| json!({
                    "id": format!("secret-{index}"),
                    "environment": "prod",
                    "version": version,
                    "type": "shared",
                    "secretKey": name,
                    "secretValue": value,
                    "createdAt": "2026-07-19T12:00:00.000Z",
                    "updatedAt": "2026-07-19T12:05:00.000Z"
                }))
                .collect::<Vec<_>>()
        })
    }

    fn batch_values(first: &str, second: &str) -> Vec<SecretValueMutation> {
        vec![
            SecretValueMutation::new(
                SecretName::new("STRIPE_API_KEY").unwrap(),
                SecretValue::new(first),
            ),
            SecretValueMutation::new(
                SecretName::new("STRIPE_WEBHOOK_SECRET").unwrap(),
                SecretValue::new(second),
            ),
        ]
    }

    #[tokio::test]
    async fn secret_metadata_forces_value_free_flags_and_drops_upstream_values() {
        let server = MockServer::start().await;
        mount_login(&server, "metadata-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v4/secrets"))
            .and(query_param("projectId", "project-1"))
            .and(query_param("environment", "prod"))
            .and(query_param("secretPath", "/payments"))
            .and(query_param("viewSecretValue", "false"))
            .and(query_param("expandSecretReferences", "false"))
            .and(query_param("recursive", "false"))
            .and(query_param("includePersonalOverrides", "false"))
            .and(query_param("includeImports", "false"))
            .and(header("authorization", "Bearer metadata-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secrets": [{
                    "id": "secret-1",
                    "_id": "secret-1",
                    "workspace": "project-1",
                    "environment": "prod",
                    "version": 7,
                    "type": "shared",
                    "secretKey": "STRIPE_API_KEY",
                    "secretValue": "response-secret-canary",
                    "secretComment": "not exposed by the concise contract",
                    "secretValueHidden": true,
                    "secretPath": "/payments",
                    "secretMetadata": [{ "key": "owner", "value": "billing", "isEncrypted": false }],
                    "tags": [{ "id": "tag-1", "name": "Critical", "slug": "critical", "color": null }]
                }],
                "imports": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let scope = payments_scope();
        let page = client
            .list_secret_metadata(&scope, PageRequest::new(0, 10).unwrap())
            .await
            .unwrap();
        let serialized = serde_json::to_string(&page).unwrap();

        assert_eq!(page.items[0].name, "STRIPE_API_KEY");
        assert_eq!(page.items[0].version, 7);
        assert_eq!(page.items[0].metadata[0].key, "owner");
        assert!(!serialized.contains("response-secret-canary"));
        assert!(!serialized.contains("secretValue"));
        assert!(!serialized.contains("secretComment"));
    }

    #[tokio::test]
    async fn reveal_requests_one_unexpanded_shared_secret_and_keeps_value_redacted() {
        let server = MockServer::start().await;
        mount_login(&server, "reveal-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v4/secrets/STRIPE_API_KEY"))
            .and(query_param("projectId", "project-1"))
            .and(query_param("environment", "prod"))
            .and(query_param("secretPath", "/payments"))
            .and(query_param("type", "shared"))
            .and(query_param("viewSecretValue", "true"))
            .and(query_param("expandSecretReferences", "false"))
            .and(query_param("includeImports", "false"))
            .and(header("authorization", "Bearer reveal-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secret": {
                    "id": "secret-1",
                    "environment": "prod",
                    "version": 7,
                    "type": "shared",
                    "secretKey": "STRIPE_API_KEY",
                    "secretValue": "revealed-secret-canary",
                    "secretPath": "/payments"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let revealed = client
            .reveal_secret(
                &payments_scope(),
                &SecretName::new("STRIPE_API_KEY").unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(revealed.name, "STRIPE_API_KEY");
        assert_eq!(revealed.version, 7);
        assert_eq!(
            revealed.secret_value.expose_secret(),
            "revealed-secret-canary"
        );
        assert!(!format!("{revealed:?}").contains("revealed-secret-canary"));
    }

    #[tokio::test]
    async fn reveal_rejects_each_mismatched_coordinate_without_exposing_the_value() {
        for (field, value) in [
            ("secretKey", "OTHER_KEY"),
            ("environment", "staging"),
            ("secretPath", "/other"),
            ("type", "personal"),
            ("type", "unknown"),
        ] {
            let server = MockServer::start().await;
            mount_login(&server, "reveal-token").await;
            let mut secret = json!({
                "id": "secret-1", "environment": "prod", "version": 7,
                "type": "shared", "secretKey": "STRIPE_API_KEY",
                "secretValue": "wrong-scope-secret-canary", "secretPath": "/payments"
            });
            secret[field] = json!(value);
            Mock::given(method("GET"))
                .and(path("/api/v4/secrets/STRIPE_API_KEY"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"secret": secret})))
                .expect(1)
                .mount(&server)
                .await;
            let client = InfisicalClient::new(settings(&server)).unwrap();
            let error = client
                .reveal_secret(
                    &payments_scope(),
                    &SecretName::new("STRIPE_API_KEY").unwrap(),
                )
                .await
                .unwrap_err();
            assert_eq!(
                error,
                ResourceError::InvalidSecretResponse,
                "{field}: {value}"
            );
            assert!(!format!("{error} {error:?}").contains("wrong-scope-secret-canary"));
        }
    }

    #[tokio::test]
    async fn create_update_and_delete_send_exact_scopes_once_and_drop_echoed_values() {
        let server = MockServer::start().await;
        mount_login(&server, "mutation-token").await;
        let scope_body = json!({
            "projectId": "project-1",
            "environment": "prod",
            "secretPath": "/payments",
            "type": "shared"
        });
        Mock::given(method("POST"))
            .and(path("/api/v4/secrets/STRIPE_API_KEY"))
            .and(header("authorization", "Bearer mutation-token"))
            .and(body_json(json!({
                "projectId": scope_body["projectId"],
                "environment": scope_body["environment"],
                "secretPath": scope_body["secretPath"],
                "type": scope_body["type"],
                "secretValue": "create-input-canary"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(mutation_response(
                "STRIPE_API_KEY",
                "create-response-canary",
                1,
            )))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v4/secrets/STRIPE_API_KEY"))
            .and(header("authorization", "Bearer mutation-token"))
            .and(body_json(json!({
                "projectId": scope_body["projectId"],
                "environment": scope_body["environment"],
                "secretPath": scope_body["secretPath"],
                "type": scope_body["type"],
                "secretValue": "update-input-canary"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(mutation_response(
                "STRIPE_API_KEY",
                "update-response-canary",
                2,
            )))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/v4/secrets/STRIPE_API_KEY"))
            .and(header("authorization", "Bearer mutation-token"))
            .and(body_json(scope_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(mutation_response(
                "STRIPE_API_KEY",
                "delete-response-canary",
                2,
            )))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let scope = payments_scope();
        let name = SecretName::new("STRIPE_API_KEY").unwrap();
        let created = client
            .create_secret(&scope, &name, SecretValue::new("create-input-canary"))
            .await
            .unwrap();
        let updated = client
            .update_secret(&scope, &name, SecretValue::new("update-input-canary"))
            .await
            .unwrap();
        let deleted = client.delete_secret(&scope, &name, true).await.unwrap();
        let serialized = serde_json::to_string(&[created, updated, deleted]).unwrap();

        assert!(serialized.contains("\"version\":1"));
        assert!(serialized.contains("\"version\":2"));
        for canary in [
            "create-input-canary",
            "create-response-canary",
            "update-input-canary",
            "update-response-canary",
            "delete-response-canary",
            "secretValue",
        ] {
            assert!(!serialized.contains(canary), "receipt leaked {canary}");
        }
    }

    #[tokio::test]
    async fn protected_create_returns_a_value_free_approval_receipt() {
        let server = MockServer::start().await;
        mount_login(&server, "approval-token").await;
        Mock::given(method("POST"))
            .and(path("/api/v4/secrets/APPROVAL_SECRET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "approval": {
                    "id": "11111111-1111-4111-8111-111111111111",
                    "policyId": "22222222-2222-4222-8222-222222222222",
                    "hasMerged": false,
                    "status": "open",
                    "slug": "approval-42",
                    "folderId": "33333333-3333-4333-8333-333333333333",
                    "createdAt": "2026-07-19T12:00:00.000Z",
                    "updatedAt": "2026-07-19T12:00:00.000Z"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let receipt = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_secret(
                &payments_scope(),
                &SecretName::new("APPROVAL_SECRET").unwrap(),
                SecretValue::new("approval-input-canary"),
            )
            .await
            .unwrap();
        let serialized = serde_json::to_string(&receipt).unwrap();

        assert_eq!(
            serialized,
            r#"{"status":"approvalRequired","approval":{"id":"11111111-1111-4111-8111-111111111111","slug":"approval-42","status":"open"}}"#
        );
        assert!(!serialized.contains("approval-input-canary"));
    }

    #[tokio::test]
    async fn delete_requires_confirmation_before_authentication_or_mutation() {
        let server = MockServer::start().await;
        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .delete_secret(
                &payments_scope(),
                &SecretName::new("STRIPE_API_KEY").unwrap(),
                false,
            )
            .await
            .unwrap_err();

        assert_eq!(error, crate::ResourceError::DeletionNotConfirmed);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    async fn mount_batch_create(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v4/secrets/batch"))
            .and(header("authorization", "Bearer batch-token"))
            .and(body_json(json!({
                "projectId": "project-1",
                "environment": "prod",
                "secretPath": "/payments",
                "secrets": [
                    { "secretKey": "STRIPE_API_KEY", "secretValue": "create-one" },
                    { "secretKey": "STRIPE_WEBHOOK_SECRET", "secretValue": "create-two" }
                ]
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(batch_mutation_response(
                    &[
                        ("STRIPE_API_KEY", "create-response-one"),
                        ("STRIPE_WEBHOOK_SECRET", "create-response-two"),
                    ],
                    1,
                )),
            )
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_batch_update(server: &MockServer) {
        Mock::given(method("PATCH"))
            .and(path("/api/v4/secrets/batch"))
            .and(header("authorization", "Bearer batch-token"))
            .and(body_json(json!({
                "projectId": "project-1",
                "environment": "prod",
                "secretPath": "/payments",
                "mode": "failOnNotFound",
                "secrets": [
                    { "secretKey": "STRIPE_API_KEY", "secretValue": "update-one" },
                    { "secretKey": "STRIPE_WEBHOOK_SECRET", "secretValue": "update-two" }
                ]
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(batch_mutation_response(
                    &[
                        ("STRIPE_API_KEY", "update-response-one"),
                        ("STRIPE_WEBHOOK_SECRET", "update-response-two"),
                    ],
                    2,
                )),
            )
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_batch_delete(server: &MockServer) {
        Mock::given(method("DELETE"))
            .and(path("/api/v4/secrets/batch"))
            .and(header("authorization", "Bearer batch-token"))
            .and(body_json(json!({
                "projectId": "project-1",
                "environment": "prod",
                "secretPath": "/payments",
                "secrets": [
                    { "secretKey": "STRIPE_API_KEY", "type": "shared" },
                    { "secretKey": "STRIPE_WEBHOOK_SECRET", "type": "shared" }
                ]
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(batch_mutation_response(
                    &[
                        ("STRIPE_API_KEY", "delete-response-one"),
                        ("STRIPE_WEBHOOK_SECRET", "delete-response-two"),
                    ],
                    2,
                )),
            )
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn batch_mutations_send_exact_bounded_bodies_and_drop_all_values() {
        let server = MockServer::start().await;
        mount_login(&server, "batch-token").await;
        mount_batch_create(&server).await;
        mount_batch_update(&server).await;
        mount_batch_delete(&server).await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let created = client
            .create_secrets_batch(&payments_scope(), batch_values("create-one", "create-two"))
            .await
            .unwrap();
        let updated = client
            .update_secrets_batch(&payments_scope(), batch_values("update-one", "update-two"))
            .await
            .unwrap();
        let deleted = client
            .delete_secrets_batch(
                &payments_scope(),
                vec![
                    SecretName::new("STRIPE_API_KEY").unwrap(),
                    SecretName::new("STRIPE_WEBHOOK_SECRET").unwrap(),
                ],
                true,
            )
            .await
            .unwrap();
        let serialized = serde_json::to_string(&[created, updated, deleted]).unwrap();

        assert!(serialized.contains("STRIPE_API_KEY"));
        for canary in [
            "create-one",
            "create-two",
            "create-response-one",
            "create-response-two",
            "update-one",
            "update-two",
            "update-response-one",
            "update-response-two",
            "delete-response-one",
            "delete-response-two",
            "secretValue",
        ] {
            assert!(!serialized.contains(canary), "receipt leaked {canary}");
        }
    }

    #[tokio::test]
    async fn protected_batch_returns_one_value_free_approval_receipt() {
        let server = MockServer::start().await;
        mount_login(&server, "batch-approval-token").await;
        Mock::given(method("POST"))
            .and(path("/api/v4/secrets/batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "approval": {
                    "id": "11111111-1111-4111-8111-111111111111",
                    "slug": "approval-43",
                    "status": "open"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let receipt = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_secrets_batch(
                &payments_scope(),
                vec![SecretValueMutation::new(
                    SecretName::new("APPROVAL_SECRET").unwrap(),
                    SecretValue::new("batch-approval-canary"),
                )],
            )
            .await
            .unwrap();
        let serialized = serde_json::to_string(&receipt).unwrap();

        assert_eq!(
            serialized,
            r#"{"status":"approvalRequired","approval":{"id":"11111111-1111-4111-8111-111111111111","slug":"approval-43","status":"open"}}"#
        );
        assert!(!serialized.contains("batch-approval-canary"));
    }

    #[tokio::test]
    async fn invalid_batch_inputs_fail_before_authentication_or_mutation() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let scope = payments_scope();

        assert_eq!(
            client
                .create_secrets_batch(&scope, Vec::new())
                .await
                .unwrap_err(),
            crate::ResourceError::InvalidSecretBatchSize
        );
        let oversized_names = (0..=crate::MAX_SECRET_BATCH_SIZE)
            .map(|index| SecretName::new(format!("SECRET_{index}")).unwrap())
            .collect();
        assert_eq!(
            client
                .delete_secrets_batch(&scope, oversized_names, true)
                .await
                .unwrap_err(),
            crate::ResourceError::InvalidSecretBatchSize
        );
        assert_eq!(
            client
                .update_secrets_batch(
                    &scope,
                    batch_values("duplicate-one", "duplicate-two")
                        .into_iter()
                        .map(|secret| {
                            SecretValueMutation::new(
                                SecretName::new("DUPLICATE").unwrap(),
                                secret.value,
                            )
                        })
                        .collect(),
                )
                .await
                .unwrap_err(),
            crate::ResourceError::DuplicateSecretName
        );
        assert_eq!(
            client
                .delete_secrets_batch(
                    &scope,
                    vec![SecretName::new("STRIPE_API_KEY").unwrap()],
                    false,
                )
                .await
                .unwrap_err(),
            crate::ResourceError::DeletionNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
