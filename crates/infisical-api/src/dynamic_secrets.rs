use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::IgnoredAny};
use thiserror::Error;

use crate::{
    EnvironmentSlug, InfisicalClient, MutationOperation, ObservableReadOperation, Page,
    PageRequest, ProjectSlug, ResourceError, SecretPath,
    client::{ApiVersion, Endpoint, sealed},
    resources::{is_bounded_text, is_uuid, paginate, utc_timestamp_millis},
};

const MAX_DYNAMIC_SECRET_NAME_BYTES: usize = 64;
const MAX_DYNAMIC_TTL_SECONDS: u32 = 315_360_000;
const MAX_DYNAMIC_TTL_TEXT_BYTES: usize = 64;
const MIN_DYNAMIC_TTL_MILLIS: f64 = 60_000.0;
const MAX_DYNAMIC_TTL_MILLIS: f64 = 315_576_000_000.0;
const MAX_EXTERNAL_ENTITY_BYTES: usize = 1_024;
const MAX_USERNAME_TEMPLATE_BYTES: usize = 255;

/// Validation failures for dynamic-secret coordinates and lease lifetimes.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DynamicSecretInputError {
    /// A dynamic-secret name was not a canonical slug.
    #[error(
        "dynamic-secret names must contain 1 to 64 lowercase letters or numbers separated by single hyphens"
    )]
    InvalidName,
    /// A lease identifier was not a UUID.
    #[error("dynamic-secret lease IDs must be UUIDs")]
    InvalidLeaseId,
    /// A lease lifetime fell outside Infisical's supported range.
    #[error("dynamic-secret lease TTL must be between 60 and 315360000 seconds")]
    InvalidTtl,
    /// A maximum lifetime was shorter than the default lifetime.
    #[error("dynamic-secret maximum TTL must be greater than or equal to the default TTL")]
    InvalidTtlOrder,
}

/// Canonical dynamic-secret name used by the pinned route family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct DynamicSecretName(String);

impl DynamicSecretName {
    /// Validate a lowercase dynamic-secret slug.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, padded, or non-canonical text.
    pub fn new(value: impl Into<String>) -> Result<Self, DynamicSecretInputError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_DYNAMIC_SECRET_NAME_BYTES
            || !value.split('-').all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
        {
            return Err(DynamicSecretInputError::InvalidName);
        }
        Ok(Self(value))
    }

    /// Borrow the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque UUID identifying one dynamic-secret lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct DynamicSecretLeaseId(String);

impl DynamicSecretLeaseId {
    /// Validate one lease UUID.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value has canonical UUID shape.
    pub fn new(value: impl Into<String>) -> Result<Self, DynamicSecretInputError> {
        let value = value.into();
        if !is_uuid(&value) {
            return Err(DynamicSecretInputError::InvalidLeaseId);
        }
        Ok(Self(value))
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Explicit lease lifetime represented in whole seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct DynamicSecretTtlSeconds(#[schemars(range(min = 60, max = 315_360_000))] u32);

impl DynamicSecretTtlSeconds {
    /// Validate a lease lifetime inside the pinned route's safe range.
    ///
    /// # Errors
    ///
    /// Returns an error for values below one minute or above ten years.
    pub fn new(seconds: u32) -> Result<Self, DynamicSecretInputError> {
        if !(60..=MAX_DYNAMIC_TTL_SECONDS).contains(&seconds) {
            return Err(DynamicSecretInputError::InvalidTtl);
        }
        Ok(Self(seconds))
    }

    /// Return the validated whole-second duration.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }

    pub(crate) fn wire(self) -> String {
        format!("{}s", self.0)
    }
}

/// One provider-neutral dynamic-secret configuration change.
///
/// Changes are opaque so every lifetime policy passes through [`Self::lifetime`].
/// Direct construction of an unchecked policy is intentionally impossible:
///
/// ```compile_fail
/// # use infisical_api::{DynamicSecretChange, DynamicSecretTtlSeconds};
/// let default_ttl = DynamicSecretTtlSeconds::new(7_200).unwrap();
/// let max_ttl = Some(DynamicSecretTtlSeconds::new(3_600).unwrap());
/// let change = DynamicSecretChange::Lifetime { default_ttl, max_ttl };
/// ```
#[derive(Debug)]
pub struct DynamicSecretChange(DynamicSecretChangeKind);

#[derive(Debug)]
enum DynamicSecretChangeKind {
    /// Rename the configuration within its existing project, environment, and path.
    Rename(DynamicSecretName),
    /// Replace the complete default and optional maximum lifetime policy.
    Lifetime {
        /// Default lifetime used when a lease request omits its TTL.
        default_ttl: DynamicSecretTtlSeconds,
        /// Maximum caller-selectable lifetime, or no explicit maximum.
        max_ttl: Option<DynamicSecretTtlSeconds>,
    },
}

impl DynamicSecretChange {
    /// Construct a canonical rename.
    #[must_use]
    pub fn rename(new_name: DynamicSecretName) -> Self {
        Self(DynamicSecretChangeKind::Rename(new_name))
    }

    /// Construct a coherent complete lifetime replacement.
    ///
    /// # Errors
    ///
    /// Returns an error when the optional maximum is shorter than the default.
    pub fn lifetime(
        default_ttl: DynamicSecretTtlSeconds,
        max_ttl: Option<DynamicSecretTtlSeconds>,
    ) -> Result<Self, DynamicSecretInputError> {
        if max_ttl.is_some_and(|maximum| maximum.get() < default_ttl.get()) {
            return Err(DynamicSecretInputError::InvalidTtlOrder);
        }
        Ok(Self(DynamicSecretChangeKind::Lifetime {
            default_ttl,
            max_ttl,
        }))
    }
}

/// Exact project, environment, and secret-tree scope for dynamic secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicSecretScope {
    project: ProjectSlug,
    environment: EnvironmentSlug,
    path: SecretPath,
}

impl DynamicSecretScope {
    /// Construct a fully validated dynamic-secret scope.
    #[must_use]
    pub fn new(project: ProjectSlug, environment: EnvironmentSlug, path: SecretPath) -> Self {
        Self {
            project,
            environment,
            path,
        }
    }

    /// Project slug used by the pinned dynamic-secret routes.
    #[must_use]
    pub fn project(&self) -> &ProjectSlug {
        &self.project
    }

    /// Environment slug used by the pinned dynamic-secret routes.
    #[must_use]
    pub fn environment(&self) -> &EnvironmentSlug {
        &self.environment
    }

    /// Absolute secret-tree path used by the pinned dynamic-secret routes.
    #[must_use]
    pub fn path(&self) -> &SecretPath {
        &self.path
    }
}

/// Provider families defined by Infisical v0.160.12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DynamicSecretProvider {
    #[serde(rename = "sql-database")]
    SqlDatabase,
    #[serde(rename = "clickhouse")]
    Clickhouse,
    #[serde(rename = "cassandra")]
    Cassandra,
    #[serde(rename = "aws-iam")]
    AwsIam,
    #[serde(rename = "redis")]
    Redis,
    #[serde(rename = "aws-elasticache")]
    AwsElastiCache,
    #[serde(rename = "aws-memorydb")]
    AwsMemoryDb,
    #[serde(rename = "mongo-db-atlas")]
    MongoDbAtlas,
    #[serde(rename = "elastic-search")]
    ElasticSearch,
    #[serde(rename = "mongo-db")]
    MongoDb,
    #[serde(rename = "rabbit-mq")]
    RabbitMq,
    #[serde(rename = "azure-entra-id")]
    AzureEntraId,
    #[serde(rename = "azure-sql-database")]
    AzureSqlDatabase,
    #[serde(rename = "ldap")]
    Ldap,
    #[serde(rename = "sap-hana")]
    SapHana,
    #[serde(rename = "snowflake")]
    Snowflake,
    #[serde(rename = "totp")]
    Totp,
    #[serde(rename = "sap-ase")]
    SapAse,
    #[serde(rename = "kubernetes")]
    Kubernetes,
    #[serde(rename = "vertica")]
    Vertica,
    #[serde(rename = "gcp-iam")]
    GcpIam,
    #[serde(rename = "github")]
    Github,
    #[serde(rename = "couchbase")]
    Couchbase,
    #[serde(rename = "milvus")]
    Milvus,
    #[serde(rename = "ssh")]
    Ssh,
    #[serde(rename = "ibm-api-connect")]
    IbmApiConnect,
}

/// Background state reported for a dynamic-secret configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DynamicSecretStatus {
    #[serde(rename = "Revocation in process")]
    RevocationInProcess,
    #[serde(rename = "Failed to delete")]
    FailedToDelete,
}

/// Failure state reported for a dynamic-secret lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DynamicSecretLeaseStatus {
    #[serde(rename = "Failed to delete")]
    FailedToDelete,
}

/// Value-free metadata for one configured dynamic secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DynamicSecret {
    /// Opaque dynamic-secret UUID.
    pub id: String,
    /// Stable name under the exact scope.
    pub name: String,
    /// Pinned provider family.
    pub provider: DynamicSecretProvider,
    /// Upstream record version.
    pub version: u64,
    /// Upstream default TTL expression.
    #[serde(rename = "defaultTTL")]
    pub default_ttl: String,
    /// Optional upstream maximum TTL expression.
    #[serde(rename = "maxTTL")]
    pub max_ttl: Option<String>,
    /// Opaque owning-folder UUID.
    pub folder_id: String,
    /// Optional background operation status.
    pub status: Option<DynamicSecretStatus>,
    /// Infisical creation timestamp.
    pub created_at: String,
    /// Infisical update timestamp.
    pub updated_at: String,
    /// Legacy project-gateway UUID, when configured.
    pub project_gateway_id: Option<String>,
    /// Legacy gateway UUID, when configured.
    pub gateway_id: Option<String>,
    /// Current gateway UUID, when configured.
    pub gateway_v2_id: Option<String>,
    /// Gateway-pool UUID, when configured.
    pub gateway_pool_id: Option<String>,
    /// Bounded username template, when configured.
    pub username_template: Option<String>,
}

/// Value-free metadata for one issued dynamic-secret lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DynamicSecretLease {
    /// Opaque lease UUID.
    pub id: String,
    /// Upstream record version.
    pub version: u64,
    /// Provider-side principal or resource identifier.
    pub external_entity_id: String,
    /// Canonical lease expiration timestamp.
    pub expires_at: String,
    /// Optional failed-revocation state.
    pub status: Option<DynamicSecretLeaseStatus>,
    /// Owning dynamic-secret UUID.
    pub dynamic_secret_id: String,
    /// Infisical creation timestamp.
    pub created_at: String,
    /// Infisical update timestamp.
    pub updated_at: String,
}

/// Exact lease details with its value-free dynamic-secret owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DynamicSecretLeaseDetails {
    /// Lease metadata.
    pub lease: DynamicSecretLease,
    /// Owning dynamic-secret configuration metadata.
    pub dynamic_secret: DynamicSecret,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DynamicSecretScopeWire {
    project_slug: String,
    path: String,
    environment_slug: String,
}

impl From<&DynamicSecretScope> for DynamicSecretScopeWire {
    fn from(scope: &DynamicSecretScope) -> Self {
        Self {
            project_slug: scope.project.as_str().to_owned(),
            path: scope.path.as_str().to_owned(),
            environment_slug: scope.environment.as_str().to_owned(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DynamicSecretTargetWire {
    #[serde(skip_serializing)]
    name: DynamicSecretName,
    #[serde(flatten)]
    scope: DynamicSecretScopeWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DynamicSecretLeaseTargetWire {
    #[serde(skip_serializing)]
    lease_id: DynamicSecretLeaseId,
    #[serde(flatten)]
    scope: DynamicSecretScopeWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DynamicSecretLeaseListWire {
    #[serde(skip_serializing)]
    name: DynamicSecretName,
    #[serde(flatten)]
    scope: DynamicSecretScopeWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RenewDynamicSecretLeaseWire {
    #[serde(skip_serializing)]
    lease_id: DynamicSecretLeaseId,
    #[serde(flatten)]
    scope: DynamicSecretScopeWire,
    ttl: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RevokeDynamicSecretLeaseWire {
    #[serde(skip_serializing)]
    lease_id: DynamicSecretLeaseId,
    #[serde(flatten)]
    scope: DynamicSecretScopeWire,
    is_forced: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateDynamicSecretWire {
    #[serde(skip_serializing)]
    name: DynamicSecretName,
    #[serde(flatten)]
    scope: DynamicSecretScopeWire,
    data: DynamicSecretChangeWire,
}

#[derive(Serialize)]
#[serde(untagged)]
enum DynamicSecretChangeWire {
    Rename {
        #[serde(rename = "newName")]
        new_name: String,
    },
    Lifetime {
        #[serde(rename = "defaultTTL")]
        default_ttl: String,
        #[serde(rename = "maxTTL")]
        max_ttl: Option<String>,
    },
}

impl DynamicSecretChangeWire {
    fn from_change(
        current_name: &DynamicSecretName,
        change: DynamicSecretChange,
    ) -> Result<Self, ResourceError> {
        match change.0 {
            DynamicSecretChangeKind::Rename(new_name) => {
                if new_name == *current_name {
                    return Err(ResourceError::DynamicSecretRenameWouldBeNoop);
                }
                Ok(Self::Rename {
                    new_name: new_name.as_str().to_owned(),
                })
            }
            DynamicSecretChangeKind::Lifetime {
                default_ttl,
                max_ttl,
            } => Ok(Self::Lifetime {
                default_ttl: default_ttl.wire(),
                max_ttl: max_ttl.map(DynamicSecretTtlSeconds::wire),
            }),
        }
    }

    fn expected_name<'a>(&'a self, current_name: &'a DynamicSecretName) -> &'a str {
        match self {
            Self::Rename { new_name } => new_name,
            Self::Lifetime { .. } => current_name.as_str(),
        }
    }

    fn response_matches(&self, resource: &DynamicSecret) -> bool {
        match self {
            Self::Rename { new_name } => resource.name == *new_name,
            Self::Lifetime {
                default_ttl,
                max_ttl,
            } => resource.default_ttl == *default_ttl && resource.max_ttl == *max_ttl,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteDynamicSecretWire {
    #[serde(skip_serializing)]
    name: DynamicSecretName,
    #[serde(flatten)]
    scope: DynamicSecretScopeWire,
    is_forced: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawDynamicSecret {
    id: String,
    name: String,
    version: u64,
    #[serde(rename = "type")]
    provider: DynamicSecretProvider,
    #[serde(rename = "defaultTTL")]
    default_ttl: String,
    #[serde(rename = "maxTTL")]
    max_ttl: Option<String>,
    folder_id: String,
    status: Option<DynamicSecretStatus>,
    #[serde(default)]
    _status_details: Option<IgnoredAny>,
    created_at: String,
    updated_at: String,
    project_gateway_id: Option<String>,
    gateway_id: Option<String>,
    gateway_v2_id: Option<String>,
    gateway_pool_id: Option<String>,
    username_template: Option<String>,
    #[serde(default)]
    _metadata: Option<IgnoredAny>,
    #[serde(default)]
    _inputs: Option<IgnoredAny>,
}

impl RawDynamicSecret {
    pub(crate) fn into_validated(self) -> Result<DynamicSecret, ResourceError> {
        let created = utc_timestamp_millis(&self.created_at)
            .ok_or(ResourceError::InvalidDynamicSecretResponse)?;
        let updated = utc_timestamp_millis(&self.updated_at)
            .ok_or(ResourceError::InvalidDynamicSecretResponse)?;
        if self.version == 0
            || !is_uuid(&self.id)
            || !is_uuid(&self.folder_id)
            || DynamicSecretName::new(&self.name).is_err()
            || !dynamic_secret_ttls_are_valid(&self.default_ttl, self.max_ttl.as_deref())
            || updated < created
            || optional_uuid_is_invalid(self.project_gateway_id.as_deref())
            || optional_uuid_is_invalid(self.gateway_id.as_deref())
            || optional_uuid_is_invalid(self.gateway_v2_id.as_deref())
            || optional_uuid_is_invalid(self.gateway_pool_id.as_deref())
            || self
                .username_template
                .as_deref()
                .is_some_and(|value| !is_bounded_text(value, MAX_USERNAME_TEMPLATE_BYTES))
        {
            return Err(ResourceError::InvalidDynamicSecretResponse);
        }
        Ok(DynamicSecret {
            id: self.id,
            name: self.name,
            provider: self.provider,
            version: self.version,
            default_ttl: self.default_ttl,
            max_ttl: self.max_ttl,
            folder_id: self.folder_id,
            status: self.status,
            created_at: self.created_at,
            updated_at: self.updated_at,
            project_gateway_id: self.project_gateway_id,
            gateway_id: self.gateway_id,
            gateway_v2_id: self.gateway_v2_id,
            gateway_pool_id: self.gateway_pool_id,
            username_template: self.username_template,
        })
    }
}

fn dynamic_secret_ttls_are_valid(default_ttl: &str, max_ttl: Option<&str>) -> bool {
    let Some(default_millis) = parse_dynamic_ttl_millis(default_ttl) else {
        return false;
    };
    if !(MIN_DYNAMIC_TTL_MILLIS..=MAX_DYNAMIC_TTL_MILLIS).contains(&default_millis) {
        return false;
    }
    max_ttl.is_none_or(|value| {
        parse_dynamic_ttl_millis(value).is_some_and(|max_millis| {
            (MIN_DYNAMIC_TTL_MILLIS..=MAX_DYNAMIC_TTL_MILLIS).contains(&max_millis)
                && max_millis >= default_millis
        })
    })
}

fn parse_dynamic_ttl_millis(value: &str) -> Option<f64> {
    if value.len() > MAX_DYNAMIC_TTL_TEXT_BYTES {
        return None;
    }
    let number_end = value
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(value.len());
    let number_text = &value[..number_end];
    let number_shape_is_valid = match number_text.split_once('.') {
        None => !number_text.is_empty(),
        Some((_, fraction)) => !fraction.is_empty() && !fraction.contains('.'),
    };
    if !number_shape_is_valid {
        return None;
    }
    let unit_text = &value[number_end..];
    if !unit_text
        .bytes()
        .all(|byte| byte == b' ' || byte.is_ascii_alphabetic())
    {
        return None;
    }
    let factor = match unit_text.trim_matches(' ').to_ascii_lowercase().as_str() {
        "" | "ms" | "msec" | "msecs" | "millisecond" | "milliseconds" => 1.0,
        "s" | "sec" | "secs" | "second" | "seconds" => 1_000.0,
        "m" | "min" | "mins" | "minute" | "minutes" => 60_000.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600_000.0,
        "d" | "day" | "days" => 86_400_000.0,
        "w" | "week" | "weeks" => 604_800_000.0,
        "y" | "yr" | "yrs" | "year" | "years" => 31_557_600_000.0,
        _ => return None,
    };
    let millis = number_text.parse::<f64>().ok()? * factor;
    Some(millis)
}

fn optional_uuid_is_invalid(value: Option<&str>) -> bool {
    value.is_some_and(|value| !is_uuid(value))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawDynamicSecretLease {
    id: String,
    version: u64,
    external_entity_id: String,
    expire_at: String,
    status: Option<DynamicSecretLeaseStatus>,
    #[serde(default)]
    _status_details: Option<IgnoredAny>,
    dynamic_secret_id: String,
    created_at: String,
    updated_at: String,
    #[serde(default)]
    _config: Option<IgnoredAny>,
}

impl RawDynamicSecretLease {
    pub(crate) fn into_validated(
        self,
        expected_id: Option<&DynamicSecretLeaseId>,
    ) -> Result<DynamicSecretLease, ResourceError> {
        let created = utc_timestamp_millis(&self.created_at)
            .ok_or(ResourceError::InvalidDynamicSecretLeaseResponse)?;
        let updated = utc_timestamp_millis(&self.updated_at)
            .ok_or(ResourceError::InvalidDynamicSecretLeaseResponse)?;
        let expires = utc_timestamp_millis(&self.expire_at)
            .ok_or(ResourceError::InvalidDynamicSecretLeaseResponse)?;
        if self.version == 0
            || !is_uuid(&self.id)
            || expected_id.is_some_and(|expected| self.id != expected.as_str())
            || !is_uuid(&self.dynamic_secret_id)
            || !is_bounded_text(&self.external_entity_id, MAX_EXTERNAL_ENTITY_BYTES)
            || updated < created
            || expires < created
        {
            return Err(ResourceError::InvalidDynamicSecretLeaseResponse);
        }
        Ok(DynamicSecretLease {
            id: self.id,
            version: self.version,
            external_entity_id: self.external_entity_id,
            expires_at: self.expire_at,
            status: self.status,
            dynamic_secret_id: self.dynamic_secret_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListDynamicSecretsResponse {
    dynamic_secrets: Vec<RawDynamicSecret>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynamicSecretResponse {
    dynamic_secret: RawDynamicSecret,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListDynamicSecretLeasesResponse {
    leases: Vec<RawDynamicSecretLease>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynamicSecretLeaseResponse {
    lease: RawDynamicSecretLease,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDynamicSecretLeaseDetails {
    #[serde(flatten)]
    lease: RawDynamicSecretLease,
    dynamic_secret: RawDynamicSecret,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynamicSecretLeaseDetailsResponse {
    lease: RawDynamicSecretLeaseDetails,
}

struct ListDynamicSecrets;
impl sealed::Sealed for ListDynamicSecrets {}
impl ObservableReadOperation for ListDynamicSecrets {
    type Query = DynamicSecretScopeWire;
    type Output = ListDynamicSecretsResponse;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "dynamic-secrets")
    }
}

struct GetDynamicSecret;
impl sealed::Sealed for GetDynamicSecret {}
impl ObservableReadOperation for GetDynamicSecret {
    type Query = DynamicSecretTargetWire;
    type Output = DynamicSecretResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["dynamic-secrets", query.name.as_str()])
    }
}

struct ListDynamicSecretLeases;
impl sealed::Sealed for ListDynamicSecretLeases {}
impl ObservableReadOperation for ListDynamicSecretLeases {
    type Query = DynamicSecretLeaseListWire;
    type Output = ListDynamicSecretLeasesResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["dynamic-secrets", query.name.as_str(), "leases"],
        )
    }
}

struct GetDynamicSecretLease;
impl sealed::Sealed for GetDynamicSecretLease {}
impl ObservableReadOperation for GetDynamicSecretLease {
    type Query = DynamicSecretLeaseTargetWire;
    type Output = DynamicSecretLeaseDetailsResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["dynamic-secrets", "leases", query.lease_id.as_str()],
        )
    }
}

struct RenewDynamicSecretLease;
impl sealed::Sealed for RenewDynamicSecretLease {}
impl MutationOperation for RenewDynamicSecretLease {
    type Input = RenewDynamicSecretLeaseWire;
    type Output = DynamicSecretLeaseResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "dynamic-secrets",
                "leases",
                input.lease_id.as_str(),
                "renew",
            ],
        )
    }
}

struct RevokeDynamicSecretLease;
impl sealed::Sealed for RevokeDynamicSecretLease {}
impl MutationOperation for RevokeDynamicSecretLease {
    type Input = RevokeDynamicSecretLeaseWire;
    type Output = DynamicSecretLeaseResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["dynamic-secrets", "leases", input.lease_id.as_str()],
        )
    }
}

struct UpdateDynamicSecret;
impl sealed::Sealed for UpdateDynamicSecret {}
impl MutationOperation for UpdateDynamicSecret {
    type Input = UpdateDynamicSecretWire;
    type Output = DynamicSecretResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["dynamic-secrets", input.name.as_str()])
    }
}

struct DeleteDynamicSecret;
impl sealed::Sealed for DeleteDynamicSecret {}
impl MutationOperation for DeleteDynamicSecret {
    type Input = DeleteDynamicSecretWire;
    type Output = DynamicSecretResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["dynamic-secrets", input.name.as_str()])
    }
}

impl InfisicalClient {
    /// List one locally bounded page of value-free dynamic-secret configurations.
    ///
    /// Infisical records this discovery in its audit log, so the GET is sent
    /// exactly once and is never replayed after authentication rejection.
    ///
    /// # Errors
    ///
    /// Returns a typed client, response-contract, or pagination error.
    pub async fn list_dynamic_secrets(
        &self,
        scope: &DynamicSecretScope,
        page: PageRequest,
    ) -> Result<Page<DynamicSecret>, ResourceError> {
        let response = self
            .execute_observable_read::<ListDynamicSecrets>(&scope.into())
            .await?;
        let records = response
            .dynamic_secrets
            .into_iter()
            .map(RawDynamicSecret::into_validated)
            .collect::<Result<Vec<_>, _>>()?;
        paginate(page, records)
    }

    /// Get one value-free dynamic-secret configuration by exact scoped name.
    ///
    /// # Errors
    ///
    /// Returns a typed client or response-contract error.
    pub async fn get_dynamic_secret(
        &self,
        scope: &DynamicSecretScope,
        name: &DynamicSecretName,
    ) -> Result<DynamicSecret, ResourceError> {
        let response = self
            .execute_observable_read::<GetDynamicSecret>(&DynamicSecretTargetWire {
                name: name.clone(),
                scope: scope.into(),
            })
            .await?;
        let resource = response.dynamic_secret.into_validated()?;
        if resource.name != name.as_str() {
            return Err(ResourceError::InvalidDynamicSecretResponse);
        }
        Ok(resource)
    }

    /// Apply one provider-neutral configuration change by exact scoped name.
    ///
    /// Infisical validates the stored provider connection during this update,
    /// so callers should expect an external provider probe even when only the
    /// name or lifetime policy changes.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, client, or response-contract error. The
    /// mutation is sent once and is never automatically replayed.
    pub async fn update_dynamic_secret(
        &self,
        scope: &DynamicSecretScope,
        name: &DynamicSecretName,
        change: DynamicSecretChange,
    ) -> Result<DynamicSecret, ResourceError> {
        let data = DynamicSecretChangeWire::from_change(name, change)?;
        let expected_name = data.expected_name(name).to_owned();
        let input = UpdateDynamicSecretWire {
            name: name.clone(),
            scope: scope.into(),
            data,
        };
        let response = self.execute_mutation::<UpdateDynamicSecret>(&input).await?;
        let resource = response.dynamic_secret.into_validated()?;
        if resource.name != expected_name || !input.data.response_matches(&resource) {
            return Err(ResourceError::InvalidDynamicSecretResponse);
        }
        Ok(resource)
    }

    /// Delete one scoped dynamic-secret configuration after explicit confirmation.
    ///
    /// Ordinary deletion revokes existing leases before removal. Forced deletion
    /// removes Infisical tracking without requiring provider cleanup.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, typed client, or response-contract error. The
    /// mutation is sent once and is never automatically replayed.
    pub async fn delete_dynamic_secret(
        &self,
        scope: &DynamicSecretScope,
        name: &DynamicSecretName,
        force: bool,
        confirm: bool,
    ) -> Result<DynamicSecret, ResourceError> {
        if !confirm {
            return Err(ResourceError::DynamicSecretDeletionNotConfirmed);
        }
        let response = self
            .execute_mutation::<DeleteDynamicSecret>(&DeleteDynamicSecretWire {
                name: name.clone(),
                scope: scope.into(),
                is_forced: force,
            })
            .await?;
        let resource = response.dynamic_secret.into_validated()?;
        if resource.name != name.as_str() {
            return Err(ResourceError::InvalidDynamicSecretResponse);
        }
        Ok(resource)
    }

    /// List one locally bounded page of value-free leases for a scoped configuration.
    ///
    /// # Errors
    ///
    /// Returns a typed client, response-contract, or pagination error.
    pub async fn list_dynamic_secret_leases(
        &self,
        scope: &DynamicSecretScope,
        name: &DynamicSecretName,
        page: PageRequest,
    ) -> Result<Page<DynamicSecretLease>, ResourceError> {
        let response = self
            .execute_observable_read::<ListDynamicSecretLeases>(&DynamicSecretLeaseListWire {
                name: name.clone(),
                scope: scope.into(),
            })
            .await?;
        let records = response
            .leases
            .into_iter()
            .map(|lease| lease.into_validated(None))
            .collect::<Result<Vec<_>, _>>()?;
        paginate(page, records)
    }

    /// Get one value-free lease and its owning configuration metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed client or response-contract error.
    pub async fn get_dynamic_secret_lease(
        &self,
        scope: &DynamicSecretScope,
        lease_id: &DynamicSecretLeaseId,
    ) -> Result<DynamicSecretLeaseDetails, ResourceError> {
        let response = self
            .execute_observable_read::<GetDynamicSecretLease>(&DynamicSecretLeaseTargetWire {
                lease_id: lease_id.clone(),
                scope: scope.into(),
            })
            .await?;
        let lease = response.lease.lease.into_validated(Some(lease_id))?;
        let dynamic_secret = response.lease.dynamic_secret.into_validated()?;
        if lease.dynamic_secret_id != dynamic_secret.id {
            return Err(ResourceError::InvalidDynamicSecretLeaseResponse);
        }
        Ok(DynamicSecretLeaseDetails {
            lease,
            dynamic_secret,
        })
    }

    /// Renew one exact lease for an explicit whole-second lifetime.
    ///
    /// # Errors
    ///
    /// Returns a typed client or response-contract error. The mutation is sent once.
    pub async fn renew_dynamic_secret_lease(
        &self,
        scope: &DynamicSecretScope,
        lease_id: &DynamicSecretLeaseId,
        ttl: DynamicSecretTtlSeconds,
    ) -> Result<DynamicSecretLease, ResourceError> {
        let response = self
            .execute_mutation::<RenewDynamicSecretLease>(&RenewDynamicSecretLeaseWire {
                lease_id: lease_id.clone(),
                scope: scope.into(),
                ttl: ttl.wire(),
            })
            .await?;
        response.lease.into_validated(Some(lease_id))
    }

    /// Revoke one exact lease after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, typed client, or response-contract error. The
    /// mutation is sent once.
    pub async fn revoke_dynamic_secret_lease(
        &self,
        scope: &DynamicSecretScope,
        lease_id: &DynamicSecretLeaseId,
        force: bool,
        confirm: bool,
    ) -> Result<DynamicSecretLease, ResourceError> {
        if !confirm {
            return Err(ResourceError::DynamicSecretLeaseRevocationNotConfirmed);
        }
        let response = self
            .execute_mutation::<RevokeDynamicSecretLease>(&RevokeDynamicSecretLeaseWire {
                lease_id: lease_id.clone(),
                scope: scope.into(),
                is_forced: force,
            })
            .await?;
        response.lease.into_validated(Some(lease_id))
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
        DynamicSecretChange, DynamicSecretInputError, DynamicSecretLeaseId, DynamicSecretName,
        DynamicSecretScope, DynamicSecretTtlSeconds, EnvironmentSlug, InfisicalClient, PageRequest,
        ProjectSlug, ResourceError, SecretPath,
        test_support::{mount_login, settings},
    };

    const CONFIG_ID: &str = "0b30c3c2-6a13-485f-9775-9768d8d2708a";
    const FOLDER_ID: &str = "573a2b87-7f44-4fb4-81ca-851679a7419f";
    const LEASE_ID: &str = "4d40b103-d45a-44ca-a95f-57d7361a4d2a";

    fn scope() -> DynamicSecretScope {
        DynamicSecretScope::new(
            ProjectSlug::new("platform").unwrap(),
            EnvironmentSlug::new("prod").unwrap(),
            SecretPath::new("/database").unwrap(),
        )
    }

    fn dynamic_secret_fixture(name: &str) -> Value {
        json!({
            "id": CONFIG_ID,
            "name": name,
            "version": 1,
            "type": "sql-database",
            "defaultTTL": "3600s",
            "maxTTL": "86400s",
            "folderId": FOLDER_ID,
            "status": null,
            "statusDetails": "must-not-escape",
            "createdAt": "2026-07-20T12:00:00.000Z",
            "updatedAt": "2026-07-20T12:05:00.000Z",
            "projectGatewayId": null,
            "gatewayId": null,
            "gatewayV2Id": null,
            "gatewayPoolId": null,
            "usernameTemplate": "svc-{{randomUsername}}",
            "metadata": { "secretValue": "must-not-escape" },
            "inputs": { "password": "must-not-escape" }
        })
    }

    fn lease_fixture(id: &str) -> Value {
        json!({
            "id": id,
            "version": 1,
            "externalEntityId": "svc-lease-user",
            "expireAt": "2026-07-20T14:00:00.000Z",
            "status": null,
            "statusDetails": "must-not-escape",
            "dynamicSecretId": CONFIG_ID,
            "createdAt": "2026-07-20T12:00:00.000Z",
            "updatedAt": "2026-07-20T12:05:00.000Z",
            "config": { "secretValue": "must-not-escape" }
        })
    }

    #[test]
    fn coordinates_and_ttl_enforce_every_boundary() {
        assert!(DynamicSecretName::new("database-user").is_ok());
        assert_eq!(
            DynamicSecretName::new("Database User").unwrap_err(),
            DynamicSecretInputError::InvalidName
        );
        assert_eq!(
            DynamicSecretLeaseId::new("lease/escape").unwrap_err(),
            DynamicSecretInputError::InvalidLeaseId
        );
        assert_eq!(
            DynamicSecretTtlSeconds::new(59).unwrap_err(),
            DynamicSecretInputError::InvalidTtl
        );
        assert!(DynamicSecretTtlSeconds::new(60).is_ok());
        assert!(DynamicSecretTtlSeconds::new(315_360_000).is_ok());
        assert_eq!(
            DynamicSecretTtlSeconds::new(315_360_001).unwrap_err(),
            DynamicSecretInputError::InvalidTtl
        );
        assert_eq!(DynamicSecretTtlSeconds::new(60).unwrap().get(), 60);
        assert_eq!(
            DynamicSecretTtlSeconds::new(315_360_000).unwrap().get(),
            315_360_000
        );
        assert_eq!(
            DynamicSecretChange::lifetime(
                DynamicSecretTtlSeconds::new(7_200).unwrap(),
                Some(DynamicSecretTtlSeconds::new(3_600).unwrap()),
            )
            .unwrap_err(),
            DynamicSecretInputError::InvalidTtlOrder
        );
        assert!(
            DynamicSecretChange::lifetime(
                DynamicSecretTtlSeconds::new(7_200).unwrap(),
                Some(DynamicSecretTtlSeconds::new(7_200).unwrap()),
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn configuration_reads_use_exact_observable_routes_and_drop_sensitive_maps() {
        let server = MockServer::start().await;
        mount_login(&server, "dynamic-token").await;
        for (route, body) in [
            (
                "/api/v1/dynamic-secrets",
                json!({
                    "dynamicSecrets": [
                        dynamic_secret_fixture("database-user"),
                        dynamic_secret_fixture("database-reader")
                    ]
                }),
            ),
            (
                "/api/v1/dynamic-secrets/database-user",
                json!({ "dynamicSecret": dynamic_secret_fixture("database-user") }),
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(route))
                .and(header("authorization", "Bearer dynamic-token"))
                .and(query_param("projectSlug", "platform"))
                .and(query_param("environmentSlug", "prod"))
                .and(query_param("path", "/database"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
        }

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let page = client
            .list_dynamic_secrets(&scope(), PageRequest::new(0, 1).unwrap())
            .await
            .unwrap();
        let exact = client
            .get_dynamic_secret(&scope(), &DynamicSecretName::new("database-user").unwrap())
            .await
            .unwrap();

        assert_eq!(page.items, vec![exact.clone()]);
        assert!(page.next.is_some());
        let serialized = serde_json::to_string(&exact).unwrap();
        assert!(!serialized.contains("statusDetails"));
        assert!(!serialized.contains("metadata"));
        assert!(!serialized.contains("inputs"));
        assert!(!serialized.contains("must-not-escape"));
    }

    #[tokio::test]
    async fn configuration_mutations_use_exact_typed_bodies_and_validate_results() {
        let server = MockServer::start().await;
        mount_login(&server, "dynamic-token").await;

        Mock::given(method("PATCH"))
            .and(path("/api/v1/dynamic-secrets/database-user"))
            .and(header("authorization", "Bearer dynamic-token"))
            .and(body_json(json!({
                "projectSlug": "platform",
                "environmentSlug": "prod",
                "path": "/database",
                "data": { "newName": "database-writer" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dynamicSecret": dynamic_secret_fixture("database-writer")
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut lifetime_response = dynamic_secret_fixture("database-writer");
        lifetime_response["defaultTTL"] = json!("7200s");
        lifetime_response["maxTTL"] = json!("86400s");
        Mock::given(method("PATCH"))
            .and(path("/api/v1/dynamic-secrets/database-writer"))
            .and(header("authorization", "Bearer dynamic-token"))
            .and(body_json(json!({
                "projectSlug": "platform",
                "environmentSlug": "prod",
                "path": "/database",
                "data": {
                    "defaultTTL": "7200s",
                    "maxTTL": "86400s"
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dynamicSecret": lifetime_response
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("DELETE"))
            .and(path("/api/v1/dynamic-secrets/database-writer"))
            .and(header("authorization", "Bearer dynamic-token"))
            .and(body_json(json!({
                "projectSlug": "platform",
                "environmentSlug": "prod",
                "path": "/database",
                "isForced": true
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dynamicSecret": dynamic_secret_fixture("database-writer")
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let original = DynamicSecretName::new("database-user").unwrap();
        let renamed = client
            .update_dynamic_secret(
                &scope(),
                &original,
                DynamicSecretChange::rename(DynamicSecretName::new("database-writer").unwrap()),
            )
            .await
            .unwrap();
        let renamed_name = DynamicSecretName::new(renamed.name.clone()).unwrap();
        let lifetime = client
            .update_dynamic_secret(
                &scope(),
                &renamed_name,
                DynamicSecretChange::lifetime(
                    DynamicSecretTtlSeconds::new(7_200).unwrap(),
                    Some(DynamicSecretTtlSeconds::new(86_400).unwrap()),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let deleted = client
            .delete_dynamic_secret(&scope(), &renamed_name, true, true)
            .await
            .unwrap();

        assert_eq!(renamed.name, "database-writer");
        assert_eq!(lifetime.default_ttl, "7200s");
        assert_eq!(lifetime.max_ttl.as_deref(), Some("86400s"));
        assert_eq!(deleted.name, "database-writer");
    }

    #[tokio::test]
    async fn configuration_mutation_preconditions_fail_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let name = DynamicSecretName::new("database-user").unwrap();

        assert_eq!(
            client
                .update_dynamic_secret(&scope(), &name, DynamicSecretChange::rename(name.clone()),)
                .await
                .unwrap_err(),
            ResourceError::DynamicSecretRenameWouldBeNoop
        );
        assert_eq!(
            client
                .delete_dynamic_secret(&scope(), &name, false, false)
                .await
                .unwrap_err(),
            ResourceError::DynamicSecretDeletionNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn lifetime_update_rejects_a_response_that_does_not_match_the_request() {
        let server = MockServer::start().await;
        mount_login(&server, "dynamic-token").await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/dynamic-secrets/database-user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dynamicSecret": dynamic_secret_fixture("database-user")
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert_eq!(
            client
                .update_dynamic_secret(
                    &scope(),
                    &DynamicSecretName::new("database-user").unwrap(),
                    DynamicSecretChange::lifetime(
                        DynamicSecretTtlSeconds::new(7_200).unwrap(),
                        Some(DynamicSecretTtlSeconds::new(86_400).unwrap()),
                    )
                    .unwrap(),
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidDynamicSecretResponse
        );
    }

    #[tokio::test]
    async fn lease_reads_and_mutations_use_exact_routes_and_value_free_outputs() {
        let server = MockServer::start().await;
        mount_login(&server, "dynamic-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/dynamic-secrets/database-user/leases"))
            .and(header("authorization", "Bearer dynamic-token"))
            .and(query_param("projectSlug", "platform"))
            .and(query_param("environmentSlug", "prod"))
            .and(query_param("path", "/database"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "leases": [lease_fixture(LEASE_ID)]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut details = lease_fixture(LEASE_ID);
        details["dynamicSecret"] = dynamic_secret_fixture("database-user");
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/dynamic-secrets/leases/{LEASE_ID}")))
            .and(header("authorization", "Bearer dynamic-token"))
            .and(query_param("projectSlug", "platform"))
            .and(query_param("environmentSlug", "prod"))
            .and(query_param("path", "/database"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "lease": details })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/dynamic-secrets/leases/{LEASE_ID}/renew"
            )))
            .and(header("authorization", "Bearer dynamic-token"))
            .and(body_json(json!({
                "projectSlug": "platform",
                "environmentSlug": "prod",
                "path": "/database",
                "ttl": "7200s"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease": lease_fixture(LEASE_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/dynamic-secrets/leases/{LEASE_ID}")))
            .and(header("authorization", "Bearer dynamic-token"))
            .and(body_json(json!({
                "projectSlug": "platform",
                "environmentSlug": "prod",
                "path": "/database",
                "isForced": false
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease": lease_fixture(LEASE_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let name = DynamicSecretName::new("database-user").unwrap();
        let lease_id = DynamicSecretLeaseId::new(LEASE_ID).unwrap();
        let leases = client
            .list_dynamic_secret_leases(&scope(), &name, PageRequest::new(0, 1).unwrap())
            .await
            .unwrap();
        let details = client
            .get_dynamic_secret_lease(&scope(), &lease_id)
            .await
            .unwrap();
        let renewed = client
            .renew_dynamic_secret_lease(
                &scope(),
                &lease_id,
                DynamicSecretTtlSeconds::new(7_200).unwrap(),
            )
            .await
            .unwrap();
        let revoked = client
            .revoke_dynamic_secret_lease(&scope(), &lease_id, false, true)
            .await
            .unwrap();

        assert_eq!(leases.items[0], details.lease);
        assert_eq!(renewed.id, LEASE_ID);
        assert_eq!(revoked.id, LEASE_ID);
        assert!(
            !serde_json::to_string(&details)
                .unwrap()
                .contains("must-not-escape")
        );
    }

    #[tokio::test]
    async fn unconfirmed_revocation_fails_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert_eq!(
            client
                .revoke_dynamic_secret_lease(
                    &scope(),
                    &DynamicSecretLeaseId::new(LEASE_ID).unwrap(),
                    false,
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::DynamicSecretLeaseRevocationNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn response_validation_rejects_scope_and_lifetime_drift() {
        let mut wrong_name = dynamic_secret_fixture("other-name");
        let raw: super::RawDynamicSecret = serde_json::from_value(wrong_name.clone()).unwrap();
        assert_eq!(raw.into_validated().unwrap().name, "other-name");
        wrong_name["id"] = json!("not-a-uuid");
        let raw: super::RawDynamicSecret = serde_json::from_value(wrong_name).unwrap();
        assert_eq!(
            raw.into_validated().unwrap_err(),
            ResourceError::InvalidDynamicSecretResponse
        );

        let mut expired_before_creation = lease_fixture(LEASE_ID);
        expired_before_creation["expireAt"] = json!("2026-07-20T11:59:59.000Z");
        let raw: super::RawDynamicSecretLease =
            serde_json::from_value(expired_before_creation).unwrap();
        assert_eq!(
            raw.into_validated(None).unwrap_err(),
            ResourceError::InvalidDynamicSecretLeaseResponse
        );
    }

    fn assert_configuration_field_rejected(field: &str, value: Value) {
        let mut fixture = dynamic_secret_fixture("database-user");
        fixture[field] = value;
        let raw: super::RawDynamicSecret = serde_json::from_value(fixture).unwrap();
        assert_eq!(
            raw.into_validated().unwrap_err(),
            ResourceError::InvalidDynamicSecretResponse,
            "{field} must be validated independently"
        );
    }

    #[test]
    fn configuration_response_validates_each_independent_invariant() {
        for (field, value) in [
            ("version", json!(0)),
            ("id", json!("not-a-uuid")),
            ("folderId", json!("not-a-uuid")),
            ("name", json!("Not Canonical")),
            ("defaultTTL", json!("")),
            ("maxTTL", json!("")),
            ("maxTTL", json!("59m")),
            ("updatedAt", json!("2026-07-20T11:59:59.000Z")),
            ("projectGatewayId", json!("not-a-uuid")),
            ("gatewayId", json!("not-a-uuid")),
            ("gatewayV2Id", json!("not-a-uuid")),
            ("gatewayPoolId", json!("not-a-uuid")),
            ("usernameTemplate", json!("")),
        ] {
            assert_configuration_field_rejected(field, value);
        }

        let mut equal_timestamps = dynamic_secret_fixture("database-user");
        equal_timestamps["updatedAt"] = equal_timestamps["createdAt"].clone();
        let raw: super::RawDynamicSecret = serde_json::from_value(equal_timestamps).unwrap();
        assert!(raw.into_validated().is_ok());
    }

    #[test]
    fn configuration_ttls_match_the_pinned_duration_grammar_and_ordering() {
        for (value, expected_millis) in [
            ("60000", 60_000.0),
            ("60000 ms", 60_000.0),
            ("60 seconds", 60_000.0),
            ("1m", 60_000.0),
            (".5 H", 1_800_000.0),
            ("1 day", 86_400_000.0),
            ("1w", 604_800_000.0),
            ("1y", 31_557_600_000.0),
        ] {
            assert_eq!(
                super::parse_dynamic_ttl_millis(value),
                Some(expected_millis),
                "{value} must match Infisical's pinned ms grammar"
            );
        }
        for malformed in [
            "",
            " 1h",
            "1h\n",
            "1..0h",
            "1.h",
            ".h",
            "1e3s",
            "-1h",
            "+1h",
            "1 lightyear",
            "1 h h",
        ] {
            assert_eq!(
                super::parse_dynamic_ttl_millis(malformed),
                None,
                "{malformed:?} must be rejected"
            );
        }
        let at_text_limit = format!("{}1h", "0".repeat(62));
        let over_text_limit = format!("{}1h", "0".repeat(63));
        assert_eq!(at_text_limit.len(), super::MAX_DYNAMIC_TTL_TEXT_BYTES);
        assert_eq!(
            super::parse_dynamic_ttl_millis(&at_text_limit),
            Some(3_600_000.0)
        );
        assert_eq!(super::parse_dynamic_ttl_millis(&over_text_limit), None);
        assert!(super::dynamic_secret_ttls_are_valid("1h", None));
        assert!(super::dynamic_secret_ttls_are_valid("1h", Some("1h")));
        assert!(super::dynamic_secret_ttls_are_valid("1h", Some("2h")));
        assert!(!super::dynamic_secret_ttls_are_valid("59s", None));
        assert!(!super::dynamic_secret_ttls_are_valid("11y", None));
        assert!(!super::dynamic_secret_ttls_are_valid("1h", Some("11y")));
        assert!(!super::dynamic_secret_ttls_are_valid("2h", Some("1h")));
        assert!(!super::dynamic_secret_ttls_are_valid("forever", None));
    }

    fn assert_lease_field_rejected(field: &str, value: Value) {
        let mut fixture = lease_fixture(LEASE_ID);
        fixture[field] = value;
        let raw: super::RawDynamicSecretLease = serde_json::from_value(fixture).unwrap();
        assert_eq!(
            raw.into_validated(None).unwrap_err(),
            ResourceError::InvalidDynamicSecretLeaseResponse,
            "{field} must be validated independently"
        );
    }

    #[test]
    fn lease_response_validates_each_independent_invariant() {
        for (field, value) in [
            ("version", json!(0)),
            ("id", json!("not-a-uuid")),
            ("dynamicSecretId", json!("not-a-uuid")),
            ("externalEntityId", json!("")),
            ("updatedAt", json!("2026-07-20T11:59:59.000Z")),
            ("expireAt", json!("2026-07-20T11:59:59.000Z")),
        ] {
            assert_lease_field_rejected(field, value);
        }

        let different_id = "db27f5c0-c104-43eb-9318-3c218ef27933";
        let raw: super::RawDynamicSecretLease =
            serde_json::from_value(lease_fixture(different_id)).unwrap();
        assert_eq!(
            raw.into_validated(Some(&DynamicSecretLeaseId::new(LEASE_ID).unwrap()))
                .unwrap_err(),
            ResourceError::InvalidDynamicSecretLeaseResponse
        );

        let mut equal_timestamps = lease_fixture(LEASE_ID);
        equal_timestamps["updatedAt"] = equal_timestamps["createdAt"].clone();
        equal_timestamps["expireAt"] = equal_timestamps["createdAt"].clone();
        let raw: super::RawDynamicSecretLease = serde_json::from_value(equal_timestamps).unwrap();
        assert!(raw.into_validated(None).is_ok());
    }
}
