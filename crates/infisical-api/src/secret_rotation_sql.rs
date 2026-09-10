use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AutomationDescriptionChange, EnvironmentSlug, InfisicalClient, MutationOperation,
    ObservableReadOperation, ProjectId, ResourceError, RotationTimeOfDay, SecretName, SecretPath,
    SecretRotation, SecretRotationType, SecretValue, SqlDynamicSecretClient,
    SqlDynamicSecretPasswordRequirements,
    app_automations::{RawSecretRotation, project_environments},
    client::{ApiVersion, DeserializedSecret, Endpoint, sealed},
    dynamic_secret_sql::validate_sql_template,
    resources::{is_bounded_text, is_uuid},
};

const MAX_ROTATION_NAME_BYTES: usize = 64;
const MAX_DESCRIPTION_BYTES: usize = 256;
const MAX_SQL_USERNAME_BYTES: usize = 256;
const MAX_GENERATED_PASSWORD_BYTES: usize = 16_384;

/// Validation or confirmation failures for the pinned SQL credential-rotation contract.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SqlSecretRotationInputError {
    /// The rotation name was not a canonical Infisical slug.
    #[error(
        "SQL secret-rotation names must be 1 to 64 lowercase letters, numbers, or single hyphens"
    )]
    InvalidName,
    /// The optional description was padded, control-bearing, or oversized.
    #[error("SQL secret-rotation descriptions must be unpadded and at most 256 bytes")]
    InvalidDescription,
    /// The app-connection or rotation identifier was not a UUID.
    #[error("SQL secret-rotation connection and rotation identifiers must be UUIDs")]
    InvalidIdentifier,
    /// A SQL principal name was empty, padded, control-bearing, or oversized.
    #[error("SQL rotation usernames must contain 1 to 256 unpadded bytes")]
    InvalidUsername,
    /// Both alternating database principals had the same name.
    #[error("SQL rotation usernames must identify two distinct principals")]
    DuplicateUsername,
    /// Both generated-credential fields mapped to the same Infisical secret.
    #[error("SQL rotation username and password mappings must use distinct secret names")]
    DuplicateSecretMapping,
    /// The parameter contract did not match the selected provider.
    #[error("SQL rotation parameters and password requirements must match the selected provider")]
    ParameterProviderMismatch,
    /// The optional rotation statement was malformed or used unsupported expressions.
    #[error(
        "SQL rotation statements may use only username, password, and database templates and must include username and password"
    )]
    InvalidRotationStatement,
    /// The automatic rotation interval was zero.
    #[error("SQL rotation intervals must be at least one day")]
    InvalidRotationInterval,
    /// The UTC rotation schedule exceeded clock bounds.
    #[error("SQL rotation time must use an hour from 0 through 23 and minute from 0 through 59")]
    InvalidRotationTime,
    /// The requested update had no fields.
    #[error("SQL secret-rotation updates must change at least one field")]
    EmptyUpdate,
}

/// SQL credential-rotation providers sharing the pinned Infisical lifecycle contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SqlSecretRotationProvider {
    /// `PostgreSQL` alternating credentials.
    #[serde(rename = "postgres-credentials")]
    Postgres,
    /// `MySQL` alternating credentials.
    #[serde(rename = "mysql-credentials")]
    MySql,
    /// Microsoft SQL Server alternating credentials.
    #[serde(rename = "mssql-credentials")]
    MsSql,
    /// Oracle Database alternating credentials.
    #[serde(rename = "oracledb-credentials")]
    OracleDb,
}

impl SqlSecretRotationProvider {
    const fn route_segment(self) -> &'static str {
        match self {
            Self::Postgres => "postgres-credentials",
            Self::MySql => "mysql-credentials",
            Self::MsSql => "mssql-credentials",
            Self::OracleDb => "oracledb-credentials",
        }
    }

    const fn rotation_type(self) -> SecretRotationType {
        match self {
            Self::Postgres => SecretRotationType::PostgresCredentials,
            Self::MySql => SecretRotationType::MySqlCredentials,
            Self::MsSql => SecretRotationType::MsSqlCredentials,
            Self::OracleDb => SecretRotationType::OracleDbCredentials,
        }
    }

    /// SQL client family used by the shared password-policy validator.
    #[must_use]
    pub const fn sql_client(self) -> SqlDynamicSecretClient {
        match self {
            Self::Postgres => SqlDynamicSecretClient::Postgres,
            Self::MySql => SqlDynamicSecretClient::MySql,
            Self::MsSql => SqlDynamicSecretClient::MsSql,
            Self::OracleDb => SqlDynamicSecretClient::Oracle,
        }
    }
}

/// Canonical provider-side SQL rotation name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SqlSecretRotationName(String);

impl SqlSecretRotationName {
    /// Validate a name before it reaches an Infisical route or body.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value is a canonical lowercase slug.
    pub fn new(value: impl Into<String>) -> Result<Self, SqlSecretRotationInputError> {
        let value = value.into();
        if !canonical_slug(&value) {
            return Err(SqlSecretRotationInputError::InvalidName);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Complete provider parameters for alternating SQL credentials.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlSecretRotationParameters {
    #[serde(skip)]
    provider: SqlSecretRotationProvider,
    username1: String,
    username2: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rotation_statement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_requirements: Option<SqlDynamicSecretPasswordRequirements>,
}

impl SqlSecretRotationParameters {
    /// Validate alternating usernames, the optional statement, and password policy.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or duplicate usernames, an unsupported
    /// statement template, or a provider-mismatched password policy.
    pub fn new(
        provider: SqlSecretRotationProvider,
        username1: impl Into<String>,
        username2: impl Into<String>,
        rotation_statement: Option<String>,
        password_requirements: Option<SqlDynamicSecretPasswordRequirements>,
    ) -> Result<Self, SqlSecretRotationInputError> {
        let username1 = username1.into();
        let username2 = username2.into();
        if !sql_username_is_valid(&username1) || !sql_username_is_valid(&username2) {
            return Err(SqlSecretRotationInputError::InvalidUsername);
        }
        if username1 == username2 {
            return Err(SqlSecretRotationInputError::DuplicateUsername);
        }
        if let Some(statement) = rotation_statement.as_deref() {
            validate_sql_template(
                statement,
                &["username", "password", "database"],
                &["username", "password"],
            )
            .map_err(|_| SqlSecretRotationInputError::InvalidRotationStatement)?;
        }
        if password_requirements
            .as_ref()
            .is_some_and(|requirements| requirements.client() != provider.sql_client())
        {
            return Err(SqlSecretRotationInputError::ParameterProviderMismatch);
        }
        Ok(Self {
            provider,
            username1,
            username2,
            rotation_statement,
            password_requirements,
        })
    }
}

/// Names of the two Infisical secrets maintained by a SQL rotation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlSecretRotationSecretsMapping {
    username: SecretName,
    password: SecretName,
}

impl SqlSecretRotationSecretsMapping {
    /// Construct a mapping with distinct secret names.
    ///
    /// # Errors
    ///
    /// Returns an error when both fields map to the same secret.
    pub fn new(
        username: SecretName,
        password: SecretName,
    ) -> Result<Self, SqlSecretRotationInputError> {
        if username == password {
            return Err(SqlSecretRotationInputError::DuplicateSecretMapping);
        }
        Ok(Self { username, password })
    }
}

/// Exact project-owned SQL rotation target.
#[derive(Debug, Clone, Serialize)]
pub struct SqlSecretRotationTarget {
    #[serde(skip)]
    provider: SqlSecretRotationProvider,
    #[serde(skip)]
    project_id: ProjectId,
    #[serde(skip)]
    rotation_id: String,
}

impl SqlSecretRotationTarget {
    /// Validate one exact target.
    ///
    /// # Errors
    ///
    /// Returns an error unless the rotation identifier is a UUID.
    pub fn new(
        provider: SqlSecretRotationProvider,
        project_id: ProjectId,
        rotation_id: impl Into<String>,
    ) -> Result<Self, SqlSecretRotationInputError> {
        let rotation_id = rotation_id.into();
        if !is_uuid(&rotation_id) {
            return Err(SqlSecretRotationInputError::InvalidIdentifier);
        }
        Ok(Self {
            provider,
            project_id,
            rotation_id,
        })
    }
}

/// Exact name-addressed SQL rotation target.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlSecretRotationNameTarget {
    #[serde(skip)]
    provider: SqlSecretRotationProvider,
    project_id: ProjectId,
    #[serde(skip)]
    name: SqlSecretRotationName,
    environment: EnvironmentSlug,
    secret_path: SecretPath,
}

impl SqlSecretRotationNameTarget {
    /// Construct a fully validated name-addressed target.
    #[must_use]
    pub fn new(
        provider: SqlSecretRotationProvider,
        project_id: ProjectId,
        name: SqlSecretRotationName,
        environment: EnvironmentSlug,
        secret_path: SecretPath,
    ) -> Self {
        Self {
            provider,
            project_id,
            name,
            environment,
            secret_path,
        }
    }
}

/// Complete SQL credential-rotation creation request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlSecretRotationCreation {
    #[serde(skip)]
    provider: SqlSecretRotationProvider,
    name: SqlSecretRotationName,
    project_id: ProjectId,
    description: Option<String>,
    connection_id: String,
    environment: EnvironmentSlug,
    secret_path: SecretPath,
    is_auto_rotation_enabled: bool,
    rotation_interval: u32,
    rotate_at_utc: RotationTimeOfDay,
    parameters: SqlSecretRotationParameters,
    secrets_mapping: SqlSecretRotationSecretsMapping,
}

impl SqlSecretRotationCreation {
    /// Assemble and validate a complete creation request.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid connection ID, description, or interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: SqlSecretRotationProvider,
        name: SqlSecretRotationName,
        project_id: ProjectId,
        description: Option<String>,
        connection_id: impl Into<String>,
        environment: EnvironmentSlug,
        secret_path: SecretPath,
        is_auto_rotation_enabled: bool,
        rotation_interval: u32,
        rotate_at_utc: RotationTimeOfDay,
        parameters: SqlSecretRotationParameters,
        secrets_mapping: SqlSecretRotationSecretsMapping,
    ) -> Result<Self, SqlSecretRotationInputError> {
        let connection_id = connection_id.into();
        if !is_uuid(&connection_id) {
            return Err(SqlSecretRotationInputError::InvalidIdentifier);
        }
        if parameters.provider != provider {
            return Err(SqlSecretRotationInputError::ParameterProviderMismatch);
        }
        validate_description(description.as_deref())?;
        if rotation_interval == 0 {
            return Err(SqlSecretRotationInputError::InvalidRotationInterval);
        }
        if !rotation_time_is_valid(rotate_at_utc) {
            return Err(SqlSecretRotationInputError::InvalidRotationTime);
        }
        Ok(Self {
            provider,
            name,
            project_id,
            description,
            connection_id,
            environment,
            secret_path,
            is_auto_rotation_enabled,
            rotation_interval,
            rotate_at_utc,
            parameters,
            secrets_mapping,
        })
    }
}

/// Partial SQL credential-rotation replacement.
#[derive(Debug)]
pub struct SqlSecretRotationChange {
    provider: SqlSecretRotationProvider,
    name: Option<SqlSecretRotationName>,
    description: AutomationDescriptionChange,
    is_auto_rotation_enabled: Option<bool>,
    rotation_interval: Option<u32>,
    rotate_at_utc: Option<RotationTimeOfDay>,
    parameters: Option<SqlSecretRotationParameters>,
    secrets_mapping: Option<SqlSecretRotationSecretsMapping>,
}

impl SqlSecretRotationChange {
    /// Validate a non-empty partial update.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty update, invalid description, or zero interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: SqlSecretRotationProvider,
        name: Option<SqlSecretRotationName>,
        description: AutomationDescriptionChange,
        is_auto_rotation_enabled: Option<bool>,
        rotation_interval: Option<u32>,
        rotate_at_utc: Option<RotationTimeOfDay>,
        parameters: Option<SqlSecretRotationParameters>,
        secrets_mapping: Option<SqlSecretRotationSecretsMapping>,
    ) -> Result<Self, SqlSecretRotationInputError> {
        if let AutomationDescriptionChange::Set(value) = &description {
            validate_description(Some(value))?;
        }
        if rotation_interval == Some(0) {
            return Err(SqlSecretRotationInputError::InvalidRotationInterval);
        }
        if rotate_at_utc.is_some_and(|value| !rotation_time_is_valid(value)) {
            return Err(SqlSecretRotationInputError::InvalidRotationTime);
        }
        if parameters
            .as_ref()
            .is_some_and(|parameters| parameters.provider != provider)
        {
            return Err(SqlSecretRotationInputError::ParameterProviderMismatch);
        }
        if name.is_none()
            && description == AutomationDescriptionChange::Keep
            && is_auto_rotation_enabled.is_none()
            && rotation_interval.is_none()
            && rotate_at_utc.is_none()
            && parameters.is_none()
            && secrets_mapping.is_none()
        {
            return Err(SqlSecretRotationInputError::EmptyUpdate);
        }
        Ok(Self {
            provider,
            name,
            description,
            is_auto_rotation_enabled,
            rotation_interval,
            rotate_at_utc,
            parameters,
            secrets_mapping,
        })
    }
}

/// One generated SQL credential. The password is sensitive.
#[derive(Debug, JsonSchema)]
#[schemars(rename_all = "camelCase")]
pub struct SqlGeneratedCredential {
    /// Provider-created database username.
    pub username: String,
    /// Provider-created database password.
    #[schemars(with = "String")]
    pub password: SecretValue,
}

impl Serialize for SqlGeneratedCredential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer.serialize_map(Some(2))?;
        output.serialize_entry("username", &self.username)?;
        output.serialize_entry("password", self.password.expose_secret())?;
        output.end()
    }
}

/// Generated credential slots and the active slot index for one exact rotation.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SqlGeneratedCredentials {
    /// Exact rotation identifier validated against the request.
    pub rotation_id: String,
    /// Exact provider validated against the request.
    pub provider: SqlSecretRotationProvider,
    /// Active zero-based credential slot.
    pub active_index: u8,
    /// One or two generated credential slots.
    pub credentials: Vec<SqlGeneratedCredential>,
}

/// Explicit mapped-secret cleanup selected for rotation deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlMappedSecretCleanup {
    /// Preserve the two mapped Infisical secrets.
    Preserve,
    /// Delete both mapped secrets; the caller has already confirmed this effect.
    DeleteConfirmed,
}

/// Explicit provider-credential cleanup selected for rotation deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlGeneratedCredentialCleanup {
    /// Preserve generated database principals at the provider.
    Preserve,
    /// Revoke generated principals; the caller has already confirmed this effect.
    RevokeConfirmed,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSqlSecretRotation {
    #[serde(flatten)]
    common: RawSecretRotation,
    parameters: Value,
    secrets_mapping: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SqlSecretRotationResponse {
    secret_rotation: RawSqlSecretRotation,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawGeneratedCredentials {
    generated_credentials: Vec<RawGeneratedCredential>,
    active_index: u32,
    rotation_id: String,
    #[serde(rename = "type")]
    rotation_type: SecretRotationType,
}

#[derive(Deserialize)]
struct RawGeneratedCredential {
    username: String,
    password: DeserializedSecret,
}

struct GetSqlSecretRotation;

impl sealed::Sealed for GetSqlSecretRotation {}

impl ObservableReadOperation for GetSqlSecretRotation {
    type Query = SqlSecretRotationTarget;
    type Output = SqlSecretRotationResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V2,
            [
                "secret-rotations",
                query.provider.route_segment(),
                query.rotation_id.as_str(),
            ],
        )
    }
}

struct GetSqlSecretRotationByName;

impl sealed::Sealed for GetSqlSecretRotationByName {}

impl ObservableReadOperation for GetSqlSecretRotationByName {
    type Query = SqlSecretRotationNameTarget;
    type Output = SqlSecretRotationResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V2,
            [
                "secret-rotations",
                query.provider.route_segment(),
                "rotation-name",
                query.name.as_str(),
            ],
        )
    }
}

struct CreateSqlSecretRotation;

impl sealed::Sealed for CreateSqlSecretRotation {}

impl MutationOperation for CreateSqlSecretRotation {
    type Input = SqlSecretRotationCreation;
    type Output = SqlSecretRotationResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V2,
            ["secret-rotations", input.provider.route_segment()],
        )
    }
}

struct UpdateSqlSecretRotationWire {
    target: SqlSecretRotationTarget,
    change: SqlSecretRotationChange,
}

impl Serialize for UpdateSqlSecretRotationWire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer.serialize_map(None)?;
        if let Some(value) = &self.change.name {
            output.serialize_entry("name", value)?;
        }
        match &self.change.description {
            AutomationDescriptionChange::Keep => {}
            AutomationDescriptionChange::Clear => {
                output.serialize_entry("description", &Option::<&str>::None)?;
            }
            AutomationDescriptionChange::Set(value) => {
                output.serialize_entry("description", value)?;
            }
        }
        if let Some(value) = self.change.is_auto_rotation_enabled {
            output.serialize_entry("isAutoRotationEnabled", &value)?;
        }
        if let Some(value) = self.change.rotation_interval {
            output.serialize_entry("rotationInterval", &value)?;
        }
        if let Some(value) = self.change.rotate_at_utc {
            output.serialize_entry("rotateAtUtc", &value)?;
        }
        if let Some(value) = &self.change.parameters {
            output.serialize_entry("parameters", value)?;
        }
        if let Some(value) = &self.change.secrets_mapping {
            output.serialize_entry("secretsMapping", value)?;
        }
        output.end()
    }
}

struct UpdateSqlSecretRotation;

impl sealed::Sealed for UpdateSqlSecretRotation {}

impl MutationOperation for UpdateSqlSecretRotation {
    type Input = UpdateSqlSecretRotationWire;
    type Output = SqlSecretRotationResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        rotation_endpoint(&input.target)
    }
}

#[derive(Serialize)]
struct DeleteSqlSecretRotationWire {
    #[serde(skip)]
    target: SqlSecretRotationTarget,
    #[serde(skip)]
    delete_secrets: bool,
    #[serde(skip)]
    revoke_generated_credentials: bool,
}

struct DeleteSqlSecretRotation;

impl sealed::Sealed for DeleteSqlSecretRotation {}

impl MutationOperation for DeleteSqlSecretRotation {
    type Input = DeleteSqlSecretRotationWire;
    type Output = SqlSecretRotationResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        rotation_endpoint(&input.target)
    }

    fn query(input: &Self::Input) -> Vec<(&'static str, String)> {
        vec![
            ("deleteSecrets", input.delete_secrets.to_string()),
            (
                "revokeGeneratedCredentials",
                input.revoke_generated_credentials.to_string(),
            ),
        ]
    }

    fn sends_json_body() -> bool {
        false
    }
}

struct GetSqlGeneratedCredentials;

impl sealed::Sealed for GetSqlGeneratedCredentials {}

impl ObservableReadOperation for GetSqlGeneratedCredentials {
    type Query = SqlSecretRotationTarget;
    type Output = RawGeneratedCredentials;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V2,
            [
                "secret-rotations",
                query.provider.route_segment(),
                query.rotation_id.as_str(),
                "generated-credentials",
            ],
        )
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MoveSqlSecretRotationWire {
    #[serde(skip)]
    target: SqlSecretRotationTarget,
    destination_environment: EnvironmentSlug,
    destination_secret_path: SecretPath,
    overwrite_destination: bool,
}

struct MoveSqlSecretRotation;

impl sealed::Sealed for MoveSqlSecretRotation {}

impl MutationOperation for MoveSqlSecretRotation {
    type Input = MoveSqlSecretRotationWire;
    type Output = SqlSecretRotationResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        action_endpoint(&input.target, "move")
    }
}

#[derive(Serialize)]
struct SqlSecretRotationActionWire {
    #[serde(skip)]
    target: SqlSecretRotationTarget,
}

struct RotateSqlSecretRotation;

impl sealed::Sealed for RotateSqlSecretRotation {}

impl MutationOperation for RotateSqlSecretRotation {
    type Input = SqlSecretRotationActionWire;
    type Output = SqlSecretRotationResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        action_endpoint(&input.target, "rotate-secrets")
    }

    fn sends_json_body() -> bool {
        false
    }
}

struct CheckSqlSecretRotation;

impl sealed::Sealed for CheckSqlSecretRotation {}

impl MutationOperation for CheckSqlSecretRotation {
    type Input = SqlSecretRotationActionWire;
    type Output = ();

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        action_endpoint(&input.target, "check-credentials")
    }

    fn sends_json_body() -> bool {
        false
    }

    fn accepts_empty_response() -> bool {
        true
    }
}

impl InfisicalClient {
    /// Get one exact SQL rotation without replaying its audited provider read.
    ///
    /// # Errors
    ///
    /// Returns a typed client, permission, or response-contract error.
    pub async fn get_sql_secret_rotation(
        &self,
        target: &SqlSecretRotationTarget,
    ) -> Result<SecretRotation, ResourceError> {
        self.preflight_sql_secret_rotation(target)
            .await
            .map(|(rotation, _)| rotation)
    }

    /// Get one exact SQL rotation by canonical project scope and name.
    ///
    /// # Errors
    ///
    /// Returns a typed client, permission, or response-contract error.
    pub async fn get_sql_secret_rotation_by_name(
        &self,
        target: &SqlSecretRotationNameTarget,
    ) -> Result<SecretRotation, ResourceError> {
        let environments = self.rotation_environments(&target.project_id).await?;
        let response = self
            .execute_observable_read::<GetSqlSecretRotationByName>(target)
            .await?;
        let rotation = response
            .secret_rotation
            .common
            .into_validated(&target.project_id, &environments)?;
        if rotation.rotation_type != target.provider.rotation_type()
            || rotation.name != target.name.as_str()
            || rotation.environment.slug != target.environment.as_str()
            || rotation.folder.path != target.secret_path.as_str()
        {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(rotation)
    }

    /// Create external SQL credentials and mapped secrets exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error unless the external side effects are explicitly confirmed,
    /// or for a typed client, permission, or response-contract failure.
    pub async fn create_sql_secret_rotation(
        &self,
        creation: SqlSecretRotationCreation,
        confirm_create_credentials_and_secrets: bool,
    ) -> Result<SecretRotation, ResourceError> {
        if !confirm_create_credentials_and_secrets {
            return Err(ResourceError::SqlSecretRotationCreateNotConfirmed);
        }
        let environments = self.rotation_environments(&creation.project_id).await?;
        let expected_parameters = serde_json::to_value(&creation.parameters)
            .map_err(|_| ResourceError::InvalidAppAutomationResponse)?;
        let expected_mapping = serde_json::to_value(&creation.secrets_mapping)
            .map_err(|_| ResourceError::InvalidAppAutomationResponse)?;
        let response = self
            .execute_mutation::<CreateSqlSecretRotation>(&creation)
            .await?;
        let target = SqlSecretRotationTarget {
            provider: creation.provider,
            project_id: creation.project_id.clone(),
            rotation_id: response.secret_rotation.common.id().to_owned(),
        };
        let (rotation, parameters, mapping) =
            validate_rotation_response(response, &target, &environments)?;
        if rotation.name != creation.name.as_str()
            || rotation.description != creation.description
            || rotation.connection.id != creation.connection_id
            || rotation.environment.slug != creation.environment.as_str()
            || rotation.folder.path != creation.secret_path.as_str()
            || rotation.is_auto_rotation_enabled != creation.is_auto_rotation_enabled
            || rotation.rotation_interval_days != creation.rotation_interval
            || rotation.rotate_at_utc != creation.rotate_at_utc
            || parameters != expected_parameters
            || mapping != expected_mapping
        {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(rotation)
    }

    /// Update one exact SQL rotation after an audited ownership preflight.
    ///
    /// # Errors
    ///
    /// Returns an error unless possible secret renames and scheduled rotation are
    /// explicitly confirmed, or for a typed client, permission, or contract failure.
    pub async fn update_sql_secret_rotation(
        &self,
        target: SqlSecretRotationTarget,
        change: SqlSecretRotationChange,
        confirm_update_effects: bool,
    ) -> Result<SecretRotation, ResourceError> {
        if !confirm_update_effects {
            return Err(ResourceError::SqlSecretRotationUpdateNotConfirmed);
        }
        if target.provider != change.provider {
            return Err(ResourceError::SqlSecretRotationProviderMismatch);
        }
        let (_, environments) = self.preflight_sql_secret_rotation(&target).await?;
        let wire = UpdateSqlSecretRotationWire { target, change };
        let response = self
            .execute_mutation::<UpdateSqlSecretRotation>(&wire)
            .await?;
        let (rotation, parameters, mapping) =
            validate_rotation_response(response, &wire.target, &environments)?;
        validate_change_result(&rotation, &parameters, &mapping, &wire.change)?;
        Ok(rotation)
    }

    /// Delete one exact SQL rotation with independent secret and credential cleanup choices.
    ///
    /// # Errors
    ///
    /// Returns an error unless deletion and each selected cleanup effect has its
    /// own confirmation, or for a typed client, permission, or contract failure.
    pub async fn delete_sql_secret_rotation(
        &self,
        target: SqlSecretRotationTarget,
        mapped_secret_cleanup: SqlMappedSecretCleanup,
        generated_credential_cleanup: SqlGeneratedCredentialCleanup,
        confirm_delete: bool,
    ) -> Result<SecretRotation, ResourceError> {
        if !confirm_delete {
            return Err(ResourceError::SqlSecretRotationDeleteNotConfirmed);
        }
        let (_, environments) = self.preflight_sql_secret_rotation(&target).await?;
        let wire = DeleteSqlSecretRotationWire {
            target,
            delete_secrets: mapped_secret_cleanup == SqlMappedSecretCleanup::DeleteConfirmed,
            revoke_generated_credentials: generated_credential_cleanup
                == SqlGeneratedCredentialCleanup::RevokeConfirmed,
        };
        let response = self
            .execute_mutation::<DeleteSqlSecretRotation>(&wire)
            .await?;
        validate_rotation_response(response, &wire.target, &environments)
            .map(|(rotation, _, _)| rotation)
    }

    /// Reveal one exact SQL rotation's one or two generated credential slots.
    ///
    /// # Errors
    ///
    /// Returns an error unless reveal is explicitly confirmed, or for a typed
    /// client, permission, secret-bound, or response-contract failure.
    pub async fn get_sql_generated_credentials(
        &self,
        target: &SqlSecretRotationTarget,
        confirm_reveal: bool,
    ) -> Result<SqlGeneratedCredentials, ResourceError> {
        if !confirm_reveal {
            return Err(ResourceError::SqlSecretRotationRevealNotConfirmed);
        }
        self.get_sql_secret_rotation(target).await?;
        let response = self
            .execute_observable_read::<GetSqlGeneratedCredentials>(target)
            .await?;
        validate_generated_credentials(response, target)
    }

    /// Move one exact SQL rotation and its mapped secrets.
    ///
    /// # Errors
    ///
    /// Returns an error unless the move and any destination overwrite are
    /// explicitly confirmed, or for a typed client, permission, or contract failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn move_sql_secret_rotation(
        &self,
        target: SqlSecretRotationTarget,
        destination_environment: EnvironmentSlug,
        destination_secret_path: SecretPath,
        overwrite_destination: bool,
        confirm_move: bool,
        confirm_overwrite_destination: bool,
    ) -> Result<SecretRotation, ResourceError> {
        if !confirm_move {
            return Err(ResourceError::SqlSecretRotationMoveNotConfirmed);
        }
        if overwrite_destination && !confirm_overwrite_destination {
            return Err(ResourceError::SqlSecretRotationOverwriteNotConfirmed);
        }
        let (_, environments) = self.preflight_sql_secret_rotation(&target).await?;
        let wire = MoveSqlSecretRotationWire {
            target,
            destination_environment,
            destination_secret_path,
            overwrite_destination,
        };
        let response = self
            .execute_mutation::<MoveSqlSecretRotation>(&wire)
            .await?;
        let (rotation, _, _) = validate_rotation_response(response, &wire.target, &environments)?;
        if rotation.environment.slug != wire.destination_environment.as_str()
            || rotation.folder.path != wire.destination_secret_path.as_str()
        {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(rotation)
    }

    /// Rotate one exact SQL credential pair and mapped secrets once.
    ///
    /// # Errors
    ///
    /// Returns an error unless rotation is explicitly confirmed, or for a typed
    /// client, permission, provider, or response-contract failure.
    pub async fn rotate_sql_secret_rotation(
        &self,
        target: SqlSecretRotationTarget,
        confirm_rotate: bool,
    ) -> Result<SecretRotation, ResourceError> {
        if !confirm_rotate {
            return Err(ResourceError::SqlSecretRotationRotateNotConfirmed);
        }
        let (_, environments) = self.preflight_sql_secret_rotation(&target).await?;
        let wire = SqlSecretRotationActionWire { target };
        let response = self
            .execute_mutation::<RotateSqlSecretRotation>(&wire)
            .await?;
        validate_rotation_response(response, &wire.target, &environments)
            .map(|(rotation, _, _)| rotation)
    }

    /// Check one exact rotation's active credentials against its SQL provider once.
    ///
    /// # Errors
    ///
    /// Returns an error unless the external check is explicitly confirmed, or
    /// for a typed client, permission, provider, or response-contract failure.
    pub async fn check_sql_secret_rotation_credentials(
        &self,
        target: SqlSecretRotationTarget,
        confirm_check: bool,
    ) -> Result<(), ResourceError> {
        if !confirm_check {
            return Err(ResourceError::SqlSecretRotationCheckNotConfirmed);
        }
        self.get_sql_secret_rotation(&target).await?;
        self.execute_mutation::<CheckSqlSecretRotation>(&SqlSecretRotationActionWire { target })
            .await?;
        Ok(())
    }

    async fn rotation_environments(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<crate::Environment>, ResourceError> {
        self.get_project(project_id)
            .await?
            .ok_or(ResourceError::InvalidAppAutomationResponse)
            .and_then(|project| project_environments(project, project_id))
    }

    async fn preflight_sql_secret_rotation(
        &self,
        target: &SqlSecretRotationTarget,
    ) -> Result<(SecretRotation, Vec<crate::Environment>), ResourceError> {
        let environments = self.rotation_environments(&target.project_id).await?;
        let response = self
            .execute_observable_read::<GetSqlSecretRotation>(target)
            .await?;
        let (rotation, _, _) = validate_rotation_response(response, target, &environments)?;
        Ok((rotation, environments))
    }
}

fn validate_rotation_response(
    response: SqlSecretRotationResponse,
    target: &SqlSecretRotationTarget,
    environments: &[crate::Environment],
) -> Result<(SecretRotation, Value, Value), ResourceError> {
    let RawSqlSecretRotation {
        common,
        parameters,
        secrets_mapping,
    } = response.secret_rotation;
    let rotation = common.into_validated(&target.project_id, environments)?;
    if rotation.id != target.rotation_id
        || rotation.rotation_type != target.provider.rotation_type()
    {
        return Err(ResourceError::InvalidAppAutomationResponse);
    }
    Ok((rotation, parameters, secrets_mapping))
}

fn validate_change_result(
    rotation: &SecretRotation,
    parameters: &Value,
    mapping: &Value,
    change: &SqlSecretRotationChange,
) -> Result<(), ResourceError> {
    let description_matches = match &change.description {
        AutomationDescriptionChange::Keep => true,
        AutomationDescriptionChange::Clear => rotation.description.is_none(),
        AutomationDescriptionChange::Set(value) => rotation.description.as_ref() == Some(value),
    };
    let parameters_match = change.parameters.as_ref().is_none_or(|value| {
        serde_json::to_value(value).is_ok_and(|expected| expected == *parameters)
    });
    let mapping_matches = change
        .secrets_mapping
        .as_ref()
        .is_none_or(|value| serde_json::to_value(value).is_ok_and(|expected| expected == *mapping));
    if change
        .name
        .as_ref()
        .is_some_and(|value| rotation.name != value.as_str())
        || !description_matches
        || change
            .is_auto_rotation_enabled
            .is_some_and(|value| rotation.is_auto_rotation_enabled != value)
        || change
            .rotation_interval
            .is_some_and(|value| rotation.rotation_interval_days != value)
        || change
            .rotate_at_utc
            .is_some_and(|value| rotation.rotate_at_utc != value)
        || !parameters_match
        || !mapping_matches
    {
        return Err(ResourceError::InvalidAppAutomationResponse);
    }
    Ok(())
}

fn validate_generated_credentials(
    response: RawGeneratedCredentials,
    target: &SqlSecretRotationTarget,
) -> Result<SqlGeneratedCredentials, ResourceError> {
    if response.rotation_id != target.rotation_id
        || response.rotation_type != target.provider.rotation_type()
        || response.active_index > 1
        || !(1..=2).contains(&response.generated_credentials.len())
        || usize::try_from(response.active_index)
            .ok()
            .is_none_or(|index| index >= response.generated_credentials.len())
    {
        return Err(ResourceError::InvalidAppAutomationResponse);
    }
    let credentials = response
        .generated_credentials
        .into_iter()
        .map(|credential| {
            if !sql_username_is_valid(&credential.username)
                || !is_bounded_text(
                    credential.password.0.expose_secret(),
                    MAX_GENERATED_PASSWORD_BYTES,
                )
            {
                return Err(ResourceError::InvalidAppAutomationResponse);
            }
            Ok(SqlGeneratedCredential {
                username: credential.username,
                password: credential.password.0,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SqlGeneratedCredentials {
        rotation_id: response.rotation_id,
        provider: target.provider,
        active_index: u8::try_from(response.active_index)
            .map_err(|_| ResourceError::InvalidAppAutomationResponse)?,
        credentials,
    })
}

fn rotation_endpoint(target: &SqlSecretRotationTarget) -> Endpoint {
    Endpoint::from_segments(
        ApiVersion::V2,
        [
            "secret-rotations",
            target.provider.route_segment(),
            target.rotation_id.as_str(),
        ],
    )
}

fn action_endpoint(target: &SqlSecretRotationTarget, action: &'static str) -> Endpoint {
    Endpoint::from_segments(
        ApiVersion::V2,
        [
            "secret-rotations",
            target.provider.route_segment(),
            target.rotation_id.as_str(),
            action,
        ],
    )
}

fn validate_description(value: Option<&str>) -> Result<(), SqlSecretRotationInputError> {
    if value.is_some_and(|value| {
        value.len() > MAX_DESCRIPTION_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
    }) {
        Err(SqlSecretRotationInputError::InvalidDescription)
    } else {
        Ok(())
    }
}

fn sql_username_is_valid(value: &str) -> bool {
    is_bounded_text(value, MAX_SQL_USERNAME_BYTES)
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

const fn rotation_time_is_valid(value: RotationTimeOfDay) -> bool {
    value.hours <= 23 && value.minutes <= 59
}

fn canonical_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ROTATION_NAME_BYTES
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path, query_param},
    };

    use super::{
        RawGeneratedCredentials, SqlSecretRotationChange, SqlSecretRotationCreation,
        SqlSecretRotationInputError, SqlSecretRotationName, SqlSecretRotationNameTarget,
        SqlSecretRotationParameters, SqlSecretRotationProvider, SqlSecretRotationResponse,
        SqlSecretRotationSecretsMapping, SqlSecretRotationTarget, sql_username_is_valid,
        validate_change_result, validate_description, validate_generated_credentials,
        validate_rotation_response,
    };
    use crate::{
        AutomationDescriptionChange, EnvironmentSlug, InfisicalClient, ProjectId, ResourceError,
        RotationTimeOfDay, SecretName, SecretPath, SqlDynamicSecretClient,
        SqlDynamicSecretPasswordRequirements,
        test_support::{mount_login, settings},
    };

    const PROJECT_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const CONNECTION_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const FOLDER_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const ENVIRONMENT_ID: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    const ROTATION_ID: &str = "22222222-2222-4222-8222-222222222222";

    #[test]
    fn shared_sql_inputs_reject_ambiguous_provider_configuration() {
        assert_eq!(
            SqlSecretRotationName::new("Bad Name").unwrap_err(),
            SqlSecretRotationInputError::InvalidName
        );
        assert_eq!(
            SqlSecretRotationParameters::new(
                SqlSecretRotationProvider::Postgres,
                "app_user",
                "app_user",
                None,
                None,
            )
            .unwrap_err(),
            SqlSecretRotationInputError::DuplicateUsername
        );
        assert_eq!(
            SqlSecretRotationParameters::new(
                SqlSecretRotationProvider::Postgres,
                "app_user_a",
                "app_user_b",
                Some("ALTER USER {{username}} PASSWORD {{unknown}}".to_owned()),
                None,
            )
            .unwrap_err(),
            SqlSecretRotationInputError::InvalidRotationStatement
        );
        assert_eq!(
            SqlSecretRotationParameters::new(
                SqlSecretRotationProvider::Postgres,
                "app_user_a",
                "app_user_b",
                None,
                Some(SqlDynamicSecretPasswordRequirements::provider_default(
                    SqlDynamicSecretClient::Oracle,
                )),
            )
            .unwrap_err(),
            SqlSecretRotationInputError::ParameterProviderMismatch
        );
        assert_eq!(
            SqlSecretRotationSecretsMapping::new(
                SecretName::new("DB_USER").unwrap(),
                SecretName::new("DB_USER").unwrap(),
            )
            .unwrap_err(),
            SqlSecretRotationInputError::DuplicateSecretMapping
        );
        for invalid in ["", " padded", "padded ", "control\n"] {
            assert!(!sql_username_is_valid(invalid), "{invalid:?}");
        }
        assert!(sql_username_is_valid(&"u".repeat(256)));
        assert!(!sql_username_is_valid(&"u".repeat(257)));
        assert!(validate_description(None).is_ok());
        assert!(validate_description(Some(&"d".repeat(256))).is_ok());
        for invalid in [" padded", "padded ", "control\n"] {
            assert_eq!(
                validate_description(Some(invalid)).unwrap_err(),
                SqlSecretRotationInputError::InvalidDescription
            );
        }
        assert_eq!(
            validate_description(Some(&"d".repeat(257))).unwrap_err(),
            SqlSecretRotationInputError::InvalidDescription
        );
    }

    #[test]
    fn rotation_times_enforce_clock_bounds_for_create_and_update() {
        let boundary = RotationTimeOfDay {
            hours: 23,
            minutes: 59,
        };
        assert!(creation_with_time(boundary).is_ok());
        assert!(
            SqlSecretRotationChange::new(
                SqlSecretRotationProvider::Postgres,
                None,
                AutomationDescriptionChange::Keep,
                None,
                None,
                Some(boundary),
                None,
                None,
            )
            .is_ok()
        );
        for invalid in [
            RotationTimeOfDay {
                hours: 24,
                minutes: 0,
            },
            RotationTimeOfDay {
                hours: 0,
                minutes: 60,
            },
        ] {
            assert_eq!(
                creation_with_time(invalid).unwrap_err(),
                SqlSecretRotationInputError::InvalidRotationTime
            );
            assert_eq!(
                SqlSecretRotationChange::new(
                    SqlSecretRotationProvider::Postgres,
                    None,
                    AutomationDescriptionChange::Keep,
                    None,
                    None,
                    Some(invalid),
                    None,
                    None,
                )
                .unwrap_err(),
                SqlSecretRotationInputError::InvalidRotationTime
            );
        }
    }

    #[tokio::test]
    async fn provider_binding_is_enforced_before_authentication() {
        let parameters = || {
            SqlSecretRotationParameters::new(
                SqlSecretRotationProvider::Postgres,
                "app_user_a",
                "app_user_b",
                None,
                None,
            )
            .unwrap()
        };
        let creation_error = SqlSecretRotationCreation::new(
            SqlSecretRotationProvider::OracleDb,
            SqlSecretRotationName::new("database-password").unwrap(),
            ProjectId::new(PROJECT_ID).unwrap(),
            None,
            CONNECTION_ID,
            EnvironmentSlug::new("prod").unwrap(),
            SecretPath::new("/apps").unwrap(),
            true,
            30,
            RotationTimeOfDay {
                hours: 3,
                minutes: 15,
            },
            parameters(),
            SqlSecretRotationSecretsMapping::new(
                SecretName::new("DB_USER").unwrap(),
                SecretName::new("DB_PASSWORD").unwrap(),
            )
            .unwrap(),
        )
        .unwrap_err();
        assert_eq!(
            creation_error,
            SqlSecretRotationInputError::ParameterProviderMismatch
        );

        let change_error = SqlSecretRotationChange::new(
            SqlSecretRotationProvider::OracleDb,
            None,
            AutomationDescriptionChange::Keep,
            None,
            None,
            None,
            Some(parameters()),
            None,
        )
        .unwrap_err();
        assert_eq!(
            change_error,
            SqlSecretRotationInputError::ParameterProviderMismatch
        );

        let mismatched_change = SqlSecretRotationChange::new(
            SqlSecretRotationProvider::OracleDb,
            None,
            AutomationDescriptionChange::Keep,
            Some(false),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let server = MockServer::start().await;
        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .update_sql_secret_rotation(target(), mismatched_change, true)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ResourceError::SqlSecretRotationProviderMismatch
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_requires_confirmation_before_authentication() {
        let server = MockServer::start().await;
        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_sql_secret_rotation(creation(), false)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ResourceError::SqlSecretRotationCreateNotConfirmed
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_uses_exact_provider_body_and_validates_reflected_configuration() {
        let server = MockServer::start().await;
        mount_login(&server, "rotation-token").await;
        mount_project(&server, 1).await;
        Mock::given(method("POST"))
            .and(path("/api/v2/secret-rotations/postgres-credentials"))
            .and(header("authorization", "Bearer rotation-token"))
            .and(body_json(json!({
                "name": "database-password",
                "projectId": PROJECT_ID,
                "description": "Database credential rotation",
                "connectionId": CONNECTION_ID,
                "environment": "prod",
                "secretPath": "/apps",
                "isAutoRotationEnabled": true,
                "rotationInterval": 30,
                "rotateAtUtc": { "hours": 3, "minutes": 15 },
                "parameters": {
                    "username1": "app_user_a",
                    "username2": "app_user_b",
                    "rotationStatement": "ALTER USER {{username}} PASSWORD '{{password}}'"
                },
                "secretsMapping": { "username": "DB_USER", "password": "DB_PASSWORD" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretRotation": rotation_fixture()
            })))
            .expect(1)
            .mount(&server)
            .await;

        let rotation = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_sql_secret_rotation(creation(), true)
            .await
            .unwrap();
        assert_eq!(rotation.id, ROTATION_ID);
        assert_eq!(rotation.folder.path, "/apps");
    }

    #[tokio::test]
    async fn create_rejects_each_reflected_field_drift_independently() {
        for (field, response) in create_drift_cases() {
            let server = MockServer::start().await;
            mount_login(&server, "rotation-token").await;
            mount_project(&server, 1).await;
            Mock::given(method("POST"))
                .and(path("/api/v2/secret-rotations/postgres-credentials"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "secretRotation": response
                })))
                .expect(1)
                .mount(&server)
                .await;

            let result = InfisicalClient::new(settings(&server))
                .unwrap()
                .create_sql_secret_rotation(creation(), true)
                .await;
            assert!(
                matches!(result, Err(ResourceError::InvalidAppAutomationResponse)),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn update_preflights_scope_and_sends_only_the_declared_patch() {
        let server = MockServer::start().await;
        mount_login(&server, "rotation-token").await;
        mount_project(&server, 1).await;
        mount_exact_rotation(&server, 1).await;
        let mut updated = rotation_fixture();
        updated["description"] = Value::Null;
        updated["rotationInterval"] = json!(14);
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v2/secret-rotations/postgres-credentials/{ROTATION_ID}"
            )))
            .and(header("authorization", "Bearer rotation-token"))
            .and(body_json(json!({
                "description": null,
                "rotationInterval": 14
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretRotation": updated
            })))
            .expect(1)
            .mount(&server)
            .await;

        let changed = InfisicalClient::new(settings(&server))
            .unwrap()
            .update_sql_secret_rotation(
                target(),
                SqlSecretRotationChange::new(
                    SqlSecretRotationProvider::Postgres,
                    None,
                    AutomationDescriptionChange::Clear,
                    None,
                    Some(14),
                    None,
                    None,
                    None,
                )
                .unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(changed.description, None);
        assert_eq!(changed.rotation_interval_days, 14);
    }

    #[tokio::test]
    async fn delete_transmits_independent_cleanup_flags_without_a_body() {
        let server = MockServer::start().await;
        mount_login(&server, "rotation-token").await;
        mount_project(&server, 1).await;
        mount_exact_rotation(&server, 1).await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v2/secret-rotations/postgres-credentials/{ROTATION_ID}"
            )))
            .and(query_param("deleteSecrets", "true"))
            .and(query_param("revokeGeneratedCredentials", "false"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretRotation": rotation_fixture()
            })))
            .expect(1)
            .mount(&server)
            .await;

        InfisicalClient::new(settings(&server))
            .unwrap()
            .delete_sql_secret_rotation(
                target(),
                super::SqlMappedSecretCleanup::DeleteConfirmed,
                super::SqlGeneratedCredentialCleanup::Preserve,
                true,
            )
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let delete = requests
            .iter()
            .find(|request| request.method.as_str() == "DELETE")
            .unwrap();
        assert!(delete.body.is_empty());
    }

    #[tokio::test]
    async fn generated_credentials_are_exact_bounded_and_explicitly_sensitive() {
        let server = MockServer::start().await;
        mount_login(&server, "rotation-token").await;
        mount_project(&server, 1).await;
        mount_exact_rotation(&server, 1).await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v2/secret-rotations/postgres-credentials/{ROTATION_ID}/generated-credentials"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "generatedCredentials": [
                    { "username": "app_user_a", "password": "first-secret" },
                    { "username": "app_user_b", "password": "second-secret" }
                ],
                "activeIndex": 1,
                "rotationId": ROTATION_ID,
                "type": "postgres-credentials"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let credentials = InfisicalClient::new(settings(&server))
            .unwrap()
            .get_sql_generated_credentials(&target(), true)
            .await
            .unwrap();
        assert_eq!(credentials.active_index, 1);
        assert!(!format!("{credentials:?}").contains("first-secret"));
        let encoded = serde_json::to_value(credentials).unwrap();
        assert_eq!(encoded["credentials"][1]["password"], "second-secret");
    }

    #[tokio::test]
    async fn name_read_and_bodyless_check_use_exact_non_replayed_routes() {
        let server = MockServer::start().await;
        mount_login(&server, "rotation-token").await;
        mount_project(&server, 2).await;
        mount_exact_rotation(&server, 1).await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v2/secret-rotations/postgres-credentials/rotation-name/database-password",
            ))
            .and(query_param("projectId", PROJECT_ID))
            .and(query_param("environment", "prod"))
            .and(query_param("secretPath", "/apps"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretRotation": rotation_fixture()
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v2/secret-rotations/postgres-credentials/{ROTATION_ID}/check-credentials"
            )))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let named = client
            .get_sql_secret_rotation_by_name(&SqlSecretRotationNameTarget::new(
                SqlSecretRotationProvider::Postgres,
                ProjectId::new(PROJECT_ID).unwrap(),
                SqlSecretRotationName::new("database-password").unwrap(),
                EnvironmentSlug::new("prod").unwrap(),
                SecretPath::new("/apps").unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(named.id, ROTATION_ID);
        client
            .check_sql_secret_rotation_credentials(target(), true)
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let check = requests
            .iter()
            .find(|request| request.url.path().ends_with("/check-credentials"))
            .unwrap();
        assert!(check.body.is_empty());
    }

    #[tokio::test]
    async fn name_read_rejects_each_provider_and_scope_drift_independently() {
        for (field, response) in name_read_drift_cases() {
            let server = MockServer::start().await;
            mount_login(&server, "rotation-token").await;
            mount_project(&server, 1).await;
            Mock::given(method("GET"))
                .and(path(
                    "/api/v2/secret-rotations/postgres-credentials/rotation-name/database-password",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "secretRotation": response
                })))
                .expect(1)
                .mount(&server)
                .await;

            let result = InfisicalClient::new(settings(&server))
                .unwrap()
                .get_sql_secret_rotation_by_name(&SqlSecretRotationNameTarget::new(
                    SqlSecretRotationProvider::Postgres,
                    ProjectId::new(PROJECT_ID).unwrap(),
                    SqlSecretRotationName::new("database-password").unwrap(),
                    EnvironmentSlug::new("prod").unwrap(),
                    SecretPath::new("/apps").unwrap(),
                ))
                .await;
            assert!(
                matches!(result, Err(ResourceError::InvalidAppAutomationResponse)),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn manual_rotation_uses_the_exact_bodyless_provider_route() {
        let server = MockServer::start().await;
        mount_login(&server, "rotation-token").await;
        mount_project(&server, 1).await;
        mount_exact_rotation(&server, 1).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v2/secret-rotations/postgres-credentials/{ROTATION_ID}/rotate-secrets"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretRotation": rotation_fixture()
            })))
            .expect(1)
            .mount(&server)
            .await;

        let rotated = InfisicalClient::new(settings(&server))
            .unwrap()
            .rotate_sql_secret_rotation(target(), true)
            .await
            .unwrap();
        assert_eq!(rotated.id, ROTATION_ID);
        let requests = server.received_requests().await.unwrap();
        let rotation = requests
            .iter()
            .find(|request| request.url.path().ends_with("/rotate-secrets"))
            .unwrap();
        assert!(rotation.body.is_empty());
    }

    #[tokio::test]
    async fn move_requires_both_confirmations_and_binds_the_exact_destination() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert!(matches!(
            client
                .move_sql_secret_rotation(
                    target(),
                    EnvironmentSlug::new("prod").unwrap(),
                    SecretPath::new("/moved").unwrap(),
                    false,
                    false,
                    false,
                )
                .await,
            Err(ResourceError::SqlSecretRotationMoveNotConfirmed)
        ));
        assert!(matches!(
            client
                .move_sql_secret_rotation(
                    target(),
                    EnvironmentSlug::new("prod").unwrap(),
                    SecretPath::new("/moved").unwrap(),
                    true,
                    true,
                    false,
                )
                .await,
            Err(ResourceError::SqlSecretRotationOverwriteNotConfirmed)
        ));
        assert!(server.received_requests().await.unwrap().is_empty());

        for (field, response, succeeds) in move_response_cases() {
            let server = MockServer::start().await;
            mount_login(&server, "rotation-token").await;
            mount_project(&server, 1).await;
            mount_exact_rotation(&server, 1).await;
            Mock::given(method("POST"))
                .and(path(format!(
                    "/api/v2/secret-rotations/postgres-credentials/{ROTATION_ID}/move"
                )))
                .and(body_json(json!({
                    "destinationEnvironment": "prod",
                    "destinationSecretPath": "/moved",
                    "overwriteDestination": true
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "secretRotation": response
                })))
                .expect(1)
                .mount(&server)
                .await;

            let result = InfisicalClient::new(settings(&server))
                .unwrap()
                .move_sql_secret_rotation(
                    target(),
                    EnvironmentSlug::new("prod").unwrap(),
                    SecretPath::new("/moved").unwrap(),
                    true,
                    true,
                    true,
                )
                .await;
            assert_eq!(result.is_ok(), succeeds, "{field}");
        }
    }

    #[test]
    fn exact_response_and_update_reflection_reject_each_independent_drift() {
        let environments = project_environments();
        let valid = response_parts(&rotation_fixture(), &environments).unwrap();
        let expected_change = complete_change();
        assert!(validate_change_result(&valid.0, &valid.1, &valid.2, &expected_change).is_ok());

        for (field, response) in exact_target_drift_cases() {
            assert!(response_parts(&response, &environments).is_err(), "{field}");
        }
        for (field, response) in update_drift_cases() {
            let (rotation, parameters, mapping) = response_parts(&response, &environments).unwrap();
            assert!(
                validate_change_result(&rotation, &parameters, &mapping, &complete_change())
                    .is_err(),
                "{field}"
            );
        }

        let mut cleared = rotation_fixture();
        cleared["description"] = Value::Null;
        let (cleared, parameters, mapping) = response_parts(&cleared, &environments).unwrap();
        let clear_change = SqlSecretRotationChange::new(
            SqlSecretRotationProvider::Postgres,
            None,
            AutomationDescriptionChange::Clear,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(validate_change_result(&cleared, &parameters, &mapping, &clear_change).is_ok());
        let (not_cleared, parameters, mapping) =
            response_parts(&rotation_fixture(), &environments).unwrap();
        assert!(
            validate_change_result(&not_cleared, &parameters, &mapping, &clear_change).is_err()
        );
    }

    #[test]
    fn generated_credentials_reject_each_bound_and_target_drift_independently() {
        let valid = raw_generated_credentials(json!({
            "generatedCredentials": [
                { "username": "app_user_a", "password": "first-secret" },
                { "username": "app_user_b", "password": "second-secret" }
            ],
            "activeIndex": 1,
            "rotationId": ROTATION_ID,
            "type": "postgres-credentials"
        }));
        assert!(validate_generated_credentials(valid, &target()).is_ok());

        let zero_index = raw_generated_credentials(json!({
            "generatedCredentials": [
                { "username": "app_user_a", "password": "first-secret" }
            ],
            "activeIndex": 0,
            "rotationId": ROTATION_ID,
            "type": "postgres-credentials"
        }));
        let zero_index = validate_generated_credentials(zero_index, &target()).unwrap();
        assert_eq!(zero_index.active_index, 0);

        for (field, response) in generated_credential_drift_cases() {
            assert!(
                validate_generated_credentials(raw_generated_credentials(response), &target())
                    .is_err(),
                "{field}"
            );
        }
    }

    fn creation() -> SqlSecretRotationCreation {
        creation_with_time(RotationTimeOfDay {
            hours: 3,
            minutes: 15,
        })
        .unwrap()
    }

    fn creation_with_time(
        rotate_at_utc: RotationTimeOfDay,
    ) -> Result<SqlSecretRotationCreation, SqlSecretRotationInputError> {
        SqlSecretRotationCreation::new(
            SqlSecretRotationProvider::Postgres,
            SqlSecretRotationName::new("database-password").unwrap(),
            ProjectId::new(PROJECT_ID).unwrap(),
            Some("Database credential rotation".to_owned()),
            CONNECTION_ID,
            EnvironmentSlug::new("prod").unwrap(),
            SecretPath::new("/apps").unwrap(),
            true,
            30,
            rotate_at_utc,
            SqlSecretRotationParameters::new(
                SqlSecretRotationProvider::Postgres,
                "app_user_a",
                "app_user_b",
                Some("ALTER USER {{username}} PASSWORD '{{password}}'".to_owned()),
                None,
            )
            .unwrap(),
            SqlSecretRotationSecretsMapping::new(
                SecretName::new("DB_USER").unwrap(),
                SecretName::new("DB_PASSWORD").unwrap(),
            )
            .unwrap(),
        )
    }

    fn target() -> SqlSecretRotationTarget {
        SqlSecretRotationTarget::new(
            SqlSecretRotationProvider::Postgres,
            ProjectId::new(PROJECT_ID).unwrap(),
            ROTATION_ID,
        )
        .unwrap()
    }

    fn complete_change() -> SqlSecretRotationChange {
        SqlSecretRotationChange::new(
            SqlSecretRotationProvider::Postgres,
            Some(SqlSecretRotationName::new("database-password").unwrap()),
            AutomationDescriptionChange::Set("Database credential rotation".to_owned()),
            Some(true),
            Some(30),
            Some(RotationTimeOfDay {
                hours: 3,
                minutes: 15,
            }),
            Some(
                SqlSecretRotationParameters::new(
                    SqlSecretRotationProvider::Postgres,
                    "app_user_a",
                    "app_user_b",
                    Some("ALTER USER {{username}} PASSWORD '{{password}}'".to_owned()),
                    None,
                )
                .unwrap(),
            ),
            Some(
                SqlSecretRotationSecretsMapping::new(
                    SecretName::new("DB_USER").unwrap(),
                    SecretName::new("DB_PASSWORD").unwrap(),
                )
                .unwrap(),
            ),
        )
        .unwrap()
    }

    fn response_parts(
        fixture: &Value,
        environments: &[crate::Environment],
    ) -> Result<(crate::SecretRotation, Value, Value), ResourceError> {
        validate_rotation_response(
            serde_json::from_value::<SqlSecretRotationResponse>(json!({
                "secretRotation": fixture
            }))
            .unwrap(),
            &target(),
            environments,
        )
    }

    fn raw_generated_credentials(value: Value) -> RawGeneratedCredentials {
        serde_json::from_value(value).unwrap()
    }

    fn project_environments() -> Vec<crate::Environment> {
        vec![
            serde_json::from_value(json!({
                "id": ENVIRONMENT_ID,
                "name": "Production",
                "slug": "prod"
            }))
            .unwrap(),
        ]
    }

    async fn mount_project(server: &MockServer, expected: u64) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{PROJECT_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": {
                    "id": PROJECT_ID,
                    "name": "Platform",
                    "slug": "platform",
                    "type": "secret-manager",
                    "orgId": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    "environments": [{
                        "id": ENVIRONMENT_ID,
                        "name": "Production",
                        "slug": "prod"
                    }]
                }
            })))
            .expect(expected)
            .mount(server)
            .await;
    }

    async fn mount_exact_rotation(server: &MockServer, expected: u64) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v2/secret-rotations/postgres-credentials/{ROTATION_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretRotation": rotation_fixture()
            })))
            .expect(expected)
            .mount(server)
            .await;
    }

    fn rotation_fixture() -> Value {
        json!({
            "id": ROTATION_ID,
            "name": "database-password",
            "description": "Database credential rotation",
            "type": "postgres-credentials",
            "projectId": PROJECT_ID,
            "folderId": FOLDER_ID,
            "connectionId": CONNECTION_ID,
            "connection": { "id": CONNECTION_ID, "name": "postgres-primary", "app": "postgres" },
            "environment": { "id": ENVIRONMENT_ID, "name": "Production", "slug": "prod" },
            "folder": { "id": FOLDER_ID, "path": "/apps" },
            "isAutoRotationEnabled": true,
            "activeIndex": 1,
            "rotationInterval": 30,
            "rotateAtUtc": { "hours": 3, "minutes": 15 },
            "rotationStatus": "success",
            "lastRotationAttemptedAt": "2026-07-20T12:01:00.000Z",
            "lastRotatedAt": "2026-07-20T12:01:00.000Z",
            "nextRotationAt": "2026-08-19T03:15:00.000Z",
            "isLastRotationManual": false,
            "createdAt": "2026-07-20T12:00:00.000Z",
            "updatedAt": "2026-07-20T12:01:00.000Z",
            "parameters": {
                "username1": "app_user_a",
                "username2": "app_user_b",
                "rotationStatement": "ALTER USER {{username}} PASSWORD '{{password}}'"
            },
            "secretsMapping": { "username": "DB_USER", "password": "DB_PASSWORD" },
            "lastRotationMessage": null
        })
    }

    fn name_read_drift_cases() -> Vec<(&'static str, Value)> {
        let mut cases = Vec::new();
        let mut provider = rotation_fixture();
        provider["type"] = json!("mysql-credentials");
        provider["connection"]["app"] = json!("mysql");
        cases.push(("provider", provider));
        let mut name = rotation_fixture();
        name["name"] = json!("other-rotation");
        cases.push(("name", name));
        let mut environment = rotation_fixture();
        environment["environment"]["slug"] = json!("other");
        cases.push(("environment", environment));
        let mut path = rotation_fixture();
        path["folder"]["path"] = json!("/other");
        cases.push(("path", path));
        cases
    }

    fn create_drift_cases() -> Vec<(&'static str, Value)> {
        let mut cases = Vec::new();
        for (field, value) in [
            ("name", json!("other-rotation")),
            ("description", json!("Other description")),
            ("isAutoRotationEnabled", json!(false)),
            ("rotationInterval", json!(31)),
        ] {
            let mut fixture = rotation_fixture();
            fixture[field] = value;
            cases.push((field, fixture));
        }
        let mut connection = rotation_fixture();
        connection["connectionId"] = json!("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
        connection["connection"]["id"] = json!("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
        cases.push(("connection", connection));
        let mut environment = rotation_fixture();
        environment["environment"]["slug"] = json!("other");
        cases.push(("environment", environment));
        let mut path = rotation_fixture();
        path["folder"]["path"] = json!("/other");
        cases.push(("path", path));
        let mut time = rotation_fixture();
        time["rotateAtUtc"]["minutes"] = json!(16);
        cases.push(("rotateAtUtc", time));
        let mut parameters = rotation_fixture();
        parameters["parameters"]["username1"] = json!("other_user");
        cases.push(("parameters", parameters));
        let mut mapping = rotation_fixture();
        mapping["secretsMapping"]["password"] = json!("OTHER_PASSWORD");
        cases.push(("secretsMapping", mapping));
        cases
    }

    fn move_response_cases() -> Vec<(&'static str, Value, bool)> {
        let mut valid = rotation_fixture();
        valid["folder"]["path"] = json!("/moved");
        let mut wrong_environment = valid.clone();
        wrong_environment["environment"]["slug"] = json!("other");
        let mut wrong_path = valid.clone();
        wrong_path["folder"]["path"] = json!("/other");
        vec![
            ("valid", valid, true),
            ("environment", wrong_environment, false),
            ("path", wrong_path, false),
        ]
    }

    fn exact_target_drift_cases() -> Vec<(&'static str, Value)> {
        let mut id = rotation_fixture();
        id["id"] = json!("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
        let mut provider = rotation_fixture();
        provider["type"] = json!("mysql-credentials");
        provider["connection"]["app"] = json!("mysql");
        vec![("rotationId", id), ("provider", provider)]
    }

    fn update_drift_cases() -> Vec<(&'static str, Value)> {
        let mut cases = create_drift_cases();
        cases.retain(|(field, _)| {
            *field != "connection" && *field != "environment" && *field != "path"
        });
        cases
    }

    fn generated_credential_drift_cases() -> Vec<(&'static str, Value)> {
        let base = json!({
            "generatedCredentials": [
                { "username": "app_user_a", "password": "first-secret" },
                { "username": "app_user_b", "password": "second-secret" }
            ],
            "activeIndex": 1,
            "rotationId": ROTATION_ID,
            "type": "postgres-credentials"
        });
        let mut cases = Vec::new();
        let mut id = base.clone();
        id["rotationId"] = json!("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
        cases.push(("rotationId", id));
        let mut provider = base.clone();
        provider["type"] = json!("mysql-credentials");
        cases.push(("provider", provider));
        let mut active_index = base.clone();
        active_index["activeIndex"] = json!(2);
        cases.push(("activeIndex", active_index));
        let mut empty = base.clone();
        empty["generatedCredentials"] = json!([]);
        empty["activeIndex"] = json!(0);
        cases.push(("empty", empty));
        let mut too_many = base.clone();
        too_many["generatedCredentials"] = json!([
            { "username": "app_user_a", "password": "first-secret" },
            { "username": "app_user_b", "password": "second-secret" },
            { "username": "app_user_c", "password": "third-secret" }
        ]);
        cases.push(("tooMany", too_many));
        let mut missing_active = base.clone();
        missing_active["generatedCredentials"] = json!([
            { "username": "app_user_a", "password": "first-secret" }
        ]);
        cases.push(("missingActive", missing_active));
        let mut username = base.clone();
        username["generatedCredentials"][0]["username"] = json!("");
        cases.push(("username", username));
        let mut password = base;
        password["generatedCredentials"][0]["password"] = json!("p".repeat(16_385));
        cases.push(("password", password));
        cases
    }
}
