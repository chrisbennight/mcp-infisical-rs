use std::fmt;

use reqwest::Method;
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    DynamicSecret, DynamicSecretChange, DynamicSecretInputError, DynamicSecretLease,
    DynamicSecretLeaseId, DynamicSecretName, DynamicSecretProvider, DynamicSecretScope,
    DynamicSecretTtlSeconds, InfisicalClient, MutationOperation, ResourceError, SecretValue,
    certificate::is_valid_ca_certificate_bundle,
    client::{ApiVersion, Endpoint, sealed},
    dynamic_secrets::{RawDynamicSecret, RawDynamicSecretLease},
    resources::{is_bounded_text, is_uuid},
};

const MAX_SQL_HOST_BYTES: usize = 253;
const MAX_SQL_IDENTIFIER_BYTES: usize = 256;
const MAX_SQL_STATEMENT_BYTES: usize = 16_384;
const MAX_SQL_CA_BYTES: usize = 65_536;
const MAX_SQL_ROOT_PASSWORD_BYTES: usize = 16_384;
const MAX_SQL_LEASE_PASSWORD_BYTES: usize = 1_024;

/// Validation failures for the pinned SQL dynamic-secret provider contract.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SqlDynamicSecretInputError {
    /// The connection host was empty, oversized, or not a plain host name or address.
    #[error("SQL dynamic-secret host must be a plain 1 to 253 byte host name or IP address")]
    InvalidHost,
    /// The database or root username was empty, padded, or oversized.
    #[error("SQL dynamic-secret database and username must contain 1 to 256 unpadded bytes")]
    InvalidConnectionIdentifier,
    /// The port was zero.
    #[error("SQL dynamic-secret port must be between 1 and 65535")]
    InvalidPort,
    /// The root credential was empty or oversized.
    #[error("SQL dynamic-secret root password must contain 1 to 16384 bytes")]
    InvalidRootPassword,
    /// A SQL statement was empty, padded, oversized, or contained unsupported control characters.
    #[error("SQL dynamic-secret statements must contain 1 to 16384 bounded bytes")]
    InvalidStatement,
    /// A statement contained malformed or unsupported template expressions.
    #[error("SQL dynamic-secret statements may use only their documented plain placeholders")]
    InvalidStatementTemplate,
    /// Password-generation requirements were incoherent.
    #[error("SQL lease password requirements exceed the selected provider limit or are incoherent")]
    InvalidPasswordRequirements,
    /// The custom symbol alphabet was empty, unsafe, duplicated, or oversized.
    #[error("SQL lease password symbols must be 1 to 32 unique ASCII punctuation characters")]
    InvalidAllowedSymbols,
    /// The optional CA bundle was malformed, unsuitable as trust material, or out of bounds.
    #[error("SQL dynamic-secret CA bundles must contain valid bounded PEM trust anchors")]
    InvalidCaBundle,
    /// A gateway or gateway-pool identifier was not a UUID.
    #[error("SQL dynamic-secret gateway references must be UUIDs")]
    InvalidGatewayReference,
}

/// SQL driver identifiers accepted by Infisical v0.160.12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SqlDynamicSecretClient {
    #[serde(rename = "postgres")]
    Postgres,
    #[serde(rename = "mysql2")]
    MySql,
    #[serde(rename = "oracledb")]
    Oracle,
    #[serde(rename = "mssql")]
    MsSql,
    #[serde(rename = "sap-ase")]
    SapAse,
    #[serde(rename = "vertica")]
    Vertica,
}

/// Validated SQL connection coordinates and root identity.
#[derive(Debug)]
pub struct SqlDynamicSecretConnection {
    client: SqlDynamicSecretClient,
    host: String,
    port: u16,
    database: String,
    username: String,
}

impl SqlDynamicSecretConnection {
    /// Validate one SQL provider connection target.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed hosts or empty, padded, or oversized identifiers.
    pub fn new(
        client: SqlDynamicSecretClient,
        host: impl Into<String>,
        port: u16,
        database: impl Into<String>,
        username: impl Into<String>,
    ) -> Result<Self, SqlDynamicSecretInputError> {
        let host = host.into();
        let database = database.into();
        let username = username.into();
        if !sql_host_is_valid(&host) {
            return Err(SqlDynamicSecretInputError::InvalidHost);
        }
        if port == 0 {
            return Err(SqlDynamicSecretInputError::InvalidPort);
        }
        if !sql_identifier_is_valid(&database) || !sql_identifier_is_valid(&username) {
            return Err(SqlDynamicSecretInputError::InvalidConnectionIdentifier);
        }
        Ok(Self {
            client,
            host: host.to_ascii_lowercase(),
            port,
            database,
            username,
        })
    }
}

/// Locally validated creation, revocation, and optional renewal templates.
#[derive(Debug)]
pub struct SqlDynamicSecretStatements {
    creation: String,
    revocation: String,
    renewal: Option<String>,
}

impl SqlDynamicSecretStatements {
    /// Validate the three statement templates against the pinned placeholders.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, unsupported, empty, or oversized templates.
    pub fn new(
        creation: impl Into<String>,
        revocation: impl Into<String>,
        renewal: Option<String>,
    ) -> Result<Self, SqlDynamicSecretInputError> {
        let creation = creation.into();
        let revocation = revocation.into();
        validate_sql_template(
            &creation,
            &["username", "password", "expiration", "database"],
            &["username", "password"],
        )?;
        validate_sql_template(&revocation, &["username", "database"], &["username"])?;
        if let Some(value) = renewal.as_deref() {
            validate_sql_template(
                value,
                &["username", "expiration", "database"],
                &["username"],
            )?;
        }
        Ok(Self {
            creation,
            revocation,
            renewal,
        })
    }
}

/// Complete password-generation policy for provider-created SQL principals.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlDynamicSecretPasswordRequirements {
    #[serde(skip)]
    client: SqlDynamicSecretClient,
    length: u16,
    required: SqlDynamicSecretRequiredCharacters,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_symbols: Option<String>,
}

#[derive(Debug, Serialize)]
struct SqlDynamicSecretRequiredCharacters {
    lowercase: u16,
    uppercase: u16,
    digits: u16,
    symbols: u16,
}

impl SqlDynamicSecretPasswordRequirements {
    /// Validate one complete SQL lease-password generation policy.
    ///
    /// # Errors
    ///
    /// Returns an error unless the required counts fit the total length and a
    /// custom symbol alphabet contains unique ASCII punctuation.
    pub fn new(
        client: SqlDynamicSecretClient,
        length: u16,
        lowercase: u16,
        uppercase: u16,
        digits: u16,
        symbols: u16,
        allowed_symbols: Option<String>,
    ) -> Result<Self, SqlDynamicSecretInputError> {
        let required_total = lowercase
            .checked_add(uppercase)
            .and_then(|value| value.checked_add(digits))
            .and_then(|value| value.checked_add(symbols))
            .ok_or(SqlDynamicSecretInputError::InvalidPasswordRequirements)?;
        let maximum_length = if client == SqlDynamicSecretClient::Oracle {
            30
        } else {
            250
        };
        if !(1..=maximum_length).contains(&length) || required_total == 0 || required_total > length
        {
            return Err(SqlDynamicSecretInputError::InvalidPasswordRequirements);
        }
        if let Some(value) = allowed_symbols.as_deref()
            && !allowed_symbols_are_valid(value)
        {
            return Err(SqlDynamicSecretInputError::InvalidAllowedSymbols);
        }
        Ok(Self {
            client,
            length,
            required: SqlDynamicSecretRequiredCharacters {
                lowercase,
                uppercase,
                digits,
                symbols,
            },
            allowed_symbols,
        })
    }

    /// Return the pinned provider default, including Oracle's shorter limit.
    #[must_use]
    pub fn provider_default(client: SqlDynamicSecretClient) -> Self {
        Self {
            client,
            length: if client == SqlDynamicSecretClient::Oracle {
                30
            } else {
                48
            },
            required: SqlDynamicSecretRequiredCharacters {
                lowercase: 1,
                uppercase: 1,
                digits: 1,
                symbols: 0,
            },
            allowed_symbols: Some("-_.~!*".to_owned()),
        }
    }

    pub(crate) const fn client(&self) -> SqlDynamicSecretClient {
        self.client
    }
}

/// TLS settings sent with a complete SQL provider configuration.
#[derive(Debug)]
pub struct SqlDynamicSecretTls {
    ca: Option<String>,
    ssl_enabled: bool,
    ssl_reject_unauthorized: bool,
}

impl SqlDynamicSecretTls {
    /// Validate optional CA material and preserve explicit TLS booleans.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, unsafe, or invalid PEM trust anchors.
    pub fn new(
        ca: Option<String>,
        ssl_enabled: bool,
        ssl_reject_unauthorized: bool,
    ) -> Result<Self, SqlDynamicSecretInputError> {
        let ca = ca.map(validate_sql_ca_bundle).transpose()?;
        Ok(Self {
            ca,
            ssl_enabled,
            ssl_reject_unauthorized,
        })
    }
}

/// Direct, gateway, or gateway-pool routing for the provider connection.
#[derive(Debug)]
pub enum SqlDynamicSecretRoute {
    /// Connect directly from Infisical.
    Direct,
    /// Route through one exact gateway UUID.
    Gateway(String),
    /// Route through one exact gateway-pool UUID.
    GatewayPool(String),
}

impl SqlDynamicSecretRoute {
    /// Validate one gateway UUID.
    ///
    /// # Errors
    ///
    /// Returns an error unless the gateway identifier is a UUID.
    pub fn gateway(id: impl Into<String>) -> Result<Self, SqlDynamicSecretInputError> {
        let id = id.into();
        if !is_uuid(&id) {
            return Err(SqlDynamicSecretInputError::InvalidGatewayReference);
        }
        Ok(Self::Gateway(id))
    }

    /// Validate one gateway-pool UUID.
    ///
    /// # Errors
    ///
    /// Returns an error unless the gateway-pool identifier is a UUID.
    pub fn gateway_pool(id: impl Into<String>) -> Result<Self, SqlDynamicSecretInputError> {
        let id = id.into();
        if !is_uuid(&id) {
            return Err(SqlDynamicSecretInputError::InvalidGatewayReference);
        }
        Ok(Self::GatewayPool(id))
    }
}

/// Complete, validated SQL provider inputs.
#[derive(Debug)]
pub struct SqlDynamicSecretInputs {
    connection: SqlDynamicSecretConnection,
    root_password: SecretValue,
    statements: SqlDynamicSecretStatements,
    password_requirements: SqlDynamicSecretPasswordRequirements,
    tls: SqlDynamicSecretTls,
    route: SqlDynamicSecretRoute,
}

impl SqlDynamicSecretInputs {
    /// Assemble a complete provider configuration after validating the root credential.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized root password.
    pub fn new(
        connection: SqlDynamicSecretConnection,
        root_password: SecretValue,
        statements: SqlDynamicSecretStatements,
        password_requirements: SqlDynamicSecretPasswordRequirements,
        tls: SqlDynamicSecretTls,
        route: SqlDynamicSecretRoute,
    ) -> Result<Self, SqlDynamicSecretInputError> {
        if connection.client != password_requirements.client {
            return Err(SqlDynamicSecretInputError::InvalidPasswordRequirements);
        }
        if !is_bounded_text(root_password.expose_secret(), MAX_SQL_ROOT_PASSWORD_BYTES) {
            return Err(SqlDynamicSecretInputError::InvalidRootPassword);
        }
        Ok(Self {
            connection,
            root_password,
            statements,
            password_requirements,
            tls,
            route,
        })
    }
}

impl Serialize for SqlDynamicSecretInputs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut output = serializer.serialize_struct("SqlDynamicSecretInputs", 15)?;
        output.serialize_field("client", &self.connection.client)?;
        output.serialize_field("host", &self.connection.host)?;
        output.serialize_field("port", &self.connection.port)?;
        output.serialize_field("database", &self.connection.database)?;
        output.serialize_field("username", &self.connection.username)?;
        output.serialize_field("password", self.root_password.expose_secret())?;
        output.serialize_field("passwordRequirements", &self.password_requirements)?;
        output.serialize_field("creationStatement", &self.statements.creation)?;
        output.serialize_field("revocationStatement", &self.statements.revocation)?;
        output.serialize_field(
            "renewStatement",
            self.statements.renewal.as_deref().unwrap_or(""),
        )?;
        output.serialize_field("ca", self.tls.ca.as_deref().unwrap_or(""))?;
        output.serialize_field("sslEnabled", &self.tls.ssl_enabled)?;
        output.serialize_field("sslRejectUnauthorized", &self.tls.ssl_reject_unauthorized)?;
        let (gateway_id, gateway_pool_id) = match &self.route {
            SqlDynamicSecretRoute::Direct => (None, None),
            SqlDynamicSecretRoute::Gateway(id) => (Some(id.as_str()), None),
            SqlDynamicSecretRoute::GatewayPool(id) => (None, Some(id.as_str())),
        };
        output.serialize_field("gatewayId", &gateway_id)?;
        output.serialize_field("gatewayPoolId", &gateway_pool_id)?;
        output.end()
    }
}

/// Complete SQL dynamic-secret creation request.
#[derive(Debug)]
pub struct SqlDynamicSecretCreation {
    name: DynamicSecretName,
    default_ttl: DynamicSecretTtlSeconds,
    max_ttl: Option<DynamicSecretTtlSeconds>,
    inputs: SqlDynamicSecretInputs,
}

impl SqlDynamicSecretCreation {
    /// Construct a coherent complete SQL dynamic-secret creation.
    ///
    /// # Errors
    ///
    /// Returns an error when the optional maximum is shorter than the default.
    pub fn new(
        name: DynamicSecretName,
        default_ttl: DynamicSecretTtlSeconds,
        max_ttl: Option<DynamicSecretTtlSeconds>,
        inputs: SqlDynamicSecretInputs,
    ) -> Result<Self, DynamicSecretInputError> {
        DynamicSecretChange::lifetime(default_ttl, max_ttl)?;
        Ok(Self {
            name,
            default_ttl,
            max_ttl,
            inputs,
        })
    }
}

/// One-time SQL lease credentials plus validated value-free metadata.
pub struct CreatedSqlDynamicSecretLease {
    /// Lease metadata safe for subsequent reads.
    pub lease: DynamicSecretLease,
    /// Owning SQL dynamic-secret metadata.
    pub dynamic_secret: DynamicSecret,
    /// Provider-created database username.
    pub username: String,
    /// Provider-created database password, revealed only at the MCP output boundary.
    pub password: SecretValue,
}

impl fmt::Debug for CreatedSqlDynamicSecretLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedSqlDynamicSecretLease")
            .field("lease", &self.lease)
            .field("dynamic_secret", &self.dynamic_secret)
            .field("username", &self.username)
            .field("password", &self.password)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSqlDynamicSecretWire {
    #[serde(flatten)]
    scope: SqlDynamicSecretScopeWire,
    name: DynamicSecretName,
    #[serde(rename = "defaultTTL")]
    default_ttl: String,
    #[serde(rename = "maxTTL")]
    max_ttl: Option<String>,
    provider: SqlDynamicSecretProviderWire,
}

#[derive(Serialize)]
struct SqlDynamicSecretProviderWire {
    #[serde(rename = "type")]
    provider_type: &'static str,
    inputs: SqlDynamicSecretInputs,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSqlDynamicSecretLeaseWire {
    dynamic_secret_name: DynamicSecretName,
    #[serde(flatten)]
    scope: SqlDynamicSecretScopeWire,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SqlDynamicSecretScopeWire {
    project_slug: String,
    path: String,
    environment_slug: String,
}

impl From<&DynamicSecretScope> for SqlDynamicSecretScopeWire {
    fn from(scope: &DynamicSecretScope) -> Self {
        Self {
            project_slug: scope.project().as_str().to_owned(),
            path: scope.path().as_str().to_owned(),
            environment_slug: scope.environment().as_str().to_owned(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SqlDynamicSecretResponse {
    dynamic_secret: RawDynamicSecret,
}

struct SensitiveJsonValue(serde_json::Value);

#[cfg(test)]
std::thread_local! {
    static SENSITIVE_JSON_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl SensitiveJsonValue {
    fn owned_sql_lease_cleanup_target(
        &self,
        expected_dynamic_secret_id: &str,
        expected_dynamic_secret_name: &str,
    ) -> Option<DynamicSecretLeaseId> {
        let lease = self.0.get("lease")?.as_object()?;
        let lease_owner = lease.get("dynamicSecretId")?.as_str()?;
        let lease_id = DynamicSecretLeaseId::new(lease.get("id")?.as_str()?.to_owned()).ok()?;
        if lease_owner == expected_dynamic_secret_id {
            return Some(lease_id);
        }
        let dynamic_secret = self.0.get("dynamicSecret")?.as_object()?;
        let returned_id = dynamic_secret.get("id")?.as_str()?;
        if !is_uuid(returned_id)
            || returned_id != lease_owner
            || dynamic_secret.get("name")?.as_str()? != expected_dynamic_secret_name
            || dynamic_secret.get("type")?.as_str()? != "sql-database"
        {
            return None;
        }
        Some(lease_id)
    }

    fn sql_lease_response_parts(&self) -> Result<(RawDynamicSecretLease, RawDynamicSecret), ()> {
        let object = self.0.as_object().ok_or(())?;
        let lease =
            RawDynamicSecretLease::deserialize(object.get("lease").ok_or(())?).map_err(|_| ())?;
        let dynamic_secret = RawDynamicSecret::deserialize(object.get("dynamicSecret").ok_or(())?)
            .map_err(|_| ())?;
        Ok((lease, dynamic_secret))
    }

    fn sql_credentials(&self) -> Result<SqlDynamicSecretCredentialsWire, ()> {
        let object = self
            .0
            .get("data")
            .and_then(serde_json::Value::as_object)
            .ok_or(())?;
        if object.len() != 2 {
            return Err(());
        }
        let username = object
            .get("DB_USERNAME")
            .and_then(serde_json::Value::as_str)
            .ok_or(())?;
        let password = object
            .get("DB_PASSWORD")
            .and_then(serde_json::Value::as_str)
            .ok_or(())?;
        Ok(SqlDynamicSecretCredentialsWire {
            username: username.to_owned(),
            password: SecretValue::new(password.to_owned()),
        })
    }
}

impl Drop for SensitiveJsonValue {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
        #[cfg(test)]
        SENSITIVE_JSON_DROPS.with(|drops| drops.set(drops.get() + 1));
    }
}

struct SqlDynamicSecretCredentialsWire {
    username: String,
    password: SecretValue,
}

struct CreateSqlDynamicSecret;
impl sealed::Sealed for CreateSqlDynamicSecret {}
impl MutationOperation for CreateSqlDynamicSecret {
    type Input = CreateSqlDynamicSecretWire;
    type Output = SqlDynamicSecretResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "dynamic-secrets")
    }
}

struct CreateSqlDynamicSecretLease;
impl sealed::Sealed for CreateSqlDynamicSecretLease {}
impl MutationOperation for CreateSqlDynamicSecretLease {
    type Input = CreateSqlDynamicSecretLeaseWire;
    type Output = serde_json::Value;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "dynamic-secrets/leases")
    }
}

impl InfisicalClient {
    /// Create one SQL dynamic-secret configuration after complete local validation.
    ///
    /// # Errors
    ///
    /// Returns a typed client or response-contract error. Infisical probes the
    /// provider connection, and the mutation is sent exactly once.
    pub async fn create_sql_dynamic_secret(
        &self,
        scope: &DynamicSecretScope,
        creation: SqlDynamicSecretCreation,
    ) -> Result<DynamicSecret, ResourceError> {
        let expected_name = creation.name.as_str().to_owned();
        let expected_default_ttl = creation.default_ttl.wire();
        let expected_max_ttl = creation.max_ttl.map(DynamicSecretTtlSeconds::wire);
        let input = CreateSqlDynamicSecretWire {
            scope: scope.into(),
            name: creation.name,
            default_ttl: expected_default_ttl.clone(),
            max_ttl: expected_max_ttl.clone(),
            provider: SqlDynamicSecretProviderWire {
                provider_type: "sql-database",
                inputs: creation.inputs,
            },
        };
        let response = self
            .execute_mutation::<CreateSqlDynamicSecret>(&input)
            .await?;
        let dynamic_secret = response.dynamic_secret.into_validated()?;
        if dynamic_secret.name != expected_name
            || dynamic_secret.provider != DynamicSecretProvider::SqlDatabase
            || dynamic_secret.default_ttl != expected_default_ttl
            || dynamic_secret.max_ttl != expected_max_ttl
        {
            return Err(ResourceError::InvalidDynamicSecretResponse);
        }
        Ok(dynamic_secret)
    }

    /// Create one SQL lease and return its credentials exactly once.
    ///
    /// # Errors
    ///
    /// Returns a typed client or response-contract error. An observable exact
    /// read proves the stored provider before the single creation attempt. A
    /// malformed result owned by that configuration is revoked before the
    /// contract error is returned; an unrelated returned lease is never touched.
    pub async fn create_sql_dynamic_secret_lease(
        &self,
        scope: &DynamicSecretScope,
        name: &DynamicSecretName,
        ttl: Option<DynamicSecretTtlSeconds>,
    ) -> Result<CreatedSqlDynamicSecretLease, ResourceError> {
        let expected_dynamic_secret = self.get_dynamic_secret(scope, name).await?;
        if expected_dynamic_secret.provider != DynamicSecretProvider::SqlDatabase {
            return Err(ResourceError::InvalidDynamicSecretResponse);
        }
        let expected_dynamic_secret_id = expected_dynamic_secret.id;
        let response = SensitiveJsonValue(
            self.execute_mutation::<CreateSqlDynamicSecretLease>(
                &CreateSqlDynamicSecretLeaseWire {
                    dynamic_secret_name: name.clone(),
                    scope: scope.into(),
                    ttl: ttl.map(DynamicSecretTtlSeconds::wire),
                },
            )
            .await?,
        );
        let cleanup_target =
            response.owned_sql_lease_cleanup_target(&expected_dynamic_secret_id, name.as_str());
        let Ok((lease, dynamic_secret)) = response.sql_lease_response_parts() else {
            if let Some(lease_id) = cleanup_target.as_ref() {
                self.revoke_invalid_sql_lease(scope, lease_id).await?;
            }
            return Err(ResourceError::InvalidDynamicSecretLeaseResponse);
        };
        let Ok(lease) = lease.into_validated(None) else {
            if let Some(lease_id) = cleanup_target.as_ref() {
                self.revoke_invalid_sql_lease(scope, lease_id).await?;
            }
            return Err(ResourceError::InvalidDynamicSecretLeaseResponse);
        };
        if lease.dynamic_secret_id != expected_dynamic_secret_id {
            if let Some(lease_id) = cleanup_target.as_ref() {
                self.revoke_invalid_sql_lease(scope, lease_id).await?;
            }
            return Err(ResourceError::InvalidDynamicSecretLeaseResponse);
        }
        let cleanup_target =
            cleanup_target.ok_or(ResourceError::InvalidDynamicSecretLeaseResponse)?;
        let Ok(dynamic_secret) = dynamic_secret.into_validated() else {
            self.revoke_invalid_sql_lease(scope, &cleanup_target)
                .await?;
            return Err(ResourceError::InvalidDynamicSecretLeaseResponse);
        };
        if dynamic_secret.name != name.as_str()
            || dynamic_secret.provider != DynamicSecretProvider::SqlDatabase
            || dynamic_secret.id != expected_dynamic_secret_id
        {
            self.revoke_invalid_sql_lease(scope, &cleanup_target)
                .await?;
            return Err(ResourceError::InvalidDynamicSecretLeaseResponse);
        }
        let Ok(credentials) = response.sql_credentials() else {
            self.revoke_invalid_sql_lease(scope, &cleanup_target)
                .await?;
            return Err(ResourceError::InvalidDynamicSecretLeaseResponse);
        };
        if credentials.username != lease.external_entity_id
            || !is_bounded_text(&credentials.username, MAX_SQL_IDENTIFIER_BYTES)
            || !is_bounded_text(
                credentials.password.expose_secret(),
                MAX_SQL_LEASE_PASSWORD_BYTES,
            )
        {
            self.revoke_invalid_sql_lease(scope, &cleanup_target)
                .await?;
            return Err(ResourceError::InvalidDynamicSecretLeaseResponse);
        }
        Ok(CreatedSqlDynamicSecretLease {
            lease,
            dynamic_secret,
            username: credentials.username,
            password: credentials.password,
        })
    }

    async fn revoke_invalid_sql_lease(
        &self,
        scope: &DynamicSecretScope,
        lease_id: &DynamicSecretLeaseId,
    ) -> Result<(), ResourceError> {
        self.revoke_dynamic_secret_lease(scope, lease_id, false, true)
            .await?;
        Ok(())
    }
}

fn sql_host_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SQL_HOST_BYTES
        && value.is_ascii()
        && !value.contains('_')
        && ServerName::try_from(value).is_ok()
}

fn sql_identifier_is_valid(value: &str) -> bool {
    is_bounded_text(value, MAX_SQL_IDENTIFIER_BYTES) && value.trim() == value
}

fn bounded_multiline(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn sql_ca_raw_text_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SQL_CA_BYTES
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn zeroize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(value) => value.zeroize(),
        serde_json::Value::Array(values) => values.iter_mut().for_each(zeroize_json_value),
        serde_json::Value::Object(values) => {
            let values = std::mem::take(values);
            for (mut key, mut value) in values {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn validate_sql_ca_bundle(mut value: String) -> Result<String, SqlDynamicSecretInputError> {
    if !sql_ca_raw_text_is_valid(&value) {
        return Err(SqlDynamicSecretInputError::InvalidCaBundle);
    }
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') {
        value.pop();
    }
    if !bounded_multiline(&value, MAX_SQL_CA_BYTES) || !is_valid_ca_certificate_bundle(&value) {
        return Err(SqlDynamicSecretInputError::InvalidCaBundle);
    }
    Ok(value)
}

fn allowed_symbols_are_valid(value: &str) -> bool {
    if value.is_empty() || !value.is_ascii() {
        return false;
    }
    let mut seen = [false; 128];
    for byte in value.bytes() {
        if !byte.is_ascii_graphic() || byte.is_ascii_alphanumeric() || seen[usize::from(byte)] {
            return false;
        }
        seen[usize::from(byte)] = true;
    }
    true
}

pub(crate) fn validate_sql_template(
    value: &str,
    allowed: &[&str],
    required: &[&str],
) -> Result<(), SqlDynamicSecretInputError> {
    if !bounded_multiline(value, MAX_SQL_STATEMENT_BYTES) {
        return Err(SqlDynamicSecretInputError::InvalidStatement);
    }
    let mut remainder = value;
    let mut observed = Vec::new();
    while let Some(start) = remainder.find("{{") {
        if remainder[..start].contains(['{', '}']) {
            return Err(SqlDynamicSecretInputError::InvalidStatementTemplate);
        }
        let after_start = &remainder[start + 2..];
        let Some(end) = after_start.find("}}") else {
            return Err(SqlDynamicSecretInputError::InvalidStatementTemplate);
        };
        let expression = after_start[..end].trim();
        if !allowed.contains(&expression) {
            return Err(SqlDynamicSecretInputError::InvalidStatementTemplate);
        }
        observed.push(expression);
        remainder = &after_start[end + 2..];
    }
    if remainder.contains(['{', '}']) || required.iter().any(|name| !observed.contains(name)) {
        return Err(SqlDynamicSecretInputError::InvalidStatementTemplate);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path, query_param},
    };

    use super::{
        MAX_SQL_CA_BYTES, MAX_SQL_IDENTIFIER_BYTES, SENSITIVE_JSON_DROPS, SensitiveJsonValue,
        SqlDynamicSecretClient, SqlDynamicSecretConnection, SqlDynamicSecretCreation,
        SqlDynamicSecretInputError, SqlDynamicSecretInputs, SqlDynamicSecretPasswordRequirements,
        SqlDynamicSecretRoute, SqlDynamicSecretStatements, SqlDynamicSecretTls,
        sql_ca_raw_text_is_valid, zeroize_json_value,
    };
    use crate::{
        DynamicSecretInputError, DynamicSecretName, DynamicSecretScope, DynamicSecretTtlSeconds,
        EnvironmentSlug, InfisicalClient, ProjectSlug, ResourceError, SecretPath, SecretValue,
        test_support::{CA_CERT, mount_login, settings},
    };

    const CONFIG_ID: &str = "0b30c3c2-6a13-485f-9775-9768d8d2708a";
    const FOLDER_ID: &str = "573a2b87-7f44-4fb4-81ca-851679a7419f";
    const LEASE_ID: &str = "4d40b103-d45a-44ca-a95f-57d7361a4d2a";
    const GATEWAY_ID: &str = "04790815-b0c3-44e8-83a6-2532e953fd33";

    fn scope() -> DynamicSecretScope {
        DynamicSecretScope::new(
            ProjectSlug::new("platform").unwrap(),
            EnvironmentSlug::new("prod").unwrap(),
            SecretPath::new("/database").unwrap(),
        )
    }

    fn statements() -> SqlDynamicSecretStatements {
        SqlDynamicSecretStatements::new(
            "CREATE USER {{username}} WITH PASSWORD '{{password}}'",
            "DROP USER {{username}}",
            Some("ALTER USER {{username}} VALID UNTIL '{{expiration}}'".to_owned()),
        )
        .unwrap()
    }

    fn inputs(password: &str, route: SqlDynamicSecretRoute) -> SqlDynamicSecretInputs {
        let client = SqlDynamicSecretClient::Postgres;
        SqlDynamicSecretInputs::new(
            SqlDynamicSecretConnection::new(client, "db.internal", 5432, "app", "root").unwrap(),
            SecretValue::new(password),
            statements(),
            SqlDynamicSecretPasswordRequirements::provider_default(client),
            SqlDynamicSecretTls::new(None, false, true).unwrap(),
            route,
        )
        .unwrap()
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
            "usernameTemplate": null,
            "metadata": { "secretValue": "must-not-escape" },
            "inputs": { "password": "must-not-escape" }
        })
    }

    fn lease_fixture() -> Value {
        json!({
            "id": LEASE_ID,
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

    fn provider_inputs_body(password: &str, gateway_id: Option<&str>) -> Value {
        json!({
            "client": "postgres",
            "host": "db.internal",
            "port": 5432,
            "database": "app",
            "username": "root",
            "password": password,
            "passwordRequirements": {
                "length": 48,
                "required": {
                    "lowercase": 1,
                    "uppercase": 1,
                    "digits": 1,
                    "symbols": 0
                },
                "allowedSymbols": "-_.~!*"
            },
            "creationStatement": "CREATE USER {{username}} WITH PASSWORD '{{password}}'",
            "revocationStatement": "DROP USER {{username}}",
            "renewStatement": "ALTER USER {{username}} VALID UNTIL '{{expiration}}'",
            "ca": "",
            "sslEnabled": false,
            "sslRejectUnauthorized": true,
            "gatewayId": gateway_id,
            "gatewayPoolId": null
        })
    }

    async fn mount_sql_lease_creation(server: &MockServer) {
        mount_sql_lease_preflight(server, dynamic_secret_fixture("database-user"), 1).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/dynamic-secrets/leases"))
            .and(header("authorization", "Bearer sql-token"))
            .and(body_json(json!({
                "dynamicSecretName": "database-user",
                "projectSlug": "platform",
                "path": "/database",
                "environmentSlug": "prod",
                "ttl": "7200s"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease": lease_fixture(),
                "dynamicSecret": dynamic_secret_fixture("database-user"),
                "data": {
                    "DB_USERNAME": "svc-lease-user",
                    "DB_PASSWORD": "lease-password-canary"
                }
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_sql_lease_preflight(
        server: &MockServer,
        dynamic_secret: Value,
        expected_calls: u64,
    ) {
        Mock::given(method("GET"))
            .and(path("/api/v1/dynamic-secrets/database-user"))
            .and(header("authorization", "Bearer sql-token"))
            .and(query_param("projectSlug", "platform"))
            .and(query_param("environmentSlug", "prod"))
            .and(query_param("path", "/database"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dynamicSecret": dynamic_secret
            })))
            .expect(expected_calls)
            .mount(server)
            .await;
    }

    async fn assert_sql_creation_response_rejected(dynamic_secret: Value) {
        let server = MockServer::start().await;
        mount_login(&server, "sql-token").await;
        Mock::given(method("POST"))
            .and(path("/api/v1/dynamic-secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dynamicSecret": dynamic_secret
            })))
            .expect(1)
            .mount(&server)
            .await;
        let result = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_sql_dynamic_secret(
                &scope(),
                SqlDynamicSecretCreation::new(
                    DynamicSecretName::new("database-user").unwrap(),
                    DynamicSecretTtlSeconds::new(3_600).unwrap(),
                    Some(DynamicSecretTtlSeconds::new(86_400).unwrap()),
                    inputs("root-canary", SqlDynamicSecretRoute::Direct),
                )
                .unwrap(),
            )
            .await;
        assert_eq!(
            result.unwrap_err(),
            ResourceError::InvalidDynamicSecretResponse
        );
    }

    async fn assert_sql_lease_response_rejected(
        lease: Value,
        dynamic_secret: Value,
        username: String,
        password: String,
        cleanup_expected: bool,
    ) {
        let server = MockServer::start().await;
        mount_login(&server, "sql-token").await;
        mount_sql_lease_preflight(&server, dynamic_secret_fixture("database-user"), 1).await;
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/dynamic-secrets/leases/{LEASE_ID}")))
            .and(header("authorization", "Bearer sql-token"))
            .and(body_json(json!({
                "projectSlug": "platform",
                "environmentSlug": "prod",
                "path": "/database",
                "isForced": false
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease": lease_fixture()
            })))
            .expect(u64::from(cleanup_expected))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/dynamic-secrets/leases"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease": lease,
                "dynamicSecret": dynamic_secret,
                "data": { "DB_USERNAME": username, "DB_PASSWORD": password }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let result = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_sql_dynamic_secret_lease(
                &scope(),
                &DynamicSecretName::new("database-user").unwrap(),
                None,
            )
            .await;
        assert_eq!(
            result.unwrap_err(),
            ResourceError::InvalidDynamicSecretLeaseResponse
        );
    }

    fn lease_rejection_case(
        lease: Value,
        dynamic_secret: Value,
        cleanup_expected: bool,
    ) -> (Value, Value, String, String, bool) {
        (
            lease,
            dynamic_secret,
            "svc-lease-user".to_owned(),
            "lease-password-canary".to_owned(),
            cleanup_expected,
        )
    }

    #[test]
    fn sql_hosts_require_dns_names_or_ip_addresses() {
        for valid_host in ["db.internal", "localhost", "127.0.0.1", "2001:db8::1"] {
            assert!(
                SqlDynamicSecretConnection::new(
                    SqlDynamicSecretClient::Postgres,
                    valid_host,
                    5432,
                    "app",
                    "root",
                )
                .is_ok()
            );
        }
        for invalid_host in [
            "https://db.internal",
            "-",
            "[]",
            "...",
            "db_internal",
            "999.999.999.999",
            "[::1]",
        ] {
            assert_eq!(
                SqlDynamicSecretConnection::new(
                    SqlDynamicSecretClient::Postgres,
                    invalid_host,
                    5432,
                    "app",
                    "root",
                )
                .unwrap_err(),
                SqlDynamicSecretInputError::InvalidHost
            );
        }
    }

    #[test]
    fn sql_connection_and_statements_enforce_each_independent_boundary() {
        assert_eq!(
            SqlDynamicSecretConnection::new(
                SqlDynamicSecretClient::Postgres,
                "db.internal",
                0,
                "app",
                "root",
            )
            .unwrap_err(),
            SqlDynamicSecretInputError::InvalidPort
        );
        assert_eq!(
            SqlDynamicSecretConnection::new(
                SqlDynamicSecretClient::Postgres,
                "db.internal",
                5432,
                " app",
                "root",
            )
            .unwrap_err(),
            SqlDynamicSecretInputError::InvalidConnectionIdentifier
        );
        assert_eq!(
            SqlDynamicSecretStatements::new(
                "CREATE USER {{username}}",
                "DROP USER {{username}}",
                None,
            )
            .unwrap_err(),
            SqlDynamicSecretInputError::InvalidStatementTemplate
        );
        assert_eq!(
            SqlDynamicSecretStatements::new(
                "CREATE USER {{username}} WITH PASSWORD '{{password}}'",
                "DROP USER {{admin}}",
                None,
            )
            .unwrap_err(),
            SqlDynamicSecretInputError::InvalidStatementTemplate
        );
        assert_eq!(
            SqlDynamicSecretStatements::new(
                "CREATE USER {{username}} WITH PASSWORD '{{password}}'\u{7}",
                "DROP USER {{username}}",
                None,
            )
            .unwrap_err(),
            SqlDynamicSecretInputError::InvalidStatement
        );
        for invalid_creation in [
            "CREATE USER {{ }} WITH PASSWORD '{{password}}'",
            "CREATE USER {{{{username}}}} WITH PASSWORD '{{password}}'",
        ] {
            assert_eq!(
                SqlDynamicSecretStatements::new(invalid_creation, "DROP USER {{username}}", None,)
                    .unwrap_err(),
                SqlDynamicSecretInputError::InvalidStatementTemplate
            );
        }
    }

    #[test]
    fn sql_password_symbol_alphabet_enforces_each_independent_boundary() {
        let all_ascii_punctuation: String = (b'!'..=b'~')
            .filter(|byte| !byte.is_ascii_alphanumeric())
            .map(char::from)
            .collect();
        assert_eq!(all_ascii_punctuation.len(), 32);
        assert!(
            SqlDynamicSecretPasswordRequirements::new(
                SqlDynamicSecretClient::Postgres,
                36,
                1,
                1,
                1,
                32,
                Some(all_ascii_punctuation),
            )
            .is_ok()
        );
        assert!(
            SqlDynamicSecretPasswordRequirements::new(
                SqlDynamicSecretClient::Postgres,
                12,
                1,
                1,
                1,
                1,
                Some("!".to_owned()),
            )
            .is_ok()
        );
        for invalid_symbols in ["", "A", " ", "!!", "é"] {
            assert_eq!(
                SqlDynamicSecretPasswordRequirements::new(
                    SqlDynamicSecretClient::Postgres,
                    12,
                    1,
                    1,
                    1,
                    1,
                    Some(invalid_symbols.to_owned()),
                )
                .unwrap_err(),
                SqlDynamicSecretInputError::InvalidAllowedSymbols
            );
        }
    }

    #[test]
    fn sql_password_policy_cannot_cross_driver_boundaries() {
        let postgres_policy = SqlDynamicSecretPasswordRequirements::new(
            SqlDynamicSecretClient::Postgres,
            31,
            1,
            1,
            1,
            0,
            None,
        )
        .unwrap();
        let result = SqlDynamicSecretInputs::new(
            SqlDynamicSecretConnection::new(
                SqlDynamicSecretClient::Oracle,
                "db.internal",
                1521,
                "app",
                "root",
            )
            .unwrap(),
            SecretValue::new("root-canary"),
            statements(),
            postgres_policy,
            SqlDynamicSecretTls::new(None, false, true).unwrap(),
            SqlDynamicSecretRoute::Direct,
        );
        assert_eq!(
            result.unwrap_err(),
            SqlDynamicSecretInputError::InvalidPasswordRequirements
        );
    }

    #[test]
    fn sql_ca_bundles_require_valid_trust_anchors() {
        for valid_ca in [
            CA_CERT.to_owned(),
            format!("{CA_CERT}\n"),
            format!("{CA_CERT}\r\n"),
        ] {
            let tls = SqlDynamicSecretTls::new(Some(valid_ca), true, true).unwrap();
            assert_eq!(tls.ca.as_deref(), Some(CA_CERT));
        }
        for invalid_ca in [
            String::new(),
            "not a PEM certificate".to_owned(),
            "-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----".to_owned(),
            "-----BEGIN PRIVATE KEY-----\nY2VydA==\n-----END PRIVATE KEY-----".to_owned(),
            format!("{CA_CERT} "),
            format!("{CA_CERT}\n\n"),
            "x".repeat(MAX_SQL_CA_BYTES + 1),
        ] {
            assert_eq!(
                SqlDynamicSecretTls::new(Some(invalid_ca), true, true).unwrap_err(),
                SqlDynamicSecretInputError::InvalidCaBundle
            );
        }
    }

    #[test]
    fn sql_ca_raw_text_enforces_each_independent_boundary() {
        assert!(sql_ca_raw_text_is_valid(&"A".repeat(MAX_SQL_CA_BYTES)));
        for invalid_ca in [
            String::new(),
            "A".repeat(MAX_SQL_CA_BYTES + 1),
            "valid-prefix\0valid-suffix".to_owned(),
        ] {
            assert!(!sql_ca_raw_text_is_valid(&invalid_ca));
        }
    }

    #[test]
    fn sql_credential_json_requires_exact_string_fields_and_zeroizes_raw_values() {
        let drops_before = SENSITIVE_JSON_DROPS.with(std::cell::Cell::get);
        drop(SensitiveJsonValue(json!({
            "DB_PASSWORD": "drop-path-canary"
        })));
        let drops_after = SENSITIVE_JSON_DROPS.with(std::cell::Cell::get);
        assert_eq!(drops_after, drops_before + 1);

        let response = SensitiveJsonValue(json!({
            "data": {
                "DB_USERNAME": "svc-lease-user",
                "DB_PASSWORD": "lease-password-canary"
            }
        }));
        let credentials = response.sql_credentials().unwrap();
        assert_eq!(credentials.username, "svc-lease-user");
        assert_eq!(
            credentials.password.expose_secret(),
            "lease-password-canary"
        );

        for invalid_data in [
            json!({ "DB_USERNAME": "svc-lease-user" }),
            json!({ "DB_PASSWORD": "lease-password-canary" }),
            json!({
                "DB_USERNAME": "svc-lease-user",
                "DB_PASSWORD": "lease-password-canary",
                "extra": "must-not-survive"
            }),
            json!({ "DB_USERNAME": 7, "DB_PASSWORD": "lease-password-canary" }),
            json!({ "DB_USERNAME": "svc-lease-user", "DB_PASSWORD": 7 }),
            json!(["lease-password-canary"]),
        ] {
            assert!(
                SensitiveJsonValue(json!({ "data": invalid_data }))
                    .sql_credentials()
                    .is_err()
            );
        }

        let mut raw = json!([
            "top-level-canary",
            { "secret-key-canary": "nested-canary" },
            ["array-canary"]
        ]);
        zeroize_json_value(&mut raw);
        assert_eq!(raw, json!(["", {}, [""]]));
    }

    #[test]
    fn sql_credentials_routing_and_lifetime_enforce_each_independent_boundary() {
        assert_eq!(
            SqlDynamicSecretPasswordRequirements::new(
                SqlDynamicSecretClient::Postgres,
                8,
                3,
                3,
                3,
                0,
                None,
            )
            .unwrap_err(),
            SqlDynamicSecretInputError::InvalidPasswordRequirements
        );
        assert_eq!(
            SqlDynamicSecretPasswordRequirements::new(
                SqlDynamicSecretClient::Postgres,
                12,
                1,
                1,
                1,
                1,
                Some("!!".to_owned()),
            )
            .unwrap_err(),
            SqlDynamicSecretInputError::InvalidAllowedSymbols
        );
        assert!(
            SqlDynamicSecretPasswordRequirements::new(
                SqlDynamicSecretClient::Oracle,
                30,
                1,
                1,
                1,
                0,
                None,
            )
            .is_ok()
        );
        assert_eq!(
            SqlDynamicSecretPasswordRequirements::new(
                SqlDynamicSecretClient::Oracle,
                31,
                1,
                1,
                1,
                0,
                None,
            )
            .unwrap_err(),
            SqlDynamicSecretInputError::InvalidPasswordRequirements
        );
        assert_eq!(
            SqlDynamicSecretRoute::gateway("not-a-uuid").unwrap_err(),
            SqlDynamicSecretInputError::InvalidGatewayReference
        );
        assert!(SqlDynamicSecretRoute::gateway_pool(GATEWAY_ID).is_ok());
        assert_eq!(
            SqlDynamicSecretRoute::gateway_pool("not-a-uuid").unwrap_err(),
            SqlDynamicSecretInputError::InvalidGatewayReference
        );
        let invalid_password = SqlDynamicSecretInputs::new(
            SqlDynamicSecretConnection::new(
                SqlDynamicSecretClient::Postgres,
                "db.internal",
                5432,
                "app",
                "root",
            )
            .unwrap(),
            SecretValue::new(""),
            statements(),
            SqlDynamicSecretPasswordRequirements::provider_default(
                SqlDynamicSecretClient::Postgres,
            ),
            SqlDynamicSecretTls::new(None, false, true).unwrap(),
            SqlDynamicSecretRoute::Direct,
        )
        .unwrap_err();
        assert_eq!(
            invalid_password,
            SqlDynamicSecretInputError::InvalidRootPassword
        );
        assert_eq!(
            SqlDynamicSecretCreation::new(
                DynamicSecretName::new("database-user").unwrap(),
                DynamicSecretTtlSeconds::new(7_200).unwrap(),
                Some(DynamicSecretTtlSeconds::new(3_600).unwrap()),
                inputs("root-canary", SqlDynamicSecretRoute::Direct),
            )
            .unwrap_err(),
            DynamicSecretInputError::InvalidTtlOrder
        );
        assert!(
            !format!("{:?}", inputs("root-canary", SqlDynamicSecretRoute::Direct))
                .contains("root-canary")
        );
    }

    #[tokio::test]
    async fn sql_configuration_and_lease_mutations_use_exact_non_replaying_contracts() {
        let server = MockServer::start().await;
        mount_login(&server, "sql-token").await;
        mount_sql_lease_creation(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/dynamic-secrets"))
            .and(header("authorization", "Bearer sql-token"))
            .and(body_json(json!({
                "projectSlug": "platform",
                "path": "/database",
                "environmentSlug": "prod",
                "name": "database-user",
                "defaultTTL": "3600s",
                "maxTTL": "86400s",
                "provider": {
                    "type": "sql-database",
                    "inputs": provider_inputs_body("create-root-canary", None)
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dynamicSecret": dynamic_secret_fixture("database-user")
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let name = DynamicSecretName::new("database-user").unwrap();
        let created = client
            .create_sql_dynamic_secret(
                &scope(),
                SqlDynamicSecretCreation::new(
                    name.clone(),
                    DynamicSecretTtlSeconds::new(3_600).unwrap(),
                    Some(DynamicSecretTtlSeconds::new(86_400).unwrap()),
                    inputs("create-root-canary", SqlDynamicSecretRoute::Direct),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let lease = client
            .create_sql_dynamic_secret_lease(
                &scope(),
                &name,
                Some(DynamicSecretTtlSeconds::new(7_200).unwrap()),
            )
            .await
            .unwrap();

        assert_eq!(created.name, "database-user");
        assert_eq!(lease.username, "svc-lease-user");
        assert_eq!(lease.password.expose_secret(), "lease-password-canary");
        let debug = format!("{lease:?}");
        assert!(debug.starts_with("CreatedSqlDynamicSecretLease {"));
        assert!(debug.contains("svc-lease-user"));
        assert!(debug.contains("SecretValue([REDACTED])"));
        assert!(!debug.contains("lease-password-canary"));
        assert!(!debug.contains("create-root-canary"));
    }

    #[tokio::test]
    async fn sql_configuration_responses_must_match_each_requested_invariant() {
        let mut wrong_name = dynamic_secret_fixture("different-name");
        let mut wrong_provider = dynamic_secret_fixture("database-user");
        wrong_provider["type"] = json!("clickhouse");
        let mut wrong_default_ttl = dynamic_secret_fixture("database-user");
        wrong_default_ttl["defaultTTL"] = json!("7200s");
        let mut wrong_max_ttl = dynamic_secret_fixture("database-user");
        wrong_max_ttl["maxTTL"] = json!("172800s");
        for response in [
            wrong_name.take(),
            wrong_provider,
            wrong_default_ttl,
            wrong_max_ttl,
        ] {
            assert_sql_creation_response_rejected(response).await;
        }
    }

    #[tokio::test]
    async fn sql_lease_rejects_a_non_sql_target_before_provider_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "sql-token").await;
        let mut non_sql = dynamic_secret_fixture("database-user");
        non_sql["type"] = json!("clickhouse");
        mount_sql_lease_preflight(&server, non_sql, 1).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/dynamic-secrets/leases"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let result = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_sql_dynamic_secret_lease(
                &scope(),
                &DynamicSecretName::new("database-user").unwrap(),
                None,
            )
            .await;
        assert_eq!(
            result.unwrap_err(),
            ResourceError::InvalidDynamicSecretResponse
        );
    }

    #[tokio::test]
    async fn sql_lease_compensation_failure_is_returned_loudly() {
        let server = MockServer::start().await;
        mount_login(&server, "sql-token").await;
        mount_sql_lease_preflight(&server, dynamic_secret_fixture("database-user"), 1).await;
        let mut wrong_provider = dynamic_secret_fixture("database-user");
        wrong_provider["type"] = json!("clickhouse");
        Mock::given(method("POST"))
            .and(path("/api/v1/dynamic-secrets/leases"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease": lease_fixture(),
                "dynamicSecret": wrong_provider,
                "data": { "providerSpecific": "must-not-escape" }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/dynamic-secrets/leases/{LEASE_ID}")))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let result = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_sql_dynamic_secret_lease(
                &scope(),
                &DynamicSecretName::new("database-user").unwrap(),
                None,
            )
            .await;
        assert!(matches!(result, Err(ResourceError::Client(_))));
    }

    #[tokio::test]
    async fn sql_lease_response_must_match_each_owner_and_credential_invariant() {
        let mut wrong_name = dynamic_secret_fixture("different-name");
        let mut wrong_provider = dynamic_secret_fixture("database-user");
        wrong_provider["type"] = json!("clickhouse");
        let mut malformed_owner = dynamic_secret_fixture("database-user");
        malformed_owner["id"] = json!("not-a-uuid");
        let structurally_malformed_owner = json!({ "id": CONFIG_ID });
        let mut wrong_owner = lease_fixture();
        wrong_owner["dynamicSecretId"] = json!("d71de724-704b-4f06-b15d-6a2f86ea478a");
        let mut malformed_owned_lease = lease_fixture();
        malformed_owned_lease["createdAt"] = json!("not-a-timestamp");
        let replacement_id = "d71de724-704b-4f06-b15d-6a2f86ea478a";
        let mut replaced_secret = dynamic_secret_fixture("database-user");
        replaced_secret["id"] = json!(replacement_id);
        let mut replaced_non_sql_secret = replaced_secret.clone();
        replaced_non_sql_secret["type"] = json!("clickhouse");
        let mut replaced_lease = lease_fixture();
        replaced_lease["dynamicSecretId"] = json!(replacement_id);
        let oversized_username = "u".repeat(MAX_SQL_IDENTIFIER_BYTES + 1);
        let mut oversized_owner = lease_fixture();
        oversized_owner["externalEntityId"] = json!(oversized_username);
        let cases = [
            lease_rejection_case(lease_fixture(), wrong_name.take(), true),
            lease_rejection_case(lease_fixture(), wrong_provider, true),
            lease_rejection_case(lease_fixture(), malformed_owner, true),
            lease_rejection_case(lease_fixture(), structurally_malformed_owner, true),
            lease_rejection_case(wrong_owner, dynamic_secret_fixture("database-user"), false),
            lease_rejection_case(
                malformed_owned_lease,
                dynamic_secret_fixture("database-user"),
                true,
            ),
            lease_rejection_case(replaced_lease.clone(), replaced_non_sql_secret, false),
            lease_rejection_case(replaced_lease, replaced_secret, true),
            (
                lease_fixture(),
                dynamic_secret_fixture("database-user"),
                "different-user".to_owned(),
                "lease-password-canary".to_owned(),
                true,
            ),
            (
                oversized_owner,
                dynamic_secret_fixture("database-user"),
                oversized_username,
                "lease-password-canary".to_owned(),
                true,
            ),
            (
                lease_fixture(),
                dynamic_secret_fixture("database-user"),
                "svc-lease-user".to_owned(),
                String::new(),
                true,
            ),
        ];
        for (lease, dynamic_secret, username, password, cleanup_expected) in cases {
            assert_sql_lease_response_rejected(
                lease,
                dynamic_secret,
                username,
                password,
                cleanup_expected,
            )
            .await;
        }
    }
}
