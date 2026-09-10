use reqwest::Method;
use rustls_pki_types::ServerName;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

use crate::{
    EnvironmentSlug, InfisicalClient, MutationOperation, ObservableReadOperation, Page,
    PageRequest, ProjectId, ResourceError, SecretPath, SecretValue,
    client::{ApiVersion, Endpoint, sealed},
    resources::{is_uuid, paginate, utc_timestamp_millis},
};

const MAX_NAME_BYTES: usize = 256;
const MAX_DESCRIPTION_BYTES: usize = 256;
const MAX_JOINED_NAME_BYTES: usize = 256;
const MAX_SECRET_PATH_BYTES: usize = 2_048;
const MAX_GITHUB_HOST_BYTES: usize = 253;
const MAX_GITHUB_CREDENTIAL_BYTES: usize = 16_384;
const MAX_GITHUB_INSTALLATION_ID_BYTES: usize = 128;
const MAX_GITHUB_DESTINATION_NAME_BYTES: usize = 256;
const MAX_GITHUB_KEY_SCHEMA_BYTES: usize = 2_048;
const MAX_GITHUB_SELECTED_REPOSITORIES: usize = 1_000;

/// Validation failures for GitHub app-connection and secret-sync inputs.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AppAutomationInputError {
    /// An app-connection or secret-sync identifier was not a UUID.
    #[error("app-connection and secret-sync identifiers must be UUIDs")]
    InvalidIdentifier,
    /// A resource name was not a canonical Infisical slug.
    #[error(
        "app-connection and secret-sync names must be canonical lowercase slugs of at most 256 bytes"
    )]
    InvalidName,
    /// A description was padded, oversized, or contained control characters.
    #[error("app-connection and secret-sync descriptions must contain at most 256 unpadded bytes")]
    InvalidDescription,
    /// A GitHub credential was empty or exceeded its bound.
    #[error("GitHub credentials must contain 1 to 16384 bytes")]
    InvalidCredential,
    /// A GitHub App installation identifier was invalid.
    #[error("GitHub App installation IDs must contain 1 to 128 unpadded bytes")]
    InvalidInstallationId,
    /// A GitHub Enterprise Server host was not a plain host name or address.
    #[error("GitHub Enterprise Server hosts must be plain host names or IP addresses")]
    InvalidHost,
    /// A gateway reference was not a UUID.
    #[error("app-connection gateway references must be UUIDs")]
    InvalidGatewayReference,
    /// An update did not contain any change.
    #[error("app-connection and secret-sync updates must change at least one field")]
    EmptyChange,
    /// A GitHub secret-sync destination was malformed or incoherent.
    #[error("GitHub secret-sync destination configuration is invalid")]
    InvalidDestination,
    /// Selected repository identifiers were empty, duplicated, zero, or excessive.
    #[error("selected GitHub repository IDs must contain 1 to 1000 unique positive values")]
    InvalidSelectedRepositories,
    /// A secret-sync key schema was malformed or used unsupported placeholders.
    #[error(
        "GitHub sync key schemas must contain exactly one {{secretKey}} placeholder and only documented characters"
    )]
    InvalidKeySchema,
}

/// GitHub authentication method accepted by Infisical v0.160.12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum GitHubConnectionMethod {
    /// GitHub App installation authorization.
    #[serde(rename = "github-app")]
    GitHubApp,
    /// OAuth authorization-code exchange.
    #[serde(rename = "oauth")]
    OAuth,
    /// Personal access token.
    #[serde(rename = "pat")]
    PersonalAccessToken,
}

/// GitHub Cloud or an explicitly named GitHub Enterprise Server instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitHubInstance {
    /// GitHub Cloud, optionally with an Enterprise Cloud hostname.
    Cloud {
        /// Optional GitHub Enterprise Cloud hostname.
        host: Option<String>,
    },
    /// One plain GitHub Enterprise Server host without a scheme or path.
    Server(String),
}

/// Locally validated, secret-bearing GitHub connection credentials.
#[derive(Debug)]
pub struct GitHubAppConnectionCredentials {
    kind: GitHubCredentialKind,
}

#[derive(Debug)]
enum GitHubCredentialKind {
    App {
        code: SecretValue,
        installation_id: String,
        instance: GitHubInstance,
    },
    OAuth {
        code: SecretValue,
        instance: GitHubInstance,
    },
    Pat {
        personal_access_token: SecretValue,
        instance: GitHubInstance,
    },
}

impl GitHubAppConnectionCredentials {
    /// Validate GitHub App installation credentials.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed credentials, installation IDs, or hosts.
    pub fn github_app(
        code: SecretValue,
        installation_id: impl Into<String>,
        instance: GitHubInstance,
    ) -> Result<Self, AppAutomationInputError> {
        let installation_id = installation_id.into();
        validate_github_secret(&code)?;
        if !bounded_unpadded(&installation_id, MAX_GITHUB_INSTALLATION_ID_BYTES) {
            return Err(AppAutomationInputError::InvalidInstallationId);
        }
        validate_github_instance(&instance)?;
        Ok(Self {
            kind: GitHubCredentialKind::App {
                code,
                installation_id,
                instance,
            },
        })
    }

    /// Validate OAuth authorization-code credentials.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty code or malformed server host.
    pub fn oauth(
        code: SecretValue,
        instance: GitHubInstance,
    ) -> Result<Self, AppAutomationInputError> {
        validate_github_secret(&code)?;
        validate_github_instance(&instance)?;
        Ok(Self {
            kind: GitHubCredentialKind::OAuth { code, instance },
        })
    }

    /// Validate personal-access-token credentials.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty token or malformed server host.
    pub fn personal_access_token(
        personal_access_token: SecretValue,
        instance: GitHubInstance,
    ) -> Result<Self, AppAutomationInputError> {
        validate_github_secret(&personal_access_token)?;
        validate_github_instance(&instance)?;
        Ok(Self {
            kind: GitHubCredentialKind::Pat {
                personal_access_token,
                instance,
            },
        })
    }

    fn method(&self) -> GitHubConnectionMethod {
        match self.kind {
            GitHubCredentialKind::App { .. } => GitHubConnectionMethod::GitHubApp,
            GitHubCredentialKind::OAuth { .. } => GitHubConnectionMethod::OAuth,
            GitHubCredentialKind::Pat { .. } => GitHubConnectionMethod::PersonalAccessToken,
        }
    }

    fn instance_metadata(&self) -> GitHubInstanceMetadata {
        let instance = match &self.kind {
            GitHubCredentialKind::App { instance, .. }
            | GitHubCredentialKind::OAuth { instance, .. }
            | GitHubCredentialKind::Pat { instance, .. } => instance,
        };
        GitHubInstanceMetadata::from(instance)
    }
}

impl Serialize for GitHubAppConnectionCredentials {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct WireCredentials<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            code: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            personal_access_token: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            installation_id: Option<&'a str>,
            instance_type: &'static str,
            #[serde(skip_serializing_if = "Option::is_none")]
            host: Option<&'a str>,
        }

        let (code, personal_access_token, installation_id, instance) = match &self.kind {
            GitHubCredentialKind::App {
                code,
                installation_id,
                instance,
            } => (
                Some(code.expose_secret()),
                None,
                Some(installation_id.as_str()),
                instance,
            ),
            GitHubCredentialKind::OAuth { code, instance } => {
                (Some(code.expose_secret()), None, None, instance)
            }
            GitHubCredentialKind::Pat {
                personal_access_token,
                instance,
            } => (
                None,
                Some(personal_access_token.expose_secret()),
                None,
                instance,
            ),
        };
        let (instance_type, host) = match instance {
            GitHubInstance::Cloud { host } => ("cloud", host.as_deref()),
            GitHubInstance::Server(host) => ("server", Some(host.as_str())),
        };
        WireCredentials {
            code,
            personal_access_token,
            installation_id,
            instance_type,
            host,
        }
        .serialize(serializer)
    }
}

/// Direct, gateway, or gateway-pool routing for a GitHub connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppConnectionRoute {
    /// Connect directly from Infisical.
    Direct,
    /// Route through one legacy gateway UUID.
    Gateway(String),
    /// Route through one gateway-pool UUID.
    GatewayPool(String),
}

/// Explicit optional-description change for partial updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutomationDescriptionChange {
    /// Leave the current description unchanged.
    Keep,
    /// Clear the current description.
    Clear,
    /// Replace the current description.
    Set(String),
}

/// Complete locally validated GitHub app-connection creation.
#[derive(Debug)]
pub struct GitHubAppConnectionCreation {
    name: String,
    description: Option<String>,
    project_id: Option<ProjectId>,
    credentials: GitHubAppConnectionCredentials,
    route: AppConnectionRoute,
}

impl GitHubAppConnectionCreation {
    /// Assemble one complete GitHub app-connection request.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed names, descriptions, or gateway IDs.
    pub fn new(
        name: impl Into<String>,
        description: Option<String>,
        project_id: Option<ProjectId>,
        credentials: GitHubAppConnectionCredentials,
        route: AppConnectionRoute,
    ) -> Result<Self, AppAutomationInputError> {
        let name = name.into();
        validate_automation_name(&name)?;
        validate_input_description(description.as_deref())?;
        validate_app_connection_route(&route)?;
        Ok(Self {
            name,
            description,
            project_id,
            credentials,
            route,
        })
    }
}

/// Partial, non-empty GitHub app-connection update.
#[derive(Debug)]
pub struct GitHubAppConnectionChange {
    name: Option<String>,
    description: AutomationDescriptionChange,
    credentials: Option<GitHubAppConnectionCredentials>,
    route: Option<AppConnectionRoute>,
}

impl GitHubAppConnectionChange {
    /// Validate one non-empty app-connection update.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed fields or an empty update.
    pub fn new(
        name: Option<String>,
        description: AutomationDescriptionChange,
        credentials: Option<GitHubAppConnectionCredentials>,
        route: Option<AppConnectionRoute>,
    ) -> Result<Self, AppAutomationInputError> {
        if name.is_none()
            && description == AutomationDescriptionChange::Keep
            && credentials.is_none()
            && route.is_none()
        {
            return Err(AppAutomationInputError::EmptyChange);
        }
        if let Some(name) = name.as_deref() {
            validate_automation_name(name)?;
        }
        if let AutomationDescriptionChange::Set(description) = &description {
            validate_input_description(Some(description))?;
        }
        if let Some(route) = route.as_ref() {
            validate_app_connection_route(route)?;
        }
        Ok(Self {
            name,
            description,
            credentials,
            route,
        })
    }
}

/// Value-free GitHub instance metadata retained by Infisical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubInstanceMetadata {
    /// Whether the credentials target GitHub Cloud or GitHub Enterprise Server.
    pub instance_type: GitHubInstanceType,
    /// Plain GitHub Enterprise Server host when one is configured.
    pub host: Option<String>,
}

impl From<&GitHubInstance> for GitHubInstanceMetadata {
    fn from(instance: &GitHubInstance) -> Self {
        match instance {
            GitHubInstance::Cloud { host } => Self {
                instance_type: GitHubInstanceType::Cloud,
                host: host.clone(),
            },
            GitHubInstance::Server(host) => Self {
                instance_type: GitHubInstanceType::Server,
                host: Some(host.clone()),
            },
        }
    }
}

/// Value-free GitHub instance kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GitHubInstanceType {
    /// GitHub Cloud, including an optional Enterprise Cloud host.
    Cloud,
    /// A self-hosted GitHub Enterprise Server.
    Server,
}

/// Value-free, provider-specific GitHub app connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubAppConnection {
    /// Common value-free app-connection metadata.
    pub connection: AppConnection,
    /// Immutable authentication method selected at creation.
    pub method: GitHubConnectionMethod,
    /// Safe instance location; authorization codes, tokens, and installation IDs are omitted.
    pub instance: GitHubInstanceMetadata,
}

/// GitHub organization-secret visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GitHubSyncVisibility {
    /// All repositories in the organization.
    All,
    /// All private repositories in the organization.
    Private,
    /// Only the explicitly listed repository IDs.
    Selected,
}

/// Closed GitHub secret-sync destination configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "scope",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum GitHubSecretSyncDestination {
    /// GitHub organization Actions secrets.
    Organization {
        /// GitHub organization login.
        org: String,
        /// Repository visibility selection.
        visibility: GitHubSyncVisibility,
        /// Positive repository IDs, required only for selected visibility.
        #[serde(skip_serializing_if = "Option::is_none")]
        selected_repository_ids: Option<Vec<u64>>,
    },
    /// GitHub repository Actions secrets.
    Repository {
        /// Repository owner login.
        owner: String,
        /// Repository name.
        repo: String,
    },
    /// GitHub repository-environment Actions secrets.
    RepositoryEnvironment {
        /// Repository owner login.
        owner: String,
        /// Repository name.
        repo: String,
        /// GitHub environment name.
        env: String,
    },
}

/// Complete outbound GitHub sync policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubSecretSyncOptions {
    /// Optional key template with exactly one `{{secretKey}}` placeholder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_schema: Option<String>,
    /// Preserve remote keys that disappear from the Infisical source folder.
    #[serde(default)]
    pub disable_secret_deletion: bool,
}

impl GitHubSecretSyncOptions {
    /// Validate one complete GitHub sync policy.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed key templates.
    pub fn new(
        key_schema: Option<String>,
        disable_secret_deletion: bool,
    ) -> Result<Self, AppAutomationInputError> {
        if let Some(key_schema) = key_schema.as_deref() {
            validate_github_key_schema(key_schema)?;
        }
        Ok(Self {
            key_schema,
            disable_secret_deletion,
        })
    }
}

/// Exact source coordinates for a GitHub secret sync.
#[derive(Debug)]
pub struct GitHubSecretSyncSource {
    connection_id: String,
    environment: EnvironmentSlug,
    secret_path: SecretPath,
}

impl GitHubSecretSyncSource {
    /// Assemble validated connection and Infisical source coordinates.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection identifier is not a UUID.
    pub fn new(
        connection_id: impl Into<String>,
        environment: EnvironmentSlug,
        secret_path: SecretPath,
    ) -> Result<Self, AppAutomationInputError> {
        let connection_id = connection_id.into();
        if !is_uuid(&connection_id) {
            return Err(AppAutomationInputError::InvalidIdentifier);
        }
        Ok(Self {
            connection_id,
            environment,
            secret_path,
        })
    }
}

/// Complete locally validated GitHub secret-sync creation.
#[derive(Debug)]
pub struct GitHubSecretSyncCreation {
    name: String,
    description: Option<String>,
    connection_id: String,
    environment: EnvironmentSlug,
    secret_path: SecretPath,
    is_auto_sync_enabled: bool,
    destination: GitHubSecretSyncDestination,
    options: GitHubSecretSyncOptions,
}

impl GitHubSecretSyncCreation {
    /// Assemble one complete GitHub secret-sync request.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed names, identifiers, descriptions, or destination settings.
    pub fn new(
        name: impl Into<String>,
        description: Option<String>,
        source: GitHubSecretSyncSource,
        is_auto_sync_enabled: bool,
        destination: GitHubSecretSyncDestination,
        options: GitHubSecretSyncOptions,
    ) -> Result<Self, AppAutomationInputError> {
        let name = name.into();
        validate_automation_name(&name)?;
        validate_input_description(description.as_deref())?;
        validate_github_destination(&destination)?;
        if let Some(key_schema) = options.key_schema.as_deref() {
            validate_github_key_schema(key_schema)?;
        }
        Ok(Self {
            name,
            description,
            connection_id: source.connection_id,
            environment: source.environment,
            secret_path: source.secret_path,
            is_auto_sync_enabled,
            destination,
            options,
        })
    }
}

/// Partial, non-empty GitHub secret-sync update.
#[derive(Debug)]
pub struct GitHubSecretSyncChange {
    name: Option<String>,
    description: AutomationDescriptionChange,
    connection_id: Option<String>,
    environment: Option<EnvironmentSlug>,
    secret_path: Option<SecretPath>,
    is_auto_sync_enabled: Option<bool>,
    destination: Option<GitHubSecretSyncDestination>,
    options: Option<GitHubSecretSyncOptions>,
}

impl GitHubSecretSyncChange {
    /// Validate one non-empty GitHub secret-sync update.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed fields or an empty update.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: Option<String>,
        description: AutomationDescriptionChange,
        connection_id: Option<String>,
        environment: Option<EnvironmentSlug>,
        secret_path: Option<SecretPath>,
        is_auto_sync_enabled: Option<bool>,
        destination: Option<GitHubSecretSyncDestination>,
        options: Option<GitHubSecretSyncOptions>,
    ) -> Result<Self, AppAutomationInputError> {
        if name.is_none()
            && description == AutomationDescriptionChange::Keep
            && connection_id.is_none()
            && environment.is_none()
            && secret_path.is_none()
            && is_auto_sync_enabled.is_none()
            && destination.is_none()
            && options.is_none()
        {
            return Err(AppAutomationInputError::EmptyChange);
        }
        if let Some(name) = name.as_deref() {
            validate_automation_name(name)?;
        }
        if let AutomationDescriptionChange::Set(description) = &description {
            validate_input_description(Some(description))?;
        }
        if connection_id.as_deref().is_some_and(|id| !is_uuid(id)) {
            return Err(AppAutomationInputError::InvalidIdentifier);
        }
        if let Some(destination) = destination.as_ref() {
            validate_github_destination(destination)?;
        }
        if let Some(key_schema) = options
            .as_ref()
            .and_then(|options| options.key_schema.as_deref())
        {
            validate_github_key_schema(key_schema)?;
        }
        Ok(Self {
            name,
            description,
            connection_id,
            environment,
            secret_path,
            is_auto_sync_enabled,
            destination,
            options,
        })
    }
}

/// Value-free GitHub secret-sync metadata plus its typed destination contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubSecretSync {
    /// Common value-free secret-sync metadata.
    pub sync: SecretSync,
    /// Provider destination coordinates without secret values.
    pub destination: GitHubSecretSyncDestination,
    /// Complete outbound sync behavior.
    pub options: GitHubSecretSyncOptions,
}

/// App-connection provider values compiled from Infisical v0.160.12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum AppConnectionProvider {
    #[serde(rename = "github")]
    GitHub,
    #[serde(rename = "github-radar")]
    GitHubRadar,
    #[serde(rename = "aws")]
    Aws,
    #[serde(rename = "databricks")]
    Databricks,
    #[serde(rename = "gcp")]
    Gcp,
    #[serde(rename = "azure-key-vault")]
    AzureKeyVault,
    #[serde(rename = "azure-app-configuration")]
    AzureAppConfiguration,
    #[serde(rename = "azure-client-secrets")]
    AzureClientSecrets,
    #[serde(rename = "azure-devops")]
    AzureDevOps,
    #[serde(rename = "azure-adcs")]
    AzureAdcs,
    #[serde(rename = "azure-dns")]
    AzureDns,
    #[serde(rename = "humanitec")]
    Humanitec,
    #[serde(rename = "terraform-cloud")]
    TerraformCloud,
    #[serde(rename = "vercel")]
    Vercel,
    #[serde(rename = "postgres")]
    Postgres,
    #[serde(rename = "mssql")]
    MsSql,
    #[serde(rename = "mysql")]
    MySql,
    #[serde(rename = "camunda")]
    Camunda,
    #[serde(rename = "windmill")]
    Windmill,
    #[serde(rename = "auth0")]
    Auth0,
    #[serde(rename = "hashicorp-vault")]
    HashicorpVault,
    #[serde(rename = "ldap")]
    Ldap,
    #[serde(rename = "teamcity")]
    TeamCity,
    #[serde(rename = "oci")]
    Oci,
    #[serde(rename = "oracledb")]
    OracleDb,
    #[serde(rename = "1password")]
    OnePassword,
    #[serde(rename = "heroku")]
    Heroku,
    #[serde(rename = "render")]
    Render,
    #[serde(rename = "flyio")]
    FlyIo,
    #[serde(rename = "gitlab")]
    GitLab,
    #[serde(rename = "cloudflare")]
    Cloudflare,
    #[serde(rename = "dns-made-easy")]
    DnsMadeEasy,
    #[serde(rename = "zabbix")]
    Zabbix,
    #[serde(rename = "railway")]
    Railway,
    #[serde(rename = "bitbucket")]
    Bitbucket,
    #[serde(rename = "checkly")]
    Checkly,
    #[serde(rename = "supabase")]
    Supabase,
    #[serde(rename = "digital-ocean")]
    DigitalOcean,
    #[serde(rename = "netlify")]
    Netlify,
    #[serde(rename = "okta")]
    Okta,
    #[serde(rename = "redis")]
    Redis,
    #[serde(rename = "mongodb")]
    MongoDb,
    #[serde(rename = "laravel-forge")]
    LaravelForge,
    #[serde(rename = "chef")]
    Chef,
    #[serde(rename = "northflank")]
    Northflank,
    #[serde(rename = "octopus-deploy")]
    OctopusDeploy,
    #[serde(rename = "ssh")]
    Ssh,
    #[serde(rename = "dbt")]
    Dbt,
    #[serde(rename = "smb")]
    Smb,
    #[serde(rename = "open-router")]
    OpenRouter,
    #[serde(rename = "circleci")]
    CircleCi,
    #[serde(rename = "azure-entra-id")]
    AzureEntraId,
    #[serde(rename = "venafi")]
    Venafi,
    #[serde(rename = "venafi-tpp")]
    VenafiTpp,
    #[serde(rename = "external-infisical")]
    ExternalInfisical,
    #[serde(rename = "doppler")]
    Doppler,
    #[serde(rename = "netscaler")]
    NetScaler,
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "ovh")]
    Ovh,
    #[serde(rename = "devin")]
    Devin,
    #[serde(rename = "ona")]
    Ona,
    #[serde(rename = "digicert")]
    DigiCert,
    #[serde(rename = "travis-ci")]
    TravisCi,
    #[serde(rename = "salesforce")]
    Salesforce,
    #[serde(rename = "snowflake")]
    Snowflake,
    #[serde(rename = "datadog")]
    Datadog,
    #[serde(rename = "f5-big-ip")]
    F5BigIp,
    #[serde(rename = "godaddy")]
    GoDaddy,
}

/// Secret-sync destination values compiled from Infisical v0.160.12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SecretSyncDestination {
    #[serde(rename = "aws-parameter-store")]
    AwsParameterStore,
    #[serde(rename = "aws-secrets-manager")]
    AwsSecretsManager,
    #[serde(rename = "github")]
    GitHub,
    #[serde(rename = "gcp-secret-manager")]
    GcpSecretManager,
    #[serde(rename = "azure-key-vault")]
    AzureKeyVault,
    #[serde(rename = "azure-app-configuration")]
    AzureAppConfiguration,
    #[serde(rename = "azure-devops")]
    AzureDevOps,
    #[serde(rename = "databricks")]
    Databricks,
    #[serde(rename = "humanitec")]
    Humanitec,
    #[serde(rename = "terraform-cloud")]
    TerraformCloud,
    #[serde(rename = "camunda")]
    Camunda,
    #[serde(rename = "vercel")]
    Vercel,
    #[serde(rename = "windmill")]
    Windmill,
    #[serde(rename = "hashicorp-vault")]
    HashicorpVault,
    #[serde(rename = "teamcity")]
    TeamCity,
    #[serde(rename = "oci-vault")]
    OciVault,
    #[serde(rename = "1password")]
    OnePassword,
    #[serde(rename = "heroku")]
    Heroku,
    #[serde(rename = "render")]
    Render,
    #[serde(rename = "flyio")]
    FlyIo,
    #[serde(rename = "gitlab")]
    GitLab,
    #[serde(rename = "cloudflare-pages")]
    CloudflarePages,
    #[serde(rename = "cloudflare-workers")]
    CloudflareWorkers,
    #[serde(rename = "supabase")]
    Supabase,
    #[serde(rename = "zabbix")]
    Zabbix,
    #[serde(rename = "railway")]
    Railway,
    #[serde(rename = "checkly")]
    Checkly,
    #[serde(rename = "digital-ocean-app-platform")]
    DigitalOceanAppPlatform,
    #[serde(rename = "netlify")]
    Netlify,
    #[serde(rename = "northflank")]
    Northflank,
    #[serde(rename = "bitbucket")]
    Bitbucket,
    #[serde(rename = "laravel-forge")]
    LaravelForge,
    #[serde(rename = "chef")]
    Chef,
    #[serde(rename = "octopus-deploy")]
    OctopusDeploy,
    #[serde(rename = "circleci")]
    CircleCi,
    #[serde(rename = "azure-entra-id-scim")]
    AzureEntraIdScim,
    #[serde(rename = "external-infisical")]
    ExternalInfisical,
    #[serde(rename = "ovh")]
    Ovh,
    #[serde(rename = "devin")]
    Devin,
    #[serde(rename = "ona")]
    Ona,
    #[serde(rename = "travis-ci")]
    TravisCi,
    #[serde(rename = "snowflake")]
    Snowflake,
}

impl SecretSyncDestination {
    const fn connection_provider(self) -> AppConnectionProvider {
        match self {
            Self::AwsParameterStore | Self::AwsSecretsManager => AppConnectionProvider::Aws,
            Self::GitHub => AppConnectionProvider::GitHub,
            Self::GcpSecretManager => AppConnectionProvider::Gcp,
            Self::AzureKeyVault => AppConnectionProvider::AzureKeyVault,
            Self::AzureAppConfiguration => AppConnectionProvider::AzureAppConfiguration,
            Self::AzureDevOps => AppConnectionProvider::AzureDevOps,
            Self::Databricks => AppConnectionProvider::Databricks,
            Self::Humanitec => AppConnectionProvider::Humanitec,
            Self::TerraformCloud => AppConnectionProvider::TerraformCloud,
            Self::Camunda => AppConnectionProvider::Camunda,
            Self::Vercel => AppConnectionProvider::Vercel,
            Self::Windmill => AppConnectionProvider::Windmill,
            Self::HashicorpVault => AppConnectionProvider::HashicorpVault,
            Self::TeamCity => AppConnectionProvider::TeamCity,
            Self::OciVault => AppConnectionProvider::Oci,
            Self::OnePassword => AppConnectionProvider::OnePassword,
            Self::Heroku => AppConnectionProvider::Heroku,
            Self::Render => AppConnectionProvider::Render,
            Self::FlyIo => AppConnectionProvider::FlyIo,
            Self::GitLab => AppConnectionProvider::GitLab,
            Self::CloudflarePages | Self::CloudflareWorkers => AppConnectionProvider::Cloudflare,
            Self::Supabase => AppConnectionProvider::Supabase,
            Self::Zabbix => AppConnectionProvider::Zabbix,
            Self::Railway => AppConnectionProvider::Railway,
            Self::Checkly => AppConnectionProvider::Checkly,
            Self::DigitalOceanAppPlatform => AppConnectionProvider::DigitalOcean,
            Self::Netlify => AppConnectionProvider::Netlify,
            Self::Northflank => AppConnectionProvider::Northflank,
            Self::Bitbucket => AppConnectionProvider::Bitbucket,
            Self::LaravelForge => AppConnectionProvider::LaravelForge,
            Self::Chef => AppConnectionProvider::Chef,
            Self::OctopusDeploy => AppConnectionProvider::OctopusDeploy,
            Self::CircleCi => AppConnectionProvider::CircleCi,
            Self::AzureEntraIdScim => AppConnectionProvider::AzureEntraId,
            Self::ExternalInfisical => AppConnectionProvider::ExternalInfisical,
            Self::Ovh => AppConnectionProvider::Ovh,
            Self::Devin => AppConnectionProvider::Devin,
            Self::Ona => AppConnectionProvider::Ona,
            Self::TravisCi => AppConnectionProvider::TravisCi,
            Self::Snowflake => AppConnectionProvider::Snowflake,
        }
    }
}

/// Secret-rotation provider values compiled from Infisical v0.160.12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SecretRotationType {
    #[serde(rename = "postgres-credentials")]
    PostgresCredentials,
    #[serde(rename = "mssql-credentials")]
    MsSqlCredentials,
    #[serde(rename = "mysql-credentials")]
    MySqlCredentials,
    #[serde(rename = "oracledb-credentials")]
    OracleDbCredentials,
    #[serde(rename = "auth0-client-secret")]
    Auth0ClientSecret,
    #[serde(rename = "azure-client-secret")]
    AzureClientSecret,
    #[serde(rename = "aws-iam-user-secret")]
    AwsIamUserSecret,
    #[serde(rename = "ldap-password")]
    LdapPassword,
    #[serde(rename = "okta-client-secret")]
    OktaClientSecret,
    #[serde(rename = "redis-credentials")]
    RedisCredentials,
    #[serde(rename = "mongodb-credentials")]
    MongoDbCredentials,
    #[serde(rename = "databricks-service-principal-secret")]
    DatabricksServicePrincipalSecret,
    #[serde(rename = "unix-linux-local-account")]
    UnixLinuxLocalAccount,
    #[serde(rename = "dbt-service-token")]
    DbtServiceToken,
    #[serde(rename = "windows-local-account")]
    WindowsLocalAccount,
    #[serde(rename = "open-router-api-key")]
    OpenRouterApiKey,
    #[serde(rename = "hp-ilo-local-account")]
    HpIloLocalAccount,
    #[serde(rename = "supabase-api-key")]
    SupabaseApiKey,
    #[serde(rename = "salesforce-oauth-credentials")]
    SalesforceOauthCredentials,
    #[serde(rename = "datadog-application-key-secret")]
    DatadogApplicationKeySecret,
}

impl SecretRotationType {
    const fn connection_provider(self) -> AppConnectionProvider {
        match self {
            Self::PostgresCredentials => AppConnectionProvider::Postgres,
            Self::MsSqlCredentials => AppConnectionProvider::MsSql,
            Self::MySqlCredentials => AppConnectionProvider::MySql,
            Self::OracleDbCredentials => AppConnectionProvider::OracleDb,
            Self::Auth0ClientSecret => AppConnectionProvider::Auth0,
            Self::AzureClientSecret => AppConnectionProvider::AzureClientSecrets,
            Self::AwsIamUserSecret => AppConnectionProvider::Aws,
            Self::LdapPassword => AppConnectionProvider::Ldap,
            Self::OktaClientSecret => AppConnectionProvider::Okta,
            Self::RedisCredentials => AppConnectionProvider::Redis,
            Self::MongoDbCredentials => AppConnectionProvider::MongoDb,
            Self::DatabricksServicePrincipalSecret => AppConnectionProvider::Databricks,
            Self::UnixLinuxLocalAccount | Self::HpIloLocalAccount => AppConnectionProvider::Ssh,
            Self::DbtServiceToken => AppConnectionProvider::Dbt,
            Self::WindowsLocalAccount => AppConnectionProvider::Smb,
            Self::OpenRouterApiKey => AppConnectionProvider::OpenRouter,
            Self::SupabaseApiKey => AppConnectionProvider::Supabase,
            Self::SalesforceOauthCredentials => AppConnectionProvider::Salesforce,
            Self::DatadogApplicationKeySecret => AppConnectionProvider::Datadog,
        }
    }
}

/// Status of an asynchronous secret-sync action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SecretSyncStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
}

/// Result of the most recent secret-rotation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SecretRotationStatus {
    Success,
    Failed,
}

/// Value-free app-connection inventory record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AppConnection {
    /// Opaque app-connection identifier.
    pub id: String,
    /// Human-readable app-connection name.
    pub name: String,
    /// Optional human-readable app-connection description.
    pub description: Option<String>,
    /// Closed Infisical provider family for this connection.
    pub provider: AppConnectionProvider,
    /// Positive provider-schema version reported by Infisical.
    pub version: u32,
    /// Opaque identifier of the organization that owns the connection.
    pub organization_id: String,
    /// Optional opaque identifier of the project that owns the connection.
    pub project_id: Option<String>,
    /// Canonical UTC creation timestamp.
    pub created_at: String,
    /// Canonical UTC last-update timestamp.
    pub updated_at: String,
    /// Whether Infisical manages the provider credentials.
    pub is_platform_managed_credentials: bool,
    /// Whether provider credential auto-rotation is enabled.
    pub is_auto_rotation_enabled: bool,
    /// Optional opaque legacy gateway identifier.
    pub gateway_id: Option<String>,
    /// Optional opaque gateway-pool identifier.
    pub gateway_pool_id: Option<String>,
}

/// Value-free app-connection reference embedded by sync and rotation records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutomationConnection {
    /// Opaque app-connection identifier echoed by the parent record.
    pub id: String,
    /// Human-readable app-connection name.
    pub name: String,
    /// Provider family required by the parent sync or rotation type.
    pub provider: AppConnectionProvider,
}

/// Validated environment reference embedded by sync and rotation records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutomationEnvironment {
    /// Opaque environment identifier verified against the requested project.
    pub id: String,
    /// Human-readable environment name verified against the project catalog.
    pub name: String,
    /// Stable environment slug verified against the project catalog.
    pub slug: String,
}

/// Validated secret-folder reference embedded by sync and rotation records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutomationFolder {
    /// Opaque folder identifier echoed by the parent record.
    pub id: String,
    /// Normalized absolute secret-tree path for the folder.
    pub path: String,
}

/// Value-free secret-sync inventory record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretSync {
    /// Opaque secret-sync identifier.
    pub id: String,
    /// Human-readable secret-sync name.
    pub name: String,
    /// Optional human-readable secret-sync description.
    pub description: Option<String>,
    /// Closed destination family configured for this sync.
    pub destination: SecretSyncDestination,
    /// Positive destination-schema version reported by Infisical.
    pub version: u32,
    /// Opaque identifier of the project that owns the sync.
    pub project_id: String,
    /// Value-free reference to the validated app connection.
    pub connection: AutomationConnection,
    /// Optional environment verified against the requested project catalog.
    pub environment: Option<AutomationEnvironment>,
    /// Optional folder whose identifier matches the sync record.
    pub folder: Option<AutomationFolder>,
    /// Whether Infisical automatically pushes secret changes.
    pub is_auto_sync_enabled: bool,
    /// Optional state of the most recent outbound sync.
    pub sync_status: Option<SecretSyncStatus>,
    /// Optional canonical UTC timestamp of the most recent outbound sync.
    pub last_synced_at: Option<String>,
    /// Optional state of the most recent destination import.
    pub import_status: Option<SecretSyncStatus>,
    /// Optional canonical UTC timestamp of the most recent destination import.
    pub last_imported_at: Option<String>,
    /// Optional state of the most recent destination removal.
    pub remove_status: Option<SecretSyncStatus>,
    /// Optional canonical UTC timestamp of the most recent destination removal.
    pub last_removed_at: Option<String>,
    /// Canonical UTC creation timestamp.
    pub created_at: String,
    /// Canonical UTC last-update timestamp.
    pub updated_at: String,
}

/// UTC schedule used for an automatic secret rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RotationTimeOfDay {
    /// UTC hour from 0 through 23.
    #[schemars(range(min = 0, max = 23))]
    pub hours: u8,
    /// UTC minute from 0 through 59.
    #[schemars(range(min = 0, max = 59))]
    pub minutes: u8,
}

/// Value-free secret-rotation inventory record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretRotation {
    /// Opaque secret-rotation identifier.
    pub id: String,
    /// Human-readable secret-rotation name.
    pub name: String,
    /// Optional human-readable secret-rotation description.
    pub description: Option<String>,
    /// Closed provider-specific rotation contract.
    pub rotation_type: SecretRotationType,
    /// Opaque identifier of the project that owns the rotation.
    pub project_id: String,
    /// Value-free reference to the validated app connection.
    pub connection: AutomationConnection,
    /// Environment verified against the requested project catalog.
    pub environment: AutomationEnvironment,
    /// Folder whose identifier matches the rotation record.
    pub folder: AutomationFolder,
    /// Whether Infisical schedules this rotation automatically.
    pub is_auto_rotation_enabled: bool,
    /// Active credential slot, either zero or one.
    pub active_index: u8,
    /// Positive interval between automatic rotations in days.
    pub rotation_interval_days: u32,
    /// UTC time of day used for automatic rotation.
    pub rotate_at_utc: RotationTimeOfDay,
    /// Result of the most recent rotation attempt.
    pub rotation_status: SecretRotationStatus,
    /// Canonical UTC timestamp of the most recent rotation attempt.
    pub last_rotation_attempted_at: String,
    /// Canonical UTC timestamp of the most recent successful rotation.
    pub last_rotated_at: String,
    /// Optional canonical UTC timestamp of the next scheduled rotation.
    pub next_rotation_at: Option<String>,
    /// Whether the most recent rotation was started manually.
    pub is_last_rotation_manual: bool,
    /// Canonical UTC creation timestamp.
    pub created_at: String,
    /// Canonical UTC last-update timestamp.
    pub updated_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListAppConnectionsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectInventoryQuery {
    project_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAppConnection {
    id: String,
    name: String,
    description: Option<String>,
    app: AppConnectionProvider,
    version: u32,
    org_id: String,
    project_id: Option<String>,
    created_at: String,
    updated_at: String,
    is_platform_managed_credentials: Option<bool>,
    gateway_id: Option<String>,
    gateway_pool_id: Option<String>,
    is_auto_rotation_enabled: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawGitHubAppConnection {
    #[serde(flatten)]
    connection: RawAppConnection,
    method: GitHubConnectionMethod,
    credentials: RawGitHubInstance,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawGitHubInstance {
    instance_type: Option<GitHubInstanceType>,
    host: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAutomationConnection {
    id: String,
    name: String,
    app: AppConnectionProvider,
}

#[derive(Deserialize)]
struct RawAutomationEnvironment {
    id: String,
    name: String,
    slug: String,
}

#[derive(Deserialize)]
struct RawAutomationFolder {
    id: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSecretSync {
    id: String,
    name: String,
    description: Option<String>,
    destination: SecretSyncDestination,
    version: u32,
    project_id: String,
    folder_id: Option<String>,
    connection_id: String,
    connection: RawAutomationConnection,
    environment: Option<RawAutomationEnvironment>,
    folder: Option<RawAutomationFolder>,
    is_auto_sync_enabled: bool,
    sync_status: Option<SecretSyncStatus>,
    last_synced_at: Option<String>,
    import_status: Option<SecretSyncStatus>,
    last_imported_at: Option<String>,
    remove_status: Option<SecretSyncStatus>,
    last_removed_at: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawGitHubSecretSync {
    #[serde(flatten)]
    sync: RawSecretSync,
    destination_config: GitHubSecretSyncDestination,
    sync_options: RawGitHubSecretSyncOptions,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawGitHubSecretSyncOptions {
    initial_sync_behavior: GitHubInitialSyncBehavior,
    key_schema: Option<String>,
    disable_secret_deletion: Option<bool>,
}

#[derive(Deserialize, PartialEq, Eq)]
enum GitHubInitialSyncBehavior {
    #[serde(rename = "overwrite-destination")]
    OverwriteDestination,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawSecretRotation {
    id: String,
    name: String,
    description: Option<String>,
    #[serde(rename = "type")]
    rotation_type: SecretRotationType,
    project_id: String,
    folder_id: String,
    connection_id: String,
    connection: RawAutomationConnection,
    environment: RawAutomationEnvironment,
    folder: RawAutomationFolder,
    is_auto_rotation_enabled: bool,
    active_index: u32,
    rotation_interval: u32,
    rotate_at_utc: RotationTimeOfDay,
    rotation_status: SecretRotationStatus,
    last_rotation_attempted_at: String,
    last_rotated_at: String,
    next_rotation_at: Option<String>,
    is_last_rotation_manual: bool,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppConnectionsResponse {
    app_connections: Vec<RawAppConnection>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretSyncsResponse {
    secret_syncs: Vec<RawSecretSync>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretRotationsResponse {
    secret_rotations: Vec<RawSecretRotation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GitHubAppConnectionResponse {
    app_connection: RawGitHubAppConnection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GitHubSecretSyncResponse {
    secret_sync: RawGitHubSecretSync,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GitHubAppConnectionTarget {
    #[serde(skip_serializing)]
    connection_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateGitHubAppConnectionWire {
    name: String,
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    method: GitHubConnectionMethod,
    credentials: GitHubAppConnectionCredentials,
    is_platform_managed_credentials: bool,
    is_auto_rotation_enabled: bool,
    gateway_id: Option<String>,
    gateway_pool_id: Option<String>,
}

#[derive(Debug)]
enum NullableUpdate<T> {
    Omitted,
    Null,
    Value(T),
}

impl<T> NullableUpdate<T> {
    const fn is_omitted(&self) -> bool {
        matches!(self, Self::Omitted)
    }
}

impl<T: PartialEq> NullableUpdate<T> {
    fn matches(&self, actual: Option<&T>) -> bool {
        match self {
            Self::Omitted => true,
            Self::Null => actual.is_none(),
            Self::Value(expected) => actual == Some(expected),
        }
    }
}

impl<T: Serialize> Serialize for NullableUpdate<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Omitted | Self::Null => serializer.serialize_none(),
            Self::Value(value) => value.serialize(serializer),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateGitHubAppConnectionWire {
    #[serde(skip_serializing)]
    connection_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "NullableUpdate::is_omitted")]
    description: NullableUpdate<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials: Option<GitHubAppConnectionCredentials>,
    #[serde(skip_serializing_if = "NullableUpdate::is_omitted")]
    gateway_id: NullableUpdate<String>,
    #[serde(skip_serializing_if = "NullableUpdate::is_omitted")]
    gateway_pool_id: NullableUpdate<String>,
}

#[derive(Serialize)]
struct DeleteGitHubAppConnectionWire {
    #[serde(skip_serializing)]
    connection_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GitHubSecretSyncTarget {
    #[serde(skip_serializing)]
    sync_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GitHubSecretSyncOptionsWire {
    initial_sync_behavior: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_schema: Option<String>,
    disable_secret_deletion: bool,
}

impl From<GitHubSecretSyncOptions> for GitHubSecretSyncOptionsWire {
    fn from(options: GitHubSecretSyncOptions) -> Self {
        Self {
            initial_sync_behavior: "overwrite-destination",
            key_schema: options.key_schema,
            disable_secret_deletion: options.disable_secret_deletion,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateGitHubSecretSyncWire {
    name: String,
    description: Option<String>,
    project_id: String,
    connection_id: String,
    environment: String,
    secret_path: String,
    is_auto_sync_enabled: bool,
    destination_config: GitHubSecretSyncDestination,
    sync_options: GitHubSecretSyncOptionsWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateGitHubSecretSyncWire {
    #[serde(skip_serializing)]
    sync_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "NullableUpdate::is_omitted")]
    description: NullableUpdate<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_auto_sync_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_config: Option<GitHubSecretSyncDestination>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sync_options: Option<GitHubSecretSyncOptionsWire>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteGitHubSecretSyncWire {
    #[serde(skip_serializing)]
    sync_id: String,
    #[serde(skip_serializing)]
    remove_secrets: bool,
}

#[derive(Serialize)]
struct GitHubSecretSyncActionWire {
    #[serde(skip_serializing)]
    sync_id: String,
}

struct ListAppConnections;

impl sealed::Sealed for ListAppConnections {}

impl ObservableReadOperation for ListAppConnections {
    type Query = ListAppConnectionsQuery;
    type Output = AppConnectionsResponse;

    fn endpoint(_: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "app-connections")
    }
}

struct ListSecretSyncs;

impl sealed::Sealed for ListSecretSyncs {}

impl ObservableReadOperation for ListSecretSyncs {
    type Query = ProjectInventoryQuery;
    type Output = SecretSyncsResponse;

    fn endpoint(_: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "secret-syncs")
    }
}

struct ListSecretRotations;

impl sealed::Sealed for ListSecretRotations {}

impl ObservableReadOperation for ListSecretRotations {
    type Query = ProjectInventoryQuery;
    type Output = SecretRotationsResponse;

    fn endpoint(_: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V2, "secret-rotations")
    }
}

struct GetGitHubAppConnection;

impl sealed::Sealed for GetGitHubAppConnection {}

impl ObservableReadOperation for GetGitHubAppConnection {
    type Query = GitHubAppConnectionTarget;
    type Output = GitHubAppConnectionResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["app-connections", "github", query.connection_id.as_str()],
        )
    }
}

struct CreateGitHubAppConnection;

impl sealed::Sealed for CreateGitHubAppConnection {}

impl MutationOperation for CreateGitHubAppConnection {
    type Input = CreateGitHubAppConnectionWire;
    type Output = GitHubAppConnectionResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_: &Self::Input) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "app-connections/github")
    }
}

struct UpdateGitHubAppConnection;

impl sealed::Sealed for UpdateGitHubAppConnection {}

impl MutationOperation for UpdateGitHubAppConnection {
    type Input = UpdateGitHubAppConnectionWire;
    type Output = GitHubAppConnectionResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["app-connections", "github", input.connection_id.as_str()],
        )
    }
}

struct DeleteGitHubAppConnection;

impl sealed::Sealed for DeleteGitHubAppConnection {}

impl MutationOperation for DeleteGitHubAppConnection {
    type Input = DeleteGitHubAppConnectionWire;
    type Output = GitHubAppConnectionResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["app-connections", "github", input.connection_id.as_str()],
        )
    }

    fn sends_json_body() -> bool {
        false
    }
}

struct RotateGitHubAppConnectionCredentials;

impl sealed::Sealed for RotateGitHubAppConnectionCredentials {}

impl MutationOperation for RotateGitHubAppConnectionCredentials {
    type Input = GitHubAppConnectionTarget;
    type Output = GitHubAppConnectionResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "app-connections",
                "github",
                input.connection_id.as_str(),
                "rotate-credentials",
            ],
        )
    }

    fn sends_json_body() -> bool {
        false
    }
}

struct GetGitHubSecretSync;

impl sealed::Sealed for GetGitHubSecretSync {}

impl ObservableReadOperation for GetGitHubSecretSync {
    type Query = GitHubSecretSyncTarget;
    type Output = GitHubSecretSyncResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["secret-syncs", "github", query.sync_id.as_str()],
        )
    }
}

struct CreateGitHubSecretSync;

impl sealed::Sealed for CreateGitHubSecretSync {}

impl MutationOperation for CreateGitHubSecretSync {
    type Input = CreateGitHubSecretSyncWire;
    type Output = GitHubSecretSyncResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_: &Self::Input) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "secret-syncs/github")
    }
}

struct UpdateGitHubSecretSync;

impl sealed::Sealed for UpdateGitHubSecretSync {}

impl MutationOperation for UpdateGitHubSecretSync {
    type Input = UpdateGitHubSecretSyncWire;
    type Output = GitHubSecretSyncResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["secret-syncs", "github", input.sync_id.as_str()],
        )
    }
}

struct DeleteGitHubSecretSync;

impl sealed::Sealed for DeleteGitHubSecretSync {}

impl MutationOperation for DeleteGitHubSecretSync {
    type Input = DeleteGitHubSecretSyncWire;
    type Output = GitHubSecretSyncResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["secret-syncs", "github", input.sync_id.as_str()],
        )
    }

    fn query(input: &Self::Input) -> Vec<(&'static str, String)> {
        vec![("removeSecrets", input.remove_secrets.to_string())]
    }

    fn sends_json_body() -> bool {
        false
    }
}

struct RunGitHubSecretSync;

impl sealed::Sealed for RunGitHubSecretSync {}

impl MutationOperation for RunGitHubSecretSync {
    type Input = GitHubSecretSyncActionWire;
    type Output = GitHubSecretSyncResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "secret-syncs",
                "github",
                input.sync_id.as_str(),
                "sync-secrets",
            ],
        )
    }

    fn sends_json_body() -> bool {
        false
    }
}

struct RemoveGitHubSecretSyncSecrets;

impl sealed::Sealed for RemoveGitHubSecretSyncSecrets {}

impl MutationOperation for RemoveGitHubSecretSyncSecrets {
    type Input = GitHubSecretSyncActionWire;
    type Output = GitHubSecretSyncResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "secret-syncs",
                "github",
                input.sync_id.as_str(),
                "remove-secrets",
            ],
        )
    }

    fn sends_json_body() -> bool {
        false
    }
}

impl RawAppConnection {
    fn into_validated(
        self,
        expected_project: Option<&ProjectId>,
    ) -> Result<AppConnection, ResourceError> {
        validate_uuid(&self.id)?;
        validate_text(&self.name, MAX_NAME_BYTES, false)?;
        validate_optional_text(self.description.as_deref(), MAX_DESCRIPTION_BYTES)?;
        validate_uuid(&self.org_id)?;
        validate_optional_uuid(self.project_id.as_deref())?;
        validate_optional_uuid(self.gateway_id.as_deref())?;
        validate_optional_uuid(self.gateway_pool_id.as_deref())?;
        validate_version(self.version)?;
        validate_timestamp_pair(&self.created_at, &self.updated_at)?;
        if (self.gateway_id.is_some() && self.gateway_pool_id.is_some())
            || expected_project
                .is_some_and(|project| self.project_id.as_deref() != Some(project.as_str()))
        {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(AppConnection {
            id: self.id,
            name: self.name,
            description: self.description,
            provider: self.app,
            version: self.version,
            organization_id: self.org_id,
            project_id: self.project_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
            is_platform_managed_credentials: self.is_platform_managed_credentials.unwrap_or(false),
            is_auto_rotation_enabled: self.is_auto_rotation_enabled,
            gateway_id: self.gateway_id,
            gateway_pool_id: self.gateway_pool_id,
        })
    }
}

impl RawGitHubAppConnection {
    fn into_validated(
        self,
        expected_id: Option<&str>,
        expected_project: Option<&ProjectId>,
    ) -> Result<GitHubAppConnection, ResourceError> {
        let connection = self.connection.into_validated(expected_project)?;
        if connection.provider != AppConnectionProvider::GitHub
            || expected_id.is_some_and(|expected_id| connection.id != expected_id)
        {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        let instance_type = self
            .credentials
            .instance_type
            .unwrap_or(GitHubInstanceType::Cloud);
        if let Some(host) = self.credentials.host.as_deref()
            && !github_host_is_valid(host)
        {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        if instance_type == GitHubInstanceType::Server && self.credentials.host.is_none() {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(GitHubAppConnection {
            connection,
            method: self.method,
            instance: GitHubInstanceMetadata {
                instance_type,
                host: self.credentials.host,
            },
        })
    }
}

impl RawAutomationConnection {
    fn into_validated(
        self,
        expected_id: &str,
        expected_provider: AppConnectionProvider,
    ) -> Result<AutomationConnection, ResourceError> {
        validate_uuid(&self.id)?;
        validate_text(&self.name, MAX_JOINED_NAME_BYTES, false)?;
        if self.id != expected_id || self.app != expected_provider {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(AutomationConnection {
            id: self.id,
            name: self.name,
            provider: self.app,
        })
    }
}

impl RawAutomationEnvironment {
    fn into_validated(
        self,
        project_environments: &[crate::Environment],
    ) -> Result<AutomationEnvironment, ResourceError> {
        validate_uuid(&self.id)?;
        validate_text(&self.name, MAX_JOINED_NAME_BYTES, false)?;
        validate_slug(&self.slug)?;
        if !project_environments.iter().any(|environment| {
            environment.id == self.id
                && environment.name == self.name
                && environment.slug == self.slug
        }) {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(AutomationEnvironment {
            id: self.id,
            name: self.name,
            slug: self.slug,
        })
    }
}

impl RawAutomationFolder {
    fn into_validated(self, expected_id: &str) -> Result<AutomationFolder, ResourceError> {
        validate_uuid(&self.id)?;
        validate_secret_path(&self.path)?;
        if self.id != expected_id {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(AutomationFolder {
            id: self.id,
            path: self.path,
        })
    }
}

impl RawSecretSync {
    fn into_validated(
        self,
        project_id: &ProjectId,
        project_environments: &[crate::Environment],
    ) -> Result<SecretSync, ResourceError> {
        validate_uuid(&self.id)?;
        validate_text(&self.name, MAX_NAME_BYTES, false)?;
        validate_optional_text(self.description.as_deref(), MAX_DESCRIPTION_BYTES)?;
        validate_uuid(&self.project_id)?;
        validate_uuid(&self.connection_id)?;
        validate_optional_uuid(self.folder_id.as_deref())?;
        validate_version(self.version)?;
        validate_timestamp_pair(&self.created_at, &self.updated_at)?;
        validate_optional_timestamp(self.last_synced_at.as_deref())?;
        validate_optional_timestamp(self.last_imported_at.as_deref())?;
        validate_optional_timestamp(self.last_removed_at.as_deref())?;
        if self.project_id != project_id.as_str() {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        let connection = self
            .connection
            .into_validated(&self.connection_id, self.destination.connection_provider())?;
        let folder = match (self.folder_id.as_deref(), self.folder) {
            (Some(expected_id), Some(folder)) => Some(folder.into_validated(expected_id)?),
            (None, None) => None,
            _ => return Err(ResourceError::InvalidAppAutomationResponse),
        };
        let environment = self
            .environment
            .map(|environment| environment.into_validated(project_environments))
            .transpose()?;
        Ok(SecretSync {
            id: self.id,
            name: self.name,
            description: self.description,
            destination: self.destination,
            version: self.version,
            project_id: self.project_id,
            connection,
            environment,
            folder,
            is_auto_sync_enabled: self.is_auto_sync_enabled,
            sync_status: self.sync_status,
            last_synced_at: self.last_synced_at,
            import_status: self.import_status,
            last_imported_at: self.last_imported_at,
            remove_status: self.remove_status,
            last_removed_at: self.last_removed_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl RawGitHubSecretSyncOptions {
    fn into_validated(self) -> Result<GitHubSecretSyncOptions, ResourceError> {
        if self.initial_sync_behavior != GitHubInitialSyncBehavior::OverwriteDestination {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        GitHubSecretSyncOptions::new(
            self.key_schema,
            self.disable_secret_deletion.unwrap_or(false),
        )
        .map_err(|_| ResourceError::InvalidAppAutomationResponse)
    }
}

impl RawGitHubSecretSync {
    fn into_validated(
        self,
        project_id: &ProjectId,
        project_environments: &[crate::Environment],
        expected_id: Option<&str>,
    ) -> Result<GitHubSecretSync, ResourceError> {
        validate_github_destination(&self.destination_config)
            .map_err(|_| ResourceError::InvalidAppAutomationResponse)?;
        let options = self.sync_options.into_validated()?;
        let sync = self.sync.into_validated(project_id, project_environments)?;
        if sync.destination != SecretSyncDestination::GitHub
            || expected_id.is_some_and(|expected_id| sync.id != expected_id)
        {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(GitHubSecretSync {
            sync,
            destination: self.destination_config,
            options,
        })
    }
}

impl RawSecretRotation {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn into_validated(
        self,
        project_id: &ProjectId,
        project_environments: &[crate::Environment],
    ) -> Result<SecretRotation, ResourceError> {
        validate_uuid(&self.id)?;
        validate_text(&self.name, MAX_NAME_BYTES, false)?;
        validate_optional_text(self.description.as_deref(), MAX_DESCRIPTION_BYTES)?;
        validate_uuid(&self.project_id)?;
        validate_uuid(&self.connection_id)?;
        validate_uuid(&self.folder_id)?;
        validate_timestamp_pair(&self.created_at, &self.updated_at)?;
        validate_timestamp(&self.last_rotation_attempted_at)?;
        validate_timestamp(&self.last_rotated_at)?;
        validate_optional_timestamp(self.next_rotation_at.as_deref())?;
        if self.project_id != project_id.as_str()
            || self.active_index > 1
            || self.rotation_interval == 0
            || self.rotate_at_utc.hours > 23
            || self.rotate_at_utc.minutes > 59
        {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        let connection = self.connection.into_validated(
            &self.connection_id,
            self.rotation_type.connection_provider(),
        )?;
        let environment = self.environment.into_validated(project_environments)?;
        let folder = self.folder.into_validated(&self.folder_id)?;
        Ok(SecretRotation {
            id: self.id,
            name: self.name,
            description: self.description,
            rotation_type: self.rotation_type,
            project_id: self.project_id,
            connection,
            environment,
            folder,
            is_auto_rotation_enabled: self.is_auto_rotation_enabled,
            active_index: u8::try_from(self.active_index)
                .map_err(|_| ResourceError::InvalidAppAutomationResponse)?,
            rotation_interval_days: self.rotation_interval,
            rotate_at_utc: self.rotate_at_utc,
            rotation_status: self.rotation_status,
            last_rotation_attempted_at: self.last_rotation_attempted_at,
            last_rotated_at: self.last_rotated_at,
            next_rotation_at: self.next_rotation_at,
            is_last_rotation_manual: self.is_last_rotation_manual,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

fn validate_uuid(value: &str) -> Result<(), ResourceError> {
    if is_uuid(value) {
        Ok(())
    } else {
        Err(ResourceError::InvalidAppAutomationResponse)
    }
}

fn validate_optional_uuid(value: Option<&str>) -> Result<(), ResourceError> {
    value.map_or(Ok(()), validate_uuid)
}

fn validate_text(value: &str, max_bytes: usize, allow_empty: bool) -> Result<(), ResourceError> {
    if (allow_empty || !value.is_empty())
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
    {
        Ok(())
    } else {
        Err(ResourceError::InvalidAppAutomationResponse)
    }
}

fn validate_optional_text(value: Option<&str>, max_bytes: usize) -> Result<(), ResourceError> {
    value.map_or(Ok(()), |value| validate_text(value, max_bytes, true))
}

fn bounded_unpadded(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_automation_name(value: &str) -> Result<(), AppAutomationInputError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        });
    if valid {
        Ok(())
    } else {
        Err(AppAutomationInputError::InvalidName)
    }
}

fn validate_input_description(value: Option<&str>) -> Result<(), AppAutomationInputError> {
    if value.is_none_or(|value| {
        value.len() <= MAX_DESCRIPTION_BYTES
            && value.trim() == value
            && !value.chars().any(char::is_control)
    }) {
        Ok(())
    } else {
        Err(AppAutomationInputError::InvalidDescription)
    }
}

fn validate_github_secret(value: &SecretValue) -> Result<(), AppAutomationInputError> {
    if (1..=MAX_GITHUB_CREDENTIAL_BYTES).contains(&value.expose_secret().len()) {
        Ok(())
    } else {
        Err(AppAutomationInputError::InvalidCredential)
    }
}

fn github_host_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_GITHUB_HOST_BYTES
        && value.is_ascii()
        && !value.contains('_')
        && ServerName::try_from(value).is_ok()
}

fn validate_github_instance(instance: &GitHubInstance) -> Result<(), AppAutomationInputError> {
    let host = match instance {
        GitHubInstance::Cloud { host } => host.as_deref(),
        GitHubInstance::Server(host) => Some(host.as_str()),
    };
    if host.is_some_and(|host| !github_host_is_valid(host)) {
        Err(AppAutomationInputError::InvalidHost)
    } else {
        Ok(())
    }
}

fn validate_app_connection_route(
    route: &AppConnectionRoute,
) -> Result<(), AppAutomationInputError> {
    if matches!(route, AppConnectionRoute::Gateway(id) | AppConnectionRoute::GatewayPool(id) if !is_uuid(id))
    {
        Err(AppAutomationInputError::InvalidGatewayReference)
    } else {
        Ok(())
    }
}

fn validate_github_destination(
    destination: &GitHubSecretSyncDestination,
) -> Result<(), AppAutomationInputError> {
    let names_valid = match destination {
        GitHubSecretSyncDestination::Organization { org, .. } => {
            bounded_unpadded(org, MAX_GITHUB_DESTINATION_NAME_BYTES)
        }
        GitHubSecretSyncDestination::Repository { owner, repo }
        | GitHubSecretSyncDestination::RepositoryEnvironment { owner, repo, .. } => {
            bounded_unpadded(owner, MAX_GITHUB_DESTINATION_NAME_BYTES)
                && bounded_unpadded(repo, MAX_GITHUB_DESTINATION_NAME_BYTES)
        }
    };
    if !names_valid
        || matches!(
            destination,
            GitHubSecretSyncDestination::RepositoryEnvironment { env, .. }
                if !bounded_unpadded(env, MAX_GITHUB_DESTINATION_NAME_BYTES)
        )
    {
        return Err(AppAutomationInputError::InvalidDestination);
    }
    if let GitHubSecretSyncDestination::Organization {
        visibility,
        selected_repository_ids,
        ..
    } = destination
    {
        match (visibility, selected_repository_ids.as_deref()) {
            (GitHubSyncVisibility::Selected, Some(ids)) => {
                if ids.is_empty()
                    || ids.len() > MAX_GITHUB_SELECTED_REPOSITORIES
                    || ids.contains(&0)
                {
                    return Err(AppAutomationInputError::InvalidSelectedRepositories);
                }
                let mut sorted = ids.to_vec();
                sorted.sort_unstable();
                if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(AppAutomationInputError::InvalidSelectedRepositories);
                }
            }
            (GitHubSyncVisibility::Selected, None) => {
                return Err(AppAutomationInputError::InvalidSelectedRepositories);
            }
            (_, Some(ids)) if !ids.is_empty() => {
                return Err(AppAutomationInputError::InvalidSelectedRepositories);
            }
            (_, _) => {}
        }
    }
    Ok(())
}

fn validate_github_key_schema(value: &str) -> Result<(), AppAutomationInputError> {
    if value.is_empty() || value.len() > MAX_GITHUB_KEY_SCHEMA_BYTES {
        return Err(AppAutomationInputError::InvalidKeySchema);
    }
    let mut secret_key_count = 0_u8;
    let mut remainder = value;
    while !remainder.is_empty() {
        if let Some(next) = remainder.strip_prefix("{{secretKey}}") {
            secret_key_count = secret_key_count.saturating_add(1);
            remainder = next;
        } else if let Some(next) = remainder.strip_prefix("{{environment}}") {
            remainder = next;
        } else {
            let byte = remainder.as_bytes()[0];
            if !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'/')) {
                return Err(AppAutomationInputError::InvalidKeySchema);
            }
            remainder = &remainder[1..];
        }
    }
    if secret_key_count == 1 {
        Ok(())
    } else {
        Err(AppAutomationInputError::InvalidKeySchema)
    }
}

fn validate_slug(value: &str) -> Result<(), ResourceError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        });
    if valid {
        Ok(())
    } else {
        Err(ResourceError::InvalidAppAutomationResponse)
    }
}

fn validate_secret_path(value: &str) -> Result<(), ResourceError> {
    let valid = value == "/"
        || value.strip_prefix('/').is_some_and(|path| {
            !path.is_empty()
                && path.split('/').all(|segment| {
                    !segment.is_empty()
                        && segment != "."
                        && segment != ".."
                        && !segment.chars().any(char::is_control)
                })
        });
    if value.len() <= MAX_SECRET_PATH_BYTES && valid {
        Ok(())
    } else {
        Err(ResourceError::InvalidAppAutomationResponse)
    }
}

fn validate_version(version: u32) -> Result<(), ResourceError> {
    if version > 0 {
        Ok(())
    } else {
        Err(ResourceError::InvalidAppAutomationResponse)
    }
}

fn validate_timestamp(value: &str) -> Result<i64, ResourceError> {
    utc_timestamp_millis(value).ok_or(ResourceError::InvalidAppAutomationResponse)
}

fn validate_optional_timestamp(value: Option<&str>) -> Result<(), ResourceError> {
    value.map_or(Ok(()), |value| validate_timestamp(value).map(|_| ()))
}

fn validate_timestamp_pair(created_at: &str, updated_at: &str) -> Result<(), ResourceError> {
    let created = validate_timestamp(created_at)?;
    let updated = validate_timestamp(updated_at)?;
    if updated >= created {
        Ok(())
    } else {
        Err(ResourceError::InvalidAppAutomationResponse)
    }
}

pub(crate) fn project_environments(
    project: crate::Project,
    expected_project_id: &ProjectId,
) -> Result<Vec<crate::Environment>, ResourceError> {
    validate_uuid(&project.id)?;
    if project.id != expected_project_id.as_str() {
        return Err(ResourceError::InvalidAppAutomationResponse);
    }
    for environment in &project.environments {
        validate_uuid(&environment.id)?;
        validate_text(&environment.name, MAX_JOINED_NAME_BYTES, false)?;
        validate_slug(&environment.slug)?;
    }
    Ok(project.environments)
}

fn create_route_wire(route: &AppConnectionRoute) -> (Option<String>, Option<String>) {
    match route {
        AppConnectionRoute::Direct => (None, None),
        AppConnectionRoute::Gateway(id) => (Some(id.clone()), None),
        AppConnectionRoute::GatewayPool(id) => (None, Some(id.clone())),
    }
}

fn update_route_wire(
    route: Option<AppConnectionRoute>,
) -> (NullableUpdate<String>, NullableUpdate<String>) {
    match route {
        None => (NullableUpdate::Omitted, NullableUpdate::Omitted),
        Some(AppConnectionRoute::Direct) => (NullableUpdate::Null, NullableUpdate::Null),
        Some(AppConnectionRoute::Gateway(id)) => (NullableUpdate::Value(id), NullableUpdate::Null),
        Some(AppConnectionRoute::GatewayPool(id)) => {
            (NullableUpdate::Null, NullableUpdate::Value(id))
        }
    }
}

fn description_change_wire(change: AutomationDescriptionChange) -> NullableUpdate<String> {
    match change {
        AutomationDescriptionChange::Keep => NullableUpdate::Omitted,
        AutomationDescriptionChange::Clear => NullableUpdate::Null,
        AutomationDescriptionChange::Set(description) => NullableUpdate::Value(description),
    }
}

fn source_secret_path(sync: &SecretSync) -> &str {
    sync.folder
        .as_ref()
        .map_or("/", |folder| folder.path.as_str())
}

fn environment_exists(environments: &[crate::Environment], slug: &EnvironmentSlug) -> bool {
    environments
        .iter()
        .any(|environment| environment.slug == slug.as_str())
}

impl InfisicalClient {
    /// Get one value-free GitHub app connection by exact UUID.
    ///
    /// Infisical records this GET as an audit event, so it is sent exactly once.
    ///
    /// # Errors
    ///
    /// Returns an input, typed client, or response-contract error.
    pub async fn get_github_app_connection(
        &self,
        connection_id: &str,
    ) -> Result<GitHubAppConnection, ResourceError> {
        if !is_uuid(connection_id) {
            return Err(ResourceError::InvalidAppAutomationScope);
        }
        self.execute_observable_read::<GetGitHubAppConnection>(&GitHubAppConnectionTarget {
            connection_id: connection_id.to_owned(),
        })
        .await?
        .app_connection
        .into_validated(Some(connection_id), None)
    }

    /// Create one typed GitHub app connection.
    ///
    /// # Errors
    ///
    /// Returns a typed client or response-contract error. Infisical validates
    /// the supplied provider credential and the mutation is sent exactly once.
    pub async fn create_github_app_connection(
        &self,
        creation: GitHubAppConnectionCreation,
    ) -> Result<GitHubAppConnection, ResourceError> {
        let expected_name = creation.name.clone();
        let expected_description = creation.description.clone();
        let expected_project = creation.project_id;
        let expected_project_id = expected_project.as_ref().map(ProjectId::as_str);
        let expected_method = creation.credentials.method();
        let expected_instance = creation.credentials.instance_metadata();
        let (gateway_id, gateway_pool_id) = create_route_wire(&creation.route);
        let wire = CreateGitHubAppConnectionWire {
            name: creation.name,
            description: creation.description,
            project_id: expected_project
                .as_ref()
                .map(|project_id| project_id.as_str().to_owned()),
            method: expected_method,
            credentials: creation.credentials,
            is_platform_managed_credentials: false,
            is_auto_rotation_enabled: false,
            gateway_id: gateway_id.clone(),
            gateway_pool_id: gateway_pool_id.clone(),
        };
        let connection = self
            .execute_mutation::<CreateGitHubAppConnection>(&wire)
            .await?
            .app_connection
            .into_validated(None, expected_project.as_ref())?;
        if connection.connection.name != expected_name
            || connection.connection.description != expected_description
            || connection.connection.project_id.as_deref() != expected_project_id
            || connection.connection.gateway_id != gateway_id
            || connection.connection.gateway_pool_id != gateway_pool_id
            || connection.connection.is_platform_managed_credentials
            || connection.connection.is_auto_rotation_enabled
            || connection.method != expected_method
            || connection.instance != expected_instance
        {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(connection)
    }

    /// Update one GitHub app connection with a non-empty typed change.
    ///
    /// Credential replacement first performs one audited exact read to prove
    /// the immutable stored method. The mutation itself is sent once.
    ///
    /// # Errors
    ///
    /// Returns an input, typed client, scope, or response-contract error.
    pub async fn update_github_app_connection(
        &self,
        connection_id: &str,
        change: GitHubAppConnectionChange,
        confirm_credential_replacement: bool,
    ) -> Result<GitHubAppConnection, ResourceError> {
        if change.credentials.is_some() && !confirm_credential_replacement {
            return Err(ResourceError::AppConnectionCredentialReplacementNotConfirmed);
        }
        if !is_uuid(connection_id) {
            return Err(ResourceError::InvalidAppAutomationScope);
        }
        let expected_method = change
            .credentials
            .as_ref()
            .map(GitHubAppConnectionCredentials::method);
        let expected_instance = change
            .credentials
            .as_ref()
            .map(GitHubAppConnectionCredentials::instance_metadata);
        if let Some(expected_method) = expected_method {
            let current = self.get_github_app_connection(connection_id).await?;
            if current.method != expected_method {
                return Err(ResourceError::InvalidAppAutomationScope);
            }
        }
        let (gateway_id, gateway_pool_id) = update_route_wire(change.route);
        let wire = UpdateGitHubAppConnectionWire {
            connection_id: connection_id.to_owned(),
            name: change.name,
            description: description_change_wire(change.description),
            credentials: change.credentials,
            gateway_id,
            gateway_pool_id,
        };
        let connection = self
            .execute_mutation::<UpdateGitHubAppConnection>(&wire)
            .await?
            .app_connection
            .into_validated(Some(connection_id), None)?;
        if wire
            .name
            .as_ref()
            .is_some_and(|name| connection.connection.name != *name)
            || !wire
                .description
                .matches(connection.connection.description.as_ref())
            || !wire
                .gateway_id
                .matches(connection.connection.gateway_id.as_ref())
            || !wire
                .gateway_pool_id
                .matches(connection.connection.gateway_pool_id.as_ref())
            || expected_method.is_some_and(|method| connection.method != method)
            || expected_instance
                .as_ref()
                .is_some_and(|instance| connection.instance != *instance)
        {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(connection)
    }

    /// Delete one exact GitHub app connection after confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, input, typed client, or response-contract error.
    pub async fn delete_github_app_connection(
        &self,
        connection_id: &str,
        confirm: bool,
    ) -> Result<GitHubAppConnection, ResourceError> {
        if !confirm {
            return Err(ResourceError::AppConnectionDeletionNotConfirmed);
        }
        if !is_uuid(connection_id) {
            return Err(ResourceError::InvalidAppAutomationScope);
        }
        self.execute_mutation::<DeleteGitHubAppConnection>(&DeleteGitHubAppConnectionWire {
            connection_id: connection_id.to_owned(),
        })
        .await?
        .app_connection
        .into_validated(Some(connection_id), None)
    }

    /// Rotate the credentials of one exact GitHub app connection after confirmation.
    ///
    /// The action is non-replayable and returns only value-free connection metadata.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, input, typed client, or response-contract error.
    pub async fn rotate_github_app_connection_credentials(
        &self,
        connection_id: &str,
        confirm: bool,
    ) -> Result<GitHubAppConnection, ResourceError> {
        if !confirm {
            return Err(ResourceError::AppConnectionCredentialRotationNotConfirmed);
        }
        if !is_uuid(connection_id) {
            return Err(ResourceError::InvalidAppAutomationScope);
        }
        self.execute_mutation::<RotateGitHubAppConnectionCredentials>(&GitHubAppConnectionTarget {
            connection_id: connection_id.to_owned(),
        })
        .await?
        .app_connection
        .into_validated(Some(connection_id), None)
    }

    async fn github_secret_sync_with_environments(
        &self,
        project_id: &ProjectId,
        sync_id: &str,
    ) -> Result<(GitHubSecretSync, Vec<crate::Environment>), ResourceError> {
        if !is_uuid(sync_id) {
            return Err(ResourceError::InvalidAppAutomationScope);
        }
        let response = self
            .execute_observable_read::<GetGitHubSecretSync>(&GitHubSecretSyncTarget {
                sync_id: sync_id.to_owned(),
            })
            .await?;
        let environments = self
            .get_project(project_id)
            .await?
            .ok_or(ResourceError::InvalidAppAutomationScope)
            .and_then(|project| project_environments(project, project_id))?;
        let sync = response
            .secret_sync
            .into_validated(project_id, &environments, Some(sync_id))?;
        Ok((sync, environments))
    }

    /// Get one typed, value-free GitHub secret sync by exact UUID and project.
    ///
    /// Infisical records the provider GET as an audit event, so it is sent exactly once.
    ///
    /// # Errors
    ///
    /// Returns an input, typed client, scope, or response-contract error.
    pub async fn get_github_secret_sync(
        &self,
        project_id: &ProjectId,
        sync_id: &str,
    ) -> Result<GitHubSecretSync, ResourceError> {
        self.github_secret_sync_with_environments(project_id, sync_id)
            .await
            .map(|(sync, _)| sync)
    }

    /// Create one typed GitHub secret sync after confirming the initial overwrite.
    ///
    /// The project environment is validated before the single mutation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, typed client, scope, or response-contract error.
    pub async fn create_github_secret_sync(
        &self,
        project_id: &ProjectId,
        creation: GitHubSecretSyncCreation,
        confirm_initial_overwrite: bool,
    ) -> Result<GitHubSecretSync, ResourceError> {
        if !confirm_initial_overwrite {
            return Err(ResourceError::SecretSyncInitialOverwriteNotConfirmed);
        }
        let environments = self
            .get_project(project_id)
            .await?
            .ok_or(ResourceError::InvalidAppAutomationScope)
            .and_then(|project| project_environments(project, project_id))?;
        if !environment_exists(&environments, &creation.environment) {
            return Err(ResourceError::InvalidAppAutomationScope);
        }
        let wire = CreateGitHubSecretSyncWire {
            name: creation.name,
            description: creation.description,
            project_id: project_id.as_str().to_owned(),
            connection_id: creation.connection_id,
            environment: creation.environment.as_str().to_owned(),
            secret_path: creation.secret_path.as_str().to_owned(),
            is_auto_sync_enabled: creation.is_auto_sync_enabled,
            destination_config: creation.destination,
            sync_options: creation.options.into(),
        };
        let sync = self
            .execute_mutation::<CreateGitHubSecretSync>(&wire)
            .await?
            .secret_sync
            .into_validated(project_id, &environments, None)?;
        if sync.sync.name != wire.name
            || sync.sync.description != wire.description
            || sync.sync.connection.id != wire.connection_id
            || sync
                .sync
                .environment
                .as_ref()
                .map(|environment| environment.slug.as_str())
                != Some(wire.environment.as_str())
            || source_secret_path(&sync.sync) != wire.secret_path
            || sync.sync.is_auto_sync_enabled != wire.is_auto_sync_enabled
            || sync.destination != wire.destination_config
            || sync.options.key_schema != wire.sync_options.key_schema
            || sync.options.disable_secret_deletion != wire.sync_options.disable_secret_deletion
        {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(sync)
    }

    /// Update one exact GitHub secret sync after an audited scope preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, input, typed client, scope, or response-contract error.
    pub async fn update_github_secret_sync(
        &self,
        project_id: &ProjectId,
        sync_id: &str,
        change: GitHubSecretSyncChange,
        confirm: bool,
    ) -> Result<GitHubSecretSync, ResourceError> {
        if !confirm {
            return Err(ResourceError::SecretSyncUpdateNotConfirmed);
        }
        let (_, environments) = self
            .github_secret_sync_with_environments(project_id, sync_id)
            .await?;
        if change
            .environment
            .as_ref()
            .is_some_and(|environment| !environment_exists(&environments, environment))
        {
            return Err(ResourceError::InvalidAppAutomationScope);
        }
        let wire = UpdateGitHubSecretSyncWire {
            sync_id: sync_id.to_owned(),
            name: change.name,
            description: description_change_wire(change.description),
            connection_id: change.connection_id,
            environment: change
                .environment
                .map(|environment| environment.as_str().to_owned()),
            secret_path: change
                .secret_path
                .map(|secret_path| secret_path.as_str().to_owned()),
            is_auto_sync_enabled: change.is_auto_sync_enabled,
            destination_config: change.destination,
            sync_options: change.options.map(Into::into),
        };
        let sync = self
            .execute_mutation::<UpdateGitHubSecretSync>(&wire)
            .await?
            .secret_sync
            .into_validated(project_id, &environments, Some(sync_id))?;
        if wire
            .name
            .as_ref()
            .is_some_and(|name| sync.sync.name != *name)
            || !wire.description.matches(sync.sync.description.as_ref())
            || wire
                .connection_id
                .as_ref()
                .is_some_and(|connection_id| sync.sync.connection.id != *connection_id)
            || wire.environment.as_ref().is_some_and(|environment| {
                sync.sync.environment.as_ref().map(|value| &value.slug) != Some(environment)
            })
            || wire
                .secret_path
                .as_ref()
                .is_some_and(|path| source_secret_path(&sync.sync) != path)
            || wire
                .is_auto_sync_enabled
                .is_some_and(|enabled| sync.sync.is_auto_sync_enabled != enabled)
            || wire
                .destination_config
                .as_ref()
                .is_some_and(|destination| sync.destination != *destination)
            || wire.sync_options.as_ref().is_some_and(|options| {
                sync.options.key_schema != options.key_schema
                    || sync.options.disable_secret_deletion != options.disable_secret_deletion
            })
        {
            return Err(ResourceError::InvalidAppAutomationResponse);
        }
        Ok(sync)
    }

    /// Delete one exact GitHub secret sync, optionally removing destination secrets.
    ///
    /// Remote removal requires a second independent confirmation. The provider
    /// sync is scope-checked before the single delete attempt.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, input, typed client, scope, or response-contract error.
    pub async fn delete_github_secret_sync(
        &self,
        project_id: &ProjectId,
        sync_id: &str,
        remove_secrets: bool,
        confirm_delete: bool,
        confirm_remote_removal: bool,
    ) -> Result<GitHubSecretSync, ResourceError> {
        if !confirm_delete {
            return Err(ResourceError::SecretSyncDeletionNotConfirmed);
        }
        if remove_secrets && !confirm_remote_removal {
            return Err(ResourceError::SecretSyncRemoteRemovalNotConfirmed);
        }
        let (_, environments) = self
            .github_secret_sync_with_environments(project_id, sync_id)
            .await?;
        self.execute_mutation::<DeleteGitHubSecretSync>(&DeleteGitHubSecretSyncWire {
            sync_id: sync_id.to_owned(),
            remove_secrets,
        })
        .await?
        .secret_sync
        .into_validated(project_id, &environments, Some(sync_id))
    }

    /// Trigger one manual outbound GitHub secret sync after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, input, typed client, scope, or response-contract error.
    pub async fn run_github_secret_sync(
        &self,
        project_id: &ProjectId,
        sync_id: &str,
        confirm: bool,
    ) -> Result<GitHubSecretSync, ResourceError> {
        if !confirm {
            return Err(ResourceError::SecretSyncRunNotConfirmed);
        }
        let (_, environments) = self
            .github_secret_sync_with_environments(project_id, sync_id)
            .await?;
        self.execute_mutation::<RunGitHubSecretSync>(&GitHubSecretSyncActionWire {
            sync_id: sync_id.to_owned(),
        })
        .await?
        .secret_sync
        .into_validated(project_id, &environments, Some(sync_id))
    }

    /// Remove previously synchronized GitHub destination secrets after confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, input, typed client, scope, or response-contract error.
    pub async fn remove_github_secret_sync_secrets(
        &self,
        project_id: &ProjectId,
        sync_id: &str,
        confirm: bool,
    ) -> Result<GitHubSecretSync, ResourceError> {
        if !confirm {
            return Err(ResourceError::SecretSyncRemoteRemovalNotConfirmed);
        }
        let (_, environments) = self
            .github_secret_sync_with_environments(project_id, sync_id)
            .await?;
        self.execute_mutation::<RemoveGitHubSecretSyncSecrets>(&GitHubSecretSyncActionWire {
            sync_id: sync_id.to_owned(),
        })
        .await?
        .secret_sync
        .into_validated(project_id, &environments, Some(sync_id))
    }

    /// List a bounded local page of value-free app connections.
    ///
    /// Infisical records this GET as an audit event, so it is sent exactly once.
    ///
    /// # Errors
    ///
    /// Returns a typed client, response-contract, or pagination error.
    pub async fn list_app_connections(
        &self,
        project_id: Option<&ProjectId>,
        page: PageRequest,
    ) -> Result<Page<AppConnection>, ResourceError> {
        let response = self
            .execute_observable_read::<ListAppConnections>(&ListAppConnectionsQuery {
                project_id: project_id.map(|project_id| project_id.as_str().to_owned()),
            })
            .await?;
        let connections = response
            .app_connections
            .into_iter()
            .map(|connection| connection.into_validated(project_id))
            .collect::<Result<Vec<_>, _>>()?;
        paginate(page, connections)
    }

    /// List a bounded local page of value-free secret-sync inventory records.
    ///
    /// Infisical records this GET as an audit event, so it is sent exactly once.
    ///
    /// # Errors
    ///
    /// Returns a typed client, response-contract, or pagination error.
    pub async fn list_secret_syncs(
        &self,
        project_id: &ProjectId,
        page: PageRequest,
    ) -> Result<Page<SecretSync>, ResourceError> {
        let response = self
            .execute_observable_read::<ListSecretSyncs>(&ProjectInventoryQuery {
                project_id: project_id.as_str().to_owned(),
            })
            .await?;
        let environments = self
            .get_project(project_id)
            .await?
            .ok_or(ResourceError::InvalidAppAutomationResponse)
            .and_then(|project| project_environments(project, project_id))?;
        let syncs = response
            .secret_syncs
            .into_iter()
            .map(|sync| sync.into_validated(project_id, &environments))
            .collect::<Result<Vec<_>, _>>()?;
        paginate(page, syncs)
    }

    /// List a bounded local page of value-free secret-rotation inventory records.
    ///
    /// Infisical records this GET as an audit event, so it is sent exactly once.
    ///
    /// # Errors
    ///
    /// Returns a typed client, response-contract, or pagination error.
    pub async fn list_secret_rotations(
        &self,
        project_id: &ProjectId,
        page: PageRequest,
    ) -> Result<Page<SecretRotation>, ResourceError> {
        let response = self
            .execute_observable_read::<ListSecretRotations>(&ProjectInventoryQuery {
                project_id: project_id.as_str().to_owned(),
            })
            .await?;
        let environments = self
            .get_project(project_id)
            .await?
            .ok_or(ResourceError::InvalidAppAutomationResponse)
            .and_then(|project| project_environments(project, project_id))?;
        let rotations = response
            .secret_rotations
            .into_iter()
            .map(|rotation| rotation.into_validated(project_id, &environments))
            .collect::<Result<Vec<_>, _>>()?;
        paginate(page, rotations)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path, query_param},
    };

    use super::{
        AppAutomationInputError, AppConnectionProvider, AppConnectionRoute,
        AutomationDescriptionChange, GitHubAppConnectionChange, GitHubAppConnectionCreation,
        GitHubAppConnectionCredentials, GitHubConnectionMethod, GitHubInstance,
        GitHubSecretSyncChange, GitHubSecretSyncCreation, GitHubSecretSyncDestination,
        GitHubSecretSyncOptions, GitHubSecretSyncSource, GitHubSyncVisibility,
        SecretRotationStatus, SecretRotationType, SecretSyncDestination, SecretSyncStatus,
    };
    use crate::{
        ApiErrorKind, EnvironmentSlug, InfisicalClient, PageRequest, ProjectId, ResourceError,
        SecretPath, SecretValue,
        test_support::{mount_login, settings},
    };

    const PROJECT_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const CONNECTION_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const FOLDER_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const ENVIRONMENT_ID: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    const SYNC_ID: &str = "11111111-1111-4111-8111-111111111111";
    const GATEWAY_ID: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

    async fn mount_project_environment_inventory(server: &MockServer, expected: u64) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{PROJECT_ID}")))
            .and(header("authorization", "Bearer inventory-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": {
                    "id": PROJECT_ID,
                    "name": "Platform",
                    "slug": "platform",
                    "type": "secret-manager",
                    "orgId": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    "environments": [project_environment_fixture()]
                }
            })))
            .expect(expected)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn inventory_lists_use_exact_observable_routes_and_omit_provider_payloads() {
        let server = MockServer::start().await;
        mount_login(&server, "inventory-token").await;
        mount_project_environment_inventory(&server, 2).await;
        Mock::given(method("GET"))
            .and(path("/api/v1/app-connections"))
            .and(header("authorization", "Bearer inventory-token"))
            .and(query_param("projectId", PROJECT_ID))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnections": [app_connection_fixture(PROJECT_ID)]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/secret-syncs"))
            .and(header("authorization", "Bearer inventory-token"))
            .and(query_param("projectId", PROJECT_ID))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretSyncs": [secret_sync_fixture(PROJECT_ID)]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v2/secret-rotations"))
            .and(header("authorization", "Bearer inventory-token"))
            .and(query_param("projectId", PROJECT_ID))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretRotations": [secret_rotation_fixture(PROJECT_ID)]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new(PROJECT_ID).unwrap();
        let page = PageRequest::new(0, 10).unwrap();
        let connections = client
            .list_app_connections(Some(&project_id), page)
            .await
            .unwrap();
        let syncs = client.list_secret_syncs(&project_id, page).await.unwrap();
        let rotations = client
            .list_secret_rotations(&project_id, page)
            .await
            .unwrap();

        assert_eq!(connections.items[0].provider, AppConnectionProvider::GitHub);
        assert_eq!(syncs.items[0].destination, SecretSyncDestination::GitHub);
        assert_eq!(
            syncs.items[0].sync_status,
            Some(SecretSyncStatus::Succeeded)
        );
        assert_eq!(
            rotations.items[0].rotation_type,
            SecretRotationType::PostgresCredentials
        );
        assert_eq!(
            rotations.items[0].rotation_status,
            SecretRotationStatus::Success
        );
        for value in [
            serde_json::to_value(&connections.items[0]).unwrap(),
            serde_json::to_value(&syncs.items[0]).unwrap(),
            serde_json::to_value(&rotations.items[0]).unwrap(),
        ] {
            let encoded = value.to_string();
            for forbidden in [
                "credentialsHash",
                "configuration",
                "destinationConfig",
                "syncOptions",
                "parameters",
                "secretsMapping",
                "lastSyncMessage",
                "lastRotationMessage",
            ] {
                assert!(!encoded.contains(forbidden), "{forbidden}");
            }
        }
    }

    #[tokio::test]
    async fn inventory_lists_reject_scope_and_join_drift() {
        let cases = [
            (
                "/api/v1/app-connections",
                "appConnections",
                app_connection_fixture("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
                1_u8,
            ),
            (
                "/api/v1/secret-syncs",
                "secretSyncs",
                secret_sync_fixture("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
                1_u8,
            ),
            (
                "/api/v2/secret-rotations",
                "secretRotations",
                mismatched_rotation_fixture(PROJECT_ID),
                2_u8,
            ),
        ];
        for (route, key, fixture, version) in cases {
            let server = MockServer::start().await;
            mount_login(&server, "inventory-token").await;
            if key != "appConnections" {
                mount_project_environment_inventory(&server, 1).await;
            }
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ key: [fixture] })))
                .mount(&server)
                .await;
            let client = InfisicalClient::new(settings(&server)).unwrap();
            let project_id = ProjectId::new(PROJECT_ID).unwrap();
            let page = PageRequest::new(0, 10).unwrap();
            let result = match version {
                1 if key == "appConnections" => client
                    .list_app_connections(Some(&project_id), page)
                    .await
                    .map(|_| ()),
                1 => client
                    .list_secret_syncs(&project_id, page)
                    .await
                    .map(|_| ()),
                _ => client
                    .list_secret_rotations(&project_id, page)
                    .await
                    .map(|_| ()),
            };
            assert_eq!(
                result.unwrap_err(),
                ResourceError::InvalidAppAutomationResponse
            );
        }
    }

    #[tokio::test]
    async fn observable_inventory_read_is_never_replayed_after_authentication_rejection() {
        let server = MockServer::start().await;
        mount_login(&server, "rejected-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/app-connections"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "message": "expired"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .list_app_connections(None, PageRequest::new(0, 10).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ResourceError::Client(crate::ClientError::Api(ref failure))
                if failure.kind() == ApiErrorKind::Authentication
        ));
    }

    #[test]
    fn github_inputs_validate_closed_credentials_destinations_and_templates() {
        let credentials = GitHubAppConnectionCredentials::personal_access_token(
            SecretValue::new("github-canary-token"),
            GitHubInstance::Server("github.example.com".to_owned()),
        )
        .unwrap();
        let serialized = serde_json::to_value(&credentials).unwrap();
        assert_eq!(serialized["instanceType"], "server");
        assert_eq!(serialized["host"], "github.example.com");
        assert_eq!(serialized["personalAccessToken"], "github-canary-token");
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("github-canary-token"));
        assert!(debug.contains("[REDACTED]"));

        assert!(
            GitHubAppConnectionCredentials::oauth(
                SecretValue::new(""),
                GitHubInstance::Cloud { host: None }
            )
            .is_err()
        );
        assert!(
            GitHubAppConnectionCredentials::oauth(
                SecretValue::new("code"),
                GitHubInstance::Server("https://github.example.com/path".to_owned())
            )
            .is_err()
        );
        assert!(
            GitHubSecretSyncOptions::new(Some("{{environment}}/{{secretKey}}".to_owned()), false)
                .is_ok()
        );
        for invalid in [
            "{{environment}}",
            "{{secretKey}}/{{secretKey}}",
            "{{secretKey}}.value",
            "{{unknown}}/{{secretKey}}",
        ] {
            assert!(
                GitHubSecretSyncOptions::new(Some(invalid.to_owned()), false).is_err(),
                "accepted invalid key schema {invalid}"
            );
        }
        assert!(
            super::validate_github_destination(&GitHubSecretSyncDestination::Organization {
                org: "platform".to_owned(),
                visibility: GitHubSyncVisibility::Selected,
                selected_repository_ids: Some(vec![10, 20]),
            })
            .is_ok()
        );
        assert!(
            super::validate_github_destination(&GitHubSecretSyncDestination::Organization {
                org: "platform".to_owned(),
                visibility: GitHubSyncVisibility::Selected,
                selected_repository_ids: Some(vec![10, 10]),
            })
            .is_err()
        );

        let source = || {
            GitHubSecretSyncSource::new(
                CONNECTION_ID,
                EnvironmentSlug::new("prod").unwrap(),
                SecretPath::new("/apps").unwrap(),
            )
            .unwrap()
        };
        let invalid_options = || GitHubSecretSyncOptions {
            key_schema: Some("{{unknown}}".to_owned()),
            disable_secret_deletion: false,
        };
        assert_eq!(
            GitHubSecretSyncCreation::new(
                "github-actions",
                None,
                source(),
                true,
                GitHubSecretSyncDestination::Repository {
                    owner: "platform".to_owned(),
                    repo: "api".to_owned(),
                },
                invalid_options(),
            )
            .unwrap_err(),
            AppAutomationInputError::InvalidKeySchema
        );
        assert_eq!(
            GitHubSecretSyncChange::new(
                None,
                AutomationDescriptionChange::Keep,
                None,
                None,
                None,
                None,
                None,
                Some(invalid_options()),
            )
            .unwrap_err(),
            AppAutomationInputError::InvalidKeySchema
        );
    }

    #[test]
    fn github_credentials_validate_and_serialize_each_closed_variant() {
        let app = GitHubAppConnectionCredentials::github_app(
            SecretValue::new("app-code"),
            "installation-42",
            GitHubInstance::Cloud { host: None },
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&app).unwrap(),
            json!({
                "code": "app-code",
                "installationId": "installation-42",
                "instanceType": "cloud"
            })
        );
        let oauth = GitHubAppConnectionCredentials::oauth(
            SecretValue::new("oauth-code"),
            GitHubInstance::Server("github.example.com".to_owned()),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&oauth).unwrap(),
            json!({
                "code": "oauth-code",
                "instanceType": "server",
                "host": "github.example.com"
            })
        );
        let enterprise_cloud = GitHubAppConnectionCredentials::oauth(
            SecretValue::new("enterprise-cloud-code"),
            GitHubInstance::Cloud {
                host: Some("octocat.ghe.com".to_owned()),
            },
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&enterprise_cloud).unwrap(),
            json!({
                "code": "enterprise-cloud-code",
                "instanceType": "cloud",
                "host": "octocat.ghe.com"
            })
        );
        for installation_id in [
            String::new(),
            " padded".to_owned(),
            "line\nbreak".to_owned(),
            "x".repeat(super::MAX_GITHUB_INSTALLATION_ID_BYTES + 1),
        ] {
            assert_eq!(
                GitHubAppConnectionCredentials::github_app(
                    SecretValue::new("app-code"),
                    installation_id,
                    GitHubInstance::Cloud { host: None },
                )
                .unwrap_err(),
                AppAutomationInputError::InvalidInstallationId
            );
        }
    }

    #[test]
    fn github_input_text_and_route_predicates_enforce_each_boundary() {
        for (value, valid) in [
            ("value", true),
            ("", false),
            (" padded", false),
            ("padded ", false),
            ("line\nbreak", false),
        ] {
            assert_eq!(super::bounded_unpadded(value, 32), valid, "{value:?}");
        }
        assert!(super::bounded_unpadded(&"x".repeat(32), 32));
        assert!(!super::bounded_unpadded(&"x".repeat(33), 32));

        for (name, valid) in [
            ("github-primary", true),
            ("", false),
            ("-github", false),
            ("github-", false),
            ("github--primary", false),
            ("GitHub", false),
            ("github_primary", false),
        ] {
            assert_eq!(
                super::validate_automation_name(name).is_ok(),
                valid,
                "{name}"
            );
        }
        assert!(super::validate_automation_name(&"x".repeat(super::MAX_NAME_BYTES)).is_ok());
        assert!(super::validate_automation_name(&"x".repeat(super::MAX_NAME_BYTES + 1)).is_err());

        assert!(super::validate_input_description(None).is_ok());
        assert!(super::validate_input_description(Some("")).is_ok());
        assert!(super::validate_input_description(Some("description")).is_ok());
        assert!(super::validate_input_description(Some(" padded")).is_err());
        assert!(super::validate_input_description(Some("line\nbreak")).is_err());
        assert!(
            super::validate_input_description(Some(&"x".repeat(super::MAX_DESCRIPTION_BYTES + 1)))
                .is_err()
        );

        assert!(super::validate_app_connection_route(&AppConnectionRoute::Direct).is_ok());
        assert!(
            super::validate_app_connection_route(&AppConnectionRoute::Gateway(
                GATEWAY_ID.to_owned()
            ))
            .is_ok()
        );
        for route in [
            AppConnectionRoute::Gateway("not-a-uuid".to_owned()),
            AppConnectionRoute::GatewayPool("not-a-uuid".to_owned()),
        ] {
            assert_eq!(
                super::validate_app_connection_route(&route).unwrap_err(),
                AppAutomationInputError::InvalidGatewayReference
            );
        }
    }

    #[test]
    fn github_destinations_enforce_each_scope_and_selection_invariant() {
        let repository = |owner: &str, repo: &str| GitHubSecretSyncDestination::Repository {
            owner: owner.to_owned(),
            repo: repo.to_owned(),
        };
        let environment = |env: &str| GitHubSecretSyncDestination::RepositoryEnvironment {
            owner: "platform".to_owned(),
            repo: "api".to_owned(),
            env: env.to_owned(),
        };
        assert!(super::validate_github_destination(&repository("platform", "api")).is_ok());
        assert!(super::validate_github_destination(&environment("prod")).is_ok());
        for invalid in [
            repository("", "api"),
            repository("platform", ""),
            repository(" platform", "api"),
            environment(""),
        ] {
            assert_eq!(
                super::validate_github_destination(&invalid).unwrap_err(),
                AppAutomationInputError::InvalidDestination
            );
        }

        let organization = |visibility, ids| GitHubSecretSyncDestination::Organization {
            org: "platform".to_owned(),
            visibility,
            selected_repository_ids: ids,
        };
        for valid in [
            organization(GitHubSyncVisibility::All, None),
            organization(GitHubSyncVisibility::Private, Some(Vec::new())),
            organization(GitHubSyncVisibility::Selected, Some(vec![1, 2])),
        ] {
            assert!(super::validate_github_destination(&valid).is_ok());
        }
        for invalid in [
            organization(GitHubSyncVisibility::All, Some(vec![1])),
            organization(GitHubSyncVisibility::Selected, None),
            organization(GitHubSyncVisibility::Selected, Some(Vec::new())),
            organization(GitHubSyncVisibility::Selected, Some(vec![0])),
            organization(GitHubSyncVisibility::Selected, Some(vec![1, 1])),
            organization(
                GitHubSyncVisibility::Selected,
                Some(vec![1; super::MAX_GITHUB_SELECTED_REPOSITORIES + 1]),
            ),
        ] {
            assert_eq!(
                super::validate_github_destination(&invalid).unwrap_err(),
                AppAutomationInputError::InvalidSelectedRepositories
            );
        }
    }

    #[test]
    fn github_key_schema_accepts_the_limit_and_rejects_each_invalid_class() {
        let at_limit = format!(
            "{{{{secretKey}}}}{}",
            "x".repeat(super::MAX_GITHUB_KEY_SCHEMA_BYTES - "{{secretKey}}".len())
        );
        assert!(super::validate_github_key_schema(&at_limit).is_ok());
        assert!(super::validate_github_key_schema("").is_err());
        assert!(super::validate_github_key_schema(&format!("{at_limit}x")).is_err());
        for invalid in [
            "{{environment}}",
            "{{secretKey}}/{{secretKey}}",
            "{{secretKey}}.value",
            "{{unknown}}/{{secretKey}}",
        ] {
            assert!(
                super::validate_github_key_schema(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[tokio::test]
    async fn github_app_connection_create_and_get_use_typed_redacted_contracts() {
        let server = MockServer::start().await;
        mount_login(&server, "github-token").await;
        let create_response = github_connection_fixture(PROJECT_ID);
        Mock::given(method("POST"))
            .and(path("/api/v1/app-connections/github"))
            .and(header("authorization", "Bearer github-token"))
            .and(body_json(json!({
                "name": "github-primary",
                "description": "GitHub connection",
                "projectId": PROJECT_ID,
                "method": "pat",
                "credentials": {
                    "personalAccessToken": "first-pat",
                    "instanceType": "cloud"
                },
                "isPlatformManagedCredentials": false,
                "isAutoRotationEnabled": false,
                "gatewayId": null,
                "gatewayPoolId": null
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnection": create_response
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/app-connections/github/{CONNECTION_ID}"
            )))
            .and(header("authorization", "Bearer github-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnection": github_connection_fixture(PROJECT_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new(PROJECT_ID).unwrap();
        let created = client
            .create_github_app_connection(
                GitHubAppConnectionCreation::new(
                    "github-primary",
                    Some("GitHub connection".to_owned()),
                    Some(project_id),
                    GitHubAppConnectionCredentials::personal_access_token(
                        SecretValue::new("first-pat"),
                        GitHubInstance::Cloud { host: None },
                    )
                    .unwrap(),
                    AppConnectionRoute::Direct,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.method, GitHubConnectionMethod::PersonalAccessToken);
        let exact = client
            .get_github_app_connection(CONNECTION_ID)
            .await
            .unwrap();
        assert_eq!(exact.connection.id, CONNECTION_ID);
    }

    #[tokio::test]
    async fn github_app_connection_update_and_delete_use_exact_typed_routes() {
        let server = MockServer::start().await;
        mount_login(&server, "github-token").await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/app-connections/github/{CONNECTION_ID}"
            )))
            .and(header("authorization", "Bearer github-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnection": github_connection_fixture(PROJECT_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut updated = github_connection_fixture(PROJECT_ID);
        updated["description"] = Value::Null;
        updated["gatewayId"] = json!(GATEWAY_ID);
        updated["credentials"] = json!({
            "instanceType": "server",
            "host": "github.example.com"
        });
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/app-connections/github/{CONNECTION_ID}"
            )))
            .and(body_json(json!({
                "description": null,
                "credentials": {
                    "personalAccessToken": "replacement-pat",
                    "instanceType": "server",
                    "host": "github.example.com"
                },
                "gatewayId": GATEWAY_ID,
                "gatewayPoolId": null
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnection": updated
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/app-connections/github/{CONNECTION_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnection": github_connection_fixture(PROJECT_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let updated = client
            .update_github_app_connection(
                CONNECTION_ID,
                GitHubAppConnectionChange::new(
                    None,
                    AutomationDescriptionChange::Clear,
                    Some(
                        GitHubAppConnectionCredentials::personal_access_token(
                            SecretValue::new("replacement-pat"),
                            GitHubInstance::Server("github.example.com".to_owned()),
                        )
                        .unwrap(),
                    ),
                    Some(AppConnectionRoute::Gateway(GATEWAY_ID.to_owned())),
                )
                .unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(updated.connection.gateway_id.as_deref(), Some(GATEWAY_ID));
        let deleted = client
            .delete_github_app_connection(CONNECTION_ID, true)
            .await
            .unwrap();
        assert_eq!(deleted.connection.id, CONNECTION_ID);
        let requests = server.received_requests().await.unwrap();
        let delete = requests
            .iter()
            .find(|request| request.method.as_str() == "DELETE")
            .unwrap();
        assert!(delete.body.is_empty());
    }

    #[tokio::test]
    async fn github_app_connection_rotation_uses_the_exact_bodyless_route() {
        let server = MockServer::start().await;
        mount_login(&server, "github-token").await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/app-connections/github/{CONNECTION_ID}/rotate-credentials"
            )))
            .and(header("authorization", "Bearer github-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnection": github_connection_fixture(PROJECT_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;

        let rotated = InfisicalClient::new(settings(&server))
            .unwrap()
            .rotate_github_app_connection_credentials(CONNECTION_ID, true)
            .await
            .unwrap();
        assert_eq!(rotated.connection.id, CONNECTION_ID);
        let requests = server.received_requests().await.unwrap();
        let rotation = requests
            .iter()
            .find(|request| request.url.path().ends_with("/rotate-credentials"))
            .unwrap();
        assert!(rotation.body.is_empty());
    }

    #[tokio::test]
    async fn github_app_connection_creation_rejects_each_response_drift() {
        for (field, response) in github_connection_create_drift_cases() {
            let server = MockServer::start().await;
            mount_login(&server, "github-token").await;
            Mock::given(method("POST"))
                .and(path("/api/v1/app-connections/github"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "appConnection": response
                })))
                .expect(1)
                .mount(&server)
                .await;

            assert_eq!(
                InfisicalClient::new(settings(&server))
                    .unwrap()
                    .create_github_app_connection(github_connection_creation(Some(
                        ProjectId::new(PROJECT_ID).unwrap(),
                    )))
                    .await
                    .unwrap_err(),
                ResourceError::InvalidAppAutomationResponse,
                "accepted mismatched {field}"
            );
        }
    }

    #[tokio::test]
    async fn organization_github_connection_creation_rejects_project_scoped_response() {
        let server = MockServer::start().await;
        mount_login(&server, "github-token").await;
        Mock::given(method("POST"))
            .and(path("/api/v1/app-connections/github"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnection": github_connection_fixture(PROJECT_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .create_github_app_connection(github_connection_creation(None))
                .await
                .unwrap_err(),
            ResourceError::InvalidAppAutomationResponse
        );
    }

    #[tokio::test]
    async fn github_app_connection_update_rejects_each_changed_field_drift() {
        for field in ["name", "description", "gatewayPoolId"] {
            let server = MockServer::start().await;
            mount_login(&server, "github-token").await;
            Mock::given(method("PATCH"))
                .and(path(format!(
                    "/api/v1/app-connections/github/{CONNECTION_ID}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "appConnection": github_connection_fixture(PROJECT_ID)
                })))
                .expect(1)
                .mount(&server)
                .await;
            let change = match field {
                "name" => GitHubAppConnectionChange::new(
                    Some("github-renamed".to_owned()),
                    AutomationDescriptionChange::Keep,
                    None,
                    None,
                ),
                "description" => GitHubAppConnectionChange::new(
                    None,
                    AutomationDescriptionChange::Set("Updated description".to_owned()),
                    None,
                    None,
                ),
                _ => GitHubAppConnectionChange::new(
                    None,
                    AutomationDescriptionChange::Keep,
                    None,
                    Some(AppConnectionRoute::GatewayPool(GATEWAY_ID.to_owned())),
                ),
            }
            .unwrap();
            assert_eq!(
                InfisicalClient::new(settings(&server))
                    .unwrap()
                    .update_github_app_connection(CONNECTION_ID, change, false)
                    .await
                    .unwrap_err(),
                ResourceError::InvalidAppAutomationResponse,
                "accepted mismatched {field}"
            );
        }
    }

    #[tokio::test]
    async fn github_app_connection_update_rejects_credential_instance_drift() {
        let server = MockServer::start().await;
        mount_login(&server, "github-token").await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/app-connections/github/{CONNECTION_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnection": github_connection_fixture(PROJECT_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/app-connections/github/{CONNECTION_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnection": github_connection_fixture(PROJECT_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;

        let change = GitHubAppConnectionChange::new(
            None,
            AutomationDescriptionChange::Keep,
            Some(
                GitHubAppConnectionCredentials::personal_access_token(
                    SecretValue::new("replacement-pat"),
                    GitHubInstance::Server("github.example.com".to_owned()),
                )
                .unwrap(),
            ),
            None,
        )
        .unwrap();
        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .update_github_app_connection(CONNECTION_ID, change, true)
                .await
                .unwrap_err(),
            ResourceError::InvalidAppAutomationResponse
        );
    }

    #[tokio::test]
    async fn github_sync_create_uses_complete_typed_contract() {
        let server = MockServer::start().await;
        mount_login(&server, "inventory-token").await;
        mount_project_environment_inventory(&server, 1).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/secret-syncs/github"))
            .and(body_json(json!({
                "name": "github-actions",
                "description": "CI variables",
                "projectId": PROJECT_ID,
                "connectionId": CONNECTION_ID,
                "environment": "prod",
                "secretPath": "/apps",
                "isAutoSyncEnabled": true,
                "destinationConfig": {
                    "scope": "repository",
                    "owner": "platform",
                    "repo": "api"
                },
                "syncOptions": {
                    "initialSyncBehavior": "overwrite-destination",
                    "keySchema": "{{environment}}/{{secretKey}}",
                    "disableSecretDeletion": false
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretSync": github_sync_fixture(PROJECT_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new(PROJECT_ID).unwrap();
        let created = client
            .create_github_secret_sync(&project_id, github_sync_creation(), true)
            .await
            .unwrap();
        assert_eq!(created.sync.id, SYNC_ID);
    }

    #[tokio::test]
    async fn github_sync_creation_rejects_an_unknown_source_environment_before_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "inventory-token").await;
        mount_project_environment_inventory(&server, 1).await;
        let project_id = ProjectId::new(PROJECT_ID).unwrap();

        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .create_github_secret_sync(&project_id, github_sync_creation_for("staging"), true,)
                .await
                .unwrap_err(),
            ResourceError::InvalidAppAutomationScope
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.url.path() != "/api/v1/secret-syncs/github")
        );
    }

    #[tokio::test]
    async fn github_sync_creation_rejects_a_different_valid_response_environment() {
        let server = MockServer::start().await;
        mount_login(&server, "inventory-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{PROJECT_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": {
                    "id": PROJECT_ID,
                    "name": "Platform",
                    "slug": "platform",
                    "type": "secret-manager",
                    "orgId": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    "environments": [
                        project_environment_fixture(),
                        {
                            "id": "99999999-9999-4999-8999-999999999999",
                            "name": "Staging",
                            "slug": "staging"
                        }
                    ]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut response = github_sync_fixture(PROJECT_ID);
        response["environment"] = json!({
            "id": "99999999-9999-4999-8999-999999999999",
            "name": "Staging",
            "slug": "staging"
        });
        Mock::given(method("POST"))
            .and(path("/api/v1/secret-syncs/github"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretSync": response
            })))
            .expect(1)
            .mount(&server)
            .await;

        let project_id = ProjectId::new(PROJECT_ID).unwrap();
        assert_eq!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .create_github_secret_sync(&project_id, github_sync_creation(), true)
                .await
                .unwrap_err(),
            ResourceError::InvalidAppAutomationResponse
        );
    }

    #[tokio::test]
    async fn github_sync_update_validates_exact_scope() {
        let server = MockServer::start().await;
        mount_login(&server, "inventory-token").await;
        mount_project_environment_inventory(&server, 1).await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/secret-syncs/github/{SYNC_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretSync": github_sync_fixture(PROJECT_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut updated_sync = github_sync_fixture(PROJECT_ID);
        updated_sync["isAutoSyncEnabled"] = json!(false);
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/secret-syncs/github/{SYNC_ID}")))
            .and(body_json(json!({ "isAutoSyncEnabled": false })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretSync": updated_sync
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new(PROJECT_ID).unwrap();
        let updated = client
            .update_github_secret_sync(
                &project_id,
                SYNC_ID,
                GitHubSecretSyncChange::new(
                    None,
                    AutomationDescriptionChange::Keep,
                    None,
                    None,
                    None,
                    Some(false),
                    None,
                    None,
                )
                .unwrap(),
                true,
            )
            .await
            .unwrap();
        assert!(!updated.sync.is_auto_sync_enabled);
    }

    #[tokio::test]
    async fn github_sync_update_rejects_each_option_response_drift() {
        for field in ["keySchema", "disableSecretDeletion"] {
            let server = MockServer::start().await;
            mount_login(&server, "inventory-token").await;
            mount_project_environment_inventory(&server, 1).await;
            Mock::given(method("GET"))
                .and(path(format!("/api/v1/secret-syncs/github/{SYNC_ID}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "secretSync": github_sync_fixture(PROJECT_ID)
                })))
                .expect(1)
                .mount(&server)
                .await;
            let mut response = github_sync_fixture(PROJECT_ID);
            response["syncOptions"]["keySchema"] = json!("{{secretKey}}");
            response["syncOptions"]["disableSecretDeletion"] = json!(true);
            match field {
                "keySchema" => {
                    response["syncOptions"]["keySchema"] = json!("{{environment}}/{{secretKey}}");
                }
                _ => response["syncOptions"]["disableSecretDeletion"] = json!(false),
            }
            Mock::given(method("PATCH"))
                .and(path(format!("/api/v1/secret-syncs/github/{SYNC_ID}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "secretSync": response
                })))
                .expect(1)
                .mount(&server)
                .await;

            let change = GitHubSecretSyncChange::new(
                None,
                AutomationDescriptionChange::Keep,
                None,
                None,
                None,
                None,
                None,
                Some(GitHubSecretSyncOptions::new(Some("{{secretKey}}".to_owned()), true).unwrap()),
            )
            .unwrap();
            assert_eq!(
                InfisicalClient::new(settings(&server))
                    .unwrap()
                    .update_github_secret_sync(
                        &ProjectId::new(PROJECT_ID).unwrap(),
                        SYNC_ID,
                        change,
                        true,
                    )
                    .await
                    .unwrap_err(),
                ResourceError::InvalidAppAutomationResponse,
                "accepted mismatched {field}"
            );
        }
    }

    #[tokio::test]
    async fn github_sync_jobs_and_deletion_send_no_json_body() {
        let server = MockServer::start().await;
        mount_login(&server, "inventory-token").await;
        mount_project_environment_inventory(&server, 3).await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/secret-syncs/github/{SYNC_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretSync": github_sync_fixture(PROJECT_ID)
            })))
            .expect(3)
            .mount(&server)
            .await;
        for action in ["sync-secrets", "remove-secrets"] {
            Mock::given(method("POST"))
                .and(path(format!(
                    "/api/v1/secret-syncs/github/{SYNC_ID}/{action}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "secretSync": github_sync_fixture(PROJECT_ID)
                })))
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/secret-syncs/github/{SYNC_ID}")))
            .and(query_param("removeSecrets", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretSync": github_sync_fixture(PROJECT_ID)
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new(PROJECT_ID).unwrap();
        client
            .run_github_secret_sync(&project_id, SYNC_ID, true)
            .await
            .unwrap();
        client
            .remove_github_secret_sync_secrets(&project_id, SYNC_ID, true)
            .await
            .unwrap();
        client
            .delete_github_secret_sync(&project_id, SYNC_ID, true, true, true)
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        for request in requests.iter().filter(|request| {
            request.url.path().contains("/secret-syncs/github/")
                && matches!(request.method.as_str(), "POST" | "DELETE")
        }) {
            assert!(request.body.is_empty(), "action unexpectedly sent a body");
        }
    }

    #[tokio::test]
    async fn destructive_github_automation_actions_fail_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new(PROJECT_ID).unwrap();
        assert_eq!(
            client
                .rotate_github_app_connection_credentials(CONNECTION_ID, false)
                .await
                .unwrap_err(),
            ResourceError::AppConnectionCredentialRotationNotConfirmed
        );
        assert_eq!(
            client
                .update_github_app_connection(
                    CONNECTION_ID,
                    GitHubAppConnectionChange::new(
                        None,
                        AutomationDescriptionChange::Keep,
                        Some(
                            GitHubAppConnectionCredentials::personal_access_token(
                                SecretValue::new("replacement-pat"),
                                GitHubInstance::Cloud { host: None },
                            )
                            .unwrap(),
                        ),
                        None,
                    )
                    .unwrap(),
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::AppConnectionCredentialReplacementNotConfirmed
        );
        assert_eq!(
            client
                .create_github_secret_sync(&project_id, github_sync_creation(), false)
                .await
                .unwrap_err(),
            ResourceError::SecretSyncInitialOverwriteNotConfirmed
        );
        assert_eq!(
            client
                .delete_github_secret_sync(&project_id, SYNC_ID, true, true, false)
                .await
                .unwrap_err(),
            ResourceError::SecretSyncRemoteRemovalNotConfirmed
        );
        assert_eq!(
            client
                .run_github_secret_sync(&project_id, SYNC_ID, false)
                .await
                .unwrap_err(),
            ResourceError::SecretSyncRunNotConfirmed
        );
        assert_eq!(
            client
                .update_github_secret_sync(
                    &project_id,
                    SYNC_ID,
                    GitHubSecretSyncChange::new(
                        None,
                        AutomationDescriptionChange::Keep,
                        None,
                        None,
                        None,
                        Some(false),
                        None,
                        None,
                    )
                    .unwrap(),
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::SecretSyncUpdateNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn response_scalar_validators_enforce_each_independent_boundary() {
        assert!(super::validate_uuid(PROJECT_ID).is_ok());
        assert!(super::validate_uuid("not-a-uuid").is_err());
        assert!(super::validate_optional_uuid(None).is_ok());
        assert!(super::validate_optional_uuid(Some(PROJECT_ID)).is_ok());
        assert!(super::validate_optional_uuid(Some("not-a-uuid")).is_err());

        for (value, max_bytes, allow_empty, valid) in [
            ("connection", 10, false, true),
            ("", 10, true, true),
            ("", 10, false, false),
            ("eleven-byte", 10, false, false),
            (" padded", 10, false, false),
            ("padded ", 10, false, false),
            ("line\nbreak", 10, false, false),
        ] {
            assert_eq!(
                super::validate_text(value, max_bytes, allow_empty).is_ok(),
                valid,
                "unexpected text validation for {value:?}"
            );
        }
        assert!(super::validate_optional_text(None, 10).is_ok());
        assert!(super::validate_optional_text(Some(""), 10).is_ok());
        assert!(super::validate_optional_text(Some("too-long-value"), 10).is_err());

        for (value, valid) in [
            ("prod-2", true),
            ("", false),
            ("-prod", false),
            ("prod-", false),
            ("prod--two", false),
            ("Prod", false),
            ("prod_two", false),
        ] {
            assert_eq!(
                super::validate_slug(value).is_ok(),
                valid,
                "unexpected slug validation for {value:?}"
            );
        }
        assert!(super::validate_slug(&"a".repeat(64)).is_ok());
        assert!(super::validate_slug(&"a".repeat(65)).is_err());

        assert!(super::validate_version(1).is_ok());
        assert!(super::validate_version(0).is_err());
    }

    #[test]
    fn github_connection_responses_validate_cloud_server_and_routing_metadata() {
        let mut cloud_host = github_connection_fixture(PROJECT_ID);
        cloud_host["credentials"] = json!({ "instanceType": "cloud", "host": "octocat.ghe.com" });
        let raw: super::RawGitHubAppConnection = serde_json::from_value(cloud_host).unwrap();
        let validated = raw.into_validated(Some(CONNECTION_ID), None).unwrap();
        assert_eq!(
            validated.instance.instance_type,
            super::GitHubInstanceType::Cloud
        );
        assert_eq!(validated.instance.host.as_deref(), Some("octocat.ghe.com"));

        let mut server_without_host = github_connection_fixture(PROJECT_ID);
        server_without_host["credentials"] = json!({ "instanceType": "server" });
        let raw: super::RawGitHubAppConnection =
            serde_json::from_value(server_without_host).unwrap();
        assert_eq!(
            raw.into_validated(Some(CONNECTION_ID), None).unwrap_err(),
            ResourceError::InvalidAppAutomationResponse
        );

        let mut dual_gateway = github_connection_fixture(PROJECT_ID);
        dual_gateway["gatewayId"] = json!(GATEWAY_ID);
        dual_gateway["gatewayPoolId"] = json!("99999999-9999-4999-8999-999999999999");
        let raw: super::RawGitHubAppConnection = serde_json::from_value(dual_gateway).unwrap();
        assert_eq!(
            raw.into_validated(Some(CONNECTION_ID), None).unwrap_err(),
            ResourceError::InvalidAppAutomationResponse
        );
    }

    #[test]
    fn response_paths_and_timestamps_enforce_each_independent_boundary() {
        for (value, valid) in [
            ("/", true),
            ("/apps/prod", true),
            ("", false),
            ("apps", false),
            ("//", false),
            ("/apps/", false),
            ("/./secrets", false),
            ("/../secrets", false),
            ("/apps/line\nbreak", false),
        ] {
            assert_eq!(
                super::validate_secret_path(value).is_ok(),
                valid,
                "unexpected path validation for {value:?}"
            );
        }
        let oversized_path = format!("/{}", "a".repeat(super::MAX_SECRET_PATH_BYTES));
        assert!(super::validate_secret_path(&oversized_path).is_err());

        let created_at = "2026-07-20T12:00:00.000Z";
        let updated_at = "2026-07-20T12:00:01.000Z";
        assert!(super::validate_timestamp(created_at).unwrap() > 1);
        assert!(super::validate_timestamp("not-a-timestamp").is_err());
        assert!(super::validate_optional_timestamp(None).is_ok());
        assert!(super::validate_optional_timestamp(Some(created_at)).is_ok());
        assert!(super::validate_optional_timestamp(Some("not-a-timestamp")).is_err());
        assert!(super::validate_timestamp_pair(created_at, created_at).is_ok());
        assert!(super::validate_timestamp_pair(created_at, updated_at).is_ok());
        assert!(super::validate_timestamp_pair(updated_at, created_at).is_err());
    }

    #[test]
    fn sync_without_a_folder_preserves_the_absent_join() {
        let mut fixture = secret_sync_fixture(PROJECT_ID);
        fixture["folderId"] = Value::Null;
        fixture["folder"] = Value::Null;
        let raw: super::RawSecretSync = serde_json::from_value(fixture).unwrap();
        let project_id = ProjectId::new(PROJECT_ID).unwrap();
        let environments = project_environments_fixture();

        assert!(
            raw.into_validated(&project_id, &environments)
                .unwrap()
                .folder
                .is_none()
        );
    }

    #[test]
    fn joined_environments_must_match_the_project_inventory_exactly() {
        let project_id = ProjectId::new(PROJECT_ID).unwrap();
        let environments = project_environments_fixture();
        for field in ["id", "name", "slug"] {
            let mut sync = secret_sync_fixture(PROJECT_ID);
            let mut rotation = secret_rotation_fixture(PROJECT_ID);
            let replacement = match field {
                "id" => json!("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
                "name" => json!("Foreign"),
                _ => json!("foreign"),
            };
            sync["environment"][field] = replacement.clone();
            rotation["environment"][field] = replacement;
            let sync: super::RawSecretSync = serde_json::from_value(sync).unwrap();
            let rotation: super::RawSecretRotation = serde_json::from_value(rotation).unwrap();
            assert_eq!(
                sync.into_validated(&project_id, &environments).unwrap_err(),
                ResourceError::InvalidAppAutomationResponse,
                "sync accepted mismatched environment {field}"
            );
            assert_eq!(
                rotation
                    .into_validated(&project_id, &environments)
                    .unwrap_err(),
                ResourceError::InvalidAppAutomationResponse,
                "rotation accepted mismatched environment {field}"
            );
        }
    }

    #[test]
    fn github_sync_response_requires_provider_and_exact_id_independently() {
        let project_id = ProjectId::new(PROJECT_ID).unwrap();
        let environments = project_environments_fixture();

        let mut wrong_provider = github_sync_fixture(PROJECT_ID);
        wrong_provider["destination"] = json!("aws-secrets-manager");
        let wrong_provider: super::RawGitHubSecretSync =
            serde_json::from_value(wrong_provider).unwrap();
        assert_eq!(
            wrong_provider
                .into_validated(&project_id, &environments, Some(SYNC_ID))
                .unwrap_err(),
            ResourceError::InvalidAppAutomationResponse
        );

        let wrong_id: super::RawGitHubSecretSync =
            serde_json::from_value(github_sync_fixture(PROJECT_ID)).unwrap();
        assert_eq!(
            wrong_id
                .into_validated(
                    &project_id,
                    &environments,
                    Some("99999999-9999-4999-8999-999999999999"),
                )
                .unwrap_err(),
            ResourceError::InvalidAppAutomationResponse
        );
    }

    #[test]
    fn rotation_bounds_are_validated_independently() {
        let project_id = ProjectId::new(PROJECT_ID).unwrap();
        let environments = project_environments_fixture();
        for (field, value) in [
            ("projectId", json!("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")),
            ("activeIndex", json!(2)),
            ("rotationInterval", json!(0)),
            ("rotateAtUtc.hours", json!(24)),
            ("rotateAtUtc.minutes", json!(60)),
        ] {
            let mut fixture = secret_rotation_fixture(PROJECT_ID);
            match field {
                "rotateAtUtc.hours" => fixture["rotateAtUtc"]["hours"] = value,
                "rotateAtUtc.minutes" => fixture["rotateAtUtc"]["minutes"] = value,
                _ => fixture[field] = value,
            }
            let raw: super::RawSecretRotation = serde_json::from_value(fixture).unwrap();
            assert_eq!(
                raw.into_validated(&project_id, &environments).unwrap_err(),
                ResourceError::InvalidAppAutomationResponse,
                "accepted invalid {field}"
            );
        }

        let mut boundary = secret_rotation_fixture(PROJECT_ID);
        boundary["activeIndex"] = json!(0);
        boundary["rotationInterval"] = json!(1);
        boundary["rotateAtUtc"] = json!({ "hours": 23, "minutes": 59 });
        let raw: super::RawSecretRotation = serde_json::from_value(boundary).unwrap();
        let validated = raw.into_validated(&project_id, &environments).unwrap();
        assert_eq!(validated.active_index, 0);
        assert_eq!(validated.rotation_interval_days, 1);
        assert_eq!(validated.rotate_at_utc.hours, 23);
        assert_eq!(validated.rotate_at_utc.minutes, 59);
    }

    fn app_connection_fixture(project_id: &str) -> Value {
        json!({
            "id": CONNECTION_ID,
            "name": "github-primary",
            "description": "GitHub connection",
            "app": "github",
            "method": "access-token",
            "version": 1,
            "orgId": "ffffffff-ffff-4fff-8fff-ffffffffffff",
            "projectId": project_id,
            "createdAt": "2026-07-20T12:00:00.000Z",
            "updatedAt": "2026-07-20T12:00:01.000Z",
            "isPlatformManagedCredentials": false,
            "isAutoRotationEnabled": false,
            "gatewayId": null,
            "gatewayPoolId": null,
            "credentialsHash": "must-not-cross",
            "configuration": { "secret": "must-not-cross" }
        })
    }

    fn github_connection_fixture(project_id: &str) -> Value {
        let mut fixture = app_connection_fixture(project_id);
        fixture["method"] = json!("pat");
        fixture["credentials"] = json!({ "instanceType": "cloud" });
        fixture
    }

    fn github_connection_creation(project_id: Option<ProjectId>) -> GitHubAppConnectionCreation {
        GitHubAppConnectionCreation::new(
            "github-primary",
            Some("GitHub connection".to_owned()),
            project_id,
            GitHubAppConnectionCredentials::personal_access_token(
                SecretValue::new("first-pat"),
                GitHubInstance::Cloud { host: None },
            )
            .unwrap(),
            AppConnectionRoute::Direct,
        )
        .unwrap()
    }

    fn github_connection_create_drift_cases() -> Vec<(&'static str, Value)> {
        let mut cases = Vec::new();
        for (field, value) in [
            ("name", json!("github-foreign")),
            ("description", json!("Foreign description")),
            ("gatewayId", json!(GATEWAY_ID)),
            (
                "gatewayPoolId",
                json!("99999999-9999-4999-8999-999999999999"),
            ),
            ("isPlatformManagedCredentials", json!(true)),
            ("isAutoRotationEnabled", json!(true)),
            ("app", json!("aws")),
            ("method", json!("oauth")),
        ] {
            let mut fixture = github_connection_fixture(PROJECT_ID);
            fixture[field] = value;
            cases.push((field, fixture));
        }
        let mut instance = github_connection_fixture(PROJECT_ID);
        instance["credentials"] = json!({ "instanceType": "server", "host": "github.example.com" });
        cases.push(("credentials.instanceType", instance));
        let mut cloud_host = github_connection_fixture(PROJECT_ID);
        cloud_host["credentials"] =
            json!({ "instanceType": "cloud", "host": "github.example.com" });
        cases.push(("credentials.cloudHost", cloud_host));
        cases
    }

    fn project_environment_fixture() -> Value {
        json!({ "id": ENVIRONMENT_ID, "name": "Production", "slug": "prod" })
    }

    fn project_environments_fixture() -> Vec<crate::Environment> {
        vec![serde_json::from_value(project_environment_fixture()).unwrap()]
    }

    fn secret_sync_fixture(project_id: &str) -> Value {
        json!({
            "id": "11111111-1111-4111-8111-111111111111",
            "name": "github-actions",
            "description": "CI variables",
            "destination": "github",
            "version": 1,
            "projectId": project_id,
            "folderId": FOLDER_ID,
            "connectionId": CONNECTION_ID,
            "connection": { "id": CONNECTION_ID, "name": "github-primary", "app": "github" },
            "environment": { "id": ENVIRONMENT_ID, "name": "Production", "slug": "prod" },
            "folder": { "id": FOLDER_ID, "path": "/apps" },
            "isAutoSyncEnabled": true,
            "syncStatus": "succeeded",
            "lastSyncedAt": "2026-07-20T12:01:00.000Z",
            "importStatus": null,
            "lastImportedAt": null,
            "removeStatus": null,
            "lastRemovedAt": null,
            "createdAt": "2026-07-20T12:00:00.000Z",
            "updatedAt": "2026-07-20T12:01:00.000Z",
            "destinationConfig": { "repository": "must-not-cross" },
            "syncOptions": { "keySchema": "must-not-cross" },
            "lastSyncMessage": "must-not-cross"
        })
    }

    fn github_sync_fixture(project_id: &str) -> Value {
        let mut fixture = secret_sync_fixture(project_id);
        fixture["destinationConfig"] = json!({
            "scope": "repository",
            "owner": "platform",
            "repo": "api"
        });
        fixture["syncOptions"] = json!({
            "initialSyncBehavior": "overwrite-destination",
            "keySchema": "{{environment}}/{{secretKey}}",
            "disableSecretDeletion": false
        });
        fixture
    }

    fn github_sync_creation_for(environment: &str) -> GitHubSecretSyncCreation {
        GitHubSecretSyncCreation::new(
            "github-actions",
            Some("CI variables".to_owned()),
            GitHubSecretSyncSource::new(
                CONNECTION_ID,
                EnvironmentSlug::new(environment).unwrap(),
                SecretPath::new("/apps").unwrap(),
            )
            .unwrap(),
            true,
            GitHubSecretSyncDestination::Repository {
                owner: "platform".to_owned(),
                repo: "api".to_owned(),
            },
            GitHubSecretSyncOptions::new(Some("{{environment}}/{{secretKey}}".to_owned()), false)
                .unwrap(),
        )
        .unwrap()
    }

    fn github_sync_creation() -> GitHubSecretSyncCreation {
        github_sync_creation_for("prod")
    }

    fn secret_rotation_fixture(project_id: &str) -> Value {
        json!({
            "id": "22222222-2222-4222-8222-222222222222",
            "name": "database-password",
            "description": "Database credential rotation",
            "type": "postgres-credentials",
            "projectId": project_id,
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
            "parameters": { "username": "must-not-cross" },
            "secretsMapping": { "password": "must-not-cross" },
            "lastRotationMessage": "must-not-cross"
        })
    }

    fn mismatched_rotation_fixture(project_id: &str) -> Value {
        let mut fixture = secret_rotation_fixture(project_id);
        fixture["connection"]["app"] = json!("mysql");
        fixture
    }
}
