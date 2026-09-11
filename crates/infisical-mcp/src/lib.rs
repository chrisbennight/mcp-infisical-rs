//! MCP catalog and dispatch contracts for Infisical.

use std::sync::{Arc, OnceLock};

use infisical_api::InfisicalClient;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, CustomRequest, CustomResult, ErrorCode,
        Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
        ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
};
use serde::Deserialize;

use crate::files::SecretFilePlane;

pub mod files;
mod tools;

static TOOL_CATALOG: OnceLock<ListToolsResult> = OnceLock::new();

/// Stable server name used by gateway manifests and identity audiences.
pub const MCP_SERVER_NAME: &str = "infisical";

/// Authenticated Streamable HTTP endpoint for standalone and gateway profiles.
pub const MCP_ENDPOINT: &str = "/mcp";

/// MCP protocol revision targeted by the server and gateway.
pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

/// Security guidance returned to every MCP client during initialization.
pub const MCP_INSTRUCTIONS: &str = "Manage Infisical through typed, bounded operations. Operations are not listed individually: call operations.list for the names this build serves and operations.describe for one operation's input and output schema, then pass that operation and its arguments to the executor for its tier. infisical.read runs repeatable reads; infisical.readAudited runs reads Infisical records as access events; infisical.write applies changes this server does not classify as destructive; infisical.destroy applies the ones it does. Everything except infisical.read is sent exactly once and never replayed, so a failure is not retried for you. Collections are bounded and paginated, every input is validated before the first upstream call, and most destructive operations take their own explicit confirmation field, except dynamicSecretLeases.create, which issues a credential lease and takes none; some write operations take one too, so the field is the operation's property rather than the tier's and its schema is what states it. Secret values appear only from secrets.reveal, the one-time outputs of identityUniversalAuth.clientSecrets.create, identityTokenAuth.tokens.create, dynamicSecretLeases.create, sshCertificates.issue, certificates.issue with an Infisical-managed key, and certificates.renew, and the confirmed secretRotations.sql.generatedCredentials.get, kms.decrypt, kms.keys.privateKey.reveal, kms.keys.privateKeys.bulkReveal, certificates.bundle.reveal, certificates.privateKey.reveal, certificateProfiles.latestActiveBundle.reveal, certificateProfiles.acmeEabSecret.reveal, and certificateRequests.result.reveal operations; mutations never echo submitted secret values. When this deployment configures the reveal transfer plane, those operations return an opaque secretFile reference delivered out-of-band instead of the value, and an inline value requires the operation's delivery argument set to inlineValue. On such a deployment secrets.create and secrets.update also accept a secretValueFile reference to a value uploaded out-of-band, and certificates.import accepts certificateFile plus optional privateKeyFile and certificateChainFile uploads; every executor accepts resultDelivery set to file to receive any operation's whole structured result as an out-of-context resultFile reference instead of inline content.";

/// Typed MCP surface backed by a dedicated Infisical Machine Identity.
#[derive(Clone)]
pub struct InfisicalMcp {
    client: InfisicalClient,
    files: Option<Arc<SecretFilePlane>>,
}

impl InfisicalMcp {
    /// Bind the MCP catalog to a validated, bounded Infisical client.
    #[must_use]
    pub fn new(client: InfisicalClient) -> Self {
        Self {
            client,
            files: None,
        }
    }

    /// Attach the reveal transfer plane, enabling reference delivery by default.
    #[must_use]
    pub fn with_files(mut self, files: Option<Arc<SecretFilePlane>>) -> Self {
        self.files = files;
        self
    }

    /// Return the complete catalog while reusing its immutable schemas.
    #[must_use]
    pub fn list_tools_payload() -> ListToolsResult {
        TOOL_CATALOG.get_or_init(tools::catalog).clone()
    }
}

/// Name the executor that serves one operation, if this build serves it.
///
/// Operations are reached through their tier's executor rather than by name,
/// so a caller constructing a request needs the executor that will accept it.
/// Returns `None` for a published tool, which is addressed directly, and for a
/// name this build does not serve.
#[must_use]
pub fn executor_for_operation(operation: &str) -> Option<&'static str> {
    tools::tool_tier(operation).map(tools::ToolTier::executor)
}

/// Serialize the exact registry returned by the `server.capabilities` MCP tool.
///
/// This is used by offline contract validation so registry evidence follows the
/// executable response path instead of source-text inspection.
///
/// # Errors
///
/// Returns an error if the static capability registry cannot be serialized.
pub fn server_capabilities_payload() -> Result<serde_json::Value, serde_json::Error> {
    tools::server_capabilities_payload()
}

impl ServerHandler for InfisicalMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(Implementation::new(
                "mcp-infisical-rs",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(MCP_INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _params: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(Self::list_tools_payload())
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tools::dispatch(&self.client, self.files.as_deref(), params).await
    }

    async fn on_custom_request(
        &self,
        request: CustomRequest,
        _context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, McpError> {
        // `_meta` may carry the caller's file capability declaration; it is deliberately
        // not read, because a caller reaches this method only after seeing a reference
        // this server minted.
        #[derive(Deserialize)]
        struct AuthorizeDownloadParams {
            uri: String,
        }

        // A plane that is off answers exactly like a server that never had one:
        // method-not-found is what a file-aware intermediary reads as "no native file
        // transfer", so the absence is the advertisement. The requested method is not
        // reflected: it is caller-controlled, and a misplaced credential in it would be
        // copied into an error a client stores and displays.
        let refused = || {
            Err(McpError::new(
                ErrorCode::METHOD_NOT_FOUND,
                "the requested method is not one this server provides",
                None,
            ))
        };
        let Some(plane) = self.files.as_deref() else {
            return refused();
        };

        let authorized = match request.method.as_str() {
            files::AUTHORIZE_DOWNLOAD_METHOD => {
                let params: AuthorizeDownloadParams = request
                    .params
                    .map(serde_json::from_value)
                    .transpose()
                    .ok()
                    .flatten()
                    .ok_or_else(|| {
                        McpError::invalid_params(
                            "files/authorizeDownload params must carry a uri",
                            None,
                        )
                    })?;
                plane
                    .authorize_download(&params.uri)
                    .map_err(|error| McpError::invalid_params(error.to_string(), None))
                    .and_then(|authorized| {
                        serde_json::to_value(authorized).map_err(|_| {
                            McpError::internal_error("serialize download authorization", None)
                        })
                    })?
            }
            files::AUTHORIZE_UPLOAD_METHOD => {
                // Every param is optional in the draft, so absent params are legal.
                let params: files::AuthorizeUploadParams = request
                    .params
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|_| {
                        McpError::invalid_params(
                            "files/authorizeUpload params do not match the declared shape",
                            None,
                        )
                    })?
                    .unwrap_or_default();
                plane
                    .authorize_upload(params)
                    .map_err(|error| McpError::invalid_params(error.to_string(), None))
                    .and_then(|authorized| {
                        serde_json::to_value(authorized).map_err(|_| {
                            McpError::internal_error("serialize upload authorization", None)
                        })
                    })?
            }
            _ => return refused(),
        };
        Ok(CustomResult::new(authorized))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use infisical_api::{ClientSettings, InfisicalClient, SecretValue};
    use rmcp::{
        ServerHandler,
        model::{CallToolRequestParams, Tool},
    };
    use serde_json::{Map, Value, json};

    use super::{
        InfisicalMcp, MCP_ENDPOINT, MCP_INSTRUCTIONS, MCP_PROTOCOL_VERSION, MCP_SERVER_NAME,
        tools::{
            self, APP_CONNECTIONS_LIST_TOOL, AUDIT_LOGS_LIST_TOOL,
            CERTIFICATE_AUTHORITIES_LIST_TOOL, CERTIFICATE_POLICIES_CREATE_TOOL,
            CERTIFICATE_POLICIES_DELETE_TOOL, CERTIFICATE_POLICIES_GET_TOOL,
            CERTIFICATE_POLICIES_LIST_TOOL, CERTIFICATE_POLICIES_UPDATE_TOOL,
            CERTIFICATE_PROFILE_CERTIFICATES_LIST_TOOL, CERTIFICATE_PROFILE_EAB_SECRET_REVEAL_TOOL,
            CERTIFICATE_PROFILE_LATEST_BUNDLE_REVEAL_TOOL, CERTIFICATE_PROFILES_CREATE_TOOL,
            CERTIFICATE_PROFILES_DELETE_TOOL, CERTIFICATE_PROFILES_GET_BY_SLUG_TOOL,
            CERTIFICATE_PROFILES_GET_TOOL, CERTIFICATE_PROFILES_LIST_TOOL,
            CERTIFICATE_PROFILES_UPDATE_TOOL, CERTIFICATE_REQUEST_RESULT_REVEAL_TOOL,
            CERTIFICATE_REQUESTS_CANCEL_TOOL, CERTIFICATE_REQUESTS_GET_TOOL,
            CERTIFICATE_REQUESTS_LIST_TOOL, CERTIFICATES_BUNDLE_REVEAL_TOOL,
            CERTIFICATES_CERTIFICATE_GET_TOOL, CERTIFICATES_DELETE_TOOL, CERTIFICATES_GET_TOOL,
            CERTIFICATES_IMPORT_TOOL, CERTIFICATES_ISSUE_TOOL, CERTIFICATES_LIST_TOOL,
            CERTIFICATES_PRIVATE_KEY_REVEAL_TOOL, CERTIFICATES_RENEW_TOOL,
            CERTIFICATES_RENEWAL_CONFIGURATION_UPDATE_TOOL, CERTIFICATES_REVOKE_TOOL,
            CODE_SIGNER_APPROVAL_POLICY_GET_TOOL, CODE_SIGNER_APPROVAL_POLICY_REPLACE_TOOL,
            CODE_SIGNER_APPROVAL_REQUESTS_CREATE_TOOL, CODE_SIGNER_APPROVAL_REQUESTS_LIST_TOOL,
            CODE_SIGNER_APPROVAL_REQUESTS_PRE_APPROVE_TOOL,
            CODE_SIGNER_APPROVAL_REQUESTS_REVOKE_TOOL, CODE_SIGNER_EFFECTIVE_MEMBERS_LIST_TOOL,
            CODE_SIGNER_MEMBER_ROLE_UPDATE_TOOL, CODE_SIGNER_MEMBERS_ADD_TOOL,
            CODE_SIGNER_MEMBERS_LIST_TOOL, CODE_SIGNER_MEMBERS_REMOVE_TOOL,
            CODE_SIGNER_OPERATIONS_LIST_TOOL, CODE_SIGNER_PERMISSIONS_GET_TOOL,
            CODE_SIGNERS_CERTIFICATE_EXPORT_TOOL, CODE_SIGNERS_CERTIFICATE_REISSUE_TOOL,
            CODE_SIGNERS_CREATE_TOOL, CODE_SIGNERS_DELETE_TOOL, CODE_SIGNERS_GET_TOOL,
            CODE_SIGNERS_LIST_TOOL, CODE_SIGNERS_PUBLIC_KEY_GET_TOOL, CODE_SIGNERS_SIGN_TOOL,
            CODE_SIGNERS_STATUS_UPDATE_TOOL, CODE_SIGNERS_UPDATE_TOOL,
            DYNAMIC_SECRET_LEASES_GET_TOOL, DYNAMIC_SECRET_LEASES_LIST_TOOL,
            DYNAMIC_SECRET_LEASES_RENEW_TOOL, DYNAMIC_SECRET_LEASES_REVOKE_TOOL,
            DYNAMIC_SECRETS_GET_TOOL, DYNAMIC_SECRETS_LIST_TOOL, ENVIRONMENTS_CREATE_TOOL,
            ENVIRONMENTS_DELETE_TOOL, ENVIRONMENTS_RESTORE_TOOL, ENVIRONMENTS_UPDATE_TOOL,
            FOLDERS_BATCH_UPDATE_TOOL, FOLDERS_CREATE_TOOL, FOLDERS_DELETE_TOOL, FOLDERS_GET_TOOL,
            FOLDERS_UPDATE_TOOL, GITHUB_APP_CONNECTION_CREATE_TOOL,
            GITHUB_APP_CONNECTION_DELETE_TOOL, GITHUB_APP_CONNECTION_GET_TOOL,
            GITHUB_APP_CONNECTION_ROTATE_CREDENTIALS_TOOL, GITHUB_APP_CONNECTION_UPDATE_TOOL,
            GITHUB_SECRET_SYNC_CREATE_TOOL, GITHUB_SECRET_SYNC_DELETE_TOOL,
            GITHUB_SECRET_SYNC_GET_TOOL, GITHUB_SECRET_SYNC_REMOVE_SECRETS_TOOL,
            GITHUB_SECRET_SYNC_RUN_TOOL, GITHUB_SECRET_SYNC_UPDATE_TOOL, GROUP_MEMBERS_LIST_TOOL,
            GROUP_PROJECTS_LIST_TOOL, IDENTITIES_CREATE_TOOL, IDENTITIES_DELETE_TOOL,
            IDENTITIES_GET_TOOL, IDENTITIES_LIST_TOOL, IDENTITIES_UPDATE_TOOL,
            IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_CREATE_TOOL,
            IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_DELETE_TOOL,
            IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_GET_TOOL,
            IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_LIST_TOOL,
            IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_UPDATE_TOOL, INFISICAL_DESTROY_TOOL,
            INFISICAL_READ_AUDITED_TOOL, INFISICAL_READ_TOOL, INFISICAL_WRITE_TOOL,
            INTERNAL_CA_CERTIFICATE_GENERATE_TOOL, INTERNAL_CA_CERTIFICATE_GET_TOOL,
            INTERNAL_CA_CERTIFICATE_IMPORT_TOOL, INTERNAL_CA_CERTIFICATE_RENEW_TOOL,
            INTERNAL_CA_CERTIFICATE_VERSION_GET_TOOL, INTERNAL_CA_CERTIFICATES_LIST_TOOL,
            INTERNAL_CA_CRLS_LIST_TOOL, INTERNAL_CA_CSR_GET_TOOL,
            INTERNAL_CA_INTERMEDIATE_SIGN_TOOL, INTERNAL_CERTIFICATE_AUTHORITIES_CREATE_TOOL,
            INTERNAL_CERTIFICATE_AUTHORITIES_DELETE_TOOL,
            INTERNAL_CERTIFICATE_AUTHORITIES_GET_TOOL, INTERNAL_CERTIFICATE_AUTHORITIES_LIST_TOOL,
            INTERNAL_CERTIFICATE_AUTHORITIES_UPDATE_TOOL, KMS_DECRYPT_TOOL, KMS_ENCRYPT_TOOL,
            KMS_KEYS_BULK_IMPORT_TOOL, KMS_KEYS_CREATE_TOOL, KMS_KEYS_DELETE_TOOL,
            KMS_KEYS_GET_BY_NAME_TOOL, KMS_KEYS_GET_TOOL, KMS_KEYS_LIST_TOOL, KMS_KEYS_UPDATE_TOOL,
            KMS_PRIVATE_KEY_REVEAL_TOOL, KMS_PRIVATE_KEYS_BULK_REVEAL_TOOL,
            KMS_PUBLIC_KEY_GET_TOOL, KMS_SIGN_TOOL, KMS_SIGNING_ALGORITHMS_LIST_TOOL,
            KMS_VERIFY_TOOL, KUBERNETES_AUTH_ATTACH_TOOL, KUBERNETES_AUTH_GET_TOOL,
            KUBERNETES_AUTH_REMOVE_TOOL, KUBERNETES_AUTH_UPDATE_TOOL, OPERATIONS_DESCRIBE_TOOL,
            OPERATIONS_LIST_TOOL, PROJECT_GROUP_MEMBERSHIPS_LIST_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_CREATE_TOOL, PROJECT_IDENTITY_MEMBERSHIPS_DELETE_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_GET_TOOL, PROJECT_IDENTITY_MEMBERSHIPS_LIST_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_UPDATE_TOOL, PROJECT_ROLES_LIST_TOOL,
            PROJECT_USER_MEMBERSHIPS_DELETE_TOOL, PROJECT_USER_MEMBERSHIPS_GET_TOOL,
            PROJECT_USER_MEMBERSHIPS_INVITE_TOOL, PROJECT_USER_MEMBERSHIPS_LIST_TOOL,
            PROJECT_USER_MEMBERSHIPS_UPDATE_TOOL, PROJECTS_CREATE_TOOL, PROJECTS_DELETE_TOOL,
            PROJECTS_UPDATE_TOOL, SECRET_BATCH_CREATE_TOOL, SECRET_BATCH_DELETE_TOOL,
            SECRET_BATCH_UPDATE_TOOL, SECRET_CREATE_TOOL, SECRET_DELETE_TOOL,
            SECRET_IMPORTS_CREATE_TOOL, SECRET_IMPORTS_DELETE_TOOL, SECRET_IMPORTS_GET_TOOL,
            SECRET_IMPORTS_LIST_TOOL, SECRET_IMPORTS_UPDATE_TOOL, SECRET_METADATA_LIST_TOOL,
            SECRET_REVEAL_TOOL, SECRET_ROTATIONS_LIST_TOOL, SECRET_SYNCS_LIST_TOOL,
            SECRET_UPDATE_TOOL, SERVER_CAPABILITIES_TOOL, SERVER_INFO_TOOL,
            SQL_SECRET_ROTATION_CHECK_TOOL, SQL_SECRET_ROTATION_CREATE_TOOL,
            SQL_SECRET_ROTATION_DELETE_TOOL, SQL_SECRET_ROTATION_GENERATED_CREDENTIALS_GET_TOOL,
            SQL_SECRET_ROTATION_GET_BY_NAME_TOOL, SQL_SECRET_ROTATION_GET_TOOL,
            SQL_SECRET_ROTATION_MOVE_TOOL, SQL_SECRET_ROTATION_ROTATE_TOOL,
            SQL_SECRET_ROTATION_UPDATE_TOOL, SSH_CERTIFICATE_AUTHORITIES_CREATE_TOOL,
            SSH_CERTIFICATE_AUTHORITIES_DELETE_TOOL, SSH_CERTIFICATE_AUTHORITIES_GET_TOOL,
            SSH_CERTIFICATE_AUTHORITIES_LIST_TOOL, SSH_CERTIFICATE_AUTHORITIES_PUBLIC_KEY_GET_TOOL,
            SSH_CERTIFICATE_AUTHORITIES_REPLACE_TOOL,
            SSH_CERTIFICATE_AUTHORITY_TEMPLATES_LIST_TOOL, SSH_CERTIFICATE_TEMPLATES_CREATE_TOOL,
            SSH_CERTIFICATE_TEMPLATES_DELETE_TOOL, SSH_CERTIFICATE_TEMPLATES_GET_TOOL,
            SSH_CERTIFICATE_TEMPLATES_LIST_TOOL, SSH_CERTIFICATE_TEMPLATES_REPLACE_TOOL,
            SSH_CERTIFICATES_ISSUE_TOOL, SSH_CERTIFICATES_SIGN_TOOL, SSH_HOST_GROUP_HOSTS_ADD_TOOL,
            SSH_HOST_GROUP_HOSTS_LIST_TOOL, SSH_HOST_GROUP_HOSTS_REMOVE_TOOL,
            SSH_HOST_GROUPS_CREATE_TOOL, SSH_HOST_GROUPS_DELETE_TOOL, SSH_HOST_GROUPS_GET_TOOL,
            SSH_HOST_GROUPS_LIST_TOOL, SSH_HOST_GROUPS_REPLACE_TOOL, SSH_HOSTS_CREATE_TOOL,
            SSH_HOSTS_DELETE_TOOL, SSH_HOSTS_GET_TOOL, SSH_HOSTS_HOST_CA_PUBLIC_KEY_GET_TOOL,
            SSH_HOSTS_HOST_CERTIFICATE_ISSUE_TOOL, SSH_HOSTS_LIST_TOOL, SSH_HOSTS_REPLACE_TOOL,
            SSH_HOSTS_USER_CA_PUBLIC_KEY_GET_TOOL, TAGS_CREATE_TOOL, TAGS_DELETE_TOOL,
            TAGS_GET_TOOL, TAGS_UPDATE_TOOL, TOKEN_AUTH_ATTACH_TOOL, TOKEN_AUTH_GET_TOOL,
            TOKEN_AUTH_REMOVE_TOOL, TOKEN_AUTH_TOKENS_CREATE_TOOL, TOKEN_AUTH_TOKENS_GET_TOOL,
            TOKEN_AUTH_TOKENS_LIST_TOOL, TOKEN_AUTH_TOKENS_REVOKE_TOOL,
            TOKEN_AUTH_TOKENS_UPDATE_TOOL, TOKEN_AUTH_UPDATE_TOOL, TYPES_DESCRIBE_TOOL,
            UNIVERSAL_AUTH_ATTACH_TOOL, UNIVERSAL_AUTH_CLIENT_SECRETS_CREATE_TOOL,
            UNIVERSAL_AUTH_CLIENT_SECRETS_GET_TOOL, UNIVERSAL_AUTH_CLIENT_SECRETS_LIST_TOOL,
            UNIVERSAL_AUTH_CLIENT_SECRETS_REVOKE_TOOL, UNIVERSAL_AUTH_GET_TOOL,
            UNIVERSAL_AUTH_LOCKOUTS_CLEAR_TOOL, UNIVERSAL_AUTH_REMOVE_TOOL,
            UNIVERSAL_AUTH_UPDATE_TOOL,
        },
    };

    fn mcp() -> InfisicalMcp {
        let settings = ClientSettings::new(
            "http://127.0.0.1:9".parse().unwrap(),
            "test-client".into(),
            SecretValue::new("test-client-secret"),
        );
        InfisicalMcp::new(InfisicalClient::new(settings).unwrap())
    }

    fn assert_catalog_identity(tools: &[Tool]) {
        assert_discovery_catalog_identity(&tools[..2]);
        assert_admin_catalog_identity(&tools[2..11]);
        assert_folder_tag_catalog_identity(&tools[11..22]);
        assert_identity_catalog_identity(&tools[22..27]);
        assert_project_membership_catalog_identity(&tools[27..37]);
        assert_role_catalog_identity(&tools[37..41]);
        assert_group_catalog_identity(&tools[41..47]);
        assert_identity_project_additional_privilege_catalog_identity(&tools[47..53]);
        assert_universal_auth_catalog_identity(&tools[53..62]);
        assert_token_auth_catalog_identity(&tools[62..71]);
        assert_kubernetes_auth_catalog_identity(&tools[71..75]);
        assert_secret_catalog_identity(&tools[75..83]);
        assert_secret_import_catalog_identity(&tools[83..88]);
        assert_audit_log_catalog_identity(&tools[88..89]);
        assert_app_automation_catalog_identity(&tools[89..103]);
        assert_sql_secret_rotation_catalog_identity(&tools[103..112]);
        assert_certificate_authority_catalog_identity(&tools[112..127]);
        assert_certificate_catalog_identity(&tools[127..138]);
        assert_certificate_request_catalog_identity(&tools[138..142]);
        assert_certificate_policy_catalog_identity(&tools[142..147]);
        assert_certificate_profile_catalog_identity(&tools[147..156]);
        assert_ssh_certificate_authority_catalog_identity(&tools[156..170]);
        assert_code_signer_catalog_identity(&tools[170..193]);
        assert_kms_catalog_identity(&tools[193..208]);
        assert_dynamic_secret_catalog_identity(&tools[208..218]);
        assert_ssh_host_catalog_identity(&tools[218..234]);
    }

    type ToolIdentity<'a> = (&'a str, &'a str, &'a str);

    fn assert_tool_identity(tools: &[Tool], expected: &[ToolIdentity<'_>]) {
        assert_eq!(
            tools
                .iter()
                .map(|tool| (
                    tool.name.as_ref(),
                    tool.title.as_deref().expect("tool title"),
                    tool.description.as_deref().expect("tool description"),
                ))
                .collect::<Vec<_>>(),
            expected
        );
    }

    fn assert_certificate_profile_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    CERTIFICATE_PROFILES_LIST_TOOL,
                    "List certificate profiles",
                    "List one bounded page of sanitized certificate profiles with typed issuer and enrollment metadata; EST passphrases are discarded before the MCP boundary.",
                ),
                (
                    CERTIFICATE_PROFILES_GET_TOOL,
                    "Get certificate profile",
                    "Get one exact sanitized certificate profile after proving its stated Certificate Manager project ownership.",
                ),
                (
                    CERTIFICATE_PROFILES_GET_BY_SLUG_TOOL,
                    "Get certificate profile by slug",
                    "Get one exact sanitized certificate profile by project-local slug through a non-replayed audited GET.",
                ),
                (
                    CERTIFICATE_PROFILES_CREATE_TOOL,
                    "Create certificate profile",
                    "Create one API, EST, ACME, or SCEP certificate profile after project, policy, and optional CA scope preflights and explicit confirmation.",
                ),
                (
                    CERTIFICATE_PROFILES_UPDATE_TOOL,
                    "Update certificate profile",
                    "Apply one non-empty metadata, defaults, or same-enrollment-family configuration change after an audited ownership preflight and explicit confirmation.",
                ),
                (
                    CERTIFICATE_PROFILES_DELETE_TOOL,
                    "Delete certificate profile",
                    "Permanently delete one exact certificate profile after an audited ownership preflight and explicit confirmation.",
                ),
                (
                    CERTIFICATE_PROFILE_CERTIFICATES_LIST_TOOL,
                    "List certificate-profile certificates",
                    "List one bounded page of certificate metadata issued through an exact profile after an audited ownership preflight.",
                ),
                (
                    CERTIFICATE_PROFILE_LATEST_BUNDLE_REVEAL_TOOL,
                    "Reveal latest certificate-profile bundle",
                    "Reveal the latest active certificate, chain, and private key for one exact profile only after explicit confirmation, an audited ownership preflight, and current leaf/issuer validity checks.",
                ),
                (
                    CERTIFICATE_PROFILE_EAB_SECRET_REVEAL_TOOL,
                    "Reveal certificate-profile ACME EAB secret",
                    "Reveal the ACME External Account Binding secret for one exact ACME profile only after explicit confirmation and an audited ownership preflight.",
                ),
            ],
        );
    }

    fn assert_certificate_policy_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    CERTIFICATE_POLICIES_LIST_TOOL,
                    "List certificate policies",
                    "List one bounded page of typed certificate-policy metadata in one Certificate Manager project.",
                ),
                (
                    CERTIFICATE_POLICIES_GET_TOOL,
                    "Get certificate policy",
                    "Get one exact certificate policy after proving its stated Certificate Manager project ownership.",
                ),
                (
                    CERTIFICATE_POLICIES_CREATE_TOOL,
                    "Create certificate policy",
                    "Create one typed certificate policy after validating its rules, project scope, and explicit confirmation.",
                ),
                (
                    CERTIFICATE_POLICIES_UPDATE_TOOL,
                    "Update certificate policy",
                    "Update one exact project-owned certificate policy after validating a non-empty change and explicit confirmation.",
                ),
                (
                    CERTIFICATE_POLICIES_DELETE_TOOL,
                    "Delete certificate policy",
                    "Delete one exact project-owned certificate policy after explicit confirmation and an ownership preflight.",
                ),
            ],
        );
    }

    fn assert_certificate_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    CERTIFICATES_LIST_TOOL,
                    "Search certificates",
                    "Search one bounded page of project-scoped certificate metadata without returning certificate bodies, issuer chains, or private keys.",
                ),
                (
                    CERTIFICATES_GET_TOOL,
                    "Get certificate metadata",
                    "Get one exact project-owned certificate as sanitized metadata, including lifecycle state and whether Infisical holds its private key.",
                ),
                (
                    CERTIFICATES_ISSUE_TOOL,
                    "Issue certificate",
                    "Request one certificate through a project-owned API-enrolled profile, returning either a pending request reference or validated immediate material with governed private-key delivery.",
                ),
                (
                    CERTIFICATES_RENEW_TOOL,
                    "Renew certificate",
                    "Renew an active API-enrolled managed-key certificate, returning validated replacement material through governed private-key delivery.",
                ),
                (
                    CERTIFICATES_REVOKE_TOOL,
                    "Revoke certificate",
                    "Revoke an active project-owned certificate with a selected RFC 5280 reason after confirmation.",
                ),
                (
                    CERTIFICATES_RENEWAL_CONFIGURATION_UPDATE_TOOL,
                    "Update certificate renewal configuration",
                    "Set or disable renewal for an eligible project-owned managed-key certificate.",
                ),
                (
                    CERTIFICATES_DELETE_TOOL,
                    "Delete certificate",
                    "Remove a project-owned certificate record after confirmation.",
                ),
                (
                    CERTIFICATES_IMPORT_TOOL,
                    "Import certificate material",
                    "Import one validated certificate and optional matching private material from governed uploads, then reconcile the created project inventory record.",
                ),
                (
                    CERTIFICATES_CERTIFICATE_GET_TOOL,
                    "Get public certificate material",
                    "Retrieve a project-owned certificate body and issuer chain as public material after binding the response to inventory.",
                ),
                (
                    CERTIFICATES_BUNDLE_REVEAL_TOOL,
                    "Reveal certificate bundle",
                    "Retrieve a project-owned certificate bundle after confirmation, with private-key material returned inline unless the HTTP file-transfer extension is configured.",
                ),
                (
                    CERTIFICATES_PRIVATE_KEY_REVEAL_TOOL,
                    "Reveal certificate private key",
                    "Retrieve a project-owned stored private key after confirmation and bind it cryptographically to the selected certificate, returning it inline unless the HTTP file-transfer extension is configured.",
                ),
            ],
        );
    }

    fn assert_certificate_request_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    CERTIFICATE_REQUESTS_LIST_TOOL,
                    "Search certificate requests",
                    "Search one bounded page of project-scoped certificate-request status metadata without returning certificate bodies, private keys, or upstream status messages.",
                ),
                (
                    CERTIFICATE_REQUESTS_GET_TOOL,
                    "Get certificate-request status",
                    "Find one exact certificate request through project-scoped sanitized inventory without returning certificate or private-key material.",
                ),
                (
                    CERTIFICATE_REQUEST_RESULT_REVEAL_TOOL,
                    "Reveal certificate-request result",
                    "Retrieve one issued request's certificate and optional private key only after explicit confirmation and a project-scoped status preflight.",
                ),
                (
                    CERTIFICATE_REQUESTS_CANCEL_TOOL,
                    "Cancel certificate request",
                    "Cancel one pending or pending-validation certificate request after a project-scoped status preflight and explicit confirmation.",
                ),
            ],
        );
    }

    fn assert_ssh_certificate_authority_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    SSH_CERTIFICATE_AUTHORITIES_LIST_TOOL,
                    "List SSH certificate authorities",
                    "List bounded value-free SSH certificate-authority metadata for one exact SSH Access project.",
                ),
                (
                    SSH_CERTIFICATE_AUTHORITIES_GET_TOOL,
                    "Get SSH certificate authority",
                    "Get one exact SSH certificate authority after proving its stated SSH Access project ownership; only public key material is returned.",
                ),
                (
                    SSH_CERTIFICATE_AUTHORITIES_PUBLIC_KEY_GET_TOOL,
                    "Get SSH certificate-authority public key",
                    "Read the dedicated SSH CA public-key route and bind it to the authenticated authority record.",
                ),
                (
                    SSH_CERTIFICATE_AUTHORITIES_CREATE_TOOL,
                    "Create SSH certificate authority",
                    "Create one internally generated or externally keyed SSH certificate authority in the exact requested project after explicit confirmation; imported private keys are consumed and never returned.",
                ),
                (
                    SSH_CERTIFICATE_AUTHORITIES_REPLACE_TOOL,
                    "Replace SSH certificate authority",
                    "Replace every mutable SSH certificate-authority field after an exact ownership preflight and explicit confirmation.",
                ),
                (
                    SSH_CERTIFICATE_AUTHORITIES_DELETE_TOOL,
                    "Delete SSH certificate authority",
                    "Permanently delete one exact SSH certificate authority after ownership preflight and explicit confirmation.",
                ),
                (
                    SSH_CERTIFICATE_TEMPLATES_LIST_TOOL,
                    "List SSH certificate templates",
                    "List every bounded SSH certificate template in one exact SSH Access project.",
                ),
                (
                    SSH_CERTIFICATE_AUTHORITY_TEMPLATES_LIST_TOOL,
                    "List SSH certificate-authority templates",
                    "List bounded templates attached to one exact SSH certificate authority after an ownership preflight.",
                ),
                (
                    SSH_CERTIFICATE_TEMPLATES_GET_TOOL,
                    "Get SSH certificate template",
                    "Get one exact SSH certificate template after proving its SSH CA and project ownership.",
                ),
                (
                    SSH_CERTIFICATE_TEMPLATES_CREATE_TOOL,
                    "Create SSH certificate template",
                    "Create one closed SSH certificate issuance policy beneath an active exact CA after explicit confirmation.",
                ),
                (
                    SSH_CERTIFICATE_TEMPLATES_REPLACE_TOOL,
                    "Replace SSH certificate template",
                    "Replace every mutable SSH certificate-template field as one complete validated policy after explicit confirmation.",
                ),
                (
                    SSH_CERTIFICATE_TEMPLATES_DELETE_TOOL,
                    "Delete SSH certificate template",
                    "Permanently delete one exact SSH certificate template after CA ownership preflight and explicit confirmation.",
                ),
                (
                    SSH_CERTIFICATES_SIGN_TOOL,
                    "Sign SSH public key",
                    "Sign one bounded existing OpenSSH public key after exact CA ownership and template-policy preflights; the single mutation is never replayed and the returned certificate is cryptographically and semantically verified.",
                ),
                (
                    SSH_CERTIFICATES_ISSUE_TOOL,
                    "Issue SSH certificate and key pair",
                    "Generate one supported OpenSSH key pair and issue its certificate after exact policy preflights and explicit reveal confirmation; the private key is returned once only after pair and certificate verification.",
                ),
            ],
        );
    }

    #[allow(clippy::too_many_lines)]
    fn assert_code_signer_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    CODE_SIGNERS_LIST_TOOL,
                    "List code signers",
                    "List one bounded page of code signers after binding every result to the requested Certificate Manager project.",
                ),
                (
                    CODE_SIGNERS_GET_TOOL,
                    "Get code signer",
                    "Get one exact code signer after proving its stated Certificate Manager project ownership.",
                ),
                (
                    CODE_SIGNERS_CREATE_TOOL,
                    "Create code signer",
                    "Create one signer from an active existing code-signing certificate or enabled internal CA after audited scope preflights and explicit confirmation.",
                ),
                (
                    CODE_SIGNERS_UPDATE_TOOL,
                    "Update code signer",
                    "Apply one non-empty signer metadata or renewal-window change after an audited ownership preflight and explicit confirmation.",
                ),
                (
                    CODE_SIGNERS_DELETE_TOOL,
                    "Delete code signer",
                    "Permanently delete one exact signer and its governance state after an audited ownership preflight and explicit confirmation.",
                ),
                (
                    CODE_SIGNERS_STATUS_UPDATE_TOOL,
                    "Update code-signer status",
                    "Enable or disable one exact signer after validating a real state transition and explicit confirmation.",
                ),
                (
                    CODE_SIGNERS_CERTIFICATE_REISSUE_TOOL,
                    "Reissue code-signer certificate",
                    "Issue and attach a replacement signer certificate from an enabled internal CA after signer and CA scope preflights and explicit confirmation.",
                ),
                (
                    CODE_SIGNERS_CERTIFICATE_EXPORT_TOOL,
                    "Export code-signer certificate",
                    "Export one exact signer's validated public leaf certificate after an audited ownership preflight.",
                ),
                (
                    CODE_SIGNERS_PUBLIC_KEY_GET_TOOL,
                    "Get code-signer public key",
                    "Get one exact signer's bounded base64 DER SubjectPublicKeyInfo after an audited ownership preflight.",
                ),
                (
                    CODE_SIGNERS_SIGN_TOOL,
                    "Sign with code signer",
                    "Sign at most 128 decoded bytes with one active signer after project, certificate, state, digest, and algorithm preflights and explicit confirmation; the operation is never replayed.",
                ),
                (
                    CODE_SIGNER_MEMBERS_LIST_TOOL,
                    "List code-signer members",
                    "List bounded direct user, machine-identity, or group memberships for one exact signer after an audited ownership preflight.",
                ),
                (
                    CODE_SIGNER_MEMBERS_ADD_TOOL,
                    "Add code-signer member",
                    "Add one exact direct signer member with a built-in role after project and signer preflights and explicit confirmation.",
                ),
                (
                    CODE_SIGNER_MEMBER_ROLE_UPDATE_TOOL,
                    "Update code-signer member role",
                    "Replace one exact direct signer member's built-in role after confirming current membership and explicit confirmation.",
                ),
                (
                    CODE_SIGNER_MEMBERS_REMOVE_TOOL,
                    "Remove code-signer member",
                    "Remove one exact direct signer membership after an audited ownership and membership preflight and explicit confirmation.",
                ),
                (
                    CODE_SIGNER_EFFECTIVE_MEMBERS_LIST_TOOL,
                    "List effective code-signer members",
                    "List bounded direct and group-derived user or machine-identity access for one exact signer.",
                ),
                (
                    CODE_SIGNER_PERMISSIONS_GET_TOOL,
                    "Get code-signer permissions",
                    "Get normalized effective signer permissions for the authenticated Infisical identity without exposing arbitrary CASL condition payloads.",
                ),
                (
                    CODE_SIGNER_APPROVAL_POLICY_GET_TOOL,
                    "Get code-signer approval policy",
                    "Get one exact signer's bounded approval steps, approvers, and signing limits.",
                ),
                (
                    CODE_SIGNER_APPROVAL_POLICY_REPLACE_TOOL,
                    "Replace code-signer approval policy",
                    "Replace one exact signer's complete approval policy after verifying every approver is a non-auditor signer member and obtaining explicit confirmation.",
                ),
                (
                    CODE_SIGNER_APPROVAL_REQUESTS_LIST_TOOL,
                    "List code-signer approval requests",
                    "List one bounded page of sanitized signing approval requests for one exact signer.",
                ),
                (
                    CODE_SIGNER_APPROVAL_REQUESTS_CREATE_TOOL,
                    "Create code-signer approval request",
                    "Open one finite signing approval request after validating it against the current signer policy and explicit confirmation.",
                ),
                (
                    CODE_SIGNER_APPROVAL_REQUESTS_PRE_APPROVE_TOOL,
                    "Pre-approve code-signer request",
                    "Create one finite active signing grant for an effective non-auditor signer member after explicit confirmation.",
                ),
                (
                    CODE_SIGNER_APPROVAL_REQUESTS_REVOKE_TOOL,
                    "Revoke code-signer approval request",
                    "Revoke one exact pending or active signer approval request and its active grants after explicit confirmation.",
                ),
                (
                    CODE_SIGNER_OPERATIONS_LIST_TOOL,
                    "List code-signer operations",
                    "List one bounded page of sanitized code-signing operation history without returning signed-data hashes, client metadata, or upstream error text.",
                ),
            ],
        );
    }

    fn assert_discovery_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "projects.list",
                    "List projects",
                    "List a bounded page of projects visible to the dedicated Infisical Machine Identity.",
                ),
                (
                    "projects.get",
                    "Get project",
                    "Get concise metadata for one project by exact Infisical project ID.",
                ),
            ],
        );
    }

    fn assert_admin_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "projects.create",
                    "Create project",
                    "Create one typed Infisical project with explicit default-environment and deletion-protection settings.",
                ),
                (
                    "projects.update",
                    "Update project",
                    "Apply one exact name, description, slug, protection, capitalization, metadata-encryption, sharing, or retention change to a project.",
                ),
                (
                    "projects.delete",
                    "Delete project",
                    "Soft-delete one exact project after explicit confirmation; Infisical schedules later cleanup.",
                ),
                (
                    "environments.list",
                    "List environments",
                    "List a bounded page of environments embedded in one exact Infisical project.",
                ),
                (
                    "environments.get",
                    "Get environment",
                    "Get one environment by exact project and environment identifiers.",
                ),
                (
                    "environments.create",
                    "Create environment",
                    "Create one environment with an exact name, slug, and optional bounded position.",
                ),
                (
                    "environments.update",
                    "Update environment",
                    "Apply one exact name, slug, or position change to an environment.",
                ),
                (
                    "environments.delete",
                    "Delete environment",
                    "Soft-delete one exact environment after explicit confirmation; hard deletion is not exposed.",
                ),
                (
                    "environments.restore",
                    "Restore environment",
                    "Restore one previously soft-deleted environment by exact identifiers.",
                ),
            ],
        );
    }

    fn assert_folder_tag_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "folders.list",
                    "List folders",
                    "List a bounded page of folders under an exact project, environment, and secret-tree path.",
                ),
                (
                    "folders.get",
                    "Get folder",
                    "Get one folder by exact opaque Infisical folder ID.",
                ),
                (
                    "folders.create",
                    "Create folder",
                    "Create one folder under an exact parent path; Infisical may create missing parent segments.",
                ),
                (
                    "folders.update",
                    "Update folder",
                    "Replace one folder's complete name and nullable description at its exact parent path.",
                ),
                (
                    "folders.batch.update",
                    "Update folder batch",
                    "Replace the complete mutable state of one to fifty uniquely identified folders in one project.",
                ),
                (
                    "folders.delete",
                    "Delete folder",
                    "Delete one exact folder after confirmation; forceDelete must be explicitly selected to remove contained resources.",
                ),
                (
                    "tags.list",
                    "List tags",
                    "List a bounded page of secret tags defined for one exact Infisical project.",
                ),
                (
                    "tags.get",
                    "Get tag",
                    "Get one project tag by an exact opaque ID or stable slug.",
                ),
                (
                    "tags.create",
                    "Create tag",
                    "Create one project tag with an exact slug and bounded color string.",
                ),
                (
                    "tags.update",
                    "Update tag",
                    "Replace one project tag's complete slug and color state.",
                ),
                (
                    "tags.delete",
                    "Delete tag",
                    "Permanently delete one exact project tag after explicit confirmation.",
                ),
            ],
        );
    }

    fn assert_secret_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "secrets.metadata.list",
                    "List secret metadata",
                    "List bounded, value-free secret metadata under an exact scope; secret values, imports, references, and personal overrides stay disabled.",
                ),
                (
                    "secrets.reveal",
                    "Reveal secret",
                    "Reveal the current value of one exact shared secret; imports and reference expansion stay disabled.",
                ),
                (
                    "secrets.create",
                    "Create secret",
                    "Create one exact shared secret and return only value-free identity, version, timestamp, or approval metadata.",
                ),
                (
                    "secrets.update",
                    "Update secret",
                    "Replace one exact shared secret value once and return only value-free identity, version, timestamp, or approval metadata.",
                ),
                (
                    "secrets.delete",
                    "Delete secret",
                    "Permanently delete one exact shared secret after explicit confirmation and return value-free affected-secret or approval metadata.",
                ),
                (
                    "secrets.batch.create",
                    "Create secret batch",
                    "Create one to fifty uniquely named shared secrets under one exact scope and return only value-free affected-secret or approval metadata.",
                ),
                (
                    "secrets.batch.update",
                    "Update secret batch",
                    "Replace one to fifty uniquely named shared secret values under one exact scope, failing if any name is absent, and return only value-free metadata.",
                ),
                (
                    "secrets.batch.delete",
                    "Delete secret batch",
                    "Permanently delete one to fifty uniquely named shared secrets under one exact scope after explicit confirmation and return only value-free metadata.",
                ),
            ],
        );
    }

    fn assert_identity_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "identities.list",
                    "List machine identities",
                    "List a bounded page of non-secret machine-identity metadata for one exact organization.",
                ),
                (
                    "identities.get",
                    "Get machine identity",
                    "Get non-secret metadata and organization membership for one exact machine identity.",
                ),
                (
                    "identities.create",
                    "Create machine identity",
                    "Create one machine identity with a built-in role and delete protection enabled by default.",
                ),
                (
                    "identities.update",
                    "Update machine identity",
                    "Apply one exact name, built-in role, or delete-protection change to a machine identity.",
                ),
                (
                    "identities.delete",
                    "Delete machine identity",
                    "Permanently delete one exact machine identity and its credentials after explicit confirmation.",
                ),
            ],
        );
    }

    fn assert_project_membership_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "projectUserMemberships.list",
                    "List project user memberships",
                    "List a bounded page of sanitized human-user memberships and role assignments for one project.",
                ),
                (
                    "projectUserMemberships.get",
                    "Get project user membership",
                    "Get one sanitized human-user project membership by exact membership ID.",
                ),
                (
                    "projectUserMemberships.invite",
                    "Invite project users",
                    "Invite one to fifty lowercase user handles with a complete permanent role assignment.",
                ),
                (
                    "projectUserMemberships.update",
                    "Update project user membership",
                    "Replace every role on one human-user membership with confirmed permanent assignments.",
                ),
                (
                    "projectUserMemberships.delete",
                    "Delete project user membership",
                    "Remove one exact human-user project membership after explicit confirmation.",
                ),
                (
                    "projectIdentityMemberships.list",
                    "List project identity memberships",
                    "List a bounded page of machine-identity memberships and role assignments for one project.",
                ),
                (
                    "projectIdentityMemberships.get",
                    "Get project identity membership",
                    "Get one machine-identity project membership by exact project and identity IDs.",
                ),
                (
                    "projectIdentityMemberships.create",
                    "Create project identity membership",
                    "Add one machine identity to a project with a complete permanent role assignment.",
                ),
                (
                    "projectIdentityMemberships.update",
                    "Update project identity membership",
                    "Replace every role on one machine-identity membership with confirmed permanent assignments.",
                ),
                (
                    "projectIdentityMemberships.delete",
                    "Delete project identity membership",
                    "Remove one exact machine-identity project membership after explicit confirmation.",
                ),
            ],
        );
    }

    fn assert_role_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "projectRoles.list",
                    "List project roles",
                    "List a bounded page of built-in and custom roles for one exact project without synthetic role IDs or timestamps.",
                ),
                (
                    "projectRoles.get",
                    "Get project role",
                    "Get one project role by stable slug, including its normalized permission rules.",
                ),
                (
                    "organizationRoles.list",
                    "List organization roles",
                    "List a bounded page of built-in and custom roles for the authenticated identity's organization.",
                ),
                (
                    "organizationRoles.get",
                    "Get organization role",
                    "Get one organization role by stable slug, including its normalized permission rules.",
                ),
            ],
        );
    }

    fn assert_group_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "groups.list",
                    "List groups",
                    "List a locally bounded page of groups and organization-role assignments for the authenticated identity's organization.",
                ),
                (
                    "groups.get",
                    "Get group",
                    "Get one organization group by exact identifier, including its organization-role assignment.",
                ),
                (
                    "groups.members.list",
                    "List group members",
                    "List a bounded page of human users and machine identities assigned to one exact group.",
                ),
                (
                    "groups.projects.list",
                    "List group projects",
                    "List a bounded page of organization projects and their assignment state for one exact group.",
                ),
                (
                    "projectGroupMemberships.list",
                    "List project group memberships",
                    "List a locally bounded page of group memberships and role assignments for one exact project.",
                ),
                (
                    "projectGroupMemberships.get",
                    "Get project group membership",
                    "Get one project group membership by exact project and group identifiers.",
                ),
            ],
        );
    }

    fn assert_identity_project_additional_privilege_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "identityProjectAdditionalPrivileges.list",
                    "List identity project additional privileges",
                    "List a locally bounded page of additional privilege grants for one exact machine identity in one exact project.",
                ),
                (
                    "identityProjectAdditionalPrivileges.get",
                    "Get identity project additional privilege",
                    "Get one identity project additional privilege by exact ID after confirming it belongs to the requested project and identity.",
                ),
                (
                    "identityProjectAdditionalPrivileges.getBySlug",
                    "Get identity project additional privilege by slug",
                    "Get one identity project additional privilege by stable slug after confirming it belongs to the requested project and identity.",
                ),
                (
                    "identityProjectAdditionalPrivileges.create",
                    "Create identity project additional privilege",
                    "Create one permanent or scheduled temporary project permission grant for one exact machine identity, acknowledging any inverted deny rules.",
                ),
                (
                    "identityProjectAdditionalPrivileges.update",
                    "Update identity project additional privilege",
                    "Replace one additional privilege's slug and lifetime, optionally replacing every permission after explicit acknowledgement.",
                ),
                (
                    "identityProjectAdditionalPrivileges.delete",
                    "Delete identity project additional privilege",
                    "Delete one exact identity project additional privilege after scope preflight and explicit confirmation.",
                ),
            ],
        );
    }

    fn assert_universal_auth_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "identityUniversalAuth.get",
                    "Get Universal Auth configuration",
                    "Get non-secret Universal Auth configuration, including public client ID and current trusted-IP metadata, for one machine identity.",
                ),
                (
                    "identityUniversalAuth.attach",
                    "Attach Universal Auth",
                    "Attach one complete community-compatible Universal Auth configuration; enterprise trusted-IP mutation remains capability-gated.",
                ),
                (
                    "identityUniversalAuth.update",
                    "Update Universal Auth",
                    "Apply one coherent token-lifetime, use-limit, or complete lockout-policy change without a read-before-write window.",
                ),
                (
                    "identityUniversalAuth.remove",
                    "Remove Universal Auth",
                    "Remove Universal Auth and revoke its credentials and derived tokens after explicit confirmation.",
                ),
                (
                    "identityUniversalAuth.clientSecrets.list",
                    "List Universal Auth client secrets",
                    "List a bounded page of value-free Universal Auth client-secret metadata for one machine identity.",
                ),
                (
                    "identityUniversalAuth.clientSecrets.get",
                    "Get Universal Auth client secret",
                    "Get value-free metadata for one exact Universal Auth client secret.",
                ),
                (
                    "identityUniversalAuth.clientSecrets.create",
                    "Create Universal Auth client secret",
                    "Create one Universal Auth client secret and reveal the generated credential exactly once with non-secret metadata.",
                ),
                (
                    "identityUniversalAuth.clientSecrets.revoke",
                    "Revoke Universal Auth client secret",
                    "Revoke one exact Universal Auth client secret and its derived tokens after explicit confirmation.",
                ),
                (
                    "identityUniversalAuth.lockouts.clear",
                    "Clear Universal Auth lockouts",
                    "Clear all current Universal Auth lockouts for one machine identity after explicit confirmation.",
                ),
            ],
        );
    }

    fn assert_token_auth_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "identityTokenAuth.get",
                    "Get Token Auth configuration",
                    "Get non-secret Token Auth configuration and current trusted-IP metadata for one machine identity.",
                ),
                (
                    "identityTokenAuth.attach",
                    "Attach Token Auth",
                    "Attach one explicit community-compatible Token Auth configuration; enterprise trusted-IP mutation remains capability-gated.",
                ),
                (
                    "identityTokenAuth.update",
                    "Update Token Auth",
                    "Apply one coherent token-lifetime or use-limit change without a read-before-write window.",
                ),
                (
                    "identityTokenAuth.remove",
                    "Remove Token Auth",
                    "Remove Token Auth and revoke all of its credentials after explicit confirmation.",
                ),
                (
                    "identityTokenAuth.tokens.list",
                    "List Token Auth tokens",
                    "List one bounded upstream page of value-free Token Auth token metadata for one machine identity.",
                ),
                (
                    "identityTokenAuth.tokens.get",
                    "Get Token Auth token",
                    "Get value-free metadata for one exact Token Auth token by opaque ID.",
                ),
                (
                    "identityTokenAuth.tokens.create",
                    "Create Token Auth token",
                    "Generate one Token Auth bearer credential and reveal it exactly once with non-secret metadata.",
                ),
                (
                    "identityTokenAuth.tokens.update",
                    "Update Token Auth token",
                    "Replace the complete non-secret operator label of one exact Token Auth token.",
                ),
                (
                    "identityTokenAuth.tokens.revoke",
                    "Revoke Token Auth token",
                    "Revoke one exact Token Auth bearer credential after explicit confirmation.",
                ),
            ],
        );
    }

    fn assert_kubernetes_auth_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "identityKubernetesAuth.get",
                    "Get Kubernetes Auth configuration",
                    "Get value-free Kubernetes Auth configuration, reviewer-credential presence, and current paid-feature metadata for one machine identity.",
                ),
                (
                    "identityKubernetesAuth.attach",
                    "Attach Kubernetes Auth",
                    "Attach a complete direct Kubernetes API review configuration with explicit workload and audience restrictions.",
                ),
                (
                    "identityKubernetesAuth.update",
                    "Update Kubernetes Auth",
                    "Apply one coherent token, workload-policy, or direct-reviewer change without a read-before-write window.",
                ),
                (
                    "identityKubernetesAuth.remove",
                    "Remove Kubernetes Auth",
                    "Remove Kubernetes Auth and revoke its derived tokens after explicit confirmation.",
                ),
            ],
        );
    }

    fn assert_secret_import_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "secretImports.list",
                    "List secret imports",
                    "List a bounded page of value-free secret-import mappings under one exact destination scope.",
                ),
                (
                    "secretImports.get",
                    "Get secret import",
                    "Get one value-free secret-import mapping by exact opaque identifier.",
                ),
                (
                    "secretImports.create",
                    "Create secret import",
                    "Create one non-replicating secret import between exact destination and source scopes in the same project.",
                ),
                (
                    "secretImports.update",
                    "Update secret import",
                    "Replace one secret import's complete source coordinate or move it to one bounded position.",
                ),
                (
                    "secretImports.delete",
                    "Delete secret import",
                    "Permanently delete one exact secret-import mapping after explicit confirmation.",
                ),
            ],
        );
    }

    fn assert_audit_log_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[(
                "auditLogs.list",
                "List audit logs",
                "List one bounded organization or project audit-log page without arbitrary actor or event metadata; requesting offset zero creates Infisical's view-audit-logs record.",
            )],
        );
    }

    fn assert_app_automation_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "appConnections.list",
                    "List app connections",
                    "List one locally bounded page of value-free app connections; Infisical records this GET as an audit event, so it is sent exactly once and never retried.",
                ),
                (
                    "appConnections.github.get",
                    "Get GitHub app connection",
                    "Get one exact value-free GitHub app connection; Infisical records this GET as an audit event, so it is sent exactly once and never retried.",
                ),
                (
                    "appConnections.github.create",
                    "Create GitHub app connection",
                    "Create one typed GitHub app connection; authorization codes and tokens are sent only to Infisical and never returned.",
                ),
                (
                    "appConnections.github.update",
                    "Update GitHub app connection",
                    "Update one exact GitHub app connection; credential replacement requires explicit confirmation and the stored immutable method, and the mutation is sent once.",
                ),
                (
                    "appConnections.github.rotateCredentials",
                    "Rotate GitHub app-connection credentials",
                    "Rotate the stored credential of one exact GitHub app connection after explicit confirmation; the bodyless action is sent once and returns value-free metadata.",
                ),
                (
                    "appConnections.github.delete",
                    "Delete GitHub app connection",
                    "Permanently delete one exact GitHub app connection after explicit confirmation.",
                ),
                (
                    "secretSyncs.list",
                    "List secret syncs",
                    "List one locally bounded project page of value-free secret-sync inventory; provider destination configuration and status messages never cross the MCP boundary.",
                ),
                (
                    "secretSyncs.github.get",
                    "Get GitHub secret sync",
                    "Get one exact typed GitHub secret sync after validating its project and joined environment; the audited provider GET is sent once.",
                ),
                (
                    "secretSyncs.github.create",
                    "Create GitHub secret sync",
                    "Create one typed GitHub secret sync after explicit acknowledgement that its initial run overwrites destination keys.",
                ),
                (
                    "secretSyncs.github.update",
                    "Update GitHub secret sync",
                    "Update one exact GitHub secret sync after an audited project-scope preflight and explicit overwrite acknowledgement.",
                ),
                (
                    "secretSyncs.github.delete",
                    "Delete GitHub secret sync",
                    "Delete one exact GitHub secret sync; removing destination secrets requires a separate explicit confirmation.",
                ),
                (
                    "secretSyncs.github.run",
                    "Run GitHub secret sync",
                    "Manually overwrite one GitHub sync destination from Infisical after an audited scope preflight and explicit confirmation.",
                ),
                (
                    "secretSyncs.github.removeSecrets",
                    "Remove GitHub destination secrets",
                    "Remove previously synchronized secrets from one exact GitHub destination after an audited scope preflight and explicit confirmation.",
                ),
                (
                    "secretRotations.list",
                    "List secret rotations",
                    "List one locally bounded project page of value-free secret-rotation inventory; provider parameters, mappings, generated credentials, and status messages never cross the MCP boundary.",
                ),
            ],
        );
    }

    fn assert_sql_secret_rotation_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "secretRotations.sql.get",
                    "Get SQL secret rotation",
                    "Get one exact value-free SQL credential rotation after validating its project, provider, connection, and joined environment; the audited provider GET is sent once.",
                ),
                (
                    "secretRotations.sql.getByName",
                    "Get SQL secret rotation by name",
                    "Get one exact value-free SQL credential rotation by canonical project scope and name; the audited provider GET is sent once.",
                ),
                (
                    "secretRotations.sql.create",
                    "Create SQL secret rotation",
                    "Create one provider-tagged SQL credential rotation after complete validation and explicit confirmation that database principals and mapped secrets are created immediately.",
                ),
                (
                    "secretRotations.sql.update",
                    "Update SQL secret rotation",
                    "Update one exact SQL credential rotation after an audited scope preflight and confirmation of mapped-secret renames or an imminent scheduled rotation.",
                ),
                (
                    "secretRotations.sql.delete",
                    "Delete SQL secret rotation",
                    "Delete one exact SQL credential rotation with independent confirmations for mapped-secret deletion and generated-credential revocation.",
                ),
                (
                    "secretRotations.sql.generatedCredentials.get",
                    "Reveal SQL rotation credentials",
                    "Reveal one exact SQL rotation's one or two live credential slots only after explicit confirmation and an audited ownership preflight.",
                ),
                (
                    "secretRotations.sql.move",
                    "Move SQL secret rotation",
                    "Move one exact SQL rotation and its mapped secrets after confirmation; destination overwrite requires a separate confirmation.",
                ),
                (
                    "secretRotations.sql.rotate",
                    "Rotate SQL credentials",
                    "Rotate one exact SQL credential pair and mapped secrets after an audited scope preflight and explicit confirmation.",
                ),
                (
                    "secretRotations.sql.checkCredentials",
                    "Check SQL rotation credentials",
                    "Check one exact rotation's active credentials against its SQL provider after an audited scope preflight and explicit confirmation.",
                ),
            ],
        );
    }

    fn assert_kms_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "kms.keys.list",
                    "List KMS keys",
                    "List one bounded project page of value-free KMS key metadata; Infisical audits the GET, so it is sent exactly once.",
                ),
                (
                    "kms.keys.get",
                    "Get KMS key",
                    "Get one exact value-free KMS key after validating its stated project; the audited GET is sent exactly once.",
                ),
                (
                    "kms.keys.getByName",
                    "Get KMS key by name",
                    "Get one exact value-free KMS key by canonical project and name; the audited GET is sent exactly once.",
                ),
                (
                    "kms.keys.create",
                    "Create KMS key",
                    "Create one typed KMS key after project validation and explicit confirmation; the mutation is sent exactly once.",
                ),
                (
                    "kms.keys.update",
                    "Update KMS key",
                    "Apply one non-empty metadata or disabled-state change after an audited ownership preflight and explicit confirmation.",
                ),
                (
                    "kms.keys.delete",
                    "Delete KMS key",
                    "Permanently delete one exact KMS key after an audited ownership preflight and explicit confirmation.",
                ),
                (
                    "kms.encrypt",
                    "Encrypt with KMS key",
                    "Encrypt one bounded base64 plaintext with an active symmetric key after explicit confirmation; the operation is never replayed.",
                ),
                (
                    "kms.decrypt",
                    "Decrypt with KMS key",
                    "Decrypt one bounded base64 ciphertext with an active symmetric key and reveal plaintext only after explicit confirmation.",
                ),
                (
                    "kms.keys.publicKey.get",
                    "Get KMS public key",
                    "Get the bounded public key of one active asymmetric KMS key after an audited ownership preflight.",
                ),
                (
                    "kms.keys.privateKey.reveal",
                    "Reveal KMS private key",
                    "Reveal one active KMS private key only after explicit confirmation and an audited ownership preflight.",
                ),
                (
                    "kms.keys.bulkImport",
                    "Bulk import KMS keys",
                    "Import one to one hundred uniquely named typed private keys, capped at 512 KiB of aggregate decoded material, after project validation and explicit confirmation.",
                ),
                (
                    "kms.keys.privateKeys.bulkReveal",
                    "Bulk reveal KMS private keys",
                    "Reveal one to one hundred exact active KMS private keys after independent ownership preflights and explicit confirmation.",
                ),
                (
                    "kms.keys.signingAlgorithms.list",
                    "List KMS signing algorithms",
                    "List the exact supported signing algorithms for one active asymmetric KMS key through a non-replayed audited GET.",
                ),
                (
                    "kms.sign",
                    "Sign with KMS key",
                    "Sign one bounded base64 message or digest with an active asymmetric KMS key after explicit confirmation; the operation is never replayed.",
                ),
                (
                    "kms.verify",
                    "Verify with KMS key",
                    "Verify one bounded base64 signature with an active asymmetric KMS key after explicit confirmation; the operation is never replayed.",
                ),
            ],
        );
    }

    fn assert_certificate_authority_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "certificateAuthorities.list",
                    "List certificate authorities",
                    "List bounded value-free metadata for every CA provider family in one Certificate Manager project; provider configuration is discarded before the MCP boundary.",
                ),
                (
                    "certificateAuthorities.internal.list",
                    "List internal certificate authorities",
                    "List bounded typed internal-CA metadata in one exact Certificate Manager project through a non-replayed audited GET.",
                ),
                (
                    "certificateAuthorities.internal.get",
                    "Get internal certificate authority",
                    "Get one exact internal CA after proving its stated Certificate Manager project ownership; encrypted private material never crosses the MCP boundary.",
                ),
                (
                    "certificateAuthorities.internal.create",
                    "Create internal certificate authority",
                    "Create one typed internal CA and encrypted private key after project validation and explicit confirmation; optional root validity creates the root certificate in the same non-replayed mutation.",
                ),
                (
                    "certificateAuthorities.internal.update",
                    "Update internal certificate authority",
                    "Apply one non-empty name, lifecycle-state, or CRL-distribution change after an audited ownership preflight and explicit confirmation.",
                ),
                (
                    "certificateAuthorities.internal.delete",
                    "Delete internal certificate authority",
                    "Permanently delete one exact internal CA and its key, certificates, and CRLs after an audited ownership preflight and explicit confirmation.",
                ),
                (
                    "certificateAuthorities.internal.csr.get",
                    "Get internal CA CSR",
                    "Get the bounded PKCS #10 CSR for one exact internal CA after proving Certificate Manager project ownership.",
                ),
                (
                    "certificateAuthorities.internal.certificates.list",
                    "List internal CA certificates",
                    "List the bounded PEM certificate history for one exact internal CA after an audited ownership preflight.",
                ),
                (
                    "certificateAuthorities.internal.certificate.get",
                    "Get active internal CA certificate",
                    "Get the active PEM certificate and chain for one exact internal CA after an audited ownership preflight.",
                ),
                (
                    "certificateAuthorities.internal.certificateVersion.get",
                    "Get historical internal CA certificate",
                    "Get one exact historical CA certificate version after proving its internal CA and Certificate Manager project scope.",
                ),
                (
                    "certificateAuthorities.internal.certificate.generate",
                    "Generate internal CA certificate",
                    "Generate and install one root or intermediate CA certificate after target and optional parent scope preflights and explicit confirmation.",
                ),
                (
                    "certificateAuthorities.internal.certificate.renew",
                    "Renew internal CA certificate",
                    "Rotate the active internal-CA certificate with a future validity boundary after scope preflight and explicit confirmation.",
                ),
                (
                    "certificateAuthorities.internal.intermediate.sign",
                    "Sign intermediate CA CSR",
                    "Sign one bounded intermediate-CA CSR exactly once after signer scope preflight and explicit confirmation.",
                ),
                (
                    "certificateAuthorities.internal.certificate.import",
                    "Import internal CA certificate",
                    "Install bounded CA certificate and chain PEM into one exact internal CA after scope preflight and explicit confirmation.",
                ),
                (
                    "certificateAuthorities.internal.crls.list",
                    "List internal CA CRLs",
                    "List bounded PEM certificate revocation lists for one exact internal CA after an audited ownership preflight.",
                ),
            ],
        );
    }

    fn assert_dynamic_secret_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    "dynamicSecrets.list",
                    "List dynamic secrets",
                    "List one locally bounded page of value-free dynamic-secret configurations; Infisical records this GET as an audit event, so it is sent exactly once and never retried.",
                ),
                (
                    "dynamicSecrets.get",
                    "Get dynamic secret",
                    "Get one value-free dynamic-secret configuration by exact scoped name; Infisical records this GET as an audit event, so it is sent exactly once and never retried.",
                ),
                (
                    "dynamicSecrets.create",
                    "Create dynamic secret",
                    "Create one provider-tagged dynamic-secret configuration after complete local validation; the SQL provider connection is probed and the mutation is sent once.",
                ),
                (
                    "dynamicSecrets.update",
                    "Update dynamic secret",
                    "Rename one exact dynamic-secret configuration or replace its complete lifetime policy; Infisical also probes the stored provider connection, and the mutation is sent once.",
                ),
                (
                    "dynamicSecrets.delete",
                    "Delete dynamic secret",
                    "Delete one exact dynamic-secret configuration once after explicit confirmation; ordinary deletion cleans up leases, while force removes Infisical tracking without provider cleanup.",
                ),
                (
                    "dynamicSecretLeases.list",
                    "List dynamic-secret leases",
                    "List one locally bounded page of value-free leases for an exact dynamic-secret configuration; Infisical records this GET as an audit event, so it is sent exactly once and never retried.",
                ),
                (
                    "dynamicSecretLeases.get",
                    "Get dynamic-secret lease",
                    "Get value-free metadata for one exact lease and its owning configuration; Infisical records this GET as an audit event, so it is sent exactly once and never retried.",
                ),
                (
                    "dynamicSecretLeases.create",
                    "Create dynamic-secret lease",
                    "Preflight one exact SQL configuration, create its provider principal and lease once, and return the typed password only in this response; an invalid owned result is revoked without touching an unrelated lease.",
                ),
                (
                    "dynamicSecretLeases.renew",
                    "Renew dynamic-secret lease",
                    "Renew one exact dynamic-secret lease once for an explicit lifetime between 60 and 315360000 seconds.",
                ),
                (
                    "dynamicSecretLeases.revoke",
                    "Revoke dynamic-secret lease",
                    "Revoke one exact dynamic-secret lease once after explicit confirmation; force is an independent provider-cleanup override.",
                ),
            ],
        );
    }

    fn assert_ssh_host_catalog_identity(tools: &[Tool]) {
        assert_tool_identity(
            tools,
            &[
                (
                    SSH_HOSTS_LIST_TOOL,
                    "List SSH hosts",
                    "List a bounded canonical SSH host inventory for one exact SSH Access project, including direct and inherited login-policy provenance.",
                ),
                (
                    SSH_HOSTS_GET_TOOL,
                    "Get SSH host",
                    "Get one exact SSH host after proving its project ownership and canonicalizing its effective login policy.",
                ),
                (
                    SSH_HOSTS_CREATE_TOOL,
                    "Create SSH host",
                    "Register one complete SSH host policy beneath explicit active user and host CAs after confirmation; no implicit CA selection is permitted.",
                ),
                (
                    SSH_HOSTS_REPLACE_TOOL,
                    "Replace SSH host",
                    "Replace every mutable SSH host field and direct login mapping after an exact ownership preflight and explicit confirmation.",
                ),
                (
                    SSH_HOSTS_DELETE_TOOL,
                    "Delete SSH host",
                    "Permanently delete one exact SSH host after ownership preflight and explicit confirmation.",
                ),
                (
                    SSH_HOSTS_USER_CA_PUBLIC_KEY_GET_TOOL,
                    "Get SSH host user-CA public key",
                    "Read and verify the public key for the user CA linked to one exact SSH host.",
                ),
                (
                    SSH_HOSTS_HOST_CA_PUBLIC_KEY_GET_TOOL,
                    "Get SSH host host-CA public key",
                    "Read and verify the public key for the host CA linked to one exact SSH host.",
                ),
                (
                    SSH_HOSTS_HOST_CERTIFICATE_ISSUE_TOOL,
                    "Issue SSH host certificate",
                    "Issue one host certificate under the exact host record; the single mutation is never replayed and signer, subject, hostname principal, key ID, type, authorization fields, serial, and TTL are verified.",
                ),
                (
                    SSH_HOST_GROUPS_LIST_TOOL,
                    "List SSH host groups",
                    "List a bounded canonical SSH host-group inventory and reflected host counts for one exact project.",
                ),
                (
                    SSH_HOST_GROUPS_GET_TOOL,
                    "Get SSH host group",
                    "Get one exact SSH host group after proving its project ownership.",
                ),
                (
                    SSH_HOST_GROUPS_CREATE_TOOL,
                    "Create SSH host group",
                    "Create one complete bounded SSH host-group login policy after explicit confirmation.",
                ),
                (
                    SSH_HOST_GROUPS_REPLACE_TOOL,
                    "Replace SSH host group",
                    "Replace every mutable SSH host-group field and login mapping after an exact ownership preflight and explicit confirmation.",
                ),
                (
                    SSH_HOST_GROUPS_DELETE_TOOL,
                    "Delete SSH host group",
                    "Permanently delete one exact SSH host group after ownership preflight and explicit confirmation.",
                ),
                (
                    SSH_HOST_GROUP_HOSTS_LIST_TOOL,
                    "List SSH host-group hosts",
                    "List a bounded, filter-consistent set of current members or non-members for one exact SSH host group.",
                ),
                (
                    SSH_HOST_GROUP_HOSTS_ADD_TOOL,
                    "Add SSH host-group host",
                    "Add one exact host to one exact host group after project ownership preflight and explicit confirmation; return the reflected mutation receipt without a race-prone follow-up read.",
                ),
                (
                    SSH_HOST_GROUP_HOSTS_REMOVE_TOOL,
                    "Remove SSH host-group host",
                    "Remove one exact host from one exact host group after project ownership preflight and explicit confirmation; return the reflected mutation receipt without a race-prone follow-up read.",
                ),
            ],
        );
    }

    fn sorted_property_names(schema: &Map<String, Value>) -> Vec<&str> {
        let mut names = schema
            .get("properties")
            .map(|properties| {
                properties
                    .as_object()
                    .expect("schema properties")
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        names.sort_unstable();
        names
    }

    fn assert_definition_properties(
        schema: &Map<String, Value>,
        definition: &str,
        expected: &[&str],
    ) {
        assert_eq!(
            sorted_property_names(
                schema["$defs"][definition]
                    .as_object()
                    .expect("object definition"),
            ),
            expected,
            "{definition} fields drifted"
        );
    }

    fn assert_definition_property_descriptions(schema: &Map<String, Value>, definition: &str) {
        let properties = schema["$defs"][definition]["properties"]
            .as_object()
            .expect("definition properties");
        for (field, property) in properties {
            assert!(
                property["description"]
                    .as_str()
                    .is_some_and(|description| !description.is_empty()),
                "{definition}.{field} must have a schema description"
            );
        }
    }

    fn assert_catalog_schema_fields(tools: &[Tool]) {
        assert_discovery_catalog_schema_fields(&tools[..2]);
        assert_admin_catalog_schema_fields(&tools[2..11]);
        assert_folder_tag_catalog_schema_fields(&tools[11..22]);
        assert_identity_catalog_schema_fields(&tools[22..27]);
        assert_project_membership_catalog_schema_fields(&tools[27..37]);
        assert_role_catalog_schema_fields(&tools[37..41]);
        assert_group_catalog_schema_fields(&tools[41..47]);
        assert_identity_project_additional_privilege_catalog_schema_fields(&tools[47..53]);
        assert_universal_auth_catalog_schema_fields(&tools[53..62]);
        assert_token_auth_catalog_schema_fields(&tools[62..71]);
        assert_kubernetes_auth_catalog_schema_fields(&tools[71..75]);
        assert_secret_catalog_schema_fields(&tools[75..83]);
        assert_secret_import_catalog_schema_fields(&tools[83..88]);
        assert_audit_log_catalog_schema_fields(&tools[88..89]);
        assert_app_automation_catalog_schema_fields(&tools[89..103]);
        assert_sql_secret_rotation_catalog_schema_fields(&tools[103..112]);
        assert_certificate_authority_catalog_schema_fields(&tools[112..127]);
        assert_certificate_catalog_schema_fields(&tools[127..138]);
        assert_certificate_request_catalog_schema_fields(&tools[138..142]);
        assert_certificate_policy_catalog_schema_fields(&tools[142..147]);
        assert_certificate_profile_catalog_schema_fields(&tools[147..156]);
        assert_ssh_certificate_authority_catalog_schema_fields(&tools[156..170]);
        assert_code_signer_catalog_schema_fields(&tools[170..193]);
        assert_kms_catalog_schema_fields(&tools[193..208]);
        assert_dynamic_secret_catalog_schema_fields(&tools[208..218]);
        assert_ssh_host_catalog_schema_fields(&tools[218..234]);
        assert_catalog_resource_fields(tools);
    }

    type ToolSchemaFields<'a> = (&'a str, &'a [&'a str], &'a [&'a str]);

    const SECRET_ROTATION_FIELDS: &[&str] = &[
        "activeIndex",
        "connection",
        "createdAt",
        "description",
        "environment",
        "folder",
        "id",
        "isAutoRotationEnabled",
        "isLastRotationManual",
        "lastRotatedAt",
        "lastRotationAttemptedAt",
        "name",
        "nextRotationAt",
        "projectId",
        "rotateAtUtc",
        "rotationIntervalDays",
        "rotationStatus",
        "rotationType",
        "updatedAt",
    ];

    fn assert_discovery_catalog_schema_fields(tools: &[Tool]) {
        let expected: [ToolSchemaFields<'_>; 2] = [
            (
                "projects.list",
                &["limit", "offset"][..],
                &["items", "next", "total"][..],
            ),
            ("projects.get", &["projectId"][..], &["project"][..]),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_admin_catalog_schema_fields(tools: &[Tool]) {
        let project_fields = &[
            "description",
            "environments",
            "id",
            "name",
            "orgId",
            "slug",
            "type",
        ][..];
        let environment_fields = &["id", "name", "slug"][..];
        let expected: [ToolSchemaFields<'_>; 9] = [
            (
                "projects.create",
                &[
                    "createDefaultEnvironments",
                    "deleteProtection",
                    "description",
                    "kind",
                    "name",
                    "slug",
                ][..],
                project_fields,
            ),
            (
                "projects.update",
                &["change", "projectId"][..],
                project_fields,
            ),
            (
                "projects.delete",
                &["confirm", "projectId"][..],
                project_fields,
            ),
            (
                "environments.list",
                &["limit", "offset", "projectId"][..],
                &["environments", "projectId"][..],
            ),
            (
                "environments.get",
                &["environmentId", "projectId"][..],
                environment_fields,
            ),
            (
                "environments.create",
                &["name", "position", "projectId", "slug"][..],
                environment_fields,
            ),
            (
                "environments.update",
                &["change", "target"][..],
                environment_fields,
            ),
            (
                "environments.delete",
                &["confirm", "target"][..],
                environment_fields,
            ),
            (
                "environments.restore",
                &["environmentId", "projectId"][..],
                environment_fields,
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_folder_tag_catalog_schema_fields(tools: &[Tool]) {
        let folder_fields = &[
            "description",
            "envId",
            "environment",
            "id",
            "isReserved",
            "name",
            "parentId",
            "path",
            "projectId",
            "relativePath",
        ][..];
        let tag_fields = &["color", "id", "name", "projectId", "slug"][..];
        let expected: [ToolSchemaFields<'_>; 11] = [
            (
                "folders.list",
                &[
                    "environment",
                    "limit",
                    "offset",
                    "path",
                    "projectId",
                    "recursive",
                ][..],
                &["items", "next", "total"][..],
            ),
            ("folders.get", &["folderId"][..], folder_fields),
            (
                "folders.create",
                &["description", "name", "parent"][..],
                folder_fields,
            ),
            (
                "folders.update",
                &["description", "name", "target"][..],
                folder_fields,
            ),
            (
                "folders.batch.update",
                &["folders", "projectId"][..],
                &["folders"][..],
            ),
            (
                "folders.delete",
                &["confirm", "forceDelete", "target"][..],
                folder_fields,
            ),
            (
                "tags.list",
                &["limit", "offset", "projectId"][..],
                &["items", "next", "total"][..],
            ),
            ("tags.get", &["projectId", "selector"][..], tag_fields),
            (
                "tags.create",
                &["color", "projectId", "slug"][..],
                tag_fields,
            ),
            ("tags.update", &["color", "slug", "target"][..], tag_fields),
            ("tags.delete", &["confirm", "target"][..], tag_fields),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_secret_catalog_schema_fields(tools: &[Tool]) {
        let expected: [ToolSchemaFields<'_>; 8] = [
            (
                "secrets.metadata.list",
                &[
                    "environment",
                    "limit",
                    "offset",
                    "path",
                    "projectId",
                    "recursive",
                ][..],
                &["items", "next", "total"][..],
            ),
            (
                "secrets.reveal",
                &["delivery", "target"][..],
                &[
                    "environment",
                    "id",
                    "name",
                    "secretFile",
                    "secretPath",
                    "secretValue",
                    "type",
                    "version",
                ][..],
            ),
            (
                "secrets.create",
                &["secretValue", "secretValueFile", "target"][..],
                &[][..],
            ),
            (
                "secrets.update",
                &["secretValue", "secretValueFile", "target"][..],
                &[][..],
            ),
            ("secrets.delete", &["confirm", "target"][..], &[][..]),
            ("secrets.batch.create", &["scope", "secrets"][..], &[][..]),
            ("secrets.batch.update", &["scope", "secrets"][..], &[][..]),
            (
                "secrets.batch.delete",
                &["confirm", "names", "scope"][..],
                &[][..],
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_identity_catalog_schema_fields(tools: &[Tool]) {
        let identity_fields = &[
            "authMethods",
            "hasDeleteProtection",
            "id",
            "name",
            "organizationId",
            "organizationMembershipId",
            "organizationRole",
            "organizationRoleId",
            "projectId",
        ][..];
        let expected: [ToolSchemaFields<'_>; 5] = [
            (
                "identities.list",
                &["limit", "offset", "organizationId"][..],
                &["items", "next", "total"][..],
            ),
            ("identities.get", &["identityId"][..], identity_fields),
            (
                "identities.create",
                &["deleteProtection", "name", "organizationId", "role"][..],
                identity_fields,
            ),
            (
                "identities.update",
                &["change", "identityId"][..],
                identity_fields,
            ),
            (
                "identities.delete",
                &["confirm", "identityId"][..],
                identity_fields,
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_project_membership_catalog_schema_fields(tools: &[Tool]) {
        let user_membership_fields =
            &["createdAt", "id", "projectId", "roles", "user", "userId"][..];
        let identity_membership_fields = &[
            "createdAt",
            "id",
            "identity",
            "identityId",
            "projectId",
            "roles",
            "updatedAt",
        ][..];
        let receipt_fields = &["membershipId", "principalId", "projectId"][..];
        let expected: [ToolSchemaFields<'_>; 10] = [
            (
                "projectUserMemberships.list",
                &["limit", "offset", "projectId"][..],
                &["items", "next", "total"][..],
            ),
            (
                "projectUserMemberships.get",
                &["membershipId", "projectId"][..],
                user_membership_fields,
            ),
            (
                "projectUserMemberships.invite",
                &["emails", "projectId", "roles", "usernames"][..],
                &["memberships"][..],
            ),
            (
                "projectUserMemberships.update",
                &[
                    "confirmReplaceAllRoles",
                    "membershipId",
                    "projectId",
                    "roles",
                ][..],
                &["roles"][..],
            ),
            (
                "projectUserMemberships.delete",
                &["confirm", "membershipId", "projectId"][..],
                receipt_fields,
            ),
            (
                "projectIdentityMemberships.list",
                &["limit", "offset", "projectId"][..],
                &["items", "next", "total"][..],
            ),
            (
                "projectIdentityMemberships.get",
                &["identityId", "projectId"][..],
                identity_membership_fields,
            ),
            (
                "projectIdentityMemberships.create",
                &["identityId", "projectId", "roles"][..],
                receipt_fields,
            ),
            (
                "projectIdentityMemberships.update",
                &["confirmReplaceAllRoles", "identityId", "projectId", "roles"][..],
                receipt_fields,
            ),
            (
                "projectIdentityMemberships.delete",
                &["confirm", "identityId", "projectId"][..],
                receipt_fields,
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_role_catalog_schema_fields(tools: &[Tool]) {
        let role_fields = &[
            "builtIn",
            "description",
            "name",
            "permissions",
            "scope",
            "scopeId",
            "slug",
        ][..];
        let expected: [ToolSchemaFields<'_>; 4] = [
            (
                "projectRoles.list",
                &["limit", "offset", "projectId"][..],
                &["items", "next", "total"][..],
            ),
            (
                "projectRoles.get",
                &["projectId", "roleSlug"][..],
                role_fields,
            ),
            (
                "organizationRoles.list",
                &["limit", "offset"][..],
                &["items", "next", "total"][..],
            ),
            ("organizationRoles.get", &["roleSlug"][..], role_fields),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_group_catalog_schema_fields(tools: &[Tool]) {
        let group_fields = &[
            "createdAt",
            "customRoleSlug",
            "id",
            "name",
            "orgId",
            "role",
            "roleId",
            "slug",
            "updatedAt",
        ][..];
        let membership_fields = &[
            "createdAt",
            "group",
            "groupId",
            "id",
            "projectId",
            "roles",
            "updatedAt",
        ][..];
        let expected: [ToolSchemaFields<'_>; 6] = [
            (
                "groups.list",
                &["limit", "offset"][..],
                &["items", "next", "total"][..],
            ),
            ("groups.get", &["groupId"][..], group_fields),
            (
                "groups.members.list",
                &["groupId", "limit", "memberType", "offset"][..],
                &["items", "next", "total"][..],
            ),
            (
                "groups.projects.list",
                &["assignment", "groupId", "limit", "offset"][..],
                &["items", "next", "total"][..],
            ),
            (
                "projectGroupMemberships.list",
                &["limit", "offset", "projectId"][..],
                &["items", "next", "total"][..],
            ),
            (
                "projectGroupMemberships.get",
                &["groupId", "projectId"][..],
                membership_fields,
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_identity_project_additional_privilege_catalog_schema_fields(tools: &[Tool]) {
        let exact_fields = &[
            "createdAt",
            "id",
            "identityId",
            "isTemporary",
            "permissions",
            "projectId",
            "slug",
            "temporaryAccessEndTime",
            "temporaryAccessStartTime",
            "temporaryMode",
            "temporaryRange",
            "updatedAt",
        ][..];
        let expected: [ToolSchemaFields<'_>; 6] = [
            (
                "identityProjectAdditionalPrivileges.list",
                &["identityId", "limit", "offset", "projectId"][..],
                &["items", "next", "total"][..],
            ),
            (
                "identityProjectAdditionalPrivileges.get",
                &["identityId", "privilegeId", "projectId"][..],
                exact_fields,
            ),
            (
                "identityProjectAdditionalPrivileges.getBySlug",
                &["identityId", "privilegeSlug", "projectId", "projectSlug"][..],
                exact_fields,
            ),
            (
                "identityProjectAdditionalPrivileges.create",
                &[
                    "confirmDenyPermissions",
                    "identityId",
                    "lifetime",
                    "permissions",
                    "projectId",
                    "slug",
                ][..],
                exact_fields,
            ),
            (
                "identityProjectAdditionalPrivileges.update",
                &[
                    "confirmReplacePermissions",
                    "identityId",
                    "lifetime",
                    "permissions",
                    "privilegeId",
                    "projectId",
                    "slug",
                ][..],
                exact_fields,
            ),
            (
                "identityProjectAdditionalPrivileges.delete",
                &["confirmDelete", "identityId", "privilegeId", "projectId"][..],
                exact_fields,
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_universal_auth_catalog_schema_fields(tools: &[Tool]) {
        let config_fields = &[
            "accessTokenMaxTTL",
            "accessTokenNumUsesLimit",
            "accessTokenPeriod",
            "accessTokenTTL",
            "accessTokenTrustedIps",
            "clientId",
            "clientSecretTrustedIps",
            "id",
            "identityId",
            "lockoutCounterResetSeconds",
            "lockoutDurationSeconds",
            "lockoutEnabled",
            "lockoutThreshold",
        ][..];
        let client_secret_fields = &[
            "clientSecretNumUses",
            "clientSecretNumUsesLimit",
            "clientSecretPrefix",
            "clientSecretTTL",
            "createdAt",
            "description",
            "id",
            "identityUAId",
            "isClientSecretRevoked",
            "updatedAt",
        ][..];
        let expected: [ToolSchemaFields<'_>; 9] = [
            (
                "identityUniversalAuth.get",
                &["identityId"][..],
                config_fields,
            ),
            (
                "identityUniversalAuth.attach",
                &[
                    "accessTokenMaxTTL",
                    "accessTokenNumUsesLimit",
                    "accessTokenPeriod",
                    "accessTokenTTL",
                    "identityId",
                    "lockoutCounterResetSeconds",
                    "lockoutDurationSeconds",
                    "lockoutEnabled",
                    "lockoutThreshold",
                ][..],
                config_fields,
            ),
            (
                "identityUniversalAuth.update",
                &["change", "identityId"][..],
                config_fields,
            ),
            (
                "identityUniversalAuth.remove",
                &["confirm", "identityId"][..],
                config_fields,
            ),
            (
                "identityUniversalAuth.clientSecrets.list",
                &["identityId", "limit", "offset"][..],
                &["items", "next", "total"][..],
            ),
            (
                "identityUniversalAuth.clientSecrets.get",
                &["clientSecretId", "identityId"][..],
                client_secret_fields,
            ),
            (
                "identityUniversalAuth.clientSecrets.create",
                &[
                    "delivery",
                    "description",
                    "identityId",
                    "numUsesLimit",
                    "ttl",
                ][..],
                &["clientSecret", "metadata", "secretFile"][..],
            ),
            (
                "identityUniversalAuth.clientSecrets.revoke",
                &["clientSecretId", "confirm", "identityId"][..],
                client_secret_fields,
            ),
            (
                "identityUniversalAuth.lockouts.clear",
                &["confirm", "identityId"][..],
                &["deleted"][..],
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_token_auth_catalog_schema_fields(tools: &[Tool]) {
        let config_fields = &[
            "accessTokenMaxTTL",
            "accessTokenNumUsesLimit",
            "accessTokenPeriod",
            "accessTokenTTL",
            "accessTokenTrustedIps",
            "createdAt",
            "id",
            "identityId",
            "updatedAt",
        ][..];
        let token_fields = &[
            "accessTokenLastRenewedAt",
            "accessTokenLastUsedAt",
            "accessTokenMaxTTL",
            "accessTokenNumUses",
            "accessTokenNumUsesLimit",
            "accessTokenPeriod",
            "accessTokenTTL",
            "authMethod",
            "createdAt",
            "id",
            "identityId",
            "isAccessTokenRevoked",
            "name",
            "subOrganizationId",
            "updatedAt",
        ][..];
        let expected: [ToolSchemaFields<'_>; 9] = [
            ("identityTokenAuth.get", &["identityId"][..], config_fields),
            (
                "identityTokenAuth.attach",
                &[
                    "accessTokenMaxTTL",
                    "accessTokenNumUsesLimit",
                    "accessTokenTTL",
                    "identityId",
                ][..],
                config_fields,
            ),
            (
                "identityTokenAuth.update",
                &["change", "identityId"][..],
                config_fields,
            ),
            (
                "identityTokenAuth.remove",
                &["confirm", "identityId"][..],
                config_fields,
            ),
            (
                "identityTokenAuth.tokens.list",
                &["identityId", "limit", "offset"][..],
                &["items", "next", "total"][..],
            ),
            (
                "identityTokenAuth.tokens.get",
                &["tokenId"][..],
                token_fields,
            ),
            (
                "identityTokenAuth.tokens.create",
                &["delivery", "identityId", "name", "organizationSlug"][..],
                &[
                    "accessToken",
                    "accessTokenMaxTTL",
                    "expiresIn",
                    "metadata",
                    "secretFile",
                ][..],
            ),
            (
                "identityTokenAuth.tokens.update",
                &["name", "tokenId"][..],
                token_fields,
            ),
            (
                "identityTokenAuth.tokens.revoke",
                &["confirm", "tokenId"][..],
                &["message"][..],
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_kubernetes_auth_catalog_schema_fields(tools: &[Tool]) {
        let config_fields = &[
            "accessTokenMaxTTL",
            "accessTokenNumUsesLimit",
            "accessTokenTTL",
            "accessTokenTrustedIps",
            "allowedAudience",
            "allowedNames",
            "allowedNamespaces",
            "caCertificateConfigured",
            "createdAt",
            "gatewayId",
            "gatewayPoolId",
            "id",
            "identityId",
            "kubernetesHost",
            "tokenReviewMode",
            "tokenReviewerJwtConfigured",
            "updatedAt",
            "verifyTlsCertificate",
        ][..];
        let expected: [ToolSchemaFields<'_>; 4] = [
            (
                "identityKubernetesAuth.get",
                &["identityId"][..],
                config_fields,
            ),
            (
                "identityKubernetesAuth.attach",
                &[
                    "accessTokenMaxTTL",
                    "accessTokenNumUsesLimit",
                    "accessTokenTTL",
                    "allowedAudience",
                    "allowedNames",
                    "allowedNamespaces",
                    "caCert",
                    "identityId",
                    "kubernetesHost",
                    "tokenReviewerJwt",
                    "verifyTlsCertificate",
                ][..],
                config_fields,
            ),
            (
                "identityKubernetesAuth.update",
                &["change", "identityId"][..],
                config_fields,
            ),
            (
                "identityKubernetesAuth.remove",
                &["confirm", "identityId"][..],
                config_fields,
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_secret_import_catalog_schema_fields(tools: &[Tool]) {
        let expected = [
            (
                "secretImports.list",
                &["limit", "offset", "target"][..],
                &["items", "next", "total"][..],
            ),
            (
                "secretImports.get",
                &["secretImportId"][..],
                &[
                    "createdAt",
                    "folderId",
                    "id",
                    "isReplication",
                    "isReplicationSuccess",
                    "isReserved",
                    "lastReplicated",
                    "position",
                    "source",
                    "target",
                    "updatedAt",
                    "version",
                ][..],
            ),
            (
                "secretImports.create",
                &["source", "target"][..],
                &[
                    "createdAt",
                    "folderId",
                    "id",
                    "isReplication",
                    "isReplicationSuccess",
                    "isReserved",
                    "lastReplicated",
                    "position",
                    "source",
                    "target",
                    "updatedAt",
                    "version",
                ][..],
            ),
            (
                "secretImports.update",
                &["change", "secretImportId", "target"][..],
                &[
                    "createdAt",
                    "folderId",
                    "id",
                    "isReplication",
                    "isReplicationSuccess",
                    "isReserved",
                    "lastReplicated",
                    "position",
                    "source",
                    "target",
                    "updatedAt",
                    "version",
                ][..],
            ),
            (
                "secretImports.delete",
                &["confirm", "secretImportId", "target"][..],
                &[
                    "createdAt",
                    "folderId",
                    "id",
                    "isReplication",
                    "isReplicationSuccess",
                    "isReserved",
                    "lastReplicated",
                    "position",
                    "source",
                    "target",
                    "updatedAt",
                    "version",
                ][..],
            ),
        ];

        assert_schema_field_table(tools, &expected);
    }

    fn assert_audit_log_catalog_schema_fields(tools: &[Tool]) {
        let expected = [(
            "auditLogs.list",
            &[
                "actorType",
                "environment",
                "eventTypes",
                "limit",
                "offset",
                "projectId",
                "secretKey",
                "secretPath",
                "timeRange",
                "userAgentType",
            ][..],
            &["items", "next", "total"][..],
        )];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_app_automation_catalog_schema_fields(tools: &[Tool]) {
        assert_app_connection_catalog_schema_fields(&tools[..6]);
        assert_secret_sync_catalog_schema_fields(&tools[6..]);
    }

    fn assert_app_connection_catalog_schema_fields(tools: &[Tool]) {
        let inventory_and_connection = [
            (
                "appConnections.list",
                &["limit", "offset", "projectId"][..],
                &["items", "next", "total"][..],
            ),
            (
                "appConnections.github.get",
                &["connectionId"][..],
                &["connection", "instance", "method"][..],
            ),
            (
                "appConnections.github.create",
                &["description", "name", "projectId", "provider"][..],
                &["connection", "instance", "method"][..],
            ),
            (
                "appConnections.github.update",
                &[
                    "confirmCredentialReplacement",
                    "connectionId",
                    "credentials",
                    "description",
                    "name",
                    "route",
                ][..],
                &["connection", "instance", "method"][..],
            ),
            (
                "appConnections.github.rotateCredentials",
                &["confirm", "connectionId"][..],
                &["connection", "instance", "method"][..],
            ),
            (
                "appConnections.github.delete",
                &["confirmDelete", "connectionId"][..],
                &["connection", "instance", "method"][..],
            ),
        ];
        assert_schema_field_table(tools, &inventory_and_connection);
    }

    fn assert_secret_sync_catalog_schema_fields(tools: &[Tool]) {
        let sync_and_rotation = [
            (
                "secretSyncs.list",
                &["limit", "offset", "projectId"][..],
                &["items", "next", "total"][..],
            ),
            (
                "secretSyncs.github.get",
                &["projectId", "syncId"][..],
                &["destination", "options", "sync"][..],
            ),
            (
                "secretSyncs.github.create",
                &[
                    "config",
                    "confirmInitialOverwrite",
                    "connectionId",
                    "description",
                    "environment",
                    "isAutoSyncEnabled",
                    "name",
                    "projectId",
                    "secretPath",
                ][..],
                &["destination", "options", "sync"][..],
            ),
            (
                "secretSyncs.github.update",
                &[
                    "config",
                    "confirmUpdate",
                    "connectionId",
                    "description",
                    "environment",
                    "isAutoSyncEnabled",
                    "name",
                    "projectId",
                    "secretPath",
                    "syncId",
                ][..],
                &["destination", "options", "sync"][..],
            ),
            (
                "secretSyncs.github.delete",
                &[
                    "confirmDelete",
                    "confirmRemoteRemoval",
                    "projectId",
                    "removeSecrets",
                    "syncId",
                ][..],
                &["destination", "options", "sync"][..],
            ),
            (
                "secretSyncs.github.run",
                &["confirm", "projectId", "syncId"][..],
                &["destination", "options", "sync"][..],
            ),
            (
                "secretSyncs.github.removeSecrets",
                &["confirm", "projectId", "syncId"][..],
                &["destination", "options", "sync"][..],
            ),
            (
                "secretRotations.list",
                &["limit", "offset", "projectId"][..],
                &["items", "next", "total"][..],
            ),
        ];
        assert_schema_field_table(tools, &sync_and_rotation);
    }

    #[allow(clippy::too_many_lines)]
    fn assert_sql_secret_rotation_catalog_schema_fields(tools: &[Tool]) {
        let expected = [
            (
                "secretRotations.sql.get",
                &["projectId", "provider", "rotationId"][..],
                SECRET_ROTATION_FIELDS,
            ),
            (
                "secretRotations.sql.getByName",
                &["environment", "name", "projectId", "provider", "secretPath"][..],
                SECRET_ROTATION_FIELDS,
            ),
            (
                "secretRotations.sql.create",
                &[
                    "config",
                    "confirmCreateCredentialsAndSecrets",
                    "connectionId",
                    "description",
                    "environment",
                    "isAutoRotationEnabled",
                    "name",
                    "projectId",
                    "provider",
                    "rotateAtUtc",
                    "rotationIntervalDays",
                    "secretPath",
                ][..],
                SECRET_ROTATION_FIELDS,
            ),
            (
                "secretRotations.sql.update",
                &[
                    "confirmUpdateEffects",
                    "description",
                    "isAutoRotationEnabled",
                    "name",
                    "parameters",
                    "projectId",
                    "provider",
                    "rotateAtUtc",
                    "rotationId",
                    "rotationIntervalDays",
                    "secretsMapping",
                ][..],
                SECRET_ROTATION_FIELDS,
            ),
            (
                "secretRotations.sql.delete",
                &[
                    "confirmDelete",
                    "generatedCredentials",
                    "mappedSecrets",
                    "projectId",
                    "provider",
                    "rotationId",
                ][..],
                SECRET_ROTATION_FIELDS,
            ),
            (
                "secretRotations.sql.generatedCredentials.get",
                &[
                    "confirmReveal",
                    "delivery",
                    "projectId",
                    "provider",
                    "rotationId",
                ][..],
                &[
                    "activeIndex",
                    "credentials",
                    "provider",
                    "rotationId",
                    "secretFile",
                ][..],
            ),
            (
                "secretRotations.sql.move",
                &[
                    "confirmMove",
                    "confirmOverwriteDestination",
                    "destinationEnvironment",
                    "destinationSecretPath",
                    "overwriteDestination",
                    "projectId",
                    "provider",
                    "rotationId",
                ][..],
                SECRET_ROTATION_FIELDS,
            ),
            (
                "secretRotations.sql.rotate",
                &["confirm", "projectId", "provider", "rotationId"][..],
                SECRET_ROTATION_FIELDS,
            ),
            (
                "secretRotations.sql.checkCredentials",
                &["confirm", "projectId", "provider", "rotationId"][..],
                &["valid"][..],
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_kms_catalog_schema_fields(tools: &[Tool]) {
        let key_fields = &[
            "algorithm",
            "createdAt",
            "description",
            "disabled",
            "id",
            "keyUsage",
            "name",
            "projectId",
            "updatedAt",
            "version",
        ][..];
        let expected: [ToolSchemaFields<'_>; 15] = [
            (
                "kms.keys.list",
                &["descending", "limit", "offset", "projectId", "search"][..],
                &["items", "next", "total"][..],
            ),
            ("kms.keys.get", &["keyId", "projectId"][..], key_fields),
            (
                "kms.keys.getByName",
                &["keyName", "projectId"][..],
                key_fields,
            ),
            (
                "kms.keys.create",
                &[
                    "algorithm",
                    "confirm",
                    "description",
                    "keyUsage",
                    "name",
                    "projectId",
                ][..],
                key_fields,
            ),
            (
                "kms.keys.update",
                &["confirm", "description", "disabled", "name", "target"][..],
                key_fields,
            ),
            ("kms.keys.delete", &["confirm", "target"][..], key_fields),
            (
                "kms.encrypt",
                &["confirm", "data", "target"][..],
                &["ciphertext", "keyId"][..],
            ),
            (
                "kms.decrypt",
                &["ciphertext", "confirmReveal", "delivery", "target"][..],
                &["keyId", "plaintext", "secretFile"][..],
            ),
            (
                "kms.keys.publicKey.get",
                &["keyId", "projectId"][..],
                &["keyId", "publicKey"][..],
            ),
            (
                "kms.keys.privateKey.reveal",
                &["confirmReveal", "delivery", "target"][..],
                &["keyId", "privateKey", "secretFile"][..],
            ),
            (
                "kms.keys.bulkImport",
                &["confirm", "keys", "projectId"][..],
                &["errors", "imported", "projectId"][..],
            ),
            (
                "kms.keys.privateKeys.bulkReveal",
                &["confirmReveal", "delivery", "keyIds", "projectId"][..],
                &["keys", "projectId", "secretFile"][..],
            ),
            (
                "kms.keys.signingAlgorithms.list",
                &["keyId", "projectId"][..],
                &["keyId", "signingAlgorithms"][..],
            ),
            (
                "kms.sign",
                &["confirm", "data", "isDigest", "signingAlgorithm", "target"][..],
                &["keyId", "signature", "signingAlgorithm"][..],
            ),
            (
                "kms.verify",
                &[
                    "confirm",
                    "data",
                    "isDigest",
                    "signature",
                    "signingAlgorithm",
                    "target",
                ][..],
                &["keyId", "signatureValid", "signingAlgorithm"][..],
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_certificate_policy_catalog_schema_fields(tools: &[Tool]) {
        let policy_fields = &[
            "algorithms",
            "basicConstraints",
            "createdAt",
            "description",
            "extendedKeyUsages",
            "id",
            "keyUsages",
            "name",
            "projectId",
            "sans",
            "subject",
            "updatedAt",
            "validity",
        ][..];
        let expected: [ToolSchemaFields<'_>; 5] = [
            (
                CERTIFICATE_POLICIES_LIST_TOOL,
                &["limit", "offset", "projectId", "search"][..],
                &["items", "next", "total"][..],
            ),
            (
                CERTIFICATE_POLICIES_GET_TOOL,
                &["policyId", "projectId"][..],
                policy_fields,
            ),
            (
                CERTIFICATE_POLICIES_CREATE_TOOL,
                &[
                    "algorithms",
                    "basicConstraints",
                    "confirm",
                    "description",
                    "extendedKeyUsages",
                    "keyUsages",
                    "name",
                    "projectId",
                    "sans",
                    "subject",
                    "validity",
                ][..],
                policy_fields,
            ),
            (
                CERTIFICATE_POLICIES_UPDATE_TOOL,
                &[
                    "algorithms",
                    "basicConstraints",
                    "clearBasicConstraints",
                    "confirm",
                    "description",
                    "extendedKeyUsages",
                    "keyUsages",
                    "name",
                    "sans",
                    "subject",
                    "target",
                    "validity",
                ][..],
                policy_fields,
            ),
            (
                CERTIFICATE_POLICIES_DELETE_TOOL,
                &["confirm", "target"][..],
                policy_fields,
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_certificate_catalog_schema_fields(tools: &[Tool]) {
        let certificate_fields = &[
            "alternativeNames",
            "applicationId",
            "applicationName",
            "caId",
            "caName",
            "commonName",
            "createdAt",
            "enrollmentType",
            "extendedKeyUsages",
            "friendlyName",
            "hasPrivateKey",
            "id",
            "isCa",
            "keyAlgorithm",
            "keyUsages",
            "notAfter",
            "notBefore",
            "profileId",
            "profileName",
            "projectId",
            "revocationReason",
            "revokedAt",
            "serialNumber",
            "signatureAlgorithm",
            "status",
            "updatedAt",
        ][..];
        let expected: [ToolSchemaFields<'_>; 3] = [
            (
                CERTIFICATES_LIST_TOOL,
                &[
                    "applicationIds",
                    "caIds",
                    "keyAlgorithms",
                    "limit",
                    "offset",
                    "profileIds",
                    "projectId",
                    "search",
                    "sortBy",
                    "sortOrder",
                    "status",
                ][..],
                &["items", "next", "total"][..],
            ),
            (
                CERTIFICATES_GET_TOOL,
                &["certificateId", "projectId"][..],
                certificate_fields,
            ),
            (
                CERTIFICATES_ISSUE_TOOL,
                &[
                    "applicationId",
                    "confirm",
                    "delivery",
                    "metadata",
                    "profileId",
                    "projectId",
                    "removeRootsFromChain",
                    "request",
                ][..],
                &[
                    "certificate",
                    "certificateChain",
                    "certificateId",
                    "issuingCaCertificate",
                    "outcome",
                    "privateKey",
                    "profileId",
                    "projectId",
                    "requestId",
                    "secretFile",
                    "serialNumber",
                    "status",
                ][..],
            ),
        ];
        assert_schema_field_table(&tools[..3], &expected);
        assert_certificate_lifecycle_catalog_schema_fields(&tools[3..7], certificate_fields);
        assert_certificate_material_catalog_schema_fields(&tools[7..], certificate_fields);
    }

    fn assert_certificate_material_catalog_schema_fields(
        tools: &[Tool],
        certificate_fields: &[&str],
    ) {
        let material_expected: [ToolSchemaFields<'_>; 4] = [
            (
                CERTIFICATES_IMPORT_TOOL,
                &[
                    "applicationId",
                    "certificateChainFile",
                    "certificateFile",
                    "confirm",
                    "friendlyName",
                    "pkiCollectionId",
                    "privateKeyFile",
                    "projectId",
                ][..],
                certificate_fields,
            ),
            (
                CERTIFICATES_CERTIFICATE_GET_TOOL,
                &["certificateId", "projectId"][..],
                &[
                    "certificate",
                    "certificateChain",
                    "certificateId",
                    "projectId",
                    "serialNumber",
                ][..],
            ),
            (
                CERTIFICATES_BUNDLE_REVEAL_TOOL,
                &["confirmReveal", "delivery", "target"][..],
                &[
                    "certificate",
                    "certificateChain",
                    "certificateId",
                    "privateKey",
                    "projectId",
                    "secretFile",
                    "serialNumber",
                ][..],
            ),
            (
                CERTIFICATES_PRIVATE_KEY_REVEAL_TOOL,
                &["confirmReveal", "delivery", "target"][..],
                &[
                    "certificateId",
                    "privateKey",
                    "projectId",
                    "secretFile",
                    "serialNumber",
                ][..],
            ),
        ];
        assert_schema_field_table(tools, &material_expected);
    }

    fn assert_certificate_lifecycle_catalog_schema_fields(
        tools: &[Tool],
        certificate_fields: &[&str],
    ) {
        let expected: [ToolSchemaFields<'_>; 4] = [
            (
                CERTIFICATES_RENEW_TOOL,
                &["confirm", "delivery", "removeRootsFromChain", "target"][..],
                &[
                    "certificate",
                    "certificateChain",
                    "certificateId",
                    "issuingCaCertificate",
                    "previousCertificateId",
                    "privateKey",
                    "projectId",
                    "requestId",
                    "secretFile",
                    "serialNumber",
                ][..],
            ),
            (
                CERTIFICATES_REVOKE_TOOL,
                &["confirm", "reason", "target"][..],
                &[
                    "certificateId",
                    "projectId",
                    "reason",
                    "revokedAt",
                    "serialNumber",
                ][..],
            ),
            (
                CERTIFICATES_RENEWAL_CONFIGURATION_UPDATE_TOOL,
                &["change", "target"][..],
                &["certificateId", "enabled", "projectId", "renewBeforeDays"][..],
            ),
            (
                CERTIFICATES_DELETE_TOOL,
                &["confirm", "target"][..],
                certificate_fields,
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_certificate_request_catalog_schema_fields(tools: &[Tool]) {
        let request_fields = &[
            "alternativeNames",
            "approvalRequestId",
            "caId",
            "certificate",
            "certificateId",
            "commonName",
            "createdAt",
            "id",
            "profileId",
            "profileName",
            "projectId",
            "status",
            "updatedAt",
        ][..];
        let expected: [ToolSchemaFields<'_>; 4] = [
            (
                CERTIFICATE_REQUESTS_LIST_TOOL,
                &[
                    "fromDate",
                    "limit",
                    "offset",
                    "profileIds",
                    "projectId",
                    "search",
                    "sortBy",
                    "sortOrder",
                    "status",
                    "toDate",
                ][..],
                &["items", "next", "total"][..],
            ),
            (
                CERTIFICATE_REQUESTS_GET_TOOL,
                &["projectId", "requestId"][..],
                request_fields,
            ),
            (
                CERTIFICATE_REQUEST_RESULT_REVEAL_TOOL,
                &["confirmReveal", "delivery", "target"][..],
                &[
                    "certificate",
                    "certificateId",
                    "privateKey",
                    "projectId",
                    "requestId",
                    "secretFile",
                    "serialNumber",
                ][..],
            ),
            (
                CERTIFICATE_REQUESTS_CANCEL_TOOL,
                &["confirm", "target"][..],
                &["cancelled", "projectId", "requestId", "status"][..],
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_certificate_profile_catalog_schema_fields(tools: &[Tool]) {
        let profile_fields = &[
            "caId",
            "certificateAuthority",
            "certificatePolicy",
            "certificatePolicyId",
            "createdAt",
            "defaults",
            "description",
            "enrollment",
            "enrollmentType",
            "externalConfigs",
            "id",
            "issuerType",
            "metrics",
            "projectId",
            "slug",
            "updatedAt",
        ][..];
        let expected: [ToolSchemaFields<'_>; 9] = [
            (
                CERTIFICATE_PROFILES_LIST_TOOL,
                &[
                    "applicationId",
                    "caId",
                    "enrollmentType",
                    "issuerType",
                    "limit",
                    "offset",
                    "projectId",
                    "search",
                ][..],
                &["items", "next", "total"][..],
            ),
            (
                CERTIFICATE_PROFILES_GET_TOOL,
                &["profileId", "projectId"][..],
                profile_fields,
            ),
            (
                CERTIFICATE_PROFILES_GET_BY_SLUG_TOOL,
                &["projectId", "slug"][..],
                profile_fields,
            ),
            (
                CERTIFICATE_PROFILES_CREATE_TOOL,
                &[
                    "certificatePolicyId",
                    "confirm",
                    "defaults",
                    "description",
                    "enrollment",
                    "externalConfig",
                    "issuer",
                    "projectId",
                    "slug",
                ][..],
                profile_fields,
            ),
            (
                CERTIFICATE_PROFILES_UPDATE_TOOL,
                &[
                    "clearDefaults",
                    "clearDescription",
                    "clearExternalConfig",
                    "confirm",
                    "defaults",
                    "description",
                    "enrollment",
                    "externalConfig",
                    "slug",
                    "target",
                ][..],
                profile_fields,
            ),
            (
                CERTIFICATE_PROFILES_DELETE_TOOL,
                &["confirm", "target"][..],
                profile_fields,
            ),
            (
                CERTIFICATE_PROFILE_CERTIFICATES_LIST_TOOL,
                &["limit", "offset", "search", "status", "target"][..],
                &["items", "next", "total"][..],
            ),
            (
                CERTIFICATE_PROFILE_LATEST_BUNDLE_REVEAL_TOOL,
                &["confirmReveal", "delivery", "target"][..],
                &["bundle"][..],
            ),
            (
                CERTIFICATE_PROFILE_EAB_SECRET_REVEAL_TOOL,
                &["confirmReveal", "delivery", "target"][..],
                &["eabKid", "eabSecret", "profileId", "secretFile"][..],
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    #[allow(clippy::too_many_lines)]
    fn assert_ssh_certificate_authority_catalog_schema_fields(tools: &[Tool]) {
        let authority_fields = &[
            "friendlyName",
            "id",
            "keyAlgorithm",
            "keySource",
            "projectId",
            "publicKey",
            "status",
        ][..];
        let template_fields = &[
            "allowCustomKeyIds",
            "allowHostCertificates",
            "allowUserCertificates",
            "allowedHosts",
            "allowedUsers",
            "id",
            "maxTTL",
            "name",
            "projectId",
            "sshCaId",
            "status",
            "ttl",
        ][..];
        let expected: [ToolSchemaFields<'_>; 14] = [
            (
                SSH_CERTIFICATE_AUTHORITIES_LIST_TOOL,
                &["projectId"][..],
                &["certificateAuthorities"][..],
            ),
            (
                SSH_CERTIFICATE_AUTHORITIES_GET_TOOL,
                &["projectId", "sshCaId"][..],
                authority_fields,
            ),
            (
                SSH_CERTIFICATE_AUTHORITIES_PUBLIC_KEY_GET_TOOL,
                &["projectId", "sshCaId"][..],
                &["publicKey", "sshCaId"][..],
            ),
            (
                SSH_CERTIFICATE_AUTHORITIES_CREATE_TOOL,
                &["confirm", "friendlyName", "keyMaterial", "projectId"][..],
                authority_fields,
            ),
            (
                SSH_CERTIFICATE_AUTHORITIES_REPLACE_TOOL,
                &["confirm", "friendlyName", "status", "target"][..],
                authority_fields,
            ),
            (
                SSH_CERTIFICATE_AUTHORITIES_DELETE_TOOL,
                &["confirm", "target"][..],
                &[
                    "friendlyName",
                    "id",
                    "keyAlgorithm",
                    "keySource",
                    "projectId",
                    "status",
                ][..],
            ),
            (
                SSH_CERTIFICATE_TEMPLATES_LIST_TOOL,
                &["projectId"][..],
                &["certificateTemplates"][..],
            ),
            (
                SSH_CERTIFICATE_AUTHORITY_TEMPLATES_LIST_TOOL,
                &["projectId", "sshCaId"][..],
                &["certificateTemplates"][..],
            ),
            (
                SSH_CERTIFICATE_TEMPLATES_GET_TOOL,
                &["certificateTemplateId", "target"][..],
                template_fields,
            ),
            (
                SSH_CERTIFICATE_TEMPLATES_CREATE_TOOL,
                &["confirm", "policy", "target"][..],
                template_fields,
            ),
            (
                SSH_CERTIFICATE_TEMPLATES_REPLACE_TOOL,
                &["confirm", "policy", "status", "target"][..],
                template_fields,
            ),
            (
                SSH_CERTIFICATE_TEMPLATES_DELETE_TOOL,
                &["confirm", "target"][..],
                template_fields,
            ),
            (
                SSH_CERTIFICATES_SIGN_TOOL,
                &["certificate", "confirm", "publicKey", "target"][..],
                &["serialNumber", "signedKey"][..],
            ),
            (
                SSH_CERTIFICATES_ISSUE_TOOL,
                &[
                    "certificate",
                    "confirmReveal",
                    "delivery",
                    "keyAlgorithm",
                    "target",
                ][..],
                &[
                    "keyAlgorithm",
                    "privateKey",
                    "publicKey",
                    "secretFile",
                    "serialNumber",
                    "signedKey",
                ][..],
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    #[allow(clippy::too_many_lines)]
    fn assert_code_signer_catalog_schema_fields(tools: &[Tool]) {
        let signer_fields = &[
            "approvalPolicyId",
            "approvalPolicyName",
            "caId",
            "certificateCaId",
            "certificateCommonName",
            "certificateFailureReason",
            "certificateId",
            "certificateKeyAlgorithm",
            "certificateNotAfter",
            "certificateNotBefore",
            "certificateRenewBeforeDays",
            "certificateSerialNumber",
            "certificateStatus",
            "certificateTtlDays",
            "commonName",
            "createdAt",
            "description",
            "id",
            "keyAlgorithm",
            "lastSignedAt",
            "name",
            "projectId",
            "status",
            "updatedAt",
        ][..];
        let membership_fields = &[
            "createdAt",
            "details",
            "memberId",
            "memberKind",
            "membershipId",
            "role",
            "signerId",
            "updatedAt",
        ][..];
        let approval_request_fields = &[
            "createdAt",
            "currentStep",
            "expiresAt",
            "grantStatus",
            "id",
            "justification",
            "maxSignings",
            "policyId",
            "requesterEmail",
            "requesterId",
            "requesterKind",
            "requesterName",
            "signerId",
            "status",
            "updatedAt",
            "usedSignings",
            "windowEnd",
            "windowStart",
        ][..];
        let expected: [ToolSchemaFields<'_>; 23] = [
            (
                CODE_SIGNERS_LIST_TOOL,
                &["limit", "offset", "projectId", "search"][..],
                &["items", "next", "total"][..],
            ),
            (
                CODE_SIGNERS_GET_TOOL,
                &["projectId", "signerId"][..],
                signer_fields,
            ),
            (
                CODE_SIGNERS_CREATE_TOOL,
                &["confirm", "description", "name", "projectId", "source"][..],
                signer_fields,
            ),
            (
                CODE_SIGNERS_UPDATE_TOOL,
                &[
                    "certificateRenewBeforeDays",
                    "clearCertificateRenewBeforeDays",
                    "clearDescription",
                    "confirm",
                    "description",
                    "name",
                    "target",
                ][..],
                signer_fields,
            ),
            (
                CODE_SIGNERS_DELETE_TOOL,
                &["confirm", "target"][..],
                signer_fields,
            ),
            (
                CODE_SIGNERS_STATUS_UPDATE_TOOL,
                &["confirm", "status", "target"][..],
                signer_fields,
            ),
            (
                CODE_SIGNERS_CERTIFICATE_REISSUE_TOOL,
                &[
                    "caId",
                    "certificateTtlDays",
                    "commonName",
                    "confirm",
                    "target",
                ][..],
                signer_fields,
            ),
            (
                CODE_SIGNERS_CERTIFICATE_EXPORT_TOOL,
                &["projectId", "signerId"][..],
                &["certificatePem", "serialNumber", "signerId", "signerName"][..],
            ),
            (
                CODE_SIGNERS_PUBLIC_KEY_GET_TOOL,
                &["projectId", "signerId"][..],
                &["algorithm", "publicKey", "signerId", "signerName"][..],
            ),
            (
                CODE_SIGNERS_SIGN_TOOL,
                &[
                    "clientMetadata",
                    "confirm",
                    "data",
                    "isDigest",
                    "signingAlgorithm",
                    "target",
                ][..],
                &["signature", "signerId", "signingAlgorithm"][..],
            ),
            (
                CODE_SIGNER_MEMBERS_LIST_TOOL,
                &["memberKind", "target"][..],
                &["memberships"][..],
            ),
            (
                CODE_SIGNER_MEMBERS_ADD_TOOL,
                &["confirm", "memberId", "memberKind", "role", "target"][..],
                membership_fields,
            ),
            (
                CODE_SIGNER_MEMBER_ROLE_UPDATE_TOOL,
                &["confirm", "memberId", "memberKind", "role", "target"][..],
                membership_fields,
            ),
            (
                CODE_SIGNER_MEMBERS_REMOVE_TOOL,
                &["confirm", "memberId", "memberKind", "target"][..],
                &["memberId", "memberKind", "membershipId", "signerId"][..],
            ),
            (
                CODE_SIGNER_EFFECTIVE_MEMBERS_LIST_TOOL,
                &["memberKind", "target"][..],
                &["members"][..],
            ),
            (
                CODE_SIGNER_PERMISSIONS_GET_TOOL,
                &["projectId", "signerId"][..],
                &["memberships", "rules", "signerId"][..],
            ),
            (
                CODE_SIGNER_APPROVAL_POLICY_GET_TOOL,
                &["projectId", "signerId"][..],
                &["constraints", "id", "signerId", "steps"][..],
            ),
            (
                CODE_SIGNER_APPROVAL_POLICY_REPLACE_TOOL,
                &[
                    "confirm",
                    "maxSignings",
                    "maxWindowDuration",
                    "steps",
                    "target",
                ][..],
                &["constraints", "id", "signerId", "steps"][..],
            ),
            (
                CODE_SIGNER_APPROVAL_REQUESTS_LIST_TOOL,
                &["limit", "offset", "statuses", "target"][..],
                &["items", "next", "total"][..],
            ),
            (
                CODE_SIGNER_APPROVAL_REQUESTS_CREATE_TOOL,
                &[
                    "confirm",
                    "justification",
                    "requestedSignings",
                    "requestedWindowEnd",
                    "requestedWindowStart",
                    "target",
                ][..],
                approval_request_fields,
            ),
            (
                CODE_SIGNER_APPROVAL_REQUESTS_PRE_APPROVE_TOOL,
                &[
                    "confirm",
                    "granteeId",
                    "granteeKind",
                    "justification",
                    "requestedSignings",
                    "requestedWindowEnd",
                    "requestedWindowStart",
                    "target",
                ][..],
                &["grant", "request"][..],
            ),
            (
                CODE_SIGNER_APPROVAL_REQUESTS_REVOKE_TOOL,
                &["confirm", "requestId", "target"][..],
                &["requestId", "signerId"][..],
            ),
            (
                CODE_SIGNER_OPERATIONS_LIST_TOOL,
                &["limit", "offset", "status", "target"][..],
                &["items", "next", "total"][..],
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_certificate_authority_catalog_schema_fields(tools: &[Tool]) {
        assert_certificate_authority_lifecycle_schema_fields(&tools[..6]);
        assert_certificate_authority_certificate_schema_fields(&tools[6..]);
    }

    fn assert_certificate_authority_lifecycle_schema_fields(tools: &[Tool]) {
        let internal_fields = &[
            "configuration",
            "enableDirectIssuance",
            "id",
            "name",
            "projectId",
            "status",
        ][..];
        let expected: [ToolSchemaFields<'_>; 6] = [
            (
                "certificateAuthorities.list",
                &["projectId"][..],
                &["certificateAuthorities"][..],
            ),
            (
                "certificateAuthorities.internal.list",
                &["projectId"][..],
                &["certificateAuthorities"][..],
            ),
            (
                "certificateAuthorities.internal.get",
                &["caId", "projectId"][..],
                internal_fields,
            ),
            (
                "certificateAuthorities.internal.create",
                &[
                    "confirm",
                    "crlDistributionPointUrls",
                    "disableManagedCrlDistributionPointUrl",
                    "keyAlgorithm",
                    "maxPathLength",
                    "name",
                    "notAfter",
                    "notBefore",
                    "projectId",
                    "subject",
                    "type",
                ][..],
                internal_fields,
            ),
            (
                "certificateAuthorities.internal.update",
                &[
                    "confirm",
                    "crlDistributionPointUrls",
                    "disableManagedCrlDistributionPointUrl",
                    "name",
                    "status",
                    "target",
                ][..],
                internal_fields,
            ),
            (
                "certificateAuthorities.internal.delete",
                &["confirm", "target"][..],
                internal_fields,
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_certificate_authority_certificate_schema_fields(tools: &[Tool]) {
        let certificate_fields = &[
            "certificate",
            "certificateChain",
            "certificateId",
            "maxPathLength",
            "notAfter",
            "notBefore",
            "parentCaId",
            "serialNumber",
            "version",
        ][..];
        let expected: [ToolSchemaFields<'_>; 9] = [
            (
                "certificateAuthorities.internal.csr.get",
                &["caId", "projectId"][..],
                &["csr"][..],
            ),
            (
                "certificateAuthorities.internal.certificates.list",
                &["caId", "projectId"][..],
                &["certificates"][..],
            ),
            (
                "certificateAuthorities.internal.certificate.get",
                &["caId", "projectId"][..],
                certificate_fields,
            ),
            (
                "certificateAuthorities.internal.certificateVersion.get",
                &["certificateId", "target"][..],
                certificate_fields,
            ),
            (
                "certificateAuthorities.internal.certificate.generate",
                &[
                    "confirm",
                    "maxPathLength",
                    "notAfter",
                    "notBefore",
                    "parentCaId",
                    "target",
                ][..],
                certificate_fields,
            ),
            (
                "certificateAuthorities.internal.certificate.renew",
                &["confirm", "notAfter", "target"][..],
                certificate_fields,
            ),
            (
                "certificateAuthorities.internal.intermediate.sign",
                &[
                    "confirm",
                    "csr",
                    "maxPathLength",
                    "notAfter",
                    "notBefore",
                    "target",
                ][..],
                &[
                    "certificate",
                    "certificateChain",
                    "issuingCaCertificate",
                    "serialNumber",
                ][..],
            ),
            (
                "certificateAuthorities.internal.certificate.import",
                &["certificate", "certificateChain", "confirm", "target"][..],
                &["caId", "message"][..],
            ),
            (
                "certificateAuthorities.internal.crls.list",
                &["caId", "projectId"][..],
                &["crls"][..],
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_dynamic_secret_catalog_schema_fields(tools: &[Tool]) {
        let dynamic_secret_fields = &[
            "createdAt",
            "defaultTTL",
            "folderId",
            "gatewayId",
            "gatewayPoolId",
            "gatewayV2Id",
            "id",
            "maxTTL",
            "name",
            "projectGatewayId",
            "provider",
            "status",
            "updatedAt",
            "usernameTemplate",
            "version",
        ][..];
        let lease_fields = &[
            "createdAt",
            "dynamicSecretId",
            "expiresAt",
            "externalEntityId",
            "id",
            "status",
            "updatedAt",
            "version",
        ][..];
        let expected: [ToolSchemaFields<'_>; 10] = [
            (
                "dynamicSecrets.list",
                &["limit", "offset", "scope"][..],
                &["items", "next", "total"][..],
            ),
            (
                "dynamicSecrets.get",
                &["dynamicSecretName", "scope"][..],
                dynamic_secret_fields,
            ),
            (
                "dynamicSecrets.create",
                &[
                    "defaultTtlSeconds",
                    "maxTtlSeconds",
                    "name",
                    "provider",
                    "scope",
                ][..],
                dynamic_secret_fields,
            ),
            (
                "dynamicSecrets.update",
                &["change", "target"][..],
                dynamic_secret_fields,
            ),
            (
                "dynamicSecrets.delete",
                &["confirm", "force", "target"][..],
                dynamic_secret_fields,
            ),
            (
                "dynamicSecretLeases.list",
                &["dynamicSecretName", "limit", "offset", "scope"][..],
                &["items", "next", "total"][..],
            ),
            (
                "dynamicSecretLeases.get",
                &["leaseId", "scope"][..],
                &["dynamicSecret", "lease"][..],
            ),
            (
                "dynamicSecretLeases.create",
                &["delivery", "provider", "target", "ttlSeconds"][..],
                &[
                    "dynamicSecret",
                    "lease",
                    "password",
                    "provider",
                    "secretFile",
                    "username",
                ][..],
            ),
            (
                "dynamicSecretLeases.renew",
                &["leaseId", "scope", "ttlSeconds"][..],
                lease_fields,
            ),
            (
                "dynamicSecretLeases.revoke",
                &["confirm", "force", "leaseId", "scope"][..],
                lease_fields,
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    #[allow(clippy::too_many_lines)]
    fn assert_ssh_host_catalog_schema_fields(tools: &[Tool]) {
        let host_fields = &[
            "alias",
            "hostCertTtl",
            "hostSshCaId",
            "hostname",
            "id",
            "loginMappings",
            "projectId",
            "userCertTtl",
            "userSshCaId",
        ][..];
        let group_fields = &["hostCount", "id", "loginMappings", "name", "projectId"][..];
        let expected: [ToolSchemaFields<'_>; 16] = [
            (SSH_HOSTS_LIST_TOOL, &["projectId"][..], &["hosts"][..]),
            (
                SSH_HOSTS_GET_TOOL,
                &["projectId", "sshHostId"][..],
                host_fields,
            ),
            (
                SSH_HOSTS_CREATE_TOOL,
                &[
                    "confirm",
                    "hostSshCaId",
                    "policy",
                    "projectId",
                    "userSshCaId",
                ][..],
                host_fields,
            ),
            (
                SSH_HOSTS_REPLACE_TOOL,
                &["confirm", "policy", "target"][..],
                host_fields,
            ),
            (
                SSH_HOSTS_DELETE_TOOL,
                &["confirm", "target"][..],
                host_fields,
            ),
            (
                SSH_HOSTS_USER_CA_PUBLIC_KEY_GET_TOOL,
                &["projectId", "sshHostId"][..],
                &["caId", "hostId", "publicKey"][..],
            ),
            (
                SSH_HOSTS_HOST_CA_PUBLIC_KEY_GET_TOOL,
                &["projectId", "sshHostId"][..],
                &["caId", "hostId", "publicKey"][..],
            ),
            (
                SSH_HOSTS_HOST_CERTIFICATE_ISSUE_TOOL,
                &["confirm", "publicKey", "target"][..],
                &["serialNumber", "signedKey"][..],
            ),
            (
                SSH_HOST_GROUPS_LIST_TOOL,
                &["projectId"][..],
                &["groups"][..],
            ),
            (
                SSH_HOST_GROUPS_GET_TOOL,
                &["projectId", "sshHostGroupId"][..],
                group_fields,
            ),
            (
                SSH_HOST_GROUPS_CREATE_TOOL,
                &["confirm", "policy", "projectId"][..],
                group_fields,
            ),
            (
                SSH_HOST_GROUPS_REPLACE_TOOL,
                &["confirm", "policy", "target"][..],
                group_fields,
            ),
            (
                SSH_HOST_GROUPS_DELETE_TOOL,
                &["confirm", "target"][..],
                group_fields,
            ),
            (
                SSH_HOST_GROUP_HOSTS_LIST_TOOL,
                &["filter", "target"][..],
                &["filter", "groupId", "hosts", "projectId", "totalCount"][..],
            ),
            (
                SSH_HOST_GROUP_HOSTS_ADD_TOOL,
                &["confirm", "sshHostId", "target"][..],
                &[
                    "groupId",
                    "hostId",
                    "hostname",
                    "isPartOfGroup",
                    "projectId",
                ][..],
            ),
            (
                SSH_HOST_GROUP_HOSTS_REMOVE_TOOL,
                &["confirm", "sshHostId", "target"][..],
                &[
                    "groupId",
                    "hostId",
                    "hostname",
                    "isPartOfGroup",
                    "projectId",
                ][..],
            ),
        ];
        assert_schema_field_table(tools, &expected);
    }

    fn assert_schema_field_table(tools: &[Tool], expected: &[(&str, &[&str], &[&str])]) {
        for (tool, &(name, input_fields, output_fields)) in tools.iter().zip(expected) {
            assert_eq!(tool.name, name);
            assert_eq!(sorted_property_names(&tool.input_schema), input_fields);
            assert_eq!(
                sorted_property_names(tool.output_schema.as_ref().expect("output schema")),
                output_fields,
            );
        }
    }

    fn assert_catalog_resource_fields(tools: &[Tool]) {
        assert_project_resource_fields(tools);
        assert_identity_resource_fields(tools);
        assert_project_membership_resource_fields(tools);
        assert_role_resource_fields(tools);
        assert_group_resource_fields(tools);
        assert_identity_project_additional_privilege_resource_fields(tools);
        assert_universal_auth_resource_fields(tools);
        assert_token_auth_resource_fields(tools);
        assert_kubernetes_auth_resource_fields(tools);
        assert_secret_resource_fields(tools);
        assert_secret_import_resource_fields(tools);
        assert_audit_log_resource_fields(tools);
        assert_app_automation_resource_fields(tools);
        assert_kms_resource_fields(tools);
        assert_dynamic_secret_resource_fields(tools);
    }

    fn assert_kms_resource_fields(tools: &[Tool]) {
        for name in [
            KMS_KEYS_LIST_TOOL,
            KMS_KEYS_GET_TOOL,
            KMS_KEYS_GET_BY_NAME_TOOL,
            KMS_KEYS_CREATE_TOOL,
            KMS_KEYS_UPDATE_TOOL,
            KMS_KEYS_DELETE_TOOL,
        ] {
            let schema = tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap()
                .output_schema
                .as_ref()
                .unwrap();
            let encoded = serde_json::to_string(schema).unwrap();
            for secret_field in ["privateKey", "plaintext", "keyMaterial"] {
                assert!(
                    !encoded.contains(secret_field),
                    "{name} exposed {secret_field}"
                );
            }
        }
    }

    fn assert_app_automation_resource_fields(tools: &[Tool]) {
        let forbidden = [
            "credentialsHash",
            "configuration",
            "destinationConfig",
            "syncOptions",
            "parameters",
            "secretsMapping",
            "lastSyncMessage",
            "lastRotationMessage",
        ];
        for name in [
            APP_CONNECTIONS_LIST_TOOL,
            SECRET_SYNCS_LIST_TOOL,
            SECRET_ROTATIONS_LIST_TOOL,
            SQL_SECRET_ROTATION_GET_TOOL,
            SQL_SECRET_ROTATION_GET_BY_NAME_TOOL,
            SQL_SECRET_ROTATION_CREATE_TOOL,
            SQL_SECRET_ROTATION_UPDATE_TOOL,
            SQL_SECRET_ROTATION_DELETE_TOOL,
            SQL_SECRET_ROTATION_MOVE_TOOL,
            SQL_SECRET_ROTATION_ROTATE_TOOL,
            SQL_SECRET_ROTATION_CHECK_TOOL,
        ] {
            let schema = tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap()
                .output_schema
                .as_ref()
                .unwrap();
            let schema = serde_json::to_string(schema).unwrap();
            for field in forbidden {
                assert!(
                    !schema.contains(&format!("\"{field}\"")),
                    "{name} exposed {field}"
                );
            }
        }
        for (name, definitions) in [
            (APP_CONNECTIONS_LIST_TOOL, &["AppConnection"][..]),
            (
                GITHUB_APP_CONNECTION_GET_TOOL,
                &["AppConnection", "GitHubInstanceMetadata"][..],
            ),
            (
                GITHUB_APP_CONNECTION_CREATE_TOOL,
                &["AppConnection", "GitHubInstanceMetadata"][..],
            ),
            (
                SECRET_SYNCS_LIST_TOOL,
                &[
                    "AutomationConnection",
                    "AutomationEnvironment",
                    "AutomationFolder",
                    "SecretSync",
                ][..],
            ),
            (
                GITHUB_SECRET_SYNC_GET_TOOL,
                &[
                    "AutomationConnection",
                    "AutomationEnvironment",
                    "AutomationFolder",
                    "GitHubSecretSyncOptions",
                    "SecretSync",
                ][..],
            ),
            (
                GITHUB_SECRET_SYNC_CREATE_TOOL,
                &[
                    "AutomationConnection",
                    "AutomationEnvironment",
                    "AutomationFolder",
                    "GitHubSecretSyncOptions",
                    "SecretSync",
                ][..],
            ),
            (
                SECRET_ROTATIONS_LIST_TOOL,
                &["RotationTimeOfDay", "SecretRotation"][..],
            ),
        ] {
            let schema = tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap()
                .output_schema
                .as_ref()
                .unwrap();
            for definition in definitions {
                assert_definition_property_descriptions(schema, definition);
            }
        }
    }

    fn assert_audit_log_resource_fields(tools: &[Tool]) {
        let output = tools
            .iter()
            .find(|tool| tool.name == AUDIT_LOGS_LIST_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            output,
            "AuditLog",
            &[
                "actorType",
                "createdAt",
                "eventType",
                "expiresAt",
                "id",
                "ipAddress",
                "organizationId",
                "projectId",
                "projectName",
                "userAgent",
                "userAgentType",
            ],
        );
        let serialized = serde_json::to_string(output).unwrap();
        assert!(!serialized.contains("eventMetadata"));
        assert!(!serialized.contains("actorMetadata"));
    }

    fn assert_dynamic_secret_resource_fields(tools: &[Tool]) {
        for name in [
            DYNAMIC_SECRETS_LIST_TOOL,
            DYNAMIC_SECRETS_GET_TOOL,
            tools::DYNAMIC_SECRETS_UPDATE_TOOL,
            tools::DYNAMIC_SECRETS_DELETE_TOOL,
            DYNAMIC_SECRET_LEASES_LIST_TOOL,
            DYNAMIC_SECRET_LEASES_GET_TOOL,
            DYNAMIC_SECRET_LEASES_RENEW_TOOL,
            DYNAMIC_SECRET_LEASES_REVOKE_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert_definition_properties(
                &tool.input_schema,
                "DynamicSecretScopeInput",
                &["environmentSlug", "path", "projectSlug"],
            );
            assert_eq!(
                tool.input_schema["$defs"]["DynamicSecretScopeInput"]["additionalProperties"],
                false,
                "{name} scope must reject unknown fields"
            );
        }

        let config_list = tools
            .iter()
            .find(|tool| tool.name == DYNAMIC_SECRETS_LIST_TOOL)
            .unwrap();
        assert_definition_properties(
            config_list.output_schema.as_ref().unwrap(),
            "DynamicSecret",
            &[
                "createdAt",
                "defaultTTL",
                "folderId",
                "gatewayId",
                "gatewayPoolId",
                "gatewayV2Id",
                "id",
                "maxTTL",
                "name",
                "projectGatewayId",
                "provider",
                "status",
                "updatedAt",
                "usernameTemplate",
                "version",
            ],
        );

        let lease_list = tools
            .iter()
            .find(|tool| tool.name == DYNAMIC_SECRET_LEASES_LIST_TOOL)
            .unwrap();
        assert_definition_properties(
            lease_list.output_schema.as_ref().unwrap(),
            "DynamicSecretLease",
            &[
                "createdAt",
                "dynamicSecretId",
                "expiresAt",
                "externalEntityId",
                "id",
                "status",
                "updatedAt",
                "version",
            ],
        );

        for name in [
            DYNAMIC_SECRETS_LIST_TOOL,
            DYNAMIC_SECRETS_GET_TOOL,
            tools::DYNAMIC_SECRETS_UPDATE_TOOL,
            tools::DYNAMIC_SECRETS_DELETE_TOOL,
            DYNAMIC_SECRET_LEASES_LIST_TOOL,
            DYNAMIC_SECRET_LEASES_GET_TOOL,
            DYNAMIC_SECRET_LEASES_RENEW_TOOL,
            DYNAMIC_SECRET_LEASES_REVOKE_TOOL,
        ] {
            let schema = tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap()
                .output_schema
                .as_ref()
                .unwrap();
            let serialized = serde_json::to_string(schema).unwrap();
            for forbidden in [
                "\"inputs\"",
                "\"metadata\"",
                "\"config\"",
                "\"statusDetails\"",
            ] {
                assert!(
                    !serialized.contains(forbidden),
                    "{name} output schema must omit {forbidden}"
                );
            }
        }
    }

    fn assert_identity_resource_fields(tools: &[Tool]) {
        let identities = tools
            .iter()
            .find(|tool| tool.name == IDENTITIES_LIST_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            identities,
            "MachineIdentity",
            &[
                "authMethods",
                "hasDeleteProtection",
                "id",
                "name",
                "organizationId",
                "organizationMembershipId",
                "organizationRole",
                "organizationRoleId",
                "projectId",
            ],
        );
    }

    fn assert_project_membership_resource_fields(tools: &[Tool]) {
        let users = tools
            .iter()
            .find(|tool| tool.name == PROJECT_USER_MEMBERSHIPS_LIST_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            users,
            "ProjectUserMembership",
            &["createdAt", "id", "projectId", "roles", "user", "userId"],
        );
        assert_definition_properties(
            users,
            "ProjectMemberUser",
            &[
                "authMethods",
                "email",
                "firstName",
                "id",
                "isEmailVerified",
                "lastName",
                "username",
            ],
        );
        assert_definition_properties(
            users,
            "ProjectMembershipRole",
            &[
                "customRoleId",
                "customRoleName",
                "customRoleSlug",
                "id",
                "isTemporary",
                "projectMembershipId",
                "role",
                "temporaryAccessEndTime",
                "temporaryAccessStartTime",
                "temporaryMode",
                "temporaryRange",
            ],
        );
        let identities = tools
            .iter()
            .find(|tool| tool.name == PROJECT_IDENTITY_MEMBERSHIPS_LIST_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            identities,
            "ProjectIdentityMembership",
            &[
                "createdAt",
                "id",
                "identity",
                "identityId",
                "projectId",
                "roles",
                "updatedAt",
            ],
        );
        assert_definition_properties(
            identities,
            "ProjectMemberIdentity",
            &["authMethods", "id", "name", "orgId", "projectId"],
        );
    }

    fn assert_role_resource_fields(tools: &[Tool]) {
        let roles = tools
            .iter()
            .find(|tool| tool.name == PROJECT_ROLES_LIST_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            roles,
            "RoleSummary",
            &["builtIn", "description", "name", "scope", "scopeId", "slug"],
        );
        let role = tools
            .iter()
            .find(|tool| tool.name == "projectRoles.get")
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            role,
            "RolePermission",
            &["action", "conditions", "inverted", "subject"],
        );
    }

    fn assert_group_resource_fields(tools: &[Tool]) {
        let members = tools
            .iter()
            .find(|tool| tool.name == GROUP_MEMBERS_LIST_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            members,
            "GroupUser",
            &["email", "firstName", "id", "lastName", "username"],
        );
        assert_definition_properties(members, "GroupIdentity", &["id", "name"]);

        let projects = tools
            .iter()
            .find(|tool| tool.name == GROUP_PROJECTS_LIST_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            projects,
            "GroupProject",
            &["description", "id", "joinedGroupAt", "name", "slug", "type"],
        );

        let memberships = tools
            .iter()
            .find(|tool| tool.name == PROJECT_GROUP_MEMBERSHIPS_LIST_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            memberships,
            "ProjectGroupMembership",
            &[
                "createdAt",
                "group",
                "groupId",
                "id",
                "projectId",
                "roles",
                "updatedAt",
            ],
        );
        assert_definition_properties(
            memberships,
            "GroupReference",
            &["id", "name", "orgId", "slug"],
        );
    }

    fn assert_identity_project_additional_privilege_resource_fields(tools: &[Tool]) {
        let privileges = tools
            .iter()
            .find(|tool| tool.name == IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_LIST_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            privileges,
            "IdentityProjectAdditionalPrivilegeSummary",
            &[
                "createdAt",
                "id",
                "identityId",
                "isTemporary",
                "projectId",
                "slug",
                "temporaryAccessEndTime",
                "temporaryAccessStartTime",
                "temporaryMode",
                "temporaryRange",
                "updatedAt",
            ],
        );
        let exact = tools
            .iter()
            .find(|tool| tool.name == IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_GET_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            exact,
            "RolePermission",
            &["action", "conditions", "inverted", "subject"],
        );
    }

    fn assert_universal_auth_resource_fields(tools: &[Tool]) {
        let config = tools
            .iter()
            .find(|tool| tool.name == UNIVERSAL_AUTH_GET_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(config, "TrustedIp", &["ipAddress", "prefix", "type"]);

        let client_secrets = tools
            .iter()
            .find(|tool| tool.name == UNIVERSAL_AUTH_CLIENT_SECRETS_LIST_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            client_secrets,
            "UniversalAuthClientSecret",
            &[
                "clientSecretNumUses",
                "clientSecretNumUsesLimit",
                "clientSecretPrefix",
                "clientSecretTTL",
                "createdAt",
                "description",
                "id",
                "identityUAId",
                "isClientSecretRevoked",
                "updatedAt",
            ],
        );
    }

    fn assert_token_auth_resource_fields(tools: &[Tool]) {
        let config = tools
            .iter()
            .find(|tool| tool.name == TOKEN_AUTH_GET_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(config, "TrustedIp", &["ipAddress", "prefix", "type"]);

        let tokens = tools
            .iter()
            .find(|tool| tool.name == TOKEN_AUTH_TOKENS_LIST_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            tokens,
            "TokenAuthToken",
            &[
                "accessTokenLastRenewedAt",
                "accessTokenLastUsedAt",
                "accessTokenMaxTTL",
                "accessTokenNumUses",
                "accessTokenNumUsesLimit",
                "accessTokenPeriod",
                "accessTokenTTL",
                "authMethod",
                "createdAt",
                "id",
                "identityId",
                "isAccessTokenRevoked",
                "name",
                "subOrganizationId",
                "updatedAt",
            ],
        );
    }

    fn assert_kubernetes_auth_resource_fields(tools: &[Tool]) {
        let config = tools
            .iter()
            .find(|tool| tool.name == KUBERNETES_AUTH_GET_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(config, "TrustedIp", &["ipAddress", "prefix", "type"]);
        let serialized = serde_json::to_string(config).unwrap();
        assert!(!serialized.contains("tokenReviewerJwt\""));
        assert!(!serialized.contains("caCert\""));
    }

    fn assert_project_resource_fields(tools: &[Tool]) {
        let projects = tools
            .iter()
            .find(|tool| tool.name == "projects.list")
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            projects,
            "Project",
            &[
                "description",
                "environments",
                "id",
                "name",
                "orgId",
                "slug",
                "type",
            ],
        );
        assert_definition_properties(projects, "Environment", &["id", "name", "slug"]);
        assert_definition_properties(projects, "PageRequest", &["limit", "offset"]);
    }

    fn assert_secret_resource_fields(tools: &[Tool]) {
        assert_secret_metadata_resource_fields(tools);
        assert_secret_target_resource_fields(tools);
    }

    fn assert_secret_metadata_resource_fields(tools: &[Tool]) {
        let folders = tools
            .iter()
            .find(|tool| tool.name == "folders.list")
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            folders,
            "Folder",
            &[
                "description",
                "envId",
                "environment",
                "id",
                "isReserved",
                "name",
                "parentId",
                "path",
                "projectId",
                "relativePath",
            ],
        );
        assert_definition_properties(
            folders,
            "FolderEnvironment",
            &["envId", "envName", "envSlug"],
        );

        let tags = tools
            .iter()
            .find(|tool| tool.name == "tags.list")
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(tags, "Tag", &["color", "id", "name", "projectId", "slug"]);

        let secrets = tools
            .iter()
            .find(|tool| tool.name == SECRET_METADATA_LIST_TOOL)
            .unwrap()
            .output_schema
            .as_ref()
            .unwrap();
        assert_definition_properties(
            secrets,
            "SecretMetadata",
            &[
                "environment",
                "id",
                "metadata",
                "name",
                "secretPath",
                "tags",
                "type",
                "valueHidden",
                "version",
            ],
        );
        assert_definition_properties(
            secrets,
            "SecretMetadataEntry",
            &["isEncrypted", "key", "value"],
        );
        assert_definition_properties(
            secrets,
            "SecretMetadataTag",
            &["color", "id", "name", "slug"],
        );
    }

    fn assert_secret_target_resource_fields(tools: &[Tool]) {
        let reveal = &tools
            .iter()
            .find(|tool| tool.name == SECRET_REVEAL_TOOL)
            .unwrap()
            .input_schema;
        assert_definition_properties(
            reveal,
            "SecretTargetInput",
            &["environment", "name", "path", "projectId"],
        );

        for name in [SECRET_CREATE_TOOL, SECRET_UPDATE_TOOL, SECRET_DELETE_TOOL] {
            let mutation = tools.iter().find(|tool| tool.name == name).unwrap();
            let input = &mutation.input_schema;
            assert_definition_properties(
                input,
                "SecretTargetInput",
                &["environment", "name", "path", "projectId"],
            );
            let target = input["$defs"]["SecretTargetInput"]
                .as_object()
                .expect("secret target definition");
            assert_eq!(
                target.get("additionalProperties"),
                Some(&Value::Bool(false))
            );
        }

        for name in [
            SECRET_BATCH_CREATE_TOOL,
            SECRET_BATCH_UPDATE_TOOL,
            SECRET_BATCH_DELETE_TOOL,
        ] {
            let mutation = tools.iter().find(|tool| tool.name == name).unwrap();
            let input = &mutation.input_schema;
            assert_definition_properties(
                input,
                "ExactSecretScopeInput",
                &["environment", "path", "projectId"],
            );
            let scope = input["$defs"]["ExactSecretScopeInput"]
                .as_object()
                .expect("secret batch scope definition");
            assert_eq!(scope.get("additionalProperties"), Some(&Value::Bool(false)));
        }
        for name in [SECRET_BATCH_CREATE_TOOL, SECRET_BATCH_UPDATE_TOOL] {
            let mutation = tools.iter().find(|tool| tool.name == name).unwrap();
            assert_definition_properties(
                &mutation.input_schema,
                "SecretBatchValueInput",
                &["name", "secretValue"],
            );
        }
    }

    fn assert_secret_import_resource_fields(tools: &[Tool]) {
        for name in [
            SECRET_IMPORTS_LIST_TOOL,
            SECRET_IMPORTS_CREATE_TOOL,
            SECRET_IMPORTS_UPDATE_TOOL,
            SECRET_IMPORTS_DELETE_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert_definition_properties(
                &tool.input_schema,
                "ExactSecretScopeInput",
                &["environment", "path", "projectId"],
            );
            assert_eq!(
                tool.input_schema["$defs"]["ExactSecretScopeInput"]["additionalProperties"], false,
                "{name} exact scope must reject unknown fields"
            );
        }
        let import_list = tools
            .iter()
            .find(|tool| tool.name == SECRET_IMPORTS_LIST_TOOL)
            .unwrap();
        let import_output = import_list.output_schema.as_ref().unwrap();
        assert_definition_properties(
            import_output,
            "SecretImport",
            &[
                "createdAt",
                "folderId",
                "id",
                "isReplication",
                "isReplicationSuccess",
                "isReserved",
                "lastReplicated",
                "position",
                "source",
                "target",
                "updatedAt",
                "version",
            ],
        );
        assert_definition_properties(
            import_output,
            "SecretImportEnvironment",
            &["id", "name", "slug"],
        );
        assert_definition_properties(
            import_output,
            "SecretImportSource",
            &["environment", "path"],
        );
        assert_definition_properties(
            import_output,
            "SecretImportTarget",
            &["environment", "path", "projectId"],
        );
    }

    #[allow(clippy::too_many_lines)]
    fn is_catalog_mutation(name: &str) -> bool {
        matches!(
            name,
            PROJECTS_CREATE_TOOL
                | PROJECTS_UPDATE_TOOL
                | PROJECTS_DELETE_TOOL
                | ENVIRONMENTS_CREATE_TOOL
                | ENVIRONMENTS_UPDATE_TOOL
                | ENVIRONMENTS_DELETE_TOOL
                | ENVIRONMENTS_RESTORE_TOOL
                | FOLDERS_CREATE_TOOL
                | FOLDERS_UPDATE_TOOL
                | FOLDERS_BATCH_UPDATE_TOOL
                | FOLDERS_DELETE_TOOL
                | TAGS_CREATE_TOOL
                | TAGS_UPDATE_TOOL
                | TAGS_DELETE_TOOL
                | IDENTITIES_CREATE_TOOL
                | IDENTITIES_UPDATE_TOOL
                | IDENTITIES_DELETE_TOOL
                | PROJECT_USER_MEMBERSHIPS_INVITE_TOOL
                | PROJECT_USER_MEMBERSHIPS_UPDATE_TOOL
                | PROJECT_USER_MEMBERSHIPS_DELETE_TOOL
                | PROJECT_IDENTITY_MEMBERSHIPS_CREATE_TOOL
                | PROJECT_IDENTITY_MEMBERSHIPS_UPDATE_TOOL
                | PROJECT_IDENTITY_MEMBERSHIPS_DELETE_TOOL
                | IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_CREATE_TOOL
                | IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_UPDATE_TOOL
                | IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_DELETE_TOOL
                | UNIVERSAL_AUTH_ATTACH_TOOL
                | UNIVERSAL_AUTH_UPDATE_TOOL
                | UNIVERSAL_AUTH_REMOVE_TOOL
                | UNIVERSAL_AUTH_CLIENT_SECRETS_CREATE_TOOL
                | UNIVERSAL_AUTH_CLIENT_SECRETS_REVOKE_TOOL
                | UNIVERSAL_AUTH_LOCKOUTS_CLEAR_TOOL
                | TOKEN_AUTH_ATTACH_TOOL
                | TOKEN_AUTH_UPDATE_TOOL
                | TOKEN_AUTH_REMOVE_TOOL
                | TOKEN_AUTH_TOKENS_CREATE_TOOL
                | TOKEN_AUTH_TOKENS_UPDATE_TOOL
                | TOKEN_AUTH_TOKENS_REVOKE_TOOL
                | KUBERNETES_AUTH_ATTACH_TOOL
                | KUBERNETES_AUTH_UPDATE_TOOL
                | KUBERNETES_AUTH_REMOVE_TOOL
                | SECRET_CREATE_TOOL
                | SECRET_UPDATE_TOOL
                | SECRET_DELETE_TOOL
                | SECRET_BATCH_CREATE_TOOL
                | SECRET_BATCH_UPDATE_TOOL
                | SECRET_BATCH_DELETE_TOOL
                | SECRET_IMPORTS_CREATE_TOOL
                | SECRET_IMPORTS_UPDATE_TOOL
                | SECRET_IMPORTS_DELETE_TOOL
                | GITHUB_APP_CONNECTION_CREATE_TOOL
                | GITHUB_APP_CONNECTION_UPDATE_TOOL
                | GITHUB_APP_CONNECTION_ROTATE_CREDENTIALS_TOOL
                | GITHUB_APP_CONNECTION_DELETE_TOOL
                | GITHUB_SECRET_SYNC_CREATE_TOOL
                | GITHUB_SECRET_SYNC_UPDATE_TOOL
                | GITHUB_SECRET_SYNC_DELETE_TOOL
                | GITHUB_SECRET_SYNC_RUN_TOOL
                | GITHUB_SECRET_SYNC_REMOVE_SECRETS_TOOL
                | SQL_SECRET_ROTATION_CREATE_TOOL
                | SQL_SECRET_ROTATION_UPDATE_TOOL
                | SQL_SECRET_ROTATION_DELETE_TOOL
                | SQL_SECRET_ROTATION_MOVE_TOOL
                | SQL_SECRET_ROTATION_ROTATE_TOOL
                | SQL_SECRET_ROTATION_CHECK_TOOL
                | INTERNAL_CERTIFICATE_AUTHORITIES_CREATE_TOOL
                | INTERNAL_CERTIFICATE_AUTHORITIES_UPDATE_TOOL
                | INTERNAL_CERTIFICATE_AUTHORITIES_DELETE_TOOL
                | INTERNAL_CA_CERTIFICATE_GENERATE_TOOL
                | INTERNAL_CA_CERTIFICATE_RENEW_TOOL
                | INTERNAL_CA_INTERMEDIATE_SIGN_TOOL
                | INTERNAL_CA_CERTIFICATE_IMPORT_TOOL
                | CERTIFICATE_POLICIES_CREATE_TOOL
                | CERTIFICATE_POLICIES_UPDATE_TOOL
                | CERTIFICATE_POLICIES_DELETE_TOOL
                | CERTIFICATES_ISSUE_TOOL
                | CERTIFICATES_RENEW_TOOL
                | CERTIFICATES_REVOKE_TOOL
                | CERTIFICATES_RENEWAL_CONFIGURATION_UPDATE_TOOL
                | CERTIFICATES_DELETE_TOOL
                | CERTIFICATES_IMPORT_TOOL
                | CERTIFICATE_REQUESTS_CANCEL_TOOL
                | CERTIFICATE_PROFILES_CREATE_TOOL
                | CERTIFICATE_PROFILES_UPDATE_TOOL
                | CERTIFICATE_PROFILES_DELETE_TOOL
                | SSH_CERTIFICATE_AUTHORITIES_CREATE_TOOL
                | SSH_CERTIFICATE_AUTHORITIES_REPLACE_TOOL
                | SSH_CERTIFICATE_AUTHORITIES_DELETE_TOOL
                | SSH_CERTIFICATE_TEMPLATES_CREATE_TOOL
                | SSH_CERTIFICATE_TEMPLATES_REPLACE_TOOL
                | SSH_CERTIFICATE_TEMPLATES_DELETE_TOOL
                | SSH_CERTIFICATES_SIGN_TOOL
                | SSH_CERTIFICATES_ISSUE_TOOL
                | SSH_HOSTS_CREATE_TOOL
                | SSH_HOSTS_REPLACE_TOOL
                | SSH_HOSTS_DELETE_TOOL
                | SSH_HOSTS_HOST_CERTIFICATE_ISSUE_TOOL
                | SSH_HOST_GROUPS_CREATE_TOOL
                | SSH_HOST_GROUPS_REPLACE_TOOL
                | SSH_HOST_GROUPS_DELETE_TOOL
                | SSH_HOST_GROUP_HOSTS_ADD_TOOL
                | SSH_HOST_GROUP_HOSTS_REMOVE_TOOL
                | CODE_SIGNERS_CREATE_TOOL
                | CODE_SIGNERS_UPDATE_TOOL
                | CODE_SIGNERS_DELETE_TOOL
                | CODE_SIGNERS_STATUS_UPDATE_TOOL
                | CODE_SIGNERS_CERTIFICATE_REISSUE_TOOL
                | CODE_SIGNERS_SIGN_TOOL
                | CODE_SIGNER_MEMBERS_ADD_TOOL
                | CODE_SIGNER_MEMBER_ROLE_UPDATE_TOOL
                | CODE_SIGNER_MEMBERS_REMOVE_TOOL
                | CODE_SIGNER_APPROVAL_POLICY_REPLACE_TOOL
                | CODE_SIGNER_APPROVAL_REQUESTS_CREATE_TOOL
                | CODE_SIGNER_APPROVAL_REQUESTS_PRE_APPROVE_TOOL
                | CODE_SIGNER_APPROVAL_REQUESTS_REVOKE_TOOL
                | KMS_KEYS_CREATE_TOOL
                | KMS_KEYS_UPDATE_TOOL
                | KMS_KEYS_DELETE_TOOL
                | KMS_ENCRYPT_TOOL
                | KMS_DECRYPT_TOOL
                | KMS_KEYS_BULK_IMPORT_TOOL
                | KMS_PRIVATE_KEYS_BULK_REVEAL_TOOL
                | KMS_SIGN_TOOL
                | KMS_VERIFY_TOOL
                | tools::DYNAMIC_SECRETS_CREATE_TOOL
                | tools::DYNAMIC_SECRETS_UPDATE_TOOL
                | tools::DYNAMIC_SECRETS_DELETE_TOOL
                | tools::DYNAMIC_SECRET_LEASES_CREATE_TOOL
                | DYNAMIC_SECRET_LEASES_RENEW_TOOL
                | DYNAMIC_SECRET_LEASES_REVOKE_TOOL
        )
    }

    fn is_catalog_destructive(name: &str) -> bool {
        matches!(
            name,
            PROJECTS_DELETE_TOOL
                | ENVIRONMENTS_DELETE_TOOL
                | FOLDERS_DELETE_TOOL
                | TAGS_DELETE_TOOL
                | IDENTITIES_DELETE_TOOL
                | PROJECT_USER_MEMBERSHIPS_UPDATE_TOOL
                | PROJECT_USER_MEMBERSHIPS_DELETE_TOOL
                | PROJECT_IDENTITY_MEMBERSHIPS_UPDATE_TOOL
                | PROJECT_IDENTITY_MEMBERSHIPS_DELETE_TOOL
                | IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_CREATE_TOOL
                | IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_UPDATE_TOOL
                | IDENTITY_PROJECT_ADDITIONAL_PRIVILEGES_DELETE_TOOL
                | UNIVERSAL_AUTH_REMOVE_TOOL
                | UNIVERSAL_AUTH_CLIENT_SECRETS_REVOKE_TOOL
                | UNIVERSAL_AUTH_LOCKOUTS_CLEAR_TOOL
                | TOKEN_AUTH_REMOVE_TOOL
                | TOKEN_AUTH_TOKENS_REVOKE_TOOL
                | KUBERNETES_AUTH_REMOVE_TOOL
                | SECRET_DELETE_TOOL
                | SECRET_BATCH_DELETE_TOOL
                | SECRET_IMPORTS_DELETE_TOOL
                | GITHUB_APP_CONNECTION_UPDATE_TOOL
                | GITHUB_APP_CONNECTION_ROTATE_CREDENTIALS_TOOL
                | GITHUB_APP_CONNECTION_DELETE_TOOL
                | GITHUB_SECRET_SYNC_CREATE_TOOL
                | GITHUB_SECRET_SYNC_UPDATE_TOOL
                | GITHUB_SECRET_SYNC_DELETE_TOOL
                | GITHUB_SECRET_SYNC_RUN_TOOL
                | GITHUB_SECRET_SYNC_REMOVE_SECRETS_TOOL
                | SQL_SECRET_ROTATION_CREATE_TOOL
                | SQL_SECRET_ROTATION_UPDATE_TOOL
                | SQL_SECRET_ROTATION_DELETE_TOOL
                | SQL_SECRET_ROTATION_MOVE_TOOL
                | SQL_SECRET_ROTATION_ROTATE_TOOL
                | INTERNAL_CERTIFICATE_AUTHORITIES_UPDATE_TOOL
                | INTERNAL_CERTIFICATE_AUTHORITIES_DELETE_TOOL
                | INTERNAL_CA_CERTIFICATE_GENERATE_TOOL
                | INTERNAL_CA_CERTIFICATE_RENEW_TOOL
                | INTERNAL_CA_CERTIFICATE_IMPORT_TOOL
                | CERTIFICATES_REVOKE_TOOL
                | CERTIFICATES_DELETE_TOOL
                | CERTIFICATE_REQUESTS_CANCEL_TOOL
                | CERTIFICATE_POLICIES_DELETE_TOOL
                | CERTIFICATE_PROFILES_UPDATE_TOOL
                | CERTIFICATE_PROFILES_DELETE_TOOL
                | SSH_CERTIFICATE_AUTHORITIES_REPLACE_TOOL
                | SSH_CERTIFICATE_AUTHORITIES_DELETE_TOOL
                | SSH_CERTIFICATE_TEMPLATES_REPLACE_TOOL
                | SSH_CERTIFICATE_TEMPLATES_DELETE_TOOL
                | SSH_HOSTS_REPLACE_TOOL
                | SSH_HOSTS_DELETE_TOOL
                | SSH_HOST_GROUPS_REPLACE_TOOL
                | SSH_HOST_GROUPS_DELETE_TOOL
                | SSH_HOST_GROUP_HOSTS_REMOVE_TOOL
                | CODE_SIGNERS_DELETE_TOOL
                | CODE_SIGNER_MEMBERS_REMOVE_TOOL
                | CODE_SIGNER_APPROVAL_POLICY_REPLACE_TOOL
                | CODE_SIGNER_APPROVAL_REQUESTS_REVOKE_TOOL
                | KMS_KEYS_UPDATE_TOOL
                | KMS_KEYS_DELETE_TOOL
                | tools::DYNAMIC_SECRETS_DELETE_TOOL
                | tools::DYNAMIC_SECRET_LEASES_CREATE_TOOL
                | DYNAMIC_SECRET_LEASES_REVOKE_TOOL
        )
    }

    fn is_catalog_observable_read(name: &str) -> bool {
        matches!(
            name,
            AUDIT_LOGS_LIST_TOOL
                | APP_CONNECTIONS_LIST_TOOL
                | GITHUB_APP_CONNECTION_GET_TOOL
                | SECRET_SYNCS_LIST_TOOL
                | GITHUB_SECRET_SYNC_GET_TOOL
                | SECRET_ROTATIONS_LIST_TOOL
                | SQL_SECRET_ROTATION_GET_TOOL
                | SQL_SECRET_ROTATION_GET_BY_NAME_TOOL
                | SQL_SECRET_ROTATION_GENERATED_CREDENTIALS_GET_TOOL
                | CERTIFICATE_AUTHORITIES_LIST_TOOL
                | INTERNAL_CERTIFICATE_AUTHORITIES_LIST_TOOL
                | INTERNAL_CERTIFICATE_AUTHORITIES_GET_TOOL
                | INTERNAL_CA_CSR_GET_TOOL
                | INTERNAL_CA_CERTIFICATES_LIST_TOOL
                | INTERNAL_CA_CERTIFICATE_GET_TOOL
                | INTERNAL_CA_CERTIFICATE_VERSION_GET_TOOL
                | INTERNAL_CA_CRLS_LIST_TOOL
                | CERTIFICATES_LIST_TOOL
                | CERTIFICATES_GET_TOOL
                | CERTIFICATES_CERTIFICATE_GET_TOOL
                | CERTIFICATES_BUNDLE_REVEAL_TOOL
                | CERTIFICATES_PRIVATE_KEY_REVEAL_TOOL
                | CERTIFICATE_REQUESTS_LIST_TOOL
                | CERTIFICATE_REQUESTS_GET_TOOL
                | CERTIFICATE_REQUEST_RESULT_REVEAL_TOOL
                | CERTIFICATE_POLICIES_LIST_TOOL
                | CERTIFICATE_POLICIES_GET_TOOL
                | CERTIFICATE_PROFILES_LIST_TOOL
                | CERTIFICATE_PROFILES_GET_TOOL
                | CERTIFICATE_PROFILES_GET_BY_SLUG_TOOL
                | CERTIFICATE_PROFILE_CERTIFICATES_LIST_TOOL
                | CERTIFICATE_PROFILE_LATEST_BUNDLE_REVEAL_TOOL
                | CERTIFICATE_PROFILE_EAB_SECRET_REVEAL_TOOL
                | SSH_CERTIFICATE_AUTHORITIES_LIST_TOOL
                | SSH_CERTIFICATE_AUTHORITIES_GET_TOOL
                | SSH_CERTIFICATE_AUTHORITIES_PUBLIC_KEY_GET_TOOL
                | SSH_CERTIFICATE_TEMPLATES_LIST_TOOL
                | SSH_CERTIFICATE_AUTHORITY_TEMPLATES_LIST_TOOL
                | SSH_CERTIFICATE_TEMPLATES_GET_TOOL
                | SSH_HOSTS_LIST_TOOL
                | SSH_HOSTS_GET_TOOL
                | SSH_HOSTS_USER_CA_PUBLIC_KEY_GET_TOOL
                | SSH_HOSTS_HOST_CA_PUBLIC_KEY_GET_TOOL
                | SSH_HOST_GROUPS_LIST_TOOL
                | SSH_HOST_GROUPS_GET_TOOL
                | SSH_HOST_GROUP_HOSTS_LIST_TOOL
                | CODE_SIGNERS_LIST_TOOL
                | CODE_SIGNERS_GET_TOOL
                | CODE_SIGNERS_CERTIFICATE_EXPORT_TOOL
                | CODE_SIGNERS_PUBLIC_KEY_GET_TOOL
                | CODE_SIGNER_MEMBERS_LIST_TOOL
                | CODE_SIGNER_EFFECTIVE_MEMBERS_LIST_TOOL
                | CODE_SIGNER_PERMISSIONS_GET_TOOL
                | CODE_SIGNER_APPROVAL_POLICY_GET_TOOL
                | CODE_SIGNER_APPROVAL_REQUESTS_LIST_TOOL
                | CODE_SIGNER_OPERATIONS_LIST_TOOL
                | KMS_KEYS_LIST_TOOL
                | KMS_KEYS_GET_TOOL
                | KMS_KEYS_GET_BY_NAME_TOOL
                | KMS_PUBLIC_KEY_GET_TOOL
                | KMS_PRIVATE_KEY_REVEAL_TOOL
                | KMS_SIGNING_ALGORITHMS_LIST_TOOL
                | DYNAMIC_SECRETS_LIST_TOOL
                | DYNAMIC_SECRETS_GET_TOOL
                | DYNAMIC_SECRET_LEASES_LIST_TOOL
                | DYNAMIC_SECRET_LEASES_GET_TOOL
        )
    }

    fn assert_catalog_contracts(tools: &[Tool]) {
        for tool in tools {
            assert!(tool.title.as_deref().is_some_and(|title| !title.is_empty()));
            assert!(
                tool.description
                    .as_deref()
                    .is_some_and(|description| !description.is_empty())
            );
            assert_eq!(
                tool.input_schema.get("additionalProperties"),
                Some(&Value::Bool(false)),
                "{} input must reject unknown fields",
                tool.name
            );
            let output_schema = tool.output_schema.as_ref().expect("output schema required");
            // A tool result travels in `structuredContent`, which MCP defines
            // as a JSON object, so an output schema must have an object root.
            // A top-level array or a bare `oneOf` is unsatisfiable, and a
            // strict client rejects the WHOLE `tools/list` response over one
            // offending tool — taking the entire catalog down, not just this
            // tool. `Vec<T>` outputs need a named wrapper struct; internally
            // tagged enums need an explicit `extend("type" = "object")`.
            assert_eq!(
                output_schema.get("type"),
                Some(&Value::String("object".to_owned())),
                "{} output schema root must be type: \"object\"",
                tool.name
            );
            let annotations = tool.annotations.as_ref().expect("annotations required");
            assert_eq!(annotations.title, tool.title);
            let has_side_effect = is_catalog_mutation(tool.name.as_ref())
                || is_catalog_observable_read(tool.name.as_ref());
            assert_eq!(annotations.read_only_hint, Some(!has_side_effect));
            assert_eq!(
                annotations.destructive_hint,
                Some(is_catalog_destructive(tool.name.as_ref()))
            );
            assert_eq!(annotations.idempotent_hint, Some(!has_side_effect));
            assert_eq!(
                annotations.open_world_hint,
                Some(!matches!(
                    tool.name.as_ref(),
                    "server.info" | "server.capabilities" | "types.describe"
                ))
            );
        }
    }

    fn assert_sensitive_output_schemas(tools: &[Tool]) {
        assert_secret_output_boundaries(tools);
    }

    /// `server.info` pins its identity in the schema, not only in its result.
    fn assert_server_info_output_schema(tools: &[Tool]) {
        let server_info = tools
            .iter()
            .find(|tool| tool.name == SERVER_INFO_TOOL)
            .expect("the published catalog reports this server's identity");
        let output_schema = server_info.output_schema.as_ref().unwrap();
        let properties = output_schema["properties"]
            .as_object()
            .expect("output properties");

        assert_eq!(properties["name"]["const"], MCP_SERVER_NAME);
        assert_eq!(properties["protocolVersion"]["const"], MCP_PROTOCOL_VERSION);
        assert_eq!(properties["transport"]["const"], "streamable-http");
        assert!(properties.values().all(|property| {
            property["description"]
                .as_str()
                .is_some_and(|description| !description.is_empty())
        }));
        assert!(properties["version"]["pattern"].as_str().is_some());
    }

    fn assert_generated_credential_schemas(tools: &[Tool]) {
        let generated_client_secret = tools
            .iter()
            .find(|tool| tool.name == UNIVERSAL_AUTH_CLIENT_SECRETS_CREATE_TOOL)
            .unwrap();
        assert!(
            generated_client_secret.output_schema.as_ref().unwrap()["properties"]
                .get("clientSecret")
                .is_some(),
            "client-secret creation must declare its one-time sensitive output"
        );
        let generated_token = tools
            .iter()
            .find(|tool| tool.name == TOKEN_AUTH_TOKENS_CREATE_TOOL)
            .unwrap();
        assert!(
            generated_token.output_schema.as_ref().unwrap()["properties"]
                .get("accessToken")
                .is_some(),
            "Token Auth creation must declare its one-time sensitive output"
        );
        let generated_dynamic_secret = tools
            .iter()
            .find(|tool| tool.name == tools::DYNAMIC_SECRET_LEASES_CREATE_TOOL)
            .unwrap();
        assert_eq!(
            generated_dynamic_secret.output_schema.as_ref().unwrap()["properties"]["provider"]["const"],
            "sqlDatabase"
        );
        assert!(
            generated_dynamic_secret.output_schema.as_ref().unwrap()["properties"]
                .get("password")
                .is_some(),
            "dynamic-secret lease creation must declare its one-time sensitive output"
        );
        let generated_sql_rotation = tools
            .iter()
            .find(|tool| tool.name == SQL_SECRET_ROTATION_GENERATED_CREDENTIALS_GET_TOOL)
            .unwrap();
        let generated_sql_rotation_schema =
            serde_json::to_string(generated_sql_rotation.output_schema.as_ref().unwrap()).unwrap();
        assert!(generated_sql_rotation_schema.contains("\"password\""));
        assert!(generated_sql_rotation_schema.contains("\"activeIndex\""));
        let issued_ssh_certificate = tools
            .iter()
            .find(|tool| tool.name == SSH_CERTIFICATES_ISSUE_TOOL)
            .unwrap();
        assert!(
            issued_ssh_certificate.output_schema.as_ref().unwrap()["properties"]
                .get("privateKey")
                .is_some(),
            "SSH certificate issuance must declare its one-time private-key output"
        );
        let issued_certificate = tools
            .iter()
            .find(|tool| tool.name == CERTIFICATES_ISSUE_TOOL)
            .unwrap();
        assert!(
            issued_certificate.output_schema.as_ref().unwrap()["properties"]
                .get("privateKey")
                .is_some(),
            "certificate issuance must declare its managed private-key output"
        );
        for name in [
            UNIVERSAL_AUTH_CLIENT_SECRETS_LIST_TOOL,
            UNIVERSAL_AUTH_CLIENT_SECRETS_GET_TOOL,
            UNIVERSAL_AUTH_CLIENT_SECRETS_REVOKE_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                tool.output_schema.as_ref().unwrap()["properties"]
                    .get("clientSecret")
                    .is_none(),
                "{name} must not declare a client-secret value"
            );
        }
        for name in [
            TOKEN_AUTH_TOKENS_LIST_TOOL,
            TOKEN_AUTH_TOKENS_GET_TOOL,
            TOKEN_AUTH_TOKENS_UPDATE_TOOL,
            TOKEN_AUTH_TOKENS_REVOKE_TOOL,
            KUBERNETES_AUTH_GET_TOOL,
            KUBERNETES_AUTH_ATTACH_TOOL,
            KUBERNETES_AUTH_UPDATE_TOOL,
            KUBERNETES_AUTH_REMOVE_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                tool.output_schema.as_ref().unwrap()["properties"]
                    .get("accessToken")
                    .is_none(),
                "{name} must not declare an access-token value"
            );
        }
    }

    fn assert_secret_output_boundaries(tools: &[Tool]) {
        let secret_metadata = tools
            .iter()
            .find(|tool| tool.name == SECRET_METADATA_LIST_TOOL)
            .unwrap();
        assert!(
            !serde_json::to_string(secret_metadata.output_schema.as_ref().unwrap())
                .unwrap()
                .contains("secretValue")
        );
        let reveal = tools
            .iter()
            .find(|tool| tool.name == SECRET_REVEAL_TOOL)
            .unwrap();
        assert!(
            serde_json::to_string(reveal.output_schema.as_ref().unwrap())
                .unwrap()
                .contains("secretValue")
        );
        assert_generated_credential_schemas(tools);
        assert_kms_output_boundaries(tools);
        for name in [
            PROJECTS_CREATE_TOOL,
            PROJECTS_UPDATE_TOOL,
            PROJECTS_DELETE_TOOL,
            ENVIRONMENTS_CREATE_TOOL,
            ENVIRONMENTS_UPDATE_TOOL,
            ENVIRONMENTS_DELETE_TOOL,
            ENVIRONMENTS_RESTORE_TOOL,
            FOLDERS_GET_TOOL,
            FOLDERS_CREATE_TOOL,
            FOLDERS_UPDATE_TOOL,
            FOLDERS_BATCH_UPDATE_TOOL,
            FOLDERS_DELETE_TOOL,
            TAGS_GET_TOOL,
            TAGS_CREATE_TOOL,
            TAGS_UPDATE_TOOL,
            TAGS_DELETE_TOOL,
            IDENTITIES_LIST_TOOL,
            IDENTITIES_GET_TOOL,
            IDENTITIES_CREATE_TOOL,
            IDENTITIES_UPDATE_TOOL,
            IDENTITIES_DELETE_TOOL,
            PROJECT_USER_MEMBERSHIPS_LIST_TOOL,
            PROJECT_USER_MEMBERSHIPS_GET_TOOL,
            PROJECT_USER_MEMBERSHIPS_INVITE_TOOL,
            PROJECT_USER_MEMBERSHIPS_UPDATE_TOOL,
            PROJECT_USER_MEMBERSHIPS_DELETE_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_LIST_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_GET_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_CREATE_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_UPDATE_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_DELETE_TOOL,
            UNIVERSAL_AUTH_GET_TOOL,
            UNIVERSAL_AUTH_ATTACH_TOOL,
            UNIVERSAL_AUTH_UPDATE_TOOL,
            UNIVERSAL_AUTH_REMOVE_TOOL,
            UNIVERSAL_AUTH_CLIENT_SECRETS_LIST_TOOL,
            UNIVERSAL_AUTH_CLIENT_SECRETS_GET_TOOL,
            UNIVERSAL_AUTH_CLIENT_SECRETS_REVOKE_TOOL,
            TOKEN_AUTH_GET_TOOL,
            TOKEN_AUTH_ATTACH_TOOL,
            TOKEN_AUTH_UPDATE_TOOL,
            TOKEN_AUTH_REMOVE_TOOL,
            TOKEN_AUTH_TOKENS_LIST_TOOL,
            TOKEN_AUTH_TOKENS_GET_TOOL,
            TOKEN_AUTH_TOKENS_UPDATE_TOOL,
            TOKEN_AUTH_TOKENS_REVOKE_TOOL,
            UNIVERSAL_AUTH_LOCKOUTS_CLEAR_TOOL,
            SECRET_CREATE_TOOL,
            SECRET_UPDATE_TOOL,
            SECRET_DELETE_TOOL,
            SECRET_BATCH_CREATE_TOOL,
            SECRET_BATCH_UPDATE_TOOL,
            SECRET_BATCH_DELETE_TOOL,
            SECRET_IMPORTS_LIST_TOOL,
            AUDIT_LOGS_LIST_TOOL,
            SECRET_IMPORTS_GET_TOOL,
            SECRET_IMPORTS_CREATE_TOOL,
            SECRET_IMPORTS_UPDATE_TOOL,
            SECRET_IMPORTS_DELETE_TOOL,
            DYNAMIC_SECRETS_LIST_TOOL,
            DYNAMIC_SECRETS_GET_TOOL,
            tools::DYNAMIC_SECRETS_CREATE_TOOL,
            DYNAMIC_SECRET_LEASES_LIST_TOOL,
            DYNAMIC_SECRET_LEASES_GET_TOOL,
            DYNAMIC_SECRET_LEASES_RENEW_TOOL,
            DYNAMIC_SECRET_LEASES_REVOKE_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                !serde_json::to_string(tool.output_schema.as_ref().unwrap())
                    .unwrap()
                    .contains("secretValue"),
                "{name} output schema must stay value-free"
            );
        }
        assert_app_automation_output_boundaries(tools);
        assert_certificate_authority_output_boundaries(tools);
        assert_certificate_profile_output_boundaries(tools);
        assert_code_signer_output_boundaries(tools);
    }

    fn assert_code_signer_output_boundaries(tools: &[Tool]) {
        for name in [
            CODE_SIGNERS_LIST_TOOL,
            CODE_SIGNERS_GET_TOOL,
            CODE_SIGNERS_CREATE_TOOL,
            CODE_SIGNERS_UPDATE_TOOL,
            CODE_SIGNERS_DELETE_TOOL,
            CODE_SIGNERS_STATUS_UPDATE_TOOL,
            CODE_SIGNERS_CERTIFICATE_REISSUE_TOOL,
            CODE_SIGNERS_CERTIFICATE_EXPORT_TOOL,
            CODE_SIGNERS_PUBLIC_KEY_GET_TOOL,
            CODE_SIGNERS_SIGN_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            let encoded = serde_json::to_string(tool.output_schema.as_ref().unwrap()).unwrap();
            for secret_field in ["privateKey", "secretValue", "data"] {
                assert!(
                    !encoded.contains(&format!("\"{secret_field}\"")),
                    "{name} output schema exposed {secret_field}"
                );
            }
        }
    }

    fn assert_certificate_profile_output_boundaries(tools: &[Tool]) {
        for name in [
            CERTIFICATE_PROFILES_LIST_TOOL,
            CERTIFICATE_PROFILES_GET_TOOL,
            CERTIFICATE_PROFILES_GET_BY_SLUG_TOOL,
            CERTIFICATE_PROFILES_CREATE_TOOL,
            CERTIFICATE_PROFILES_UPDATE_TOOL,
            CERTIFICATE_PROFILES_DELETE_TOOL,
            CERTIFICATE_PROFILE_CERTIFICATES_LIST_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            let encoded = serde_json::to_string(tool.output_schema.as_ref().unwrap()).unwrap();
            for secret_field in ["privateKey", "eabSecret", "passphrase"] {
                assert!(
                    !encoded.contains(&format!("\"{secret_field}\"")),
                    "{name} output schema exposed {secret_field}"
                );
            }
        }
        for (name, secret_field) in [
            (CERTIFICATE_PROFILE_LATEST_BUNDLE_REVEAL_TOOL, "privateKey"),
            (CERTIFICATE_PROFILE_EAB_SECRET_REVEAL_TOOL, "eabSecret"),
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                serde_json::to_string(tool.output_schema.as_ref().unwrap())
                    .unwrap()
                    .contains(secret_field),
                "{name} must declare {secret_field} only at its explicit reveal boundary"
            );
        }
    }

    fn assert_certificate_authority_output_boundaries(tools: &[Tool]) {
        let general = tools
            .iter()
            .find(|tool| tool.name == CERTIFICATE_AUTHORITIES_LIST_TOOL)
            .unwrap();
        let general_schema =
            serde_json::to_string(general.output_schema.as_ref().unwrap()).unwrap();
        assert!(!general_schema.contains("configuration"));
        for name in [
            CERTIFICATE_AUTHORITIES_LIST_TOOL,
            INTERNAL_CERTIFICATE_AUTHORITIES_LIST_TOOL,
            INTERNAL_CERTIFICATE_AUTHORITIES_GET_TOOL,
            INTERNAL_CERTIFICATE_AUTHORITIES_CREATE_TOOL,
            INTERNAL_CERTIFICATE_AUTHORITIES_UPDATE_TOOL,
            INTERNAL_CERTIFICATE_AUTHORITIES_DELETE_TOOL,
            INTERNAL_CA_CSR_GET_TOOL,
            INTERNAL_CA_CERTIFICATES_LIST_TOOL,
            INTERNAL_CA_CERTIFICATE_GET_TOOL,
            INTERNAL_CA_CERTIFICATE_VERSION_GET_TOOL,
            INTERNAL_CA_CERTIFICATE_GENERATE_TOOL,
            INTERNAL_CA_CERTIFICATE_RENEW_TOOL,
            INTERNAL_CA_INTERMEDIATE_SIGN_TOOL,
            INTERNAL_CA_CERTIFICATE_IMPORT_TOOL,
            INTERNAL_CA_CRLS_LIST_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            let encoded = serde_json::to_string(tool.output_schema.as_ref().unwrap()).unwrap();
            for secret_field in ["privateKey", "encryptedPrivateKey", "apiKey", "credentials"] {
                assert!(
                    !encoded.contains(secret_field),
                    "{name} output schema exposed {secret_field}"
                );
            }
        }
    }

    fn assert_kms_output_boundaries(tools: &[Tool]) {
        for (name, secret_field) in [
            (KMS_DECRYPT_TOOL, "plaintext"),
            (KMS_PRIVATE_KEY_REVEAL_TOOL, "privateKey"),
            (KMS_PRIVATE_KEYS_BULK_REVEAL_TOOL, "privateKey"),
        ] {
            let schema = tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap()
                .output_schema
                .as_ref()
                .unwrap();
            assert!(
                serde_json::to_string(schema)
                    .unwrap()
                    .contains(secret_field),
                "{name} must declare {secret_field} only at its explicit reveal boundary"
            );
        }
        for name in [
            KMS_KEYS_LIST_TOOL,
            KMS_KEYS_GET_TOOL,
            KMS_KEYS_GET_BY_NAME_TOOL,
            KMS_KEYS_CREATE_TOOL,
            KMS_KEYS_UPDATE_TOOL,
            KMS_KEYS_DELETE_TOOL,
            KMS_ENCRYPT_TOOL,
            KMS_PUBLIC_KEY_GET_TOOL,
            KMS_KEYS_BULK_IMPORT_TOOL,
            KMS_SIGNING_ALGORITHMS_LIST_TOOL,
            KMS_SIGN_TOOL,
            KMS_VERIFY_TOOL,
        ] {
            let schema = tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap()
                .output_schema
                .as_ref()
                .unwrap();
            let encoded = serde_json::to_string(schema).unwrap();
            for secret_field in ["privateKey", "plaintext", "keyMaterial"] {
                assert!(
                    !encoded.contains(secret_field),
                    "{name} must not expose {secret_field}"
                );
            }
        }
    }

    fn assert_app_automation_output_boundaries(tools: &[Tool]) {
        for name in [
            GITHUB_APP_CONNECTION_GET_TOOL,
            GITHUB_APP_CONNECTION_CREATE_TOOL,
            GITHUB_APP_CONNECTION_UPDATE_TOOL,
            GITHUB_APP_CONNECTION_ROTATE_CREDENTIALS_TOOL,
            GITHUB_APP_CONNECTION_DELETE_TOOL,
            GITHUB_SECRET_SYNC_GET_TOOL,
            GITHUB_SECRET_SYNC_CREATE_TOOL,
            GITHUB_SECRET_SYNC_UPDATE_TOOL,
            GITHUB_SECRET_SYNC_DELETE_TOOL,
            GITHUB_SECRET_SYNC_RUN_TOOL,
            GITHUB_SECRET_SYNC_REMOVE_SECRETS_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            let encoded = serde_json::to_string(tool.output_schema.as_ref().unwrap()).unwrap();
            for secret_field in [
                "secretValue",
                "personalAccessToken",
                "accessToken",
                "installationId",
                "credentialsHash",
            ] {
                assert!(
                    !encoded.contains(secret_field),
                    "{name} output schema exposed {secret_field}"
                );
            }
        }
    }

    fn assert_sensitive_input_schemas(tools: &[Tool]) {
        assert_admin_input_schemas(tools);
        assert_folder_tag_input_schemas(tools);
        assert_identity_input_schemas(tools);
        assert_project_membership_input_schemas(tools);
        assert_universal_auth_input_schemas(tools);
        assert_token_auth_input_schemas(tools);
        assert_kubernetes_auth_input_schemas(tools);
        assert_certificate_authority_input_schemas(tools);
        assert_certificate_profile_input_schemas(tools);
        assert_code_signer_input_schemas(tools);
        assert_secret_input_schemas(tools);
        assert_secret_import_input_schemas(tools);
        assert_github_app_automation_input_schemas(tools);
        assert_kms_input_schemas(tools);
        assert_dynamic_secret_input_schemas(tools);
    }

    fn assert_certificate_authority_input_schemas(tools: &[Tool]) {
        for name in [
            INTERNAL_CERTIFICATE_AUTHORITIES_CREATE_TOOL,
            INTERNAL_CERTIFICATE_AUTHORITIES_UPDATE_TOOL,
            INTERNAL_CERTIFICATE_AUTHORITIES_DELETE_TOOL,
            INTERNAL_CA_CERTIFICATE_GENERATE_TOOL,
            INTERNAL_CA_CERTIFICATE_RENEW_TOOL,
            INTERNAL_CA_INTERMEDIATE_SIGN_TOOL,
            INTERNAL_CA_CERTIFICATE_IMPORT_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String("confirm".into())),
                "{name} must require confirm"
            );
        }
        let create = tools
            .iter()
            .find(|tool| tool.name == INTERNAL_CERTIFICATE_AUTHORITIES_CREATE_TOOL)
            .unwrap();
        assert_eq!(
            create.input_schema["$defs"]["CertificateAuthoritySubjectInput"]["additionalProperties"],
            false
        );
        assert_eq!(
            create.input_schema["properties"]["crlDistributionPointUrls"]["maxItems"],
            4
        );
    }

    fn assert_certificate_profile_input_schemas(tools: &[Tool]) {
        for (name, confirmation) in [
            (CERTIFICATE_PROFILES_CREATE_TOOL, "confirm"),
            (CERTIFICATE_PROFILES_UPDATE_TOOL, "confirm"),
            (CERTIFICATE_PROFILES_DELETE_TOOL, "confirm"),
            (
                CERTIFICATE_PROFILE_LATEST_BUNDLE_REVEAL_TOOL,
                "confirmReveal",
            ),
            (CERTIFICATE_PROFILE_EAB_SECRET_REVEAL_TOOL, "confirmReveal"),
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String(confirmation.into())),
                "{name} must require {confirmation}"
            );
        }
        let create = tools
            .iter()
            .find(|tool| tool.name == CERTIFICATE_PROFILES_CREATE_TOOL)
            .unwrap();
        let encoded = serde_json::to_string(&create.input_schema).unwrap();
        assert!(encoded.contains("passphrase"));
        assert!(encoded.contains("challengePassword"));
        assert_eq!(create.input_schema["additionalProperties"], false);

        let create_enrollment =
            &create.input_schema["$defs"]["CertificateProfileEnrollmentCreationInput"];
        assert_secret_schema_bounds(
            tagged_schema_variant(create_enrollment, "est"),
            "passphrase",
            1,
        );
        assert_secret_schema_bounds(
            tagged_schema_variant(create_enrollment, "scep"),
            "challengePassword",
            8,
        );

        let update = tools
            .iter()
            .find(|tool| tool.name == CERTIFICATE_PROFILES_UPDATE_TOOL)
            .unwrap();
        let update_enrollment =
            &update.input_schema["$defs"]["CertificateProfileEnrollmentChangeInput"];
        assert_secret_schema_bounds(
            tagged_schema_variant(update_enrollment, "est"),
            "passphrase",
            1,
        );
        assert_secret_schema_bounds(
            tagged_schema_variant(update_enrollment, "scep"),
            "challengePassword",
            8,
        );
    }

    fn assert_code_signer_input_schemas(tools: &[Tool]) {
        for name in [
            CODE_SIGNERS_CREATE_TOOL,
            CODE_SIGNERS_UPDATE_TOOL,
            CODE_SIGNERS_DELETE_TOOL,
            CODE_SIGNERS_STATUS_UPDATE_TOOL,
            CODE_SIGNERS_CERTIFICATE_REISSUE_TOOL,
            CODE_SIGNERS_SIGN_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String("confirm".into())),
                "{name} must require confirm"
            );
        }
        let create = tools
            .iter()
            .find(|tool| tool.name == CODE_SIGNERS_CREATE_TOOL)
            .unwrap();
        let source = &create.input_schema["$defs"]["CodeSignerCertificateSourceInput"];
        let encoded = serde_json::to_string(source).unwrap();
        assert!(encoded.contains("existing_certificate"));
        assert!(encoded.contains("internal_certificate_authority"));
        assert!(!encoded.contains("privateKey"));

        let sign = tools
            .iter()
            .find(|tool| tool.name == CODE_SIGNERS_SIGN_TOOL)
            .unwrap();
        assert_eq!(sign.input_schema["properties"]["data"]["minLength"], 4);
        assert_eq!(sign.input_schema["properties"]["data"]["maxLength"], 172);

        for name in [
            CODE_SIGNER_MEMBERS_ADD_TOOL,
            CODE_SIGNER_MEMBER_ROLE_UPDATE_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String("role".into())),
                "{name} must require role"
            );
        }
        let remove = tools
            .iter()
            .find(|tool| tool.name == CODE_SIGNER_MEMBERS_REMOVE_TOOL)
            .unwrap();
        assert!(remove.input_schema["properties"].get("role").is_none());
    }

    fn tagged_schema_variant<'a>(schema: &'a Value, tag: &str) -> &'a Value {
        schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| variant["properties"]["type"]["const"] == tag)
            .unwrap()
    }

    fn assert_secret_schema_bounds(schema: &Value, field: &str, minimum: u64) {
        let secret = &schema["properties"][field];
        assert_eq!(secret["minLength"], minimum);
        assert_eq!(secret["maxLength"], 4_096);
    }

    fn assert_kms_input_schemas(tools: &[Tool]) {
        let encrypt = tools
            .iter()
            .find(|tool| tool.name == KMS_ENCRYPT_TOOL)
            .unwrap();
        assert_eq!(
            encrypt.input_schema["properties"]["data"]["maxLength"],
            699_052
        );
        let decrypt = tools
            .iter()
            .find(|tool| tool.name == KMS_DECRYPT_TOOL)
            .unwrap();
        assert_eq!(
            decrypt.input_schema["properties"]["ciphertext"]["maxLength"],
            700_416
        );
        for (name, confirmation) in [
            (KMS_KEYS_CREATE_TOOL, "confirm"),
            (KMS_KEYS_UPDATE_TOOL, "confirm"),
            (KMS_KEYS_DELETE_TOOL, "confirm"),
            (KMS_ENCRYPT_TOOL, "confirm"),
            (KMS_DECRYPT_TOOL, "confirmReveal"),
            (KMS_PRIVATE_KEY_REVEAL_TOOL, "confirmReveal"),
            (KMS_KEYS_BULK_IMPORT_TOOL, "confirm"),
            (KMS_PRIVATE_KEYS_BULK_REVEAL_TOOL, "confirmReveal"),
            (KMS_SIGN_TOOL, "confirm"),
            (KMS_VERIFY_TOOL, "confirm"),
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String(confirmation.into())),
                "{name} must require {confirmation}"
            );
        }
        let import = tools
            .iter()
            .find(|tool| tool.name == KMS_KEYS_BULK_IMPORT_TOOL)
            .unwrap();
        assert_eq!(import.input_schema["properties"]["keys"]["minItems"], 1);
        assert_eq!(import.input_schema["properties"]["keys"]["maxItems"], 100);
        assert_eq!(
            import.input_schema["$defs"]["KmsBulkImportEntryInput"]["additionalProperties"],
            false
        );
    }

    fn assert_github_app_automation_input_schemas(tools: &[Tool]) {
        let create_connection = tools
            .iter()
            .find(|tool| tool.name == GITHUB_APP_CONNECTION_CREATE_TOOL)
            .unwrap();
        let encoded = serde_json::to_string(&create_connection.input_schema).unwrap();
        for field in ["code", "personalAccessToken", "installationId"] {
            assert!(encoded.contains(field), "missing {field} input contract");
        }
        assert!(encoded.contains("16384"));

        let update_connection = tools
            .iter()
            .find(|tool| tool.name == GITHUB_APP_CONNECTION_UPDATE_TOOL)
            .unwrap();
        assert_eq!(
            update_connection.input_schema["properties"]["confirmCredentialReplacement"]["default"],
            false
        );

        let rotate_connection = tools
            .iter()
            .find(|tool| tool.name == GITHUB_APP_CONNECTION_ROTATE_CREDENTIALS_TOOL)
            .unwrap();
        assert_eq!(
            rotate_connection.input_schema["properties"]["confirm"]["type"],
            "boolean"
        );
        assert!(
            rotate_connection.input_schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field == "confirm")
        );

        let create_sync = tools
            .iter()
            .find(|tool| tool.name == GITHUB_SECRET_SYNC_CREATE_TOOL)
            .unwrap();
        assert_eq!(
            create_sync.input_schema["properties"]["confirmInitialOverwrite"]["type"],
            "boolean"
        );
        assert_eq!(
            create_sync.input_schema["properties"]["secretPath"]["maxLength"],
            2_048
        );

        let delete_sync = tools
            .iter()
            .find(|tool| tool.name == GITHUB_SECRET_SYNC_DELETE_TOOL)
            .unwrap();
        for field in ["confirmDelete", "confirmRemoteRemoval", "removeSecrets"] {
            assert!(
                delete_sync.input_schema["properties"][field].is_object(),
                "missing {field} safety input"
            );
        }
    }

    fn assert_dynamic_secret_input_schemas(tools: &[Tool]) {
        let list = tools
            .iter()
            .find(|tool| tool.name == DYNAMIC_SECRETS_LIST_TOOL)
            .unwrap();
        let scope = &list.input_schema["$defs"]["DynamicSecretScopeInput"]["properties"];
        assert_eq!(scope["projectSlug"]["maxLength"], 64);
        assert_eq!(scope["environmentSlug"]["maxLength"], 64);
        assert_eq!(scope["path"]["maxLength"], 2_048);

        let renew = tools
            .iter()
            .find(|tool| tool.name == DYNAMIC_SECRET_LEASES_RENEW_TOOL)
            .unwrap();
        assert_eq!(
            renew.input_schema["properties"]["ttlSeconds"]["minimum"],
            60
        );
        assert_eq!(
            renew.input_schema["properties"]["ttlSeconds"]["maximum"],
            315_360_000
        );

        let revoke = tools
            .iter()
            .find(|tool| tool.name == DYNAMIC_SECRET_LEASES_REVOKE_TOOL)
            .unwrap();
        assert_eq!(revoke.input_schema["properties"]["force"]["default"], false);
        let required = revoke.input_schema["required"].as_array().unwrap();
        assert!(required.contains(&Value::String("confirm".into())));
        assert!(required.contains(&Value::String("leaseId".into())));
        assert!(required.contains(&Value::String("scope".into())));

        let update = tools
            .iter()
            .find(|tool| tool.name == tools::DYNAMIC_SECRETS_UPDATE_TOOL)
            .unwrap();
        let update_schema = serde_json::to_string(&update.input_schema).unwrap();
        assert!(update_schema.contains("defaultTtlSeconds"));
        assert!(update_schema.contains("maxTtlSeconds"));
        assert!(!update_schema.contains("\"inputs\""));
        assert!(!update_schema.contains("\"metadata\""));

        let delete = tools
            .iter()
            .find(|tool| tool.name == tools::DYNAMIC_SECRETS_DELETE_TOOL)
            .unwrap();
        assert_eq!(delete.input_schema["properties"]["force"]["default"], false);
        let required = delete.input_schema["required"].as_array().unwrap();
        assert!(required.contains(&Value::String("confirm".into())));
        assert!(required.contains(&Value::String("target".into())));

        let create = tools
            .iter()
            .find(|tool| tool.name == tools::DYNAMIC_SECRETS_CREATE_TOOL)
            .unwrap();
        let sql_inputs = &create.input_schema["$defs"]["SqlDynamicSecretProviderInputsInput"];
        assert_eq!(sql_inputs["additionalProperties"], false);
        assert_eq!(sql_inputs["properties"]["password"]["maxLength"], 16_384);
        assert_eq!(
            sql_inputs["properties"]["creationStatement"]["maxLength"],
            16_384
        );
        let provider_variants = create.input_schema["$defs"]["DynamicSecretProviderInput"]["oneOf"]
            .as_array()
            .expect("provider-tagged dynamic-secret variants");
        assert_eq!(provider_variants.len(), 1);
        assert_eq!(provider_variants[0]["additionalProperties"], false);
    }

    fn assert_identity_input_schemas(tools: &[Tool]) {
        let create = tools
            .iter()
            .find(|tool| tool.name == IDENTITIES_CREATE_TOOL)
            .unwrap();
        assert_eq!(
            create.input_schema["properties"]["role"]["default"],
            "no-access"
        );
        assert_eq!(
            create.input_schema["properties"]["deleteProtection"]["default"],
            true
        );
        let update = tools
            .iter()
            .find(|tool| tool.name == IDENTITIES_UPDATE_TOOL)
            .unwrap();
        let variants = update.input_schema["$defs"]["IdentityChangeInput"]["oneOf"]
            .as_array()
            .expect("tagged identity change variants");
        assert_eq!(variants.len(), 3);
        assert!(variants.iter().all(|variant| {
            variant["additionalProperties"] == false
                && variant["required"]
                    .as_array()
                    .is_some_and(|required| required.contains(&Value::String("kind".into())))
        }));
        let delete = tools
            .iter()
            .find(|tool| tool.name == IDENTITIES_DELETE_TOOL)
            .unwrap();
        assert!(
            delete.input_schema["required"]
                .as_array()
                .unwrap()
                .contains(&Value::String("confirm".into()))
        );
    }

    fn assert_project_membership_input_schemas(tools: &[Tool]) {
        let invite = tools
            .iter()
            .find(|tool| tool.name == PROJECT_USER_MEMBERSHIPS_INVITE_TOOL)
            .unwrap();
        assert_eq!(invite.input_schema["properties"]["emails"]["maxItems"], 50);
        assert_eq!(
            invite.input_schema["properties"]["usernames"]["maxItems"],
            50
        );
        assert_eq!(invite.input_schema["properties"]["roles"]["minItems"], 1);
        assert_eq!(invite.input_schema["properties"]["roles"]["maxItems"], 10);
        for name in [
            PROJECT_USER_MEMBERSHIPS_UPDATE_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_CREATE_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_UPDATE_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert_eq!(tool.input_schema["properties"]["roles"]["minItems"], 1);
            assert_eq!(tool.input_schema["properties"]["roles"]["maxItems"], 10);
        }
        for name in [
            PROJECT_USER_MEMBERSHIPS_DELETE_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_DELETE_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String("confirm".into()))
            );
        }
        for name in [
            PROJECT_USER_MEMBERSHIPS_UPDATE_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_UPDATE_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String("confirmReplaceAllRoles".into()))
            );
        }
    }

    fn assert_universal_auth_input_schemas(tools: &[Tool]) {
        let attach = tools
            .iter()
            .find(|tool| tool.name == UNIVERSAL_AUTH_ATTACH_TOOL)
            .unwrap();
        let properties = &attach.input_schema["properties"];
        assert_eq!(properties["accessTokenTTL"]["default"], 2_592_000);
        assert_eq!(properties["accessTokenMaxTTL"]["default"], 2_592_000);
        assert_eq!(properties["lockoutEnabled"]["default"], true);
        assert_eq!(properties["lockoutThreshold"]["default"], 3);
        assert_eq!(properties["lockoutDurationSeconds"]["default"], 300);
        assert_eq!(properties["lockoutCounterResetSeconds"]["default"], 30);
        assert!(properties.get("clientSecretTrustedIps").is_none());
        assert!(properties.get("accessTokenTrustedIps").is_none());

        let update = tools
            .iter()
            .find(|tool| tool.name == UNIVERSAL_AUTH_UPDATE_TOOL)
            .unwrap();
        let variants = update.input_schema["$defs"]["UniversalAuthChangeInput"]["oneOf"]
            .as_array()
            .expect("tagged Universal Auth change variants");
        assert_eq!(variants.len(), 3);
        assert!(variants.iter().all(|variant| {
            variant["additionalProperties"] == false
                && variant["required"]
                    .as_array()
                    .is_some_and(|required| required.contains(&Value::String("kind".into())))
        }));

        for name in [
            UNIVERSAL_AUTH_REMOVE_TOOL,
            UNIVERSAL_AUTH_CLIENT_SECRETS_REVOKE_TOOL,
            UNIVERSAL_AUTH_LOCKOUTS_CLEAR_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String("confirm".into())),
                "{name} must require explicit confirmation"
            );
        }
        let client_secret_create = tools
            .iter()
            .find(|tool| tool.name == UNIVERSAL_AUTH_CLIENT_SECRETS_CREATE_TOOL)
            .unwrap();
        let required = client_secret_create.input_schema["required"]
            .as_array()
            .unwrap();
        for field in ["identityId", "numUsesLimit", "ttl"] {
            assert!(
                required.contains(&Value::String(field.into())),
                "client-secret creation must require an explicit {field}"
            );
        }
    }

    fn assert_token_auth_input_schemas(tools: &[Tool]) {
        let attach = tools
            .iter()
            .find(|tool| tool.name == TOKEN_AUTH_ATTACH_TOOL)
            .unwrap();
        let required = attach.input_schema["required"].as_array().unwrap();
        for field in [
            "identityId",
            "accessTokenTTL",
            "accessTokenMaxTTL",
            "accessTokenNumUsesLimit",
        ] {
            assert!(
                required.contains(&Value::String(field.into())),
                "Token Auth attachment must require explicit {field}"
            );
        }
        assert!(
            attach.input_schema["properties"]
                .as_object()
                .unwrap()
                .get("accessTokenTrustedIps")
                .is_none()
        );

        let update = tools
            .iter()
            .find(|tool| tool.name == TOKEN_AUTH_UPDATE_TOOL)
            .unwrap();
        let variants = update.input_schema["$defs"]["TokenAuthChangeInput"]["oneOf"]
            .as_array()
            .expect("tagged Token Auth change variants");
        assert_eq!(variants.len(), 2);
        assert!(variants.iter().all(|variant| {
            variant["additionalProperties"] == false
                && variant["required"]
                    .as_array()
                    .is_some_and(|required| required.contains(&Value::String("kind".into())))
        }));

        for name in [TOKEN_AUTH_REMOVE_TOOL, TOKEN_AUTH_TOKENS_REVOKE_TOOL] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String("confirm".into())),
                "{name} must require explicit confirmation"
            );
        }
    }

    fn assert_kubernetes_auth_input_schemas(tools: &[Tool]) {
        let attach = tools
            .iter()
            .find(|tool| tool.name == KUBERNETES_AUTH_ATTACH_TOOL)
            .unwrap();
        let required = attach.input_schema["required"].as_array().unwrap();
        for field in [
            "identityId",
            "kubernetesHost",
            "verifyTlsCertificate",
            "allowedNamespaces",
            "allowedNames",
            "allowedAudience",
            "accessTokenTTL",
            "accessTokenMaxTTL",
            "accessTokenNumUsesLimit",
        ] {
            assert!(
                required.contains(&Value::String(field.into())),
                "Kubernetes Auth attachment must require explicit {field}"
            );
        }
        let properties = attach.input_schema["properties"].as_object().unwrap();
        assert!(properties.get("gatewayId").is_none());
        assert!(properties.get("gatewayPoolId").is_none());
        assert!(properties.get("accessTokenTrustedIps").is_none());
        assert_eq!(properties["kubernetesHost"]["maxLength"], 2_048);
        assert_eq!(properties["tokenReviewerJwt"]["maxLength"], 16_384);

        let update = tools
            .iter()
            .find(|tool| tool.name == KUBERNETES_AUTH_UPDATE_TOOL)
            .unwrap();
        let variants = update.input_schema["$defs"]["KubernetesAuthChangeInput"]["oneOf"]
            .as_array()
            .expect("tagged Kubernetes Auth change variants");
        assert_eq!(variants.len(), 4);
        assert!(variants.iter().all(|variant| {
            variant["additionalProperties"] == false
                && variant["required"]
                    .as_array()
                    .is_some_and(|required| required.contains(&Value::String("kind".into())))
        }));

        let remove = tools
            .iter()
            .find(|tool| tool.name == KUBERNETES_AUTH_REMOVE_TOOL)
            .unwrap();
        assert!(
            remove.input_schema["required"]
                .as_array()
                .unwrap()
                .contains(&Value::String("confirm".into()))
        );
    }

    fn assert_admin_input_schemas(tools: &[Tool]) {
        let project_create = tools
            .iter()
            .find(|tool| tool.name == PROJECTS_CREATE_TOOL)
            .unwrap();
        assert_eq!(
            project_create.input_schema["properties"]["createDefaultEnvironments"]["default"],
            true
        );
        assert_eq!(
            project_create.input_schema["properties"]["deleteProtection"]["default"],
            true
        );
        assert_eq!(
            project_create.input_schema["properties"]["kind"]["default"],
            "secret-manager"
        );
        for name in [
            PROJECTS_DELETE_TOOL,
            ENVIRONMENTS_DELETE_TOOL,
            FOLDERS_DELETE_TOOL,
            TAGS_DELETE_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String("confirm".into())),
                "{name} must require explicit confirmation"
            );
        }
        for (name, definition, variant_count) in [
            (PROJECTS_UPDATE_TOOL, "ProjectChangeInput", 8),
            (ENVIRONMENTS_UPDATE_TOOL, "EnvironmentChangeInput", 3),
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            let variants = tool.input_schema["$defs"][definition]["oneOf"]
                .as_array()
                .expect("tagged administrative change variants");
            assert_eq!(variants.len(), variant_count, "{name} change variants");
            assert!(variants.iter().all(|variant| {
                variant["additionalProperties"] == false
                    && variant["required"]
                        .as_array()
                        .is_some_and(|required| required.contains(&Value::String("kind".into())))
            }));
        }
        for name in [ENVIRONMENTS_UPDATE_TOOL, ENVIRONMENTS_DELETE_TOOL] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert_definition_properties(
                &tool.input_schema,
                "EnvironmentTargetInput",
                &["environmentId", "projectId"],
            );
            assert_eq!(
                tool.input_schema["$defs"]["EnvironmentTargetInput"]["additionalProperties"],
                false
            );
        }
    }

    fn assert_folder_tag_input_schemas(tools: &[Tool]) {
        let folder_delete = tools
            .iter()
            .find(|tool| tool.name == FOLDERS_DELETE_TOOL)
            .unwrap();
        assert_eq!(
            folder_delete.input_schema["properties"]["forceDelete"]["default"],
            false
        );
        for name in [FOLDERS_UPDATE_TOOL, FOLDERS_DELETE_TOOL] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert_definition_properties(
                &tool.input_schema,
                "FolderTargetInput",
                &["folderId", "parent"],
            );
            assert_definition_properties(
                &tool.input_schema,
                "FolderParentInput",
                &["environment", "path", "projectId"],
            );
        }
        let folder_update = tools
            .iter()
            .find(|tool| tool.name == FOLDERS_UPDATE_TOOL)
            .unwrap();
        assert!(
            folder_update.input_schema["required"]
                .as_array()
                .unwrap()
                .contains(&Value::String("description".into()))
        );
        let folder_batch = tools
            .iter()
            .find(|tool| tool.name == FOLDERS_BATCH_UPDATE_TOOL)
            .unwrap();
        assert_eq!(
            folder_batch.input_schema["properties"]["folders"]["minItems"],
            1
        );
        assert_eq!(
            folder_batch.input_schema["properties"]["folders"]["maxItems"],
            50
        );
        assert!(
            folder_batch.input_schema["$defs"]["FolderBatchUpdateEntryInput"]["required"]
                .as_array()
                .unwrap()
                .contains(&Value::String("description".into()))
        );
        let tag_create = tools
            .iter()
            .find(|tool| tool.name == TAGS_CREATE_TOOL)
            .unwrap();
        assert_eq!(
            tag_create.input_schema["properties"]["color"]["default"],
            ""
        );
        let tag_get = tools
            .iter()
            .find(|tool| tool.name == TAGS_GET_TOOL)
            .unwrap();
        let selectors = tag_get.input_schema["$defs"]["TagSelectorInput"]["oneOf"]
            .as_array()
            .expect("tag selector variants");
        assert_eq!(selectors.len(), 2);
        assert!(selectors.iter().all(|selector| {
            selector["additionalProperties"] == false
                && selector["required"]
                    .as_array()
                    .is_some_and(|required| required.contains(&Value::String("kind".into())))
        }));
    }

    fn assert_secret_input_schemas(tools: &[Tool]) {
        // secretValue and secretValueFile are an exactly-one pair enforced at parse
        // time, so neither is schema-required; both must be offered, and the file
        // reference must carry the annotation an intermediary delivers against.
        for name in [SECRET_CREATE_TOOL, SECRET_UPDATE_TOOL] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            let required = tool.input_schema["required"].as_array().unwrap();
            assert!(required.contains(&Value::String("target".into())));
            assert!(!required.contains(&Value::String("secretValue".into())));
            let properties = tool.input_schema["properties"].as_object().unwrap();
            assert!(properties.contains_key("secretValue"));
            let property = properties
                .get("secretValueFile")
                .expect("a secretValueFile schema is published");
            // An optional field nests its reference as anyOf [$ref, null].
            let reference = property
                .get("$ref")
                .or_else(|| property.pointer("/anyOf/0/$ref"))
                .and_then(Value::as_str);
            let file = match reference {
                Some(reference) => {
                    let name = reference
                        .strip_prefix("#/$defs/")
                        .expect("local schema reference");
                    &tool.input_schema["$defs"][name]
                }
                None => property,
            };
            assert_eq!(
                file.pointer("/x-mcp-file/transferModes/0"),
                Some(&Value::String("upload".into())),
                "the file input must be discoverable by a file-aware intermediary"
            );
        }
        for name in [SECRET_BATCH_CREATE_TOOL, SECRET_BATCH_UPDATE_TOOL] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            assert_eq!(tool.input_schema["properties"]["secrets"]["minItems"], 1);
            assert_eq!(tool.input_schema["properties"]["secrets"]["maxItems"], 50);
            let entry = &tool.input_schema["$defs"]["SecretBatchValueInput"];
            assert!(
                entry["required"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String("secretValue".into()))
            );
        }
        let delete = tools
            .iter()
            .find(|tool| tool.name == SECRET_DELETE_TOOL)
            .unwrap();
        assert!(
            delete.input_schema["required"]
                .as_array()
                .unwrap()
                .contains(&Value::String("confirm".into()))
        );
        let batch_delete = tools
            .iter()
            .find(|tool| tool.name == SECRET_BATCH_DELETE_TOOL)
            .unwrap();
        assert_eq!(
            batch_delete.input_schema["properties"]["names"]["minItems"],
            1
        );
        assert_eq!(
            batch_delete.input_schema["properties"]["names"]["maxItems"],
            50
        );
        assert!(
            batch_delete.input_schema["required"]
                .as_array()
                .unwrap()
                .contains(&Value::String("confirm".into()))
        );
    }

    fn assert_secret_import_input_schemas(tools: &[Tool]) {
        let import_delete = tools
            .iter()
            .find(|tool| tool.name == SECRET_IMPORTS_DELETE_TOOL)
            .unwrap();
        assert!(
            import_delete.input_schema["required"]
                .as_array()
                .unwrap()
                .contains(&Value::String("confirm".into()))
        );
        let import_update = tools
            .iter()
            .find(|tool| tool.name == SECRET_IMPORTS_UPDATE_TOOL)
            .unwrap();
        let variants = import_update.input_schema["$defs"]["SecretImportChangeInput"]["oneOf"]
            .as_array()
            .expect("tagged import change variants");
        assert_eq!(variants.len(), 2);
        let position = variants
            .iter()
            .find(|variant| variant["properties"]["kind"]["const"] == "position")
            .expect("position change variant");
        assert_eq!(position["properties"]["position"]["minimum"], 1);
        assert_eq!(position["properties"]["position"]["maximum"], 100_000);
        assert_eq!(position["additionalProperties"], false);
        let source = variants
            .iter()
            .find(|variant| variant["properties"]["kind"]["const"] == "source")
            .expect("source change variant");
        assert_eq!(source["additionalProperties"], false);
        for required in ["kind", "environment", "path"] {
            assert!(
                source["required"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String(required.into()))
            );
        }
    }

    fn assert_pagination_schema_bounds(tools: &[Tool]) {
        for name in [
            "projects.list",
            "environments.list",
            "folders.list",
            "tags.list",
            IDENTITIES_LIST_TOOL,
            PROJECT_USER_MEMBERSHIPS_LIST_TOOL,
            PROJECT_IDENTITY_MEMBERSHIPS_LIST_TOOL,
            UNIVERSAL_AUTH_CLIENT_SECRETS_LIST_TOOL,
            "secrets.metadata.list",
            SECRET_IMPORTS_LIST_TOOL,
            APP_CONNECTIONS_LIST_TOOL,
            SECRET_SYNCS_LIST_TOOL,
            SECRET_ROTATIONS_LIST_TOOL,
            CERTIFICATE_PROFILES_LIST_TOOL,
            CERTIFICATE_PROFILE_CERTIFICATES_LIST_TOOL,
            KMS_KEYS_LIST_TOOL,
            DYNAMIC_SECRETS_LIST_TOOL,
            DYNAMIC_SECRET_LEASES_LIST_TOOL,
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).unwrap();
            let properties = &tool.input_schema["properties"];
            assert_eq!(properties["offset"]["minimum"], 0, "{name} offset minimum");
            assert_eq!(
                properties["offset"]["maximum"], 100_000,
                "{name} offset maximum"
            );
            assert_eq!(properties["limit"]["minimum"], 1, "{name} limit minimum");
            assert_eq!(properties["limit"]["maximum"], 100, "{name} limit maximum");
            assert_eq!(properties["limit"]["default"], 50, "{name} limit default");
        }
        let token_list = tools
            .iter()
            .find(|tool| tool.name == TOKEN_AUTH_TOKENS_LIST_TOOL)
            .unwrap();
        let properties = &token_list.input_schema["properties"];
        assert_eq!(properties["offset"]["minimum"], 0);
        assert_eq!(properties["offset"]["maximum"], 100);
        assert_eq!(properties["limit"]["minimum"], 1);
        assert_eq!(properties["limit"]["maximum"], 100);
        assert_eq!(properties["limit"]["default"], 50);
    }

    #[test]
    fn published_catalog_reuses_immutable_schema_allocations() {
        let first = InfisicalMcp::list_tools_payload();
        let second = InfisicalMcp::list_tools_payload();

        assert_eq!(first.tools.len(), second.tools.len());
        for (first_tool, second_tool) in first.tools.iter().zip(&second.tools) {
            assert_eq!(first_tool.name, second_tool.name);
            assert!(
                Arc::ptr_eq(&first_tool.input_schema, &second_tool.input_schema),
                "{} input schema should be reused",
                first_tool.name
            );
            match (&first_tool.output_schema, &second_tool.output_schema) {
                (Some(first_schema), Some(second_schema)) => assert!(
                    Arc::ptr_eq(first_schema, second_schema),
                    "{} output schema should be reused",
                    first_tool.name
                ),
                (None, None) => {}
                _ => panic!("{} output schema presence changed", first_tool.name),
            }
        }
    }

    #[test]
    fn gateway_identifiers_are_stable() {
        assert_eq!(MCP_SERVER_NAME, "infisical");
        assert_eq!(MCP_ENDPOINT, "/mcp");
        assert_eq!(MCP_PROTOCOL_VERSION, "2025-11-25");
    }

    #[test]
    fn gateway_manifest_exactly_classifies_the_published_catalog() {
        let catalog = InfisicalMcp::list_tools_payload();
        let classifications =
            parse_gateway_manifest(include_str!("../../../gateway-manifest.yaml"));

        assert_eq!(
            classifications.len(),
            catalog.tools.len(),
            "every published tool requires one reviewed gateway classification"
        );
        for (classification, tool) in classifications.iter().zip(&catalog.tools) {
            assert_eq!(
                classification.name,
                tool.name.as_ref(),
                "gateway manifest must preserve catalog order"
            );
            assert_eq!(
                classification.risk,
                expected_gateway_risk(tool.name.as_ref()),
                "{} risk classification drifted",
                tool.name
            );
            assert_eq!(
                classification.pii,
                expected_gateway_pii(tool.name.as_ref()),
                "{} PII classification drifted",
                tool.name
            );
            let annotations = tool.annotations.as_ref().expect("annotations required");
            if annotations
                .destructive_hint
                .expect("destructive annotation required")
            {
                assert_eq!(
                    classification.risk, "high",
                    "{} destructive operations must be high risk",
                    tool.name
                );
            }
            assert_eq!(
                classification.side_effects,
                !annotations
                    .read_only_hint
                    .expect("read-only annotation required"),
                "{} side-effect classification must match the MCP semantic boundary",
                tool.name
            );
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct GatewayToolClassification<'a> {
        name: &'a str,
        risk: &'a str,
        side_effects: bool,
        pii: bool,
    }

    fn parse_gateway_manifest(manifest: &str) -> Vec<GatewayToolClassification<'_>> {
        let mut lines = manifest.lines();
        for expected in [
            "name: infisical",
            "transport: http",
            "url: http://infisical-mcp:8000/mcp",
            "auth:",
            "  bearer_env: MCP_GATEWAY_UPSTREAM_BEARER_INFISICAL",
            "session:",
            "  isolation: per_call",
            "  scope: per_principal",
            "tools:",
        ] {
            assert_eq!(
                lines.next(),
                Some(expected),
                "gateway manifest header drifted"
            );
        }

        let mut tools = Vec::new();
        while let Some(name_line) = lines.next() {
            let name = name_line
                .strip_prefix("  - name: ")
                .filter(|name| !name.is_empty())
                .expect("gateway tool name line");
            let risk = lines
                .next()
                .and_then(|line| line.strip_prefix("    risk: "))
                .filter(|risk| matches!(*risk, "low" | "high"))
                .expect("gateway tool risk must be low or high");
            let side_effects = parse_gateway_bool(
                lines
                    .next()
                    .and_then(|line| line.strip_prefix("    side_effects: "))
                    .expect("gateway tool side_effects line"),
            );
            let pii = parse_gateway_bool(
                lines
                    .next()
                    .and_then(|line| line.strip_prefix("    pii: "))
                    .expect("gateway tool pii line"),
            );
            tools.push(GatewayToolClassification {
                name,
                risk,
                side_effects,
                pii,
            });
        }
        tools
    }

    fn parse_gateway_bool(value: &str) -> bool {
        match value {
            "true" => true,
            "false" => false,
            _ => panic!("gateway manifest booleans must be true or false"),
        }
    }

    /// Risk a reviewer expects for one published tool.
    ///
    /// Derived here rather than read from production, so the manifest is
    /// checked against an independent statement of the policy instead of
    /// against the code that produced it.
    ///
    /// An executor carries every operation of its tier, and the gateway sees
    /// only the tool name, so each executor takes the highest risk any of its
    /// operations would have carried. Local discovery contacts nothing and
    /// returns no resource data.
    fn expected_gateway_risk(name: &str) -> &'static str {
        assert!(
            is_reviewed_gateway_family(name),
            "new tool family requires explicit gateway policy review: {name}"
        );
        if is_local_discovery(name) {
            "low"
        } else {
            "high"
        }
    }

    /// Whether a reviewer expects this published tool to carry personal data.
    ///
    /// Every executor can reach identity, membership, or audit records, so all
    /// four are marked. Local discovery returns build metadata and schemas.
    fn expected_gateway_pii(name: &str) -> bool {
        !is_local_discovery(name)
    }

    fn is_local_discovery(name: &str) -> bool {
        matches!(
            name,
            SERVER_INFO_TOOL
                | SERVER_CAPABILITIES_TOOL
                | OPERATIONS_LIST_TOOL
                | OPERATIONS_DESCRIBE_TOOL
                | TYPES_DESCRIBE_TOOL
        )
    }

    fn is_reviewed_gateway_family(name: &str) -> bool {
        is_local_discovery(name)
            || matches!(
                name,
                INFISICAL_READ_TOOL
                    | INFISICAL_READ_AUDITED_TOOL
                    | INFISICAL_WRITE_TOOL
                    | INFISICAL_DESTROY_TOOL
            )
    }

    #[test]
    #[should_panic(expected = "new tool family requires explicit gateway policy review")]
    fn gateway_policy_fails_closed_for_an_unknown_tool_family() {
        expected_gateway_risk("futureProvider.unreviewed");
    }

    /// Serialized `tools/list` ceiling, in bytes.
    ///
    /// A client's context window is fixed by its model provider, and the
    /// catalog is charged against that window before the caller's first
    /// message. This ceiling is a ratchet: it may be lowered as the published
    /// surface shrinks, and raising it means the catalog is displacing
    /// conversation the caller needs.
    const CATALOG_SERIALIZED_CEILING_BYTES: usize = 24_000;

    #[test]
    fn published_catalog_stays_within_the_serialized_ceiling() {
        let catalog = InfisicalMcp::list_tools_payload();
        let serialized =
            serde_json::to_string(&catalog).expect("catalog must serialize for a client");

        assert!(
            serialized.len() <= CATALOG_SERIALIZED_CEILING_BYTES,
            "serialized catalog is {} bytes, over the {CATALOG_SERIALIZED_CEILING_BYTES}-byte \
             ceiling; shrink the published surface rather than raising the ceiling",
            serialized.len()
        );
    }

    #[test]
    fn tool_surface_documentation_lists_exactly_the_served_operations() {
        // The operations are what drifts: they are no longer visible in the
        // catalog a client reads, so nothing else would catch a rename.
        let served: HashSet<String> = tools::operations()
            .into_iter()
            .map(|tiered| tiered.tool.name.to_string())
            .collect();
        let documented = parse_documented_tool_names(include_str!("../../../docs/tool-surface.md"));

        let mut undocumented: Vec<&str> = served
            .iter()
            .map(String::as_str)
            .filter(|name| !documented.contains(name))
            .collect();
        undocumented.sort_unstable();
        assert!(
            undocumented.is_empty(),
            "served operations missing from the documented surface: {undocumented:?}"
        );

        let mut unserved: Vec<&str> = documented
            .iter()
            .copied()
            .filter(|name| !served.contains(*name))
            .collect();
        unserved.sort_unstable();
        assert!(
            unserved.is_empty(),
            "documented operations this build does not serve: {unserved:?}"
        );
    }

    /// Collect the backticked tool names from the tool surface's current-catalog
    /// section.
    ///
    /// Scoping to that one section keeps prose elsewhere in the document, which
    /// legitimately mentions type names and individual tools, from being read as
    /// catalog membership.
    fn parse_documented_tool_names(surface: &str) -> HashSet<&str> {
        let section = surface
            .split_once("\n## Operations\n")
            .expect("tool surface must document the served operations")
            .1;
        let section = section
            .split_once("\n## ")
            .map_or(section, |(body, _)| body);

        section
            .split('`')
            .skip(1)
            .step_by(2)
            .filter(|token| is_tool_name(token))
            .collect()
    }

    #[test]
    fn documented_tool_parsing_reads_only_backticked_names_in_the_operations_section() {
        let surface = concat!(
            "# Tool surface\n",
            "\n## Catalog rules\n",
            "\nNames use `resource.action`; `outsideTheSection.get` is not membership.\n",
            "\n## Operations\n",
            "\nThe build registers `projects.list`, `secrets.reveal`, and\n",
            "`kms.keys.privateKey.reveal`. Ordinary `prose` and a bare `word` are\n",
            "not names.\n",
            "\n## App-automation inventory\n",
            "\n`laterSection.list` is outside the catalog.\n",
        );

        let documented = parse_documented_tool_names(surface);

        let mut names: Vec<&str> = documented.into_iter().collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "kms.keys.privateKey.reveal",
                "projects.list",
                "secrets.reveal"
            ]
        );
    }

    #[test]
    fn documented_tool_parsing_detects_a_name_dropped_from_the_operations_section() {
        let complete = concat!(
            "\n## Operations\n",
            "\nRegisters `projects.list` and `projects.get`.\n",
            "\n## Next\n",
        );
        let drifted = concat!(
            "\n## Operations\n",
            "\nRegisters `projects.list`.\n",
            "\n## Next\n",
        );

        let complete = parse_documented_tool_names(complete);
        let drifted = parse_documented_tool_names(drifted);

        assert!(complete.contains("projects.get"));
        assert!(
            !drifted.contains("projects.get"),
            "a name dropped from the documented catalog must be observable"
        );
    }

    /// Recognize a dotted `resource.action` tool identifier.
    ///
    /// Backticked prose in the catalog section also carries ordinary words, so
    /// membership requires the dotted shape every catalog name uses.
    fn is_tool_name(token: &str) -> bool {
        let mut segments = token.split('.');
        let well_formed = segments.all(|segment| {
            !segment.is_empty()
                && segment.starts_with(|first: char| first.is_ascii_alphabetic())
                && segment
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        });

        well_formed && token.contains('.')
    }

    #[test]
    fn gateway_policy_keeps_privileged_automation_and_dynamic_secret_operations_high() {
        // The gateway sees the executor, not the operation it carries, so an
        // executor must never be classified below anything reachable through
        // it. These operations were each individually high risk before the
        // surface collapsed, and their executors have to remain at least that
        // strong or the collapse would have quietly widened access.
        for name in [
            "appConnections.list",
            "appConnections.github.update",
            "secretSyncs.list",
            "secretSyncs.github.create",
            "secretSyncs.github.update",
            "secretSyncs.github.run",
            "secretRotations.list",
            "dynamicSecrets.list",
            "dynamicSecrets.get",
            "dynamicSecrets.create",
            "dynamicSecrets.update",
            "dynamicSecretLeases.list",
            "dynamicSecretLeases.get",
            "dynamicSecretLeases.create",
            "secrets.reveal",
            "kms.decrypt",
        ] {
            let tier = tools::tool_tier(name).unwrap_or_else(|| panic!("{name} must be served"));
            let executor = tier.executor();

            assert_eq!(
                expected_gateway_risk(executor),
                "high",
                "{name} is reachable through {executor}, which must stay high risk"
            );
            assert!(
                expected_gateway_pii(executor),
                "{name} is reachable through {executor}, which must stay marked for personal data"
            );
        }
    }

    #[test]
    fn every_operation_is_reachable_only_through_a_high_risk_executor() {
        // Collapsing the surface removed the gateway's ability to tell one
        // operation from another. Every operation therefore has to sit behind
        // an executor classified for the most sensitive thing that executor can
        // reach, which for all four is secret or personal data.
        for tiered in tools::operations() {
            let executor = tiered.tier.executor();

            assert_eq!(
                expected_gateway_risk(executor),
                "high",
                "{} is reachable through {executor}",
                tiered.tool.name
            );
            assert!(
                expected_gateway_pii(executor),
                "{} is reachable through {executor}",
                tiered.tool.name
            );
        }
    }

    #[test]
    fn operations_are_schema_complete_and_classified_by_side_effect() {
        // The operations are reached through executors rather than listed, but
        // their schemas and classifications are what an executor validates
        // against and what operations.describe hands to a caller.
        let operations: Vec<Tool> = tools::operations()
            .into_iter()
            .map(|tiered| tiered.tool)
            .collect();

        assert!(!operations.is_empty());
        assert_server_info_output_schema(&InfisicalMcp::list_tools_payload().tools);
        assert_catalog_identity(&operations);
        assert_catalog_contracts(&operations);
        assert_catalog_schema_fields(&operations);
        assert_sensitive_output_schemas(&operations);
        assert_sensitive_input_schemas(&operations);
        assert_pagination_schema_bounds(&operations);
    }

    #[test]
    fn server_advertises_the_pinned_protocol() {
        let info = mcp().get_info();

        assert_eq!(info.protocol_version.to_string(), MCP_PROTOCOL_VERSION);
        assert!(info.capabilities.tools.is_some());
        assert_eq!(info.instructions.as_deref(), Some(MCP_INSTRUCTIONS));
        assert!(
            MCP_INSTRUCTIONS.contains("secretRotations.sql.generatedCredentials.get"),
            "initialization guidance must name every credential-bearing tool"
        );
        for tool in [
            KMS_DECRYPT_TOOL,
            KMS_PRIVATE_KEY_REVEAL_TOOL,
            KMS_PRIVATE_KEYS_BULK_REVEAL_TOOL,
            CERTIFICATE_PROFILE_LATEST_BUNDLE_REVEAL_TOOL,
            CERTIFICATE_PROFILE_EAB_SECRET_REVEAL_TOOL,
            CERTIFICATE_REQUEST_RESULT_REVEAL_TOOL,
            CERTIFICATES_BUNDLE_REVEAL_TOOL,
            CERTIFICATES_PRIVATE_KEY_REVEAL_TOOL,
            CERTIFICATES_ISSUE_TOOL,
            SSH_CERTIFICATES_ISSUE_TOOL,
        ] {
            assert!(
                MCP_INSTRUCTIONS.contains(tool),
                "initialization guidance must name {tool}"
            );
        }
    }

    fn assert_discovery_capabilities(capabilities: &Value) {
        assert_eq!(capabilities["targetInfisicalVersion"], "0.160.12");
        let capabilities = capabilities["capabilities"].as_array().unwrap();
        let mut expected_names = HashSet::new();
        assert_core_capabilities(capabilities, &mut expected_names);
        assert_kms_capabilities(capabilities, &mut expected_names);
        assert_unavailable_capabilities(capabilities, &mut expected_names);
        assert_certificate_authority_capabilities(capabilities, &mut expected_names);
        assert_certificate_capabilities(capabilities, &mut expected_names);
        assert_certificate_request_capabilities(capabilities, &mut expected_names);
        assert_certificate_policy_capabilities(capabilities, &mut expected_names);
        assert_certificate_profile_capabilities(capabilities, &mut expected_names);
        assert_ssh_certificate_authority_capabilities(capabilities, &mut expected_names);
        assert_code_signer_capabilities(capabilities, &mut expected_names);

        let names = capabilities
            .iter()
            .map(|capability| capability["name"].as_str().unwrap().to_owned())
            .collect::<HashSet<_>>();
        assert_eq!(
            names.len(),
            capabilities.len(),
            "capability names must be unique"
        );
        assert_eq!(
            names, expected_names,
            "capability contract must be exhaustive"
        );
    }

    fn assert_core_capabilities(capabilities: &[Value], expected_names: &mut HashSet<String>) {
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "projects.read",
                "projects.create",
                "auditLogs.read",
                "projects.update",
                "projects.delete",
                "environments.read",
                "environments.create",
                "environments.update",
                "environments.delete",
                "environments.restore",
                "folders.read",
                "folders.create",
                "folders.update",
                "folders.batch.update",
                "folders.delete",
                "tags.read",
                "tags.create",
                "tags.update",
                "tags.delete",
                "identities.read",
                "identities.create",
                "identities.update",
                "identities.delete",
                "projectUserMemberships.read",
                "projectUserMemberships.invite",
                "projectUserMemberships.update",
                "projectUserMemberships.delete",
                "projectIdentityMemberships.read",
                "projectIdentityMemberships.create",
                "projectIdentityMemberships.update",
                "projectIdentityMemberships.delete",
                "projectRoles.read",
                "organizationRoles.read",
                "groups.read",
                "projectGroupMemberships.read",
                "identityProjectAdditionalPrivileges.read",
                "identityProjectAdditionalPrivileges.create",
                "identityProjectAdditionalPrivileges.update",
                "identityProjectAdditionalPrivileges.delete",
                "identityUniversalAuth.read",
                "identityUniversalAuth.attach",
                "identityUniversalAuth.update",
                "identityUniversalAuth.remove",
                "identityUniversalAuth.clientSecrets.read",
                "identityUniversalAuth.clientSecrets.create",
                "identityUniversalAuth.clientSecrets.revoke",
                "identityUniversalAuth.lockouts.clear",
                "identityTokenAuth.read",
                "identityTokenAuth.attach",
                "identityTokenAuth.update",
                "identityTokenAuth.remove",
                "identityTokenAuth.tokens.read",
                "identityTokenAuth.tokens.create",
                "identityTokenAuth.tokens.update",
                "identityTokenAuth.tokens.revoke",
                "identityKubernetesAuth.read",
                "identityKubernetesAuth.attach",
                "identityKubernetesAuth.update",
                "identityKubernetesAuth.remove",
                "secretImports.list",
                "secretImports.get",
                "secretImports.create",
                "secretImports.update",
                "secretImports.delete",
                "secretMetadata.read",
                "secrets.reveal",
                "secrets.create",
                "secrets.update",
                "secrets.delete",
                "secrets.batch.create",
                "secrets.batch.update",
                "secrets.batch.delete",
                "dynamicSecrets.read",
                "dynamicSecrets.create",
                "dynamicSecrets.updateSettings",
                "dynamicSecrets.delete",
                "dynamicSecretLeases.read",
                "dynamicSecretLeases.create",
                "dynamicSecretLeases.renew",
                "dynamicSecretLeases.revoke",
                "appConnections.read",
                "appConnections.github.admin",
                "appConnections.github.rotateCredentials",
                "secretSyncs.read",
                "secretSyncs.github.admin",
                "secretSyncs.github.run",
                "secretRotations.read",
                "secretRotations.sql.admin",
                "secretRotations.sql.generatedCredentials.read",
                "secretRotations.sql.rotate",
                "secretRotations.sql.checkCredentials",
            ],
            true,
        );
    }

    fn assert_kms_capabilities(capabilities: &[Value], expected_names: &mut HashSet<String>) {
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "kms.keys.read",
                "kms.keys.create",
                "kms.keys.update",
                "kms.keys.delete",
                "kms.keys.bulkImport",
                "kms.keys.privateMaterial.reveal",
                "kms.encrypt",
                "kms.decrypt",
                "kms.sign",
                "kms.verify",
            ],
            true,
        );
    }

    fn assert_unavailable_capabilities(
        capabilities: &[Value],
        expected_names: &mut HashSet<String>,
    ) {
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "secretImports.values.read",
                "secretImports.replicationResync",
                "secretVersions.read",
                "dynamicSecrets.create.providersExceptSqlDatabase",
                "dynamicSecrets.updateProviderInputs",
                "dynamicSecretLeases.create.providersExceptSqlDatabase",
                "secrets.rollback",
                "organizations.read",
                "organizations.admin",
                "identityUniversalAuth.trustedIps.update",
                "identityTokenAuth.trustedIps.update",
                "identityKubernetesAuth.trustedIps.update",
                "identityKubernetesAuth.gateway.update",
                "identityKubernetesAuth.gatewayPool.update",
                "identityAwsAuth.admin",
                "identityGcpAuth.admin",
                "identityAzureAuth.admin",
                "identityOidcAuth.admin",
                "identityJwtAuth.admin",
                "identityLdapAuth.admin",
                "identityOciAuth.admin",
                "identityAliCloudAuth.admin",
                "identityTlsCertificateAuth.admin",
                "identitySpiffeAuth.admin",
                "projectMemberships.temporaryRoles.update",
                "projectRoles.admin",
                "organizationRoles.admin",
                "groups.admin",
                "projectGroupMemberships.admin",
                "userProjectAdditionalPrivileges.read",
                "userProjectAdditionalPrivileges.admin",
                "appConnections.otherProviders.admin",
                "secretSyncs.otherDestinations.admin",
                "secretSyncs.github.import",
                "secretSyncs.otherDestinations.run",
                "secretRotations.otherProviders.lifecycle",
                "kms.postQuantum.entitlementDetection",
                "admin.bootstrap",
                "certificateTemplates.admin",
                "certificateSyncs.admin",
                "events.subscriptions",
                "externalMigrations.admin",
                "identities.search",
                "identityAuth.tokenMinting",
                "integrations.admin",
                "organizationGroupMemberships.admin",
                "organizationSso.admin",
                "organizationScim.admin",
                "pkiAlerts.admin",
                "pkiCollections.admin",
                "pkiDiscovery.admin",
                "pkiInstallations.admin",
                "projectTemplates.admin",
                "secretScanning.admin",
                "secrets.duplicate",
                "serviceTokens.read",
                "sharedSecrets.admin",
                "subOrganizations.admin",
                "users.read",
                "webhooks.admin",
            ],
            false,
        );
    }

    fn assert_certificate_authority_capabilities(
        capabilities: &[Value],
        expected_names: &mut HashSet<String>,
    ) {
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "certificateAuthorities.read",
                "certificateAuthorities.internal.create",
                "certificateAuthorities.internal.update",
                "certificateAuthorities.internal.delete",
                "certificateAuthorities.internal.certificateOperations",
            ],
            true,
        );
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "certificateAuthorities.external.admin",
                "certificateAuthorities.internal.signingConfig",
                "certificateAuthorities.internal.autoRenewal",
                "certificateAuthorities.internal.installExternalCertificate",
                "certificateAuthorities.der.read",
                "certificateAuthorities.deprecatedPkiRoutes",
            ],
            false,
        );
    }

    fn assert_certificate_profile_capabilities(
        capabilities: &[Value],
        expected_names: &mut HashSet<String>,
    ) {
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "certificateProfiles.read",
                "certificateProfiles.create",
                "certificateProfiles.update",
                "certificateProfiles.delete",
                "certificateProfiles.certificates.read",
                "certificateProfiles.latestActiveBundle.reveal",
                "certificateProfiles.acmeEabSecret.reveal",
            ],
            true,
        );
    }

    fn assert_certificate_capabilities(
        capabilities: &[Value],
        expected_names: &mut HashSet<String>,
    ) {
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "certificates.inventory",
                "certificates.issue",
                "certificates.renew",
                "certificates.revoke",
                "certificates.renewalConfiguration.update",
                "certificates.delete",
                "certificates.materialTransfer",
            ],
            true,
        );
    }

    fn assert_certificate_request_capabilities(
        capabilities: &[Value],
        expected_names: &mut HashSet<String>,
    ) {
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "certificateRequests.observe",
                "certificateRequests.result.reveal",
                "certificateRequests.cancel",
            ],
            true,
        );
    }

    fn assert_certificate_policy_capabilities(
        capabilities: &[Value],
        expected_names: &mut HashSet<String>,
    ) {
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "certificatePolicies.read",
                "certificatePolicies.create",
                "certificatePolicies.update",
                "certificatePolicies.delete",
            ],
            true,
        );
    }

    fn assert_ssh_certificate_authority_capabilities(
        capabilities: &[Value],
        expected_names: &mut HashSet<String>,
    ) {
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "sshCertificateAuthorities.read",
                "sshCertificateAuthorities.create",
                "sshCertificateAuthorities.replace",
                "sshCertificateAuthorities.delete",
                "sshCertificateTemplates.read",
                "sshCertificateTemplates.create",
                "sshCertificateTemplates.replace",
                "sshCertificateTemplates.delete",
                "sshCertificates.sign",
                "sshCertificates.issue",
                "sshHosts.read",
                "sshHosts.create",
                "sshHosts.replace",
                "sshHosts.delete",
                "sshHosts.hostCertificate.issue",
                "sshHostGroups.read",
                "sshHostGroups.create",
                "sshHostGroups.replace",
                "sshHostGroups.delete",
                "sshHostGroups.membership.change",
            ],
            true,
        );
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "sshHosts.globalInventory.read",
                "sshHosts.userCertificate.issue",
            ],
            false,
        );
    }

    fn assert_code_signer_capabilities(
        capabilities: &[Value],
        expected_names: &mut HashSet<String>,
    ) {
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "codeSigners.read",
                "codeSigners.create",
                "codeSigners.update",
                "codeSigners.delete",
                "codeSigners.status.update",
                "codeSigners.certificate.reissue.internal",
                "codeSigners.certificate.export",
                "codeSigners.publicKey.read",
                "codeSigners.sign",
                "codeSigners.members.read",
                "codeSigners.members.add",
                "codeSigners.members.role.update",
                "codeSigners.members.remove",
                "codeSigners.effectiveMembers.read",
                "codeSigners.permissions.read",
                "codeSigners.approvalPolicy.read",
                "codeSigners.approvalPolicy.replace",
                "codeSigners.approvalRequests.read",
                "codeSigners.approvalRequests.create",
                "codeSigners.approvalRequests.preApprove",
                "codeSigners.approvalRequests.revoke",
                "codeSigners.operations.read",
            ],
            true,
        );
        assert_capability_states(
            capabilities,
            expected_names,
            &[
                "codeSigners.certificate.issue.external",
                "codeSigners.certificate.reissue.external",
            ],
            false,
        );
    }

    fn assert_capability_states(
        capabilities: &[Value],
        expected_names: &mut HashSet<String>,
        names: &[&str],
        available: bool,
    ) {
        for &name in names {
            assert!(
                expected_names.insert(name.to_owned()),
                "duplicate expected capability {name}"
            );
            let capability = capabilities
                .iter()
                .find(|capability| capability["name"] == name)
                .unwrap();
            assert_eq!(capability["available"], available, "{name}");
            if available {
                assert!(capability.get("reason").is_none(), "{name}");
            } else {
                assert!(
                    capability["reason"]
                        .as_str()
                        .is_some_and(|reason| !reason.is_empty()),
                    "{name}"
                );
            }
        }
    }

    async fn assert_dynamic_secret_type_description(client: &InfisicalClient) {
        let request = CallToolRequestParams::new("types.describe").with_arguments(
            json!({ "typeName": "dynamicSecretLeaseDetails" })
                .as_object()
                .unwrap()
                .clone(),
        );
        let described = tools::dispatch_tool(client, None, request)
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(described["typeName"], "dynamicSecretLeaseDetails");
        assert!(described["schema"]["properties"]["lease"].is_object());

        let provider_request = CallToolRequestParams::new("types.describe").with_arguments(
            json!({ "typeName": "dynamicSecretProviderInput" })
                .as_object()
                .unwrap()
                .clone(),
        );
        let provider = tools::dispatch_tool(client, None, provider_request)
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(provider["typeName"], "dynamicSecretProviderInput");
        assert_eq!(provider["schema"]["oneOf"].as_array().unwrap().len(), 1);
    }

    async fn assert_github_app_automation_type_descriptions(client: &InfisicalClient) {
        let request = CallToolRequestParams::new("types.describe").with_arguments(
            json!({ "typeName": "githubAppConnectionInput" })
                .as_object()
                .unwrap()
                .clone(),
        );
        let connection = tools::dispatch_tool(client, None, request)
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(connection["typeName"], "githubAppConnectionInput");
        assert!(connection["schema"]["properties"]["credentials"].is_object());

        let request = CallToolRequestParams::new("types.describe").with_arguments(
            json!({ "typeName": "githubSecretSyncConfig" })
                .as_object()
                .unwrap()
                .clone(),
        );
        let sync = tools::dispatch_tool(client, None, request)
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(sync["typeName"], "githubSecretSyncConfig");
        assert!(sync["schema"]["properties"]["destination"].is_object());
    }

    async fn describe_type(client: &InfisicalClient, type_name: &str) -> Value {
        let request = CallToolRequestParams::new("types.describe").with_arguments(
            json!({ "typeName": type_name })
                .as_object()
                .unwrap()
                .clone(),
        );
        tools::dispatch_tool(client, None, request)
            .await
            .unwrap()
            .structured_content
            .unwrap()
    }

    async fn assert_ssh_host_type_descriptions(client: &InfisicalClient) {
        let host = describe_type(client, "sshHost").await;
        let host_schema = &host["schema"];
        assert_eq!(host["typeName"], "sshHost");
        for field in [
            "id",
            "projectId",
            "hostname",
            "alias",
            "userCertTtl",
            "hostCertTtl",
            "userSshCaId",
            "hostSshCaId",
            "loginMappings",
        ] {
            assert!(
                host_schema["properties"][field]["description"]
                    .as_str()
                    .is_some_and(|description| !description.is_empty()),
                "sshHost.{field} description"
            );
        }
        assert!(host_schema["properties"]["id"]["pattern"].is_string());
        assert_eq!(host_schema["properties"]["hostname"]["maxLength"], 253);
        assert_eq!(host_schema["properties"]["loginMappings"]["maxItems"], 128);
        assert!(host_schema["$defs"]["SshHostDuration"]["pattern"].is_string());

        let group = describe_type(client, "sshHostGroup").await;
        let group_schema = &group["schema"];
        assert!(group_schema["properties"]["id"]["description"].is_string());
        assert!(group_schema["properties"]["id"]["pattern"].is_string());
        assert_eq!(group_schema["properties"]["name"]["maxLength"], 64);
        assert_eq!(group_schema["properties"]["loginMappings"]["maxItems"], 64);

        let members = describe_type(client, "sshHostGroupMembers").await;
        let members_schema = &members["schema"];
        assert!(members_schema["properties"]["groupId"]["description"].is_string());
        assert!(members_schema["properties"]["groupId"]["pattern"].is_string());
        assert_eq!(members_schema["properties"]["totalCount"]["maximum"], 500);
        assert_eq!(members_schema["properties"]["hosts"]["maxItems"], 500);
        assert!(
            members_schema["$defs"]["SshHostGroupMember"]["properties"]["joinedGroupAt"]["pattern"]
                .is_string()
        );

        let receipt = describe_type(client, "sshHostGroupMembershipReceipt").await;
        assert!(receipt["schema"]["properties"]["hostId"]["description"].is_string());
        assert!(receipt["schema"]["properties"]["hostId"]["pattern"].is_string());
        assert_eq!(
            receipt["schema"]["properties"]["hostname"]["maxLength"],
            253
        );

        let linked_key = describe_type(client, "sshHostLinkedCaPublicKey").await;
        assert!(linked_key["schema"]["properties"]["caId"]["description"].is_string());
        assert!(linked_key["schema"]["properties"]["caId"]["pattern"].is_string());
        assert!(linked_key["schema"]["properties"]["publicKey"]["description"].is_string());

        let mapping = describe_type(client, "sshLoginMapping").await;
        assert!(mapping["schema"]["properties"]["loginUser"]["description"].is_string());
        assert!(mapping["schema"]["properties"]["loginUser"]["pattern"].is_string());
        assert_eq!(
            mapping["schema"]["$defs"]["SshAllowedPrincipals"]["properties"]["usernames"]["maxItems"],
            128
        );
    }

    #[tokio::test]
    async fn local_discovery_tools_return_structured_content_and_reject_bad_arguments() {
        let mcp = mcp();
        let result =
            tools::dispatch_tool(&mcp.client, None, CallToolRequestParams::new("server.info"))
                .await
                .expect("argument-free server.info succeeds");
        let structured = result
            .structured_content
            .expect("server.info has structured content");

        assert_eq!(structured["name"], MCP_SERVER_NAME);
        assert_eq!(structured["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert_eq!(structured["transport"], "streamable-http");
        assert_eq!(result.is_error, Some(false));

        let mut unexpected = Map::new();
        unexpected.insert("extra".into(), Value::Bool(true));
        let request = CallToolRequestParams::new("server.info").with_arguments(unexpected);
        assert!(
            tools::dispatch_tool(&mcp.client, None, request)
                .await
                .is_err()
        );

        let capabilities = tools::dispatch_tool(
            &mcp.client,
            None,
            CallToolRequestParams::new("server.capabilities"),
        )
        .await
        .unwrap()
        .structured_content
        .unwrap();
        assert_discovery_capabilities(&capabilities);
        assert_eq!(
            capabilities,
            super::server_capabilities_payload().expect("serialize capability registry")
        );

        let type_request = CallToolRequestParams::new("types.describe").with_arguments(
            json!({ "typeName": "project" })
                .as_object()
                .unwrap()
                .clone(),
        );
        let described = tools::dispatch_tool(&mcp.client, None, type_request)
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(described["typeName"], "project");
        assert!(described["schema"]["properties"]["id"].is_object());

        let import_type_request = CallToolRequestParams::new("types.describe").with_arguments(
            json!({ "typeName": "secretImport" })
                .as_object()
                .unwrap()
                .clone(),
        );
        let described_import = tools::dispatch_tool(&mcp.client, None, import_type_request)
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(described_import["typeName"], "secretImport");
        assert!(described_import["schema"]["properties"]["source"].is_object());

        assert_dynamic_secret_type_description(&mcp.client).await;

        assert_github_app_automation_type_descriptions(&mcp.client).await;

        let token_type_request = CallToolRequestParams::new("types.describe").with_arguments(
            json!({ "typeName": "tokenAuthToken" })
                .as_object()
                .unwrap()
                .clone(),
        );
        let described_token = tools::dispatch_tool(&mcp.client, None, token_type_request)
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(described_token["typeName"], "tokenAuthToken");
        assert!(described_token["schema"]["properties"]["isAccessTokenRevoked"].is_object());

        let kubernetes_type_request = CallToolRequestParams::new("types.describe").with_arguments(
            json!({ "typeName": "kubernetesAuthConfig" })
                .as_object()
                .unwrap()
                .clone(),
        );
        let described_kubernetes = tools::dispatch_tool(&mcp.client, None, kubernetes_type_request)
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(described_kubernetes["typeName"], "kubernetesAuthConfig");
        assert!(
            described_kubernetes["schema"]["properties"]["tokenReviewerJwtConfigured"].is_object()
        );

        assert_ssh_host_type_descriptions(&mcp.client).await;

        let invalid_page = CallToolRequestParams::new("projects.list")
            .with_arguments(json!({ "limit": 101 }).as_object().unwrap().clone());
        let error = tools::dispatch_tool(&mcp.client, None, invalid_page)
            .await
            .unwrap_err();
        assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert_eq!(error.message, "page limit must be between 1 and 100");
    }
}
