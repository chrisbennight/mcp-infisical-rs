//! Client-facing approval guidance and session controls.

use std::sync::Arc;

use rmcp::model::CallToolResult;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use url::Url;

use super::{
    ApprovalError, ApprovalMode, ApprovalOwner, ApprovalPermit, ApprovalSession, ApprovalState,
    ApprovalStore, ApprovalToken, ProjectEnvironment,
};
use crate::execution_error::{Category, Effect, ExecutionError, Recovery};

/// Shared process-local approval service, attached only to the HTTP host.
pub struct ApprovalService {
    store: Arc<ApprovalStore>,
    dashboard: Url,
}

/// Authenticated caller context supplied by the transport, never request arguments.
pub(crate) struct ApprovalContext<'a> {
    pub service: &'a Arc<ApprovalService>,
    pub owner: ApprovalOwner,
}

impl ApprovalService {
    /// Bind the store to the operator's public HTTPS origin (loopback HTTP for local use).
    ///
    /// # Errors
    /// Rejects credentials, paths, query strings, fragments, or unsafe public HTTP URLs.
    pub fn new(store: Arc<ApprovalStore>, origin: &Url) -> Result<Self, ApprovalError> {
        let local = origin.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        if origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
            || !(origin.scheme() == "https" || origin.scheme() == "http" && local)
        {
            return Err(ApprovalError::InvalidConfiguration);
        }
        let dashboard = origin
            .join("approval")
            .map_err(|_| ApprovalError::InvalidConfiguration)?;
        Ok(Self { store, dashboard })
    }

    /// Store used by the host's separately authenticated human routes.
    #[must_use]
    pub fn store(&self) -> &Arc<ApprovalStore> {
        &self.store
    }

    /// Build a public approval link containing only the non-credential request identifier.
    #[must_use]
    pub fn approval_url(&self, session_id: &str) -> String {
        let mut url = self.dashboard.clone();
        url.query_pairs_mut().append_pair("request", session_id);
        url.into()
    }

    pub(crate) fn authorize(
        &self,
        owner: &ApprovalOwner,
        operation: &'static str,
        arguments: &Value,
        scope: Option<ProjectEnvironment>,
        token: Option<ApprovalToken>,
    ) -> Result<Arc<ApprovalPermit>, CallToolResult> {
        let mut prepared = self
            .store
            .prepare(operation, arguments, scope)
            .map_err(|error| Self::failure(operation, error, None))?;
        prepared.target = target_summary(&arguments["arguments"]);
        if let Some(token) = token {
            return self
                .store
                .admit(owner, &token, prepared)
                .map(Arc::new)
                .map_err(|error| {
                    let guidance =
                        self.store
                            .status(owner, &token)
                            .ok()
                            .map(|session| ApprovalGuidance {
                                reason: reason(error),
                                approval_url: Some(self.approval_url(&session.session_id)),
                                approval_token: Some(token),
                                session: Some(session),
                            });
                    Self::failure(operation, error, guidance)
                });
        }
        let challenge = self
            .store
            .request(owner.clone(), prepared)
            .map_err(|error| Self::failure(operation, error, None))?;
        Err(Self::failure(
            operation,
            ApprovalError::Pending,
            Some(ApprovalGuidance {
                reason: "required",
                approval_url: Some(self.approval_url(&challenge.session.session_id)),
                approval_token: Some(challenge.token),
                session: Some(challenge.session),
            }),
        ))
    }

    fn failure(
        operation: &'static str,
        error: ApprovalError,
        guidance: Option<ApprovalGuidance>,
    ) -> CallToolResult {
        let output = ApprovalRequiredOutput {
            error: ExecutionError::new(Category::ApprovalRequired, Effect::NotStarted,
                Recovery::ObtainApproval,
                format!("{error}. Present the approval link to the human, then explicitly retry with approvalToken. Approval never starts work automatically."))
                .for_operation(operation),
            approval: guidance.unwrap_or(ApprovalGuidance { reason: reason(error), approval_url: None,
                approval_token: None, session: None }),
        };
        let mut result = CallToolResult::structured(
            serde_json::to_value(output).expect("approval response serializes"),
        );
        result.is_error = Some(true);
        result
    }

    pub(crate) fn session(
        &self,
        owner: &ApprovalOwner,
        input: SessionInput,
    ) -> Result<SessionOutput, ApprovalError> {
        let token = input.approval_token.ok_or(ApprovalError::UnknownSession)?;
        let session = match input.action {
            SessionAction::Status => self.store.status(owner, &token)?,
            SessionAction::Close => self.store.close(owner, &token)?,
        };
        Ok(SessionOutput {
            enabled: true,
            session: Some(ClientSession {
                state: session.state,
                mode: session.mode,
                remaining_seconds: session.remaining_seconds,
                remaining_uses: session.remaining_uses,
            }),
        })
    }

    pub(crate) fn guard(
        self: &Arc<Self>,
        permit: Arc<ApprovalPermit>,
    ) -> Arc<dyn Fn() -> bool + Send + Sync> {
        let service = Arc::clone(self);
        Arc::new(move || service.store.check(&permit).is_ok())
    }
}

fn reason(error: ApprovalError) -> &'static str {
    match error {
        ApprovalError::Pending => "pending",
        ApprovalError::UnknownSession => "unknownSession",
        ApprovalError::Denied => "denied",
        ApprovalError::Expired => "expired",
        ApprovalError::Revoked => "revoked",
        ApprovalError::Closed => "closed",
        ApprovalError::Consumed => "consumed",
        ApprovalError::ScopeMismatch => "scopeMismatch",
        ApprovalError::RequestMismatch => "requestMismatch",
        ApprovalError::Capacity => "capacity",
        ApprovalError::RecordingFailed => "recordingFailed",
        ApprovalError::InvalidConfiguration
        | ApprovalError::InvalidIdentity
        | ApprovalError::AlreadyDecided
        | ApprovalError::InvalidDuration => "invalidApproval",
    }
}

fn target_summary(arguments: &Value) -> std::collections::BTreeMap<String, String> {
    // Only typed resource identifiers and namespace coordinates are shown. Provider
    // configuration, free-form objects, secret inputs and file credentials are excluded.
    let fields = [
        "projectId",
        "projectSlug",
        "environment",
        "environmentSlug",
        "environmentId",
        "path",
        "name",
        "folderId",
        "certificateId",
        "identityId",
        "organizationId",
        "signerId",
        "secretName",
        "leaseId",
        "connectionId",
        "id",
    ];
    let containers = [
        "",
        "/target",
        "/scope",
        "/parent",
        "/target/parent",
        "/target/scope",
    ];
    let mut summary = std::collections::BTreeMap::new();
    for container in containers {
        let prefix = container.trim_start_matches('/').replace('/', ".");
        for field in fields {
            if summary.len() == 16 {
                return summary;
            }
            if let Some(value) = arguments
                .pointer(container)
                .and_then(|value| value[field].as_str())
            {
                let label = if prefix.is_empty() {
                    field.to_owned()
                } else {
                    format!("{prefix}.{field}")
                };
                summary.insert(
                    label,
                    if value.len() <= 512 {
                        value.to_owned()
                    } else {
                        "[long coordinate omitted]".to_owned()
                    },
                );
            }
        }
    }
    summary
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovalRequiredOutput {
    /// Explicit rejection before this operation starts.
    error: ExecutionError,
    /// Public guidance and a credential for this authenticated client only.
    approval: ApprovalGuidance,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ApprovalGuidance {
    /// Stable reason such as required, pending, expired, or scopeMismatch.
    reason: &'static str,
    /// Human approval URL, containing no credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_url: Option<String>,
    /// Sensitive inactive or reusable credential; pass only as executor approvalToken.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_token"
    )]
    #[schemars(with = "Option<String>", length(min = 43, max = 43))]
    approval_token: Option<ApprovalToken>,
    /// Current permission, scope, and time remaining.
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<ApprovalSession>,
}

// Serde's serialize_with callback requires a reference to the optional field.
#[allow(clippy::ref_option)]
fn serialize_token<S: Serializer>(
    token: &Option<ApprovalToken>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    token
        .as_ref()
        .map(ApprovalToken::expose_secret)
        .serialize(serializer)
}

pub(crate) fn deserialize_optional_token<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ApprovalToken>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(ApprovalToken::parse)
        .transpose()
        .map_err(serde::de::Error::custom)
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum SessionAction {
    #[default]
    Status,
    Close,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SessionInput {
    /// status (default) or close.
    #[serde(default)]
    action: SessionAction,
    /// Token from the approval rejection.
    #[serde(default, deserialize_with = "deserialize_optional_token")]
    #[schemars(with = "Option<String>", length(min = 43, max = 43))]
    approval_token: Option<ApprovalToken>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionOutput {
    /// Human approval enabled.
    pub enabled: bool,
    /// Current permission, if enabled.
    pub session: Option<ClientSession>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClientSession {
    /// Current permission state.
    state: ApprovalState,
    /// Permission mode.
    mode: Option<ApprovalMode>,
    /// Seconds remaining.
    remaining_seconds: u64,
    /// Exact-once attempts remaining.
    remaining_uses: Option<u8>,
}
