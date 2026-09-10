use std::{collections::HashSet, net::IpAddr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::IgnoredAny};
use thiserror::Error;

use crate::{
    EnvironmentSlug, InfisicalClient, ObservableReadOperation, Page, PageRequest, ProjectId,
    ResourceError, SecretName, SecretPath,
    client::{ApiVersion, Endpoint, sealed},
    resources::{is_bounded_text, is_uuid, utc_timestamp_millis},
};

const MAX_AUDIT_EVENT_TYPES: usize = 32;
const MAX_AUDIT_EVENT_TYPE_BYTES: usize = 128;
const MAX_AUDIT_TEXT_BYTES: usize = 1_024;
const MAX_AUDIT_TIME_RANGE_MILLIS: i64 = 90 * 24 * 60 * 60 * 1_000;

/// Validation failures for bounded audit-log filters.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuditLogInputError {
    /// An event type was outside the canonical subset accepted by Infisical.
    #[error(
        "audit event types must contain 1 to 128 lowercase letters or numbers separated by single hyphens"
    )]
    InvalidEventType,
    /// The event-type filter was empty, duplicated, or too large.
    #[error("audit event filters must contain 1 to 32 unique event types")]
    InvalidEventTypeFilter,
    /// A time coordinate was not a canonical UTC timestamp.
    #[error("audit timestamps must use canonical YYYY-MM-DDTHH:MM:SS[.sss]Z UTC form")]
    InvalidTimestamp,
    /// The range was inverted or exceeded the local bound.
    #[error("audit time ranges must be ordered and span no more than 90 days")]
    InvalidTimeRange,
}

/// One canonical audit-event type accepted as a server-side filter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct AuditLogEventType(String);

impl AuditLogEventType {
    /// Validate one event type against the pinned route's stable slug shape.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, padded, or non-canonical text.
    pub fn new(value: impl Into<String>) -> Result<Self, AuditLogInputError> {
        let value = value.into();
        if !is_event_type(&value) {
            return Err(AuditLogInputError::InvalidEventType);
        }
        Ok(Self(value))
    }

    /// Borrow the validated event type.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_event_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AUDIT_EVENT_TYPE_BYTES
        && value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

/// Canonical UTC instant accepted by the audit-log route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct AuditLogTimestamp(String);

impl AuditLogTimestamp {
    /// Validate a UTC instant at seconds or milliseconds precision.
    ///
    /// # Errors
    ///
    /// Returns an error unless the instant is a real calendar time in canonical
    /// UTC form.
    pub fn new(value: impl Into<String>) -> Result<Self, AuditLogInputError> {
        let value = value.into();
        if utc_timestamp_millis(&value).is_none() {
            return Err(AuditLogInputError::InvalidTimestamp);
        }
        Ok(Self(value))
    }

    /// Borrow the validated timestamp.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Principal family recorded by Infisical audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum AuditLogActorType {
    #[serde(rename = "platform")]
    Platform,
    #[serde(rename = "kmipClient")]
    KmipClient,
    #[serde(rename = "user")]
    User,
    #[serde(rename = "service")]
    Service,
    #[serde(rename = "identity")]
    Identity,
    #[serde(rename = "scimClient")]
    ScimClient,
    #[serde(rename = "acmeProfile")]
    AcmeProfile,
    #[serde(rename = "acmeAccount")]
    AcmeAccount,
    #[serde(rename = "estAccount")]
    EstAccount,
    #[serde(rename = "scepAccount")]
    ScepAccount,
    #[serde(rename = "unknownUser")]
    UnknownUser,
    #[serde(rename = "gateway")]
    Gateway,
    #[serde(rename = "relay")]
    Relay,
}

/// Client family recorded by Infisical audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum AuditLogUserAgentType {
    #[serde(rename = "web")]
    Web,
    #[serde(rename = "cli")]
    Cli,
    #[serde(rename = "k8-operator")]
    KubernetesOperator,
    #[serde(rename = "terraform")]
    Terraform,
    #[serde(rename = "other")]
    Other,
    #[serde(rename = "InfisicalPythonSDK")]
    PythonSdk,
    #[serde(rename = "InfisicalNodeSDK")]
    NodeSdk,
}

/// Bounded server-side filters for one audit-log page.
#[derive(Debug, Clone)]
pub struct AuditLogListRequest {
    page: PageRequest,
    project_id: Option<ProjectId>,
    environment: Option<EnvironmentSlug>,
    actor_type: Option<AuditLogActorType>,
    user_agent_type: Option<AuditLogUserAgentType>,
    secret_path: Option<SecretPath>,
    secret_key: Option<SecretName>,
    event_types: Vec<AuditLogEventType>,
    time_range: Option<(AuditLogTimestamp, AuditLogTimestamp)>,
}

impl AuditLogListRequest {
    /// Start one bounded audit-log request without optional filters.
    #[must_use]
    pub fn new(page: PageRequest) -> Self {
        Self {
            page,
            project_id: None,
            environment: None,
            actor_type: None,
            user_agent_type: None,
            secret_path: None,
            secret_key: None,
            event_types: Vec::new(),
            time_range: None,
        }
    }

    /// Restrict results to one exact project.
    #[must_use]
    pub fn with_project(mut self, project_id: ProjectId) -> Self {
        self.project_id = Some(project_id);
        self
    }

    /// Restrict results to one exact environment slug embedded in event metadata.
    #[must_use]
    pub fn with_environment(mut self, environment: EnvironmentSlug) -> Self {
        self.environment = Some(environment);
        self
    }

    /// Restrict results to one principal family.
    #[must_use]
    pub fn with_actor_type(mut self, actor_type: AuditLogActorType) -> Self {
        self.actor_type = Some(actor_type);
        self
    }

    /// Restrict results to one client family.
    #[must_use]
    pub fn with_user_agent_type(mut self, user_agent_type: AuditLogUserAgentType) -> Self {
        self.user_agent_type = Some(user_agent_type);
        self
    }

    /// Restrict results to one normalized secret path embedded in event metadata.
    #[must_use]
    pub fn with_secret_path(mut self, secret_path: SecretPath) -> Self {
        self.secret_path = Some(secret_path);
        self
    }

    /// Restrict results to one bounded secret key embedded in event metadata.
    #[must_use]
    pub fn with_secret_key(mut self, secret_key: SecretName) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    /// Restrict results to a non-empty bounded set of event types.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, duplicated, or oversized set.
    pub fn with_event_types(
        mut self,
        event_types: Vec<AuditLogEventType>,
    ) -> Result<Self, AuditLogInputError> {
        let unique = event_types
            .iter()
            .map(AuditLogEventType::as_str)
            .collect::<HashSet<_>>();
        if event_types.is_empty()
            || event_types.len() > MAX_AUDIT_EVENT_TYPES
            || unique.len() != event_types.len()
        {
            return Err(AuditLogInputError::InvalidEventTypeFilter);
        }
        self.event_types = event_types;
        Ok(self)
    }

    /// Restrict results to an ordered UTC interval of at most 90 days.
    ///
    /// # Errors
    ///
    /// Returns an error for an inverted or oversized interval.
    pub fn with_time_range(
        mut self,
        start: AuditLogTimestamp,
        end: AuditLogTimestamp,
    ) -> Result<Self, AuditLogInputError> {
        let (Some(start_millis), Some(end_millis)) = (
            utc_timestamp_millis(start.as_str()),
            utc_timestamp_millis(end.as_str()),
        ) else {
            return Err(AuditLogInputError::InvalidTimestamp);
        };
        let duration = end_millis.checked_sub(start_millis);
        if !duration.is_some_and(|duration| (0..=MAX_AUDIT_TIME_RANGE_MILLIS).contains(&duration)) {
            return Err(AuditLogInputError::InvalidTimeRange);
        }
        self.time_range = Some((start, end));
        Ok(self)
    }

    fn validate(&self) -> Result<(), ResourceError> {
        if !self.has_metadata_filters() {
            return Ok(());
        }
        if self.project_id.is_none() {
            return Err(ResourceError::AuditLogMetadataFilterRequiresProject);
        }
        if !self.event_types.is_empty()
            && !self
                .event_types
                .iter()
                .any(|event_type| is_filterable_secret_event(event_type.as_str()))
        {
            return Err(ResourceError::AuditLogMetadataFilterRequiresSecretEvent);
        }
        Ok(())
    }

    fn has_metadata_filters(&self) -> bool {
        self.environment.is_some() || self.secret_path.is_some() || self.secret_key.is_some()
    }
}

fn is_filterable_secret_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "get-secret"
            | "delete-secrets"
            | "create-secrets"
            | "update-secrets"
            | "create-secret"
            | "update-secret"
            | "delete-secret"
    )
}

/// Value-free audit event metadata returned by the MCP-safe client boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditLog {
    /// Opaque Infisical audit-event identifier.
    pub id: String,
    /// Principal family responsible for the event.
    pub actor_type: AuditLogActorType,
    /// Stable event type, without arbitrary event metadata.
    pub event_type: String,
    /// Source IP address, when recorded.
    pub ip_address: Option<String>,
    /// Bounded user-agent string, when recorded.
    pub user_agent: Option<String>,
    /// Bounded upstream user-agent classification, when recorded.
    pub user_agent_type: Option<AuditLogUserAgentType>,
    /// Owning organization identifier, when recorded.
    pub organization_id: Option<String>,
    /// Project identifier, when the event belongs to a project.
    pub project_id: Option<String>,
    /// Project display name, when recorded.
    pub project_name: Option<String>,
    /// Canonical creation timestamp.
    pub created_at: String,
    /// Optional event expiration timestamp.
    pub expires_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListAuditLogsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_type: Option<AuditLogActorType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent_type: Option<AuditLogUserAgentType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_date: Option<String>,
    offset: u32,
    limit: u16,
}

impl From<&AuditLogListRequest> for ListAuditLogsQuery {
    fn from(request: &AuditLogListRequest) -> Self {
        let (start_date, end_date) =
            request
                .time_range
                .as_ref()
                .map_or((None, None), |(start, end)| {
                    (
                        Some(start.as_str().to_owned()),
                        Some(end.as_str().to_owned()),
                    )
                });
        Self {
            project_id: request
                .project_id
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            environment: request
                .environment
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            actor_type: request.actor_type,
            user_agent_type: request.user_agent_type,
            secret_path: request
                .secret_path
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            secret_key: request
                .secret_key
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            event_type: (!request.event_types.is_empty()).then(|| {
                request
                    .event_types
                    .iter()
                    .map(AuditLogEventType::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            }),
            start_date,
            end_date,
            offset: request.page.offset(),
            limit: request.page.limit(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAuditLog {
    id: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    user_agent_type: Option<AuditLogUserAgentType>,
    expires_at: Option<String>,
    created_at: String,
    updated_at: String,
    org_id: Option<String>,
    project_id: Option<String>,
    project_name: Option<String>,
    event: RawAuditEvent,
    actor: RawAuditActor,
}

#[derive(Deserialize)]
struct RawAuditEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(rename = "metadata")]
    metadata: RawAuditEventMetadata,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawAuditEventMetadata {
    Filterable(RawAuditFilterMetadata),
    Other(IgnoredAny),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAuditFilterMetadata {
    environment: Option<String>,
    secret_path: Option<String>,
    secret_key: Option<String>,
    #[serde(default)]
    secrets: Vec<RawAuditSecretMetadata>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAuditSecretMetadata {
    secret_key: Option<String>,
}

#[derive(Deserialize)]
struct RawAuditActor {
    #[serde(rename = "type")]
    actor_type: AuditLogActorType,
    #[serde(rename = "metadata")]
    _metadata: IgnoredAny,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListAuditLogsResponse {
    audit_logs: Vec<RawAuditLog>,
}

struct ListAuditLogs;

impl sealed::Sealed for ListAuditLogs {}

impl ObservableReadOperation for ListAuditLogs {
    type Query = ListAuditLogsQuery;
    type Output = ListAuditLogsResponse;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "organization/audit-logs")
    }
}

impl RawAuditLog {
    fn into_validated(self, request: &AuditLogListRequest) -> Result<AuditLog, ResourceError> {
        let created_millis =
            utc_timestamp_millis(&self.created_at).ok_or(ResourceError::InvalidAuditLogResponse)?;
        if self.updated_at != self.created_at
            || utc_timestamp_millis(&self.updated_at) != Some(created_millis)
            || self
                .expires_at
                .as_deref()
                .is_some_and(|value| utc_timestamp_millis(value).is_none())
            || !is_event_type(&self.event.event_type)
            || !is_uuid(&self.id)
            || self
                .ip_address
                .as_deref()
                .is_some_and(|value| value.parse::<IpAddr>().is_err())
            || self
                .user_agent
                .as_deref()
                .is_some_and(|value| !is_bounded_text(value, MAX_AUDIT_TEXT_BYTES))
            || self.org_id.as_deref().is_some_and(|value| !is_uuid(value))
            || self
                .project_id
                .as_deref()
                .is_some_and(|value| ProjectId::new(value).is_err())
            || self
                .project_name
                .as_deref()
                .is_some_and(|value| !is_bounded_text(value, MAX_AUDIT_TEXT_BYTES))
        {
            return Err(ResourceError::InvalidAuditLogResponse);
        }
        if request
            .project_id
            .as_ref()
            .is_some_and(|expected| self.project_id.as_deref() != Some(expected.as_str()))
            || request
                .actor_type
                .is_some_and(|expected| self.actor.actor_type != expected)
            || request
                .user_agent_type
                .is_some_and(|expected| self.user_agent_type != Some(expected))
            || (!request.event_types.is_empty()
                && !request
                    .event_types
                    .iter()
                    .any(|event_type| event_type.as_str() == self.event.event_type))
            || !self.event.metadata.matches_filters(request)
        {
            return Err(ResourceError::InvalidAuditLogResponse);
        }
        if let Some((start, end)) = &request.time_range {
            let (Some(start), Some(end)) = (
                utc_timestamp_millis(start.as_str()),
                utc_timestamp_millis(end.as_str()),
            ) else {
                return Err(ResourceError::InvalidAuditLogResponse);
            };
            if !(start..=end).contains(&created_millis) {
                return Err(ResourceError::InvalidAuditLogResponse);
            }
        }
        Ok(AuditLog {
            id: self.id,
            actor_type: self.actor.actor_type,
            event_type: self.event.event_type,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            user_agent_type: self.user_agent_type,
            organization_id: self.org_id,
            project_id: self.project_id,
            project_name: self.project_name,
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }
}

impl RawAuditEventMetadata {
    fn matches_filters(&self, request: &AuditLogListRequest) -> bool {
        if !request.has_metadata_filters() {
            return true;
        }
        let Self::Filterable(metadata) = self else {
            return false;
        };
        if request
            .environment
            .as_ref()
            .is_some_and(|expected| metadata.environment.as_deref() != Some(expected.as_str()))
            || request
                .secret_path
                .as_ref()
                .is_some_and(|expected| metadata.secret_path.as_deref() != Some(expected.as_str()))
        {
            return false;
        }
        request.secret_key.as_ref().is_none_or(|expected| {
            metadata.secret_key.as_deref() == Some(expected.as_str())
                || metadata
                    .secrets
                    .iter()
                    .any(|secret| secret.secret_key.as_deref() == Some(expected.as_str()))
        })
    }
}

impl InfisicalClient {
    /// List one bounded upstream audit-log page without actor or event metadata.
    ///
    /// Infisical creates a `view-audit-logs` audit event when offset zero is
    /// requested, so callers must treat the first page as externally observable.
    ///
    /// # Errors
    ///
    /// Returns a typed client, response-contract, or pagination error.
    pub async fn list_audit_logs(
        &self,
        request: &AuditLogListRequest,
    ) -> Result<Page<AuditLog>, ResourceError> {
        request.validate()?;
        let response = self
            .execute_observable_read::<ListAuditLogs>(&ListAuditLogsQuery::from(request))
            .await?;
        let audit_logs = response
            .audit_logs
            .into_iter()
            .map(|audit_log| audit_log.into_validated(request))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Page::new(request.page, audit_logs, None)?)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    use super::{
        AuditLogActorType, AuditLogEventType, AuditLogInputError, AuditLogListRequest,
        AuditLogTimestamp, AuditLogUserAgentType, RawAuditLog,
    };
    use crate::{
        EnvironmentSlug, InfisicalClient, PageRequest, ProjectId, ResourceError, SecretName,
        SecretPath,
        test_support::{mount_login, settings},
    };

    #[test]
    fn audit_filters_reject_ambiguous_event_and_time_ranges() {
        assert_eq!(
            AuditLogEventType::new("create--secret").unwrap_err(),
            AuditLogInputError::InvalidEventType
        );
        let event = AuditLogEventType::new("create-secret").unwrap();
        assert_eq!(
            AuditLogListRequest::new(PageRequest::new(0, 20).unwrap())
                .with_event_types(vec![event.clone(), event])
                .unwrap_err(),
            AuditLogInputError::InvalidEventTypeFilter
        );
        let maximum_events = (0..32)
            .map(|index| AuditLogEventType::new(format!("event-{index}")).unwrap())
            .collect::<Vec<_>>();
        assert!(
            AuditLogListRequest::new(PageRequest::new(0, 20).unwrap())
                .with_event_types(maximum_events)
                .is_ok()
        );
        let too_many_events = (0..33)
            .map(|index| AuditLogEventType::new(format!("event-{index}")).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            AuditLogListRequest::new(PageRequest::new(0, 20).unwrap())
                .with_event_types(too_many_events)
                .unwrap_err(),
            AuditLogInputError::InvalidEventTypeFilter
        );
        assert_eq!(
            AuditLogTimestamp::new("2026-02-30T00:00:00Z").unwrap_err(),
            AuditLogInputError::InvalidTimestamp
        );
        let start = AuditLogTimestamp::new("2026-01-01T00:00:00.000Z").unwrap();
        let too_late = AuditLogTimestamp::new("2026-04-02T00:00:00.000Z").unwrap();
        assert_eq!(
            AuditLogListRequest::new(PageRequest::new(0, 20).unwrap())
                .with_time_range(start, too_late)
                .unwrap_err(),
            AuditLogInputError::InvalidTimeRange
        );
    }

    #[test]
    fn metadata_filters_require_the_scope_where_infisical_applies_them() {
        let page = PageRequest::new(0, 20).unwrap();
        assert!(AuditLogListRequest::new(page).validate().is_ok());
        for request in [
            AuditLogListRequest::new(page).with_environment(EnvironmentSlug::new("prod").unwrap()),
            AuditLogListRequest::new(page).with_secret_path(SecretPath::new("/apps").unwrap()),
            AuditLogListRequest::new(page)
                .with_secret_key(SecretName::new("DATABASE_URL").unwrap()),
        ] {
            assert_eq!(
                request.validate().unwrap_err(),
                ResourceError::AuditLogMetadataFilterRequiresProject
            );
        }

        let unsupported_event = AuditLogListRequest::new(page)
            .with_project(ProjectId::new("project-1").unwrap())
            .with_environment(EnvironmentSlug::new("prod").unwrap())
            .with_event_types(vec![AuditLogEventType::new("login").unwrap()])
            .unwrap();
        assert_eq!(
            unsupported_event.validate().unwrap_err(),
            ResourceError::AuditLogMetadataFilterRequiresSecretEvent
        );

        assert!(
            AuditLogListRequest::new(page)
                .with_project(ProjectId::new("project-1").unwrap())
                .with_environment(EnvironmentSlug::new("prod").unwrap())
                .validate()
                .is_ok()
        );
        assert!(
            AuditLogListRequest::new(page)
                .with_project(ProjectId::new("project-1").unwrap())
                .with_environment(EnvironmentSlug::new("prod").unwrap())
                .with_event_types(vec![AuditLogEventType::new("create-secret").unwrap()])
                .unwrap()
                .validate()
                .is_ok()
        );
    }

    #[tokio::test]
    async fn audit_log_listing_uses_the_pinned_wire_contract_and_omits_arbitrary_metadata() {
        let server = MockServer::start().await;
        mount_login(&server, "audit-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organization/audit-logs"))
            .and(header("authorization", "Bearer audit-token"))
            .and(query_param("projectId", "project-1"))
            .and(query_param("environment", "prod"))
            .and(query_param("actorType", "identity"))
            .and(query_param("userAgentType", "cli"))
            .and(query_param("secretPath", "/apps"))
            .and(query_param("secretKey", "DATABASE_URL"))
            .and(query_param("eventType", "create-secret,update-secret"))
            .and(query_param("startDate", "2026-07-01T00:00:00.000Z"))
            .and(query_param("endDate", "2026-07-20T00:00:00.000Z"))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auditLogs": [audit_fixture("project-1", "create-secret", "identity", "cli")]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let request = AuditLogListRequest::new(PageRequest::new(0, 1).unwrap())
            .with_project(ProjectId::new("project-1").unwrap())
            .with_environment(EnvironmentSlug::new("prod").unwrap())
            .with_actor_type(AuditLogActorType::Identity)
            .with_user_agent_type(AuditLogUserAgentType::Cli)
            .with_secret_path(SecretPath::new("/apps").unwrap())
            .with_secret_key(SecretName::new("DATABASE_URL").unwrap())
            .with_event_types(vec![
                AuditLogEventType::new("create-secret").unwrap(),
                AuditLogEventType::new("update-secret").unwrap(),
            ])
            .unwrap()
            .with_time_range(
                AuditLogTimestamp::new("2026-07-01T00:00:00.000Z").unwrap(),
                AuditLogTimestamp::new("2026-07-20T00:00:00.000Z").unwrap(),
            )
            .unwrap();
        let page = InfisicalClient::new(settings(&server))
            .unwrap()
            .list_audit_logs(&request)
            .await
            .unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].event_type, "create-secret");
        assert_eq!(page.items[0].actor_type, AuditLogActorType::Identity);
        assert!(page.next.is_some());
        let serialized = serde_json::to_value(&page.items[0]).unwrap();
        assert!(serialized.get("eventMetadata").is_none());
        assert!(serialized.get("actorMetadata").is_none());
    }

    #[tokio::test]
    async fn audit_log_listing_rejects_scope_drift_and_malformed_records() {
        for fixture in [
            audit_fixture("project-other", "create-secret", "identity", "cli"),
            audit_fixture("project-1", "CREATE SECRET", "identity", "cli"),
        ] {
            let server = MockServer::start().await;
            mount_login(&server, "audit-token").await;
            Mock::given(method("GET"))
                .and(path("/api/v1/organization/audit-logs"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "auditLogs": [fixture]
                })))
                .mount(&server)
                .await;
            let request = AuditLogListRequest::new(PageRequest::new(0, 20).unwrap())
                .with_project(ProjectId::new("project-1").unwrap());
            assert_eq!(
                InfisicalClient::new(settings(&server))
                    .unwrap()
                    .list_audit_logs(&request)
                    .await
                    .unwrap_err(),
                ResourceError::InvalidAuditLogResponse
            );
        }
    }

    #[test]
    fn audit_log_response_validation_checks_each_bounded_field_and_event_filter() {
        let mut invalid_records = Vec::new();

        let mut invalid_expiry = audit_fixture("project-1", "create-secret", "identity", "cli");
        invalid_expiry["expiresAt"] = json!("not-a-timestamp");
        invalid_records.push(invalid_expiry);

        let mut mismatched_update = audit_fixture("project-1", "create-secret", "identity", "cli");
        mismatched_update["updatedAt"] = json!("2026-07-10T12:30:00Z");
        invalid_records.push(mismatched_update);

        let mut invalid_ip = audit_fixture("project-1", "create-secret", "identity", "cli");
        invalid_ip["ipAddress"] = json!("not-an-ip-address");
        invalid_records.push(invalid_ip);

        let mut invalid_user_agent = audit_fixture("project-1", "create-secret", "identity", "cli");
        invalid_user_agent["userAgent"] = json!("bad\nagent");
        invalid_records.push(invalid_user_agent);

        let mut invalid_organization =
            audit_fixture("project-1", "create-secret", "identity", "cli");
        invalid_organization["orgId"] = json!("not-a-uuid");
        invalid_records.push(invalid_organization);

        let mut invalid_project = audit_fixture("project-1", "create-secret", "identity", "cli");
        invalid_project["projectId"] = json!("project/escape");
        invalid_records.push(invalid_project);

        let mut invalid_project_name =
            audit_fixture("project-1", "create-secret", "identity", "cli");
        invalid_project_name["projectName"] = json!("bad\nname");
        invalid_records.push(invalid_project_name);

        let request = AuditLogListRequest::new(PageRequest::new(0, 20).unwrap());
        for fixture in invalid_records {
            let raw: RawAuditLog = serde_json::from_value(fixture).unwrap();
            assert_eq!(
                raw.into_validated(&request).unwrap_err(),
                ResourceError::InvalidAuditLogResponse
            );
        }

        let filtered_request = AuditLogListRequest::new(PageRequest::new(0, 20).unwrap())
            .with_event_types(vec![AuditLogEventType::new("update-secret").unwrap()])
            .unwrap();
        let raw: RawAuditLog = serde_json::from_value(audit_fixture(
            "project-1",
            "create-secret",
            "identity",
            "cli",
        ))
        .unwrap();
        assert_eq!(
            raw.into_validated(&filtered_request).unwrap_err(),
            ResourceError::InvalidAuditLogResponse
        );

        let client_filtered_request = AuditLogListRequest::new(PageRequest::new(0, 20).unwrap())
            .with_actor_type(AuditLogActorType::Identity)
            .with_user_agent_type(AuditLogUserAgentType::Web);
        let raw: RawAuditLog = serde_json::from_value(audit_fixture(
            "project-1",
            "create-secret",
            "identity",
            "cli",
        ))
        .unwrap();
        assert_eq!(
            raw.into_validated(&client_filtered_request).unwrap_err(),
            ResourceError::InvalidAuditLogResponse
        );
    }

    #[test]
    fn audit_log_response_proves_each_metadata_backed_filter() {
        let request = AuditLogListRequest::new(PageRequest::new(0, 20).unwrap())
            .with_project(ProjectId::new("project-1").unwrap())
            .with_environment(EnvironmentSlug::new("prod").unwrap())
            .with_secret_path(SecretPath::new("/apps").unwrap())
            .with_secret_key(SecretName::new("DATABASE_URL").unwrap());

        for (field, mismatched) in [
            ("environment", json!("staging")),
            ("secretPath", json!("/other")),
            ("secretKey", json!("OTHER_KEY")),
        ] {
            let mut fixture = audit_fixture("project-1", "create-secret", "identity", "cli");
            fixture["event"]["metadata"][field] = mismatched;
            let raw: RawAuditLog = serde_json::from_value(fixture).unwrap();
            assert_eq!(
                raw.into_validated(&request).unwrap_err(),
                ResourceError::InvalidAuditLogResponse
            );
        }

        let mut nested_match = audit_fixture("project-1", "create-secret", "identity", "cli");
        nested_match["event"]["metadata"]["secretKey"] = serde_json::Value::Null;
        nested_match["event"]["metadata"]["secrets"] =
            json!([{ "secretKey": "DATABASE_URL", "secretValue": "must-not-escape" }]);
        let raw: RawAuditLog = serde_json::from_value(nested_match).unwrap();
        assert!(raw.into_validated(&request).is_ok());

        let mut nested_mismatch = audit_fixture("project-1", "create-secret", "identity", "cli");
        nested_mismatch["event"]["metadata"]["secretKey"] = serde_json::Value::Null;
        nested_mismatch["event"]["metadata"]["secrets"] =
            json!([{ "secretKey": "OTHER_KEY", "secretValue": "must-not-escape" }]);
        let raw: RawAuditLog = serde_json::from_value(nested_mismatch).unwrap();
        assert_eq!(
            raw.into_validated(&request).unwrap_err(),
            ResourceError::InvalidAuditLogResponse
        );

        let mut missing = audit_fixture("project-1", "create-secret", "identity", "cli");
        missing["event"]["metadata"] = serde_json::Value::Null;
        let raw: RawAuditLog = serde_json::from_value(missing).unwrap();
        assert_eq!(
            raw.into_validated(&request).unwrap_err(),
            ResourceError::InvalidAuditLogResponse
        );
    }

    #[test]
    fn audit_log_text_and_uuid_helpers_enforce_every_boundary() {
        assert!(super::is_bounded_text("x", 1));
        assert!(!super::is_bounded_text("", 1));
        assert!(!super::is_bounded_text("xx", 1));
        assert!(!super::is_bounded_text("\n", 1));

        let valid = "e94e92dc-494f-4c06-bbd3-bf75c5011d62";
        assert!(super::is_uuid(valid));
        assert!(!super::is_uuid(&valid[..35]));
        assert!(!super::is_uuid("e94e92dc_494f-4c06-bbd3-bf75c5011d62"));
    }

    fn audit_fixture(
        project_id: &str,
        event_type: &str,
        actor_type: &str,
        user_agent_type: &str,
    ) -> serde_json::Value {
        json!({
            "id": "e94e92dc-494f-4c06-bbd3-bf75c5011d62",
            "actor": { "type": actor_type, "metadata": { "identityId": "identity-1" } },
            "event": {
                "type": event_type,
                "metadata": {
                    "environment": "prod",
                    "secretPath": "/apps",
                    "secretKey": "DATABASE_URL",
                    "secretValue": "must-not-escape"
                }
            },
            "ipAddress": "192.0.2.10",
            "userAgent": "Infisical CLI",
            "userAgentType": user_agent_type,
            "expiresAt": null,
            "createdAt": "2026-07-10T12:30:00.000Z",
            "updatedAt": "2026-07-10T12:30:00.000Z",
            "orgId": "d5d7469f-91c4-4da9-8587-b59325fd89f7",
            "projectId": project_id,
            "projectName": "Production"
        })
    }
}
