use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AdditionalPrivilegeId, IdentityId, InfisicalClient, MutationOperation, Page, PageRequest,
    ProjectId, ProjectSlug, ReadOperation, ResourceError, RolePermission,
    client::{ApiVersion, Endpoint, sealed},
    resources::{paginate, utc_timestamp_millis},
};

const MAX_ADDITIONAL_PRIVILEGE_SLUG_BYTES: usize = 60;
const MAX_PERMISSION_TEXT_BYTES: usize = 128;
/// Maximum permission rules accepted in one additional privilege.
pub const MAX_ADDITIONAL_PRIVILEGE_PERMISSIONS: usize = 256;
/// Maximum actions accepted in one permission rule.
pub const MAX_ADDITIONAL_PRIVILEGE_ACTIONS: usize = 64;
/// Maximum serialized condition expression accepted in one permission rule.
pub const MAX_ADDITIONAL_PRIVILEGE_CONDITION_BYTES: usize = 65_536;
/// Maximum temporary privilege lifetime exposed through this bounded client.
pub const MAX_ADDITIONAL_PRIVILEGE_DURATION_SECONDS: u32 = 315_360_000;

/// Validation failures for identity project additional-privilege inputs.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AdditionalPrivilegeInputError {
    /// A slug was outside the canonical subset accepted by Infisical.
    #[error(
        "additional privilege slug must contain 1 to 60 lowercase letters or numbers separated by single hyphens"
    )]
    InvalidSlug,
    /// A temporary duration was zero or beyond the local request bound.
    #[error("temporary privilege duration must be between 1 and 315360000 seconds")]
    InvalidDuration,
    /// A start time was not a canonical UTC timestamp at seconds precision.
    #[error("temporary privilege start time must use canonical YYYY-MM-DDTHH:MM:SSZ UTC form")]
    InvalidStartTime,
    /// Too many permission rules were supplied.
    #[error("additional privileges may contain at most 256 permission rules")]
    TooManyPermissions,
    /// A permission rule omitted a bounded subject.
    #[error("each additional privilege permission must contain one bounded subject")]
    InvalidPermissionSubject,
    /// A permission rule omitted actions or exceeded the action bound.
    #[error("each additional privilege permission must contain 1 to 64 bounded actions")]
    InvalidPermissionActions,
    /// One or more deny rules were supplied without explicit acknowledgement.
    #[error("creating inverted permissions requires explicit deny acknowledgement")]
    InvertedPermissionsNotConfirmed,
    /// A complete permission replacement lacked explicit acknowledgement.
    #[error("replacing additional privilege permissions requires explicit acknowledgement")]
    PermissionReplacementNotConfirmed,
    /// A condition expression exceeded the serialized request bound.
    #[error("each additional privilege condition must serialize to at most 65536 bytes")]
    ConditionTooLarge,
}

/// Stable slug for one identity project additional privilege.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct AdditionalPrivilegeSlug(String);

impl AdditionalPrivilegeSlug {
    /// Validate a canonical Infisical additional-privilege slug.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, padded, or non-canonical text.
    pub fn new(value: impl Into<String>) -> Result<Self, AdditionalPrivilegeInputError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ADDITIONAL_PRIVILEGE_SLUG_BYTES
            || value.split('-').any(|segment| {
                segment.is_empty()
                    || !segment
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
        {
            return Err(AdditionalPrivilegeInputError::InvalidSlug);
        }
        Ok(Self(value))
    }

    /// Borrow the validated slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical UTC start time for a temporary additional privilege.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct AdditionalPrivilegeStartTime(String);

impl AdditionalPrivilegeStartTime {
    /// Validate a UTC timestamp at seconds precision.
    ///
    /// # Errors
    ///
    /// Returns an error unless the timestamp is a real calendar instant in
    /// canonical `YYYY-MM-DDTHH:MM:SSZ` form.
    pub fn new(value: impl Into<String>) -> Result<Self, AdditionalPrivilegeInputError> {
        let value = value.into();
        if !is_canonical_utc_timestamp(&value) {
            return Err(AdditionalPrivilegeInputError::InvalidStartTime);
        }
        Ok(Self(value))
    }

    /// Borrow the validated timestamp.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_canonical_utc_timestamp(value: &str) -> bool {
    value.len() == 20 && utc_timestamp_millis(value).is_some()
}

fn duration_millis(value: &str) -> Option<u64> {
    if value.len() > 64 {
        return None;
    }
    let numeric_end = value
        .bytes()
        .position(|byte| !byte.is_ascii_digit() && byte != b'.')
        .unwrap_or(value.len());
    let numeric = &value[..numeric_end];
    let unit = value[numeric_end..].trim_start().to_ascii_lowercase();
    let (whole, fraction, scale) = match numeric.split_once('.') {
        Some((whole, fraction)) => {
            if fraction.contains('.') {
                return None;
            }
            let scale = 10_u128.checked_pow(u32::try_from(fraction.len()).ok()?)?;
            (
                whole.parse::<u128>().ok()?,
                fraction.parse::<u128>().ok()?,
                scale,
            )
        }
        None => (numeric.parse::<u128>().ok()?, 0, 1),
    };
    let unit_millis = match unit.as_str() {
        "" | "ms" | "msec" | "msecs" | "millisecond" | "milliseconds" => 1_u128,
        "s" | "sec" | "secs" | "second" | "seconds" => 1_000,
        "m" | "min" | "mins" | "minute" | "minutes" => 60_000,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600_000,
        "d" | "day" | "days" => 86_400_000,
        "w" | "week" | "weeks" => 604_800_000,
        "y" | "yr" | "yrs" | "year" | "years" => 31_557_600_000,
        _ => return None,
    };
    let numerator = whole.checked_mul(scale)?.checked_add(fraction)?;
    let scaled_millis = numerator.checked_mul(unit_millis)?;
    if scaled_millis % scale != 0 {
        return None;
    }
    let millis = u64::try_from(scaled_millis / scale).ok()?;
    (millis > 0 && millis <= u64::from(MAX_ADDITIONAL_PRIVILEGE_DURATION_SECONDS) * 1_000)
        .then_some(millis)
}

/// Permanent or scheduled temporary lifetime for an additional privilege.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdditionalPrivilegeLifetime {
    /// The privilege remains active until changed or deleted.
    Permanent,
    /// The privilege begins at one UTC instant and lasts for a bounded duration.
    Temporary {
        /// Positive lifetime in seconds.
        duration_seconds: u32,
        /// Scheduled UTC activation time.
        start_time: AdditionalPrivilegeStartTime,
    },
}

impl AdditionalPrivilegeLifetime {
    /// Construct a bounded scheduled temporary lifetime.
    ///
    /// # Errors
    ///
    /// Returns an error when the duration is zero or exceeds ten years.
    pub fn temporary(
        duration_seconds: u32,
        start_time: AdditionalPrivilegeStartTime,
    ) -> Result<Self, AdditionalPrivilegeInputError> {
        if !(1..=MAX_ADDITIONAL_PRIVILEGE_DURATION_SECONDS).contains(&duration_seconds) {
            return Err(AdditionalPrivilegeInputError::InvalidDuration);
        }
        Ok(Self::Temporary {
            duration_seconds,
            start_time,
        })
    }
}

/// Complete settings for one new identity project additional privilege.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdditionalPrivilegeCreation {
    slug: Option<AdditionalPrivilegeSlug>,
    permissions: Vec<RolePermission>,
    lifetime: AdditionalPrivilegeLifetime,
}

impl AdditionalPrivilegeCreation {
    /// Validate one creation request before it reaches Infisical.
    ///
    /// Omitting the slug asks Infisical to generate one.
    ///
    /// # Errors
    ///
    /// Returns an error for unbounded or malformed permission rules, or when
    /// an inverted deny rule lacks explicit acknowledgement.
    pub fn new(
        slug: Option<AdditionalPrivilegeSlug>,
        permissions: Vec<RolePermission>,
        confirm_deny_permissions: bool,
        lifetime: AdditionalPrivilegeLifetime,
    ) -> Result<Self, AdditionalPrivilegeInputError> {
        validate_permissions(&permissions)?;
        if permissions.iter().any(|permission| permission.inverted) && !confirm_deny_permissions {
            return Err(AdditionalPrivilegeInputError::InvertedPermissionsNotConfirmed);
        }
        Ok(Self {
            slug,
            permissions,
            lifetime,
        })
    }
}

/// Complete mutable state for one identity project additional privilege.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdditionalPrivilegeChange {
    slug: AdditionalPrivilegeSlug,
    permissions: Option<Vec<RolePermission>>,
    lifetime: AdditionalPrivilegeLifetime,
}

impl AdditionalPrivilegeChange {
    /// Validate one update request before it reaches Infisical.
    ///
    /// `None` leaves permissions unchanged; `Some([])` removes every permission.
    ///
    /// # Errors
    ///
    /// Returns an error for unbounded or malformed permission rules, or when a
    /// supplied replacement lacks explicit acknowledgement.
    pub fn new(
        slug: AdditionalPrivilegeSlug,
        permissions: Option<Vec<RolePermission>>,
        confirm_replace_permissions: bool,
        lifetime: AdditionalPrivilegeLifetime,
    ) -> Result<Self, AdditionalPrivilegeInputError> {
        if permissions.is_some() && !confirm_replace_permissions {
            return Err(AdditionalPrivilegeInputError::PermissionReplacementNotConfirmed);
        }
        if let Some(permissions) = &permissions {
            validate_permissions(permissions)?;
        }
        Ok(Self {
            slug,
            permissions,
            lifetime,
        })
    }
}

fn validate_permissions(
    permissions: &[RolePermission],
) -> Result<(), AdditionalPrivilegeInputError> {
    if permissions.len() > MAX_ADDITIONAL_PRIVILEGE_PERMISSIONS {
        return Err(AdditionalPrivilegeInputError::TooManyPermissions);
    }
    for permission in permissions {
        let valid_subject = permission.subject.as_deref().is_some_and(|subject| {
            !subject.is_empty()
                && subject.len() <= MAX_PERMISSION_TEXT_BYTES
                && subject.trim() == subject
                && !subject.chars().any(char::is_control)
        });
        if !valid_subject {
            return Err(AdditionalPrivilegeInputError::InvalidPermissionSubject);
        }
        if permission.action.is_empty()
            || permission.action.len() > MAX_ADDITIONAL_PRIVILEGE_ACTIONS
            || permission.action.iter().any(|action| {
                action.is_empty()
                    || action.len() > MAX_PERMISSION_TEXT_BYTES
                    || action.trim() != action
                    || action.chars().any(char::is_control)
            })
        {
            return Err(AdditionalPrivilegeInputError::InvalidPermissionActions);
        }
        if permission.conditions.as_ref().is_some_and(|conditions| {
            serde_json::to_vec(conditions)
                .is_ok_and(|encoded| encoded.len() > MAX_ADDITIONAL_PRIVILEGE_CONDITION_BYTES)
        }) {
            return Err(AdditionalPrivilegeInputError::ConditionTooLarge);
        }
    }
    Ok(())
}

/// Non-secret identity project additional-privilege metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IdentityProjectAdditionalPrivilegeSummary {
    /// Opaque additional-privilege identifier.
    pub id: String,
    /// Stable privilege slug.
    pub slug: String,
    /// Opaque machine-identity identifier receiving the privilege.
    pub identity_id: String,
    /// Opaque project identifier owning the privilege.
    pub project_id: String,
    /// Whether this privilege is scheduled to expire.
    pub is_temporary: bool,
    /// Temporary scheduling mode returned by Infisical.
    #[serde(default)]
    pub temporary_mode: Option<String>,
    /// Upstream human-readable temporary range.
    #[serde(default)]
    pub temporary_range: Option<String>,
    /// Scheduled activation timestamp.
    #[serde(default)]
    pub temporary_access_start_time: Option<String>,
    /// Computed expiration timestamp.
    #[serde(default)]
    pub temporary_access_end_time: Option<String>,
    /// Upstream creation timestamp.
    pub created_at: String,
    /// Upstream last-update timestamp.
    pub updated_at: String,
}

/// Exact identity project additional privilege with normalized permission rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IdentityProjectAdditionalPrivilege {
    /// Non-secret privilege metadata.
    #[serde(flatten)]
    pub summary: IdentityProjectAdditionalPrivilegeSummary,
    /// Complete normalized permission rule set.
    pub permissions: Vec<RolePermission>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListPrivilegesQuery {
    identity_id: IdentityId,
    project_id: ProjectId,
}

#[derive(Serialize)]
struct GetPrivilegeQuery {
    #[serde(skip_serializing)]
    privilege_id: AdditionalPrivilegeId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetPrivilegeBySlugQuery {
    identity_id: IdentityId,
    project_slug: ProjectSlug,
    #[serde(skip_serializing)]
    privilege_slug: AdditionalPrivilegeSlug,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
enum LifetimeRequest {
    Permanent(PermanentLifetimeRequest),
    Temporary(TemporaryLifetimeRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PermanentLifetimeRequest {
    is_temporary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct TemporaryLifetimeRequest {
    is_temporary: bool,
    temporary_mode: TemporaryMode,
    temporary_range: String,
    temporary_access_start_time: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum TemporaryMode {
    Relative,
}

impl From<&AdditionalPrivilegeLifetime> for LifetimeRequest {
    fn from(lifetime: &AdditionalPrivilegeLifetime) -> Self {
        match lifetime {
            AdditionalPrivilegeLifetime::Permanent => Self::Permanent(PermanentLifetimeRequest {
                is_temporary: false,
            }),
            AdditionalPrivilegeLifetime::Temporary {
                duration_seconds,
                start_time,
            } => Self::Temporary(TemporaryLifetimeRequest {
                is_temporary: true,
                temporary_mode: TemporaryMode::Relative,
                temporary_range: format!("{duration_seconds}s"),
                temporary_access_start_time: start_time.as_str().to_owned(),
            }),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatePrivilegeRequest {
    identity_id: IdentityId,
    project_id: ProjectId,
    #[serde(skip_serializing_if = "Option::is_none")]
    slug: Option<AdditionalPrivilegeSlug>,
    permissions: Vec<RolePermission>,
    #[serde(rename = "type")]
    lifetime: LifetimeRequest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdatePrivilegeRequest {
    #[serde(skip_serializing)]
    privilege_id: AdditionalPrivilegeId,
    slug: AdditionalPrivilegeSlug,
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<Vec<RolePermission>>,
    #[serde(rename = "type")]
    lifetime: LifetimeRequest,
}

#[derive(Serialize)]
struct DeletePrivilegeRequest {
    #[serde(skip_serializing)]
    privilege_id: AdditionalPrivilegeId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityProjectAdditionalPrivilegeSummaryWire {
    id: String,
    slug: String,
    #[serde(default)]
    identity_id: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    is_temporary: bool,
    #[serde(default)]
    temporary_mode: Option<String>,
    #[serde(default)]
    temporary_range: Option<String>,
    #[serde(default)]
    temporary_access_start_time: Option<String>,
    #[serde(default)]
    temporary_access_end_time: Option<String>,
    created_at: String,
    updated_at: String,
}

impl IdentityProjectAdditionalPrivilegeSummaryWire {
    fn bind_scope(
        self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
    ) -> Result<IdentityProjectAdditionalPrivilegeSummary, ResourceError> {
        if self
            .project_id
            .as_deref()
            .is_some_and(|actual| actual != project_id.as_str())
            || self
                .identity_id
                .as_deref()
                .is_some_and(|actual| actual != identity_id.as_str())
        {
            return Err(ResourceError::InvalidAdditionalPrivilegeScope);
        }
        Ok(IdentityProjectAdditionalPrivilegeSummary {
            id: self.id,
            slug: self.slug,
            identity_id: identity_id.as_str().to_owned(),
            project_id: project_id.as_str().to_owned(),
            is_temporary: self.is_temporary,
            temporary_mode: self.temporary_mode,
            temporary_range: self.temporary_range,
            temporary_access_start_time: self.temporary_access_start_time,
            temporary_access_end_time: self.temporary_access_end_time,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityProjectAdditionalPrivilegeWire {
    #[serde(flatten)]
    summary: IdentityProjectAdditionalPrivilegeSummaryWire,
    permissions: Vec<RolePermission>,
}

impl IdentityProjectAdditionalPrivilegeWire {
    fn bind_scope(
        self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
    ) -> Result<IdentityProjectAdditionalPrivilege, ResourceError> {
        Ok(IdentityProjectAdditionalPrivilege {
            summary: self.summary.bind_scope(project_id, identity_id)?,
            permissions: self.permissions,
        })
    }
}

#[derive(Deserialize)]
struct ListPrivilegesResponse {
    privileges: Vec<IdentityProjectAdditionalPrivilegeSummaryWire>,
}

#[derive(Deserialize)]
struct PrivilegeResponse {
    privilege: IdentityProjectAdditionalPrivilegeWire,
}

struct ListPrivileges;
impl sealed::Sealed for ListPrivileges {}
impl ReadOperation for ListPrivileges {
    type Query = ListPrivilegesQuery;
    type Output = ListPrivilegesResponse;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V2, "identity-project-additional-privilege")
    }
}

struct GetPrivilege;
impl sealed::Sealed for GetPrivilege {}
impl ReadOperation for GetPrivilege {
    type Query = GetPrivilegeQuery;
    type Output = PrivilegeResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V2,
            [
                "identity-project-additional-privilege",
                query.privilege_id.as_str(),
            ],
        )
    }
}

struct GetPrivilegeBySlug;
impl sealed::Sealed for GetPrivilegeBySlug {}
impl ReadOperation for GetPrivilegeBySlug {
    type Query = GetPrivilegeBySlugQuery;
    type Output = PrivilegeResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V2,
            [
                "identity-project-additional-privilege",
                "slug",
                query.privilege_slug.as_str(),
            ],
        )
    }
}

struct CreatePrivilege;
impl sealed::Sealed for CreatePrivilege {}
impl MutationOperation for CreatePrivilege {
    type Input = CreatePrivilegeRequest;
    type Output = PrivilegeResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_static(ApiVersion::V2, "identity-project-additional-privilege")
    }
}

struct UpdatePrivilege;
impl sealed::Sealed for UpdatePrivilege {}
impl MutationOperation for UpdatePrivilege {
    type Input = UpdatePrivilegeRequest;
    type Output = PrivilegeResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V2,
            [
                "identity-project-additional-privilege",
                input.privilege_id.as_str(),
            ],
        )
    }
}

struct DeletePrivilege;
impl sealed::Sealed for DeletePrivilege {}
impl MutationOperation for DeletePrivilege {
    type Input = DeletePrivilegeRequest;
    type Output = PrivilegeResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V2,
            [
                "identity-project-additional-privilege",
                input.privilege_id.as_str(),
            ],
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TemporarySchedule {
    duration_millis: u64,
    start_millis: i64,
}

fn validate_summary(
    summary: &IdentityProjectAdditionalPrivilegeSummary,
    project_id: &ProjectId,
    identity_id: &IdentityId,
    privilege_id: Option<&AdditionalPrivilegeId>,
    slug: Option<&AdditionalPrivilegeSlug>,
) -> Result<Option<TemporarySchedule>, ResourceError> {
    if summary.project_id != project_id.as_str()
        || summary.identity_id != identity_id.as_str()
        || privilege_id.is_some_and(|expected| summary.id != expected.as_str())
        || slug.is_some_and(|expected| summary.slug != expected.as_str())
    {
        return Err(ResourceError::InvalidAdditionalPrivilegeScope);
    }
    let has_no_temporary_schedule = summary.temporary_mode.is_none()
        && summary.temporary_range.is_none()
        && summary.temporary_access_start_time.is_none()
        && summary.temporary_access_end_time.is_none();
    if !summary.is_temporary {
        return has_no_temporary_schedule
            .then_some(None)
            .ok_or(ResourceError::InvalidAdditionalPrivilegeLifetime);
    }
    if summary.temporary_mode.as_deref() != Some("relative") {
        return Err(ResourceError::InvalidAdditionalPrivilegeLifetime);
    }
    let duration_millis = summary
        .temporary_range
        .as_deref()
        .and_then(duration_millis)
        .ok_or(ResourceError::InvalidAdditionalPrivilegeLifetime)?;
    let start_millis = summary
        .temporary_access_start_time
        .as_deref()
        .and_then(utc_timestamp_millis)
        .ok_or(ResourceError::InvalidAdditionalPrivilegeLifetime)?;
    let end_millis = summary
        .temporary_access_end_time
        .as_deref()
        .and_then(utc_timestamp_millis)
        .ok_or(ResourceError::InvalidAdditionalPrivilegeLifetime)?;
    let duration_millis_i64 = i64::try_from(duration_millis)
        .map_err(|_| ResourceError::InvalidAdditionalPrivilegeLifetime)?;
    if end_millis.checked_sub(start_millis) != Some(duration_millis_i64) {
        return Err(ResourceError::InvalidAdditionalPrivilegeLifetime);
    }
    Ok(Some(TemporarySchedule {
        duration_millis,
        start_millis,
    }))
}

fn validate_exact(
    privilege: &IdentityProjectAdditionalPrivilege,
    project_id: &ProjectId,
    identity_id: &IdentityId,
    privilege_id: Option<&AdditionalPrivilegeId>,
    slug: Option<&AdditionalPrivilegeSlug>,
    permissions: Option<&[RolePermission]>,
    lifetime: Option<&AdditionalPrivilegeLifetime>,
) -> Result<(), ResourceError> {
    let schedule = validate_summary(
        &privilege.summary,
        project_id,
        identity_id,
        privilege_id,
        slug,
    )?;
    validate_permissions(&privilege.permissions)
        .map_err(|_| ResourceError::InvalidAdditionalPrivilegePermissions)?;
    if permissions.is_some_and(|expected| privilege.permissions != expected) {
        return Err(ResourceError::InvalidAdditionalPrivilegePermissions);
    }
    if let Some(expected) = lifetime {
        match (expected, schedule) {
            (AdditionalPrivilegeLifetime::Permanent, None) => {}
            (
                AdditionalPrivilegeLifetime::Temporary {
                    duration_seconds,
                    start_time,
                },
                Some(actual),
            ) if actual.duration_millis == u64::from(*duration_seconds) * 1_000
                && utc_timestamp_millis(start_time.as_str()) == Some(actual.start_millis) => {}
            _ => return Err(ResourceError::InvalidAdditionalPrivilegeLifetime),
        }
    }
    Ok(())
}

impl InfisicalClient {
    async fn scoped_identity_project_additional_privileges(
        &self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
    ) -> Result<Vec<IdentityProjectAdditionalPrivilegeSummary>, ResourceError> {
        let response = self
            .execute_read::<ListPrivileges>(&ListPrivilegesQuery {
                identity_id: identity_id.clone(),
                project_id: project_id.clone(),
            })
            .await?;
        response
            .privileges
            .into_iter()
            .map(|privilege| {
                let privilege = privilege.bind_scope(project_id, identity_id)?;
                let _ = validate_summary(&privilege, project_id, identity_id, None, None)?;
                Ok(privilege)
            })
            .collect()
    }

    async fn preflight_identity_project_additional_privilege(
        &self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
        privilege_id: &AdditionalPrivilegeId,
    ) -> Result<IdentityProjectAdditionalPrivilegeSummary, ResourceError> {
        self.scoped_identity_project_additional_privileges(project_id, identity_id)
            .await?
            .into_iter()
            .find(|privilege| privilege.id == privilege_id.as_str())
            .ok_or(ResourceError::InvalidAdditionalPrivilegeScope)
    }

    /// List a locally bounded page of additional privileges for one identity in one project.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope-validation, or pagination error.
    pub async fn list_identity_project_additional_privileges(
        &self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
        page: PageRequest,
    ) -> Result<Page<IdentityProjectAdditionalPrivilegeSummary>, ResourceError> {
        let privileges = self
            .scoped_identity_project_additional_privileges(project_id, identity_id)
            .await?;
        paginate(page, privileges)
    }

    /// Get one additional privilege by exact ID and verify its owning scope.
    ///
    /// # Errors
    ///
    /// Returns a typed client or scope-validation error.
    pub async fn get_identity_project_additional_privilege(
        &self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
        privilege_id: &AdditionalPrivilegeId,
    ) -> Result<IdentityProjectAdditionalPrivilege, ResourceError> {
        self.preflight_identity_project_additional_privilege(project_id, identity_id, privilege_id)
            .await?;
        let response = self
            .execute_read::<GetPrivilege>(&GetPrivilegeQuery {
                privilege_id: privilege_id.clone(),
            })
            .await?;
        let privilege = response.privilege.bind_scope(project_id, identity_id)?;
        validate_exact(
            &privilege,
            project_id,
            identity_id,
            Some(privilege_id),
            None,
            None,
            None,
        )?;
        Ok(privilege)
    }

    /// Get one additional privilege by exact slug and verify its owning scope.
    ///
    /// # Errors
    ///
    /// Returns a typed client or scope-validation error.
    pub async fn get_identity_project_additional_privilege_by_slug(
        &self,
        project_id: &ProjectId,
        project_slug: &ProjectSlug,
        identity_id: &IdentityId,
        privilege_slug: &AdditionalPrivilegeSlug,
    ) -> Result<IdentityProjectAdditionalPrivilege, ResourceError> {
        let preflight = self
            .scoped_identity_project_additional_privileges(project_id, identity_id)
            .await?
            .into_iter()
            .find(|privilege| privilege.slug == privilege_slug.as_str())
            .ok_or(ResourceError::InvalidAdditionalPrivilegeScope)?;
        let response = self
            .execute_read::<GetPrivilegeBySlug>(&GetPrivilegeBySlugQuery {
                identity_id: identity_id.clone(),
                project_slug: project_slug.clone(),
                privilege_slug: privilege_slug.clone(),
            })
            .await?;
        let privilege = response.privilege.bind_scope(project_id, identity_id)?;
        if privilege.summary.id != preflight.id {
            return Err(ResourceError::InvalidAdditionalPrivilegeScope);
        }
        validate_exact(
            &privilege,
            project_id,
            identity_id,
            None,
            Some(privilege_slug),
            None,
            None,
        )?;
        Ok(privilege)
    }

    /// Create one permanent or scheduled temporary additional privilege.
    ///
    /// # Errors
    ///
    /// Returns a typed client or scope-validation error. The mutation is sent once.
    pub async fn create_identity_project_additional_privilege(
        &self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
        creation: AdditionalPrivilegeCreation,
    ) -> Result<IdentityProjectAdditionalPrivilege, ResourceError> {
        let expected_slug = creation.slug.clone();
        let expected_permissions = creation.permissions.clone();
        let expected_lifetime = creation.lifetime.clone();
        let response = self
            .execute_mutation::<CreatePrivilege>(&CreatePrivilegeRequest {
                identity_id: identity_id.clone(),
                project_id: project_id.clone(),
                slug: creation.slug,
                permissions: creation.permissions,
                lifetime: LifetimeRequest::from(&creation.lifetime),
            })
            .await?;
        let privilege = response.privilege.bind_scope(project_id, identity_id)?;
        validate_exact(
            &privilege,
            project_id,
            identity_id,
            None,
            expected_slug.as_ref(),
            Some(&expected_permissions),
            Some(&expected_lifetime),
        )?;
        Ok(privilege)
    }

    /// Replace one privilege's slug and lifetime, optionally replacing all permissions.
    ///
    /// The current privilege is read and scope-validated before the mutation.
    ///
    /// # Errors
    ///
    /// Returns a typed client or scope-validation error. The mutation is sent once.
    pub async fn update_identity_project_additional_privilege(
        &self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
        privilege_id: &AdditionalPrivilegeId,
        change: AdditionalPrivilegeChange,
    ) -> Result<IdentityProjectAdditionalPrivilege, ResourceError> {
        self.preflight_identity_project_additional_privilege(project_id, identity_id, privilege_id)
            .await?;
        let expected_slug = change.slug.clone();
        let expected_permissions = change.permissions.clone();
        let expected_lifetime = change.lifetime.clone();
        let response = self
            .execute_mutation::<UpdatePrivilege>(&UpdatePrivilegeRequest {
                privilege_id: privilege_id.clone(),
                slug: change.slug,
                permissions: change.permissions,
                lifetime: LifetimeRequest::from(&change.lifetime),
            })
            .await?;
        let privilege = response.privilege.bind_scope(project_id, identity_id)?;
        validate_exact(
            &privilege,
            project_id,
            identity_id,
            Some(privilege_id),
            Some(&expected_slug),
            expected_permissions.as_deref(),
            Some(&expected_lifetime),
        )?;
        Ok(privilege)
    }

    /// Delete one exact privilege after a scope-validated preflight and explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, typed client, or scope-validation error. The mutation is sent once.
    pub async fn delete_identity_project_additional_privilege(
        &self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
        privilege_id: &AdditionalPrivilegeId,
        confirm: bool,
    ) -> Result<IdentityProjectAdditionalPrivilege, ResourceError> {
        if !confirm {
            return Err(ResourceError::AdditionalPrivilegeDeletionNotConfirmed);
        }
        self.preflight_identity_project_additional_privilege(project_id, identity_id, privilege_id)
            .await?;
        let response = self
            .execute_mutation::<DeletePrivilege>(&DeletePrivilegeRequest {
                privilege_id: privilege_id.clone(),
            })
            .await?;
        let privilege = response.privilege.bind_scope(project_id, identity_id)?;
        validate_exact(
            &privilege,
            project_id,
            identity_id,
            Some(privilege_id),
            None,
            None,
            None,
        )?;
        Ok(privilege)
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
        AdditionalPrivilegeChange, AdditionalPrivilegeCreation, AdditionalPrivilegeId,
        AdditionalPrivilegeInputError, AdditionalPrivilegeLifetime, AdditionalPrivilegeSlug,
        AdditionalPrivilegeStartTime, IdentityId, InfisicalClient, PageRequest, ProjectId,
        ProjectSlug, ResourceError, RolePermission,
        test_support::{mount_login, settings},
    };

    fn permission(subject: Option<&str>, actions: &[&str]) -> RolePermission {
        RolePermission {
            subject: subject.map(str::to_owned),
            action: actions.iter().map(|action| (*action).to_owned()).collect(),
            conditions: None,
            inverted: false,
        }
    }

    fn serialized_privilege() -> Value {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/infisical-v0.160.12/identity-project-additional-privilege.json"
        )))
        .unwrap()
    }

    fn summary(id: &str, slug: &str, _project_id: &str, _identity_id: &str) -> Value {
        let mut privilege = serialized_privilege();
        privilege["id"] = json!(id);
        privilege["slug"] = json!(slug);
        privilege.as_object_mut().unwrap().remove("permissions");
        privilege
    }

    fn exact(id: &str, slug: &str, _project_id: &str, _identity_id: &str) -> Value {
        let mut privilege = serialized_privilege();
        privilege["id"] = json!(id);
        privilege["slug"] = json!(slug);
        privilege["permissions"] = json!([{
            "subject": "secrets",
            "action": ["read"],
            "inverted": false
        }]);
        privilege
    }

    fn exact_without_permissions(
        id: &str,
        slug: &str,
        project_id: &str,
        identity_id: &str,
    ) -> Value {
        let mut privilege = exact(id, slug, project_id, identity_id);
        privilege["permissions"] = json!([]);
        privilege
    }

    fn temporary_exact(id: &str, slug: &str, project_id: &str, identity_id: &str) -> Value {
        let mut privilege = exact(id, slug, project_id, identity_id);
        privilege["isTemporary"] = json!(true);
        privilege["temporaryMode"] = json!("relative");
        privilege["temporaryRange"] = json!("3600s");
        privilege["temporaryAccessStartTime"] = json!("2026-07-20T12:00:00.000Z");
        privilege["temporaryAccessEndTime"] = json!("2026-07-20T13:00:00.000Z");
        privilege
    }

    fn with_public_scope(mut privilege: Value) -> Value {
        privilege["projectId"] = json!("project-1");
        privilege["identityId"] = json!("identity-1");
        privilege
    }

    #[test]
    fn inputs_reject_noncanonical_schedules_and_unbounded_permissions() {
        assert_eq!(
            AdditionalPrivilegeSlug::new("Bad Slug").unwrap_err(),
            AdditionalPrivilegeInputError::InvalidSlug
        );
        assert_eq!(
            AdditionalPrivilegeStartTime::new("2025-02-29T12:00:00Z").unwrap_err(),
            AdditionalPrivilegeInputError::InvalidStartTime
        );
        assert!(AdditionalPrivilegeStartTime::new("2024-02-29T12:00:00Z").is_ok());
        for timestamp in [
            "not-a-timestamp",
            "2026-04-31T12:00:00Z",
            "2026-07-20T24:00:00Z",
            "2026-07-20T12:60:00Z",
            "2026-07-20T12:00:60Z",
        ] {
            assert_eq!(
                AdditionalPrivilegeStartTime::new(timestamp).unwrap_err(),
                AdditionalPrivilegeInputError::InvalidStartTime
            );
        }
        let start = AdditionalPrivilegeStartTime::new("2026-07-20T12:00:00Z").unwrap();
        assert_eq!(
            AdditionalPrivilegeLifetime::temporary(0, start).unwrap_err(),
            AdditionalPrivilegeInputError::InvalidDuration
        );
        assert_eq!(
            AdditionalPrivilegeCreation::new(
                None,
                vec![permission(None, &["read"])],
                false,
                AdditionalPrivilegeLifetime::Permanent,
            )
            .unwrap_err(),
            AdditionalPrivilegeInputError::InvalidPermissionSubject
        );
        assert_eq!(
            AdditionalPrivilegeChange::new(
                AdditionalPrivilegeSlug::new("auditor").unwrap(),
                Some(vec![permission(Some("secrets"), &[])]),
                true,
                AdditionalPrivilegeLifetime::Permanent,
            )
            .unwrap_err(),
            AdditionalPrivilegeInputError::InvalidPermissionActions
        );
        assert_eq!(
            AdditionalPrivilegeChange::new(
                AdditionalPrivilegeSlug::new("auditor").unwrap(),
                Some(Vec::new()),
                false,
                AdditionalPrivilegeLifetime::Permanent,
            )
            .unwrap_err(),
            AdditionalPrivilegeInputError::PermissionReplacementNotConfirmed
        );
        let mut deny_rule = permission(Some("secrets"), &["read"]);
        deny_rule.inverted = true;
        assert_eq!(
            AdditionalPrivilegeCreation::new(
                None,
                vec![deny_rule.clone()],
                false,
                AdditionalPrivilegeLifetime::Permanent,
            )
            .unwrap_err(),
            AdditionalPrivilegeInputError::InvertedPermissionsNotConfirmed
        );
        assert!(
            AdditionalPrivilegeCreation::new(
                None,
                vec![deny_rule],
                true,
                AdditionalPrivilegeLifetime::Permanent,
            )
            .is_ok()
        );
        assert!(
            AdditionalPrivilegeLifetime::temporary(
                super::MAX_ADDITIONAL_PRIVILEGE_DURATION_SECONDS,
                AdditionalPrivilegeStartTime::new("2026-07-20T12:00:00Z").unwrap(),
            )
            .is_ok()
        );
        assert_eq!(
            AdditionalPrivilegeLifetime::temporary(
                super::MAX_ADDITIONAL_PRIVILEGE_DURATION_SECONDS + 1,
                AdditionalPrivilegeStartTime::new("2026-07-20T12:00:00Z").unwrap(),
            )
            .unwrap_err(),
            AdditionalPrivilegeInputError::InvalidDuration
        );
    }

    #[test]
    fn schedules_validate_every_canonical_component_and_calendar_branch() {
        for separator in [4, 7, 10, 13, 16, 19] {
            let mut timestamp = b"2026-07-20T12:00:00Z".to_vec();
            timestamp[separator] = b'X';
            assert_eq!(
                AdditionalPrivilegeStartTime::new(String::from_utf8(timestamp).unwrap())
                    .unwrap_err(),
                AdditionalPrivilegeInputError::InvalidStartTime
            );
        }

        for timestamp in [
            "2026-02-28T12:00:00Z",
            "2026-04-30T12:00:00Z",
            "2026-06-30T12:00:00Z",
            "2026-09-30T12:00:00Z",
            "2026-11-30T12:00:00Z",
        ] {
            assert!(AdditionalPrivilegeStartTime::new(timestamp).is_ok());
        }
    }

    #[test]
    fn response_schedule_parsers_enforce_pinned_formats_and_bounds() {
        for (value, expected_millis) in [
            ("3600000", 3_600_000),
            ("3600s", 3_600_000),
            ("60 min", 3_600_000),
            ("1h", 3_600_000),
            ("0.5d", 43_200_000),
            ("1w", 604_800_000),
            ("1y", 31_557_600_000),
            ("315360000s", 315_360_000_000),
        ] {
            assert_eq!(super::duration_millis(value), Some(expected_millis));
        }
        for value in [
            "",
            ".5h",
            "1.h",
            "h",
            "0s",
            "1.5ms",
            "1fortnight",
            "315360001s",
            " 1h",
            "1h ",
        ] {
            assert_eq!(super::duration_millis(value), None);
        }
        let maximum_length = format!("1{}ms", " ".repeat(61));
        let oversized = format!("1{}ms", " ".repeat(62));
        assert_eq!(maximum_length.len(), 64);
        assert_eq!(super::duration_millis(&maximum_length), Some(1));
        assert_eq!(oversized.len(), 65);
        assert_eq!(super::duration_millis(&oversized), None);
        assert_eq!(
            super::utc_timestamp_millis("2026-07-20T12:00:00Z"),
            super::utc_timestamp_millis("2026-07-20T12:00:00.000Z")
        );
        for value in [
            "2026-07-20T12:00:00.00Z",
            "2026-07-20T12:00:00.0000Z",
            "2026-07-20T12:00:00.00XZ",
            "2026-07-20T12:00:00X000Z",
            "2026-07-20T12:00:00.000X",
        ] {
            assert_eq!(super::utc_timestamp_millis(value), None);
        }
    }

    #[test]
    fn serialized_scope_echoes_are_optional_but_must_match_the_request() {
        let project_id = ProjectId::new("project-1").unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let without_echoes =
            serde_json::from_value::<super::IdentityProjectAdditionalPrivilegeSummaryWire>(
                summary("privilege-1", "auditor", "project-1", "identity-1"),
            )
            .unwrap()
            .bind_scope(&project_id, &identity_id)
            .unwrap();
        assert_eq!(without_echoes.project_id, "project-1");
        assert_eq!(without_echoes.identity_id, "identity-1");

        for (field, value) in [
            ("projectId", json!("project-other")),
            ("identityId", json!("identity-other")),
        ] {
            let mut mismatched = summary("privilege-1", "auditor", "project-1", "identity-1");
            mismatched[field] = value;
            assert_eq!(
                serde_json::from_value::<super::IdentityProjectAdditionalPrivilegeSummaryWire>(
                    mismatched
                )
                .unwrap()
                .bind_scope(&project_id, &identity_id)
                .unwrap_err(),
                ResourceError::InvalidAdditionalPrivilegeScope
            );
        }
    }

    #[test]
    fn serialized_issue_fixture_preserves_permission_actions_and_conditions() {
        let project_id = ProjectId::new("project-1").unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let serialized = serialized_privilege();
        assert!(serialized.get("projectId").is_none());
        assert!(serialized.get("identityId").is_none());
        let privilege =
            serde_json::from_value::<super::IdentityProjectAdditionalPrivilegeWire>(serialized)
                .unwrap()
                .bind_scope(&project_id, &identity_id)
                .unwrap();

        super::validate_exact(
            &privilege,
            &project_id,
            &identity_id,
            None,
            None,
            None,
            Some(&AdditionalPrivilegeLifetime::Permanent),
        )
        .unwrap();
        assert_eq!(
            privilege.permissions[0].action,
            ["describeSecret", "readValue"]
        );
        assert_eq!(
            privilege.permissions[0].conditions,
            Some(json!({
                "environment": "prod",
                "secretPath": "/shared"
            }))
        );
    }

    #[test]
    fn timestamp_millis_preserves_calendar_and_clock_deltas() {
        const SECOND: i64 = 1_000;
        const MINUTE: i64 = 60 * SECOND;
        const HOUR: i64 = 60 * MINUTE;
        const DAY: i64 = 24 * HOUR;

        assert_eq!(
            super::utc_timestamp_millis("0001-01-01T00:00:00.000Z"),
            Some(0)
        );
        assert_eq!(
            super::utc_timestamp_millis("1970-01-01T00:00:00.000Z"),
            Some(62_135_596_800_000)
        );
        for (start, end, elapsed) in [
            ("0001-01-01T00:00:00.000Z", "0001-01-01T00:00:00.001Z", 1),
            (
                "2026-07-20T12:00:00.000Z",
                "2026-07-20T12:00:01.000Z",
                SECOND,
            ),
            (
                "2026-07-20T12:00:00.000Z",
                "2026-07-20T12:01:00.000Z",
                MINUTE,
            ),
            ("2026-07-20T12:00:00.000Z", "2026-07-20T13:00:00.000Z", HOUR),
            ("2026-07-20T00:00:00.000Z", "2026-07-21T00:00:00.000Z", DAY),
            (
                "2025-01-01T00:00:00.000Z",
                "2025-02-01T00:00:00.000Z",
                31 * DAY,
            ),
            (
                "2025-01-01T00:00:00.000Z",
                "2025-03-01T00:00:00.000Z",
                59 * DAY,
            ),
            (
                "2024-01-01T00:00:00.000Z",
                "2024-03-01T00:00:00.000Z",
                60 * DAY,
            ),
            ("2024-01-31T00:00:00.000Z", "2024-02-01T00:00:00.000Z", DAY),
            ("2025-02-28T00:00:00.000Z", "2025-03-01T00:00:00.000Z", DAY),
            (
                "2024-02-28T00:00:00.000Z",
                "2024-03-01T00:00:00.000Z",
                2 * DAY,
            ),
            (
                "1899-03-01T00:00:00.000Z",
                "1900-03-01T00:00:00.000Z",
                365 * DAY,
            ),
            (
                "1999-03-01T00:00:00.000Z",
                "2000-03-01T00:00:00.000Z",
                366 * DAY,
            ),
            (
                "2024-03-01T00:00:00.000Z",
                "2025-03-01T00:00:00.000Z",
                365 * DAY,
            ),
        ] {
            let start = super::utc_timestamp_millis(start).unwrap();
            let end = super::utc_timestamp_millis(end).unwrap();
            assert_eq!(end - start, elapsed);
        }
        assert!(super::utc_timestamp_millis("2026-12-31T23:59:59.999Z").is_some());
    }

    #[test]
    fn permission_sets_and_subjects_enforce_each_boundary() {
        let valid_rule = permission(Some("secrets"), &["read"]);
        assert!(
            AdditionalPrivilegeCreation::new(
                None,
                vec![valid_rule.clone(); super::MAX_ADDITIONAL_PRIVILEGE_PERMISSIONS],
                false,
                AdditionalPrivilegeLifetime::Permanent,
            )
            .is_ok()
        );
        assert_eq!(
            AdditionalPrivilegeCreation::new(
                None,
                vec![valid_rule.clone(); super::MAX_ADDITIONAL_PRIVILEGE_PERMISSIONS + 1],
                false,
                AdditionalPrivilegeLifetime::Permanent,
            )
            .unwrap_err(),
            AdditionalPrivilegeInputError::TooManyPermissions
        );

        for subject in [
            String::new(),
            "s".repeat(super::MAX_PERMISSION_TEXT_BYTES + 1),
            " padded".to_owned(),
            "control\u{7}".to_owned(),
        ] {
            let rule = permission(Some(&subject), &["read"]);
            assert_eq!(
                AdditionalPrivilegeCreation::new(
                    None,
                    vec![rule],
                    false,
                    AdditionalPrivilegeLifetime::Permanent,
                )
                .unwrap_err(),
                AdditionalPrivilegeInputError::InvalidPermissionSubject
            );
        }
        assert!(
            AdditionalPrivilegeCreation::new(
                None,
                vec![permission(
                    Some(&"s".repeat(super::MAX_PERMISSION_TEXT_BYTES)),
                    &["read"],
                )],
                false,
                AdditionalPrivilegeLifetime::Permanent,
            )
            .is_ok()
        );
    }

    #[test]
    fn permission_actions_and_conditions_enforce_each_boundary() {
        let valid_rule = permission(Some("secrets"), &["read"]);

        let mut too_many_actions = valid_rule.clone();
        too_many_actions.action =
            vec!["read".to_owned(); super::MAX_ADDITIONAL_PRIVILEGE_ACTIONS + 1];
        assert_eq!(
            AdditionalPrivilegeCreation::new(
                None,
                vec![too_many_actions],
                false,
                AdditionalPrivilegeLifetime::Permanent,
            )
            .unwrap_err(),
            AdditionalPrivilegeInputError::InvalidPermissionActions
        );
        for action in [
            String::new(),
            "a".repeat(super::MAX_PERMISSION_TEXT_BYTES + 1),
            " padded".to_owned(),
            "control\u{7}".to_owned(),
        ] {
            let mut rule = valid_rule.clone();
            rule.action = vec![action];
            assert_eq!(
                AdditionalPrivilegeCreation::new(
                    None,
                    vec![rule],
                    false,
                    AdditionalPrivilegeLifetime::Permanent,
                )
                .unwrap_err(),
                AdditionalPrivilegeInputError::InvalidPermissionActions
            );
        }
        let mut boundary_action = valid_rule.clone();
        boundary_action.action = vec!["a".repeat(super::MAX_PERMISSION_TEXT_BYTES)];
        assert!(
            AdditionalPrivilegeCreation::new(
                None,
                vec![boundary_action],
                false,
                AdditionalPrivilegeLifetime::Permanent,
            )
            .is_ok()
        );

        let mut boundary_condition = valid_rule.clone();
        boundary_condition.conditions = Some(Value::String(
            "x".repeat(super::MAX_ADDITIONAL_PRIVILEGE_CONDITION_BYTES - 2),
        ));
        assert!(
            AdditionalPrivilegeCreation::new(
                None,
                vec![boundary_condition],
                false,
                AdditionalPrivilegeLifetime::Permanent,
            )
            .is_ok()
        );
        let mut oversized_condition = valid_rule;
        oversized_condition.conditions = Some(Value::String(
            "x".repeat(super::MAX_ADDITIONAL_PRIVILEGE_CONDITION_BYTES - 1),
        ));
        assert_eq!(
            AdditionalPrivilegeCreation::new(
                None,
                vec![oversized_condition],
                false,
                AdditionalPrivilegeLifetime::Permanent,
            )
            .unwrap_err(),
            AdditionalPrivilegeInputError::ConditionTooLarge
        );
    }

    #[test]
    fn summaries_require_all_and_only_temporary_schedule_fields() {
        let project_id = ProjectId::new("project-1").unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        for field in [
            "temporaryMode",
            "temporaryRange",
            "temporaryAccessStartTime",
            "temporaryAccessEndTime",
        ] {
            let mut value = temporary_exact(
                "privilege-1",
                "temporary-auditor",
                "project-1",
                "identity-1",
            );
            value[field] = Value::Null;
            let parsed = serde_json::from_value(with_public_scope(value)).unwrap();
            assert_eq!(
                super::validate_summary(&parsed, &project_id, &identity_id, None, None)
                    .unwrap_err(),
                ResourceError::InvalidAdditionalPrivilegeLifetime
            );
        }

        for (field, value) in [
            ("temporaryMode", json!("relative")),
            ("temporaryRange", json!("3600s")),
            (
                "temporaryAccessStartTime",
                json!("2026-07-20T12:00:00.000Z"),
            ),
            ("temporaryAccessEndTime", json!("2026-07-20T13:00:00.000Z")),
        ] {
            let mut malformed = summary("privilege-1", "auditor", "project-1", "identity-1");
            malformed[field] = value;
            let parsed = serde_json::from_value(with_public_scope(malformed)).unwrap();
            assert_eq!(
                super::validate_summary(&parsed, &project_id, &identity_id, None, None)
                    .unwrap_err(),
                ResourceError::InvalidAdditionalPrivilegeLifetime
            );
        }

        for (field, value) in [
            ("temporaryRange", json!("not-a-duration")),
            ("temporaryAccessStartTime", json!("not-a-timestamp")),
            ("temporaryAccessEndTime", json!("2026-07-20T12:30:00.000Z")),
        ] {
            let mut malformed = temporary_exact(
                "privilege-1",
                "temporary-auditor",
                "project-1",
                "identity-1",
            );
            malformed[field] = value;
            let parsed = serde_json::from_value(with_public_scope(malformed)).unwrap();
            assert_eq!(
                super::validate_summary(&parsed, &project_id, &identity_id, None, None)
                    .unwrap_err(),
                ResourceError::InvalidAdditionalPrivilegeLifetime
            );
        }
    }

    #[test]
    fn exact_validation_matches_the_requested_temporary_start_and_duration() {
        let privilege = serde_json::from_value(with_public_scope(temporary_exact(
            "privilege-1",
            "temporary-auditor",
            "project-1",
            "identity-1",
        )))
        .unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let start = AdditionalPrivilegeStartTime::new("2026-07-20T12:00:00Z").unwrap();
        let wrong_start = AdditionalPrivilegeStartTime::new("2026-07-20T12:30:00Z").unwrap();
        assert_eq!(
            super::validate_exact(
                &privilege,
                &project_id,
                &identity_id,
                None,
                None,
                Some(&[]),
                None,
            )
            .unwrap_err(),
            ResourceError::InvalidAdditionalPrivilegePermissions
        );
        for lifetime in [
            AdditionalPrivilegeLifetime::temporary(7_200, start).unwrap(),
            AdditionalPrivilegeLifetime::temporary(3_600, wrong_start).unwrap(),
        ] {
            assert_eq!(
                super::validate_exact(
                    &privilege,
                    &project_id,
                    &identity_id,
                    None,
                    None,
                    None,
                    Some(&lifetime),
                )
                .unwrap_err(),
                ResourceError::InvalidAdditionalPrivilegeLifetime
            );
        }
    }

    #[tokio::test]
    async fn list_and_exact_reads_use_the_scoped_v2_contracts() {
        let server = MockServer::start().await;
        mount_login(&server, "privilege-read-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v2/identity-project-additional-privilege"))
            .and(query_param("projectId", "project-1"))
            .and(query_param("identityId", "identity-1"))
            .and(header("authorization", "Bearer privilege-read-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privileges": [
                    summary("privilege-1", "auditor", "project-1", "identity-1"),
                    summary("privilege-2", "operator", "project-1", "identity-1")
                ]
            })))
            .expect(3)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v2/identity-project-additional-privilege/privilege-1",
            ))
            .and(header("authorization", "Bearer privilege-read-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privilege": exact("privilege-1", "auditor", "project-1", "identity-1")
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v2/identity-project-additional-privilege/slug/auditor",
            ))
            .and(query_param("projectSlug", "payments"))
            .and(query_param("identityId", "identity-1"))
            .and(header("authorization", "Bearer privilege-read-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privilege": exact("privilege-1", "auditor", "project-1", "identity-1")
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let privilege_id = AdditionalPrivilegeId::new("privilege-1").unwrap();
        let slug = AdditionalPrivilegeSlug::new("auditor").unwrap();
        let page = client
            .list_identity_project_additional_privileges(
                &project_id,
                &identity_id,
                PageRequest::new(1, 1).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.items[0].slug, "operator");
        assert_eq!(page.total, Some(2));
        let by_id = client
            .get_identity_project_additional_privilege(&project_id, &identity_id, &privilege_id)
            .await
            .unwrap();
        assert_eq!(
            by_id.permissions,
            vec![permission(Some("secrets"), &["read"])]
        );
        let by_slug = client
            .get_identity_project_additional_privilege_by_slug(
                &project_id,
                &ProjectSlug::new("payments").unwrap(),
                &identity_id,
                &slug,
            )
            .await
            .unwrap();
        assert_eq!(by_slug.summary.id, "privilege-1");
    }

    #[tokio::test]
    async fn creates_permanent_and_temporary_privileges_once() {
        let server = MockServer::start().await;
        mount_login(&server, "privilege-create-token").await;
        let permission_body = json!([{
            "subject": "secrets",
            "action": ["read"],
            "inverted": false
        }]);
        for (body, slug, response) in [
            (
                json!({
                    "projectId": "project-1",
                    "identityId": "identity-1",
                    "slug": "auditor",
                    "permissions": permission_body,
                    "type": { "isTemporary": false }
                }),
                "auditor",
                exact("privilege-1", "auditor", "project-1", "identity-1"),
            ),
            (
                json!({
                    "projectId": "project-1",
                    "identityId": "identity-1",
                    "slug": "temporary-auditor",
                    "permissions": permission_body,
                    "type": {
                        "isTemporary": true,
                        "temporaryMode": "relative",
                        "temporaryRange": "3600s",
                        "temporaryAccessStartTime": "2026-07-20T12:00:00Z"
                    }
                }),
                "temporary-auditor",
                temporary_exact(
                    "privilege-2",
                    "temporary-auditor",
                    "project-1",
                    "identity-1",
                ),
            ),
        ] {
            Mock::given(method("POST"))
                .and(path("/api/v2/identity-project-additional-privilege"))
                .and(header("authorization", "Bearer privilege-create-token"))
                .and(body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "privilege": response
                })))
                .expect(1)
                .mount(&server)
                .await;
            assert!(!slug.is_empty());
        }

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let rules = vec![permission(Some("secrets"), &["read"])];
        client
            .create_identity_project_additional_privilege(
                &project_id,
                &identity_id,
                AdditionalPrivilegeCreation::new(
                    Some(AdditionalPrivilegeSlug::new("auditor").unwrap()),
                    rules.clone(),
                    false,
                    AdditionalPrivilegeLifetime::Permanent,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let lifetime = AdditionalPrivilegeLifetime::temporary(
            3_600,
            AdditionalPrivilegeStartTime::new("2026-07-20T12:00:00Z").unwrap(),
        )
        .unwrap();
        client
            .create_identity_project_additional_privilege(
                &project_id,
                &identity_id,
                AdditionalPrivilegeCreation::new(
                    Some(AdditionalPrivilegeSlug::new("temporary-auditor").unwrap()),
                    rules,
                    false,
                    lifetime,
                )
                .unwrap(),
            )
            .await
            .unwrap();
    }

    async fn mount_update_and_delete_fixtures(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/v2/identity-project-additional-privilege"))
            .and(query_param("projectId", "project-1"))
            .and(query_param("identityId", "identity-1"))
            .and(header("authorization", "Bearer privilege-admin-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privileges": [
                    summary("privilege-1", "auditor", "project-1", "identity-1")
                ]
            })))
            .expect(3)
            .mount(server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/api/v2/identity-project-additional-privilege/privilege-1",
            ))
            .and(body_json(json!({
                "slug": "operator",
                "permissions": [],
                "type": { "isTemporary": false }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privilege": exact_without_permissions(
                    "privilege-1",
                    "operator",
                    "project-1",
                    "identity-1"
                )
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/api/v2/identity-project-additional-privilege/privilege-1",
            ))
            .and(body_json(json!({
                "slug": "operator-preserved",
                "type": { "isTemporary": false }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privilege": exact(
                    "privilege-1",
                    "operator-preserved",
                    "project-1",
                    "identity-1"
                )
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v2/identity-project-additional-privilege/privilege-1",
            ))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privilege": exact("privilege-1", "operator", "project-1", "identity-1")
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn update_and_delete_preflight_scope_and_mutate_once() {
        let server = MockServer::start().await;
        mount_login(&server, "privilege-admin-token").await;
        mount_update_and_delete_fixtures(&server).await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let privilege_id = AdditionalPrivilegeId::new("privilege-1").unwrap();
        let replaced = client
            .update_identity_project_additional_privilege(
                &project_id,
                &identity_id,
                &privilege_id,
                AdditionalPrivilegeChange::new(
                    AdditionalPrivilegeSlug::new("operator").unwrap(),
                    Some(Vec::new()),
                    true,
                    AdditionalPrivilegeLifetime::Permanent,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(replaced.permissions.is_empty());
        client
            .update_identity_project_additional_privilege(
                &project_id,
                &identity_id,
                &privilege_id,
                AdditionalPrivilegeChange::new(
                    AdditionalPrivilegeSlug::new("operator-preserved").unwrap(),
                    None,
                    false,
                    AdditionalPrivilegeLifetime::Permanent,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            client
                .delete_identity_project_additional_privilege(
                    &project_id,
                    &identity_id,
                    &privilege_id,
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::AdditionalPrivilegeDeletionNotConfirmed
        );
        client
            .delete_identity_project_additional_privilege(
                &project_id,
                &identity_id,
                &privilege_id,
                true,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn mismatched_preflight_scope_blocks_the_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "privilege-scope-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v2/identity-project-additional-privilege"))
            .and(query_param("projectId", "project-1"))
            .and(query_param("identityId", "identity-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privileges": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/api/v2/identity-project-additional-privilege/privilege-1",
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let result = client
            .update_identity_project_additional_privilege(
                &ProjectId::new("project-1").unwrap(),
                &IdentityId::new("identity-1").unwrap(),
                &AdditionalPrivilegeId::new("privilege-1").unwrap(),
                AdditionalPrivilegeChange::new(
                    AdditionalPrivilegeSlug::new("operator").unwrap(),
                    None,
                    false,
                    AdditionalPrivilegeLifetime::Permanent,
                )
                .unwrap(),
            )
            .await;
        assert_eq!(
            result.unwrap_err(),
            ResourceError::InvalidAdditionalPrivilegeScope
        );
    }

    #[tokio::test]
    async fn exact_reads_reject_incoherent_lifetimes_and_permissions() {
        let server = MockServer::start().await;
        mount_login(&server, "privilege-invalid-response-token").await;
        let mut incoherent = exact(
            "privilege-lifetime",
            "temporary-auditor",
            "project-1",
            "identity-1",
        );
        incoherent["isTemporary"] = json!(true);
        Mock::given(method("GET"))
            .and(path(
                "/api/v2/identity-project-additional-privilege/privilege-lifetime",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privilege": incoherent
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut malformed = exact(
            "privilege-permissions",
            "auditor",
            "project-1",
            "identity-1",
        );
        malformed["permissions"][0]["subject"] = Value::Null;
        Mock::given(method("GET"))
            .and(path("/api/v2/identity-project-additional-privilege"))
            .and(query_param("projectId", "project-1"))
            .and(query_param("identityId", "identity-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privileges": [
                    summary(
                        "privilege-lifetime",
                        "temporary-auditor",
                        "project-1",
                        "identity-1"
                    ),
                    summary(
                        "privilege-permissions",
                        "auditor",
                        "project-1",
                        "identity-1"
                    )
                ]
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v2/identity-project-additional-privilege/privilege-permissions",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privilege": malformed
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        let lifetime_error = client
            .get_identity_project_additional_privilege(
                &project_id,
                &identity_id,
                &AdditionalPrivilegeId::new("privilege-lifetime").unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            lifetime_error,
            ResourceError::InvalidAdditionalPrivilegeLifetime
        );
        let permission_error = client
            .get_identity_project_additional_privilege(
                &project_id,
                &identity_id,
                &AdditionalPrivilegeId::new("privilege-permissions").unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            permission_error,
            ResourceError::InvalidAdditionalPrivilegePermissions
        );
    }
}
