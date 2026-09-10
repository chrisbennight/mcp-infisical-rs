use std::{collections::HashSet, net::IpAddr};

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    InfisicalClient, MutationOperation, ObservableReadOperation, ResourceError,
    client::{ApiVersion, Endpoint, sealed},
    resources::is_uuid,
    ssh_certificate_authorities::{SshCaStatus, SshCertificateAuthorityId, SshProjectId},
};

const MAX_SSH_TEMPLATE_ENTRIES: usize = 500;
const MAX_SSH_TEMPLATE_NAME_BYTES: usize = 36;
const MAX_SSH_TEMPLATE_PATTERNS: usize = 128;
const MAX_SSH_USER_PATTERN_BYTES: usize = 32;
const MAX_SSH_DURATION_MILLIS: u64 = 315_360_000_000;

/// Input validation failures for SSH certificate templates.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SshCertificateTemplateInputError {
    #[error("SSH certificate-template ID must be a UUID")]
    InvalidId,
    #[error(
        "SSH certificate-template name must contain 1 to 36 lowercase letters or numbers separated by single hyphens"
    )]
    InvalidName,
    #[error(
        "SSH certificate-template duration must be a canonical positive duration up to ten years"
    )]
    InvalidDuration,
    #[error("SSH certificate-template maximum TTL must be greater than or equal to its TTL")]
    InvalidDurationOrder,
    #[error("SSH certificate templates must enable at least one certificate type")]
    NoCertificateType,
    #[error("enabled SSH user certificates require at least one valid unique user pattern")]
    InvalidUserPatterns,
    #[error("enabled SSH host certificates require at least one valid unique host pattern")]
    InvalidHostPatterns,
}

/// A validated SSH certificate-template identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SshCertificateTemplateId(String);

impl SshCertificateTemplateId {
    /// Validate a UUID before it reaches an SSH template URL path.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, SshCertificateTemplateInputError> {
        let value = value.into();
        if !is_uuid(&value) {
            return Err(SshCertificateTemplateInputError::InvalidId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lifecycle state of an SSH certificate template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SshCertificateTemplateStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "disabled")]
    Disabled,
}

/// A canonical positive SSH TTL expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SshDuration(String);

impl SshDuration {
    /// Validate an integer duration using `ms`, `s`, `m`, `h`, `d`, or `w`.
    ///
    /// # Errors
    ///
    /// Returns an error for zero, malformed, non-canonical, or excessive values.
    pub fn new(value: impl Into<String>) -> Result<Self, SshCertificateTemplateInputError> {
        let value = value.into();
        if duration_millis(&value).is_none() {
            return Err(SshCertificateTemplateInputError::InvalidDuration);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical duration expression.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn millis(&self) -> u64 {
        duration_millis(&self.0).expect("SshDuration construction proves its invariant")
    }
}

/// Complete input for creating an SSH certificate template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCertificateTemplateCreation {
    name: String,
    ttl: SshDuration,
    max_ttl: SshDuration,
    allowed_users: Vec<String>,
    allowed_hosts: Vec<String>,
    allow_user_certificates: bool,
    allow_host_certificates: bool,
    allow_custom_key_ids: bool,
}

impl SshCertificateTemplateCreation {
    /// Validate a complete SSH certificate-template policy.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed names, durations, patterns, or disabled policy families.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        ttl: SshDuration,
        max_ttl: SshDuration,
        allowed_users: Vec<String>,
        allowed_hosts: Vec<String>,
        allow_user_certificates: bool,
        allow_host_certificates: bool,
        allow_custom_key_ids: bool,
    ) -> Result<Self, SshCertificateTemplateInputError> {
        let name = validate_name(name.into())?;
        validate_policy(
            &ttl,
            &max_ttl,
            &allowed_users,
            &allowed_hosts,
            allow_user_certificates,
            allow_host_certificates,
        )?;
        Ok(Self {
            name,
            ttl,
            max_ttl,
            allowed_users,
            allowed_hosts,
            allow_user_certificates,
            allow_host_certificates,
            allow_custom_key_ids,
        })
    }
}

/// Full replacement of every mutable SSH certificate-template field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCertificateTemplateReplacement {
    status: SshCertificateTemplateStatus,
    policy: SshCertificateTemplateCreation,
}

impl SshCertificateTemplateReplacement {
    /// Combine a lifecycle state with a fully validated policy replacement.
    #[must_use]
    pub const fn new(
        status: SshCertificateTemplateStatus,
        policy: SshCertificateTemplateCreation,
    ) -> Self {
        Self { status, policy }
    }
}

/// Bounded SSH certificate-template metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshCertificateTemplate {
    /// Canonical template UUID.
    pub id: String,
    /// Canonical owning SSH project UUID, bound from the audited route.
    pub project_id: String,
    /// Canonical owning SSH CA UUID.
    pub ssh_ca_id: String,
    /// Current lifecycle state.
    pub status: SshCertificateTemplateStatus,
    /// Canonical template slug.
    pub name: String,
    /// Default certificate lifetime.
    pub ttl: SshDuration,
    /// Maximum requested certificate lifetime.
    #[serde(rename = "maxTTL")]
    pub max_ttl: SshDuration,
    /// Bounded unique user patterns.
    pub allowed_users: Vec<String>,
    /// Bounded unique host patterns.
    pub allowed_hosts: Vec<String>,
    /// Whether user certificates may be issued.
    pub allow_user_certificates: bool,
    /// Whether host certificates may be issued.
    pub allow_host_certificates: bool,
    /// Whether callers may choose certificate key IDs.
    pub allow_custom_key_ids: bool,
}

fn duration_millis(value: &str) -> Option<u64> {
    let digit_count = value.bytes().take_while(u8::is_ascii_digit).count();
    if digit_count == 0 || value.starts_with('0') {
        return None;
    }
    let amount = value[..digit_count].parse::<u64>().ok()?;
    let multiplier = match &value[digit_count..] {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        "w" => 604_800_000,
        _ => return None,
    };
    let millis = amount.checked_mul(multiplier)?;
    (millis <= MAX_SSH_DURATION_MILLIS).then_some(millis)
}

fn validate_name(value: String) -> Result<String, SshCertificateTemplateInputError> {
    if value.is_empty()
        || value.len() > MAX_SSH_TEMPLATE_NAME_BYTES
        || !value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
    {
        return Err(SshCertificateTemplateInputError::InvalidName);
    }
    Ok(value)
}

pub(crate) fn valid_user_pattern(value: &str) -> bool {
    if value == "*" {
        return true;
    }
    if value.is_empty() || value.len() > MAX_SSH_USER_PATTERN_BYTES {
        return false;
    }
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn valid_host_pattern(value: &str) -> bool {
    if value == "*" || value.parse::<IpAddr>().is_ok() {
        return true;
    }
    let domain = value.strip_prefix("*.").unwrap_or(value);
    domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn patterns_are_valid(values: &[String], validator: impl Fn(&str) -> bool) -> bool {
    values.len() <= MAX_SSH_TEMPLATE_PATTERNS
        && values.iter().all(|value| validator(value))
        && values.iter().collect::<HashSet<_>>().len() == values.len()
}

fn validate_policy(
    ttl: &SshDuration,
    max_ttl: &SshDuration,
    allowed_users: &[String],
    allowed_hosts: &[String],
    allow_user_certificates: bool,
    allow_host_certificates: bool,
) -> Result<(), SshCertificateTemplateInputError> {
    if max_ttl.millis() < ttl.millis() {
        return Err(SshCertificateTemplateInputError::InvalidDurationOrder);
    }
    if !allow_user_certificates && !allow_host_certificates {
        return Err(SshCertificateTemplateInputError::NoCertificateType);
    }
    if !patterns_are_valid(allowed_users, valid_user_pattern)
        || (allow_user_certificates && allowed_users.is_empty())
    {
        return Err(SshCertificateTemplateInputError::InvalidUserPatterns);
    }
    if !patterns_are_valid(allowed_hosts, valid_host_pattern)
        || (allow_host_certificates && allowed_hosts.is_empty())
    {
        return Err(SshCertificateTemplateInputError::InvalidHostPatterns);
    }
    Ok(())
}

#[derive(Serialize)]
struct ProjectTemplateQuery {
    #[serde(skip_serializing)]
    project_id: SshProjectId,
}

#[derive(Serialize)]
struct CaTemplateQuery {
    #[serde(skip_serializing)]
    ca_id: SshCertificateAuthorityId,
}

#[derive(Serialize)]
struct ExactTemplateQuery {
    #[serde(skip_serializing)]
    template_id: SshCertificateTemplateId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshCertificateTemplateWire {
    id: String,
    ssh_ca_id: String,
    status: SshCertificateTemplateStatus,
    name: String,
    ttl: String,
    #[serde(rename = "maxTTL")]
    max_ttl: String,
    allowed_users: Vec<String>,
    allowed_hosts: Vec<String>,
    allow_custom_key_ids: bool,
    allow_user_certificates: bool,
    allow_host_certificates: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshCertificateTemplateListResponse {
    certificate_templates: Vec<SshCertificateTemplateWire>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSshCertificateTemplateRequest {
    ssh_ca_id: String,
    name: String,
    ttl: String,
    #[serde(rename = "maxTTL")]
    max_ttl: String,
    allowed_users: Vec<String>,
    allowed_hosts: Vec<String>,
    allow_user_certificates: bool,
    allow_host_certificates: bool,
    allow_custom_key_ids: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplaceSshCertificateTemplateRequest {
    #[serde(skip_serializing)]
    template_id: SshCertificateTemplateId,
    status: SshCertificateTemplateStatus,
    name: String,
    ttl: String,
    #[serde(rename = "maxTTL")]
    max_ttl: String,
    allowed_users: Vec<String>,
    allowed_hosts: Vec<String>,
    allow_user_certificates: bool,
    allow_host_certificates: bool,
    allow_custom_key_ids: bool,
}

#[derive(Serialize)]
struct DeleteSshCertificateTemplateRequest {
    #[serde(skip_serializing)]
    template_id: SshCertificateTemplateId,
}

struct ListProjectSshCertificateTemplates;
impl sealed::Sealed for ListProjectSshCertificateTemplates {}
impl ObservableReadOperation for ListProjectSshCertificateTemplates {
    type Query = ProjectTemplateQuery;
    type Output = SshCertificateTemplateListResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects",
                query.project_id.as_str(),
                "ssh-certificate-templates",
            ],
        )
    }
}

struct ListSshCaCertificateTemplates;
impl sealed::Sealed for ListSshCaCertificateTemplates {}
impl ObservableReadOperation for ListSshCaCertificateTemplates {
    type Query = CaTemplateQuery;
    type Output = SshCertificateTemplateListResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["ssh", "ca", query.ca_id.as_str(), "certificate-templates"],
        )
    }
}

struct GetSshCertificateTemplate;
impl sealed::Sealed for GetSshCertificateTemplate {}
impl ObservableReadOperation for GetSshCertificateTemplate {
    type Query = ExactTemplateQuery;
    type Output = SshCertificateTemplateWire;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["ssh", "certificate-templates", query.template_id.as_str()],
        )
    }
}

macro_rules! ssh_template_mutation {
    ($operation:ident, $input:ty, $method:expr, $id:expr) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl MutationOperation for $operation {
            type Input = $input;
            type Output = SshCertificateTemplateWire;

            fn method() -> Method {
                $method
            }

            fn endpoint(input: &Self::Input) -> Endpoint {
                let mut segments = vec!["ssh".to_owned(), "certificate-templates".to_owned()];
                if let Some(id) = ($id)(input) {
                    segments.push(id);
                }
                Endpoint::from_segments(ApiVersion::V1, segments)
            }
        }
    };
}

ssh_template_mutation!(
    CreateSshCertificateTemplate,
    CreateSshCertificateTemplateRequest,
    Method::POST,
    |_input: &CreateSshCertificateTemplateRequest| None::<String>
);
ssh_template_mutation!(
    ReplaceSshCertificateTemplate,
    ReplaceSshCertificateTemplateRequest,
    Method::PATCH,
    |input: &ReplaceSshCertificateTemplateRequest| Some(input.template_id.as_str().to_owned())
);
ssh_template_mutation!(
    DeleteSshCertificateTemplate,
    DeleteSshCertificateTemplateRequest,
    Method::DELETE,
    |input: &DeleteSshCertificateTemplateRequest| Some(input.template_id.as_str().to_owned())
);

fn template_from_wire(
    wire: SshCertificateTemplateWire,
    project_id: &SshProjectId,
    expected_ca_id: Option<&SshCertificateAuthorityId>,
    expected_template_id: Option<&SshCertificateTemplateId>,
) -> Result<SshCertificateTemplate, ResourceError> {
    let template_id = SshCertificateTemplateId::new(wire.id)
        .map_err(|_| ResourceError::InvalidSshCertificateTemplateResponse)?;
    let ca_id = SshCertificateAuthorityId::new(wire.ssh_ca_id)
        .map_err(|_| ResourceError::InvalidSshCertificateTemplateResponse)?;
    if expected_ca_id.is_some_and(|expected| expected != &ca_id)
        || expected_template_id.is_some_and(|expected| expected != &template_id)
    {
        return Err(ResourceError::InvalidSshCertificateTemplateScope);
    }
    let ttl = SshDuration::new(wire.ttl)
        .map_err(|_| ResourceError::InvalidSshCertificateTemplateResponse)?;
    let max_ttl = SshDuration::new(wire.max_ttl)
        .map_err(|_| ResourceError::InvalidSshCertificateTemplateResponse)?;
    validate_policy(
        &ttl,
        &max_ttl,
        &wire.allowed_users,
        &wire.allowed_hosts,
        wire.allow_user_certificates,
        wire.allow_host_certificates,
    )
    .map_err(|_| ResourceError::InvalidSshCertificateTemplateResponse)?;
    Ok(SshCertificateTemplate {
        id: template_id.as_str().to_owned(),
        project_id: project_id.as_str().to_owned(),
        ssh_ca_id: ca_id.as_str().to_owned(),
        status: wire.status,
        name: validate_name(wire.name)
            .map_err(|_| ResourceError::InvalidSshCertificateTemplateResponse)?,
        ttl,
        max_ttl,
        allowed_users: wire.allowed_users,
        allowed_hosts: wire.allowed_hosts,
        allow_user_certificates: wire.allow_user_certificates,
        allow_host_certificates: wire.allow_host_certificates,
        allow_custom_key_ids: wire.allow_custom_key_ids,
    })
}

fn list_from_wire(
    wires: Vec<SshCertificateTemplateWire>,
    project_id: &SshProjectId,
    expected_ca_id: Option<&SshCertificateAuthorityId>,
) -> Result<Vec<SshCertificateTemplate>, ResourceError> {
    if wires.len() > MAX_SSH_TEMPLATE_ENTRIES {
        return Err(ResourceError::InvalidSshCertificateTemplateResponse);
    }
    let templates = wires
        .into_iter()
        .map(|wire| template_from_wire(wire, project_id, expected_ca_id, None))
        .collect::<Result<Vec<_>, _>>()?;
    if templates
        .iter()
        .map(|template| template.id.as_str())
        .collect::<HashSet<_>>()
        .len()
        != templates.len()
    {
        return Err(ResourceError::InvalidSshCertificateTemplateResponse);
    }
    Ok(templates)
}

fn creation_request(
    ca_id: &SshCertificateAuthorityId,
    creation: &SshCertificateTemplateCreation,
) -> CreateSshCertificateTemplateRequest {
    CreateSshCertificateTemplateRequest {
        ssh_ca_id: ca_id.as_str().to_owned(),
        name: creation.name.clone(),
        ttl: creation.ttl.as_str().to_owned(),
        max_ttl: creation.max_ttl.as_str().to_owned(),
        allowed_users: creation.allowed_users.clone(),
        allowed_hosts: creation.allowed_hosts.clone(),
        allow_user_certificates: creation.allow_user_certificates,
        allow_host_certificates: creation.allow_host_certificates,
        allow_custom_key_ids: creation.allow_custom_key_ids,
    }
}

fn template_matches_policy(
    template: &SshCertificateTemplate,
    policy: &SshCertificateTemplateCreation,
) -> bool {
    template.name == policy.name
        && template.ttl == policy.ttl
        && template.max_ttl == policy.max_ttl
        && template.allowed_users == policy.allowed_users
        && template.allowed_hosts == policy.allowed_hosts
        && template.allow_user_certificates == policy.allow_user_certificates
        && template.allow_host_certificates == policy.allow_host_certificates
        && template.allow_custom_key_ids == policy.allow_custom_key_ids
}

impl InfisicalClient {
    pub(crate) async fn preflight_ssh_certificate_template(
        &self,
        project_id: &SshProjectId,
        ca_id: &SshCertificateAuthorityId,
        template_id: &SshCertificateTemplateId,
    ) -> Result<(crate::SshCertificateAuthority, SshCertificateTemplate), ResourceError> {
        let authority = self
            .get_ssh_certificate_authority(project_id, ca_id)
            .await?;
        let response = self
            .execute_observable_read::<GetSshCertificateTemplate>(&ExactTemplateQuery {
                template_id: template_id.clone(),
            })
            .await?;
        let template = template_from_wire(response, project_id, Some(ca_id), Some(template_id))?;
        Ok((authority, template))
    }

    /// List every bounded SSH certificate template in one SSH Access project.
    ///
    /// # Errors
    ///
    /// Returns a typed client, project-kind, duplicate, or response-contract error.
    pub async fn list_ssh_certificate_templates(
        &self,
        project_id: &SshProjectId,
    ) -> Result<Vec<SshCertificateTemplate>, ResourceError> {
        let response = self
            .execute_observable_read::<ListProjectSshCertificateTemplates>(&ProjectTemplateQuery {
                project_id: project_id.clone(),
            })
            .await?;
        list_from_wire(response.certificate_templates, project_id, None)
    }

    /// List bounded templates attached to one exact SSH CA.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, duplicate, or response-contract error.
    pub async fn list_ssh_certificate_authority_templates(
        &self,
        project_id: &SshProjectId,
        ca_id: &SshCertificateAuthorityId,
    ) -> Result<Vec<SshCertificateTemplate>, ResourceError> {
        self.get_ssh_certificate_authority(project_id, ca_id)
            .await?;
        let response = self
            .execute_observable_read::<ListSshCaCertificateTemplates>(&CaTemplateQuery {
                ca_id: ca_id.clone(),
            })
            .await?;
        list_from_wire(response.certificate_templates, project_id, Some(ca_id))
    }

    /// Get one exact SSH certificate template and prove its CA ownership.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or response-contract error.
    pub async fn get_ssh_certificate_template(
        &self,
        project_id: &SshProjectId,
        ca_id: &SshCertificateAuthorityId,
        template_id: &SshCertificateTemplateId,
    ) -> Result<SshCertificateTemplate, ResourceError> {
        self.preflight_ssh_certificate_template(project_id, ca_id, template_id)
            .await
            .map(|(_, template)| template)
    }

    /// Create one SSH certificate template beneath an active exact CA.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, state, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn create_ssh_certificate_template(
        &self,
        project_id: &SshProjectId,
        ca_id: &SshCertificateAuthorityId,
        creation: &SshCertificateTemplateCreation,
        confirm: bool,
    ) -> Result<SshCertificateTemplate, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshCertificateTemplateCreateNotConfirmed);
        }
        let authority = self
            .get_ssh_certificate_authority(project_id, ca_id)
            .await?;
        if authority.status != SshCaStatus::Active {
            return Err(ResourceError::InvalidSshCertificateAuthorityState);
        }
        let response = self
            .execute_mutation::<CreateSshCertificateTemplate>(&creation_request(ca_id, creation))
            .await?;
        let template = template_from_wire(response, project_id, Some(ca_id), None)?;
        if template.status != SshCertificateTemplateStatus::Active
            || !template_matches_policy(&template, creation)
        {
            return Err(ResourceError::InvalidSshCertificateTemplateResponse);
        }
        Ok(template)
    }

    /// Replace every mutable SSH certificate-template field.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn replace_ssh_certificate_template(
        &self,
        project_id: &SshProjectId,
        ca_id: &SshCertificateAuthorityId,
        template_id: &SshCertificateTemplateId,
        replacement: &SshCertificateTemplateReplacement,
        confirm: bool,
    ) -> Result<SshCertificateTemplate, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshCertificateTemplateReplaceNotConfirmed);
        }
        self.get_ssh_certificate_template(project_id, ca_id, template_id)
            .await?;
        let policy = &replacement.policy;
        let response = self
            .execute_mutation::<ReplaceSshCertificateTemplate>(
                &ReplaceSshCertificateTemplateRequest {
                    template_id: template_id.clone(),
                    status: replacement.status,
                    name: policy.name.clone(),
                    ttl: policy.ttl.as_str().to_owned(),
                    max_ttl: policy.max_ttl.as_str().to_owned(),
                    allowed_users: policy.allowed_users.clone(),
                    allowed_hosts: policy.allowed_hosts.clone(),
                    allow_user_certificates: policy.allow_user_certificates,
                    allow_host_certificates: policy.allow_host_certificates,
                    allow_custom_key_ids: policy.allow_custom_key_ids,
                },
            )
            .await?;
        let template = template_from_wire(response, project_id, Some(ca_id), Some(template_id))?;
        if template.status != replacement.status || !template_matches_policy(&template, policy) {
            return Err(ResourceError::InvalidSshCertificateTemplateResponse);
        }
        Ok(template)
    }

    /// Delete one exact SSH certificate template after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn delete_ssh_certificate_template(
        &self,
        project_id: &SshProjectId,
        ca_id: &SshCertificateAuthorityId,
        template_id: &SshCertificateTemplateId,
        confirm: bool,
    ) -> Result<SshCertificateTemplate, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshCertificateTemplateDeleteNotConfirmed);
        }
        let before = self
            .get_ssh_certificate_template(project_id, ca_id, template_id)
            .await?;
        let response = self
            .execute_mutation::<DeleteSshCertificateTemplate>(
                &DeleteSshCertificateTemplateRequest {
                    template_id: template_id.clone(),
                },
            )
            .await?;
        let deleted = template_from_wire(response, project_id, Some(ca_id), Some(template_id))?;
        if deleted != before {
            return Err(ResourceError::InvalidSshCertificateTemplateResponse);
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    use super::{
        MAX_SSH_TEMPLATE_ENTRIES, SshCertificateTemplateCreation, SshCertificateTemplateId,
        SshCertificateTemplateInputError, SshCertificateTemplateReplacement,
        SshCertificateTemplateStatus, SshCertificateTemplateWire, SshDuration, list_from_wire,
        template_from_wire, template_matches_policy, valid_host_pattern, valid_user_pattern,
    };
    use crate::{
        InfisicalClient, ResourceError, SshCertificateAuthorityId, SshProjectId,
        test_support::{mount_login, settings},
    };

    const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const CA_ID: &str = "22222222-2222-4222-8222-222222222222";
    const TEMPLATE_ID: &str = "33333333-3333-4333-8333-333333333333";
    fn public_key() -> &'static str {
        include_str!("../test-fixtures/ssh-ed25519-public-key.txt").trim()
    }

    fn ca_json() -> Value {
        json!({
            "ca": {
                "id": CA_ID,
                "projectId": PROJECT_ID,
                "friendlyName": "primary-ca",
                "status": "active",
                "keyAlgorithm": "ED25519",
                "keySource": "internal",
                "publicKey": public_key()
            }
        })
    }

    fn template_json(name: &str, status: &str) -> Value {
        json!({
            "id": TEMPLATE_ID,
            "sshCaId": CA_ID,
            "status": status,
            "name": name,
            "ttl": "1h",
            "maxTTL": "24h",
            "allowedUsers": ["deploy"],
            "allowedHosts": ["*.example.com"],
            "allowCustomKeyIds": false,
            "allowUserCertificates": true,
            "allowHostCertificates": true
        })
    }

    fn template_wire(name: &str, status: &str) -> SshCertificateTemplateWire {
        serde_json::from_value(template_json(name, status)).unwrap()
    }

    fn policy(name: &str) -> SshCertificateTemplateCreation {
        SshCertificateTemplateCreation::new(
            name,
            SshDuration::new("1h").unwrap(),
            SshDuration::new("24h").unwrap(),
            vec!["deploy".into()],
            vec!["*.example.com".into()],
            true,
            true,
            false,
        )
        .unwrap()
    }

    #[test]
    fn ssh_template_durations_are_canonical_and_bounded() {
        for (value, expected_millis) in [
            ("1ms", 1),
            ("1s", 1_000),
            ("1m", 60_000),
            ("1h", 3_600_000),
            ("1d", 86_400_000),
            ("1w", 604_800_000),
            ("315360000000ms", 315_360_000_000),
        ] {
            assert_eq!(
                SshDuration::new(value).unwrap().millis(),
                expected_millis,
                "{value}"
            );
        }
        assert!(SshDuration::new("521w").is_ok());
        for invalid in ["", "01h", "0h", "1month", "522w", "315360000001ms"] {
            assert_eq!(
                SshDuration::new(invalid).unwrap_err(),
                SshCertificateTemplateInputError::InvalidDuration,
                "{invalid}"
            );
        }
    }

    #[test]
    fn ssh_template_policy_rejects_each_invalid_dimension() {
        assert_eq!(
            SshCertificateTemplateId::new("template/escape").unwrap_err(),
            SshCertificateTemplateInputError::InvalidId
        );
        assert!(
            SshCertificateTemplateCreation::new(
                "Not A Slug",
                SshDuration::new("1h").unwrap(),
                SshDuration::new("2h").unwrap(),
                vec!["deploy".into()],
                vec!["host.example.com".into()],
                true,
                true,
                false,
            )
            .is_err()
        );
        assert_eq!(
            SshCertificateTemplateCreation::new(
                "ordered",
                SshDuration::new("2h").unwrap(),
                SshDuration::new("1h").unwrap(),
                vec!["deploy".into()],
                vec!["host.example.com".into()],
                true,
                true,
                false,
            )
            .unwrap_err(),
            SshCertificateTemplateInputError::InvalidDurationOrder
        );
        assert!(
            SshCertificateTemplateCreation::new(
                "equal-duration",
                SshDuration::new("1h").unwrap(),
                SshDuration::new("1h").unwrap(),
                vec!["deploy".into()],
                vec!["host.example.com".into()],
                true,
                true,
                false,
            )
            .is_ok()
        );
        assert_eq!(
            SshCertificateTemplateCreation::new(
                "disabled",
                SshDuration::new("1h").unwrap(),
                SshDuration::new("2h").unwrap(),
                Vec::new(),
                Vec::new(),
                false,
                false,
                false,
            )
            .unwrap_err(),
            SshCertificateTemplateInputError::NoCertificateType
        );
        for users in [
            vec![],
            vec!["root user".into()],
            vec!["deploy".into(), "deploy".into()],
        ] {
            assert_eq!(
                SshCertificateTemplateCreation::new(
                    "users",
                    SshDuration::new("1h").unwrap(),
                    SshDuration::new("2h").unwrap(),
                    users,
                    Vec::new(),
                    true,
                    false,
                    false,
                )
                .unwrap_err(),
                SshCertificateTemplateInputError::InvalidUserPatterns
            );
        }
        for hosts in [
            vec![],
            vec!["host without dots".into()],
            vec!["*.example.com".into(), "*.example.com".into()],
        ] {
            assert_eq!(
                SshCertificateTemplateCreation::new(
                    "hosts",
                    SshDuration::new("1h").unwrap(),
                    SshDuration::new("2h").unwrap(),
                    Vec::new(),
                    hosts,
                    false,
                    true,
                    false,
                )
                .unwrap_err(),
                SshCertificateTemplateInputError::InvalidHostPatterns
            );
        }
    }

    #[test]
    fn ssh_template_patterns_match_the_pinned_validator_contract() {
        let maximum_user = format!("a{}", "0".repeat(31));
        for valid in ["*", "deploy", "_deploy", "deploy-user", &maximum_user] {
            assert!(valid_user_pattern(valid), "{valid}");
        }
        let oversized_user = format!("a{}", "0".repeat(32));
        for invalid in ["", "-deploy", "deploy.user", &oversized_user] {
            assert!(!valid_user_pattern(invalid), "{invalid}");
        }

        let maximum_domain = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(maximum_domain.len(), 253);
        let maximum_wildcard = format!("*.{maximum_domain}");
        assert_eq!(maximum_wildcard.len(), 255);
        for valid in [
            "*",
            "192.0.2.1",
            "2001:db8::1",
            "host.example.com",
            "*.example.com",
            &maximum_wildcard,
        ] {
            assert!(valid_host_pattern(valid), "{valid}");
        }

        let overlong_domain = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        let overlong_label = format!("{}.example.com", "a".repeat(64));
        for invalid in [
            "",
            "host\n.example.com",
            "host .example.com",
            "host..example.com",
            "-host.example.com",
            "host-.example.com",
            "host_name.example.com",
            &overlong_domain,
            &overlong_label,
        ] {
            assert!(!valid_host_pattern(invalid), "{invalid}");
        }
    }

    #[test]
    fn ssh_template_responses_rebind_scope_and_bound_collection_size() {
        let project_id = SshProjectId::new(PROJECT_ID).unwrap();
        let ca_id = SshCertificateAuthorityId::new(CA_ID).unwrap();
        let template_id = SshCertificateTemplateId::new(TEMPLATE_ID).unwrap();
        let other_ca_id =
            SshCertificateAuthorityId::new("44444444-4444-4444-8444-444444444444").unwrap();
        let other_template_id =
            SshCertificateTemplateId::new("55555555-5555-4555-8555-555555555555").unwrap();
        assert!(matches!(
            template_from_wire(
                template_wire("policy", "active"),
                &project_id,
                Some(&other_ca_id),
                Some(&template_id),
            ),
            Err(ResourceError::InvalidSshCertificateTemplateScope)
        ));
        assert!(matches!(
            template_from_wire(
                template_wire("policy", "active"),
                &project_id,
                Some(&ca_id),
                Some(&other_template_id),
            ),
            Err(ResourceError::InvalidSshCertificateTemplateScope)
        ));

        let wires = |count: usize| {
            (0..count)
                .map(|index| {
                    let mut wire = template_wire("policy", "active");
                    wire.id = format!("00000000-0000-4000-8000-{index:012}");
                    wire
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            list_from_wire(wires(MAX_SSH_TEMPLATE_ENTRIES), &project_id, Some(&ca_id),)
                .unwrap()
                .len(),
            MAX_SSH_TEMPLATE_ENTRIES
        );
        assert!(matches!(
            list_from_wire(
                wires(MAX_SSH_TEMPLATE_ENTRIES + 1),
                &project_id,
                Some(&ca_id),
            ),
            Err(ResourceError::InvalidSshCertificateTemplateResponse)
        ));
    }

    #[test]
    fn ssh_template_policy_comparison_rejects_each_reflected_field_drift() {
        let project_id = SshProjectId::new(PROJECT_ID).unwrap();
        let ca_id = SshCertificateAuthorityId::new(CA_ID).unwrap();
        let expected = policy("policy");
        let template = template_from_wire(
            template_wire("policy", "active"),
            &project_id,
            Some(&ca_id),
            None,
        )
        .unwrap();
        assert!(template_matches_policy(&template, &expected));

        let mut drifts = Vec::new();
        let mut drift = template.clone();
        drift.name = "different".into();
        drifts.push(drift);
        let mut drift = template.clone();
        drift.ttl = SshDuration::new("2h").unwrap();
        drifts.push(drift);
        let mut drift = template.clone();
        drift.max_ttl = SshDuration::new("48h").unwrap();
        drifts.push(drift);
        let mut drift = template.clone();
        drift.allowed_users = vec!["other".into()];
        drifts.push(drift);
        let mut drift = template.clone();
        drift.allowed_hosts = vec!["other.example.com".into()];
        drifts.push(drift);
        let mut drift = template.clone();
        drift.allow_user_certificates = false;
        drifts.push(drift);
        let mut drift = template.clone();
        drift.allow_host_certificates = false;
        drifts.push(drift);
        let mut drift = template;
        drift.allow_custom_key_ids = true;
        drifts.push(drift);

        assert!(
            drifts
                .iter()
                .all(|drift| !template_matches_policy(drift, &expected))
        );
    }

    #[tokio::test]
    async fn project_and_ca_template_inventory_use_each_exact_pinned_route() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-template-list-token").await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/projects/{PROJECT_ID}/ssh-certificate-templates"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateTemplates": [template_json("project-template", "active")]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/ca/{CA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(ca_json()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/ssh/ca/{CA_ID}/certificate-templates"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateTemplates": [template_json("ca-template", "active")]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = SshProjectId::new(PROJECT_ID).unwrap();
        let ca_id = SshCertificateAuthorityId::new(CA_ID).unwrap();
        assert_eq!(
            client
                .list_ssh_certificate_templates(&project_id)
                .await
                .unwrap()[0]
                .project_id,
            PROJECT_ID
        );
        assert_eq!(
            client
                .list_ssh_certificate_authority_templates(&project_id, &ca_id)
                .await
                .unwrap()[0]
                .ssh_ca_id,
            CA_ID
        );
    }

    #[tokio::test]
    async fn unconfirmed_ssh_template_mutations_fail_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = SshProjectId::new(PROJECT_ID).unwrap();
        let ca_id = SshCertificateAuthorityId::new(CA_ID).unwrap();
        let template_id = SshCertificateTemplateId::new(TEMPLATE_ID).unwrap();
        let policy = policy("policy");
        assert!(matches!(
            client
                .create_ssh_certificate_template(&project_id, &ca_id, &policy, false)
                .await,
            Err(ResourceError::SshCertificateTemplateCreateNotConfirmed)
        ));
        assert!(matches!(
            client
                .replace_ssh_certificate_template(
                    &project_id,
                    &ca_id,
                    &template_id,
                    &SshCertificateTemplateReplacement::new(
                        SshCertificateTemplateStatus::Disabled,
                        policy.clone(),
                    ),
                    false,
                )
                .await,
            Err(ResourceError::SshCertificateTemplateReplaceNotConfirmed)
        ));
        assert!(matches!(
            client
                .delete_ssh_certificate_template(&project_id, &ca_id, &template_id, false,)
                .await,
            Err(ResourceError::SshCertificateTemplateDeleteNotConfirmed)
        ));
    }

    #[tokio::test]
    async fn ssh_template_mutations_reject_partial_response_reflection() {
        let create_server = MockServer::start().await;
        mount_login(&create_server, "ssh-template-create-reflection-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/ca/{CA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(ca_json()))
            .expect(1)
            .mount(&create_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ssh/certificate-templates"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(template_json("policy", "disabled")),
            )
            .expect(1)
            .mount(&create_server)
            .await;
        let project_id = SshProjectId::new(PROJECT_ID).unwrap();
        let ca_id = SshCertificateAuthorityId::new(CA_ID).unwrap();
        let template_id = SshCertificateTemplateId::new(TEMPLATE_ID).unwrap();
        let expected_policy = policy("policy");
        assert!(matches!(
            InfisicalClient::new(settings(&create_server))
                .unwrap()
                .create_ssh_certificate_template(&project_id, &ca_id, &expected_policy, true)
                .await,
            Err(ResourceError::InvalidSshCertificateTemplateResponse)
        ));

        let replace_server = MockServer::start().await;
        mount_login(&replace_server, "ssh-template-replace-reflection-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/ca/{CA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(ca_json()))
            .expect(1)
            .mount(&replace_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/ssh/certificate-templates/{TEMPLATE_ID}"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(template_json("policy", "active")),
            )
            .expect(1)
            .mount(&replace_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/ssh/certificate-templates/{TEMPLATE_ID}"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(template_json("policy", "active")),
            )
            .expect(1)
            .mount(&replace_server)
            .await;
        assert!(matches!(
            InfisicalClient::new(settings(&replace_server))
                .unwrap()
                .replace_ssh_certificate_template(
                    &project_id,
                    &ca_id,
                    &template_id,
                    &SshCertificateTemplateReplacement::new(
                        SshCertificateTemplateStatus::Disabled,
                        expected_policy,
                    ),
                    true,
                )
                .await,
            Err(ResourceError::InvalidSshCertificateTemplateResponse)
        ));
    }

    #[tokio::test]
    async fn ssh_template_lifecycle_uses_complete_bodies_and_rebinds_every_field() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-template-lifecycle-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/ca/{CA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(ca_json()))
            .expect(3)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/ssh/certificate-templates/{TEMPLATE_ID}"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(template_json("replacement", "disabled")),
            )
            .expect(2)
            .mount(&server)
            .await;
        let complete_body = json!({
            "name": "replacement",
            "ttl": "1h",
            "maxTTL": "24h",
            "allowedUsers": ["deploy"],
            "allowedHosts": ["*.example.com"],
            "allowUserCertificates": true,
            "allowHostCertificates": true,
            "allowCustomKeyIds": false
        });
        let mut creation_body = complete_body.clone();
        creation_body["sshCaId"] = json!(CA_ID);
        Mock::given(method("POST"))
            .and(path("/api/v1/ssh/certificate-templates"))
            .and(body_json(creation_body))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(template_json("replacement", "active")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut replacement_body = complete_body;
        replacement_body["status"] = json!("disabled");
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/ssh/certificate-templates/{TEMPLATE_ID}"
            )))
            .and(body_json(replacement_body))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(template_json("replacement", "disabled")),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/ssh/certificate-templates/{TEMPLATE_ID}"
            )))
            .and(body_json(json!({})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(template_json("replacement", "disabled")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = SshProjectId::new(PROJECT_ID).unwrap();
        let ca_id = SshCertificateAuthorityId::new(CA_ID).unwrap();
        let template_id = SshCertificateTemplateId::new(TEMPLATE_ID).unwrap();
        let policy = policy("replacement");
        let created = client
            .create_ssh_certificate_template(&project_id, &ca_id, &policy, true)
            .await
            .unwrap();
        assert_eq!(created.status, SshCertificateTemplateStatus::Active);
        let replaced = client
            .replace_ssh_certificate_template(
                &project_id,
                &ca_id,
                &template_id,
                &SshCertificateTemplateReplacement::new(
                    SshCertificateTemplateStatus::Disabled,
                    policy,
                ),
                true,
            )
            .await
            .unwrap();
        assert_eq!(replaced.status, SshCertificateTemplateStatus::Disabled);
        assert_eq!(
            client
                .delete_ssh_certificate_template(&project_id, &ca_id, &template_id, true,)
                .await
                .unwrap(),
            replaced
        );
    }
}
