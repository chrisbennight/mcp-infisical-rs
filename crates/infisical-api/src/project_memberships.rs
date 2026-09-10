use std::collections::HashSet;

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    IdentityId, InfisicalClient, MutationOperation, Page, PageRequest, ProjectId, ReadOperation,
    ResourceError,
    client::{ApiVersion, Endpoint, sealed},
    resources::paginate,
};

/// Maximum users accepted by one project invitation call.
pub const MAX_PROJECT_MEMBERSHIP_BATCH_SIZE: usize = 50;
/// Maximum long-lived roles accepted by one membership mutation.
pub const MAX_PROJECT_MEMBERSHIP_ROLES: usize = 10;
const MAX_MEMBER_HANDLE_BYTES: usize = 254;
const MAX_ROLE_SLUG_BYTES: usize = 128;

/// A validated built-in or custom project-role slug.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct ProjectRoleSlug(String);

impl ProjectRoleSlug {
    /// Validate a role slug before it reaches a membership mutation.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, uppercase, or punctuation-bearing slugs.
    pub fn new(value: impl Into<String>) -> Result<Self, ProjectMembershipInputError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ROLE_SLUG_BYTES
            || value.trim() != value
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
        {
            return Err(ProjectMembershipInputError::InvalidRoleSlug);
        }
        Ok(Self(value))
    }

    /// Borrow the validated role slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A non-empty, bounded set of permanent project roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectMembershipRoles(Vec<ProjectRoleSlug>);

impl ProjectMembershipRoles {
    /// Validate one complete long-lived role assignment.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or duplicate role set.
    pub fn new(roles: Vec<ProjectRoleSlug>) -> Result<Self, ProjectMembershipInputError> {
        if roles.is_empty() || roles.len() > MAX_PROJECT_MEMBERSHIP_ROLES {
            return Err(ProjectMembershipInputError::InvalidRoleCount);
        }
        let unique: HashSet<&str> = roles.iter().map(ProjectRoleSlug::as_str).collect();
        if unique.len() != roles.len() {
            return Err(ProjectMembershipInputError::DuplicateRole);
        }
        Ok(Self(roles))
    }

    fn into_requests(self) -> Vec<RoleRequest> {
        self.0
            .into_iter()
            .map(|role| RoleRequest {
                role: role.0,
                is_temporary: false,
            })
            .collect()
    }

    fn into_slugs(self) -> Vec<String> {
        self.0.into_iter().map(|role| role.0).collect()
    }
}

/// Validated users and roles for one project invitation mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectUserInvitation {
    emails: Vec<String>,
    usernames: Vec<String>,
    roles: ProjectMembershipRoles,
}

impl ProjectUserInvitation {
    /// Validate a bounded invitation before any upstream request is sent.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized batch, invalid handles, duplicate
    /// principals, or an invalid role set.
    pub fn new(
        emails: Vec<String>,
        usernames: Vec<String>,
        roles: ProjectMembershipRoles,
    ) -> Result<Self, ProjectMembershipInputError> {
        let principal_count = emails
            .len()
            .checked_add(usernames.len())
            .ok_or(ProjectMembershipInputError::InvalidPrincipalCount)?;
        if principal_count == 0 || principal_count > MAX_PROJECT_MEMBERSHIP_BATCH_SIZE {
            return Err(ProjectMembershipInputError::InvalidPrincipalCount);
        }
        if emails.iter().any(|email| !is_valid_email(email)) {
            return Err(ProjectMembershipInputError::InvalidEmail);
        }
        if usernames
            .iter()
            .any(|username| !is_valid_username(username))
        {
            return Err(ProjectMembershipInputError::InvalidUsername);
        }
        let unique: HashSet<&str> = emails
            .iter()
            .chain(usernames.iter())
            .map(String::as_str)
            .collect();
        if unique.len() != principal_count {
            return Err(ProjectMembershipInputError::DuplicatePrincipal);
        }
        Ok(Self {
            emails,
            usernames,
            roles,
        })
    }
}

fn is_valid_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MEMBER_HANDLE_BYTES
        && value.trim() == value
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'@' | b'.' | b'_' | b'+' | b'-')
        })
}

fn is_valid_email(value: &str) -> bool {
    if !is_valid_username(value) {
        return false;
    }
    let mut parts = value.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.as_bytes().windows(2).any(|pair| pair == b"..")
        || domain.is_empty()
        || parts.next().is_some()
        || !domain.contains('.')
    {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

/// Non-secret user metadata embedded in a project membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectMemberUser {
    /// Opaque user identifier.
    pub id: String,
    /// Stable username.
    pub username: String,
    /// Optional email address returned by Infisical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Optional first name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// Optional last name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// Configured user authentication-method names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_methods: Option<Vec<String>>,
    /// Whether the email address has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_email_verified: Option<bool>,
}

/// One role attached to a project membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectMembershipRole {
    /// Opaque role-assignment identifier.
    pub id: String,
    /// Built-in or custom role slug.
    pub role: String,
    /// Custom role identifier, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_role_id: Option<String>,
    /// Custom role display name, when returned by the route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_role_name: Option<String>,
    /// Custom role slug, when returned separately by the route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_role_slug: Option<String>,
    /// Whether this role expires.
    #[serde(default)]
    pub is_temporary: bool,
    /// Upstream scheduling mode for an existing temporary role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporary_mode: Option<String>,
    /// Upstream relative-duration expression for an existing temporary role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporary_range: Option<String>,
    /// Scheduled access start timestamp for an existing temporary role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporary_access_start_time: Option<String>,
    /// Scheduled access end timestamp for an existing temporary role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporary_access_end_time: Option<String>,
    /// Membership identifier, when returned by a mutation route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_membership_id: Option<String>,
}

/// One human-user membership in a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectUserMembership {
    /// Opaque membership identifier used by get, update, and delete routes.
    pub id: String,
    /// Owning project identifier.
    pub project_id: String,
    /// Member user identifier.
    pub user_id: String,
    /// Membership creation timestamp from Infisical.
    pub created_at: String,
    /// Sanitized member profile.
    pub user: ProjectMemberUser,
    /// Complete role assignments returned by Infisical.
    pub roles: Vec<ProjectMembershipRole>,
}

/// Non-secret machine-identity metadata embedded in a project membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectMemberIdentity {
    /// Opaque identity identifier.
    pub id: String,
    /// Identity display name.
    pub name: String,
    /// Owning organization identifier.
    pub org_id: String,
    /// Optional legacy project association.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Configured authentication-method names.
    #[serde(default)]
    pub auth_methods: Vec<String>,
}

/// One machine-identity membership in a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectIdentityMembership {
    /// Opaque project-membership identifier.
    pub id: String,
    /// Owning project identifier.
    pub project_id: String,
    /// Member identity identifier.
    pub identity_id: String,
    /// Membership creation timestamp from Infisical.
    pub created_at: String,
    /// Membership update timestamp from Infisical.
    pub updated_at: String,
    /// Complete role assignments returned by Infisical.
    pub roles: Vec<ProjectMembershipRole>,
    /// Concise machine-identity metadata.
    pub identity: ProjectMemberIdentity,
}

/// Narrow result returned by project-membership mutations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectMembershipMutationReceipt {
    /// Affected membership identifier.
    pub membership_id: String,
    /// Owning project identifier.
    pub project_id: String,
    /// Affected user or machine-identity identifier.
    pub principal_id: String,
}

/// Every membership created by one bounded invitation batch.
///
/// The collection is wrapped in a named field because a tool result is
/// carried in `structuredContent`, which MCP defines as a JSON object: a
/// bare array is neither a valid payload nor a valid `outputSchema` root,
/// and a strict client rejects the entire `tools/list` response over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ProjectMembershipMutationReceiptBatch {
    /// Memberships created by this invitation, in the order Infisical returned them.
    pub memberships: Vec<ProjectMembershipMutationReceipt>,
}

impl From<Vec<ProjectMembershipMutationReceipt>> for ProjectMembershipMutationReceiptBatch {
    fn from(memberships: Vec<ProjectMembershipMutationReceipt>) -> Self {
        Self { memberships }
    }
}

/// The complete role set attached to one membership after a replacement.
///
/// Wrapped for the same reason as
/// [`ProjectMembershipMutationReceiptBatch`]: `structuredContent` is an
/// object, so a bare array cannot be the payload or the schema root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ProjectMembershipRoleSet {
    /// Roles now attached to the membership, in the order Infisical returned them.
    pub roles: Vec<ProjectMembershipRole>,
}

impl From<Vec<ProjectMembershipRole>> for ProjectMembershipRoleSet {
    fn from(roles: Vec<ProjectMembershipRole>) -> Self {
        Self { roles }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProjectMembershipInputError {
    #[error("project membership batches must contain between 1 and 50 users")]
    InvalidPrincipalCount,
    #[error("project member email addresses must be lowercase, bounded, and syntactically valid")]
    InvalidEmail,
    #[error("project member usernames must be lowercase and contain at most 254 safe ASCII bytes")]
    InvalidUsername,
    #[error("project membership batches must not contain duplicate users")]
    DuplicatePrincipal,
    #[error("project memberships must contain between 1 and 10 long-lived roles")]
    InvalidRoleCount,
    #[error(
        "project role slugs must contain 1 to 128 lowercase letters, numbers, hyphens, or underscores"
    )]
    InvalidRoleSlug,
    #[error("project memberships must not contain duplicate role slugs")]
    DuplicateRole,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListUserMembershipsQuery {
    #[serde(skip_serializing)]
    project_id: ProjectId,
}

#[derive(Deserialize)]
struct ListUserMembershipsResponse {
    memberships: Vec<UserMembershipWire>,
}

#[derive(Serialize)]
struct GetUserMembershipQuery {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(skip_serializing)]
    membership_id: crate::ProjectMembershipId,
}

#[derive(Deserialize)]
struct UserMembershipResponse {
    membership: UserMembershipWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserMembershipWire {
    id: String,
    created_at: String,
    user_id: String,
    project_id: String,
    user: ProjectMemberUser,
    roles: Vec<ProjectMembershipRole>,
}

impl From<UserMembershipWire> for ProjectUserMembership {
    fn from(membership: UserMembershipWire) -> Self {
        Self {
            id: membership.id,
            project_id: membership.project_id,
            user_id: membership.user_id,
            created_at: membership.created_at,
            user: membership.user,
            roles: membership.roles,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RoleRequest {
    role: String,
    is_temporary: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InviteUsersRequest {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    emails: Vec<String>,
    usernames: Vec<String>,
    role_slugs: Vec<String>,
}

impl InviteUsersRequest {
    fn new(project_id: &ProjectId, invitation: ProjectUserInvitation) -> Self {
        Self {
            project_id: project_id.clone(),
            emails: invitation.emails,
            usernames: invitation.usernames,
            role_slugs: invitation.roles.into_slugs(),
        }
    }
}

#[derive(Deserialize)]
struct MembershipReceiptsResponse {
    memberships: Vec<UserMembershipReceiptWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserMembershipReceiptWire {
    id: String,
    project_id: String,
    user_id: String,
}

impl From<UserMembershipReceiptWire> for ProjectMembershipMutationReceipt {
    fn from(membership: UserMembershipReceiptWire) -> Self {
        Self {
            membership_id: membership.id,
            project_id: membership.project_id,
            principal_id: membership.user_id,
        }
    }
}

#[derive(Serialize)]
struct UpdateUserMembershipRequest {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(skip_serializing)]
    membership_id: crate::ProjectMembershipId,
    roles: Vec<RoleRequest>,
}

#[derive(Deserialize)]
struct RolesResponse {
    roles: Vec<ProjectMembershipRole>,
}

#[derive(Serialize)]
struct DeleteUserMembershipRequest {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(skip_serializing)]
    membership_id: crate::ProjectMembershipId,
}

#[derive(Deserialize)]
struct UserMembershipReceiptResponse {
    membership: UserMembershipReceiptWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListIdentityMembershipsQuery {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    offset: u32,
    limit: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListIdentityMembershipsResponse {
    identity_memberships: Vec<IdentityMembershipWire>,
    total_count: u64,
}

#[derive(Serialize)]
struct GetIdentityMembershipQuery {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(skip_serializing)]
    identity_id: IdentityId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityMembershipResponse {
    identity_membership: IdentityMembershipWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityMembershipWire {
    id: String,
    created_at: String,
    updated_at: String,
    #[serde(default)]
    identity_id: Option<String>,
    roles: Vec<ProjectMembershipRole>,
    identity: ProjectMemberIdentity,
}

impl IdentityMembershipWire {
    fn into_membership(self, project_id: &ProjectId) -> ProjectIdentityMembership {
        let identity_id = self.identity_id.unwrap_or_else(|| self.identity.id.clone());
        ProjectIdentityMembership {
            id: self.id,
            project_id: project_id.as_str().to_owned(),
            identity_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
            roles: self.roles,
            identity: self.identity,
        }
    }
}

#[derive(Serialize)]
struct IdentityMembershipMutationRequest {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(skip_serializing)]
    identity_id: IdentityId,
    roles: Vec<RoleRequest>,
}

#[derive(Serialize)]
struct DeleteIdentityMembershipRequest {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(skip_serializing)]
    identity_id: IdentityId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityMembershipReceiptResponse {
    identity_membership: IdentityMembershipReceiptWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityMembershipReceiptWire {
    id: String,
    project_id: String,
    identity_id: String,
}

impl From<IdentityMembershipReceiptWire> for ProjectMembershipMutationReceipt {
    fn from(membership: IdentityMembershipReceiptWire) -> Self {
        Self {
            membership_id: membership.id,
            project_id: membership.project_id,
            principal_id: membership.identity_id,
        }
    }
}

struct ListUserMemberships;
impl sealed::Sealed for ListUserMemberships {}
impl ReadOperation for ListUserMemberships {
    type Query = ListUserMembershipsQuery;
    type Output = ListUserMembershipsResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["projects", query.project_id.as_str(), "memberships"],
        )
    }
}

struct GetUserMembership;
impl sealed::Sealed for GetUserMembership {}
impl ReadOperation for GetUserMembership {
    type Query = GetUserMembershipQuery;
    type Output = UserMembershipResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects",
                query.project_id.as_str(),
                "memberships",
                query.membership_id.as_str(),
            ],
        )
    }
}

struct InviteUsers;
impl sealed::Sealed for InviteUsers {}
impl MutationOperation for InviteUsers {
    type Input = InviteUsersRequest;
    type Output = MembershipReceiptsResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["projects", input.project_id.as_str(), "memberships"],
        )
    }
}

struct UpdateUserMembership;
impl sealed::Sealed for UpdateUserMembership {}
impl MutationOperation for UpdateUserMembership {
    type Input = UpdateUserMembershipRequest;
    type Output = RolesResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects",
                input.project_id.as_str(),
                "memberships",
                input.membership_id.as_str(),
            ],
        )
    }
}

struct DeleteUserMembership;
impl sealed::Sealed for DeleteUserMembership {}
impl MutationOperation for DeleteUserMembership {
    type Input = DeleteUserMembershipRequest;
    type Output = UserMembershipReceiptResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects",
                input.project_id.as_str(),
                "memberships",
                input.membership_id.as_str(),
            ],
        )
    }
}

struct ListIdentityMemberships;
impl sealed::Sealed for ListIdentityMemberships {}
impl ReadOperation for ListIdentityMemberships {
    type Query = ListIdentityMembershipsQuery;
    type Output = ListIdentityMembershipsResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects",
                query.project_id.as_str(),
                "memberships",
                "identities",
            ],
        )
    }
}

struct GetIdentityMembership;
impl sealed::Sealed for GetIdentityMembership {}
impl ReadOperation for GetIdentityMembership {
    type Query = GetIdentityMembershipQuery;
    type Output = IdentityMembershipResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects",
                query.project_id.as_str(),
                "memberships",
                "identities",
                query.identity_id.as_str(),
            ],
        )
    }
}

struct CreateIdentityMembership;
impl sealed::Sealed for CreateIdentityMembership {}
impl MutationOperation for CreateIdentityMembership {
    type Input = IdentityMembershipMutationRequest;
    type Output = IdentityMembershipReceiptResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        identity_mutation_endpoint(input)
    }
}

struct UpdateIdentityMembership;
impl sealed::Sealed for UpdateIdentityMembership {}
impl MutationOperation for UpdateIdentityMembership {
    type Input = IdentityMembershipMutationRequest;
    type Output = IdentityMembershipReceiptResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        identity_mutation_endpoint(input)
    }
}

fn identity_mutation_endpoint(input: &IdentityMembershipMutationRequest) -> Endpoint {
    Endpoint::from_segments(
        ApiVersion::V1,
        [
            "projects",
            input.project_id.as_str(),
            "memberships",
            "identities",
            input.identity_id.as_str(),
        ],
    )
}

struct DeleteIdentityMembership;
impl sealed::Sealed for DeleteIdentityMembership {}
impl MutationOperation for DeleteIdentityMembership {
    type Input = DeleteIdentityMembershipRequest;
    type Output = IdentityMembershipReceiptResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects",
                input.project_id.as_str(),
                "memberships",
                "identities",
                input.identity_id.as_str(),
            ],
        )
    }
}

impl InfisicalClient {
    /// List a bounded local page of human-user memberships for one project.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_project_user_memberships(
        &self,
        project_id: &ProjectId,
        page: PageRequest,
    ) -> Result<Page<ProjectUserMembership>, ResourceError> {
        let response = self
            .execute_read::<ListUserMemberships>(&ListUserMembershipsQuery {
                project_id: project_id.clone(),
            })
            .await?;
        paginate(
            page,
            response
                .memberships
                .into_iter()
                .map(ProjectUserMembership::from)
                .collect(),
        )
    }

    /// Get one human-user project membership by exact membership ID.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_project_user_membership(
        &self,
        project_id: &ProjectId,
        membership_id: &crate::ProjectMembershipId,
    ) -> Result<ProjectUserMembership, ResourceError> {
        let response = self
            .execute_read::<GetUserMembership>(&GetUserMembershipQuery {
                project_id: project_id.clone(),
                membership_id: membership_id.clone(),
            })
            .await?;
        Ok(response.membership.into())
    }

    /// Invite a bounded batch of users with complete long-lived roles.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn invite_project_users(
        &self,
        project_id: &ProjectId,
        invitation: ProjectUserInvitation,
    ) -> Result<Vec<ProjectMembershipMutationReceipt>, ResourceError> {
        let response = self
            .execute_mutation::<InviteUsers>(&InviteUsersRequest::new(project_id, invitation))
            .await?;
        Ok(response
            .memberships
            .into_iter()
            .map(ProjectMembershipMutationReceipt::from)
            .collect())
    }

    /// Replace every role on one human-user membership after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. Omitted temporary roles are removed,
    /// and the mutation is sent once.
    pub async fn update_project_user_membership(
        &self,
        project_id: &ProjectId,
        membership_id: &crate::ProjectMembershipId,
        roles: ProjectMembershipRoles,
        confirm_replace_all_roles: bool,
    ) -> Result<Vec<ProjectMembershipRole>, ResourceError> {
        if !confirm_replace_all_roles {
            return Err(ResourceError::ProjectMembershipRoleReplacementNotConfirmed);
        }
        let response = self
            .execute_mutation::<UpdateUserMembership>(&UpdateUserMembershipRequest {
                project_id: project_id.clone(),
                membership_id: membership_id.clone(),
                roles: roles.into_requests(),
            })
            .await?;
        Ok(response.roles)
    }

    /// Delete one human-user project membership after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn delete_project_user_membership(
        &self,
        project_id: &ProjectId,
        membership_id: &crate::ProjectMembershipId,
        confirm: bool,
    ) -> Result<ProjectMembershipMutationReceipt, ResourceError> {
        if !confirm {
            return Err(ResourceError::ProjectMembershipDeletionNotConfirmed);
        }
        let response = self
            .execute_mutation::<DeleteUserMembership>(&DeleteUserMembershipRequest {
                project_id: project_id.clone(),
                membership_id: membership_id.clone(),
            })
            .await?;
        Ok(response.membership.into())
    }

    /// List a bounded upstream page of machine-identity memberships for one project.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_project_identity_memberships(
        &self,
        project_id: &ProjectId,
        page: PageRequest,
    ) -> Result<Page<ProjectIdentityMembership>, ResourceError> {
        let response = self
            .execute_read::<ListIdentityMemberships>(&ListIdentityMembershipsQuery {
                project_id: project_id.clone(),
                offset: page.offset(),
                limit: page.limit(),
            })
            .await?;
        let memberships = response
            .identity_memberships
            .into_iter()
            .map(|membership| membership.into_membership(project_id))
            .collect();
        Ok(Page::new(page, memberships, Some(response.total_count))?)
    }

    /// Get one machine-identity project membership by exact identity ID.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_project_identity_membership(
        &self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
    ) -> Result<ProjectIdentityMembership, ResourceError> {
        let response = self
            .execute_read::<GetIdentityMembership>(&GetIdentityMembershipQuery {
                project_id: project_id.clone(),
                identity_id: identity_id.clone(),
            })
            .await?;
        Ok(response.identity_membership.into_membership(project_id))
    }

    /// Add one machine identity to a project with complete long-lived roles.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn create_project_identity_membership(
        &self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
        roles: ProjectMembershipRoles,
    ) -> Result<ProjectMembershipMutationReceipt, ResourceError> {
        self.mutate_project_identity_membership::<CreateIdentityMembership>(
            project_id,
            identity_id,
            roles,
        )
        .await
    }

    /// Replace every role on one machine-identity membership after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. Omitted temporary roles are removed,
    /// and the mutation is sent once.
    pub async fn update_project_identity_membership(
        &self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
        roles: ProjectMembershipRoles,
        confirm_replace_all_roles: bool,
    ) -> Result<ProjectMembershipMutationReceipt, ResourceError> {
        if !confirm_replace_all_roles {
            return Err(ResourceError::ProjectMembershipRoleReplacementNotConfirmed);
        }
        self.mutate_project_identity_membership::<UpdateIdentityMembership>(
            project_id,
            identity_id,
            roles,
        )
        .await
    }

    async fn mutate_project_identity_membership<O>(
        &self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
        roles: ProjectMembershipRoles,
    ) -> Result<ProjectMembershipMutationReceipt, ResourceError>
    where
        O: MutationOperation<
                Input = IdentityMembershipMutationRequest,
                Output = IdentityMembershipReceiptResponse,
            >,
    {
        let response = self
            .execute_mutation::<O>(&IdentityMembershipMutationRequest {
                project_id: project_id.clone(),
                identity_id: identity_id.clone(),
                roles: roles.into_requests(),
            })
            .await?;
        Ok(response.identity_membership.into())
    }

    /// Delete one machine-identity project membership after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn delete_project_identity_membership(
        &self,
        project_id: &ProjectId,
        identity_id: &IdentityId,
        confirm: bool,
    ) -> Result<ProjectMembershipMutationReceipt, ResourceError> {
        if !confirm {
            return Err(ResourceError::ProjectMembershipDeletionNotConfirmed);
        }
        let response = self
            .execute_mutation::<DeleteIdentityMembership>(&DeleteIdentityMembershipRequest {
                project_id: project_id.clone(),
                identity_id: identity_id.clone(),
            })
            .await?;
        Ok(response.identity_membership.into())
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
        IdentityId, InfisicalClient, PageRequest, ProjectId, ProjectMembershipId,
        ProjectMembershipInputError, ProjectMembershipRoles, ProjectRoleSlug,
        ProjectUserInvitation, ResourceError,
        test_support::{mount_login, settings},
    };

    fn role(id: &str, slug: &str) -> Value {
        json!({
            "id": id,
            "role": slug,
            "customRoleId": null,
            "customRoleName": null,
            "customRoleSlug": null,
            "isTemporary": true,
            "temporaryMode": "relative",
            "temporaryRange": "1h",
            "temporaryAccessStartTime": "2026-07-19T20:00:00.000Z",
            "temporaryAccessEndTime": "2026-07-19T21:00:00.000Z"
        })
    }

    fn user_membership(id: &str, user_id: &str, username: &str) -> Value {
        json!({
            "id": id,
            "projectId": "project-1",
            "userId": user_id,
            "createdAt": "2026-07-19T20:00:00.000Z",
            "user": {
                "id": user_id,
                "username": username,
                "email": format!("{username}@example.com"),
                "firstName": "Project",
                "lastName": "Member",
                "authMethods": ["email"],
                "isEmailVerified": true
            },
            "roles": [role(&format!("role-{id}"), "member")]
        })
    }

    fn identity_membership(id: &str, identity_id: &str, name: &str) -> Value {
        json!({
            "id": id,
            "identityId": identity_id,
            "createdAt": "2026-07-19T20:00:00.000Z",
            "updatedAt": "2026-07-19T20:01:00.000Z",
            "roles": [role(&format!("role-{id}"), "viewer")],
            "identity": {
                "id": identity_id,
                "name": name,
                "orgId": "org-1",
                "projectId": null,
                "authMethods": ["universal-auth"],
                "activeLockoutAuthMethods": []
            }
        })
    }

    fn roles(slugs: &[&str]) -> ProjectMembershipRoles {
        ProjectMembershipRoles::new(
            slugs
                .iter()
                .map(|slug| ProjectRoleSlug::new(*slug).unwrap())
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn membership_inputs_reject_ambiguous_batches_handles_and_roles() {
        assert_eq!(ProjectRoleSlug::new("member").unwrap().as_str(), "member");
        assert_eq!(
            ProjectRoleSlug::new("Admin").unwrap_err(),
            ProjectMembershipInputError::InvalidRoleSlug
        );
        assert_eq!(
            ProjectMembershipRoles::new(Vec::new()).unwrap_err(),
            ProjectMembershipInputError::InvalidRoleCount
        );
        assert_eq!(
            ProjectMembershipRoles::new(vec![
                ProjectRoleSlug::new("member").unwrap(),
                ProjectRoleSlug::new("member").unwrap(),
            ])
            .unwrap_err(),
            ProjectMembershipInputError::DuplicateRole
        );
        assert_eq!(
            ProjectUserInvitation::new(Vec::new(), Vec::new(), roles(&["member"])).unwrap_err(),
            ProjectMembershipInputError::InvalidPrincipalCount
        );
        assert_eq!(
            ProjectUserInvitation::new(
                vec!["UPPER@example.com".into()],
                Vec::new(),
                roles(&["member"]),
            )
            .unwrap_err(),
            ProjectMembershipInputError::InvalidEmail
        );
        for email in [
            "@example.com",
            "agent@",
            "agent@example.com@extra",
            "agent@example.com.",
            ".agent@example.com",
            "agent.@example.com",
            "agent..ops@example.com",
            "agent@example..com",
            "agent@-example.com",
            "agent@example-.com",
            "agent@example_com",
        ] {
            assert_eq!(
                ProjectUserInvitation::new(vec![email.into()], Vec::new(), roles(&["member"]),)
                    .unwrap_err(),
                ProjectMembershipInputError::InvalidEmail,
                "{email} must be rejected"
            );
        }
        assert!(
            ProjectUserInvitation::new(
                vec!["agent.one+ops@example-domain.com".into()],
                Vec::new(),
                roles(&["member"]),
            )
            .is_ok()
        );
        let maximum_local_part = format!("{}@example.com", "a".repeat(64));
        assert!(
            ProjectUserInvitation::new(vec![maximum_local_part], Vec::new(), roles(&["member"]),)
                .is_ok()
        );
        let oversized_local_part = format!("{}@example.com", "a".repeat(65));
        assert_eq!(
            ProjectUserInvitation::new(vec![oversized_local_part], Vec::new(), roles(&["member"]),)
                .unwrap_err(),
            ProjectMembershipInputError::InvalidEmail
        );
        assert_eq!(
            ProjectUserInvitation::new(
                vec!["agent@example.com".into()],
                vec!["agent@example.com".into()],
                roles(&["member"]),
            )
            .unwrap_err(),
            ProjectMembershipInputError::DuplicatePrincipal
        );
    }

    #[tokio::test]
    async fn membership_reads_use_exact_v1_contracts_and_bounded_pages() {
        let server = MockServer::start().await;
        mount_login(&server, "membership-read-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1/memberships"))
            .and(header("authorization", "Bearer membership-read-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "memberships": [
                    user_membership("membership-1", "user-1", "one"),
                    user_membership("membership-2", "user-2", "two")
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1/memberships/membership-2"))
            .and(header("authorization", "Bearer membership-read-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "membership": user_membership("membership-2", "user-2", "two")
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1/memberships/identities"))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"))
            .and(header("authorization", "Bearer membership-read-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityMemberships": [identity_membership(
                    "identity-membership-1",
                    "identity-1",
                    "automation"
                )],
                "totalCount": 2
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/projects/project-1/memberships/identities/identity-1",
            ))
            .and(header("authorization", "Bearer membership-read-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityMembership": identity_membership(
                    "identity-membership-1",
                    "identity-1",
                    "automation"
                )
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let user_page = client
            .list_project_user_memberships(&project_id, PageRequest::new(1, 1).unwrap())
            .await
            .unwrap();
        assert_eq!(user_page.items[0].id, "membership-2");
        assert_eq!(user_page.total, Some(2));
        let user = client
            .get_project_user_membership(
                &project_id,
                &ProjectMembershipId::new("membership-2").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(user.user.username, "two");
        assert_eq!(user.roles[0].temporary_mode.as_deref(), Some("relative"));
        assert_eq!(user.roles[0].temporary_range.as_deref(), Some("1h"));
        assert_eq!(
            user.roles[0].temporary_access_end_time.as_deref(),
            Some("2026-07-19T21:00:00.000Z")
        );
        let identity_page = client
            .list_project_identity_memberships(&project_id, PageRequest::new(0, 1).unwrap())
            .await
            .unwrap();
        assert_eq!(identity_page.total, Some(2));
        assert_eq!(identity_page.next, Some(PageRequest::new(1, 1).unwrap()));
        let identity = client
            .get_project_identity_membership(&project_id, &IdentityId::new("identity-1").unwrap())
            .await
            .unwrap();
        assert_eq!(identity.identity.name, "automation");
    }

    async fn mount_user_membership_mutations(server: &MockServer, user_receipt: &Value) {
        Mock::given(method("POST"))
            .and(path("/api/v1/projects/project-1/memberships"))
            .and(header("authorization", "Bearer membership-admin-token"))
            .and(body_json(json!({
                "emails": ["agent@example.com"],
                "usernames": ["operator"],
                "roleSlugs": ["member"]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "memberships": [user_receipt.clone()]
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/projects/project-1/memberships/membership-1"))
            .and(header("authorization", "Bearer membership-admin-token"))
            .and(body_json(json!({
                "roles": [{"role": "viewer", "isTemporary": false}]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "roles": [{
                    "id": "role-membership-1",
                    "role": "viewer",
                    "projectMembershipId": "membership-1",
                    "customRoleId": null,
                    "isTemporary": false,
                    "createdAt": "2026-07-19T20:00:00.000Z",
                    "updatedAt": "2026-07-19T20:00:00.000Z"
                }]
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/projects/project-1/memberships/membership-1"))
            .and(header("authorization", "Bearer membership-admin-token"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "membership": user_receipt
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_identity_membership_mutations(server: &MockServer, identity_receipt: &Value) {
        for method_name in ["POST", "PATCH"] {
            Mock::given(method(method_name))
                .and(path(
                    "/api/v1/projects/project-1/memberships/identities/identity-1",
                ))
                .and(header("authorization", "Bearer membership-admin-token"))
                .and(body_json(json!({
                    "roles": [{"role": "admin", "isTemporary": false}]
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "identityMembership": identity_receipt.clone()
                })))
                .expect(1)
                .mount(server)
                .await;
        }
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/projects/project-1/memberships/identities/identity-1",
            ))
            .and(header("authorization", "Bearer membership-admin-token"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityMembership": identity_receipt
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn membership_mutations_send_one_narrow_request_each() {
        let server = MockServer::start().await;
        mount_login(&server, "membership-admin-token").await;
        let user_receipt = json!({
            "id": "membership-1",
            "projectId": "project-1",
            "userId": "user-1",
            "createdAt": "2026-07-19T20:00:00.000Z",
            "updatedAt": "2026-07-19T20:00:00.000Z"
        });
        let identity_receipt = json!({
            "id": "identity-membership-1",
            "projectId": "project-1",
            "identityId": "identity-1",
            "createdAt": "2026-07-19T20:00:00.000Z",
            "updatedAt": "2026-07-19T20:00:00.000Z"
        });
        mount_user_membership_mutations(&server, &user_receipt).await;
        mount_identity_membership_mutations(&server, &identity_receipt).await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let membership_id = ProjectMembershipId::new("membership-1").unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        client
            .invite_project_users(
                &project_id,
                ProjectUserInvitation::new(
                    vec!["agent@example.com".into()],
                    vec!["operator".into()],
                    roles(&["member"]),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        client
            .update_project_user_membership(&project_id, &membership_id, roles(&["viewer"]), true)
            .await
            .unwrap();
        client
            .delete_project_user_membership(&project_id, &membership_id, true)
            .await
            .unwrap();
        client
            .create_project_identity_membership(&project_id, &identity_id, roles(&["admin"]))
            .await
            .unwrap();
        client
            .update_project_identity_membership(&project_id, &identity_id, roles(&["admin"]), true)
            .await
            .unwrap();
        client
            .delete_project_identity_membership(&project_id, &identity_id, true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn unconfirmed_role_replacements_and_deletes_fail_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        assert_eq!(
            client
                .update_project_user_membership(
                    &project_id,
                    &ProjectMembershipId::new("membership-1").unwrap(),
                    roles(&["member"]),
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::ProjectMembershipRoleReplacementNotConfirmed
        );
        assert_eq!(
            client
                .update_project_identity_membership(
                    &project_id,
                    &IdentityId::new("identity-1").unwrap(),
                    roles(&["member"]),
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::ProjectMembershipRoleReplacementNotConfirmed
        );
        assert_eq!(
            client
                .delete_project_user_membership(
                    &project_id,
                    &ProjectMembershipId::new("membership-1").unwrap(),
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::ProjectMembershipDeletionNotConfirmed
        );
        assert_eq!(
            client
                .delete_project_identity_membership(
                    &project_id,
                    &IdentityId::new("identity-1").unwrap(),
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::ProjectMembershipDeletionNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
