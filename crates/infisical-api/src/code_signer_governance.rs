use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    CertificateAuthorityProjectId, CodeSignerId, CodeSigningAlgorithm, InfisicalClient,
    MutationOperation, ObservableReadOperation, Page, PageRequest, ResourceError,
    client::{ApiVersion, Endpoint, sealed},
    resources::{is_bounded_text, is_uuid, utc_timestamp_millis},
};

const MAX_GOVERNANCE_ITEMS: usize = 100;
const MAX_MEMBER_DETAIL_BYTES: usize = 256;
const MAX_PERMISSION_RULES: usize = 64;
const MAX_PERMISSION_VALUES: usize = 32;
const MAX_PERMISSION_VALUE_BYTES: usize = 64;
const MAX_PERMISSION_REASON_BYTES: usize = 256;
const MAX_POLICY_STEPS: usize = 16;
const MAX_POLICY_APPROVERS: usize = 64;
const MAX_POLICY_STEP_NAME_BYTES: usize = 64;
const MAX_POLICY_DURATION_BYTES: usize = 32;
const MAX_POLICY_SIGNINGS: u32 = 1_000_000;
const MAX_REQUEST_JUSTIFICATION_BYTES: usize = 2_048;
const MAX_REQUESTER_NAME_BYTES: usize = 256;
const MAX_REQUESTER_EMAIL_BYTES: usize = 320;
const MAX_OPERATION_ACTOR_NAME_BYTES: usize = 256;

/// Input validation failures for code-signer governance operations.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SignerGovernanceInputError {
    #[error("code-signer member ID must be a UUID")]
    InvalidMemberId,
    #[error("code-signer approval-request ID must be a UUID")]
    InvalidRequestId,
    #[error("approval policy must contain at most 16 sequentially numbered valid steps")]
    InvalidPolicySteps,
    #[error("approval policy approvers must be unique member UUIDs and cannot be empty")]
    InvalidPolicyApprovers,
    #[error("approval policy constraints are missing, unbounded, or non-canonical")]
    InvalidPolicyConstraints,
    #[error("signing approval request justification must be trimmed and contain 1 to 2048 bytes")]
    InvalidRequestJustification,
    #[error("signing approval request limits or UTC window are missing or invalid")]
    InvalidRequestLimits,
}

/// A validated user, machine-identity, or group UUID used by signer governance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct CodeSignerMemberId(String);

impl CodeSignerMemberId {
    /// Validate a member identifier before it reaches a signer-membership route.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, SignerGovernanceInputError> {
        let value = value.into();
        if !is_uuid(&value) {
            return Err(SignerGovernanceInputError::InvalidMemberId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Borrow the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated signing approval-request UUID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct CodeSignerApprovalRequestId(String);

impl CodeSignerApprovalRequestId {
    /// Validate an approval-request identifier before it reaches a signer route.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, SignerGovernanceInputError> {
        let value = value.into();
        if !is_uuid(&value) {
            return Err(SignerGovernanceInputError::InvalidRequestId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Borrow the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Principal family attached directly to a code signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeSignerMemberKind {
    /// Human user.
    User,
    /// Machine identity.
    Identity,
    /// Organization group.
    Group,
}

impl CodeSignerMemberKind {
    const fn path_segment(self) -> &'static str {
        match self {
            Self::User => "users",
            Self::Identity => "identities",
            Self::Group => "groups",
        }
    }
}

/// Principal families for which Infisical exposes effective group-derived membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeSignerEffectiveMemberKind {
    /// Human users, direct and group-derived.
    User,
    /// Machine identities, direct and group-derived.
    Identity,
}

impl CodeSignerEffectiveMemberKind {
    const fn path_segment(self) -> &'static str {
        match self {
            Self::User => "effective-users",
            Self::Identity => "effective-identities",
        }
    }

    const fn member_kind(self) -> CodeSignerMemberKind {
        match self {
            Self::User => CodeSignerMemberKind::User,
            Self::Identity => CodeSignerMemberKind::Identity,
        }
    }
}

/// Built-in signer role accepted by the pinned membership routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CodeSignerRole {
    /// Full signer administration.
    Admin,
    /// Signing and approval-request operation.
    Operator,
    /// Read-only auditing.
    Auditor,
}

/// Sanitized display metadata for a signer member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerMemberDetails {
    /// Infisical display name when present.
    pub name: Option<String>,
    /// User email when present.
    pub email: Option<String>,
    /// User name when present.
    pub username: Option<String>,
    /// Machine-identity authentication method when present.
    pub auth_method: Option<String>,
    /// Group slug when present.
    pub slug: Option<String>,
}

/// One direct signer membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerMembership {
    /// Exact membership UUID.
    pub membership_id: String,
    /// Exact owning signer UUID.
    pub signer_id: String,
    /// Principal family.
    pub member_kind: CodeSignerMemberKind,
    /// Exact user, machine-identity, or group UUID.
    pub member_id: String,
    /// Built-in signer role.
    pub role: CodeSignerRole,
    /// Creation timestamp from Infisical.
    pub created_at: String,
    /// Last-update timestamp from Infisical.
    pub updated_at: String,
    /// Optional bounded display metadata.
    pub details: Option<CodeSignerMemberDetails>,
}

/// One user or machine identity with direct or group-derived signer access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerEffectiveMember {
    /// Principal family.
    pub member_kind: CodeSignerEffectiveMemberKind,
    /// Exact user or machine-identity UUID.
    pub member_id: String,
    /// Strongest effective built-in signer role reported by Infisical.
    pub role: CodeSignerRole,
    /// Group UUIDs through which access is inherited.
    pub via_group_ids: Vec<String>,
    /// Whether a direct signer membership also exists.
    pub is_direct: bool,
    /// Optional bounded display metadata.
    pub details: Option<CodeSignerMemberDetails>,
}

/// Exact receipt returned after signer-member removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerMembershipMutationReceipt {
    /// Removed membership UUID.
    pub membership_id: String,
    /// Owning signer UUID.
    pub signer_id: String,
    /// Removed principal family.
    pub member_kind: CodeSignerMemberKind,
    /// Removed user, identity, or group UUID.
    pub member_id: String,
}

/// One normalized CASL rule from Infisical's effective signer permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerPermissionRule {
    /// Bounded action names from the packed rule.
    pub actions: Vec<String>,
    /// Bounded subject names from the packed rule.
    pub subjects: Vec<String>,
    /// Whether Infisical attached a condition that the MCP output intentionally withholds.
    pub conditional: bool,
    /// Whether this is a denying CASL rule.
    pub inverted: bool,
    /// Optional bounded field restriction.
    pub fields: Vec<String>,
    /// Optional bounded human-readable rule reason.
    pub reason: Option<String>,
}

/// One direct membership contributing to the caller's effective permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerPermissionMembership {
    /// Exact contributing membership UUID.
    pub membership_id: String,
    /// Principal family represented by the membership.
    pub member_kind: CodeSignerMemberKind,
    /// Exact user, identity, or group UUID represented by the membership.
    pub member_id: String,
    /// Built-in roles attached to the membership.
    pub roles: Vec<CodeSignerRole>,
}

/// Typed effective permission view for the authenticated Infisical identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerPermissions {
    /// Exact signer UUID selected by the caller.
    pub signer_id: String,
    /// Normalized packed CASL rules; arbitrary condition payloads are not exposed.
    pub rules: Vec<CodeSignerPermissionRule>,
    /// Memberships that contributed to the computed rules.
    pub memberships: Vec<CodeSignerPermissionMembership>,
}

/// User or group principal eligible to approve one signing step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerApprovalPolicyApprover {
    /// Approver principal family.
    pub kind: CodeSignerApprovalPolicyApproverKind,
    /// Exact user or group UUID.
    pub id: String,
}

/// Principal families accepted by the pinned signer approval-policy API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CodeSignerApprovalPolicyApproverKind {
    /// Human user.
    User,
    /// Organization group.
    Group,
}

/// One ordered step in a signer approval policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerApprovalPolicyStep {
    /// One-based position inferred from the ordered Infisical response.
    pub step_number: u16,
    /// Optional bounded display name.
    pub name: Option<String>,
    /// Number of approvals required to advance.
    pub required_approvals: u16,
    /// Unique user and group approvers.
    pub approvers: Vec<CodeSignerApprovalPolicyApprover>,
    /// Whether Infisical notifies approvers when the step begins.
    pub notify_approvers: bool,
}

/// Signing limits attached to a signer approval policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerApprovalPolicyConstraints {
    /// Maximum successful signings granted by one approval.
    pub max_signings: Option<u32>,
    /// Canonical positive duration such as `30m`, `8h`, or `7d`.
    pub max_window_duration: Option<String>,
}

/// Sanitized signer approval policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerApprovalPolicy {
    /// Exact approval-policy UUID.
    pub id: String,
    /// Exact owning signer UUID.
    pub signer_id: String,
    /// Ordered approval steps; empty means direct signing.
    pub steps: Vec<CodeSignerApprovalPolicyStep>,
    /// Signing limits applied to approvals.
    pub constraints: CodeSignerApprovalPolicyConstraints,
}

/// One validated replacement policy step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignerApprovalPolicyStepChange {
    step_number: u16,
    name: Option<String>,
    required_approvals: u16,
    approver_user_ids: Vec<CodeSignerMemberId>,
    approver_group_ids: Vec<CodeSignerMemberId>,
}

impl CodeSignerApprovalPolicyStepChange {
    /// Build one sequential approval step with unique user and group approvers.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid numbering, names, thresholds, or approver sets.
    pub fn new(
        step_number: u16,
        name: Option<String>,
        required_approvals: u16,
        approver_user_ids: Vec<CodeSignerMemberId>,
        approver_group_ids: Vec<CodeSignerMemberId>,
    ) -> Result<Self, SignerGovernanceInputError> {
        let approver_count = approver_user_ids.len() + approver_group_ids.len();
        let mut unique = HashSet::new();
        if step_number == 0
            || usize::from(step_number) > MAX_POLICY_STEPS
            || name.as_deref().is_some_and(|name| {
                name.is_empty()
                    || name.len() > MAX_POLICY_STEP_NAME_BYTES
                    || name.trim() != name
                    || name.chars().any(char::is_control)
            })
            || required_approvals == 0
            || approver_count == 0
            || approver_count > MAX_POLICY_APPROVERS
            || approver_user_ids
                .iter()
                .chain(&approver_group_ids)
                .any(|id| !unique.insert(id.as_str()))
            || (approver_group_ids.is_empty()
                && usize::from(required_approvals) > approver_user_ids.len())
        {
            return Err(SignerGovernanceInputError::InvalidPolicyApprovers);
        }
        Ok(Self {
            step_number,
            name,
            required_approvals,
            approver_user_ids,
            approver_group_ids,
        })
    }
}

/// Complete validated replacement for an existing signer approval policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignerApprovalPolicyReplacement {
    steps: Vec<CodeSignerApprovalPolicyStepChange>,
    constraints: CodeSignerApprovalPolicyConstraints,
}

impl CodeSignerApprovalPolicyReplacement {
    /// Validate one complete policy replacement.
    ///
    /// Empty steps disable approvals. Non-empty steps require at least one finite grant limit.
    ///
    /// # Errors
    ///
    /// Returns an error for non-sequential steps or invalid constraints.
    pub fn new(
        steps: Vec<CodeSignerApprovalPolicyStepChange>,
        constraints: CodeSignerApprovalPolicyConstraints,
    ) -> Result<Self, SignerGovernanceInputError> {
        if steps.len() > MAX_POLICY_STEPS
            || steps
                .iter()
                .enumerate()
                .any(|(index, step)| usize::from(step.step_number) != index + 1)
        {
            return Err(SignerGovernanceInputError::InvalidPolicySteps);
        }
        if constraints
            .max_signings
            .is_some_and(|value| value == 0 || value > MAX_POLICY_SIGNINGS)
            || constraints
                .max_window_duration
                .as_deref()
                .is_some_and(|value| !valid_policy_duration(value))
            || (!steps.is_empty()
                && constraints.max_signings.is_none()
                && constraints.max_window_duration.is_none())
        {
            return Err(SignerGovernanceInputError::InvalidPolicyConstraints);
        }
        Ok(Self { steps, constraints })
    }
}

/// Public status filter accepted by signer approval-request listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CodeSignerApprovalRequestStatusFilter {
    /// Awaiting approvals.
    Pending,
    /// Approved with a grant.
    Approved,
    /// Approval window expired.
    Expired,
    /// Rejected or cancelled.
    Revoked,
}

/// Normalized signer approval-request status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CodeSignerApprovalRequestStatus {
    /// Awaiting approvals.
    Pending,
    /// Approved with a grant.
    Approved,
    /// Approval window expired.
    Expired,
    /// Rejected or cancelled.
    Revoked,
}

/// Status of an approval grant attached to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CodeSignerApprovalGrantStatus {
    /// Grant can be used for signing.
    Active,
    /// Grant expired.
    Expired,
    /// Grant was revoked.
    Revoked,
}

/// Caller or grantee family represented in approval and operation history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CodeSignerOperationActorKind {
    /// Human user.
    User,
    /// Machine identity.
    Identity,
}

/// Optional bounded UTC window requested for signing authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerApprovalRequestWindow {
    /// Optional explicit window start; omission lets Infisical use the current time.
    pub start: Option<String>,
    /// Required window end when a window is requested.
    pub end: String,
}

/// Validated input for opening a signing approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignerApprovalRequestCreation {
    justification: String,
    requested_signings: Option<u32>,
    requested_window: Option<CodeSignerApprovalRequestWindow>,
}

impl CodeSignerApprovalRequestCreation {
    /// Validate one request for a finite signing count, time window, or both.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid justification, counts, or UTC windows.
    pub fn new(
        justification: String,
        requested_signings: Option<u32>,
        requested_window: Option<CodeSignerApprovalRequestWindow>,
    ) -> Result<Self, SignerGovernanceInputError> {
        if !is_bounded_text(&justification, MAX_REQUEST_JUSTIFICATION_BYTES)
            || justification.trim() != justification
        {
            return Err(SignerGovernanceInputError::InvalidRequestJustification);
        }
        if requested_signings.is_none() && requested_window.is_none()
            || requested_signings.is_some_and(|value| value == 0 || value > MAX_POLICY_SIGNINGS)
            || requested_window.as_ref().is_some_and(|window| {
                let Some(end) = utc_timestamp_millis(&window.end) else {
                    return true;
                };
                window.start.as_deref().is_some_and(|start| {
                    utc_timestamp_millis(start).is_none_or(|start| start >= end)
                })
            })
        {
            return Err(SignerGovernanceInputError::InvalidRequestLimits);
        }
        Ok(Self {
            justification,
            requested_signings,
            requested_window,
        })
    }
}

/// Validated input for an administrator to pre-approve one signer member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignerPreApprovalCreation {
    grantee_kind: CodeSignerOperationActorKind,
    grantee_id: CodeSignerMemberId,
    request: CodeSignerApprovalRequestCreation,
}

impl CodeSignerPreApprovalCreation {
    /// Build a pre-approval for one exact user or machine identity.
    #[must_use]
    pub const fn new(
        grantee_kind: CodeSignerOperationActorKind,
        grantee_id: CodeSignerMemberId,
        request: CodeSignerApprovalRequestCreation,
    ) -> Self {
        Self {
            grantee_kind,
            grantee_id,
            request,
        }
    }
}

/// One bounded request-list query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignerApprovalRequestListRequest {
    /// Exact owning Certificate Manager project.
    project_id: CertificateAuthorityProjectId,
    /// Exact owning signer.
    signer_id: CodeSignerId,
    /// Bounded pagination coordinates.
    page: PageRequest,
    /// Optional normalized status filters.
    statuses: Vec<CodeSignerApprovalRequestStatusFilter>,
}

impl CodeSignerApprovalRequestListRequest {
    /// Build one bounded request-list query with unique status filters.
    ///
    /// # Errors
    ///
    /// Returns an error when status filters repeat.
    pub fn new(
        project_id: CertificateAuthorityProjectId,
        signer_id: CodeSignerId,
        page: PageRequest,
        statuses: Vec<CodeSignerApprovalRequestStatusFilter>,
    ) -> Result<Self, SignerGovernanceInputError> {
        let unique = statuses.iter().copied().collect::<HashSet<_>>();
        if statuses.len() > 4 || unique.len() != statuses.len() {
            return Err(SignerGovernanceInputError::InvalidRequestLimits);
        }
        Ok(Self {
            project_id,
            signer_id,
            page,
            statuses,
        })
    }
}

/// Sanitized signing approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerApprovalRequest {
    /// Exact approval-request UUID.
    pub id: String,
    /// Exact owning signer UUID.
    pub signer_id: String,
    /// Exact approval-policy UUID.
    pub policy_id: String,
    /// Requesting user or machine-identity family.
    pub requester_kind: CodeSignerOperationActorKind,
    /// Exact requester UUID.
    pub requester_id: String,
    /// Bounded requester display name.
    pub requester_name: String,
    /// Bounded requester email when present.
    pub requester_email: Option<String>,
    /// Normalized request status.
    pub status: CodeSignerApprovalRequestStatus,
    /// Bounded human justification.
    pub justification: Option<String>,
    /// Current one-based approval step.
    pub current_step: u16,
    /// Effective maximum signings granted or requested.
    pub max_signings: Option<u32>,
    /// Successful signing operations already charged to the grant.
    pub used_signings: u32,
    /// Requested or effective UTC window start.
    pub window_start: Option<String>,
    /// Requested or effective UTC window end.
    pub window_end: Option<String>,
    /// Grant status when an approval produced a grant.
    pub grant_status: Option<CodeSignerApprovalGrantStatus>,
    /// Effective expiration timestamp when present.
    pub expires_at: Option<String>,
    /// Creation timestamp.
    pub created_at: String,
    /// Last-update timestamp.
    pub updated_at: String,
}

/// Exact receipt returned after revoking one approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerApprovalRequestRevocation {
    /// Exact owning signer UUID.
    pub signer_id: String,
    /// Exact revoked request UUID.
    pub request_id: String,
}

/// Grant returned by an administrator pre-approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerApprovalGrant {
    /// Exact grant UUID.
    pub id: String,
    /// Exact request UUID that created the grant.
    pub request_id: String,
    /// Exact grantee family.
    pub grantee_kind: CodeSignerOperationActorKind,
    /// Exact grantee UUID.
    pub grantee_id: String,
    /// Active, expired, or revoked grant status.
    pub status: CodeSignerApprovalGrantStatus,
    /// Maximum successful signings when constrained.
    pub max_signings: Option<u32>,
    /// Grant expiration timestamp when constrained.
    pub expires_at: Option<String>,
}

/// Request and grant produced by one administrator pre-approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerPreApproval {
    /// Approved request metadata.
    pub request: CodeSignerApprovalRequest,
    /// Active grant metadata.
    pub grant: CodeSignerApprovalGrant,
}

/// Signing-operation outcome filter and result status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CodeSignerOperationStatus {
    /// Signing succeeded.
    Success,
    /// Signing failed after authorization.
    Failed,
    /// Signing was denied by governance.
    Denied,
}

/// One bounded operation-history query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignerSigningOperationListRequest {
    /// Exact owning Certificate Manager project.
    project_id: CertificateAuthorityProjectId,
    /// Exact owning signer.
    signer_id: CodeSignerId,
    /// Bounded pagination coordinates.
    page: PageRequest,
    /// Optional exact status filter.
    status: Option<CodeSignerOperationStatus>,
}

impl CodeSignerSigningOperationListRequest {
    /// Build one bounded operation-history query.
    #[must_use]
    pub const fn new(
        project_id: CertificateAuthorityProjectId,
        signer_id: CodeSignerId,
        page: PageRequest,
        status: Option<CodeSignerOperationStatus>,
    ) -> Self {
        Self {
            project_id,
            signer_id,
            page,
            status,
        }
    }
}

/// Sanitized code-signing operation history entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CodeSignerSigningOperation {
    /// Exact signing-operation UUID.
    pub id: String,
    /// Exact signer UUID.
    pub signer_id: String,
    /// Operation outcome.
    pub status: CodeSignerOperationStatus,
    /// Exact signing algorithm.
    pub signing_algorithm: CodeSigningAlgorithm,
    /// User or machine identity that initiated the operation.
    pub actor_kind: CodeSignerOperationActorKind,
    /// Exact actor UUID.
    pub actor_id: String,
    /// Bounded resolved actor display name when present.
    pub actor_name: Option<String>,
    /// Project membership UUID for a human actor when present.
    pub actor_membership_id: Option<String>,
    /// Approval grant charged by the operation when present.
    pub approval_grant_id: Option<String>,
    /// Operation creation timestamp.
    pub created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignerMembershipTarget {
    #[serde(skip)]
    signer_id: CodeSignerId,
    #[serde(skip)]
    member_kind: CodeSignerMemberKind,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EffectiveMembersTarget {
    #[serde(skip)]
    signer_id: CodeSignerId,
    #[serde(skip)]
    member_kind: CodeSignerEffectiveMemberKind,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AddUserMemberRequest {
    #[serde(skip)]
    signer_id: CodeSignerId,
    user_ids: Vec<String>,
    emails: Vec<String>,
    role: CodeSignerRole,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AddIdentityMemberRequest {
    #[serde(skip)]
    signer_id: CodeSignerId,
    identity_id: String,
    role: CodeSignerRole,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AddGroupMemberRequest {
    #[serde(skip)]
    signer_id: CodeSignerId,
    group_id: String,
    role: CodeSignerRole,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateMemberRoleRequest {
    #[serde(skip)]
    signer_id: CodeSignerId,
    #[serde(skip)]
    member_kind: CodeSignerMemberKind,
    #[serde(skip)]
    member_id: CodeSignerMemberId,
    role: CodeSignerRole,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveMemberRequest {
    #[serde(skip)]
    signer_id: CodeSignerId,
    #[serde(skip)]
    member_kind: CodeSignerMemberKind,
    #[serde(skip)]
    member_id: CodeSignerMemberId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberDetailsWire {
    name: Option<String>,
    email: Option<String>,
    username: Option<String>,
    auth_method: Option<String>,
    slug: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MembershipWire {
    membership_id: String,
    signer_id: String,
    actor_user_id: Option<String>,
    actor_identity_id: Option<String>,
    actor_group_id: Option<String>,
    role: CodeSignerRole,
    custom_role_id: Option<String>,
    created_at: String,
    updated_at: String,
    details: Option<MemberDetailsWire>,
}

#[derive(Deserialize)]
struct MembershipsWire {
    memberships: Vec<MembershipWire>,
}

#[derive(Deserialize)]
struct AddedUserMembershipsWire {
    memberships: Vec<MembershipWire>,
    skipped: Vec<String>,
    unresolved: Vec<String>,
}

#[derive(Deserialize)]
struct UpdatedMembershipWire {
    membership: MembershipWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemovedMembershipWire {
    membership_id: String,
    signer_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EffectiveMemberWire {
    actor_user_id: Option<String>,
    actor_identity_id: Option<String>,
    role: CodeSignerRole,
    via_group_ids: Vec<String>,
    is_direct: bool,
    details: Option<MemberDetailsWire>,
}

#[derive(Deserialize)]
struct EffectiveMembersWire {
    members: Vec<EffectiveMemberWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PermissionRoleWire {
    role: CodeSignerRole,
    custom_role_slug: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PermissionMembershipWire {
    id: String,
    actor_user_id: Option<String>,
    actor_identity_id: Option<String>,
    actor_group_id: Option<String>,
    roles: Vec<PermissionRoleWire>,
}

#[derive(Deserialize)]
struct PermissionsDataWire {
    permissions: Vec<Value>,
    memberships: Vec<PermissionMembershipWire>,
}

#[derive(Deserialize)]
struct PermissionsWire {
    data: PermissionsDataWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyApproverWire {
    #[serde(rename = "type")]
    kind: CodeSignerApprovalPolicyApproverKind,
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyStepWire {
    name: Option<String>,
    required_approvals: u16,
    approvers: Vec<PolicyApproverWire>,
    notify_approvers: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyStepRequest {
    step_number: u16,
    name: Option<String>,
    required_approvals: u16,
    approver_user_ids: Vec<String>,
    approver_group_ids: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyConstraintsWire {
    max_signings: Option<u32>,
    max_window_duration: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyWire {
    id: String,
    signer_id: String,
    has_steps: bool,
    steps: Vec<PolicyStepWire>,
    constraints: PolicyConstraintsWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyTarget {
    #[serde(skip)]
    signer_id: CodeSignerId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplacePolicyRequest {
    #[serde(skip)]
    signer_id: CodeSignerId,
    steps: Vec<PolicyStepRequest>,
    constraints: PolicyConstraintsWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListApprovalRequestsQuery {
    #[serde(skip)]
    signer_id: CodeSignerId,
    #[serde(skip_serializing_if = "Option::is_none")]
    statuses: Option<String>,
    offset: u32,
    limit: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateApprovalRequestWire {
    #[serde(skip)]
    signer_id: CodeSignerId,
    justification: String,
    requested_signings: Option<u32>,
    requested_window_start: Option<String>,
    requested_window_end: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreApproveRequestWire {
    #[serde(skip)]
    signer_id: CodeSignerId,
    grantee_user_id: Option<String>,
    grantee_identity_id: Option<String>,
    justification: String,
    requested_signings: Option<u32>,
    requested_window_start: Option<String>,
    requested_window_end: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RevokeApprovalRequestWire {
    #[serde(skip)]
    signer_id: CodeSignerId,
    #[serde(skip)]
    request_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ApprovalRequestStatusWire {
    Pending,
    Approved,
    Rejected,
    Expired,
    Cancelled,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalRequestDataWire {
    signer_id: String,
    signer_name: String,
    approval_policy_id: String,
    justification: String,
    requested_signings: Option<u32>,
    requested_window_start: Option<String>,
    requested_window_end: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalRequestEnvelopeWire {
    version: u8,
    request_data: ApprovalRequestDataWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalRequestWire {
    id: String,
    project_id: String,
    policy_id: Option<String>,
    requester_id: Option<String>,
    requester_name: String,
    requester_email: String,
    #[serde(rename = "type")]
    request_type: String,
    status: ApprovalRequestStatusWire,
    justification: Option<String>,
    current_step: u16,
    request_data: ApprovalRequestEnvelopeWire,
    expires_at: Option<String>,
    created_at: String,
    updated_at: String,
    machine_identity_id: Option<String>,
    scope_type: Option<String>,
    scope_id: Option<String>,
    max_signings: Option<u32>,
    #[serde(default)]
    used_signings: u32,
    grant_status: Option<CodeSignerApprovalGrantStatus>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalRequestsWire {
    requests: Vec<ApprovalRequestWire>,
    total_count: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalGrantAttributesWire {
    signer_id: String,
    signer_name: String,
    max_signings: Option<u32>,
    window_start: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalGrantWire {
    id: String,
    project_id: String,
    request_id: Option<String>,
    grantee_user_id: Option<String>,
    grantee_machine_identity_id: Option<String>,
    status: CodeSignerApprovalGrantStatus,
    #[serde(rename = "type")]
    grant_type: String,
    attributes: ApprovalGrantAttributesWire,
    expires_at: Option<String>,
    is_break_glass: bool,
}

#[derive(Deserialize)]
struct PreApprovalWire {
    request: ApprovalRequestWire,
    grant: ApprovalGrantWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeReceiptWire {
    request_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListSigningOperationsQuery {
    #[serde(skip)]
    signer_id: CodeSignerId,
    offset: u32,
    limit: u16,
    status: Option<CodeSignerOperationStatus>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningOperationWire {
    id: String,
    signer_id: String,
    project_id: String,
    status: CodeSignerOperationStatus,
    signing_algorithm: CodeSigningAlgorithm,
    data_hash: String,
    actor_type: CodeSignerOperationActorKind,
    actor_id: String,
    actor_name: Option<String>,
    actor_membership_id: Option<String>,
    approval_grant_id: Option<String>,
    created_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningOperationsWire {
    operations: Vec<SigningOperationWire>,
    total_count: u64,
}

macro_rules! governance_read {
    ($operation:ident, $query:ty, $output:ty, $segments:expr) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl ObservableReadOperation for $operation {
            type Query = $query;
            type Output = $output;

            fn endpoint(query: &Self::Query) -> Endpoint {
                Endpoint::from_segments(ApiVersion::V1, ($segments)(query))
            }
        }
    };
}

governance_read!(
    ListSignerMembers,
    SignerMembershipTarget,
    MembershipsWire,
    |query: &SignerMembershipTarget| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        query.signer_id.as_str().to_owned(),
        query.member_kind.path_segment().to_owned()
    ]
);
governance_read!(
    GetSignerApprovalPolicy,
    PolicyTarget,
    PolicyWire,
    |query: &PolicyTarget| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        query.signer_id.as_str().to_owned(),
        "approval-policy".to_owned()
    ]
);
governance_read!(
    ListSignerApprovalRequests,
    ListApprovalRequestsQuery,
    ApprovalRequestsWire,
    |query: &ListApprovalRequestsQuery| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        query.signer_id.as_str().to_owned(),
        "requests".to_owned()
    ]
);
governance_read!(
    ListSignerSigningOperations,
    ListSigningOperationsQuery,
    SigningOperationsWire,
    |query: &ListSigningOperationsQuery| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        query.signer_id.as_str().to_owned(),
        "operations".to_owned()
    ]
);
governance_read!(
    GetSignerPermissions,
    SignerMembershipTarget,
    PermissionsWire,
    |query: &SignerMembershipTarget| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        query.signer_id.as_str().to_owned(),
        "permissions".to_owned()
    ]
);
governance_read!(
    ListEffectiveSignerMembers,
    EffectiveMembersTarget,
    EffectiveMembersWire,
    |query: &EffectiveMembersTarget| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        query.signer_id.as_str().to_owned(),
        query.member_kind.path_segment().to_owned()
    ]
);

macro_rules! governance_mutation {
    ($operation:ident, $input:ty, $output:ty, $method:expr, $segments:expr) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl MutationOperation for $operation {
            type Input = $input;
            type Output = $output;

            fn method() -> Method {
                $method
            }

            fn endpoint(input: &Self::Input) -> Endpoint {
                Endpoint::from_segments(ApiVersion::V1, ($segments)(input))
            }
        }
    };
}

governance_mutation!(
    AddSignerUserMember,
    AddUserMemberRequest,
    AddedUserMembershipsWire,
    Method::POST,
    |input: &AddUserMemberRequest| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned(),
        "users".to_owned()
    ]
);
governance_mutation!(
    ReplaceSignerApprovalPolicy,
    ReplacePolicyRequest,
    PolicyWire,
    Method::PUT,
    |input: &ReplacePolicyRequest| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned(),
        "approval-policy".to_owned()
    ]
);
governance_mutation!(
    CreateSignerApprovalRequest,
    CreateApprovalRequestWire,
    ApprovalRequestWire,
    Method::POST,
    |input: &CreateApprovalRequestWire| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned(),
        "requests".to_owned()
    ]
);
governance_mutation!(
    PreApproveSignerRequest,
    PreApproveRequestWire,
    PreApprovalWire,
    Method::POST,
    |input: &PreApproveRequestWire| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned(),
        "requests".to_owned(),
        "pre-approve".to_owned()
    ]
);
governance_mutation!(
    RevokeSignerApprovalRequest,
    RevokeApprovalRequestWire,
    RevokeReceiptWire,
    Method::POST,
    |input: &RevokeApprovalRequestWire| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned(),
        "requests".to_owned(),
        input.request_id.clone(),
        "revoke".to_owned()
    ]
);
governance_mutation!(
    AddSignerIdentityMember,
    AddIdentityMemberRequest,
    MembershipWire,
    Method::POST,
    |input: &AddIdentityMemberRequest| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned(),
        "identities".to_owned()
    ]
);
governance_mutation!(
    AddSignerGroupMember,
    AddGroupMemberRequest,
    MembershipWire,
    Method::POST,
    |input: &AddGroupMemberRequest| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned(),
        "groups".to_owned()
    ]
);
governance_mutation!(
    UpdateSignerMemberRole,
    UpdateMemberRoleRequest,
    UpdatedMembershipWire,
    Method::PATCH,
    |input: &UpdateMemberRoleRequest| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned(),
        input.member_kind.path_segment().to_owned(),
        input.member_id.as_str().to_owned()
    ]
);
governance_mutation!(
    RemoveSignerMember,
    RemoveMemberRequest,
    RemovedMembershipWire,
    Method::DELETE,
    |input: &RemoveMemberRequest| [
        "cert-manager".to_owned(),
        "signers".to_owned(),
        input.signer_id.as_str().to_owned(),
        input.member_kind.path_segment().to_owned(),
        input.member_id.as_str().to_owned()
    ]
);

fn valid_optional_detail(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        value.len() <= MAX_MEMBER_DETAIL_BYTES
            && value.trim() == value
            && !value.chars().any(char::is_control)
    })
}

fn details_from_wire(
    details: Option<MemberDetailsWire>,
) -> Result<Option<CodeSignerMemberDetails>, ResourceError> {
    let Some(details) = details else {
        return Ok(None);
    };
    if !valid_optional_detail(details.name.as_deref())
        || !valid_optional_detail(details.email.as_deref())
        || !valid_optional_detail(details.username.as_deref())
        || !valid_optional_detail(details.auth_method.as_deref())
        || !valid_optional_detail(details.slug.as_deref())
    {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    Ok(Some(CodeSignerMemberDetails {
        name: details.name,
        email: details.email,
        username: details.username,
        auth_method: details.auth_method,
        slug: details.slug,
    }))
}

fn membership_from_wire(
    wire: MembershipWire,
    signer_id: &CodeSignerId,
    expected_kind: CodeSignerMemberKind,
    expected_member_id: Option<&CodeSignerMemberId>,
) -> Result<CodeSignerMembership, ResourceError> {
    let actor_ids = [
        (CodeSignerMemberKind::User, wire.actor_user_id.as_deref()),
        (
            CodeSignerMemberKind::Identity,
            wire.actor_identity_id.as_deref(),
        ),
        (CodeSignerMemberKind::Group, wire.actor_group_id.as_deref()),
    ];
    let present = actor_ids
        .iter()
        .filter_map(|(kind, id)| id.map(|id| (*kind, id)))
        .collect::<Vec<_>>();
    if !is_uuid(&wire.membership_id)
        || wire.signer_id != signer_id.as_str()
        || wire.custom_role_id.is_some()
        || utc_timestamp_millis(&wire.created_at).is_none()
        || utc_timestamp_millis(&wire.updated_at).is_none()
        || present.len() != 1
        || present[0].0 != expected_kind
        || !is_uuid(present[0].1)
        || expected_member_id.is_some_and(|expected| present[0].1 != expected.as_str())
    {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    Ok(CodeSignerMembership {
        membership_id: wire.membership_id,
        signer_id: wire.signer_id,
        member_kind: expected_kind,
        member_id: present[0].1.to_ascii_lowercase(),
        role: wire.role,
        created_at: wire.created_at,
        updated_at: wire.updated_at,
        details: details_from_wire(wire.details)?,
    })
}

fn memberships_from_wire(
    response: MembershipsWire,
    signer_id: &CodeSignerId,
    member_kind: CodeSignerMemberKind,
) -> Result<Vec<CodeSignerMembership>, ResourceError> {
    if response.memberships.len() > MAX_GOVERNANCE_ITEMS {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    let memberships = response
        .memberships
        .into_iter()
        .map(|wire| membership_from_wire(wire, signer_id, member_kind, None))
        .collect::<Result<Vec<_>, _>>()?;
    let mut membership_ids = memberships
        .iter()
        .map(|membership| membership.membership_id.as_str())
        .collect::<Vec<_>>();
    membership_ids.sort_unstable();
    if membership_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    Ok(memberships)
}

fn effective_members_from_wire(
    response: EffectiveMembersWire,
    member_kind: CodeSignerEffectiveMemberKind,
) -> Result<Vec<CodeSignerEffectiveMember>, ResourceError> {
    if response.members.len() > MAX_GOVERNANCE_ITEMS {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    let expected_kind = member_kind.member_kind();
    let members = response
        .members
        .into_iter()
        .map(|wire| {
            let actor_ids = [
                (CodeSignerMemberKind::User, wire.actor_user_id.as_deref()),
                (
                    CodeSignerMemberKind::Identity,
                    wire.actor_identity_id.as_deref(),
                ),
            ];
            let present = actor_ids
                .iter()
                .filter_map(|(kind, id)| id.map(|id| (*kind, id)))
                .collect::<Vec<_>>();
            if present.len() != 1
                || present[0].0 != expected_kind
                || !is_uuid(present[0].1)
                || wire.via_group_ids.len() > MAX_GOVERNANCE_ITEMS
                || wire.via_group_ids.iter().any(|id| !is_uuid(id))
            {
                return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
            }
            Ok(CodeSignerEffectiveMember {
                member_kind,
                member_id: present[0].1.to_ascii_lowercase(),
                role: wire.role,
                via_group_ids: wire.via_group_ids,
                is_direct: wire.is_direct,
                details: details_from_wire(wire.details)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut member_ids = members
        .iter()
        .map(|member| member.member_id.as_str())
        .collect::<Vec<_>>();
    member_ids.sort_unstable();
    if member_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    Ok(members)
}

fn valid_permission_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PERMISSION_VALUE_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.' | b'*')
        })
}

fn split_permission_values(value: &str) -> Result<Vec<String>, ResourceError> {
    let values = value.split(',').map(str::to_owned).collect::<Vec<_>>();
    if values.is_empty()
        || values.len() > MAX_PERMISSION_VALUES
        || values.iter().any(|value| !valid_permission_value(value))
    {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    Ok(values)
}

fn permission_rule_from_wire(value: Value) -> Result<CodeSignerPermissionRule, ResourceError> {
    let Value::Array(parts) = value else {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    };
    if !(2..=6).contains(&parts.len()) {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    let actions = parts[0]
        .as_str()
        .ok_or(ResourceError::InvalidCodeSignerGovernanceResponse)
        .and_then(split_permission_values)?;
    let subjects = parts[1]
        .as_str()
        .ok_or(ResourceError::InvalidCodeSignerGovernanceResponse)
        .and_then(split_permission_values)?;
    let conditional = parts.get(2).is_some_and(|value| value != &Value::from(0));
    if parts
        .get(2)
        .is_some_and(|value| value != &Value::from(0) && !value.is_object())
    {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    let inverted = match parts.get(3) {
        None => false,
        Some(Value::Number(_)) if parts.get(3).and_then(Value::as_u64) == Some(0) => false,
        Some(Value::Number(_)) if parts.get(3).and_then(Value::as_u64) == Some(1) => true,
        _ => return Err(ResourceError::InvalidCodeSignerGovernanceResponse),
    };
    let fields = match parts.get(4) {
        None => Vec::new(),
        Some(Value::Number(_)) if parts.get(4).and_then(Value::as_u64) == Some(0) => Vec::new(),
        Some(Value::String(value)) => split_permission_values(value)?,
        _ => return Err(ResourceError::InvalidCodeSignerGovernanceResponse),
    };
    let reason = match parts.get(5) {
        None => None,
        Some(Value::String(value))
            if is_bounded_text(value, MAX_PERMISSION_REASON_BYTES) && value.trim() == value =>
        {
            Some(value.clone())
        }
        _ => return Err(ResourceError::InvalidCodeSignerGovernanceResponse),
    };
    Ok(CodeSignerPermissionRule {
        actions,
        subjects,
        conditional,
        inverted,
        fields,
        reason,
    })
}

fn permission_membership_from_wire(
    wire: PermissionMembershipWire,
) -> Result<CodeSignerPermissionMembership, ResourceError> {
    let actor_ids = [
        (CodeSignerMemberKind::User, wire.actor_user_id.as_deref()),
        (
            CodeSignerMemberKind::Identity,
            wire.actor_identity_id.as_deref(),
        ),
        (CodeSignerMemberKind::Group, wire.actor_group_id.as_deref()),
    ];
    let present = actor_ids
        .iter()
        .filter_map(|(kind, id)| id.map(|id| (*kind, id)))
        .collect::<Vec<_>>();
    if !is_uuid(&wire.id)
        || present.len() != 1
        || !is_uuid(present[0].1)
        || wire.roles.is_empty()
        || wire.roles.len() > MAX_PERMISSION_VALUES
        || wire
            .roles
            .iter()
            .any(|role| role.custom_role_slug.is_some())
    {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    let roles = wire.roles.into_iter().map(|role| role.role).collect();
    Ok(CodeSignerPermissionMembership {
        membership_id: wire.id,
        member_kind: present[0].0,
        member_id: present[0].1.to_ascii_lowercase(),
        roles,
    })
}

fn permissions_from_wire(
    response: PermissionsWire,
    signer_id: &CodeSignerId,
) -> Result<CodeSignerPermissions, ResourceError> {
    if response.data.permissions.len() > MAX_PERMISSION_RULES
        || response.data.memberships.len() > MAX_GOVERNANCE_ITEMS
    {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    let rules = response
        .data
        .permissions
        .into_iter()
        .map(permission_rule_from_wire)
        .collect::<Result<Vec<_>, _>>()?;
    let memberships = response
        .data
        .memberships
        .into_iter()
        .map(permission_membership_from_wire)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CodeSignerPermissions {
        signer_id: signer_id.as_str().to_owned(),
        rules,
        memberships,
    })
}

fn valid_policy_duration(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_POLICY_DURATION_BYTES || value.trim() != value {
        return false;
    }
    let digit_count = value.bytes().take_while(u8::is_ascii_digit).count();
    if digit_count == 0 || value.as_bytes()[0] == b'0' {
        return false;
    }
    matches!(&value[digit_count..], "ms" | "s" | "m" | "h" | "d" | "w")
}

fn policy_from_wire(
    wire: PolicyWire,
    signer_id: &CodeSignerId,
) -> Result<CodeSignerApprovalPolicy, ResourceError> {
    if !is_uuid(&wire.id)
        || wire.signer_id != signer_id.as_str()
        || wire.has_steps == wire.steps.is_empty()
        || wire.steps.len() > MAX_POLICY_STEPS
        || wire
            .constraints
            .max_signings
            .is_some_and(|value| value == 0 || value > MAX_POLICY_SIGNINGS)
        || wire
            .constraints
            .max_window_duration
            .as_deref()
            .is_some_and(|value| !valid_policy_duration(value))
        || (!wire.steps.is_empty()
            && wire.constraints.max_signings.is_none()
            && wire.constraints.max_window_duration.is_none())
    {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    let steps =
        wire.steps
            .into_iter()
            .enumerate()
            .map(|(index, step)| {
                let has_group = step
                    .approvers
                    .iter()
                    .any(|approver| approver.kind == CodeSignerApprovalPolicyApproverKind::Group);
                let mut unique = HashSet::new();
                if step.required_approvals == 0
                    || step.approvers.is_empty()
                    || step.approvers.len() > MAX_POLICY_APPROVERS
                    || step.name.as_deref().is_some_and(|name| {
                        name.is_empty()
                            || name.len() > MAX_POLICY_STEP_NAME_BYTES
                            || name.trim() != name
                            || name.chars().any(char::is_control)
                    })
                    || step.approvers.iter().any(|approver| {
                        !is_uuid(&approver.id) || !unique.insert(approver.id.as_str())
                    })
                    || (!has_group && usize::from(step.required_approvals) > step.approvers.len())
                {
                    return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
                }
                Ok(CodeSignerApprovalPolicyStep {
                    step_number: u16::try_from(index + 1)
                        .map_err(|_| ResourceError::InvalidCodeSignerGovernanceResponse)?,
                    name: step.name,
                    required_approvals: step.required_approvals,
                    approvers: step
                        .approvers
                        .into_iter()
                        .map(|approver| CodeSignerApprovalPolicyApprover {
                            kind: approver.kind,
                            id: approver.id.to_ascii_lowercase(),
                        })
                        .collect(),
                    notify_approvers: step.notify_approvers.unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
    Ok(CodeSignerApprovalPolicy {
        id: wire.id,
        signer_id: wire.signer_id,
        steps,
        constraints: CodeSignerApprovalPolicyConstraints {
            max_signings: wire.constraints.max_signings,
            max_window_duration: wire.constraints.max_window_duration,
        },
    })
}

fn policy_request(replacement: &CodeSignerApprovalPolicyReplacement) -> Vec<PolicyStepRequest> {
    replacement
        .steps
        .iter()
        .map(|step| PolicyStepRequest {
            step_number: step.step_number,
            name: step.name.clone(),
            required_approvals: step.required_approvals,
            approver_user_ids: step
                .approver_user_ids
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
            approver_group_ids: step
                .approver_group_ids
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
        })
        .collect()
}

fn policy_matches_replacement(
    policy: &CodeSignerApprovalPolicy,
    replacement: &CodeSignerApprovalPolicyReplacement,
) -> bool {
    if policy.constraints != replacement.constraints
        || policy.steps.len() != replacement.steps.len()
    {
        return false;
    }
    policy
        .steps
        .iter()
        .zip(&replacement.steps)
        .all(|(actual, expected)| {
            let actual_approvers = actual
                .approvers
                .iter()
                .map(|approver| (approver.kind, approver.id.as_str()))
                .collect::<HashSet<_>>();
            let expected_approvers = expected
                .approver_user_ids
                .iter()
                .map(|id| (CodeSignerApprovalPolicyApproverKind::User, id.as_str()))
                .chain(
                    expected
                        .approver_group_ids
                        .iter()
                        .map(|id| (CodeSignerApprovalPolicyApproverKind::Group, id.as_str())),
                )
                .collect::<HashSet<_>>();
            actual.step_number == expected.step_number
                && actual.name == expected.name
                && actual.required_approvals == expected.required_approvals
                && !actual.notify_approvers
                && actual_approvers == expected_approvers
        })
}

fn approvers_are_active_members(
    replacement: &CodeSignerApprovalPolicyReplacement,
    user_memberships: &[CodeSignerMembership],
    group_memberships: &[CodeSignerMembership],
) -> bool {
    let users = user_memberships
        .iter()
        .map(|membership| (membership.member_id.as_str(), membership.role))
        .collect::<std::collections::HashMap<_, _>>();
    let groups = group_memberships
        .iter()
        .map(|membership| (membership.member_id.as_str(), membership.role))
        .collect::<std::collections::HashMap<_, _>>();
    replacement.steps.iter().all(|step| {
        step.approver_user_ids.iter().all(|id| {
            users
                .get(id.as_str())
                .is_some_and(|role| *role != CodeSignerRole::Auditor)
        }) && step.approver_group_ids.iter().all(|id| {
            groups
                .get(id.as_str())
                .is_some_and(|role| *role != CodeSignerRole::Auditor)
        })
    })
}

fn request_status_from_wire(status: &ApprovalRequestStatusWire) -> CodeSignerApprovalRequestStatus {
    match status {
        ApprovalRequestStatusWire::Pending => CodeSignerApprovalRequestStatus::Pending,
        ApprovalRequestStatusWire::Approved => CodeSignerApprovalRequestStatus::Approved,
        ApprovalRequestStatusWire::Expired => CodeSignerApprovalRequestStatus::Expired,
        ApprovalRequestStatusWire::Rejected | ApprovalRequestStatusWire::Cancelled => {
            CodeSignerApprovalRequestStatus::Revoked
        }
    }
}

fn valid_optional_timestamp(value: Option<&str>) -> bool {
    value.is_none_or(|value| utc_timestamp_millis(value).is_some())
}

fn approval_request_from_wire(
    wire: ApprovalRequestWire,
    project_id: &CertificateAuthorityProjectId,
    signer_id: &CodeSignerId,
    expected_request_id: Option<&CodeSignerApprovalRequestId>,
) -> Result<CodeSignerApprovalRequest, ResourceError> {
    let policy_id = wire
        .policy_id
        .as_deref()
        .ok_or(ResourceError::InvalidCodeSignerGovernanceResponse)?;
    let requester = match (
        wire.requester_id.as_deref(),
        wire.machine_identity_id.as_deref(),
    ) {
        (Some(id), None) => (CodeSignerOperationActorKind::User, id),
        (None, Some(id)) => (CodeSignerOperationActorKind::Identity, id),
        _ => return Err(ResourceError::InvalidCodeSignerGovernanceResponse),
    };
    let request_data = &wire.request_data.request_data;
    let window_start = request_data.requested_window_start.as_deref();
    let window_end = request_data.requested_window_end.as_deref();
    let invalid_window = !valid_optional_timestamp(window_start)
        || !valid_optional_timestamp(window_end)
        || window_start.is_some() && window_end.is_none()
        || window_start
            .zip(window_end)
            .is_some_and(|(start, end)| utc_timestamp_millis(start) >= utc_timestamp_millis(end));
    if !is_uuid(&wire.id)
        || expected_request_id.is_some_and(|expected| wire.id != expected.as_str())
        || wire.project_id != project_id.as_str()
        || !is_uuid(policy_id)
        || wire.request_data.version != 1
        || request_data.signer_id != signer_id.as_str()
        || request_data.approval_policy_id != policy_id
        || !is_bounded_text(&request_data.signer_name, 64)
        || wire.request_type != "cert-code-signing"
        || wire.scope_type.as_deref() != Some("pki-signer")
        || wire.scope_id.as_deref() != Some(signer_id.as_str())
        || !is_uuid(requester.1)
        || !is_bounded_text(&wire.requester_name, MAX_REQUESTER_NAME_BYTES)
        || wire.requester_email.len() > MAX_REQUESTER_EMAIL_BYTES
        || wire.requester_email.chars().any(char::is_control)
        || wire.justification.as_deref() != Some(request_data.justification.as_str())
        || !is_bounded_text(&request_data.justification, MAX_REQUEST_JUSTIFICATION_BYTES)
        || wire.current_step == 0
        || usize::from(wire.current_step) > MAX_POLICY_STEPS
        || request_data
            .requested_signings
            .is_some_and(|value| value == 0 || value > MAX_POLICY_SIGNINGS)
        || wire
            .max_signings
            .is_some_and(|value| value == 0 || value > MAX_POLICY_SIGNINGS)
        || invalid_window
        || !valid_optional_timestamp(wire.expires_at.as_deref())
        || utc_timestamp_millis(&wire.created_at).is_none()
        || utc_timestamp_millis(&wire.updated_at).is_none()
    {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    let max_signings = wire.max_signings.or(request_data.requested_signings);
    if max_signings.is_some_and(|maximum| wire.used_signings > maximum) {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    Ok(CodeSignerApprovalRequest {
        id: wire.id,
        signer_id: request_data.signer_id.clone(),
        policy_id: policy_id.to_ascii_lowercase(),
        requester_kind: requester.0,
        requester_id: requester.1.to_ascii_lowercase(),
        requester_name: wire.requester_name,
        requester_email: (!wire.requester_email.is_empty()).then_some(wire.requester_email),
        status: request_status_from_wire(&wire.status),
        justification: wire.justification,
        current_step: wire.current_step,
        max_signings,
        used_signings: wire.used_signings,
        window_start: request_data.requested_window_start.clone(),
        window_end: request_data.requested_window_end.clone(),
        grant_status: wire.grant_status,
        expires_at: wire.expires_at,
        created_at: wire.created_at,
        updated_at: wire.updated_at,
    })
}

fn request_matches_creation(
    request: &CodeSignerApprovalRequest,
    creation: &CodeSignerApprovalRequestCreation,
) -> bool {
    request.justification.as_deref() == Some(creation.justification.as_str())
        && request.max_signings == creation.requested_signings
        && request.window_start
            == creation
                .requested_window
                .as_ref()
                .and_then(|window| window.start.clone())
        && request.window_end
            == creation
                .requested_window
                .as_ref()
                .map(|window| window.end.clone())
}

fn requested_limits_fit_policy(
    creation: &CodeSignerApprovalRequestCreation,
    policy: &CodeSignerApprovalPolicy,
    default_window_start: Option<i64>,
) -> bool {
    if policy.steps.is_empty()
        || creation.requested_signings.is_some_and(|requested| {
            policy
                .constraints
                .max_signings
                .is_some_and(|maximum| requested > maximum)
        })
    {
        return false;
    }
    let Some(window) = creation.requested_window.as_ref() else {
        return true;
    };
    let Some(maximum) = policy
        .constraints
        .max_window_duration
        .as_deref()
        .and_then(policy_duration_millis)
    else {
        return true;
    };
    let start = match window.start.as_deref() {
        Some(start) => utc_timestamp_millis(start),
        None => default_window_start,
    };
    utc_timestamp_millis(&window.end)
        .zip(start)
        .is_some_and(|(end, start)| end > start && end - start <= maximum)
}

fn policy_duration_millis(value: &str) -> Option<i64> {
    let digit_count = value.bytes().take_while(u8::is_ascii_digit).count();
    let amount = value[..digit_count].parse::<i64>().ok()?;
    let multiplier = match &value[digit_count..] {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        "w" => 604_800_000,
        _ => return None,
    };
    amount.checked_mul(multiplier)
}

fn current_timestamp_millis() -> Option<i64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let unix_epoch = utc_timestamp_millis("1970-01-01T00:00:00Z")?;
    i64::try_from(elapsed.as_millis())
        .ok()?
        .checked_add(unix_epoch)
}

fn request_status_matches_filter(
    status: CodeSignerApprovalRequestStatus,
    filter: CodeSignerApprovalRequestStatusFilter,
) -> bool {
    matches!(
        (status, filter),
        (
            CodeSignerApprovalRequestStatus::Pending,
            CodeSignerApprovalRequestStatusFilter::Pending
        ) | (
            CodeSignerApprovalRequestStatus::Approved,
            CodeSignerApprovalRequestStatusFilter::Approved
        ) | (
            CodeSignerApprovalRequestStatus::Expired,
            CodeSignerApprovalRequestStatusFilter::Expired
        ) | (
            CodeSignerApprovalRequestStatus::Revoked,
            CodeSignerApprovalRequestStatusFilter::Revoked
        )
    )
}

fn approval_requests_page_from_wire(
    response: ApprovalRequestsWire,
    request: &CodeSignerApprovalRequestListRequest,
) -> Result<Page<CodeSignerApprovalRequest>, ResourceError> {
    let returned = u32::try_from(response.requests.len())
        .map_err(|_| ResourceError::InvalidCodeSignerGovernanceResponse)?;
    let end = request
        .page
        .offset()
        .checked_add(returned)
        .ok_or(ResourceError::InvalidCodeSignerGovernanceResponse)?;
    if response.requests.len() > usize::from(request.page.limit())
        || response.total_count < u64::from(end)
        || (returned < u32::from(request.page.limit()) && u64::from(end) < response.total_count)
    {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    let requests = response
        .requests
        .into_iter()
        .map(|wire| approval_request_from_wire(wire, &request.project_id, &request.signer_id, None))
        .collect::<Result<Vec<_>, _>>()?;
    if !request.statuses.is_empty()
        && requests.iter().any(|returned| {
            !request
                .statuses
                .iter()
                .any(|filter| request_status_matches_filter(returned.status, *filter))
        })
    {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    Page::new(request.page, requests, Some(response.total_count)).map_err(ResourceError::from)
}

fn approval_grant_from_wire(
    wire: ApprovalGrantWire,
    project_id: &CertificateAuthorityProjectId,
    signer_id: &CodeSignerId,
    request_id: &str,
    creation: &CodeSignerPreApprovalCreation,
) -> Result<CodeSignerApprovalGrant, ResourceError> {
    let grantee = match (
        wire.grantee_user_id.as_deref(),
        wire.grantee_machine_identity_id.as_deref(),
    ) {
        (Some(id), None) => (CodeSignerOperationActorKind::User, id),
        (None, Some(id)) => (CodeSignerOperationActorKind::Identity, id),
        _ => return Err(ResourceError::InvalidCodeSignerGovernanceResponse),
    };
    if !is_uuid(&wire.id)
        || wire.project_id != project_id.as_str()
        || wire.request_id.as_deref() != Some(request_id)
        || wire.grant_type != "cert-code-signing"
        || wire.attributes.signer_id != signer_id.as_str()
        || !is_bounded_text(&wire.attributes.signer_name, 64)
        || grantee.0 != creation.grantee_kind
        || grantee.1 != creation.grantee_id.as_str()
        || wire.status != CodeSignerApprovalGrantStatus::Active
        || wire.is_break_glass
        || wire.attributes.max_signings != creation.request.requested_signings
        || wire.attributes.window_start
            != creation
                .request
                .requested_window
                .as_ref()
                .and_then(|window| window.start.clone())
        || !valid_optional_timestamp(wire.expires_at.as_deref())
        || wire.expires_at
            != creation
                .request
                .requested_window
                .as_ref()
                .map(|window| window.end.clone())
    {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    Ok(CodeSignerApprovalGrant {
        id: wire.id,
        request_id: request_id.to_owned(),
        grantee_kind: grantee.0,
        grantee_id: grantee.1.to_ascii_lowercase(),
        status: wire.status,
        max_signings: wire.attributes.max_signings,
        expires_at: wire.expires_at,
    })
}

fn signing_operations_page_from_wire(
    response: SigningOperationsWire,
    request: &CodeSignerSigningOperationListRequest,
) -> Result<Page<CodeSignerSigningOperation>, ResourceError> {
    let returned = u32::try_from(response.operations.len())
        .map_err(|_| ResourceError::InvalidCodeSignerGovernanceResponse)?;
    let end = request
        .page
        .offset()
        .checked_add(returned)
        .ok_or(ResourceError::InvalidCodeSignerGovernanceResponse)?;
    if response.operations.len() > usize::from(request.page.limit())
        || response.total_count < u64::from(end)
        || (returned < u32::from(request.page.limit()) && u64::from(end) < response.total_count)
    {
        return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
    }
    let operations = response
        .operations
        .into_iter()
        .map(|wire| {
            if !is_uuid(&wire.id)
                || wire.signer_id != request.signer_id.as_str()
                || wire.project_id != request.project_id.as_str()
                || wire.data_hash.len() != 64
                || !wire.data_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !is_uuid(&wire.actor_id)
                || wire
                    .actor_name
                    .as_deref()
                    .is_some_and(|name| !is_bounded_text(name, MAX_OPERATION_ACTOR_NAME_BYTES))
                || wire
                    .actor_membership_id
                    .as_deref()
                    .is_some_and(|id| !is_uuid(id))
                || wire
                    .approval_grant_id
                    .as_deref()
                    .is_some_and(|id| !is_uuid(id))
                || utc_timestamp_millis(&wire.created_at).is_none()
                || request.status.is_some_and(|status| status != wire.status)
            {
                return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
            }
            Ok(CodeSignerSigningOperation {
                id: wire.id,
                signer_id: wire.signer_id,
                status: wire.status,
                signing_algorithm: wire.signing_algorithm,
                actor_kind: wire.actor_type,
                actor_id: wire.actor_id,
                actor_name: wire.actor_name,
                actor_membership_id: wire.actor_membership_id,
                approval_grant_id: wire.approval_grant_id,
                created_at: wire.created_at,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Page::new(request.page, operations, Some(response.total_count)).map_err(ResourceError::from)
}

impl InfisicalClient {
    /// List bounded direct memberships for one exact signer.
    ///
    /// # Errors
    ///
    /// Returns a scope, client, or bounded response-contract error.
    pub async fn list_code_signer_members(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        member_kind: CodeSignerMemberKind,
    ) -> Result<Vec<CodeSignerMembership>, ResourceError> {
        self.get_code_signer(project_id, signer_id).await?;
        let response = self
            .execute_observable_read::<ListSignerMembers>(&SignerMembershipTarget {
                signer_id: signer_id.clone(),
                member_kind,
            })
            .await?;
        memberships_from_wire(response, signer_id, member_kind)
    }

    /// List bounded direct and group-derived users or identities for one signer.
    ///
    /// # Errors
    ///
    /// Returns a scope, client, or bounded response-contract error.
    pub async fn list_code_signer_effective_members(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        member_kind: CodeSignerEffectiveMemberKind,
    ) -> Result<Vec<CodeSignerEffectiveMember>, ResourceError> {
        self.get_code_signer(project_id, signer_id).await?;
        let response = self
            .execute_observable_read::<ListEffectiveSignerMembers>(&EffectiveMembersTarget {
                signer_id: signer_id.clone(),
                member_kind,
            })
            .await?;
        effective_members_from_wire(response, member_kind)
    }

    /// Get the authenticated Infisical identity's normalized effective signer permissions.
    ///
    /// Arbitrary CASL condition payloads are intentionally reduced to a `conditional` marker.
    ///
    /// # Errors
    ///
    /// Returns a scope, client, or bounded response-contract error.
    pub async fn get_code_signer_permissions(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
    ) -> Result<CodeSignerPermissions, ResourceError> {
        self.get_code_signer(project_id, signer_id).await?;
        let response = self
            .execute_observable_read::<GetSignerPermissions>(&SignerMembershipTarget {
                signer_id: signer_id.clone(),
                member_kind: CodeSignerMemberKind::Identity,
            })
            .await?;
        permissions_from_wire(response, signer_id)
    }

    /// Get one exact signer's sanitized approval policy.
    ///
    /// # Errors
    ///
    /// Returns a scope, client, or bounded response-contract error.
    pub async fn get_code_signer_approval_policy(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
    ) -> Result<CodeSignerApprovalPolicy, ResourceError> {
        self.get_code_signer(project_id, signer_id).await?;
        let response = self
            .execute_observable_read::<GetSignerApprovalPolicy>(&PolicyTarget {
                signer_id: signer_id.clone(),
            })
            .await?;
        policy_from_wire(response, signer_id)
    }

    /// Replace all approval steps and signing limits for one exact signer.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, membership, client, or reflected-response error.
    pub async fn replace_code_signer_approval_policy(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        replacement: CodeSignerApprovalPolicyReplacement,
        confirm: bool,
    ) -> Result<CodeSignerApprovalPolicy, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSignerGovernanceMutationNotConfirmed);
        }
        let before = self
            .get_code_signer_approval_policy(project_id, signer_id)
            .await?;
        let user_memberships = if replacement
            .steps
            .iter()
            .any(|step| !step.approver_user_ids.is_empty())
        {
            self.list_code_signer_members(project_id, signer_id, CodeSignerMemberKind::User)
                .await?
        } else {
            Vec::new()
        };
        let group_memberships = if replacement
            .steps
            .iter()
            .any(|step| !step.approver_group_ids.is_empty())
        {
            self.list_code_signer_members(project_id, signer_id, CodeSignerMemberKind::Group)
                .await?
        } else {
            Vec::new()
        };
        if !approvers_are_active_members(&replacement, &user_memberships, &group_memberships) {
            return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
        }
        let response = self
            .execute_mutation::<ReplaceSignerApprovalPolicy>(&ReplacePolicyRequest {
                signer_id: signer_id.clone(),
                steps: policy_request(&replacement),
                constraints: PolicyConstraintsWire {
                    max_signings: replacement.constraints.max_signings,
                    max_window_duration: replacement.constraints.max_window_duration.clone(),
                },
            })
            .await?;
        let policy = policy_from_wire(response, signer_id)?;
        if policy.id != before.id || !policy_matches_replacement(&policy, &replacement) {
            return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
        }
        Ok(policy)
    }

    /// List one bounded page of approval requests for one exact signer.
    ///
    /// # Errors
    ///
    /// Returns a scope, pagination, client, or bounded response-contract error.
    pub async fn list_code_signer_approval_requests(
        &self,
        request: CodeSignerApprovalRequestListRequest,
    ) -> Result<Page<CodeSignerApprovalRequest>, ResourceError> {
        self.get_code_signer(&request.project_id, &request.signer_id)
            .await?;
        let statuses = (!request.statuses.is_empty()).then(|| {
            request
                .statuses
                .iter()
                .map(|status| match status {
                    CodeSignerApprovalRequestStatusFilter::Pending => "pending",
                    CodeSignerApprovalRequestStatusFilter::Approved => "approved",
                    CodeSignerApprovalRequestStatusFilter::Expired => "expired",
                    // The pinned public router expands this UI value to rejected and cancelled.
                    CodeSignerApprovalRequestStatusFilter::Revoked => "revoked",
                })
                .collect::<Vec<_>>()
                .join(",")
        });
        let response = self
            .execute_observable_read::<ListSignerApprovalRequests>(&ListApprovalRequestsQuery {
                signer_id: request.signer_id.clone(),
                statuses,
                offset: request.page.offset(),
                limit: request.page.limit(),
            })
            .await?;
        approval_requests_page_from_wire(response, &request)
    }

    /// Open one finite signing approval request for the authenticated identity.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, policy, client, or reflected-response error.
    pub async fn create_code_signer_approval_request(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        creation: CodeSignerApprovalRequestCreation,
        confirm: bool,
    ) -> Result<CodeSignerApprovalRequest, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSignerGovernanceMutationNotConfirmed);
        }
        let policy = self
            .get_code_signer_approval_policy(project_id, signer_id)
            .await?;
        if !requested_limits_fit_policy(&creation, &policy, current_timestamp_millis()) {
            return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
        }
        let response = self
            .execute_mutation::<CreateSignerApprovalRequest>(&CreateApprovalRequestWire {
                signer_id: signer_id.clone(),
                justification: creation.justification.clone(),
                requested_signings: creation.requested_signings,
                requested_window_start: creation
                    .requested_window
                    .as_ref()
                    .and_then(|window| window.start.clone()),
                requested_window_end: creation
                    .requested_window
                    .as_ref()
                    .map(|window| window.end.clone()),
            })
            .await?;
        let request = approval_request_from_wire(response, project_id, signer_id, None)?;
        if request.status != CodeSignerApprovalRequestStatus::Pending
            || request.policy_id != policy.id
            || !request_matches_creation(&request, &creation)
        {
            return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
        }
        Ok(request)
    }

    /// Pre-approve finite signing authority for one exact user or machine-identity member.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, membership, policy, client, or reflected-response error.
    pub async fn pre_approve_code_signer_request(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        creation: CodeSignerPreApprovalCreation,
        confirm: bool,
    ) -> Result<CodeSignerPreApproval, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSignerGovernanceMutationNotConfirmed);
        }
        let policy = self
            .get_code_signer_approval_policy(project_id, signer_id)
            .await?;
        if !requested_limits_fit_policy(&creation.request, &policy, current_timestamp_millis()) {
            return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
        }
        let effective_kind = match creation.grantee_kind {
            CodeSignerOperationActorKind::User => CodeSignerEffectiveMemberKind::User,
            CodeSignerOperationActorKind::Identity => CodeSignerEffectiveMemberKind::Identity,
        };
        let is_grantable_member = self
            .list_code_signer_effective_members(project_id, signer_id, effective_kind)
            .await?
            .iter()
            .any(|member| {
                member.member_id == creation.grantee_id.as_str()
                    && member.role != CodeSignerRole::Auditor
            });
        if !is_grantable_member {
            return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
        }
        let (grantee_user_id, grantee_identity_id) = match creation.grantee_kind {
            CodeSignerOperationActorKind::User => {
                (Some(creation.grantee_id.as_str().to_owned()), None)
            }
            CodeSignerOperationActorKind::Identity => {
                (None, Some(creation.grantee_id.as_str().to_owned()))
            }
        };
        let response = self
            .execute_mutation::<PreApproveSignerRequest>(&PreApproveRequestWire {
                signer_id: signer_id.clone(),
                grantee_user_id,
                grantee_identity_id,
                justification: creation.request.justification.clone(),
                requested_signings: creation.request.requested_signings,
                requested_window_start: creation
                    .request
                    .requested_window
                    .as_ref()
                    .and_then(|window| window.start.clone()),
                requested_window_end: creation
                    .request
                    .requested_window
                    .as_ref()
                    .map(|window| window.end.clone()),
            })
            .await?;
        let request = approval_request_from_wire(response.request, project_id, signer_id, None)?;
        if request.status != CodeSignerApprovalRequestStatus::Approved
            || request.policy_id != policy.id
            || request.requester_kind != creation.grantee_kind
            || request.requester_id != creation.grantee_id.as_str()
            || !request_matches_creation(&request, &creation.request)
        {
            return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
        }
        let grant = approval_grant_from_wire(
            response.grant,
            project_id,
            signer_id,
            &request.id,
            &creation,
        )?;
        Ok(CodeSignerPreApproval { request, grant })
    }

    /// Revoke one pending or active signing approval request.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, client, or reflected-response error.
    pub async fn revoke_code_signer_approval_request(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        request_id: &CodeSignerApprovalRequestId,
        confirm: bool,
    ) -> Result<CodeSignerApprovalRequestRevocation, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSignerGovernanceMutationNotConfirmed);
        }
        self.get_code_signer(project_id, signer_id).await?;
        let response = self
            .execute_mutation::<RevokeSignerApprovalRequest>(&RevokeApprovalRequestWire {
                signer_id: signer_id.clone(),
                request_id: request_id.as_str().to_owned(),
            })
            .await?;
        if response.request_id != request_id.as_str() {
            return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
        }
        Ok(CodeSignerApprovalRequestRevocation {
            signer_id: signer_id.as_str().to_owned(),
            request_id: response.request_id,
        })
    }

    /// List one bounded page of sanitized signing-operation history.
    ///
    /// # Errors
    ///
    /// Returns a scope, pagination, client, or bounded response-contract error.
    pub async fn list_code_signer_signing_operations(
        &self,
        request: CodeSignerSigningOperationListRequest,
    ) -> Result<Page<CodeSignerSigningOperation>, ResourceError> {
        self.get_code_signer(&request.project_id, &request.signer_id)
            .await?;
        let response = self
            .execute_observable_read::<ListSignerSigningOperations>(&ListSigningOperationsQuery {
                signer_id: request.signer_id.clone(),
                offset: request.page.offset(),
                limit: request.page.limit(),
                status: request.status,
            })
            .await?;
        signing_operations_page_from_wire(response, &request)
    }

    /// Add one exact direct user, identity, or group membership.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, client, or reflected-response error.
    pub async fn add_code_signer_member(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        member_kind: CodeSignerMemberKind,
        member_id: &CodeSignerMemberId,
        role: CodeSignerRole,
        confirm: bool,
    ) -> Result<CodeSignerMembership, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSignerGovernanceMutationNotConfirmed);
        }
        self.get_code_signer(project_id, signer_id).await?;
        let membership = match member_kind {
            CodeSignerMemberKind::User => {
                let response = self
                    .execute_mutation::<AddSignerUserMember>(&AddUserMemberRequest {
                        signer_id: signer_id.clone(),
                        user_ids: vec![member_id.as_str().to_owned()],
                        emails: Vec::new(),
                        role,
                    })
                    .await?;
                if !response.skipped.is_empty()
                    || !response.unresolved.is_empty()
                    || response.memberships.len() != 1
                {
                    return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
                }
                membership_from_wire(
                    response
                        .memberships
                        .into_iter()
                        .next()
                        .ok_or(ResourceError::InvalidCodeSignerGovernanceResponse)?,
                    signer_id,
                    member_kind,
                    Some(member_id),
                )?
            }
            CodeSignerMemberKind::Identity => {
                let response = self
                    .execute_mutation::<AddSignerIdentityMember>(&AddIdentityMemberRequest {
                        signer_id: signer_id.clone(),
                        identity_id: member_id.as_str().to_owned(),
                        role,
                    })
                    .await?;
                membership_from_wire(response, signer_id, member_kind, Some(member_id))?
            }
            CodeSignerMemberKind::Group => {
                let response = self
                    .execute_mutation::<AddSignerGroupMember>(&AddGroupMemberRequest {
                        signer_id: signer_id.clone(),
                        group_id: member_id.as_str().to_owned(),
                        role,
                    })
                    .await?;
                membership_from_wire(response, signer_id, member_kind, Some(member_id))?
            }
        };
        if membership.role != role {
            return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
        }
        Ok(membership)
    }

    /// Replace one exact direct member's built-in signer role.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, state, client, or reflected-response error.
    pub async fn update_code_signer_member_role(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        member_kind: CodeSignerMemberKind,
        member_id: &CodeSignerMemberId,
        role: CodeSignerRole,
        confirm: bool,
    ) -> Result<CodeSignerMembership, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSignerGovernanceMutationNotConfirmed);
        }
        let existing = self
            .list_code_signer_members(project_id, signer_id, member_kind)
            .await?
            .into_iter()
            .find(|membership| membership.member_id == member_id.as_str())
            .ok_or(ResourceError::InvalidCodeSignerGovernanceResponse)?;
        if existing.role == role {
            return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
        }
        let response = self
            .execute_mutation::<UpdateSignerMemberRole>(&UpdateMemberRoleRequest {
                signer_id: signer_id.clone(),
                member_kind,
                member_id: member_id.clone(),
                role,
            })
            .await?;
        let membership =
            membership_from_wire(response.membership, signer_id, member_kind, Some(member_id))?;
        if membership.membership_id != existing.membership_id || membership.role != role {
            return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
        }
        Ok(membership)
    }

    /// Remove one exact direct signer member.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, client, or reflected-response error.
    pub async fn remove_code_signer_member(
        &self,
        project_id: &CertificateAuthorityProjectId,
        signer_id: &CodeSignerId,
        member_kind: CodeSignerMemberKind,
        member_id: &CodeSignerMemberId,
        confirm: bool,
    ) -> Result<CodeSignerMembershipMutationReceipt, ResourceError> {
        if !confirm {
            return Err(ResourceError::CodeSignerGovernanceMutationNotConfirmed);
        }
        let existing = self
            .list_code_signer_members(project_id, signer_id, member_kind)
            .await?
            .into_iter()
            .find(|membership| membership.member_id == member_id.as_str())
            .ok_or(ResourceError::InvalidCodeSignerGovernanceResponse)?;
        let response = self
            .execute_mutation::<RemoveSignerMember>(&RemoveMemberRequest {
                signer_id: signer_id.clone(),
                member_kind,
                member_id: member_id.clone(),
            })
            .await?;
        if response.membership_id != existing.membership_id
            || response.signer_id != signer_id.as_str()
        {
            return Err(ResourceError::InvalidCodeSignerGovernanceResponse);
        }
        Ok(CodeSignerMembershipMutationReceipt {
            membership_id: response.membership_id,
            signer_id: response.signer_id,
            member_kind,
            member_id: member_id.as_str().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path, query_param},
    };

    use super::*;
    use crate::test_support::{mount_login, settings};

    const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const SIGNER_ID: &str = "22222222-2222-4222-8222-222222222222";
    const MEMBER_ID: &str = "33333333-3333-4333-8333-333333333333";
    const MEMBERSHIP_ID: &str = "44444444-4444-4444-8444-444444444444";
    const CERTIFICATE_ID: &str = "55555555-5555-4555-8555-555555555555";
    const POLICY_ID: &str = "66666666-6666-4666-8666-666666666666";
    const REQUEST_ID: &str = "77777777-7777-4777-8777-777777777777";
    const OPERATION_ID: &str = "88888888-8888-4888-8888-888888888888";
    const OTHER_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const CREATED_AT: &str = "2026-07-20T12:00:00.000Z";
    const NOT_AFTER: &str = "2036-07-20T12:00:00.000Z";

    fn project_id() -> CertificateAuthorityProjectId {
        CertificateAuthorityProjectId::new(PROJECT_ID).unwrap()
    }

    fn signer_id() -> CodeSignerId {
        CodeSignerId::new(SIGNER_ID).unwrap()
    }

    fn member_id() -> CodeSignerMemberId {
        CodeSignerMemberId::new(MEMBER_ID).unwrap()
    }

    fn signer_value() -> Value {
        json!({
            "id": SIGNER_ID,
            "projectId": PROJECT_ID,
            "name": "release-signer",
            "description": null,
            "status": "active",
            "certificateId": CERTIFICATE_ID,
            "approvalPolicyId": POLICY_ID,
            "lastSignedAt": null,
            "createdAt": CREATED_AT,
            "updatedAt": CREATED_AT,
            "caId": null,
            "commonName": null,
            "certificateTtlDays": null,
            "certificateRenewBeforeDays": null,
            "certificateFailureReason": null,
            "keyAlgorithm": "RSA_2048",
            "certificateCommonName": "release.example.test",
            "certificateSerialNumber": "53D112612118759DA8F4154E67C467098521A0C5",
            "certificateNotBefore": CREATED_AT,
            "certificateNotAfter": NOT_AFTER,
            "certificateKeyAlgorithm": "RSA_2048",
            "certificateStatus": "active",
            "certificateCaId": null,
            "approvalPolicyName": "release approvals"
        })
    }

    fn member_value(kind: CodeSignerMemberKind, role: &str) -> Value {
        let (user_id, identity_id, group_id) = match kind {
            CodeSignerMemberKind::User => (Some(MEMBER_ID), None, None),
            CodeSignerMemberKind::Identity => (None, Some(MEMBER_ID), None),
            CodeSignerMemberKind::Group => (None, None, Some(MEMBER_ID)),
        };
        json!({
            "membershipId": MEMBERSHIP_ID,
            "signerId": SIGNER_ID,
            "actorUserId": user_id,
            "actorIdentityId": identity_id,
            "actorGroupId": group_id,
            "role": role,
            "customRoleId": null,
            "createdAt": CREATED_AT,
            "updatedAt": CREATED_AT,
            "details": {
                "name": "Release operator",
                "email": "release@example.test",
                "username": null,
                "authMethod": null,
                "slug": null
            }
        })
    }

    fn approval_request_value(status: &str) -> Value {
        json!({
            "id": REQUEST_ID,
            "projectId": PROJECT_ID,
            "organizationId": "99999999-9999-4999-8999-999999999999",
            "policyId": POLICY_ID,
            "requesterId": null,
            "requesterName": "release-identity",
            "requesterEmail": "",
            "type": "cert-code-signing",
            "status": status,
            "justification": "Publish the verified release",
            "currentStep": 1,
            "requestData": {
                "version": 1,
                "requestData": {
                    "signerId": SIGNER_ID,
                    "signerName": "release-signer",
                    "approvalPolicyId": POLICY_ID,
                    "justification": "Publish the verified release",
                    "requestedSignings": 2,
                    "requestedWindowStart": CREATED_AT,
                    "requestedWindowEnd": "2026-07-20T13:00:00.000Z"
                }
            },
            "expiresAt": null,
            "createdAt": CREATED_AT,
            "updatedAt": CREATED_AT,
            "machineIdentityId": MEMBER_ID,
            "scopeType": "pki-signer",
            "scopeId": SIGNER_ID,
            "maxSignings": null,
            "usedSignings": 0,
            "grantStatus": null
        })
    }

    fn policy_value() -> Value {
        json!({
            "id": POLICY_ID,
            "signerId": SIGNER_ID,
            "hasSteps": true,
            "steps": [{
                "name": "Release approval",
                "requiredApprovals": 1,
                "approvers": [{ "type": "user", "id": MEMBER_ID }],
                "notifyApprovers": false
            }],
            "constraints": {
                "maxSignings": 2,
                "maxWindowDuration": "1h"
            }
        })
    }

    fn grant_value() -> Value {
        json!({
            "id": OPERATION_ID,
            "projectId": PROJECT_ID,
            "requestId": REQUEST_ID,
            "granteeUserId": null,
            "granteeMachineIdentityId": MEMBER_ID,
            "status": "active",
            "type": "cert-code-signing",
            "attributes": {
                "signerId": SIGNER_ID,
                "signerName": "release-signer",
                "maxSignings": 2,
                "windowStart": CREATED_AT
            },
            "expiresAt": "2026-07-20T13:00:00.000Z",
            "isBreakGlass": false
        })
    }

    fn operation_value(id: &str) -> Value {
        json!({
            "id": id,
            "signerId": SIGNER_ID,
            "projectId": PROJECT_ID,
            "status": "success",
            "signingAlgorithm": "RSASSA_PSS_SHA_256",
            "dataHash": "a".repeat(64),
            "actorType": "identity",
            "actorId": MEMBER_ID,
            "actorName": "release-identity",
            "actorMembershipId": MEMBERSHIP_ID,
            "approvalGrantId": OPERATION_ID,
            "createdAt": CREATED_AT
        })
    }

    fn indexed_uuid(index: usize) -> String {
        format!("00000000-0000-4000-8000-{index:012x}")
    }

    async fn mount_signer(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/cert-manager/signers/{SIGNER_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(signer_value()))
            .mount(server)
            .await;
    }

    async fn mount_policy(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/approval-policy"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy_value()))
            .mount(server)
            .await;
    }

    async fn mount_memberships(
        server: &MockServer,
        member_kind: CodeSignerMemberKind,
        memberships: Vec<Value>,
    ) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/{}",
                member_kind.path_segment()
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "memberships": memberships
            })))
            .mount(server)
            .await;
    }

    async fn mount_effective_identities(server: &MockServer, members: Vec<Value>) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/effective-identities"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "members": members
            })))
            .mount(server)
            .await;
    }

    fn effective_identity_value(id: &str, role: &str) -> Value {
        json!({
            "actorUserId": null,
            "actorIdentityId": id,
            "role": role,
            "viaGroupIds": [],
            "isDirect": true,
            "details": null
        })
    }

    fn approval_creation() -> CodeSignerApprovalRequestCreation {
        CodeSignerApprovalRequestCreation::new(
            "Publish the verified release".to_owned(),
            Some(2),
            Some(CodeSignerApprovalRequestWindow {
                start: Some(CREATED_AT.to_owned()),
                end: "2026-07-20T13:00:00.000Z".to_owned(),
            }),
        )
        .unwrap()
    }

    fn pre_approval_creation() -> CodeSignerPreApprovalCreation {
        CodeSignerPreApprovalCreation::new(
            CodeSignerOperationActorKind::Identity,
            member_id(),
            approval_creation(),
        )
    }

    fn replacement_policy() -> CodeSignerApprovalPolicyReplacement {
        CodeSignerApprovalPolicyReplacement::new(
            vec![
                CodeSignerApprovalPolicyStepChange::new(
                    1,
                    Some("Release approval".to_owned()),
                    1,
                    vec![member_id()],
                    Vec::new(),
                )
                .unwrap(),
            ],
            CodeSignerApprovalPolicyConstraints {
                max_signings: Some(1),
                max_window_duration: Some("1h".to_owned()),
            },
        )
        .unwrap()
    }

    #[test]
    fn member_details_validate_each_field_and_preserve_valid_content() {
        assert!(valid_optional_detail(None));
        assert!(valid_optional_detail(Some("")));
        assert!(valid_optional_detail(Some(
            &"a".repeat(MAX_MEMBER_DETAIL_BYTES)
        )));
        assert!(!valid_optional_detail(Some(
            &"a".repeat(MAX_MEMBER_DETAIL_BYTES + 1)
        )));
        assert!(!valid_optional_detail(Some(" padded ")));
        assert!(!valid_optional_detail(Some("control\n")));

        let value = json!({
            "name": "Release operator",
            "email": "release@example.test",
            "username": "release",
            "authMethod": "universal-auth",
            "slug": "release-operators"
        });
        let details: MemberDetailsWire = serde_json::from_value(value.clone()).unwrap();
        let parsed = details_from_wire(Some(details)).unwrap().unwrap();
        assert_eq!(parsed.name.as_deref(), Some("Release operator"));
        assert_eq!(parsed.email.as_deref(), Some("release@example.test"));
        assert_eq!(parsed.username.as_deref(), Some("release"));
        assert_eq!(parsed.auth_method.as_deref(), Some("universal-auth"));
        assert_eq!(parsed.slug.as_deref(), Some("release-operators"));
        assert!(details_from_wire(None).unwrap().is_none());

        for field in ["name", "email", "username", "authMethod", "slug"] {
            let mut invalid = value.clone();
            invalid[field] = json!(" padded ");
            let invalid: MemberDetailsWire = serde_json::from_value(invalid).unwrap();
            assert_eq!(
                details_from_wire(Some(invalid)).unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse,
                "{field}"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn membership_parsers_validate_each_field_cardinality_and_uniqueness() {
        let valid: MembershipWire =
            serde_json::from_value(member_value(CodeSignerMemberKind::User, "operator")).unwrap();
        let parsed = membership_from_wire(
            valid,
            &signer_id(),
            CodeSignerMemberKind::User,
            Some(&member_id()),
        )
        .unwrap();
        assert_eq!(parsed.membership_id, MEMBERSHIP_ID);
        assert_eq!(parsed.member_id, MEMBER_ID);
        assert!(parsed.details.is_some());

        let mut cases = Vec::new();
        for (pointer, replacement) in [
            ("/membershipId", json!("not-a-uuid")),
            ("/signerId", json!(OTHER_ID)),
            ("/customRoleId", json!(OTHER_ID)),
            ("/createdAt", json!("not-a-timestamp")),
            ("/updatedAt", json!("not-a-timestamp")),
            ("/actorUserId", json!("not-a-uuid")),
        ] {
            let mut value = member_value(CodeSignerMemberKind::User, "operator");
            *value.pointer_mut(pointer).unwrap() = replacement;
            cases.push(value);
        }
        let mut no_actor = member_value(CodeSignerMemberKind::User, "operator");
        no_actor["actorUserId"] = Value::Null;
        cases.push(no_actor);
        let mut two_actors = member_value(CodeSignerMemberKind::User, "operator");
        two_actors["actorIdentityId"] = json!(OTHER_ID);
        cases.push(two_actors);
        let wrong_kind = member_value(CodeSignerMemberKind::Identity, "operator");
        cases.push(wrong_kind);
        for (index, value) in cases.into_iter().enumerate() {
            let wire: MembershipWire = serde_json::from_value(value).unwrap();
            assert_eq!(
                membership_from_wire(
                    wire,
                    &signer_id(),
                    CodeSignerMemberKind::User,
                    Some(&member_id()),
                )
                .unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse,
                "case {index}"
            );
        }
        let valid: MembershipWire =
            serde_json::from_value(member_value(CodeSignerMemberKind::User, "operator")).unwrap();
        let other_member = CodeSignerMemberId::new(OTHER_ID).unwrap();
        assert_eq!(
            membership_from_wire(
                valid,
                &signer_id(),
                CodeSignerMemberKind::User,
                Some(&other_member),
            )
            .unwrap_err(),
            ResourceError::InvalidCodeSignerGovernanceResponse
        );

        let memberships = (0..MAX_GOVERNANCE_ITEMS)
            .map(|index| {
                let mut value = member_value(CodeSignerMemberKind::User, "operator");
                value["membershipId"] = json!(indexed_uuid(index));
                value["actorUserId"] = json!(indexed_uuid(index + 1_000));
                serde_json::from_value(value).unwrap()
            })
            .collect();
        let parsed = memberships_from_wire(
            MembershipsWire { memberships },
            &signer_id(),
            CodeSignerMemberKind::User,
        )
        .unwrap();
        assert_eq!(parsed.len(), MAX_GOVERNANCE_ITEMS);
        let memberships = (0..=MAX_GOVERNANCE_ITEMS)
            .map(|index| {
                let mut value = member_value(CodeSignerMemberKind::User, "operator");
                value["membershipId"] = json!(indexed_uuid(index));
                value["actorUserId"] = json!(indexed_uuid(index + 1_000));
                serde_json::from_value(value).unwrap()
            })
            .collect();
        assert_eq!(
            memberships_from_wire(
                MembershipsWire { memberships },
                &signer_id(),
                CodeSignerMemberKind::User,
            )
            .unwrap_err(),
            ResourceError::InvalidCodeSignerGovernanceResponse
        );
        let duplicate: MembershipWire =
            serde_json::from_value(member_value(CodeSignerMemberKind::User, "operator")).unwrap();
        let duplicate_again: MembershipWire =
            serde_json::from_value(member_value(CodeSignerMemberKind::User, "admin")).unwrap();
        assert_eq!(
            memberships_from_wire(
                MembershipsWire {
                    memberships: vec![duplicate, duplicate_again],
                },
                &signer_id(),
                CodeSignerMemberKind::User,
            )
            .unwrap_err(),
            ResourceError::InvalidCodeSignerGovernanceResponse
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn effective_members_validate_each_field_cardinality_and_uniqueness() {
        let effective_value = |id: &str| {
            json!({
                "actorUserId": null,
                "actorIdentityId": id,
                "role": "operator",
                "viaGroupIds": [OTHER_ID],
                "isDirect": false,
                "details": null
            })
        };
        let valid: EffectiveMembersWire = serde_json::from_value(json!({
            "members": [effective_value(MEMBER_ID)]
        }))
        .unwrap();
        let parsed =
            effective_members_from_wire(valid, CodeSignerEffectiveMemberKind::Identity).unwrap();
        assert_eq!(parsed[0].member_id, MEMBER_ID);
        assert_eq!(parsed[0].via_group_ids, [OTHER_ID]);
        let mut exact_groups = effective_value(MEMBER_ID);
        exact_groups["viaGroupIds"] = json!(
            (0..MAX_GOVERNANCE_ITEMS)
                .map(indexed_uuid)
                .collect::<Vec<_>>()
        );
        let response: EffectiveMembersWire =
            serde_json::from_value(json!({ "members": [exact_groups] })).unwrap();
        assert_eq!(
            effective_members_from_wire(response, CodeSignerEffectiveMemberKind::Identity).unwrap()
                [0]
            .via_group_ids
            .len(),
            MAX_GOVERNANCE_ITEMS
        );

        let mut cases = Vec::new();
        let mut no_actor = effective_value(MEMBER_ID);
        no_actor["actorIdentityId"] = Value::Null;
        cases.push(no_actor);
        let mut two_actors = effective_value(MEMBER_ID);
        two_actors["actorUserId"] = json!(OTHER_ID);
        cases.push(two_actors);
        cases.push(json!({
            "actorUserId": MEMBER_ID,
            "actorIdentityId": null,
            "role": "operator",
            "viaGroupIds": [],
            "isDirect": true,
            "details": null
        }));
        let mut invalid_actor = effective_value(MEMBER_ID);
        invalid_actor["actorIdentityId"] = json!("not-a-uuid");
        cases.push(invalid_actor);
        let mut invalid_group = effective_value(MEMBER_ID);
        invalid_group["viaGroupIds"] = json!(["not-a-uuid"]);
        cases.push(invalid_group);
        let mut too_many_groups = effective_value(MEMBER_ID);
        too_many_groups["viaGroupIds"] = json!(
            (0..=MAX_GOVERNANCE_ITEMS)
                .map(indexed_uuid)
                .collect::<Vec<_>>()
        );
        cases.push(too_many_groups);
        for (index, value) in cases.into_iter().enumerate() {
            let response: EffectiveMembersWire =
                serde_json::from_value(json!({ "members": [value] })).unwrap();
            assert_eq!(
                effective_members_from_wire(response, CodeSignerEffectiveMemberKind::Identity)
                    .unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse,
                "case {index}"
            );
        }
        let members = (0..MAX_GOVERNANCE_ITEMS)
            .map(|index| serde_json::from_value(effective_value(&indexed_uuid(index))).unwrap())
            .collect();
        assert_eq!(
            effective_members_from_wire(
                EffectiveMembersWire { members },
                CodeSignerEffectiveMemberKind::Identity,
            )
            .unwrap()
            .len(),
            MAX_GOVERNANCE_ITEMS
        );
        let members = (0..=MAX_GOVERNANCE_ITEMS)
            .map(|index| serde_json::from_value(effective_value(&indexed_uuid(index))).unwrap())
            .collect();
        assert_eq!(
            effective_members_from_wire(
                EffectiveMembersWire { members },
                CodeSignerEffectiveMemberKind::Identity,
            )
            .unwrap_err(),
            ResourceError::InvalidCodeSignerGovernanceResponse
        );
        let duplicate: EffectiveMemberWire =
            serde_json::from_value(effective_value(MEMBER_ID)).unwrap();
        let duplicate_again: EffectiveMemberWire =
            serde_json::from_value(effective_value(MEMBER_ID)).unwrap();
        assert_eq!(
            effective_members_from_wire(
                EffectiveMembersWire {
                    members: vec![duplicate, duplicate_again],
                },
                CodeSignerEffectiveMemberKind::Identity,
            )
            .unwrap_err(),
            ResourceError::InvalidCodeSignerGovernanceResponse
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn packed_permissions_are_strict_bounded_and_condition_safe() {
        assert!(valid_permission_value("read:*_scope.value"));
        assert!(valid_permission_value(
            &"a".repeat(MAX_PERMISSION_VALUE_BYTES)
        ));
        assert!(!valid_permission_value(""));
        assert!(!valid_permission_value(
            &"a".repeat(MAX_PERMISSION_VALUE_BYTES + 1)
        ));
        assert!(!valid_permission_value("read/write"));
        assert_eq!(
            split_permission_values(
                &(0..MAX_PERMISSION_VALUES)
                    .map(|index| format!("value{index}"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
            .unwrap()
            .len(),
            MAX_PERMISSION_VALUES
        );
        assert_eq!(
            split_permission_values(
                &(0..=MAX_PERMISSION_VALUES)
                    .map(|index| format!("value{index}"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
            .unwrap_err(),
            ResourceError::InvalidCodeSignerGovernanceResponse
        );
        for invalid in ["read,", "read,write/value", "read, padded"] {
            assert_eq!(
                split_permission_values(invalid).unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse,
                "{invalid}"
            );
        }

        let rule = permission_rule_from_wire(json!([
            "read,sign",
            "signer",
            {"projectId": PROJECT_ID},
            0,
            "name,status",
            "bounded role"
        ]))
        .unwrap();

        assert_eq!(rule.actions, ["read", "sign"]);
        assert_eq!(rule.subjects, ["signer"]);
        assert!(rule.conditional);
        assert!(!rule.inverted);
        assert_eq!(rule.fields, ["name", "status"]);
        assert_eq!(rule.reason.as_deref(), Some("bounded role"));
        let minimal = permission_rule_from_wire(json!(["read", "signer"])).unwrap();
        assert!(!minimal.conditional);
        assert!(!minimal.inverted);
        assert!(minimal.fields.is_empty());
        assert!(minimal.reason.is_none());
        let inverted = permission_rule_from_wire(json!(["read", "signer", 0, 1, 0])).unwrap();
        assert!(inverted.inverted);
        assert!(!inverted.conditional);
        assert!(inverted.fields.is_empty());
        assert_eq!(
            permission_rule_from_wire(json!(["read", "signer", "raw-condition"])).unwrap_err(),
            ResourceError::InvalidCodeSignerGovernanceResponse
        );
        for invalid in [
            json!(["read", "signer", 0, 2]),
            json!(["read", "signer", 0, -1]),
            json!(["read", "signer", 0, "0"]),
            json!(["read", "signer", 0, 0, 1]),
            json!(["read", "signer", 0, 0, {}]),
            json!(["read", "signer", 0, 0, 0, " padded "]),
            json!([
                "read",
                "signer",
                0,
                0,
                0,
                "a".repeat(MAX_PERMISSION_REASON_BYTES + 1)
            ]),
        ] {
            assert_eq!(
                permission_rule_from_wire(invalid).unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse
            );
        }

        let membership = |id: &str| {
            json!({
                "id": id,
                "actorUserId": null,
                "actorIdentityId": MEMBER_ID,
                "actorGroupId": null,
                "roles": [{ "role": "operator", "customRoleSlug": null }]
            })
        };
        let response: PermissionsWire = serde_json::from_value(json!({
            "data": {
                "permissions": [["read", "signer"]],
                "memberships": [membership(MEMBERSHIP_ID)]
            }
        }))
        .unwrap();
        let parsed = permissions_from_wire(response, &signer_id()).unwrap();
        assert_eq!(parsed.signer_id, SIGNER_ID);
        assert_eq!(parsed.rules.len(), 1);
        assert_eq!(parsed.memberships.len(), 1);

        let mut exact_roles = membership(MEMBERSHIP_ID);
        exact_roles["roles"] = json!(
            (0..MAX_PERMISSION_VALUES)
                .map(|_| json!({ "role": "operator", "customRoleSlug": null }))
                .collect::<Vec<_>>()
        );
        let wire: PermissionMembershipWire = serde_json::from_value(exact_roles).unwrap();
        assert_eq!(
            permission_membership_from_wire(wire).unwrap().roles.len(),
            MAX_PERMISSION_VALUES
        );

        let mut membership_cases = Vec::new();
        let mut invalid_id = membership(MEMBERSHIP_ID);
        invalid_id["id"] = json!("not-a-uuid");
        membership_cases.push(invalid_id);
        let mut no_actor = membership(MEMBERSHIP_ID);
        no_actor["actorIdentityId"] = Value::Null;
        membership_cases.push(no_actor);
        let mut two_actors = membership(MEMBERSHIP_ID);
        two_actors["actorUserId"] = json!(OTHER_ID);
        membership_cases.push(two_actors);
        let mut invalid_actor = membership(MEMBERSHIP_ID);
        invalid_actor["actorIdentityId"] = json!("not-a-uuid");
        membership_cases.push(invalid_actor);
        let mut no_roles = membership(MEMBERSHIP_ID);
        no_roles["roles"] = json!([]);
        membership_cases.push(no_roles);
        let mut too_many_roles = membership(MEMBERSHIP_ID);
        too_many_roles["roles"] = json!(
            (0..=MAX_PERMISSION_VALUES)
                .map(|_| json!({ "role": "operator", "customRoleSlug": null }))
                .collect::<Vec<_>>()
        );
        membership_cases.push(too_many_roles);
        let mut custom_role = membership(MEMBERSHIP_ID);
        custom_role["roles"][0]["customRoleSlug"] = json!("custom");
        membership_cases.push(custom_role);
        for value in membership_cases {
            let wire: PermissionMembershipWire = serde_json::from_value(value).unwrap();
            assert_eq!(
                permission_membership_from_wire(wire).unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse
            );
        }

        let permissions = (0..MAX_PERMISSION_RULES)
            .map(|_| json!(["read", "signer"]))
            .collect::<Vec<_>>();
        let response: PermissionsWire = serde_json::from_value(json!({
            "data": { "permissions": permissions, "memberships": [] }
        }))
        .unwrap();
        assert_eq!(
            permissions_from_wire(response, &signer_id())
                .unwrap()
                .rules
                .len(),
            MAX_PERMISSION_RULES
        );
        let permissions = (0..=MAX_PERMISSION_RULES)
            .map(|_| json!(["read", "signer"]))
            .collect::<Vec<_>>();
        let response: PermissionsWire = serde_json::from_value(json!({
            "data": { "permissions": permissions, "memberships": [] }
        }))
        .unwrap();
        assert_eq!(
            permissions_from_wire(response, &signer_id()).unwrap_err(),
            ResourceError::InvalidCodeSignerGovernanceResponse
        );
        let memberships = (0..MAX_GOVERNANCE_ITEMS)
            .map(|index| membership(&indexed_uuid(index)))
            .collect::<Vec<_>>();
        let response: PermissionsWire = serde_json::from_value(json!({
            "data": { "permissions": [], "memberships": memberships }
        }))
        .unwrap();
        assert_eq!(
            permissions_from_wire(response, &signer_id())
                .unwrap()
                .memberships
                .len(),
            MAX_GOVERNANCE_ITEMS
        );
        let memberships = (0..=MAX_GOVERNANCE_ITEMS)
            .map(|index| membership(&indexed_uuid(index)))
            .collect::<Vec<_>>();
        let response: PermissionsWire = serde_json::from_value(json!({
            "data": { "permissions": [], "memberships": memberships }
        }))
        .unwrap();
        assert_eq!(
            permissions_from_wire(response, &signer_id()).unwrap_err(),
            ResourceError::InvalidCodeSignerGovernanceResponse
        );
    }

    #[test]
    fn policy_and_request_inputs_require_finite_coherent_authority() {
        let step = CodeSignerApprovalPolicyStepChange::new(
            1,
            Some("Release approval".to_owned()),
            1,
            vec![member_id()],
            Vec::new(),
        )
        .unwrap();
        assert!(
            CodeSignerApprovalPolicyReplacement::new(
                vec![step.clone()],
                CodeSignerApprovalPolicyConstraints {
                    max_signings: Some(2),
                    max_window_duration: Some("1h".to_owned()),
                }
            )
            .is_ok()
        );
        assert!(
            CodeSignerApprovalPolicyReplacement::new(
                vec![step],
                CodeSignerApprovalPolicyConstraints {
                    max_signings: None,
                    max_window_duration: None,
                }
            )
            .is_err()
        );
        assert!(
            CodeSignerApprovalRequestCreation::new(
                "Publish the verified release".to_owned(),
                Some(2),
                Some(CodeSignerApprovalRequestWindow {
                    start: Some(CREATED_AT.to_owned()),
                    end: "2026-07-20T13:00:00.000Z".to_owned(),
                })
            )
            .is_ok()
        );
        assert!(
            CodeSignerApprovalRequestCreation::new(
                "Publish the verified release".to_owned(),
                None,
                None
            )
            .is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn approval_policy_parser_validates_each_field_and_exact_boundaries() {
        for valid in ["1ms", "1s", "1m", "1h", "1d", "1w", "999999999999w"] {
            assert!(valid_policy_duration(valid), "{valid}");
        }
        assert!(valid_policy_duration(&format!(
            "1{}s",
            "0".repeat(MAX_POLICY_DURATION_BYTES - 2)
        )));
        for invalid in ["", "0s", "01s", "1y", "1 h", " 1h", "1h ", "1\nh"] {
            assert!(!valid_policy_duration(invalid), "{invalid:?}");
        }
        assert!(!valid_policy_duration(&format!(
            "1{}s",
            "0".repeat(MAX_POLICY_DURATION_BYTES)
        )));

        let wire: PolicyWire = serde_json::from_value(policy_value()).unwrap();
        let policy = policy_from_wire(wire, &signer_id()).unwrap();
        assert_eq!(policy.id, POLICY_ID);
        assert_eq!(policy.signer_id, SIGNER_ID);
        assert_eq!(policy.steps.len(), 1);
        assert_eq!(policy.steps[0].step_number, 1);
        assert_eq!(policy.steps[0].required_approvals, 1);
        assert_eq!(policy.constraints.max_signings, Some(2));

        let mut top_level_cases = Vec::new();
        for (pointer, replacement) in [
            ("/id", json!("not-a-uuid")),
            ("/signerId", json!(OTHER_ID)),
            ("/hasSteps", json!(false)),
            ("/constraints/maxSignings", json!(0)),
            ("/constraints/maxSignings", json!(MAX_POLICY_SIGNINGS + 1)),
            ("/constraints/maxWindowDuration", json!("0h")),
        ] {
            let mut value = policy_value();
            *value.pointer_mut(pointer).unwrap() = replacement;
            top_level_cases.push(value);
        }
        let mut no_limits = policy_value();
        no_limits["constraints"]["maxSignings"] = Value::Null;
        no_limits["constraints"]["maxWindowDuration"] = Value::Null;
        top_level_cases.push(no_limits);
        let mut too_many_steps = policy_value();
        too_many_steps["steps"] = json!(
            (0..=MAX_POLICY_STEPS)
                .map(|_| policy_value()["steps"][0].clone())
                .collect::<Vec<_>>()
        );
        top_level_cases.push(too_many_steps);
        let mut empty_inconsistent = policy_value();
        empty_inconsistent["steps"] = json!([]);
        top_level_cases.push(empty_inconsistent);
        for (index, value) in top_level_cases.into_iter().enumerate() {
            let wire: PolicyWire = serde_json::from_value(value).unwrap();
            assert_eq!(
                policy_from_wire(wire, &signer_id()).unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse,
                "top-level case {index}"
            );
        }

        let mut exact_max = policy_value();
        exact_max["constraints"]["maxSignings"] = json!(MAX_POLICY_SIGNINGS);
        let wire: PolicyWire = serde_json::from_value(exact_max).unwrap();
        assert!(policy_from_wire(wire, &signer_id()).is_ok());
        for missing_constraint in ["maxSignings", "maxWindowDuration"] {
            let mut one_limit = policy_value();
            one_limit["constraints"][missing_constraint] = Value::Null;
            let wire: PolicyWire = serde_json::from_value(one_limit).unwrap();
            assert!(
                policy_from_wire(wire, &signer_id()).is_ok(),
                "one finite limit remains when {missing_constraint} is absent"
            );
        }
        let mut exact_steps = policy_value();
        exact_steps["steps"] = json!(
            (0..MAX_POLICY_STEPS)
                .map(|_| policy_value()["steps"][0].clone())
                .collect::<Vec<_>>()
        );
        let wire: PolicyWire = serde_json::from_value(exact_steps).unwrap();
        assert_eq!(
            policy_from_wire(wire, &signer_id()).unwrap().steps.len(),
            16
        );

        let mut step_cases = Vec::new();
        for (pointer, replacement) in [
            ("/steps/0/requiredApprovals", json!(0)),
            ("/steps/0/name", json!("")),
            ("/steps/0/name", json!(" padded ")),
            ("/steps/0/name", json!("control\n")),
            (
                "/steps/0/name",
                json!("a".repeat(MAX_POLICY_STEP_NAME_BYTES + 1)),
            ),
            ("/steps/0/approvers/0/id", json!("not-a-uuid")),
        ] {
            let mut value = policy_value();
            *value.pointer_mut(pointer).unwrap() = replacement;
            step_cases.push(value);
        }
        let mut no_approvers = policy_value();
        no_approvers["steps"][0]["approvers"] = json!([]);
        step_cases.push(no_approvers);
        let mut duplicate_approver = policy_value();
        duplicate_approver["steps"][0]["approvers"] = json!([
            { "type": "user", "id": MEMBER_ID },
            { "type": "user", "id": MEMBER_ID }
        ]);
        step_cases.push(duplicate_approver);
        let mut too_many_approvers = policy_value();
        too_many_approvers["steps"][0]["approvers"] = json!(
            (0..=MAX_POLICY_APPROVERS)
                .map(|index| json!({ "type": "user", "id": indexed_uuid(index) }))
                .collect::<Vec<_>>()
        );
        step_cases.push(too_many_approvers);
        let mut threshold_too_high = policy_value();
        threshold_too_high["steps"][0]["requiredApprovals"] = json!(2);
        step_cases.push(threshold_too_high);
        for (index, value) in step_cases.into_iter().enumerate() {
            let wire: PolicyWire = serde_json::from_value(value).unwrap();
            assert_eq!(
                policy_from_wire(wire, &signer_id()).unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse,
                "step case {index}"
            );
        }
        let mut max_approvers = policy_value();
        max_approvers["steps"][0]["approvers"] = json!(
            (0..MAX_POLICY_APPROVERS)
                .map(|index| json!({ "type": "user", "id": indexed_uuid(index) }))
                .collect::<Vec<_>>()
        );
        let wire: PolicyWire = serde_json::from_value(max_approvers).unwrap();
        assert!(policy_from_wire(wire, &signer_id()).is_ok());
        let mut max_name = policy_value();
        max_name["steps"][0]["name"] = json!("a".repeat(MAX_POLICY_STEP_NAME_BYTES));
        let wire: PolicyWire = serde_json::from_value(max_name).unwrap();
        assert!(policy_from_wire(wire, &signer_id()).is_ok());
        let mut group_threshold = policy_value();
        group_threshold["steps"][0]["requiredApprovals"] = json!(2);
        group_threshold["steps"][0]["approvers"][0]["type"] = json!("group");
        let wire: PolicyWire = serde_json::from_value(group_threshold).unwrap();
        assert!(policy_from_wire(wire, &signer_id()).is_ok());
    }

    #[test]
    fn policy_reflection_and_approver_membership_are_exact() {
        let step = CodeSignerApprovalPolicyStepChange::new(
            1,
            Some("Release approval".to_owned()),
            1,
            vec![member_id()],
            Vec::new(),
        )
        .unwrap();
        let replacement = CodeSignerApprovalPolicyReplacement::new(
            vec![step],
            CodeSignerApprovalPolicyConstraints {
                max_signings: Some(2),
                max_window_duration: Some("1h".to_owned()),
            },
        )
        .unwrap();
        let wire: PolicyWire = serde_json::from_value(policy_value()).unwrap();
        let policy = policy_from_wire(wire, &signer_id()).unwrap();
        assert!(policy_matches_replacement(&policy, &replacement));

        let mut mismatches = Vec::new();
        let mut mismatch = policy.clone();
        mismatch.constraints.max_signings = Some(1);
        mismatches.push(mismatch);
        let mut mismatch = policy.clone();
        mismatch.steps[0].step_number = 2;
        mismatches.push(mismatch);
        let mut mismatch = policy.clone();
        mismatch.steps[0].name = Some("Other".to_owned());
        mismatches.push(mismatch);
        let mut mismatch = policy.clone();
        mismatch.steps[0].required_approvals = 2;
        mismatches.push(mismatch);
        let mut mismatch = policy.clone();
        mismatch.steps[0].notify_approvers = true;
        mismatches.push(mismatch);
        let mut mismatch = policy.clone();
        mismatch.steps[0].approvers[0].id = OTHER_ID.to_owned();
        mismatches.push(mismatch);
        let mut mismatch = policy.clone();
        mismatch.steps.clear();
        mismatches.push(mismatch);
        for mismatch in mismatches {
            assert!(!policy_matches_replacement(&mismatch, &replacement));
        }

        let user: MembershipWire =
            serde_json::from_value(member_value(CodeSignerMemberKind::User, "admin")).unwrap();
        let user = membership_from_wire(
            user,
            &signer_id(),
            CodeSignerMemberKind::User,
            Some(&member_id()),
        )
        .unwrap();
        assert!(approvers_are_active_members(
            &replacement,
            std::slice::from_ref(&user),
            &[]
        ));
        let mut auditor = user.clone();
        auditor.role = CodeSignerRole::Auditor;
        assert!(!approvers_are_active_members(&replacement, &[auditor], &[]));
        assert!(!approvers_are_active_members(&replacement, &[], &[]));

        let group_id = CodeSignerMemberId::new(OTHER_ID).unwrap();
        let group_step =
            CodeSignerApprovalPolicyStepChange::new(1, None, 1, Vec::new(), vec![group_id])
                .unwrap();
        let group_replacement = CodeSignerApprovalPolicyReplacement::new(
            vec![group_step],
            CodeSignerApprovalPolicyConstraints {
                max_signings: Some(1),
                max_window_duration: None,
            },
        )
        .unwrap();
        let mut value = member_value(CodeSignerMemberKind::Group, "operator");
        value["actorGroupId"] = json!(OTHER_ID);
        let group: MembershipWire = serde_json::from_value(value).unwrap();
        let group = membership_from_wire(
            group,
            &signer_id(),
            CodeSignerMemberKind::Group,
            Some(&CodeSignerMemberId::new(OTHER_ID).unwrap()),
        )
        .unwrap();
        assert!(approvers_are_active_members(
            &group_replacement,
            &[],
            std::slice::from_ref(&group)
        ));
        let mut auditor = group;
        auditor.role = CodeSignerRole::Auditor;
        assert!(!approvers_are_active_members(
            &group_replacement,
            &[],
            &[auditor]
        ));
    }

    #[test]
    fn policy_limit_duration_math_is_exact() {
        for (duration, millis) in [
            ("1ms", 1),
            ("2s", 2_000),
            ("3m", 180_000),
            ("4h", 14_400_000),
            ("5d", 432_000_000),
            ("6w", 3_628_800_000),
        ] {
            assert_eq!(policy_duration_millis(duration), Some(millis), "{duration}");
        }
        assert_eq!(policy_duration_millis("1y"), None);
        assert_eq!(policy_duration_millis("999999999999999999999999w"), None);
        assert!(valid_optional_timestamp(None));
        assert!(valid_optional_timestamp(Some(CREATED_AT)));
        assert!(!valid_optional_timestamp(Some("not-a-timestamp")));

        let policy: PolicyWire = serde_json::from_value(policy_value()).unwrap();
        let policy = policy_from_wire(policy, &signer_id()).unwrap();
        let current_time = utc_timestamp_millis(CREATED_AT);
        let within = CodeSignerApprovalRequestCreation::new(
            "Publish".to_owned(),
            Some(2),
            Some(CodeSignerApprovalRequestWindow {
                start: Some(CREATED_AT.to_owned()),
                end: "2026-07-20T13:00:00.000Z".to_owned(),
            }),
        )
        .unwrap();
        assert!(requested_limits_fit_policy(&within, &policy, current_time));
        let too_many =
            CodeSignerApprovalRequestCreation::new("Publish".to_owned(), Some(3), None).unwrap();
        assert!(!requested_limits_fit_policy(
            &too_many,
            &policy,
            current_time
        ));
        let too_long = CodeSignerApprovalRequestCreation::new(
            "Publish".to_owned(),
            None,
            Some(CodeSignerApprovalRequestWindow {
                start: Some(CREATED_AT.to_owned()),
                end: "2026-07-20T13:00:00.001Z".to_owned(),
            }),
        )
        .unwrap();
        assert!(!requested_limits_fit_policy(
            &too_long,
            &policy,
            current_time
        ));
        let no_start_within = CodeSignerApprovalRequestCreation::new(
            "Publish".to_owned(),
            None,
            Some(CodeSignerApprovalRequestWindow {
                start: None,
                end: "2026-07-20T13:00:00.000Z".to_owned(),
            }),
        )
        .unwrap();
        assert!(requested_limits_fit_policy(
            &no_start_within,
            &policy,
            current_time
        ));
        let no_start_too_long = CodeSignerApprovalRequestCreation::new(
            "Publish".to_owned(),
            None,
            Some(CodeSignerApprovalRequestWindow {
                start: None,
                end: "2026-07-20T13:00:00.001Z".to_owned(),
            }),
        )
        .unwrap();
        assert!(!requested_limits_fit_policy(
            &no_start_too_long,
            &policy,
            current_time
        ));
        assert!(!requested_limits_fit_policy(
            &no_start_within,
            &policy,
            None
        ));
    }

    #[test]
    fn request_creation_reflection_is_exact() {
        let request: ApprovalRequestWire =
            serde_json::from_value(approval_request_value("pending")).unwrap();
        let request =
            approval_request_from_wire(request, &project_id(), &signer_id(), None).unwrap();
        let matching = approval_creation();
        assert!(request_matches_creation(&request, &matching));
        let mismatch_count = CodeSignerApprovalRequestCreation::new(
            "Publish the verified release".to_owned(),
            Some(1),
            matching.requested_window.clone(),
        )
        .unwrap();
        assert!(!request_matches_creation(&request, &mismatch_count));
        let mismatch_justification = CodeSignerApprovalRequestCreation::new(
            "Other".to_owned(),
            Some(2),
            matching.requested_window.clone(),
        )
        .unwrap();
        assert!(!request_matches_creation(&request, &mismatch_justification));
        let mismatch_window = CodeSignerApprovalRequestCreation::new(
            "Publish the verified release".to_owned(),
            Some(2),
            Some(CodeSignerApprovalRequestWindow {
                start: None,
                end: "2026-07-20T13:00:00.000Z".to_owned(),
            }),
        )
        .unwrap();
        assert!(!request_matches_creation(&request, &mismatch_window));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn approval_request_parser_validates_each_field_and_exact_boundaries() {
        let wire: ApprovalRequestWire =
            serde_json::from_value(approval_request_value("cancelled")).unwrap();
        let request = approval_request_from_wire(wire, &project_id(), &signer_id(), None).unwrap();

        assert_eq!(request.id, REQUEST_ID);
        assert_eq!(request.status, CodeSignerApprovalRequestStatus::Revoked);
        assert_eq!(request.max_signings, Some(2));
        assert!(request.requester_email.is_none());

        let mut user_request = approval_request_value("pending");
        user_request["requesterId"] = json!(MEMBER_ID);
        user_request["machineIdentityId"] = Value::Null;
        let user_request: ApprovalRequestWire = serde_json::from_value(user_request).unwrap();
        let user = approval_request_from_wire(
            user_request,
            &project_id(),
            &signer_id(),
            Some(&CodeSignerApprovalRequestId::new(REQUEST_ID).unwrap()),
        )
        .unwrap();
        assert_eq!(user.requester_kind, CodeSignerOperationActorKind::User);

        let mut invalid_cases = Vec::new();
        for (pointer, replacement) in [
            ("/id", json!("not-a-uuid")),
            ("/projectId", json!(OTHER_ID)),
            ("/policyId", json!(OTHER_ID)),
            ("/requestData/version", json!(2)),
            ("/requestData/requestData/signerId", json!(OTHER_ID)),
            ("/requestData/requestData/approvalPolicyId", json!(OTHER_ID)),
            ("/requestData/requestData/signerName", json!("")),
            ("/type", json!("other")),
            ("/scopeType", json!("other")),
            ("/scopeId", json!(OTHER_ID)),
            ("/machineIdentityId", json!("not-a-uuid")),
            ("/requesterName", json!("")),
            ("/requesterEmail", json!("control\n")),
            ("/justification", json!("Other")),
            ("/currentStep", json!(0)),
            ("/currentStep", json!(MAX_POLICY_STEPS + 1)),
            ("/requestData/requestData/requestedSignings", json!(0)),
            (
                "/requestData/requestData/requestedSignings",
                json!(MAX_POLICY_SIGNINGS + 1),
            ),
            ("/maxSignings", json!(0)),
            ("/maxSignings", json!(MAX_POLICY_SIGNINGS + 1)),
            (
                "/requestData/requestData/requestedWindowStart",
                json!("not-a-timestamp"),
            ),
            (
                "/requestData/requestData/requestedWindowEnd",
                json!("not-a-timestamp"),
            ),
            ("/expiresAt", json!("not-a-timestamp")),
            ("/createdAt", json!("not-a-timestamp")),
            ("/updatedAt", json!("not-a-timestamp")),
        ] {
            let mut value = approval_request_value("pending");
            *value.pointer_mut(pointer).unwrap() = replacement;
            invalid_cases.push(value);
        }
        let mut two_requesters = approval_request_value("pending");
        two_requesters["requesterId"] = json!(OTHER_ID);
        invalid_cases.push(two_requesters);
        let mut mismatched_justification = approval_request_value("pending");
        mismatched_justification["requestData"]["requestData"]["justification"] = json!("Other");
        invalid_cases.push(mismatched_justification);
        let mut empty_justification = approval_request_value("pending");
        empty_justification["justification"] = json!("");
        empty_justification["requestData"]["requestData"]["justification"] = json!("");
        invalid_cases.push(empty_justification);
        let mut start_without_end = approval_request_value("pending");
        start_without_end["requestData"]["requestData"]["requestedWindowEnd"] = Value::Null;
        invalid_cases.push(start_without_end);
        let mut reversed_window = approval_request_value("pending");
        reversed_window["requestData"]["requestData"]["requestedWindowStart"] =
            json!("2026-07-20T13:00:00.000Z");
        invalid_cases.push(reversed_window);
        let mut overused = approval_request_value("pending");
        overused["maxSignings"] = json!(1);
        overused["usedSignings"] = json!(2);
        invalid_cases.push(overused);
        for (index, value) in invalid_cases.into_iter().enumerate() {
            let wire: ApprovalRequestWire = serde_json::from_value(value).unwrap();
            assert_eq!(
                approval_request_from_wire(wire, &project_id(), &signer_id(), None).unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse,
                "case {index}"
            );
        }

        let wire: ApprovalRequestWire =
            serde_json::from_value(approval_request_value("pending")).unwrap();
        assert_eq!(
            approval_request_from_wire(
                wire,
                &project_id(),
                &signer_id(),
                Some(&CodeSignerApprovalRequestId::new(OTHER_ID).unwrap()),
            )
            .unwrap_err(),
            ResourceError::InvalidCodeSignerGovernanceResponse
        );

        let mut boundaries = approval_request_value("pending");
        boundaries["requesterEmail"] = json!("a".repeat(MAX_REQUESTER_EMAIL_BYTES));
        boundaries["currentStep"] = json!(MAX_POLICY_STEPS);
        boundaries["requestData"]["requestData"]["requestedSignings"] = json!(MAX_POLICY_SIGNINGS);
        boundaries["maxSignings"] = json!(MAX_POLICY_SIGNINGS);
        boundaries["usedSignings"] = json!(MAX_POLICY_SIGNINGS);
        let wire: ApprovalRequestWire = serde_json::from_value(boundaries).unwrap();
        assert!(approval_request_from_wire(wire, &project_id(), &signer_id(), None).is_ok());
        let mut overlong_email = approval_request_value("pending");
        overlong_email["requesterEmail"] = json!("a".repeat(MAX_REQUESTER_EMAIL_BYTES + 1));
        let wire: ApprovalRequestWire = serde_json::from_value(overlong_email).unwrap();
        assert_eq!(
            approval_request_from_wire(wire, &project_id(), &signer_id(), None).unwrap_err(),
            ResourceError::InvalidCodeSignerGovernanceResponse
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn approval_grant_parser_validates_each_authority_binding() {
        let request = CodeSignerApprovalRequestCreation::new(
            "Publish the verified release".to_owned(),
            Some(2),
            Some(CodeSignerApprovalRequestWindow {
                start: Some(CREATED_AT.to_owned()),
                end: "2026-07-20T13:00:00.000Z".to_owned(),
            }),
        )
        .unwrap();
        let creation = CodeSignerPreApprovalCreation::new(
            CodeSignerOperationActorKind::Identity,
            member_id(),
            request.clone(),
        );
        let wire: ApprovalGrantWire = serde_json::from_value(grant_value()).unwrap();
        let grant =
            approval_grant_from_wire(wire, &project_id(), &signer_id(), REQUEST_ID, &creation)
                .unwrap();
        assert_eq!(grant.id, OPERATION_ID);
        assert_eq!(grant.grantee_id, MEMBER_ID);
        assert_eq!(grant.max_signings, Some(2));

        let mut user_value = grant_value();
        user_value["granteeUserId"] = json!(MEMBER_ID);
        user_value["granteeMachineIdentityId"] = Value::Null;
        let user_creation = CodeSignerPreApprovalCreation::new(
            CodeSignerOperationActorKind::User,
            member_id(),
            request,
        );
        let wire: ApprovalGrantWire = serde_json::from_value(user_value).unwrap();
        assert_eq!(
            approval_grant_from_wire(
                wire,
                &project_id(),
                &signer_id(),
                REQUEST_ID,
                &user_creation,
            )
            .unwrap()
            .grantee_kind,
            CodeSignerOperationActorKind::User
        );

        let mut cases = Vec::new();
        for (pointer, replacement) in [
            ("/id", json!("not-a-uuid")),
            ("/projectId", json!(OTHER_ID)),
            ("/requestId", json!(OTHER_ID)),
            ("/type", json!("other")),
            ("/attributes/signerId", json!(OTHER_ID)),
            ("/attributes/signerName", json!("")),
            ("/granteeMachineIdentityId", json!(OTHER_ID)),
            ("/status", json!("expired")),
            ("/isBreakGlass", json!(true)),
            ("/attributes/maxSignings", json!(1)),
            ("/attributes/windowStart", json!(OTHER_ID)),
            ("/expiresAt", json!(CREATED_AT)),
        ] {
            let mut value = grant_value();
            *value.pointer_mut(pointer).unwrap() = replacement;
            cases.push(value);
        }
        let mut no_request = grant_value();
        no_request["requestId"] = Value::Null;
        cases.push(no_request);
        let mut two_grantees = grant_value();
        two_grantees["granteeUserId"] = json!(OTHER_ID);
        cases.push(two_grantees);
        for (index, value) in cases.into_iter().enumerate() {
            let wire: ApprovalGrantWire = serde_json::from_value(value).unwrap();
            assert_eq!(
                approval_grant_from_wire(wire, &project_id(), &signer_id(), REQUEST_ID, &creation,)
                    .unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse,
                "case {index}"
            );
        }
    }

    #[test]
    fn approval_request_pages_reconcile_limit_offset_and_total() {
        let request = CodeSignerApprovalRequestListRequest::new(
            project_id(),
            signer_id(),
            PageRequest::new(0, 2).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let request_value = |id: &str| {
            let mut value = approval_request_value("pending");
            value["id"] = json!(id);
            value
        };
        let response: ApprovalRequestsWire = serde_json::from_value(json!({
            "requests": [request_value(REQUEST_ID), request_value(OTHER_ID)],
            "totalCount": 3
        }))
        .unwrap();
        assert_eq!(
            approval_requests_page_from_wire(response, &request)
                .unwrap()
                .items
                .len(),
            2
        );
        let response: ApprovalRequestsWire = serde_json::from_value(json!({
            "requests": [request_value(REQUEST_ID)],
            "totalCount": 1
        }))
        .unwrap();
        assert_eq!(
            approval_requests_page_from_wire(response, &request)
                .unwrap()
                .items
                .len(),
            1
        );
        for value in [
            json!({
                "requests": [
                    request_value(REQUEST_ID),
                    request_value(OTHER_ID),
                    request_value(OPERATION_ID)
                ],
                "totalCount": 3
            }),
            json!({
                "requests": [request_value(REQUEST_ID), request_value(OTHER_ID)],
                "totalCount": 1
            }),
            json!({
                "requests": [request_value(REQUEST_ID)],
                "totalCount": 2
            }),
        ] {
            let response: ApprovalRequestsWire = serde_json::from_value(value).unwrap();
            assert_eq!(
                approval_requests_page_from_wire(response, &request).unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse
            );
        }
        let offset_request = CodeSignerApprovalRequestListRequest::new(
            project_id(),
            signer_id(),
            PageRequest::new(2, 2).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let response: ApprovalRequestsWire = serde_json::from_value(json!({
            "requests": [request_value(REQUEST_ID)],
            "totalCount": 3
        }))
        .unwrap();
        assert!(approval_requests_page_from_wire(response, &offset_request).is_ok());

        let pending_request = CodeSignerApprovalRequestListRequest::new(
            project_id(),
            signer_id(),
            PageRequest::new(0, 2).unwrap(),
            vec![CodeSignerApprovalRequestStatusFilter::Pending],
        )
        .unwrap();
        let pending_response: ApprovalRequestsWire = serde_json::from_value(json!({
            "requests": [request_value(REQUEST_ID)],
            "totalCount": 1
        }))
        .unwrap();
        assert!(approval_requests_page_from_wire(pending_response, &pending_request).is_ok());
        let approved_response: ApprovalRequestsWire = serde_json::from_value(json!({
            "requests": [approval_request_value("approved")],
            "totalCount": 1
        }))
        .unwrap();
        assert_eq!(
            approval_requests_page_from_wire(approved_response, &pending_request).unwrap_err(),
            ResourceError::InvalidCodeSignerGovernanceResponse
        );
    }

    #[tokio::test]
    async fn revoked_request_filter_uses_the_public_value_and_normalizes_terminal_states() {
        let server = MockServer::start().await;
        mount_login(&server, "governance-token").await;
        mount_signer(&server).await;
        let mut cancelled = approval_request_value("cancelled");
        cancelled["id"] = json!(OTHER_ID);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/requests"
            )))
            .and(query_param("statuses", "revoked"))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "requests": [approval_request_value("rejected"), cancelled],
                "totalCount": 2
            })))
            .expect(1)
            .mount(&server)
            .await;
        let request = CodeSignerApprovalRequestListRequest::new(
            project_id(),
            signer_id(),
            PageRequest::new(0, 2).unwrap(),
            vec![CodeSignerApprovalRequestStatusFilter::Revoked],
        )
        .unwrap();

        let page = InfisicalClient::new(settings(&server))
            .unwrap()
            .list_code_signer_approval_requests(request)
            .await
            .unwrap();

        assert_eq!(page.items.len(), 2);
        assert!(
            page.items
                .iter()
                .all(|request| { request.status == CodeSignerApprovalRequestStatus::Revoked })
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn operation_history_validates_each_field_pagination_and_discards_data_hash() {
        let response: SigningOperationsWire = serde_json::from_value(json!({
            "operations": [operation_value(OPERATION_ID)],
            "totalCount": 1
        }))
        .unwrap();
        let request = CodeSignerSigningOperationListRequest::new(
            project_id(),
            signer_id(),
            crate::PageRequest::new(0, 20).unwrap(),
            Some(CodeSignerOperationStatus::Success),
        );
        let page = signing_operations_page_from_wire(response, &request).unwrap();

        assert_eq!(page.items[0].id, OPERATION_ID);
        assert_eq!(page.items[0].status, CodeSignerOperationStatus::Success);
        let serialized = serde_json::to_string(&page).unwrap();
        assert!(!serialized.contains("dataHash"));
        assert!(!serialized.contains(&"a".repeat(64)));

        let mut invalid_cases = Vec::new();
        for (pointer, replacement) in [
            ("/id", json!("not-a-uuid")),
            ("/signerId", json!(OTHER_ID)),
            ("/projectId", json!(OTHER_ID)),
            ("/dataHash", json!("a".repeat(63))),
            ("/dataHash", json!("g".repeat(64))),
            ("/actorId", json!("not-a-uuid")),
            (
                "/actorName",
                json!("a".repeat(MAX_OPERATION_ACTOR_NAME_BYTES + 1)),
            ),
            ("/actorMembershipId", json!("not-a-uuid")),
            ("/approvalGrantId", json!("not-a-uuid")),
            ("/createdAt", json!("not-a-timestamp")),
            ("/status", json!("failed")),
        ] {
            let mut value = operation_value(OPERATION_ID);
            *value.pointer_mut(pointer).unwrap() = replacement;
            invalid_cases.push(value);
        }
        for (index, operation) in invalid_cases.into_iter().enumerate() {
            let response: SigningOperationsWire = serde_json::from_value(json!({
                "operations": [operation],
                "totalCount": 1
            }))
            .unwrap();
            assert_eq!(
                signing_operations_page_from_wire(response, &request).unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse,
                "case {index}"
            );
        }
        let mut boundary = operation_value(OPERATION_ID);
        boundary["actorName"] = json!("a".repeat(MAX_OPERATION_ACTOR_NAME_BYTES));
        let response: SigningOperationsWire = serde_json::from_value(json!({
            "operations": [boundary],
            "totalCount": 1
        }))
        .unwrap();
        assert!(signing_operations_page_from_wire(response, &request).is_ok());

        let paged_request = CodeSignerSigningOperationListRequest::new(
            project_id(),
            signer_id(),
            PageRequest::new(0, 2).unwrap(),
            Some(CodeSignerOperationStatus::Success),
        );
        let response: SigningOperationsWire = serde_json::from_value(json!({
            "operations": [operation_value(OPERATION_ID), operation_value(OTHER_ID)],
            "totalCount": 3
        }))
        .unwrap();
        assert_eq!(
            signing_operations_page_from_wire(response, &paged_request)
                .unwrap()
                .items
                .len(),
            2
        );
        let response: SigningOperationsWire = serde_json::from_value(json!({
            "operations": [operation_value(OPERATION_ID)],
            "totalCount": 1
        }))
        .unwrap();
        assert!(signing_operations_page_from_wire(response, &paged_request).is_ok());
        for value in [
            json!({
                "operations": [
                    operation_value(OPERATION_ID),
                    operation_value(OTHER_ID),
                    operation_value(REQUEST_ID)
                ],
                "totalCount": 3
            }),
            json!({
                "operations": [operation_value(OPERATION_ID), operation_value(OTHER_ID)],
                "totalCount": 1
            }),
            json!({
                "operations": [operation_value(OPERATION_ID)],
                "totalCount": 2
            }),
        ] {
            let response: SigningOperationsWire = serde_json::from_value(value).unwrap();
            assert_eq!(
                signing_operations_page_from_wire(response, &paged_request).unwrap_err(),
                ResourceError::InvalidCodeSignerGovernanceResponse
            );
        }
        let offset_request = CodeSignerSigningOperationListRequest::new(
            project_id(),
            signer_id(),
            PageRequest::new(2, 2).unwrap(),
            Some(CodeSignerOperationStatus::Success),
        );
        let response: SigningOperationsWire = serde_json::from_value(json!({
            "operations": [operation_value(OPERATION_ID)],
            "totalCount": 3
        }))
        .unwrap();
        assert!(signing_operations_page_from_wire(response, &offset_request).is_ok());
    }

    #[tokio::test]
    async fn policy_replacement_rejects_a_partial_response_mismatch() {
        let server = MockServer::start().await;
        mount_login(&server, "governance-token").await;
        mount_signer(&server).await;
        mount_policy(&server).await;
        mount_memberships(
            &server,
            CodeSignerMemberKind::User,
            vec![member_value(CodeSignerMemberKind::User, "operator")],
        )
        .await;
        mount_memberships(&server, CodeSignerMemberKind::Group, Vec::new()).await;
        Mock::given(method("PUT"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/approval-policy"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy_value()))
            .mount(&server)
            .await;

        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .replace_code_signer_approval_policy(
                &project_id(),
                &signer_id(),
                replacement_policy(),
                true,
            )
            .await
            .unwrap_err();

        assert_eq!(error, ResourceError::InvalidCodeSignerGovernanceResponse);
    }

    #[tokio::test]
    async fn user_only_policy_replacement_reads_only_user_memberships() {
        let server = MockServer::start().await;
        mount_login(&server, "governance-token").await;
        mount_signer(&server).await;
        mount_policy(&server).await;
        mount_memberships(
            &server,
            CodeSignerMemberKind::User,
            vec![member_value(CodeSignerMemberKind::User, "operator")],
        )
        .await;
        let mut replacement_response = policy_value();
        replacement_response["constraints"]["maxSignings"] = json!(1);
        Mock::given(method("PUT"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/approval-policy"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(replacement_response))
            .expect(1)
            .mount(&server)
            .await;

        let policy = InfisicalClient::new(settings(&server))
            .unwrap()
            .replace_code_signer_approval_policy(
                &project_id(),
                &signer_id(),
                replacement_policy(),
                true,
            )
            .await
            .unwrap();

        assert_eq!(policy.constraints.max_signings, Some(1));
    }

    #[tokio::test]
    async fn policy_disablement_avoids_unneeded_membership_reads() {
        let server = MockServer::start().await;
        mount_login(&server, "governance-token").await;
        mount_signer(&server).await;
        mount_policy(&server).await;
        let mut disabled_policy = policy_value();
        disabled_policy["hasSteps"] = json!(false);
        disabled_policy["steps"] = json!([]);
        disabled_policy["constraints"]["maxSignings"] = Value::Null;
        disabled_policy["constraints"]["maxWindowDuration"] = Value::Null;
        Mock::given(method("PUT"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/approval-policy"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(disabled_policy))
            .expect(1)
            .mount(&server)
            .await;
        let replacement = CodeSignerApprovalPolicyReplacement::new(
            Vec::new(),
            CodeSignerApprovalPolicyConstraints {
                max_signings: None,
                max_window_duration: None,
            },
        )
        .unwrap();

        let policy = InfisicalClient::new(settings(&server))
            .unwrap()
            .replace_code_signer_approval_policy(&project_id(), &signer_id(), replacement, true)
            .await
            .unwrap();

        assert!(policy.steps.is_empty());
    }

    #[tokio::test]
    async fn request_creation_rejects_each_partial_response_mismatch() {
        let mut wrong_policy = approval_request_value("pending");
        wrong_policy["policyId"] = json!(OTHER_ID);
        wrong_policy["requestData"]["requestData"]["approvalPolicyId"] = json!(OTHER_ID);
        let mut wrong_creation = approval_request_value("pending");
        wrong_creation["justification"] = json!("A different release");
        wrong_creation["requestData"]["requestData"]["justification"] =
            json!("A different release");

        for response in [wrong_policy, wrong_creation] {
            let server = MockServer::start().await;
            mount_login(&server, "governance-token").await;
            mount_signer(&server).await;
            mount_policy(&server).await;
            Mock::given(method("POST"))
                .and(path(format!(
                    "/api/v1/cert-manager/signers/{SIGNER_ID}/requests"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .mount(&server)
                .await;

            let error = InfisicalClient::new(settings(&server))
                .unwrap()
                .create_code_signer_approval_request(
                    &project_id(),
                    &signer_id(),
                    approval_creation(),
                    true,
                )
                .await
                .unwrap_err();

            assert_eq!(error, ResourceError::InvalidCodeSignerGovernanceResponse);
        }
    }

    #[tokio::test]
    async fn request_creation_rejects_an_omitted_start_beyond_the_policy_before_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "governance-token").await;
        mount_signer(&server).await;
        mount_policy(&server).await;
        let creation = CodeSignerApprovalRequestCreation::new(
            "Publish the verified release".to_owned(),
            None,
            Some(CodeSignerApprovalRequestWindow {
                start: None,
                end: "9999-12-31T23:59:59.999Z".to_owned(),
            }),
        )
        .unwrap();

        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .create_code_signer_approval_request(&project_id(), &signer_id(), creation, true)
            .await
            .unwrap_err();

        assert_eq!(error, ResourceError::InvalidCodeSignerGovernanceResponse);
        let mutation_path = format!("/api/v1/cert-manager/signers/{SIGNER_ID}/requests");
        assert!(
            !server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| {
                    request.method.as_str() == "POST" && request.url.path() == mutation_path
                })
        );
    }

    #[tokio::test]
    async fn pre_approval_requires_the_matching_non_auditor_member() {
        let server = MockServer::start().await;
        mount_login(&server, "governance-token").await;
        mount_signer(&server).await;
        mount_policy(&server).await;
        mount_effective_identities(
            &server,
            vec![effective_identity_value(OTHER_ID, "operator")],
        )
        .await;

        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .pre_approve_code_signer_request(
                &project_id(),
                &signer_id(),
                pre_approval_creation(),
                true,
            )
            .await
            .unwrap_err();

        assert_eq!(error, ResourceError::InvalidCodeSignerGovernanceResponse);
    }

    #[tokio::test]
    async fn pre_approval_rejects_each_partial_request_mismatch() {
        let mut wrong_policy = approval_request_value("approved");
        wrong_policy["policyId"] = json!(OTHER_ID);
        wrong_policy["requestData"]["requestData"]["approvalPolicyId"] = json!(OTHER_ID);
        let mut wrong_kind = approval_request_value("approved");
        wrong_kind["requesterId"] = json!(MEMBER_ID);
        wrong_kind["machineIdentityId"] = Value::Null;
        let mut wrong_id = approval_request_value("approved");
        wrong_id["machineIdentityId"] = json!(OTHER_ID);
        let mut wrong_creation = approval_request_value("approved");
        wrong_creation["justification"] = json!("A different release");
        wrong_creation["requestData"]["requestData"]["justification"] =
            json!("A different release");

        for request in [wrong_policy, wrong_kind, wrong_id, wrong_creation] {
            let server = MockServer::start().await;
            mount_login(&server, "governance-token").await;
            mount_signer(&server).await;
            mount_policy(&server).await;
            mount_effective_identities(
                &server,
                vec![effective_identity_value(MEMBER_ID, "operator")],
            )
            .await;
            Mock::given(method("POST"))
                .and(path(format!(
                    "/api/v1/cert-manager/signers/{SIGNER_ID}/requests/pre-approve"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "request": request,
                    "grant": grant_value()
                })))
                .mount(&server)
                .await;

            let error = InfisicalClient::new(settings(&server))
                .unwrap()
                .pre_approve_code_signer_request(
                    &project_id(),
                    &signer_id(),
                    pre_approval_creation(),
                    true,
                )
                .await
                .unwrap_err();

            assert_eq!(error, ResourceError::InvalidCodeSignerGovernanceResponse);
        }
    }

    #[tokio::test]
    async fn adding_a_user_rejects_skipped_or_unresolved_results() {
        for (skipped, unresolved) in [(vec![MEMBER_ID], Vec::new()), (Vec::new(), vec![MEMBER_ID])]
        {
            let server = MockServer::start().await;
            mount_login(&server, "governance-token").await;
            mount_signer(&server).await;
            Mock::given(method("POST"))
                .and(path(format!(
                    "/api/v1/cert-manager/signers/{SIGNER_ID}/users"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "memberships": [member_value(CodeSignerMemberKind::User, "operator")],
                    "skipped": skipped,
                    "unresolved": unresolved
                })))
                .mount(&server)
                .await;

            let error = InfisicalClient::new(settings(&server))
                .unwrap()
                .add_code_signer_member(
                    &project_id(),
                    &signer_id(),
                    CodeSignerMemberKind::User,
                    &member_id(),
                    CodeSignerRole::Operator,
                    true,
                )
                .await
                .unwrap_err();

            assert_eq!(error, ResourceError::InvalidCodeSignerGovernanceResponse);
        }
    }

    #[tokio::test]
    async fn role_update_rejects_a_reflected_role_mismatch() {
        let server = MockServer::start().await;
        mount_login(&server, "governance-token").await;
        mount_signer(&server).await;
        mount_memberships(
            &server,
            CodeSignerMemberKind::User,
            vec![member_value(CodeSignerMemberKind::User, "operator")],
        )
        .await;
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/users/{MEMBER_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "membership": member_value(CodeSignerMemberKind::User, "operator")
            })))
            .mount(&server)
            .await;

        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .update_code_signer_member_role(
                &project_id(),
                &signer_id(),
                CodeSignerMemberKind::User,
                &member_id(),
                CodeSignerRole::Admin,
                true,
            )
            .await
            .unwrap_err();

        assert_eq!(error, ResourceError::InvalidCodeSignerGovernanceResponse);
    }

    #[tokio::test]
    async fn member_removal_rejects_a_reflected_signer_mismatch() {
        let server = MockServer::start().await;
        mount_login(&server, "governance-token").await;
        mount_signer(&server).await;
        mount_memberships(
            &server,
            CodeSignerMemberKind::User,
            vec![member_value(CodeSignerMemberKind::User, "operator")],
        )
        .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/users/{MEMBER_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "membershipId": MEMBERSHIP_ID,
                "signerId": OTHER_ID
            })))
            .mount(&server)
            .await;

        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .remove_code_signer_member(
                &project_id(),
                &signer_id(),
                CodeSignerMemberKind::User,
                &member_id(),
                true,
            )
            .await
            .unwrap_err();

        assert_eq!(error, ResourceError::InvalidCodeSignerGovernanceResponse);
    }

    #[tokio::test]
    async fn confirmation_is_checked_before_governance_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();

        let error = client
            .add_code_signer_member(
                &project_id(),
                &signer_id(),
                CodeSignerMemberKind::User,
                &member_id(),
                CodeSignerRole::Operator,
                false,
            )
            .await
            .unwrap_err();

        assert_eq!(
            error,
            ResourceError::CodeSignerGovernanceMutationNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn adding_one_user_binds_project_signer_member_and_role() {
        let server = MockServer::start().await;
        mount_login(&server, "governance-token").await;
        mount_signer(&server).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/users"
            )))
            .and(body_json(json!({
                "userIds": [MEMBER_ID],
                "emails": [],
                "role": "operator"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "memberships": [member_value(CodeSignerMemberKind::User, "operator")],
                "skipped": [],
                "unresolved": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let membership = InfisicalClient::new(settings(&server))
            .unwrap()
            .add_code_signer_member(
                &project_id(),
                &signer_id(),
                CodeSignerMemberKind::User,
                &member_id(),
                CodeSignerRole::Operator,
                true,
            )
            .await
            .unwrap();

        assert_eq!(membership.membership_id, MEMBERSHIP_ID);
        assert_eq!(membership.member_id, MEMBER_ID);
        assert_eq!(membership.role, CodeSignerRole::Operator);
    }

    #[tokio::test]
    async fn effective_identity_list_rejects_user_shaped_results() {
        let server = MockServer::start().await;
        mount_login(&server, "governance-token").await;
        mount_signer(&server).await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{SIGNER_ID}/effective-identities"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "members": [{
                    "actorUserId": MEMBER_ID,
                    "actorIdentityId": null,
                    "role": "operator",
                    "viaGroupIds": [],
                    "isDirect": true,
                    "details": null
                }]
            })))
            .mount(&server)
            .await;

        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .list_code_signer_effective_members(
                &project_id(),
                &signer_id(),
                CodeSignerEffectiveMemberKind::Identity,
            )
            .await
            .unwrap_err();

        assert_eq!(error, ResourceError::InvalidCodeSignerGovernanceResponse);
    }
}
