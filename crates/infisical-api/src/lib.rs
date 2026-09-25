//! Typed access to the self-hosted Infisical REST API.

use std::fmt;

use zeroize::Zeroizing;

mod app_automations;
mod audit_logs;
mod certificate;
mod client;
mod code_signer_governance;
mod code_signers;
mod dynamic_secret_sql;
mod dynamic_secrets;
mod folders;
mod groups;
mod identities;
mod identity_kubernetes_auth;
mod identity_project_additional_privileges;
mod identity_token_auth;
mod identity_universal_auth;
mod kms;
mod network;
mod pagination;
mod pki_certificate_authorities;
mod pki_certificate_issuance;
mod pki_certificate_operations;
mod pki_certificate_policies;
mod pki_certificate_profiles;
mod pki_certificate_requests;
mod pki_certificates;
mod project_admin;
mod project_memberships;
mod projects;
mod resources;
mod roles;
mod secret_imports;
mod secret_rotation_sql;
mod secrets;
mod ssh_certificate_authorities;
mod ssh_certificate_templates;
mod ssh_certificates;
mod ssh_hosts;
mod tags;
#[cfg(test)]
mod test_support;

pub use app_automations::{
    AppAutomationInputError, AppConnection, AppConnectionProvider, AppConnectionRoute,
    AutomationConnection, AutomationDescriptionChange, AutomationEnvironment, AutomationFolder,
    GitHubAppConnection, GitHubAppConnectionChange, GitHubAppConnectionCreation,
    GitHubAppConnectionCredentials, GitHubConnectionMethod, GitHubInstance, GitHubInstanceMetadata,
    GitHubInstanceType, GitHubSecretSync, GitHubSecretSyncChange, GitHubSecretSyncCreation,
    GitHubSecretSyncDestination, GitHubSecretSyncOptions, GitHubSecretSyncSource,
    GitHubSyncVisibility, RotationTimeOfDay, SecretRotation, SecretRotationStatus,
    SecretRotationType, SecretSync, SecretSyncDestination, SecretSyncStatus,
};
pub use audit_logs::{
    AuditLog, AuditLogActorType, AuditLogEventType, AuditLogInputError, AuditLogListRequest,
    AuditLogTimestamp, AuditLogUserAgentType,
};
pub use client::{
    ApiErrorKind, ApiFailure, CapabilityAvailability, ClientConfigError, ClientError,
    ClientSettings, InfisicalClient, MAXIMUM_RESPONSE_BYTES, MutationOperation,
    ObservableReadBodyOperation, ObservableReadOperation, ReadOperation, TransportErrorKind,
};
pub use code_signer_governance::{
    CodeSignerApprovalGrant, CodeSignerApprovalGrantStatus, CodeSignerApprovalPolicy,
    CodeSignerApprovalPolicyApprover, CodeSignerApprovalPolicyApproverKind,
    CodeSignerApprovalPolicyConstraints, CodeSignerApprovalPolicyReplacement,
    CodeSignerApprovalPolicyStep, CodeSignerApprovalPolicyStepChange, CodeSignerApprovalRequest,
    CodeSignerApprovalRequestCreation, CodeSignerApprovalRequestId,
    CodeSignerApprovalRequestListRequest, CodeSignerApprovalRequestRevocation,
    CodeSignerApprovalRequestStatus, CodeSignerApprovalRequestStatusFilter,
    CodeSignerApprovalRequestWindow, CodeSignerEffectiveMember, CodeSignerEffectiveMemberKind,
    CodeSignerMemberDetails, CodeSignerMemberId, CodeSignerMemberKind, CodeSignerMembership,
    CodeSignerMembershipMutationReceipt, CodeSignerOperationActorKind, CodeSignerOperationStatus,
    CodeSignerPermissionMembership, CodeSignerPermissionRule, CodeSignerPermissions,
    CodeSignerPreApproval, CodeSignerPreApprovalCreation, CodeSignerRole,
    CodeSignerSigningOperation, CodeSignerSigningOperationListRequest, SignerGovernanceInputError,
};
pub use code_signers::{
    CodeSigner, CodeSignerCertificate, CodeSignerCertificateId, CodeSignerCertificateReissue,
    CodeSignerCertificateSource, CodeSignerChange, CodeSignerCreation, CodeSignerDescriptionChange,
    CodeSignerDesiredStatus, CodeSignerId, CodeSignerInputError, CodeSignerListRequest,
    CodeSignerName, CodeSignerPublicKey, CodeSignerRenewBeforeChange, CodeSignerSignature,
    CodeSignerStatus, CodeSigningAlgorithm, CodeSigningClientMetadata, CodeSigningData,
};
pub use dynamic_secret_sql::{
    CreatedSqlDynamicSecretLease, SqlDynamicSecretClient, SqlDynamicSecretConnection,
    SqlDynamicSecretCreation, SqlDynamicSecretInputError, SqlDynamicSecretInputs,
    SqlDynamicSecretPasswordRequirements, SqlDynamicSecretRoute, SqlDynamicSecretStatements,
    SqlDynamicSecretTls,
};
pub use dynamic_secrets::{
    DynamicSecret, DynamicSecretChange, DynamicSecretInputError, DynamicSecretLease,
    DynamicSecretLeaseDetails, DynamicSecretLeaseId, DynamicSecretLeaseStatus, DynamicSecretName,
    DynamicSecretProvider, DynamicSecretScope, DynamicSecretStatus, DynamicSecretTtlSeconds,
};
pub use folders::{
    Folder, FolderBatch, FolderBatchUpdate, FolderCreation, FolderEnvironment, FolderParent,
    FolderUpdate, MAX_FOLDER_BATCH_SIZE,
};
pub use groups::{
    Group, GroupIdentity, GroupMember, GroupMemberTypeFilter, GroupProject, GroupProjectFilter,
    GroupReference, GroupUser, ProjectGroupMembership,
};
pub use identities::{IdentityChange, IdentityCreation, MachineIdentity, OrganizationRole};
pub use identity_kubernetes_auth::{
    KubernetesAuthChange, KubernetesAuthConfig, KubernetesAuthInputError, KubernetesAuthSettings,
    KubernetesAuthTokenReviewMode, KubernetesTokenReviewerJwtChange,
    MAX_KUBERNETES_AUTH_AUDIENCE_BYTES, MAX_KUBERNETES_AUTH_CA_CERT_BYTES,
    MAX_KUBERNETES_AUTH_HOST_BYTES, MAX_KUBERNETES_AUTH_LIFETIME_SECONDS,
    MAX_KUBERNETES_AUTH_POLICY_PATTERN_BYTES, MAX_KUBERNETES_AUTH_POLICY_PATTERNS,
    MAX_KUBERNETES_AUTH_REVIEWER_JWT_BYTES,
};
pub use identity_project_additional_privileges::{
    AdditionalPrivilegeChange, AdditionalPrivilegeCreation, AdditionalPrivilegeInputError,
    AdditionalPrivilegeLifetime, AdditionalPrivilegeSlug, AdditionalPrivilegeStartTime,
    IdentityProjectAdditionalPrivilege, IdentityProjectAdditionalPrivilegeSummary,
    MAX_ADDITIONAL_PRIVILEGE_ACTIONS, MAX_ADDITIONAL_PRIVILEGE_CONDITION_BYTES,
    MAX_ADDITIONAL_PRIVILEGE_DURATION_SECONDS, MAX_ADDITIONAL_PRIVILEGE_PERMISSIONS,
};
pub use identity_token_auth::{
    CreatedTokenAuthToken, MAX_TOKEN_AUTH_LIFETIME_SECONDS, MAX_TOKEN_AUTH_LIST_OFFSET,
    MAX_TOKEN_AUTH_TOKEN_NAME_BYTES, TokenAuthChange, TokenAuthConfig, TokenAuthInputError,
    TokenAuthSettings, TokenAuthToken, TokenAuthTokenCreation, TokenAuthTokenRevocation,
};
pub use identity_universal_auth::{
    CreatedUniversalAuthClientSecret, MAX_AUTH_LIFETIME_SECONDS,
    MAX_CLIENT_SECRET_DESCRIPTION_BYTES, TrustedIp, UniversalAuthChange, UniversalAuthClientSecret,
    UniversalAuthClientSecretCreation, UniversalAuthConfig, UniversalAuthInputError,
    UniversalAuthLockoutClear, UniversalAuthLockoutPolicy, UniversalAuthSettings,
};
pub use kms::{
    KmsBulkImportEntry, KmsBulkImportResult, KmsBulkPrivateKey, KmsCiphertext, KmsData,
    KmsDecryptedData, KmsImportError, KmsImportedKey, KmsInputError, KmsKey, KmsKeyAlgorithm,
    KmsKeyChange, KmsKeyCreation, KmsKeyId, KmsKeyListRequest, KmsKeyMaterial, KmsKeyName,
    KmsKeyUsage, KmsPrivateKey, KmsPublicKey, KmsSignature, KmsSigningAlgorithm,
    KmsSigningAlgorithms, KmsVerification, MAX_KMS_BULK_KEYS, MAX_KMS_PAYLOAD_BYTES,
};
#[doc(hidden)]
pub use network::{
    PrivateHttpResolver, ResolutionPolicy, SystemResolver, url_resolution_policy,
    validate_private_resolution,
};
pub use pagination::{MAX_PAGE_OFFSET, MAX_PAGE_SIZE, Page, PageRequest, PaginationError};
pub use pki_certificate_authorities::{
    CertificateAuthorityId, CertificateAuthorityInputError, CertificateAuthorityName,
    CertificateAuthorityProjectId, CertificateAuthorityStatus, CertificateAuthoritySubject,
    CertificateAuthoritySummary, CertificateAuthorityType, CertificateKeyAlgorithm,
    InternalCertificateAuthority, InternalCertificateAuthorityChange,
    InternalCertificateAuthorityConfiguration, InternalCertificateAuthorityCreation,
    InternalCertificateAuthorityType,
};
pub use pki_certificate_issuance::{
    CertificateIssuance, CertificateIssuanceAttributes, CertificateIssuanceBasicConstraints,
    CertificateIssuanceInputError, CertificateIssuanceMetadata, CertificateIssuanceMethod,
    CertificateIssuanceOutcome, CertificateIssuanceSan, CertificateIssuanceValidity,
    IssuedCertificate, MAX_CERTIFICATE_ISSUANCE_MATERIAL_BYTES,
};
pub use pki_certificate_operations::{
    CertificateAuthorityCertificate, CertificateAuthorityCertificateGeneration,
    CertificateAuthorityCertificateImport, CertificateAuthorityCertificateInputError,
    CertificateAuthorityCertificateRenewal, CertificateAuthorityCrl, CertificateAuthorityCsr,
    CertificateAuthorityImportReceipt, CertificateAuthoritySignedIntermediate,
    CertificateAuthoritySigningRequest,
};
pub use pki_certificate_policies::{
    CertificatePolicy, CertificatePolicyAlgorithms, CertificatePolicyBasicConstraints,
    CertificatePolicyChange, CertificatePolicyCreation, CertificatePolicyFieldChange,
    CertificatePolicyInputError, CertificatePolicyKeyAlgorithm, CertificatePolicyListRequest,
    CertificatePolicyMaxValidity, CertificatePolicySanType, CertificatePolicySignatureAlgorithm,
    CertificatePolicyState, CertificatePolicySubjectAttribute, CertificatePolicyUsageRule,
    CertificatePolicyValidity, CertificatePolicyValueRule,
};
pub use pki_certificate_profiles::{
    CertificateExtendedKeyUsage, CertificateKeyUsage, CertificatePolicyId, CertificateProfile,
    CertificateProfileAcmeChange, CertificateProfileApplicationId, CertificateProfileBundle,
    CertificateProfileCertificate, CertificateProfileCertificateListRequest,
    CertificateProfileCertificateStatus, CertificateProfileChange, CertificateProfileCreation,
    CertificateProfileDefaults, CertificateProfileDefaultsChange,
    CertificateProfileDescriptionChange, CertificateProfileEabSecret,
    CertificateProfileEnrollmentChange, CertificateProfileEnrollmentConfiguration,
    CertificateProfileEnrollmentType, CertificateProfileExternalConfig,
    CertificateProfileExternalConfigChange, CertificateProfileId, CertificateProfileInputError,
    CertificateProfileIssuer, CertificateProfileIssuerType, CertificateProfileListRequest,
    CertificateProfileScepChallengeType, CertificateProfileSlug, CertificateSignatureAlgorithm,
};
pub use pki_certificate_requests::{
    CertificateRequest, CertificateRequestCancellation, CertificateRequestCertificate,
    CertificateRequestId, CertificateRequestInputError, CertificateRequestListRequest,
    CertificateRequestMaterial, CertificateRequestSort, CertificateRequestSortOrder,
    CertificateRequestStatus,
};
pub use pki_certificates::{
    Certificate, CertificateBundle, CertificateId, CertificateImport, CertificateInputError,
    CertificateInventorySort, CertificateInventorySortOrder, CertificateListRequest,
    CertificatePrivateKey, CertificatePublicMaterial, CertificateRenewBeforeDays,
    CertificateRenewalConfiguration, CertificateRenewalConfigurationChange, CertificateRevocation,
    CertificateRevocationReason, CertificateStatus, RenewedCertificate,
};
pub use project_admin::{
    EnvironmentChange, EnvironmentCreation, ProjectChange, ProjectCreation, ProjectKind,
};
pub use project_memberships::{
    MAX_PROJECT_MEMBERSHIP_BATCH_SIZE, MAX_PROJECT_MEMBERSHIP_ROLES, ProjectIdentityMembership,
    ProjectMemberIdentity, ProjectMemberUser, ProjectMembershipInputError,
    ProjectMembershipMutationReceipt, ProjectMembershipMutationReceiptBatch, ProjectMembershipRole,
    ProjectMembershipRoleSet, ProjectMembershipRoles, ProjectRoleSlug, ProjectUserInvitation,
    ProjectUserMembership,
};
pub use projects::{Environment, Project};
pub use resources::{
    AdditionalPrivilegeId, EnvironmentId, EnvironmentName, EnvironmentPosition, EnvironmentSlug,
    FolderDescription, FolderId, FolderName, GroupId, IdentityId, IdentityName, NewProjectSlug,
    OrganizationId, PointInTimeVersionLimit, ProjectDescription, ProjectId, ProjectMembershipId,
    ProjectName, ProjectSlug, ResourceError, ResourceInputError, SecretImportId,
    SecretImportPosition, SecretName, SecretPath, SecretScope, TagColor, TagId, TagSlug,
    TokenAuthTokenId, UniversalAuthClientSecretId,
};
pub use roles::{Role, RoleInputError, RolePermission, RoleScope, RoleSlug, RoleSummary};
pub use secret_imports::{
    SecretImport, SecretImportChange, SecretImportEnvironment, SecretImportSource,
    SecretImportTarget,
};
pub use secret_rotation_sql::{
    SqlGeneratedCredential, SqlGeneratedCredentialCleanup, SqlGeneratedCredentials,
    SqlMappedSecretCleanup, SqlSecretRotationChange, SqlSecretRotationCreation,
    SqlSecretRotationInputError, SqlSecretRotationName, SqlSecretRotationNameTarget,
    SqlSecretRotationParameters, SqlSecretRotationProvider, SqlSecretRotationSecretsMapping,
    SqlSecretRotationTarget,
};
pub use secrets::{
    MAX_SECRET_BATCH_SIZE, RevealedSecret, SecretApproval, SecretBatchMutationReceipt,
    SecretMetadata, SecretMetadataEntry, SecretMetadataTag, SecretMutationMetadata,
    SecretMutationReceipt, SecretValueMutation,
};
pub use ssh_certificate_authorities::{
    SshCaKeyMaterial, SshCaKeySource, SshCaReplacement, SshCaStatus, SshCertificateAuthority,
    SshCertificateAuthorityCreation, SshCertificateAuthorityId, SshCertificateAuthorityInputError,
    SshCertificateAuthoritySummary, SshKeyAlgorithm, SshProjectId, SshPublicKey,
};
pub use ssh_certificate_templates::{
    SshCertificateTemplate, SshCertificateTemplateCreation, SshCertificateTemplateId,
    SshCertificateTemplateInputError, SshCertificateTemplateReplacement,
    SshCertificateTemplateStatus, SshDuration,
};
pub use ssh_certificates::{
    IssuedSshCertificate, SignedSshCertificate, SshCertificateInputError,
    SshCertificateIssueRequest, SshCertificateRequest, SshCertificateSignRequest,
    SshCertificateType,
};
pub use ssh_hosts::{
    EffectiveSshLoginMapping, SshAllowedPrincipals, SshHost, SshHostCreation, SshHostDuration,
    SshHostGroup, SshHostGroupId, SshHostGroupMember, SshHostGroupMembers,
    SshHostGroupMembershipFilter, SshHostGroupMembershipReceipt, SshHostGroupPolicy, SshHostId,
    SshHostInputError, SshHostLinkedCaPublicKey, SshHostReplacement, SshLoginMapping,
    SshLoginMappingSource,
};
pub use tags::{Tag, TagCreation, TagSelector, TagUpdate};

/// Infisical release whose API documentation defines the initial contract.
pub const TARGET_INFISICAL_VERSION: &str = "0.160.12";

/// A secret-bearing string with redacted standard formatting.
///
/// Callers must opt in to exposing the value at the narrow serialization or
/// upstream-request boundary. The type intentionally does not implement
/// `Clone`, `Serialize`, or `AsRef<str>`.
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    /// Wrap a value that must not appear in logs or ordinary responses.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Expose the value at an explicitly reviewed secret boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretValue, TARGET_INFISICAL_VERSION};

    #[test]
    fn target_version_has_three_numeric_components() {
        let components = TARGET_INFISICAL_VERSION
            .split('.')
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .expect("target version components must be numeric");

        assert_eq!(components.len(), 3);
    }

    #[test]
    fn standard_formatters_never_expose_a_secret() {
        let secret = SecretValue::new("canary-value");

        assert_eq!(format!("{secret}"), "[REDACTED]");
        assert_eq!(format!("{secret:?}"), "SecretValue([REDACTED])");
        assert_eq!(secret.expose_secret(), "canary-value");
    }
}
