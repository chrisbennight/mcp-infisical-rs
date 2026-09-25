//! Typed recovery facts for a known operation, independent of error prose.

use infisical_api::{ApiErrorKind, ClientError, ResourceError};
use rmcp::model::CallToolResult;
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Category {
    Validation,
    Authentication,
    PermissionDenied,
    NotFound,
    Conflict,
    Capacity,
    RateLimited,
    Transport,
    ResponseValidation,
    Internal,
    Upstream,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Effect {
    NotStarted,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Recovery {
    CorrectRequest,
    Wait,
    Reconcile,
    InspectConfiguration,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExecutionError {
    /// Registry-owned operation name, added by the validated executor boundary.
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
    /// Safe schema path; never includes a rejected value.
    #[serde(skip_serializing_if = "Option::is_none")]
    field_path: Option<&'static str>,
    /// Stable failure class; no classification requires parsing the message.
    category: Category,
    /// Whether the final action was not initiated or its outcome is uncertain.
    effect: Effect,
    /// The next decision for the caller; the server never replays mutations.
    recovery: Recovery,
    /// Safe correction or reconciliation guidance without rejected values.
    correction: String,
    /// Allowlisted upstream correlation identifier, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    /// Bounded pacing guidance; this does not authorize mutation replay.
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u64>,
    /// Whether earlier preflight observations may have generated audit records; omitted when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    preflight_observations_possible: Option<bool>,
}

impl ExecutionError {
    pub(crate) fn new(
        category: Category,
        effect: Effect,
        recovery: Recovery,
        correction: impl Into<String>,
    ) -> Self {
        Self {
            operation: None,
            field_path: None,
            category,
            effect,
            recovery,
            correction: correction.into(),
            request_id: None,
            retry_after_seconds: None,
            preflight_observations_possible: None,
        }
    }

    pub(crate) fn into_result(self) -> CallToolResult {
        let mut result = CallToolResult::structured(serde_json::json!({"error": self}));
        result.is_error = Some(true);
        result
    }

    pub(crate) fn from_client(error: &ClientError) -> Self {
        use Category as C;
        use Effect::Unknown;
        use Recovery as R;
        let mut result = match error {
            ClientError::WorkBudgetExhausted => Self::new(
                C::Capacity,
                Unknown,
                R::Reconcile,
                "This HTTP request was not sent. Reconcile any earlier operation steps before trying again.",
            ),
            ClientError::Transport(_) => Self::new(
                C::Transport,
                Unknown,
                R::Reconcile,
                "The response was not received. Inspect the operation's state before deciding whether another request is safe.",
            ),
            ClientError::ResponseTooLarge { .. } => Self::new(
                C::Capacity,
                Unknown,
                R::Reconcile,
                "The upstream response exceeded its bound. Reconcile effects; narrow supported retrieval filters for a later read.",
            ),
            ClientError::InvalidResponse | ClientError::InvalidMutationResponse => Self::new(
                C::ResponseValidation,
                Unknown,
                R::Reconcile,
                "The upstream response could not be verified. Reconcile the operation's state before another request.",
            ),
            ClientError::InvalidEndpoint => Self::new(
                C::Internal,
                Unknown,
                R::InspectConfiguration,
                "The server endpoint declaration is invalid; report this operation to the operator.",
            ),
            ClientError::RefreshInterrupted => Self::new(
                C::Authentication,
                Unknown,
                R::Reconcile,
                "Authentication refresh was interrupted. Reconcile earlier operation steps before trying again.",
            ),
            ClientError::AuthenticationCooldown {
                failure,
                retry_after_seconds,
            } => {
                let mut result = Self::from_client(failure);
                result.category = C::Authentication;
                result.recovery = R::Wait;
                result.retry_after_seconds = Some((*retry_after_seconds).min(300));
                result.correction = "Wait for the authentication cooldown, then reconcile any earlier operation steps. Do not automatically replay a mutation.".into();
                result
            }
            ClientError::Api(failure) => {
                let (category, recovery) = match failure.kind() {
                    ApiErrorKind::InvalidRequest => (C::Validation, R::CorrectRequest),
                    ApiErrorKind::Authentication => (C::Authentication, R::InspectConfiguration),
                    ApiErrorKind::PermissionDenied => {
                        (C::PermissionDenied, R::InspectConfiguration)
                    }
                    ApiErrorKind::NotFound => (C::NotFound, R::CorrectRequest),
                    ApiErrorKind::Conflict => (C::Conflict, R::Reconcile),
                    ApiErrorKind::RateLimited => (C::RateLimited, R::Wait),
                    ApiErrorKind::Server => (C::Upstream, R::Reconcile),
                };
                let mut result = Self::new(category, Unknown, recovery, error.to_string());
                result.request_id = failure.request_id().map(str::to_owned);
                result.retry_after_seconds =
                    failure.retry_after().map(|delay| delay.as_secs().min(300));
                result
            }
        };
        if result.retry_after_seconds.is_none() {
            result.retry_after_seconds = error.retry_after().map(|delay| delay.as_secs().min(300));
        }
        result
    }

    pub(crate) fn from_handler(error: rmcp::ErrorData) -> Self {
        if error
            .data
            .as_ref()
            .and_then(|data| data.get("capacityBeforeExecution"))
            == Some(&serde_json::Value::Bool(true))
        {
            let mut result = Self::new(
                Category::Capacity,
                Effect::NotStarted,
                Recovery::Wait,
                error.message,
            );
            result.preflight_observations_possible = Some(false);
            return result;
        }
        if error.code == rmcp::model::ErrorCode::INVALID_PARAMS {
            let mut result = Self::new(
                Category::Validation,
                Effect::NotStarted,
                Recovery::CorrectRequest,
                error.message,
            );
            result.field_path = Some("arguments");
            result.preflight_observations_possible = Some(false);
            return result;
        }
        Self::new(
            Category::Internal,
            Effect::Unknown,
            Recovery::Reconcile,
            "The operation result could not be completed. Reconcile its state and retain any returned delivery references.",
        )
    }
}

pub(crate) fn capacity_before_execution(error: &crate::files::FileError) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(
        error.to_string(),
        Some(serde_json::json!({"capacityBeforeExecution": true})),
    )
}

/// Add only a validated registry name, then rebuild the compatibility JSON text.
pub(crate) fn name_error(operation: &str, mut result: CallToolResult) -> CallToolResult {
    if result.is_error != Some(true) {
        return result;
    }
    let Some(value) = result.structured_content.as_mut() else {
        return result;
    };
    let Some(error) = value
        .get_mut("error")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return result;
    };
    error.insert("operation".into(), operation.into());
    let mut named = CallToolResult::structured(
        result
            .structured_content
            .take()
            .expect("structured error exists"),
    );
    named.is_error = Some(true);
    named
}

impl ExecutionError {
    // Exhaustive variant matching makes additions require an explicit recovery decision.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn from_resource(error: &ResourceError) -> Self {
        match error {
            ResourceError::Client(error) => Self::from_client(error),
            ResourceError::InvalidKmsCryptographicInput => {
                let mut result = Self::new(
                    Category::Validation,
                    Effect::NotStarted,
                    Recovery::CorrectRequest,
                    error.to_string(),
                );
                result.preflight_observations_possible = Some(true);
                result
            }
            ResourceError::KmsBulkPreflightFailed { source, .. } => {
                let mut result = Self::from_resource(source);
                result.effect = Effect::NotStarted;
                result.preflight_observations_possible = Some(true);
                result.correction = error.to_string();
                result
            }
            ResourceError::KmsBulkPreflightTimeout { .. } => {
                let mut result = Self::new(
                    Category::Capacity,
                    Effect::NotStarted,
                    Recovery::Wait,
                    error.to_string(),
                );
                result.preflight_observations_possible = Some(true);
                result
            }
            ResourceError::DeletionNotConfirmed
            | ResourceError::SecretImportDeletionNotConfirmed
            | ResourceError::ProjectDeletionNotConfirmed
            | ResourceError::EnvironmentDeletionNotConfirmed
            | ResourceError::FolderDeletionNotConfirmed
            | ResourceError::TagDeletionNotConfirmed
            | ResourceError::IdentityDeletionNotConfirmed
            | ResourceError::AdditionalPrivilegeDeletionNotConfirmed
            | ResourceError::ProjectMembershipDeletionNotConfirmed
            | ResourceError::ProjectMembershipRoleReplacementNotConfirmed
            | ResourceError::UniversalAuthRemovalNotConfirmed
            | ResourceError::UniversalAuthClientSecretRevocationNotConfirmed
            | ResourceError::TokenAuthRemovalNotConfirmed
            | ResourceError::TokenAuthTokenRevocationNotConfirmed
            | ResourceError::KubernetesAuthRemovalNotConfirmed
            | ResourceError::UniversalAuthLockoutClearNotConfirmed
            | ResourceError::DynamicSecretLeaseRevocationNotConfirmed
            | ResourceError::DynamicSecretDeletionNotConfirmed
            | ResourceError::AppConnectionDeletionNotConfirmed
            | ResourceError::AppConnectionCredentialReplacementNotConfirmed
            | ResourceError::AppConnectionCredentialRotationNotConfirmed
            | ResourceError::SecretSyncInitialOverwriteNotConfirmed
            | ResourceError::SecretSyncUpdateNotConfirmed
            | ResourceError::SecretSyncDeletionNotConfirmed
            | ResourceError::SecretSyncRemoteRemovalNotConfirmed
            | ResourceError::SecretSyncRunNotConfirmed
            | ResourceError::SqlSecretRotationCreateNotConfirmed
            | ResourceError::SqlSecretRotationUpdateNotConfirmed
            | ResourceError::SqlSecretRotationDeleteNotConfirmed
            | ResourceError::SqlSecretRotationMoveNotConfirmed
            | ResourceError::SqlSecretRotationOverwriteNotConfirmed
            | ResourceError::SqlSecretRotationRevealNotConfirmed
            | ResourceError::SqlSecretRotationRotateNotConfirmed
            | ResourceError::SqlSecretRotationCheckNotConfirmed
            | ResourceError::KmsKeyDeletionNotConfirmed
            | ResourceError::KmsOperationNotConfirmed
            | ResourceError::KmsSecretRevealNotConfirmed
            | ResourceError::CertificateAuthorityCreateNotConfirmed
            | ResourceError::CertificateAuthorityUpdateNotConfirmed
            | ResourceError::CertificateAuthorityDeleteNotConfirmed
            | ResourceError::CertificateAuthorityCertificateMutationNotConfirmed
            | ResourceError::CertificatePolicyCreateNotConfirmed
            | ResourceError::CertificatePolicyUpdateNotConfirmed
            | ResourceError::CertificatePolicyDeleteNotConfirmed
            | ResourceError::CertificateImportNotConfirmed
            | ResourceError::CertificateMaterialRevealNotConfirmed
            | ResourceError::CertificateRenewalNotConfirmed
            | ResourceError::CertificateRevocationNotConfirmed
            | ResourceError::CertificateDeletionNotConfirmed
            | ResourceError::CertificateRequestRevealNotConfirmed
            | ResourceError::CertificateRequestCancelNotConfirmed
            | ResourceError::CertificateIssuanceNotConfirmed
            | ResourceError::CertificateProfileCreateNotConfirmed
            | ResourceError::CertificateProfileUpdateNotConfirmed
            | ResourceError::CertificateProfileDeleteNotConfirmed
            | ResourceError::CertificateProfileSecretRevealNotConfirmed
            | ResourceError::CodeSignerCreateNotConfirmed
            | ResourceError::CodeSignerUpdateNotConfirmed
            | ResourceError::CodeSignerDeleteNotConfirmed
            | ResourceError::CodeSignerStatusUpdateNotConfirmed
            | ResourceError::CodeSignerCertificateMutationNotConfirmed
            | ResourceError::CodeSigningNotConfirmed
            | ResourceError::CodeSignerGovernanceMutationNotConfirmed
            | ResourceError::SshCertificateAuthorityCreateNotConfirmed
            | ResourceError::SshCertificateAuthorityReplaceNotConfirmed
            | ResourceError::SshCertificateAuthorityDeleteNotConfirmed
            | ResourceError::SshCertificateTemplateCreateNotConfirmed
            | ResourceError::SshCertificateTemplateReplaceNotConfirmed
            | ResourceError::SshCertificateTemplateDeleteNotConfirmed
            | ResourceError::SshCertificateSigningNotConfirmed
            | ResourceError::SshCertificateIssuanceNotConfirmed
            | ResourceError::SshHostCreateNotConfirmed
            | ResourceError::SshHostReplaceNotConfirmed
            | ResourceError::SshHostDeleteNotConfirmed
            | ResourceError::SshHostCertificateIssuanceNotConfirmed
            | ResourceError::SshHostGroupCreateNotConfirmed
            | ResourceError::SshHostGroupReplaceNotConfirmed
            | ResourceError::SshHostGroupDeleteNotConfirmed
            | ResourceError::SshHostGroupMembershipNotConfirmed
            | ResourceError::InvalidSecretTagFilter
            | ResourceError::InvalidSecretBatchSize
            | ResourceError::DuplicateSecretName
            | ResourceError::CyclicSecretImport
            | ResourceError::TokenAuthPageOffsetLimit
            | ResourceError::InvalidTokenAuthTokenName
            | ResourceError::InvalidFolderBatchSize
            | ResourceError::DuplicateFolderId
            | ResourceError::AuditLogMetadataFilterRequiresProject
            | ResourceError::AuditLogMetadataFilterRequiresSecretEvent
            | ResourceError::DynamicSecretRenameWouldBeNoop
            | ResourceError::SqlSecretRotationProviderMismatch
            | ResourceError::InvalidKmsBulkRequest
            | ResourceError::InvalidCodeSigningInput => Self::new(
                Category::Validation,
                Effect::NotStarted,
                Recovery::CorrectRequest,
                error.to_string(),
            ),
            ResourceError::Pagination(_)
            | ResourceError::InvalidAppAutomationScope
            | ResourceError::InvalidKmsKeyScope
            | ResourceError::InvalidKmsKeyUsage
            | ResourceError::KmsKeyDisabled
            | ResourceError::InvalidCertificateAuthorityScope
            | ResourceError::InvalidCertificateAuthorityCertificateState
            | ResourceError::InvalidCertificateAuthorityProjectKind
            | ResourceError::CertificatePolicyInUse
            | ResourceError::InvalidCertificatePolicyScope
            | ResourceError::InvalidCertificateInventoryScope
            | ResourceError::CertificatePrivateKeyUnavailable
            | ResourceError::InvalidCertificateLifecycleState
            | ResourceError::InvalidCertificateRequestScope
            | ResourceError::InvalidCertificateRequestState
            | ResourceError::InvalidCertificateIssuanceProfile
            | ResourceError::InvalidCertificateProfileScope
            | ResourceError::InvalidCertificateProfileState
            | ResourceError::InvalidCodeSignerScope
            | ResourceError::InvalidCodeSignerState
            | ResourceError::InvalidCodeSignerCertificateState
            | ResourceError::MissingCodeSignerCertificatePrivateKey
            | ResourceError::InvalidSshCertificateAuthorityScope
            | ResourceError::InvalidSshCertificateAuthorityState
            | ResourceError::InvalidSshCertificateTemplateScope
            | ResourceError::InvalidSshCertificateTemplateState
            | ResourceError::SshCertificateTypeNotAllowed
            | ResourceError::SshCertificatePrincipalNotAllowed
            | ResourceError::SshCertificateTtlNotAllowed
            | ResourceError::SshCertificateCustomKeyIdNotAllowed
            | ResourceError::InvalidSshHostScope
            | ResourceError::InvalidSshHostGroupScope => Self::new(
                Category::Validation,
                Effect::Unknown,
                Recovery::CorrectRequest,
                error.to_string(),
            ),
            ResourceError::CertificateIssuanceResponseUnverified { .. }
            | ResourceError::CollectionTooLarge
            | ResourceError::CollectionCountMismatch
            | ResourceError::InvalidProjectResponse
            | ResourceError::InvalidSecretResponse
            | ResourceError::InvalidSecretTagResponse
            | ResourceError::MissingMutationResource
            | ResourceError::InvalidRoleScope
            | ResourceError::MissingRolePermissions
            | ResourceError::InvalidGroupMembershipScope
            | ResourceError::InvalidGroupResponse
            | ResourceError::InvalidGroupProjectAssignment
            | ResourceError::InvalidAdditionalPrivilegeScope
            | ResourceError::InvalidAdditionalPrivilegeLifetime
            | ResourceError::InvalidAdditionalPrivilegePermissions
            | ResourceError::InvalidAuditLogResponse
            | ResourceError::InvalidAppAutomationResponse
            | ResourceError::InvalidDynamicSecretResponse
            | ResourceError::InvalidDynamicSecretLeaseResponse
            | ResourceError::InvalidKmsResponse
            | ResourceError::InvalidCertificateAuthorityResponse
            | ResourceError::InvalidCertificatePolicyResponse
            | ResourceError::InvalidCertificateInventoryResponse
            | ResourceError::InvalidCertificateMaterialResponse
            | ResourceError::CertificateImportOutcomeUnknown
            | ResourceError::InvalidCertificateLifecycleResponse
            | ResourceError::CertificateRenewalOutcomeUnknown
            | ResourceError::CertificateRevocationOutcomeUnknown
            | ResourceError::CertificateRenewalConfigurationOutcomeUnknown
            | ResourceError::CertificateDeletionOutcomeUnknown
            | ResourceError::InvalidCertificateRequestInventoryResponse
            | ResourceError::InvalidCertificateRequestMaterialResponse
            | ResourceError::InvalidCertificateRequestCancellationResponse
            | ResourceError::InvalidCertificateIssuanceResponse
            | ResourceError::CertificateIssuanceOutcomeUnknown
            | ResourceError::InvalidCertificateProfileResponse
            | ResourceError::InvalidCodeSignerResponse
            | ResourceError::InvalidCodeSignerGovernanceResponse
            | ResourceError::InvalidSshCertificateAuthorityResponse
            | ResourceError::InvalidSshCertificateTemplateResponse
            | ResourceError::InvalidSshCertificateResponse
            | ResourceError::InvalidSshHostResponse
            | ResourceError::InvalidSshHostGroupResponse
            | ResourceError::InvalidSshHostGroupMembershipResponse => Self::new(
                Category::ResponseValidation,
                Effect::Unknown,
                Recovery::Reconcile,
                error.to_string(),
            ),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use infisical_api::TransportErrorKind;

    fn value(error: ExecutionError) -> serde_json::Value {
        let result = name_error("kms.keys.privateKeys.bulkReveal", error.into_result());
        assert_eq!(result.is_error, Some(true));
        let wire = serde_json::to_value(result).unwrap();
        let compatibility: serde_json::Value =
            serde_json::from_str(wire["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(compatibility, wire["structuredContent"]);
        assert_eq!(
            compatibility["error"]["operation"],
            "kms.keys.privateKeys.bulkReveal"
        );
        compatibility["error"].clone()
    }

    #[test]
    fn failed_preflight_and_uncertain_final_request_have_different_effects() {
        let transport = ClientError::Transport(TransportErrorKind::Timeout);
        let final_request = value(ExecutionError::from_client(&transport));
        assert_eq!(final_request["effect"], "unknown");
        assert_eq!(final_request["recovery"], "reconcile");
        assert!(final_request.get("preflightObservationsPossible").is_none());
        let preflight = value(ExecutionError::from_resource(
            &ResourceError::KmsBulkPreflightFailed {
                validated: 1,
                requested: 2,
                source: Box::new(ResourceError::Client(transport)),
            },
        ));
        assert_eq!(preflight["effect"], "notStarted");
        assert_eq!(preflight["preflightObservationsPossible"], true);
    }

    #[test]
    fn cooldown_retains_bounded_wait_without_promising_absence_of_earlier_effects() {
        let cooldown = value(ExecutionError::from_client(
            &ClientError::AuthenticationCooldown {
                failure: Box::new(ClientError::RefreshInterrupted),
                retry_after_seconds: 900,
            },
        ));
        assert_eq!(cooldown["category"], "authentication");
        assert_eq!(cooldown["recovery"], "wait");
        assert_eq!(cooldown["retryAfterSeconds"], 300);
        assert_eq!(cooldown["effect"], "unknown");
    }

    #[test]
    fn capacity_reservation_failure_precedes_the_final_action() {
        let capacity = value(ExecutionError::from_handler(capacity_before_execution(
            &crate::files::FileError::TooManyStaged { staged: 64 },
        )));
        assert_eq!(capacity["category"], "capacity");
        assert_eq!(capacity["effect"], "notStarted");
        assert_eq!(capacity["recovery"], "wait");
        assert_eq!(capacity["preflightObservationsPossible"], false);
        let budget = value(ExecutionError::from_client(
            &ClientError::WorkBudgetExhausted,
        ));
        assert_eq!(budget["effect"], "unknown");
    }
}
