//! Pagination facts verified against the pinned API clients.

use schemars::JsonSchema;
use serde::Serialize;

/// nativeUpstream sends page coordinates; localSlice refetches all records; boundedUnpaged has no pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) enum PaginationKind {
    NativeUpstream,
    LocalSlice,
    BoundedUnpaged,
}

pub(crate) fn pagination(name: &str) -> Option<PaginationKind> {
    use PaginationKind::{BoundedUnpaged, LocalSlice, NativeUpstream};
    Some(match name {
        "projects.list"
        | "environments.list"
        | "folders.list"
        | "tags.list"
        | "identities.list"
        | "projectUserMemberships.list"
        | "projectRoles.list"
        | "organizationRoles.list"
        | "groups.list"
        | "projectGroupMemberships.list"
        | "identityProjectAdditionalPrivileges.list"
        | "identityUniversalAuth.clientSecrets.list"
        | "secrets.metadata.list"
        | "secretImports.list"
        | "appConnections.list"
        | "secretSyncs.list"
        | "secretRotations.list"
        | "dynamicSecrets.list"
        | "dynamicSecretLeases.list" => LocalSlice,
        "projectIdentityMemberships.list"
        | "groups.members.list"
        | "groups.projects.list"
        | "identityTokenAuth.tokens.list"
        | "auditLogs.list"
        | "certificates.list"
        | "certificateRequests.list"
        | "certificatePolicies.list"
        | "certificateProfiles.list"
        | "certificateProfiles.certificates.list"
        | "codeSigners.list"
        | "codeSigners.approvalRequests.list"
        | "codeSigners.operations.list"
        | "kms.keys.list" => NativeUpstream,
        "certificateAuthorities.list"
        | "certificateAuthorities.internal.list"
        | "certificateAuthorities.internal.certificates.list"
        | "certificateAuthorities.internal.crls.list"
        | "sshCertificateAuthorities.list"
        | "sshCertificateTemplates.list"
        | "sshCertificateAuthorities.templates.list"
        | "codeSigners.members.list"
        | "codeSigners.effectiveMembers.list"
        | "kms.keys.signingAlgorithms.list"
        | "sshHosts.list"
        | "sshHostGroups.list"
        | "sshHostGroups.hosts.list" => BoundedUnpaged,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_served_list_has_reviewed_pagination_facts() {
        for operation in crate::tools::operations() {
            let kind = pagination(&operation.tool.name);
            assert_eq!(
                kind.is_some(),
                operation.tool.name.ends_with(".list"),
                "{}",
                operation.tool.name
            );
            if matches!(
                kind,
                Some(PaginationKind::LocalSlice | PaginationKind::NativeUpstream)
            ) {
                assert!(
                    operation.tool.input_schema["properties"]
                        .get("limit")
                        .is_some(),
                    "{}",
                    operation.tool.name
                );
            }
        }
        assert_eq!(
            pagination("projects.list"),
            Some(PaginationKind::LocalSlice)
        );
        assert_eq!(
            pagination("kms.keys.list"),
            Some(PaginationKind::NativeUpstream)
        );
        assert_eq!(
            pagination("sshHosts.list"),
            Some(PaginationKind::BoundedUnpaged)
        );
    }
}
