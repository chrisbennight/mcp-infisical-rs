use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    InfisicalClient, Page, PageRequest, ProjectId, ReadOperation, ResourceError,
    client::{ApiVersion, Endpoint, sealed},
    resources::paginate,
};

const MAX_ROLE_SLUG_BYTES: usize = 128;

/// Scope that owns a role definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RoleScope {
    /// Role applies across one organization.
    Organization,
    /// Role applies within one project.
    Project,
}

/// One normalized permission rule returned by Infisical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolePermission {
    /// Resource family constrained by the rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Allowed or denied actions in the rule.
    pub action: Vec<String>,
    /// Optional upstream condition expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Value>,
    /// Whether the rule denies rather than grants its actions.
    #[serde(default)]
    pub inverted: bool,
}

/// Stable role metadata without permissions or Infisical's synthetic IDs and timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoleSummary {
    /// Human-readable role name.
    pub name: String,
    /// Stable built-in or custom role slug.
    pub slug: String,
    /// Optional role description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Scope that owns the role.
    pub scope: RoleScope,
    /// Opaque organization or project identifier that owns the role.
    pub scope_id: String,
    /// Whether Infisical supplies this role without custom RBAC.
    pub built_in: bool,
}

/// Exact role metadata with normalized permission rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    /// Stable role summary shared with list results.
    #[serde(flatten)]
    pub summary: RoleSummary,
    /// Complete normalized permission rules returned by the exact-slug route.
    pub permissions: Vec<RolePermission>,
}

/// Validated organization or project role slug.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct RoleSlug(String);

impl RoleSlug {
    /// Validate a role slug accepted by the pinned read routes.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, padded, or non-canonical slugs.
    pub fn new(value: impl Into<String>) -> Result<Self, RoleInputError> {
        let value = value.into();
        let bytes = value.as_bytes();
        if value.is_empty()
            || value.len() > MAX_ROLE_SLUG_BYTES
            || value.trim() != value
            || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || bytes
                .windows(2)
                .any(|pair| matches!(pair[0], b'-' | b'_') && matches!(pair[1], b'-' | b'_'))
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
        {
            return Err(RoleInputError::InvalidSlug);
        }
        Ok(Self(value))
    }

    /// Borrow the validated slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validation failures for role discovery inputs.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RoleInputError {
    /// Role slug is outside the pinned route's safe input subset.
    #[error(
        "role slug must contain 1 to 128 lowercase ASCII letters or numbers separated by single hyphens or underscores"
    )]
    InvalidSlug,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamRole {
    name: String,
    slug: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    permissions: Option<Vec<RolePermission>>,
}

impl UpstreamRole {
    fn into_project_summary(
        self,
        expected_project_id: &ProjectId,
    ) -> Result<RoleSummary, ResourceError> {
        let scope_id = self
            .project_id
            .filter(|project_id| project_id == expected_project_id.as_str())
            .ok_or(ResourceError::InvalidRoleScope)?;
        Ok(RoleSummary {
            built_in: is_builtin_project_role(&self.slug),
            name: self.name,
            slug: self.slug,
            description: self.description,
            scope: RoleScope::Project,
            scope_id,
        })
    }

    fn into_project(mut self, expected_project_id: &ProjectId) -> Result<Role, ResourceError> {
        let permissions = self
            .permissions
            .take()
            .ok_or(ResourceError::MissingRolePermissions)?;
        Ok(Role {
            summary: self.into_project_summary(expected_project_id)?,
            permissions,
        })
    }

    fn into_organization_summary(self) -> Result<RoleSummary, ResourceError> {
        let scope_id = self.org_id.ok_or(ResourceError::InvalidRoleScope)?;
        Ok(RoleSummary {
            built_in: is_builtin_organization_role(&self.slug),
            name: self.name,
            slug: self.slug,
            description: self.description,
            scope: RoleScope::Organization,
            scope_id,
        })
    }

    fn into_organization(mut self) -> Result<Role, ResourceError> {
        let permissions = self
            .permissions
            .take()
            .ok_or(ResourceError::MissingRolePermissions)?;
        Ok(Role {
            summary: self.into_organization_summary()?,
            permissions,
        })
    }
}

fn is_builtin_project_role(slug: &str) -> bool {
    matches!(
        slug,
        "admin"
            | "member"
            | "viewer"
            | "no-access"
            | "ssh-host-bootstrapper"
            | "cryptographic-operator"
    )
}

fn is_builtin_organization_role(slug: &str) -> bool {
    matches!(slug, "admin" | "member" | "no-access")
}

#[derive(Serialize)]
struct ProjectRolesQuery {
    #[serde(skip_serializing)]
    project_id: String,
}

#[derive(Deserialize)]
struct RolesResponse {
    roles: Vec<UpstreamRole>,
}

struct ListProjectRoles;

impl sealed::Sealed for ListProjectRoles {}

impl ReadOperation for ListProjectRoles {
    type Query = ProjectRolesQuery;
    type Output = RolesResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects".to_owned(),
                query.project_id.clone(),
                "roles".to_owned(),
            ],
        )
    }
}

#[derive(Serialize)]
struct ProjectRoleQuery {
    #[serde(skip_serializing)]
    project_id: String,
    #[serde(skip_serializing)]
    role_slug: String,
}

#[derive(Deserialize)]
struct RoleResponse {
    role: UpstreamRole,
}

struct GetProjectRole;

impl sealed::Sealed for GetProjectRole {}

impl ReadOperation for GetProjectRole {
    type Query = ProjectRoleQuery;
    type Output = RoleResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects".to_owned(),
                query.project_id.clone(),
                "roles".to_owned(),
                "slug".to_owned(),
                query.role_slug.clone(),
            ],
        )
    }
}

#[derive(Serialize)]
struct OrganizationRolesQuery;

struct ListOrganizationRoles;

impl sealed::Sealed for ListOrganizationRoles {}

impl ReadOperation for ListOrganizationRoles {
    type Query = OrganizationRolesQuery;
    type Output = RolesResponse;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "organization/roles")
    }
}

#[derive(Serialize)]
struct OrganizationRoleQuery {
    #[serde(skip_serializing)]
    role_slug: String,
}

struct GetOrganizationRole;

impl sealed::Sealed for GetOrganizationRole {}

impl ReadOperation for GetOrganizationRole {
    type Query = OrganizationRoleQuery;
    type Output = RoleResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "organization".to_owned(),
                "roles".to_owned(),
                "slug".to_owned(),
                query.role_slug.clone(),
            ],
        )
    }
}

impl InfisicalClient {
    /// List a locally bounded page of built-in and custom project roles.
    ///
    /// # Errors
    ///
    /// Returns a typed client, response-contract, or pagination error.
    pub async fn list_project_roles(
        &self,
        project_id: &ProjectId,
        page: PageRequest,
    ) -> Result<Page<RoleSummary>, ResourceError> {
        let response = self
            .execute_read::<ListProjectRoles>(&ProjectRolesQuery {
                project_id: project_id.as_str().to_owned(),
            })
            .await?;
        let roles = response
            .roles
            .into_iter()
            .map(|role| role.into_project_summary(project_id))
            .collect::<Result<Vec<_>, _>>()?;
        paginate(page, roles)
    }

    /// Get one project role by its stable slug, including normalized permissions.
    ///
    /// # Errors
    ///
    /// Returns a typed client or response-contract error.
    pub async fn get_project_role(
        &self,
        project_id: &ProjectId,
        role_slug: &RoleSlug,
    ) -> Result<Role, ResourceError> {
        self.execute_read::<GetProjectRole>(&ProjectRoleQuery {
            project_id: project_id.as_str().to_owned(),
            role_slug: role_slug.as_str().to_owned(),
        })
        .await?
        .role
        .into_project(project_id)
    }

    /// List a locally bounded page of built-in and custom organization roles.
    ///
    /// The pinned route derives the organization from the authenticated identity.
    ///
    /// # Errors
    ///
    /// Returns a typed client, response-contract, or pagination error.
    pub async fn list_organization_roles(
        &self,
        page: PageRequest,
    ) -> Result<Page<RoleSummary>, ResourceError> {
        let response = self
            .execute_read::<ListOrganizationRoles>(&OrganizationRolesQuery)
            .await?;
        let roles = response
            .roles
            .into_iter()
            .map(UpstreamRole::into_organization_summary)
            .collect::<Result<Vec<_>, _>>()?;
        paginate(page, roles)
    }

    /// Get one organization role by its stable slug, including normalized permissions.
    ///
    /// The pinned route derives the organization from the authenticated identity.
    ///
    /// # Errors
    ///
    /// Returns a typed client or response-contract error.
    pub async fn get_organization_role(&self, role_slug: &RoleSlug) -> Result<Role, ResourceError> {
        self.execute_read::<GetOrganizationRole>(&OrganizationRoleQuery {
            role_slug: role_slug.as_str().to_owned(),
        })
        .await?
        .role
        .into_organization()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::{
        RoleInputError, RolePermission, RoleScope, RoleSlug, UpstreamRole,
        is_builtin_organization_role, is_builtin_project_role,
    };
    use crate::{
        InfisicalClient, PageRequest, ProjectId, ResourceError,
        test_support::{mount_login, settings},
    };

    #[tokio::test]
    async fn role_discovery_follows_the_pinned_wire_contract_and_omits_synthetic_state() {
        let server = MockServer::start().await;
        mount_login(&server, "role-token").await;

        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1/roles"))
            .and(header("authorization", "Bearer role-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "roles": [
                    role_fixture("random-built-in-id", "Admin", "admin", "projectId", "project-1", false),
                    role_fixture("custom-id", "Deployer", "deployer", "projectId", "project-1", false)
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1/roles/slug/deployer"))
            .and(header("authorization", "Bearer role-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "role": role_fixture("custom-id", "Deployer", "deployer", "projectId", "project-1", true)
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organization/roles"))
            .and(header("authorization", "Bearer role-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "roles": [role_fixture("dummy-id", "No Access", "no-access", "orgId", "org-1", false)]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organization/roles/slug/auditor"))
            .and(header("authorization", "Bearer role-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "role": role_fixture("custom-org-id", "Auditor", "auditor", "orgId", "org-1", true)
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let project_roles = client
            .list_project_roles(&project_id, PageRequest::new(1, 1).unwrap())
            .await
            .unwrap();
        assert_eq!(project_roles.items[0].slug, "deployer");
        assert!(!project_roles.items[0].built_in);
        assert_eq!(project_roles.total, Some(2));
        assert_eq!(project_roles.next, None);

        let project_role = client
            .get_project_role(&project_id, &RoleSlug::new("deployer").unwrap())
            .await
            .unwrap();
        assert_eq!(project_role.summary.scope, RoleScope::Project);
        assert_eq!(project_role.summary.scope_id, "project-1");
        assert_eq!(project_role.permissions, expected_permissions());

        let organization_roles = client
            .list_organization_roles(PageRequest::new(0, 1).unwrap())
            .await
            .unwrap();
        assert!(organization_roles.items[0].built_in);
        assert_eq!(organization_roles.items[0].scope, RoleScope::Organization);

        let organization_role = client
            .get_organization_role(&RoleSlug::new("auditor").unwrap())
            .await
            .unwrap();
        assert!(!organization_role.summary.built_in);
        assert_eq!(organization_role.summary.scope_id, "org-1");
        assert_eq!(organization_role.permissions, expected_permissions());

        let serialized = serde_json::to_value(project_role).unwrap();
        assert!(serialized.get("id").is_none());
        assert!(serialized.get("createdAt").is_none());
        assert!(serialized.get("updatedAt").is_none());
    }

    #[test]
    fn role_slugs_reject_ambiguous_or_unbounded_inputs() {
        for invalid in [
            "",
            "Admin",
            " padded",
            "bad/slug",
            "-admin",
            "admin-",
            "bad--slug",
            "bad-_slug",
            &"a".repeat(129),
        ] {
            assert_eq!(RoleSlug::new(invalid), Err(RoleInputError::InvalidSlug));
        }
        assert_eq!(
            RoleSlug::new("release_manager").unwrap().as_str(),
            "release_manager"
        );
    }

    #[test]
    fn built_in_classification_matches_the_pinned_role_sets() {
        for slug in [
            "admin",
            "member",
            "viewer",
            "no-access",
            "ssh-host-bootstrapper",
            "cryptographic-operator",
        ] {
            assert!(is_builtin_project_role(slug), "{slug}");
        }
        assert!(!is_builtin_project_role("deployer"));

        for slug in ["admin", "member", "no-access"] {
            assert!(is_builtin_organization_role(slug), "{slug}");
        }
        assert!(!is_builtin_organization_role("auditor"));
        assert!(!is_builtin_organization_role("viewer"));
    }

    #[test]
    fn role_mapping_rejects_missing_or_mismatched_owning_scope() {
        let project_id = ProjectId::new("project-1").unwrap();
        assert_eq!(
            upstream_role(Some("project-2"), None).into_project_summary(&project_id),
            Err(ResourceError::InvalidRoleScope)
        );
        assert_eq!(
            upstream_role(None, None).into_organization_summary(),
            Err(ResourceError::InvalidRoleScope)
        );
        assert_eq!(
            upstream_role(None, Some("org-1")).into_organization(),
            Err(ResourceError::MissingRolePermissions)
        );
    }

    fn upstream_role(project_id: Option<&str>, org_id: Option<&str>) -> UpstreamRole {
        UpstreamRole {
            name: "Role".into(),
            slug: "role".into(),
            description: None,
            project_id: project_id.map(str::to_owned),
            org_id: org_id.map(str::to_owned),
            permissions: None,
        }
    }

    fn role_fixture(
        id: &str,
        name: &str,
        slug: &str,
        scope_key: &str,
        scope_id: &str,
        include_permissions: bool,
    ) -> serde_json::Value {
        let mut role = json!({
            "id": id,
            "name": name,
            "slug": slug,
            "description": null,
            "createdAt": "2026-01-01T00:00:00.000Z",
            "updatedAt": "2026-01-01T00:00:00.000Z"
        });
        role[scope_key] = json!(scope_id);
        if include_permissions {
            role["permissions"] = json!([{
                "subject": "secrets",
                "action": ["read"],
                "conditions": { "environment": "prod" },
                "inverted": false
            }]);
        }
        role
    }

    fn expected_permissions() -> Vec<RolePermission> {
        vec![RolePermission {
            subject: Some("secrets".into()),
            action: vec!["read".into()],
            conditions: Some(json!({ "environment": "prod" })),
            inverted: false,
        }]
    }
}
