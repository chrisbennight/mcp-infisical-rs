use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    IdentityId, IdentityName, InfisicalClient, MutationOperation, OrganizationId, Page,
    PageRequest, ReadOperation, ResourceError,
    client::{ApiVersion, Endpoint, sealed},
    resources::paginate,
};

/// Built-in organization role assignable without enterprise custom RBAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OrganizationRole {
    /// Full organization administration.
    Admin,
    /// Ordinary organization membership.
    Member,
    /// Identity exists but receives no organization access.
    NoAccess,
}

/// Concise, non-secret machine-identity metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineIdentity {
    /// Opaque identity identifier.
    pub id: String,
    /// Identity display name.
    pub name: String,
    /// Owning organization identifier.
    pub organization_id: String,
    /// Optional legacy project association.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Whether Infisical prevents deletion.
    pub has_delete_protection: bool,
    /// Configured authentication method names; no credentials are returned.
    pub auth_methods: Vec<String>,
    /// Organization membership identifier when returned by a membership read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_membership_id: Option<String>,
    /// Organization role slug, including existing custom roles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_role: Option<String>,
    /// Custom organization-role identifier when one is already assigned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_role_id: Option<String>,
}

/// Validated settings for a machine identity creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCreation {
    /// Identity display name.
    pub name: IdentityName,
    /// Organization that owns the identity.
    pub organization_id: OrganizationId,
    /// Initial built-in organization role.
    pub role: OrganizationRole,
    /// Whether Infisical prevents accidental deletion.
    pub has_delete_protection: bool,
}

/// One atomic machine-identity metadata change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityChange {
    /// Replace the display name.
    Name(IdentityName),
    /// Assign one built-in organization role.
    Role(OrganizationRole),
    /// Enable or disable delete protection.
    DeleteProtection(bool),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectIdentity {
    id: String,
    name: String,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    has_delete_protection: bool,
    #[serde(default)]
    auth_methods: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityMembership {
    id: String,
    role: String,
    #[serde(default)]
    role_id: Option<String>,
    org_id: String,
    identity: DirectIdentity,
}

impl TryFrom<DirectIdentity> for MachineIdentity {
    type Error = ResourceError;

    fn try_from(identity: DirectIdentity) -> Result<Self, Self::Error> {
        Ok(Self {
            id: identity.id,
            name: identity.name,
            organization_id: identity
                .org_id
                .ok_or(ResourceError::MissingMutationResource)?,
            project_id: identity.project_id,
            has_delete_protection: identity.has_delete_protection,
            auth_methods: identity.auth_methods,
            organization_membership_id: None,
            organization_role: None,
            organization_role_id: None,
        })
    }
}

impl From<IdentityMembership> for MachineIdentity {
    fn from(membership: IdentityMembership) -> Self {
        let identity = membership.identity;
        Self {
            id: identity.id,
            name: identity.name,
            organization_id: membership.org_id,
            project_id: identity.project_id,
            has_delete_protection: identity.has_delete_protection,
            auth_methods: identity.auth_methods,
            organization_membership_id: Some(membership.id),
            organization_role: Some(membership.role),
            organization_role_id: membership.role_id,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListIdentitiesQuery {
    org_id: OrganizationId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListIdentitiesResponse {
    identities: Vec<IdentityMembership>,
    total_count: u64,
}

#[derive(Serialize)]
struct GetIdentityQuery {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
}

#[derive(Deserialize)]
struct MembershipResponse {
    identity: IdentityMembership,
}

#[derive(Deserialize)]
struct DirectIdentityResponse {
    identity: DirectIdentity,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateIdentityRequest {
    name: String,
    organization_id: OrganizationId,
    role: OrganizationRole,
    has_delete_protection: bool,
}

impl From<IdentityCreation> for CreateIdentityRequest {
    fn from(creation: IdentityCreation) -> Self {
        Self {
            name: creation.name.as_str().to_owned(),
            organization_id: creation.organization_id,
            role: creation.role,
            has_delete_protection: creation.has_delete_protection,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateIdentityRequest {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<OrganizationRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    has_delete_protection: Option<bool>,
}

impl UpdateIdentityRequest {
    fn change(identity_id: &IdentityId, change: IdentityChange) -> Self {
        let mut request = Self {
            identity_id: identity_id.clone(),
            name: None,
            role: None,
            has_delete_protection: None,
        };
        match change {
            IdentityChange::Name(name) => request.name = Some(name.as_str().to_owned()),
            IdentityChange::Role(role) => request.role = Some(role),
            IdentityChange::DeleteProtection(enabled) => {
                request.has_delete_protection = Some(enabled);
            }
        }
        request
    }
}

#[derive(Serialize)]
struct DeleteIdentityRequest {
    #[serde(skip_serializing)]
    identity_id: IdentityId,
}

struct ListIdentities;

impl sealed::Sealed for ListIdentities {}

impl ReadOperation for ListIdentities {
    type Query = ListIdentitiesQuery;
    type Output = ListIdentitiesResponse;

    fn endpoint(_: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "identities")
    }
}

struct GetIdentity;

impl sealed::Sealed for GetIdentity {}

impl ReadOperation for GetIdentity {
    type Query = GetIdentityQuery;
    type Output = MembershipResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["identities", query.identity_id.as_str()])
    }
}

struct CreateIdentity;

impl sealed::Sealed for CreateIdentity {}

impl MutationOperation for CreateIdentity {
    type Input = CreateIdentityRequest;
    type Output = DirectIdentityResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_: &Self::Input) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "identities")
    }
}

struct UpdateIdentity;

impl sealed::Sealed for UpdateIdentity {}

impl MutationOperation for UpdateIdentity {
    type Input = UpdateIdentityRequest;
    type Output = DirectIdentityResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["identities", input.identity_id.as_str()])
    }
}

struct DeleteIdentity;

impl sealed::Sealed for DeleteIdentity {}

impl MutationOperation for DeleteIdentity {
    type Input = DeleteIdentityRequest;
    type Output = DirectIdentityResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["identities", input.identity_id.as_str()])
    }
}

impl InfisicalClient {
    /// List a bounded local page of machine identities for one organization.
    ///
    /// Infisical's pinned endpoint returns the complete organization collection;
    /// the HTTP response-size limit and local paginator bound its exposure here.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_identities(
        &self,
        organization_id: OrganizationId,
        page: PageRequest,
    ) -> Result<Page<MachineIdentity>, ResourceError> {
        let response = self
            .execute_read::<ListIdentities>(&ListIdentitiesQuery {
                org_id: organization_id,
            })
            .await?;
        let identities: Vec<MachineIdentity> = response
            .identities
            .into_iter()
            .map(MachineIdentity::from)
            .collect();
        let returned_count =
            u64::try_from(identities.len()).map_err(|_| ResourceError::CollectionTooLarge)?;
        if returned_count != response.total_count {
            return Err(ResourceError::CollectionCountMismatch);
        }
        paginate(page, identities)
    }

    /// Get one exact machine identity with its organization membership.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_identity(
        &self,
        identity_id: &IdentityId,
    ) -> Result<MachineIdentity, ResourceError> {
        let response = self
            .execute_read::<GetIdentity>(&GetIdentityQuery {
                identity_id: identity_id.clone(),
            })
            .await?;
        Ok(response.identity.into())
    }

    /// Create one machine identity with a built-in organization role.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn create_identity(
        &self,
        creation: IdentityCreation,
    ) -> Result<MachineIdentity, ResourceError> {
        let response = self
            .execute_mutation::<CreateIdentity>(&creation.into())
            .await?;
        response.identity.try_into()
    }

    /// Apply one exact machine-identity metadata change.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn update_identity(
        &self,
        identity_id: &IdentityId,
        change: IdentityChange,
    ) -> Result<MachineIdentity, ResourceError> {
        let response = self
            .execute_mutation::<UpdateIdentity>(&UpdateIdentityRequest::change(identity_id, change))
            .await?;
        response.identity.try_into()
    }

    /// Delete one exact machine identity after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn delete_identity(
        &self,
        identity_id: &IdentityId,
        confirm: bool,
    ) -> Result<MachineIdentity, ResourceError> {
        if !confirm {
            return Err(ResourceError::IdentityDeletionNotConfirmed);
        }
        let response = self
            .execute_mutation::<DeleteIdentity>(&DeleteIdentityRequest {
                identity_id: identity_id.clone(),
            })
            .await?;
        response.identity.try_into()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path, query_param},
    };

    use crate::{
        IdentityChange, IdentityCreation, IdentityId, IdentityName, InfisicalClient,
        OrganizationId, OrganizationRole, PageRequest, ResourceError,
        test_support::{mount_login, settings},
    };

    fn direct_identity(name: &str, protected: bool) -> serde_json::Value {
        json!({
            "id": "identity-1",
            "name": name,
            "orgId": "org-1",
            "projectId": null,
            "hasDeleteProtection": protected,
            "authMethods": ["universal-auth"]
        })
    }

    fn membership(id: &str, name: &str, role: &str) -> serde_json::Value {
        json!({
            "id": format!("membership-{id}"),
            "role": role,
            "roleId": null,
            "orgId": "org-1",
            "identityId": id,
            "identity": {
                "id": id,
                "name": name,
                "hasDeleteProtection": true,
                "authMethods": ["universal-auth"]
            }
        })
    }

    #[tokio::test]
    async fn identity_reads_use_exact_v1_contracts_and_bound_the_list_locally() {
        let server = MockServer::start().await;
        mount_login(&server, "identity-read-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/identities"))
            .and(query_param("orgId", "org-1"))
            .and(header("authorization", "Bearer identity-read-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identities": [
                    membership("identity-1", "agent-one", "no-access"),
                    membership("identity-2", "agent-two", "custom")
                ],
                "totalCount": 2
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/identities/identity-2"))
            .and(header("authorization", "Bearer identity-read-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identity": membership("identity-2", "agent-two", "custom")
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let page = client
            .list_identities(
                OrganizationId::new("org-1").unwrap(),
                PageRequest::new(1, 1).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.items[0].id, "identity-2");
        assert_eq!(page.items[0].organization_role.as_deref(), Some("custom"));
        assert_eq!(page.total, Some(2));
        let identity = client
            .get_identity(&IdentityId::new("identity-2").unwrap())
            .await
            .unwrap();
        assert_eq!(
            identity.organization_membership_id.as_deref(),
            Some("membership-identity-2")
        );
    }

    #[tokio::test]
    async fn identity_mutations_send_one_narrow_request_each() {
        let server = MockServer::start().await;
        mount_login(&server, "identity-admin-token").await;
        for (method_name, body, response_name, protected) in [
            (
                "POST",
                json!({
                    "name": "agent-one",
                    "organizationId": "org-1",
                    "role": "no-access",
                    "hasDeleteProtection": true
                }),
                "agent-one",
                true,
            ),
            (
                "PATCH",
                json!({ "name": "agent-renamed" }),
                "agent-renamed",
                true,
            ),
            ("PATCH", json!({ "role": "member" }), "agent-renamed", true),
            (
                "PATCH",
                json!({ "hasDeleteProtection": false }),
                "agent-renamed",
                false,
            ),
            ("DELETE", json!({}), "agent-renamed", false),
        ] {
            let route = if method_name == "POST" {
                "/api/v1/identities"
            } else {
                "/api/v1/identities/identity-1"
            };
            Mock::given(method(method_name))
                .and(path(route))
                .and(header("authorization", "Bearer identity-admin-token"))
                .and(body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "identity": direct_identity(response_name, protected)
                })))
                .expect(1)
                .mount(&server)
                .await;
        }

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let identity_id = IdentityId::new("identity-1").unwrap();
        client
            .create_identity(IdentityCreation {
                name: IdentityName::new("agent-one").unwrap(),
                organization_id: OrganizationId::new("org-1").unwrap(),
                role: OrganizationRole::NoAccess,
                has_delete_protection: true,
            })
            .await
            .unwrap();
        client
            .update_identity(
                &identity_id,
                IdentityChange::Name(IdentityName::new("agent-renamed").unwrap()),
            )
            .await
            .unwrap();
        client
            .update_identity(&identity_id, IdentityChange::Role(OrganizationRole::Member))
            .await
            .unwrap();
        client
            .update_identity(&identity_id, IdentityChange::DeleteProtection(false))
            .await
            .unwrap();
        client.delete_identity(&identity_id, true).await.unwrap();
    }

    #[tokio::test]
    async fn unconfirmed_identity_delete_fails_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert_eq!(
            client
                .delete_identity(&IdentityId::new("identity-1").unwrap(), false)
                .await
                .unwrap_err(),
            ResourceError::IdentityDeletionNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
