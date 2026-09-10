use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    GroupId, InfisicalClient, Page, PageRequest, ProjectId, ProjectMembershipRole, ReadOperation,
    ResourceError,
    client::{ApiVersion, Endpoint, sealed},
    resources::paginate,
};

/// One organization group and its organization-level role assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    /// Opaque group identifier.
    pub id: String,
    /// Opaque owning organization identifier.
    pub org_id: String,
    /// Human-readable group name.
    pub name: String,
    /// Stable group slug.
    pub slug: String,
    /// Built-in or custom organization-role slug.
    pub role: String,
    /// Role-assignment identifier when returned by Infisical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_id: Option<String>,
    /// Custom organization-role slug when the group uses one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_role_slug: Option<String>,
    /// Creation timestamp returned by Infisical.
    pub created_at: String,
    /// Last-update timestamp returned by Infisical.
    pub updated_at: String,
}

/// Non-secret human-user metadata embedded in a group membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupUser {
    /// Opaque user identifier.
    pub id: String,
    /// Optional first name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// Optional last name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// Optional email address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Stable username.
    pub username: String,
}

/// One principal assigned to an organization group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum GroupMember {
    /// Human user assigned to the group.
    #[serde(rename = "user", rename_all = "camelCase")]
    User {
        /// Opaque user identifier repeated by the pinned response.
        id: String,
        /// Timestamp when the user joined the group.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        joined_group_at: Option<String>,
        /// Sanitized user metadata.
        user: GroupUser,
    },
    /// Machine identity assigned to the group.
    #[serde(rename = "machineIdentity", rename_all = "camelCase")]
    MachineIdentity {
        /// Opaque identity identifier repeated by the pinned response.
        id: String,
        /// Timestamp when the identity joined the group.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        joined_group_at: Option<String>,
        /// Minimal non-secret identity metadata.
        machine_identity: GroupIdentity,
    },
}

/// Minimal non-secret machine-identity metadata embedded in a group membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GroupIdentity {
    /// Opaque machine-identity identifier.
    pub id: String,
    /// Machine-identity display name.
    pub name: String,
}

/// Principal type selected by a group-member listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum GroupMemberTypeFilter {
    /// Return both human users and machine identities.
    All,
    /// Return human users only.
    Users,
    /// Return machine identities only.
    MachineIdentities,
}

impl GroupMemberTypeFilter {
    fn upstream(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Users => Some("users"),
            Self::MachineIdentities => Some("machineIdentities"),
        }
    }

    fn accepts(self, member: &GroupMember) -> bool {
        match self {
            Self::All => true,
            Self::Users => matches!(member, GroupMember::User { .. }),
            Self::MachineIdentities => matches!(member, GroupMember::MachineIdentity { .. }),
        }
    }
}

/// Assignment state selected by a group-project listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum GroupProjectFilter {
    /// Return both assigned and unassigned organization projects.
    All,
    /// Return projects currently assigned to the group.
    Assigned,
    /// Return projects not assigned to the group.
    Unassigned,
}

impl GroupProjectFilter {
    fn upstream(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Assigned => Some("assignedProjects"),
            Self::Unassigned => Some("unassignedProjects"),
        }
    }

    fn accepts(self, project: &GroupProject) -> bool {
        match self {
            Self::All => true,
            Self::Assigned => project.joined_group_at.is_some(),
            Self::Unassigned => project.joined_group_at.is_none(),
        }
    }
}

/// One organization project and its assignment state for a group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupProject {
    /// Opaque project identifier.
    pub id: String,
    /// Human-readable project name.
    pub name: String,
    /// Stable project slug.
    pub slug: String,
    /// Optional project description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Infisical project family.
    #[serde(rename = "type")]
    pub project_type: String,
    /// Timestamp when the group joined the project; null means unassigned.
    #[serde(default)]
    pub joined_group_at: Option<String>,
}

/// Minimal organization-group metadata embedded in a project membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupReference {
    /// Opaque group identifier.
    pub id: String,
    /// Human-readable group name.
    pub name: String,
    /// Stable group slug.
    pub slug: String,
    /// Owning organization identifier when returned by Infisical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

/// One organization's group membership and role assignments in a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectGroupMembership {
    /// Opaque project-membership identifier.
    pub id: String,
    /// Opaque group identifier.
    pub group_id: String,
    /// Opaque project identifier.
    pub project_id: String,
    /// Group metadata embedded by Infisical.
    pub group: GroupReference,
    /// Complete current project-role assignments.
    pub roles: Vec<ProjectMembershipRole>,
    /// Creation timestamp returned by Infisical.
    pub created_at: String,
    /// Last-update timestamp returned by Infisical.
    pub updated_at: String,
}

#[derive(Serialize)]
struct EmptyQuery;

struct ListGroups;

impl sealed::Sealed for ListGroups {}

impl ReadOperation for ListGroups {
    type Query = EmptyQuery;
    type Output = Vec<Group>;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "groups")
    }
}

#[derive(Serialize)]
struct GroupQuery {
    #[serde(skip_serializing)]
    group_id: String,
}

struct GetGroup;

impl sealed::Sealed for GetGroup {}

impl ReadOperation for GetGroup {
    type Query = GroupQuery;
    type Output = Group;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["groups".to_owned(), query.group_id.clone()],
        )
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupMembersQuery {
    #[serde(skip_serializing)]
    group_id: String,
    offset: u32,
    limit: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    member_type_filter: Option<&'static str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupMembersResponse {
    members: Vec<GroupMember>,
    total_count: u64,
}

struct ListGroupMembers;

impl sealed::Sealed for ListGroupMembers {}

impl ReadOperation for ListGroupMembers {
    type Query = GroupMembersQuery;
    type Output = GroupMembersResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "groups".to_owned(),
                query.group_id.clone(),
                "members".to_owned(),
            ],
        )
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupProjectsQuery {
    #[serde(skip_serializing)]
    group_id: String,
    offset: u32,
    limit: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<&'static str>,
    order_by: &'static str,
    order_direction: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupProjectsResponse {
    projects: Vec<GroupProject>,
    total_count: u64,
}

struct ListGroupProjects;

impl sealed::Sealed for ListGroupProjects {}

impl ReadOperation for ListGroupProjects {
    type Query = GroupProjectsQuery;
    type Output = GroupProjectsResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "groups".to_owned(),
                query.group_id.clone(),
                "projects".to_owned(),
            ],
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectGroupMembershipsResponse {
    group_memberships: Vec<ProjectGroupMembership>,
}

#[derive(Serialize)]
struct ProjectGroupMembershipsQuery {
    #[serde(skip_serializing)]
    project_id: String,
}

struct ListProjectGroupMemberships;

impl sealed::Sealed for ListProjectGroupMemberships {}

impl ReadOperation for ListProjectGroupMemberships {
    type Query = ProjectGroupMembershipsQuery;
    type Output = ProjectGroupMembershipsResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects".to_owned(),
                query.project_id.clone(),
                "memberships".to_owned(),
                "groups".to_owned(),
            ],
        )
    }
}

#[derive(Serialize)]
struct ProjectGroupMembershipQuery {
    #[serde(skip_serializing)]
    project_id: String,
    #[serde(skip_serializing)]
    group_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectGroupMembershipResponse {
    group_membership: ProjectGroupMembership,
}

struct GetProjectGroupMembership;

impl sealed::Sealed for GetProjectGroupMembership {}

impl ReadOperation for GetProjectGroupMembership {
    type Query = ProjectGroupMembershipQuery;
    type Output = ProjectGroupMembershipResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects".to_owned(),
                query.project_id.clone(),
                "memberships".to_owned(),
                "groups".to_owned(),
                query.group_id.clone(),
            ],
        )
    }
}

fn validate_membership_scope(
    membership: &ProjectGroupMembership,
    project_id: &ProjectId,
    group_id: Option<&GroupId>,
) -> Result<(), ResourceError> {
    if membership.project_id != project_id.as_str()
        || membership.group_id != membership.group.id
        || group_id.is_some_and(|group_id| membership.group_id != group_id.as_str())
    {
        return Err(ResourceError::InvalidGroupMembershipScope);
    }
    Ok(())
}

impl InfisicalClient {
    /// List a locally bounded page of organization groups.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_groups(&self, page: PageRequest) -> Result<Page<Group>, ResourceError> {
        let groups = self.execute_read::<ListGroups>(&EmptyQuery).await?;
        paginate(page, groups)
    }

    /// Get one organization group by exact identifier.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_group(&self, group_id: &GroupId) -> Result<Group, ResourceError> {
        let group = self
            .execute_read::<GetGroup>(&GroupQuery {
                group_id: group_id.as_str().to_owned(),
            })
            .await?;
        if group.id != group_id.as_str() {
            return Err(ResourceError::InvalidGroupResponse);
        }
        Ok(group)
    }

    /// List one bounded upstream page of principals assigned to a group.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_group_members(
        &self,
        group_id: &GroupId,
        member_type: GroupMemberTypeFilter,
        page: PageRequest,
    ) -> Result<Page<GroupMember>, ResourceError> {
        let response = self
            .execute_read::<ListGroupMembers>(&GroupMembersQuery {
                group_id: group_id.as_str().to_owned(),
                offset: page.offset(),
                limit: page.limit(),
                member_type_filter: member_type.upstream(),
            })
            .await?;
        if response.members.iter().any(|member| {
            !member_type.accepts(member)
                || match member {
                    GroupMember::User { id, user, .. } => id != &user.id,
                    GroupMember::MachineIdentity {
                        id,
                        machine_identity,
                        ..
                    } => id != &machine_identity.id,
                }
        }) {
            return Err(ResourceError::InvalidGroupResponse);
        }
        Ok(Page::new(
            page,
            response.members,
            Some(response.total_count),
        )?)
    }

    /// List one bounded upstream page of organization projects and group assignment state.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_group_projects(
        &self,
        group_id: &GroupId,
        filter: GroupProjectFilter,
        page: PageRequest,
    ) -> Result<Page<GroupProject>, ResourceError> {
        let response = self
            .execute_read::<ListGroupProjects>(&GroupProjectsQuery {
                group_id: group_id.as_str().to_owned(),
                offset: page.offset(),
                limit: page.limit(),
                filter: filter.upstream(),
                order_by: "name",
                order_direction: "asc",
            })
            .await?;
        if response
            .projects
            .iter()
            .any(|project| !filter.accepts(project))
        {
            return Err(ResourceError::InvalidGroupProjectAssignment);
        }
        Ok(Page::new(
            page,
            response.projects,
            Some(response.total_count),
        )?)
    }

    /// List a locally bounded page of group memberships for one project.
    ///
    /// # Errors
    ///
    /// Returns a typed client, response-contract, or pagination error.
    pub async fn list_project_group_memberships(
        &self,
        project_id: &ProjectId,
        page: PageRequest,
    ) -> Result<Page<ProjectGroupMembership>, ResourceError> {
        let response = self
            .execute_read::<ListProjectGroupMemberships>(&ProjectGroupMembershipsQuery {
                project_id: project_id.as_str().to_owned(),
            })
            .await?;
        for membership in &response.group_memberships {
            validate_membership_scope(membership, project_id, None)?;
        }
        paginate(page, response.group_memberships)
    }

    /// Get one group membership by exact project and group identifiers.
    ///
    /// # Errors
    ///
    /// Returns a typed client or response-contract error.
    pub async fn get_project_group_membership(
        &self,
        project_id: &ProjectId,
        group_id: &GroupId,
    ) -> Result<ProjectGroupMembership, ResourceError> {
        let response = self
            .execute_read::<GetProjectGroupMembership>(&ProjectGroupMembershipQuery {
                project_id: project_id.as_str().to_owned(),
                group_id: group_id.as_str().to_owned(),
            })
            .await?;
        validate_membership_scope(&response.group_membership, project_id, Some(group_id))?;
        Ok(response.group_membership)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    use super::{GroupMember, GroupMemberTypeFilter, GroupProject, GroupProjectFilter};
    use crate::{
        GroupId, InfisicalClient, PageRequest, ProjectId, ResourceError,
        test_support::{mount_login, settings},
    };

    #[tokio::test]
    async fn group_discovery_uses_exact_identity_compatible_routes_and_bounded_pages() {
        let server = MockServer::start().await;
        mount_login(&server, "group-token").await;
        mount_group_metadata_fixtures(&server).await;
        mount_group_assignment_fixtures(&server).await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let group_id = GroupId::new("group-1").unwrap();

        let groups = client
            .list_groups(PageRequest::new(1, 1).unwrap())
            .await
            .unwrap();
        assert_eq!(groups.items[0].id, "group-2");
        assert_eq!(groups.total, Some(2));
        assert!(groups.next.is_none());

        let group = client.get_group(&group_id).await.unwrap();
        assert_eq!(group.custom_role_slug.as_deref(), Some("auditor"));
        assert_eq!(group.org_id, "org-1");

        let members = client
            .list_group_members(
                &group_id,
                GroupMemberTypeFilter::Users,
                PageRequest::new(0, 1).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(members.total, Some(2));
        assert_eq!(members.next, Some(PageRequest::new(1, 1).unwrap()));
        assert!(matches!(
            &members.items[0],
            GroupMember::User { user, .. } if user.username == "ada@example.test"
        ));

        let projects = client
            .list_group_projects(
                &group_id,
                GroupProjectFilter::Assigned,
                PageRequest::new(0, 1).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(projects.items[0].project_type, "secret-manager");
        assert!(projects.items[0].joined_group_at.is_some());
        assert!(projects.next.is_none());
    }

    async fn mount_group_metadata_fixtures(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/v1/groups"))
            .and(header("authorization", "Bearer group-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                group_fixture("group-1", None),
                group_fixture("group-2", None)
            ])))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/groups/group-1"))
            .and(header("authorization", "Bearer group-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(group_fixture("group-1", Some("auditor"))),
            )
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_group_assignment_fixtures(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/v1/groups/group-1/members"))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"))
            .and(query_param("memberTypeFilter", "users"))
            .and(header("authorization", "Bearer group-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "members": [{
                    "id": "user-1",
                    "joinedGroupAt": "2026-01-02T00:00:00.000Z",
                    "type": "user",
                    "user": {
                        "id": "user-1",
                        "firstName": "Ada",
                        "lastName": "Lovelace",
                        "email": "ada@example.test",
                        "username": "ada@example.test"
                    }
                }],
                "totalCount": 2
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/groups/group-1/projects"))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"))
            .and(query_param("filter", "assignedProjects"))
            .and(query_param("orderBy", "name"))
            .and(query_param("orderDirection", "asc"))
            .and(header("authorization", "Bearer group-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "projects": [{
                    "id": "project-1",
                    "name": "Payments",
                    "slug": "payments",
                    "description": null,
                    "type": "secret-manager",
                    "joinedGroupAt": "2026-01-03T00:00:00.000Z"
                }],
                "totalCount": 1
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn project_group_memberships_validate_the_explicit_project_and_group_scope() {
        let server = MockServer::start().await;
        mount_login(&server, "membership-token").await;
        let mut mismatched_embedded_group = membership_fixture("project-1", "group-bad-embedded");
        mismatched_embedded_group["group"]["id"] = json!("group-other");

        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1/memberships/groups"))
            .and(header("authorization", "Bearer membership-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "groupMemberships": [membership_fixture("project-1", "group-1")]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/projects/project-1/memberships/groups/group-1",
            ))
            .and(header("authorization", "Bearer membership-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "groupMembership": membership_fixture("project-1", "group-1")
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/projects/project-1/memberships/groups/group-bad-project",
            ))
            .and(header("authorization", "Bearer membership-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "groupMembership": membership_fixture("project-2", "group-bad-project")
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/projects/project-1/memberships/groups/group-bad-request",
            ))
            .and(header("authorization", "Bearer membership-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "groupMembership": membership_fixture("project-1", "group-other")
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/projects/project-1/memberships/groups/group-bad-embedded",
            ))
            .and(header("authorization", "Bearer membership-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "groupMembership": mismatched_embedded_group
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let group_id = GroupId::new("group-1").unwrap();

        let memberships = client
            .list_project_group_memberships(&project_id, PageRequest::new(0, 1).unwrap())
            .await
            .unwrap();
        assert_eq!(memberships.items[0].roles[0].role, "viewer");
        assert_eq!(memberships.total, Some(1));

        let membership = client
            .get_project_group_membership(&project_id, &group_id)
            .await
            .unwrap();
        assert_eq!(membership.group.slug, "operators");

        for invalid_group_id in [
            "group-bad-project",
            "group-bad-request",
            "group-bad-embedded",
        ] {
            assert_eq!(
                client
                    .get_project_group_membership(
                        &project_id,
                        &GroupId::new(invalid_group_id).unwrap(),
                    )
                    .await
                    .unwrap_err(),
                ResourceError::InvalidGroupMembershipScope,
                "{invalid_group_id}"
            );
        }
    }

    #[tokio::test]
    async fn group_reads_reject_mismatched_exact_ids_filters_and_embedded_member_ids() {
        let server = MockServer::start().await;
        mount_login(&server, "invalid-group-token").await;

        Mock::given(method("GET"))
            .and(path("/api/v1/groups/group-bad"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(group_fixture("group-other", None)),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/groups/group-bad/members"))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"))
            .and(query_param("memberTypeFilter", "users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "members": [{
                    "id": "identity-1",
                    "joinedGroupAt": "2026-01-02T00:00:00.000Z",
                    "type": "machineIdentity",
                    "machineIdentity": {"id": "identity-1", "name": "automation"}
                }],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/groups/group-embedded/members"))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"))
            .and(query_param("memberTypeFilter", "machineIdentities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "members": [{
                    "id": "identity-1",
                    "joinedGroupAt": "2026-01-02T00:00:00.000Z",
                    "type": "machineIdentity",
                    "machineIdentity": {"id": "identity-other", "name": "automation"}
                }],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/groups/group-bad/projects"))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"))
            .and(query_param("filter", "assignedProjects"))
            .and(query_param("orderBy", "name"))
            .and(query_param("orderDirection", "asc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "projects": [{
                    "id": "project-1",
                    "name": "Payments",
                    "slug": "payments",
                    "description": null,
                    "type": "secret-manager",
                    "joinedGroupAt": null
                }],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let group_id = GroupId::new("group-bad").unwrap();
        let page = PageRequest::new(0, 1).unwrap();
        assert_eq!(
            client.get_group(&group_id).await.unwrap_err(),
            ResourceError::InvalidGroupResponse
        );
        assert_eq!(
            client
                .list_group_members(&group_id, GroupMemberTypeFilter::Users, page,)
                .await
                .unwrap_err(),
            ResourceError::InvalidGroupResponse
        );
        assert_eq!(
            client
                .list_group_members(
                    &GroupId::new("group-embedded").unwrap(),
                    GroupMemberTypeFilter::MachineIdentities,
                    page,
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidGroupResponse
        );
        assert_eq!(
            client
                .list_group_projects(&group_id, GroupProjectFilter::Assigned, page,)
                .await
                .unwrap_err(),
            ResourceError::InvalidGroupProjectAssignment
        );
    }

    #[test]
    fn group_filters_and_assignment_marker_preserve_the_public_contract() {
        assert_eq!(GroupMemberTypeFilter::All.upstream(), None);
        assert_eq!(GroupMemberTypeFilter::Users.upstream(), Some("users"));
        assert_eq!(
            GroupMemberTypeFilter::MachineIdentities.upstream(),
            Some("machineIdentities")
        );
        assert_eq!(GroupProjectFilter::All.upstream(), None);
        assert_eq!(
            GroupProjectFilter::Assigned.upstream(),
            Some("assignedProjects")
        );
        assert_eq!(
            GroupProjectFilter::Unassigned.upstream(),
            Some("unassignedProjects")
        );

        let unassigned = GroupProject {
            id: "project-1".into(),
            name: "Payments".into(),
            slug: "payments".into(),
            description: None,
            project_type: "secret-manager".into(),
            joined_group_at: None,
        };
        assert!(GroupProjectFilter::All.accepts(&unassigned));
        assert!(GroupProjectFilter::Unassigned.accepts(&unassigned));
        assert!(!GroupProjectFilter::Assigned.accepts(&unassigned));
        assert!(
            serde_json::to_value(unassigned).unwrap()["joinedGroupAt"].is_null(),
            "unassigned projects must preserve an explicit null assignment marker"
        );
    }

    fn group_fixture(id: &str, custom_role_slug: Option<&str>) -> Value {
        json!({
            "id": id,
            "orgId": "org-1",
            "name": "Operators",
            "slug": "operators",
            "role": "custom",
            "roleId": "role-1",
            "customRoleSlug": custom_role_slug,
            "createdAt": "2026-01-01T00:00:00.000Z",
            "updatedAt": "2026-01-01T00:00:00.000Z"
        })
    }

    fn membership_fixture(project_id: &str, group_id: &str) -> Value {
        json!({
            "id": "membership-1",
            "groupId": group_id,
            "projectId": project_id,
            "group": {
                "id": group_id,
                "name": "Operators",
                "slug": "operators",
                "orgId": "org-1"
            },
            "roles": [{
                "id": "assignment-1",
                "role": "viewer",
                "isTemporary": false
            }],
            "createdAt": "2026-01-01T00:00:00.000Z",
            "updatedAt": "2026-01-01T00:00:00.000Z"
        })
    }
}
