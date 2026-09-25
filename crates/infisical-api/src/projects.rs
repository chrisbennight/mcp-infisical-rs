use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    InfisicalClient, Page, PageRequest, ProjectId, ReadOperation, ResourceError,
    client::{ApiVersion, Endpoint, sealed},
    resources::paginate,
};

/// Concise project metadata returned by Infisical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    /// Opaque Infisical project identifier.
    pub id: String,
    /// Human-readable project name.
    pub name: String,
    /// Stable human-readable project slug.
    pub slug: String,
    /// Infisical project family, such as `secret-manager`.
    #[serde(rename = "type")]
    pub project_type: String,
    /// Opaque owning organization identifier.
    pub org_id: String,
    /// Optional project description.
    #[serde(default)]
    pub description: Option<String>,
    /// Environments embedded by the pinned project endpoint.
    #[serde(default)]
    pub environments: Vec<Environment>,
}

/// Concise environment metadata embedded in a project response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Environment {
    /// Opaque Infisical environment identifier.
    pub id: String,
    /// Human-readable environment name.
    pub name: String,
    /// Stable environment slug used in scoped API requests.
    pub slug: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListProjectsQuery {
    include_roles: bool,
}

#[derive(Deserialize)]
struct ListProjectsResponse {
    projects: Vec<Project>,
}

struct ListProjects;

impl sealed::Sealed for ListProjects {}

impl ReadOperation for ListProjects {
    type Query = ListProjectsQuery;
    type Output = ListProjectsResponse;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "projects")
    }
}

#[derive(Serialize)]
struct GetProjectQuery {
    #[serde(skip_serializing)]
    project_id: String,
}

#[derive(Deserialize)]
struct GetProjectResponse {
    project: Option<Project>,
}

struct GetProject;

impl sealed::Sealed for GetProject {}

impl ReadOperation for GetProject {
    type Query = GetProjectQuery;
    type Output = GetProjectResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["projects".to_owned(), query.project_id.clone()],
        )
    }
}

impl InfisicalClient {
    /// List the projects visible to the Universal Auth identity.
    ///
    /// Infisical's pinned project endpoint is not paginated, so the HTTP body
    /// remains protected by the client's response-size bound and this method
    /// exposes only the requested local page.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_projects(&self, page: PageRequest) -> Result<Page<Project>, ResourceError> {
        let response = self
            .execute_read::<ListProjects>(&ListProjectsQuery {
                include_roles: false,
            })
            .await?;
        paginate(page, response.projects)
    }

    /// Get one project by its validated identifier.
    ///
    /// # Errors
    ///
    /// Returns a typed client error when Infisical cannot serve the request, or
    /// a response error when the returned project does not match the identifier.
    pub async fn get_project(
        &self,
        project_id: &ProjectId,
    ) -> Result<Option<Project>, ResourceError> {
        let response = self
            .execute_read::<GetProject>(&GetProjectQuery {
                project_id: project_id.as_str().to_owned(),
            })
            .await?;
        if response
            .project
            .as_ref()
            .is_some_and(|project| project.id != project_id.as_str())
        {
            return Err(ResourceError::InvalidProjectResponse);
        }
        Ok(response.project)
    }

    /// List environments embedded in one project response.
    ///
    /// `None` distinguishes an absent project from a project with no
    /// environments.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_environments(
        &self,
        project_id: &ProjectId,
        page: PageRequest,
    ) -> Result<Option<Page<Environment>>, ResourceError> {
        let Some(project) = self.get_project(project_id).await? else {
            return Ok(None);
        };
        Ok(Some(paginate(page, project.environments)?))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    use super::{Environment, Project};
    use crate::{
        InfisicalClient, PageRequest, ProjectId, ResourceError,
        test_support::{mount_login, settings},
    };

    #[tokio::test]
    async fn projects_and_embedded_environments_follow_the_pinned_wire_contract() {
        let server = MockServer::start().await;
        mount_login(&server, "read-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects"))
            .and(query_param("includeRoles", "false"))
            .and(header("authorization", "Bearer read-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "projects": [
                    project_fixture("project-1", "alpha", &[]),
                    project_fixture(
                        "project-2",
                        "bravo",
                        &[json!({ "id": "env-1", "name": "Production", "slug": "prod" })]
                    ),
                    project_fixture("project-3", "charlie", &[])
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-2"))
            .and(header("authorization", "Bearer read-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": project_fixture(
                    "project-2",
                    "bravo",
                    &[
                        json!({ "id": "env-1", "name": "Production", "slug": "prod" }),
                        json!({ "id": "env-2", "name": "Staging", "slug": "staging" })
                    ]
                )
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let projects = client
            .list_projects(PageRequest::new(1, 1).unwrap())
            .await
            .unwrap();
        assert_eq!(projects.items[0].id, "project-2");
        assert_eq!(projects.total, Some(3));
        assert_eq!(projects.next, Some(PageRequest::new(2, 1).unwrap()));

        let project_id = ProjectId::new("project-2").unwrap();
        let environments = client
            .list_environments(&project_id, PageRequest::new(0, 1).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            environments.items,
            vec![Environment {
                id: "env-1".into(),
                name: "Production".into(),
                slug: "prod".into(),
            }]
        );
        assert_eq!(environments.total, Some(2));
        assert_eq!(environments.next, Some(PageRequest::new(1, 1).unwrap()));
    }

    #[tokio::test]
    async fn project_reads_reject_a_different_project_before_returning_metadata() {
        let server = MockServer::start().await;
        mount_login(&server, "read-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": project_fixture("project-2", "unexpected-project-canary", &[])
            })))
            .expect(2)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let error = client.get_project(&project_id).await.unwrap_err();
        assert_eq!(error, ResourceError::InvalidProjectResponse);
        assert!(!format!("{error} {error:?}").contains("unexpected-project-canary"));
        assert_eq!(
            client
                .list_environments(&project_id, PageRequest::new(0, 10).unwrap())
                .await
                .unwrap_err(),
            ResourceError::InvalidProjectResponse
        );
    }

    #[tokio::test]
    async fn an_absent_project_remains_distinct_from_an_empty_environment_list() {
        let server = MockServer::start().await;
        mount_login(&server, "read-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"project": null})))
            .expect(2)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        assert_eq!(client.get_project(&project_id).await.unwrap(), None);
        assert_eq!(
            client
                .list_environments(&project_id, PageRequest::new(0, 10).unwrap())
                .await
                .unwrap(),
            None
        );
    }

    fn project_fixture(
        id: &str,
        slug: &str,
        environments: &[serde_json::Value],
    ) -> serde_json::Value {
        json!({
            "id": id,
            "_id": id,
            "name": slug,
            "slug": slug,
            "type": "secret-manager",
            "orgId": "org-1",
            "description": null,
            "environments": environments,
            "deletedEnvironments": []
        })
    }

    #[test]
    fn project_output_is_concise_and_serializable() {
        let value = serde_json::to_value(Project {
            id: "project-1".into(),
            name: "Alpha".into(),
            slug: "alpha".into(),
            project_type: "secret-manager".into(),
            org_id: "org-1".into(),
            description: None,
            environments: vec![],
        })
        .unwrap();

        assert_eq!(
            value,
            json!({
                "id": "project-1",
                "name": "Alpha",
                "slug": "alpha",
                "type": "secret-manager",
                "orgId": "org-1",
                "description": null,
                "environments": []
            })
        );
    }
}
