use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    Environment, EnvironmentId, EnvironmentName, EnvironmentPosition, EnvironmentSlug,
    InfisicalClient, MutationOperation, NewProjectSlug, PointInTimeVersionLimit, Project,
    ProjectDescription, ProjectId, ProjectName, ProjectSlug, ReadOperation, ResourceError,
    client::{ApiVersion, Endpoint, sealed},
};

/// Infisical project family accepted by the pinned project-creation endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectKind {
    /// Secret-management project.
    SecretManager,
    /// Certificate-management project.
    CertManager,
    /// Key-management project.
    Kms,
    /// SSH access project.
    Ssh,
    /// Secret-scanning project.
    SecretScanning,
    /// Privileged-access-management project.
    Pam,
    /// Artificial-intelligence project.
    Ai,
}

/// Validated settings for one project creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCreation {
    /// Project display name.
    pub name: ProjectName,
    /// Optional non-secret project description.
    pub description: Option<ProjectDescription>,
    /// Optional stable project slug.
    pub slug: Option<NewProjectSlug>,
    /// Project product family.
    pub kind: ProjectKind,
    /// Whether Infisical creates its default environments.
    pub create_default_environments: bool,
    /// Whether project deletion starts protected.
    pub delete_protection: bool,
}

/// One precise change to an existing project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectChange {
    /// Replace the project display name.
    Name(ProjectName),
    /// Replace or clear the project description.
    Description(ProjectDescription),
    /// Replace the project slug.
    Slug(ProjectSlug),
    /// Enable or disable deletion protection.
    DeleteProtection(bool),
    /// Enable or disable automatic secret-name capitalization.
    AutoCapitalization(bool),
    /// Require or stop requiring encrypted secret metadata.
    EncryptedSecretMetadata(bool),
    /// Enable or disable secret sharing.
    SecretSharing(bool),
    /// Change the point-in-time version retention limit.
    PointInTimeVersionLimit(PointInTimeVersionLimit),
}

/// Validated settings for one environment creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentCreation {
    /// Environment display name.
    pub name: EnvironmentName,
    /// Stable environment slug.
    pub slug: EnvironmentSlug,
    /// Optional one-based environment ordering position.
    pub position: Option<EnvironmentPosition>,
}

/// One precise change to an existing environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentChange {
    /// Replace the environment display name.
    Name(EnvironmentName),
    /// Replace the environment slug.
    Slug(EnvironmentSlug),
    /// Move the environment to a one-based ordering position.
    Position(EnvironmentPosition),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateProjectRequest {
    project_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slug: Option<String>,
    #[serde(rename = "type")]
    kind: ProjectKind,
    should_create_default_envs: bool,
    has_delete_protection: bool,
}

impl From<ProjectCreation> for CreateProjectRequest {
    fn from(creation: ProjectCreation) -> Self {
        Self {
            project_name: creation.name.as_str().to_owned(),
            project_description: creation
                .description
                .map(|description| description.as_str().to_owned()),
            slug: creation.slug.map(|slug| slug.as_str().to_owned()),
            kind: creation.kind,
            should_create_default_envs: creation.create_default_environments,
            has_delete_protection: creation.delete_protection,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectMutationRequest<T> {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(flatten)]
    body: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectChangeWire {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    has_delete_protection: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_capitalization: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enforce_encrypted_secret_manager_secret_metadata: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_sharing: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pit_version_limit: Option<u8>,
}

impl From<ProjectChange> for ProjectChangeWire {
    fn from(change: ProjectChange) -> Self {
        let mut wire = Self {
            name: None,
            description: None,
            slug: None,
            has_delete_protection: None,
            auto_capitalization: None,
            enforce_encrypted_secret_manager_secret_metadata: None,
            secret_sharing: None,
            pit_version_limit: None,
        };
        match change {
            ProjectChange::Name(value) => wire.name = Some(value.as_str().to_owned()),
            ProjectChange::Description(value) => {
                wire.description = Some(value.as_str().to_owned());
            }
            ProjectChange::Slug(value) => wire.slug = Some(value.as_str().to_owned()),
            ProjectChange::DeleteProtection(value) => wire.has_delete_protection = Some(value),
            ProjectChange::AutoCapitalization(value) => wire.auto_capitalization = Some(value),
            ProjectChange::EncryptedSecretMetadata(value) => {
                wire.enforce_encrypted_secret_manager_secret_metadata = Some(value);
            }
            ProjectChange::SecretSharing(value) => wire.secret_sharing = Some(value),
            ProjectChange::PointInTimeVersionLimit(value) => {
                wire.pit_version_limit = Some(value.get());
            }
        }
        wire
    }
}

#[derive(Serialize)]
struct EmptyBody {}

#[derive(Deserialize)]
struct ProjectResponse {
    project: Project,
}

#[derive(Deserialize)]
struct OptionalProjectResponse {
    project: Option<Project>,
}

struct CreateProject;

impl sealed::Sealed for CreateProject {}

impl MutationOperation for CreateProject {
    type Input = CreateProjectRequest;
    type Output = ProjectResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_static(ApiVersion::V1, "projects")
    }
}

struct UpdateProject;

impl sealed::Sealed for UpdateProject {}

impl MutationOperation for UpdateProject {
    type Input = ProjectMutationRequest<ProjectChangeWire>;
    type Output = ProjectResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["projects", input.project_id.as_str()])
    }
}

struct DeleteProject;

impl sealed::Sealed for DeleteProject {}

impl MutationOperation for DeleteProject {
    type Input = ProjectMutationRequest<EmptyBody>;
    type Output = OptionalProjectResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["projects", input.project_id.as_str()])
    }
}

#[derive(Serialize)]
struct GetEnvironmentQuery {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(skip_serializing)]
    environment_id: EnvironmentId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateEnvironmentRequest {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(flatten)]
    body: CreateEnvironmentWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvironmentMutationRequest<T> {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(skip_serializing)]
    environment_id: EnvironmentId,
    #[serde(flatten)]
    body: T,
}

#[derive(Serialize)]
struct CreateEnvironmentWire {
    name: String,
    slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    position: Option<u32>,
}

impl From<EnvironmentCreation> for CreateEnvironmentWire {
    fn from(creation: EnvironmentCreation) -> Self {
        Self {
            name: creation.name.as_str().to_owned(),
            slug: creation.slug.as_str().to_owned(),
            position: creation.position.map(EnvironmentPosition::get),
        }
    }
}

#[derive(Serialize)]
struct EnvironmentChangeWire {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    position: Option<u32>,
}

impl From<EnvironmentChange> for EnvironmentChangeWire {
    fn from(change: EnvironmentChange) -> Self {
        match change {
            EnvironmentChange::Name(value) => Self {
                name: Some(value.as_str().to_owned()),
                slug: None,
                position: None,
            },
            EnvironmentChange::Slug(value) => Self {
                name: None,
                slug: Some(value.as_str().to_owned()),
                position: None,
            },
            EnvironmentChange::Position(value) => Self {
                name: None,
                slug: None,
                position: Some(value.get()),
            },
        }
    }
}

#[derive(Deserialize)]
struct EnvironmentResponse {
    environment: Environment,
}

struct GetEnvironment;

impl sealed::Sealed for GetEnvironment {}

impl ReadOperation for GetEnvironment {
    type Query = GetEnvironmentQuery;
    type Output = EnvironmentResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects",
                query.project_id.as_str(),
                "environments",
                query.environment_id.as_str(),
            ],
        )
    }
}

struct CreateEnvironment;

impl sealed::Sealed for CreateEnvironment {}

impl MutationOperation for CreateEnvironment {
    type Input = CreateEnvironmentRequest;
    type Output = EnvironmentResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["projects", input.project_id.as_str(), "environments"],
        )
    }
}

struct UpdateEnvironment;

impl sealed::Sealed for UpdateEnvironment {}

impl MutationOperation for UpdateEnvironment {
    type Input = EnvironmentMutationRequest<EnvironmentChangeWire>;
    type Output = EnvironmentResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        environment_endpoint(input, None)
    }
}

struct DeleteEnvironment;

impl sealed::Sealed for DeleteEnvironment {}

impl MutationOperation for DeleteEnvironment {
    type Input = EnvironmentMutationRequest<EmptyBody>;
    type Output = EnvironmentResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        environment_endpoint(input, None)
    }
}

struct RestoreEnvironment;

impl sealed::Sealed for RestoreEnvironment {}

impl MutationOperation for RestoreEnvironment {
    type Input = EnvironmentMutationRequest<EmptyBody>;
    type Output = EnvironmentResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        environment_endpoint(input, Some("restore"))
    }
}

fn environment_endpoint<T>(
    input: &EnvironmentMutationRequest<T>,
    suffix: Option<&str>,
) -> Endpoint {
    let mut segments = vec![
        "projects",
        input.project_id.as_str(),
        "environments",
        input.environment_id.as_str(),
    ];
    if let Some(suffix) = suffix {
        segments.push(suffix);
    }
    Endpoint::from_segments(ApiVersion::V1, segments)
}

impl InfisicalClient {
    /// Create one project using explicit deletion-protection and default-environment settings.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn create_project(
        &self,
        creation: ProjectCreation,
    ) -> Result<Project, ResourceError> {
        let response = self
            .execute_mutation::<CreateProject>(&creation.into())
            .await?;
        Ok(response.project)
    }

    /// Apply one exact project change.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn update_project(
        &self,
        project_id: &ProjectId,
        change: ProjectChange,
    ) -> Result<Project, ResourceError> {
        let response = self
            .execute_mutation::<UpdateProject>(&ProjectMutationRequest {
                project_id: project_id.clone(),
                body: change.into(),
            })
            .await?;
        Ok(response.project)
    }

    /// Soft-delete one exact project after explicit confirmation.
    ///
    /// Infisical schedules later cleanup; the tool never exposes a hard-delete option.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn delete_project(
        &self,
        project_id: &ProjectId,
        confirm: bool,
    ) -> Result<Project, ResourceError> {
        if !confirm {
            return Err(ResourceError::ProjectDeletionNotConfirmed);
        }
        let response = self
            .execute_mutation::<DeleteProject>(&ProjectMutationRequest {
                project_id: project_id.clone(),
                body: EmptyBody {},
            })
            .await?;
        response
            .project
            .ok_or(ResourceError::MissingMutationResource)
    }

    /// Get one environment by exact project and environment identifiers.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_environment(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
    ) -> Result<Environment, ResourceError> {
        let response = self
            .execute_read::<GetEnvironment>(&GetEnvironmentQuery {
                project_id: project_id.clone(),
                environment_id: environment_id.clone(),
            })
            .await?;
        Ok(response.environment)
    }

    /// Create one environment at an optional bounded position.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn create_environment(
        &self,
        project_id: &ProjectId,
        creation: EnvironmentCreation,
    ) -> Result<Environment, ResourceError> {
        let response = self
            .execute_mutation::<CreateEnvironment>(&CreateEnvironmentRequest {
                project_id: project_id.clone(),
                body: creation.into(),
            })
            .await?;
        Ok(response.environment)
    }

    /// Apply one exact environment change.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn update_environment(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
        change: EnvironmentChange,
    ) -> Result<Environment, ResourceError> {
        let response = self
            .execute_mutation::<UpdateEnvironment>(&EnvironmentMutationRequest {
                project_id: project_id.clone(),
                environment_id: environment_id.clone(),
                body: change.into(),
            })
            .await?;
        Ok(response.environment)
    }

    /// Soft-delete one environment after explicit confirmation.
    ///
    /// The request deliberately omits Infisical's hard-delete query parameter.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn delete_environment(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
        confirm: bool,
    ) -> Result<Environment, ResourceError> {
        if !confirm {
            return Err(ResourceError::EnvironmentDeletionNotConfirmed);
        }
        let response = self
            .execute_mutation::<DeleteEnvironment>(&EnvironmentMutationRequest {
                project_id: project_id.clone(),
                environment_id: environment_id.clone(),
                body: EmptyBody {},
            })
            .await?;
        Ok(response.environment)
    }

    /// Restore one previously soft-deleted environment.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn restore_environment(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
    ) -> Result<Environment, ResourceError> {
        let response = self
            .execute_mutation::<RestoreEnvironment>(&EnvironmentMutationRequest {
                project_id: project_id.clone(),
                environment_id: environment_id.clone(),
                body: EmptyBody {},
            })
            .await?;
        Ok(response.environment)
    }
}

#[cfg(test)]
mod tests {
    use reqwest::Method;
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    use crate::{
        EnvironmentChange, EnvironmentCreation, EnvironmentId, EnvironmentName,
        EnvironmentPosition, EnvironmentSlug, InfisicalClient, NewProjectSlug,
        PointInTimeVersionLimit, ProjectChange, ProjectCreation, ProjectDescription, ProjectId,
        ProjectKind, ProjectName, ProjectSlug, ResourceError,
        test_support::{mount_login, settings},
    };

    fn project_fixture(name: &str, slug: &str) -> Value {
        json!({
            "id": "project-1",
            "name": name,
            "slug": slug,
            "type": "secret-manager",
            "orgId": "org-1",
            "description": "managed by MCP"
        })
    }

    fn environment_fixture(name: &str, slug: &str, position: u32) -> Value {
        json!({
            "id": "env-1",
            "name": name,
            "slug": slug,
            "position": position,
            "projectId": "project-1",
            "createdAt": "2026-07-19T12:00:00.000Z",
            "updatedAt": "2026-07-19T12:00:00.000Z"
        })
    }

    async fn mount_project_mutations(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/projects"))
            .and(header("authorization", "Bearer admin-token"))
            .and(body_json(json!({
                "projectName": "Payments",
                "projectDescription": "managed by MCP",
                "slug": "payments-prod",
                "type": "secret-manager",
                "shouldCreateDefaultEnvs": true,
                "hasDeleteProtection": true
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": project_fixture("Payments", "payments-prod")
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/projects/project-1"))
            .and(header("authorization", "Bearer admin-token"))
            .and(body_json(json!({ "pitVersionLimit": 25 })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": project_fixture("Payments", "payments-prod")
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/projects/project-1"))
            .and(header("authorization", "Bearer admin-token"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": project_fixture("Payments", "payments-prod")
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_environment_operations(server: &MockServer) {
        for (method_name, suffix, body, name, slug, position) in [
            (
                "POST",
                "",
                json!({ "name": "Production", "slug": "prod", "position": 2 }),
                "Production",
                "prod",
                2,
            ),
            (
                "PATCH",
                "/env-1",
                json!({ "name": "Primary" }),
                "Primary",
                "prod",
                2,
            ),
            ("DELETE", "/env-1", json!({}), "Primary", "prod", 2),
            ("POST", "/env-1/restore", json!({}), "Primary", "prod", 2),
        ] {
            Mock::given(method(method_name))
                .and(path(format!(
                    "/api/v1/projects/project-1/environments{suffix}"
                )))
                .and(header("authorization", "Bearer admin-token"))
                .and(body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "message": "ok",
                    "projectId": "project-1",
                    "environment": environment_fixture(name, slug, position)
                })))
                .expect(1)
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1/environments/env-1"))
            .and(header("authorization", "Bearer admin-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "environment": environment_fixture("Production", "prod", 2)
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn project_mutations_send_one_exact_typed_body() {
        let server = MockServer::start().await;
        mount_login(&server, "admin-token").await;
        mount_project_mutations(&server).await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();

        let created = client
            .create_project(ProjectCreation {
                name: ProjectName::new("Payments").unwrap(),
                description: Some(ProjectDescription::new("managed by MCP").unwrap()),
                slug: Some(NewProjectSlug::new("payments-prod").unwrap()),
                kind: ProjectKind::SecretManager,
                create_default_environments: true,
                delete_protection: true,
            })
            .await
            .unwrap();
        let updated = client
            .update_project(
                &project_id,
                ProjectChange::PointInTimeVersionLimit(PointInTimeVersionLimit::new(25).unwrap()),
            )
            .await
            .unwrap();
        let deleted = client.delete_project(&project_id, true).await.unwrap();

        assert_eq!(created.slug, "payments-prod");
        assert_eq!(updated.id, "project-1");
        assert_eq!(deleted.id, "project-1");
    }

    #[tokio::test]
    async fn environment_operations_use_exact_ids_and_soft_delete_only() {
        let server = MockServer::start().await;
        mount_login(&server, "admin-token").await;
        mount_environment_operations(&server).await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let environment_id = EnvironmentId::new("env-1").unwrap();

        let fetched = client
            .get_environment(&project_id, &environment_id)
            .await
            .unwrap();
        let created = client
            .create_environment(
                &project_id,
                EnvironmentCreation {
                    name: EnvironmentName::new("Production").unwrap(),
                    slug: EnvironmentSlug::new("prod").unwrap(),
                    position: Some(EnvironmentPosition::new(2).unwrap()),
                },
            )
            .await
            .unwrap();
        let updated = client
            .update_environment(
                &project_id,
                &environment_id,
                EnvironmentChange::Name(EnvironmentName::new("Primary").unwrap()),
            )
            .await
            .unwrap();
        let deleted = client
            .delete_environment(&project_id, &environment_id, true)
            .await
            .unwrap();
        let restored = client
            .restore_environment(&project_id, &environment_id)
            .await
            .unwrap();

        assert_eq!(fetched.slug, "prod");
        assert_eq!(created.name, "Production");
        assert_eq!(updated.name, "Primary");
        assert_eq!(deleted.id, "env-1");
        assert_eq!(restored.id, "env-1");
        let requests = server.received_requests().await.unwrap();
        let delete = requests
            .iter()
            .find(|request| request.method == Method::DELETE)
            .expect("environment delete request");
        assert!(delete.url.query().is_none());
    }

    #[tokio::test]
    async fn missing_confirmation_fails_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let environment_id = EnvironmentId::new("env-1").unwrap();

        assert_eq!(
            client.delete_project(&project_id, false).await.unwrap_err(),
            ResourceError::ProjectDeletionNotConfirmed
        );
        assert_eq!(
            client
                .delete_environment(&project_id, &environment_id, false)
                .await
                .unwrap_err(),
            ResourceError::EnvironmentDeletionNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn every_project_and_environment_change_serializes_one_field() {
        let project_changes = [
            ProjectChange::Name(ProjectName::new("Payments").unwrap()),
            ProjectChange::Description(ProjectDescription::new("").unwrap()),
            ProjectChange::Slug(ProjectSlug::new("payments").unwrap()),
            ProjectChange::DeleteProtection(true),
            ProjectChange::AutoCapitalization(false),
            ProjectChange::EncryptedSecretMetadata(true),
            ProjectChange::SecretSharing(false),
            ProjectChange::PointInTimeVersionLimit(PointInTimeVersionLimit::new(25).unwrap()),
        ];
        for change in project_changes {
            let body = serde_json::to_value(super::ProjectChangeWire::from(change)).unwrap();
            assert_eq!(body.as_object().unwrap().len(), 1);
        }
        let environment_changes = [
            EnvironmentChange::Name(EnvironmentName::new("Production").unwrap()),
            EnvironmentChange::Slug(EnvironmentSlug::new("prod").unwrap()),
            EnvironmentChange::Position(EnvironmentPosition::new(2).unwrap()),
        ];
        for change in environment_changes {
            let body = serde_json::to_value(super::EnvironmentChangeWire::from(change)).unwrap();
            assert_eq!(body.as_object().unwrap().len(), 1);
        }
    }
}
