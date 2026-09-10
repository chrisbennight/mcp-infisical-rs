use std::collections::HashSet;

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    EnvironmentSlug, FolderDescription, FolderId, FolderName, InfisicalClient, MutationOperation,
    Page, PageRequest, ProjectId, ReadOperation, ResourceError, SecretPath, SecretScope,
    client::{ApiVersion, Endpoint, sealed},
    resources::paginate,
};

/// Maximum number of folders accepted by one batch update.
pub const MAX_FOLDER_BATCH_SIZE: usize = 50;

/// Concise secret-folder metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    /// Opaque Infisical folder identifier.
    pub id: String,
    /// Folder name within its parent path.
    pub name: String,
    /// Opaque owning environment identifier.
    pub env_id: String,
    /// Parent folder identifier, or null for a root-level folder.
    #[serde(default)]
    pub parent_id: Option<String>,
    /// Optional folder description.
    #[serde(default)]
    pub description: Option<String>,
    /// Whether Infisical reserves this folder for internal behavior.
    #[serde(default)]
    pub is_reserved: Option<bool>,
    /// Folder path relative to the environment's secret-tree root.
    #[serde(default)]
    pub relative_path: Option<String>,
    /// Absolute folder path returned by exact lookups and create/update calls.
    #[serde(default)]
    pub path: Option<String>,
    /// Opaque project identifier returned by an exact lookup.
    #[serde(default)]
    pub project_id: Option<String>,
    /// Owning environment metadata returned by an exact lookup.
    #[serde(default)]
    pub environment: Option<FolderEnvironment>,
}

/// Every folder returned by one bounded batch update.
///
/// The collection is wrapped in a named field because a tool result is
/// carried in `structuredContent`, which MCP defines as a JSON object: a
/// bare array is neither a valid payload nor a valid `outputSchema` root,
/// and a strict client rejects the entire `tools/list` response over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct FolderBatch {
    /// Folders updated by this batch, in the order Infisical returned them.
    pub folders: Vec<Folder>,
}

impl From<Vec<Folder>> for FolderBatch {
    fn from(folders: Vec<Folder>) -> Self {
        Self { folders }
    }
}

/// Concise environment coordinates embedded in an exact folder lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FolderEnvironment {
    /// Opaque Infisical environment identifier.
    pub env_id: String,
    /// Environment display name.
    pub env_name: String,
    /// Stable environment slug.
    pub env_slug: String,
}

/// Exact parent coordinates for one folder mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderParent {
    /// Project containing the folder tree.
    pub project_id: ProjectId,
    /// Environment containing the folder tree.
    pub environment: EnvironmentSlug,
    /// Absolute parent path.
    pub path: SecretPath,
}

/// Validated settings for one folder creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderCreation {
    /// Exact parent coordinates.
    pub parent: FolderParent,
    /// Folder name under the parent path.
    pub name: FolderName,
    /// Optional folder description.
    pub description: Option<FolderDescription>,
}

/// Complete desired state for one folder update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderUpdate {
    /// Exact parent coordinates used to locate the folder.
    pub parent: FolderParent,
    /// Opaque folder identifier.
    pub folder_id: FolderId,
    /// Desired folder name.
    pub name: FolderName,
    /// Desired description, or null to clear it.
    pub description: Option<FolderDescription>,
}

/// One complete desired-state entry in a folder batch update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderBatchUpdate {
    /// Opaque folder identifier.
    pub folder_id: FolderId,
    /// Environment containing the folder.
    pub environment: EnvironmentSlug,
    /// Absolute parent path.
    pub path: SecretPath,
    /// Desired folder name.
    pub name: FolderName,
    /// Desired description, or null to clear it.
    pub description: Option<FolderDescription>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListFoldersQuery {
    project_id: String,
    environment: String,
    path: String,
    recursive: bool,
}

#[derive(Deserialize)]
struct ListFoldersResponse {
    folders: Vec<Folder>,
}

#[derive(Serialize)]
struct GetFolderQuery {
    #[serde(skip_serializing)]
    folder_id: FolderId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateFolderRequest {
    project_id: String,
    environment: String,
    name: String,
    path: String,
    description: Option<String>,
}

impl From<FolderCreation> for CreateFolderRequest {
    fn from(creation: FolderCreation) -> Self {
        Self {
            project_id: creation.parent.project_id.as_str().to_owned(),
            environment: creation.parent.environment.as_str().to_owned(),
            name: creation.name.as_str().to_owned(),
            path: creation.parent.path.as_str().to_owned(),
            description: creation
                .description
                .map(|description| description.as_str().to_owned()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateFolderRequest {
    #[serde(skip_serializing)]
    folder_id: FolderId,
    project_id: String,
    environment: String,
    name: String,
    path: String,
    description: Option<String>,
}

impl From<FolderUpdate> for UpdateFolderRequest {
    fn from(update: FolderUpdate) -> Self {
        Self {
            folder_id: update.folder_id,
            project_id: update.parent.project_id.as_str().to_owned(),
            environment: update.parent.environment.as_str().to_owned(),
            name: update.name.as_str().to_owned(),
            path: update.parent.path.as_str().to_owned(),
            description: update
                .description
                .map(|description| description.as_str().to_owned()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchUpdateFoldersRequest {
    project_id: String,
    folders: Vec<BatchUpdateFolderWire>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchUpdateFolderWire {
    id: String,
    environment: String,
    name: String,
    path: String,
    description: Option<String>,
}

impl From<FolderBatchUpdate> for BatchUpdateFolderWire {
    fn from(update: FolderBatchUpdate) -> Self {
        Self {
            id: update.folder_id.as_str().to_owned(),
            environment: update.environment.as_str().to_owned(),
            name: update.name.as_str().to_owned(),
            path: update.path.as_str().to_owned(),
            description: update
                .description
                .map(|description| description.as_str().to_owned()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteFolderRequest {
    #[serde(skip_serializing)]
    folder_id: FolderId,
    project_id: String,
    environment: String,
    path: String,
    force_delete: bool,
}

#[derive(Deserialize)]
struct FolderResponse {
    folder: Folder,
}

#[derive(Deserialize)]
struct FoldersResponse {
    folders: Vec<Folder>,
}

struct ListFolders;

impl sealed::Sealed for ListFolders {}

impl ReadOperation for ListFolders {
    type Query = ListFoldersQuery;
    type Output = ListFoldersResponse;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V2, "folders")
    }
}

struct GetFolder;

impl sealed::Sealed for GetFolder {}

impl ReadOperation for GetFolder {
    type Query = GetFolderQuery;
    type Output = FolderResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V2, ["folders", query.folder_id.as_str()])
    }
}

struct CreateFolder;

impl sealed::Sealed for CreateFolder {}

impl MutationOperation for CreateFolder {
    type Input = CreateFolderRequest;
    type Output = FolderResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_static(ApiVersion::V2, "folders")
    }
}

struct UpdateFolder;

impl sealed::Sealed for UpdateFolder {}

impl MutationOperation for UpdateFolder {
    type Input = UpdateFolderRequest;
    type Output = FolderResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V2, ["folders", input.folder_id.as_str()])
    }
}

struct UpdateFoldersBatch;

impl sealed::Sealed for UpdateFoldersBatch {}

impl MutationOperation for UpdateFoldersBatch {
    type Input = BatchUpdateFoldersRequest;
    type Output = FoldersResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V2, ["folders", "batch"])
    }
}

struct DeleteFolder;

impl sealed::Sealed for DeleteFolder {}

impl MutationOperation for DeleteFolder {
    type Input = DeleteFolderRequest;
    type Output = FolderResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V2, ["folders", input.folder_id.as_str()])
    }
}

impl InfisicalClient {
    /// List secret folders under an exact project, environment, and path.
    ///
    /// Infisical's pinned folder endpoint is not paginated, so the HTTP body
    /// remains protected by the client's response-size bound and this method
    /// exposes only the requested local page.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_folders(
        &self,
        scope: &SecretScope,
        page: PageRequest,
    ) -> Result<Page<Folder>, ResourceError> {
        let response = self
            .execute_read::<ListFolders>(&ListFoldersQuery {
                project_id: scope.project_id().as_str().to_owned(),
                environment: scope.environment().as_str().to_owned(),
                path: scope.path().as_str().to_owned(),
                recursive: scope.recursive(),
            })
            .await?;
        paginate(page, response.folders)
    }

    /// Get one folder by exact opaque identifier.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_folder(&self, folder_id: &FolderId) -> Result<Folder, ResourceError> {
        let response = self
            .execute_read::<GetFolder>(&GetFolderQuery {
                folder_id: folder_id.clone(),
            })
            .await?;
        Ok(response.folder)
    }

    /// Create one folder under an exact project, environment, and parent path.
    ///
    /// Infisical may create missing parent path segments as part of this request.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn create_folder(&self, creation: FolderCreation) -> Result<Folder, ResourceError> {
        let response = self
            .execute_mutation::<CreateFolder>(&creation.into())
            .await?;
        Ok(response.folder)
    }

    /// Replace one folder's complete name and description at its exact parent path.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn update_folder(&self, update: FolderUpdate) -> Result<Folder, ResourceError> {
        let response = self
            .execute_mutation::<UpdateFolder>(&update.into())
            .await?;
        Ok(response.folder)
    }

    /// Replace one to fifty folders' complete mutable state in one upstream request.
    ///
    /// # Errors
    ///
    /// Returns a validation or typed client error. Invalid and duplicate-ID
    /// batches fail before authentication.
    pub async fn update_folders_batch(
        &self,
        project_id: &ProjectId,
        updates: Vec<FolderBatchUpdate>,
    ) -> Result<Vec<Folder>, ResourceError> {
        validate_folder_batch(&updates)?;
        let response = self
            .execute_mutation::<UpdateFoldersBatch>(&BatchUpdateFoldersRequest {
                project_id: project_id.as_str().to_owned(),
                folders: updates.into_iter().map(Into::into).collect(),
            })
            .await?;
        Ok(response.folders)
    }

    /// Delete one exact folder after explicit confirmation.
    ///
    /// `force_delete` permits Infisical to remove contained resources. Callers
    /// should leave it false unless recursive deletion is explicitly intended.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn delete_folder(
        &self,
        parent: &FolderParent,
        folder_id: &FolderId,
        force_delete: bool,
        confirm: bool,
    ) -> Result<Folder, ResourceError> {
        if !confirm {
            return Err(ResourceError::FolderDeletionNotConfirmed);
        }
        let response = self
            .execute_mutation::<DeleteFolder>(&DeleteFolderRequest {
                folder_id: folder_id.clone(),
                project_id: parent.project_id.as_str().to_owned(),
                environment: parent.environment.as_str().to_owned(),
                path: parent.path.as_str().to_owned(),
                force_delete,
            })
            .await?;
        Ok(response.folder)
    }
}

fn validate_folder_batch(updates: &[FolderBatchUpdate]) -> Result<(), ResourceError> {
    if updates.is_empty() || updates.len() > MAX_FOLDER_BATCH_SIZE {
        return Err(ResourceError::InvalidFolderBatchSize);
    }
    let unique_ids = updates
        .iter()
        .map(|update| update.folder_id.as_str())
        .collect::<HashSet<_>>();
    if unique_ids.len() != updates.len() {
        return Err(ResourceError::DuplicateFolderId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    use super::validate_folder_batch;

    use crate::{
        EnvironmentSlug, FolderBatchUpdate, FolderCreation, FolderDescription, FolderId,
        FolderName, FolderParent, FolderUpdate, InfisicalClient, PageRequest, ProjectId,
        ResourceError, SecretPath, SecretScope,
        test_support::{mount_login, settings},
    };

    #[tokio::test]
    async fn folders_use_v2_exact_scope_and_local_bounded_pagination() {
        let server = MockServer::start().await;
        mount_login(&server, "folder-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v2/folders"))
            .and(query_param("projectId", "project-1"))
            .and(query_param("environment", "prod"))
            .and(query_param("path", "/payments"))
            .and(query_param("recursive", "true"))
            .and(header("authorization", "Bearer folder-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "folders": [
                    folder_fixture("folder-1", "api"),
                    folder_fixture("folder-2", "workers"),
                    folder_fixture("folder-3", "jobs")
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let scope = SecretScope::new(
            ProjectId::new("project-1").unwrap(),
            EnvironmentSlug::new("prod").unwrap(),
            SecretPath::new("/payments").unwrap(),
            true,
        );
        let page = client
            .list_folders(&scope, PageRequest::new(1, 1).unwrap())
            .await
            .unwrap();

        assert_eq!(page.items[0].id, "folder-2");
        assert_eq!(page.total, Some(3));
        assert_eq!(page.next, Some(PageRequest::new(2, 1).unwrap()));
    }

    fn folder_fixture(id: &str, name: &str) -> serde_json::Value {
        json!({
            "id": id,
            "name": name,
            "envId": "env-1",
            "parentId": null,
            "description": null,
            "isReserved": false,
            "relativePath": format!("/payments/{name}")
        })
    }

    fn parent() -> FolderParent {
        FolderParent {
            project_id: ProjectId::new("project-1").unwrap(),
            environment: EnvironmentSlug::new("prod").unwrap(),
            path: SecretPath::new("/payments").unwrap(),
        }
    }

    fn batch_update(index: usize) -> FolderBatchUpdate {
        FolderBatchUpdate {
            folder_id: FolderId::new(format!("folder-{index}")).unwrap(),
            environment: EnvironmentSlug::new("prod").unwrap(),
            path: SecretPath::new("/payments").unwrap(),
            name: FolderName::new(format!("folder_{index}")).unwrap(),
            description: None,
        }
    }

    #[test]
    fn folder_batch_bounds_include_fifty_and_reject_fifty_one() {
        let fifty = (0..50).map(batch_update).collect::<Vec<_>>();
        assert_eq!(validate_folder_batch(&fifty), Ok(()));

        let fifty_one = (0..51).map(batch_update).collect::<Vec<_>>();
        assert_eq!(
            validate_folder_batch(&fifty_one),
            Err(ResourceError::InvalidFolderBatchSize)
        );
    }

    #[tokio::test]
    async fn folder_get_and_mutations_use_exact_v2_contracts_once() {
        let server = MockServer::start().await;
        mount_login(&server, "folder-admin-token").await;
        for (method_name, expected_body, name) in [
            (
                "POST",
                json!({
                    "projectId": "project-1",
                    "environment": "prod",
                    "name": "api",
                    "path": "/payments",
                    "description": "API credentials"
                }),
                "api",
            ),
            (
                "PATCH",
                json!({
                    "projectId": "project-1",
                    "environment": "prod",
                    "name": "backend",
                    "path": "/payments",
                    "description": null
                }),
                "backend",
            ),
            (
                "DELETE",
                json!({
                    "projectId": "project-1",
                    "environment": "prod",
                    "path": "/payments",
                    "forceDelete": false
                }),
                "backend",
            ),
        ] {
            let route = if method_name == "POST" {
                "/api/v2/folders"
            } else {
                "/api/v2/folders/folder-1"
            };
            Mock::given(method(method_name))
                .and(path(route))
                .and(header("authorization", "Bearer folder-admin-token"))
                .and(wiremock::matchers::body_json(expected_body))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "folder": folder_fixture("folder-1", name)
                })))
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/api/v2/folders/folder-1"))
            .and(header("authorization", "Bearer folder-admin-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "folder": {
                    "id": "folder-1",
                    "name": "api",
                    "envId": "env-1",
                    "path": "/payments/api",
                    "projectId": "project-1",
                    "environment": { "envId": "env-1", "envName": "Production", "envSlug": "prod" }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let folder_id = FolderId::new("folder-1").unwrap();
        assert_eq!(
            client.get_folder(&folder_id).await.unwrap().path.as_deref(),
            Some("/payments/api")
        );
        client
            .create_folder(FolderCreation {
                parent: parent(),
                name: FolderName::new("api").unwrap(),
                description: Some(FolderDescription::new("API credentials").unwrap()),
            })
            .await
            .unwrap();
        client
            .update_folder(FolderUpdate {
                parent: parent(),
                folder_id: folder_id.clone(),
                name: FolderName::new("backend").unwrap(),
                description: None,
            })
            .await
            .unwrap();
        client
            .delete_folder(&parent(), &folder_id, false, true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn folder_batch_is_bounded_unique_and_serializes_complete_entries() {
        let server = MockServer::start().await;
        mount_login(&server, "folder-batch-token").await;
        Mock::given(method("PATCH"))
            .and(path("/api/v2/folders/batch"))
            .and(header("authorization", "Bearer folder-batch-token"))
            .and(wiremock::matchers::body_json(json!({
                "projectId": "project-1",
                "folders": [{
                    "id": "folder-1",
                    "environment": "prod",
                    "name": "api",
                    "path": "/payments",
                    "description": null
                }]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "folders": [folder_fixture("folder-1", "api")]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let update = FolderBatchUpdate {
            folder_id: FolderId::new("folder-1").unwrap(),
            environment: EnvironmentSlug::new("prod").unwrap(),
            path: SecretPath::new("/payments").unwrap(),
            name: FolderName::new("api").unwrap(),
            description: None,
        };
        assert_eq!(
            client
                .update_folders_batch(&project_id, Vec::new())
                .await
                .unwrap_err(),
            ResourceError::InvalidFolderBatchSize
        );
        assert_eq!(
            client
                .update_folders_batch(&project_id, vec![update.clone(), update.clone()])
                .await
                .unwrap_err(),
            ResourceError::DuplicateFolderId
        );
        assert_eq!(
            client
                .update_folders_batch(&project_id, vec![update])
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn unconfirmed_folder_delete_fails_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert_eq!(
            client
                .delete_folder(&parent(), &FolderId::new("folder-1").unwrap(), true, false)
                .await
                .unwrap_err(),
            ResourceError::FolderDeletionNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
