use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    EnvironmentSlug, InfisicalClient, MutationOperation, Page, PageRequest, ReadOperation,
    ResourceError, SecretImportId, SecretImportPosition, SecretPath, SecretScope,
    client::{ApiVersion, Endpoint, sealed},
    resources::paginate,
};

/// Concise Infisical environment metadata attached to an import source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretImportEnvironment {
    /// Opaque environment identifier.
    pub id: String,
    /// Human-readable environment name.
    pub name: String,
    /// Canonical environment slug.
    pub slug: String,
}

/// Exact destination scope receiving imported secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretImportTarget {
    /// Opaque project identifier.
    pub project_id: String,
    /// Destination environment slug.
    pub environment: String,
    /// Absolute destination secret-tree path.
    pub path: String,
}

/// Exact source scope from which secrets are imported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretImportSource {
    /// Source environment metadata.
    pub environment: SecretImportEnvironment,
    /// Absolute source secret-tree path.
    pub path: String,
}

/// Value-free metadata for one Infisical secret import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretImport {
    /// Opaque secret-import identifier.
    pub id: String,
    /// Exact destination scope.
    pub target: SecretImportTarget,
    /// Exact source scope.
    pub source: SecretImportSource,
    /// One-based ordering position under the destination scope.
    pub position: u64,
    /// Opaque destination folder identifier.
    pub folder_id: String,
    /// Upstream record version, when reported.
    pub version: Option<u64>,
    /// Whether Infisical treats this import as a replication workflow.
    pub is_replication: bool,
    /// Whether the last replication succeeded, when applicable.
    pub is_replication_success: Option<bool>,
    /// Timestamp of the last replication, when applicable.
    pub last_replicated: Option<String>,
    /// Whether Infisical reserves the record for internal behavior.
    pub is_reserved: bool,
    /// Infisical creation timestamp.
    pub created_at: String,
    /// Infisical update timestamp.
    pub updated_at: String,
}

/// One precise change to an existing secret import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretImportChange {
    /// Replace the complete source coordinate.
    Source {
        /// New source environment.
        environment: EnvironmentSlug,
        /// New absolute source path.
        path: SecretPath,
    },
    /// Move the import to a validated one-based position.
    Position(SecretImportPosition),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretImportScopeWire {
    project_id: String,
    environment: String,
    path: String,
}

impl From<&SecretScope> for SecretImportScopeWire {
    fn from(scope: &SecretScope) -> Self {
        Self {
            project_id: scope.project_id().as_str().to_owned(),
            environment: scope.environment().as_str().to_owned(),
            path: scope.path().as_str().to_owned(),
        }
    }
}

impl From<&SecretScope> for SecretImportTarget {
    fn from(scope: &SecretScope) -> Self {
        Self {
            project_id: scope.project_id().as_str().to_owned(),
            environment: scope.environment().as_str().to_owned(),
            path: scope.path().as_str().to_owned(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListSecretImportsQuery {
    project_id: String,
    environment: String,
    path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetSecretImportQuery {
    #[serde(skip_serializing)]
    secret_import_id: SecretImportId,
}

#[derive(Serialize)]
struct SecretImportSourceWire {
    environment: String,
    path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSecretImportRequest {
    #[serde(flatten)]
    target: SecretImportScopeWire,
    #[serde(rename = "import")]
    source: SecretImportSourceWire,
    is_replication: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateSecretImportWire {
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    position: Option<u32>,
}

impl From<SecretImportChange> for UpdateSecretImportWire {
    fn from(change: SecretImportChange) -> Self {
        match change {
            SecretImportChange::Source { environment, path } => Self {
                environment: Some(environment.as_str().to_owned()),
                path: Some(path.as_str().to_owned()),
                position: None,
            },
            SecretImportChange::Position(position) => Self {
                environment: None,
                path: None,
                position: Some(position.get()),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateSecretImportRequest {
    #[serde(skip_serializing)]
    secret_import_id: SecretImportId,
    #[serde(flatten)]
    target: SecretImportScopeWire,
    #[serde(rename = "import")]
    change: UpdateSecretImportWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteSecretImportRequest {
    #[serde(skip_serializing)]
    secret_import_id: SecretImportId,
    #[serde(flatten)]
    target: SecretImportScopeWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretImportEnvironmentWire {
    id: String,
    name: String,
    slug: String,
}

impl From<SecretImportEnvironmentWire> for SecretImportEnvironment {
    fn from(environment: SecretImportEnvironmentWire) -> Self {
        Self {
            id: environment.id,
            name: environment.name,
            slug: environment.slug,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretImportWire {
    id: String,
    #[serde(default)]
    version: Option<u64>,
    import_path: String,
    import_env: SecretImportEnvironmentWire,
    position: u64,
    created_at: String,
    updated_at: String,
    folder_id: String,
    #[serde(default)]
    is_replication: Option<bool>,
    #[serde(default)]
    is_replication_success: Option<bool>,
    #[serde(default)]
    last_replicated: Option<String>,
    #[serde(default)]
    is_reserved: Option<bool>,
}

impl SecretImportWire {
    fn into_resource(self, target: SecretImportTarget) -> SecretImport {
        SecretImport {
            id: self.id,
            target,
            source: SecretImportSource {
                environment: self.import_env.into(),
                path: self.import_path,
            },
            position: self.position,
            folder_id: self.folder_id,
            version: self.version,
            is_replication: self.is_replication.unwrap_or(false),
            is_replication_success: self.is_replication_success,
            last_replicated: self.last_replicated,
            is_reserved: self.is_reserved.unwrap_or(false),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopedSecretImportWire {
    #[serde(flatten)]
    secret_import: SecretImportWire,
    project_id: String,
    environment: SecretImportEnvironmentWire,
    secret_path: String,
}

impl From<ScopedSecretImportWire> for SecretImport {
    fn from(secret_import: ScopedSecretImportWire) -> Self {
        let target = SecretImportTarget {
            project_id: secret_import.project_id,
            environment: secret_import.environment.slug,
            path: secret_import.secret_path,
        };
        secret_import.secret_import.into_resource(target)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListSecretImportsResponse {
    secret_imports: Vec<SecretImportWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretImportMutationResponse {
    secret_import: SecretImportWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetSecretImportResponse {
    secret_import: ScopedSecretImportWire,
}

struct ListSecretImports;

impl sealed::Sealed for ListSecretImports {}

impl ReadOperation for ListSecretImports {
    type Query = ListSecretImportsQuery;
    type Output = ListSecretImportsResponse;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_static(ApiVersion::V2, "secret-imports")
    }
}

struct GetSecretImport;

impl sealed::Sealed for GetSecretImport {}

impl ReadOperation for GetSecretImport {
    type Query = GetSecretImportQuery;
    type Output = GetSecretImportResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V2,
            ["secret-imports", query.secret_import_id.as_str()],
        )
    }
}

struct CreateSecretImport;

impl sealed::Sealed for CreateSecretImport {}

impl MutationOperation for CreateSecretImport {
    type Input = CreateSecretImportRequest;
    type Output = SecretImportMutationResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_static(ApiVersion::V2, "secret-imports")
    }
}

struct UpdateSecretImport;

impl sealed::Sealed for UpdateSecretImport {}

impl MutationOperation for UpdateSecretImport {
    type Input = UpdateSecretImportRequest;
    type Output = SecretImportMutationResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V2,
            ["secret-imports", input.secret_import_id.as_str()],
        )
    }
}

struct DeleteSecretImport;

impl sealed::Sealed for DeleteSecretImport {}

impl MutationOperation for DeleteSecretImport {
    type Input = DeleteSecretImportRequest;
    type Output = SecretImportMutationResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V2,
            ["secret-imports", input.secret_import_id.as_str()],
        )
    }
}

fn source_matches_target(
    target: &SecretScope,
    environment: &EnvironmentSlug,
    path: &SecretPath,
) -> bool {
    target.environment() == environment && target.path() == path
}

impl InfisicalClient {
    /// List a bounded page of value-free secret-import metadata under one scope.
    ///
    /// Infisical's pinned route returns the complete collection, so the HTTP
    /// body remains protected by the client's response-size bound and this
    /// method exposes only the requested local page.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_secret_imports(
        &self,
        target: &SecretScope,
        page: PageRequest,
    ) -> Result<Page<SecretImport>, ResourceError> {
        let response = self
            .execute_read::<ListSecretImports>(&ListSecretImportsQuery {
                project_id: target.project_id().as_str().to_owned(),
                environment: target.environment().as_str().to_owned(),
                path: target.path().as_str().to_owned(),
            })
            .await?;
        let target = SecretImportTarget::from(target);
        paginate(
            page,
            response
                .secret_imports
                .into_iter()
                .map(|secret_import| secret_import.into_resource(target.clone()))
                .collect(),
        )
    }

    /// Get one value-free secret import by its opaque identifier.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_secret_import(
        &self,
        secret_import_id: &SecretImportId,
    ) -> Result<SecretImport, ResourceError> {
        let response = self
            .execute_read::<GetSecretImport>(&GetSecretImportQuery {
                secret_import_id: secret_import_id.clone(),
            })
            .await?;
        Ok(response.secret_import.into())
    }

    /// Create one non-replicating secret import between two exact scopes.
    ///
    /// Direct cycles are rejected before authentication. Replication is fixed
    /// off because its separate resync workflow is not available to Universal
    /// Auth in the pinned Infisical release.
    ///
    /// # Errors
    ///
    /// Returns a validation or typed client error. The mutation is sent once.
    pub async fn create_secret_import(
        &self,
        target: &SecretScope,
        source_environment: &EnvironmentSlug,
        source_path: &SecretPath,
    ) -> Result<SecretImport, ResourceError> {
        if source_matches_target(target, source_environment, source_path) {
            return Err(ResourceError::CyclicSecretImport);
        }
        let response = self
            .execute_mutation::<CreateSecretImport>(&CreateSecretImportRequest {
                target: target.into(),
                source: SecretImportSourceWire {
                    environment: source_environment.as_str().to_owned(),
                    path: source_path.as_str().to_owned(),
                },
                is_replication: false,
            })
            .await?;
        Ok(response
            .secret_import
            .into_resource(SecretImportTarget::from(target)))
    }

    /// Change one import's complete source coordinate or bounded position.
    ///
    /// Source coordinates cannot be partially updated. This keeps direct cycle
    /// validation complete without a racy read-before-write operation.
    ///
    /// # Errors
    ///
    /// Returns a validation or typed client error. The mutation is sent once.
    pub async fn update_secret_import(
        &self,
        target: &SecretScope,
        secret_import_id: &SecretImportId,
        change: SecretImportChange,
    ) -> Result<SecretImport, ResourceError> {
        if matches!(
            &change,
            SecretImportChange::Source { environment, path }
                if source_matches_target(target, environment, path)
        ) {
            return Err(ResourceError::CyclicSecretImport);
        }
        let response = self
            .execute_mutation::<UpdateSecretImport>(&UpdateSecretImportRequest {
                secret_import_id: secret_import_id.clone(),
                target: target.into(),
                change: change.into(),
            })
            .await?;
        Ok(response
            .secret_import
            .into_resource(SecretImportTarget::from(target)))
    }

    /// Delete one exact secret import after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a validation or typed client error. The mutation is sent once.
    pub async fn delete_secret_import(
        &self,
        target: &SecretScope,
        secret_import_id: &SecretImportId,
        confirm: bool,
    ) -> Result<SecretImport, ResourceError> {
        if !confirm {
            return Err(ResourceError::SecretImportDeletionNotConfirmed);
        }
        let response = self
            .execute_mutation::<DeleteSecretImport>(&DeleteSecretImportRequest {
                secret_import_id: secret_import_id.clone(),
                target: target.into(),
            })
            .await?;
        Ok(response
            .secret_import
            .into_resource(SecretImportTarget::from(target)))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path, query_param},
    };

    use crate::{
        EnvironmentSlug, InfisicalClient, PageRequest, ProjectId, SecretImportChange,
        SecretImportId, SecretImportPosition, SecretPath, SecretScope,
        test_support::{mount_login, settings},
    };

    fn target_scope() -> SecretScope {
        SecretScope::new(
            ProjectId::new("project-1").unwrap(),
            EnvironmentSlug::new("prod").unwrap(),
            SecretPath::new("/payments").unwrap(),
            false,
        )
    }

    #[test]
    fn direct_cycle_detection_requires_both_source_coordinates_to_match() {
        let target = target_scope();
        let prod = EnvironmentSlug::new("prod").unwrap();
        let staging = EnvironmentSlug::new("staging").unwrap();
        let payments = SecretPath::new("/payments").unwrap();
        let shared = SecretPath::new("/shared").unwrap();

        assert!(super::source_matches_target(&target, &prod, &payments));
        assert!(!super::source_matches_target(&target, &prod, &shared));
        assert!(!super::source_matches_target(&target, &staging, &payments));
    }

    fn import_fixture(id: &str, source_environment: &str, position: u64) -> Value {
        json!({
            "id": id,
            "version": 1,
            "importPath": "/shared",
            "importEnv": {
                "id": format!("env-{source_environment}"),
                "name": "Staging",
                "slug": source_environment
            },
            "position": position,
            "createdAt": "2026-07-19T12:00:00.000Z",
            "updatedAt": "2026-07-19T12:05:00.000Z",
            "folderId": "folder-1",
            "isReplication": false,
            "isReplicationSuccess": null,
            "replicationStatus": null,
            "lastReplicated": null,
            "isReserved": false
        })
    }

    async fn mount_import_reads(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/v2/secret-imports"))
            .and(query_param("projectId", "project-1"))
            .and(query_param("environment", "prod"))
            .and(query_param("path", "/payments"))
            .and(header("authorization", "Bearer import-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "Successfully fetched secret imports",
                "secretImports": [
                    import_fixture("import-1", "staging", 1),
                    import_fixture("import-2", "dev", 2)
                ]
            })))
            .expect(1)
            .mount(server)
            .await;
        let mut scoped = import_fixture("import-1", "staging", 1);
        let scoped = scoped.as_object_mut().unwrap();
        scoped.insert("projectId".into(), json!("project-1"));
        scoped.insert(
            "environment".into(),
            json!({ "id": "env-prod", "name": "Production", "slug": "prod" }),
        );
        scoped.insert("secretPath".into(), json!("/payments"));
        Mock::given(method("GET"))
            .and(path("/api/v2/secret-imports/import-1"))
            .and(header("authorization", "Bearer import-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretImport": scoped
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_create_import(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v2/secret-imports"))
            .and(header("authorization", "Bearer import-token"))
            .and(body_json(json!({
                "projectId": "project-1",
                "environment": "prod",
                "path": "/payments",
                "import": { "environment": "staging", "path": "/shared" },
                "isReplication": false
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "Successfully created secret import",
                "secretImport": import_fixture("import-1", "staging", 1)
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_update_imports(server: &MockServer) {
        Mock::given(method("PATCH"))
            .and(path("/api/v2/secret-imports/import-1"))
            .and(header("authorization", "Bearer import-token"))
            .and(body_json(json!({
                "projectId": "project-1",
                "environment": "prod",
                "path": "/payments",
                "import": { "environment": "dev", "path": "/shared" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretImport": import_fixture("import-1", "dev", 1)
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v2/secret-imports/import-1"))
            .and(header("authorization", "Bearer import-token"))
            .and(body_json(json!({
                "projectId": "project-1",
                "environment": "prod",
                "path": "/payments",
                "import": { "position": 2 }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretImport": import_fixture("import-1", "staging", 2)
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_delete_import(server: &MockServer) {
        Mock::given(method("DELETE"))
            .and(path("/api/v2/secret-imports/import-1"))
            .and(header("authorization", "Bearer import-token"))
            .and(body_json(json!({
                "projectId": "project-1",
                "environment": "prod",
                "path": "/payments"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretImport": import_fixture("import-1", "staging", 1)
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn import_reads_use_v2_exact_scope_and_return_bounded_metadata() {
        let server = MockServer::start().await;
        mount_login(&server, "import-token").await;
        mount_import_reads(&server).await;
        let client = InfisicalClient::new(settings(&server)).unwrap();

        let page = client
            .list_secret_imports(&target_scope(), PageRequest::new(1, 1).unwrap())
            .await
            .unwrap();
        let secret_import = client
            .get_secret_import(&SecretImportId::new("import-1").unwrap())
            .await
            .unwrap();

        assert_eq!(page.items[0].id, "import-2");
        assert_eq!(page.total, Some(2));
        assert_eq!(secret_import.target.project_id, "project-1");
        assert_eq!(secret_import.target.environment, "prod");
        assert_eq!(secret_import.source.environment.slug, "staging");
        assert_eq!(secret_import.source.path, "/shared");
    }

    #[tokio::test]
    async fn import_mutations_send_exact_non_replicating_bodies_once() {
        let server = MockServer::start().await;
        mount_login(&server, "import-token").await;
        mount_create_import(&server).await;
        mount_update_imports(&server).await;
        mount_delete_import(&server).await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let target = target_scope();
        let import_id = SecretImportId::new("import-1").unwrap();

        let created = client
            .create_secret_import(
                &target,
                &EnvironmentSlug::new("staging").unwrap(),
                &SecretPath::new("/shared").unwrap(),
            )
            .await
            .unwrap();
        let source_updated = client
            .update_secret_import(
                &target,
                &import_id,
                SecretImportChange::Source {
                    environment: EnvironmentSlug::new("dev").unwrap(),
                    path: SecretPath::new("/shared").unwrap(),
                },
            )
            .await
            .unwrap();
        let position_updated = client
            .update_secret_import(
                &target,
                &import_id,
                SecretImportChange::Position(SecretImportPosition::new(2).unwrap()),
            )
            .await
            .unwrap();
        let deleted = client
            .delete_secret_import(&target, &import_id, true)
            .await
            .unwrap();

        assert!(!created.is_replication);
        assert_eq!(source_updated.source.environment.slug, "dev");
        assert_eq!(position_updated.position, 2);
        assert_eq!(deleted.id, "import-1");
    }

    #[tokio::test]
    async fn invalid_import_mutations_fail_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let target = target_scope();
        let import_id = SecretImportId::new("import-1").unwrap();

        assert_eq!(
            client
                .create_secret_import(
                    &target,
                    &EnvironmentSlug::new("prod").unwrap(),
                    &SecretPath::new("/payments").unwrap(),
                )
                .await
                .unwrap_err(),
            crate::ResourceError::CyclicSecretImport
        );
        assert_eq!(
            client
                .update_secret_import(
                    &target,
                    &import_id,
                    SecretImportChange::Source {
                        environment: EnvironmentSlug::new("prod").unwrap(),
                        path: SecretPath::new("/payments").unwrap(),
                    },
                )
                .await
                .unwrap_err(),
            crate::ResourceError::CyclicSecretImport
        );
        assert_eq!(
            client
                .delete_secret_import(&target, &import_id, false)
                .await
                .unwrap_err(),
            crate::ResourceError::SecretImportDeletionNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
