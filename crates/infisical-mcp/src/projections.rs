//! Explicit collection projections; these reduce MCP output, not upstream bytes.

use infisical_api::{
    Environment, Page, Project, SecretMetadata, SecretMetadataEntry, SecretMetadataTag,
};
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProjectSummary {
    /// Opaque project identifier for exact subsequent operations.
    id: String,
    /// Human-readable project name.
    name: String,
    /// Stable project slug.
    slug: String,
    /// Infisical project family.
    #[serde(rename = "type")]
    project_type: String,
    /// Owning organization identifier.
    org_id: String,
    /// Project description; omitted unless includeDetails is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// Embedded environments; omitted unless includeDetails is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    environments: Option<Vec<Environment>>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecretMetadataSummary {
    /// Opaque secret identifier.
    id: String,
    /// Exact secret name for subsequent scoped operations.
    name: String,
    /// Environment slug containing this secret.
    environment: String,
    /// Current secret version.
    version: u64,
    /// Infisical secret type.
    #[serde(rename = "type")]
    secret_type: String,
    /// Secret-tree path reported by Infisical, when present.
    secret_path: Option<String>,
    /// Whether Infisical reports the secret value as hidden.
    value_hidden: bool,
    /// Operator metadata, which can contain sensitive configuration; opt in with includeMetadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Vec<SecretMetadataEntry>>,
    /// Full tag details; opt in with includeTags.
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<SecretMetadataTag>>,
}

pub(crate) fn projects(page: Page<Project>, details: bool) -> Page<ProjectSummary> {
    Page {
        items: page
            .items
            .into_iter()
            .map(|project| ProjectSummary {
                id: project.id,
                name: project.name,
                slug: project.slug,
                project_type: project.project_type,
                org_id: project.org_id,
                description: details.then_some(project.description).flatten(),
                environments: details.then_some(project.environments),
            })
            .collect(),
        next: page.next,
        total: page.total,
    }
}

pub(crate) fn secrets(
    page: Page<SecretMetadata>,
    metadata: bool,
    tags: bool,
) -> Page<SecretMetadataSummary> {
    Page {
        items: page
            .items
            .into_iter()
            .map(|secret| SecretMetadataSummary {
                id: secret.id,
                name: secret.name,
                environment: secret.environment,
                version: secret.version,
                secret_type: secret.secret_type,
                secret_path: secret.secret_path,
                value_hidden: secret.value_hidden,
                metadata: metadata.then_some(secret.metadata),
                tags: tags.then_some(secret.tags),
            })
            .collect(),
        next: page.next,
        total: page.total,
    }
}
