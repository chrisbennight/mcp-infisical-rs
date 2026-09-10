use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    InfisicalClient, MutationOperation, Page, PageRequest, ProjectId, ReadOperation, ResourceError,
    TagColor, TagId, TagSlug,
    client::{ApiVersion, Endpoint, sealed},
    resources::paginate,
};

/// Concise secret-tag metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Tag {
    /// Opaque Infisical tag identifier.
    pub id: String,
    /// Stable tag slug.
    pub slug: String,
    /// Opaque project identifier that owns the tag.
    pub project_id: String,
    /// Optional display color supplied by Infisical.
    #[serde(default)]
    pub color: Option<String>,
    /// Compatibility display name returned by exact lookups.
    #[serde(default)]
    pub name: Option<String>,
}

/// Exact selector for one project tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagSelector {
    /// Select by opaque tag identifier.
    Id(TagId),
    /// Select by stable tag slug.
    Slug(TagSlug),
}

/// Validated settings for one tag creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagCreation {
    /// Stable lowercase tag slug.
    pub slug: TagSlug,
    /// Optional display color; empty text selects Infisical's default.
    pub color: TagColor,
}

/// Complete desired state for one tag update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagUpdate {
    /// Stable lowercase tag slug.
    pub slug: TagSlug,
    /// Optional display color; empty text clears the explicit color.
    pub color: TagColor,
}

#[derive(Serialize)]
struct ListTagsQuery {
    #[serde(skip_serializing)]
    project_id: String,
}

#[derive(Deserialize)]
struct ListTagsResponse {
    tags: Vec<Tag>,
}

#[derive(Serialize)]
struct GetTagQuery {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(skip_serializing)]
    selector: TagSelector,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateTagRequest {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    slug: String,
    color: String,
}

impl CreateTagRequest {
    fn create(project_id: &ProjectId, creation: &TagCreation) -> Self {
        Self {
            project_id: project_id.clone(),
            slug: creation.slug.as_str().to_owned(),
            color: creation.color.as_str().to_owned(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateTagRequest {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(skip_serializing)]
    tag_id: TagId,
    slug: String,
    color: String,
}

impl UpdateTagRequest {
    fn update(project_id: &ProjectId, tag_id: &TagId, update: &TagUpdate) -> Self {
        Self {
            project_id: project_id.clone(),
            tag_id: tag_id.clone(),
            slug: update.slug.as_str().to_owned(),
            color: update.color.as_str().to_owned(),
        }
    }
}

#[derive(Serialize)]
struct DeleteTagRequest {
    #[serde(skip_serializing)]
    project_id: ProjectId,
    #[serde(skip_serializing)]
    tag_id: TagId,
}

#[derive(Deserialize)]
struct TagResponse {
    tag: Tag,
}

struct ListTags;

impl sealed::Sealed for ListTags {}

impl ReadOperation for ListTags {
    type Query = ListTagsQuery;
    type Output = ListTagsResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects".to_owned(),
                query.project_id.clone(),
                "tags".to_owned(),
            ],
        )
    }
}

struct GetTag;

impl sealed::Sealed for GetTag {}

impl ReadOperation for GetTag {
    type Query = GetTagQuery;
    type Output = TagResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        match &query.selector {
            TagSelector::Id(tag_id) => Endpoint::from_segments(
                ApiVersion::V1,
                [
                    "projects",
                    query.project_id.as_str(),
                    "tags",
                    tag_id.as_str(),
                ],
            ),
            TagSelector::Slug(slug) => Endpoint::from_segments(
                ApiVersion::V1,
                [
                    "projects",
                    query.project_id.as_str(),
                    "tags",
                    "slug",
                    slug.as_str(),
                ],
            ),
        }
    }
}

struct CreateTag;

impl sealed::Sealed for CreateTag {}

impl MutationOperation for CreateTag {
    type Input = CreateTagRequest;
    type Output = TagResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["projects", input.project_id.as_str(), "tags"],
        )
    }
}

struct UpdateTag;

impl sealed::Sealed for UpdateTag {}

impl MutationOperation for UpdateTag {
    type Input = UpdateTagRequest;
    type Output = TagResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects",
                input.project_id.as_str(),
                "tags",
                input.tag_id.as_str(),
            ],
        )
    }
}

struct DeleteTag;

impl sealed::Sealed for DeleteTag {}

impl MutationOperation for DeleteTag {
    type Input = DeleteTagRequest;
    type Output = TagResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "projects",
                input.project_id.as_str(),
                "tags",
                input.tag_id.as_str(),
            ],
        )
    }
}

impl InfisicalClient {
    /// List the secret tags defined for one project.
    ///
    /// Infisical's pinned tag endpoint is not paginated, so the HTTP body
    /// remains protected by the client's response-size bound and this method
    /// exposes only the requested local page.
    ///
    /// # Errors
    ///
    /// Returns a typed client or pagination error.
    pub async fn list_tags(
        &self,
        project_id: &ProjectId,
        page: PageRequest,
    ) -> Result<Page<Tag>, ResourceError> {
        let response = self
            .execute_read::<ListTags>(&ListTagsQuery {
                project_id: project_id.as_str().to_owned(),
            })
            .await?;
        paginate(page, response.tags)
    }

    /// Get one tag by exact ID or slug within one project.
    ///
    /// # Errors
    ///
    /// Returns a typed client error.
    pub async fn get_tag(
        &self,
        project_id: &ProjectId,
        selector: TagSelector,
    ) -> Result<Tag, ResourceError> {
        let response = self
            .execute_read::<GetTag>(&GetTagQuery {
                project_id: project_id.clone(),
                selector,
            })
            .await?;
        Ok(response.tag)
    }

    /// Create one tag with an exact slug and color.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn create_tag(
        &self,
        project_id: &ProjectId,
        creation: TagCreation,
    ) -> Result<Tag, ResourceError> {
        let response = self
            .execute_mutation::<CreateTag>(&CreateTagRequest::create(project_id, &creation))
            .await?;
        Ok(response.tag)
    }

    /// Replace one tag's complete slug and color state.
    ///
    /// # Errors
    ///
    /// Returns a typed client error. The mutation is sent once.
    pub async fn update_tag(
        &self,
        project_id: &ProjectId,
        tag_id: &TagId,
        update: TagUpdate,
    ) -> Result<Tag, ResourceError> {
        let response = self
            .execute_mutation::<UpdateTag>(&UpdateTagRequest::update(project_id, tag_id, &update))
            .await?;
        Ok(response.tag)
    }

    /// Delete one exact project tag after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation or typed client error. The mutation is sent once.
    pub async fn delete_tag(
        &self,
        project_id: &ProjectId,
        tag_id: &TagId,
        confirm: bool,
    ) -> Result<Tag, ResourceError> {
        if !confirm {
            return Err(ResourceError::TagDeletionNotConfirmed);
        }
        let response = self
            .execute_mutation::<DeleteTag>(&DeleteTagRequest {
                project_id: project_id.clone(),
                tag_id: tag_id.clone(),
            })
            .await?;
        Ok(response.tag)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use crate::{
        InfisicalClient, PageRequest, ProjectId, ResourceError, TagColor, TagCreation, TagId,
        TagSelector, TagSlug, TagUpdate,
        test_support::{mount_login, settings},
    };

    #[tokio::test]
    async fn tags_use_the_project_scoped_v1_route_and_are_bounded_locally() {
        let server = MockServer::start().await;
        mount_login(&server, "tag-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1/tags"))
            .and(header("authorization", "Bearer tag-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tags": [
                    { "id": "tag-1", "slug": "billing", "projectId": "project-1", "color": "#f00" },
                    { "id": "tag-2", "slug": "critical", "projectId": "project-1", "color": null }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let page = client
            .list_tags(&project_id, PageRequest::new(0, 1).unwrap())
            .await
            .unwrap();

        assert_eq!(page.items[0].slug, "billing");
        assert_eq!(page.total, Some(2));
        assert_eq!(page.next, Some(PageRequest::new(1, 1).unwrap()));
    }

    fn tag_fixture(slug: &str, color: &str) -> serde_json::Value {
        json!({ "id": "tag-1", "slug": slug, "projectId": "project-1", "color": color })
    }

    #[tokio::test]
    async fn tag_get_and_mutations_use_exact_project_scoped_contracts_once() {
        let server = MockServer::start().await;
        mount_login(&server, "tag-admin-token").await;
        for route in [
            "/api/v1/projects/project-1/tags/tag-1",
            "/api/v1/projects/project-1/tags/slug/critical",
        ] {
            Mock::given(method("GET"))
                .and(path(route))
                .and(header("authorization", "Bearer tag-admin-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "tag": tag_fixture("critical", "#ff0000")
                })))
                .expect(1)
                .mount(&server)
                .await;
        }
        for (method_name, route, body, slug, color) in [
            (
                "POST",
                "/api/v1/projects/project-1/tags",
                json!({ "slug": "critical", "color": "#ff0000" }),
                "critical",
                "#ff0000",
            ),
            (
                "PATCH",
                "/api/v1/projects/project-1/tags/tag-1",
                json!({ "slug": "urgent", "color": "" }),
                "urgent",
                "",
            ),
            (
                "DELETE",
                "/api/v1/projects/project-1/tags/tag-1",
                json!({}),
                "urgent",
                "",
            ),
        ] {
            Mock::given(method(method_name))
                .and(path(route))
                .and(header("authorization", "Bearer tag-admin-token"))
                .and(wiremock::matchers::body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "tag": tag_fixture(slug, color)
                })))
                .expect(1)
                .mount(&server)
                .await;
        }

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = ProjectId::new("project-1").unwrap();
        let tag_id = TagId::new("tag-1").unwrap();
        client
            .get_tag(&project_id, TagSelector::Id(tag_id.clone()))
            .await
            .unwrap();
        client
            .get_tag(
                &project_id,
                TagSelector::Slug(TagSlug::new("critical").unwrap()),
            )
            .await
            .unwrap();
        client
            .create_tag(
                &project_id,
                TagCreation {
                    slug: TagSlug::new("critical").unwrap(),
                    color: TagColor::new("#ff0000").unwrap(),
                },
            )
            .await
            .unwrap();
        client
            .update_tag(
                &project_id,
                &tag_id,
                TagUpdate {
                    slug: TagSlug::new("urgent").unwrap(),
                    color: TagColor::new("").unwrap(),
                },
            )
            .await
            .unwrap();
        client.delete_tag(&project_id, &tag_id, true).await.unwrap();
    }

    #[tokio::test]
    async fn unconfirmed_tag_delete_fails_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert_eq!(
            client
                .delete_tag(
                    &ProjectId::new("project-1").unwrap(),
                    &TagId::new("tag-1").unwrap(),
                    false,
                )
                .await
                .unwrap_err(),
            ResourceError::TagDeletionNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
