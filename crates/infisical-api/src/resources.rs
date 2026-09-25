use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;

use crate::{ClientError, Page, PageRequest, PaginationError};

const MAX_OPAQUE_ID_BYTES: usize = 128;
const MAX_ENVIRONMENT_SLUG_BYTES: usize = 64;
const MAX_SECRET_PATH_BYTES: usize = 2_048;
const MAX_SECRET_NAME_BYTES: usize = 512;
const MAX_SECRET_IMPORT_POSITION: u32 = 100_000;
const MAX_PROJECT_NAME_BYTES: usize = 64;
const MAX_PROJECT_DESCRIPTION_BYTES: usize = 1_024;
const MIN_NEW_PROJECT_SLUG_BYTES: usize = 5;
const MAX_NEW_PROJECT_SLUG_BYTES: usize = 36;
const MAX_PROJECT_SLUG_BYTES: usize = 64;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 64;
const MAX_ENVIRONMENT_POSITION: u32 = 100_000;
const MAX_POINT_IN_TIME_VERSION_LIMIT: u8 = 100;
const MAX_FOLDER_NAME_BYTES: usize = 255;
const MAX_FOLDER_DESCRIPTION_BYTES: usize = 1_024;
const MAX_TAG_SLUG_BYTES: usize = 64;
const MAX_TAG_COLOR_BYTES: usize = 32;
const MAX_IDENTITY_NAME_BYTES: usize = 128;

fn is_valid_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPAQUE_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_valid_display_text(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn is_valid_hyphen_slug(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(*byte - b'0'))
    })
}

pub(crate) fn utc_timestamp_millis(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    let fractional_millis = match bytes.len() {
        20 if bytes[19] == b'Z' => 0,
        24 if bytes[19] == b'.' && bytes[23] == b'Z' => decimal(&bytes[20..23])?,
        _ => return None,
    };
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let year = decimal(&bytes[0..4])?;
    let month = decimal(&bytes[5..7])?;
    let day = decimal(&bytes[8..10])?;
    let hour = decimal(&bytes[11..13])?;
    let minute = decimal(&bytes[14..16])?;
    let second = decimal(&bytes[17..19])?;
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return None,
    };
    if year == 0 || !(1..=days_in_month).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let prior_year = i64::from(year - 1);
    let days_before_year = prior_year * 365 + prior_year / 4 - prior_year / 100 + prior_year / 400;
    let days_before_month: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let leap_day = i64::from(leap_year && month > 2);
    let absolute_days = days_before_year
        + days_before_month[usize::try_from(month - 1).ok()?]
        + leap_day
        + i64::from(day - 1);
    let absolute_seconds = absolute_days * 86_400
        + i64::from(hour) * 3_600
        + i64::from(minute) * 60
        + i64::from(second);
    Some(absolute_seconds * 1_000 + i64::from(fractional_millis))
}

pub(crate) fn is_bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

pub(crate) fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// A validated Infisical project identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct ProjectId(String);

impl ProjectId {
    /// Validate an opaque project identifier before it reaches a URL path.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, non-ASCII, or punctuation-bearing
    /// identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_opaque_id(&value) {
            return Err(ResourceInputError::InvalidProjectId);
        }
        Ok(Self(value))
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated opaque secret-import identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SecretImportId(String);

impl SecretImportId {
    /// Validate an import identifier before it reaches a URL path.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, non-ASCII, or punctuation-bearing
    /// identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_opaque_id(&value) {
            return Err(ResourceInputError::InvalidSecretImportId);
        }
        Ok(Self(value))
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated opaque environment identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct EnvironmentId(String);

impl EnvironmentId {
    /// Validate an environment identifier before it reaches a URL path.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid opaque identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_opaque_id(&value) {
            return Err(ResourceInputError::InvalidEnvironmentId);
        }
        Ok(Self(value))
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! opaque_resource_id {
    ($name:ident, $error:ident, $subject:literal) => {
        #[doc = concat!("A validated opaque Infisical ", $subject, " identifier.")]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Validate a ", $subject, " identifier before it reaches a URL path.")]
            ///
            /// # Errors
            ///
            /// Returns an error for an invalid opaque identifier.
            pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
                let value = value.into();
                if !is_valid_opaque_id(&value) {
                    return Err(ResourceInputError::$error);
                }
                Ok(Self(value))
            }

            /// Borrow the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

opaque_resource_id!(FolderId, InvalidFolderId, "folder");
opaque_resource_id!(TagId, InvalidTagId, "tag");
opaque_resource_id!(OrganizationId, InvalidOrganizationId, "organization");
opaque_resource_id!(IdentityId, InvalidIdentityId, "machine identity");
opaque_resource_id!(GroupId, InvalidGroupId, "group");
opaque_resource_id!(
    AdditionalPrivilegeId,
    InvalidAdditionalPrivilegeId,
    "additional privilege"
);
opaque_resource_id!(
    ProjectMembershipId,
    InvalidProjectMembershipId,
    "project membership"
);
opaque_resource_id!(
    TokenAuthTokenId,
    InvalidTokenAuthTokenId,
    "Token Auth access token"
);
opaque_resource_id!(
    UniversalAuthClientSecretId,
    InvalidUniversalAuthClientSecretId,
    "Universal Auth client secret"
);

/// A validated machine-identity display name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct IdentityName(String);

impl IdentityName {
    /// Validate a machine-identity display name.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, padded, or control-bearing text.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_display_text(&value, MAX_IDENTITY_NAME_BYTES, false) {
            return Err(ResourceInputError::InvalidIdentityName);
        }
        Ok(Self(value))
    }

    /// Borrow the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated project display name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct ProjectName(String);

impl ProjectName {
    /// Validate a project display name.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, padded, or control-bearing text.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_display_text(&value, MAX_PROJECT_NAME_BYTES, false) {
            return Err(ResourceInputError::InvalidProjectName);
        }
        Ok(Self(value))
    }

    /// Borrow the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated optional project description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct ProjectDescription(String);

impl ProjectDescription {
    /// Validate project description text.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, padded, or control-bearing text.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_display_text(&value, MAX_PROJECT_DESCRIPTION_BYTES, true) {
            return Err(ResourceInputError::InvalidProjectDescription);
        }
        Ok(Self(value))
    }

    /// Borrow the validated description.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_valid_project_slug(value: &str, min_bytes: usize, max_bytes: usize) -> bool {
    (min_bytes..=max_bytes).contains(&value.len())
        && value.split(['-', '_']).all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

/// A validated project slug accepted by project updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct ProjectSlug(String);

impl ProjectSlug {
    /// Validate a lowercase project slug.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value is 1 to 64 bytes of lowercase words
    /// separated by single hyphens or underscores.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_project_slug(&value, 1, MAX_PROJECT_SLUG_BYTES) {
            return Err(ResourceInputError::InvalidProjectSlug);
        }
        Ok(Self(value))
    }

    /// Borrow the validated slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated project slug accepted by project creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct NewProjectSlug(String);

impl NewProjectSlug {
    /// Validate a project-creation slug.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value is 5 to 36 bytes of lowercase words
    /// separated by single hyphens or underscores.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_project_slug(
            &value,
            MIN_NEW_PROJECT_SLUG_BYTES,
            MAX_NEW_PROJECT_SLUG_BYTES,
        ) {
            return Err(ResourceInputError::InvalidNewProjectSlug);
        }
        Ok(Self(value))
    }

    /// Borrow the validated slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated environment display name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct EnvironmentName(String);

impl EnvironmentName {
    /// Validate an environment display name.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, padded, or control-bearing text.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_display_text(&value, MAX_ENVIRONMENT_NAME_BYTES, false) {
            return Err(ResourceInputError::InvalidEnvironmentName);
        }
        Ok(Self(value))
    }

    /// Borrow the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated secret-folder name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct FolderName(String);

impl FolderName {
    /// Validate the folder-name alphabet accepted by the pinned API.
    ///
    /// # Errors
    ///
    /// Returns an error unless the name contains 1 to 255 ASCII letters,
    /// numbers, hyphens, or underscores.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_FOLDER_NAME_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ResourceInputError::InvalidFolderName);
        }
        Ok(Self(value))
    }

    /// Borrow the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated optional secret-folder description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct FolderDescription(String);

impl FolderDescription {
    /// Validate bounded folder description text.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, padded, or control-bearing text.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_display_text(&value, MAX_FOLDER_DESCRIPTION_BYTES, true) {
            return Err(ResourceInputError::InvalidFolderDescription);
        }
        Ok(Self(value))
    }

    /// Borrow the validated description.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated lowercase secret-tag slug.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct TagSlug(String);

impl TagSlug {
    /// Validate the pinned tag-slug contract.
    ///
    /// # Errors
    ///
    /// Returns an error unless the slug contains 1 to 64 lowercase letters or
    /// numbers separated by single hyphens.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_hyphen_slug(&value, MAX_TAG_SLUG_BYTES) {
            return Err(ResourceInputError::InvalidTagSlug);
        }
        Ok(Self(value))
    }

    /// Borrow the validated slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated optional display color for a secret tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct TagColor(String);

impl TagColor {
    /// Validate a bounded color string accepted by the pinned API.
    ///
    /// Empty text clears the color. Non-empty values are kept opaque because
    /// the upstream route does not require one color notation.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, padded, or control-bearing text.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_display_text(&value, MAX_TAG_COLOR_BYTES, true) {
            return Err(ResourceInputError::InvalidTagColor);
        }
        Ok(Self(value))
    }

    /// Borrow the validated color string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated one-based environment position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct EnvironmentPosition(u32);

impl EnvironmentPosition {
    /// Validate a one-based bounded environment position.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or values above the server bound.
    pub fn new(value: u32) -> Result<Self, ResourceInputError> {
        if !(1..=MAX_ENVIRONMENT_POSITION).contains(&value) {
            return Err(ResourceInputError::InvalidEnvironmentPosition);
        }
        Ok(Self(value))
    }

    /// Return the validated position.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

/// A validated project point-in-time version retention limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct PointInTimeVersionLimit(u8);

impl PointInTimeVersionLimit {
    /// Validate a version retention limit accepted by Infisical.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or values above one hundred.
    pub fn new(value: u8) -> Result<Self, ResourceInputError> {
        if !(1..=MAX_POINT_IN_TIME_VERSION_LIMIT).contains(&value) {
            return Err(ResourceInputError::InvalidPointInTimeVersionLimit);
        }
        Ok(Self(value))
    }

    /// Return the validated retention limit.
    #[must_use]
    pub fn get(self) -> u8 {
        self.0
    }
}

/// A validated one-based position in a bounded secret-import collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SecretImportPosition(u32);

impl SecretImportPosition {
    /// Validate a one-based import position.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or values above the server's fixed bound.
    pub fn new(value: u32) -> Result<Self, ResourceInputError> {
        if !(1..=MAX_SECRET_IMPORT_POSITION).contains(&value) {
            return Err(ResourceInputError::InvalidSecretImportPosition);
        }
        Ok(Self(value))
    }

    /// Return the validated one-based position.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

/// A canonical Infisical environment slug.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct EnvironmentSlug(String);

impl EnvironmentSlug {
    /// Validate an Infisical environment slug.
    ///
    /// # Errors
    ///
    /// Returns an error unless the slug consists of lowercase letters or
    /// numbers separated by single hyphens.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if !is_valid_hyphen_slug(&value, MAX_ENVIRONMENT_SLUG_BYTES) {
            return Err(ResourceInputError::InvalidEnvironmentSlug);
        }
        Ok(Self(value))
    }

    /// Borrow the validated slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A canonical absolute path in Infisical's secret tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SecretPath(String);

impl SecretPath {
    /// Validate an absolute, normalized secret path.
    ///
    /// # Errors
    ///
    /// Returns an error for relative paths, control characters, empty or dot
    /// segments, trailing separators, or paths above the fixed size bound.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        let valid_segments = value == "/"
            || value.strip_prefix('/').is_some_and(|path| {
                !path.is_empty()
                    && path.split('/').all(|segment| {
                        !segment.is_empty()
                            && segment != "."
                            && segment != ".."
                            && !segment.chars().any(char::is_control)
                    })
            });
        if value.len() > MAX_SECRET_PATH_BYTES
            || value.chars().any(char::is_control)
            || !valid_segments
        {
            return Err(ResourceInputError::InvalidSecretPath);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An exact, bounded Infisical secret name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SecretName(String);

impl SecretName {
    /// Validate a secret name without applying Infisical's implicit trimming.
    ///
    /// Rejecting leading or trailing whitespace prevents the displayed name
    /// from identifying a different upstream secret after normalization.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, control-bearing, slash-bearing,
    /// colon-bearing, or surrounding-whitespace names.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceInputError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_SECRET_NAME_BYTES
            || value.trim() != value
            || matches!(value.as_str(), "." | "..")
            || value.chars().any(char::is_control)
            || value.contains(['/', ':'])
        {
            return Err(ResourceInputError::InvalidSecretName);
        }
        Ok(Self(value))
    }

    /// Borrow the exact secret name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact project, environment, and path coordinates for scoped reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretScope {
    project_id: ProjectId,
    environment: EnvironmentSlug,
    path: SecretPath,
    recursive: bool,
}

impl SecretScope {
    /// Construct a fully validated read scope.
    #[must_use]
    pub fn new(
        project_id: ProjectId,
        environment: EnvironmentSlug,
        path: SecretPath,
        recursive: bool,
    ) -> Self {
        Self {
            project_id,
            environment,
            path,
            recursive,
        }
    }

    /// Project coordinate.
    #[must_use]
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    /// Environment coordinate.
    #[must_use]
    pub fn environment(&self) -> &EnvironmentSlug {
        &self.environment
    }

    /// Secret-tree path coordinate.
    #[must_use]
    pub fn path(&self) -> &SecretPath {
        &self.path
    }

    /// Whether descendants are included.
    #[must_use]
    pub fn recursive(&self) -> bool {
        self.recursive
    }
}

pub(crate) fn paginate<T>(
    request: PageRequest,
    all_items: Vec<T>,
) -> Result<Page<T>, ResourceError> {
    let total = u64::try_from(all_items.len()).map_err(|_| ResourceError::CollectionTooLarge)?;
    let offset = usize::try_from(request.offset()).map_err(|_| PaginationError::OffsetLimit)?;
    let items = all_items
        .into_iter()
        .skip(offset)
        .take(usize::from(request.limit()))
        .collect();
    Ok(Page::new(request, items, Some(total))?)
}

/// Validation failures for coordinates supplied to typed resource calls.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ResourceInputError {
    #[error("project ID must contain 1 to 128 ASCII letters, numbers, hyphens, or underscores")]
    InvalidProjectId,
    #[error(
        "secret import ID must contain 1 to 128 ASCII letters, numbers, hyphens, or underscores"
    )]
    InvalidSecretImportId,
    #[error("secret import position must be between 1 and 100000")]
    InvalidSecretImportPosition,
    #[error("environment ID must contain 1 to 128 ASCII letters, numbers, hyphens, or underscores")]
    InvalidEnvironmentId,
    #[error("folder ID must contain 1 to 128 ASCII letters, numbers, hyphens, or underscores")]
    InvalidFolderId,
    #[error("tag ID must contain 1 to 128 ASCII letters, numbers, hyphens, or underscores")]
    InvalidTagId,
    #[error(
        "organization ID must contain 1 to 128 ASCII letters, numbers, hyphens, or underscores"
    )]
    InvalidOrganizationId,
    #[error(
        "machine identity ID must contain 1 to 128 ASCII letters, numbers, hyphens, or underscores"
    )]
    InvalidIdentityId,
    #[error("group ID must contain 1 to 128 ASCII letters, numbers, hyphens, or underscores")]
    InvalidGroupId,
    #[error(
        "additional privilege ID must contain 1 to 128 ASCII letters, numbers, hyphens, or underscores"
    )]
    InvalidAdditionalPrivilegeId,
    #[error(
        "project membership ID must contain 1 to 128 ASCII letters, numbers, hyphens, or underscores"
    )]
    InvalidProjectMembershipId,
    #[error(
        "Universal Auth client-secret ID must contain 1 to 128 ASCII letters, numbers, hyphens, or underscores"
    )]
    InvalidUniversalAuthClientSecretId,
    #[error(
        "Token Auth access-token ID must contain 1 to 128 ASCII letters, numbers, hyphens, or underscores"
    )]
    InvalidTokenAuthTokenId,
    #[error(
        "machine identity name must contain 1 to 128 bytes without surrounding whitespace or control characters"
    )]
    InvalidIdentityName,
    #[error(
        "project name must contain 1 to 64 bytes without surrounding whitespace or control characters"
    )]
    InvalidProjectName,
    #[error(
        "project description must contain at most 1024 bytes without surrounding whitespace or control characters"
    )]
    InvalidProjectDescription,
    #[error(
        "project slug must contain 5 to 36 lowercase letters or numbers separated by single hyphens or underscores"
    )]
    InvalidNewProjectSlug,
    #[error(
        "project slug must contain 1 to 64 lowercase letters or numbers separated by single hyphens or underscores"
    )]
    InvalidProjectSlug,
    #[error(
        "environment name must contain 1 to 64 bytes without surrounding whitespace or control characters"
    )]
    InvalidEnvironmentName,
    #[error("folder name must contain 1 to 255 ASCII letters, numbers, hyphens, or underscores")]
    InvalidFolderName,
    #[error(
        "folder description must contain at most 1024 bytes without surrounding whitespace or control characters"
    )]
    InvalidFolderDescription,
    #[error(
        "tag slug must contain 1 to 64 lowercase letters or numbers separated by single hyphens"
    )]
    InvalidTagSlug,
    #[error(
        "tag color must contain at most 32 bytes without surrounding whitespace or control characters"
    )]
    InvalidTagColor,
    #[error("environment position must be between 1 and 100000")]
    InvalidEnvironmentPosition,
    #[error("point-in-time version limit must be between 1 and 100")]
    InvalidPointInTimeVersionLimit,
    #[error(
        "environment slug must contain 1 to 64 lowercase letters or numbers separated by hyphens"
    )]
    InvalidEnvironmentSlug,
    #[error("secret path must be an absolute normalized path of at most 2048 bytes")]
    InvalidSecretPath,
    #[error(
        "secret name must contain 1 to 512 bytes without control characters, '/', ':', surrounding whitespace, or dot segments"
    )]
    InvalidSecretName,
}

/// Failures from a typed resource read after its coordinates are validated.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResourceError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Pagination(#[from] PaginationError),
    #[error("Infisical collection cannot be represented by the bounded paginator")]
    CollectionTooLarge,
    #[error("Infisical collection total did not match the returned records")]
    CollectionCountMismatch,
    #[error(
        "Infisical returned a different project; verify the requested project and upstream service"
    )]
    InvalidProjectResponse,
    #[error(
        "Infisical returned a different secret scope; verify the requested shared-secret coordinates and upstream service"
    )]
    InvalidSecretResponse,
    #[error("tagSlugs must contain at most sixteen distinct validated tag slugs")]
    InvalidSecretTagFilter,
    #[error("Infisical returned a secret outside the requested tag filter")]
    InvalidSecretTagResponse,
    #[error("secret deletion requires explicit confirmation")]
    DeletionNotConfirmed,
    #[error("secret batches must contain between 1 and 50 entries")]
    InvalidSecretBatchSize,
    #[error("secret batches must not contain duplicate names")]
    DuplicateSecretName,
    #[error("secret import deletion requires explicit confirmation")]
    SecretImportDeletionNotConfirmed,
    #[error("a secret import source cannot equal its target scope")]
    CyclicSecretImport,
    #[error("project deletion requires explicit confirmation")]
    ProjectDeletionNotConfirmed,
    #[error("environment deletion requires explicit confirmation")]
    EnvironmentDeletionNotConfirmed,
    #[error("folder deletion requires explicit confirmation")]
    FolderDeletionNotConfirmed,
    #[error("tag deletion requires explicit confirmation")]
    TagDeletionNotConfirmed,
    #[error("machine identity deletion requires explicit confirmation")]
    IdentityDeletionNotConfirmed,
    #[error("additional privilege deletion requires explicit confirmation")]
    AdditionalPrivilegeDeletionNotConfirmed,
    #[error("project membership deletion requires explicit confirmation")]
    ProjectMembershipDeletionNotConfirmed,
    #[error("complete project membership role replacement requires explicit confirmation")]
    ProjectMembershipRoleReplacementNotConfirmed,
    #[error("Universal Auth removal requires explicit confirmation")]
    UniversalAuthRemovalNotConfirmed,
    #[error("Universal Auth client-secret revocation requires explicit confirmation")]
    UniversalAuthClientSecretRevocationNotConfirmed,
    #[error("Token Auth removal requires explicit confirmation")]
    TokenAuthRemovalNotConfirmed,
    #[error("Token Auth access-token revocation requires explicit confirmation")]
    TokenAuthTokenRevocationNotConfirmed,
    #[error("Kubernetes Auth removal requires explicit confirmation")]
    KubernetesAuthRemovalNotConfirmed,
    #[error("Token Auth token-list offset exceeds the pinned route limit")]
    TokenAuthPageOffsetLimit,
    #[error(
        "Token Auth token name must contain 1 to 128 bytes without surrounding whitespace or control characters"
    )]
    InvalidTokenAuthTokenName,
    #[error("clearing Universal Auth lockouts requires explicit confirmation")]
    UniversalAuthLockoutClearNotConfirmed,
    #[error("folder batches must contain between 1 and 50 entries")]
    InvalidFolderBatchSize,
    #[error("folder batches must not contain duplicate folder IDs")]
    DuplicateFolderId,
    #[error("Infisical mutation response omitted the affected resource")]
    MissingMutationResource,
    #[error("Infisical role response omitted or mismatched its owning scope")]
    InvalidRoleScope,
    #[error("Infisical exact-role response omitted permission rules")]
    MissingRolePermissions,
    #[error("Infisical project group membership omitted or mismatched its owning scope")]
    InvalidGroupMembershipScope,
    #[error("Infisical group response mismatched the requested identifier or member type")]
    InvalidGroupResponse,
    #[error("Infisical group project response mismatched the requested assignment filter")]
    InvalidGroupProjectAssignment,
    #[error("Infisical additional privilege response mismatched its requested scope")]
    InvalidAdditionalPrivilegeScope,
    #[error("Infisical additional privilege response contained an incoherent lifetime")]
    InvalidAdditionalPrivilegeLifetime,
    #[error("Infisical additional privilege response contained malformed permission rules")]
    InvalidAdditionalPrivilegePermissions,
    #[error("Infisical audit-log response violated the requested bounded contract")]
    InvalidAuditLogResponse,
    #[error(
        "Infisical app-connection, secret-sync, or secret-rotation response violated the bounded value-free contract"
    )]
    InvalidAppAutomationResponse,
    #[error("audit environment, secret-path, and secret-key filters require a project ID")]
    AuditLogMetadataFilterRequiresProject,
    #[error("audit metadata filters require at least one filterable secret event type")]
    AuditLogMetadataFilterRequiresSecretEvent,
    #[error("Infisical dynamic-secret response violated the bounded value-free contract")]
    InvalidDynamicSecretResponse,
    #[error("Infisical dynamic-secret lease response violated the bounded value-free contract")]
    InvalidDynamicSecretLeaseResponse,
    #[error("dynamic-secret lease revocation requires explicit confirmation")]
    DynamicSecretLeaseRevocationNotConfirmed,
    #[error("dynamic-secret configuration deletion requires explicit confirmation")]
    DynamicSecretDeletionNotConfirmed,
    #[error("GitHub app-connection deletion requires explicit confirmation")]
    AppConnectionDeletionNotConfirmed,
    #[error("GitHub app-connection credential replacement requires explicit confirmation")]
    AppConnectionCredentialReplacementNotConfirmed,
    #[error("GitHub app-connection credential rotation requires explicit confirmation")]
    AppConnectionCredentialRotationNotConfirmed,
    #[error(
        "GitHub secret-sync creation requires confirmation that destination secrets may be overwritten"
    )]
    SecretSyncInitialOverwriteNotConfirmed,
    #[error("GitHub secret-sync update requires explicit confirmation")]
    SecretSyncUpdateNotConfirmed,
    #[error("GitHub secret-sync deletion requires explicit confirmation")]
    SecretSyncDeletionNotConfirmed,
    #[error("removing GitHub destination secrets requires separate explicit confirmation")]
    SecretSyncRemoteRemovalNotConfirmed,
    #[error("manually overwriting GitHub destination secrets requires explicit confirmation")]
    SecretSyncRunNotConfirmed,
    #[error(
        "the requested GitHub app-automation resource does not belong to the supplied project or environment"
    )]
    InvalidAppAutomationScope,
    #[error("dynamic-secret rename must change the configuration name")]
    DynamicSecretRenameWouldBeNoop,
    #[error("creating external SQL credentials and mapped secrets requires explicit confirmation")]
    SqlSecretRotationCreateNotConfirmed,
    #[error("updating SQL rotation configuration requires explicit confirmation")]
    SqlSecretRotationUpdateNotConfirmed,
    #[error("deleting a SQL secret rotation requires explicit confirmation")]
    SqlSecretRotationDeleteNotConfirmed,
    #[error("moving a SQL rotation and its mapped secrets requires explicit confirmation")]
    SqlSecretRotationMoveNotConfirmed,
    #[error("overwriting destination secrets requires separate explicit confirmation")]
    SqlSecretRotationOverwriteNotConfirmed,
    #[error("revealing generated SQL credentials requires explicit confirmation")]
    SqlSecretRotationRevealNotConfirmed,
    #[error("rotating external SQL credentials requires explicit confirmation")]
    SqlSecretRotationRotateNotConfirmed,
    #[error("checking credentials against the SQL provider requires explicit confirmation")]
    SqlSecretRotationCheckNotConfirmed,
    #[error("SQL secret-rotation target and change providers must match")]
    SqlSecretRotationProviderMismatch,
    #[error("KMS key deletion requires explicit confirmation")]
    KmsKeyDeletionNotConfirmed,
    #[error("KMS cryptographic operations require explicit confirmation")]
    KmsOperationNotConfirmed,
    #[error("revealing KMS plaintext or private key material requires explicit confirmation")]
    KmsSecretRevealNotConfirmed,
    #[error("the KMS key does not belong to the supplied project")]
    InvalidKmsKeyScope,
    #[error("the KMS key usage does not support the requested operation")]
    InvalidKmsKeyUsage,
    #[error("the KMS key is disabled")]
    KmsKeyDisabled,
    #[error(
        "KMS bulk requests must contain 1 to 100 unique keys and at most 512 KiB of aggregate decoded key material"
    )]
    InvalidKmsBulkRequest,
    #[error("KMS ciphertext or signature input violates the bounded base64 contract")]
    InvalidKmsCryptographicInput,
    #[error("Infisical KMS response violated the bounded typed contract")]
    InvalidKmsResponse,
    #[error("internal certificate-authority creation requires explicit confirmation")]
    CertificateAuthorityCreateNotConfirmed,
    #[error("internal certificate-authority update requires explicit confirmation")]
    CertificateAuthorityUpdateNotConfirmed,
    #[error("internal certificate-authority deletion requires explicit confirmation")]
    CertificateAuthorityDeleteNotConfirmed,
    #[error("internal certificate-authority certificate mutations require explicit confirmation")]
    CertificateAuthorityCertificateMutationNotConfirmed,
    #[error("the certificate authority does not belong to the supplied project")]
    InvalidCertificateAuthorityScope,
    #[error(
        "the certificate authority state or hierarchy does not support this certificate operation"
    )]
    InvalidCertificateAuthorityCertificateState,
    #[error("certificate-authority operations require a Certificate Manager project")]
    InvalidCertificateAuthorityProjectKind,
    #[error("Infisical certificate-authority response violated the bounded typed contract")]
    InvalidCertificateAuthorityResponse,
    #[error("certificate-policy creation requires explicit confirmation")]
    CertificatePolicyCreateNotConfirmed,
    #[error("certificate-policy update requires explicit confirmation")]
    CertificatePolicyUpdateNotConfirmed,
    #[error("certificate-policy deletion requires explicit confirmation")]
    CertificatePolicyDeleteNotConfirmed,
    #[error(
        "certificate policy is in use; change dependent Certificate Manager configuration before retrying deletion"
    )]
    CertificatePolicyInUse,
    #[error("the certificate policy does not belong to the supplied Certificate Manager project")]
    InvalidCertificatePolicyScope,
    #[error("Infisical certificate-policy response violated the bounded typed contract")]
    InvalidCertificatePolicyResponse,
    #[error("the certificate does not belong to the supplied Certificate Manager project")]
    InvalidCertificateInventoryScope,
    #[error("Infisical certificate inventory violated the bounded typed contract")]
    InvalidCertificateInventoryResponse,
    #[error("certificate import requires explicit confirmation")]
    CertificateImportNotConfirmed,
    #[error("certificate private material reveal requires explicit confirmation")]
    CertificateMaterialRevealNotConfirmed,
    #[error("the selected certificate has no stored private key")]
    CertificatePrivateKeyUnavailable,
    #[error("Infisical certificate material violated the bounded typed contract")]
    InvalidCertificateMaterialResponse,
    #[error(
        "certificate import may have been applied; search the project for the imported serial before retrying"
    )]
    CertificateImportOutcomeUnknown,
    #[error("certificate renewal requires explicit confirmation")]
    CertificateRenewalNotConfirmed,
    #[error("certificate revocation requires explicit confirmation")]
    CertificateRevocationNotConfirmed,
    #[error("certificate deletion requires explicit confirmation")]
    CertificateDeletionNotConfirmed,
    #[error("the certificate state does not support the requested lifecycle operation")]
    InvalidCertificateLifecycleState,
    #[error("Infisical certificate lifecycle response violated the bounded typed contract")]
    InvalidCertificateLifecycleResponse,
    #[error(
        "certificate renewal may have been applied; inspect the source certificate and recent certificate requests before retrying"
    )]
    CertificateRenewalOutcomeUnknown,
    #[error(
        "certificate revocation may have been applied; retrieve the certificate state before retrying"
    )]
    CertificateRevocationOutcomeUnknown,
    #[error(
        "certificate renewal configuration may have changed; retrieve the certificate before retrying"
    )]
    CertificateRenewalConfigurationOutcomeUnknown,
    #[error("certificate deletion may have been applied; retrieve the certificate before retrying")]
    CertificateDeletionOutcomeUnknown,
    #[error("Infisical certificate-request inventory violated the bounded typed contract")]
    InvalidCertificateRequestInventoryResponse,
    #[error("the certificate request was not found in the supplied Certificate Manager project")]
    InvalidCertificateRequestScope,
    #[error("the certificate request state does not support the requested operation")]
    InvalidCertificateRequestState,
    #[error("revealing certificate-request material requires explicit confirmation")]
    CertificateRequestRevealNotConfirmed,
    #[error("cancelling a certificate request requires explicit confirmation")]
    CertificateRequestCancelNotConfirmed,
    #[error("Infisical certificate-request material violated the bounded typed contract")]
    InvalidCertificateRequestMaterialResponse,
    #[error("Infisical certificate-request cancellation response violated the typed contract")]
    InvalidCertificateRequestCancellationResponse,
    #[error("certificate issuance requires explicit confirmation")]
    CertificateIssuanceNotConfirmed,
    #[error("certificate issuance requires a project-owned profile with API enrollment")]
    InvalidCertificateIssuanceProfile,
    #[error("Infisical certificate issuance response violated the bounded typed contract")]
    InvalidCertificateIssuanceResponse,
    #[error(
        "certificate issuance may have been applied; search certificate requests for the profile before retrying"
    )]
    CertificateIssuanceOutcomeUnknown,
    #[error(
        "certificate issuance response for request {request_id} could not be verified; inspect that request before retrying"
    )]
    CertificateIssuanceResponseUnverified { request_id: String },
    #[error("certificate-profile creation requires explicit confirmation")]
    CertificateProfileCreateNotConfirmed,
    #[error("certificate-profile update requires explicit confirmation")]
    CertificateProfileUpdateNotConfirmed,
    #[error("certificate-profile deletion requires explicit confirmation")]
    CertificateProfileDeleteNotConfirmed,
    #[error(
        "revealing certificate-profile private keys or ACME secrets requires explicit confirmation"
    )]
    CertificateProfileSecretRevealNotConfirmed,
    #[error("the certificate profile does not belong to the supplied Certificate Manager project")]
    InvalidCertificateProfileScope,
    #[error("the certificate profile state does not support the requested operation")]
    InvalidCertificateProfileState,
    #[error("Infisical certificate-profile response violated the bounded typed contract")]
    InvalidCertificateProfileResponse,
    #[error("code-signer creation requires explicit confirmation")]
    CodeSignerCreateNotConfirmed,
    #[error("code-signer update requires explicit confirmation")]
    CodeSignerUpdateNotConfirmed,
    #[error("code-signer deletion requires explicit confirmation")]
    CodeSignerDeleteNotConfirmed,
    #[error("code-signer status updates require explicit confirmation")]
    CodeSignerStatusUpdateNotConfirmed,
    #[error("code-signer certificate mutations require explicit confirmation")]
    CodeSignerCertificateMutationNotConfirmed,
    #[error("code-signing operations require explicit confirmation")]
    CodeSigningNotConfirmed,
    #[error("the code signer does not belong to the supplied Certificate Manager project")]
    InvalidCodeSignerScope,
    #[error("the code signer state does not support the requested operation")]
    InvalidCodeSignerState,
    #[error("the code-signer certificate state does not support the requested operation")]
    InvalidCodeSignerCertificateState,
    #[error("code-signer creation requires a certificate whose private key is stored in Infisical")]
    MissingCodeSignerCertificatePrivateKey,
    #[error("code-signing input violates the bounded data, digest, or algorithm contract")]
    InvalidCodeSigningInput,
    #[error("Infisical code-signer response violated the bounded typed contract")]
    InvalidCodeSignerResponse,
    #[error("code-signer governance mutations require explicit confirmation")]
    CodeSignerGovernanceMutationNotConfirmed,
    #[error("Infisical code-signer governance response violated the bounded typed contract")]
    InvalidCodeSignerGovernanceResponse,
    #[error("SSH certificate-authority creation requires explicit confirmation")]
    SshCertificateAuthorityCreateNotConfirmed,
    #[error("SSH certificate-authority replacement requires explicit confirmation")]
    SshCertificateAuthorityReplaceNotConfirmed,
    #[error("SSH certificate-authority deletion requires explicit confirmation")]
    SshCertificateAuthorityDeleteNotConfirmed,
    #[error("SSH certificate-template creation requires explicit confirmation")]
    SshCertificateTemplateCreateNotConfirmed,
    #[error("SSH certificate-template replacement requires explicit confirmation")]
    SshCertificateTemplateReplaceNotConfirmed,
    #[error("SSH certificate-template deletion requires explicit confirmation")]
    SshCertificateTemplateDeleteNotConfirmed,
    #[error("the SSH certificate authority does not belong to the supplied project")]
    InvalidSshCertificateAuthorityScope,
    #[error("the SSH certificate authority state does not support this operation")]
    InvalidSshCertificateAuthorityState,
    #[error("Infisical SSH certificate-authority response violated the bounded typed contract")]
    InvalidSshCertificateAuthorityResponse,
    #[error("the SSH certificate template does not belong to the supplied authority or project")]
    InvalidSshCertificateTemplateScope,
    #[error("Infisical SSH certificate-template response violated the bounded typed contract")]
    InvalidSshCertificateTemplateResponse,
    #[error("SSH certificate signing requires explicit confirmation")]
    SshCertificateSigningNotConfirmed,
    #[error("SSH certificate issuance and private-key reveal require explicit confirmation")]
    SshCertificateIssuanceNotConfirmed,
    #[error("the SSH certificate template state does not support signing or issuance")]
    InvalidSshCertificateTemplateState,
    #[error("the SSH certificate type is disabled by the selected template")]
    SshCertificateTypeNotAllowed,
    #[error("one or more SSH certificate principals are not allowed by the selected template")]
    SshCertificatePrincipalNotAllowed,
    #[error("the requested SSH certificate TTL exceeds the selected template maximum")]
    SshCertificateTtlNotAllowed,
    #[error("the selected SSH certificate template does not allow a custom key ID")]
    SshCertificateCustomKeyIdNotAllowed,
    #[error("Infisical SSH certificate response violated the signed bounded contract")]
    InvalidSshCertificateResponse,
    #[error("SSH host creation requires explicit confirmation")]
    SshHostCreateNotConfirmed,
    #[error("SSH host replacement requires explicit confirmation")]
    SshHostReplaceNotConfirmed,
    #[error("SSH host deletion requires explicit confirmation")]
    SshHostDeleteNotConfirmed,
    #[error("SSH host-certificate issuance requires explicit confirmation")]
    SshHostCertificateIssuanceNotConfirmed,
    #[error("the SSH host does not belong to the supplied project")]
    InvalidSshHostScope,
    #[error("Infisical SSH host response violated the bounded typed contract")]
    InvalidSshHostResponse,
    #[error("SSH host-group creation requires explicit confirmation")]
    SshHostGroupCreateNotConfirmed,
    #[error("SSH host-group replacement requires explicit confirmation")]
    SshHostGroupReplaceNotConfirmed,
    #[error("SSH host-group deletion requires explicit confirmation")]
    SshHostGroupDeleteNotConfirmed,
    #[error("SSH host-group membership changes require explicit confirmation")]
    SshHostGroupMembershipNotConfirmed,
    #[error("the SSH host group does not belong to the supplied project")]
    InvalidSshHostGroupScope,
    #[error("Infisical SSH host-group response violated the bounded typed contract")]
    InvalidSshHostGroupResponse,
    #[error("Infisical SSH host-group membership response violated the bounded typed contract")]
    InvalidSshHostGroupMembershipResponse,
}

#[cfg(test)]
mod tests {
    use super::{
        AdditionalPrivilegeId, EnvironmentId, EnvironmentName, EnvironmentPosition,
        EnvironmentSlug, FolderDescription, FolderId, FolderName, GroupId, IdentityId,
        IdentityName, NewProjectSlug, OrganizationId, PointInTimeVersionLimit, ProjectDescription,
        ProjectId, ProjectName, ProjectSlug, ResourceInputError, SecretImportId,
        SecretImportPosition, SecretName, SecretPath, TagColor, TagId, TagSlug, TokenAuthTokenId,
        UniversalAuthClientSecretId,
    };

    #[test]
    fn identity_coordinates_reject_ambiguous_or_unbounded_values() {
        assert_eq!(
            OrganizationId::new("org/escape").unwrap_err(),
            ResourceInputError::InvalidOrganizationId
        );
        assert_eq!(
            IdentityId::new("identity/escape").unwrap_err(),
            ResourceInputError::InvalidIdentityId
        );
        assert_eq!(
            GroupId::new("group/escape").unwrap_err(),
            ResourceInputError::InvalidGroupId
        );
        assert_eq!(
            AdditionalPrivilegeId::new("privilege/escape").unwrap_err(),
            ResourceInputError::InvalidAdditionalPrivilegeId
        );
        assert_eq!(
            UniversalAuthClientSecretId::new("secret/escape").unwrap_err(),
            ResourceInputError::InvalidUniversalAuthClientSecretId
        );
        assert_eq!(
            TokenAuthTokenId::new("token/escape").unwrap_err(),
            ResourceInputError::InvalidTokenAuthTokenId
        );
        assert_eq!(
            IdentityName::new(" padded ").unwrap_err(),
            ResourceInputError::InvalidIdentityName
        );
        assert!(IdentityName::new("i".repeat(128)).is_ok());
        assert_eq!(
            IdentityName::new("i".repeat(129)).unwrap_err(),
            ResourceInputError::InvalidIdentityName
        );
    }

    #[test]
    fn resource_coordinates_reject_ambiguous_or_unbounded_values() {
        assert_eq!(
            ProjectId::new("project/escape").unwrap_err(),
            ResourceInputError::InvalidProjectId
        );
        assert_eq!(
            SecretImportId::new("import/escape").unwrap_err(),
            ResourceInputError::InvalidSecretImportId
        );
        assert_eq!(
            SecretImportPosition::new(0).unwrap_err(),
            ResourceInputError::InvalidSecretImportPosition
        );
        assert_eq!(
            SecretImportPosition::new(100_001).unwrap_err(),
            ResourceInputError::InvalidSecretImportPosition
        );
        assert!(SecretImportPosition::new(100_000).is_ok());
        assert_eq!(
            EnvironmentId::new("env/escape").unwrap_err(),
            ResourceInputError::InvalidEnvironmentId
        );
        assert_eq!(
            ProjectName::new(" padded ").unwrap_err(),
            ResourceInputError::InvalidProjectName
        );
        assert_eq!(
            ProjectDescription::new("line\nbreak").unwrap_err(),
            ResourceInputError::InvalidProjectDescription
        );
        assert!(ProjectDescription::new("").is_ok());
        assert_eq!(
            NewProjectSlug::new("bad--slug").unwrap_err(),
            ResourceInputError::InvalidNewProjectSlug
        );
        assert_eq!(
            NewProjectSlug::new("four").unwrap_err(),
            ResourceInputError::InvalidNewProjectSlug
        );
        assert!(NewProjectSlug::new("valid-project").is_ok());
        assert_eq!(
            ProjectSlug::new("bad--slug").unwrap_err(),
            ResourceInputError::InvalidProjectSlug
        );
        assert_eq!(ProjectSlug::new("x").unwrap().as_str(), "x");
        assert_eq!(
            EnvironmentName::new("").unwrap_err(),
            ResourceInputError::InvalidEnvironmentName
        );
        assert_eq!(
            EnvironmentPosition::new(0).unwrap_err(),
            ResourceInputError::InvalidEnvironmentPosition
        );
        assert!(EnvironmentPosition::new(100_000).is_ok());
        assert_eq!(
            PointInTimeVersionLimit::new(0).unwrap_err(),
            ResourceInputError::InvalidPointInTimeVersionLimit
        );
        assert!(PointInTimeVersionLimit::new(100).is_ok());
        assert_eq!(
            EnvironmentSlug::new("Prod").unwrap_err(),
            ResourceInputError::InvalidEnvironmentSlug
        );
        for path in ["relative", "/trailing/", "/double//segment", "/../escape"] {
            assert_eq!(
                SecretPath::new(path).unwrap_err(),
                ResourceInputError::InvalidSecretPath
            );
        }

        assert_eq!(
            ProjectId::new("project_123").unwrap().as_str(),
            "project_123"
        );
        assert_eq!(
            EnvironmentSlug::new("production-us1").unwrap().as_str(),
            "production-us1"
        );
        assert_eq!(
            SecretPath::new("/payments/api keys").unwrap().as_str(),
            "/payments/api keys"
        );

        for name in [
            "",
            " padded",
            "padded ",
            "nested/name",
            "reference:name",
            "bad\nname",
            ".",
            "..",
        ] {
            assert_eq!(
                SecretName::new(name).unwrap_err(),
                ResourceInputError::InvalidSecretName
            );
        }
        assert_eq!(
            SecretName::new("STRIPE API KEY").unwrap().as_str(),
            "STRIPE API KEY"
        );
    }

    #[test]
    fn folder_and_tag_coordinates_reject_ambiguous_or_unbounded_values() {
        assert_eq!(
            FolderId::new("folder/escape").unwrap_err(),
            ResourceInputError::InvalidFolderId
        );
        assert_eq!(
            TagId::new("tag/escape").unwrap_err(),
            ResourceInputError::InvalidTagId
        );
        assert_eq!(
            FolderName::new("bad name").unwrap_err(),
            ResourceInputError::InvalidFolderName
        );
        assert_eq!(FolderName::new("api_keys").unwrap().as_str(), "api_keys");
        assert_eq!(
            FolderDescription::new("line\nbreak").unwrap_err(),
            ResourceInputError::InvalidFolderDescription
        );
        assert!(FolderDescription::new("").is_ok());
        assert_eq!(
            TagSlug::new("Bad-Tag").unwrap_err(),
            ResourceInputError::InvalidTagSlug
        );
        assert_eq!(
            TagSlug::new("critical-tag").unwrap().as_str(),
            "critical-tag"
        );
        assert_eq!(
            TagColor::new(" padded ").unwrap_err(),
            ResourceInputError::InvalidTagColor
        );
        assert_eq!(TagColor::new("#ff0000").unwrap().as_str(), "#ff0000");
    }
}
