use std::net::IpAddr;

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    InfisicalClient, MutationOperation, ObservableReadOperation, ResourceError,
    SignedSshCertificate, SshCaStatus, SshCertificateAuthorityId, SshCertificateRequest,
    SshCertificateType, SshProjectId, SshPublicKey,
    client::{ApiVersion, Endpoint, sealed},
    resources::utc_timestamp_millis,
    ssh_certificate_templates::{valid_host_pattern, valid_user_pattern},
    ssh_certificates::{SignedSshCertificateWire, unix_timestamp, validate_signed_certificate},
};

const MAX_SSH_HOST_ENTRIES: usize = 500;
const MAX_SSH_HOST_GROUP_ENTRIES: usize = 500;
const MAX_SSH_HOST_GROUP_MEMBERS: usize = 500;
const MAX_SSH_LOGIN_MAPPINGS: usize = 64;
const MAX_SSH_LOGIN_PRINCIPALS: usize = 128;
const MAX_SSH_USERNAME_BYTES: usize = 254;
const MAX_SSH_GROUP_NAME_BYTES: usize = 64;
const MAX_SSH_ALIAS_BYTES: usize = 64;
const MAX_SSH_HOST_DURATION_MILLIS: u64 = 315_360_000_000;

/// Input validation failures for SSH hosts and host groups.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SshHostInputError {
    #[error("SSH host and host-group IDs must be UUIDs")]
    InvalidId,
    #[error("SSH hostnames must be bounded fully qualified domain names")]
    InvalidHostname,
    #[error("SSH host aliases must be empty or lowercase slugs up to 64 bytes")]
    InvalidAlias,
    #[error("SSH host durations must be canonical positive durations up to ten years")]
    InvalidDuration,
    #[error("SSH host-group names must be lowercase slugs up to 64 bytes")]
    InvalidGroupName,
    #[error("SSH login mappings must be bounded, unique, and contain valid principals")]
    InvalidLoginMappings,
}

/// A validated SSH host identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SshHostId(
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    String,
);

impl SshHostId {
    /// Validate a UUID before it reaches an SSH host URL path.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, SshHostInputError> {
        let value = value.into();
        if !crate::resources::is_uuid(&value) {
            return Err(SshHostInputError::InvalidId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Borrow the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated SSH host-group identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SshHostGroupId(
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    String,
);

impl SshHostGroupId {
    /// Validate a UUID before it reaches an SSH host-group URL path.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, SshHostInputError> {
        let value = value.into();
        if !crate::resources::is_uuid(&value) {
            return Err(SshHostInputError::InvalidId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Borrow the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A canonical positive SSH host lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SshHostDuration(
    #[schemars(regex(pattern = r"^[1-9][0-9]*(?:ms|s|m|h|d|w|y)$"), length(max = 32))] String,
);

impl SshHostDuration {
    /// Validate an integer duration using `ms`, `s`, `m`, `h`, `d`, `w`, or `y`.
    ///
    /// # Errors
    ///
    /// Returns an error for zero, malformed, non-canonical, or excessive values.
    pub fn new(value: impl Into<String>) -> Result<Self, SshHostInputError> {
        let value = value.into();
        if host_duration_millis(&value).is_none() {
            return Err(SshHostInputError::InvalidDuration);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical duration.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn seconds(&self) -> u64 {
        host_duration_millis(&self.0)
            .expect("SshHostDuration construction proves its invariant")
            .div_ceil(1_000)
    }
}

/// Origin of one effective host login mapping.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum SshLoginMappingSource {
    /// Mapping configured directly on the host.
    Host,
    /// Mapping inherited from a host group.
    HostGroup,
}

/// Bounded principal selectors allowed to use one host login account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshAllowedPrincipals {
    /// Canonical bounded Infisical usernames.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 128))]
    pub usernames: Vec<String>,
    /// Canonical bounded Infisical group slugs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 128))]
    pub groups: Vec<String>,
}

/// One canonical SSH login mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshLoginMapping {
    /// Bounded operating-system account.
    #[schemars(regex(pattern = r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$"))]
    pub login_user: String,
    /// Bounded users and groups allowed to assume the account.
    pub allowed_principals: SshAllowedPrincipals,
}

impl SshLoginMapping {
    /// Validate and canonicalize one direct login mapping.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe login account or malformed principal selectors.
    pub fn new(
        login_user: impl Into<String>,
        usernames: Vec<String>,
        groups: Vec<String>,
    ) -> Result<Self, SshHostInputError> {
        let login_user = login_user.into();
        let allowed_principals = canonical_principals(usernames, groups)?;
        if !valid_user_pattern(&login_user) || login_user == "*" {
            return Err(SshHostInputError::InvalidLoginMappings);
        }
        Ok(Self {
            login_user,
            allowed_principals,
        })
    }
}

/// One effective host login mapping, including its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveSshLoginMapping {
    /// Bounded operating-system account.
    #[schemars(regex(pattern = r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$"))]
    pub login_user: String,
    /// Bounded users and groups allowed to assume the account.
    pub allowed_principals: SshAllowedPrincipals,
    /// Direct or inherited origin.
    pub source: SshLoginMappingSource,
}

/// Complete input for registering an SSH host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshHostCreation {
    hostname: String,
    alias: String,
    user_cert_ttl: SshHostDuration,
    host_cert_ttl: SshHostDuration,
    login_mappings: Vec<SshLoginMapping>,
    user_ssh_ca_id: SshCertificateAuthorityId,
    host_ssh_ca_id: SshCertificateAuthorityId,
}

impl SshHostCreation {
    /// Validate a complete host definition with explicit user and host CAs.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe hostname, alias, or login-mapping set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hostname: impl Into<String>,
        alias: impl Into<String>,
        user_cert_ttl: SshHostDuration,
        host_cert_ttl: SshHostDuration,
        login_mappings: Vec<SshLoginMapping>,
        user_ssh_ca_id: SshCertificateAuthorityId,
        host_ssh_ca_id: SshCertificateAuthorityId,
    ) -> Result<Self, SshHostInputError> {
        let hostname = hostname.into();
        Ok(Self {
            hostname: validate_hostname(&hostname)?,
            alias: validate_slug(alias.into(), true)?,
            user_cert_ttl,
            host_cert_ttl,
            login_mappings: canonical_mappings(login_mappings)?,
            user_ssh_ca_id,
            host_ssh_ca_id,
        })
    }
}

/// Full replacement of every mutable SSH host field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshHostReplacement {
    hostname: String,
    alias: String,
    user_cert_ttl: SshHostDuration,
    host_cert_ttl: SshHostDuration,
    login_mappings: Vec<SshLoginMapping>,
}

impl SshHostReplacement {
    /// Validate a complete replacement for the host's mutable fields.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe hostname, alias, or login-mapping set.
    pub fn new(
        hostname: impl Into<String>,
        alias: impl Into<String>,
        user_cert_ttl: SshHostDuration,
        host_cert_ttl: SshHostDuration,
        login_mappings: Vec<SshLoginMapping>,
    ) -> Result<Self, SshHostInputError> {
        let hostname = hostname.into();
        Ok(Self {
            hostname: validate_hostname(&hostname)?,
            alias: validate_slug(alias.into(), true)?,
            user_cert_ttl,
            host_cert_ttl,
            login_mappings: canonical_mappings(login_mappings)?,
        })
    }
}

/// A bounded SSH host and its effective login policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshHost {
    /// Canonical UUID of the host.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub id: String,
    /// Canonical UUID of the owning SSH Access project.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub project_id: String,
    /// Canonical fully qualified DNS hostname certified by this host record.
    #[schemars(length(min = 1, max = 253))]
    pub hostname: String,
    /// Empty or canonical lowercase operational alias.
    #[schemars(regex(pattern = r"^(?:[a-z0-9]+(?:-[a-z0-9]+)*)?$"), length(max = 64))]
    pub alias: String,
    /// Canonical configured user-certificate lifetime.
    pub user_cert_ttl: SshHostDuration,
    /// Canonical configured host-certificate lifetime.
    pub host_cert_ttl: SshHostDuration,
    /// Canonical UUID of the linked user certificate authority.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub user_ssh_ca_id: String,
    /// Canonical UUID of the linked host certificate authority.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub host_ssh_ca_id: String,
    /// Bounded canonical direct and inherited login mappings.
    #[schemars(length(max = 128))]
    pub login_mappings: Vec<EffectiveSshLoginMapping>,
}

/// Complete SSH host-group policy used for creation or replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshHostGroupPolicy {
    name: String,
    login_mappings: Vec<SshLoginMapping>,
}

impl SshHostGroupPolicy {
    /// Validate one complete host-group policy.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe group name or login-mapping set.
    pub fn new(
        name: impl Into<String>,
        login_mappings: Vec<SshLoginMapping>,
    ) -> Result<Self, SshHostInputError> {
        Ok(Self {
            name: validate_slug(name.into(), false)?,
            login_mappings: canonical_mappings(login_mappings)?,
        })
    }
}

/// Bounded SSH host-group metadata and direct login policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshHostGroup {
    /// Canonical UUID of the host group.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub id: String,
    /// Canonical UUID of the owning SSH Access project.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub project_id: String,
    /// Canonical lowercase host-group slug.
    #[schemars(
        regex(pattern = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"),
        length(min = 1, max = 64)
    )]
    pub name: String,
    /// Complete bounded direct login policy for the group.
    #[schemars(length(max = 64))]
    pub login_mappings: Vec<SshLoginMapping>,
    /// Reflected non-negative host count, present only in project inventory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_count: Option<u64>,
}

/// Membership filter for one SSH host group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SshHostGroupMembershipFilter {
    /// Return only current members.
    #[serde(rename = "group-members")]
    Members,
    /// Return only hosts that are not current members.
    #[serde(rename = "non-group-members")]
    NonMembers,
}

/// One bounded host entry in a membership query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshHostGroupMember {
    /// Canonical UUID of the host.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub id: String,
    /// Canonical fully qualified DNS hostname.
    #[schemars(length(min = 1, max = 253))]
    pub hostname: String,
    /// Empty or canonical lowercase operational alias.
    #[schemars(regex(pattern = r"^(?:[a-z0-9]+(?:-[a-z0-9]+)*)?$"), length(max = 64))]
    pub alias: String,
    /// Whether the host is a member of the exact queried group.
    pub is_part_of_group: bool,
    /// Canonical UTC join timestamp, present exactly for current members.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        regex(
            pattern = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3})?Z$"
        ),
        length(min = 20, max = 24)
    )]
    pub joined_group_at: Option<String>,
}

/// Bounded membership results for one exact SSH host group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshHostGroupMembers {
    /// Canonical UUID of the exact queried host group.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub group_id: String,
    /// Canonical UUID of the owning SSH Access project.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub project_id: String,
    /// Membership state selected by the query.
    pub filter: SshHostGroupMembershipFilter,
    /// Reflected number of hosts, equal to the bounded returned collection.
    #[schemars(range(max = 500))]
    pub total_count: u64,
    /// Canonical unique hosts matching the exact membership filter.
    #[schemars(length(max = 500))]
    pub hosts: Vec<SshHostGroupMember>,
}

/// Receipt for one reflected host-group membership mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshHostGroupMembershipReceipt {
    /// Canonical UUID of the owning SSH Access project.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub project_id: String,
    /// Canonical UUID of the host group changed by the exact route.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub group_id: String,
    /// Canonical UUID of the host changed by the exact route.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub host_id: String,
    /// Canonical hostname reflected by the mutation response and preflight.
    #[schemars(length(min = 1, max = 253))]
    pub hostname: String,
    /// Membership state implied by successful completion of the exact add or remove route.
    pub is_part_of_group: bool,
}

/// Public key linked to one exact host through one exact SSH CA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshHostLinkedCaPublicKey {
    /// Canonical UUID of the exact host.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub host_id: String,
    /// Canonical UUID of the linked certificate authority.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub ca_id: String,
    /// Canonical bounded OpenSSH public key verified against the linked CA.
    pub public_key: SshPublicKey,
}

fn host_duration_millis(value: &str) -> Option<u64> {
    let digit_count = value.bytes().take_while(u8::is_ascii_digit).count();
    if digit_count == 0 || value.starts_with('0') {
        return None;
    }
    let amount = value[..digit_count].parse::<u64>().ok()?;
    let multiplier = match &value[digit_count..] {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        "w" => 604_800_000,
        "y" => 31_536_000_000,
        _ => return None,
    };
    let millis = amount.checked_mul(multiplier)?;
    (millis <= MAX_SSH_HOST_DURATION_MILLIS).then_some(millis)
}

fn validate_hostname(value: &str) -> Result<String, SshHostInputError> {
    if value != value.trim()
        || value == "*"
        || value.starts_with("*.")
        || value.parse::<IpAddr>().is_ok()
        || !valid_host_pattern(value)
    {
        return Err(SshHostInputError::InvalidHostname);
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_slug(value: String, allow_empty: bool) -> Result<String, SshHostInputError> {
    let valid = (allow_empty && value.is_empty())
        || (!value.is_empty()
            && value.len() <= MAX_SSH_ALIAS_BYTES
            && value.split('-').all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            }));
    if !valid {
        return Err(if allow_empty {
            SshHostInputError::InvalidAlias
        } else {
            SshHostInputError::InvalidGroupName
        });
    }
    Ok(value)
}

fn valid_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SSH_USERNAME_BYTES
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn valid_group_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SSH_GROUP_NAME_BYTES
        && value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn canonical_principals(
    mut usernames: Vec<String>,
    mut groups: Vec<String>,
) -> Result<SshAllowedPrincipals, SshHostInputError> {
    if usernames.iter().any(|value| !valid_username(value))
        || groups.iter().any(|value| !valid_group_name(value))
    {
        return Err(SshHostInputError::InvalidLoginMappings);
    }
    usernames.sort_unstable();
    groups.sort_unstable();
    if usernames.windows(2).any(|pair| pair[0] == pair[1])
        || groups.windows(2).any(|pair| pair[0] == pair[1])
        || usernames.len() + groups.len() == 0
        || usernames.len() + groups.len() > MAX_SSH_LOGIN_PRINCIPALS
    {
        return Err(SshHostInputError::InvalidLoginMappings);
    }
    Ok(SshAllowedPrincipals { usernames, groups })
}

fn canonical_mappings(
    mut mappings: Vec<SshLoginMapping>,
) -> Result<Vec<SshLoginMapping>, SshHostInputError> {
    if mappings.len() > MAX_SSH_LOGIN_MAPPINGS {
        return Err(SshHostInputError::InvalidLoginMappings);
    }
    mappings.sort_unstable_by(|left, right| left.login_user.cmp(&right.login_user));
    if mappings
        .windows(2)
        .any(|pair| pair[0].login_user == pair[1].login_user)
    {
        return Err(SshHostInputError::InvalidLoginMappings);
    }
    Ok(mappings)
}

#[derive(Serialize)]
struct ProjectQuery {
    #[serde(skip_serializing)]
    project_id: SshProjectId,
}

#[derive(Serialize)]
struct ExactHostQuery {
    #[serde(skip_serializing)]
    host_id: SshHostId,
}

#[derive(Serialize)]
struct ExactGroupQuery {
    #[serde(skip_serializing)]
    group_id: SshHostGroupId,
}

#[derive(Serialize)]
struct GroupMembersQuery {
    #[serde(skip_serializing)]
    group_id: SshHostGroupId,
    filter: SshHostGroupMembershipFilter,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AllowedPrincipalsWire {
    #[serde(default)]
    usernames: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginMappingWire {
    login_user: String,
    allowed_principals: AllowedPrincipalsWire,
    #[serde(default)]
    source: Option<SshLoginMappingSource>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshHostWire {
    id: String,
    project_id: String,
    hostname: String,
    #[serde(default)]
    alias: Option<String>,
    user_cert_ttl: String,
    host_cert_ttl: String,
    user_ssh_ca_id: String,
    host_ssh_ca_id: String,
    login_mappings: Vec<LoginMappingWire>,
}

#[derive(Deserialize)]
struct SshHostListResponse {
    hosts: Vec<SshHostWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshHostGroupWire {
    id: String,
    project_id: String,
    name: String,
    login_mappings: Vec<LoginMappingWire>,
    #[serde(default)]
    host_count: Option<u64>,
}

#[derive(Deserialize)]
struct SshHostGroupListResponse {
    groups: Vec<SshHostGroupWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshHostGroupMemberWire {
    id: String,
    hostname: String,
    #[serde(default)]
    alias: Option<String>,
    is_part_of_group: bool,
    joined_group_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshHostGroupMembersResponse {
    hosts: Vec<SshHostGroupMemberWire>,
    total_count: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MembershipMutationWire {
    id: String,
    project_id: String,
    hostname: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginMappingRequest {
    login_user: String,
    allowed_principals: SshAllowedPrincipals,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateHostRequest {
    project_id: String,
    hostname: String,
    alias: String,
    user_cert_ttl: String,
    host_cert_ttl: String,
    login_mappings: Vec<LoginMappingRequest>,
    user_ssh_ca_id: String,
    host_ssh_ca_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplaceHostRequest {
    #[serde(skip_serializing)]
    host_id: SshHostId,
    hostname: String,
    alias: String,
    user_cert_ttl: String,
    host_cert_ttl: String,
    login_mappings: Vec<LoginMappingRequest>,
}

#[derive(Serialize)]
struct DeleteHostRequest {
    #[serde(skip_serializing)]
    host_id: SshHostId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IssueHostCertificateRequest {
    #[serde(skip_serializing)]
    host_id: SshHostId,
    public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateGroupRequest {
    project_id: String,
    name: String,
    login_mappings: Vec<LoginMappingRequest>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplaceGroupRequest {
    #[serde(skip_serializing)]
    group_id: SshHostGroupId,
    name: String,
    login_mappings: Vec<LoginMappingRequest>,
}

#[derive(Serialize)]
struct DeleteGroupRequest {
    #[serde(skip_serializing)]
    group_id: SshHostGroupId,
}

#[derive(Serialize)]
struct GroupMembershipMutationRequest {
    #[serde(skip_serializing)]
    group_id: SshHostGroupId,
    #[serde(skip_serializing)]
    host_id: SshHostId,
}

struct ListHosts;
impl sealed::Sealed for ListHosts {}
impl ObservableReadOperation for ListHosts {
    type Query = ProjectQuery;
    type Output = SshHostListResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["projects", query.project_id.as_str(), "ssh-hosts"],
        )
    }
}

struct GetHost;
impl sealed::Sealed for GetHost {}
impl ObservableReadOperation for GetHost {
    type Query = ExactHostQuery;
    type Output = SshHostWire;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["ssh", "hosts", query.host_id.as_str()])
    }
}

struct GetUserCaPublicKey;
impl sealed::Sealed for GetUserCaPublicKey {}
impl ObservableReadOperation for GetUserCaPublicKey {
    type Query = ExactHostQuery;
    type Output = String;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["ssh", "hosts", query.host_id.as_str(), "user-ca-public-key"],
        )
    }
}

struct GetHostCaPublicKey;
impl sealed::Sealed for GetHostCaPublicKey {}
impl ObservableReadOperation for GetHostCaPublicKey {
    type Query = ExactHostQuery;
    type Output = String;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["ssh", "hosts", query.host_id.as_str(), "host-ca-public-key"],
        )
    }
}

struct ListGroups;
impl sealed::Sealed for ListGroups {}
impl ObservableReadOperation for ListGroups {
    type Query = ProjectQuery;
    type Output = SshHostGroupListResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["projects", query.project_id.as_str(), "ssh-host-groups"],
        )
    }
}

struct GetGroup;
impl sealed::Sealed for GetGroup {}
impl ObservableReadOperation for GetGroup {
    type Query = ExactGroupQuery;
    type Output = SshHostGroupWire;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["ssh", "host-groups", query.group_id.as_str()],
        )
    }
}

struct ListGroupMembers;
impl sealed::Sealed for ListGroupMembers {}
impl ObservableReadOperation for ListGroupMembers {
    type Query = GroupMembersQuery;
    type Output = SshHostGroupMembersResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            ["ssh", "host-groups", query.group_id.as_str(), "hosts"],
        )
    }
}

macro_rules! host_mutation {
    ($name:ident, $input:ty, $output:ty, $method:expr, $segments:expr) => {
        struct $name;
        impl sealed::Sealed for $name {}
        impl MutationOperation for $name {
            type Input = $input;
            type Output = $output;

            fn method() -> Method {
                $method
            }

            fn endpoint(input: &Self::Input) -> Endpoint {
                Endpoint::from_segments(ApiVersion::V1, ($segments)(input))
            }
        }
    };
}

host_mutation!(
    CreateHost,
    CreateHostRequest,
    SshHostWire,
    Method::POST,
    |_input: &CreateHostRequest| vec!["ssh".to_owned(), "hosts".to_owned()]
);
host_mutation!(
    ReplaceHost,
    ReplaceHostRequest,
    SshHostWire,
    Method::PATCH,
    |input: &ReplaceHostRequest| vec![
        "ssh".to_owned(),
        "hosts".to_owned(),
        input.host_id.as_str().to_owned()
    ]
);
host_mutation!(
    DeleteHost,
    DeleteHostRequest,
    SshHostWire,
    Method::DELETE,
    |input: &DeleteHostRequest| vec![
        "ssh".to_owned(),
        "hosts".to_owned(),
        input.host_id.as_str().to_owned()
    ]
);
host_mutation!(
    IssueHostCertificate,
    IssueHostCertificateRequest,
    SignedSshCertificateWire,
    Method::POST,
    |input: &IssueHostCertificateRequest| vec![
        "ssh".to_owned(),
        "hosts".to_owned(),
        input.host_id.as_str().to_owned(),
        "issue-host-cert".to_owned()
    ]
);
host_mutation!(
    CreateGroup,
    CreateGroupRequest,
    SshHostGroupWire,
    Method::POST,
    |_input: &CreateGroupRequest| vec!["ssh".to_owned(), "host-groups".to_owned()]
);
host_mutation!(
    ReplaceGroup,
    ReplaceGroupRequest,
    SshHostGroupWire,
    Method::PATCH,
    |input: &ReplaceGroupRequest| vec![
        "ssh".to_owned(),
        "host-groups".to_owned(),
        input.group_id.as_str().to_owned()
    ]
);
host_mutation!(
    DeleteGroup,
    DeleteGroupRequest,
    SshHostGroupWire,
    Method::DELETE,
    |input: &DeleteGroupRequest| vec![
        "ssh".to_owned(),
        "host-groups".to_owned(),
        input.group_id.as_str().to_owned()
    ]
);

macro_rules! membership_mutation {
    ($name:ident, $method:expr) => {
        struct $name;
        impl sealed::Sealed for $name {}
        impl MutationOperation for $name {
            type Input = GroupMembershipMutationRequest;
            type Output = MembershipMutationWire;

            fn method() -> Method {
                $method
            }

            fn endpoint(input: &Self::Input) -> Endpoint {
                Endpoint::from_segments(
                    ApiVersion::V1,
                    [
                        "ssh",
                        "host-groups",
                        input.group_id.as_str(),
                        "hosts",
                        input.host_id.as_str(),
                    ],
                )
            }

            fn sends_json_body() -> bool {
                false
            }
        }
    };
}

membership_mutation!(AddGroupMember, Method::POST);
membership_mutation!(RemoveGroupMember, Method::DELETE);

fn mapping_requests(mappings: &[SshLoginMapping]) -> Vec<LoginMappingRequest> {
    mappings
        .iter()
        .map(|mapping| LoginMappingRequest {
            login_user: mapping.login_user.clone(),
            allowed_principals: mapping.allowed_principals.clone(),
        })
        .collect()
}

fn mapping_from_wire(
    wire: LoginMappingWire,
    source_required: bool,
) -> Result<(SshLoginMapping, Option<SshLoginMappingSource>), ResourceError> {
    if source_required != wire.source.is_some() {
        return Err(ResourceError::InvalidSshHostResponse);
    }
    let mapping = SshLoginMapping::new(
        wire.login_user,
        wire.allowed_principals.usernames,
        wire.allowed_principals.groups,
    )
    .map_err(|_| ResourceError::InvalidSshHostResponse)?;
    Ok((mapping, wire.source))
}

fn host_from_wire(
    wire: SshHostWire,
    project_id: &SshProjectId,
    expected_id: Option<&SshHostId>,
) -> Result<SshHost, ResourceError> {
    let id = SshHostId::new(wire.id).map_err(|_| ResourceError::InvalidSshHostResponse)?;
    let response_project =
        SshProjectId::new(wire.project_id).map_err(|_| ResourceError::InvalidSshHostResponse)?;
    if &response_project != project_id || expected_id.is_some_and(|expected| expected != &id) {
        return Err(ResourceError::InvalidSshHostScope);
    }
    if wire.login_mappings.len() > MAX_SSH_LOGIN_MAPPINGS * 2 {
        return Err(ResourceError::InvalidSshHostResponse);
    }
    let mut login_mappings = wire
        .login_mappings
        .into_iter()
        .map(|mapping| {
            let (mapping, source) = mapping_from_wire(mapping, true)?;
            Ok(EffectiveSshLoginMapping {
                login_user: mapping.login_user,
                allowed_principals: mapping.allowed_principals,
                source: source.expect("source presence checked"),
            })
        })
        .collect::<Result<Vec<_>, ResourceError>>()?;
    login_mappings.sort_unstable_by(|left, right| {
        left.source
            .cmp(&right.source)
            .then_with(|| left.login_user.cmp(&right.login_user))
    });
    if login_mappings
        .windows(2)
        .any(|pair| pair[0].source == pair[1].source && pair[0].login_user == pair[1].login_user)
    {
        return Err(ResourceError::InvalidSshHostResponse);
    }
    let user_ca = SshCertificateAuthorityId::new(wire.user_ssh_ca_id)
        .map_err(|_| ResourceError::InvalidSshHostResponse)?;
    let host_ca = SshCertificateAuthorityId::new(wire.host_ssh_ca_id)
        .map_err(|_| ResourceError::InvalidSshHostResponse)?;
    Ok(SshHost {
        id: id.as_str().to_owned(),
        project_id: response_project.as_str().to_owned(),
        hostname: validate_hostname(&wire.hostname)
            .map_err(|_| ResourceError::InvalidSshHostResponse)?,
        alias: validate_slug(wire.alias.unwrap_or_default(), true)
            .map_err(|_| ResourceError::InvalidSshHostResponse)?,
        user_cert_ttl: SshHostDuration::new(wire.user_cert_ttl)
            .map_err(|_| ResourceError::InvalidSshHostResponse)?,
        host_cert_ttl: SshHostDuration::new(wire.host_cert_ttl)
            .map_err(|_| ResourceError::InvalidSshHostResponse)?,
        user_ssh_ca_id: user_ca.as_str().to_owned(),
        host_ssh_ca_id: host_ca.as_str().to_owned(),
        login_mappings,
    })
}

fn direct_mappings(host: &SshHost) -> Vec<SshLoginMapping> {
    host.login_mappings
        .iter()
        .filter(|mapping| mapping.source == SshLoginMappingSource::Host)
        .map(|mapping| SshLoginMapping {
            login_user: mapping.login_user.clone(),
            allowed_principals: mapping.allowed_principals.clone(),
        })
        .collect()
}

fn group_from_wire(
    wire: SshHostGroupWire,
    project_id: &SshProjectId,
    expected_id: Option<&SshHostGroupId>,
    inventory: bool,
) -> Result<SshHostGroup, ResourceError> {
    let id =
        SshHostGroupId::new(wire.id).map_err(|_| ResourceError::InvalidSshHostGroupResponse)?;
    let response_project = SshProjectId::new(wire.project_id)
        .map_err(|_| ResourceError::InvalidSshHostGroupResponse)?;
    if &response_project != project_id || expected_id.is_some_and(|expected| expected != &id) {
        return Err(ResourceError::InvalidSshHostGroupScope);
    }
    if inventory != wire.host_count.is_some() || wire.login_mappings.len() > MAX_SSH_LOGIN_MAPPINGS
    {
        return Err(ResourceError::InvalidSshHostGroupResponse);
    }
    let mut login_mappings = wire
        .login_mappings
        .into_iter()
        .map(|mapping| {
            mapping_from_wire(mapping, false)
                .map(|(mapping, _)| mapping)
                .map_err(|_| ResourceError::InvalidSshHostGroupResponse)
        })
        .collect::<Result<Vec<_>, _>>()?;
    login_mappings = canonical_mappings(login_mappings)
        .map_err(|_| ResourceError::InvalidSshHostGroupResponse)?;
    let name =
        validate_slug(wire.name, false).map_err(|_| ResourceError::InvalidSshHostGroupResponse)?;
    Ok(SshHostGroup {
        id: id.as_str().to_owned(),
        project_id: response_project.as_str().to_owned(),
        name,
        login_mappings,
        host_count: wire.host_count,
    })
}

fn host_matches_creation(host: &SshHost, creation: &SshHostCreation) -> bool {
    host.hostname == creation.hostname
        && host.alias == creation.alias
        && host.user_cert_ttl == creation.user_cert_ttl
        && host.host_cert_ttl == creation.host_cert_ttl
        && host.user_ssh_ca_id == creation.user_ssh_ca_id.as_str()
        && host.host_ssh_ca_id == creation.host_ssh_ca_id.as_str()
        && direct_mappings(host) == creation.login_mappings
}

fn host_matches_replacement(
    host: &SshHost,
    before: &SshHost,
    replacement: &SshHostReplacement,
) -> bool {
    host.hostname == replacement.hostname
        && host.alias == replacement.alias
        && host.user_cert_ttl == replacement.user_cert_ttl
        && host.host_cert_ttl == replacement.host_cert_ttl
        && host.user_ssh_ca_id == before.user_ssh_ca_id
        && host.host_ssh_ca_id == before.host_ssh_ca_id
        && direct_mappings(host) == replacement.login_mappings
}

impl InfisicalClient {
    /// List a bounded, canonical inventory of SSH hosts in one project.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, duplicate, or response-contract error.
    pub async fn list_ssh_hosts(
        &self,
        project_id: &SshProjectId,
    ) -> Result<Vec<SshHost>, ResourceError> {
        let response = self
            .execute_observable_read::<ListHosts>(&ProjectQuery {
                project_id: project_id.clone(),
            })
            .await?;
        if response.hosts.len() > MAX_SSH_HOST_ENTRIES {
            return Err(ResourceError::InvalidSshHostResponse);
        }
        let mut hosts = response
            .hosts
            .into_iter()
            .map(|wire| host_from_wire(wire, project_id, None))
            .collect::<Result<Vec<_>, _>>()?;
        hosts.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        if hosts.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(ResourceError::InvalidSshHostResponse);
        }
        Ok(hosts)
    }

    /// Get one exact SSH host and prove its project ownership.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or response-contract error.
    pub async fn get_ssh_host(
        &self,
        project_id: &SshProjectId,
        host_id: &SshHostId,
    ) -> Result<SshHost, ResourceError> {
        let response = self
            .execute_observable_read::<GetHost>(&ExactHostQuery {
                host_id: host_id.clone(),
            })
            .await?;
        host_from_wire(response, project_id, Some(host_id))
    }

    /// Register one SSH host beneath two explicit active CAs.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, state, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn create_ssh_host(
        &self,
        project_id: &SshProjectId,
        creation: &SshHostCreation,
        confirm: bool,
    ) -> Result<SshHost, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshHostCreateNotConfirmed);
        }
        let cas_are_active = if creation.user_ssh_ca_id == creation.host_ssh_ca_id {
            self.get_ssh_certificate_authority(project_id, &creation.user_ssh_ca_id)
                .await?
                .status
                == SshCaStatus::Active
        } else {
            let (user_ca, host_ca) = tokio::try_join!(
                self.get_ssh_certificate_authority(project_id, &creation.user_ssh_ca_id),
                self.get_ssh_certificate_authority(project_id, &creation.host_ssh_ca_id)
            )?;
            user_ca.status == SshCaStatus::Active && host_ca.status == SshCaStatus::Active
        };
        if !cas_are_active {
            return Err(ResourceError::InvalidSshCertificateAuthorityState);
        }
        let response = self
            .execute_mutation::<CreateHost>(&CreateHostRequest {
                project_id: project_id.as_str().to_owned(),
                hostname: creation.hostname.clone(),
                alias: creation.alias.clone(),
                user_cert_ttl: creation.user_cert_ttl.as_str().to_owned(),
                host_cert_ttl: creation.host_cert_ttl.as_str().to_owned(),
                login_mappings: mapping_requests(&creation.login_mappings),
                user_ssh_ca_id: creation.user_ssh_ca_id.as_str().to_owned(),
                host_ssh_ca_id: creation.host_ssh_ca_id.as_str().to_owned(),
            })
            .await?;
        let host = host_from_wire(response, project_id, None)?;
        if !host_matches_creation(&host, creation) {
            return Err(ResourceError::InvalidSshHostResponse);
        }
        Ok(host)
    }

    /// Replace every mutable field on one exact SSH host.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn replace_ssh_host(
        &self,
        project_id: &SshProjectId,
        host_id: &SshHostId,
        replacement: &SshHostReplacement,
        confirm: bool,
    ) -> Result<SshHost, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshHostReplaceNotConfirmed);
        }
        let before = self.get_ssh_host(project_id, host_id).await?;
        let response = self
            .execute_mutation::<ReplaceHost>(&ReplaceHostRequest {
                host_id: host_id.clone(),
                hostname: replacement.hostname.clone(),
                alias: replacement.alias.clone(),
                user_cert_ttl: replacement.user_cert_ttl.as_str().to_owned(),
                host_cert_ttl: replacement.host_cert_ttl.as_str().to_owned(),
                login_mappings: mapping_requests(&replacement.login_mappings),
            })
            .await?;
        let host = host_from_wire(response, project_id, Some(host_id))?;
        if !host_matches_replacement(&host, &before, replacement) {
            return Err(ResourceError::InvalidSshHostResponse);
        }
        Ok(host)
    }

    /// Delete one exact SSH host after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn delete_ssh_host(
        &self,
        project_id: &SshProjectId,
        host_id: &SshHostId,
        confirm: bool,
    ) -> Result<SshHost, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshHostDeleteNotConfirmed);
        }
        let before = self.get_ssh_host(project_id, host_id).await?;
        let response = self
            .execute_mutation::<DeleteHost>(&DeleteHostRequest {
                host_id: host_id.clone(),
            })
            .await?;
        let deleted = host_from_wire(response, project_id, Some(host_id))?;
        if deleted != before {
            return Err(ResourceError::InvalidSshHostResponse);
        }
        Ok(deleted)
    }

    async fn get_linked_ssh_host_ca_public_key(
        &self,
        project_id: &SshProjectId,
        host_id: &SshHostId,
        user_ca: bool,
    ) -> Result<SshHostLinkedCaPublicKey, ResourceError> {
        let host = self.get_ssh_host(project_id, host_id).await?;
        let ca_id = SshCertificateAuthorityId::new(if user_ca {
            host.user_ssh_ca_id
        } else {
            host.host_ssh_ca_id
        })
        .map_err(|_| ResourceError::InvalidSshHostResponse)?;
        let (authority, route_key) = if user_ca {
            tokio::try_join!(
                self.get_ssh_certificate_authority(project_id, &ca_id),
                async {
                    self.execute_observable_read::<GetUserCaPublicKey>(&ExactHostQuery {
                        host_id: host_id.clone(),
                    })
                    .await
                    .map_err(ResourceError::from)
                }
            )?
        } else {
            tokio::try_join!(
                self.get_ssh_certificate_authority(project_id, &ca_id),
                async {
                    self.execute_observable_read::<GetHostCaPublicKey>(&ExactHostQuery {
                        host_id: host_id.clone(),
                    })
                    .await
                    .map_err(ResourceError::from)
                }
            )?
        };
        let public_key =
            SshPublicKey::new(route_key).map_err(|_| ResourceError::InvalidSshHostResponse)?;
        if public_key != authority.public_key {
            return Err(ResourceError::InvalidSshHostResponse);
        }
        Ok(SshHostLinkedCaPublicKey {
            host_id: host_id.as_str().to_owned(),
            ca_id: ca_id.as_str().to_owned(),
            public_key,
        })
    }

    /// Get and verify the public key for the user CA linked to one exact host.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or mismatched-key error.
    pub async fn get_ssh_host_user_ca_public_key(
        &self,
        project_id: &SshProjectId,
        host_id: &SshHostId,
    ) -> Result<SshHostLinkedCaPublicKey, ResourceError> {
        self.get_linked_ssh_host_ca_public_key(project_id, host_id, true)
            .await
    }

    /// Get and verify the public key for the host CA linked to one exact host.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or mismatched-key error.
    pub async fn get_ssh_host_host_ca_public_key(
        &self,
        project_id: &SshProjectId,
        host_id: &SshHostId,
    ) -> Result<SshHostLinkedCaPublicKey, ResourceError> {
        self.get_linked_ssh_host_ca_public_key(project_id, host_id, false)
            .await
    }

    /// Issue and cryptographically verify a host certificate using the host's exact policy.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, state, typed client, or signed-contract error.
    /// The mutation is sent exactly once and is never retried after an ambiguous result.
    pub async fn issue_ssh_host_certificate(
        &self,
        project_id: &SshProjectId,
        host_id: &SshHostId,
        public_key: &SshPublicKey,
        confirm: bool,
    ) -> Result<SignedSshCertificate, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshHostCertificateIssuanceNotConfirmed);
        }
        let host = self.get_ssh_host(project_id, host_id).await?;
        let ca_id = SshCertificateAuthorityId::new(host.host_ssh_ca_id.clone())
            .map_err(|_| ResourceError::InvalidSshHostResponse)?;
        let authority = self
            .get_ssh_certificate_authority(project_id, &ca_id)
            .await?;
        if authority.status != SshCaStatus::Active {
            return Err(ResourceError::InvalidSshCertificateAuthorityState);
        }
        let request = SshCertificateRequest::new(
            SshCertificateType::Host,
            vec![host.hostname],
            None,
            Some(format!("host-{}", host.id)),
        )
        .map_err(|_| ResourceError::InvalidSshHostResponse)?;
        let request_started_at = unix_timestamp()?;
        let response = self
            .execute_mutation::<IssueHostCertificate>(&IssueHostCertificateRequest {
                host_id: host_id.clone(),
                public_key: public_key.as_str().to_owned(),
            })
            .await?;
        let response_received_at = unix_timestamp()?;
        validate_signed_certificate(
            response,
            &authority,
            public_key,
            &request,
            host.host_cert_ttl.seconds(),
            request_started_at,
            response_received_at,
        )
    }

    /// List a bounded, canonical inventory of SSH host groups in one project.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, duplicate, or response-contract error.
    pub async fn list_ssh_host_groups(
        &self,
        project_id: &SshProjectId,
    ) -> Result<Vec<SshHostGroup>, ResourceError> {
        let response = self
            .execute_observable_read::<ListGroups>(&ProjectQuery {
                project_id: project_id.clone(),
            })
            .await?;
        if response.groups.len() > MAX_SSH_HOST_GROUP_ENTRIES {
            return Err(ResourceError::InvalidSshHostGroupResponse);
        }
        let mut groups = response
            .groups
            .into_iter()
            .map(|wire| group_from_wire(wire, project_id, None, true))
            .collect::<Result<Vec<_>, _>>()?;
        groups.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        if groups.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(ResourceError::InvalidSshHostGroupResponse);
        }
        Ok(groups)
    }

    /// Get one exact SSH host group and prove its project ownership.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or response-contract error.
    pub async fn get_ssh_host_group(
        &self,
        project_id: &SshProjectId,
        group_id: &SshHostGroupId,
    ) -> Result<SshHostGroup, ResourceError> {
        let response = self
            .execute_observable_read::<GetGroup>(&ExactGroupQuery {
                group_id: group_id.clone(),
            })
            .await?;
        group_from_wire(response, project_id, Some(group_id), false)
    }

    /// Create one complete SSH host-group policy.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn create_ssh_host_group(
        &self,
        project_id: &SshProjectId,
        policy: &SshHostGroupPolicy,
        confirm: bool,
    ) -> Result<SshHostGroup, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshHostGroupCreateNotConfirmed);
        }
        let response = self
            .execute_mutation::<CreateGroup>(&CreateGroupRequest {
                project_id: project_id.as_str().to_owned(),
                name: policy.name.clone(),
                login_mappings: mapping_requests(&policy.login_mappings),
            })
            .await?;
        let group = group_from_wire(response, project_id, None, false)?;
        if group.name != policy.name || group.login_mappings != policy.login_mappings {
            return Err(ResourceError::InvalidSshHostGroupResponse);
        }
        Ok(group)
    }

    /// Replace every mutable field on one exact SSH host group.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn replace_ssh_host_group(
        &self,
        project_id: &SshProjectId,
        group_id: &SshHostGroupId,
        policy: &SshHostGroupPolicy,
        confirm: bool,
    ) -> Result<SshHostGroup, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshHostGroupReplaceNotConfirmed);
        }
        self.get_ssh_host_group(project_id, group_id).await?;
        let response = self
            .execute_mutation::<ReplaceGroup>(&ReplaceGroupRequest {
                group_id: group_id.clone(),
                name: policy.name.clone(),
                login_mappings: mapping_requests(&policy.login_mappings),
            })
            .await?;
        let group = group_from_wire(response, project_id, Some(group_id), false)?;
        if group.name != policy.name || group.login_mappings != policy.login_mappings {
            return Err(ResourceError::InvalidSshHostGroupResponse);
        }
        Ok(group)
    }

    /// Delete one exact SSH host group after explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn delete_ssh_host_group(
        &self,
        project_id: &SshProjectId,
        group_id: &SshHostGroupId,
        confirm: bool,
    ) -> Result<SshHostGroup, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshHostGroupDeleteNotConfirmed);
        }
        let before = self.get_ssh_host_group(project_id, group_id).await?;
        let response = self
            .execute_mutation::<DeleteGroup>(&DeleteGroupRequest {
                group_id: group_id.clone(),
            })
            .await?;
        let deleted = group_from_wire(response, project_id, Some(group_id), false)?;
        if deleted != before {
            return Err(ResourceError::InvalidSshHostGroupResponse);
        }
        Ok(deleted)
    }

    /// List a bounded and filter-consistent set of hosts for one exact host group.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, duplicate, or response-contract error.
    pub async fn list_ssh_host_group_members(
        &self,
        project_id: &SshProjectId,
        group_id: &SshHostGroupId,
        filter: SshHostGroupMembershipFilter,
    ) -> Result<SshHostGroupMembers, ResourceError> {
        self.get_ssh_host_group(project_id, group_id).await?;
        let response = self
            .execute_observable_read::<ListGroupMembers>(&GroupMembersQuery {
                group_id: group_id.clone(),
                filter,
            })
            .await?;
        if response.hosts.len() > MAX_SSH_HOST_GROUP_MEMBERS
            || response.total_count != response.hosts.len() as u64
        {
            return Err(ResourceError::InvalidSshHostGroupMembershipResponse);
        }
        let expected_membership = filter == SshHostGroupMembershipFilter::Members;
        let mut hosts = response
            .hosts
            .into_iter()
            .map(|wire| {
                let id = SshHostId::new(wire.id)
                    .map_err(|_| ResourceError::InvalidSshHostGroupMembershipResponse)?;
                if wire.is_part_of_group != expected_membership
                    || wire.is_part_of_group != wire.joined_group_at.is_some()
                    || wire
                        .joined_group_at
                        .as_deref()
                        .is_some_and(|value| utc_timestamp_millis(value).is_none())
                {
                    return Err(ResourceError::InvalidSshHostGroupMembershipResponse);
                }
                Ok(SshHostGroupMember {
                    id: id.as_str().to_owned(),
                    hostname: validate_hostname(&wire.hostname)
                        .map_err(|_| ResourceError::InvalidSshHostGroupMembershipResponse)?,
                    alias: validate_slug(wire.alias.unwrap_or_default(), true)
                        .map_err(|_| ResourceError::InvalidSshHostGroupMembershipResponse)?,
                    is_part_of_group: wire.is_part_of_group,
                    joined_group_at: wire.joined_group_at,
                })
            })
            .collect::<Result<Vec<_>, ResourceError>>()?;
        hosts.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        if hosts.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(ResourceError::InvalidSshHostGroupMembershipResponse);
        }
        Ok(SshHostGroupMembers {
            group_id: group_id.as_str().to_owned(),
            project_id: project_id.as_str().to_owned(),
            filter,
            total_count: response.total_count,
            hosts,
        })
    }

    async fn mutate_ssh_host_group_membership<O>(
        &self,
        project_id: &SshProjectId,
        group_id: &SshHostGroupId,
        host_id: &SshHostId,
        is_part_of_group: bool,
        confirm: bool,
    ) -> Result<SshHostGroupMembershipReceipt, ResourceError>
    where
        O: MutationOperation<
                Input = GroupMembershipMutationRequest,
                Output = MembershipMutationWire,
            >,
    {
        if !confirm {
            return Err(ResourceError::SshHostGroupMembershipNotConfirmed);
        }
        let (_, host) = tokio::try_join!(
            self.get_ssh_host_group(project_id, group_id),
            self.get_ssh_host(project_id, host_id)
        )?;
        let response = self
            .execute_mutation::<O>(&GroupMembershipMutationRequest {
                group_id: group_id.clone(),
                host_id: host_id.clone(),
            })
            .await?;
        let response_id = SshHostId::new(response.id)
            .map_err(|_| ResourceError::InvalidSshHostGroupMembershipResponse)?;
        let response_project = SshProjectId::new(response.project_id)
            .map_err(|_| ResourceError::InvalidSshHostGroupMembershipResponse)?;
        let response_hostname = validate_hostname(&response.hostname)
            .map_err(|_| ResourceError::InvalidSshHostGroupMembershipResponse)?;
        if &response_id != host_id
            || &response_project != project_id
            || response_hostname != host.hostname
        {
            return Err(ResourceError::InvalidSshHostGroupMembershipResponse);
        }
        Ok(SshHostGroupMembershipReceipt {
            project_id: response_project.as_str().to_owned(),
            group_id: group_id.as_str().to_owned(),
            host_id: response_id.as_str().to_owned(),
            hostname: response_hostname,
            is_part_of_group,
        })
    }

    /// Add one exact host to one exact host group.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn add_ssh_host_group_member(
        &self,
        project_id: &SshProjectId,
        group_id: &SshHostGroupId,
        host_id: &SshHostId,
        confirm: bool,
    ) -> Result<SshHostGroupMembershipReceipt, ResourceError> {
        self.mutate_ssh_host_group_membership::<AddGroupMember>(
            project_id, group_id, host_id, true, confirm,
        )
        .await
    }

    /// Remove one exact host from one exact host group.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn remove_ssh_host_group_member(
        &self,
        project_id: &SshProjectId,
        group_id: &SshHostGroupId,
        host_id: &SshHostId,
        confirm: bool,
    ) -> Result<SshHostGroupMembershipReceipt, ResourceError> {
        self.mutate_ssh_host_group_membership::<RemoveGroupMember>(
            project_id, group_id, host_id, false, confirm,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path, query_param},
    };

    use super::{
        MAX_SSH_HOST_GROUP_MEMBERS, MAX_SSH_LOGIN_MAPPINGS, MAX_SSH_LOGIN_PRINCIPALS,
        SshHostCreation, SshHostDuration, SshHostGroupId, SshHostGroupMembershipFilter,
        SshHostGroupPolicy, SshHostId, SshHostInputError, SshHostWire, SshLoginMapping,
        SshLoginMappingSource, canonical_mappings, canonical_principals, host_from_wire,
        host_matches_creation, validate_hostname,
    };
    use crate::{
        InfisicalClient, ResourceError, SshCertificateAuthorityId, SshProjectId,
        test_support::{mount_login, settings},
    };

    const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const HOST_ID: &str = "22222222-2222-4222-8222-222222222222";
    const GROUP_ID: &str = "33333333-3333-4333-8333-333333333333";
    const USER_CA_ID: &str = "44444444-4444-4444-8444-444444444444";
    const HOST_CA_ID: &str = "55555555-5555-4555-8555-555555555555";

    fn public_key() -> &'static str {
        include_str!("../test-fixtures/ssh-ed25519-public-key.txt").trim()
    }

    fn ca_json(id: &str) -> Value {
        json!({
            "ca": {
                "id": id,
                "projectId": PROJECT_ID,
                "friendlyName": format!("ca-{}", &id[..8]),
                "status": "active",
                "keyAlgorithm": "ED25519",
                "keySource": "internal",
                "publicKey": public_key()
            }
        })
    }

    fn host_json(id: &str, hostname: &str) -> Value {
        json!({
            "id": id,
            "projectId": PROJECT_ID,
            "hostname": hostname,
            "alias": null,
            "userCertTtl": "8h",
            "hostCertTtl": "1y",
            "userSshCaId": USER_CA_ID,
            "hostSshCaId": HOST_CA_ID,
            "loginMappings": [
                {
                    "loginUser": "deploy",
                    "allowedPrincipals": {
                        "usernames": ["z@example.com", "a@example.com"]
                    },
                    "source": "host"
                },
                {
                    "loginUser": "ops",
                    "allowedPrincipals": {
                        "groups": ["ops-team"]
                    },
                    "source": "hostGroup"
                }
            ]
        })
    }

    fn group_json() -> Value {
        json!({
            "id": GROUP_ID,
            "projectId": PROJECT_ID,
            "name": "ops-team",
            "loginMappings": [
                {
                    "loginUser": "ops",
                    "allowedPrincipals": {
                        "groups": ["ops-team"]
                    }
                }
            ]
        })
    }

    fn project_id() -> SshProjectId {
        SshProjectId::new(PROJECT_ID).unwrap()
    }

    fn host_id() -> SshHostId {
        SshHostId::new(HOST_ID).unwrap()
    }

    fn group_id() -> SshHostGroupId {
        SshHostGroupId::new(GROUP_ID).unwrap()
    }

    fn membership_host(id: &str, is_part_of_group: bool, joined_group_at: Option<&str>) -> Value {
        json!({
            "id": id,
            "hostname": "node.example.com",
            "alias": null,
            "isPartOfGroup": is_part_of_group,
            "joinedGroupAt": joined_group_at
        })
    }

    async fn list_members_from_response(
        filter: SshHostGroupMembershipFilter,
        response: Value,
    ) -> Result<super::SshHostGroupMembers, ResourceError> {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-host-test-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/host-groups/{GROUP_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(group_json()))
            .expect(1)
            .mount(&server)
            .await;
        let filter_value = match filter {
            SshHostGroupMembershipFilter::Members => "group-members",
            SshHostGroupMembershipFilter::NonMembers => "non-group-members",
        };
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/host-groups/{GROUP_ID}/hosts")))
            .and(query_param("filter", filter_value))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;

        InfisicalClient::new(settings(&server))
            .unwrap()
            .list_ssh_host_group_members(&project_id(), &group_id(), filter)
            .await
    }

    async fn membership_mutation_error(response: Value) -> ResourceError {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-host-test-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/host-groups/{GROUP_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(group_json()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/hosts/{HOST_ID}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(host_json(HOST_ID, "node.example.com")),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/ssh/host-groups/{GROUP_ID}/hosts/{HOST_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;

        InfisicalClient::new(settings(&server))
            .unwrap()
            .add_ssh_host_group_member(&project_id(), &group_id(), &host_id(), true)
            .await
            .unwrap_err()
    }

    #[test]
    fn host_coordinates_and_durations_are_canonical_and_bounded() {
        for valid in ["host.example.com", "a-b.example.com"] {
            assert_eq!(validate_hostname(valid).unwrap(), valid);
        }
        for invalid in [
            "localhost",
            "*",
            "*.example.com",
            "192.0.2.1",
            " padded.example.com",
        ] {
            assert_eq!(
                validate_hostname(invalid).unwrap_err(),
                SshHostInputError::InvalidHostname
            );
        }
        for valid in ["1ms", "1s", "1m", "8h", "1d", "1w", "1y", "10y"] {
            assert!(SshHostDuration::new(valid).is_ok(), "{valid}");
        }
        for invalid in ["", "0h", "01h", "11y", "1month"] {
            assert_eq!(
                SshHostDuration::new(invalid).unwrap_err(),
                SshHostInputError::InvalidDuration,
                "{invalid}"
            );
        }
    }

    #[test]
    fn login_mapping_policy_canonicalizes_and_rejects_ambiguity() {
        let mapping = SshLoginMapping::new(
            "deploy",
            vec!["z@example.com".into(), "a@example.com".into()],
            vec!["ops-team".into()],
        )
        .unwrap();
        assert_eq!(
            mapping.allowed_principals.usernames,
            ["a@example.com", "z@example.com"]
        );
        assert!(
            SshLoginMapping::new("root", vec!["same".into(), "same".into()], Vec::new()).is_err()
        );
        assert!(SshLoginMapping::new("*", vec!["user".into()], Vec::new()).is_err());
        assert!(
            canonical_mappings(vec![
                SshLoginMapping::new("deploy", vec!["one".into()], Vec::new()).unwrap(),
                SshLoginMapping::new("deploy", vec!["two".into()], Vec::new()).unwrap(),
            ])
            .is_err()
        );
        assert!(SshHostGroupPolicy::new("ops-team", vec![mapping]).is_ok());
        assert!(SshHostGroupPolicy::new("Ops Team", Vec::new()).is_err());
    }

    #[test]
    fn login_mapping_cardinality_boundaries_are_enforced() {
        assert!(canonical_principals(Vec::new(), Vec::new()).is_err());
        assert!(
            canonical_principals(vec!["user@example.com".into()], vec!["Ops Team".into()]).is_err()
        );
        assert!(
            canonical_principals(
                vec!["user@example.com".into()],
                vec!["ops-team".into(), "ops-team".into()],
            )
            .is_err()
        );

        let usernames = (0..MAX_SSH_LOGIN_PRINCIPALS / 2)
            .map(|index| format!("user-{index}@example.com"))
            .collect::<Vec<_>>();
        let groups = (0..MAX_SSH_LOGIN_PRINCIPALS / 2)
            .map(|index| format!("group-{index}"))
            .collect::<Vec<_>>();
        assert!(canonical_principals(usernames.clone(), groups.clone()).is_ok());

        let mut excessive_usernames = usernames;
        excessive_usernames.push("overflow@example.com".into());
        assert!(canonical_principals(excessive_usernames, groups).is_err());

        let mappings = (0..MAX_SSH_LOGIN_MAPPINGS)
            .map(|index| {
                SshLoginMapping::new(
                    format!("account{index}"),
                    vec![format!("user-{index}@example.com")],
                    Vec::new(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(canonical_mappings(mappings.clone()).is_ok());

        let mut excessive_mappings = mappings;
        excessive_mappings.push(
            SshLoginMapping::new("overflow", vec!["overflow@example.com".into()], Vec::new())
                .unwrap(),
        );
        assert!(canonical_mappings(excessive_mappings).is_err());
    }

    #[test]
    fn host_creation_reflection_checks_every_requested_field() {
        let creation = SshHostCreation::new(
            "node.example.com",
            "",
            SshHostDuration::new("8h").unwrap(),
            SshHostDuration::new("1y").unwrap(),
            vec![
                SshLoginMapping::new(
                    "deploy",
                    vec!["z@example.com".into(), "a@example.com".into()],
                    Vec::new(),
                )
                .unwrap(),
            ],
            SshCertificateAuthorityId::new(USER_CA_ID).unwrap(),
            SshCertificateAuthorityId::new(HOST_CA_ID).unwrap(),
        )
        .unwrap();
        let wire: SshHostWire =
            serde_json::from_value(host_json(HOST_ID, "node.example.com")).unwrap();
        let reflected =
            host_from_wire(wire, &project_id(), Some(&host_id())).expect("valid host fixture");
        assert!(host_matches_creation(&reflected, &creation));

        let mut mismatch = reflected.clone();
        mismatch.hostname = "other.example.com".into();
        assert!(!host_matches_creation(&mismatch, &creation));

        let mut mismatch = reflected.clone();
        mismatch.alias = "other".into();
        assert!(!host_matches_creation(&mismatch, &creation));

        let mut mismatch = reflected.clone();
        mismatch.user_cert_ttl = SshHostDuration::new("9h").unwrap();
        assert!(!host_matches_creation(&mismatch, &creation));

        let mut mismatch = reflected.clone();
        mismatch.host_cert_ttl = SshHostDuration::new("2y").unwrap();
        assert!(!host_matches_creation(&mismatch, &creation));

        let mut mismatch = reflected.clone();
        mismatch.user_ssh_ca_id = HOST_CA_ID.into();
        assert!(!host_matches_creation(&mismatch, &creation));

        let mut mismatch = reflected.clone();
        mismatch.host_ssh_ca_id = USER_CA_ID.into();
        assert!(!host_matches_creation(&mismatch, &creation));

        let mut mismatch = reflected;
        mismatch.login_mappings[0].login_user = "other".into();
        assert!(!host_matches_creation(&mismatch, &creation));
    }

    #[tokio::test]
    async fn host_inventory_is_project_bound_and_canonical() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-host-test-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{PROJECT_ID}/ssh-hosts")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hosts": [
                    host_json("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "z.example.com"),
                    host_json(HOST_ID, "a.example.com")
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let hosts = client.list_ssh_hosts(&project_id()).await.unwrap();

        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].id, HOST_ID);
        assert_eq!(hosts[0].alias, "");
        assert_eq!(
            hosts[0].login_mappings[0].source,
            SshLoginMappingSource::Host
        );
        assert_eq!(
            hosts[0].login_mappings[0].allowed_principals.usernames,
            ["a@example.com", "z@example.com"]
        );
        assert_eq!(
            hosts[0].login_mappings[1].source,
            SshLoginMappingSource::HostGroup
        );
    }

    #[tokio::test]
    async fn host_creation_preflights_explicit_cas_and_reflects_the_complete_policy() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-host-test-token").await;
        for ca_id in [USER_CA_ID, HOST_CA_ID] {
            Mock::given(method("GET"))
                .and(path(format!("/api/v1/ssh/ca/{ca_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(ca_json(ca_id)))
                .expect(1)
                .mount(&server)
                .await;
        }
        let expected_body = json!({
            "projectId": PROJECT_ID,
            "hostname": "node.example.com",
            "alias": "",
            "userCertTtl": "8h",
            "hostCertTtl": "1y",
            "loginMappings": [{
                "loginUser": "deploy",
                "allowedPrincipals": {"usernames": ["a@example.com"]}
            }],
            "userSshCaId": USER_CA_ID,
            "hostSshCaId": HOST_CA_ID
        });
        let mut response = host_json(HOST_ID, "node.example.com");
        response["loginMappings"] = json!([{
            "loginUser": "deploy",
            "allowedPrincipals": {"usernames": ["a@example.com"]},
            "source": "host"
        }]);
        Mock::given(method("POST"))
            .and(path("/api/v1/ssh/hosts"))
            .and(body_json(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;

        let creation = SshHostCreation::new(
            "node.example.com",
            "",
            SshHostDuration::new("8h").unwrap(),
            SshHostDuration::new("1y").unwrap(),
            vec![SshLoginMapping::new("deploy", vec!["a@example.com".into()], Vec::new()).unwrap()],
            SshCertificateAuthorityId::new(USER_CA_ID).unwrap(),
            SshCertificateAuthorityId::new(HOST_CA_ID).unwrap(),
        )
        .unwrap();
        let client = InfisicalClient::new(settings(&server)).unwrap();

        let host = client
            .create_ssh_host(&project_id(), &creation, true)
            .await
            .unwrap();
        assert_eq!(host.id, HOST_ID);
        assert_eq!(host.host_ssh_ca_id, HOST_CA_ID);
    }

    #[tokio::test]
    async fn group_membership_list_and_mutation_are_bounded_and_bodyless() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-host-test-token").await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/host-groups/{GROUP_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(group_json()))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/hosts/{HOST_ID}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(host_json(HOST_ID, "node.example.com")),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/host-groups/{GROUP_ID}/hosts")))
            .and(query_param("filter", "group-members"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hosts": [{
                    "id": HOST_ID,
                    "hostname": "node.example.com",
                    "alias": null,
                    "isPartOfGroup": true,
                    "joinedGroupAt": "2026-07-23T12:00:00.000Z"
                }],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/ssh/host-groups/{GROUP_ID}/hosts/{HOST_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": HOST_ID,
                "projectId": PROJECT_ID,
                "hostname": "node.example.com",
                "alias": null,
                "userCertTtl": "8h",
                "hostCertTtl": "1y",
                "userSshCaId": USER_CA_ID,
                "hostSshCaId": HOST_CA_ID,
                "loginMappings": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let members = client
            .list_ssh_host_group_members(
                &project_id(),
                &group_id(),
                SshHostGroupMembershipFilter::Members,
            )
            .await
            .unwrap();
        assert_eq!(members.total_count, 1);
        assert!(members.hosts[0].is_part_of_group);

        let receipt = client
            .add_ssh_host_group_member(&project_id(), &group_id(), &host_id(), true)
            .await
            .unwrap();
        assert!(receipt.is_part_of_group);

        let requests = server.received_requests().await.unwrap();
        let mutation = requests
            .iter()
            .find(|request| {
                request.method.as_str() == "POST"
                    && request.url.path()
                        == format!("/api/v1/ssh/host-groups/{GROUP_ID}/hosts/{HOST_ID}")
            })
            .unwrap();
        assert!(mutation.body.is_empty());
    }

    #[tokio::test]
    async fn group_membership_inventory_enforces_boundaries_and_response_consistency() {
        let maximum_non_members = (0..MAX_SSH_HOST_GROUP_MEMBERS)
            .map(|index| {
                membership_host(
                    &format!("{index:08x}-0000-4000-8000-{index:012x}"),
                    false,
                    None,
                )
            })
            .collect::<Vec<_>>();
        let maximum = list_members_from_response(
            SshHostGroupMembershipFilter::NonMembers,
            json!({
                "totalCount": MAX_SSH_HOST_GROUP_MEMBERS,
                "hosts": maximum_non_members
            }),
        )
        .await
        .unwrap();
        assert_eq!(maximum.hosts.len(), MAX_SSH_HOST_GROUP_MEMBERS);

        let excessive_non_members = (0..=MAX_SSH_HOST_GROUP_MEMBERS)
            .map(|index| {
                membership_host(
                    &format!("{index:08x}-0000-4000-8000-{index:012x}"),
                    false,
                    None,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            list_members_from_response(
                SshHostGroupMembershipFilter::NonMembers,
                json!({
                    "totalCount": excessive_non_members.len(),
                    "hosts": excessive_non_members
                }),
            )
            .await
            .unwrap_err(),
            ResourceError::InvalidSshHostGroupMembershipResponse
        );

        let invalid_responses = [
            (
                SshHostGroupMembershipFilter::NonMembers,
                json!({
                    "totalCount": 2,
                    "hosts": [membership_host(HOST_ID, false, None)]
                }),
            ),
            (
                SshHostGroupMembershipFilter::Members,
                json!({
                    "totalCount": 1,
                    "hosts": [membership_host(HOST_ID, false, None)]
                }),
            ),
            (
                SshHostGroupMembershipFilter::Members,
                json!({
                    "totalCount": 1,
                    "hosts": [membership_host(HOST_ID, true, None)]
                }),
            ),
            (
                SshHostGroupMembershipFilter::Members,
                json!({
                    "totalCount": 1,
                    "hosts": [membership_host(HOST_ID, true, Some("not-a-timestamp"))]
                }),
            ),
            (
                SshHostGroupMembershipFilter::NonMembers,
                json!({
                    "totalCount": 2,
                    "hosts": [
                        membership_host(HOST_ID, false, None),
                        membership_host(HOST_ID, false, None)
                    ]
                }),
            ),
        ];
        for (filter, response) in invalid_responses {
            assert_eq!(
                list_members_from_response(filter, response)
                    .await
                    .unwrap_err(),
                ResourceError::InvalidSshHostGroupMembershipResponse
            );
        }
    }

    #[tokio::test]
    async fn group_membership_mutation_rejects_each_scope_mismatch() {
        let mut wrong_host = host_json("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "node.example.com");
        wrong_host["projectId"] = json!(PROJECT_ID);
        assert_eq!(
            membership_mutation_error(wrong_host).await,
            ResourceError::InvalidSshHostGroupMembershipResponse
        );

        let mut wrong_project = host_json(HOST_ID, "node.example.com");
        wrong_project["projectId"] = json!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        assert_eq!(
            membership_mutation_error(wrong_project).await,
            ResourceError::InvalidSshHostGroupMembershipResponse
        );

        let wrong_hostname = host_json(HOST_ID, "other.example.com");
        assert_eq!(
            membership_mutation_error(wrong_hostname).await,
            ResourceError::InvalidSshHostGroupMembershipResponse
        );
    }

    #[tokio::test]
    async fn host_and_group_mutations_require_confirmation_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let policy = SshHostGroupPolicy::new("ops-team", Vec::new()).unwrap();

        assert_eq!(
            client
                .delete_ssh_host(&project_id(), &host_id(), false)
                .await
                .unwrap_err(),
            ResourceError::SshHostDeleteNotConfirmed
        );
        assert_eq!(
            client
                .create_ssh_host_group(&project_id(), &policy, false)
                .await
                .unwrap_err(),
            ResourceError::SshHostGroupCreateNotConfirmed
        );
        assert_eq!(
            client
                .add_ssh_host_group_member(&project_id(), &group_id(), &host_id(), false,)
                .await
                .unwrap_err(),
            ResourceError::SshHostGroupMembershipNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
