use std::{collections::HashSet, hash::Hash};

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

use crate::{
    CertificateAuthorityProjectId, CertificateExtendedKeyUsage, CertificateKeyUsage,
    CertificatePolicyId, InfisicalClient, MutationOperation, ObservableReadOperation, Page,
    PageRequest, ResourceError,
    client::{ApiVersion, Endpoint, sealed},
    resources::{is_bounded_text, utc_timestamp_millis},
};

const MAX_POLICY_NAME_BYTES: usize = 255;
const MAX_POLICY_DESCRIPTION_BYTES: usize = 1_000;
const MAX_POLICY_SEARCH_BYTES: usize = 255;
const MAX_POLICY_VALUE_BYTES: usize = 255;
const MAX_POLICY_VALUES_PER_RULE: usize = 100;
const POLICY_COLLISION_SUFFIX_BYTES: usize = 8;
const POLICY_FALLBACK_NAME_BYTES: usize = 12;

/// Input validation failures for certificate-policy operations.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CertificatePolicyInputError {
    #[error(
        "certificate-policy name must contain lowercase letters or numbers separated by single hyphens and be at most 255 bytes"
    )]
    InvalidName,
    #[error("certificate-policy description must be trimmed, control-free, and at most 1000 bytes")]
    InvalidDescription,
    #[error("certificate-policy search must be trimmed, control-free, and at most 255 bytes")]
    InvalidSearch,
    #[error("certificate-policy rule values must be unique bounded non-empty text")]
    InvalidRuleValues,
    #[error("certificate-policy rule types must be unique")]
    DuplicateRuleType,
    #[error("certificate-policy denied values cannot also be allowed or required")]
    ContradictoryRule,
    #[error("certificate-policy usage collections must be unique and non-empty")]
    InvalidUsages,
    #[error("certificate-policy algorithm collections must be unique and non-empty")]
    InvalidAlgorithms,
    #[error(
        "certificate-policy maximum validity must be a bounded positive duration such as 24h, 365d, 12m, or 1y"
    )]
    InvalidValidity,
    #[error("certificate-policy basic constraints are empty or contradictory")]
    InvalidBasicConstraints,
    #[error("certificate-policy update must change or clear at least one field")]
    EmptyChange,
}

/// Subject attribute controlled by a certificate policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertificatePolicySubjectAttribute {
    CommonName,
    Organization,
    Country,
    State,
    Locality,
    OrganizationalUnit,
}

/// Subject-alternative-name family controlled by a certificate policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertificatePolicySanType {
    DnsName,
    IpAddress,
    Email,
    Uri,
}

/// Policy disposition for CA basic constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CertificatePolicyState {
    Allowed,
    Required,
    Denied,
}

/// Allowed, required, and denied text patterns for one subject or SAN type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePolicyValueRule<T> {
    /// Subject or SAN family governed by this rule.
    #[serde(rename = "type")]
    pub rule_type: T,
    /// Values or wildcard patterns the policy permits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<String>>,
    /// Values or wildcard patterns the request must satisfy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    /// Values or wildcard patterns the policy rejects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied: Option<Vec<String>>,
}

impl<T> CertificatePolicyValueRule<T> {
    /// Construct one policy value rule. Complete validation runs when the rule enters a policy.
    #[must_use]
    pub const fn new(
        rule_type: T,
        allowed: Option<Vec<String>>,
        required: Option<Vec<String>>,
        denied: Option<Vec<String>>,
    ) -> Self {
        Self {
            rule_type,
            allowed,
            required,
            denied,
        }
    }
}

/// Allowed, required, and denied members of one closed usage enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePolicyUsageRule<T> {
    /// Usage values the policy permits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<T>>,
    /// Usage values certificate requests must include.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<T>>,
    /// Usage values the policy rejects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied: Option<Vec<T>>,
}

impl<T> CertificatePolicyUsageRule<T> {
    /// Construct one usage rule. Complete validation runs when the rule enters a policy.
    #[must_use]
    pub const fn new(
        allowed: Option<Vec<T>>,
        required: Option<Vec<T>>,
        denied: Option<Vec<T>>,
    ) -> Self {
        Self {
            allowed,
            required,
            denied,
        }
    }
}

/// Closed signature and key-algorithm policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CertificatePolicySignatureAlgorithm {
    #[serde(rename = "SHA256-RSA", alias = "RSA-SHA256")]
    Sha256Rsa,
    #[serde(rename = "SHA384-RSA", alias = "RSA-SHA384")]
    Sha384Rsa,
    #[serde(rename = "SHA512-RSA", alias = "RSA-SHA512")]
    Sha512Rsa,
    #[serde(rename = "SHA256-ECDSA", alias = "ECDSA-SHA256")]
    Sha256Ecdsa,
    #[serde(rename = "SHA384-ECDSA", alias = "ECDSA-SHA384")]
    Sha384Ecdsa,
    #[serde(rename = "SHA512-ECDSA", alias = "ECDSA-SHA512")]
    Sha512Ecdsa,
    #[serde(rename = "ML-DSA-44")]
    MlDsa44,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,
    #[serde(rename = "SLH-DSA-SHA2-128f")]
    SlhDsaSha2_128f,
    #[serde(rename = "SLH-DSA-SHA2-128s")]
    SlhDsaSha2_128s,
    #[serde(rename = "SLH-DSA-SHA2-192f")]
    SlhDsaSha2_192f,
    #[serde(rename = "SLH-DSA-SHA2-192s")]
    SlhDsaSha2_192s,
    #[serde(rename = "SLH-DSA-SHA2-256f")]
    SlhDsaSha2_256f,
    #[serde(rename = "SLH-DSA-SHA2-256s")]
    SlhDsaSha2_256s,
    #[serde(rename = "SLH-DSA-SHAKE-128f")]
    SlhDsaShake128f,
    #[serde(rename = "SLH-DSA-SHAKE-128s")]
    SlhDsaShake128s,
    #[serde(rename = "SLH-DSA-SHAKE-192f")]
    SlhDsaShake192f,
    #[serde(rename = "SLH-DSA-SHAKE-192s")]
    SlhDsaShake192s,
    #[serde(rename = "SLH-DSA-SHAKE-256f")]
    SlhDsaShake256f,
    #[serde(rename = "SLH-DSA-SHAKE-256s")]
    SlhDsaShake256s,
}

/// Key-algorithm labels stored by the pinned certificate-policy service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CertificatePolicyKeyAlgorithm {
    #[serde(rename = "RSA-2048", alias = "RSA_2048")]
    Rsa2048,
    #[serde(rename = "RSA-3072", alias = "RSA_3072")]
    Rsa3072,
    #[serde(rename = "RSA-4096", alias = "RSA_4096")]
    Rsa4096,
    #[serde(rename = "ECDSA-P256", alias = "EC_prime256v1")]
    EcdsaP256,
    #[serde(rename = "ECDSA-P384", alias = "EC_secp384r1")]
    EcdsaP384,
    #[serde(rename = "ECDSA-P521", alias = "EC_secp521r1")]
    EcdsaP521,
    #[serde(rename = "ML-DSA-44")]
    MlDsa44,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,
    #[serde(rename = "SLH-DSA-SHA2-128f")]
    SlhDsaSha2_128f,
    #[serde(rename = "SLH-DSA-SHA2-128s")]
    SlhDsaSha2_128s,
    #[serde(rename = "SLH-DSA-SHA2-192f")]
    SlhDsaSha2_192f,
    #[serde(rename = "SLH-DSA-SHA2-192s")]
    SlhDsaSha2_192s,
    #[serde(rename = "SLH-DSA-SHA2-256f")]
    SlhDsaSha2_256f,
    #[serde(rename = "SLH-DSA-SHA2-256s")]
    SlhDsaSha2_256s,
    #[serde(rename = "SLH-DSA-SHAKE-128f")]
    SlhDsaShake128f,
    #[serde(rename = "SLH-DSA-SHAKE-128s")]
    SlhDsaShake128s,
    #[serde(rename = "SLH-DSA-SHAKE-192f")]
    SlhDsaShake192f,
    #[serde(rename = "SLH-DSA-SHAKE-192s")]
    SlhDsaShake192s,
    #[serde(rename = "SLH-DSA-SHAKE-256f")]
    SlhDsaShake256f,
    #[serde(rename = "SLH-DSA-SHAKE-256s")]
    SlhDsaShake256s,
}

/// Closed signature and key-algorithm policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePolicyAlgorithms {
    /// Policy-format signature algorithms accepted by certificate requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<CertificatePolicySignatureAlgorithm>>,
    /// Policy-format public-key algorithms accepted by certificate requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<Vec<CertificatePolicyKeyAlgorithm>>,
}

impl CertificatePolicyAlgorithms {
    /// Construct an algorithm policy. Complete validation runs when it enters a policy.
    #[must_use]
    pub const fn new(
        signature: Option<Vec<CertificatePolicySignatureAlgorithm>>,
        key_algorithm: Option<Vec<CertificatePolicyKeyAlgorithm>>,
    ) -> Self {
        Self {
            signature,
            key_algorithm,
        }
    }
}

/// Canonical positive maximum-validity expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct CertificatePolicyMaxValidity(String);

impl<'de> Deserialize<'de> for CertificatePolicyMaxValidity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl CertificatePolicyMaxValidity {
    /// Validate a positive duration using hours, days, months, or years.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, zero, non-canonical, or excessive values.
    pub fn new(value: impl Into<String>) -> Result<Self, CertificatePolicyInputError> {
        let value = value.into();
        if policy_validity_millis(&value).is_none() {
            return Err(CertificatePolicyInputError::InvalidValidity);
        }
        Ok(Self(value))
    }

    /// Borrow the validated duration expression.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Maximum certificate validity accepted by a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePolicyValidity {
    /// Optional maximum certificate lifetime in the pinned duration grammar.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<CertificatePolicyMaxValidity>,
}

impl CertificatePolicyValidity {
    /// Construct a maximum-validity rule.
    #[must_use]
    pub const fn new(max: Option<CertificatePolicyMaxValidity>) -> Self {
        Self { max }
    }
}

/// CA basic-constraints policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePolicyBasicConstraints {
    /// Whether CA certificates are allowed, required, or denied.
    #[serde(rename = "isCA", skip_serializing_if = "Option::is_none")]
    pub is_ca: Option<CertificatePolicyState>,
    /// Maximum subordinate CA depth; -1 represents no path-length limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_path_length: Option<i32>,
}

impl CertificatePolicyBasicConstraints {
    /// Construct a basic-constraints policy. Complete validation runs with the policy.
    #[must_use]
    pub const fn new(is_ca: Option<CertificatePolicyState>, max_path_length: Option<i32>) -> Self {
        Self {
            is_ca,
            max_path_length,
        }
    }
}

/// Complete validated certificate-policy creation input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatePolicyCreation {
    name: String,
    description: Option<String>,
    subject: Option<Vec<CertificatePolicyValueRule<CertificatePolicySubjectAttribute>>>,
    sans: Option<Vec<CertificatePolicyValueRule<CertificatePolicySanType>>>,
    key_usages: Option<CertificatePolicyUsageRule<CertificateKeyUsage>>,
    extended_key_usages: Option<CertificatePolicyUsageRule<CertificateExtendedKeyUsage>>,
    algorithms: Option<CertificatePolicyAlgorithms>,
    validity: Option<CertificatePolicyValidity>,
    basic_constraints: Option<CertificatePolicyBasicConstraints>,
}

/// One optional policy-field update, distinguishing replacement from clearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificatePolicyFieldChange<T> {
    Set(T),
    Clear,
}

/// Validated non-empty certificate-policy update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatePolicyChange {
    name: Option<String>,
    description: Option<String>,
    subject: Option<Vec<CertificatePolicyValueRule<CertificatePolicySubjectAttribute>>>,
    sans: Option<Vec<CertificatePolicyValueRule<CertificatePolicySanType>>>,
    key_usages: Option<CertificatePolicyUsageRule<CertificateKeyUsage>>,
    extended_key_usages: Option<CertificatePolicyUsageRule<CertificateExtendedKeyUsage>>,
    algorithms: Option<CertificatePolicyAlgorithms>,
    validity: Option<CertificatePolicyValidity>,
    basic_constraints: Option<CertificatePolicyFieldChange<CertificatePolicyBasicConstraints>>,
}

impl CertificatePolicyChange {
    /// Validate a non-empty policy update before its first upstream call.
    ///
    /// # Errors
    ///
    /// Returns an error when no field changes or a replacement value violates the policy contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: Option<String>,
        description: Option<String>,
        subject: Option<Vec<CertificatePolicyValueRule<CertificatePolicySubjectAttribute>>>,
        sans: Option<Vec<CertificatePolicyValueRule<CertificatePolicySanType>>>,
        key_usages: Option<CertificatePolicyUsageRule<CertificateKeyUsage>>,
        extended_key_usages: Option<CertificatePolicyUsageRule<CertificateExtendedKeyUsage>>,
        algorithms: Option<CertificatePolicyAlgorithms>,
        validity: Option<CertificatePolicyValidity>,
        basic_constraints: Option<CertificatePolicyFieldChange<CertificatePolicyBasicConstraints>>,
    ) -> Result<Self, CertificatePolicyInputError> {
        if name.is_none()
            && description.is_none()
            && subject.is_none()
            && sans.is_none()
            && key_usages.is_none()
            && extended_key_usages.is_none()
            && algorithms.is_none()
            && validity.is_none()
            && basic_constraints.is_none()
        {
            return Err(CertificatePolicyInputError::EmptyChange);
        }
        let change = Self {
            name: name.map(validate_requested_name).transpose()?,
            description,
            subject,
            sans,
            key_usages,
            extended_key_usages,
            algorithms,
            validity,
            basic_constraints,
        };
        validate_description(change.description.as_deref())?;
        if let Some(value) = change.subject.as_ref() {
            validate_value_rules(Some(value), true)?;
        }
        if let Some(value) = change.sans.as_ref() {
            validate_value_rules(Some(value), true)?;
        }
        if let Some(value) = change.key_usages.as_ref() {
            validate_usage_rule(Some(value), true)?;
        }
        if let Some(value) = change.extended_key_usages.as_ref() {
            validate_usage_rule(Some(value), true)?;
        }
        if let Some(value) = change.algorithms.as_ref() {
            validate_algorithms(Some(value), true)?;
        }
        if let Some(value) = change.validity.as_ref() {
            validate_validity(Some(value), true)?;
        }
        if let Some(CertificatePolicyFieldChange::Set(value)) = change.basic_constraints.as_ref() {
            validate_basic_constraints(Some(value), true)?;
        }
        Ok(change)
    }
}

impl CertificatePolicyCreation {
    /// Validate a complete certificate policy before its first upstream call.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed names, text, rules, usages, algorithms, validity, or
    /// constraints.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        description: Option<String>,
        subject: Option<Vec<CertificatePolicyValueRule<CertificatePolicySubjectAttribute>>>,
        sans: Option<Vec<CertificatePolicyValueRule<CertificatePolicySanType>>>,
        key_usages: Option<CertificatePolicyUsageRule<CertificateKeyUsage>>,
        extended_key_usages: Option<CertificatePolicyUsageRule<CertificateExtendedKeyUsage>>,
        algorithms: Option<CertificatePolicyAlgorithms>,
        validity: Option<CertificatePolicyValidity>,
        basic_constraints: Option<CertificatePolicyBasicConstraints>,
    ) -> Result<Self, CertificatePolicyInputError> {
        let creation = Self {
            name: validate_requested_name(name.into())?,
            description,
            subject,
            sans,
            key_usages,
            extended_key_usages,
            algorithms,
            validity,
            basic_constraints,
        };
        creation.validate(true)?;
        Ok(creation)
    }

    fn validate(&self, mutation_input: bool) -> Result<(), CertificatePolicyInputError> {
        validate_description(self.description.as_deref())?;
        validate_value_rules(self.subject.as_deref(), mutation_input)?;
        validate_value_rules(self.sans.as_deref(), mutation_input)?;
        validate_usage_rule(self.key_usages.as_ref(), mutation_input)?;
        validate_usage_rule(self.extended_key_usages.as_ref(), mutation_input)?;
        validate_algorithms(self.algorithms.as_ref(), mutation_input)?;
        validate_validity(self.validity.as_ref(), mutation_input)?;
        validate_basic_constraints(self.basic_constraints.as_ref(), mutation_input)
    }
}

/// Bounded policy list request for one Certificate Manager project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatePolicyListRequest {
    project_id: CertificateAuthorityProjectId,
    page: PageRequest,
    search: Option<String>,
}

impl CertificatePolicyListRequest {
    /// Validate one project-scoped policy page request.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, untrimmed, control-bearing, or oversized search text.
    pub fn new(
        project_id: CertificateAuthorityProjectId,
        page: PageRequest,
        search: Option<String>,
    ) -> Result<Self, CertificatePolicyInputError> {
        if search.as_deref().is_some_and(|value| {
            !is_bounded_text(value, MAX_POLICY_SEARCH_BYTES) || value != value.trim()
        }) {
            return Err(CertificatePolicyInputError::InvalidSearch);
        }
        Ok(Self {
            project_id,
            page,
            search,
        })
    }
}

/// Complete bounded certificate-policy metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePolicy {
    /// Canonical policy UUID.
    pub id: String,
    /// Owning Certificate Manager project UUID.
    pub project_id: String,
    /// Project-local policy slug returned by Infisical.
    pub name: String,
    /// Optional human-readable purpose.
    pub description: Option<String>,
    /// Optional subject-attribute rules.
    pub subject: Option<Vec<CertificatePolicyValueRule<CertificatePolicySubjectAttribute>>>,
    /// Optional subject-alternative-name rules.
    pub sans: Option<Vec<CertificatePolicyValueRule<CertificatePolicySanType>>>,
    /// Optional X.509 key-usage rules.
    pub key_usages: Option<CertificatePolicyUsageRule<CertificateKeyUsage>>,
    /// Optional X.509 extended-key-usage rules.
    pub extended_key_usages: Option<CertificatePolicyUsageRule<CertificateExtendedKeyUsage>>,
    /// Optional signature and public-key algorithm policy.
    pub algorithms: Option<CertificatePolicyAlgorithms>,
    /// Optional maximum certificate lifetime.
    pub validity: Option<CertificatePolicyValidity>,
    /// Optional certificate-authority basic constraints.
    pub basic_constraints: Option<CertificatePolicyBasicConstraints>,
    /// Canonical UTC creation timestamp.
    pub created_at: String,
    /// Canonical UTC last-update timestamp.
    pub updated_at: String,
}

fn validate_requested_name(value: String) -> Result<String, CertificatePolicyInputError> {
    if value.is_empty()
        || value.len() > MAX_POLICY_NAME_BYTES
        || !value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
    {
        return Err(CertificatePolicyInputError::InvalidName);
    }
    Ok(value)
}

fn valid_response_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_POLICY_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_description(value: Option<&str>) -> Result<(), CertificatePolicyInputError> {
    if value.is_some_and(|value| {
        !is_bounded_text(value, MAX_POLICY_DESCRIPTION_BYTES) || value != value.trim()
    }) {
        return Err(CertificatePolicyInputError::InvalidDescription);
    }
    Ok(())
}

fn value_collection_is_valid(values: &[String]) -> bool {
    values.len() <= MAX_POLICY_VALUES_PER_RULE
        && values
            .iter()
            .all(|value| !value.is_empty() && is_bounded_text(value, MAX_POLICY_VALUE_BYTES))
        && values.iter().collect::<HashSet<_>>().len() == values.len()
}

fn validate_value_rules<T: Eq + Hash>(
    rules: Option<&[CertificatePolicyValueRule<T>]>,
    mutation_input: bool,
) -> Result<(), CertificatePolicyInputError> {
    let Some(rules) = rules else {
        return Ok(());
    };
    if rules
        .iter()
        .map(|rule| &rule.rule_type)
        .collect::<HashSet<_>>()
        .len()
        != rules.len()
    {
        return Err(CertificatePolicyInputError::DuplicateRuleType);
    }
    for rule in rules {
        let collections = [
            rule.allowed.as_deref(),
            rule.required.as_deref(),
            rule.denied.as_deref(),
        ];
        if collections.iter().all(Option::is_none)
            || collections
                .into_iter()
                .flatten()
                .any(|values| !value_collection_is_valid(values))
        {
            return Err(CertificatePolicyInputError::InvalidRuleValues);
        }
        if mutation_input {
            let allowed = rule.allowed.as_deref().unwrap_or_default();
            let required = rule.required.as_deref().unwrap_or_default();
            let denied = rule.denied.as_deref().unwrap_or_default();
            if denied
                .iter()
                .any(|value| allowed.contains(value) || required.contains(value))
            {
                return Err(CertificatePolicyInputError::ContradictoryRule);
            }
        }
    }
    Ok(())
}

fn validate_usage_rule<T: Eq + Hash>(
    rule: Option<&CertificatePolicyUsageRule<T>>,
    mutation_input: bool,
) -> Result<(), CertificatePolicyInputError> {
    let Some(rule) = rule else {
        return Ok(());
    };
    let collections = [
        rule.allowed.as_deref(),
        rule.required.as_deref(),
        rule.denied.as_deref(),
    ];
    if collections.iter().all(Option::is_none)
        || collections
            .into_iter()
            .flatten()
            .any(|values| values.iter().collect::<HashSet<_>>().len() != values.len())
    {
        return Err(CertificatePolicyInputError::InvalidUsages);
    }
    if mutation_input {
        let allowed = rule.allowed.as_deref().unwrap_or_default();
        let required = rule.required.as_deref().unwrap_or_default();
        let denied = rule.denied.as_deref().unwrap_or_default();
        if denied
            .iter()
            .any(|value| allowed.contains(value) || required.contains(value))
        {
            return Err(CertificatePolicyInputError::ContradictoryRule);
        }
    }
    Ok(())
}

fn validate_algorithms(
    algorithms: Option<&CertificatePolicyAlgorithms>,
    mutation_input: bool,
) -> Result<(), CertificatePolicyInputError> {
    let Some(algorithms) = algorithms else {
        return Ok(());
    };
    let signature_valid = algorithms.signature.as_ref().is_none_or(|values| {
        !values.is_empty()
            && values
                .iter()
                .enumerate()
                .all(|(index, value)| !values[index + 1..].contains(value))
    });
    let key_valid = algorithms.key_algorithm.as_ref().is_none_or(|values| {
        !values.is_empty()
            && values
                .iter()
                .enumerate()
                .all(|(index, value)| !values[index + 1..].contains(value))
    });
    if !signature_valid
        || !key_valid
        || (mutation_input && algorithms.signature.is_none() && algorithms.key_algorithm.is_none())
    {
        return Err(CertificatePolicyInputError::InvalidAlgorithms);
    }
    Ok(())
}

fn validate_validity(
    validity: Option<&CertificatePolicyValidity>,
    mutation_input: bool,
) -> Result<(), CertificatePolicyInputError> {
    if validity.is_some_and(|value| {
        (mutation_input && value.max.is_none())
            || value
                .max
                .as_ref()
                .is_some_and(|max| policy_validity_millis(max.as_str()).is_none())
    }) {
        return Err(CertificatePolicyInputError::InvalidValidity);
    }
    Ok(())
}

fn validate_basic_constraints(
    constraints: Option<&CertificatePolicyBasicConstraints>,
    mutation_input: bool,
) -> Result<(), CertificatePolicyInputError> {
    let Some(constraints) = constraints else {
        return Ok(());
    };
    if constraints
        .max_path_length
        .is_some_and(|length| length < -1)
        || (mutation_input && constraints.is_ca.is_none() && constraints.max_path_length.is_none())
        || (mutation_input
            && constraints.is_ca == Some(CertificatePolicyState::Denied)
            && constraints.max_path_length.is_some())
    {
        return Err(CertificatePolicyInputError::InvalidBasicConstraints);
    }
    Ok(())
}

fn policy_validity_millis(value: &str) -> Option<u64> {
    let digit_count = value.bytes().take_while(u8::is_ascii_digit).count();
    if digit_count == 0 || value.starts_with('0') {
        return None;
    }
    let amount = value[..digit_count].parse::<u64>().ok()?;
    let multiplier = match &value[digit_count..] {
        "h" => 3_600_000,
        "d" => 86_400_000,
        "m" => 2_592_000_000,
        "y" => 31_536_000_000,
        _ => return None,
    };
    amount.checked_mul(multiplier)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListPoliciesQuery {
    project_id: String,
    offset: u32,
    limit: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    search: Option<String>,
}

#[derive(Serialize)]
struct ExactPolicyQuery {
    #[serde(skip_serializing)]
    policy_id: CertificatePolicyId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyResponse {
    certificate_policy: CertificatePolicyWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListPoliciesResponse {
    certificate_policies: Vec<CertificatePolicyWire>,
    total_count: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificatePolicyWire {
    id: String,
    project_id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    subject: Option<Vec<CertificatePolicyValueRule<CertificatePolicySubjectAttribute>>>,
    #[serde(default)]
    sans: Option<Vec<CertificatePolicyValueRule<CertificatePolicySanType>>>,
    #[serde(default)]
    key_usages: Option<CertificatePolicyUsageRule<CertificateKeyUsage>>,
    #[serde(default)]
    extended_key_usages: Option<CertificatePolicyUsageRule<CertificateExtendedKeyUsage>>,
    #[serde(default)]
    algorithms: Option<CertificatePolicyAlgorithms>,
    #[serde(default)]
    validity: Option<CertificatePolicyValidity>,
    #[serde(default)]
    basic_constraints: Option<CertificatePolicyBasicConstraints>,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatePolicyRequest {
    project_id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<Vec<CertificatePolicyValueRule<CertificatePolicySubjectAttribute>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sans: Option<Vec<CertificatePolicyValueRule<CertificatePolicySanType>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_usages: Option<CertificatePolicyUsageRule<CertificateKeyUsage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extended_key_usages: Option<CertificatePolicyUsageRule<CertificateExtendedKeyUsage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithms: Option<CertificatePolicyAlgorithms>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validity: Option<CertificatePolicyValidity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    basic_constraints: Option<CertificatePolicyBasicConstraints>,
}

enum NullableUpdate<T> {
    Value(T),
    Null,
}

impl<T: Serialize> Serialize for NullableUpdate<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Value(value) => value.serialize(serializer),
            Self::Null => serializer.serialize_none(),
        }
    }
}

impl<T> From<CertificatePolicyFieldChange<T>> for NullableUpdate<T> {
    fn from(change: CertificatePolicyFieldChange<T>) -> Self {
        match change {
            CertificatePolicyFieldChange::Set(value) => Self::Value(value),
            CertificatePolicyFieldChange::Clear => Self::Null,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdatePolicyRequest {
    #[serde(skip_serializing)]
    policy_id: CertificatePolicyId,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<Vec<CertificatePolicyValueRule<CertificatePolicySubjectAttribute>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sans: Option<Vec<CertificatePolicyValueRule<CertificatePolicySanType>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_usages: Option<CertificatePolicyUsageRule<CertificateKeyUsage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extended_key_usages: Option<CertificatePolicyUsageRule<CertificateExtendedKeyUsage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithms: Option<CertificatePolicyAlgorithms>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validity: Option<CertificatePolicyValidity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    basic_constraints: Option<NullableUpdate<CertificatePolicyBasicConstraints>>,
}

#[derive(Serialize)]
struct DeletePolicyRequest {
    #[serde(skip_serializing)]
    policy_id: CertificatePolicyId,
}

struct ListPolicies;
impl sealed::Sealed for ListPolicies {}
impl ObservableReadOperation for ListPolicies {
    type Query = ListPoliciesQuery;
    type Output = ListPoliciesResponse;

    fn endpoint(_query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["cert-manager", "certificate-policies"])
    }
}

struct GetPolicy;
impl sealed::Sealed for GetPolicy {}
impl ObservableReadOperation for GetPolicy {
    type Query = ExactPolicyQuery;
    type Output = PolicyResponse;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "cert-manager",
                "certificate-policies",
                query.policy_id.as_str(),
            ],
        )
    }
}

struct CreatePolicy;
impl sealed::Sealed for CreatePolicy {}
impl MutationOperation for CreatePolicy {
    type Input = CreatePolicyRequest;
    type Output = PolicyResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["cert-manager", "certificate-policies"])
    }
}

struct UpdatePolicy;
impl sealed::Sealed for UpdatePolicy {}
impl MutationOperation for UpdatePolicy {
    type Input = UpdatePolicyRequest;
    type Output = PolicyResponse;

    fn method() -> Method {
        Method::PATCH
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "cert-manager",
                "certificate-policies",
                input.policy_id.as_str(),
            ],
        )
    }
}

struct DeletePolicy;
impl sealed::Sealed for DeletePolicy {}
impl MutationOperation for DeletePolicy {
    type Input = DeletePolicyRequest;
    type Output = PolicyResponse;

    fn method() -> Method {
        Method::DELETE
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "cert-manager",
                "certificate-policies",
                input.policy_id.as_str(),
            ],
        )
    }
}

fn policy_from_wire(
    wire: CertificatePolicyWire,
    project_id: &CertificateAuthorityProjectId,
    expected_id: Option<&CertificatePolicyId>,
) -> Result<CertificatePolicy, ResourceError> {
    let id = CertificatePolicyId::new(wire.id)
        .map_err(|_| ResourceError::InvalidCertificatePolicyResponse)?;
    if wire.project_id != project_id.as_str() || expected_id.is_some_and(|expected| expected != &id)
    {
        return Err(ResourceError::InvalidCertificatePolicyScope);
    }
    if !valid_response_name(&wire.name)
        || utc_timestamp_millis(&wire.created_at).is_none()
        || utc_timestamp_millis(&wire.updated_at).is_none()
        || utc_timestamp_millis(&wire.updated_at) < utc_timestamp_millis(&wire.created_at)
    {
        return Err(ResourceError::InvalidCertificatePolicyResponse);
    }
    let policy = CertificatePolicy {
        id: id.as_str().to_owned(),
        project_id: project_id.as_str().to_owned(),
        name: wire.name,
        description: wire.description,
        subject: wire.subject,
        sans: wire.sans,
        key_usages: wire.key_usages,
        extended_key_usages: wire.extended_key_usages,
        algorithms: wire.algorithms,
        validity: wire.validity,
        basic_constraints: wire.basic_constraints,
        created_at: wire.created_at,
        updated_at: wire.updated_at,
    };
    let response_contract = CertificatePolicyCreation {
        name: policy.name.clone(),
        description: policy.description.clone(),
        subject: policy.subject.clone(),
        sans: policy.sans.clone(),
        key_usages: policy.key_usages.clone(),
        extended_key_usages: policy.extended_key_usages.clone(),
        algorithms: policy.algorithms.clone(),
        validity: policy.validity.clone(),
        basic_constraints: policy.basic_constraints.clone(),
    };
    response_contract
        .validate(false)
        .map_err(|_| ResourceError::InvalidCertificatePolicyResponse)?;
    Ok(policy)
}

fn policy_matches_creation(
    policy: &CertificatePolicy,
    creation: &CertificatePolicyCreation,
) -> bool {
    policy_name_matches_creation(&policy.name, &creation.name)
        && policy.description == creation.description
        && policy.subject == creation.subject
        && policy.sans == creation.sans
        && policy.key_usages == creation.key_usages
        && policy.extended_key_usages == creation.extended_key_usages
        && policy.algorithms == creation.algorithms
        && policy.validity == creation.validity
        && policy.basic_constraints == creation.basic_constraints
}

fn nullable_update_or_unchanged_matches<T: PartialEq>(
    actual: Option<&T>,
    before: Option<&T>,
    change: Option<&NullableUpdate<T>>,
) -> bool {
    match change {
        None => actual == before,
        Some(NullableUpdate::Value(expected)) => actual == Some(expected),
        Some(NullableUpdate::Null) => actual.is_none(),
    }
}

fn replacement_or_unchanged_matches<T: PartialEq>(
    actual: Option<&T>,
    before: Option<&T>,
    replacement: Option<&T>,
) -> bool {
    replacement.map_or(actual == before, |expected| actual == Some(expected))
}

fn policy_update_reflected(
    policy: &CertificatePolicy,
    before: &CertificatePolicy,
    request: &UpdatePolicyRequest,
) -> bool {
    policy.id == before.id
        && policy.project_id == before.project_id
        && policy.created_at == before.created_at
        && request
            .name
            .as_ref()
            .map_or(policy.name == before.name, |name| {
                policy_name_matches_update(&policy.name, &before.name, name)
            })
        && replacement_or_unchanged_matches(
            policy.description.as_ref(),
            before.description.as_ref(),
            request.description.as_ref(),
        )
        && replacement_or_unchanged_matches(
            policy.subject.as_ref(),
            before.subject.as_ref(),
            request.subject.as_ref(),
        )
        && replacement_or_unchanged_matches(
            policy.sans.as_ref(),
            before.sans.as_ref(),
            request.sans.as_ref(),
        )
        && replacement_or_unchanged_matches(
            policy.key_usages.as_ref(),
            before.key_usages.as_ref(),
            request.key_usages.as_ref(),
        )
        && replacement_or_unchanged_matches(
            policy.extended_key_usages.as_ref(),
            before.extended_key_usages.as_ref(),
            request.extended_key_usages.as_ref(),
        )
        && replacement_or_unchanged_matches(
            policy.algorithms.as_ref(),
            before.algorithms.as_ref(),
            request.algorithms.as_ref(),
        )
        && replacement_or_unchanged_matches(
            policy.validity.as_ref(),
            before.validity.as_ref(),
            request.validity.as_ref(),
        )
        && nullable_update_or_unchanged_matches(
            policy.basic_constraints.as_ref(),
            before.basic_constraints.as_ref(),
            request.basic_constraints.as_ref(),
        )
}

fn policy_core_eq(left: &CertificatePolicy, right: &CertificatePolicy) -> bool {
    left.id == right.id
        && left.project_id == right.project_id
        && left.name == right.name
        && left.description == right.description
        && left.subject == right.subject
        && left.sans == right.sans
        && left.key_usages == right.key_usages
        && left.extended_key_usages == right.extended_key_usages
        && left.algorithms == right.algorithms
        && left.validity == right.validity
        && left.basic_constraints == right.basic_constraints
        && left.created_at == right.created_at
}

fn policy_name_matches_creation(actual: &str, requested: &str) -> bool {
    if actual == requested {
        return true;
    }
    if let Some(suffix) = actual
        .strip_prefix(requested)
        .and_then(|remainder| remainder.strip_prefix('-'))
    {
        return suffix.len() == POLICY_COLLISION_SUFFIX_BYTES
            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric());
    }
    actual.len() == POLICY_FALLBACK_NAME_BYTES
        && actual
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn policy_name_matches_update(actual: &str, before: &str, requested: &str) -> bool {
    if requested == before {
        return actual == before;
    }
    actual != before && policy_name_matches_creation(actual, requested)
}

fn validate_policy_page_bounds(
    page: PageRequest,
    returned: usize,
    total_count: u64,
) -> Result<(), ResourceError> {
    if returned > usize::from(page.limit()) {
        return Err(ResourceError::InvalidCertificatePolicyResponse);
    }
    let returned =
        u64::try_from(returned).map_err(|_| ResourceError::InvalidCertificatePolicyResponse)?;
    let offset = u64::from(page.offset());
    let end = offset
        .checked_add(returned)
        .ok_or(ResourceError::InvalidCertificatePolicyResponse)?;
    let page_fits_total = if returned == 0 {
        offset >= total_count
    } else if returned < u64::from(page.limit()) {
        end == total_count
    } else {
        end <= total_count
    };
    if !page_fits_total {
        return Err(ResourceError::InvalidCertificatePolicyResponse);
    }
    Ok(())
}

impl InfisicalClient {
    /// List one bounded page of certificate policies in a Certificate Manager project.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, filter, response-contract, or pagination error.
    pub async fn list_certificate_policies(
        &self,
        request: CertificatePolicyListRequest,
    ) -> Result<Page<CertificatePolicy>, ResourceError> {
        let response = self
            .execute_observable_read::<ListPolicies>(&ListPoliciesQuery {
                project_id: request.project_id.as_str().to_owned(),
                offset: request.page.offset(),
                limit: request.page.limit(),
                search: request.search.clone(),
            })
            .await?;
        validate_policy_page_bounds(
            request.page,
            response.certificate_policies.len(),
            response.total_count,
        )?;
        let policies = response
            .certificate_policies
            .into_iter()
            .map(|wire| policy_from_wire(wire, &request.project_id, None))
            .collect::<Result<Vec<_>, _>>()?;
        if policies
            .iter()
            .map(|policy| policy.id.as_str())
            .collect::<HashSet<_>>()
            .len()
            != policies.len()
        {
            return Err(ResourceError::InvalidCertificatePolicyResponse);
        }
        if let Some(search) = request.search.as_deref().map(str::to_lowercase)
            && policies.iter().any(|policy| {
                !policy.name.to_lowercase().contains(&search)
                    && !policy
                        .description
                        .as_deref()
                        .is_some_and(|value| value.to_lowercase().contains(&search))
            })
        {
            return Err(ResourceError::InvalidCertificatePolicyResponse);
        }
        Ok(Page::new(
            request.page,
            policies,
            Some(response.total_count),
        )?)
    }

    /// Get one exact certificate policy and prove project ownership.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or response-contract error.
    pub async fn get_certificate_policy(
        &self,
        project_id: &CertificateAuthorityProjectId,
        policy_id: &CertificatePolicyId,
    ) -> Result<CertificatePolicy, ResourceError> {
        let response = self
            .execute_observable_read::<GetPolicy>(&ExactPolicyQuery {
                policy_id: policy_id.clone(),
            })
            .await?;
        policy_from_wire(response.certificate_policy, project_id, Some(policy_id))
    }

    /// Create one certificate policy after project validation and explicit confirmation.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, project-kind, typed client, scope, or response-contract error.
    /// The mutation is sent exactly once.
    pub async fn create_certificate_policy(
        &self,
        project_id: &CertificateAuthorityProjectId,
        creation: &CertificatePolicyCreation,
        confirm: bool,
    ) -> Result<CertificatePolicy, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificatePolicyCreateNotConfirmed);
        }
        self.ensure_certificate_manager_project(project_id).await?;
        let response = self
            .execute_mutation::<CreatePolicy>(&CreatePolicyRequest {
                project_id: project_id.as_str().to_owned(),
                name: creation.name.clone(),
                description: creation.description.clone(),
                subject: creation.subject.clone(),
                sans: creation.sans.clone(),
                key_usages: creation.key_usages.clone(),
                extended_key_usages: creation.extended_key_usages.clone(),
                algorithms: creation.algorithms.clone(),
                validity: creation.validity.clone(),
                basic_constraints: creation.basic_constraints.clone(),
            })
            .await?;
        let policy = policy_from_wire(response.certificate_policy, project_id, None)?;
        if !policy_matches_creation(&policy, creation) {
            return Err(ResourceError::InvalidCertificatePolicyResponse);
        }
        Ok(policy)
    }

    /// Apply one validated policy change after confirmation and ownership preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error. The mutation is
    /// sent exactly once.
    pub async fn update_certificate_policy(
        &self,
        project_id: &CertificateAuthorityProjectId,
        policy_id: &CertificatePolicyId,
        change: CertificatePolicyChange,
        confirm: bool,
    ) -> Result<CertificatePolicy, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificatePolicyUpdateNotConfirmed);
        }
        let before = self.get_certificate_policy(project_id, policy_id).await?;
        let request = UpdatePolicyRequest {
            policy_id: policy_id.clone(),
            name: change.name,
            description: change.description,
            subject: change.subject,
            sans: change.sans,
            key_usages: change.key_usages,
            extended_key_usages: change.extended_key_usages,
            algorithms: change.algorithms,
            validity: change.validity,
            basic_constraints: change.basic_constraints.map(Into::into),
        };
        let response = self.execute_mutation::<UpdatePolicy>(&request).await?;
        let policy = policy_from_wire(response.certificate_policy, project_id, Some(policy_id))?;
        if !policy_update_reflected(&policy, &before, &request) {
            return Err(ResourceError::InvalidCertificatePolicyResponse);
        }
        Ok(policy)
    }

    /// Permanently delete one exact policy after confirmation and ownership preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error. The pinned
    /// in-use rejection explains that dependent Certificate Manager configuration must change.
    pub async fn delete_certificate_policy(
        &self,
        project_id: &CertificateAuthorityProjectId,
        policy_id: &CertificatePolicyId,
        confirm: bool,
    ) -> Result<CertificatePolicy, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificatePolicyDeleteNotConfirmed);
        }
        let before = self.get_certificate_policy(project_id, policy_id).await?;
        let response = self
            .execute_mutation::<DeletePolicy>(&DeletePolicyRequest {
                policy_id: policy_id.clone(),
            })
            .await
            .map_err(|error| match &error {
                crate::ClientError::Api(failure) if failure.status() == 400 => {
                    ResourceError::CertificatePolicyInUse
                }
                _ => ResourceError::Client(error),
            })?;
        let deleted = policy_from_wire(response.certificate_policy, project_id, Some(policy_id))?;
        if !policy_core_eq(&before, &deleted) {
            return Err(ResourceError::InvalidCertificatePolicyResponse);
        }
        Ok(deleted)
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
        CertificatePolicyAlgorithms, CertificatePolicyBasicConstraints, CertificatePolicyChange,
        CertificatePolicyCreation, CertificatePolicyFieldChange, CertificatePolicyInputError,
        CertificatePolicyKeyAlgorithm, CertificatePolicyListRequest, CertificatePolicyMaxValidity,
        CertificatePolicySanType, CertificatePolicySignatureAlgorithm, CertificatePolicyState,
        CertificatePolicySubjectAttribute, CertificatePolicyUsageRule, CertificatePolicyValidity,
        CertificatePolicyValueRule, policy_name_matches_creation, validate_policy_page_bounds,
    };
    use crate::{
        CertificateAuthorityProjectId, CertificateExtendedKeyUsage, CertificateKeyUsage,
        CertificatePolicyId, InfisicalClient, PageRequest, ResourceError,
        test_support::{mount_login, settings},
    };

    const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const POLICY_ID: &str = "22222222-2222-4222-8222-222222222222";

    fn policy_value(name: &str) -> Value {
        json!({
            "id": POLICY_ID,
            "projectId": PROJECT_ID,
            "name": name,
            "description": "server certificates",
            "subject": [{
                "type": "common_name",
                "allowed": ["*.example.test"]
            }],
            "sans": [{
                "type": "dns_name",
                "required": ["*.example.test"]
            }],
            "keyUsages": {
                "required": ["digital_signature"]
            },
            "extendedKeyUsages": {
                "required": ["server_auth"]
            },
            "algorithms": {
                "signature": ["SHA256-RSA"],
                "keyAlgorithm": ["RSA-2048"]
            },
            "validity": { "max": "365d" },
            "basicConstraints": { "isCA": "denied" },
            "createdAt": "2026-07-21T12:00:00.000Z",
            "updatedAt": "2026-07-21T12:00:01.000Z"
        })
    }

    fn creation() -> CertificatePolicyCreation {
        CertificatePolicyCreation::new(
            "server-certificates",
            Some("server certificates".into()),
            Some(vec![CertificatePolicyValueRule::new(
                CertificatePolicySubjectAttribute::CommonName,
                Some(vec!["*.example.test".into()]),
                None,
                None,
            )]),
            Some(vec![CertificatePolicyValueRule::new(
                CertificatePolicySanType::DnsName,
                None,
                Some(vec!["*.example.test".into()]),
                None,
            )]),
            Some(CertificatePolicyUsageRule::new(
                None,
                Some(vec![CertificateKeyUsage::DigitalSignature]),
                None,
            )),
            Some(CertificatePolicyUsageRule::new(
                None,
                Some(vec![CertificateExtendedKeyUsage::ServerAuth]),
                None,
            )),
            Some(CertificatePolicyAlgorithms::new(
                Some(vec![CertificatePolicySignatureAlgorithm::Sha256Rsa]),
                Some(vec![CertificatePolicyKeyAlgorithm::Rsa2048]),
            )),
            Some(CertificatePolicyValidity::new(Some(
                CertificatePolicyMaxValidity::new("365d").unwrap(),
            ))),
            Some(CertificatePolicyBasicConstraints::new(
                Some(CertificatePolicyState::Denied),
                None,
            )),
        )
        .unwrap()
    }

    async fn mount_project(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{PROJECT_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": {
                    "id": PROJECT_ID,
                    "name": "Certificates",
                    "slug": "certificates",
                    "type": "cert-manager",
                    "orgId": "org_123",
                    "description": null,
                    "environments": []
                }
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[test]
    fn policy_text_inputs_reject_surrounding_whitespace() {
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        assert_eq!(
            CertificatePolicyListRequest::new(
                project_id,
                PageRequest::new(0, 20).unwrap(),
                Some(" server".into()),
            )
            .unwrap_err(),
            CertificatePolicyInputError::InvalidSearch
        );
        assert_eq!(
            CertificatePolicyCreation::new(
                "policy",
                Some("description ".into()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            CertificatePolicyInputError::InvalidDescription
        );
    }

    #[test]
    fn policy_wire_invariants_reject_invalid_validity_names_and_totals() {
        assert!(serde_json::from_value::<CertificatePolicyMaxValidity>(json!("0d")).is_err());
        assert!(policy_name_matches_creation(
            "server-certificates-ab12CD34",
            "server-certificates"
        ));
        assert!(policy_name_matches_creation(
            "ab12cd34ef56",
            "server-certificates"
        ));
        assert!(!policy_name_matches_creation(
            "unrelated-policy",
            "server-certificates"
        ));

        let page = PageRequest::new(0, 20).unwrap();
        assert_eq!(
            validate_policy_page_bounds(page, 1, 2).unwrap_err(),
            ResourceError::InvalidCertificatePolicyResponse
        );
        assert_eq!(
            validate_policy_page_bounds(PageRequest::new(20, 20).unwrap(), 1, 20).unwrap_err(),
            ResourceError::InvalidCertificatePolicyResponse
        );
    }

    #[test]
    fn policy_inputs_reject_ambiguous_or_contradictory_rules() {
        assert_eq!(
            CertificatePolicyMaxValidity::new("0d").unwrap_err(),
            CertificatePolicyInputError::InvalidValidity
        );
        assert_eq!(
            CertificatePolicyChange::new(None, None, None, None, None, None, None, None, None)
                .unwrap_err(),
            CertificatePolicyInputError::EmptyChange
        );
        assert_eq!(
            CertificatePolicyCreation::new(
                "Not a slug",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            CertificatePolicyInputError::InvalidName
        );
        let contradictory = CertificatePolicyUsageRule::new(
            Some(vec![CertificateKeyUsage::DigitalSignature]),
            None,
            Some(vec![CertificateKeyUsage::DigitalSignature]),
        );
        assert_eq!(
            CertificatePolicyCreation::new(
                "policy",
                None,
                None,
                None,
                Some(contradictory),
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            CertificatePolicyInputError::ContradictoryRule
        );
        assert_eq!(
            CertificatePolicyCreation::new(
                "policy",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(CertificatePolicyBasicConstraints::new(
                    Some(CertificatePolicyState::Denied),
                    Some(0),
                )),
            )
            .unwrap_err(),
            CertificatePolicyInputError::InvalidBasicConstraints
        );
        CertificatePolicyCreation::new(
            "deny-subjects",
            None,
            Some(vec![CertificatePolicyValueRule::new(
                CertificatePolicySubjectAttribute::CommonName,
                Some(Vec::new()),
                None,
                None,
            )]),
            None,
            None,
            None,
            None,
            None,
            Some(CertificatePolicyBasicConstraints::new(None, Some(1_000))),
        )
        .unwrap();

        let aliases: CertificatePolicyAlgorithms = serde_json::from_value(json!({
            "signature": ["RSA-SHA256"],
            "keyAlgorithm": ["RSA_2048"]
        }))
        .unwrap();
        assert_eq!(
            serde_json::to_value(aliases).unwrap(),
            json!({
                "signature": ["SHA256-RSA"],
                "keyAlgorithm": ["RSA-2048"]
            })
        );
    }

    #[tokio::test]
    async fn list_and_get_bind_policy_scope_and_filters() {
        let server = MockServer::start().await;
        mount_login(&server, "policy-read-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/certificate-policies"))
            .and(query_param("projectId", PROJECT_ID))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "20"))
            .and(query_param("search", "server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicies": [policy_value("server-certificates")],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{POLICY_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": policy_value("server-certificates")
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let request = CertificatePolicyListRequest::new(
            project_id.clone(),
            PageRequest::new(0, 20).unwrap(),
            Some("server".into()),
        )
        .unwrap();
        let page = client.list_certificate_policies(request).await.unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].id, POLICY_ID);
        let exact = client
            .get_certificate_policy(&project_id, &CertificatePolicyId::new(POLICY_ID).unwrap())
            .await
            .unwrap();
        assert_eq!(exact.name, "server-certificates");
    }

    #[tokio::test]
    async fn create_preflights_project_and_accepts_canonicalized_name() {
        let server = MockServer::start().await;
        mount_login(&server, "policy-create-token").await;
        mount_project(&server).await;
        let expected_body = json!({
            "projectId": PROJECT_ID,
            "name": "server-certificates",
            "description": "server certificates",
            "subject": [{
                "type": "common_name",
                "allowed": ["*.example.test"]
            }],
            "sans": [{
                "type": "dns_name",
                "required": ["*.example.test"]
            }],
            "keyUsages": {
                "required": ["digital_signature"]
            },
            "extendedKeyUsages": {
                "required": ["server_auth"]
            },
            "algorithms": {
                "signature": ["SHA256-RSA"],
                "keyAlgorithm": ["RSA-2048"]
            },
            "validity": { "max": "365d" },
            "basicConstraints": { "isCA": "denied" }
        });
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificate-policies"))
            .and(body_json(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": policy_value("server-certificates-ab12cd34")
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let policy = client
            .create_certificate_policy(&project_id, &creation(), true)
            .await
            .unwrap();
        assert_eq!(policy.name, "server-certificates-ab12cd34");
    }

    #[tokio::test]
    async fn create_rejects_an_unrelated_returned_policy_name() {
        let server = MockServer::start().await;
        mount_login(&server, "policy-create-token").await;
        mount_project(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificate-policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": policy_value("unrelated-policy")
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        assert_eq!(
            client
                .create_certificate_policy(&project_id, &creation(), true)
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificatePolicyResponse
        );
    }

    #[tokio::test]
    async fn create_requires_confirmation_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        assert_eq!(
            client
                .create_certificate_policy(&project_id, &creation(), false)
                .await
                .unwrap_err(),
            ResourceError::CertificatePolicyCreateNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn update_preflights_scope_sends_null_and_checks_reflection() {
        let server = MockServer::start().await;
        mount_login(&server, "policy-update-token").await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{POLICY_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": policy_value("server-certificates")
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut updated = policy_value("renamed-policy-ab12cd34");
        updated["description"] = json!("renamed server policy");
        updated["basicConstraints"] = Value::Null;
        updated["updatedAt"] = json!("2026-07-21T12:00:02.000Z");
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{POLICY_ID}"
            )))
            .and(body_json(json!({
                "name": "renamed-policy",
                "description": "renamed server policy",
                "basicConstraints": null
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": updated
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let policy_id = CertificatePolicyId::new(POLICY_ID).unwrap();
        let change = CertificatePolicyChange::new(
            Some("renamed-policy".into()),
            Some("renamed server policy".into()),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(CertificatePolicyFieldChange::Clear),
        )
        .unwrap();
        let policy = client
            .update_certificate_policy(&project_id, &policy_id, change, true)
            .await
            .unwrap();
        assert_eq!(policy.name, "renamed-policy-ab12cd34");
        assert_eq!(policy.description.as_deref(), Some("renamed server policy"));
        assert_eq!(policy.basic_constraints, None);
    }

    #[tokio::test]
    async fn update_rejects_an_unchanged_fallback_shaped_name() {
        let server = MockServer::start().await;
        mount_login(&server, "policy-update-token").await;
        let fallback_name = "abcdefghijkl";
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{POLICY_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": policy_value(fallback_name)
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut unchanged = policy_value(fallback_name);
        unchanged["updatedAt"] = json!("2026-07-21T12:00:02.000Z");
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{POLICY_ID}"
            )))
            .and(body_json(json!({ "name": "renamed-policy" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": unchanged
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let change = CertificatePolicyChange::new(
            Some("renamed-policy".into()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            client
                .update_certificate_policy(
                    &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                    &CertificatePolicyId::new(POLICY_ID).unwrap(),
                    change,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificatePolicyResponse
        );
    }

    #[tokio::test]
    async fn delete_preflights_scope_and_returns_the_deleted_policy() {
        let server = MockServer::start().await;
        mount_login(&server, "policy-delete-token").await;
        for request_method in ["GET", "DELETE"] {
            Mock::given(method(request_method))
                .and(path(format!(
                    "/api/v1/cert-manager/certificate-policies/{POLICY_ID}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "certificatePolicy": policy_value("server-certificates")
                })))
                .expect(1)
                .mount(&server)
                .await;
        }
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let policy = client
            .delete_certificate_policy(
                &project_id,
                &CertificatePolicyId::new(POLICY_ID).unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(policy.id, POLICY_ID);
    }

    #[tokio::test]
    async fn policy_mutations_require_confirmation_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let policy_id = CertificatePolicyId::new(POLICY_ID).unwrap();
        let change = CertificatePolicyChange::new(
            Some("renamed-policy".into()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            client
                .update_certificate_policy(&project_id, &policy_id, change, false)
                .await
                .unwrap_err(),
            ResourceError::CertificatePolicyUpdateNotConfirmed
        );
        assert_eq!(
            client
                .delete_certificate_policy(&project_id, &policy_id, false)
                .await
                .unwrap_err(),
            ResourceError::CertificatePolicyDeleteNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_sanitizes_the_pinned_in_use_rejection() {
        let server = MockServer::start().await;
        mount_login(&server, "policy-delete-token").await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{POLICY_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": policy_value("server-certificates")
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{POLICY_ID}"
            )))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "message": "profile-name-must-not-cross-the-boundary"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let error = client
            .delete_certificate_policy(
                &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                &CertificatePolicyId::new(POLICY_ID).unwrap(),
                true,
            )
            .await
            .unwrap_err();
        assert_eq!(error, ResourceError::CertificatePolicyInUse);
        assert!(!error.to_string().contains("profile-name"));
    }

    #[tokio::test]
    async fn delete_preserves_a_non_reference_validation_rejection() {
        let server = MockServer::start().await;
        mount_login(&server, "policy-delete-token").await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{POLICY_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": policy_value("server-certificates")
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{POLICY_ID}"
            )))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "message": "validation-detail-must-not-cross-the-boundary"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let error = client
            .delete_certificate_policy(
                &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                &CertificatePolicyId::new(POLICY_ID).unwrap(),
                true,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ResourceError::Client(crate::ClientError::Api(ref failure))
                if failure.status() == 422
        ));
        assert!(!error.to_string().contains("validation-detail"));
    }
}
