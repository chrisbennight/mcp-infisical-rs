use std::{collections::HashSet, net::IpAddr, str::FromStr};

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use x509_parser::{
    cri_attributes::ParsedCriAttribute,
    extensions::{GeneralName, ParsedExtension},
    oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME,
    prelude::{FromDer, X509Certificate, X509CertificationRequest},
};

use crate::{
    CertificateAuthorityProjectId, CertificateExtendedKeyUsage, CertificateId,
    CertificateKeyAlgorithm, CertificateKeyUsage, CertificatePolicyMaxValidity,
    CertificatePolicySanType, CertificateProfileEnrollmentType, CertificateProfileId,
    CertificateRequestId, CertificateRequestStatus, CertificateSignatureAlgorithm, ClientError,
    InfisicalClient, MutationOperation, ResourceError, SecretValue,
    certificate::{certificate_bundle_der, certificate_serial_matches, normalize_pem},
    client::{ApiVersion, Endpoint, sealed},
    pki_certificate_operations::is_valid_csr,
    pki_certificate_profiles::{
        CertificateProfileEnrollmentMetadata, certificate_chain_is_linked_to_leaf,
        certificate_signature_is_valid, is_valid_single_certificate,
        private_key_matches_certificate,
    },
    resources::{is_bounded_text, is_uuid, utc_timestamp_millis},
};

const MAX_CSR_BYTES: usize = 4_096;
const MAX_SUBJECT_BYTES: usize = 256;
const MAX_SAN_VALUES: usize = 100;
const MAX_SAN_BYTES: usize = 2_048;
const MAX_METADATA_ENTRIES: usize = 100;
const MAX_METADATA_KEY_BYTES: usize = 255;
const MAX_METADATA_VALUE_BYTES: usize = 1_020;
const MAX_CERTIFICATE_PEM_BYTES: usize = 64 * 1_024;
const MAX_CERTIFICATE_CHAIN_PEM_BYTES: usize = 512 * 1_024;
const MAX_SERIAL_NUMBER_BYTES: usize = 128;
/// Maximum combined bytes of normalized leaf, issuer, chain, and private-key PEM in one
/// successful issuance outcome.
pub const MAX_CERTIFICATE_ISSUANCE_MATERIAL_BYTES: usize = 96 * 1_024;

/// Input validation failures for certificate issuance.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CertificateIssuanceInputError {
    #[error("certificate subject fields must be trimmed, control-free, and bounded")]
    InvalidSubject,
    #[error("certificate country must contain two uppercase ASCII letters")]
    InvalidCountry,
    #[error("certificate SANs must be bounded, typed, valid, and unique")]
    InvalidSans,
    #[error("certificate usages must be non-empty bounded sets without duplicates")]
    InvalidUsages,
    #[error("certificate validity must be a positive duration or an ordered UTC window")]
    InvalidValidity,
    #[error("certificate basic constraints require a CA certificate when path length is set")]
    InvalidBasicConstraints,
    #[error("CSR must be one signed PKCS #10 PEM block accepted by the pinned route")]
    InvalidCsr,
    #[error("certificate metadata keys and values must be trimmed, bounded, and unique")]
    InvalidMetadata,
    #[error("certificate application ID must be a UUID")]
    InvalidApplicationId,
}

/// One typed subject-alternative name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateIssuanceSan {
    #[serde(rename = "type")]
    pub san_type: CertificatePolicySanType,
    pub value: String,
}

impl CertificateIssuanceSan {
    /// Validate and normalize one typed SAN.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is unbounded, malformed for its family, or
    /// cannot be normalized safely.
    pub fn new(
        san_type: CertificatePolicySanType,
        value: impl Into<String>,
    ) -> Result<Self, CertificateIssuanceInputError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_SAN_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(CertificateIssuanceInputError::InvalidSans);
        }
        let value = match san_type {
            CertificatePolicySanType::DnsName => {
                normalize_dns_name(&value).ok_or(CertificateIssuanceInputError::InvalidSans)?
            }
            CertificatePolicySanType::IpAddress => IpAddr::from_str(&value)
                .map_err(|_| CertificateIssuanceInputError::InvalidSans)?
                .to_string(),
            CertificatePolicySanType::Email => {
                if !valid_email(&value) {
                    return Err(CertificateIssuanceInputError::InvalidSans);
                }
                value
            }
            CertificatePolicySanType::Uri => {
                let uri =
                    Url::parse(&value).map_err(|_| CertificateIssuanceInputError::InvalidSans)?;
                if uri.scheme().is_empty() {
                    return Err(CertificateIssuanceInputError::InvalidSans);
                }
                value
            }
        };
        Ok(Self { san_type, value })
    }

    fn validate(&self) -> Result<(), CertificateIssuanceInputError> {
        if Self::new(self.san_type, self.value.clone()).as_ref() != Ok(self) {
            return Err(CertificateIssuanceInputError::InvalidSans);
        }
        Ok(())
    }
}

/// Explicit certificate validity selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum CertificateIssuanceValidity {
    Ttl {
        ttl: CertificatePolicyMaxValidity,
    },
    Window {
        not_before: String,
        not_after: String,
    },
}

impl CertificateIssuanceValidity {
    /// Validate an explicit UTC validity window.
    ///
    /// # Errors
    ///
    /// Returns an error when either timestamp is invalid or the window is not ordered.
    pub fn window(
        not_before: impl Into<String>,
        not_after: impl Into<String>,
    ) -> Result<Self, CertificateIssuanceInputError> {
        let not_before = not_before.into();
        let not_after = not_after.into();
        let before = utc_timestamp_millis(&not_before)
            .ok_or(CertificateIssuanceInputError::InvalidValidity)?;
        let after = utc_timestamp_millis(&not_after)
            .ok_or(CertificateIssuanceInputError::InvalidValidity)?;
        if before >= after {
            return Err(CertificateIssuanceInputError::InvalidValidity);
        }
        Ok(Self::Window {
            not_before,
            not_after,
        })
    }

    fn validate(&self) -> Result<(), CertificateIssuanceInputError> {
        match self {
            Self::Ttl { .. } => Ok(()),
            Self::Window {
                not_before,
                not_after,
            } if Self::window(not_before.clone(), not_after.clone()).as_ref() == Ok(self) => Ok(()),
            Self::Window { .. } => Err(CertificateIssuanceInputError::InvalidValidity),
        }
    }
}

/// CA basic constraints requested for an issued certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateIssuanceBasicConstraints {
    #[serde(rename = "isCA")]
    pub is_ca: bool,
    pub path_length: Option<u8>,
}

impl CertificateIssuanceBasicConstraints {
    /// Validate a CA/path-length pairing.
    ///
    /// # Errors
    ///
    /// Returns an error when a non-CA certificate declares a path length.
    pub fn new(
        is_ca: bool,
        path_length: Option<u8>,
    ) -> Result<Self, CertificateIssuanceInputError> {
        if !is_ca && path_length.is_some() {
            return Err(CertificateIssuanceInputError::InvalidBasicConstraints);
        }
        Ok(Self { is_ca, path_length })
    }

    fn validate(self) -> Result<(), CertificateIssuanceInputError> {
        Self::new(self.is_ca, self.path_length).map(|_| ())
    }
}

/// Bounded non-secret certificate metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateIssuanceMetadata {
    pub key: String,
    pub value: String,
}

impl CertificateIssuanceMetadata {
    /// Validate one metadata entry from the pinned non-encrypted schema.
    ///
    /// # Errors
    ///
    /// Returns an error when the key or value violates the bounded text contract.
    pub fn new(
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, CertificateIssuanceInputError> {
        let key = key.into();
        let value = value.into();
        if key.is_empty()
            || key.len() > MAX_METADATA_KEY_BYTES
            || key.trim() != key
            || key.chars().any(char::is_control)
            || value.len() > MAX_METADATA_VALUE_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(CertificateIssuanceInputError::InvalidMetadata);
        }
        Ok(Self { key, value })
    }

    fn validate(&self) -> Result<(), CertificateIssuanceInputError> {
        if Self::new(self.key.clone(), self.value.clone()).as_ref() != Ok(self) {
            return Err(CertificateIssuanceInputError::InvalidMetadata);
        }
        Ok(())
    }
}

/// Bounded managed-key certificate attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateIssuanceAttributes {
    common_name: Option<String>,
    organization: Option<String>,
    organizational_unit: Option<String>,
    country: Option<String>,
    state: Option<String>,
    locality: Option<String>,
    key_usages: Option<Vec<CertificateKeyUsage>>,
    extended_key_usages: Option<Vec<CertificateExtendedKeyUsage>>,
    alternative_names: Option<Vec<CertificateIssuanceSan>>,
    validity: Option<CertificateIssuanceValidity>,
    signature_algorithm: Option<CertificateSignatureAlgorithm>,
    key_algorithm: Option<CertificateKeyAlgorithm>,
    basic_constraints: Option<CertificateIssuanceBasicConstraints>,
}

impl CertificateIssuanceAttributes {
    /// Validate all managed-key request attributes before the profile preflight.
    ///
    /// # Errors
    ///
    /// Returns an error when a subject, usage, SAN, validity, algorithm, or basic
    /// constraint is malformed or internally inconsistent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        common_name: Option<String>,
        organization: Option<String>,
        organizational_unit: Option<String>,
        country: Option<String>,
        state: Option<String>,
        locality: Option<String>,
        key_usages: Option<Vec<CertificateKeyUsage>>,
        extended_key_usages: Option<Vec<CertificateExtendedKeyUsage>>,
        alternative_names: Option<Vec<CertificateIssuanceSan>>,
        validity: Option<CertificateIssuanceValidity>,
        signature_algorithm: Option<CertificateSignatureAlgorithm>,
        key_algorithm: Option<CertificateKeyAlgorithm>,
        basic_constraints: Option<CertificateIssuanceBasicConstraints>,
    ) -> Result<Self, CertificateIssuanceInputError> {
        for value in [
            common_name.as_deref(),
            organization.as_deref(),
            organizational_unit.as_deref(),
            state.as_deref(),
            locality.as_deref(),
        ] {
            if value.is_some_and(|value| {
                value.is_empty()
                    || !is_bounded_text(value, MAX_SUBJECT_BYTES)
                    || value.trim() != value
            }) {
                return Err(CertificateIssuanceInputError::InvalidSubject);
            }
        }
        if country.as_deref().is_some_and(|value| {
            value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_uppercase())
        }) {
            return Err(CertificateIssuanceInputError::InvalidCountry);
        }
        validate_unique_values(key_usages.as_deref())?;
        validate_unique_values(extended_key_usages.as_deref())?;
        if alternative_names.as_deref().is_some_and(|values| {
            values.is_empty()
                || values.len() > MAX_SAN_VALUES
                || values.iter().collect::<HashSet<_>>().len() != values.len()
        }) {
            return Err(CertificateIssuanceInputError::InvalidSans);
        }
        let attributes = Self {
            common_name,
            organization,
            organizational_unit,
            country,
            state,
            locality,
            key_usages,
            extended_key_usages,
            alternative_names,
            validity,
            signature_algorithm,
            key_algorithm,
            basic_constraints,
        };
        attributes.validate_nested()?;
        Ok(attributes)
    }

    fn validate_nested(&self) -> Result<(), CertificateIssuanceInputError> {
        if let Some(alternative_names) = &self.alternative_names {
            for alternative_name in alternative_names {
                alternative_name.validate()?;
            }
        }
        if let Some(validity) = &self.validity {
            validity.validate()?;
        }
        if let Some(basic_constraints) = self.basic_constraints {
            basic_constraints.validate()?;
        }
        Ok(())
    }
}

/// Closed certificate key-source selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateIssuanceMethod {
    Managed(CertificateIssuanceAttributes),
    Csr {
        csr: String,
        validity: Option<CertificateIssuanceValidity>,
        basic_constraints: Option<CertificateIssuanceBasicConstraints>,
    },
}

impl CertificateIssuanceMethod {
    /// Validate and normalize one caller-held PKCS #10 request.
    ///
    /// # Errors
    ///
    /// Returns an error unless the input is one bounded, signed PKCS #10 PEM block
    /// and its optional validity and basic constraints are coherent.
    pub fn csr(
        csr: impl Into<String>,
        validity: Option<CertificateIssuanceValidity>,
        basic_constraints: Option<CertificateIssuanceBasicConstraints>,
    ) -> Result<Self, CertificateIssuanceInputError> {
        let csr = csr.into();
        let csr = normalize_pem(&csr).ok_or(CertificateIssuanceInputError::InvalidCsr)?;
        let method = Self::Csr {
            csr,
            validity,
            basic_constraints,
        };
        method.validate()?;
        Ok(method)
    }

    fn validate(&self) -> Result<(), CertificateIssuanceInputError> {
        match self {
            Self::Managed(attributes) => attributes.validate_nested(),
            Self::Csr {
                csr,
                validity,
                basic_constraints,
            } => {
                let normalized =
                    normalize_pem(csr).ok_or(CertificateIssuanceInputError::InvalidCsr)?;
                if normalized != *csr || csr.len() > MAX_CSR_BYTES || !is_valid_csr(csr) {
                    return Err(CertificateIssuanceInputError::InvalidCsr);
                }
                if let Some(validity) = validity {
                    validity.validate()?;
                }
                if let Some(basic_constraints) = basic_constraints {
                    basic_constraints.validate()?;
                }
                Ok(())
            }
        }
    }
}

/// Complete canonical issuance input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateIssuance {
    profile_id: CertificateProfileId,
    application_id: Option<String>,
    method: CertificateIssuanceMethod,
    remove_roots_from_chain: bool,
    metadata: Option<Vec<CertificateIssuanceMetadata>>,
}

impl CertificateIssuance {
    /// Validate the complete issuance request before it can reach the HTTP client.
    ///
    /// # Errors
    ///
    /// Returns an error when any coordinate, method, nested attribute, or metadata
    /// invariant is invalid.
    pub fn new(
        profile_id: CertificateProfileId,
        application_id: Option<String>,
        method: CertificateIssuanceMethod,
        remove_roots_from_chain: bool,
        metadata: Option<Vec<CertificateIssuanceMetadata>>,
    ) -> Result<Self, CertificateIssuanceInputError> {
        if application_id
            .as_deref()
            .is_some_and(|value| !is_uuid(value))
        {
            return Err(CertificateIssuanceInputError::InvalidApplicationId);
        }
        method.validate()?;
        if let Some(entries) = &metadata {
            for entry in entries {
                entry.validate()?;
            }
        }
        if metadata.as_deref().is_some_and(|entries| {
            entries.len() > MAX_METADATA_ENTRIES
                || entries
                    .iter()
                    .map(|entry| entry.key.as_str())
                    .collect::<HashSet<_>>()
                    .len()
                    != entries.len()
        }) {
            return Err(CertificateIssuanceInputError::InvalidMetadata);
        }
        Ok(Self {
            profile_id,
            application_id: application_id.map(|value| value.to_ascii_lowercase()),
            method,
            remove_roots_from_chain,
            metadata,
        })
    }
}

/// Validated immediate issuance material.
#[derive(Debug)]
pub struct IssuedCertificate {
    pub project_id: String,
    pub profile_id: String,
    pub request_id: String,
    pub certificate_id: String,
    pub serial_number: String,
    pub certificate: String,
    pub issuing_ca_certificate: String,
    pub certificate_chain: String,
    pub private_key: Option<SecretValue>,
}

/// Separate immediate and pending canonical issuance outcomes.
#[derive(Debug)]
pub enum CertificateIssuanceOutcome {
    Issued(IssuedCertificate),
    Pending {
        project_id: String,
        profile_id: String,
        request_id: String,
        status: Option<CertificateRequestStatus>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IssueCertificateBody {
    profile_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    csr: Option<String>,
    attributes: IssueCertificateAttributes,
    remove_roots_from_chain: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Vec<CertificateIssuanceMetadata>>,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct IssueCertificateAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    common_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organizational_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_usages: Option<Vec<CertificateKeyUsage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extended_key_usages: Option<Vec<CertificateExtendedKeyUsage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alt_names: Option<Vec<CertificateIssuanceSan>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_algorithm: Option<CertificateSignatureAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_algorithm: Option<CertificateKeyAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    basic_constraints: Option<CertificateIssuanceBasicConstraints>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssueCertificateResponse {
    certificate: Option<IssuedCertificateWire>,
    certificate_request_id: String,
    status: Option<CertificateRequestStatus>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssuedCertificateWire {
    certificate: String,
    issuing_ca_certificate: String,
    certificate_chain: String,
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    private_key: Option<SecretValue>,
    serial_number: String,
    certificate_id: String,
}

fn deserialize_optional_secret<'de, D>(deserializer: D) -> Result<Option<SecretValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(SecretValue::new))
}

struct IssueCertificate;
impl sealed::Sealed for IssueCertificate {}
impl MutationOperation for IssueCertificate {
    type Input = IssueCertificateBody;
    type Output = IssueCertificateResponse;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["cert-manager", "certificates"])
    }
}

impl InfisicalClient {
    /// Issue one certificate through the canonical profile route exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error when confirmation, profile enrollment, upstream execution, or
    /// the returned certificate outcome violates the issuance contract.
    pub async fn issue_certificate(
        &self,
        project_id: &CertificateAuthorityProjectId,
        issuance: &CertificateIssuance,
        confirm: bool,
    ) -> Result<CertificateIssuanceOutcome, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateIssuanceNotConfirmed);
        }
        let profile = self
            .get_certificate_profile(project_id, &issuance.profile_id)
            .await?;
        if profile.enrollment_type != CertificateProfileEnrollmentType::Api
            || !matches!(
                profile.enrollment,
                Some(CertificateProfileEnrollmentMetadata::Api { .. })
            )
        {
            return Err(ResourceError::InvalidCertificateIssuanceProfile);
        }
        let body = issuance_body(issuance);
        let response = self
            .execute_mutation::<IssueCertificate>(&body)
            .await
            .map_err(|error| match error {
                ClientError::Transport(_)
                | ClientError::ResponseTooLarge { .. }
                | ClientError::InvalidMutationResponse => {
                    ResourceError::CertificateIssuanceOutcomeUnknown
                }
                other => ResourceError::Client(other),
            })?;
        let request_id = CertificateRequestId::new(response.certificate_request_id.clone())
            .map_err(|_| ResourceError::CertificateIssuanceOutcomeUnknown)?;
        let request_reference = request_id.as_str().to_owned();
        issuance_outcome(
            response,
            project_id,
            issuance,
            profile.defaults.as_ref(),
            &request_id,
        )
        .map_err(|_| ResourceError::CertificateIssuanceResponseUnverified {
            request_id: request_reference,
        })
    }
}

fn issuance_body(issuance: &CertificateIssuance) -> IssueCertificateBody {
    let (csr, attributes) = match &issuance.method {
        CertificateIssuanceMethod::Managed(attributes) => {
            (None, managed_attributes_body(attributes))
        }
        CertificateIssuanceMethod::Csr {
            csr,
            validity,
            basic_constraints,
        } => {
            let mut attributes = IssueCertificateAttributes {
                basic_constraints: *basic_constraints,
                ..IssueCertificateAttributes::default()
            };
            apply_validity(&mut attributes, validity.as_ref());
            (Some(csr.clone()), attributes)
        }
    };
    IssueCertificateBody {
        profile_id: issuance.profile_id.as_str().to_owned(),
        application_id: issuance.application_id.clone(),
        csr,
        attributes,
        remove_roots_from_chain: issuance.remove_roots_from_chain,
        metadata: issuance.metadata.clone(),
    }
}

fn managed_attributes_body(input: &CertificateIssuanceAttributes) -> IssueCertificateAttributes {
    let mut output = IssueCertificateAttributes {
        common_name: input.common_name.clone(),
        organization: input.organization.clone(),
        organizational_unit: input.organizational_unit.clone(),
        country: input.country.clone(),
        state: input.state.clone(),
        locality: input.locality.clone(),
        key_usages: input.key_usages.clone(),
        extended_key_usages: input.extended_key_usages.clone(),
        alt_names: input.alternative_names.clone(),
        signature_algorithm: input.signature_algorithm,
        key_algorithm: input.key_algorithm,
        basic_constraints: input.basic_constraints,
        ..IssueCertificateAttributes::default()
    };
    apply_validity(&mut output, input.validity.as_ref());
    output
}

fn apply_validity(
    output: &mut IssueCertificateAttributes,
    validity: Option<&CertificateIssuanceValidity>,
) {
    match validity {
        Some(CertificateIssuanceValidity::Ttl { ttl }) => {
            output.ttl = Some(ttl.as_str().to_owned());
        }
        Some(CertificateIssuanceValidity::Window {
            not_before,
            not_after,
        }) => {
            output.not_before = Some(not_before.clone());
            output.not_after = Some(not_after.clone());
        }
        None => {}
    }
}

fn issuance_outcome(
    response: IssueCertificateResponse,
    project_id: &CertificateAuthorityProjectId,
    issuance: &CertificateIssuance,
    defaults: Option<&crate::CertificateProfileDefaults>,
    request_id: &CertificateRequestId,
) -> Result<CertificateIssuanceOutcome, ResourceError> {
    match (response.status, response.certificate) {
        (None | Some(CertificateRequestStatus::Issued), Some(certificate)) => {
            issued_outcome(certificate, project_id, issuance, defaults, request_id)
                .map(CertificateIssuanceOutcome::Issued)
        }
        (
            Some(
                status @ (CertificateRequestStatus::PendingApproval
                | CertificateRequestStatus::Pending
                | CertificateRequestStatus::PendingValidation),
            ),
            None,
        ) => Ok(CertificateIssuanceOutcome::Pending {
            project_id: project_id.as_str().to_owned(),
            profile_id: issuance.profile_id.as_str().to_owned(),
            request_id: request_id.as_str().to_owned(),
            status: Some(status),
        }),
        (None, None) => Ok(CertificateIssuanceOutcome::Pending {
            project_id: project_id.as_str().to_owned(),
            profile_id: issuance.profile_id.as_str().to_owned(),
            request_id: request_id.as_str().to_owned(),
            status: None,
        }),
        _ => Err(ResourceError::InvalidCertificateIssuanceResponse),
    }
}

fn issued_outcome(
    wire: IssuedCertificateWire,
    project_id: &CertificateAuthorityProjectId,
    issuance: &CertificateIssuance,
    defaults: Option<&crate::CertificateProfileDefaults>,
    request_id: &CertificateRequestId,
) -> Result<IssuedCertificate, ResourceError> {
    let certificate_id = CertificateId::new(wire.certificate_id)
        .map_err(|_| ResourceError::InvalidCertificateIssuanceResponse)?;
    if wire.serial_number.is_empty()
        || wire.serial_number.len() > MAX_SERIAL_NUMBER_BYTES
        || !wire
            .serial_number
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ResourceError::InvalidCertificateIssuanceResponse);
    }
    let certificate = normalize_bounded_pem(&wire.certificate, MAX_CERTIFICATE_PEM_BYTES)?;
    if !is_valid_single_certificate(&certificate) {
        return Err(ResourceError::InvalidCertificateIssuanceResponse);
    }
    let certificate_der = certificate_bundle_der(&certificate)
        .and_then(|mut values| (values.len() == 1).then(|| values.pop()).flatten())
        .ok_or(ResourceError::InvalidCertificateIssuanceResponse)?;
    let (remainder, parsed) = X509Certificate::from_der(&certificate_der)
        .map_err(|_| ResourceError::InvalidCertificateIssuanceResponse)?;
    if !remainder.is_empty() || !certificate_serial_matches(&parsed, &wire.serial_number) {
        return Err(ResourceError::InvalidCertificateIssuanceResponse);
    }
    let issuing_ca_certificate = normalize_optional_certificate(&wire.issuing_ca_certificate)?;
    let certificate_chain = normalize_certificate_chain(&wire.certificate_chain)?;
    let private_key = wire
        .private_key
        .map(|value| {
            normalize_bounded_pem(value.expose_secret(), MAX_CERTIFICATE_PEM_BYTES)
                .map(SecretValue::new)
        })
        .transpose()?;
    if !issued_material_is_bounded(
        &certificate,
        &issuing_ca_certificate,
        &certificate_chain,
        private_key.as_ref(),
    ) {
        return Err(ResourceError::InvalidCertificateIssuanceResponse);
    }
    if !(certificate_chain_is_linked_to_leaf(&parsed, &certificate_chain)
        || (issuance.remove_roots_from_chain && certificate_chain.is_empty()))
        || !issuing_certificate_matches_leaf(&parsed, &issuing_ca_certificate, &certificate_chain)
    {
        return Err(ResourceError::InvalidCertificateIssuanceResponse);
    }
    match &issuance.method {
        CertificateIssuanceMethod::Managed(attributes) => {
            if private_key.as_ref().is_none_or(|value| {
                !private_key_matches_certificate(&parsed, value.expose_secret())
            }) || !managed_subject_matches(&parsed, attributes, defaults)
            {
                return Err(ResourceError::InvalidCertificateIssuanceResponse);
            }
        }
        CertificateIssuanceMethod::Csr { csr, .. } => {
            if private_key.is_some() || !csr_matches_certificate(csr, &parsed) {
                return Err(ResourceError::InvalidCertificateIssuanceResponse);
            }
        }
    }
    Ok(IssuedCertificate {
        project_id: project_id.as_str().to_owned(),
        profile_id: issuance.profile_id.as_str().to_owned(),
        request_id: request_id.as_str().to_owned(),
        certificate_id: certificate_id.as_str().to_owned(),
        serial_number: wire.serial_number,
        certificate,
        issuing_ca_certificate,
        certificate_chain,
        private_key,
    })
}

fn issued_material_is_bounded(
    certificate: &str,
    issuing_ca_certificate: &str,
    certificate_chain: &str,
    private_key: Option<&SecretValue>,
) -> bool {
    [
        certificate.len(),
        issuing_ca_certificate.len(),
        certificate_chain.len(),
        private_key.map_or(0, |value| value.expose_secret().len()),
    ]
    .into_iter()
    .try_fold(0_usize, usize::checked_add)
    .is_some_and(|total| total <= MAX_CERTIFICATE_ISSUANCE_MATERIAL_BYTES)
}

fn normalize_bounded_pem(value: &str, maximum: usize) -> Result<String, ResourceError> {
    if value.is_empty() || value.len() > maximum {
        return Err(ResourceError::InvalidCertificateIssuanceResponse);
    }
    normalize_pem(value).ok_or(ResourceError::InvalidCertificateIssuanceResponse)
}

fn normalize_optional_certificate(value: &str) -> Result<String, ResourceError> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let value = normalize_bounded_pem(value, MAX_CERTIFICATE_PEM_BYTES)?;
    is_valid_single_certificate(&value)
        .then_some(value)
        .ok_or(ResourceError::InvalidCertificateIssuanceResponse)
}

fn normalize_certificate_chain(value: &str) -> Result<String, ResourceError> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let value = normalize_bounded_pem(value, MAX_CERTIFICATE_CHAIN_PEM_BYTES)?;
    let certificates = certificate_bundle_der(&value)
        .filter(|values| !values.is_empty())
        .ok_or(ResourceError::InvalidCertificateIssuanceResponse)?;
    if certificates
        .iter()
        .any(|der| !X509Certificate::from_der(der).is_ok_and(|(remainder, _)| remainder.is_empty()))
    {
        return Err(ResourceError::InvalidCertificateIssuanceResponse);
    }
    Ok(value)
}

fn issuing_certificate_matches_leaf(
    leaf: &X509Certificate<'_>,
    issuing_certificate: &str,
    chain: &str,
) -> bool {
    if issuing_certificate.is_empty() {
        return chain.is_empty()
            && leaf.issuer() == leaf.subject()
            && certificate_signature_is_valid(leaf, leaf);
    }
    let Some(issuer_der) = certificate_bundle_der(issuing_certificate)
        .and_then(|mut values| (values.len() == 1).then(|| values.pop()).flatten())
    else {
        return false;
    };
    let Ok((remainder, issuer)) = X509Certificate::from_der(&issuer_der) else {
        return false;
    };
    if !remainder.is_empty()
        || !issuer.is_ca()
        || !issuer
            .key_usage()
            .is_ok_and(|usage| usage.is_none_or(|usage| usage.value.key_cert_sign()))
        || leaf.issuer() != issuer.subject()
        || !certificate_signature_is_valid(leaf, &issuer)
    {
        return false;
    }
    chain.is_empty()
        || certificate_bundle_der(chain)
            .and_then(|values| values.into_iter().next())
            .as_deref()
            == Some(issuer_der.as_slice())
}

fn managed_subject_matches(
    certificate: &X509Certificate<'_>,
    input: &CertificateIssuanceAttributes,
    defaults: Option<&crate::CertificateProfileDefaults>,
) -> bool {
    let expected_common_name = input
        .common_name
        .as_deref()
        .or_else(|| defaults.and_then(|value| value.common_name.as_deref()));
    let subject = certificate.subject();
    if !subject_values_match(
        subject
            .iter_common_name()
            .map(x509_parser::x509::AttributeTypeAndValue::as_str)
            .collect(),
        expected_common_name,
    ) || !subject_values_match(
        subject
            .iter_organization()
            .map(x509_parser::x509::AttributeTypeAndValue::as_str)
            .collect(),
        input
            .organization
            .as_deref()
            .or_else(|| defaults.and_then(|value| value.organization.as_deref())),
    ) || !subject_values_match(
        subject
            .iter_organizational_unit()
            .map(x509_parser::x509::AttributeTypeAndValue::as_str)
            .collect(),
        input
            .organizational_unit
            .as_deref()
            .or_else(|| defaults.and_then(|value| value.organizational_unit.as_deref())),
    ) || !subject_values_match(
        subject
            .iter_country()
            .map(x509_parser::x509::AttributeTypeAndValue::as_str)
            .collect(),
        input
            .country
            .as_deref()
            .or_else(|| defaults.and_then(|value| value.country.as_deref())),
    ) || !subject_values_match(
        subject
            .iter_state_or_province()
            .map(x509_parser::x509::AttributeTypeAndValue::as_str)
            .collect(),
        input
            .state
            .as_deref()
            .or_else(|| defaults.and_then(|value| value.state.as_deref())),
    ) || !subject_values_match(
        subject
            .iter_locality()
            .map(x509_parser::x509::AttributeTypeAndValue::as_str)
            .collect(),
        input
            .locality
            .as_deref()
            .or_else(|| defaults.and_then(|value| value.locality.as_deref())),
    ) {
        return false;
    }
    certificate_sans_match(certificate, input.alternative_names.as_deref())
}

fn subject_values_match<E>(actual: Result<Vec<&str>, E>, expected: Option<&str>) -> bool {
    actual.is_ok_and(|actual| actual.as_slice() == expected.as_slice())
}

fn certificate_sans_match(
    certificate: &X509Certificate<'_>,
    expected: Option<&[CertificateIssuanceSan]>,
) -> bool {
    let expected = expected
        .unwrap_or_default()
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    certificate_sans(certificate).is_some_and(|actual| actual == expected)
}

fn certificate_sans(certificate: &X509Certificate<'_>) -> Option<HashSet<CertificateIssuanceSan>> {
    certificate.subject_alternative_name().ok()?.map_or_else(
        || Some(HashSet::new()),
        |extension| sans(&extension.value.general_names),
    )
}

fn sans(names: &[GeneralName<'_>]) -> Option<HashSet<CertificateIssuanceSan>> {
    let mut values = HashSet::new();
    for name in names {
        let entry = match name {
            GeneralName::DNSName(value) => CertificateIssuanceSan {
                san_type: CertificatePolicySanType::DnsName,
                value: value.to_ascii_lowercase(),
            },
            GeneralName::IPAddress(bytes) => {
                let value = match bytes.len() {
                    4 => IpAddr::from(<[u8; 4]>::try_from(*bytes).ok()?).to_string(),
                    16 => IpAddr::from(<[u8; 16]>::try_from(*bytes).ok()?).to_string(),
                    _ => return None,
                };
                CertificateIssuanceSan {
                    san_type: CertificatePolicySanType::IpAddress,
                    value,
                }
            }
            GeneralName::RFC822Name(value) => CertificateIssuanceSan {
                san_type: CertificatePolicySanType::Email,
                value: (*value).to_owned(),
            },
            GeneralName::URI(value) => CertificateIssuanceSan {
                san_type: CertificatePolicySanType::Uri,
                value: (*value).to_owned(),
            },
            _ => return None,
        };
        if !values.insert(entry) {
            return None;
        }
    }
    Some(values)
}

fn csr_sans(request: &X509CertificationRequest<'_>) -> Option<HashSet<CertificateIssuanceSan>> {
    let mut extension_request_seen = false;
    let mut requested_sans = None;
    for attribute in request.certification_request_info.attributes() {
        let ParsedCriAttribute::ExtensionRequest(requested) = attribute.parsed_attribute() else {
            continue;
        };
        if extension_request_seen {
            return None;
        }
        extension_request_seen = true;
        for extension in &requested.extensions {
            if extension.oid != OID_X509_EXT_SUBJECT_ALT_NAME {
                continue;
            }
            if requested_sans.is_some() {
                return None;
            }
            let ParsedExtension::SubjectAlternativeName(subject_alternative_name) =
                extension.parsed_extension()
            else {
                return None;
            };
            requested_sans = Some(sans(&subject_alternative_name.general_names)?);
        }
    }
    Some(requested_sans.unwrap_or_default())
}

fn csr_matches_certificate(csr: &str, certificate: &X509Certificate<'_>) -> bool {
    let Ok((_, der)) = pem_rfc7468::decode_vec(csr.as_bytes()) else {
        return false;
    };
    let Ok((remainder, request)) = X509CertificationRequest::from_der(&der) else {
        return false;
    };
    let Some(requested_sans) = csr_sans(&request) else {
        return false;
    };
    remainder.is_empty()
        && request.certification_request_info.subject.to_string()
            == certificate.subject().to_string()
        && request.certification_request_info.subject_pki.raw == certificate.public_key().raw
        && certificate_sans(certificate).is_some_and(|actual| actual == requested_sans)
}

fn validate_unique_values<T: Eq + std::hash::Hash>(
    values: Option<&[T]>,
) -> Result<(), CertificateIssuanceInputError> {
    if values.is_some_and(|values| {
        values.is_empty()
            || values.len() > MAX_SAN_VALUES
            || values.iter().collect::<HashSet<_>>().len() != values.len()
    }) {
        return Err(CertificateIssuanceInputError::InvalidUsages);
    }
    Ok(())
}

fn normalize_dns_name(value: &str) -> Option<String> {
    let value = value.to_ascii_lowercase();
    let name = value.strip_prefix("*.").unwrap_or(&value);
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    name.split('.').all(valid_dns_label).then_some(value)
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.as_bytes().windows(2).any(|pair| pair == b"..")
        && domain.contains('.')
        && domain.split('.').all(valid_dns_label)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };
    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::{
        CertificateIssuance, CertificateIssuanceAttributes, CertificateIssuanceBasicConstraints,
        CertificateIssuanceInputError, CertificateIssuanceMetadata, CertificateIssuanceMethod,
        CertificateIssuanceOutcome, CertificateIssuanceSan, CertificateIssuanceValidity,
        csr_matches_certificate, issuing_certificate_matches_leaf,
    };
    use crate::{
        CertificateAuthorityProjectId, CertificatePolicySanType, CertificateProfileId,
        InfisicalClient, ResourceError,
        certificate::certificate_bundle_der,
        test_support::{mount_login, settings},
    };

    const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const PROFILE_ID: &str = "22222222-2222-4222-8222-222222222222";
    const POLICY_ID: &str = "33333333-3333-4333-8333-333333333333";
    const CONFIG_ID: &str = "44444444-4444-4444-8444-444444444444";
    const CA_ID: &str = "55555555-5555-4555-8555-555555555555";
    const REQUEST_ID: &str = "66666666-6666-4666-8666-666666666666";
    const CERTIFICATE_ID: &str = "77777777-7777-4777-8777-777777777777";

    fn project_id() -> CertificateAuthorityProjectId {
        CertificateAuthorityProjectId::new(PROJECT_ID).unwrap()
    }

    fn profile_id() -> CertificateProfileId {
        CertificateProfileId::new(PROFILE_ID).unwrap()
    }

    fn certificate_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-cert.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn issuer_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-issuer-cert.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn private_key_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-private-key.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn csr_fixture() -> &'static str {
        include_str!("../test-fixtures/ca-csr.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn san_csr_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-san-csr.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn san_certificate_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-san-cert.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn profile_value(enrollment_type: &str) -> serde_json::Value {
        let mut value = json!({
            "id": PROFILE_ID,
            "projectId": PROJECT_ID,
            "caId": CA_ID,
            "certificatePolicyId": POLICY_ID,
            "slug": "api-profile",
            "description": null,
            "enrollmentType": enrollment_type,
            "issuerType": "ca",
            "apiConfigId": null,
            "estConfigId": null,
            "acmeConfigId": null,
            "scepConfigId": null,
            "externalConfigs": null,
            "defaults": null,
            "createdAt": "2026-07-21T12:00:00.000Z",
            "updatedAt": "2026-07-21T12:00:01.000Z"
        });
        if enrollment_type == "api" {
            value["apiConfigId"] = json!(CONFIG_ID);
            value["apiConfig"] = json!({
                "id": CONFIG_ID,
                "autoRenew": false,
                "renewBeforeDays": null
            });
        } else {
            value["estConfigId"] = json!(CONFIG_ID);
            value["estConfig"] = json!({
                "id": CONFIG_ID,
                "disableBootstrapCaValidation": false,
                "passphrase": "discarded-secret"
            });
        }
        value
    }

    async fn mount_profile(server: &MockServer, enrollment_type: &str) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{PROFILE_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateProfile": profile_value(enrollment_type)
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    fn managed_issuance() -> CertificateIssuance {
        let attributes = CertificateIssuanceAttributes::new(
            Some("certificate-profile.example".into()),
            None,
            None,
            None,
            None,
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
        CertificateIssuance::new(
            profile_id(),
            None,
            CertificateIssuanceMethod::Managed(attributes),
            false,
            Some(vec![
                CertificateIssuanceMetadata::new("service", "frontend").unwrap(),
            ]),
        )
        .unwrap()
    }

    #[test]
    fn issuance_inputs_reject_invalid_sans_csrs_and_duplicate_metadata() {
        assert_eq!(
            CertificateIssuanceSan::new(CertificatePolicySanType::DnsName, "bad label.example")
                .unwrap_err(),
            CertificateIssuanceInputError::InvalidSans
        );
        assert_eq!(
            CertificateIssuanceMethod::csr("not a csr", None, None).unwrap_err(),
            CertificateIssuanceInputError::InvalidCsr
        );
        let metadata = CertificateIssuanceMetadata::new("owner", "platform").unwrap();
        assert_eq!(
            CertificateIssuance::new(
                profile_id(),
                None,
                CertificateIssuanceMethod::Managed(
                    CertificateIssuanceAttributes::new(
                        None, None, None, None, None, None, None, None, None, None, None, None,
                        None
                    )
                    .unwrap()
                ),
                false,
                Some(vec![metadata.clone(), metadata]),
            )
            .unwrap_err(),
            CertificateIssuanceInputError::InvalidMetadata
        );
    }

    #[test]
    fn issuance_aggregate_revalidates_publicly_constructible_nested_values() {
        assert_eq!(
            CertificateIssuanceAttributes::new(
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(vec![CertificateIssuanceSan {
                    san_type: CertificatePolicySanType::DnsName,
                    value: "bad label.example".into(),
                }]),
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            CertificateIssuanceInputError::InvalidSans
        );

        assert_eq!(
            CertificateIssuance::new(
                profile_id(),
                None,
                CertificateIssuanceMethod::Csr {
                    csr: csr_fixture().into(),
                    validity: Some(CertificateIssuanceValidity::Window {
                        not_before: "2026-07-22T00:00:00.000Z".into(),
                        not_after: "2026-07-21T00:00:00.000Z".into(),
                    }),
                    basic_constraints: None,
                },
                false,
                None,
            )
            .unwrap_err(),
            CertificateIssuanceInputError::InvalidValidity
        );

        assert_eq!(
            CertificateIssuance::new(
                profile_id(),
                None,
                CertificateIssuanceMethod::Csr {
                    csr: csr_fixture().into(),
                    validity: None,
                    basic_constraints: Some(CertificateIssuanceBasicConstraints {
                        is_ca: false,
                        path_length: Some(0),
                    }),
                },
                false,
                None,
            )
            .unwrap_err(),
            CertificateIssuanceInputError::InvalidBasicConstraints
        );

        assert_eq!(
            CertificateIssuance::new(
                profile_id(),
                None,
                CertificateIssuanceMethod::Csr {
                    csr: "not a csr".into(),
                    validity: None,
                    basic_constraints: None,
                },
                false,
                None,
            )
            .unwrap_err(),
            CertificateIssuanceInputError::InvalidCsr
        );

        assert_eq!(
            CertificateIssuance::new(
                profile_id(),
                None,
                CertificateIssuanceMethod::Managed(
                    CertificateIssuanceAttributes::new(
                        None, None, None, None, None, None, None, None, None, None, None, None,
                        None,
                    )
                    .unwrap(),
                ),
                false,
                Some(vec![CertificateIssuanceMetadata {
                    key: " owner".into(),
                    value: "platform".into(),
                }]),
            )
            .unwrap_err(),
            CertificateIssuanceInputError::InvalidMetadata
        );
    }

    #[test]
    fn csr_identity_matching_includes_requested_subject_alternative_names() {
        let san_der = certificate_bundle_der(san_certificate_fixture()).unwrap();
        let (_, san_certificate) = X509Certificate::from_der(&san_der[0]).unwrap();
        assert!(csr_matches_certificate(san_csr_fixture(), &san_certificate));

        let certificate_der = certificate_bundle_der(certificate_fixture()).unwrap();
        let (_, certificate_without_sans) = X509Certificate::from_der(&certificate_der[0]).unwrap();
        assert!(!csr_matches_certificate(
            san_csr_fixture(),
            &certificate_without_sans
        ));
    }

    #[test]
    fn empty_self_issued_material_requires_a_valid_self_signature() {
        let valid_der = certificate_bundle_der(issuer_fixture()).unwrap();
        let (_, valid) = X509Certificate::from_der(&valid_der[0]).unwrap();
        assert!(issuing_certificate_matches_leaf(&valid, "", ""));

        let mut invalid_der = valid_der[0].clone();
        let final_byte = invalid_der.last_mut().unwrap();
        *final_byte ^= 1;
        let (_, invalid) = X509Certificate::from_der(&invalid_der).unwrap();
        assert_eq!(invalid.issuer(), invalid.subject());
        assert!(!issuing_certificate_matches_leaf(&invalid, "", ""));
    }

    #[tokio::test]
    async fn confirmation_and_api_profile_preflight_happen_before_issuance() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert_eq!(
            client
                .issue_certificate(&project_id(), &managed_issuance(), false)
                .await
                .unwrap_err(),
            ResourceError::CertificateIssuanceNotConfirmed
        );
        assert!(server.received_requests().await.unwrap().is_empty());

        mount_login(&server, "issuance-profile-token").await;
        mount_profile(&server, "est").await;
        assert_eq!(
            client
                .issue_certificate(&project_id(), &managed_issuance(), true)
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateIssuanceProfile
        );
    }

    #[tokio::test]
    async fn managed_issuance_uses_the_canonical_route_and_validates_the_key_pair() {
        let server = MockServer::start().await;
        mount_login(&server, "managed-issuance-token").await;
        mount_profile(&server, "api").await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificates"))
            .and(body_json(json!({
                "profileId": PROFILE_ID,
                "attributes": { "commonName": "certificate-profile.example" },
                "removeRootsFromChain": false,
                "metadata": [{ "key": "service", "value": "frontend" }]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": {
                    "certificate": certificate_fixture(),
                    "issuingCaCertificate": issuer_fixture(),
                    "certificateChain": issuer_fixture(),
                    "privateKey": private_key_fixture(),
                    "serialNumber": "A1B2",
                    "certificateId": CERTIFICATE_ID
                },
                "certificateRequestId": REQUEST_ID,
                "status": "issued"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let outcome = client
            .issue_certificate(&project_id(), &managed_issuance(), true)
            .await
            .unwrap();
        let CertificateIssuanceOutcome::Issued(certificate) = outcome else {
            panic!("expected immediate issuance")
        };
        assert_eq!(certificate.request_id, REQUEST_ID);
        assert_eq!(certificate.certificate_id, CERTIFICATE_ID);
        assert_eq!(certificate.serial_number, "A1B2");
        assert!(certificate.private_key.is_some());
        assert!(!format!("{certificate:?}").contains(private_key_fixture()));
    }

    #[tokio::test]
    async fn managed_issuance_accepts_an_omitted_status_and_a_root_stripped_empty_chain() {
        let server = MockServer::start().await;
        mount_login(&server, "root-stripped-issuance-token").await;
        mount_profile(&server, "api").await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificates"))
            .and(body_json(json!({
                "profileId": PROFILE_ID,
                "attributes": { "commonName": "certificate-profile.example" },
                "removeRootsFromChain": true,
                "metadata": [{ "key": "service", "value": "frontend" }]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": {
                    "certificate": certificate_fixture(),
                    "issuingCaCertificate": issuer_fixture(),
                    "certificateChain": "",
                    "privateKey": private_key_fixture(),
                    "serialNumber": "A1B2",
                    "certificateId": CERTIFICATE_ID
                },
                "certificateRequestId": REQUEST_ID
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut issuance = managed_issuance();
        issuance.remove_roots_from_chain = true;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let CertificateIssuanceOutcome::Issued(certificate) = client
            .issue_certificate(&project_id(), &issuance, true)
            .await
            .unwrap()
        else {
            panic!("expected immediate issuance")
        };
        assert_eq!(certificate.request_id, REQUEST_ID);
        assert!(certificate.certificate_chain.is_empty());
    }

    #[tokio::test]
    async fn semantic_failure_after_issuance_preserves_the_request_for_reconciliation() {
        let server = MockServer::start().await;
        mount_login(&server, "unverified-issuance-token").await;
        mount_profile(&server, "api").await;
        let oversized_chain = format!("{}\n", issuer_fixture()).repeat(200);
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": {
                    "certificate": certificate_fixture(),
                    "issuingCaCertificate": issuer_fixture(),
                    "certificateChain": oversized_chain,
                    "privateKey": private_key_fixture(),
                    "serialNumber": "A1B2",
                    "certificateId": CERTIFICATE_ID
                },
                "certificateRequestId": REQUEST_ID,
                "status": "issued"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert_eq!(
            client
                .issue_certificate(&project_id(), &managed_issuance(), true)
                .await
                .unwrap_err(),
            ResourceError::CertificateIssuanceResponseUnverified {
                request_id: REQUEST_ID.to_owned()
            }
        );
    }

    #[tokio::test]
    async fn csr_issuance_returns_a_separate_pending_outcome_without_material() {
        let server = MockServer::start().await;
        mount_login(&server, "csr-issuance-token").await;
        mount_profile(&server, "api").await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificates"))
            .and(body_json(json!({
                "profileId": PROFILE_ID,
                "csr": csr_fixture(),
                "attributes": {},
                "removeRootsFromChain": true
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": null,
                "certificateRequestId": REQUEST_ID,
                "message": "untrusted upstream text is not returned"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let issuance = CertificateIssuance::new(
            profile_id(),
            None,
            CertificateIssuanceMethod::csr(csr_fixture(), None, None).unwrap(),
            true,
            None,
        )
        .unwrap();
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let CertificateIssuanceOutcome::Pending {
            request_id, status, ..
        } = client
            .issue_certificate(&project_id(), &issuance, true)
            .await
            .unwrap()
        else {
            panic!("expected pending issuance")
        };
        assert_eq!(request_id, REQUEST_ID);
        assert_eq!(status, None);
    }
}
