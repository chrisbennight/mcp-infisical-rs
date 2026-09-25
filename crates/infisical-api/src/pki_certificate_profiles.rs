use std::collections::HashSet;

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P521_SHA512_ASN1_SIGNING,
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING,
    PqdsaKeyPair, RsaKeyPair,
};
use fips205::traits::{SerDes, Signer};
use pkcs8::der::Decode;
use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;
use url::Url;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::time::ASN1Time;
use zeroize::Zeroizing;

use crate::{
    CertificateAuthorityId, CertificateAuthorityProjectId, CertificateAuthorityStatus,
    CertificateAuthorityType, CertificateKeyAlgorithm, InfisicalClient, MutationOperation,
    ObservableReadOperation, Page, PageRequest, ResourceError, SecretValue,
    certificate::{
        certificate_bundle_der, certificate_serial_matches, is_valid_ca_signing_certificate_bundle,
        normalize_pem, verify_certificate_signature_with_algorithm_fallback,
    },
    client::{ApiVersion, Endpoint, sealed},
    resources::{is_bounded_text, is_uuid, utc_timestamp_millis},
};

const MAX_PROFILE_SLUG_BYTES: usize = 255;
const MAX_PROFILE_DESCRIPTION_BYTES: usize = 1_000;
const MAX_PROFILE_TEXT_BYTES: usize = 256;
const MAX_PROFILE_SEARCH_BYTES: usize = 255;
const MAX_PROFILE_SECRET_BYTES: usize = 4_096;
const MAX_CERTIFICATE_PEM_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATE_CHAIN_PEM_BYTES: usize = 512 * 1024;
const MAX_SERIAL_NUMBER_BYTES: usize = 128;
const MAX_URL_BYTES: usize = 2_048;
const MAX_TTL_DAYS: u32 = 36_500;
const MAX_APPLICATION_PROFILE_RELATIONSHIPS: usize = 10_000;

macro_rules! slh_private_key_matches_public_key {
    ($module:ident, $expected:expr, $private_key:expr) => {{
        <&[u8; fips205::$module::SK_LEN]>::try_from($private_key).is_ok_and(|private_key| {
            fips205::$module::PrivateKey::try_from_bytes(private_key).is_ok_and(|private_key| {
                private_key.get_public_key().into_bytes().as_ref() == $expected
            })
        })
    }};
}

macro_rules! match_slh_private_key_parameter_set {
    ($key_oid:expr, $expected:expr, $private_key:expr, {$($oid:literal => $module:ident),+ $(,)?}) => {
        match $key_oid {
            $(
                $oid => slh_private_key_matches_public_key!(
                    $module,
                    $expected,
                    $private_key
                ),
            )+
            _ => false,
        }
    };
}

/// Input validation failures for the pinned certificate-profile contract.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CertificateProfileInputError {
    #[error("certificate-profile ID must be a UUID")]
    InvalidId,
    #[error("certificate-policy ID must be a UUID")]
    InvalidPolicyId,
    #[error("certificate-profile application ID must be a UUID")]
    InvalidApplicationId,
    #[error(
        "certificate-profile slug must contain 1 to 255 lowercase letters, numbers, or hyphens"
    )]
    InvalidSlug,
    #[error(
        "certificate-profile description must be trimmed, control-free, and at most 1000 bytes"
    )]
    InvalidDescription,
    #[error("certificate-profile text fields must be trimmed, control-free, and at most 256 bytes")]
    InvalidText,
    #[error("certificate-profile search must be trimmed, control-free, and at most 255 bytes")]
    InvalidSearch,
    #[error("certificate-profile TTL must be between 1 and 36500 days")]
    InvalidTtl,
    #[error("certificate-profile basic-constraints path length must be between 0 and 100")]
    InvalidPathLength,
    #[error("certificate-profile key usages must be unique")]
    DuplicateKeyUsage,
    #[error("certificate-profile extended key usages must be unique")]
    DuplicateExtendedKeyUsage,
    #[error("certificate-profile CA issuer requires one CA and self-signed issuer forbids it")]
    InvalidIssuer,
    #[error("self-signed certificate profiles only support API enrollment")]
    InvalidSelfSignedEnrollment,
    #[error("certificate-profile renewal days must be between 1 and 30 and require auto-renewal")]
    InvalidRenewal,
    #[error("EST passphrase must contain 1 to 4096 bytes")]
    InvalidEstPassphrase,
    #[error("EST CA chain must be a bounded PEM CA certificate bundle")]
    InvalidEstCaChain,
    #[error("ACME cannot skip both EAB binding and DNS ownership verification")]
    InvalidAcmeConfiguration,
    #[error("SCEP static challenges require an 8 to 4096 byte password")]
    InvalidScepPassword,
    #[error("SCEP dynamic-challenge limits are outside the pinned bounds")]
    InvalidScepLimits,
    #[error("Azure AD CS template must contain 1 to 256 bounded text bytes")]
    InvalidExternalTemplate,
    #[error("Azure AD CS templates require an Azure AD CS-backed CA issuer")]
    InvalidExternalProvider,
    #[error("certificate-profile update must change at least one field")]
    EmptyChange,
}

macro_rules! uuid_id {
    ($name:ident, $error:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validate a UUID before it reaches a profile route.
            ///
            /// # Errors
            ///
            /// Returns an error when the value is not a UUID.
            pub fn new(value: impl Into<String>) -> Result<Self, CertificateProfileInputError> {
                let value = value.into();
                if !is_uuid(&value) {
                    return Err($error);
                }
                Ok(Self(value.to_ascii_lowercase()))
            }

            /// Borrow the canonical identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

uuid_id!(
    CertificateProfileId,
    CertificateProfileInputError::InvalidId
);
uuid_id!(
    CertificatePolicyId,
    CertificateProfileInputError::InvalidPolicyId
);
uuid_id!(
    CertificateProfileApplicationId,
    CertificateProfileInputError::InvalidApplicationId
);

/// Validated project-local certificate-profile slug.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct CertificateProfileSlug(String);

impl CertificateProfileSlug {
    /// Validate the exact public route slug grammar.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, or non-canonical values.
    pub fn new(value: impl Into<String>) -> Result<Self, CertificateProfileInputError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PROFILE_SLUG_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(CertificateProfileInputError::InvalidSlug);
        }
        Ok(Self(value))
    }

    /// Borrow the validated slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Certificate enrollment protocol selected by one profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CertificateProfileEnrollmentType {
    Api,
    Est,
    Acme,
    Scep,
}

/// Certificate issuer category selected by one profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CertificateProfileIssuerType {
    #[serde(rename = "ca")]
    CertificateAuthority,
    #[serde(rename = "self-signed")]
    SelfSigned,
}

/// Validated issuer selection for profile creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateProfileIssuer {
    CertificateAuthority(CertificateAuthorityId),
    SelfSigned,
}

/// Key usages supported by certificate-profile defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertificateKeyUsage {
    DigitalSignature,
    KeyEncipherment,
    NonRepudiation,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

/// Extended key usages supported by certificate-profile defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertificateExtendedKeyUsage {
    ClientAuth,
    ServerAuth,
    CodeSigning,
    EmailProtection,
    OcspSigning,
    TimeStamping,
}

/// Signature algorithms accepted by the pinned certificate-profile API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CertificateSignatureAlgorithm {
    #[serde(rename = "RSA-SHA256")]
    RsaSha256,
    #[serde(rename = "RSA-SHA384")]
    RsaSha384,
    #[serde(rename = "RSA-SHA512")]
    RsaSha512,
    #[serde(rename = "ECDSA-SHA256")]
    EcdsaSha256,
    #[serde(rename = "ECDSA-SHA384")]
    EcdsaSha384,
    #[serde(rename = "ECDSA-SHA512")]
    EcdsaSha512,
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

/// Optional profile defaults applied to certificate requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProfileDefaults {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<CertificateKeyAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<CertificateSignatureAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_usages: Option<Vec<CertificateKeyUsage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_key_usages: Option<Vec<CertificateExtendedKeyUsage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_constraints: Option<CertificateProfileBasicConstraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organizational_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
}

/// Basic constraints used by profile defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProfileBasicConstraints {
    #[serde(rename = "isCA")]
    pub is_ca: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_length: Option<u8>,
}

impl CertificateProfileDefaults {
    /// Validate bounded default fields and unique usage collections.
    ///
    /// # Errors
    ///
    /// Returns an error when any default violates the pinned request schema.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ttl_days: Option<u32>,
        common_name: Option<String>,
        key_algorithm: Option<CertificateKeyAlgorithm>,
        signature_algorithm: Option<CertificateSignatureAlgorithm>,
        key_usages: Option<Vec<CertificateKeyUsage>>,
        extended_key_usages: Option<Vec<CertificateExtendedKeyUsage>>,
        basic_constraints: Option<(bool, Option<u8>)>,
        organization: Option<String>,
        organizational_unit: Option<String>,
        country: Option<String>,
        state: Option<String>,
        locality: Option<String>,
    ) -> Result<Self, CertificateProfileInputError> {
        if ttl_days.is_some_and(|days| days == 0 || days > MAX_TTL_DAYS) {
            return Err(CertificateProfileInputError::InvalidTtl);
        }
        for value in [
            common_name.as_deref(),
            organization.as_deref(),
            organizational_unit.as_deref(),
            country.as_deref(),
            state.as_deref(),
            locality.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_profile_text(value)?;
        }
        if key_usages.as_ref().is_some_and(|values| {
            values.iter().copied().collect::<HashSet<_>>().len() != values.len()
        }) {
            return Err(CertificateProfileInputError::DuplicateKeyUsage);
        }
        if extended_key_usages.as_ref().is_some_and(|values| {
            values.iter().copied().collect::<HashSet<_>>().len() != values.len()
        }) {
            return Err(CertificateProfileInputError::DuplicateExtendedKeyUsage);
        }
        let basic_constraints = basic_constraints
            .map(|(is_ca, path_length)| {
                if path_length.is_some_and(|length| length > 100) {
                    return Err(CertificateProfileInputError::InvalidPathLength);
                }
                Ok(CertificateProfileBasicConstraints { is_ca, path_length })
            })
            .transpose()?;
        Ok(Self {
            ttl_days,
            common_name,
            key_algorithm,
            signature_algorithm,
            key_usages,
            extended_key_usages,
            basic_constraints,
            organization,
            organizational_unit,
            country,
            state,
            locality,
        })
    }

    fn validate(self) -> Result<Self, CertificateProfileInputError> {
        Self::new(
            self.ttl_days,
            self.common_name,
            self.key_algorithm,
            self.signature_algorithm,
            self.key_usages,
            self.extended_key_usages,
            self.basic_constraints
                .map(|value| (value.is_ca, value.path_length)),
            self.organization,
            self.organizational_unit,
            self.country,
            self.state,
            self.locality,
        )
    }
}

/// Provider-specific public profile configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateProfileExternalConfig {
    pub template: Option<String>,
}

impl CertificateProfileExternalConfig {
    /// Validate an empty provider configuration or one Azure AD CS template.
    ///
    /// # Errors
    ///
    /// Returns an error when the template is empty or unbounded.
    pub fn new(template: Option<String>) -> Result<Self, CertificateProfileInputError> {
        if let Some(value) = template.as_deref() {
            validate_profile_text(value)
                .map_err(|_| CertificateProfileInputError::InvalidExternalTemplate)?;
        }
        Ok(Self { template })
    }

    fn has_azure_template(&self) -> bool {
        self.template.is_some()
    }
}

fn azure_template_matches_provider(
    template_present: bool,
    ca_type: Option<CertificateAuthorityType>,
) -> bool {
    !template_present || ca_type == Some(CertificateAuthorityType::AzureAdCs)
}

/// SCEP challenge mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CertificateProfileScepChallengeType {
    Static,
    Dynamic,
}

/// Complete enrollment configuration for profile creation.
#[derive(Debug)]
pub enum CertificateProfileEnrollmentConfiguration {
    Api {
        auto_renew: bool,
        renew_before_days: Option<u8>,
    },
    Est {
        disable_bootstrap_ca_validation: bool,
        passphrase: SecretValue,
        ca_chain: Option<String>,
    },
    Acme {
        skip_dns_ownership_verification: bool,
        skip_eab_binding: bool,
    },
    Scep {
        challenge_type: CertificateProfileScepChallengeType,
        challenge_password: Option<SecretValue>,
        include_ca_cert_in_response: bool,
        allow_cert_based_renewal: bool,
        dynamic_challenge_expiry_minutes: u16,
        dynamic_challenge_max_pending: u16,
    },
}

impl CertificateProfileEnrollmentConfiguration {
    fn enrollment_type(&self) -> CertificateProfileEnrollmentType {
        match self {
            Self::Api { .. } => CertificateProfileEnrollmentType::Api,
            Self::Est { .. } => CertificateProfileEnrollmentType::Est,
            Self::Acme { .. } => CertificateProfileEnrollmentType::Acme,
            Self::Scep { .. } => CertificateProfileEnrollmentType::Scep,
        }
    }

    fn validate(&self) -> Result<(), CertificateProfileInputError> {
        match self {
            Self::Api {
                auto_renew,
                renew_before_days,
            } => validate_renewal(*auto_renew, *renew_before_days),
            Self::Est {
                passphrase,
                ca_chain,
                ..
            } => {
                validate_secret(
                    passphrase,
                    1,
                    CertificateProfileInputError::InvalidEstPassphrase,
                )?;
                if ca_chain
                    .as_deref()
                    .is_some_and(|chain| normalized_est_ca_chain(chain).is_none())
                {
                    return Err(CertificateProfileInputError::InvalidEstCaChain);
                }
                Ok(())
            }
            Self::Acme {
                skip_dns_ownership_verification,
                skip_eab_binding,
            } => validate_acme(*skip_dns_ownership_verification, *skip_eab_binding),
            Self::Scep {
                challenge_type,
                challenge_password,
                dynamic_challenge_expiry_minutes,
                dynamic_challenge_max_pending,
                ..
            } => validate_scep(
                *challenge_type,
                challenge_password.as_ref(),
                *dynamic_challenge_expiry_minutes,
                *dynamic_challenge_max_pending,
            ),
        }
    }
}

/// ACME flags changed as one coherent pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateProfileAcmeChange {
    pub skip_dns_ownership_verification: Option<bool>,
    pub skip_eab_binding: Option<bool>,
}

/// Same-family enrollment configuration update.
#[derive(Debug)]
pub enum CertificateProfileEnrollmentChange {
    Api {
        auto_renew: bool,
        renew_before_days: Option<u8>,
    },
    Est {
        disable_bootstrap_ca_validation: bool,
        passphrase: Option<SecretValue>,
        ca_chain: Option<String>,
    },
    Acme(CertificateProfileAcmeChange),
    Scep {
        challenge_type: Option<CertificateProfileScepChallengeType>,
        challenge_password: Option<SecretValue>,
        include_ca_cert_in_response: Option<bool>,
        allow_cert_based_renewal: Option<bool>,
        dynamic_challenge_expiry_minutes: Option<u16>,
        dynamic_challenge_max_pending: Option<u16>,
    },
}

impl CertificateProfileEnrollmentChange {
    fn enrollment_type(&self) -> CertificateProfileEnrollmentType {
        match self {
            Self::Api { .. } => CertificateProfileEnrollmentType::Api,
            Self::Est { .. } => CertificateProfileEnrollmentType::Est,
            Self::Acme(_) => CertificateProfileEnrollmentType::Acme,
            Self::Scep { .. } => CertificateProfileEnrollmentType::Scep,
        }
    }

    fn validate(&self) -> Result<(), CertificateProfileInputError> {
        match self {
            Self::Api {
                auto_renew,
                renew_before_days,
            } => validate_renewal(*auto_renew, *renew_before_days),
            Self::Est {
                passphrase,
                ca_chain,
                ..
            } => {
                if let Some(passphrase) = passphrase.as_ref() {
                    validate_secret(
                        passphrase,
                        1,
                        CertificateProfileInputError::InvalidEstPassphrase,
                    )?;
                }
                if ca_chain
                    .as_deref()
                    .is_some_and(|chain| normalized_est_ca_chain(chain).is_none())
                {
                    return Err(CertificateProfileInputError::InvalidEstCaChain);
                }
                Ok(())
            }
            Self::Acme(change)
                if change.skip_dns_ownership_verification.is_none()
                    && change.skip_eab_binding.is_none() =>
            {
                Err(CertificateProfileInputError::EmptyChange)
            }
            Self::Acme(_) => Ok(()),
            Self::Scep {
                challenge_type,
                challenge_password,
                include_ca_cert_in_response,
                allow_cert_based_renewal,
                dynamic_challenge_expiry_minutes,
                dynamic_challenge_max_pending,
            } => {
                if challenge_type.is_none()
                    && challenge_password.is_none()
                    && include_ca_cert_in_response.is_none()
                    && allow_cert_based_renewal.is_none()
                    && dynamic_challenge_expiry_minutes.is_none()
                    && dynamic_challenge_max_pending.is_none()
                {
                    return Err(CertificateProfileInputError::EmptyChange);
                }
                if challenge_password.as_ref().is_some_and(|password| {
                    password.expose_secret().len() < 8
                        || password.expose_secret().len() > MAX_PROFILE_SECRET_BYTES
                }) {
                    return Err(CertificateProfileInputError::InvalidScepPassword);
                }
                if dynamic_challenge_expiry_minutes
                    .is_some_and(|value| !(1..=1_440).contains(&value))
                    || dynamic_challenge_max_pending
                        .is_some_and(|value| !(1..=1_000).contains(&value))
                {
                    return Err(CertificateProfileInputError::InvalidScepLimits);
                }
                if *challenge_type == Some(CertificateProfileScepChallengeType::Dynamic)
                    && challenge_password.is_some()
                {
                    return Err(CertificateProfileInputError::InvalidScepPassword);
                }
                Ok(())
            }
        }
    }
}

/// Description update that distinguishes replacement from clearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateProfileDescriptionChange {
    Set(String),
    Clear,
}

/// External provider configuration update that distinguishes replacement from clearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateProfileExternalConfigChange {
    Set(CertificateProfileExternalConfig),
    Clear,
}

/// Profile-default update that distinguishes replacement from clearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateProfileDefaultsChange {
    Set(Box<CertificateProfileDefaults>),
    Clear,
}

/// Validated profile creation request.
#[derive(Debug)]
pub struct CertificateProfileCreation {
    certificate_policy_id: CertificatePolicyId,
    slug: CertificateProfileSlug,
    description: Option<String>,
    issuer: CertificateProfileIssuer,
    enrollment: CertificateProfileEnrollmentConfiguration,
    external_configs: Option<CertificateProfileExternalConfig>,
    defaults: Option<CertificateProfileDefaults>,
}

impl CertificateProfileCreation {
    /// Validate a complete profile creation before authentication.
    ///
    /// # Errors
    ///
    /// Returns an error when profile fields or issuer/enrollment constraints are invalid.
    pub fn new(
        certificate_policy_id: CertificatePolicyId,
        slug: CertificateProfileSlug,
        description: Option<String>,
        issuer: CertificateProfileIssuer,
        enrollment: CertificateProfileEnrollmentConfiguration,
        external_configs: Option<CertificateProfileExternalConfig>,
        defaults: Option<CertificateProfileDefaults>,
    ) -> Result<Self, CertificateProfileInputError> {
        validate_description(description.as_deref())?;
        enrollment.validate()?;
        if matches!(issuer, CertificateProfileIssuer::SelfSigned)
            && enrollment.enrollment_type() != CertificateProfileEnrollmentType::Api
        {
            return Err(CertificateProfileInputError::InvalidSelfSignedEnrollment);
        }
        let external_configs = external_configs
            .map(|value| CertificateProfileExternalConfig::new(value.template))
            .transpose()?;
        if matches!(issuer, CertificateProfileIssuer::SelfSigned)
            && external_configs
                .as_ref()
                .is_some_and(CertificateProfileExternalConfig::has_azure_template)
        {
            return Err(CertificateProfileInputError::InvalidExternalProvider);
        }
        let defaults = defaults
            .map(CertificateProfileDefaults::validate)
            .transpose()?;
        Ok(Self {
            certificate_policy_id,
            slug,
            description,
            issuer,
            enrollment,
            external_configs,
            defaults,
        })
    }
}

/// Validated non-empty profile update.
#[derive(Debug)]
pub struct CertificateProfileChange {
    slug: Option<CertificateProfileSlug>,
    description: Option<CertificateProfileDescriptionChange>,
    enrollment: Option<CertificateProfileEnrollmentChange>,
    external_configs: Option<CertificateProfileExternalConfigChange>,
    defaults: Option<CertificateProfileDefaultsChange>,
}

impl CertificateProfileChange {
    /// Validate a non-empty, same-family profile update.
    ///
    /// # Errors
    ///
    /// Returns an error when no field changes or any supplied value is invalid.
    pub fn new(
        slug: Option<CertificateProfileSlug>,
        description: Option<CertificateProfileDescriptionChange>,
        enrollment: Option<CertificateProfileEnrollmentChange>,
        external_configs: Option<CertificateProfileExternalConfigChange>,
        defaults: Option<CertificateProfileDefaultsChange>,
    ) -> Result<Self, CertificateProfileInputError> {
        if slug.is_none()
            && description.is_none()
            && enrollment.is_none()
            && external_configs.is_none()
            && defaults.is_none()
        {
            return Err(CertificateProfileInputError::EmptyChange);
        }
        if let Some(CertificateProfileDescriptionChange::Set(value)) = description.as_ref() {
            validate_description(Some(value))?;
        }
        if let Some(enrollment) = enrollment.as_ref() {
            enrollment.validate()?;
        }
        let external_configs = external_configs
            .map(|change| match change {
                CertificateProfileExternalConfigChange::Set(value) => {
                    CertificateProfileExternalConfig::new(value.template)
                        .map(CertificateProfileExternalConfigChange::Set)
                }
                CertificateProfileExternalConfigChange::Clear => {
                    Ok(CertificateProfileExternalConfigChange::Clear)
                }
            })
            .transpose()?;
        let defaults = defaults
            .map(|change| match change {
                CertificateProfileDefaultsChange::Set(value) => (*value)
                    .validate()
                    .map(Box::new)
                    .map(CertificateProfileDefaultsChange::Set),
                CertificateProfileDefaultsChange::Clear => {
                    Ok(CertificateProfileDefaultsChange::Clear)
                }
            })
            .transpose()?;
        Ok(Self {
            slug,
            description,
            enrollment,
            external_configs,
            defaults,
        })
    }

    fn sets_azure_template(&self) -> bool {
        matches!(
            self.external_configs.as_ref(),
            Some(CertificateProfileExternalConfigChange::Set(value))
                if value.has_azure_template()
        )
    }
}

/// One profile list request with bounded pagination and filters.
///
/// Validated fields cannot be replaced after construction.
///
/// ```compile_fail
/// use infisical_api::CertificateProfileListRequest;
///
/// fn replace_search(mut request: CertificateProfileListRequest) {
///     request.search = Some(String::new());
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateProfileListRequest {
    project_id: CertificateAuthorityProjectId,
    page: PageRequest,
    search: Option<String>,
    enrollment_type: Option<CertificateProfileEnrollmentType>,
    issuer_type: Option<CertificateProfileIssuerType>,
    ca_id: Option<CertificateAuthorityId>,
    application_id: Option<CertificateProfileApplicationId>,
}

impl CertificateProfileListRequest {
    /// Validate bounded text filters for one list request.
    ///
    /// # Errors
    ///
    /// Returns an error for an unbounded or ambiguous search term.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: CertificateAuthorityProjectId,
        page: PageRequest,
        search: Option<String>,
        enrollment_type: Option<CertificateProfileEnrollmentType>,
        issuer_type: Option<CertificateProfileIssuerType>,
        ca_id: Option<CertificateAuthorityId>,
        application_id: Option<CertificateProfileApplicationId>,
    ) -> Result<Self, CertificateProfileInputError> {
        validate_search(search.as_deref())?;
        Ok(Self {
            project_id,
            page,
            search,
            enrollment_type,
            issuer_type,
            ca_id,
            application_id,
        })
    }
}

/// Certificate lifecycle state exposed by profile certificate listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CertificateProfileCertificateStatus {
    Active,
    Expired,
    Revoked,
}

/// One bounded profile-certificate list request.
///
/// Validated fields cannot be replaced after construction.
///
/// ```compile_fail
/// use infisical_api::CertificateProfileCertificateListRequest;
///
/// fn replace_search(mut request: CertificateProfileCertificateListRequest) {
///     request.search = Some(String::new());
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateProfileCertificateListRequest {
    project_id: CertificateAuthorityProjectId,
    profile_id: CertificateProfileId,
    page: PageRequest,
    status: Option<CertificateProfileCertificateStatus>,
    search: Option<String>,
}

impl CertificateProfileCertificateListRequest {
    /// Validate one profile-certificate query.
    ///
    /// # Errors
    ///
    /// Returns an error for an unbounded or ambiguous search term.
    pub fn new(
        project_id: CertificateAuthorityProjectId,
        profile_id: CertificateProfileId,
        page: PageRequest,
        status: Option<CertificateProfileCertificateStatus>,
        search: Option<String>,
    ) -> Result<Self, CertificateProfileInputError> {
        validate_search(search.as_deref())?;
        Ok(Self {
            project_id,
            profile_id,
            page,
            status,
            search,
        })
    }
}

/// Value-free certificate-authority reference attached to a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProfileAuthorityReference {
    pub id: String,
    pub status: CertificateAuthorityStatus,
    pub name: String,
    pub is_external: Option<bool>,
    pub external_type: Option<CertificateAuthorityType>,
}

/// Value-free certificate-policy reference attached to a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProfilePolicyReference {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub description: Option<String>,
}

/// Aggregate certificate counts returned by profile listing.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProfileMetrics {
    pub total_certificates: u64,
    pub active_certificates: u64,
    pub expired_certificates: u64,
    pub expiring_certificates: u64,
    pub revoked_certificates: u64,
}

/// Sanitized enrollment metadata; passphrases and encrypted fields are absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum CertificateProfileEnrollmentMetadata {
    Api {
        id: String,
        auto_renew: bool,
        renew_before_days: Option<u8>,
    },
    Est {
        id: String,
        disable_bootstrap_ca_validation: bool,
        ca_chain: Option<String>,
    },
    Acme {
        id: String,
        directory_url: String,
        skip_dns_ownership_verification: bool,
        skip_eab_binding: bool,
    },
    Scep {
        id: String,
        scep_endpoint_url: String,
        ra_certificate_pem: String,
        ra_cert_expires_at: String,
        include_ca_cert_in_response: bool,
        allow_cert_based_renewal: bool,
        challenge_type: CertificateProfileScepChallengeType,
        challenge_endpoint_url: Option<String>,
        dynamic_challenge_expiry_minutes: Option<u16>,
        dynamic_challenge_max_pending: Option<u16>,
    },
}

/// One bounded, sanitized certificate profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProfile {
    pub id: String,
    pub project_id: String,
    pub ca_id: Option<String>,
    pub certificate_policy_id: String,
    pub slug: String,
    pub description: Option<String>,
    pub enrollment_type: CertificateProfileEnrollmentType,
    pub issuer_type: CertificateProfileIssuerType,
    pub external_configs: Option<CertificateProfileExternalConfig>,
    pub defaults: Option<CertificateProfileDefaults>,
    pub created_at: String,
    pub updated_at: String,
    pub certificate_authority: Option<CertificateProfileAuthorityReference>,
    pub certificate_policy: Option<CertificateProfilePolicyReference>,
    pub metrics: Option<CertificateProfileMetrics>,
    pub enrollment: Option<CertificateProfileEnrollmentMetadata>,
}

/// One certificate issued through a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProfileCertificate {
    pub id: String,
    pub serial_number: String,
    pub common_name: String,
    pub status: CertificateProfileCertificateStatus,
    pub not_before: String,
    pub not_after: String,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

/// Explicit latest-active certificate bundle reveal.
#[derive(Debug)]
pub struct CertificateProfileBundle {
    pub profile_id: String,
    pub certificate: String,
    pub certificate_chain: String,
    pub private_key: SecretValue,
    pub serial_number: String,
}

/// Explicit ACME External Account Binding secret reveal.
#[derive(Debug)]
pub struct CertificateProfileEabSecret {
    pub profile_id: String,
    pub eab_kid: String,
    pub eab_secret: SecretValue,
}

fn validate_description(value: Option<&str>) -> Result<(), CertificateProfileInputError> {
    if value.is_some_and(|value| {
        value.len() > MAX_PROFILE_DESCRIPTION_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
    }) {
        return Err(CertificateProfileInputError::InvalidDescription);
    }
    Ok(())
}

fn validate_profile_text(value: &str) -> Result<(), CertificateProfileInputError> {
    if value.is_empty()
        || value.len() > MAX_PROFILE_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(CertificateProfileInputError::InvalidText);
    }
    Ok(())
}

fn validate_search(value: Option<&str>) -> Result<(), CertificateProfileInputError> {
    if value.is_some_and(|value| {
        value.is_empty()
            || value.len() > MAX_PROFILE_SEARCH_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
    }) {
        return Err(CertificateProfileInputError::InvalidSearch);
    }
    Ok(())
}

fn validate_secret(
    value: &SecretValue,
    minimum: usize,
    error: CertificateProfileInputError,
) -> Result<(), CertificateProfileInputError> {
    let length = value.expose_secret().len();
    if length < minimum || length > MAX_PROFILE_SECRET_BYTES {
        return Err(error);
    }
    Ok(())
}

fn validate_renewal(
    auto_renew: bool,
    renew_before_days: Option<u8>,
) -> Result<(), CertificateProfileInputError> {
    if renew_before_days.is_some_and(|days| !(1..=30).contains(&days))
        || (!auto_renew && renew_before_days.is_some())
    {
        return Err(CertificateProfileInputError::InvalidRenewal);
    }
    Ok(())
}

fn validate_acme(
    skip_dns_ownership_verification: bool,
    skip_eab_binding: bool,
) -> Result<(), CertificateProfileInputError> {
    if skip_dns_ownership_verification && skip_eab_binding {
        return Err(CertificateProfileInputError::InvalidAcmeConfiguration);
    }
    Ok(())
}

fn validate_scep(
    challenge_type: CertificateProfileScepChallengeType,
    challenge_password: Option<&SecretValue>,
    expiry: u16,
    maximum_pending: u16,
) -> Result<(), CertificateProfileInputError> {
    if !(1..=1_440).contains(&expiry) || !(1..=1_000).contains(&maximum_pending) {
        return Err(CertificateProfileInputError::InvalidScepLimits);
    }
    match challenge_type {
        CertificateProfileScepChallengeType::Static => {
            let Some(password) = challenge_password else {
                return Err(CertificateProfileInputError::InvalidScepPassword);
            };
            validate_secret(
                password,
                8,
                CertificateProfileInputError::InvalidScepPassword,
            )
        }
        CertificateProfileScepChallengeType::Dynamic if challenge_password.is_some() => {
            Err(CertificateProfileInputError::InvalidScepPassword)
        }
        CertificateProfileScepChallengeType::Dynamic => Ok(()),
    }
}

fn validate_scep_change_against_current(
    change: &CertificateProfileEnrollmentChange,
    current: Option<&CertificateProfileEnrollmentMetadata>,
) -> Result<(), ResourceError> {
    let CertificateProfileEnrollmentChange::Scep {
        challenge_type,
        challenge_password,
        ..
    } = change
    else {
        return Ok(());
    };
    let Some(CertificateProfileEnrollmentMetadata::Scep {
        challenge_type: current_challenge_type,
        ..
    }) = current
    else {
        return Err(ResourceError::InvalidCertificateProfileState);
    };
    if challenge_type.is_some_and(|value| value != *current_challenge_type)
        || (*current_challenge_type == CertificateProfileScepChallengeType::Dynamic
            && challenge_password.is_some())
    {
        return Err(ResourceError::InvalidCertificateProfileState);
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListProfilesQuery {
    project_id: String,
    offset: u32,
    limit: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    search: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enrollment_type: Option<CertificateProfileEnrollmentType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_type: Option<CertificateProfileIssuerType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    application_id: Option<String>,
}

#[derive(Serialize)]
struct ApplicationProfilesQuery {
    #[serde(skip_serializing)]
    application_id: CertificateProfileApplicationId,
}

#[derive(Serialize)]
struct ExactProfileQuery {
    #[serde(skip_serializing)]
    profile_id: CertificateProfileId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileBySlugQuery {
    #[serde(skip_serializing)]
    slug: CertificateProfileSlug,
    project_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileCertificatesQuery {
    #[serde(skip_serializing)]
    profile_id: CertificateProfileId,
    offset: u32,
    limit: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<CertificateProfileCertificateStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    search: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListProfilesResponse {
    certificate_profiles: Vec<ProfileWire>,
    total_count: u64,
}

#[derive(Deserialize)]
struct ApplicationProfilesResponse {
    profiles: Vec<ApplicationProfileWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationProfileWire {
    application_id: String,
    profile_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileResponse {
    certificate_profile: ProfileWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileWire {
    id: String,
    project_id: String,
    #[serde(default)]
    ca_id: Option<String>,
    certificate_policy_id: String,
    slug: String,
    #[serde(default)]
    description: Option<String>,
    enrollment_type: CertificateProfileEnrollmentType,
    #[serde(default)]
    est_config_id: Option<String>,
    #[serde(default)]
    api_config_id: Option<String>,
    created_at: String,
    updated_at: String,
    #[serde(default)]
    acme_config_id: Option<String>,
    issuer_type: CertificateProfileIssuerType,
    #[serde(default)]
    external_configs: Option<CertificateProfileExternalConfig>,
    #[serde(default)]
    defaults: Option<CertificateProfileDefaults>,
    #[serde(default)]
    scep_config_id: Option<String>,
    #[serde(default)]
    certificate_authority: Option<ProfileAuthorityWire>,
    #[serde(default)]
    certificate_policy: Option<ProfilePolicyWire>,
    #[serde(default)]
    metrics: Option<ProfileMetricsWire>,
    #[serde(default)]
    est_config: Option<EstConfigWire>,
    #[serde(default)]
    api_config: Option<ApiConfigWire>,
    #[serde(default)]
    acme_config: Option<AcmeConfigWire>,
    #[serde(default)]
    scep_config: Option<ScepConfigWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileAuthorityWire {
    id: String,
    status: CertificateAuthorityStatus,
    name: String,
    #[serde(default)]
    is_external: Option<bool>,
    #[serde(default)]
    external_type: Option<CertificateAuthorityType>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfilePolicyWire {
    id: String,
    project_id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileMetricsWire {
    profile_id: String,
    total_certificates: u64,
    active_certificates: u64,
    expired_certificates: u64,
    expiring_certificates: u64,
    revoked_certificates: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EstConfigWire {
    id: String,
    disable_bootstrap_ca_validation: bool,
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    passphrase: Option<SecretValue>,
    #[serde(default)]
    ca_chain: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiConfigWire {
    id: String,
    auto_renew: bool,
    #[serde(default)]
    renew_before_days: Option<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcmeConfigWire {
    id: String,
    directory_url: String,
    #[serde(default)]
    skip_dns_ownership_verification: bool,
    #[serde(default)]
    skip_eab_binding: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScepConfigWire {
    id: String,
    scep_endpoint_url: String,
    ra_certificate_pem: String,
    ra_cert_expires_at: String,
    include_ca_cert_in_response: bool,
    allow_cert_based_renewal: bool,
    challenge_type: CertificateProfileScepChallengeType,
    #[serde(default)]
    challenge_endpoint_url: Option<String>,
    #[serde(default)]
    dynamic_challenge_expiry_minutes: Option<u16>,
    #[serde(default)]
    dynamic_challenge_max_pending: Option<u16>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateProfileRequest {
    project_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_id: Option<String>,
    certificate_policy_id: String,
    slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    enrollment_type: CertificateProfileEnrollmentType,
    issuer_type: CertificateProfileIssuerType,
    #[serde(skip_serializing_if = "Option::is_none")]
    est_config: Option<EstCreateRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_config: Option<ApiConfigRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acme_config: Option<AcmeConfigRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scep_config: Option<ScepCreateRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_configs: Option<CertificateProfileExternalConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    defaults: Option<CertificateProfileDefaults>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EstCreateRequest {
    disable_bootstrap_ca_validation: bool,
    #[serde(serialize_with = "serialize_secret")]
    passphrase: SecretValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_chain: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiConfigRequest {
    auto_renew: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    renew_before_days: Option<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcmeConfigRequest {
    skip_dns_ownership_verification: bool,
    skip_eab_binding: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScepCreateRequest {
    challenge_type: CertificateProfileScepChallengeType,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_secret"
    )]
    challenge_password: Option<SecretValue>,
    include_ca_cert_in_response: bool,
    allow_cert_based_renewal: bool,
    dynamic_challenge_expiry_minutes: u16,
    dynamic_challenge_max_pending: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateProfileRequest {
    #[serde(skip_serializing)]
    profile_id: CertificateProfileId,
    #[serde(skip_serializing_if = "Option::is_none")]
    slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<NullableUpdate<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    est_config: Option<EstUpdateRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_config: Option<ApiConfigRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acme_config: Option<AcmeUpdateRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scep_config: Option<ScepUpdateRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_configs: Option<NullableUpdate<CertificateProfileExternalConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    defaults: Option<NullableUpdate<CertificateProfileDefaults>>,
}

enum NullableUpdate<T> {
    Value(T),
    Null,
}

impl<T> Serialize for NullableUpdate<T>
where
    T: Serialize,
{
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EstUpdateRequest {
    disable_bootstrap_ca_validation: bool,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_secret"
    )]
    passphrase: Option<SecretValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_chain: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcmeUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_dns_ownership_verification: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_eab_binding: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScepUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge_type: Option<CertificateProfileScepChallengeType>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_secret"
    )]
    challenge_password: Option<SecretValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    include_ca_cert_in_response: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_cert_based_renewal: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dynamic_challenge_expiry_minutes: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dynamic_challenge_max_pending: Option<u16>,
}

#[derive(Serialize)]
struct DeleteProfileRequest {
    #[serde(skip_serializing)]
    profile_id: CertificateProfileId,
}

#[derive(Deserialize)]
struct ProfileCertificatesResponse {
    certificates: Vec<ProfileCertificateWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileCertificateWire {
    id: String,
    serial_number: String,
    #[serde(rename = "cn")]
    common_name: String,
    status: CertificateProfileCertificateStatus,
    not_before: String,
    not_after: String,
    #[serde(default)]
    revoked_at: Option<String>,
    created_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleWire {
    #[serde(default)]
    certificate: Option<String>,
    #[serde(default)]
    certificate_chain: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    private_key: Option<SecretValue>,
    #[serde(default)]
    serial_number: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EabWire {
    eab_kid: String,
    #[serde(deserialize_with = "deserialize_secret")]
    eab_secret: SecretValue,
}

fn serialize_secret<S>(value: &SecretValue, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.expose_secret())
}

#[allow(clippy::ref_option)]
fn serialize_optional_secret<S>(
    value: &Option<SecretValue>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(value) => serializer.serialize_some(value.expose_secret()),
        None => serializer.serialize_none(),
    }
}

fn deserialize_secret<'de, D>(deserializer: D) -> Result<SecretValue, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(SecretValue::new)
}

fn deserialize_optional_secret<'de, D>(deserializer: D) -> Result<Option<SecretValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(SecretValue::new))
}

macro_rules! profile_read {
    ($operation:ident, $query:ty, $output:ty, $segments:expr) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl ObservableReadOperation for $operation {
            type Query = $query;
            type Output = $output;

            fn endpoint(query: &Self::Query) -> Endpoint {
                Endpoint::from_segments(ApiVersion::V1, ($segments)(query))
            }
        }
    };
}

profile_read!(
    ListProfiles,
    ListProfilesQuery,
    ListProfilesResponse,
    |_query: &ListProfilesQuery| ["cert-manager".to_owned(), "certificate-profiles".to_owned()]
);
profile_read!(
    ListApplicationProfiles,
    ApplicationProfilesQuery,
    ApplicationProfilesResponse,
    |query: &ApplicationProfilesQuery| [
        "cert-manager".to_owned(),
        "applications".to_owned(),
        query.application_id.as_str().to_owned(),
        "profiles".to_owned()
    ]
);
profile_read!(
    GetProfile,
    ExactProfileQuery,
    ProfileResponse,
    |query: &ExactProfileQuery| [
        "cert-manager".to_owned(),
        "certificate-profiles".to_owned(),
        query.profile_id.as_str().to_owned()
    ]
);
profile_read!(
    GetProfileBySlug,
    ProfileBySlugQuery,
    ProfileResponse,
    |query: &ProfileBySlugQuery| [
        "cert-manager".to_owned(),
        "certificate-profiles".to_owned(),
        "slug".to_owned(),
        query.slug.as_str().to_owned()
    ]
);
profile_read!(
    ListProfileCertificates,
    ProfileCertificatesQuery,
    ProfileCertificatesResponse,
    |query: &ProfileCertificatesQuery| [
        "cert-manager".to_owned(),
        "certificate-profiles".to_owned(),
        query.profile_id.as_str().to_owned(),
        "certificates".to_owned()
    ]
);
profile_read!(
    GetLatestBundle,
    ExactProfileQuery,
    BundleWire,
    |query: &ExactProfileQuery| [
        "cert-manager".to_owned(),
        "certificate-profiles".to_owned(),
        query.profile_id.as_str().to_owned(),
        "certificates".to_owned(),
        "latest-active-bundle".to_owned()
    ]
);
profile_read!(
    RevealEabSecret,
    ExactProfileQuery,
    EabWire,
    |query: &ExactProfileQuery| [
        "cert-manager".to_owned(),
        "certificate-profiles".to_owned(),
        query.profile_id.as_str().to_owned(),
        "acme".to_owned(),
        "eab-secret".to_owned(),
        "reveal".to_owned()
    ]
);
macro_rules! profile_mutation {
    ($operation:ident, $input:ty, $method:expr, $segments:expr) => {
        struct $operation;
        impl sealed::Sealed for $operation {}
        impl MutationOperation for $operation {
            type Input = $input;
            type Output = ProfileResponse;

            fn method() -> Method {
                $method
            }

            fn endpoint(input: &Self::Input) -> Endpoint {
                Endpoint::from_segments(ApiVersion::V1, ($segments)(input))
            }
        }
    };
}

profile_mutation!(
    CreateProfile,
    CreateProfileRequest,
    Method::POST,
    |_input: &CreateProfileRequest| ["cert-manager".to_owned(), "certificate-profiles".to_owned()]
);
profile_mutation!(
    UpdateProfile,
    UpdateProfileRequest,
    Method::PATCH,
    |input: &UpdateProfileRequest| [
        "cert-manager".to_owned(),
        "certificate-profiles".to_owned(),
        input.profile_id.as_str().to_owned()
    ]
);
profile_mutation!(
    DeleteProfile,
    DeleteProfileRequest,
    Method::DELETE,
    |input: &DeleteProfileRequest| [
        "cert-manager".to_owned(),
        "certificate-profiles".to_owned(),
        input.profile_id.as_str().to_owned()
    ]
);

fn profile_from_wire(
    wire: ProfileWire,
    project_id: &CertificateAuthorityProjectId,
    expected_id: Option<&CertificateProfileId>,
    expected_slug: Option<&CertificateProfileSlug>,
) -> Result<CertificateProfile, ResourceError> {
    let id = CertificateProfileId::new(wire.id)
        .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    let slug = CertificateProfileSlug::new(wire.slug)
        .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    let policy_id = CertificatePolicyId::new(wire.certificate_policy_id)
        .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    let ca_id = wire
        .ca_id
        .map(CertificateAuthorityId::new)
        .transpose()
        .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    validate_description(wire.description.as_deref())
        .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    if wire.project_id != project_id.as_str()
        || expected_id.is_some_and(|expected| expected.as_str() != id.as_str())
        || expected_slug.is_some_and(|expected| expected.as_str() != slug.as_str())
        || utc_timestamp_millis(&wire.created_at).is_none()
        || utc_timestamp_millis(&wire.updated_at).is_none()
        || utc_timestamp_millis(&wire.updated_at) < utc_timestamp_millis(&wire.created_at)
    {
        return Err(ResourceError::InvalidCertificateProfileScope);
    }
    let config_ids = [
        wire.api_config_id.as_deref(),
        wire.est_config_id.as_deref(),
        wire.acme_config_id.as_deref(),
        wire.scep_config_id.as_deref(),
    ];
    if config_ids
        .into_iter()
        .flatten()
        .any(|value| !is_uuid(value))
    {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    let expected_config_id = match wire.enrollment_type {
        CertificateProfileEnrollmentType::Api => wire.api_config_id.as_deref(),
        CertificateProfileEnrollmentType::Est => wire.est_config_id.as_deref(),
        CertificateProfileEnrollmentType::Acme => wire.acme_config_id.as_deref(),
        CertificateProfileEnrollmentType::Scep => wire.scep_config_id.as_deref(),
    };
    if expected_config_id.is_none()
        || config_ids.into_iter().flatten().count() != 1
        || (wire.issuer_type == CertificateProfileIssuerType::CertificateAuthority
            && ca_id.is_none())
        || (wire.issuer_type == CertificateProfileIssuerType::SelfSigned
            && (ca_id.is_some() || wire.enrollment_type != CertificateProfileEnrollmentType::Api))
    {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    let external_configs = wire
        .external_configs
        .map(|value| CertificateProfileExternalConfig::new(value.template))
        .transpose()
        .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    let defaults = wire
        .defaults
        .map(CertificateProfileDefaults::validate)
        .transpose()
        .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    let certificate_authority = wire
        .certificate_authority
        .map(|authority| authority_from_wire(authority, ca_id.as_ref()))
        .transpose()?;
    let certificate_policy = wire
        .certificate_policy
        .map(|policy| policy_reference_from_wire(policy, project_id, &policy_id))
        .transpose()?;
    let metrics = wire
        .metrics
        .as_ref()
        .map(|metrics| metrics_from_wire(metrics, &id))
        .transpose()?;
    let enrollment = enrollment_from_wire(
        wire.enrollment_type,
        expected_config_id.expect("validated profile configuration ID"),
        wire.est_config,
        wire.api_config,
        wire.acme_config,
        wire.scep_config,
    )?;
    Ok(CertificateProfile {
        id: id.as_str().to_owned(),
        project_id: project_id.as_str().to_owned(),
        ca_id: ca_id.map(|value| value.as_str().to_owned()),
        certificate_policy_id: policy_id.as_str().to_owned(),
        slug: slug.as_str().to_owned(),
        description: wire.description,
        enrollment_type: wire.enrollment_type,
        issuer_type: wire.issuer_type,
        external_configs,
        defaults,
        created_at: wire.created_at,
        updated_at: wire.updated_at,
        certificate_authority,
        certificate_policy,
        metrics,
        enrollment,
    })
}

fn authority_from_wire(
    wire: ProfileAuthorityWire,
    expected_id: Option<&CertificateAuthorityId>,
) -> Result<CertificateProfileAuthorityReference, ResourceError> {
    let id = CertificateAuthorityId::new(wire.id)
        .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    if expected_id != Some(&id) {
        return Err(ResourceError::InvalidCertificateProfileScope);
    }
    if !is_bounded_text(&wire.name, MAX_PROFILE_TEXT_BYTES)
        || wire.external_type == Some(CertificateAuthorityType::Internal)
        || wire.is_external.unwrap_or(false) != wire.external_type.is_some()
    {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    Ok(CertificateProfileAuthorityReference {
        id: id.as_str().to_owned(),
        status: wire.status,
        name: wire.name,
        is_external: wire.is_external,
        external_type: wire.external_type,
    })
}

fn application_profile_ids(
    response: ApplicationProfilesResponse,
    expected_application_id: &CertificateProfileApplicationId,
) -> Result<HashSet<String>, ResourceError> {
    if response.profiles.len() > MAX_APPLICATION_PROFILE_RELATIONSHIPS {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    let mut profile_ids = HashSet::with_capacity(response.profiles.len());
    for relationship in response.profiles {
        let application_id = CertificateProfileApplicationId::new(relationship.application_id)
            .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
        let profile_id = CertificateProfileId::new(relationship.profile_id)
            .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
        if &application_id != expected_application_id {
            return Err(ResourceError::InvalidCertificateProfileScope);
        }
        if !profile_ids.insert(profile_id.as_str().to_owned()) {
            return Err(ResourceError::InvalidCertificateProfileResponse);
        }
    }
    Ok(profile_ids)
}

fn profile_matches_list_filters(
    profile: &CertificateProfile,
    enrollment_type: Option<CertificateProfileEnrollmentType>,
    issuer_type: Option<CertificateProfileIssuerType>,
    ca_id: Option<&CertificateAuthorityId>,
    application_profile_ids: Option<&HashSet<String>>,
) -> bool {
    enrollment_type.is_none_or(|expected| profile.enrollment_type == expected)
        && issuer_type.is_none_or(|expected| profile.issuer_type == expected)
        && ca_id.is_none_or(|expected| profile.ca_id.as_deref() == Some(expected.as_str()))
        && application_profile_ids.is_none_or(|ids| ids.contains(&profile.id))
}

fn policy_reference_from_wire(
    wire: ProfilePolicyWire,
    project_id: &CertificateAuthorityProjectId,
    expected_id: &CertificatePolicyId,
) -> Result<CertificateProfilePolicyReference, ResourceError> {
    let id = CertificatePolicyId::new(wire.id)
        .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    validate_profile_text(&wire.name)
        .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    validate_description(wire.description.as_deref())
        .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    if &id != expected_id || wire.project_id != project_id.as_str() {
        return Err(ResourceError::InvalidCertificateProfileScope);
    }
    Ok(CertificateProfilePolicyReference {
        id: id.as_str().to_owned(),
        project_id: project_id.as_str().to_owned(),
        name: wire.name,
        description: wire.description,
    })
}

fn metrics_from_wire(
    wire: &ProfileMetricsWire,
    profile_id: &CertificateProfileId,
) -> Result<CertificateProfileMetrics, ResourceError> {
    if wire.profile_id != profile_id.as_str()
        || wire.active_certificates > wire.total_certificates
        || wire.expired_certificates > wire.total_certificates
        || wire.expiring_certificates > wire.active_certificates
        || wire.revoked_certificates > wire.total_certificates
    {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    Ok(CertificateProfileMetrics {
        total_certificates: wire.total_certificates,
        active_certificates: wire.active_certificates,
        expired_certificates: wire.expired_certificates,
        expiring_certificates: wire.expiring_certificates,
        revoked_certificates: wire.revoked_certificates,
    })
}

#[allow(clippy::too_many_arguments)]
fn enrollment_from_wire(
    enrollment_type: CertificateProfileEnrollmentType,
    expected_id: &str,
    est: Option<EstConfigWire>,
    api: Option<ApiConfigWire>,
    acme: Option<AcmeConfigWire>,
    scep: Option<ScepConfigWire>,
) -> Result<Option<CertificateProfileEnrollmentMetadata>, ResourceError> {
    let present = usize::from(est.is_some())
        + usize::from(api.is_some())
        + usize::from(acme.is_some())
        + usize::from(scep.is_some());
    if present == 0 {
        return Ok(None);
    }
    if present != 1 {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    let metadata = match (enrollment_type, est, api, acme, scep) {
        (CertificateProfileEnrollmentType::Api, None, Some(value), None, None) => {
            validate_config_id(&value.id, expected_id)?;
            validate_renewal(value.auto_renew, value.renew_before_days)
                .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
            CertificateProfileEnrollmentMetadata::Api {
                id: value.id.to_ascii_lowercase(),
                auto_renew: value.auto_renew,
                renew_before_days: value.renew_before_days,
            }
        }
        (CertificateProfileEnrollmentType::Est, Some(value), None, None, None) => {
            validate_config_id(&value.id, expected_id)?;
            drop(value.passphrase);
            let ca_chain = value
                .ca_chain
                .map(|chain| {
                    normalized_est_ca_chain(&chain)
                        .ok_or(ResourceError::InvalidCertificateProfileResponse)
                })
                .transpose()?;
            CertificateProfileEnrollmentMetadata::Est {
                id: value.id.to_ascii_lowercase(),
                disable_bootstrap_ca_validation: value.disable_bootstrap_ca_validation,
                ca_chain,
            }
        }
        (CertificateProfileEnrollmentType::Acme, None, None, Some(value), None) => {
            validate_config_id(&value.id, expected_id)?;
            validate_http_url(&value.directory_url)?;
            validate_acme(
                value.skip_dns_ownership_verification,
                value.skip_eab_binding,
            )
            .map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
            CertificateProfileEnrollmentMetadata::Acme {
                id: value.id.to_ascii_lowercase(),
                directory_url: value.directory_url,
                skip_dns_ownership_verification: value.skip_dns_ownership_verification,
                skip_eab_binding: value.skip_eab_binding,
            }
        }
        (CertificateProfileEnrollmentType::Scep, None, None, None, Some(value)) => {
            validate_config_id(&value.id, expected_id)?;
            validate_http_url(&value.scep_endpoint_url)?;
            if let Some(url) = value.challenge_endpoint_url.as_deref() {
                validate_http_url(url)?;
            }
            let ra_certificate_pem = normalize_pem(&value.ra_certificate_pem)
                .ok_or(ResourceError::InvalidCertificateProfileResponse)?;
            if utc_timestamp_millis(&value.ra_cert_expires_at).is_none()
                || !is_valid_single_certificate(&ra_certificate_pem)
                || value
                    .dynamic_challenge_expiry_minutes
                    .is_some_and(|number| !(1..=1_440).contains(&number))
                || value
                    .dynamic_challenge_max_pending
                    .is_some_and(|number| !(1..=1_000).contains(&number))
            {
                return Err(ResourceError::InvalidCertificateProfileResponse);
            }
            CertificateProfileEnrollmentMetadata::Scep {
                id: value.id.to_ascii_lowercase(),
                scep_endpoint_url: value.scep_endpoint_url,
                ra_certificate_pem,
                ra_cert_expires_at: value.ra_cert_expires_at,
                include_ca_cert_in_response: value.include_ca_cert_in_response,
                allow_cert_based_renewal: value.allow_cert_based_renewal,
                challenge_type: value.challenge_type,
                challenge_endpoint_url: value.challenge_endpoint_url,
                dynamic_challenge_expiry_minutes: value.dynamic_challenge_expiry_minutes,
                dynamic_challenge_max_pending: value.dynamic_challenge_max_pending,
            }
        }
        _ => return Err(ResourceError::InvalidCertificateProfileResponse),
    };
    Ok(Some(metadata))
}

fn validate_config_id(value: &str, expected: &str) -> Result<(), ResourceError> {
    if !is_uuid(value) || !value.eq_ignore_ascii_case(expected) {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    Ok(())
}

fn validate_http_url(value: &str) -> Result<(), ResourceError> {
    let url = Url::parse(value).map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    if value.len() > MAX_URL_BYTES
        || !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url_has_explicit_credential_free_authority(value)
    {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    Ok(())
}

fn url_has_explicit_credential_free_authority(value: &str) -> bool {
    let Some((_, remainder)) = value.split_once(':') else {
        return false;
    };
    let Some(remainder) = remainder.strip_prefix("//") else {
        return false;
    };
    remainder
        .split(&['/', '?', '#'])
        .next()
        .is_some_and(|authority| !authority.is_empty() && !authority.contains('@'))
}

fn normalized_est_ca_chain(value: &str) -> Option<String> {
    let normalized = normalize_pem(value)?;
    (normalized.len() <= MAX_CERTIFICATE_CHAIN_PEM_BYTES
        && is_valid_ca_signing_certificate_bundle(&normalized))
    .then_some(normalized)
}

pub(crate) fn is_valid_single_certificate(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_CERTIFICATE_PEM_BYTES || value.trim() != value {
        return false;
    }
    certificate_bundle_der(value).is_some_and(|certificates| {
        certificates.len() == 1
            && X509Certificate::from_der(&certificates[0])
                .is_ok_and(|(remainder, _)| remainder.is_empty())
    })
}

fn private_key_der(value: &str) -> Option<Zeroizing<Vec<u8>>> {
    if value.is_empty() || value.len() > MAX_CERTIFICATE_PEM_BYTES || value.trim() != value {
        return None;
    }
    let (label, der) = pem_rfc7468::decode_vec(value.as_bytes()).ok()?;
    let der = Zeroizing::new(der);
    (label == "PRIVATE KEY").then_some(der)
}

fn is_slh_dsa_oid(value: &str) -> bool {
    value
        .strip_prefix("2.16.840.1.101.3.4.3.")
        .and_then(|suffix| suffix.parse::<u8>().ok())
        .is_some_and(|suffix| (20..=31).contains(&suffix))
}

pub(crate) fn private_key_matches_certificate(
    certificate: &X509Certificate<'_>,
    value: &str,
) -> bool {
    let Some(der) = private_key_der(value) else {
        return false;
    };
    let Ok(private_key) = pkcs8::PrivateKeyInfo::from_der(&der) else {
        return false;
    };
    let public_key = certificate.public_key();
    let key_oid = private_key.algorithm.oid.to_string();
    if key_oid != public_key.algorithm.algorithm.to_id_string() {
        return false;
    }
    if is_slh_dsa_oid(&key_oid)
        && (private_key.algorithm.parameters.is_some() || public_key.algorithm.parameters.is_some())
    {
        return false;
    }
    private_key_der_matches_public_key(&key_oid, public_key.subject_public_key.data.as_ref(), &der)
}

fn private_key_der_matches_public_key(key_oid: &str, expected: &[u8], der: &[u8]) -> bool {
    match key_oid {
        "1.2.840.113549.1.1.1" => {
            RsaKeyPair::from_pkcs8(der).is_ok_and(|key| key.public_key().as_ref() == expected)
        }
        "1.2.840.10045.2.1" => [
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &ECDSA_P384_SHA384_ASN1_SIGNING,
            &ECDSA_P521_SHA512_ASN1_SIGNING,
        ]
        .into_iter()
        .any(|algorithm| {
            EcdsaKeyPair::from_pkcs8(algorithm, der)
                .is_ok_and(|key| key.public_key().as_ref() == expected)
        }),
        "1.3.101.112" => {
            Ed25519KeyPair::from_pkcs8(der).is_ok_and(|key| key.public_key().as_ref() == expected)
        }
        "2.16.840.1.101.3.4.3.17" => PqdsaKeyPair::from_pkcs8(&ML_DSA_44_SIGNING, der)
            .is_ok_and(|key| key.public_key().as_ref() == expected),
        "2.16.840.1.101.3.4.3.18" => PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, der)
            .is_ok_and(|key| key.public_key().as_ref() == expected),
        "2.16.840.1.101.3.4.3.19" => PqdsaKeyPair::from_pkcs8(&ML_DSA_87_SIGNING, der)
            .is_ok_and(|key| key.public_key().as_ref() == expected),
        oid @ ("2.16.840.1.101.3.4.3.20"
        | "2.16.840.1.101.3.4.3.21"
        | "2.16.840.1.101.3.4.3.22"
        | "2.16.840.1.101.3.4.3.23"
        | "2.16.840.1.101.3.4.3.24"
        | "2.16.840.1.101.3.4.3.25"
        | "2.16.840.1.101.3.4.3.26"
        | "2.16.840.1.101.3.4.3.27"
        | "2.16.840.1.101.3.4.3.28"
        | "2.16.840.1.101.3.4.3.29"
        | "2.16.840.1.101.3.4.3.30"
        | "2.16.840.1.101.3.4.3.31") => slh_private_key_der_matches_public_key(oid, expected, der),
        _ => false,
    }
}

fn slh_private_key_der_matches_public_key(key_oid: &str, expected: &[u8], der: &[u8]) -> bool {
    let Ok(private_key) = pkcs8::PrivateKeyInfo::from_der(der) else {
        return false;
    };
    if private_key.algorithm.oid.to_string() != key_oid
        || private_key.algorithm.parameters.is_some()
    {
        return false;
    }
    match_slh_private_key_parameter_set!(key_oid, expected, private_key.private_key, {
        "2.16.840.1.101.3.4.3.20" => slh_dsa_sha2_128s,
        "2.16.840.1.101.3.4.3.21" => slh_dsa_sha2_128f,
        "2.16.840.1.101.3.4.3.22" => slh_dsa_sha2_192s,
        "2.16.840.1.101.3.4.3.23" => slh_dsa_sha2_192f,
        "2.16.840.1.101.3.4.3.24" => slh_dsa_sha2_256s,
        "2.16.840.1.101.3.4.3.25" => slh_dsa_sha2_256f,
        "2.16.840.1.101.3.4.3.26" => slh_dsa_shake_128s,
        "2.16.840.1.101.3.4.3.27" => slh_dsa_shake_128f,
        "2.16.840.1.101.3.4.3.28" => slh_dsa_shake_192s,
        "2.16.840.1.101.3.4.3.29" => slh_dsa_shake_192f,
        "2.16.840.1.101.3.4.3.30" => slh_dsa_shake_256s,
        "2.16.840.1.101.3.4.3.31" => slh_dsa_shake_256f,
    })
}

pub(crate) fn certificate_signature_is_valid(
    certificate: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> bool {
    if certificate
        .verify_signature(Some(issuer.public_key()))
        .is_ok()
    {
        return true;
    }
    if certificate.signature_value.unused_bits != 0 {
        return false;
    }
    let signature_oid = certificate.signature_algorithm.algorithm.to_id_string();
    let issuer_key_oid = issuer.public_key().algorithm.algorithm.to_id_string();
    let curve_oid = issuer
        .public_key()
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.as_oid().ok())
        .map(|oid| oid.to_id_string());
    verify_certificate_signature_with_algorithm_fallback(
        &signature_oid,
        &issuer_key_oid,
        curve_oid.as_deref(),
        issuer.public_key().subject_public_key.data.as_ref(),
        certificate.tbs_certificate.as_ref(),
        certificate.signature_value.data.as_ref(),
    )
}

pub(crate) fn certificate_chain_belongs_to_leaf(
    leaf: &X509Certificate<'_>,
    value: &str,
    validation_time: ASN1Time,
) -> bool {
    certificate_chain_matches_leaf(leaf, value, Some(validation_time))
}

pub(crate) fn certificate_chain_is_linked_to_leaf(leaf: &X509Certificate<'_>, value: &str) -> bool {
    certificate_chain_matches_leaf(leaf, value, None)
}

fn certificate_chain_matches_leaf(
    leaf: &X509Certificate<'_>,
    value: &str,
    validation_time: Option<ASN1Time>,
) -> bool {
    if validation_time.is_some_and(|time| !leaf.validity().is_valid_at(time)) {
        return false;
    }
    if value.is_empty() {
        return leaf.issuer() == leaf.subject() && certificate_signature_is_valid(leaf, leaf);
    }
    if value.len() > MAX_CERTIFICATE_CHAIN_PEM_BYTES || value.trim() != value {
        return false;
    }
    let Some(chain_der) = certificate_bundle_der(value) else {
        return false;
    };
    let Some(chain) = chain_der
        .iter()
        .map(|der| {
            X509Certificate::from_der(der)
                .ok()
                .and_then(|(remainder, certificate)| remainder.is_empty().then_some(certificate))
        })
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let mut child = leaf;
    for issuer in &chain {
        if validation_time.is_some_and(|time| !issuer.validity().is_valid_at(time))
            || !issuer.is_ca()
            || !issuer
                .key_usage()
                .is_ok_and(|usage| usage.is_none_or(|usage| usage.value.key_cert_sign()))
            || child.issuer() != issuer.subject()
            || !certificate_signature_is_valid(child, issuer)
        {
            return false;
        }
        child = issuer;
    }
    child.issuer() != child.subject() || certificate_signature_is_valid(child, child)
}

fn certificate_from_wire(
    wire: ProfileCertificateWire,
) -> Result<CertificateProfileCertificate, ResourceError> {
    if !is_uuid(&wire.id)
        || !is_bounded_text(&wire.serial_number, MAX_SERIAL_NUMBER_BYTES)
        || !wire
            .serial_number
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !is_bounded_text(&wire.common_name, MAX_PROFILE_TEXT_BYTES)
        || utc_timestamp_millis(&wire.not_before).is_none()
        || utc_timestamp_millis(&wire.not_after).is_none()
        || utc_timestamp_millis(&wire.not_after) <= utc_timestamp_millis(&wire.not_before)
        || utc_timestamp_millis(&wire.created_at).is_none()
        || wire
            .revoked_at
            .as_deref()
            .is_some_and(|value| utc_timestamp_millis(value).is_none())
        || (wire.status == CertificateProfileCertificateStatus::Revoked
            && wire.revoked_at.is_none())
        || (wire.status != CertificateProfileCertificateStatus::Revoked
            && wire.revoked_at.is_some())
    {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    Ok(CertificateProfileCertificate {
        id: wire.id.to_ascii_lowercase(),
        serial_number: wire.serial_number,
        common_name: wire.common_name,
        status: wire.status,
        not_before: wire.not_before,
        not_after: wire.not_after,
        revoked_at: wire.revoked_at,
        created_at: wire.created_at,
    })
}

fn core_profile_eq(left: &CertificateProfile, right: &CertificateProfile) -> bool {
    left.id == right.id
        && left.project_id == right.project_id
        && left.ca_id == right.ca_id
        && left.certificate_policy_id == right.certificate_policy_id
        && left.slug == right.slug
        && left.description == right.description
        && left.enrollment_type == right.enrollment_type
        && left.issuer_type == right.issuer_type
        && left.external_configs == right.external_configs
        && left.defaults == right.defaults
        && left.created_at == right.created_at
}

fn enrollment_update_reflected(
    profile: &CertificateProfile,
    before: &CertificateProfile,
    request: &UpdateProfileRequest,
) -> bool {
    let mut expected = before.enrollment.clone();
    match (
        expected.as_mut(),
        request.api_config.as_ref(),
        request.est_config.as_ref(),
        request.acme_config.as_ref(),
        request.scep_config.as_ref(),
    ) {
        (
            Some(CertificateProfileEnrollmentMetadata::Api {
                auto_renew,
                renew_before_days,
                ..
            }),
            Some(request),
            None,
            None,
            None,
        ) => {
            *auto_renew = request.auto_renew;
            *renew_before_days = request.renew_before_days;
        }
        (
            Some(CertificateProfileEnrollmentMetadata::Est {
                disable_bootstrap_ca_validation,
                ca_chain,
                ..
            }),
            None,
            Some(request),
            None,
            None,
        ) => {
            *disable_bootstrap_ca_validation = request.disable_bootstrap_ca_validation;
            if let Some(value) = request.ca_chain.as_ref() {
                *ca_chain = Some(value.clone());
            }
        }
        (
            Some(CertificateProfileEnrollmentMetadata::Acme {
                skip_dns_ownership_verification,
                skip_eab_binding,
                ..
            }),
            None,
            None,
            Some(request),
            None,
        ) => {
            if let Some(value) = request.skip_dns_ownership_verification {
                *skip_dns_ownership_verification = value;
            }
            if let Some(value) = request.skip_eab_binding {
                *skip_eab_binding = value;
            }
        }
        (
            Some(CertificateProfileEnrollmentMetadata::Scep {
                challenge_type,
                include_ca_cert_in_response,
                allow_cert_based_renewal,
                dynamic_challenge_expiry_minutes,
                dynamic_challenge_max_pending,
                ..
            }),
            None,
            None,
            None,
            Some(request),
        ) => {
            if let Some(value) = request.challenge_type {
                *challenge_type = value;
            }
            if let Some(value) = request.include_ca_cert_in_response {
                *include_ca_cert_in_response = value;
            }
            if let Some(value) = request.allow_cert_based_renewal {
                *allow_cert_based_renewal = value;
            }
            if let Some(value) = request.dynamic_challenge_expiry_minutes {
                *dynamic_challenge_expiry_minutes = Some(value);
            }
            if let Some(value) = request.dynamic_challenge_max_pending {
                *dynamic_challenge_max_pending = Some(value);
            }
        }
        (_, None, None, None, None) => {}
        _ => return false,
    }
    profile.enrollment == expected
}

fn create_request(
    project_id: &CertificateAuthorityProjectId,
    creation: CertificateProfileCreation,
) -> CreateProfileRequest {
    let (issuer_type, ca_id) = match creation.issuer {
        CertificateProfileIssuer::CertificateAuthority(ca_id) => (
            CertificateProfileIssuerType::CertificateAuthority,
            Some(ca_id.as_str().to_owned()),
        ),
        CertificateProfileIssuer::SelfSigned => (CertificateProfileIssuerType::SelfSigned, None),
    };
    let enrollment_type = creation.enrollment.enrollment_type();
    let (est_config, api_config, acme_config, scep_config) = match creation.enrollment {
        CertificateProfileEnrollmentConfiguration::Api {
            auto_renew,
            renew_before_days,
        } => (
            None,
            Some(ApiConfigRequest {
                auto_renew,
                renew_before_days,
            }),
            None,
            None,
        ),
        CertificateProfileEnrollmentConfiguration::Est {
            disable_bootstrap_ca_validation,
            passphrase,
            ca_chain,
        } => (
            Some(EstCreateRequest {
                disable_bootstrap_ca_validation,
                passphrase,
                ca_chain: ca_chain.map(|chain| {
                    normalized_est_ca_chain(&chain)
                        .expect("validated EST CA chain must remain canonicalizable")
                }),
            }),
            None,
            None,
            None,
        ),
        CertificateProfileEnrollmentConfiguration::Acme {
            skip_dns_ownership_verification,
            skip_eab_binding,
        } => (
            None,
            None,
            Some(AcmeConfigRequest {
                skip_dns_ownership_verification,
                skip_eab_binding,
            }),
            None,
        ),
        CertificateProfileEnrollmentConfiguration::Scep {
            challenge_type,
            challenge_password,
            include_ca_cert_in_response,
            allow_cert_based_renewal,
            dynamic_challenge_expiry_minutes,
            dynamic_challenge_max_pending,
        } => (
            None,
            None,
            None,
            Some(ScepCreateRequest {
                challenge_type,
                challenge_password,
                include_ca_cert_in_response,
                allow_cert_based_renewal,
                dynamic_challenge_expiry_minutes,
                dynamic_challenge_max_pending,
            }),
        ),
    };
    CreateProfileRequest {
        project_id: project_id.as_str().to_owned(),
        ca_id,
        certificate_policy_id: creation.certificate_policy_id.as_str().to_owned(),
        slug: creation.slug.as_str().to_owned(),
        description: creation.description,
        enrollment_type,
        issuer_type,
        est_config,
        api_config,
        acme_config,
        scep_config,
        external_configs: creation.external_configs,
        defaults: creation.defaults,
    }
}

fn update_request(
    profile_id: &CertificateProfileId,
    change: CertificateProfileChange,
) -> UpdateProfileRequest {
    let (est_config, api_config, acme_config, scep_config) = match change.enrollment {
        Some(CertificateProfileEnrollmentChange::Api {
            auto_renew,
            renew_before_days,
        }) => (
            None,
            Some(ApiConfigRequest {
                auto_renew,
                renew_before_days,
            }),
            None,
            None,
        ),
        Some(CertificateProfileEnrollmentChange::Est {
            disable_bootstrap_ca_validation,
            passphrase,
            ca_chain,
        }) => (
            Some(EstUpdateRequest {
                disable_bootstrap_ca_validation,
                passphrase,
                ca_chain: ca_chain.map(|chain| {
                    normalized_est_ca_chain(&chain)
                        .expect("validated EST CA chain must remain canonicalizable")
                }),
            }),
            None,
            None,
            None,
        ),
        Some(CertificateProfileEnrollmentChange::Acme(value)) => (
            None,
            None,
            Some(AcmeUpdateRequest {
                skip_dns_ownership_verification: value.skip_dns_ownership_verification,
                skip_eab_binding: value.skip_eab_binding,
            }),
            None,
        ),
        Some(CertificateProfileEnrollmentChange::Scep {
            challenge_type,
            challenge_password,
            include_ca_cert_in_response,
            allow_cert_based_renewal,
            dynamic_challenge_expiry_minutes,
            dynamic_challenge_max_pending,
        }) => (
            None,
            None,
            None,
            Some(ScepUpdateRequest {
                challenge_type,
                challenge_password,
                include_ca_cert_in_response,
                allow_cert_based_renewal,
                dynamic_challenge_expiry_minutes,
                dynamic_challenge_max_pending,
            }),
        ),
        None => (None, None, None, None),
    };
    let description = change.description.map(|value| match value {
        CertificateProfileDescriptionChange::Set(value) => NullableUpdate::Value(value),
        CertificateProfileDescriptionChange::Clear => NullableUpdate::Null,
    });
    let external_configs = change.external_configs.map(|value| match value {
        CertificateProfileExternalConfigChange::Set(value) => NullableUpdate::Value(value),
        CertificateProfileExternalConfigChange::Clear => NullableUpdate::Null,
    });
    let defaults = change.defaults.map(|value| match value {
        CertificateProfileDefaultsChange::Set(value) => NullableUpdate::Value(*value),
        CertificateProfileDefaultsChange::Clear => NullableUpdate::Null,
    });
    UpdateProfileRequest {
        profile_id: profile_id.clone(),
        slug: change.slug.map(|value| value.as_str().to_owned()),
        description,
        est_config,
        api_config,
        acme_config,
        scep_config,
        external_configs,
        defaults,
    }
}

fn nullable_update_matches<T>(actual: Option<&T>, expected: &NullableUpdate<T>) -> bool
where
    T: PartialEq,
{
    match expected {
        NullableUpdate::Value(value) => actual == Some(value),
        NullableUpdate::Null => actual.is_none(),
    }
}

fn nullable_update_or_unchanged_matches<T>(
    actual: Option<&T>,
    before: Option<&T>,
    expected: Option<&NullableUpdate<T>>,
) -> bool
where
    T: PartialEq,
{
    expected.map_or(actual == before, |expected| {
        nullable_update_matches(actual, expected)
    })
}

fn validate_profile_page_bounds(
    page: PageRequest,
    returned: usize,
    total_count: u64,
) -> Result<(), ResourceError> {
    if returned > usize::from(page.limit()) {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    let returned =
        u64::try_from(returned).map_err(|_| ResourceError::InvalidCertificateProfileResponse)?;
    let offset = u64::from(page.offset());
    let end = offset
        .checked_add(returned)
        .ok_or(ResourceError::InvalidCertificateProfileResponse)?;
    let page_fits_total = if returned == 0 {
        offset >= total_count
    } else if returned < u64::from(page.limit()) {
        end == total_count
    } else {
        end <= total_count
    };
    if !page_fits_total {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    Ok(())
}

fn validate_page_limit(page: PageRequest, returned: usize) -> Result<(), ResourceError> {
    if returned > usize::from(page.limit()) {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    Ok(())
}

fn create_enrollment_reflected(
    profile: &CertificateProfile,
    request: &CreateProfileRequest,
) -> bool {
    match (
        profile.enrollment.as_ref(),
        request.api_config.as_ref(),
        request.est_config.as_ref(),
        request.acme_config.as_ref(),
        request.scep_config.as_ref(),
    ) {
        (
            Some(CertificateProfileEnrollmentMetadata::Api {
                auto_renew,
                renew_before_days,
                ..
            }),
            Some(request),
            None,
            None,
            None,
        ) => *auto_renew == request.auto_renew && *renew_before_days == request.renew_before_days,
        (
            Some(CertificateProfileEnrollmentMetadata::Est {
                disable_bootstrap_ca_validation,
                ca_chain,
                ..
            }),
            None,
            Some(request),
            None,
            None,
        ) => {
            *disable_bootstrap_ca_validation == request.disable_bootstrap_ca_validation
                && ca_chain == &request.ca_chain
        }
        (
            Some(CertificateProfileEnrollmentMetadata::Acme {
                skip_dns_ownership_verification,
                skip_eab_binding,
                ..
            }),
            None,
            None,
            Some(request),
            None,
        ) => {
            *skip_dns_ownership_verification == request.skip_dns_ownership_verification
                && *skip_eab_binding == request.skip_eab_binding
        }
        (
            Some(CertificateProfileEnrollmentMetadata::Scep {
                include_ca_cert_in_response,
                allow_cert_based_renewal,
                challenge_type,
                dynamic_challenge_expiry_minutes,
                dynamic_challenge_max_pending,
                ..
            }),
            None,
            None,
            None,
            Some(request),
        ) => {
            *include_ca_cert_in_response == request.include_ca_cert_in_response
                && *allow_cert_based_renewal == request.allow_cert_based_renewal
                && *challenge_type == request.challenge_type
                && *dynamic_challenge_expiry_minutes
                    == Some(request.dynamic_challenge_expiry_minutes)
                && *dynamic_challenge_max_pending == Some(request.dynamic_challenge_max_pending)
        }
        _ => false,
    }
}

fn create_response_reflects(
    profile: &CertificateProfile,
    expected_policy: &CertificatePolicyId,
    expected_enrollment: CertificateProfileEnrollmentType,
    expected_issuer: CertificateProfileIssuerType,
    request: &CreateProfileRequest,
) -> bool {
    profile.certificate_policy_id == expected_policy.as_str()
        && profile.enrollment_type == expected_enrollment
        && profile.issuer_type == expected_issuer
        && profile.description == request.description
        && profile.external_configs == request.external_configs
        && profile.defaults == request.defaults
        && profile.ca_id == request.ca_id
        && create_enrollment_reflected(profile, request)
}

fn update_response_reflects(
    profile: &CertificateProfile,
    before: &CertificateProfile,
    request: &UpdateProfileRequest,
) -> bool {
    profile.ca_id == before.ca_id
        && profile.certificate_policy_id == before.certificate_policy_id
        && profile.enrollment_type == before.enrollment_type
        && profile.issuer_type == before.issuer_type
        && profile.created_at == before.created_at
        && request
            .slug
            .as_ref()
            .map_or(profile.slug == before.slug, |value| profile.slug == *value)
        && nullable_update_or_unchanged_matches(
            profile.description.as_ref(),
            before.description.as_ref(),
            request.description.as_ref(),
        )
        && nullable_update_or_unchanged_matches(
            profile.external_configs.as_ref(),
            before.external_configs.as_ref(),
            request.external_configs.as_ref(),
        )
        && nullable_update_or_unchanged_matches(
            profile.defaults.as_ref(),
            before.defaults.as_ref(),
            request.defaults.as_ref(),
        )
        && enrollment_update_reflected(profile, before, request)
}

fn refreshed_update_reflects(profile: &CertificateProfile, refreshed: &CertificateProfile) -> bool {
    core_profile_eq(profile, refreshed)
        && profile.updated_at == refreshed.updated_at
        && profile.enrollment == refreshed.enrollment
}

fn bundle_from_wire(
    profile_id: &CertificateProfileId,
    response: BundleWire,
) -> Result<Option<CertificateProfileBundle>, ResourceError> {
    bundle_from_wire_at(profile_id, response, ASN1Time::now())
}

fn bundle_from_wire_at(
    profile_id: &CertificateProfileId,
    response: BundleWire,
    validation_time: ASN1Time,
) -> Result<Option<CertificateProfileBundle>, ResourceError> {
    match (
        response.certificate,
        response.certificate_chain,
        response.private_key,
        response.serial_number,
    ) {
        (None, None, None, None) => Ok(None),
        (Some(certificate), Some(certificate_chain), Some(private_key), Some(serial_number)) => {
            let certificate = normalize_pem(&certificate)
                .ok_or(ResourceError::InvalidCertificateProfileResponse)?;
            let certificate_chain = if certificate_chain.is_empty() {
                String::new()
            } else {
                normalize_pem(&certificate_chain)
                    .ok_or(ResourceError::InvalidCertificateProfileResponse)?
            };
            let private_key = normalize_pem(private_key.expose_secret())
                .map(SecretValue::new)
                .ok_or(ResourceError::InvalidCertificateProfileResponse)?;
            let Some(certificate_der) = certificate_bundle_der(&certificate)
                .filter(|certificates| certificates.len() == 1)
                .and_then(|mut certificates| certificates.pop())
            else {
                return Err(ResourceError::InvalidCertificateProfileResponse);
            };
            let Ok((remainder, parsed_certificate)) = X509Certificate::from_der(&certificate_der)
            else {
                return Err(ResourceError::InvalidCertificateProfileResponse);
            };
            if !remainder.is_empty()
                || !is_valid_single_certificate(&certificate)
                || !certificate_chain_belongs_to_leaf(
                    &parsed_certificate,
                    &certificate_chain,
                    validation_time,
                )
                || !private_key_matches_certificate(
                    &parsed_certificate,
                    private_key.expose_secret(),
                )
                || !is_bounded_text(&serial_number, MAX_SERIAL_NUMBER_BYTES)
                || !serial_number.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !certificate_serial_matches(&parsed_certificate, &serial_number)
            {
                return Err(ResourceError::InvalidCertificateProfileResponse);
            }
            Ok(Some(CertificateProfileBundle {
                profile_id: profile_id.as_str().to_owned(),
                certificate,
                certificate_chain,
                private_key,
                serial_number,
            }))
        }
        _ => Err(ResourceError::InvalidCertificateProfileResponse),
    }
}

fn eab_from_wire(
    profile_id: &CertificateProfileId,
    response: EabWire,
) -> Result<CertificateProfileEabSecret, ResourceError> {
    if !is_bounded_text(&response.eab_kid, MAX_PROFILE_TEXT_BYTES)
        || response.eab_secret.expose_secret().is_empty()
        || response.eab_secret.expose_secret().len() > MAX_PROFILE_SECRET_BYTES
    {
        return Err(ResourceError::InvalidCertificateProfileResponse);
    }
    Ok(CertificateProfileEabSecret {
        profile_id: profile_id.as_str().to_owned(),
        eab_kid: response.eab_kid,
        eab_secret: response.eab_secret,
    })
}

impl InfisicalClient {
    async fn ensure_profile_policy_scope(
        &self,
        project_id: &CertificateAuthorityProjectId,
        policy_id: &CertificatePolicyId,
    ) -> Result<(), ResourceError> {
        self.get_certificate_policy(project_id, policy_id).await?;
        Ok(())
    }

    async fn ensure_profile_ca_scope(
        &self,
        project_id: &CertificateAuthorityProjectId,
        ca_id: &CertificateAuthorityId,
    ) -> Result<CertificateAuthorityType, ResourceError> {
        let authorities = self.list_certificate_authorities(project_id).await?;
        authorities
            .into_iter()
            .find(|authority| authority.id == ca_id.as_str())
            .map(|authority| authority.ca_type)
            .ok_or(ResourceError::InvalidCertificateProfileScope)
    }

    /// List one bounded page of sanitized profiles in a Certificate Manager project.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, response-contract, or pagination error.
    pub async fn list_certificate_profiles(
        &self,
        request: CertificateProfileListRequest,
    ) -> Result<Page<CertificateProfile>, ResourceError> {
        let response = self
            .execute_observable_read::<ListProfiles>(&ListProfilesQuery {
                project_id: request.project_id.as_str().to_owned(),
                offset: request.page.offset(),
                limit: request.page.limit(),
                search: request.search.clone(),
                enrollment_type: request.enrollment_type,
                issuer_type: request.issuer_type,
                ca_id: request
                    .ca_id
                    .as_ref()
                    .map(|value| value.as_str().to_owned()),
                application_id: request
                    .application_id
                    .as_ref()
                    .map(|value| value.as_str().to_owned()),
            })
            .await?;
        validate_profile_page_bounds(
            request.page,
            response.certificate_profiles.len(),
            response.total_count,
        )?;
        let profiles = response
            .certificate_profiles
            .into_iter()
            .map(|profile| profile_from_wire(profile, &request.project_id, None, None))
            .collect::<Result<Vec<_>, _>>()?;
        let application_ids = if !profiles.is_empty()
            && let Some(application_id) = request.application_id.as_ref()
        {
            let relationships = self
                .execute_observable_read::<ListApplicationProfiles>(&ApplicationProfilesQuery {
                    application_id: application_id.clone(),
                })
                .await?;
            Some(application_profile_ids(relationships, application_id)?)
        } else {
            None
        };
        if profiles
            .iter()
            .map(|profile| &profile.id)
            .collect::<HashSet<_>>()
            .len()
            != profiles.len()
        {
            return Err(ResourceError::InvalidCertificateProfileResponse);
        }
        if profiles.iter().any(|profile| {
            !profile_matches_list_filters(
                profile,
                request.enrollment_type,
                request.issuer_type,
                request.ca_id.as_ref(),
                application_ids.as_ref(),
            )
        }) {
            return Err(ResourceError::InvalidCertificateProfileScope);
        }
        Ok(Page::new(
            request.page,
            profiles,
            Some(response.total_count),
        )?)
    }

    /// Get one exact sanitized profile by ID and prove project ownership.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or response-contract error.
    pub async fn get_certificate_profile(
        &self,
        project_id: &CertificateAuthorityProjectId,
        profile_id: &CertificateProfileId,
    ) -> Result<CertificateProfile, ResourceError> {
        let response = self
            .execute_observable_read::<GetProfile>(&ExactProfileQuery {
                profile_id: profile_id.clone(),
            })
            .await?;
        profile_from_wire(
            response.certificate_profile,
            project_id,
            Some(profile_id),
            None,
        )
    }

    /// Get one exact sanitized profile by project-local slug.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, or response-contract error.
    pub async fn get_certificate_profile_by_slug(
        &self,
        project_id: &CertificateAuthorityProjectId,
        slug: &CertificateProfileSlug,
    ) -> Result<CertificateProfile, ResourceError> {
        let response = self
            .execute_observable_read::<GetProfileBySlug>(&ProfileBySlugQuery {
                slug: slug.clone(),
                project_id: project_id.as_str().to_owned(),
            })
            .await?;
        profile_from_wire(response.certificate_profile, project_id, None, Some(slug))
    }

    /// Create one profile after project, policy, and optional CA scope preflights.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    pub async fn create_certificate_profile(
        &self,
        project_id: &CertificateAuthorityProjectId,
        creation: CertificateProfileCreation,
        confirm: bool,
    ) -> Result<CertificateProfile, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateProfileCreateNotConfirmed);
        }
        self.ensure_certificate_manager_project(project_id).await?;
        self.ensure_profile_policy_scope(project_id, &creation.certificate_policy_id)
            .await?;
        let ca_type = match &creation.issuer {
            CertificateProfileIssuer::CertificateAuthority(ca_id) => {
                Some(self.ensure_profile_ca_scope(project_id, ca_id).await?)
            }
            CertificateProfileIssuer::SelfSigned => None,
        };
        if !azure_template_matches_provider(
            creation
                .external_configs
                .as_ref()
                .is_some_and(CertificateProfileExternalConfig::has_azure_template),
            ca_type,
        ) {
            return Err(ResourceError::InvalidCertificateProfileState);
        }
        let expected_slug = creation.slug.clone();
        let expected_policy = creation.certificate_policy_id.clone();
        let expected_enrollment = creation.enrollment.enrollment_type();
        let expected_issuer = match &creation.issuer {
            CertificateProfileIssuer::CertificateAuthority(_) => {
                CertificateProfileIssuerType::CertificateAuthority
            }
            CertificateProfileIssuer::SelfSigned => CertificateProfileIssuerType::SelfSigned,
        };
        let request = create_request(project_id, creation);
        let response = self.execute_mutation::<CreateProfile>(&request).await?;
        let profile = profile_from_wire(
            response.certificate_profile,
            project_id,
            None,
            Some(&expected_slug),
        )?;
        if !create_response_reflects(
            &profile,
            &expected_policy,
            expected_enrollment,
            expected_issuer,
            &request,
        ) {
            return Err(ResourceError::InvalidCertificateProfileResponse);
        }
        Ok(profile)
    }

    /// Apply one same-family profile change after confirmation and ownership preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, state, scope, typed client, or response-contract error.
    pub async fn update_certificate_profile(
        &self,
        project_id: &CertificateAuthorityProjectId,
        profile_id: &CertificateProfileId,
        change: CertificateProfileChange,
        confirm: bool,
    ) -> Result<CertificateProfile, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateProfileUpdateNotConfirmed);
        }
        let authorities = if change.sets_azure_template() {
            Some(self.list_certificate_authorities(project_id).await?)
        } else {
            None
        };
        let before = self.get_certificate_profile(project_id, profile_id).await?;
        if change
            .enrollment
            .as_ref()
            .is_some_and(|enrollment| enrollment.enrollment_type() != before.enrollment_type)
        {
            return Err(ResourceError::InvalidCertificateProfileState);
        }
        if let Some(authorities) = authorities {
            let ca_id = before
                .ca_id
                .as_deref()
                .ok_or(ResourceError::InvalidCertificateProfileState)
                .and_then(|value| {
                    CertificateAuthorityId::new(value)
                        .map_err(|_| ResourceError::InvalidCertificateProfileState)
                })?;
            let ca_type = authorities
                .into_iter()
                .find(|authority| authority.id == ca_id.as_str())
                .map(|authority| authority.ca_type)
                .ok_or(ResourceError::InvalidCertificateProfileScope)?;
            if !azure_template_matches_provider(true, Some(ca_type)) {
                return Err(ResourceError::InvalidCertificateProfileState);
            }
        }
        if let Some(CertificateProfileEnrollmentChange::Acme(flags)) = change.enrollment.as_ref() {
            let CertificateProfileEnrollmentMetadata::Acme {
                skip_dns_ownership_verification,
                skip_eab_binding,
                ..
            } = before
                .enrollment
                .as_ref()
                .ok_or(ResourceError::InvalidCertificateProfileState)?
            else {
                return Err(ResourceError::InvalidCertificateProfileState);
            };
            validate_acme(
                flags
                    .skip_dns_ownership_verification
                    .unwrap_or(*skip_dns_ownership_verification),
                flags.skip_eab_binding.unwrap_or(*skip_eab_binding),
            )
            .map_err(|_| ResourceError::InvalidCertificateProfileState)?;
        }
        if let Some(enrollment) = change.enrollment.as_ref() {
            validate_scep_change_against_current(enrollment, before.enrollment.as_ref())?;
        }
        let request = update_request(profile_id, change);
        let response = self.execute_mutation::<UpdateProfile>(&request).await?;
        let profile = profile_from_wire(
            response.certificate_profile,
            project_id,
            Some(profile_id),
            None,
        )?;
        if !update_response_reflects(&profile, &before, &request) {
            return Err(ResourceError::InvalidCertificateProfileResponse);
        }
        if request.api_config.is_some()
            || request.est_config.is_some()
            || request.acme_config.is_some()
            || request.scep_config.is_some()
        {
            let refreshed = self.get_certificate_profile(project_id, profile_id).await?;
            if !refreshed_update_reflects(&profile, &refreshed) {
                return Err(ResourceError::InvalidCertificateProfileResponse);
            }
            return Ok(refreshed);
        }
        Ok(profile)
    }

    /// Permanently delete one exact profile after confirmation and ownership preflight.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, typed client, or response-contract error.
    pub async fn delete_certificate_profile(
        &self,
        project_id: &CertificateAuthorityProjectId,
        profile_id: &CertificateProfileId,
        confirm: bool,
    ) -> Result<CertificateProfile, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateProfileDeleteNotConfirmed);
        }
        let before = self.get_certificate_profile(project_id, profile_id).await?;
        let response = self
            .execute_mutation::<DeleteProfile>(&DeleteProfileRequest {
                profile_id: profile_id.clone(),
            })
            .await?;
        let deleted = profile_from_wire(
            response.certificate_profile,
            project_id,
            Some(profile_id),
            None,
        )?;
        if !core_profile_eq(&before, &deleted) {
            return Err(ResourceError::InvalidCertificateProfileResponse);
        }
        Ok(deleted)
    }

    /// List one bounded page of certificates issued through an exact profile.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, response-contract, or pagination error.
    pub async fn list_certificate_profile_certificates(
        &self,
        request: CertificateProfileCertificateListRequest,
    ) -> Result<Page<CertificateProfileCertificate>, ResourceError> {
        self.get_certificate_profile(&request.project_id, &request.profile_id)
            .await?;
        let expected_status = request.status;
        let response = self
            .execute_observable_read::<ListProfileCertificates>(&ProfileCertificatesQuery {
                profile_id: request.profile_id.clone(),
                offset: request.page.offset(),
                limit: request.page.limit(),
                status: expected_status,
                search: request.search,
            })
            .await?;
        validate_page_limit(request.page, response.certificates.len())?;
        let certificates = response
            .certificates
            .into_iter()
            .map(certificate_from_wire)
            .collect::<Result<Vec<_>, _>>()?;
        if certificates
            .iter()
            .map(|certificate| &certificate.id)
            .collect::<HashSet<_>>()
            .len()
            != certificates.len()
        {
            return Err(ResourceError::InvalidCertificateProfileResponse);
        }
        if certificates
            .iter()
            .any(|certificate| expected_status.is_some_and(|value| certificate.status != value))
        {
            return Err(ResourceError::InvalidCertificateProfileScope);
        }
        Ok(Page::new(request.page, certificates, None)?)
    }

    /// Reveal the latest active certificate bundle for one exact profile.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, state, typed client, or response-contract error.
    pub async fn reveal_certificate_profile_latest_bundle(
        &self,
        project_id: &CertificateAuthorityProjectId,
        profile_id: &CertificateProfileId,
        confirm_reveal: bool,
    ) -> Result<Option<CertificateProfileBundle>, ResourceError> {
        if !confirm_reveal {
            return Err(ResourceError::CertificateProfileSecretRevealNotConfirmed);
        }
        self.get_certificate_profile(project_id, profile_id).await?;
        let response = self
            .execute_observable_read::<GetLatestBundle>(&ExactProfileQuery {
                profile_id: profile_id.clone(),
            })
            .await?;
        bundle_from_wire(profile_id, response)
    }

    /// Reveal the ACME EAB secret for one exact ACME profile.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, scope, state, typed client, or response-contract error.
    pub async fn reveal_certificate_profile_eab_secret(
        &self,
        project_id: &CertificateAuthorityProjectId,
        profile_id: &CertificateProfileId,
        confirm_reveal: bool,
    ) -> Result<CertificateProfileEabSecret, ResourceError> {
        if !confirm_reveal {
            return Err(ResourceError::CertificateProfileSecretRevealNotConfirmed);
        }
        let profile = self.get_certificate_profile(project_id, profile_id).await?;
        if profile.enrollment_type != CertificateProfileEnrollmentType::Acme {
            return Err(ResourceError::InvalidCertificateProfileState);
        }
        let response = self
            .execute_observable_read::<RevealEabSecret>(&ExactProfileQuery {
                profile_id: profile_id.clone(),
            })
            .await?;
        eab_from_wire(profile_id, response)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use aws_lc_rs::{
        encoding::{AsDer, Pkcs8V1Der},
        rsa::KeySize,
        signature::{
            ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
            ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, PqdsaKeyPair, RsaKeyPair,
        },
    };
    use fips205::traits::{KeyGen, SerDes};
    use pkcs8::{
        AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfo,
        der::{Encode, asn1::AnyRef},
    };
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path, query_param},
    };
    use x509_parser::prelude::{FromDer, X509Certificate};
    use x509_parser::time::ASN1Time;

    use super::{
        AcmeUpdateRequest, ApiConfigRequest, ApplicationProfileWire, ApplicationProfilesResponse,
        BundleWire, CertificatePolicyId, CertificateProfileAcmeChange,
        CertificateProfileApplicationId, CertificateProfileCertificateListRequest,
        CertificateProfileCertificateStatus, CertificateProfileChange, CertificateProfileCreation,
        CertificateProfileDefaults, CertificateProfileDefaultsChange,
        CertificateProfileDescriptionChange, CertificateProfileEnrollmentChange,
        CertificateProfileEnrollmentConfiguration, CertificateProfileEnrollmentMetadata,
        CertificateProfileEnrollmentType, CertificateProfileExternalConfig,
        CertificateProfileExternalConfigChange, CertificateProfileId, CertificateProfileInputError,
        CertificateProfileIssuer, CertificateProfileIssuerType, CertificateProfileListRequest,
        CertificateProfileScepChallengeType, CertificateProfileSlug, EabWire, EstConfigWire,
        EstUpdateRequest, MAX_APPLICATION_PROFILE_RELATIONSHIPS, MAX_CERTIFICATE_CHAIN_PEM_BYTES,
        MAX_CERTIFICATE_PEM_BYTES, MAX_PROFILE_DESCRIPTION_BYTES, MAX_PROFILE_SEARCH_BYTES,
        MAX_PROFILE_SECRET_BYTES, MAX_PROFILE_TEXT_BYTES, MAX_URL_BYTES, ProfileWire,
        ScepConfigWire, ScepUpdateRequest, UpdateProfileRequest, application_profile_ids,
        azure_template_matches_provider, bundle_from_wire, bundle_from_wire_at,
        certificate_bundle_der, create_enrollment_reflected, create_request,
        create_response_reflects, eab_from_wire, enrollment_from_wire, enrollment_update_reflected,
        is_slh_dsa_oid, normalized_est_ca_chain, private_key_der,
        private_key_der_matches_public_key, private_key_matches_certificate, profile_from_wire,
        profile_matches_list_filters, refreshed_update_reflects, update_request,
        update_response_reflects, validate_acme, validate_description, validate_http_url,
        validate_page_limit, validate_profile_page_bounds, validate_profile_text, validate_renewal,
        validate_scep, validate_scep_change_against_current, validate_search, validate_secret,
    };
    use crate::{
        CertificateAuthorityId, CertificateAuthorityProjectId, CertificateAuthorityStatus,
        InfisicalClient, PageRequest, ResourceError,
        test_support::{CA_CERT, mount_login, settings},
    };

    const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const CA_ID: &str = "22222222-2222-4222-8222-222222222222";
    const PROFILE_ID: &str = "33333333-3333-4333-8333-333333333333";
    const POLICY_ID: &str = "44444444-4444-4444-8444-444444444444";
    const CONFIG_ID: &str = "55555555-5555-4555-8555-555555555555";
    const CERTIFICATE_ID: &str = "66666666-6666-4666-8666-666666666666";
    const APPLICATION_ID: &str = "77777777-7777-4777-8777-777777777777";
    const OTHER_ID: &str = "88888888-8888-4888-8888-888888888888";
    const UNRELATED_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICTbXxOqSduuWtnpf5Xccpl1ubMUukR9a8Eg3UxuM47O\n-----END PRIVATE KEY-----";

    fn profile_certificate_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-cert.txt")
            .strip_suffix('\n')
            .expect("profile certificate fixture must have one final line feed")
    }

    fn profile_issuer_certificate_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-issuer-cert.txt")
            .strip_suffix('\n')
            .expect("profile issuer fixture must have one final line feed")
    }

    fn profile_private_key_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-private-key.txt")
            .strip_suffix('\n')
            .expect("profile private-key fixture must have one final line feed")
    }

    #[test]
    fn decoded_private_key_der_uses_zeroizing_storage() {
        let der = private_key_der(profile_private_key_fixture()).unwrap();
        let _: &zeroize::Zeroizing<Vec<u8>> = &der;
        assert!(!der.is_empty());
    }

    fn ca_without_key_cert_sign_fixture() -> &'static str {
        include_str!("../test-fixtures/ca-without-keycertsign.txt")
            .strip_suffix('\n')
            .expect("CA fixture must have one final line feed")
    }

    fn empty_update_profile_request() -> UpdateProfileRequest {
        UpdateProfileRequest {
            profile_id: CertificateProfileId::new(PROFILE_ID).unwrap(),
            slug: None,
            description: None,
            est_config: None,
            api_config: None,
            acme_config: None,
            scep_config: None,
            external_configs: None,
            defaults: None,
        }
    }

    fn profile_bundle(
        certificate: Option<&str>,
        chain: Option<&str>,
        key: Option<&str>,
        serial: Option<&str>,
    ) -> BundleWire {
        BundleWire {
            certificate: certificate.map(str::to_owned),
            certificate_chain: chain.map(str::to_owned),
            private_key: key.map(crate::SecretValue::new),
            serial_number: serial.map(str::to_owned),
        }
    }

    fn valid_ca_chain_with_length(length: usize) -> String {
        let certificate_count = length / (CA_CERT.len() + 1);
        let chain = vec![CA_CERT; certificate_count].join("\n");
        let mut crlf_replacements = length - chain.len();
        let mut adjusted = String::with_capacity(length);
        for character in chain.chars() {
            if character == '\n' && crlf_replacements > 0 {
                adjusted.push('\r');
                crlf_replacements -= 1;
            }
            adjusted.push(character);
        }
        assert_eq!(crlf_replacements, 0);
        assert_eq!(adjusted.len(), length);
        adjusted
    }

    fn profile_value(
        slug: &str,
        enrollment_type: &str,
        description: Option<&str>,
        include_config: bool,
    ) -> Value {
        let mut profile = json!({
            "id": PROFILE_ID,
            "projectId": PROJECT_ID,
            "caId": CA_ID,
            "certificatePolicyId": POLICY_ID,
            "slug": slug,
            "description": description,
            "enrollmentType": enrollment_type,
            "estConfigId": null,
            "apiConfigId": null,
            "acmeConfigId": null,
            "scepConfigId": null,
            "createdAt": "2026-07-21T12:00:00.000Z",
            "updatedAt": "2026-07-21T12:00:01.000Z",
            "issuerType": "ca",
            "externalConfigs": null,
            "defaults": null
        });
        let id_field = match enrollment_type {
            "api" => "apiConfigId",
            "est" => "estConfigId",
            "acme" => "acmeConfigId",
            "scep" => "scepConfigId",
            _ => unreachable!(),
        };
        profile[id_field] = json!(CONFIG_ID);
        if include_config {
            match enrollment_type {
                "api" => {
                    profile["apiConfig"] = json!({
                        "id": CONFIG_ID,
                        "autoRenew": true,
                        "renewBeforeDays": 10
                    });
                }
                "est" => {
                    profile["estConfig"] = json!({
                        "id": CONFIG_ID,
                        "disableBootstrapCaValidation": false,
                        "passphrase": "profile-passphrase-canary"
                    });
                }
                "acme" => {
                    profile["acmeConfig"] = json!({
                        "id": CONFIG_ID,
                        "directoryUrl": "https://server.example.test/api/v1/cert-manager/certificate-profiles/acme/directory",
                        "skipDnsOwnershipVerification": false,
                        "skipEabBinding": false
                    });
                }
                _ => unreachable!(),
            }
        }
        profile
    }

    fn policy_value() -> Value {
        json!({
            "id": POLICY_ID,
            "projectId": PROJECT_ID,
            "name": "profile-policy",
            "description": null,
            "createdAt": "2026-07-21T12:00:00.000Z",
            "updatedAt": "2026-07-21T12:00:01.000Z"
        })
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
    fn response_rebinding_profile_authority_is_closed_bound_and_value_free() {
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let mut value = profile_value("api-profile", "api", None, true);
        value["certificateAuthority"] = json!({
            "id": CA_ID,
            "status": "active",
            "name": "root-ca",
            "isExternal": false,
            "externalType": null
        });
        let profile = profile_from_wire(
            serde_json::from_value::<ProfileWire>(value.clone()).unwrap(),
            &project_id,
            None,
            None,
        )
        .unwrap();
        let authority = profile.certificate_authority.unwrap();
        assert_eq!(authority.status, CertificateAuthorityStatus::Active);
        assert_eq!(authority.external_type, None);
        let serialized = serde_json::to_value(authority).unwrap();
        assert!(serialized.get("projectId").is_none());

        value["certificateAuthority"]["status"] = json!("future-state");
        assert!(serde_json::from_value::<ProfileWire>(value.clone()).is_err());
        value["certificateAuthority"]["status"] = json!("active");
        value["certificateAuthority"]["isExternal"] = json!(true);
        value["certificateAuthority"]["externalType"] = json!("future-provider");
        assert!(serde_json::from_value::<ProfileWire>(value.clone()).is_err());

        value["certificateAuthority"]["externalType"] = json!("internal");
        let internal_external = profile_from_wire(
            serde_json::from_value::<ProfileWire>(value.clone()).unwrap(),
            &project_id,
            None,
            None,
        );
        assert_eq!(
            internal_external,
            Err(ResourceError::InvalidCertificateProfileResponse)
        );

        value["certificateAuthority"]["externalType"] = json!("azure-ad-cs");
        value["certificateAuthority"]["isExternal"] = json!(false);
        assert_eq!(
            profile_from_wire(
                serde_json::from_value::<ProfileWire>(value.clone()).unwrap(),
                &project_id,
                None,
                None,
            ),
            Err(ResourceError::InvalidCertificateProfileResponse)
        );
        value["certificateAuthority"]["externalType"] = Value::Null;
        value["certificateAuthority"]["isExternal"] = json!(true);
        assert_eq!(
            profile_from_wire(
                serde_json::from_value::<ProfileWire>(value.clone()).unwrap(),
                &project_id,
                None,
                None,
            ),
            Err(ResourceError::InvalidCertificateProfileResponse)
        );
        value["certificateAuthority"]["isExternal"] = json!(false);
        value["certificateAuthority"]["name"] = json!("x".repeat(MAX_PROFILE_TEXT_BYTES + 1));
        assert_eq!(
            profile_from_wire(
                serde_json::from_value::<ProfileWire>(value.clone()).unwrap(),
                &project_id,
                None,
                None,
            ),
            Err(ResourceError::InvalidCertificateProfileResponse)
        );

        value["certificateAuthority"]["name"] = json!("root-ca");
        value["certificateAuthority"]["id"] = json!(OTHER_ID);
        let mismatched_id = profile_from_wire(
            serde_json::from_value::<ProfileWire>(value).unwrap(),
            &project_id,
            None,
            None,
        );
        assert_eq!(
            mismatched_id,
            Err(ResourceError::InvalidCertificateProfileScope)
        );
    }

    #[test]
    fn response_rebinding_profile_filter_checks_every_returned_coordinate() {
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let profile = profile_from_wire(
            serde_json::from_value::<ProfileWire>(profile_value("api-profile", "api", None, true))
                .unwrap(),
            &project_id,
            None,
            None,
        )
        .unwrap();
        let ca_id = CertificateAuthorityId::new(CA_ID).unwrap();
        let application_ids = [PROFILE_ID.to_owned()].into_iter().collect();
        assert!(profile_matches_list_filters(
            &profile,
            Some(CertificateProfileEnrollmentType::Api),
            Some(CertificateProfileIssuerType::CertificateAuthority),
            Some(&ca_id),
            Some(&application_ids),
        ));
        assert!(!profile_matches_list_filters(
            &profile,
            Some(CertificateProfileEnrollmentType::Acme),
            None,
            None,
            None,
        ));
        assert!(!profile_matches_list_filters(
            &profile,
            None,
            Some(CertificateProfileIssuerType::SelfSigned),
            None,
            None,
        ));
        assert!(!profile_matches_list_filters(
            &profile,
            None,
            None,
            Some(&CertificateAuthorityId::new(OTHER_ID).unwrap()),
            None,
        ));
        assert!(!profile_matches_list_filters(
            &profile,
            None,
            None,
            None,
            Some(&[OTHER_ID.to_owned()].into_iter().collect()),
        ));
    }

    #[test]
    fn response_rebinding_application_relationships_are_bounded_unique_and_scoped() {
        let application_id = CertificateProfileApplicationId::new(APPLICATION_ID).unwrap();
        let profiles = (0..MAX_APPLICATION_PROFILE_RELATIONSHIPS)
            .map(|index| ApplicationProfileWire {
                application_id: APPLICATION_ID.to_owned(),
                profile_id: format!("00000000-0000-4000-8000-{index:012x}"),
            })
            .collect();
        let ids =
            application_profile_ids(ApplicationProfilesResponse { profiles }, &application_id)
                .unwrap();
        assert_eq!(ids.len(), MAX_APPLICATION_PROFILE_RELATIONSHIPS);

        let duplicate = ApplicationProfileWire {
            application_id: APPLICATION_ID.to_owned(),
            profile_id: PROFILE_ID.to_owned(),
        };
        assert_eq!(
            application_profile_ids(
                ApplicationProfilesResponse {
                    profiles: vec![
                        ApplicationProfileWire {
                            application_id: duplicate.application_id.clone(),
                            profile_id: duplicate.profile_id.clone(),
                        },
                        duplicate,
                    ],
                },
                &application_id,
            ),
            Err(ResourceError::InvalidCertificateProfileResponse)
        );
        assert_eq!(
            application_profile_ids(
                ApplicationProfilesResponse {
                    profiles: vec![ApplicationProfileWire {
                        application_id: OTHER_ID.to_owned(),
                        profile_id: PROFILE_ID.to_owned(),
                    }],
                },
                &application_id,
            ),
            Err(ResourceError::InvalidCertificateProfileScope)
        );
        let too_many = (0..=MAX_APPLICATION_PROFILE_RELATIONSHIPS)
            .map(|_| ApplicationProfileWire {
                application_id: String::new(),
                profile_id: String::new(),
            })
            .collect();
        assert_eq!(
            application_profile_ids(
                ApplicationProfilesResponse { profiles: too_many },
                &application_id,
            ),
            Err(ResourceError::InvalidCertificateProfileResponse)
        );
    }

    #[test]
    fn azure_template_provider_mapping_is_exact() {
        assert!(azure_template_matches_provider(
            true,
            Some(crate::CertificateAuthorityType::AzureAdCs),
        ));
        assert!(!azure_template_matches_provider(
            true,
            Some(crate::CertificateAuthorityType::Internal),
        ));
        assert!(azure_template_matches_provider(
            false,
            Some(crate::CertificateAuthorityType::Internal),
        ));
        assert!(azure_template_matches_provider(false, None));
        assert!(!azure_template_matches_provider(true, None));
    }

    #[test]
    fn inputs_enforce_issuer_enrollment_and_non_empty_change_invariants() {
        assert_eq!(
            CertificateProfileSlug::new("Bad_Slug").unwrap_err(),
            CertificateProfileInputError::InvalidSlug
        );
        let policy_id = CertificatePolicyId::new(POLICY_ID).unwrap();
        let slug = CertificateProfileSlug::new("self-signed-est").unwrap();
        let invalid = CertificateProfileCreation::new(
            policy_id,
            slug,
            None,
            CertificateProfileIssuer::SelfSigned,
            CertificateProfileEnrollmentConfiguration::Est {
                disable_bootstrap_ca_validation: false,
                passphrase: crate::SecretValue::new("passphrase"),
                ca_chain: None,
            },
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(
            invalid,
            CertificateProfileInputError::InvalidSelfSignedEnrollment
        );
        assert_eq!(
            CertificateProfileCreation::new(
                CertificatePolicyId::new(POLICY_ID).unwrap(),
                CertificateProfileSlug::new("self-signed-api").unwrap(),
                None,
                CertificateProfileIssuer::SelfSigned,
                CertificateProfileEnrollmentConfiguration::Api {
                    auto_renew: false,
                    renew_before_days: None,
                },
                Some(CertificateProfileExternalConfig::new(Some("template".to_owned())).unwrap(),),
                None,
            )
            .unwrap_err(),
            CertificateProfileInputError::InvalidExternalProvider
        );
        assert_eq!(
            CertificateProfileCreation::new(
                CertificatePolicyId::new(POLICY_ID).unwrap(),
                CertificateProfileSlug::new("acme").unwrap(),
                None,
                CertificateProfileIssuer::CertificateAuthority(
                    CertificateAuthorityId::new(CA_ID).unwrap(),
                ),
                CertificateProfileEnrollmentConfiguration::Acme {
                    skip_dns_ownership_verification: true,
                    skip_eab_binding: true,
                },
                None,
                None,
            )
            .unwrap_err(),
            CertificateProfileInputError::InvalidAcmeConfiguration
        );
        assert_eq!(
            CertificateProfileChange::new(None, None, None, None, None).unwrap_err(),
            CertificateProfileInputError::EmptyChange
        );
        assert_eq!(
            CertificateProfileChange::new(
                None,
                None,
                Some(CertificateProfileEnrollmentChange::Acme(
                    CertificateProfileAcmeChange {
                        skip_dns_ownership_verification: None,
                        skip_eab_binding: None,
                    },
                )),
                None,
                None,
            )
            .unwrap_err(),
            CertificateProfileInputError::EmptyChange
        );
    }

    #[test]
    // The pinned limits and every independent text predicate are externally observable input contracts.
    fn profile_input_boundaries_reject_each_invalid_dimension() {
        assert_eq!(MAX_CERTIFICATE_PEM_BYTES, 65_536);
        assert_eq!(MAX_CERTIFICATE_CHAIN_PEM_BYTES, 524_288);

        assert_eq!(validate_description(None), Ok(()));
        assert_eq!(validate_description(Some("")), Ok(()));
        assert_eq!(
            validate_description(Some(&"a".repeat(MAX_PROFILE_DESCRIPTION_BYTES))),
            Ok(())
        );
        for description in [
            format!("{}a", "a".repeat(MAX_PROFILE_DESCRIPTION_BYTES)),
            " leading".to_owned(),
            "trailing ".to_owned(),
            "control\ncharacter".to_owned(),
        ] {
            assert_eq!(
                validate_description(Some(&description)),
                Err(CertificateProfileInputError::InvalidDescription)
            );
        }

        for text in ["a".to_owned(), "a".repeat(MAX_PROFILE_TEXT_BYTES)] {
            assert_eq!(validate_profile_text(&text), Ok(()));
        }
        for text in [
            String::new(),
            format!("{}a", "a".repeat(MAX_PROFILE_TEXT_BYTES)),
            " leading".to_owned(),
            "trailing ".to_owned(),
            "control\ncharacter".to_owned(),
        ] {
            assert_eq!(
                validate_profile_text(&text),
                Err(CertificateProfileInputError::InvalidText)
            );
        }

        assert_eq!(validate_search(None), Ok(()));
        assert_eq!(validate_search(Some("a")), Ok(()));
        assert_eq!(
            validate_search(Some(&"a".repeat(MAX_PROFILE_SEARCH_BYTES))),
            Ok(())
        );
        for search in ["", " leading", "trailing ", "control\ncharacter"] {
            assert_eq!(
                validate_search(Some(search)),
                Err(CertificateProfileInputError::InvalidSearch)
            );
        }
        assert_eq!(
            validate_search(Some(&"a".repeat(MAX_PROFILE_SEARCH_BYTES + 1))),
            Err(CertificateProfileInputError::InvalidSearch)
        );
    }

    #[test]
    // Enrollment validation treats each flag, limit, and secret bound as an independent invariant.
    #[allow(clippy::too_many_lines)]
    fn enrollment_boundaries_reject_each_invalid_dimension() {
        let secret = |value: &str| crate::SecretValue::new(value.to_owned());
        assert_eq!(
            validate_secret(
                &secret("a"),
                1,
                CertificateProfileInputError::InvalidEstPassphrase,
            ),
            Ok(())
        );
        assert_eq!(
            validate_secret(
                &secret(&"a".repeat(MAX_PROFILE_SECRET_BYTES)),
                1,
                CertificateProfileInputError::InvalidEstPassphrase,
            ),
            Ok(())
        );
        for invalid in [String::new(), "a".repeat(MAX_PROFILE_SECRET_BYTES + 1)] {
            assert_eq!(
                validate_secret(
                    &secret(&invalid),
                    1,
                    CertificateProfileInputError::InvalidEstPassphrase,
                ),
                Err(CertificateProfileInputError::InvalidEstPassphrase)
            );
        }

        for (auto_renew, days) in [
            (false, None),
            (true, None),
            (true, Some(1)),
            (true, Some(30)),
        ] {
            assert_eq!(validate_renewal(auto_renew, days), Ok(()));
        }
        for (auto_renew, days) in [(false, Some(1)), (true, Some(0)), (true, Some(31))] {
            assert_eq!(
                validate_renewal(auto_renew, days),
                Err(CertificateProfileInputError::InvalidRenewal)
            );
        }

        for (skip_dns, skip_eab) in [(false, false), (true, false), (false, true)] {
            assert_eq!(validate_acme(skip_dns, skip_eab), Ok(()));
        }
        assert_eq!(
            validate_acme(true, true),
            Err(CertificateProfileInputError::InvalidAcmeConfiguration)
        );

        let static_password = secret("12345678");
        assert_eq!(
            validate_scep(
                CertificateProfileScepChallengeType::Static,
                Some(&static_password),
                1,
                1,
            ),
            Ok(())
        );
        assert_eq!(
            validate_scep(
                CertificateProfileScepChallengeType::Static,
                Some(&secret(&"a".repeat(MAX_PROFILE_SECRET_BYTES))),
                1_440,
                1_000,
            ),
            Ok(())
        );
        for (expiry, maximum_pending) in [(0, 1), (1_441, 1), (1, 0), (1, 1_001)] {
            assert_eq!(
                validate_scep(
                    CertificateProfileScepChallengeType::Static,
                    Some(&static_password),
                    expiry,
                    maximum_pending,
                ),
                Err(CertificateProfileInputError::InvalidScepLimits)
            );
        }
        for password in [
            None,
            Some(secret("1234567")),
            Some(secret(&"a".repeat(4_097))),
        ] {
            assert_eq!(
                validate_scep(
                    CertificateProfileScepChallengeType::Static,
                    password.as_ref(),
                    60,
                    100,
                ),
                Err(CertificateProfileInputError::InvalidScepPassword)
            );
        }
        assert_eq!(
            validate_scep(CertificateProfileScepChallengeType::Dynamic, None, 60, 100,),
            Ok(())
        );
        assert_eq!(
            validate_scep(
                CertificateProfileScepChallengeType::Dynamic,
                Some(&static_password),
                60,
                100,
            ),
            Err(CertificateProfileInputError::InvalidScepPassword)
        );
    }

    #[test]
    fn est_input_pem_accepts_and_canonicalizes_one_terminal_line_ending() {
        assert!(normalized_est_ca_chain("not-a-certificate").is_none());
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let profile_id = CertificateProfileId::new(PROFILE_ID).unwrap();
        for terminal in ["\n", "\r\n"] {
            let creation = CertificateProfileCreation::new(
                CertificatePolicyId::new(POLICY_ID).unwrap(),
                CertificateProfileSlug::new("est-profile").unwrap(),
                None,
                CertificateProfileIssuer::CertificateAuthority(
                    CertificateAuthorityId::new(CA_ID).unwrap(),
                ),
                CertificateProfileEnrollmentConfiguration::Est {
                    disable_bootstrap_ca_validation: false,
                    passphrase: crate::SecretValue::new("passphrase"),
                    ca_chain: Some(format!("{CA_CERT}{terminal}")),
                },
                None,
                None,
            )
            .unwrap();
            let create = create_request(&project_id, creation);
            assert_eq!(
                create.est_config.unwrap().ca_chain.as_deref(),
                Some(CA_CERT)
            );

            let change = CertificateProfileChange::new(
                None,
                None,
                Some(CertificateProfileEnrollmentChange::Est {
                    disable_bootstrap_ca_validation: false,
                    passphrase: None,
                    ca_chain: Some(format!("{CA_CERT}{terminal}")),
                }),
                None,
                None,
            )
            .unwrap();
            let update = update_request(&profile_id, change);
            assert_eq!(
                update.est_config.unwrap().ca_chain.as_deref(),
                Some(CA_CERT)
            );
        }
    }

    #[test]
    // Creation and partial updates apply the shared enrollment rules before any request is built.
    #[allow(clippy::too_many_lines)]
    fn enrollment_configuration_and_change_validate_every_optional_field() {
        let est_configuration = |ca_chain| CertificateProfileEnrollmentConfiguration::Est {
            disable_bootstrap_ca_validation: false,
            passphrase: crate::SecretValue::new("passphrase"),
            ca_chain,
        };
        let exact_chain = valid_ca_chain_with_length(MAX_CERTIFICATE_CHAIN_PEM_BYTES);
        assert_eq!(est_configuration(Some(exact_chain)).validate(), Ok(()));
        for invalid_chain in [
            String::new(),
            format!(" {CA_CERT}"),
            format!("{CA_CERT}\n\n"),
            "not-a-certificate".to_owned(),
            profile_certificate_fixture().to_owned(),
            ca_without_key_cert_sign_fixture().to_owned(),
            valid_ca_chain_with_length(MAX_CERTIFICATE_CHAIN_PEM_BYTES + 1),
        ] {
            assert_eq!(
                est_configuration(Some(invalid_chain)).validate(),
                Err(CertificateProfileInputError::InvalidEstCaChain)
            );
        }

        let est_change = |ca_chain| CertificateProfileEnrollmentChange::Est {
            disable_bootstrap_ca_validation: false,
            passphrase: None,
            ca_chain,
        };
        assert_eq!(
            est_change(Some(valid_ca_chain_with_length(
                MAX_CERTIFICATE_CHAIN_PEM_BYTES,
            )))
            .validate(),
            Ok(())
        );
        for invalid_chain in [
            String::new(),
            format!("{CA_CERT} "),
            format!("{CA_CERT}\r\n\r\n"),
            "not-a-certificate".to_owned(),
            profile_certificate_fixture().to_owned(),
            ca_without_key_cert_sign_fixture().to_owned(),
            valid_ca_chain_with_length(MAX_CERTIFICATE_CHAIN_PEM_BYTES + 1),
        ] {
            assert_eq!(
                est_change(Some(invalid_chain)).validate(),
                Err(CertificateProfileInputError::InvalidEstCaChain)
            );
        }

        for change in [
            CertificateProfileEnrollmentChange::Acme(CertificateProfileAcmeChange {
                skip_dns_ownership_verification: Some(true),
                skip_eab_binding: None,
            }),
            CertificateProfileEnrollmentChange::Acme(CertificateProfileAcmeChange {
                skip_dns_ownership_verification: None,
                skip_eab_binding: Some(true),
            }),
        ] {
            assert_eq!(change.validate(), Ok(()));
        }

        for change in [
            CertificateProfileEnrollmentChange::Scep {
                challenge_type: None,
                challenge_password: Some(crate::SecretValue::new("12345678")),
                include_ca_cert_in_response: None,
                allow_cert_based_renewal: None,
                dynamic_challenge_expiry_minutes: None,
                dynamic_challenge_max_pending: None,
            },
            CertificateProfileEnrollmentChange::Scep {
                challenge_type: None,
                challenge_password: Some(crate::SecretValue::new(
                    "a".repeat(MAX_PROFILE_SECRET_BYTES),
                )),
                include_ca_cert_in_response: None,
                allow_cert_based_renewal: None,
                dynamic_challenge_expiry_minutes: None,
                dynamic_challenge_max_pending: None,
            },
            CertificateProfileEnrollmentChange::Scep {
                challenge_type: Some(CertificateProfileScepChallengeType::Dynamic),
                challenge_password: None,
                include_ca_cert_in_response: None,
                allow_cert_based_renewal: None,
                dynamic_challenge_expiry_minutes: None,
                dynamic_challenge_max_pending: None,
            },
            CertificateProfileEnrollmentChange::Scep {
                challenge_type: None,
                challenge_password: None,
                include_ca_cert_in_response: Some(true),
                allow_cert_based_renewal: None,
                dynamic_challenge_expiry_minutes: None,
                dynamic_challenge_max_pending: None,
            },
            CertificateProfileEnrollmentChange::Scep {
                challenge_type: None,
                challenge_password: None,
                include_ca_cert_in_response: None,
                allow_cert_based_renewal: Some(true),
                dynamic_challenge_expiry_minutes: None,
                dynamic_challenge_max_pending: None,
            },
            CertificateProfileEnrollmentChange::Scep {
                challenge_type: None,
                challenge_password: None,
                include_ca_cert_in_response: None,
                allow_cert_based_renewal: None,
                dynamic_challenge_expiry_minutes: Some(1),
                dynamic_challenge_max_pending: None,
            },
            CertificateProfileEnrollmentChange::Scep {
                challenge_type: None,
                challenge_password: None,
                include_ca_cert_in_response: None,
                allow_cert_based_renewal: None,
                dynamic_challenge_expiry_minutes: None,
                dynamic_challenge_max_pending: Some(1_000),
            },
        ] {
            assert_eq!(change.validate(), Ok(()));
        }
        for change in [
            CertificateProfileEnrollmentChange::Scep {
                challenge_type: None,
                challenge_password: Some(crate::SecretValue::new("1234567")),
                include_ca_cert_in_response: None,
                allow_cert_based_renewal: None,
                dynamic_challenge_expiry_minutes: None,
                dynamic_challenge_max_pending: None,
            },
            CertificateProfileEnrollmentChange::Scep {
                challenge_type: None,
                challenge_password: Some(crate::SecretValue::new(
                    "a".repeat(MAX_PROFILE_SECRET_BYTES + 1),
                )),
                include_ca_cert_in_response: None,
                allow_cert_based_renewal: None,
                dynamic_challenge_expiry_minutes: None,
                dynamic_challenge_max_pending: None,
            },
            CertificateProfileEnrollmentChange::Scep {
                challenge_type: None,
                challenge_password: None,
                include_ca_cert_in_response: None,
                allow_cert_based_renewal: None,
                dynamic_challenge_expiry_minutes: Some(0),
                dynamic_challenge_max_pending: None,
            },
            CertificateProfileEnrollmentChange::Scep {
                challenge_type: None,
                challenge_password: None,
                include_ca_cert_in_response: None,
                allow_cert_based_renewal: None,
                dynamic_challenge_expiry_minutes: None,
                dynamic_challenge_max_pending: Some(1_001),
            },
        ] {
            assert!(change.validate().is_err());
        }
    }

    #[test]
    fn pagination_contracts_accept_only_coherent_bounded_pages() {
        let page = PageRequest::new(2, 2).unwrap();
        for (returned, total) in [(0, 2), (1, 3), (2, 4), (2, 5)] {
            assert_eq!(validate_profile_page_bounds(page, returned, total), Ok(()));
        }
        for (returned, total) in [(0, 3), (1, 2), (1, 4), (2, 3), (3, 5)] {
            assert_eq!(
                validate_profile_page_bounds(page, returned, total),
                Err(ResourceError::InvalidCertificateProfileResponse)
            );
        }
        assert_eq!(validate_page_limit(page, 2), Ok(()));
        assert_eq!(
            validate_page_limit(page, 3),
            Err(ResourceError::InvalidCertificateProfileResponse)
        );
    }

    #[test]
    fn public_profile_urls_reject_credentials_and_invalid_values() {
        assert_eq!(validate_http_url("https://pki.example.test/scep"), Ok(()));
        assert_eq!(
            validate_http_url("https://pki.example.test/scep/@challenge"),
            Ok(())
        );
        let prefix = "https://pki.example.test/";
        let maximum = format!("{prefix}{}", "a".repeat(MAX_URL_BYTES - prefix.len()));
        assert_eq!(maximum.len(), MAX_URL_BYTES);
        assert_eq!(validate_http_url(&maximum), Ok(()));
        assert_eq!(
            validate_http_url(&format!("{maximum}a")),
            Err(ResourceError::InvalidCertificateProfileResponse)
        );
        for value in [
            "https://user:password@pki.example.test/scep",
            "https://@pki.example.test/scep",
            "HTTPS://@pki.example.test/scep",
            "https:user:password@pki.example.test/scep",
            "https:////user:password@pki.example.test/scep",
            "ftp://pki.example.test/scep",
            "not-a-url",
        ] {
            assert_eq!(
                validate_http_url(value),
                Err(ResourceError::InvalidCertificateProfileResponse)
            );
        }
    }

    #[test]
    fn scep_updates_preserve_the_preflighted_challenge_mode() {
        let current = |challenge_type| CertificateProfileEnrollmentMetadata::Scep {
            id: CONFIG_ID.to_owned(),
            scep_endpoint_url: "https://pki.example.test/scep".to_owned(),
            ra_certificate_pem: CA_CERT.to_owned(),
            ra_cert_expires_at: "2036-07-21T12:00:00.000Z".to_owned(),
            include_ca_cert_in_response: false,
            allow_cert_based_renewal: false,
            challenge_type,
            challenge_endpoint_url: None,
            dynamic_challenge_expiry_minutes: None,
            dynamic_challenge_max_pending: None,
        };
        let change =
            |challenge_type, challenge_password| CertificateProfileEnrollmentChange::Scep {
                challenge_type,
                challenge_password,
                include_ca_cert_in_response: None,
                allow_cert_based_renewal: None,
                dynamic_challenge_expiry_minutes: Some(60),
                dynamic_challenge_max_pending: None,
            };
        assert!(
            validate_scep_change_against_current(
                &change(Some(CertificateProfileScepChallengeType::Static), None),
                Some(&current(CertificateProfileScepChallengeType::Static)),
            )
            .is_ok()
        );
        for (requested, password, observed) in [
            (
                Some(CertificateProfileScepChallengeType::Dynamic),
                None,
                CertificateProfileScepChallengeType::Static,
            ),
            (
                Some(CertificateProfileScepChallengeType::Static),
                None,
                CertificateProfileScepChallengeType::Dynamic,
            ),
            (
                None,
                Some(crate::SecretValue::new("12345678")),
                CertificateProfileScepChallengeType::Dynamic,
            ),
        ] {
            assert_eq!(
                validate_scep_change_against_current(
                    &change(requested, password),
                    Some(&current(observed))
                ),
                Err(ResourceError::InvalidCertificateProfileState)
            );
        }
    }

    fn profile_from_value(value: Value) -> super::CertificateProfile {
        profile_from_wire(
            serde_json::from_value(value).unwrap(),
            &CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
            None,
            None,
        )
        .unwrap()
    }

    fn profile_defaults() -> CertificateProfileDefaults {
        CertificateProfileDefaults::new(
            Some(30),
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
        .unwrap()
    }

    #[test]
    fn partial_defaults_omit_absent_fields_but_clearing_remains_explicit() {
        let profile_id = CertificateProfileId::new(PROFILE_ID).unwrap();
        let change = CertificateProfileChange::new(
            None,
            None,
            None,
            None,
            Some(CertificateProfileDefaultsChange::Set(Box::new(
                profile_defaults(),
            ))),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(update_request(&profile_id, change)).unwrap(),
            json!({"defaults": {"ttlDays": 30}})
        );
        let clear = CertificateProfileChange::new(
            None,
            None,
            None,
            None,
            Some(CertificateProfileDefaultsChange::Clear),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(update_request(&profile_id, clear)).unwrap(),
            json!({"defaults": null})
        );
        let mut defaults = profile_defaults();
        defaults.basic_constraints = Some(super::CertificateProfileBasicConstraints {
            is_ca: false,
            path_length: None,
        });
        assert_eq!(
            serde_json::to_value(defaults).unwrap(),
            json!({"ttlDays": 30, "basicConstraints": {"isCA": false}})
        );
    }

    #[test]
    // Each reflected field independently protects callers from accepting a drifted mutation response.
    #[allow(clippy::too_many_lines)]
    fn mutation_response_contracts_reject_each_drifted_field() {
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let policy_id = CertificatePolicyId::new(POLICY_ID).unwrap();
        let creation = CertificateProfileCreation::new(
            policy_id.clone(),
            CertificateProfileSlug::new("api-profile").unwrap(),
            Some("initial".to_owned()),
            CertificateProfileIssuer::CertificateAuthority(
                CertificateAuthorityId::new(CA_ID).unwrap(),
            ),
            CertificateProfileEnrollmentConfiguration::Api {
                auto_renew: true,
                renew_before_days: Some(10),
            },
            None,
            None,
        )
        .unwrap();
        let create = create_request(&project_id, creation);
        let created =
            profile_from_value(profile_value("api-profile", "api", Some("initial"), true));
        assert!(create_response_reflects(
            &created,
            &policy_id,
            CertificateProfileEnrollmentType::Api,
            CertificateProfileIssuerType::CertificateAuthority,
            &create,
        ));
        let mut invalid_created = Vec::new();
        let mut value = created.clone();
        value.certificate_policy_id = "77777777-7777-4777-8777-777777777777".to_owned();
        invalid_created.push(value);
        let mut value = created.clone();
        value.enrollment_type = CertificateProfileEnrollmentType::Est;
        invalid_created.push(value);
        let mut value = created.clone();
        value.issuer_type = CertificateProfileIssuerType::SelfSigned;
        invalid_created.push(value);
        let mut value = created.clone();
        value.description = Some("drifted".to_owned());
        invalid_created.push(value);
        let mut value = created.clone();
        value.external_configs = Some(CertificateProfileExternalConfig::new(None).unwrap());
        invalid_created.push(value);
        let mut value = created.clone();
        value.defaults = Some(profile_defaults());
        invalid_created.push(value);
        let mut value = created.clone();
        value.ca_id = None;
        invalid_created.push(value);
        let mut value = created.clone();
        value.enrollment = None;
        invalid_created.push(value);
        for invalid in invalid_created {
            assert!(!create_response_reflects(
                &invalid,
                &policy_id,
                CertificateProfileEnrollmentType::Api,
                CertificateProfileIssuerType::CertificateAuthority,
                &create,
            ));
        }

        let before = created;
        let external = CertificateProfileExternalConfig::new(Some("template".to_owned())).unwrap();
        let defaults = profile_defaults();
        let change = CertificateProfileChange::new(
            Some(CertificateProfileSlug::new("updated-profile").unwrap()),
            Some(CertificateProfileDescriptionChange::Set(
                "updated".to_owned(),
            )),
            None,
            Some(CertificateProfileExternalConfigChange::Set(
                external.clone(),
            )),
            Some(CertificateProfileDefaultsChange::Set(Box::new(
                defaults.clone(),
            ))),
        )
        .unwrap();
        let update = update_request(&CertificateProfileId::new(PROFILE_ID).unwrap(), change);
        let mut updated = before.clone();
        updated.slug = "updated-profile".to_owned();
        updated.description = Some("updated".to_owned());
        updated.external_configs = Some(external);
        updated.defaults = Some(defaults);
        updated.updated_at = "2026-07-21T12:00:02.000Z".to_owned();
        assert!(update_response_reflects(&updated, &before, &update));

        let mut invalid_updates = Vec::new();
        let mut value = updated.clone();
        value.ca_id = None;
        invalid_updates.push(value);
        let mut value = updated.clone();
        value.certificate_policy_id = "77777777-7777-4777-8777-777777777777".to_owned();
        invalid_updates.push(value);
        let mut value = updated.clone();
        value.enrollment_type = CertificateProfileEnrollmentType::Est;
        invalid_updates.push(value);
        let mut value = updated.clone();
        value.issuer_type = CertificateProfileIssuerType::SelfSigned;
        invalid_updates.push(value);
        let mut value = updated.clone();
        value.created_at = "2026-07-21T12:00:03.000Z".to_owned();
        invalid_updates.push(value);
        let mut value = updated.clone();
        value.slug = "wrong-profile".to_owned();
        invalid_updates.push(value);
        let mut value = updated.clone();
        value.description = None;
        invalid_updates.push(value);
        let mut value = updated.clone();
        value.external_configs = None;
        invalid_updates.push(value);
        let mut value = updated.clone();
        value.defaults = None;
        invalid_updates.push(value);
        for invalid in invalid_updates {
            assert!(!update_response_reflects(&invalid, &before, &update));
        }

        let description_only_change = CertificateProfileChange::new(
            None,
            Some(CertificateProfileDescriptionChange::Set(
                "description-only".to_owned(),
            )),
            None,
            None,
            None,
        )
        .unwrap();
        let description_only_update = update_request(
            &CertificateProfileId::new(PROFILE_ID).unwrap(),
            description_only_change,
        );
        let mut description_only_response = before.clone();
        description_only_response.description = Some("description-only".to_owned());
        assert!(update_response_reflects(
            &description_only_response,
            &before,
            &description_only_update,
        ));
        let mut omitted_field_drifts = Vec::new();
        let mut value = description_only_response.clone();
        value.slug = "unexpected-slug".to_owned();
        omitted_field_drifts.push(value);
        let mut value = description_only_response.clone();
        value.external_configs = Some(CertificateProfileExternalConfig::new(None).unwrap());
        omitted_field_drifts.push(value);
        let mut value = description_only_response.clone();
        value.defaults = Some(profile_defaults());
        omitted_field_drifts.push(value);
        let mut value = description_only_response;
        value.enrollment = Some(CertificateProfileEnrollmentMetadata::Api {
            id: CONFIG_ID.to_owned(),
            auto_renew: false,
            renew_before_days: Some(10),
        });
        omitted_field_drifts.push(value);
        for drifted in omitted_field_drifts {
            assert!(!update_response_reflects(
                &drifted,
                &before,
                &description_only_update,
            ));
        }

        let enrollment_change = CertificateProfileChange::new(
            None,
            None,
            Some(CertificateProfileEnrollmentChange::Api {
                auto_renew: true,
                renew_before_days: Some(10),
            }),
            None,
            None,
        )
        .unwrap();
        let enrollment_update = update_request(
            &CertificateProfileId::new(PROFILE_ID).unwrap(),
            enrollment_change,
        );
        let response =
            profile_from_value(profile_value("api-profile", "api", Some("initial"), true));
        let mut enrollment_before = response.clone();
        let Some(CertificateProfileEnrollmentMetadata::Api { auto_renew, .. }) =
            enrollment_before.enrollment.as_mut()
        else {
            panic!("API fixture must include enrollment metadata");
        };
        *auto_renew = false;
        assert!(update_response_reflects(
            &response,
            &enrollment_before,
            &enrollment_update,
        ));
        let refreshed = response.clone();
        assert!(refreshed_update_reflects(&response, &refreshed));
        let mut drifted = refreshed.clone();
        drifted.description = Some("drifted".to_owned());
        assert!(!refreshed_update_reflects(&response, &drifted));
        let mut drifted = refreshed.clone();
        drifted.updated_at = "2026-07-21T12:00:03.000Z".to_owned();
        assert!(!refreshed_update_reflects(&response, &drifted));
        let mut drifted = refreshed;
        let Some(CertificateProfileEnrollmentMetadata::Api { auto_renew, .. }) =
            drifted.enrollment.as_mut()
        else {
            panic!("API fixture must include enrollment metadata");
        };
        *auto_renew = false;
        assert!(!refreshed_update_reflects(&response, &drifted));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn create_enrollment_reflection_requires_every_requested_family_field() {
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let request_for = |slug: &str, enrollment| {
            create_request(
                &project_id,
                CertificateProfileCreation::new(
                    CertificatePolicyId::new(POLICY_ID).unwrap(),
                    CertificateProfileSlug::new(slug).unwrap(),
                    None,
                    CertificateProfileIssuer::CertificateAuthority(
                        CertificateAuthorityId::new(CA_ID).unwrap(),
                    ),
                    enrollment,
                    None,
                    None,
                )
                .unwrap(),
            )
        };

        let api_request = request_for(
            "api-profile",
            CertificateProfileEnrollmentConfiguration::Api {
                auto_renew: true,
                renew_before_days: Some(10),
            },
        );
        let api_profile = profile_from_value(profile_value("api-profile", "api", None, true));
        assert!(create_enrollment_reflected(&api_profile, &api_request));
        let mut drifted = api_profile;
        let Some(CertificateProfileEnrollmentMetadata::Api { auto_renew, .. }) =
            drifted.enrollment.as_mut()
        else {
            unreachable!();
        };
        *auto_renew = false;
        assert!(!create_enrollment_reflected(&drifted, &api_request));

        let est_request = request_for(
            "est-profile",
            CertificateProfileEnrollmentConfiguration::Est {
                disable_bootstrap_ca_validation: true,
                passphrase: crate::SecretValue::new("passphrase"),
                ca_chain: Some(CA_CERT.to_owned()),
            },
        );
        let mut est_profile = profile_from_value(profile_value("est-profile", "est", None, false));
        est_profile.enrollment = Some(CertificateProfileEnrollmentMetadata::Est {
            id: CONFIG_ID.to_owned(),
            disable_bootstrap_ca_validation: true,
            ca_chain: Some(CA_CERT.to_owned()),
        });
        assert!(create_enrollment_reflected(&est_profile, &est_request));
        let Some(CertificateProfileEnrollmentMetadata::Est { ca_chain, .. }) =
            est_profile.enrollment.as_mut()
        else {
            unreachable!();
        };
        *ca_chain = None;
        assert!(!create_enrollment_reflected(&est_profile, &est_request));

        let acme_request = request_for(
            "acme-profile",
            CertificateProfileEnrollmentConfiguration::Acme {
                skip_dns_ownership_verification: true,
                skip_eab_binding: false,
            },
        );
        let mut acme_profile =
            profile_from_value(profile_value("acme-profile", "acme", None, true));
        let Some(CertificateProfileEnrollmentMetadata::Acme {
            skip_dns_ownership_verification,
            ..
        }) = acme_profile.enrollment.as_mut()
        else {
            unreachable!();
        };
        *skip_dns_ownership_verification = true;
        assert!(create_enrollment_reflected(&acme_profile, &acme_request));
        let Some(CertificateProfileEnrollmentMetadata::Acme {
            skip_eab_binding, ..
        }) = acme_profile.enrollment.as_mut()
        else {
            unreachable!();
        };
        *skip_eab_binding = true;
        assert!(!create_enrollment_reflected(&acme_profile, &acme_request));

        let scep_request = request_for(
            "scep-profile",
            CertificateProfileEnrollmentConfiguration::Scep {
                challenge_type: CertificateProfileScepChallengeType::Dynamic,
                challenge_password: None,
                include_ca_cert_in_response: true,
                allow_cert_based_renewal: false,
                dynamic_challenge_expiry_minutes: 60,
                dynamic_challenge_max_pending: 10,
            },
        );
        let mut scep_profile =
            profile_from_value(profile_value("scep-profile", "api", None, false));
        scep_profile.enrollment_type = CertificateProfileEnrollmentType::Scep;
        scep_profile.enrollment = Some(CertificateProfileEnrollmentMetadata::Scep {
            id: CONFIG_ID.to_owned(),
            scep_endpoint_url: "https://server.example.test/scep".to_owned(),
            ra_certificate_pem: CA_CERT.to_owned(),
            ra_cert_expires_at: "2036-07-21T12:00:00.000Z".to_owned(),
            include_ca_cert_in_response: true,
            allow_cert_based_renewal: false,
            challenge_type: CertificateProfileScepChallengeType::Dynamic,
            challenge_endpoint_url: Some("https://server.example.test/challenge".to_owned()),
            dynamic_challenge_expiry_minutes: Some(60),
            dynamic_challenge_max_pending: Some(10),
        });
        assert!(create_enrollment_reflected(&scep_profile, &scep_request));
        let Some(CertificateProfileEnrollmentMetadata::Scep {
            dynamic_challenge_max_pending,
            ..
        }) = scep_profile.enrollment.as_mut()
        else {
            unreachable!();
        };
        *dynamic_challenge_max_pending = Some(11);
        assert!(!create_enrollment_reflected(&scep_profile, &scep_request));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn enrollment_update_reflection_preserves_every_omitted_field() {
        let base_profile =
            || profile_from_value(profile_value("api-profile", "api", Some("initial"), false));

        let mut before = base_profile();
        before.enrollment = Some(CertificateProfileEnrollmentMetadata::Api {
            id: CONFIG_ID.to_owned(),
            auto_renew: false,
            renew_before_days: None,
        });
        let mut request = empty_update_profile_request();
        request.api_config = Some(ApiConfigRequest {
            auto_renew: true,
            renew_before_days: Some(10),
        });
        let mut expected = before.clone();
        expected.enrollment = Some(CertificateProfileEnrollmentMetadata::Api {
            id: CONFIG_ID.to_owned(),
            auto_renew: true,
            renew_before_days: Some(10),
        });
        assert!(enrollment_update_reflected(&expected, &before, &request));

        let mut before = base_profile();
        before.enrollment_type = CertificateProfileEnrollmentType::Est;
        before.enrollment = Some(CertificateProfileEnrollmentMetadata::Est {
            id: CONFIG_ID.to_owned(),
            disable_bootstrap_ca_validation: false,
            ca_chain: None,
        });
        let mut request = empty_update_profile_request();
        request.est_config = Some(EstUpdateRequest {
            disable_bootstrap_ca_validation: true,
            passphrase: None,
            ca_chain: Some(CA_CERT.to_owned()),
        });
        let mut expected = before.clone();
        expected.enrollment = Some(CertificateProfileEnrollmentMetadata::Est {
            id: CONFIG_ID.to_owned(),
            disable_bootstrap_ca_validation: true,
            ca_chain: Some(CA_CERT.to_owned()),
        });
        assert!(enrollment_update_reflected(&expected, &before, &request));

        let mut before = base_profile();
        before.enrollment_type = CertificateProfileEnrollmentType::Acme;
        before.enrollment = Some(CertificateProfileEnrollmentMetadata::Acme {
            id: CONFIG_ID.to_owned(),
            directory_url: "https://server.example.test/acme".to_owned(),
            skip_dns_ownership_verification: false,
            skip_eab_binding: false,
        });
        let mut request = empty_update_profile_request();
        request.acme_config = Some(AcmeUpdateRequest {
            skip_dns_ownership_verification: Some(true),
            skip_eab_binding: None,
        });
        let mut expected = before.clone();
        expected.enrollment = Some(CertificateProfileEnrollmentMetadata::Acme {
            id: CONFIG_ID.to_owned(),
            directory_url: "https://server.example.test/acme".to_owned(),
            skip_dns_ownership_verification: true,
            skip_eab_binding: false,
        });
        assert!(enrollment_update_reflected(&expected, &before, &request));
        let Some(CertificateProfileEnrollmentMetadata::Acme { directory_url, .. }) =
            expected.enrollment.as_mut()
        else {
            unreachable!();
        };
        *directory_url = "https://unexpected.example.test/acme".to_owned();
        assert!(!enrollment_update_reflected(&expected, &before, &request));

        let mut before = base_profile();
        before.enrollment_type = CertificateProfileEnrollmentType::Scep;
        before.enrollment = Some(CertificateProfileEnrollmentMetadata::Scep {
            id: CONFIG_ID.to_owned(),
            scep_endpoint_url: "https://server.example.test/scep".to_owned(),
            ra_certificate_pem: CA_CERT.to_owned(),
            ra_cert_expires_at: "2036-07-21T12:00:00.000Z".to_owned(),
            include_ca_cert_in_response: false,
            allow_cert_based_renewal: false,
            challenge_type: CertificateProfileScepChallengeType::Dynamic,
            challenge_endpoint_url: Some("https://server.example.test/challenge".to_owned()),
            dynamic_challenge_expiry_minutes: Some(60),
            dynamic_challenge_max_pending: Some(10),
        });
        let mut request = empty_update_profile_request();
        request.scep_config = Some(ScepUpdateRequest {
            challenge_type: None,
            challenge_password: None,
            include_ca_cert_in_response: Some(true),
            allow_cert_based_renewal: None,
            dynamic_challenge_expiry_minutes: None,
            dynamic_challenge_max_pending: None,
        });
        let mut expected = before.clone();
        let Some(CertificateProfileEnrollmentMetadata::Scep {
            include_ca_cert_in_response,
            ..
        }) = expected.enrollment.as_mut()
        else {
            unreachable!();
        };
        *include_ca_cert_in_response = true;
        assert!(enrollment_update_reflected(&expected, &before, &request));

        let request = empty_update_profile_request();
        assert!(enrollment_update_reflected(&before, &before, &request));
        let mut drifted = before.clone();
        drifted.enrollment = None;
        assert!(!enrollment_update_reflected(&drifted, &before, &request));
    }

    #[test]
    fn enrollment_response_pem_accepts_and_canonicalizes_one_terminal_line_ending() {
        for terminal in ["\n", "\r\n"] {
            let est = enrollment_from_wire(
                CertificateProfileEnrollmentType::Est,
                CONFIG_ID,
                Some(EstConfigWire {
                    id: CONFIG_ID.to_owned(),
                    disable_bootstrap_ca_validation: false,
                    passphrase: None,
                    ca_chain: Some(format!("{CA_CERT}{terminal}")),
                }),
                None,
                None,
                None,
            )
            .unwrap()
            .unwrap();
            assert!(matches!(
                est,
                CertificateProfileEnrollmentMetadata::Est {
                    ca_chain: Some(chain),
                    ..
                } if chain == CA_CERT
            ));

            let scep = enrollment_from_wire(
                CertificateProfileEnrollmentType::Scep,
                CONFIG_ID,
                None,
                None,
                None,
                Some(ScepConfigWire {
                    id: CONFIG_ID.to_owned(),
                    scep_endpoint_url: "https://server.example.test/scep".to_owned(),
                    ra_certificate_pem: format!("{}{terminal}", profile_certificate_fixture()),
                    ra_cert_expires_at: "2037-01-01T00:00:00.000Z".to_owned(),
                    include_ca_cert_in_response: true,
                    allow_cert_based_renewal: true,
                    challenge_type: CertificateProfileScepChallengeType::Static,
                    challenge_endpoint_url: None,
                    dynamic_challenge_expiry_minutes: None,
                    dynamic_challenge_max_pending: None,
                }),
            )
            .unwrap()
            .unwrap();
            assert!(matches!(
                scep,
                CertificateProfileEnrollmentMetadata::Scep {
                    ra_certificate_pem,
                    ..
                } if ra_certificate_pem == profile_certificate_fixture()
            ));
        }
    }

    #[test]
    fn latest_bundle_pem_accepts_and_canonicalizes_one_terminal_line_ending() {
        let profile_id = CertificateProfileId::new(PROFILE_ID).unwrap();
        for terminal in ["\n", "\r\n"] {
            let certificate = format!("{}{terminal}", profile_certificate_fixture());
            let certificate_chain = format!("{}{terminal}", profile_issuer_certificate_fixture());
            let private_key = format!("{}{terminal}", profile_private_key_fixture());
            let bundle = bundle_from_wire(
                &profile_id,
                profile_bundle(
                    Some(&certificate),
                    Some(&certificate_chain),
                    Some(&private_key),
                    Some("A1B2"),
                ),
            )
            .unwrap()
            .unwrap();
            assert_eq!(bundle.certificate, profile_certificate_fixture());
            assert_eq!(
                bundle.certificate_chain,
                profile_issuer_certificate_fixture()
            );
            assert_eq!(
                bundle.private_key.expose_secret(),
                profile_private_key_fixture()
            );
        }
    }

    #[test]
    fn bundle_response_contract_accepts_only_complete_well_formed_values() {
        let profile_id = CertificateProfileId::new(PROFILE_ID).unwrap();
        assert!(
            bundle_from_wire(
                &profile_id,
                BundleWire {
                    certificate: None,
                    certificate_chain: None,
                    private_key: None,
                    serial_number: None,
                },
            )
            .unwrap()
            .is_none()
        );
        assert!(
            bundle_from_wire(
                &profile_id,
                profile_bundle(
                    Some(profile_certificate_fixture()),
                    Some(profile_issuer_certificate_fixture()),
                    Some(profile_private_key_fixture()),
                    Some("A1B2"),
                ),
            )
            .unwrap()
            .is_some()
        );
        for invalid in [
            profile_bundle(
                Some(profile_certificate_fixture()),
                None,
                Some(profile_private_key_fixture()),
                Some("A1B2"),
            ),
            profile_bundle(
                Some("not-a-certificate"),
                Some(profile_issuer_certificate_fixture()),
                Some(profile_private_key_fixture()),
                Some("A1B2"),
            ),
            profile_bundle(
                Some(profile_certificate_fixture()),
                Some("not-a-chain"),
                Some(profile_private_key_fixture()),
                Some("A1B2"),
            ),
            profile_bundle(
                Some(profile_certificate_fixture()),
                Some(profile_issuer_certificate_fixture()),
                Some("not-a-key"),
                Some("A1B2"),
            ),
            profile_bundle(
                Some(profile_certificate_fixture()),
                Some(profile_issuer_certificate_fixture()),
                Some("-----BEGIN PRIVATE KEY-----\nAQ==\n-----END PRIVATE KEY-----"),
                Some("A1B2"),
            ),
            profile_bundle(
                Some(profile_certificate_fixture()),
                Some(profile_issuer_certificate_fixture()),
                Some(profile_private_key_fixture()),
                Some(""),
            ),
            profile_bundle(
                Some(profile_certificate_fixture()),
                Some(profile_issuer_certificate_fixture()),
                Some(profile_private_key_fixture()),
                Some("not-hex"),
            ),
        ] {
            assert!(bundle_from_wire(&profile_id, invalid).is_err());
        }
    }

    #[test]
    fn bundle_response_contract_rejects_inconsistent_material() {
        let profile_id = CertificateProfileId::new(PROFILE_ID).unwrap();
        for invalid in [
            profile_bundle(
                Some(profile_certificate_fixture()),
                Some(profile_issuer_certificate_fixture()),
                Some(UNRELATED_PRIVATE_KEY),
                Some("A1B2"),
            ),
            profile_bundle(
                Some(profile_certificate_fixture()),
                Some(profile_issuer_certificate_fixture()),
                Some(profile_private_key_fixture()),
                Some("A1B3"),
            ),
            profile_bundle(
                Some(profile_certificate_fixture()),
                Some(CA_CERT),
                Some(profile_private_key_fixture()),
                Some("A1B2"),
            ),
            profile_bundle(
                Some(profile_certificate_fixture()),
                Some(""),
                Some(profile_private_key_fixture()),
                Some("A1B2"),
            ),
        ] {
            assert!(bundle_from_wire(&profile_id, invalid).is_err());
        }
    }

    #[test]
    fn bundle_response_contract_rejects_leaf_and_issuer_validity_drift() {
        let profile_id = CertificateProfileId::new(PROFILE_ID).unwrap();
        let leaf_der = certificate_bundle_der(profile_certificate_fixture())
            .unwrap()
            .pop()
            .unwrap();
        let (_, leaf) = X509Certificate::from_der(&leaf_der).unwrap();
        let issuer_der = certificate_bundle_der(profile_issuer_certificate_fixture())
            .unwrap()
            .pop()
            .unwrap();
        let (_, issuer) = X509Certificate::from_der(&issuer_der).unwrap();
        let before_leaf = ASN1Time::from_timestamp(leaf.validity().not_before.timestamp() - 1)
            .expect("fixture not-before must have a preceding timestamp");
        let after_issuer = ASN1Time::from_timestamp(issuer.validity().not_after.timestamp() + 1)
            .expect("fixture not-after must have a following timestamp");

        for validation_time in [before_leaf, after_issuer] {
            assert!(
                bundle_from_wire_at(
                    &profile_id,
                    profile_bundle(
                        Some(profile_certificate_fixture()),
                        Some(profile_issuer_certificate_fixture()),
                        Some(profile_private_key_fixture()),
                        Some("A1B2"),
                    ),
                    validation_time,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn private_key_matching_supports_each_pinned_der_family() {
        let rsa = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let rsa_der = AsDer::<Pkcs8V1Der<'static>>::as_der(&rsa).unwrap();
        let ec = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let elliptic_curve_der = ec.to_pkcs8v1().unwrap();
        let ed = Ed25519KeyPair::generate().unwrap();
        let ed25519_der = ed.to_pkcs8v1().unwrap();
        let ml44 = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).unwrap();
        let ml44_der = ml44.to_pkcs8v1().unwrap();
        let ml65 = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let ml65_der = ml65.to_pkcs8v1().unwrap();
        let ml87 = PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).unwrap();
        let ml87_der = ml87.to_pkcs8v1().unwrap();
        let cases = [
            (
                "1.2.840.113549.1.1.1",
                rsa_der.as_ref(),
                rsa.public_key().as_ref(),
            ),
            (
                "1.2.840.10045.2.1",
                elliptic_curve_der.as_ref(),
                ec.public_key().as_ref(),
            ),
            (
                "1.3.101.112",
                ed25519_der.as_ref(),
                ed.public_key().as_ref(),
            ),
            (
                "2.16.840.1.101.3.4.3.17",
                ml44_der.as_ref(),
                ml44.public_key().as_ref(),
            ),
            (
                "2.16.840.1.101.3.4.3.18",
                ml65_der.as_ref(),
                ml65.public_key().as_ref(),
            ),
            (
                "2.16.840.1.101.3.4.3.19",
                ml87_der.as_ref(),
                ml87.public_key().as_ref(),
            ),
        ];
        for (oid, der, public_key) in cases {
            assert!(private_key_der_matches_public_key(oid, public_key, der));
            let mut unrelated_public_key = public_key.to_vec();
            unrelated_public_key[0] ^= 1;
            assert!(!private_key_der_matches_public_key(
                oid,
                &unrelated_public_key,
                der,
            ));
        }
        assert!(!private_key_der_matches_public_key(
            "1.2.3.4",
            rsa.public_key().as_ref(),
            rsa_der.as_ref(),
        ));

        let rsa_pem = pem_rfc7468::encode_string(
            "PRIVATE KEY",
            pem_rfc7468::LineEnding::LF,
            rsa_der.as_ref(),
        )
        .unwrap();
        let certificate_der = certificate_bundle_der(profile_certificate_fixture())
            .unwrap()
            .pop()
            .unwrap();
        let (_, certificate) = X509Certificate::from_der(&certificate_der).unwrap();
        assert!(!private_key_matches_certificate(&certificate, &rsa_pem));
    }

    #[test]
    fn slh_dsa_oid_recognition_covers_the_defined_range() {
        for oid in [
            "2.16.840.1.101.3.4.3.20",
            "2.16.840.1.101.3.4.3.21",
            "2.16.840.1.101.3.4.3.22",
            "2.16.840.1.101.3.4.3.23",
            "2.16.840.1.101.3.4.3.24",
            "2.16.840.1.101.3.4.3.25",
            "2.16.840.1.101.3.4.3.26",
            "2.16.840.1.101.3.4.3.27",
            "2.16.840.1.101.3.4.3.28",
            "2.16.840.1.101.3.4.3.29",
            "2.16.840.1.101.3.4.3.30",
            "2.16.840.1.101.3.4.3.31",
        ] {
            assert!(is_slh_dsa_oid(oid));
        }
        for oid in [
            "2.16.840.1.101.3.4.3.19",
            "2.16.840.1.101.3.4.3.32",
            "2.16.840.1.101.3.4.3.20.1",
        ] {
            assert!(!is_slh_dsa_oid(oid));
        }
    }

    #[test]
    fn private_key_matching_supports_every_slh_dsa_parameter_set() {
        macro_rules! assert_parameter_set {
            ($module:ident, $oid:literal) => {{
                let (public_key, private_key) = fips205::$module::KG::keygen_with_seeds(
                    &[1; fips205::$module::N],
                    &[2; fips205::$module::N],
                    &[3; fips205::$module::N],
                );
                let public_key = public_key.into_bytes();
                let private_key = private_key.into_bytes();
                let algorithm = AlgorithmIdentifierRef {
                    oid: ObjectIdentifier::new_unwrap($oid),
                    parameters: None,
                };
                let mut der_buffer = [0_u8; 256];
                let der = PrivateKeyInfo::new(algorithm, &private_key)
                    .encode_to_slice(&mut der_buffer)
                    .unwrap();
                assert!(private_key_der_matches_public_key($oid, &public_key, &der,));
            }};
        }

        assert_parameter_set!(slh_dsa_sha2_128s, "2.16.840.1.101.3.4.3.20");
        assert_parameter_set!(slh_dsa_sha2_128f, "2.16.840.1.101.3.4.3.21");
        assert_parameter_set!(slh_dsa_sha2_192s, "2.16.840.1.101.3.4.3.22");
        assert_parameter_set!(slh_dsa_sha2_192f, "2.16.840.1.101.3.4.3.23");
        assert_parameter_set!(slh_dsa_sha2_256s, "2.16.840.1.101.3.4.3.24");
        assert_parameter_set!(slh_dsa_sha2_256f, "2.16.840.1.101.3.4.3.25");
        assert_parameter_set!(slh_dsa_shake_128s, "2.16.840.1.101.3.4.3.26");
        assert_parameter_set!(slh_dsa_shake_128f, "2.16.840.1.101.3.4.3.27");
        assert_parameter_set!(slh_dsa_shake_192s, "2.16.840.1.101.3.4.3.28");
        assert_parameter_set!(slh_dsa_shake_192f, "2.16.840.1.101.3.4.3.29");
        assert_parameter_set!(slh_dsa_shake_256s, "2.16.840.1.101.3.4.3.30");
        assert_parameter_set!(slh_dsa_shake_256f, "2.16.840.1.101.3.4.3.31");
    }

    #[test]
    fn slh_dsa_matching_rejects_unrelated_and_corrupt_private_keys() {
        const OID: &str = "2.16.840.1.101.3.4.3.21";
        let (public_key, private_key) = fips205::slh_dsa_sha2_128f::KG::keygen_with_seeds(
            &[1; fips205::slh_dsa_sha2_128f::N],
            &[2; fips205::slh_dsa_sha2_128f::N],
            &[3; fips205::slh_dsa_sha2_128f::N],
        );
        let public_key = public_key.into_bytes();
        let private_key = private_key.into_bytes();
        let algorithm = AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap(OID),
            parameters: None,
        };
        let mut der_buffer = [0_u8; 256];
        let der = PrivateKeyInfo::new(algorithm, &private_key)
            .encode_to_slice(&mut der_buffer)
            .unwrap();
        let mut unrelated_public_key = public_key;
        unrelated_public_key[0] ^= 1;
        assert!(!private_key_der_matches_public_key(
            OID,
            &unrelated_public_key,
            der,
        ));

        let mut corrupt_private_key = private_key;
        corrupt_private_key[0] ^= 1;
        let mut corrupt_der_buffer = [0_u8; 256];
        let corrupt_der = PrivateKeyInfo::new(algorithm, &corrupt_private_key)
            .encode_to_slice(&mut corrupt_der_buffer)
            .unwrap();
        assert!(!private_key_der_matches_public_key(
            OID,
            &public_key,
            corrupt_der,
        ));

        let algorithm_with_parameters = AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap(OID),
            parameters: Some(AnyRef::NULL),
        };
        let mut parameterized_der_buffer = [0_u8; 256];
        let parameterized_der = PrivateKeyInfo::new(algorithm_with_parameters, &private_key)
            .encode_to_slice(&mut parameterized_der_buffer)
            .unwrap();
        assert!(!private_key_der_matches_public_key(
            OID,
            &public_key,
            parameterized_der,
        ));
    }

    #[test]
    fn eab_response_contract_rejects_partial_or_malformed_values() {
        let profile_id = CertificateProfileId::new(PROFILE_ID).unwrap();
        for secret in ["a".to_owned(), "a".repeat(MAX_PROFILE_SECRET_BYTES)] {
            assert!(
                eab_from_wire(
                    &profile_id,
                    EabWire {
                        eab_kid: "kid".to_owned(),
                        eab_secret: crate::SecretValue::new(secret),
                    },
                )
                .is_ok()
            );
        }
        for (kid, secret) in [
            ("", "a".to_owned()),
            ("kid", String::new()),
            ("kid", "a".repeat(MAX_PROFILE_SECRET_BYTES + 1)),
        ] {
            assert!(
                eab_from_wire(
                    &profile_id,
                    EabWire {
                        eab_kid: kid.to_owned(),
                        eab_secret: crate::SecretValue::new(secret),
                    },
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn confirmations_fail_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let profile_id = CertificateProfileId::new(PROFILE_ID).unwrap();
        let creation = CertificateProfileCreation::new(
            CertificatePolicyId::new(POLICY_ID).unwrap(),
            CertificateProfileSlug::new("api-profile").unwrap(),
            None,
            CertificateProfileIssuer::CertificateAuthority(
                CertificateAuthorityId::new(CA_ID).unwrap(),
            ),
            CertificateProfileEnrollmentConfiguration::Api {
                auto_renew: false,
                renew_before_days: None,
            },
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            client
                .create_certificate_profile(&project_id, creation, false)
                .await
                .unwrap_err(),
            ResourceError::CertificateProfileCreateNotConfirmed
        );
        let change = CertificateProfileChange::new(
            None,
            Some(CertificateProfileDescriptionChange::Clear),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            client
                .update_certificate_profile(&project_id, &profile_id, change, false)
                .await
                .unwrap_err(),
            ResourceError::CertificateProfileUpdateNotConfirmed
        );
        assert_eq!(
            client
                .delete_certificate_profile(&project_id, &profile_id, false)
                .await
                .unwrap_err(),
            ResourceError::CertificateProfileDeleteNotConfirmed
        );
        assert_eq!(
            client
                .reveal_certificate_profile_latest_bundle(&project_id, &profile_id, false)
                .await
                .unwrap_err(),
            ResourceError::CertificateProfileSecretRevealNotConfirmed
        );
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn azure_templates_require_a_preflighted_azure_ca_before_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "profile-provider-token").await;
        mount_project(&server).await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{POLICY_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": policy_value()
            })))
            .expect(1)
            .mount(&server)
            .await;
        let ca_preflight_count = Arc::new(AtomicUsize::new(0));
        let responder_count = ca_preflight_count.clone();
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/ca"))
            .and(query_param("projectId", PROJECT_ID))
            .respond_with(move |_: &wiremock::Request| {
                responder_count.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({
                    "certificateAuthorities": [
                        {
                            "id": "77777777-7777-4777-8777-777777777777",
                            "projectId": PROJECT_ID,
                            "name": "unrelated-azure-ca",
                            "type": "azure-ad-cs",
                            "status": "active",
                            "enableDirectIssuance": false
                        },
                        {
                            "id": CA_ID,
                            "projectId": PROJECT_ID,
                            "name": "root-ca",
                            "type": "internal",
                            "status": "active",
                            "enableDirectIssuance": false
                        }
                    ]
                }))
            })
            .expect(2)
            .mount(&server)
            .await;
        let responder_count = ca_preflight_count;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{PROFILE_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                if responder_count.load(Ordering::SeqCst) == 2 {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "certificateProfile": profile_value("api-profile", "api", None, true)
                    }))
                } else {
                    ResponseTemplate::new(409)
                }
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificate-profiles"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{PROFILE_ID}"
            )))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let external = CertificateProfileExternalConfig::new(Some("template".to_owned())).unwrap();
        let creation = CertificateProfileCreation::new(
            CertificatePolicyId::new(POLICY_ID).unwrap(),
            CertificateProfileSlug::new("api-profile").unwrap(),
            None,
            CertificateProfileIssuer::CertificateAuthority(
                CertificateAuthorityId::new(CA_ID).unwrap(),
            ),
            CertificateProfileEnrollmentConfiguration::Api {
                auto_renew: false,
                renew_before_days: None,
            },
            Some(external.clone()),
            None,
        )
        .unwrap();
        assert_eq!(
            client
                .create_certificate_profile(&project_id, creation, true)
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateProfileState
        );

        let change = CertificateProfileChange::new(
            None,
            None,
            None,
            Some(CertificateProfileExternalConfigChange::Set(external)),
            None,
        )
        .unwrap();
        assert_eq!(
            client
                .update_certificate_profile(
                    &project_id,
                    &CertificateProfileId::new(PROFILE_ID).unwrap(),
                    change,
                    true,
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateProfileState
        );
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn create_update_and_delete_use_exact_preflights_and_mutations() {
        let server = MockServer::start().await;
        mount_login(&server, "profile-lifecycle-token").await;
        mount_project(&server).await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{POLICY_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": policy_value()
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/ca"))
            .and(query_param("projectId", PROJECT_ID))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateAuthorities": [{
                    "id": CA_ID,
                    "projectId": PROJECT_ID,
                    "name": "root-ca",
                    "type": "internal",
                    "status": "active",
                    "enableDirectIssuance": false
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let created = profile_value("api-profile", "api", Some("initial"), true);
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificate-profiles"))
            .and(body_json(json!({
                "projectId": PROJECT_ID,
                "caId": CA_ID,
                "certificatePolicyId": POLICY_ID,
                "slug": "api-profile",
                "description": "initial",
                "enrollmentType": "api",
                "issuerType": "ca",
                "apiConfig": { "autoRenew": true, "renewBeforeDays": 10 }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateProfile": created
            })))
            .expect(1)
            .mount(&server)
            .await;

        let updated = profile_value("api-profile", "api", Some("updated"), true);
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{PROFILE_ID}"
            )))
            .and(body_json(json!({
                "description": "updated",
                "apiConfig": { "autoRenew": true, "renewBeforeDays": 10 }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateProfile": updated.clone()
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{PROFILE_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateProfile": profile_value("api-profile", "api", Some("updated"), true)
            })))
            .expect(3)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{PROFILE_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateProfile": updated
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let profile_id = CertificateProfileId::new(PROFILE_ID).unwrap();
        let creation = CertificateProfileCreation::new(
            CertificatePolicyId::new(POLICY_ID).unwrap(),
            CertificateProfileSlug::new("api-profile").unwrap(),
            Some("initial".to_owned()),
            CertificateProfileIssuer::CertificateAuthority(
                CertificateAuthorityId::new(CA_ID).unwrap(),
            ),
            CertificateProfileEnrollmentConfiguration::Api {
                auto_renew: true,
                renew_before_days: Some(10),
            },
            None,
            None,
        )
        .unwrap();
        let created = client
            .create_certificate_profile(&project_id, creation, true)
            .await
            .unwrap();
        assert_eq!(created.id, PROFILE_ID);

        let change = CertificateProfileChange::new(
            None,
            Some(CertificateProfileDescriptionChange::Set(
                "updated".to_owned(),
            )),
            Some(CertificateProfileEnrollmentChange::Api {
                auto_renew: true,
                renew_before_days: Some(10),
            }),
            None,
            None,
        )
        .unwrap();
        let updated = client
            .update_certificate_profile(&project_id, &profile_id, change, true)
            .await
            .unwrap();
        assert_eq!(updated.description.as_deref(), Some("updated"));
        let deleted = client
            .delete_certificate_profile(&project_id, &profile_id, true)
            .await
            .unwrap();
        assert_eq!(deleted.description.as_deref(), Some("updated"));
    }

    #[tokio::test]
    async fn response_rebinding_profile_list_rejects_every_upstream_filter_drift() {
        let server = MockServer::start().await;
        mount_login(&server, "profile-filter-token").await;
        for (name, value) in [
            ("enrollmentType", "acme"),
            ("issuerType", "self-signed"),
            ("caId", OTHER_ID),
            ("applicationId", APPLICATION_ID),
        ] {
            Mock::given(method("GET"))
                .and(path("/api/v1/cert-manager/certificate-profiles"))
                .and(query_param("projectId", PROJECT_ID))
                .and(query_param("offset", "0"))
                .and(query_param("limit", "20"))
                .and(query_param(name, value))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "certificateProfiles": [profile_value("api-profile", "api", None, true)],
                    "totalCount": 1
                })))
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/applications/{APPLICATION_ID}/profiles"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "profiles": [{
                    "applicationId": APPLICATION_ID,
                    "profileId": OTHER_ID,
                    "profileSlug": "other-profile",
                    "createdAt": "2026-07-21T12:00:00.000Z",
                    "updatedAt": "2026-07-21T12:00:01.000Z"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let page = PageRequest::new(0, 20).unwrap();
        let drifted_requests = [
            CertificateProfileListRequest::new(
                project_id.clone(),
                page,
                None,
                Some(CertificateProfileEnrollmentType::Acme),
                None,
                None,
                None,
            )
            .unwrap(),
            CertificateProfileListRequest::new(
                project_id.clone(),
                page,
                None,
                None,
                Some(CertificateProfileIssuerType::SelfSigned),
                None,
                None,
            )
            .unwrap(),
            CertificateProfileListRequest::new(
                project_id.clone(),
                page,
                None,
                None,
                None,
                Some(CertificateAuthorityId::new(OTHER_ID).unwrap()),
                None,
            )
            .unwrap(),
            CertificateProfileListRequest::new(
                project_id,
                page,
                None,
                None,
                None,
                None,
                Some(CertificateProfileApplicationId::new(APPLICATION_ID).unwrap()),
            )
            .unwrap(),
        ];
        for request in drifted_requests {
            assert_eq!(
                client.list_certificate_profiles(request).await.unwrap_err(),
                ResourceError::InvalidCertificateProfileScope
            );
        }
    }

    #[tokio::test]
    async fn response_rebinding_empty_application_page_skips_relationship_read() {
        let server = MockServer::start().await;
        mount_login(&server, "profile-empty-application-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/certificate-profiles"))
            .and(query_param("projectId", PROJECT_ID))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "20"))
            .and(query_param("applicationId", OTHER_ID))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateProfiles": [],
                "totalCount": 0
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let empty = client
            .list_certificate_profiles(
                CertificateProfileListRequest::new(
                    CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                    PageRequest::new(0, 20).unwrap(),
                    None,
                    None,
                    None,
                    None,
                    Some(CertificateProfileApplicationId::new(OTHER_ID).unwrap()),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(empty.items.is_empty());
    }

    #[tokio::test]
    async fn response_rebinding_certificate_list_rejects_upstream_status_drift() {
        let server = MockServer::start().await;
        mount_login(&server, "profile-certificate-filter-token").await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{PROFILE_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateProfile": profile_value("api-profile", "api", None, true)
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{PROFILE_ID}/certificates"
            )))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "20"))
            .and(query_param("status", "revoked"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [{
                    "id": CERTIFICATE_ID,
                    "serialNumber": "A1B2",
                    "cn": "service.example.test",
                    "status": "active",
                    "notBefore": "2026-07-21T12:00:00.000Z",
                    "notAfter": "2027-07-21T12:00:00.000Z",
                    "revokedAt": null,
                    "createdAt": "2026-07-21T12:00:00.000Z"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert_eq!(
            client
                .list_certificate_profile_certificates(
                    CertificateProfileCertificateListRequest::new(
                        CertificateAuthorityProjectId::new(PROJECT_ID).unwrap(),
                        CertificateProfileId::new(PROFILE_ID).unwrap(),
                        PageRequest::new(0, 20).unwrap(),
                        Some(CertificateProfileCertificateStatus::Revoked),
                        None,
                    )
                    .unwrap(),
                )
                .await
                .unwrap_err(),
            ResourceError::InvalidCertificateProfileScope
        );
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn all_read_routes_are_bounded_scoped_and_secret_explicit() {
        let server = MockServer::start().await;
        mount_login(&server, "profile-read-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/certificate-profiles"))
            .and(query_param("projectId", PROJECT_ID))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "20"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateProfiles": [profile_value("est-profile", "est", None, true)],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/cert-manager/certificate-profiles/slug/acme-profile",
            ))
            .and(query_param("projectId", PROJECT_ID))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateProfile": profile_value("acme-profile", "acme", None, false)
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{PROFILE_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateProfile": profile_value("acme-profile", "acme", None, true)
            })))
            .expect(3)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{PROFILE_ID}/certificates"
            )))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "20"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [{
                    "id": CERTIFICATE_ID,
                    "serialNumber": "A1B2",
                    "cn": "service.example.test",
                    "status": "active",
                    "notBefore": "2026-07-21T12:00:00.000Z",
                    "notAfter": "2027-07-21T12:00:00.000Z",
                    "revokedAt": null,
                    "createdAt": "2026-07-21T12:00:00.000Z"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{PROFILE_ID}/certificates/latest-active-bundle"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": profile_certificate_fixture(),
                "certificateChain": profile_issuer_certificate_fixture(),
                "privateKey": profile_private_key_fixture(),
                "serialNumber": "A1B2"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{PROFILE_ID}/acme/eab-secret/reveal"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "eabKid": "kid-123",
                "eabSecret": "eab-secret-canary"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = CertificateAuthorityProjectId::new(PROJECT_ID).unwrap();
        let profile_id = CertificateProfileId::new(PROFILE_ID).unwrap();
        let profiles = client
            .list_certificate_profiles(
                CertificateProfileListRequest::new(
                    project_id.clone(),
                    PageRequest::new(0, 20).unwrap(),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let serialized = serde_json::to_string(&profiles).unwrap();
        assert!(!serialized.contains("profile-passphrase-canary"));
        assert_eq!(
            profiles.items[0].enrollment_type,
            CertificateProfileEnrollmentType::Est
        );
        let by_slug = client
            .get_certificate_profile_by_slug(
                &project_id,
                &CertificateProfileSlug::new("acme-profile").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(by_slug.id, PROFILE_ID);
        let certificates = client
            .list_certificate_profile_certificates(
                CertificateProfileCertificateListRequest::new(
                    project_id.clone(),
                    profile_id.clone(),
                    PageRequest::new(0, 20).unwrap(),
                    None,
                    None,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(certificates.items[0].serial_number, "A1B2");
        let bundle = client
            .reveal_certificate_profile_latest_bundle(&project_id, &profile_id, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            bundle.private_key.expose_secret(),
            profile_private_key_fixture()
        );
        assert!(!format!("{bundle:?}").contains(profile_private_key_fixture()));
        let eab = client
            .reveal_certificate_profile_eab_secret(&project_id, &profile_id, true)
            .await
            .unwrap();
        assert_eq!(eab.eab_secret.expose_secret(), "eab-secret-canary");
        assert!(!format!("{eab:?}").contains("eab-secret-canary"));
    }
}
