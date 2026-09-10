use std::{collections::HashSet, time::UNIX_EPOCH};

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ssh_key::{
    Certificate as ParsedSshCertificate, HashAlg, PrivateKey as ParsedSshPrivateKey,
    PublicKey as ParsedSshPublicKey, certificate::CertType,
};
use thiserror::Error;

use crate::{
    InfisicalClient, MutationOperation, ResourceError, SecretValue, SshCaStatus,
    SshCertificateAuthority, SshCertificateAuthorityId, SshCertificateTemplate,
    SshCertificateTemplateId, SshCertificateTemplateStatus, SshDuration, SshKeyAlgorithm,
    SshProjectId, SshPublicKey,
    client::{ApiVersion, DeserializedSecret, Endpoint, sealed},
    ssh_certificate_templates::{valid_host_pattern, valid_user_pattern},
};

const MAX_SSH_CERTIFICATE_PRINCIPALS: usize = 128;
const MAX_SSH_CERTIFICATE_KEY_ID_BYTES: usize = 50;
const MAX_SSH_SIGNED_KEY_BYTES: usize = 131_072;
const MAX_SSH_ISSUED_PRIVATE_KEY_BYTES: usize = 131_072;
const SSH_KEYGEN_MAX_BACKDATE_SECONDS: u64 = 120;
const OPENSSH_USER_CERTIFICATE_EXTENSIONS: [&str; 5] = [
    "permit-X11-forwarding",
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-pty",
    "permit-user-rc",
];

/// Input validation failures for SSH certificate signing and issuance.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SshCertificateInputError {
    #[error("SSH certificates require 1 to 128 unique bounded principals")]
    InvalidPrincipals,
    #[error(
        "SSH certificate key IDs must contain 1 to 50 alphanumeric, hyphen, colon, or period characters"
    )]
    InvalidKeyId,
}

/// OpenSSH certificate identity type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SshCertificateType {
    /// A certificate authenticating one or more users.
    User,
    /// A certificate authenticating one or more hosts.
    Host,
}

impl SshCertificateType {
    const fn parsed(self) -> CertType {
        match self {
            Self::User => CertType::User,
            Self::Host => CertType::Host,
        }
    }
}

/// Shared, locally validated SSH certificate request policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCertificateRequest {
    certificate_type: SshCertificateType,
    principals: Vec<String>,
    ttl: Option<SshDuration>,
    key_id: Option<String>,
}

impl SshCertificateRequest {
    /// Validate bounded principals and an optional custom key ID before any upstream call.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, duplicate, or excessive principals or key IDs.
    pub fn new(
        certificate_type: SshCertificateType,
        principals: Vec<String>,
        ttl: Option<SshDuration>,
        key_id: Option<String>,
    ) -> Result<Self, SshCertificateInputError> {
        if principals.is_empty()
            || principals.len() > MAX_SSH_CERTIFICATE_PRINCIPALS
            || principals
                .iter()
                .any(|principal| !valid_principal(certificate_type, principal))
            || principals.iter().collect::<HashSet<_>>().len() != principals.len()
        {
            return Err(SshCertificateInputError::InvalidPrincipals);
        }
        if key_id.as_deref().is_some_and(|value| !valid_key_id(value)) {
            return Err(SshCertificateInputError::InvalidKeyId);
        }
        Ok(Self {
            certificate_type,
            principals,
            ttl,
            key_id,
        })
    }
}

/// A request to sign an existing supported OpenSSH public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCertificateSignRequest {
    public_key: SshPublicKey,
    certificate: SshCertificateRequest,
}

impl SshCertificateSignRequest {
    /// Combine a structurally validated public key with a validated certificate policy.
    #[must_use]
    pub const fn new(public_key: SshPublicKey, certificate: SshCertificateRequest) -> Self {
        Self {
            public_key,
            certificate,
        }
    }
}

/// A request to generate a new key pair and issue its SSH certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCertificateIssueRequest {
    key_algorithm: SshKeyAlgorithm,
    certificate: SshCertificateRequest,
}

impl SshCertificateIssueRequest {
    /// Combine a pinned key algorithm with a validated certificate policy.
    #[must_use]
    pub const fn new(key_algorithm: SshKeyAlgorithm, certificate: SshCertificateRequest) -> Self {
        Self {
            key_algorithm,
            certificate,
        }
    }
}

/// A verified certificate signed by the requested Infisical SSH CA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SignedSshCertificate {
    /// Canonical unsigned 64-bit decimal serial, kept as text to preserve JSON precision.
    #[schemars(regex(pattern = r"^(?:0|[1-9][0-9]{0,19})$"))]
    pub serial_number: String,
    /// Canonical OpenSSH certificate line whose signature and requested semantics were verified.
    pub signed_key: String,
}

/// A verified SSH certificate plus its newly generated key pair.
#[derive(Debug)]
pub struct IssuedSshCertificate {
    pub serial_number: String,
    pub signed_key: String,
    pub private_key: SecretValue,
    pub public_key: String,
    pub key_algorithm: SshKeyAlgorithm,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignSshCertificateRequest {
    certificate_template_id: String,
    public_key: String,
    cert_type: SshCertificateType,
    principals: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IssueSshCertificateRequest {
    certificate_template_id: String,
    key_algorithm: SshKeyAlgorithm,
    cert_type: SshCertificateType,
    principals: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignedSshCertificateWire {
    pub(crate) serial_number: String,
    pub(crate) signed_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssuedSshCertificateWire {
    serial_number: String,
    signed_key: String,
    private_key: DeserializedSecret,
    public_key: String,
    key_algorithm: SshKeyAlgorithm,
}

struct SignSshCertificate;
impl sealed::Sealed for SignSshCertificate {}
impl MutationOperation for SignSshCertificate {
    type Input = SignSshCertificateRequest;
    type Output = SignedSshCertificateWire;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["ssh", "certificates", "sign"])
    }
}

struct IssueSshCertificate;
impl sealed::Sealed for IssueSshCertificate {}
impl MutationOperation for IssueSshCertificate {
    type Input = IssueSshCertificateRequest;
    type Output = IssuedSshCertificateWire;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(ApiVersion::V1, ["ssh", "certificates", "issue"])
    }
}

fn valid_principal(certificate_type: SshCertificateType, value: &str) -> bool {
    match certificate_type {
        SshCertificateType::User => value != "*" && valid_user_pattern(value),
        SshCertificateType::Host => !value.contains('*') && valid_host_pattern(value),
    }
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SSH_CERTIFICATE_KEY_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b':' | b'.'))
}

fn valid_signed_key_size(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_SSH_SIGNED_KEY_BYTES
}

fn valid_issued_private_key_size(value: &str) -> bool {
    value.len() <= MAX_SSH_ISSUED_PRIVATE_KEY_BYTES
}

fn principal_is_allowed(
    certificate_type: SshCertificateType,
    principal: &str,
    template: &SshCertificateTemplate,
) -> bool {
    match certificate_type {
        SshCertificateType::User => {
            principal != "*"
                && if template.allowed_users.iter().any(|allowed| allowed == "*") {
                    valid_user_pattern(principal)
                } else {
                    template
                        .allowed_users
                        .iter()
                        .any(|allowed| allowed == principal)
                }
        }
        SshCertificateType::Host => {
            !principal.contains('*')
                && if template.allowed_hosts.iter().any(|allowed| allowed == "*") {
                    valid_host_pattern(principal)
                } else {
                    template.allowed_hosts.iter().any(|allowed| {
                        allowed.strip_prefix("*.").map_or_else(
                            || allowed == principal,
                            |domain| principal.ends_with(&format!(".{domain}")),
                        )
                    })
                }
        }
    }
}

fn validate_request_policy(
    authority: &SshCertificateAuthority,
    template: &SshCertificateTemplate,
    request: &SshCertificateRequest,
) -> Result<u64, ResourceError> {
    if authority.status != SshCaStatus::Active {
        return Err(ResourceError::InvalidSshCertificateAuthorityState);
    }
    if template.status != SshCertificateTemplateStatus::Active {
        return Err(ResourceError::InvalidSshCertificateTemplateState);
    }
    let type_allowed = match request.certificate_type {
        SshCertificateType::User => template.allow_user_certificates,
        SshCertificateType::Host => template.allow_host_certificates,
    };
    if !type_allowed {
        return Err(ResourceError::SshCertificateTypeNotAllowed);
    }
    if request
        .principals
        .iter()
        .any(|principal| !principal_is_allowed(request.certificate_type, principal, template))
    {
        return Err(ResourceError::SshCertificatePrincipalNotAllowed);
    }
    if request.key_id.is_some() && !template.allow_custom_key_ids {
        return Err(ResourceError::SshCertificateCustomKeyIdNotAllowed);
    }
    let ttl = request.ttl.as_ref().unwrap_or(&template.ttl);
    if ttl.millis() > template.max_ttl.millis() {
        return Err(ResourceError::SshCertificateTtlNotAllowed);
    }
    Ok(ttl.millis().div_ceil(1_000))
}

pub(crate) fn unix_timestamp() -> Result<u64, ResourceError> {
    UNIX_EPOCH
        .elapsed()
        .map(|duration| duration.as_secs())
        .map_err(|_| ResourceError::InvalidSshCertificateResponse)
}

fn certificate_validity_within_bounds(
    valid_after: u64,
    valid_before: u64,
    expected_ttl_seconds: u64,
    request_started_at: u64,
    response_received_at: u64,
) -> bool {
    let Some(validity_seconds) = valid_before.checked_sub(valid_after) else {
        return false;
    };
    // ssh-keygen backdates valid-after by one minute and rounds to a minute boundary. That
    // past-only skew must not extend how long the certificate remains usable after receipt.
    let minimum_valid_after = request_started_at.saturating_sub(SSH_KEYGEN_MAX_BACKDATE_SECONDS);
    let minimum_expiry = request_started_at.saturating_add(expected_ttl_seconds);
    let maximum_expiry = response_received_at.saturating_add(expected_ttl_seconds);
    validity_seconds >= expected_ttl_seconds
        && valid_after >= minimum_valid_after
        && valid_after <= response_received_at
        && valid_before >= minimum_expiry
        && valid_before <= maximum_expiry
}

fn certificate_authorization_fields_match(
    certificate: &ParsedSshCertificate,
    certificate_type: SshCertificateType,
) -> bool {
    if !certificate.critical_options().is_empty() {
        return false;
    }
    match certificate_type {
        SshCertificateType::User => {
            certificate.extensions().len() == OPENSSH_USER_CERTIFICATE_EXTENSIONS.len()
                && OPENSSH_USER_CERTIFICATE_EXTENSIONS.iter().all(|name| {
                    certificate
                        .extensions()
                        .get(*name)
                        .is_some_and(String::is_empty)
                })
        }
        SshCertificateType::Host => certificate.extensions().is_empty(),
    }
}

fn effective_certificate_ttl<'a>(
    template: &'a SshCertificateTemplate,
    request: &'a SshCertificateRequest,
) -> &'a SshDuration {
    // An explicit effective TTL prevents a concurrent template-default change from silently
    // altering the certificate created by the mutation.
    request.ttl.as_ref().unwrap_or(&template.ttl)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_signed_certificate(
    wire: SignedSshCertificateWire,
    authority: &SshCertificateAuthority,
    subject_public_key: &SshPublicKey,
    request: &SshCertificateRequest,
    expected_ttl_seconds: u64,
    request_started_at: u64,
    response_received_at: u64,
) -> Result<SignedSshCertificate, ResourceError> {
    let serial = wire
        .serial_number
        .parse::<u64>()
        .map_err(|_| ResourceError::InvalidSshCertificateResponse)?;
    if serial.to_string() != wire.serial_number || !valid_signed_key_size(&wire.signed_key) {
        return Err(ResourceError::InvalidSshCertificateResponse);
    }
    let certificate = ParsedSshCertificate::from_openssh(wire.signed_key.trim())
        .map_err(|_| ResourceError::InvalidSshCertificateResponse)?;
    let ca_public_key = ParsedSshPublicKey::from_openssh(authority.public_key.as_str())
        .map_err(|_| ResourceError::InvalidSshCertificateResponse)?;
    let subject_public_key = ParsedSshPublicKey::from_openssh(subject_public_key.as_str())
        .map_err(|_| ResourceError::InvalidSshCertificateResponse)?;
    let ca_fingerprint = ca_public_key.fingerprint(HashAlg::Sha256);
    if certificate.serial() != serial
        || certificate.cert_type() != request.certificate_type.parsed()
        || certificate.valid_principals() != request.principals
        || certificate.public_key() != subject_public_key.key_data()
        || certificate.signature_key() != ca_public_key.key_data()
        || request.key_id.as_deref().map_or_else(
            || !valid_key_id(certificate.key_id()),
            |key_id| certificate.key_id() != key_id,
        )
        || !certificate_authorization_fields_match(&certificate, request.certificate_type)
        || certificate
            .validate_at(response_received_at, [&ca_fingerprint])
            .is_err()
    {
        return Err(ResourceError::InvalidSshCertificateResponse);
    }
    if !certificate_validity_within_bounds(
        certificate.valid_after(),
        certificate.valid_before(),
        expected_ttl_seconds,
        request_started_at,
        response_received_at,
    ) {
        return Err(ResourceError::InvalidSshCertificateResponse);
    }
    let signed_key = certificate
        .to_openssh()
        .map_err(|_| ResourceError::InvalidSshCertificateResponse)?;
    Ok(SignedSshCertificate {
        serial_number: wire.serial_number,
        signed_key,
    })
}

fn sign_request(
    template_id: &SshCertificateTemplateId,
    request: &SshCertificateSignRequest,
    effective_ttl: &SshDuration,
) -> SignSshCertificateRequest {
    SignSshCertificateRequest {
        certificate_template_id: template_id.as_str().to_owned(),
        public_key: request.public_key.as_str().to_owned(),
        cert_type: request.certificate.certificate_type,
        principals: request.certificate.principals.clone(),
        ttl: Some(effective_ttl.as_str().to_owned()),
        key_id: request.certificate.key_id.clone(),
    }
}

fn issue_request(
    template_id: &SshCertificateTemplateId,
    request: &SshCertificateIssueRequest,
    effective_ttl: &SshDuration,
) -> IssueSshCertificateRequest {
    IssueSshCertificateRequest {
        certificate_template_id: template_id.as_str().to_owned(),
        key_algorithm: request.key_algorithm,
        cert_type: request.certificate.certificate_type,
        principals: request.certificate.principals.clone(),
        ttl: Some(effective_ttl.as_str().to_owned()),
        key_id: request.certificate.key_id.clone(),
    }
}

fn validate_issued_key_pair(
    private_key: DeserializedSecret,
    public_key: String,
    expected_algorithm: SshKeyAlgorithm,
) -> Result<(SecretValue, SshPublicKey), ResourceError> {
    let public_key =
        SshPublicKey::new(public_key).map_err(|_| ResourceError::InvalidSshCertificateResponse)?;
    if !public_key.matches_algorithm(expected_algorithm)
        || !valid_issued_private_key_size(private_key.0.expose_secret())
    {
        return Err(ResourceError::InvalidSshCertificateResponse);
    }
    let parsed_private_key = ParsedSshPrivateKey::from_openssh(private_key.0.expose_secret())
        .map_err(|_| ResourceError::InvalidSshCertificateResponse)?;
    let parsed_public_key = ParsedSshPublicKey::from_openssh(public_key.as_str())
        .map_err(|_| ResourceError::InvalidSshCertificateResponse)?;
    if parsed_private_key.is_encrypted()
        || parsed_private_key.public_key().key_data() != parsed_public_key.key_data()
    {
        return Err(ResourceError::InvalidSshCertificateResponse);
    }
    Ok((private_key.0, public_key))
}

impl InfisicalClient {
    /// Sign one existing SSH public key after exact ownership and template-policy preflights.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, input-policy, scope, state, client, or signed-response error.
    /// The signing mutation is sent exactly once and is never replayed.
    pub async fn sign_ssh_certificate(
        &self,
        project_id: &SshProjectId,
        ca_id: &SshCertificateAuthorityId,
        template_id: &SshCertificateTemplateId,
        request: &SshCertificateSignRequest,
        confirm: bool,
    ) -> Result<SignedSshCertificate, ResourceError> {
        if !confirm {
            return Err(ResourceError::SshCertificateSigningNotConfirmed);
        }
        let (authority, template) = self
            .preflight_ssh_certificate_template(project_id, ca_id, template_id)
            .await?;
        let expected_ttl_seconds =
            validate_request_policy(&authority, &template, &request.certificate)?;
        let effective_ttl = effective_certificate_ttl(&template, &request.certificate);
        let request_started_at = unix_timestamp()?;
        let response = self
            .execute_mutation::<SignSshCertificate>(&sign_request(
                template_id,
                request,
                effective_ttl,
            ))
            .await?;
        let response_received_at = unix_timestamp()?;
        validate_signed_certificate(
            response,
            &authority,
            &request.public_key,
            &request.certificate,
            expected_ttl_seconds,
            request_started_at,
            response_received_at,
        )
    }

    /// Generate one SSH key pair and issue its certificate after exact policy preflights.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, input-policy, scope, state, client, key-pair, or signed-response
    /// error. The issuance mutation is sent exactly once and is never replayed.
    pub async fn issue_ssh_certificate(
        &self,
        project_id: &SshProjectId,
        ca_id: &SshCertificateAuthorityId,
        template_id: &SshCertificateTemplateId,
        request: &SshCertificateIssueRequest,
        confirm_reveal: bool,
    ) -> Result<IssuedSshCertificate, ResourceError> {
        if !confirm_reveal {
            return Err(ResourceError::SshCertificateIssuanceNotConfirmed);
        }
        let (authority, template) = self
            .preflight_ssh_certificate_template(project_id, ca_id, template_id)
            .await?;
        let expected_ttl_seconds =
            validate_request_policy(&authority, &template, &request.certificate)?;
        let effective_ttl = effective_certificate_ttl(&template, &request.certificate);
        let request_started_at = unix_timestamp()?;
        let response = self
            .execute_mutation::<IssueSshCertificate>(&issue_request(
                template_id,
                request,
                effective_ttl,
            ))
            .await?;
        let response_received_at = unix_timestamp()?;
        if response.key_algorithm != request.key_algorithm {
            return Err(ResourceError::InvalidSshCertificateResponse);
        }
        let (private_key, public_key) = validate_issued_key_pair(
            response.private_key,
            response.public_key,
            request.key_algorithm,
        )?;
        let certificate = validate_signed_certificate(
            SignedSshCertificateWire {
                serial_number: response.serial_number,
                signed_key: response.signed_key,
            },
            &authority,
            &public_key,
            &request.certificate,
            expected_ttl_seconds,
            request_started_at,
            response_received_at,
        )?;
        Ok(IssuedSshCertificate {
            serial_number: certificate.serial_number,
            signed_key: certificate.signed_key,
            private_key,
            public_key: public_key.as_str().to_owned(),
            key_algorithm: response.key_algorithm,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use serde_json::{Value, json};
    use ssh_key::{
        PrivateKey, PublicKey,
        certificate::{Builder, CertType},
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    use super::{
        OPENSSH_USER_CERTIFICATE_EXTENSIONS, SignedSshCertificateWire, SshCertificateInputError,
        SshCertificateIssueRequest, SshCertificateRequest, SshCertificateSignRequest,
        SshCertificateType, certificate_validity_within_bounds, principal_is_allowed,
        valid_issued_private_key_size, valid_signed_key_size, validate_issued_key_pair,
        validate_request_policy, validate_signed_certificate,
    };
    use crate::{
        InfisicalClient, ResourceError, SshCaKeySource, SshCaStatus, SshCertificateAuthority,
        SshCertificateAuthorityId, SshCertificateTemplate, SshCertificateTemplateId,
        SshCertificateTemplateStatus, SshDuration, SshKeyAlgorithm, SshProjectId, SshPublicKey,
        client::DeserializedSecret,
        test_support::{mount_login, settings},
    };

    const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const CA_ID: &str = "22222222-2222-4222-8222-222222222222";
    const TEMPLATE_ID: &str = "33333333-3333-4333-8333-333333333333";

    fn public_key() -> &'static str {
        include_str!("../test-fixtures/ssh-ed25519-public-key.txt").trim()
    }

    fn private_key() -> &'static str {
        include_str!("../test-fixtures/ssh-ed25519-private-key.txt")
    }

    fn p256_public_key() -> &'static str {
        include_str!("../test-fixtures/ssh-ecdsa-p256-public-key.txt").trim()
    }

    fn secret(value: impl Into<String>) -> DeserializedSecret {
        DeserializedSecret(crate::SecretValue::new(value))
    }

    fn ca_json() -> Value {
        json!({
            "ca": {
                "id": CA_ID,
                "projectId": PROJECT_ID,
                "friendlyName": "primary-ca",
                "status": "active",
                "keyAlgorithm": "ED25519",
                "keySource": "internal",
                "publicKey": public_key()
            }
        })
    }

    fn template_json() -> Value {
        json!({
            "id": TEMPLATE_ID,
            "sshCaId": CA_ID,
            "status": "active",
            "name": "deploy-access",
            "ttl": "1h",
            "maxTTL": "24h",
            "allowedUsers": ["deploy"],
            "allowedHosts": ["*.example.com"],
            "allowCustomKeyIds": true,
            "allowUserCertificates": true,
            "allowHostCertificates": true
        })
    }

    fn request() -> SshCertificateRequest {
        SshCertificateRequest::new(
            SshCertificateType::User,
            vec!["deploy".into()],
            Some(SshDuration::new("1h").unwrap()),
            Some("job:deploy".into()),
        )
        .unwrap()
    }

    fn default_ttl_request() -> SshCertificateRequest {
        SshCertificateRequest::new(
            SshCertificateType::User,
            vec!["deploy".into()],
            None,
            Some("job:deploy".into()),
        )
        .unwrap()
    }

    fn authority() -> SshCertificateAuthority {
        SshCertificateAuthority {
            id: CA_ID.into(),
            project_id: PROJECT_ID.into(),
            friendly_name: "primary-ca".into(),
            status: SshCaStatus::Active,
            key_algorithm: SshKeyAlgorithm::Ed25519,
            key_source: SshCaKeySource::Internal,
            public_key: SshPublicKey::new(public_key()).unwrap(),
        }
    }

    fn template() -> SshCertificateTemplate {
        SshCertificateTemplate {
            id: TEMPLATE_ID.into(),
            project_id: PROJECT_ID.into(),
            ssh_ca_id: CA_ID.into(),
            status: SshCertificateTemplateStatus::Active,
            name: "deploy-access".into(),
            ttl: SshDuration::new("1h").unwrap(),
            max_ttl: SshDuration::new("24h").unwrap(),
            allowed_users: vec!["deploy".into()],
            allowed_hosts: vec!["*.example.com".into()],
            allow_user_certificates: true,
            allow_host_certificates: true,
            allow_custom_key_ids: true,
        }
    }

    fn signed_key(serial: u64, principals: &[&str]) -> String {
        let now = UNIX_EPOCH.elapsed().unwrap().as_secs();
        signed_key_with(
            serial,
            principals,
            CertType::User,
            "job:deploy",
            now - 60,
            now + 3_600,
        )
    }

    fn signed_key_with(
        serial: u64,
        principals: &[&str],
        certificate_type: CertType,
        key_id: &str,
        valid_after: u64,
        valid_before: u64,
    ) -> String {
        signed_key_with_authorization_fields(
            serial,
            principals,
            certificate_type,
            key_id,
            valid_after,
            valid_before,
            &[],
            &[],
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_key_with_authorization_fields(
        serial: u64,
        principals: &[&str],
        certificate_type: CertType,
        key_id: &str,
        valid_after: u64,
        valid_before: u64,
        critical_options: &[(&str, &str)],
        extra_extensions: &[(&str, &str)],
        include_default_extensions: bool,
    ) -> String {
        let ca_private_key = PrivateKey::from_openssh(private_key()).unwrap();
        let subject_public_key = PublicKey::from_openssh(public_key()).unwrap();
        let mut builder = Builder::new(
            vec![42; Builder::RECOMMENDED_NONCE_SIZE],
            subject_public_key.key_data().clone(),
            valid_after,
            valid_before,
        )
        .unwrap();
        builder.serial(serial).unwrap();
        builder.cert_type(certificate_type).unwrap();
        builder.key_id(key_id).unwrap();
        for principal in principals {
            builder.valid_principal(*principal).unwrap();
        }
        for (name, data) in critical_options {
            builder.critical_option(*name, *data).unwrap();
        }
        if certificate_type == CertType::User && include_default_extensions {
            for name in OPENSSH_USER_CERTIFICATE_EXTENSIONS {
                builder.extension(name, "").unwrap();
            }
        }
        for (name, data) in extra_extensions {
            builder.extension(*name, *data).unwrap();
        }
        builder.sign(&ca_private_key).unwrap().to_openssh().unwrap()
    }

    async fn mount_preflight(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/ssh/ca/{CA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(ca_json()))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/ssh/certificate-templates/{TEMPLATE_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(template_json()))
            .expect(1)
            .mount(server)
            .await;
    }

    #[test]
    fn certificate_request_rejects_ambiguous_principals_and_key_ids() {
        for principals in [
            Vec::new(),
            vec!["deploy".into(), "deploy".into()],
            vec!["-option".into()],
            vec!["root user".into()],
            vec!["x".repeat(65)],
        ] {
            assert_eq!(
                SshCertificateRequest::new(SshCertificateType::User, principals, None, None,)
                    .unwrap_err(),
                SshCertificateInputError::InvalidPrincipals
            );
        }
        for key_id in ["", "with space", "under_score", &"x".repeat(51)] {
            assert_eq!(
                SshCertificateRequest::new(
                    SshCertificateType::User,
                    vec!["deploy".into()],
                    None,
                    Some(key_id.into()),
                )
                .unwrap_err(),
                SshCertificateInputError::InvalidKeyId
            );
        }
    }

    #[test]
    fn certificate_request_principals_follow_the_typed_template_identity_contract() {
        let longest_dns_name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(longest_dns_name.len(), 253);
        SshCertificateRequest::new(
            SshCertificateType::Host,
            vec!["2001:db8::1".into(), longest_dns_name],
            None,
            None,
        )
        .unwrap();
        for invalid_host in ["*", "*.example.com", "single-label"] {
            assert_eq!(
                SshCertificateRequest::new(
                    SshCertificateType::Host,
                    vec![invalid_host.into()],
                    None,
                    None,
                )
                .unwrap_err(),
                SshCertificateInputError::InvalidPrincipals
            );
        }
        assert_eq!(
            SshCertificateRequest::new(SshCertificateType::User, vec!["a".repeat(33)], None, None,)
                .unwrap_err(),
            SshCertificateInputError::InvalidPrincipals
        );
    }

    #[test]
    fn certificate_request_policy_rejects_each_preflight_drift() {
        assert_eq!(
            validate_request_policy(&authority(), &template(), &request()).unwrap(),
            3_600
        );

        let mut disabled_authority = authority();
        disabled_authority.status = SshCaStatus::Disabled;
        assert_eq!(
            validate_request_policy(&disabled_authority, &template(), &request()).unwrap_err(),
            ResourceError::InvalidSshCertificateAuthorityState
        );

        let mut disabled_template = template();
        disabled_template.status = SshCertificateTemplateStatus::Disabled;
        assert_eq!(
            validate_request_policy(&authority(), &disabled_template, &request()).unwrap_err(),
            ResourceError::InvalidSshCertificateTemplateState
        );

        let mut type_restricted = template();
        type_restricted.allow_user_certificates = false;
        assert_eq!(
            validate_request_policy(&authority(), &type_restricted, &request()).unwrap_err(),
            ResourceError::SshCertificateTypeNotAllowed
        );

        let mut principal_restricted = template();
        principal_restricted.allowed_users = vec!["other".into()];
        assert_eq!(
            validate_request_policy(&authority(), &principal_restricted, &request()).unwrap_err(),
            ResourceError::SshCertificatePrincipalNotAllowed
        );

        let mut custom_key_restricted = template();
        custom_key_restricted.allow_custom_key_ids = false;
        assert_eq!(
            validate_request_policy(&authority(), &custom_key_restricted, &request()).unwrap_err(),
            ResourceError::SshCertificateCustomKeyIdNotAllowed
        );

        let excessive_ttl = SshCertificateRequest::new(
            SshCertificateType::User,
            vec!["deploy".into()],
            Some(SshDuration::new("25h").unwrap()),
            Some("job:deploy".into()),
        )
        .unwrap();
        assert_eq!(
            validate_request_policy(&authority(), &template(), &excessive_ttl).unwrap_err(),
            ResourceError::SshCertificateTtlNotAllowed
        );

        let maximum_ttl = SshCertificateRequest::new(
            SshCertificateType::User,
            vec!["deploy".into()],
            Some(SshDuration::new("24h").unwrap()),
            Some("job:deploy".into()),
        )
        .unwrap();
        assert_eq!(
            validate_request_policy(&authority(), &template(), &maximum_ttl).unwrap(),
            86_400
        );
    }

    #[test]
    fn principal_policy_supports_exact_and_wildcard_templates_without_wildcard_requests() {
        let mut policy = template();
        policy.allowed_users = vec!["*".into()];
        assert!(principal_is_allowed(
            SshCertificateType::User,
            "deploy",
            &policy
        ));
        assert!(!principal_is_allowed(
            SshCertificateType::User,
            "*",
            &policy
        ));

        policy.allowed_hosts = vec!["*".into()];
        assert!(principal_is_allowed(
            SshCertificateType::Host,
            "web.example.com",
            &policy
        ));
        assert!(!principal_is_allowed(
            SshCertificateType::Host,
            "*",
            &policy
        ));

        policy.allowed_hosts = vec!["*.example.com".into()];
        assert!(principal_is_allowed(
            SshCertificateType::Host,
            "web.example.com",
            &policy
        ));
        assert!(!principal_is_allowed(
            SshCertificateType::Host,
            "example.com",
            &policy
        ));
        assert!(!principal_is_allowed(
            SshCertificateType::Host,
            "web.example.net",
            &policy
        ));

        policy.allowed_hosts = vec!["db.example.com".into()];
        assert!(principal_is_allowed(
            SshCertificateType::Host,
            "db.example.com",
            &policy
        ));
        assert!(!principal_is_allowed(
            SshCertificateType::Host,
            "web.example.com",
            &policy
        ));
    }

    #[test]
    fn response_size_limits_have_inclusive_upper_bounds() {
        assert!(!valid_signed_key_size(""));
        assert!(valid_signed_key_size(&"x".repeat(131_072)));
        assert!(!valid_signed_key_size(&"x".repeat(131_073)));
        assert!(valid_issued_private_key_size(&"x".repeat(131_072)));
        assert!(!valid_issued_private_key_size(&"x".repeat(131_073)));
    }

    #[test]
    fn certificate_validity_bounds_limit_backdating_without_extending_expiry() {
        let cases = [
            ("exact expected lifetime", 1_000, 4_600, true),
            ("maximum past backdate", 880, 4_600, true),
            ("backdated too far", 879, 4_600, false),
            ("valid-after at response", 1_002, 4_602, true),
            ("valid-after after response", 1_003, 4_603, false),
            ("lifetime too short", 1_001, 4_600, false),
            ("expiry before requested horizon", 1_000, 4_599, false),
            ("expiry at response horizon", 1_000, 4_602, true),
            ("expiry extends past response horizon", 1_000, 4_603, false),
            ("inverted validity", 4_601, 4_600, false),
        ];
        for (dimension, valid_after, valid_before, expected) in cases {
            assert_eq!(
                certificate_validity_within_bounds(valid_after, valid_before, 3_600, 1_000, 1_002,),
                expected,
                "{dimension}"
            );
        }

        assert!(certificate_validity_within_bounds(
            880, 1_003, 1, 1_000, 1_002
        ));
        assert!(!certificate_validity_within_bounds(
            880, 1_004, 1, 1_000, 1_002
        ));
    }

    #[test]
    fn issued_key_pair_validation_proves_bounds_algorithm_and_pair_identity() {
        let (private, public) = validate_issued_key_pair(
            secret(private_key()),
            public_key().into(),
            SshKeyAlgorithm::Ed25519,
        )
        .unwrap();
        assert_eq!(private.expose_secret(), private_key());
        assert_eq!(public.as_str(), public_key());

        assert_eq!(
            validate_issued_key_pair(
                secret(private_key()),
                public_key().into(),
                SshKeyAlgorithm::EcP256,
            )
            .unwrap_err(),
            ResourceError::InvalidSshCertificateResponse
        );
        assert_eq!(
            validate_issued_key_pair(
                secret(private_key()),
                p256_public_key().into(),
                SshKeyAlgorithm::EcP256,
            )
            .unwrap_err(),
            ResourceError::InvalidSshCertificateResponse
        );
        assert_eq!(
            validate_issued_key_pair(
                secret(include_str!(
                    "../test-fixtures/ssh-ed25519-encrypted-private-key.txt"
                )),
                public_key().into(),
                SshKeyAlgorithm::Ed25519,
            )
            .unwrap_err(),
            ResourceError::InvalidSshCertificateResponse
        );
        assert_eq!(
            validate_issued_key_pair(
                secret("x".repeat(128 * 1024 + 1)),
                public_key().into(),
                SshKeyAlgorithm::Ed25519,
            )
            .unwrap_err(),
            ResourceError::InvalidSshCertificateResponse
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn signed_certificate_validation_rejects_each_trust_or_semantic_drift() {
        let now = UNIX_EPOCH.elapsed().unwrap().as_secs();
        let valid_key = signed_key_with(
            42,
            &["deploy"],
            CertType::User,
            "job:deploy",
            now - 60,
            now + 3_600,
        );
        let base_authority = authority();
        let base_public_key = SshPublicKey::new(public_key()).unwrap();
        let base_request = request();
        validate_signed_certificate(
            SignedSshCertificateWire {
                serial_number: "42".into(),
                signed_key: valid_key.clone(),
            },
            &base_authority,
            &base_public_key,
            &base_request,
            3_600,
            now,
            now,
        )
        .unwrap();
        let derived_key_id_request = SshCertificateRequest::new(
            SshCertificateType::User,
            vec!["deploy".into()],
            Some(SshDuration::new("1h").unwrap()),
            None,
        )
        .unwrap();
        validate_signed_certificate(
            SignedSshCertificateWire {
                serial_number: "43".into(),
                signed_key: signed_key_with(
                    43,
                    &["deploy"],
                    CertType::User,
                    "identity-actor",
                    now - 60,
                    now + 3_600,
                ),
            },
            &base_authority,
            &base_public_key,
            &derived_key_id_request,
            3_600,
            now,
            now,
        )
        .unwrap();
        let host_request = SshCertificateRequest::new(
            SshCertificateType::Host,
            vec!["node.example.com".into()],
            Some(SshDuration::new("1h").unwrap()),
            Some("host:node".into()),
        )
        .unwrap();
        validate_signed_certificate(
            SignedSshCertificateWire {
                serial_number: "45".into(),
                signed_key: signed_key_with(
                    45,
                    &["node.example.com"],
                    CertType::Host,
                    "host:node",
                    now - 60,
                    now + 3_600,
                ),
            },
            &base_authority,
            &base_public_key,
            &host_request,
            3_600,
            now,
            now,
        )
        .unwrap();
        assert_eq!(
            validate_signed_certificate(
                SignedSshCertificateWire {
                    serial_number: "46".into(),
                    signed_key: signed_key_with_authorization_fields(
                        46,
                        &["node.example.com"],
                        CertType::Host,
                        "host:node",
                        now - 60,
                        now + 3_600,
                        &[],
                        &[("permit-pty", "")],
                        false,
                    ),
                },
                &base_authority,
                &base_public_key,
                &host_request,
                3_600,
                now,
                now,
            )
            .unwrap_err(),
            ResourceError::InvalidSshCertificateResponse
        );
        assert_eq!(
            validate_signed_certificate(
                SignedSshCertificateWire {
                    serial_number: "44".into(),
                    signed_key: signed_key_with(
                        44,
                        &["deploy"],
                        CertType::User,
                        "invalid_key_id",
                        now - 60,
                        now + 3_600,
                    ),
                },
                &base_authority,
                &base_public_key,
                &derived_key_id_request,
                3_600,
                now,
                now,
            )
            .unwrap_err(),
            ResourceError::InvalidSshCertificateResponse
        );

        let mut wrong_authority = authority();
        wrong_authority.public_key = SshPublicKey::new(p256_public_key()).unwrap();
        wrong_authority.key_algorithm = SshKeyAlgorithm::EcP256;
        let wrong_subject = SshPublicKey::new(p256_public_key()).unwrap();
        let cases = [
            (
                "noncanonical serial",
                "0042".to_owned(),
                valid_key.clone(),
                base_authority.clone(),
                base_public_key.clone(),
            ),
            (
                "mismatched serial",
                "43".to_owned(),
                valid_key.clone(),
                base_authority.clone(),
                base_public_key.clone(),
            ),
            (
                "certificate type",
                "42".to_owned(),
                signed_key_with(
                    42,
                    &["deploy"],
                    CertType::Host,
                    "job:deploy",
                    now - 60,
                    now + 3_600,
                ),
                base_authority.clone(),
                base_public_key.clone(),
            ),
            (
                "principals",
                "42".to_owned(),
                signed_key_with(
                    42,
                    &["other"],
                    CertType::User,
                    "job:deploy",
                    now - 60,
                    now + 3_600,
                ),
                base_authority.clone(),
                base_public_key.clone(),
            ),
            (
                "key ID",
                "42".to_owned(),
                signed_key_with(
                    42,
                    &["deploy"],
                    CertType::User,
                    "other",
                    now - 60,
                    now + 3_600,
                ),
                base_authority.clone(),
                base_public_key.clone(),
            ),
            (
                "subject key",
                "42".to_owned(),
                valid_key.clone(),
                base_authority.clone(),
                wrong_subject,
            ),
            (
                "signing CA",
                "42".to_owned(),
                valid_key.clone(),
                wrong_authority,
                base_public_key.clone(),
            ),
            (
                "critical option",
                "42".to_owned(),
                signed_key_with_authorization_fields(
                    42,
                    &["deploy"],
                    CertType::User,
                    "job:deploy",
                    now - 60,
                    now + 3_600,
                    &[("force-command", "echo denied")],
                    &[],
                    true,
                ),
                base_authority.clone(),
                base_public_key.clone(),
            ),
            (
                "unexpected extension",
                "42".to_owned(),
                signed_key_with_authorization_fields(
                    42,
                    &["deploy"],
                    CertType::User,
                    "job:deploy",
                    now - 60,
                    now + 3_600,
                    &[],
                    &[("unknown@example.com", "")],
                    true,
                ),
                base_authority.clone(),
                base_public_key.clone(),
            ),
            (
                "missing default extensions",
                "42".to_owned(),
                signed_key_with_authorization_fields(
                    42,
                    &["deploy"],
                    CertType::User,
                    "job:deploy",
                    now - 60,
                    now + 3_600,
                    &[],
                    &[],
                    false,
                ),
                base_authority.clone(),
                base_public_key.clone(),
            ),
            (
                "expired validity",
                "42".to_owned(),
                signed_key_with(
                    42,
                    &["deploy"],
                    CertType::User,
                    "job:deploy",
                    now - 3_660,
                    now - 60,
                ),
                base_authority.clone(),
                base_public_key.clone(),
            ),
            (
                "short validity",
                "42".to_owned(),
                signed_key_with(
                    42,
                    &["deploy"],
                    CertType::User,
                    "job:deploy",
                    now - 60,
                    now + 3_000,
                ),
                base_authority.clone(),
                base_public_key.clone(),
            ),
            (
                "long validity",
                "42".to_owned(),
                signed_key_with(
                    42,
                    &["deploy"],
                    CertType::User,
                    "job:deploy",
                    now - 60,
                    now + 4_000,
                ),
                base_authority,
                base_public_key,
            ),
        ];
        for (dimension, serial_number, signed_key, authority, public_key) in cases {
            assert_eq!(
                validate_signed_certificate(
                    SignedSshCertificateWire {
                        serial_number,
                        signed_key,
                    },
                    &authority,
                    &public_key,
                    &base_request,
                    3_600,
                    now,
                    now,
                )
                .unwrap_err(),
                ResourceError::InvalidSshCertificateResponse,
                "{dimension}"
            );
        }
    }

    #[tokio::test]
    async fn unconfirmed_certificate_mutations_fail_before_authentication() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let project_id = SshProjectId::new(PROJECT_ID).unwrap();
        let ca_id = SshCertificateAuthorityId::new(CA_ID).unwrap();
        let template_id = SshCertificateTemplateId::new(TEMPLATE_ID).unwrap();
        let sign =
            SshCertificateSignRequest::new(SshPublicKey::new(public_key()).unwrap(), request());
        assert!(matches!(
            client
                .sign_ssh_certificate(&project_id, &ca_id, &template_id, &sign, false)
                .await,
            Err(ResourceError::SshCertificateSigningNotConfirmed)
        ));
        let issue = SshCertificateIssueRequest::new(SshKeyAlgorithm::Ed25519, request());
        assert!(matches!(
            client
                .issue_ssh_certificate(&project_id, &ca_id, &template_id, &issue, false)
                .await,
            Err(ResourceError::SshCertificateIssuanceNotConfirmed)
        ));
    }

    #[tokio::test]
    async fn signing_uses_two_preflights_one_mutation_and_verifies_the_certificate() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-sign-token").await;
        mount_preflight(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ssh/certificates/sign"))
            .and(body_json(json!({
                "certificateTemplateId": TEMPLATE_ID,
                "publicKey": public_key(),
                "certType": "user",
                "principals": ["deploy"],
                "ttl": "1h",
                "keyId": "job:deploy"
            })))
            .respond_with(|_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(json!({
                    "serialNumber": "42",
                    "signedKey": signed_key(42, &["deploy"])
                }))
            })
            .expect(1)
            .mount(&server)
            .await;
        // Cross a wall-clock second so the fake upstream must mint the certificate when it
        // handles the mutation rather than during test setup.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let signed = client
            .sign_ssh_certificate(
                &SshProjectId::new(PROJECT_ID).unwrap(),
                &SshCertificateAuthorityId::new(CA_ID).unwrap(),
                &SshCertificateTemplateId::new(TEMPLATE_ID).unwrap(),
                &SshCertificateSignRequest::new(
                    SshPublicKey::new(public_key()).unwrap(),
                    default_ttl_request(),
                ),
                true,
            )
            .await
            .unwrap();
        assert_eq!(signed.serial_number, "42");
        assert!(
            signed
                .signed_key
                .starts_with("ssh-ed25519-cert-v01@openssh.com ")
        );
    }

    #[tokio::test]
    async fn issuance_reveals_only_a_verified_matching_key_pair_and_certificate() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-issue-token").await;
        mount_preflight(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ssh/certificates/issue"))
            .and(body_json(json!({
                "certificateTemplateId": TEMPLATE_ID,
                "keyAlgorithm": "ED25519",
                "certType": "user",
                "principals": ["deploy"],
                "ttl": "1h",
                "keyId": "job:deploy"
            })))
            .respond_with(|_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(json!({
                    "serialNumber": "43",
                    "signedKey": signed_key(43, &["deploy"]),
                    "privateKey": private_key(),
                    "publicKey": public_key(),
                    "keyAlgorithm": "ED25519"
                }))
            })
            .expect(1)
            .mount(&server)
            .await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        let issued = client
            .issue_ssh_certificate(
                &SshProjectId::new(PROJECT_ID).unwrap(),
                &SshCertificateAuthorityId::new(CA_ID).unwrap(),
                &SshCertificateTemplateId::new(TEMPLATE_ID).unwrap(),
                &SshCertificateIssueRequest::new(SshKeyAlgorithm::Ed25519, request()),
                true,
            )
            .await
            .unwrap();
        assert_eq!(issued.serial_number, "43");
        assert_eq!(issued.public_key, public_key());
        assert_eq!(issued.private_key.expose_secret(), private_key());
    }

    #[tokio::test]
    async fn issuance_rejects_oversized_private_key_material() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-issue-oversized-token").await;
        mount_preflight(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ssh/certificates/issue"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "serialNumber": "45",
                "signedKey": signed_key(45, &["deploy"]),
                "privateKey": "x".repeat(128 * 1024 + 1),
                "publicKey": public_key(),
                "keyAlgorithm": "ED25519"
            })))
            .expect(1)
            .mount(&server)
            .await;
        assert!(matches!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .issue_ssh_certificate(
                    &SshProjectId::new(PROJECT_ID).unwrap(),
                    &SshCertificateAuthorityId::new(CA_ID).unwrap(),
                    &SshCertificateTemplateId::new(TEMPLATE_ID).unwrap(),
                    &SshCertificateIssueRequest::new(SshKeyAlgorithm::Ed25519, request()),
                    true,
                )
                .await,
            Err(ResourceError::InvalidSshCertificateResponse)
        ));
    }

    #[tokio::test]
    async fn signing_rejects_response_semantics_that_drift_from_the_request() {
        let server = MockServer::start().await;
        mount_login(&server, "ssh-sign-drift-token").await;
        mount_preflight(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ssh/certificates/sign"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "serialNumber": "44",
                "signedKey": signed_key(44, &["other"])
            })))
            .expect(1)
            .mount(&server)
            .await;
        assert!(matches!(
            InfisicalClient::new(settings(&server))
                .unwrap()
                .sign_ssh_certificate(
                    &SshProjectId::new(PROJECT_ID).unwrap(),
                    &SshCertificateAuthorityId::new(CA_ID).unwrap(),
                    &SshCertificateTemplateId::new(TEMPLATE_ID).unwrap(),
                    &SshCertificateSignRequest::new(
                        SshPublicKey::new(public_key()).unwrap(),
                        request(),
                    ),
                    true,
                )
                .await,
            Err(ResourceError::InvalidSshCertificateResponse)
        ));
    }
}
