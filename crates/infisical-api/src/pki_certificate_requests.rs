use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
};

use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x509_parser::{
    extensions::GeneralName,
    prelude::{FromDer, X509Certificate},
};

use crate::{
    CertificateAuthorityProjectId, CertificateStatus, InfisicalClient, MutationOperation,
    ObservableReadBodyOperation, ObservableReadOperation, Page, PageRequest, ResourceError,
    SecretValue,
    certificate::{certificate_bundle_der, certificate_serial_matches, normalize_pem},
    client::{ApiVersion, Endpoint, sealed},
    pki_certificate_profiles::{is_valid_single_certificate, private_key_matches_certificate},
    resources::{is_bounded_text, is_uuid, utc_timestamp_millis},
};

const MAX_REQUEST_SEARCH_BYTES: usize = 255;
const MAX_REQUEST_TEXT_BYTES: usize = 2_048;
const MAX_ALTERNATIVE_NAMES_BYTES: usize = 16 * 1_024;
const MAX_SERIAL_NUMBER_BYTES: usize = 128;
const MAX_CERTIFICATE_PEM_BYTES: usize = 64 * 1_024;
const MAX_FILTER_VALUES: usize = 100;

/// Input validation failures for certificate-request observation.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CertificateRequestInputError {
    #[error("certificate-request ID must be a UUID")]
    InvalidId,
    #[error("certificate-request search must be trimmed, control-free, and at most 255 bytes")]
    InvalidSearch,
    #[error("certificate-request profile filters must contain bounded unique UUIDs")]
    InvalidProfileFilter,
    #[error("certificate-request date filters must be timestamps in ascending order")]
    InvalidDateRange,
    #[error("certificate-request sort order requires a sort field")]
    InvalidSort,
}

/// Canonical certificate-request UUID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct CertificateRequestId(String);

impl CertificateRequestId {
    /// Validate one exact certificate-request identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, CertificateRequestInputError> {
        let value = value.into();
        if !is_uuid(&value) {
            return Err(CertificateRequestInputError::InvalidId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Borrow the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Certificate enrollment state returned by the pinned request routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertificateRequestStatus {
    PendingApproval,
    Pending,
    PendingValidation,
    Issued,
    Failed,
    Rejected,
}

/// Supported certificate-request inventory sort field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CertificateRequestSort {
    CreatedAt,
    UpdatedAt,
    Status,
    CommonName,
}

/// Sort direction for certificate-request inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CertificateRequestSortOrder {
    Asc,
    Desc,
}

/// One bounded project-scoped certificate-request search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequestListRequest {
    project_id: CertificateAuthorityProjectId,
    page: PageRequest,
    search: Option<String>,
    status: Option<CertificateRequestStatus>,
    from_date: Option<String>,
    to_date: Option<String>,
    profile_ids: Option<Vec<String>>,
    sort_by: Option<CertificateRequestSort>,
    sort_order: Option<CertificateRequestSortOrder>,
}

impl CertificateRequestListRequest {
    /// Validate pagination, filters, dates, and sorting before search.
    ///
    /// # Errors
    ///
    /// Returns an error for ambiguous text, duplicate identifiers, invalid dates,
    /// or a sort direction without a sort field.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: CertificateAuthorityProjectId,
        page: PageRequest,
        search: Option<String>,
        status: Option<CertificateRequestStatus>,
        from_date: Option<String>,
        to_date: Option<String>,
        profile_ids: Option<Vec<String>>,
        sort_by: Option<CertificateRequestSort>,
        sort_order: Option<CertificateRequestSortOrder>,
    ) -> Result<Self, CertificateRequestInputError> {
        if search.as_deref().is_some_and(|value| {
            value.is_empty()
                || !is_bounded_text(value, MAX_REQUEST_SEARCH_BYTES)
                || value != value.trim()
        }) {
            return Err(CertificateRequestInputError::InvalidSearch);
        }
        let from_millis = from_date.as_deref().and_then(utc_timestamp_millis);
        let to_millis = to_date.as_deref().and_then(utc_timestamp_millis);
        if from_date.is_some() != from_millis.is_some()
            || to_date.is_some() != to_millis.is_some()
            || from_millis
                .zip(to_millis)
                .is_some_and(|(from, to)| from > to)
        {
            return Err(CertificateRequestInputError::InvalidDateRange);
        }
        let profile_ids = normalize_profile_ids(profile_ids)?;
        if sort_order.is_some() && sort_by.is_none() {
            return Err(CertificateRequestInputError::InvalidSort);
        }
        Ok(Self {
            project_id,
            page,
            search,
            status,
            from_date,
            to_date,
            profile_ids,
            sort_by,
            sort_order,
        })
    }
}

/// Sanitized certificate metadata attached to an issued request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRequestCertificate {
    pub id: String,
    pub serial_number: String,
    pub status: CertificateStatus,
}

/// Sanitized project-scoped certificate-request metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRequest {
    pub id: String,
    pub project_id: String,
    pub status: CertificateRequestStatus,
    pub common_name: Option<String>,
    pub alternative_names: Option<String>,
    pub profile_id: Option<String>,
    pub profile_name: Option<String>,
    pub ca_id: Option<String>,
    pub certificate_id: Option<String>,
    pub approval_request_id: Option<String>,
    pub certificate: Option<CertificateRequestCertificate>,
    pub created_at: String,
    pub updated_at: String,
}

/// Explicit result retrieval for an issued certificate request.
#[derive(Debug)]
pub struct CertificateRequestMaterial {
    pub project_id: String,
    pub request_id: String,
    pub certificate_id: String,
    pub serial_number: String,
    pub certificate: String,
    pub private_key: Option<SecretValue>,
}

/// Definitive cancellation response for one project-bound request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRequestCancellation {
    pub project_id: String,
    pub request_id: String,
    pub cancelled: bool,
    pub status: CertificateRequestStatus,
}

fn normalize_profile_ids(
    values: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, CertificateRequestInputError> {
    let Some(values) = values else {
        return Ok(None);
    };
    if values.is_empty()
        || values.len() > MAX_FILTER_VALUES
        || values.iter().any(|value| !is_uuid(value))
    {
        return Err(CertificateRequestInputError::InvalidProfileFilter);
    }
    let values = values
        .into_iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if values.iter().collect::<HashSet<_>>().len() != values.len() {
        return Err(CertificateRequestInputError::InvalidProfileFilter);
    }
    Ok(Some(values))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchCertificateRequestsBody {
    project_id: String,
    offset: u32,
    limit: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    search: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<CertificateRequestStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sort_by: Option<CertificateRequestSort>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sort_order: Option<CertificateRequestSortOrder>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchCertificateRequestsResponse {
    certificate_requests: Vec<CertificateRequestWire>,
    total_count: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateRequestWire {
    id: String,
    status: CertificateRequestStatus,
    common_name: Option<String>,
    alt_names: Option<String>,
    profile_id: Option<String>,
    profile_name: Option<String>,
    ca_id: Option<String>,
    certificate_id: Option<String>,
    approval_request_id: Option<String>,
    certificate: Option<CertificateRequestCertificateWire>,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateRequestCertificateWire {
    id: String,
    serial_number: String,
    status: CertificateStatus,
}

struct SearchCertificateRequests;
impl sealed::Sealed for SearchCertificateRequests {}
impl ObservableReadBodyOperation for SearchCertificateRequests {
    type Input = SearchCertificateRequestsBody;
    type Output = SearchCertificateRequestsResponse;

    fn endpoint(_input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "cert-manager",
                "certificates",
                "certificate-requests",
                "search",
            ],
        )
    }
}

#[derive(Serialize)]
struct CertificateRequestTarget {
    #[serde(skip_serializing)]
    request_id: CertificateRequestId,
}

struct GetCertificateRequestResult;
impl sealed::Sealed for GetCertificateRequestResult {}
impl ObservableReadOperation for GetCertificateRequestResult {
    type Query = CertificateRequestTarget;
    type Output = CertificateRequestResultWire;

    fn endpoint(query: &Self::Query) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "cert-manager".to_owned(),
                "certificates".to_owned(),
                "certificate-requests".to_owned(),
                query.request_id.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateRequestResultWire {
    status: CertificateRequestStatus,
    certificate: Option<String>,
    certificate_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    private_key: Option<SecretValue>,
    serial_number: Option<String>,
    common_name: Option<String>,
    created_at: String,
    updated_at: String,
}

fn deserialize_optional_secret<'de, D>(deserializer: D) -> Result<Option<SecretValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(SecretValue::new))
}

struct CancelCertificateRequest;
impl sealed::Sealed for CancelCertificateRequest {}
impl MutationOperation for CancelCertificateRequest {
    type Input = CertificateRequestTarget;
    type Output = CancelCertificateRequestWire;

    fn method() -> Method {
        Method::POST
    }

    fn endpoint(input: &Self::Input) -> Endpoint {
        Endpoint::from_segments(
            ApiVersion::V1,
            [
                "cert-manager".to_owned(),
                "certificates".to_owned(),
                "certificate-requests".to_owned(),
                input.request_id.as_str().to_owned(),
                "cancel".to_owned(),
            ],
        )
    }

    fn sends_json_body() -> bool {
        false
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CancelCertificateRequestWire {
    status: CertificateRequestStatus,
    cancelled: bool,
}

fn valid_optional_text(value: Option<&str>, maximum: usize) -> bool {
    value.is_none_or(|value| {
        !value.is_empty()
            && value.len() <= maximum
            && value.trim() == value
            && !value.chars().any(char::is_control)
    })
}

fn request_from_wire(
    wire: CertificateRequestWire,
    project_id: &CertificateAuthorityProjectId,
) -> Result<CertificateRequest, ResourceError> {
    let id = CertificateRequestId::new(wire.id)
        .map_err(|_| ResourceError::InvalidCertificateRequestInventoryResponse)?;
    let created_at = utc_timestamp_millis(&wire.created_at);
    let updated_at = utc_timestamp_millis(&wire.updated_at);
    if !valid_optional_text(wire.common_name.as_deref(), MAX_REQUEST_TEXT_BYTES)
        || !valid_optional_text(wire.alt_names.as_deref(), MAX_ALTERNATIVE_NAMES_BYTES)
        || !valid_optional_text(wire.profile_name.as_deref(), MAX_REQUEST_TEXT_BYTES)
        || wire
            .profile_id
            .as_deref()
            .is_some_and(|value| !is_uuid(value))
        || wire.ca_id.as_deref().is_some_and(|value| !is_uuid(value))
        || wire
            .certificate_id
            .as_deref()
            .is_some_and(|value| !is_uuid(value))
        || wire
            .approval_request_id
            .as_deref()
            .is_some_and(|value| !is_uuid(value))
        || created_at.is_none()
        || updated_at < created_at
    {
        return Err(ResourceError::InvalidCertificateRequestInventoryResponse);
    }
    let certificate = wire
        .certificate
        .map(|certificate| {
            if !is_uuid(&certificate.id)
                || certificate.serial_number.is_empty()
                || certificate.serial_number.len() > MAX_SERIAL_NUMBER_BYTES
                || !certificate
                    .serial_number
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(ResourceError::InvalidCertificateRequestInventoryResponse);
            }
            Ok(CertificateRequestCertificate {
                id: certificate.id.to_ascii_lowercase(),
                serial_number: certificate.serial_number,
                status: certificate.status,
            })
        })
        .transpose()?;
    if wire.certificate_id.as_deref()
        != certificate
            .as_ref()
            .map(|certificate| certificate.id.as_str())
        || (wire.status == CertificateRequestStatus::Issued) != certificate.is_some()
    {
        return Err(ResourceError::InvalidCertificateRequestInventoryResponse);
    }
    Ok(CertificateRequest {
        id: id.as_str().to_owned(),
        project_id: project_id.as_str().to_owned(),
        status: wire.status,
        common_name: wire.common_name,
        alternative_names: wire.alt_names,
        profile_id: wire.profile_id.map(|value| value.to_ascii_lowercase()),
        profile_name: wire.profile_name,
        ca_id: wire.ca_id.map(|value| value.to_ascii_lowercase()),
        certificate_id: wire.certificate_id.map(|value| value.to_ascii_lowercase()),
        approval_request_id: wire
            .approval_request_id
            .map(|value| value.to_ascii_lowercase()),
        certificate,
        created_at: wire.created_at,
        updated_at: wire.updated_at,
    })
}

fn request_matches(request: &CertificateRequest, input: &CertificateRequestListRequest) -> bool {
    if input.status.is_some_and(|status| request.status != status)
        || input.profile_ids.as_ref().is_some_and(|ids| {
            request
                .profile_id
                .as_ref()
                .is_none_or(|id| !ids.contains(id))
        })
    {
        return false;
    }
    let created = utc_timestamp_millis(&request.created_at);
    if input
        .from_date
        .as_deref()
        .and_then(utc_timestamp_millis)
        .is_some_and(|from| created.is_none_or(|created| created < from))
        || input
            .to_date
            .as_deref()
            .and_then(utc_timestamp_millis)
            .is_some_and(|to| created.is_none_or(|created| created > to))
    {
        return false;
    }
    input.search.as_deref().is_none_or(|search| {
        let search = search.to_lowercase();
        request
            .common_name
            .as_deref()
            .is_some_and(|value| value.to_lowercase().contains(&search))
            || request
                .alternative_names
                .as_deref()
                .is_some_and(|value| value.to_lowercase().contains(&search))
    })
}

fn validate_page(page: PageRequest, returned: usize, total: u64) -> Result<(), ResourceError> {
    if returned > usize::from(page.limit()) {
        return Err(ResourceError::InvalidCertificateRequestInventoryResponse);
    }
    let returned = u64::try_from(returned)
        .map_err(|_| ResourceError::InvalidCertificateRequestInventoryResponse)?;
    let end = u64::from(page.offset())
        .checked_add(returned)
        .ok_or(ResourceError::InvalidCertificateRequestInventoryResponse)?;
    let consistent = if returned == 0 {
        u64::from(page.offset()) >= total
    } else if returned < u64::from(page.limit()) {
        end == total
    } else {
        end <= total
    };
    if !consistent {
        return Err(ResourceError::InvalidCertificateRequestInventoryResponse);
    }
    Ok(())
}

pub(crate) fn certificate_subject_values_match(
    certificate: &X509Certificate<'_>,
    expected_common_name: Option<&str>,
    expected_alternative_names: Option<&str>,
) -> bool {
    let Ok(common_names) = certificate
        .subject()
        .iter_common_name()
        .map(x509_parser::x509::AttributeTypeAndValue::as_str)
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    if common_names.as_slice() != expected_common_name.as_slice() {
        return false;
    }

    // The pinned search route intentionally flattens stored `{ type, value }` SANs
    // into comma-joined values, while the exact result route omits SANs. Compare
    // the complete value set without inventing a GeneralName type the API erased.
    let mut expected_names = HashSet::new();
    if let Some(names) = expected_alternative_names {
        for name in names.split(',').map(str::trim) {
            if name.is_empty() || !expected_names.insert(name.to_owned()) {
                return false;
            }
        }
    }
    let Ok(extension) = certificate.subject_alternative_name() else {
        return false;
    };
    let mut actual_names = HashSet::new();
    if let Some(extension) = extension {
        for name in &extension.value.general_names {
            let value = match name {
                GeneralName::DNSName(value)
                | GeneralName::RFC822Name(value)
                | GeneralName::URI(value) => (*value).to_owned(),
                GeneralName::IPAddress(bytes) => match bytes.len() {
                    4 => Ipv4Addr::from(<[u8; 4]>::try_from(*bytes).unwrap()).to_string(),
                    16 => Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).unwrap()).to_string(),
                    _ => return false,
                },
                _ => return false,
            };
            if !actual_names.insert(value) {
                return false;
            }
        }
    }
    actual_names == expected_names
}

impl InfisicalClient {
    /// Search one bounded page of sanitized certificate-request metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed client, scope, filter, response-contract, or pagination error.
    pub async fn list_certificate_requests(
        &self,
        request: CertificateRequestListRequest,
    ) -> Result<Page<CertificateRequest>, ResourceError> {
        let response = self
            .execute_observable_read_body::<SearchCertificateRequests>(
                &SearchCertificateRequestsBody {
                    project_id: request.project_id.as_str().to_owned(),
                    offset: request.page.offset(),
                    limit: request.page.limit(),
                    search: request.search.clone(),
                    status: request.status,
                    from_date: request.from_date.clone(),
                    to_date: request.to_date.clone(),
                    profile_ids: request.profile_ids.clone(),
                    sort_by: request.sort_by,
                    sort_order: request.sort_order,
                },
            )
            .await?;
        validate_page(
            request.page,
            response.certificate_requests.len(),
            response.total_count,
        )?;
        let items = response
            .certificate_requests
            .into_iter()
            .map(|wire| request_from_wire(wire, &request.project_id))
            .collect::<Result<Vec<_>, _>>()?;
        if items
            .iter()
            .map(|item| item.id.as_str())
            .collect::<HashSet<_>>()
            .len()
            != items.len()
            || items.iter().any(|item| !request_matches(item, &request))
        {
            return Err(ResourceError::InvalidCertificateRequestInventoryResponse);
        }
        Ok(Page::new(request.page, items, Some(response.total_count))?)
    }

    /// Find one exact request through project-scoped sanitized inventory.
    ///
    /// # Errors
    ///
    /// Returns a typed client, response-contract, or project-scope error.
    pub async fn get_certificate_request(
        &self,
        project_id: &CertificateAuthorityProjectId,
        request_id: &CertificateRequestId,
    ) -> Result<CertificateRequest, ResourceError> {
        let mut next = Some(PageRequest::new(0, 100)?);
        let mut expected_total = None;
        let mut seen_ids = HashSet::new();
        while let Some(page_request) = next {
            let request = CertificateRequestListRequest::new(
                project_id.clone(),
                page_request,
                None,
                None,
                None,
                None,
                None,
                Some(CertificateRequestSort::CreatedAt),
                Some(CertificateRequestSortOrder::Asc),
            )
            .map_err(|_| ResourceError::InvalidCertificateRequestInventoryResponse)?;
            let page = self.list_certificate_requests(request).await?;
            let total = page
                .total
                .ok_or(ResourceError::InvalidCertificateRequestInventoryResponse)?;
            if expected_total.is_some_and(|expected| expected != total) {
                return Err(ResourceError::InvalidCertificateRequestInventoryResponse);
            }
            expected_total = Some(total);
            for request in page.items {
                if !seen_ids.insert(request.id.clone()) {
                    return Err(ResourceError::InvalidCertificateRequestInventoryResponse);
                }
                if request.id == request_id.as_str() {
                    return Ok(request);
                }
            }
            next = page.next;
        }
        Err(ResourceError::InvalidCertificateRequestScope)
    }

    /// Reveal certificate material from one issued project-bound request.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, state, scope, typed client, or response-contract error.
    pub async fn reveal_certificate_request_material(
        &self,
        project_id: &CertificateAuthorityProjectId,
        request_id: &CertificateRequestId,
        confirm_reveal: bool,
    ) -> Result<CertificateRequestMaterial, ResourceError> {
        if !confirm_reveal {
            return Err(ResourceError::CertificateRequestRevealNotConfirmed);
        }
        let request = self.get_certificate_request(project_id, request_id).await?;
        if request.status != CertificateRequestStatus::Issued {
            return Err(ResourceError::InvalidCertificateRequestState);
        }
        let expected_certificate = request
            .certificate
            .as_ref()
            .ok_or(ResourceError::InvalidCertificateRequestState)?;
        let response = self
            .execute_observable_read::<GetCertificateRequestResult>(&CertificateRequestTarget {
                request_id: request_id.clone(),
            })
            .await?;
        let certificate_id = response
            .certificate_id
            .filter(|value| is_uuid(value))
            .ok_or(ResourceError::InvalidCertificateRequestMaterialResponse)?
            .to_ascii_lowercase();
        let serial_number = response
            .serial_number
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= MAX_SERIAL_NUMBER_BYTES
                    && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or(ResourceError::InvalidCertificateRequestMaterialResponse)?;
        let certificate = response
            .certificate
            .filter(|value| value.len() <= MAX_CERTIFICATE_PEM_BYTES)
            .and_then(|value| normalize_pem(&value))
            .ok_or(ResourceError::InvalidCertificateRequestMaterialResponse)?;
        let Some(certificate_der) = certificate_bundle_der(&certificate)
            .filter(|certificates| certificates.len() == 1)
            .and_then(|mut certificates| certificates.pop())
        else {
            return Err(ResourceError::InvalidCertificateRequestMaterialResponse);
        };
        let Ok((remainder, parsed_certificate)) = X509Certificate::from_der(&certificate_der)
        else {
            return Err(ResourceError::InvalidCertificateRequestMaterialResponse);
        };
        let private_key = response
            .private_key
            .map(|key| {
                normalize_pem(key.expose_secret())
                    .map(SecretValue::new)
                    .ok_or(ResourceError::InvalidCertificateRequestMaterialResponse)
            })
            .transpose()?;
        if response.status != CertificateRequestStatus::Issued
            || certificate_id != expected_certificate.id
            || serial_number != expected_certificate.serial_number
            || response.common_name != request.common_name
            || response.created_at != request.created_at
            || response.updated_at != request.updated_at
            || !remainder.is_empty()
            || !is_valid_single_certificate(&certificate)
            || !certificate_serial_matches(&parsed_certificate, &serial_number)
            || !certificate_subject_values_match(
                &parsed_certificate,
                request.common_name.as_deref(),
                request.alternative_names.as_deref(),
            )
            || private_key.as_ref().is_some_and(|key| {
                !private_key_matches_certificate(&parsed_certificate, key.expose_secret())
            })
        {
            return Err(ResourceError::InvalidCertificateRequestMaterialResponse);
        }
        Ok(CertificateRequestMaterial {
            project_id: project_id.as_str().to_owned(),
            request_id: request_id.as_str().to_owned(),
            certificate_id,
            serial_number,
            certificate,
            private_key,
        })
    }

    /// Cancel one pending project-bound certificate request exactly once.
    ///
    /// # Errors
    ///
    /// Returns a confirmation, state, scope, typed client, or response-contract error.
    pub async fn cancel_certificate_request(
        &self,
        project_id: &CertificateAuthorityProjectId,
        request_id: &CertificateRequestId,
        confirm: bool,
    ) -> Result<CertificateRequestCancellation, ResourceError> {
        if !confirm {
            return Err(ResourceError::CertificateRequestCancelNotConfirmed);
        }
        let request = self.get_certificate_request(project_id, request_id).await?;
        if !matches!(
            request.status,
            CertificateRequestStatus::Pending | CertificateRequestStatus::PendingValidation
        ) {
            return Err(ResourceError::InvalidCertificateRequestState);
        }
        let response = self
            .execute_mutation::<CancelCertificateRequest>(&CertificateRequestTarget {
                request_id: request_id.clone(),
            })
            .await?;
        if (response.cancelled && response.status != CertificateRequestStatus::Failed)
            || (!response.cancelled
                && matches!(
                    response.status,
                    CertificateRequestStatus::Pending | CertificateRequestStatus::PendingValidation
                ))
        {
            return Err(ResourceError::InvalidCertificateRequestCancellationResponse);
        }
        Ok(CertificateRequestCancellation {
            project_id: project_id.as_str().to_owned(),
            request_id: request_id.as_str().to_owned(),
            cancelled: response.cancelled,
            status: response.status,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };
    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::{
        CertificateRequestId, CertificateRequestListRequest, CertificateRequestSort,
        CertificateRequestSortOrder, CertificateRequestStatus, certificate_subject_values_match,
    };
    use crate::{
        CertificateAuthorityProjectId, InfisicalClient, PageRequest, ResourceError,
        certificate::certificate_bundle_der,
        test_support::{mount_login, settings},
    };

    const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const REQUEST_ID: &str = "22222222-2222-4222-8222-222222222222";
    const CERTIFICATE_ID: &str = "33333333-3333-4333-8333-333333333333";
    const PROFILE_ID: &str = "44444444-4444-4444-8444-444444444444";
    const CREATED_AT: &str = "2026-07-21T12:00:00.000Z";
    const UPDATED_AT: &str = "2026-07-21T12:00:01.000Z";
    const SERIAL: &str = "A1B2";

    fn project_id() -> CertificateAuthorityProjectId {
        CertificateAuthorityProjectId::new(PROJECT_ID).unwrap()
    }

    fn request_id() -> CertificateRequestId {
        CertificateRequestId::new(REQUEST_ID).unwrap()
    }

    fn certificate_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-cert.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn private_key_fixture() -> &'static str {
        include_str!("../test-fixtures/profile-private-key.txt")
            .strip_suffix('\n')
            .unwrap()
    }

    fn request_value(status: &str) -> Value {
        let issued = status == "issued";
        json!({
            "id": REQUEST_ID,
            "status": status,
            "commonName": "api.example.test",
            "altNames": "api.example.test,www.example.test",
            "profileId": PROFILE_ID,
            "profileName": "api-profile",
            "caId": null,
            "certificateId": issued.then_some(CERTIFICATE_ID),
            "approvalRequestId": null,
            "errorMessage": "discard this upstream text",
            "pendingMessage": "discard this upstream text",
            "createdAt": CREATED_AT,
            "updatedAt": UPDATED_AT,
            "certificate": issued.then(|| json!({
                "id": CERTIFICATE_ID,
                "serialNumber": SERIAL,
                "status": "active"
            }))
        })
    }

    async fn mount_exact_inventory(server: &MockServer, status: &str) {
        let mut request = request_value(status);
        if status == "issued" {
            request["commonName"] = json!("certificate-profile.example");
            request["altNames"] = Value::Null;
        }
        Mock::given(method("POST"))
            .and(path(
                "/api/v1/cert-manager/certificates/certificate-requests/search",
            ))
            .and(body_json(json!({
                "projectId": PROJECT_ID,
                "offset": 0,
                "limit": 100,
                "sortBy": "createdAt",
                "sortOrder": "asc"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateRequests": [request],
                "totalCount": 1
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[test]
    fn request_inputs_reject_ambiguous_filters_and_dates() {
        assert!(CertificateRequestId::new("not-an-id").is_err());
        let page = PageRequest::new(0, 20).unwrap();
        assert!(
            CertificateRequestListRequest::new(
                project_id(),
                page,
                Some(" api".to_owned()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .is_err()
        );
        assert!(
            CertificateRequestListRequest::new(
                project_id(),
                page,
                None,
                None,
                Some(UPDATED_AT.to_owned()),
                Some(CREATED_AT.to_owned()),
                None,
                None,
                None,
            )
            .is_err()
        );
        assert!(
            CertificateRequestListRequest::new(
                project_id(),
                page,
                None,
                None,
                None,
                None,
                Some(vec![PROFILE_ID.to_owned(), PROFILE_ID.to_owned()]),
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn parsed_leaf_subject_must_match_request_inventory() {
        let der = certificate_bundle_der(certificate_fixture())
            .unwrap()
            .remove(0);
        let (_, certificate) = X509Certificate::from_der(&der).unwrap();
        assert!(certificate_subject_values_match(
            &certificate,
            Some("certificate-profile.example"),
            None,
        ));
        assert!(!certificate_subject_values_match(
            &certificate,
            Some("other.example.test"),
            None,
        ));
        assert!(!certificate_subject_values_match(
            &certificate,
            Some("certificate-profile.example"),
            Some("unexpected.example.test"),
        ));
    }

    #[tokio::test]
    async fn request_inventory_is_project_scoped_bounded_and_sanitized() {
        let server = MockServer::start().await;
        mount_login(&server, "request-list-token").await;
        Mock::given(method("POST"))
            .and(path(
                "/api/v1/cert-manager/certificates/certificate-requests/search",
            ))
            .and(body_json(json!({
                "projectId": PROJECT_ID,
                "offset": 0,
                "limit": 20,
                "search": "api.example",
                "status": "issued",
                "fromDate": CREATED_AT,
                "toDate": UPDATED_AT,
                "profileIds": [PROFILE_ID],
                "sortBy": "updatedAt",
                "sortOrder": "desc"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateRequests": [request_value("issued")],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&server)
            .await;

        let request = CertificateRequestListRequest::new(
            project_id(),
            PageRequest::new(0, 20).unwrap(),
            Some("api.example".to_owned()),
            Some(CertificateRequestStatus::Issued),
            Some(CREATED_AT.to_owned()),
            Some(UPDATED_AT.to_owned()),
            Some(vec![PROFILE_ID.to_owned()]),
            Some(CertificateRequestSort::UpdatedAt),
            Some(CertificateRequestSortOrder::Desc),
        )
        .unwrap();
        let page = InfisicalClient::new(settings(&server))
            .unwrap()
            .list_certificate_requests(request)
            .await
            .unwrap();
        assert_eq!(page.items[0].project_id, PROJECT_ID);
        assert_eq!(page.items[0].id, REQUEST_ID);
        assert_eq!(
            page.items[0].certificate_id.as_deref(),
            Some(CERTIFICATE_ID)
        );
    }

    #[tokio::test]
    async fn confirmations_fail_before_authentication_or_inventory_reads() {
        let server = MockServer::start().await;
        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert!(matches!(
            client
                .reveal_certificate_request_material(&project_id(), &request_id(), false)
                .await,
            Err(ResourceError::CertificateRequestRevealNotConfirmed)
        ));
        assert!(matches!(
            client
                .cancel_certificate_request(&project_id(), &request_id(), false)
                .await,
            Err(ResourceError::CertificateRequestCancelNotConfirmed)
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn issued_result_reveal_binds_inventory_certificate_and_matching_key() {
        let server = MockServer::start().await;
        mount_login(&server, "request-result-token").await;
        mount_exact_inventory(&server, "issued").await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/certificate-requests/{REQUEST_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "issued",
                "certificate": certificate_fixture(),
                "certificateId": CERTIFICATE_ID,
                "privateKey": private_key_fixture(),
                "serialNumber": SERIAL,
                "commonName": "certificate-profile.example",
                "createdAt": CREATED_AT,
                "updatedAt": UPDATED_AT
            })))
            .expect(1)
            .mount(&server)
            .await;

        let material = InfisicalClient::new(settings(&server))
            .unwrap()
            .reveal_certificate_request_material(&project_id(), &request_id(), true)
            .await
            .unwrap();
        assert_eq!(material.project_id, PROJECT_ID);
        assert_eq!(material.certificate_id, CERTIFICATE_ID);
        assert_eq!(
            material.private_key.unwrap().expose_secret(),
            private_key_fixture()
        );
    }

    #[tokio::test]
    async fn cancellation_preflights_pending_state_and_sends_one_bodyless_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "request-cancel-token").await;
        mount_exact_inventory(&server, "pending_validation").await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/certificate-requests/{REQUEST_ID}/cancel"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "failed",
                "cancelled": true,
                "errorMessage": "Cancelled by identity operator"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let receipt = InfisicalClient::new(settings(&server))
            .unwrap()
            .cancel_certificate_request(&project_id(), &request_id(), true)
            .await
            .unwrap();
        assert!(receipt.cancelled);
        assert_eq!(receipt.status, CertificateRequestStatus::Failed);
        let requests = server.received_requests().await.unwrap();
        let cancellation = requests
            .iter()
            .find(|request| request.url.path().ends_with("/cancel"))
            .unwrap();
        assert!(cancellation.body.is_empty());
    }

    #[tokio::test]
    async fn cancellation_rejects_terminal_state_before_mutation() {
        let server = MockServer::start().await;
        mount_login(&server, "request-state-token").await;
        mount_exact_inventory(&server, "issued").await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/certificate-requests/{REQUEST_ID}/cancel"
            )))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let error = InfisicalClient::new(settings(&server))
            .unwrap()
            .cancel_certificate_request(&project_id(), &request_id(), true)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ResourceError::InvalidCertificateRequestState
        ));
    }
}
