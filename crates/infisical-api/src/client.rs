use std::{sync::Arc, time::Duration};

use reqwest::{Method, RequestBuilder, StatusCode, dns::Resolve, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::{
    sync::{Mutex, watch},
    time::Instant,
};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    PrivateHttpResolver, ResolutionPolicy, SecretValue, SystemResolver, url_resolution_policy,
};

const UNIVERSAL_AUTH_LOGIN_PATH: &str = "auth/universal-auth/login";
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAXIMUM_REQUEST_TIMEOUT: Duration = Duration::from_mins(2);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(30);

/// Complete configuration for the typed Infisical REST client.
#[derive(Debug)]
pub struct ClientSettings {
    pub api_url: Url,
    pub client_id: String,
    pub client_secret: SecretValue,
    pub organization_slug: Option<String>,
    /// Permit cleartext HTTP only for explicitly private network authorities.
    pub allow_private_http: bool,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    pub token_refresh_skew: Duration,
}

impl ClientSettings {
    /// Construct settings with production-safe request and response bounds.
    #[must_use]
    pub fn new(api_url: Url, client_id: String, client_secret: SecretValue) -> Self {
        Self {
            api_url,
            client_id,
            client_secret,
            organization_slug: None,
            allow_private_http: false,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            token_refresh_skew: DEFAULT_TOKEN_REFRESH_SKEW,
        }
    }
}

/// A typed, bounded client authenticated by a dedicated Universal Auth identity.
#[derive(Clone)]
pub struct InfisicalClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    settings: ClientSettings,
    http: reqwest::Client,
    token: tokio::sync::RwLock<Option<Arc<CachedToken>>>,
    refresh: Mutex<RefreshCoordinator>,
}

type RefreshOutcome = Result<Arc<CachedToken>, ClientError>;

struct RefreshCoordinator {
    in_flight: Option<watch::Receiver<Option<RefreshOutcome>>>,
}

struct CachedToken {
    value: SecretValue,
    refresh_after: Instant,
}

impl CachedToken {
    fn is_fresh(&self, now: Instant) -> bool {
        now < self.refresh_after
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ApiVersion {
    V1,
    V2,
    V4,
}

impl ApiVersion {
    const fn segment(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
            Self::V4 => "v4",
        }
    }
}

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct Endpoint {
    version: ApiVersion,
    segments: Vec<String>,
}

impl Endpoint {
    pub(crate) fn from_static(version: ApiVersion, path: &'static str) -> Self {
        Self {
            version,
            segments: path.split('/').map(str::to_owned).collect(),
        }
    }

    pub(crate) fn from_segments<I, S>(version: ApiVersion, segments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            version,
            segments: segments.into_iter().map(Into::into).collect(),
        }
    }

    fn is_valid(&self) -> bool {
        !self.segments.is_empty()
            && self
                .segments
                .iter()
                .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
    }
}

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// A read operation declared by one of this crate's typed resource modules.
///
/// This trait is sealed; downstream callers select provided operations rather
/// than supplying an arbitrary HTTP path.
pub trait ReadOperation: sealed::Sealed {
    type Query: Serialize + ?Sized;
    type Output: DeserializeOwned;

    #[doc(hidden)]
    fn endpoint(query: &Self::Query) -> Endpoint;
}

/// An externally observable GET operation declared by a typed resource module.
///
/// This trait is separate from [`ReadOperation`] because these requests must
/// never be replayed automatically, even when authentication is rejected.
pub trait ObservableReadOperation: sealed::Sealed {
    type Query: Serialize + ?Sized;
    type Output: DeserializeOwned;

    #[doc(hidden)]
    fn endpoint(query: &Self::Query) -> Endpoint;
}

/// An externally observable read whose fixed upstream route accepts a JSON body.
///
/// This covers typed search endpoints that use POST without treating them as
/// mutations. Like [`ObservableReadOperation`], these requests are sent once
/// and are not replayed after an authentication failure.
pub trait ObservableReadBodyOperation: sealed::Sealed {
    type Input: Serialize + ?Sized;
    type Output: DeserializeOwned;

    #[doc(hidden)]
    fn endpoint(input: &Self::Input) -> Endpoint;
}

/// A mutation declared by one of this crate's typed resource modules.
///
/// This trait is sealed; the owning module fixes both method and path, and the
/// client never retries the operation automatically.
pub trait MutationOperation: sealed::Sealed {
    type Input: Serialize + ?Sized;
    type Output: DeserializeOwned;

    #[doc(hidden)]
    fn method() -> Method;

    #[doc(hidden)]
    fn endpoint(input: &Self::Input) -> Endpoint;

    /// Return non-secret query parameters required by this fixed operation.
    ///
    /// The operation remains sealed so downstream callers cannot use this hook
    /// to construct arbitrary requests. Secret material must stay in the JSON
    /// body.
    #[doc(hidden)]
    fn query(_input: &Self::Input) -> Vec<(&'static str, String)> {
        Vec::new()
    }

    /// Whether this operation sends its input as a JSON body.
    ///
    /// Query-only mutations override this to avoid duplicating coordinates in
    /// an undocumented request body.
    #[doc(hidden)]
    #[must_use]
    fn sends_json_body() -> bool {
        true
    }

    /// Whether a successful empty response is the declared operation contract.
    #[doc(hidden)]
    #[must_use]
    fn accepts_empty_response() -> bool {
        false
    }
}

impl InfisicalClient {
    /// Effective response body ceiling, safe to publish in discovery.
    #[must_use]
    pub fn max_response_bytes(&self) -> usize {
        self.inner.settings.max_response_bytes
    }

    /// Effective timeout for each upstream request, safe to publish in discovery.
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        self.inner.settings.request_timeout
    }

    /// Build a redirect-free client that ignores ambient proxy configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the API URL, credentials, organization scope, or
    /// bounds are unsafe, or when the HTTP client cannot be constructed.
    pub fn new(settings: ClientSettings) -> Result<Self, ClientConfigError> {
        Self::new_with_system_resolver(settings, SystemResolver)
    }

    fn new_with_system_resolver<R>(
        settings: ClientSettings,
        system_resolver: R,
    ) -> Result<Self, ClientConfigError>
    where
        R: Resolve + 'static,
    {
        let resolution_policy = validate_settings(&settings)?;
        let mut http_builder = reqwest::Client::builder()
            .timeout(settings.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if resolution_policy == ResolutionPolicy::PrivateOnly {
            // Every connection revalidates DNS and the connector uses only the
            // accepted addresses, so a rebinding cannot redirect credentials.
            http_builder = http_builder.dns_resolver(PrivateHttpResolver::new(system_resolver));
        }
        let http = http_builder
            .build()
            .map_err(|_| ClientConfigError::HttpClient)?;
        Ok(Self {
            inner: Arc::new(ClientInner {
                settings,
                http,
                token: tokio::sync::RwLock::new(None),
                refresh: Mutex::new(RefreshCoordinator { in_flight: None }),
            }),
        })
    }

    /// Execute a crate-declared idempotent read, refreshing authentication and
    /// retrying exactly once when Infisical rejects the first access token.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration-independent transport, response-bound,
    /// decoding, authentication, permission, resource, or upstream error.
    pub async fn execute_read<O>(&self, query: &O::Query) -> Result<O::Output, ClientError>
    where
        O: ReadOperation,
    {
        let endpoint = O::endpoint(query);
        let first = self.execute_get_once(&endpoint, query).await;
        if !matches!(first, Err(ClientError::Api(ref error)) if error.kind == ApiErrorKind::Authentication)
        {
            return first;
        }

        self.execute_get_once(&endpoint, query).await
    }

    /// Execute one externally observable typed GET without automatic replay.
    ///
    /// An authentication rejection invalidates the cached access token for the
    /// next caller, but this invocation still returns the rejection after one
    /// upstream request.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration-independent transport, response-bound,
    /// decoding, authentication, permission, resource, or upstream error.
    pub async fn execute_observable_read<O>(
        &self,
        query: &O::Query,
    ) -> Result<O::Output, ClientError>
    where
        O: ObservableReadOperation,
    {
        self.execute_get_once(&O::endpoint(query), query).await
    }

    /// Execute one externally observable typed POST read without automatic replay.
    ///
    /// # Errors
    ///
    /// Returns a typed transport, response-bound, decoding, authentication,
    /// permission, resource, or upstream error after at most one request.
    pub async fn execute_observable_read_body<O>(
        &self,
        body: &O::Input,
    ) -> Result<O::Output, ClientError>
    where
        O: ObservableReadBodyOperation,
    {
        let url = self.endpoint_url(&O::endpoint(body))?;
        let token = self.access_token().await?;
        let response = self
            .send_json(
                self.inner
                    .http
                    .post(url)
                    .bearer_auth(token.value.expose_secret())
                    .json(body),
            )
            .await;
        if matches!(response, Err(ClientError::Api(ref error)) if error.kind == ApiErrorKind::Authentication)
        {
            self.invalidate_if_current(&token).await;
        }
        response
    }

    /// Execute a crate-declared mutation exactly once.
    ///
    /// # Errors
    ///
    /// Returns a typed transport, response-bound, decoding, authentication,
    /// permission, resource, or upstream error without replaying the mutation.
    pub async fn execute_mutation<O>(&self, body: &O::Input) -> Result<O::Output, ClientError>
    where
        O: MutationOperation,
    {
        let method = O::method();
        if !matches!(
            method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            return Err(ClientError::InvalidEndpoint);
        }
        let url = self.endpoint_url(&O::endpoint(body))?;
        let token = self.access_token().await?;
        let mut request = self
            .inner
            .http
            .request(method, url)
            .bearer_auth(token.value.expose_secret());
        let query = O::query(body);
        if !query.is_empty() {
            request = request.query(&query);
        }
        if O::sends_json_body() {
            request = request.json(body);
        }
        let response = self
            .send_json_with_empty_policy(request, O::accepts_empty_response())
            .await
            .map_err(|error| match error {
                ClientError::InvalidResponse => ClientError::InvalidMutationResponse,
                other => other,
            });
        if matches!(response, Err(ClientError::Api(ref error)) if error.kind == ApiErrorKind::Authentication)
        {
            self.invalidate_if_current(&token).await;
        }
        response
    }

    async fn execute_get_once<Q, T>(&self, endpoint: &Endpoint, query: &Q) -> Result<T, ClientError>
    where
        Q: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let url = self.endpoint_url(endpoint)?;
        let token = self.access_token().await?;
        let response = self
            .send_json(
                self.inner
                    .http
                    .get(url)
                    .query(query)
                    .bearer_auth(token.value.expose_secret()),
            )
            .await;
        if matches!(response, Err(ClientError::Api(ref error)) if error.kind == ApiErrorKind::Authentication)
        {
            self.invalidate_if_current(&token).await;
        }
        response
    }

    /// Classify whether a typed read capability is available to this identity.
    ///
    /// # Errors
    ///
    /// Returns errors other than the expected not-found and permission-denied
    /// capability outcomes.
    pub async fn probe_capability<O>(
        &self,
        query: &O::Query,
    ) -> Result<CapabilityAvailability, ClientError>
    where
        O: ReadOperation,
    {
        match self.execute_read::<O>(query).await {
            Ok(_) => Ok(CapabilityAvailability::Available),
            Err(ClientError::Api(error)) if error.kind == ApiErrorKind::NotFound => {
                Ok(CapabilityAvailability::Unavailable)
            }
            Err(ClientError::Api(error)) if error.kind == ApiErrorKind::PermissionDenied => {
                Ok(CapabilityAvailability::PermissionDenied)
            }
            Err(error) => Err(error),
        }
    }

    async fn access_token(&self) -> Result<Arc<CachedToken>, ClientError> {
        if let Some(token) = self.fresh_token().await {
            return Ok(token);
        }

        let mut coordinator = self.inner.refresh.lock().await;
        if let Some(token) = self.fresh_token().await {
            return Ok(token);
        }

        let mut receiver = if let Some(receiver) = coordinator.in_flight.as_ref() {
            receiver.clone()
        } else {
            let (sender, receiver) = watch::channel(None);
            coordinator.in_flight = Some(receiver.clone());
            let flight_identity = receiver.clone();
            let client = self.clone();
            // Refresh work outlives its initiating caller so cancellation cannot
            // strand waiters or provoke a duplicate login.
            let _refresh_task = tokio::spawn(async move {
                let outcome = client.login().await.map(Arc::new);
                if let Ok(token) = &outcome {
                    *client.inner.token.write().await = Some(Arc::clone(token));
                }
                sender.send_replace(Some(outcome));
                client.clear_refresh(&flight_identity).await;
            });
            receiver
        };
        drop(coordinator);

        let outcome = receiver
            .wait_for(Option::is_some)
            .await
            .map(|outcome| outcome.as_ref().cloned());
        if let Ok(Some(outcome)) = outcome {
            outcome
        } else {
            self.clear_refresh(&receiver).await;
            Err(ClientError::RefreshInterrupted)
        }
    }

    async fn fresh_token(&self) -> Option<Arc<CachedToken>> {
        let now = Instant::now();
        self.inner
            .token
            .read()
            .await
            .as_ref()
            .filter(|token| token.is_fresh(now))
            .map(Arc::clone)
    }

    async fn clear_refresh(&self, completed: &watch::Receiver<Option<RefreshOutcome>>) {
        let mut coordinator = self.inner.refresh.lock().await;
        if coordinator
            .in_flight
            .as_ref()
            .is_some_and(|current| current.same_channel(completed))
        {
            coordinator.in_flight = None;
        }
    }

    async fn invalidate_if_current(&self, used: &Arc<CachedToken>) {
        let mut cached = self.inner.token.write().await;
        if cached
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, used))
        {
            *cached = None;
        }
    }

    async fn login(&self) -> Result<CachedToken, ClientError> {
        let request = UniversalAuthLoginRequest {
            client_id: &self.inner.settings.client_id,
            client_secret: self.inner.settings.client_secret.expose_secret(),
            organization_slug: self.inner.settings.organization_slug.as_deref(),
        };
        let login_started_at = Instant::now();
        let response: UniversalAuthLoginResponse = self
            .send_json(
                self.inner
                    .http
                    .post(self.endpoint_url(&Endpoint::from_static(
                        ApiVersion::V1,
                        UNIVERSAL_AUTH_LOGIN_PATH,
                    ))?)
                    .json(&request),
            )
            .await?;
        if response.access_token.0.expose_secret().is_empty() || response.expires_in == 0 {
            return Err(ClientError::InvalidResponse);
        }
        let ttl = Duration::from_secs(response.expires_in);
        let skew = self.inner.settings.token_refresh_skew.min(ttl / 2);
        let refresh_after = login_started_at
            .checked_add(ttl.saturating_sub(skew))
            .ok_or(ClientError::InvalidResponse)?;
        Ok(CachedToken {
            value: response.access_token.0,
            refresh_after,
        })
    }

    fn endpoint_url(&self, endpoint: &Endpoint) -> Result<Url, ClientError> {
        if !endpoint.is_valid() {
            return Err(ClientError::InvalidEndpoint);
        }
        let mut url = self.inner.settings.api_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| ClientError::InvalidEndpoint)?;
            segments
                .clear()
                .push("api")
                .push(endpoint.version.segment());
            for segment in &endpoint.segments {
                segments.push(segment);
            }
        }
        Ok(url)
    }

    async fn send_json<T>(&self, request: RequestBuilder) -> Result<T, ClientError>
    where
        T: DeserializeOwned,
    {
        self.send_json_with_empty_policy(request, false).await
    }

    async fn send_json_with_empty_policy<T>(
        &self,
        request: RequestBuilder,
        accepts_empty_response: bool,
    ) -> Result<T, ClientError>
    where
        T: DeserializeOwned,
    {
        let mut response = request
            .send()
            .await
            .map_err(|error| map_transport_error(&error))?;
        let status = response.status();
        if !status.is_success() {
            return Err(ClientError::Api(ApiFailure {
                kind: ApiErrorKind::from_status(status),
                status: status.as_u16(),
                request_id: safe_request_id(response.headers()),
            }));
        }
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| map_transport_error(&error))?
        {
            let new_length =
                body.len()
                    .checked_add(chunk.len())
                    .ok_or(ClientError::ResponseTooLarge {
                        limit: self.inner.settings.max_response_bytes,
                    })?;
            if new_length > self.inner.settings.max_response_bytes {
                return Err(ClientError::ResponseTooLarge {
                    limit: self.inner.settings.max_response_bytes,
                });
            }
            grow_response_buffer(
                &mut body,
                new_length,
                self.inner.settings.max_response_bytes,
            );
            body.extend_from_slice(&chunk);
        }
        if body.is_empty() && accepts_empty_response {
            serde_json::from_slice(b"null").map_err(|_| ClientError::InvalidResponse)
        } else {
            serde_json::from_slice(body.as_slice()).map_err(|_| ClientError::InvalidResponse)
        }
    }
}

/// Replace growing allocations explicitly so their initialized bytes are wiped
/// on drop, rather than released by Vec's internal reallocation.
fn grow_response_buffer(body: &mut Zeroizing<Vec<u8>>, required: usize, limit: usize) {
    if required <= body.capacity() {
        return;
    }
    let capacity = body.capacity().saturating_mul(2).max(required).min(limit);
    let mut replacement = Zeroizing::new(Vec::with_capacity(capacity));
    replacement.extend_from_slice(body);
    *body = replacement;
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UniversalAuthLoginRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_slug: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UniversalAuthLoginResponse {
    access_token: DeserializedSecret,
    expires_in: u64,
    #[serde(rename = "accessTokenMaxTTL")]
    _access_token_max_ttl: u64,
    #[serde(rename = "tokenType")]
    _token_type: TokenType,
}

#[derive(Deserialize)]
enum TokenType {
    Bearer,
}

pub(crate) struct DeserializedSecret(pub(crate) SecretValue);

impl<'de> Deserialize<'de> for DeserializedSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(SecretValue::new(value)))
    }
}

fn validate_settings(settings: &ClientSettings) -> Result<ResolutionPolicy, ClientConfigError> {
    let resolution_policy = url_policy(&settings.api_url, settings.allow_private_http)
        .ok_or(ClientConfigError::UnsafeApiUrl)?;
    if settings.client_id.is_empty()
        || settings.client_id.trim() != settings.client_id
        || settings.client_secret.expose_secret().is_empty()
        || settings.client_secret.expose_secret().trim() != settings.client_secret.expose_secret()
    {
        return Err(ClientConfigError::InvalidCredential);
    }
    if settings
        .organization_slug
        .as_ref()
        .is_some_and(|slug| !is_valid_slug(slug))
    {
        return Err(ClientConfigError::InvalidOrganizationSlug);
    }
    if settings.request_timeout.is_zero()
        || settings.request_timeout > MAXIMUM_REQUEST_TIMEOUT
        || settings.max_response_bytes == 0
        || settings.max_response_bytes > MAXIMUM_RESPONSE_BYTES
        || settings.token_refresh_skew.is_zero()
    {
        return Err(ClientConfigError::InvalidBounds);
    }
    Ok(resolution_policy)
}

fn url_policy(url: &Url, allow_private_http: bool) -> Option<ResolutionPolicy> {
    if url.path() != "/" {
        return None;
    }
    url_resolution_policy(url, allow_private_http)
}

fn is_valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn safe_request_id(headers: &header::HeaderMap) -> Option<String> {
    let value = headers.get("x-request-id")?.to_str().ok()?;
    (value.len() <= 128
        && !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.')))
    .then(|| value.to_owned())
}

fn map_transport_error(error: &reqwest::Error) -> ClientError {
    let kind = if error.is_timeout() {
        TransportErrorKind::Timeout
    } else if error.is_connect() {
        TransportErrorKind::Connect
    } else {
        TransportErrorKind::Other
    };
    ClientError::Transport(kind)
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ClientConfigError {
    #[error(
        "Infisical API URL must be HTTPS, loopback HTTP, or explicitly allowed private HTTP without userinfo, query, fragment, or path"
    )]
    UnsafeApiUrl,
    #[error("Universal Auth credentials must be non-empty and have no surrounding whitespace")]
    InvalidCredential,
    #[error(
        "Universal Auth organization slug must contain 1 to 64 lowercase letters, numbers, or hyphen-separated segments"
    )]
    InvalidOrganizationSlug,
    #[error("Infisical client timing or response-size bounds are invalid")]
    InvalidBounds,
    #[error("failed to construct the bounded Infisical HTTP client")]
    HttpClient,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ClientError {
    #[error("Infisical transport failed: {0}")]
    Transport(TransportErrorKind),
    #[error("Infisical response exceeded the {limit}-byte limit")]
    ResponseTooLarge { limit: usize },
    #[error("Infisical returned an invalid response")]
    InvalidResponse,
    #[error(
        "Infisical returned an invalid mutation response; the operation may have succeeded, so reconcile its state before retrying"
    )]
    InvalidMutationResponse,
    #[error("internal Infisical endpoint declaration is invalid")]
    InvalidEndpoint,
    #[error("Infisical authentication refresh was interrupted")]
    RefreshInterrupted,
    #[error(transparent)]
    Api(ApiFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportErrorKind {
    Timeout,
    Connect,
    Other,
}

impl std::fmt::Display for TransportErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Timeout => "request timed out",
            Self::Connect => "connection failed",
            Self::Other => "request failed",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiFailure {
    kind: ApiErrorKind,
    status: u16,
    request_id: Option<String>,
}

impl ApiFailure {
    #[must_use]
    pub fn kind(&self) -> ApiErrorKind {
        self.kind
    }

    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
}

impl std::fmt::Display for ApiFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Infisical API {} (HTTP {})",
            self.kind, self.status
        )?;
        if let Some(request_id) = self.request_id() {
            write!(formatter, "; request ID {request_id}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiFailure {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiErrorKind {
    InvalidRequest,
    Authentication,
    PermissionDenied,
    NotFound,
    Conflict,
    RateLimited,
    Server,
}

impl ApiErrorKind {
    fn from_status(status: StatusCode) -> Self {
        match status {
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => Self::InvalidRequest,
            StatusCode::UNAUTHORIZED => Self::Authentication,
            StatusCode::FORBIDDEN => Self::PermissionDenied,
            StatusCode::NOT_FOUND => Self::NotFound,
            StatusCode::CONFLICT => Self::Conflict,
            StatusCode::TOO_MANY_REQUESTS => Self::RateLimited,
            _ => Self::Server,
        }
    }
}

impl std::fmt::Display for ApiErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "rejected the request",
            Self::Authentication => "rejected authentication",
            Self::PermissionDenied => "denied permission",
            Self::NotFound => "did not find the resource",
            Self::Conflict => "reported a conflict",
            Self::RateLimited => "rate limited the request",
            Self::Server => "reported a server error",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityAvailability {
    Available,
    Unavailable,
    PermissionDenied,
}

#[cfg(test)]
mod tests {
    #[test]
    fn response_growth_preserves_bytes_without_implicit_reallocation() {
        let limit = 128;
        let mut body = zeroize::Zeroizing::new(Vec::new());
        let chunks: [&[u8]; 4] = [b"first", b"-second", &[7; 70], &[8; 46]];
        let mut expected = Vec::new();
        for chunk in chunks {
            let required = body.len() + chunk.len();
            super::grow_response_buffer(&mut body, required, limit);
            let allocation = body.as_ptr();
            body.extend_from_slice(chunk);
            expected.extend_from_slice(chunk);
            assert_eq!(body.as_ptr(), allocation);
            assert_eq!(body.as_slice(), expected);
            assert!(body.capacity() <= limit);
        }
        assert_eq!(body.len(), limit);
    }

    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use reqwest::{
        Method, StatusCode,
        dns::{Addrs, Name, Resolve, Resolving},
        header::HeaderMap,
    };
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use tokio::{sync::Notify, task::JoinSet, time::Instant};
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    use super::{
        ApiErrorKind, ApiFailure, ApiVersion, CachedToken, CapabilityAvailability,
        ClientConfigError, ClientError, ClientSettings, DEFAULT_MAX_RESPONSE_BYTES, Endpoint,
        InfisicalClient, MAXIMUM_REQUEST_TIMEOUT, MAXIMUM_RESPONSE_BYTES, MutationOperation,
        ObservableReadOperation, ReadOperation, TransportErrorKind, safe_request_id, sealed,
        url_policy,
    };
    use crate::{
        ResolutionPolicy, SecretValue,
        test_support::{LOGIN_PATH, login_response, mount_login, settings},
        validate_private_resolution,
    };
    struct TestRead;

    impl sealed::Sealed for TestRead {}

    impl ReadOperation for TestRead {
        type Query = [(&'static str, &'static str)];
        type Output = TestResponse;

        fn endpoint(_query: &Self::Query) -> Endpoint {
            Endpoint::from_static(ApiVersion::V1, "test/read")
        }
    }

    #[derive(Clone)]
    struct StaticResolver {
        calls: Arc<AtomicUsize>,
        addresses: Vec<SocketAddr>,
    }

    impl Resolve for StaticResolver {
        fn resolve(&self, _name: Name) -> Resolving {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let addresses = self.addresses.clone();
            Box::pin(async move { Ok(Box::new(addresses.into_iter()) as Addrs) })
        }
    }

    struct TestObservableRead;

    impl sealed::Sealed for TestObservableRead {}

    impl ObservableReadOperation for TestObservableRead {
        type Query = [(&'static str, &'static str)];
        type Output = TestResponse;

        fn endpoint(_query: &Self::Query) -> Endpoint {
            Endpoint::from_static(ApiVersion::V1, "test/observable-read")
        }
    }

    struct TestMutationOperation;

    impl sealed::Sealed for TestMutationOperation {}

    impl MutationOperation for TestMutationOperation {
        type Input = TestMutation;
        type Output = TestResponse;

        fn method() -> Method {
            Method::POST
        }

        fn endpoint(_input: &Self::Input) -> Endpoint {
            Endpoint::from_static(ApiVersion::V1, "test/mutate")
        }
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct TestResponse {
        value: String,
    }

    #[derive(Serialize)]
    struct TestMutation {
        value: String,
    }

    #[tokio::test]
    async fn universal_auth_wire_and_concurrent_refresh_are_coalesced() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .and(body_json(json!({
                "clientId": "machine-client",
                "clientSecret": "client-secret-canary",
                "organizationSlug": "platform"
            })))
            .respond_with(login_response("access-token-one", 60))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/read"))
            .and(header("authorization", "Bearer access-token-one"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": "ok" })))
            .expect(8)
            .mount(&server)
            .await;

        let mut client_settings = settings(&server);
        client_settings.organization_slug = Some("platform".into());
        let client = InfisicalClient::new(client_settings).unwrap();
        let mut requests = JoinSet::new();
        for _ in 0..8 {
            let client = client.clone();
            requests.spawn(async move { client.execute_read::<TestRead>(&[]).await });
        }
        while let Some(result) = requests.join_next().await {
            assert_eq!(result.unwrap().unwrap().value, "ok");
        }
    }

    #[tokio::test]
    async fn fresh_access_token_is_reused_until_its_refresh_deadline() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(login_response("cached-token", 60))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/read"))
            .and(header("authorization", "Bearer cached-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": "cached" })))
            .expect(2)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let first = client.execute_read::<TestRead>(&[]).await.unwrap();
        let second = client.execute_read::<TestRead>(&[]).await.unwrap();

        assert_eq!(first.value, "cached");
        assert_eq!(second.value, "cached");
    }

    #[tokio::test]
    async fn concurrent_failed_refresh_is_shared_once() {
        let server = MockServer::start().await;
        let login_count = Arc::new(AtomicUsize::new(0));
        let responder_count = Arc::clone(&login_count);
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(move |_: &wiremock::Request| {
                responder_count.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(500).set_delay(Duration::from_millis(200))
            })
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let mut requests = JoinSet::new();
        for _ in 0..8 {
            let client = client.clone();
            requests.spawn(async move { client.execute_read::<TestRead>(&[]).await });
        }
        while let Some(result) = requests.join_next().await {
            assert!(matches!(
                result.unwrap().unwrap_err(),
                ClientError::Api(ref failure) if failure.kind() == ApiErrorKind::Server
            ));
        }
        assert_eq!(login_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refresh_outlives_cancellation_of_the_initiating_caller() {
        let server = MockServer::start().await;
        let login_count = Arc::new(AtomicUsize::new(0));
        let responder_count = Arc::clone(&login_count);
        let request_seen = Arc::new(Notify::new());
        let responder_seen = Arc::clone(&request_seen);
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(move |_: &wiremock::Request| {
                responder_count.fetch_add(1, Ordering::SeqCst);
                responder_seen.notify_one();
                login_response("surviving-token", 60).set_delay(Duration::from_millis(200))
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/read"))
            .and(header("authorization", "Bearer surviving-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": "ok" })))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let initiating_client = client.clone();
        let initiating_call =
            tokio::spawn(async move { initiating_client.execute_read::<TestRead>(&[]).await });
        tokio::time::timeout(Duration::from_secs(5), request_seen.notified())
            .await
            .expect("the refresh request must reach the mock within the test deadline");
        initiating_call.abort();
        assert!(initiating_call.await.unwrap_err().is_cancelled());

        assert_eq!(
            client.execute_read::<TestRead>(&[]).await.unwrap().value,
            "ok"
        );
        assert_eq!(login_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn read_authentication_failure_invalidates_and_retries_once() {
        let server = MockServer::start().await;
        let login_count = Arc::new(AtomicUsize::new(0));
        let responder_count = Arc::clone(&login_count);
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(move |_: &wiremock::Request| {
                let sequence = responder_count.fetch_add(1, Ordering::SeqCst);
                login_response(
                    if sequence == 0 {
                        "expired-token"
                    } else {
                        "replacement-token"
                    },
                    60,
                )
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/read"))
            .and(header("authorization", "Bearer expired-token"))
            .respond_with(ResponseTemplate::new(401).set_body_bytes(vec![b'x'; 1_024]))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/read"))
            .and(header("authorization", "Bearer replacement-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": "fresh" })))
            .expect(1)
            .mount(&server)
            .await;

        let mut client_settings = settings(&server);
        client_settings.max_response_bytes = 256;
        let client = InfisicalClient::new(client_settings).unwrap();
        let response = client.execute_read::<TestRead>(&[]).await.unwrap();

        assert_eq!(response.value, "fresh");
        assert_eq!(login_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn access_token_refreshes_before_expiry() {
        let server = MockServer::start().await;
        let login_count = Arc::new(AtomicUsize::new(0));
        let responder_count = Arc::clone(&login_count);
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(move |_: &wiremock::Request| {
                let sequence = responder_count.fetch_add(1, Ordering::SeqCst);
                login_response(
                    if sequence == 0 {
                        "first-token"
                    } else {
                        "second-token"
                    },
                    60,
                )
            })
            .expect(2)
            .mount(&server)
            .await;
        for token in ["first-token", "second-token"] {
            Mock::given(method("GET"))
                .and(path("/api/v1/test/read"))
                .and(header("authorization", format!("Bearer {token}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": token })))
                .expect(1)
                .mount(&server)
                .await;
        }

        let mut expiring_settings = settings(&server);
        expiring_settings.token_refresh_skew = Duration::from_secs(50);
        let client = InfisicalClient::new(expiring_settings).unwrap();
        let first = client.execute_read::<TestRead>(&[]).await.unwrap();
        let scheduled_refresh = client
            .inner
            .token
            .read()
            .await
            .as_ref()
            .unwrap()
            .refresh_after
            .saturating_duration_since(Instant::now());
        assert!(scheduled_refresh <= Duration::from_secs(30));
        assert!(scheduled_refresh > Duration::from_secs(25));
        *client.inner.token.write().await = Some(Arc::new(CachedToken {
            value: SecretValue::new("first-token"),
            refresh_after: Instant::now(),
        }));
        let second = client.execute_read::<TestRead>(&[]).await.unwrap();

        assert_eq!(first.value, "first-token");
        assert_eq!(second.value, "second-token");
        assert_eq!(login_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn login_latency_is_deducted_from_cached_token_freshness() {
        let server = MockServer::start().await;
        let login_count = Arc::new(AtomicUsize::new(0));
        let responder_count = Arc::clone(&login_count);
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(move |_: &wiremock::Request| {
                let sequence = responder_count.fetch_add(1, Ordering::SeqCst);
                if sequence == 0 {
                    login_response("delayed-token", 2).set_delay(Duration::from_millis(1_200))
                } else {
                    login_response("fresh-token", 60)
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        for (token, value) in [("delayed-token", "first"), ("fresh-token", "second")] {
            Mock::given(method("GET"))
                .and(path("/api/v1/test/read"))
                .and(header("authorization", format!("Bearer {token}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": value })))
                .expect(1)
                .mount(&server)
                .await;
        }

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let first = client.execute_read::<TestRead>(&[]).await.unwrap();
        let second = client.execute_read::<TestRead>(&[]).await.unwrap();

        assert_eq!(first.value, "first");
        assert_eq!(second.value, "second");
        assert_eq!(login_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn universal_auth_rejects_empty_tokens_and_zero_ttl_independently() {
        for (token, expires_in) in [("", 60), ("access-token", 0)] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(LOGIN_PATH))
                .respond_with(login_response(token, expires_in))
                .expect(1)
                .mount(&server)
                .await;
            let client = InfisicalClient::new(settings(&server)).unwrap();

            assert_eq!(
                client.execute_read::<TestRead>(&[]).await.unwrap_err(),
                ClientError::InvalidResponse
            );
        }
    }

    #[tokio::test]
    async fn mutation_authentication_failure_is_invalidated_but_never_replayed() {
        let server = MockServer::start().await;
        let login_count = Arc::new(AtomicUsize::new(0));
        let responder_count = Arc::clone(&login_count);
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(move |_: &wiremock::Request| {
                let sequence = responder_count.fetch_add(1, Ordering::SeqCst);
                login_response(
                    if sequence == 0 {
                        "mutation-token"
                    } else {
                        "replacement-mutation-token"
                    },
                    60,
                )
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/test/mutate"))
            .and(header("authorization", "Bearer mutation-token"))
            .respond_with(ResponseTemplate::new(401).set_body_bytes(vec![b'x'; 1_024]))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/test/mutate"))
            .and(header("authorization", "Bearer replacement-mutation-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": "changed" })))
            .expect(1)
            .mount(&server)
            .await;

        let mut client_settings = settings(&server);
        client_settings.max_response_bytes = 256;
        let client = InfisicalClient::new(client_settings).unwrap();
        let error = client
            .execute_mutation::<TestMutationOperation>(&TestMutation {
                value: "change".into(),
            })
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            ClientError::Api(ref failure) if failure.kind() == ApiErrorKind::Authentication
        ));
        assert_eq!(
            client
                .execute_mutation::<TestMutationOperation>(&TestMutation {
                    value: "change".into(),
                })
                .await
                .unwrap()
                .value,
            "changed"
        );
        assert_eq!(login_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalid_mutation_response_reports_an_unknown_outcome_without_replay() {
        let server = MockServer::start().await;
        mount_login(&server, "mutation-invalid-response-token").await;
        Mock::given(method("POST"))
            .and(path("/api/v1/test/mutate"))
            .and(header(
                "authorization",
                "Bearer mutation-invalid-response-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
            .expect(1)
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        assert_eq!(
            client
                .execute_mutation::<TestMutationOperation>(&TestMutation {
                    value: "change".into(),
                })
                .await
                .unwrap_err(),
            ClientError::InvalidMutationResponse
        );
    }

    #[tokio::test]
    async fn observable_read_authentication_failure_is_invalidated_but_never_replayed() {
        let server = MockServer::start().await;
        let login_count = Arc::new(AtomicUsize::new(0));
        let responder_count = Arc::clone(&login_count);
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(move |_: &wiremock::Request| {
                let sequence = responder_count.fetch_add(1, Ordering::SeqCst);
                login_response(
                    if sequence == 0 {
                        "observable-token"
                    } else {
                        "replacement-observable-token"
                    },
                    60,
                )
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/observable-read"))
            .and(header("authorization", "Bearer observable-token"))
            .respond_with(ResponseTemplate::new(401).set_body_bytes(vec![b'x'; 1_024]))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/observable-read"))
            .and(header(
                "authorization",
                "Bearer replacement-observable-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": "fresh" })))
            .expect(1)
            .mount(&server)
            .await;

        let mut client_settings = settings(&server);
        client_settings.max_response_bytes = 256;
        let client = InfisicalClient::new(client_settings).unwrap();
        let error = client
            .execute_observable_read::<TestObservableRead>(&[])
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            ClientError::Api(ref failure) if failure.kind() == ApiErrorKind::Authentication
        ));
        assert_eq!(login_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            client
                .execute_observable_read::<TestObservableRead>(&[])
                .await
                .unwrap()
                .value,
            "fresh"
        );
        assert_eq!(login_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn upstream_error_body_is_never_exposed_and_request_id_is_bounded() {
        let server = MockServer::start().await;
        mount_login(&server, "error-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/read"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("x-request-id", "request-123")
                    .set_body_json(json!({ "message": "secret-body-canary" })),
            )
            .mount(&server)
            .await;

        let client = InfisicalClient::new(settings(&server)).unwrap();
        let error = client.execute_read::<TestRead>(&[]).await.unwrap_err();
        let ClientError::Api(failure) = &error else {
            panic!("expected safe API failure");
        };

        assert_eq!(failure.kind(), ApiErrorKind::PermissionDenied);
        assert_eq!(failure.status(), 403);
        assert_eq!(failure.request_id(), Some("request-123"));
        assert!(!format!("{error}").contains("secret-body-canary"));
        assert!(!format!("{error:?}").contains("secret-body-canary"));
    }

    #[tokio::test]
    async fn response_size_timeout_and_capability_outcomes_are_typed() {
        let exact_server = MockServer::start().await;
        mount_login(&exact_server, "exact-token").await;
        let exact_body = json!({ "value": "x".repeat(500) }).to_string();
        Mock::given(method("GET"))
            .and(path("/api/v1/test/read"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(exact_body.clone()))
            .mount(&exact_server)
            .await;
        let mut exact_settings = settings(&exact_server);
        exact_settings.max_response_bytes = exact_body.len();
        let exact_client = InfisicalClient::new(exact_settings).unwrap();
        assert_eq!(
            exact_client
                .execute_read::<TestRead>(&[])
                .await
                .unwrap()
                .value
                .len(),
            500
        );

        let oversized_server = MockServer::start().await;
        mount_login(&oversized_server, "bounded-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/read"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "value": "x".repeat(1_024) })),
            )
            .mount(&oversized_server)
            .await;
        let mut bounded_settings = settings(&oversized_server);
        bounded_settings.max_response_bytes = 512;
        let bounded_client = InfisicalClient::new(bounded_settings).unwrap();
        assert_eq!(
            bounded_client
                .execute_read::<TestRead>(&[])
                .await
                .unwrap_err(),
            ClientError::ResponseTooLarge { limit: 512 }
        );

        let timeout_server = MockServer::start().await;
        mount_login(&timeout_server, "timeout-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/read"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(200))
                    .set_body_json(json!({ "value": "late" })),
            )
            .mount(&timeout_server)
            .await;
        let mut timeout_settings = settings(&timeout_server);
        timeout_settings.request_timeout = Duration::from_millis(50);
        let timeout_client = InfisicalClient::new(timeout_settings).unwrap();
        assert_eq!(
            timeout_client
                .execute_read::<TestRead>(&[])
                .await
                .unwrap_err(),
            ClientError::Transport(TransportErrorKind::Timeout)
        );

        let capability_server = MockServer::start().await;
        mount_login(&capability_server, "capability-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/read"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&capability_server)
            .await;
        let capability_client = InfisicalClient::new(settings(&capability_server)).unwrap();
        assert_eq!(
            capability_client
                .probe_capability::<TestRead>(&[])
                .await
                .unwrap(),
            CapabilityAvailability::Unavailable
        );
    }

    #[tokio::test]
    async fn capability_probe_distinguishes_permission_from_other_failures() {
        let permission_server = MockServer::start().await;
        mount_login(&permission_server, "permission-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/read"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&permission_server)
            .await;
        let permission_client = InfisicalClient::new(settings(&permission_server)).unwrap();
        assert_eq!(
            permission_client
                .probe_capability::<TestRead>(&[])
                .await
                .unwrap(),
            CapabilityAvailability::PermissionDenied
        );

        let conflict_server = MockServer::start().await;
        mount_login(&conflict_server, "conflict-token").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/test/read"))
            .respond_with(ResponseTemplate::new(409))
            .mount(&conflict_server)
            .await;
        let conflict_client = InfisicalClient::new(settings(&conflict_server)).unwrap();
        assert!(matches!(
            conflict_client
                .probe_capability::<TestRead>(&[])
                .await
                .unwrap_err(),
            ClientError::Api(ref failure) if failure.kind() == ApiErrorKind::Conflict
        ));
    }

    #[test]
    fn internal_endpoint_and_token_boundaries_are_exact() {
        assert_eq!(DEFAULT_MAX_RESPONSE_BYTES, 2_097_152);

        for path in [
            "",
            "/test/read",
            "test/read/",
            "test//read",
            "test/./read",
            "test/../read",
        ] {
            assert!(
                !Endpoint::from_static(ApiVersion::V1, path).is_valid(),
                "{path:?} must be rejected"
            );
        }
        assert!(Endpoint::from_static(ApiVersion::V1, "test/read").is_valid());

        let client = InfisicalClient::new(ClientSettings::new(
            Url::parse("http://127.0.0.1:8080").unwrap(),
            "machine-client".into(),
            SecretValue::new("client-secret"),
        ))
        .unwrap();
        let dynamic = Endpoint::from_segments(ApiVersion::V4, ["secrets", "folder/name"]);
        assert_eq!(
            client.endpoint_url(&dynamic).unwrap().as_str(),
            "http://127.0.0.1:8080/api/v4/secrets/folder%2Fname"
        );
        assert!(!Endpoint::from_segments(ApiVersion::V2, ["folders", ".."]).is_valid());

        let boundary = Instant::now();
        let token = CachedToken {
            value: SecretValue::new("boundary-token"),
            refresh_after: boundary,
        };
        assert!(!token.is_fresh(boundary));
    }

    #[test]
    fn safe_error_categories_and_messages_are_exact() {
        for (status, expected) in [
            (StatusCode::BAD_REQUEST, ApiErrorKind::InvalidRequest),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                ApiErrorKind::InvalidRequest,
            ),
            (StatusCode::UNAUTHORIZED, ApiErrorKind::Authentication),
            (StatusCode::FORBIDDEN, ApiErrorKind::PermissionDenied),
            (StatusCode::NOT_FOUND, ApiErrorKind::NotFound),
            (StatusCode::CONFLICT, ApiErrorKind::Conflict),
            (StatusCode::TOO_MANY_REQUESTS, ApiErrorKind::RateLimited),
            (StatusCode::INTERNAL_SERVER_ERROR, ApiErrorKind::Server),
        ] {
            assert_eq!(ApiErrorKind::from_status(status), expected, "{status}");
        }

        for (kind, expected) in [
            (ApiErrorKind::InvalidRequest, "rejected the request"),
            (ApiErrorKind::Authentication, "rejected authentication"),
            (ApiErrorKind::PermissionDenied, "denied permission"),
            (ApiErrorKind::NotFound, "did not find the resource"),
            (ApiErrorKind::Conflict, "reported a conflict"),
            (ApiErrorKind::RateLimited, "rate limited the request"),
            (ApiErrorKind::Server, "reported a server error"),
        ] {
            assert_eq!(kind.to_string(), expected);
        }

        for (kind, expected) in [
            (TransportErrorKind::Timeout, "request timed out"),
            (TransportErrorKind::Connect, "connection failed"),
            (TransportErrorKind::Other, "request failed"),
        ] {
            assert_eq!(kind.to_string(), expected);
        }

        let failure = ApiFailure {
            kind: ApiErrorKind::Conflict,
            status: 409,
            request_id: Some("request-123".into()),
        };
        assert_eq!(
            failure.to_string(),
            "Infisical API reported a conflict (HTTP 409); request ID request-123"
        );
    }

    #[test]
    fn configuration_rejects_unsafe_urls_without_exposing_secrets() {
        let unsafe_settings = test_settings(
            "http://server/",
            "machine-client",
            "configuration-secret-canary",
        );
        let rendered = format!("{unsafe_settings:?}");
        assert!(!rendered.contains("configuration-secret-canary"));
        for url in [
            "http://server/",
            "file:///tmp/infisical",
            "https://user@infisical.test/",
            "https://user:password@infisical.test/",
            "https://infisical.test/?tenant=other",
            "https://infisical.test/#fragment",
            "https://infisical.test/base/",
        ] {
            assert_eq!(
                InfisicalClient::new(test_settings(url, "machine-client", "secret"))
                    .err()
                    .expect("unsafe URL must fail"),
                ClientConfigError::UnsafeApiUrl,
                "{url}"
            );
        }
        assert!(
            InfisicalClient::new(test_settings(
                "https://infisical.test/",
                "machine-client",
                "secret"
            ))
            .is_ok()
        );
        assert!(
            InfisicalClient::new(test_settings(
                "http://[::1]:8000/",
                "machine-client",
                "secret"
            ))
            .is_ok()
        );
    }

    #[test]
    fn configuration_requires_an_explicit_and_private_cleartext_authority() {
        for url in [
            "http://server:8080/",
            "http://infisical-server/",
            "http://10.42.0.8:8080/",
            "http://172.20.0.8:8080/",
            "http://192.168.1.8:8080/",
            "http://[fd00::8]:8080/",
        ] {
            let mut settings = test_settings(url, "machine-client", "secret");
            settings.allow_private_http = true;
            assert!(InfisicalClient::new(settings).is_ok(), "{url}");
        }

        for url in [
            "http://infisical.example.test/",
            "http://infisical_server:8080/",
            "http://203.0.113.8:8080/",
            "http://169.254.169.254/",
            "http://[fd00:ec2::254]/",
            "http://[fe80::8]:8080/",
            "http://user@server:8080/",
            "http://server:8080/base/",
            "http://server:8080/?tenant=other",
            "http://server:8080/#fragment",
        ] {
            let mut settings = test_settings(url, "machine-client", "secret");
            settings.allow_private_http = true;
            assert_eq!(
                InfisicalClient::new(settings)
                    .err()
                    .expect("non-private or structurally unsafe HTTP must fail"),
                ClientConfigError::UnsafeApiUrl,
                "{url}"
            );
        }
    }

    #[test]
    fn private_cleartext_hostname_requires_private_resolution_for_every_address() {
        for (url, allow_private_http, expected) in [
            (
                "http://server:8080/",
                true,
                Some(ResolutionPolicy::PrivateOnly),
            ),
            (
                "http://[fd00::8]:8080/",
                true,
                Some(ResolutionPolicy::System),
            ),
            ("http://[fd00::8]:8080/", false, None),
            ("http://[2001:db8::8]:8080/", true, None),
        ] {
            assert_eq!(
                url_policy(&Url::parse(url).unwrap(), allow_private_http),
                expected,
                "{url}"
            );
        }

        let private_addresses = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 8)), 0),
            SocketAddr::new(IpAddr::V6("fd00::8".parse::<Ipv6Addr>().unwrap()), 0),
        ];
        assert_eq!(
            validate_private_resolution(private_addresses.clone()).unwrap(),
            private_addresses
        );

        for address in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fd00:ec2::254".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("fe80::8".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("2001:db8::8".parse::<Ipv6Addr>().unwrap()),
        ] {
            let mut mixed = private_addresses.clone();
            mixed.push(SocketAddr::new(address, 0));
            assert!(
                validate_private_resolution(mixed).is_err(),
                "{address} must make the entire resolution unsafe"
            );
        }
        assert!(validate_private_resolution(Vec::new()).is_err());
    }

    #[tokio::test]
    async fn private_hostname_request_uses_the_validating_resolver_before_authentication() {
        let server = MockServer::start().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = StaticResolver {
            calls: Arc::clone(&calls),
            addresses: vec![*server.address()],
        };
        let mut client_settings = test_settings(
            &format!("http://server:{}/", server.address().port()),
            "machine-client",
            "secret",
        );
        client_settings.allow_private_http = true;
        let client = InfisicalClient::new_with_system_resolver(client_settings, resolver).unwrap();

        assert!(matches!(
            client.execute_read::<TestRead>(&[]).await,
            Err(ClientError::Transport(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "an unsafe DNS answer must be rejected before Universal Auth"
        );
    }

    #[test]
    fn configuration_rejects_malformed_credentials_and_organization_slugs() {
        for (client_id, secret) in [
            ("", "secret"),
            (" machine-client", "secret"),
            ("machine-client ", "secret"),
            ("machine-client", ""),
            ("machine-client", " secret"),
            ("machine-client", "secret "),
        ] {
            assert_eq!(
                InfisicalClient::new(test_settings("http://127.0.0.1:8000/", client_id, secret))
                    .err()
                    .expect("invalid credential must fail"),
                ClientConfigError::InvalidCredential
            );
        }

        for slug in [
            "",
            "Platform",
            "platform_team",
            "-platform",
            "platform-",
            "platform--team",
            "platform team",
        ] {
            let mut invalid_slug =
                test_settings("http://127.0.0.1:8000/", "machine-client", "secret");
            invalid_slug.organization_slug = Some(slug.into());
            assert_eq!(
                InfisicalClient::new(invalid_slug)
                    .err()
                    .expect("invalid slug must fail"),
                ClientConfigError::InvalidOrganizationSlug,
                "{slug}"
            );
        }
        let mut overlong_slug = test_settings("http://127.0.0.1:8000/", "machine-client", "secret");
        overlong_slug.organization_slug = Some("a".repeat(65));
        assert_eq!(
            InfisicalClient::new(overlong_slug)
                .err()
                .expect("overlong slug must fail"),
            ClientConfigError::InvalidOrganizationSlug
        );
    }

    #[test]
    fn configuration_rejects_unbounded_transport_and_cache_settings() {
        let mut maximum_timeout = bounded_settings();
        maximum_timeout.request_timeout = MAXIMUM_REQUEST_TIMEOUT;
        assert!(InfisicalClient::new(maximum_timeout).is_ok());

        let mut maximum_response = bounded_settings();
        maximum_response.max_response_bytes = MAXIMUM_RESPONSE_BYTES;
        assert!(InfisicalClient::new(maximum_response).is_ok());

        let mut zero_timeout = bounded_settings();
        zero_timeout.request_timeout = Duration::ZERO;
        let mut excessive_timeout = bounded_settings();
        excessive_timeout.request_timeout = Duration::from_secs(121);
        let mut zero_response = bounded_settings();
        zero_response.max_response_bytes = 0;
        let mut excessive_response = bounded_settings();
        excessive_response.max_response_bytes = 16 * 1024 * 1024 + 1;
        let mut zero_skew = bounded_settings();
        zero_skew.token_refresh_skew = Duration::ZERO;
        for invalid_bounds in [
            zero_timeout,
            excessive_timeout,
            zero_response,
            excessive_response,
            zero_skew,
        ] {
            assert_eq!(
                InfisicalClient::new(invalid_bounds)
                    .err()
                    .expect("invalid bound must fail"),
                ClientConfigError::InvalidBounds
            );
        }
    }

    #[test]
    fn request_ids_accept_only_a_small_log_safe_alphabet() {
        let mut headers = HeaderMap::new();
        for valid in ["request-123", "request_123:part.2"] {
            headers.insert("x-request-id", valid.parse().unwrap());
            assert_eq!(safe_request_id(&headers).as_deref(), Some(valid));
        }
        for invalid in ["", "request 123", "request/123", &"a".repeat(129)] {
            headers.insert("x-request-id", invalid.parse().unwrap());
            assert!(safe_request_id(&headers).is_none(), "{invalid}");
        }
    }

    fn test_settings(url: &str, client_id: &str, secret: &str) -> ClientSettings {
        ClientSettings::new(
            Url::parse(url).unwrap(),
            client_id.into(),
            SecretValue::new(secret),
        )
    }

    fn bounded_settings() -> ClientSettings {
        test_settings("http://127.0.0.1:8000/", "machine-client", "secret")
    }
}
