use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use infisical_api::{
    PrivateHttpResolver, ResolutionPolicy, SecretValue, SystemResolver, url_resolution_policy,
};
use infisical_mcp::MCP_SERVER_NAME;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse},
};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use url::Url;

const IDENTITY_HEADER: &str = "x-mcp-identity";
const MINIMUM_BEARER_BYTES: usize = 32;
const MAXIMUM_JWKS_BYTES: usize = 64 * 1024;
const CLOCK_SKEW_SECONDS: i64 = 30;
const MAXIMUM_IDENTITY_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAXIMUM_JWKS_CACHE_TTL: Duration = Duration::from_hours(1);
const UNKNOWN_KEY_REFRESH_COOLDOWN: Duration = Duration::from_secs(5);
const FAILED_KEY_REFRESH_COOLDOWN: Duration = Duration::from_secs(5);

/// Current and optional previous HTTP connection credentials.
pub struct GatewayBearers {
    current: SecretValue,
    previous: Option<SecretValue>,
}

impl GatewayBearers {
    /// Construct a rotation set after enforcing the minimum entropy-bearing
    /// representation length.
    ///
    /// # Errors
    ///
    /// Returns an error when either value is too short or the rotation values
    /// are identical.
    pub fn new(current: String, previous: Option<String>) -> Result<Self, BearerConfigError> {
        validate_bearer("INFISICAL_MCP_BEARER_CURRENT", &current)?;
        if let Some(previous) = previous.as_deref() {
            validate_bearer("INFISICAL_MCP_BEARER_PREVIOUS", previous)?;
            if constant_time_equal(current.as_bytes(), previous.as_bytes()).into() {
                return Err(BearerConfigError::DuplicateRotationValues);
            }
        }

        Ok(Self {
            current: SecretValue::new(current),
            previous: previous.map(SecretValue::new),
        })
    }

    fn accepts(&self, supplied: &[u8]) -> bool {
        let current = constant_time_equal(supplied, self.current.expose_secret().as_bytes());
        let previous = self.previous.as_ref().map_or(Choice::from(0), |value| {
            constant_time_equal(supplied, value.expose_secret().as_bytes())
        });
        bool::from(current | previous)
    }
}

impl std::fmt::Debug for GatewayBearers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayBearers")
            .field("current", &"[REDACTED]")
            .field("previous", &self.previous.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BearerConfigError {
    #[error("{variable} must contain at least 32 bytes")]
    TooShort { variable: &'static str },
    #[error("current and previous MCP bearer values must differ")]
    DuplicateRotationValues,
    #[error("{variable} must not contain whitespace")]
    ContainsWhitespace { variable: &'static str },
}

fn validate_bearer(variable: &'static str, value: &str) -> Result<(), BearerConfigError> {
    if value.len() < MINIMUM_BEARER_BYTES {
        return Err(BearerConfigError::TooShort { variable });
    }
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(BearerConfigError::ContainsWhitespace { variable });
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> Choice {
    if left.len() != right.len() {
        return Choice::from(0);
    }
    left.ct_eq(right)
}

#[derive(Debug, Clone)]
pub struct IdentityVerifierSettings {
    pub jwks_url: Url,
    pub issuer: String,
    pub allow_private_http: bool,
    pub request_timeout: Duration,
    pub cache_ttl: Duration,
}

#[derive(Clone)]
pub struct IdentityVerifier {
    settings: Arc<IdentityVerifierSettings>,
    client: reqwest::Client,
    cache: Arc<RwLock<KeyCache>>,
    refresh: Arc<Mutex<Option<Instant>>>,
}

#[derive(Debug, Default)]
struct KeyCache {
    set: Option<JwkSet>,
    expires_at: Option<Instant>,
    unknown_key_refresh_after: Option<Instant>,
}

impl KeyCache {
    fn lookup(&self, key_id: &str, now: Instant) -> KeyLookup<'_> {
        if self.expires_at.is_none_or(|expires_at| expires_at <= now) {
            return KeyLookup::Stale;
        }
        let Some(set) = self.set.as_ref() else {
            return KeyLookup::Stale;
        };
        if let Some(key) = set.find(key_id) {
            return KeyLookup::Hit(key);
        }
        KeyLookup::Miss {
            refresh_allowed: self
                .unknown_key_refresh_after
                .is_none_or(|refresh_after| refresh_after <= now),
        }
    }

    fn defer_unknown_key_refresh(&mut self, now: Instant) {
        self.unknown_key_refresh_after = Some(now + UNKNOWN_KEY_REFRESH_COOLDOWN);
    }
}

#[derive(Debug)]
enum KeyLookup<'a> {
    Hit(&'a Jwk),
    Miss { refresh_allowed: bool },
    Stale,
}

#[derive(Debug, Clone, Deserialize)]
struct ActClaim {
    sub: String,
}

#[derive(Debug, Clone, Deserialize)]
struct IdentityClaims {
    sub: String,
    iat: i64,
    exp: i64,
    #[serde(default)]
    groups: Vec<String>,
    act: ActClaim,
}

/// Verified caller identity propagated by the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPrincipal {
    pub subject: String,
    pub actor_subject: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Error)]
pub enum IdentityVerifierError {
    #[error(
        "identity JWKS URL must be HTTPS, loopback HTTP, or explicitly allowed private HTTP without userinfo, query, or fragment"
    )]
    UnsafeJwksUrl,
    #[error("identity verifier issuer must be non-empty")]
    EmptyIssuer,
    #[error("identity verifier timeouts must be non-zero and within supported bounds")]
    InvalidBounds,
    #[error("failed to construct bounded identity HTTP client")]
    Client,
    #[error("identity header is not a valid EdDSA JWT")]
    InvalidHeader,
    #[error("identity JWT has no key identifier")]
    MissingKeyId,
    #[error("identity key is unavailable")]
    KeyUnavailable,
    #[error("identity key refresh is cooling down; retry after {retry_after_seconds} seconds")]
    KeyRefreshCooldown { retry_after_seconds: u64 },
    #[error("identity JWKS response is invalid")]
    InvalidJwks,
    #[error("identity JWKS response exceeds the configured bound")]
    JwksTooLarge,
    #[error("identity JWT validation failed")]
    InvalidToken,
    #[error("identity JWT claims are inconsistent")]
    InvalidClaims,
}

impl IdentityVerifier {
    /// Construct a verifier with a bounded, redirect-free JWKS client.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe JWKS URL, empty validation constraints,
    /// unbounded timing settings, or an HTTP client construction failure.
    pub fn new(settings: IdentityVerifierSettings) -> Result<Self, IdentityVerifierError> {
        Self::new_with_system_resolver(settings, SystemResolver)
    }

    fn new_with_system_resolver<R>(
        settings: IdentityVerifierSettings,
        system_resolver: R,
    ) -> Result<Self, IdentityVerifierError>
    where
        R: reqwest::dns::Resolve + 'static,
    {
        let resolution_policy = validate_jwks_url(&settings.jwks_url, settings.allow_private_http)?;
        if settings.issuer.is_empty() {
            return Err(IdentityVerifierError::EmptyIssuer);
        }
        if settings.request_timeout.is_zero()
            || settings.request_timeout > MAXIMUM_IDENTITY_REQUEST_TIMEOUT
            || settings.cache_ttl.is_zero()
            || settings.cache_ttl > MAXIMUM_JWKS_CACHE_TTL
        {
            return Err(IdentityVerifierError::InvalidBounds);
        }
        let mut client_builder = reqwest::Client::builder()
            .timeout(settings.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if resolution_policy == ResolutionPolicy::PrivateOnly {
            // Revalidate every connection and hand the connector only the
            // accepted addresses so DNS rebinding cannot redirect the fetch.
            client_builder = client_builder.dns_resolver(PrivateHttpResolver::new(system_resolver));
        }
        let client = client_builder
            .build()
            .map_err(|_| IdentityVerifierError::Client)?;

        Ok(Self {
            settings: Arc::new(settings),
            client,
            cache: Arc::new(RwLock::new(KeyCache::default())),
            refresh: Arc::new(Mutex::new(None)),
        })
    }

    /// Verify the JWT signature and pinned gateway identity claims.
    ///
    /// # Errors
    ///
    /// Returns an error when the header, key, signature, temporal claims,
    /// issuer, audience, subject, or actor is invalid.
    pub async fn verify(&self, token: &str) -> Result<IdentityPrincipal, IdentityVerifierError> {
        let header = decode_header(token).map_err(|_| IdentityVerifierError::InvalidHeader)?;
        if header.alg != Algorithm::EdDSA {
            return Err(IdentityVerifierError::InvalidHeader);
        }
        let key_id = header.kid.ok_or(IdentityVerifierError::MissingKeyId)?;
        let jwk = self.key_for(&key_id).await?;
        validate_jwk(&jwk)?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| IdentityVerifierError::InvalidJwks)?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.settings.issuer.as_str()]);
        validation.set_audience(&[MCP_SERVER_NAME]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub", "iat"]);
        validation.leeway = CLOCK_SKEW_SECONDS.unsigned_abs();
        let claims = decode::<IdentityClaims>(token, &key, &validation)
            .map_err(|_| IdentityVerifierError::InvalidToken)?
            .claims;

        let now = unix_timestamp()?;
        validate_claim_invariants(&claims, now)?;

        Ok(IdentityPrincipal {
            subject: claims.sub,
            actor_subject: claims.act.sub,
            groups: claims.groups,
        })
    }

    async fn key_for(&self, key_id: &str) -> Result<Jwk, IdentityVerifierError> {
        let now = Instant::now();
        if let KeyLookup::Hit(key) = self.cache.read().await.lookup(key_id, now) {
            return Ok(key.clone());
        }

        let mut retry_at = self.refresh.lock().await;
        let now = Instant::now();
        if let KeyLookup::Hit(key) = self.cache.read().await.lookup(key_id, now) {
            return Ok(key.clone());
        }
        if let Some(deadline) = *retry_at {
            let remaining = deadline.saturating_duration_since(now);
            if !remaining.is_zero() {
                return Err(IdentityVerifierError::KeyRefreshCooldown {
                    retry_after_seconds: remaining.as_secs()
                        + u64::from(remaining.subsec_nanos() != 0),
                });
            }
        }
        let refresh_for_miss = match self.cache.read().await.lookup(key_id, now) {
            KeyLookup::Hit(key) => return Ok(key.clone()),
            KeyLookup::Miss {
                refresh_allowed: false,
            } => return Err(IdentityVerifierError::KeyUnavailable),
            KeyLookup::Miss {
                refresh_allowed: true,
            } => true,
            KeyLookup::Stale => false,
        };

        if refresh_for_miss {
            self.cache.write().await.defer_unknown_key_refresh(now);
        }

        // Reserve a bounded retry window before awaiting: cancellation releases the
        // lock, but must not let another caller immediately restart the failed fetch.
        *retry_at = Some(now + self.settings.request_timeout + FAILED_KEY_REFRESH_COOLDOWN);
        let set = match self.fetch_jwks().await {
            Ok(set) => set,
            Err(error) => {
                *retry_at = Some(Instant::now() + FAILED_KEY_REFRESH_COOLDOWN);
                return Err(error);
            }
        };
        let key = set.find(key_id).cloned();
        let now = Instant::now();
        *self.cache.write().await = KeyCache {
            set: Some(set),
            expires_at: Some(now + self.settings.cache_ttl),
            unknown_key_refresh_after: (refresh_for_miss || key.is_none())
                .then_some(now + UNKNOWN_KEY_REFRESH_COOLDOWN),
        };
        *retry_at = None;
        key.ok_or(IdentityVerifierError::KeyUnavailable)
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, IdentityVerifierError> {
        let mut response = self
            .client
            .get(self.settings.jwks_url.clone())
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| IdentityVerifierError::KeyUnavailable)?;
        if !response.status().is_success() {
            return Err(IdentityVerifierError::KeyUnavailable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| IdentityVerifierError::KeyUnavailable)?
        {
            extend_bounded_jwks_body(&mut body, &chunk)?;
        }
        serde_json::from_slice(&body).map_err(|_| IdentityVerifierError::InvalidJwks)
    }
}

fn extend_bounded_jwks_body(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), IdentityVerifierError> {
    let new_length = body
        .len()
        .checked_add(chunk.len())
        .ok_or(IdentityVerifierError::JwksTooLarge)?;
    if new_length > MAXIMUM_JWKS_BYTES {
        return Err(IdentityVerifierError::JwksTooLarge);
    }
    body.extend_from_slice(chunk);
    Ok(())
}

fn validate_claim_invariants(
    claims: &IdentityClaims,
    now: i64,
) -> Result<(), IdentityVerifierError> {
    if claims.sub.is_empty() {
        return Err(IdentityVerifierError::InvalidClaims);
    }
    if claims.act.sub.is_empty() {
        return Err(IdentityVerifierError::InvalidClaims);
    }
    if claims.exp <= claims.iat {
        return Err(IdentityVerifierError::InvalidClaims);
    }
    if claims.iat > now.saturating_add(CLOCK_SKEW_SECONDS) {
        return Err(IdentityVerifierError::InvalidClaims);
    }
    Ok(())
}

fn unix_timestamp() -> Result<i64, IdentityVerifierError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IdentityVerifierError::InvalidClaims)?;
    i64::try_from(duration.as_secs()).map_err(|_| IdentityVerifierError::InvalidClaims)
}

fn validate_jwks_url(
    url: &Url,
    allow_private_http: bool,
) -> Result<ResolutionPolicy, IdentityVerifierError> {
    url_resolution_policy(url, allow_private_http).ok_or(IdentityVerifierError::UnsafeJwksUrl)
}

fn validate_jwk(jwk: &Jwk) -> Result<(), IdentityVerifierError> {
    if jwk.common.public_key_use != Some(PublicKeyUse::Signature) {
        return Err(IdentityVerifierError::InvalidJwks);
    }
    if jwk.common.key_algorithm != Some(KeyAlgorithm::EdDSA) {
        return Err(IdentityVerifierError::InvalidJwks);
    }
    if !matches!(
        &jwk.algorithm,
        AlgorithmParameters::OctetKeyPair(parameters)
            if parameters.curve == EllipticCurve::Ed25519
    ) {
        return Err(IdentityVerifierError::InvalidJwks);
    }
    Ok(())
}

#[derive(Clone)]
pub struct IngressAuth {
    bearers: Arc<GatewayBearers>,
    verifier: Option<IdentityVerifier>,
    allowed_hosts: Arc<[String]>,
    allowed_origins: Arc<[String]>,
}

impl IngressAuth {
    #[must_use]
    pub fn new(
        bearers: Arc<GatewayBearers>,
        verifier: Option<IdentityVerifier>,
        allowed_hosts: Vec<String>,
        allowed_origins: Vec<String>,
    ) -> Self {
        Self {
            bearers,
            verifier,
            allowed_hosts: allowed_hosts.into(),
            allowed_origins: allowed_origins.into(),
        }
    }
}

#[derive(Debug, Serialize)]
struct AuthErrorBody {
    error: &'static str,
}

pub async fn require_mcp_authentication(
    State(auth): State<IngressAuth>,
    mut request: Request,
    next: Next,
) -> Response {
    if !allowed_host(request.headers(), &auth.allowed_hosts) {
        return auth_error(StatusCode::FORBIDDEN, "host_not_allowed");
    }
    if !allowed_origin(request.headers(), &auth.allowed_origins) {
        return auth_error(StatusCode::FORBIDDEN, "origin_not_allowed");
    }
    let Some(bearer) = bearer_token(request.headers()) else {
        return unauthorized();
    };
    if !auth.bearers.accepts(bearer.as_bytes()) {
        return unauthorized();
    }
    if let Some(verifier) = &auth.verifier {
        let Some(identity) = single_header(request.headers(), IDENTITY_HEADER) else {
            return unauthorized();
        };
        let principal = match verifier.verify(identity).await {
            Ok(principal) => principal,
            Err(IdentityVerifierError::KeyRefreshCooldown {
                retry_after_seconds,
            }) => {
                let mut response = unauthorized();
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, retry_after_seconds.into());
                return response;
            }
            Err(_) => return unauthorized(),
        };
        request.extensions_mut().insert(principal);
    }
    next.run(request).await
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = single_header(headers, header::AUTHORIZATION.as_str())?;
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    if token.is_empty() {
        return None;
    }
    if token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }
    Some(token)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn allowed_host(headers: &HeaderMap, allowed: &[String]) -> bool {
    single_header(headers, header::HOST.as_str())
        .map(str::to_ascii_lowercase)
        .is_some_and(|host| allowed.iter().any(|candidate| candidate == &host))
}

fn allowed_origin(headers: &HeaderMap, allowed: &[String]) -> bool {
    let Some(origin) = single_header(headers, header::ORIGIN.as_str()) else {
        return !headers.contains_key(header::ORIGIN);
    };
    allowed.iter().any(|candidate| candidate == origin)
}

fn unauthorized() -> Response {
    let mut response = auth_error(StatusCode::UNAUTHORIZED, "mcp_authentication_failed");
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}

fn auth_error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(AuthErrorBody { error: code })).into_response()
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use super::{
        ActClaim, BearerConfigError, GatewayBearers, IdentityClaims, IdentityVerifier,
        IdentityVerifierError, IdentityVerifierSettings, KeyCache, KeyLookup,
        MAXIMUM_IDENTITY_REQUEST_TIMEOUT, MAXIMUM_JWKS_BYTES, MAXIMUM_JWKS_CACHE_TTL,
        UNKNOWN_KEY_REFRESH_COOLDOWN, allowed_host, allowed_origin, bearer_token,
        constant_time_equal, extend_bounded_jwks_body, validate_claim_invariants, validate_jwk,
        validate_jwks_url,
    };
    use axum::{
        Json, Router,
        http::{HeaderMap, HeaderValue, header},
        routing::get,
    };
    use infisical_api::ResolutionPolicy;
    use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm};
    use reqwest::dns::{Addrs, Name, Resolve, Resolving};
    use serde_json::json;
    use tokio::sync::oneshot;
    use url::Url;
    use wiremock::MockServer;

    const CURRENT: &str = "0123456789abcdef0123456789abcdef";
    const PREVIOUS: &str = "fedcba9876543210fedcba9876543210";

    #[test]
    fn bearer_rotation_accepts_only_current_and_previous_values() {
        let bearers = GatewayBearers::new(CURRENT.into(), Some(PREVIOUS.into()))
            .expect("valid bearer configuration");

        assert!(bearers.accepts(CURRENT.as_bytes()));
        assert!(bearers.accepts(PREVIOUS.as_bytes()));
        assert!(!bearers.accepts(b"0123456789abcdef0123456789abcdeg"));
        assert!(!bearers.accepts(b"short"));
    }

    #[test]
    fn bearer_configuration_rejects_weak_or_duplicate_values() {
        assert_eq!(
            GatewayBearers::new("short".into(), None).expect_err("weak bearer must fail"),
            BearerConfigError::TooShort {
                variable: "INFISICAL_MCP_BEARER_CURRENT"
            }
        );
        assert_eq!(
            GatewayBearers::new(CURRENT.into(), Some(CURRENT.into()))
                .expect_err("duplicate rotation values must fail"),
            BearerConfigError::DuplicateRotationValues
        );
        assert_eq!(
            GatewayBearers::new(format!("{CURRENT} "), None)
                .expect_err("unusable whitespace-bearing value must fail"),
            BearerConfigError::ContainsWhitespace {
                variable: "INFISICAL_MCP_BEARER_CURRENT"
            }
        );
    }

    #[test]
    fn bearer_debug_format_is_redacted() {
        let bearers = GatewayBearers::new(CURRENT.into(), Some(PREVIOUS.into()))
            .expect("valid bearer configuration");

        let rendered = format!("{bearers:?}");
        assert!(!rendered.contains(CURRENT));
        assert!(!rendered.contains(PREVIOUS));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn constant_time_comparison_has_expected_semantics() {
        assert!(bool::from(constant_time_equal(b"same", b"same")));
        assert!(!bool::from(constant_time_equal(b"same", b"diff")));
        assert!(!bool::from(constant_time_equal(b"same", b"shorter")));
    }

    #[test]
    fn jwks_url_requires_an_explicit_private_cleartext_authority() {
        for unsafe_url in [
            "http://gateway.internal/jwks",
            "http://203.0.113.8/jwks",
            "http://169.254.169.254/jwks",
            "http://[fd00:ec2::254]/jwks",
            "http://[fe80::8]/jwks",
            "file:///tmp/jwks",
            "https://user@gateway.internal/jwks",
            "https://user:password@gateway.internal/jwks",
            "https://gateway.internal/jwks?tenant=other",
            "https://gateway.internal/jwks#fragment",
        ] {
            assert_eq!(
                validate_jwks_url(&Url::parse(unsafe_url).unwrap(), true)
                    .expect_err("unsafe JWKS URL must fail")
                    .to_string(),
                "identity JWKS URL must be HTTPS, loopback HTTP, or explicitly allowed private HTTP without userinfo, query, or fragment"
            );
        }
        assert!(matches!(
            validate_jwks_url(
                &Url::parse("http://mcp-gateway:8080/.well-known/jwks.json").unwrap(),
                false,
            ),
            Err(IdentityVerifierError::UnsafeJwksUrl)
        ));
        assert_eq!(
            validate_jwks_url(
                &Url::parse("http://mcp-gateway:8080/.well-known/jwks.json").unwrap(),
                true,
            )
            .unwrap(),
            ResolutionPolicy::PrivateOnly
        );
        assert!(
            validate_jwks_url(&Url::parse("http://127.0.0.1:8000/jwks").unwrap(), false).is_ok()
        );
        assert!(
            validate_jwks_url(&Url::parse("https://gateway.internal/jwks").unwrap(), false).is_ok()
        );
    }

    fn local_private_ipv4() -> Ipv4Addr {
        // UDP connect selects the host's local route without transmitting a
        // packet, giving the test an assigned RFC 1918 address it can bind.
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).unwrap();
        match socket.local_addr().unwrap().ip() {
            IpAddr::V4(address) if address.is_private() => address,
            address => panic!("test host must expose an RFC 1918 address, found {address}"),
        }
    }

    #[tokio::test]
    async fn accepted_private_jwks_resolution_fetches_through_the_real_client() {
        let private_ip = local_private_ipv4();
        let listener = tokio::net::TcpListener::bind((private_ip, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected_key = signature_jwk();
        let served_key = expected_key.clone();
        let router = Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let key = served_key.clone();
                async move { Json(JwkSet { keys: vec![key] }) }
            }),
        );
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    shutdown_rx.await.expect("test shutdown sender must remain");
                })
                .await
        });

        let calls = Arc::new(AtomicUsize::new(0));
        let verifier = IdentityVerifier::new_with_system_resolver(
            IdentityVerifierSettings {
                jwks_url: Url::parse(&format!("http://mcp-gateway:{port}/.well-known/jwks.json"))
                    .unwrap(),
                issuer: "https://gateway.example.com".into(),
                allow_private_http: true,
                request_timeout: Duration::from_secs(1),
                cache_ttl: Duration::from_mins(5),
            },
            StaticResolver {
                calls: Arc::clone(&calls),
                addresses: vec![SocketAddr::new(IpAddr::V4(private_ip), 0)],
            },
        )
        .unwrap();

        let fetched = verifier.fetch_jwks().await.unwrap();
        assert_eq!(fetched.find("gateway-main"), Some(&expected_key));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        shutdown_tx.send(()).expect("test server must remain");
        server
            .await
            .expect("test server task must finish")
            .expect("test server must shut down cleanly");
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

    #[tokio::test]
    async fn private_jwks_hostname_uses_the_validating_resolver_before_fetching() {
        let server = MockServer::start().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let verifier = IdentityVerifier::new_with_system_resolver(
            IdentityVerifierSettings {
                jwks_url: Url::parse(&format!(
                    "http://mcp-gateway:{}/.well-known/jwks.json",
                    server.address().port()
                ))
                .unwrap(),
                issuer: "https://gateway.example.com".into(),
                allow_private_http: true,
                request_timeout: Duration::from_secs(1),
                cache_ttl: Duration::from_mins(5),
            },
            StaticResolver {
                calls: Arc::clone(&calls),
                addresses: vec![*server.address()],
            },
        )
        .unwrap();

        assert!(matches!(
            verifier.fetch_jwks().await,
            Err(IdentityVerifierError::KeyUnavailable)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "an unsafe DNS answer must be rejected before fetching JWKS"
        );
    }

    #[tokio::test]
    async fn failed_jwks_refresh_is_bounded_for_empty_and_expired_caches() {
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        for expired in [false, true] {
            let server = MockServer::start().await;
            let attempts = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&attempts);
            Mock::given(method("GET"))
                .and(path("/jwks"))
                .respond_with(move |_: &wiremock::Request| {
                    if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                        ResponseTemplate::new(503)
                    } else {
                        ResponseTemplate::new(200).set_body_json(JwkSet {
                            keys: vec![signature_jwk()],
                        })
                    }
                })
                .expect(2)
                .mount(&server)
                .await;
            let verifier = IdentityVerifier::new(IdentityVerifierSettings {
                jwks_url: Url::parse(&format!("{}/jwks", server.uri())).unwrap(),
                issuer: "https://gateway.example".into(),
                allow_private_http: false,
                request_timeout: Duration::from_secs(1),
                cache_ttl: Duration::from_secs(60),
            })
            .unwrap();
            if expired {
                *verifier.cache.write().await = KeyCache {
                    set: Some(JwkSet {
                        keys: vec![signature_jwk()],
                    }),
                    expires_at: Some(Instant::now()),
                    unknown_key_refresh_after: None,
                };
            }
            assert!(matches!(
                verifier.key_for("gateway-main").await,
                Err(IdentityVerifierError::KeyUnavailable)
            ));
            for _ in 0..3 {
                let mut callers = tokio::task::JoinSet::new();
                for _ in 0..16 {
                    let verifier = verifier.clone();
                    callers.spawn(async move { verifier.key_for("gateway-main").await });
                }
                while let Some(result) = callers.join_next().await {
                    assert!(matches!(
                        result.unwrap(),
                        Err(IdentityVerifierError::KeyRefreshCooldown { .. })
                    ));
                }
            }
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
            *verifier.refresh.lock().await = Some(Instant::now());
            assert_eq!(
                verifier.key_for("gateway-main").await.unwrap(),
                signature_jwk()
            );
            assert_eq!(attempts.load(Ordering::SeqCst), 2);
            assert!(verifier.refresh.lock().await.is_none());
        }
    }

    #[tokio::test]
    async fn cancelled_jwks_fetch_retains_a_bounded_retry_window() {
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        let started = Arc::new(tokio::sync::Notify::new());
        let observed = Arc::clone(&started);
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(move |_: &wiremock::Request| {
                observed.notify_one();
                ResponseTemplate::new(503).set_delay(Duration::from_millis(200))
            })
            .expect(1)
            .mount(&server)
            .await;
        let verifier = IdentityVerifier::new(IdentityVerifierSettings {
            jwks_url: Url::parse(&format!("{}/jwks", server.uri())).unwrap(),
            issuer: "https://gateway.example".into(),
            allow_private_http: false,
            request_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(60),
        })
        .unwrap();
        let caller = verifier.clone();
        let task = tokio::spawn(async move { caller.key_for("gateway-main").await });
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(matches!(verifier.key_for("gateway-main").await,
            Err(IdentityVerifierError::KeyRefreshCooldown { retry_after_seconds }) if retry_after_seconds <= 6));
        assert!(verifier.refresh.lock().await.unwrap() <= Instant::now() + Duration::from_secs(6));
    }

    #[test]
    fn identity_verifier_rejects_unbounded_timing_configuration() {
        let settings = |request_timeout, cache_ttl| IdentityVerifierSettings {
            jwks_url: Url::parse("https://gateway.internal/jwks").unwrap(),
            issuer: "https://gateway.internal".into(),
            allow_private_http: false,
            request_timeout,
            cache_ttl,
        };

        for (request_timeout, cache_ttl) in [
            (Duration::ZERO, Duration::from_mins(5)),
            (
                MAXIMUM_IDENTITY_REQUEST_TIMEOUT + Duration::from_secs(1),
                Duration::from_mins(5),
            ),
            (Duration::from_secs(3), Duration::ZERO),
            (
                Duration::from_secs(3),
                MAXIMUM_JWKS_CACHE_TTL + Duration::from_secs(1),
            ),
        ] {
            assert!(matches!(
                IdentityVerifier::new(settings(request_timeout, cache_ttl)),
                Err(IdentityVerifierError::InvalidBounds)
            ));
        }

        for (request_timeout, cache_ttl) in [
            (Duration::from_secs(1), Duration::from_secs(1)),
            (MAXIMUM_IDENTITY_REQUEST_TIMEOUT, MAXIMUM_JWKS_CACHE_TTL),
        ] {
            assert!(IdentityVerifier::new(settings(request_timeout, cache_ttl)).is_ok());
        }
    }

    #[test]
    fn jwks_body_bound_accepts_the_limit_and_rejects_one_more_byte() {
        assert_eq!(MAXIMUM_JWKS_BYTES, 65_536);
        let mut body = vec![0; 65_535];

        assert!(extend_bounded_jwks_body(&mut body, &[0]).is_ok());
        assert_eq!(body.len(), 65_536);
        assert!(extend_bounded_jwks_body(&mut body, &[0]).is_err());
    }

    #[test]
    fn key_cache_classifies_hits_staleness_and_throttled_misses() {
        let now = Instant::now();
        let jwk = signature_jwk();
        let mut cache = KeyCache {
            set: Some(JwkSet {
                keys: vec![jwk.clone()],
            }),
            expires_at: Some(now + Duration::from_mins(1)),
            unknown_key_refresh_after: None,
        };

        assert!(matches!(
            cache.lookup("gateway-main", now),
            KeyLookup::Hit(found) if found == &jwk
        ));
        assert!(matches!(
            cache.lookup("unknown", now),
            KeyLookup::Miss {
                refresh_allowed: true
            }
        ));
        cache.defer_unknown_key_refresh(now);
        assert!(matches!(
            cache.lookup("unknown", now),
            KeyLookup::Miss {
                refresh_allowed: false
            }
        ));
        assert!(matches!(
            cache.lookup("unknown", now + UNKNOWN_KEY_REFRESH_COOLDOWN),
            KeyLookup::Miss {
                refresh_allowed: true
            }
        ));
        cache.expires_at = Some(now);
        assert!(matches!(
            cache.lookup("gateway-main", now),
            KeyLookup::Stale
        ));
    }

    #[test]
    fn claim_invariants_reject_empty_subjects_and_invalid_time_ordering() {
        let now = 1_000;
        let mut claims = valid_claims(now);
        assert!(validate_claim_invariants(&claims, now).is_ok());

        claims.sub.clear();
        assert!(validate_claim_invariants(&claims, now).is_err());
        claims = valid_claims(now);
        claims.act.sub.clear();
        assert!(validate_claim_invariants(&claims, now).is_err());
        claims = valid_claims(now);
        claims.exp = claims.iat;
        assert!(validate_claim_invariants(&claims, now).is_err());
        claims = valid_claims(now);
        claims.iat = now + 31;
        assert!(validate_claim_invariants(&claims, now).is_err());
        claims.iat = now + 30;
        claims.exp = claims.iat + 1;
        assert!(validate_claim_invariants(&claims, now).is_ok());
    }

    #[test]
    fn jwk_must_be_an_ed25519_signature_key() {
        let valid = signature_jwk();
        assert!(validate_jwk(&valid).is_ok());

        let mut wrong_use = valid.clone();
        wrong_use.common.public_key_use = None;
        assert!(validate_jwk(&wrong_use).is_err());

        let mut wrong_algorithm = valid.clone();
        wrong_algorithm.common.key_algorithm = Some(KeyAlgorithm::ES256);
        assert!(validate_jwk(&wrong_algorithm).is_err());

        let mut wrong_curve = valid;
        let AlgorithmParameters::OctetKeyPair(parameters) = &mut wrong_curve.algorithm else {
            panic!("test fixture must be an octet key pair");
        };
        parameters.curve = EllipticCurve::P256;
        assert!(validate_jwk(&wrong_curve).is_err());
    }

    #[test]
    fn authorization_header_requires_one_nonempty_bearer_token() {
        assert_eq!(bearer_token(&authorization("bearer token")), Some("token"));
        assert!(bearer_token(&authorization("Basic token")).is_none());
        assert!(bearer_token(&authorization("Bearer ")).is_none());
        assert!(bearer_token(&authorization("Bearer token extra")).is_none());

        let mut duplicated = authorization("Bearer token");
        duplicated.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer another"),
        );
        assert!(bearer_token(&duplicated).is_none());
    }

    #[test]
    fn host_and_origin_allowlists_are_exact() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("MCP.EXAMPLE:8000"));
        assert!(allowed_host(&headers, &["mcp.example:8000".into()]));
        assert!(!allowed_host(&headers, &["another.example:8000".into()]));
        assert!(allowed_origin(&headers, &[]));

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://gateway.example"),
        );
        assert!(allowed_origin(
            &headers,
            &["https://gateway.example".into()]
        ));
        assert!(!allowed_origin(
            &headers,
            &["https://another.example".into()]
        ));
        assert!(!allowed_origin(&headers, &[]));
    }

    fn signature_jwk() -> Jwk {
        serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "use": "sig",
            "alg": "EdDSA",
            "kid": "gateway-main"
        }))
        .expect("valid Ed25519 JWK fixture")
    }

    fn valid_claims(now: i64) -> IdentityClaims {
        IdentityClaims {
            sub: "user-123".into(),
            iat: now,
            exp: now + 60,
            groups: vec!["infisical-admin".into()],
            act: ActClaim {
                sub: "mcp-gateway".into(),
            },
        }
    }

    fn authorization(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static(value));
        headers
    }
}
