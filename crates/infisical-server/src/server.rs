use axum::body::Bytes;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{
        HeaderMap, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use infisical_mcp::{
    InfisicalMcp,
    files::{
        DOWNLOAD_ROUTE_PREFIX, ENVELOPE_MEDIA_TYPE, FileConfig, FileError, MAX_UPLOAD_BYTES,
        SecretFilePlane, TRANSFER_CREDENTIAL_HEADER, UPLOAD_ROUTE_PREFIX,
    },
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};

use crate::{
    auth::{IdentityVerifier, IdentityVerifierError, IngressAuth, require_mcp_authentication},
    config::Settings,
};

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

/// Compose the independently healthy endpoint and authenticated MCP service.
///
/// # Errors
///
/// Returns an error when the identity verifier cannot be safely constructed.
pub fn build_router(
    settings: &Settings,
    cancellation: &CancellationToken,
) -> Result<Router, IdentityVerifierError> {
    let verifier = settings
        .identity
        .clone()
        .map(IdentityVerifier::new)
        .transpose()?;
    let auth = IngressAuth::new(
        Arc::clone(&settings.bearers),
        verifier,
        settings.allowed_hosts.clone(),
        settings.allowed_origins.clone(),
    );
    let allowed_hosts = settings.allowed_hosts.clone();
    let allowed_origins = settings.allowed_origins.clone();
    let files = settings.files.as_ref().map(|file_settings| {
        SecretFilePlane::new(FileConfig {
            public_origin: file_settings.public_origin.clone(),
            ttl: file_settings.ttl,
            max_staged: file_settings.max_staged,
        })
    });
    let profile = if settings.identity.is_some() {
        infisical_mcp::runtime::HttpProfile::Gateway
    } else {
        infisical_mcp::runtime::HttpProfile::Standalone
    };
    let handler = InfisicalMcp::new(settings.infisical.clone())
        .with_runtime(infisical_mcp::runtime::RuntimeSettings::Http {
            profile,
            max_request_bytes: settings.max_body_bytes,
            max_concurrent_requests: settings.max_concurrent_requests,
            request_timeout: settings.request_timeout,
        })
        .with_files(files.clone());
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_cancellation_token(cancellation.child_token())
            .with_allowed_hosts(allowed_hosts)
            .with_allowed_origins(allowed_origins)
            .with_stateful_mode(false)
            .with_json_response(true),
    );

    let mcp = Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(
            settings.max_body_bytes,
            enforce_body_limit,
        ))
        .layer(middleware::from_fn_with_state(
            auth,
            require_mcp_authentication,
        ))
        .layer(ConcurrencyLimitLayer::new(settings.max_concurrent_requests))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            settings.request_timeout,
        ));

    let mut app = Router::new().route("/healthz", get(healthz)).merge(mcp);
    if let Some(plane) = files {
        // The per-transfer credential is the only authority on these routes: the
        // gateway moves file bytes with descriptor headers alone, not its MCP bearer,
        // so they sit beside `/mcp` rather than behind its ingress auth. They do carry
        // the same concurrency and deadline bounds, so a stalled transfer cannot hold
        // an envelope buffer indefinitely or multiply without limit.
        app = app.merge(
            files_router(Arc::clone(&plane))
                .layer(ConcurrencyLimitLayer::new(settings.max_concurrent_requests))
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    settings.request_timeout,
                )),
        );
        tokio::spawn(run_sweeper(plane, cancellation.child_token()));
    }
    Ok(app.layer(TraceLayer::new_for_http()))
}

fn files_router(plane: Arc<SecretFilePlane>) -> Router {
    Router::new()
        .route(
            &format!("{DOWNLOAD_ROUTE_PREFIX}{{id}}"),
            get(serve_download),
        )
        .route(
            &format!("{UPLOAD_ROUTE_PREFIX}{{id}}"),
            axum::routing::put(receive_upload)
                // The whole body is one bounded secret value; anything larger is
                // refused before it is buffered.
                .layer(axum::extract::DefaultBodyLimit::max(
                    MAX_UPLOAD_BYTES + 1024,
                )),
        )
        .with_state(plane)
}

async fn receive_upload(
    State(plane): State<Arc<SecretFilePlane>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    use futures_util::StreamExt as _;

    let Some(credential) = headers
        .get(TRANSFER_CREDENTIAL_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return refusal(
            StatusCode::FORBIDDEN,
            FileError::BadCredential.public_code(),
        );
    };
    // Claimed before any body byte is read: the credential is this route's only
    // authority, so an unauthenticated peer costs nothing past this check, and a
    // valid claim spends the single-use descriptor immediately — every later outcome,
    // including a transport error or cancellation mid-body, is an already-spent
    // attempt by construction.
    let claim = match plane.claim_upload(&id, credential) {
        Ok(claim) => claim,
        Err(error) => {
            tracing::warn!(code = error.code(), "refused a secret upload");
            return refusal(StatusCode::FORBIDDEN, error.public_code());
        }
    };

    // Streamed into pre-sized zeroizing memory: a plain full-body buffer would leave
    // an unzeroized plaintext copy behind when dropped, and a growing buffer would
    // abandon one on reallocation. One byte past the cap is kept so an oversized
    // transfer fails the claim's own size check and answers with the plane's bounded
    // refusal.
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(MAX_UPLOAD_BYTES + 1));
    let mut stream = body.into_data_stream();
    while let Some(frame) = stream.next().await {
        let Ok(frame) = frame else {
            return refusal(StatusCode::BAD_REQUEST, "infisical_file_transfer_failed");
        };
        let room = (MAX_UPLOAD_BYTES + 1) - bytes.len();
        bytes.extend_from_slice(&frame[..frame.len().min(room)]);
        if frame.len() >= room {
            break;
        }
    }

    match claim.complete(bytes) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => {
            // The operator's log keeps the precise reason; the caller gets the bounded
            // one, so a refusal is never an oracle for which identifiers are real.
            tracing::warn!(code = error.code(), "refused a secret upload");
            let status = match error {
                FileError::SizeMismatch | FileError::DigestMismatch => StatusCode::BAD_REQUEST,
                _ => StatusCode::FORBIDDEN,
            };
            refusal(status, error.public_code())
        }
    }
}

async fn serve_download(
    State(plane): State<Arc<SecretFilePlane>>,
    method: axum::http::Method,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    // Axum's `get` router also dispatches HEAD and strips the body it returns. A HEAD
    // reaching `serve` would consume the one-time envelope while delivering nothing, so
    // only a true GET may redeem a download.
    if method != axum::http::Method::GET {
        return refusal(
            StatusCode::METHOD_NOT_ALLOWED,
            FileError::BadCredential.public_code(),
        );
    }
    let Some(credential) = headers
        .get(TRANSFER_CREDENTIAL_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return refusal(
            StatusCode::FORBIDDEN,
            FileError::BadCredential.public_code(),
        );
    };
    match plane.serve(&id, credential) {
        // `no-store` because the body is a secret authorized by a request header: a
        // cache keyed only by this URL would replay the envelope past the single-use
        // consumption in `serve`. The body owns the served envelope itself, so the
        // bytes stay in zeroizing memory until the transport drops them.
        Ok(envelope) => (
            StatusCode::OK,
            [
                (CONTENT_TYPE, ENVELOPE_MEDIA_TYPE),
                (CACHE_CONTROL, "no-store"),
            ],
            Body::from(Bytes::from_owner(envelope)),
        )
            .into_response(),
        Err(error) => {
            // The operator's log keeps the precise reason; the caller gets the bounded
            // one, so a refusal is never an oracle for which identifiers are real.
            tracing::warn!(code = error.code(), "refused a secret download");
            refusal(StatusCode::FORBIDDEN, error.public_code())
        }
    }
}

fn refusal(status: StatusCode, code: &str) -> Response {
    (status, Json(serde_json::json!({ "error": code }))).into_response()
}

/// How often expired envelopes are reclaimed between requests.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

async fn run_sweeper(plane: Arc<SecretFilePlane>, cancellation: CancellationToken) {
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            _ = ticker.tick() => plane.sweep(),
        }
    }
}

async fn enforce_body_limit(State(limit): State<usize>, request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, limit).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

async fn healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
    use infisical_api::{ClientSettings, InfisicalClient, SecretValue};
    use infisical_mcp::{InfisicalMcp, MCP_INSTRUCTIONS, MCP_SERVER_NAME};
    use jsonwebtoken::{
        Algorithm, EncodingKey, Header, encode,
        jwk::{
            AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm,
            OctetKeyPairParameters, OctetKeyPairType, PublicKeyUse,
        },
    };
    use serde::Serialize;
    use serde_json::{Value, json};
    use tokio_util::sync::CancellationToken;
    use tower::ServiceExt;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{
            body_bytes, body_json, body_partial_json, header as wire_header, method, path,
            query_param,
        },
    };

    use crate::{
        auth::{GatewayBearers, IdentityVerifierSettings},
        config::Settings,
        server::build_router,
    };

    const CURRENT: &str = "0123456789abcdef0123456789abcdef";
    const PREVIOUS: &str = "fedcba9876543210fedcba9876543210";
    const ISSUER: &str = "https://mcp.test";
    const AUDIENCE: &str = MCP_SERVER_NAME;
    const KEY_ID: &str = "gateway-main";

    struct TestKey {
        signing: SigningKey,
        jwk: Jwk,
    }

    #[derive(Serialize)]
    struct TestAct<'a> {
        sub: &'a str,
    }

    #[derive(Serialize)]
    struct TestClaims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        iat: i64,
        exp: i64,
        groups: Vec<&'a str>,
        act: TestAct<'a>,
    }

    fn test_key() -> TestKey {
        test_key_with(KEY_ID, 7)
    }

    fn test_key_with(key_id: &str, key_byte: u8) -> TestKey {
        let signing = SigningKey::from_bytes(&[key_byte; 32]);
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
        let jwk = Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_algorithm: Some(KeyAlgorithm::EdDSA),
                key_id: Some(key_id.to_owned()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::Ed25519,
                x,
            }),
        };
        TestKey { signing, jwk }
    }

    fn unix_timestamp() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test clock after epoch")
                .as_secs(),
        )
        .expect("test timestamp fits i64")
    }

    fn sign_identity(key: &TestKey, audience: &str, issued_at: i64, expires_at: i64) -> String {
        sign_identity_with_key_id(key, KEY_ID, audience, issued_at, expires_at)
    }

    fn sign_identity_with_key_id(
        key: &TestKey,
        key_id: &str,
        audience: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> String {
        let claims = TestClaims {
            iss: ISSUER,
            sub: "user-123",
            aud: audience,
            iat: issued_at,
            exp: expires_at,
            groups: vec!["infisical-admin"],
            act: TestAct {
                sub: "mcp-tool-search-gateway",
            },
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(key_id.to_owned());
        let private_key = key
            .signing
            .to_pkcs8_der()
            .expect("encode deterministic test key")
            .to_bytes();
        encode(&header, &claims, &EncodingKey::from_ed_der(&private_key))
            .expect("sign test identity")
    }

    async fn test_router() -> (Router, TestKey, MockServer) {
        test_router_with_timing(Duration::from_secs(5), Duration::ZERO).await
    }

    /// A router whose reveal transfer plane is on, dialable at the loopback origin the
    /// descriptor will name. The origin's host is arbitrary for `Router::oneshot` tests,
    /// which never dial it.
    async fn test_router_with_files() -> (Router, TestKey, MockServer) {
        test_router_with(
            Duration::from_secs(5),
            Duration::ZERO,
            Some(crate::config::FileSettings {
                public_origin: "http://localhost:8000".into(),
                ttl: Duration::from_mins(1),
                max_staged: 4,
            }),
        )
        .await
    }

    async fn test_router_with_timing(
        request_timeout: Duration,
        jwks_delay: Duration,
    ) -> (Router, TestKey, MockServer) {
        test_router_with(request_timeout, jwks_delay, None).await
    }

    async fn test_router_with(
        request_timeout: Duration,
        jwks_delay: Duration,
        files: Option<crate::config::FileSettings>,
    ) -> (Router, TestKey, MockServer) {
        let key = test_key();
        let jwks_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(jwks_delay)
                    .set_body_json(JwkSet {
                        keys: vec![key.jwk.clone()],
                    }),
            )
            .mount(&jwks_server)
            .await;
        let settings = Settings {
            host: "127.0.0.1".into(),
            port: 8000,
            log_level: "info".into(),
            allowed_hosts: vec!["localhost".into()],
            allowed_origins: vec!["https://gateway.test".into()],
            request_timeout,
            max_concurrent_requests: 4,
            max_body_bytes: 16 * 1024,
            bearers: Arc::new(
                GatewayBearers::new(CURRENT.into(), Some(PREVIOUS.into()))
                    .expect("valid test bearer configuration"),
            ),
            identity: Some(IdentityVerifierSettings {
                jwks_url: Url::parse(&format!("{}/jwks", jwks_server.uri()))
                    .expect("wiremock URL is valid"),
                issuer: ISSUER.into(),
                allow_private_http: false,
                request_timeout: Duration::from_secs(2),
                cache_ttl: Duration::from_mins(1),
            }),
            infisical: InfisicalClient::new(ClientSettings::new(
                Url::parse(&jwks_server.uri()).expect("wiremock URL is valid"),
                "server-test-client".into(),
                SecretValue::new("server-test-client-secret"),
            ))
            .expect("valid Infisical test client"),
            files,
        };
        let cancellation = CancellationToken::new();
        let router = build_router(&settings, &cancellation).expect("build test router");
        (router, key, jwks_server)
    }

    /// Address a `tools/call` the way a client must.
    ///
    /// Published tools are called by name; every other operation is reached
    /// through the executor serving its tier. Rewriting here keeps each test
    /// stating the operation it means to exercise.
    fn address_through_executor(body: &Value) -> Value {
        let mut body = body.clone();
        if body.get("method").and_then(Value::as_str) != Some("tools/call") {
            return body;
        }
        let Some(params) = body.get_mut("params").and_then(Value::as_object_mut) else {
            return body;
        };
        let Some(name) = params
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return body;
        };
        let Some(executor) = infisical_mcp::executor_for_operation(&name) else {
            return body;
        };

        let arguments = params.remove("arguments").unwrap_or_else(|| json!({}));
        params.insert("name".to_owned(), json!(executor));
        params.insert(
            "arguments".to_owned(),
            json!({ "operation": name, "arguments": arguments }),
        );
        body
    }

    fn mcp_request(body: &Value, bearer: Option<&str>, identity: Option<&str>) -> Request<Body> {
        let body = &address_through_executor(body);
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(bearer) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        if let Some(identity) = identity {
            builder = builder.header("x-mcp-identity", identity);
        }
        builder
            .body(Body::from(body.to_string()))
            .expect("valid MCP test request")
    }

    fn initialize_body() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "wire-test", "version": "1" }
            }
        })
    }

    async fn json_body(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .expect("bounded response body");
        serde_json::from_slice(&bytes).expect("JSON response")
    }

    async fn call_authenticated_tool(
        router: Router,
        identity: &str,
        id: u64,
        name: &str,
        arguments: Value,
    ) -> Value {
        let response = router
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": { "name": name, "arguments": arguments }
                }),
                Some(CURRENT),
                Some(identity),
            ))
            .await
            .expect("authenticated tool response");
        assert_eq!(response.status(), StatusCode::OK);
        json_body(response).await
    }

    async fn upload_authenticated_file(
        router: Router,
        identity: &str,
        id: u64,
        name: &str,
        bytes: Vec<u8>,
    ) -> String {
        let authorized = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "files/authorizeUpload",
                    "params": { "name": name, "mimeType": "application/x-pem-file" }
                }),
                Some(CURRENT),
                Some(identity),
            ))
            .await
            .expect("files/authorizeUpload response");
        assert_eq!(authorized.status(), StatusCode::OK);
        let authorized = json_body(authorized).await;
        let uri = authorized["result"]["file"]["uri"]
            .as_str()
            .expect("upload authorization returns a file reference")
            .to_owned();
        let route = authorized["result"]["upload"]["url"]
            .as_str()
            .expect("upload descriptor URL")
            .strip_prefix("http://localhost:8000")
            .expect("descriptor uses the configured public origin")
            .to_owned();
        let credential = authorized["result"]["upload"]["headers"]["Infisical-Transfer-Credential"]
            .as_str()
            .expect("upload descriptor credential")
            .to_owned();
        let uploaded = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(route)
                    .header(header::HOST, "localhost")
                    .header("Infisical-Transfer-Credential", credential)
                    .body(Body::from(bytes))
                    .expect("valid upload request"),
            )
            .await
            .expect("upload response");
        assert_eq!(uploaded.status(), StatusCode::NO_CONTENT);
        uri
    }

    fn expected_initialize_response() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "mcp-infisical-rs",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "instructions": MCP_INSTRUCTIONS
            }
        })
    }

    fn expected_call_response() -> Value {
        let expected_info = json!({
            "name": "infisical",
            "version": env!("CARGO_PKG_VERSION"),
            "protocolVersion": "2025-11-25",
            "transport": "streamable-http",
            "httpProfile": "gateway",
            "schemaRevision": infisical_mcp::runtime::SCHEMA_REVISION
        });
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string(&expected_info).unwrap()
                }],
                "structuredContent": expected_info,
                "isError": false
            }
        })
    }

    /// The surface a client sees: local discovery plus one executor per tier.
    ///
    /// The typed operations are reached through these rather than listed, so a
    /// name appearing here is a change to what clients are offered.
    const EXPECTED_WIRE_TOOL_NAMES: [&str; 9] = [
        "server.info",
        "server.capabilities",
        "operations.list",
        "operations.describe",
        "types.describe",
        "infisical.read",
        "infisical.readAudited",
        "infisical.write",
        "infisical.destroy",
    ];

    fn assert_wire_catalog(list_json: &Value) {
        assert_eq!(list_json["jsonrpc"], "2.0");
        assert_eq!(list_json["id"], 2);
        let tools = list_json["result"]["tools"]
            .as_array()
            .expect("tools/list returns an array");
        assert_eq!(
            list_json["result"],
            serde_json::to_value(InfisicalMcp::list_tools_payload()).unwrap(),
        );
        assert_eq!(wire_tool_names(tools), EXPECTED_WIRE_TOOL_NAMES);
        assert_wire_catalog_details(tools);
    }

    fn wire_tool_names(tools: &[Value]) -> Vec<&str> {
        tools
            .iter()
            .map(|tool| tool["name"].as_str().expect("tool name"))
            .collect()
    }

    /// Check the surface a client actually receives.
    ///
    /// The per-operation schemas these assertions used to walk are no longer in
    /// this catalog. They are asserted where they now live, against the
    /// operation set in `infisical-mcp`, so the coverage moved rather than
    /// went away; what belongs here is the shape of the published tools.
    fn assert_wire_catalog_details(tools: &[Value]) {
        for tool in tools {
            let name = tool["name"].as_str().expect("tool name");
            assert!(
                tool["inputSchema"].is_object(),
                "{name} must declare an input schema"
            );
            assert!(
                tool["outputSchema"].is_object(),
                "{name} must declare an output schema"
            );
            assert!(
                tool["description"]
                    .as_str()
                    .is_some_and(|description| !description.is_empty()),
                "{name} must describe itself"
            );

            let side_effects = !wire_is_local_discovery(name);
            assert_eq!(
                tool["annotations"]["readOnlyHint"],
                name != "infisical.readAudited"
                    && name != "infisical.write"
                    && name != "infisical.destroy",
                "{name} read-only annotation"
            );
            assert_eq!(
                tool["annotations"]["destructiveHint"],
                name == "infisical.destroy",
                "{name} destructive annotation"
            );
            assert_eq!(
                tool["annotations"]["openWorldHint"],
                side_effects || name == "infisical.read",
                "{name} open-world annotation"
            );
        }
    }

    fn wire_is_local_discovery(name: &str) -> bool {
        matches!(
            name,
            "server.info"
                | "server.capabilities"
                | "operations.list"
                | "operations.describe"
                | "types.describe"
        )
    }

    #[tokio::test]
    async fn operation_discovery_and_executor_refusals_are_local_on_the_wire() {
        let (router, key, upstream) = test_router().await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for tier in ["read", "readAudited", "write", "destroy"] {
            let response = call_authenticated_tool(
                router.clone(),
                &identity,
                2,
                "operations.list",
                json!({"tier": tier}),
            )
            .await;
            let operations = response["result"]["structuredContent"]["operations"]
                .as_array()
                .expect("operation discovery");
            assert!(!operations.is_empty());
            for operation in operations {
                assert_eq!(operation["tier"], tier);
                assert_eq!(operation["executor"], format!("infisical.{tier}"));
                assert_eq!(
                    infisical_mcp::executor_for_operation(operation["name"].as_str().unwrap()),
                    operation["executor"].as_str()
                );
            }
        }
        for operation in ["secrets.delete", "unknown.operation"] {
            let response = call_authenticated_tool(
                router.clone(),
                &identity,
                3,
                "infisical.read",
                json!({"operation": operation, "arguments": {}}),
            )
            .await;
            assert_eq!(response["error"]["code"], -32602);
        }
        let requests = upstream.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.path(), "/jwks");
    }

    #[tokio::test]
    async fn bounded_discovery_and_input_only_schemas_work_on_the_wire() {
        let (router, key, upstream) = test_router().await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let found = call_authenticated_tool(
            router.clone(),
            &identity,
            2,
            "operations.list",
            json!({"query": "rotate database password", "limit": 1}),
        )
        .await;
        assert_eq!(
            found["result"]["structuredContent"]["operations"][0]["name"],
            "secretRotations.sql.rotate"
        );
        let page = call_authenticated_tool(
            router.clone(),
            &identity,
            3,
            "operations.list",
            json!({"namePrefix": "secrets.", "limit": 1}),
        )
        .await;
        assert_eq!(
            page["result"]["structuredContent"]["operations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(page["result"]["structuredContent"]["nextOffset"], 1);
        let described = call_authenticated_tool(
            router.clone(),
            &identity,
            4,
            "operations.describe",
            json!({"operation": "projects.list", "includeOutputSchema": false}),
        )
        .await;
        let output = &described["result"]["structuredContent"];
        assert!(output["inputSchema"].is_object());
        assert!(output.get("outputSchema").is_none());
        let invalid = call_authenticated_tool(
            router,
            &identity,
            5,
            "operations.list",
            json!({"namePrefix": "wire-discovery-canary".repeat(4)}),
        )
        .await;
        assert_eq!(invalid["error"]["code"], -32602);
        assert!(!invalid.to_string().contains("wire-discovery-canary"));
        let requests = upstream.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.path(), "/jwks");
    }

    #[tokio::test]
    async fn gateway_discovery_reports_effective_limits_and_file_requirements() {
        for files_enabled in [false, true] {
            let (router, key, upstream) = if files_enabled {
                test_router_with_files().await
            } else {
                test_router().await
            };
            let now = unix_timestamp();
            let identity = sign_identity(&key, AUDIENCE, now, now + 60);
            let response = call_authenticated_tool(
                router.clone(),
                &identity,
                2,
                "server.capabilities",
                json!({}),
            )
            .await;
            let runtime = &response["result"]["structuredContent"]["runtime"];
            assert_eq!(runtime["transport"], "streamable-http");
            assert_eq!(runtime["httpProfile"], "gateway");
            assert_eq!(runtime["upstreamAccess"], "notProbed");
            assert_eq!(runtime["limits"]["maxRequestBytes"], 16 * 1024);
            assert_eq!(runtime["limits"]["maxConcurrentRequests"], 4);
            assert_eq!(runtime["limits"]["requestTimeoutSeconds"], 5.0);
            assert_eq!(runtime["delivery"]["uploadReferences"], files_enabled);
            if files_enabled {
                assert_eq!(runtime["delivery"]["defaultSecretDelivery"], "reference");
                assert_eq!(runtime["delivery"]["fileTransfer"]["ttlSeconds"], 60.0);
                assert_eq!(runtime["delivery"]["fileTransfer"]["maxStaged"], 4);
                assert_eq!(runtime["delivery"]["fileTransfer"]["lostOnRestart"], true);
            } else {
                assert_eq!(runtime["delivery"]["defaultSecretDelivery"], "inlineValue");
                assert!(runtime["delivery"].get("fileTransfer").is_none());
            }
            let described = call_authenticated_tool(
                router,
                &identity,
                3,
                "operations.describe",
                json!({"operation": "certificates.import"}),
            )
            .await;
            let availability = &described["result"]["structuredContent"]["availability"];
            assert_eq!(availability["implemented"], true);
            assert_eq!(availability["enabledHere"], files_enabled);
            assert_eq!(availability["requiresFileTransfer"], true);
            assert_eq!(availability["upstreamAccess"], "notProbed");
            assert!(
                upstream
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .all(|r| r.url.path() == "/jwks")
            );
            assert!(!response.to_string().contains("server-test-client-secret"));
            assert!(!response.to_string().contains("http://localhost:8000"));
        }
    }

    #[tokio::test]
    async fn authenticated_streamable_http_initializes_and_lists_bootstrap_catalog() {
        let (router, key, jwks_server) = test_router().await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);

        let initialize = router
            .clone()
            .oneshot(mcp_request(
                &initialize_body(),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("initialize response");
        assert_eq!(initialize.status(), StatusCode::OK);
        assert_eq!(
            initialize.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(initialize.headers().get("mcp-session-id").is_none());
        let initialize_json = json_body(initialize).await;
        assert_eq!(initialize_json, expected_initialize_response());

        let list = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {}
                }),
                Some(PREVIOUS),
                Some(&identity),
            ))
            .await
            .expect("tools/list response");
        assert_eq!(list.status(), StatusCode::OK);
        let list_json = json_body(list).await;
        assert_wire_catalog(&list_json);

        let call = router
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": { "name": "server.info", "arguments": {} }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("tools/call response");
        assert_eq!(call.status(), StatusCode::OK);
        let call_json = json_body(call).await;
        assert_eq!(call_json, expected_call_response());
        assert_eq!(jwks_server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn authenticated_tool_call_uses_the_dedicated_infisical_client() {
        let (router, key, upstream_server) = test_router().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "server-tool-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "projects": [{
                    "id": "project-1",
                    "name": "Payments",
                    "slug": "payments",
                    "type": "secret-manager",
                    "orgId": "org-1",
                    "description": null,
                    "environments": []
                }]
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);

        let response = router
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "projects.list",
                        "arguments": { "offset": 0, "limit": 10 }
                    }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("projects.list response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(
            body["result"]["structuredContent"]["items"][0]["id"],
            "project-1"
        );
        assert_eq!(body["result"]["structuredContent"]["total"], 1);
        assert_eq!(body["result"]["isError"], false);
        assert_eq!(upstream_server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn authenticated_certificate_policy_lifecycle_preserves_the_streamable_http_contract() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let policy_id = "22222222-2222-4222-8222-222222222222";
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "policy-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let policy = json!({
            "id": policy_id,
            "projectId": project_id,
            "name": "server-certificates",
            "description": null,
            "subject": null,
            "sans": null,
            "keyUsages": null,
            "extendedKeyUsages": null,
            "algorithms": null,
            "validity": null,
            "basicConstraints": null,
            "createdAt": "2026-07-21T12:00:00.000Z",
            "updatedAt": "2026-07-21T12:00:01.000Z"
        });
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/certificate-policies"))
            .and(query_param("projectId", project_id))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicies": [policy.clone()],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{policy_id}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": policy.clone()
            })))
            .expect(2)
            .mount(&upstream_server)
            .await;
        let mut updated_policy = policy.clone();
        updated_policy["name"] = json!("renamed-policy");
        updated_policy["updatedAt"] = json!("2026-07-21T12:00:02.000Z");
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{policy_id}"
            )))
            .and(body_json(json!({ "name": "renamed-policy" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": updated_policy
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{policy_id}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": policy
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let rejected_update = call_authenticated_tool(
            router.clone(),
            &identity,
            36,
            "certificatePolicies.update",
            json!({
                "target": { "projectId": project_id, "policyId": policy_id },
                "confirm": true
            }),
        )
        .await;
        assert_eq!(rejected_update["error"]["code"], -32602);
        let rejected_delete = call_authenticated_tool(
            router.clone(),
            &identity,
            37,
            "certificatePolicies.delete",
            json!({
                "target": { "projectId": project_id, "policyId": policy_id },
                "confirm": false
            }),
        )
        .await;
        assert_eq!(rejected_delete["result"]["isError"], true);
        let response = call_authenticated_tool(
            router.clone(),
            &identity,
            38,
            "certificatePolicies.list",
            json!({ "projectId": project_id }),
        )
        .await;
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["structuredContent"]["items"][0]["id"],
            policy_id
        );
        assert_eq!(
            response["result"]["content"][0]["text"],
            response["result"]["structuredContent"].to_string()
        );
        let updated = call_authenticated_tool(
            router.clone(),
            &identity,
            39,
            "certificatePolicies.update",
            json!({
                "target": { "projectId": project_id, "policyId": policy_id },
                "name": "renamed-policy",
                "confirm": true
            }),
        )
        .await;
        assert_eq!(updated["result"]["isError"], false);
        assert_eq!(
            updated["result"]["structuredContent"]["name"],
            "renamed-policy"
        );
        let deleted = call_authenticated_tool(
            router,
            &identity,
            40,
            "certificatePolicies.delete",
            json!({
                "target": { "projectId": project_id, "policyId": policy_id },
                "confirm": true
            }),
        )
        .await;
        assert_eq!(deleted["result"]["isError"], false);
        assert_eq!(deleted["result"]["structuredContent"]["id"], policy_id);
    }

    #[tokio::test]
    async fn authenticated_certificate_inventory_preserves_the_streamable_http_contract() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let certificate_id = "22222222-2222-4222-8222-222222222222";
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "certificate-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{project_id}/certificates/search"
            )))
            .and(body_json(json!({ "offset": 0, "limit": 50 })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [{
                    "id": certificate_id,
                    "projectId": project_id,
                    "friendlyName": "api.example.test",
                    "commonName": "api.example.test",
                    "status": "active",
                    "serialNumber": "01AB",
                    "notBefore": "2026-07-21T12:00:00.000Z",
                    "notAfter": "2027-07-21T12:00:00.000Z",
                    "keyAlgorithm": "RSA_2048",
                    "extendedKeyUsages": ["serverAuth"],
                    "isCA": false,
                    "hasPrivateKey": true,
                    "createdAt": "2026-07-21T12:00:00.000Z",
                    "updatedAt": "2026-07-21T12:00:01.000Z"
                }],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let response = call_authenticated_tool(
            router,
            &identity,
            39,
            "certificates.list",
            json!({ "projectId": project_id, "limit": 50 }),
        )
        .await;
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["structuredContent"]["items"][0]["id"],
            certificate_id
        );
        assert_eq!(
            response["result"]["structuredContent"]["items"][0]["hasPrivateKey"],
            true
        );
        assert!(
            response["result"]["structuredContent"]["items"][0]
                .get("privateKey")
                .is_none()
        );
        assert_eq!(
            response["result"]["content"][0]["text"],
            response["result"]["structuredContent"].to_string()
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn authenticated_certificate_material_transfer_preserves_the_streamable_http_contract() {
        let (router, key, upstream_server) = test_router_with_files().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let certificate_id = "22222222-2222-4222-8222-222222222222";
        let certificate = include_str!("../../infisical-api/test-fixtures/profile-cert.txt")
            .strip_suffix('\n')
            .unwrap();
        let issuer = include_str!("../../infisical-api/test-fixtures/profile-issuer-cert.txt")
            .strip_suffix('\n')
            .unwrap();
        let private_key = include_str!("../../infisical-api/test-fixtures/profile-private-key.txt")
            .strip_suffix('\n')
            .unwrap();
        let inventory = json!({
            "id": certificate_id,
            "projectId": project_id,
            "friendlyName": "imported-certificate",
            "commonName": "certificate-profile.example",
            "status": "active",
            "serialNumber": "A1B2",
            "notBefore": "2026-07-21T12:00:00.000Z",
            "notAfter": "2027-07-21T12:00:00.000Z",
            "altNames": null,
            "keyAlgorithm": "RSA_2048",
            "signatureAlgorithm": "RSA-SHA256",
            "isCA": false,
            "hasPrivateKey": true,
            "createdAt": "2026-07-21T12:00:00.000Z",
            "updatedAt": "2026-07-21T12:00:01.000Z"
        });
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "certificate-material-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let import_inventory_calls = Arc::new(AtomicUsize::new(0));
        let imported_inventory = inventory.clone();
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{project_id}/certificates/search"
            )))
            .and(body_json(json!({
                "offset": 0,
                "limit": 100,
                "search": "A1B2"
            })))
            .respond_with(move |_: &wiremock::Request| {
                if import_inventory_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "certificates": [],
                        "totalCount": 0
                    }))
                } else {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "certificates": [imported_inventory.clone()],
                        "totalCount": 1
                    }))
                }
            })
            .expect(2)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificates/import-certificate"))
            .and(wire_header(
                "authorization",
                "Bearer certificate-material-wire-token",
            ))
            .and(body_json(json!({
                "projectId": project_id,
                "certificatePem": certificate,
                "privateKeyPem": private_key,
                "chainPem": issuer,
                "friendlyName": "imported-certificate"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate,
                "privateKey": private_key,
                "certificateChain": issuer,
                "serialNumber": "A1B2"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{project_id}/certificates/search"
            )))
            .and(body_json(json!({
                "offset": 0,
                "limit": 100,
                "search": certificate_id
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [inventory],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{certificate_id}/certificate"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate,
                "certificateChain": issuer,
                "serialNumber": "A1B2"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{certificate_id}/private-key"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(private_key))
            .expect(1)
            .mount(&upstream_server)
            .await;

        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let certificate_uri = upload_authenticated_file(
            router.clone(),
            &identity,
            50,
            "certificate.pem",
            certificate.as_bytes().to_vec(),
        )
        .await;
        let private_key_uri = upload_authenticated_file(
            router.clone(),
            &identity,
            51,
            "private-key.pem",
            private_key.as_bytes().to_vec(),
        )
        .await;
        let chain_uri = upload_authenticated_file(
            router.clone(),
            &identity,
            52,
            "chain.pem",
            issuer.as_bytes().to_vec(),
        )
        .await;
        let imported = call_authenticated_tool(
            router.clone(),
            &identity,
            53,
            "certificates.import",
            json!({
                "projectId": project_id,
                "certificateFile": certificate_uri,
                "privateKeyFile": private_key_uri,
                "certificateChainFile": chain_uri,
                "friendlyName": "imported-certificate",
                "confirm": true
            }),
        )
        .await;
        assert_eq!(imported["result"]["isError"], false, "{imported}");
        assert_eq!(
            imported["result"]["structuredContent"]["id"],
            certificate_id
        );
        assert!(!imported.to_string().contains(private_key));

        let revealed = call_authenticated_tool(
            router.clone(),
            &identity,
            54,
            "certificates.privateKey.reveal",
            json!({
                "target": {"projectId": project_id, "certificateId": certificate_id},
                "confirmReveal": true
            }),
        )
        .await;
        assert_eq!(revealed["result"]["isError"], false, "{revealed}");
        assert!(!revealed.to_string().contains(private_key));
        let uri = revealed["result"]["structuredContent"]["secretFile"]["uri"]
            .as_str()
            .unwrap();
        let authorized = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 55,
                    "method": "files/authorizeDownload",
                    "params": {"uri": uri}
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("files/authorizeDownload response");
        let authorized = json_body(authorized).await;
        let route = authorized["result"]["download"]["url"]
            .as_str()
            .unwrap()
            .strip_prefix("http://localhost:8000")
            .unwrap();
        let credential =
            authorized["result"]["download"]["headers"]["Infisical-Transfer-Credential"]
                .as_str()
                .unwrap();
        let served = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(route)
                    .header(header::HOST, "localhost")
                    .header("Infisical-Transfer-Credential", credential)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("certificate private-key download");
        assert_eq!(served.status(), StatusCode::OK);
        let envelope = json_body(served).await;
        assert_eq!(envelope["operation"], "certificates.privateKey.reveal");
        assert_eq!(envelope["data"]["privateKey"], private_key);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn authenticated_certificate_lifecycle_preserves_the_streamable_http_contract() {
        let (router, key, upstream_server) = test_router_with_files().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let certificate_id = "22222222-2222-4222-8222-222222222222";
        let expired_certificate_id = "66666666-6666-4666-8666-666666666666";
        let profile_id = "33333333-3333-4333-8333-333333333333";
        let renewed_id = "44444444-4444-4444-8444-444444444444";
        let request_id = "55555555-5555-4555-8555-555555555555";
        let certificate = include_str!("../../infisical-api/test-fixtures/profile-cert.txt")
            .strip_suffix('\n')
            .unwrap();
        let issuer = include_str!("../../infisical-api/test-fixtures/profile-issuer-cert.txt")
            .strip_suffix('\n')
            .unwrap();
        let private_key = include_str!("../../infisical-api/test-fixtures/profile-private-key.txt")
            .strip_suffix('\n')
            .unwrap();
        let source = json!({
            "id": certificate_id,
            "projectId": project_id,
            "friendlyName": "certificate-profile.example",
            "commonName": "certificate-profile.example",
            "status": "active",
            "serialNumber": "01AB",
            "notBefore": "2026-07-21T12:00:00.000Z",
            "notAfter": "2027-07-21T12:00:00.000Z",
            "isCA": false,
            "profileId": profile_id,
            "enrollmentType": "api",
            "hasPrivateKey": true,
            "createdAt": "2026-07-21T12:00:00.000Z",
            "updatedAt": "2026-07-21T12:00:01.000Z"
        });
        let mut expired_source = source.clone();
        expired_source["id"] = json!(expired_certificate_id);
        expired_source["status"] = json!("expired");
        let mut renewed_source = source.clone();
        renewed_source["id"] = json!(renewed_id);
        renewed_source["serialNumber"] = json!("A1B2");
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "certificate-lifecycle-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{project_id}/certificates/search"
            )))
            .and(body_json(json!({
                "offset": 0,
                "limit": 100,
                "search": expired_certificate_id
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [expired_source],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{project_id}/certificates/search"
            )))
            .and(body_json(json!({
                "offset": 0,
                "limit": 100,
                "search": certificate_id
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [source.clone()],
                "totalCount": 1
            })))
            .expect(4)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/projects/{project_id}/certificates/search"
            )))
            .and(body_json(json!({
                "offset": 0,
                "limit": 100,
                "search": renewed_id
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [renewed_source],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{certificate_id}/renew"
            )))
            .and(body_json(json!({ "removeRootsFromChain": false })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": certificate,
                "issuingCaCertificate": issuer,
                "certificateChain": issuer,
                "privateKey": private_key,
                "serialNumber": "A1B2",
                "certificateId": renewed_id,
                "certificateRequestId": request_id
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{certificate_id}/revoke"
            )))
            .and(body_json(
                json!({ "revocationReason": "CESSATION_OF_OPERATION" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "Successfully revoked certificate",
                "serialNumber": "01AB",
                "revokedAt": "2026-08-25T02:00:00.000Z"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{certificate_id}/config"
            )))
            .and(body_json(json!({ "enableAutoRenewal": false })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "Auto-renewal disabled successfully"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/{certificate_id}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": source
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;

        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let rejected = call_authenticated_tool(
            router.clone(),
            &identity,
            48,
            "certificates.revoke",
            json!({
                "target": { "projectId": project_id, "certificateId": certificate_id },
                "reason": "CESSATION_OF_OPERATION",
                "confirm": false
            }),
        )
        .await;
        assert_eq!(rejected["result"]["isError"], true);

        let invalid_state = call_authenticated_tool(
            router.clone(),
            &identity,
            54,
            "certificates.renew",
            json!({
                "target": {
                    "projectId": project_id,
                    "certificateId": expired_certificate_id
                },
                "confirm": true
            }),
        )
        .await;
        assert_eq!(invalid_state["result"]["isError"], true);

        let renewed = call_authenticated_tool(
            router.clone(),
            &identity,
            49,
            "certificates.renew",
            json!({
                "target": { "projectId": project_id, "certificateId": certificate_id },
                "confirm": true
            }),
        )
        .await;
        assert_eq!(renewed["result"]["isError"], false);
        assert!(!renewed.to_string().contains(private_key));
        let renewed_content = &renewed["result"]["structuredContent"];
        assert_eq!(renewed_content["certificateId"], renewed_id);
        assert!(renewed_content.get("privateKey").is_none());
        assert_eq!(
            renewed["result"]["content"][0]["text"],
            renewed_content.to_string()
        );
        let uri = renewed_content["secretFile"]["uri"].as_str().unwrap();

        let revoked = call_authenticated_tool(
            router.clone(),
            &identity,
            50,
            "certificates.revoke",
            json!({
                "target": { "projectId": project_id, "certificateId": certificate_id },
                "reason": "CESSATION_OF_OPERATION",
                "confirm": true
            }),
        )
        .await;
        assert_eq!(
            revoked["result"]["structuredContent"]["serialNumber"],
            "01AB"
        );
        let configured = call_authenticated_tool(
            router.clone(),
            &identity,
            51,
            "certificates.renewalConfiguration.update",
            json!({
                "target": { "projectId": project_id, "certificateId": certificate_id },
                "change": { "type": "disable" }
            }),
        )
        .await;
        assert_eq!(configured["result"]["structuredContent"]["enabled"], false);
        let deleted = call_authenticated_tool(
            router.clone(),
            &identity,
            52,
            "certificates.delete",
            json!({
                "target": { "projectId": project_id, "certificateId": certificate_id },
                "confirm": true
            }),
        )
        .await;
        assert_eq!(deleted["result"]["structuredContent"]["id"], certificate_id);

        let authorized = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 53,
                    "method": "files/authorizeDownload",
                    "params": { "uri": uri }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("files/authorizeDownload response");
        let authorized = json_body(authorized).await;
        let download = &authorized["result"]["download"];
        let route = download["url"]
            .as_str()
            .unwrap()
            .strip_prefix("http://localhost:8000")
            .unwrap();
        let served = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(route)
                    .header(header::HOST, "localhost")
                    .header(
                        "Infisical-Transfer-Credential",
                        download["headers"]["Infisical-Transfer-Credential"]
                            .as_str()
                            .unwrap(),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("renewal private-key download");
        assert_eq!(served.status(), StatusCode::OK);
        let envelope = json_body(served).await;
        assert_eq!(envelope["operation"], "certificates.renew");
        assert_eq!(envelope["data"]["privateKey"], private_key);
    }

    #[tokio::test]
    async fn authenticated_certificate_request_status_is_sanitized_and_project_bound() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let other_project_id = "22222222-2222-4222-8222-222222222222";
        let request_id = "33333333-3333-4333-8333-333333333333";
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "request-status-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let pending = json!({
            "id": request_id,
            "status": "pending_approval",
            "commonName": "api.example.test",
            "altNames": "api.example.test",
            "profileId": "44444444-4444-4444-8444-444444444444",
            "profileName": "api-profile",
            "caId": null,
            "certificateId": null,
            "approvalRequestId": "55555555-5555-4555-8555-555555555555",
            "errorMessage": "wire-error-canary",
            "pendingMessage": "wire-pending-canary",
            "createdAt": "2026-07-21T12:00:00.000Z",
            "updatedAt": "2026-07-21T12:00:01.000Z",
            "certificate": null
        });
        Mock::given(method("POST"))
            .and(path(
                "/api/v1/cert-manager/certificates/certificate-requests/search",
            ))
            .and(body_json(json!({
                "projectId": project_id,
                "offset": 0,
                "limit": 50,
                "status": "pending_approval"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateRequests": [pending],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/api/v1/cert-manager/certificates/certificate-requests/search",
            ))
            .and(body_json(json!({
                "projectId": other_project_id,
                "offset": 0,
                "limit": 100,
                "sortBy": "createdAt",
                "sortOrder": "asc"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateRequests": [],
                "totalCount": 0
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);

        let listed = call_authenticated_tool(
            router.clone(),
            &identity,
            40,
            "certificateRequests.list",
            json!({ "projectId": project_id, "status": "pending_approval" }),
        )
        .await;
        assert_eq!(listed["result"]["isError"], false);
        assert_eq!(
            listed["result"]["structuredContent"]["items"][0]["id"],
            request_id
        );
        let serialized = listed.to_string();
        assert!(!serialized.contains("wire-error-canary"));
        assert!(!serialized.contains("wire-pending-canary"));
        assert!(!serialized.contains("privateKey"));

        let wrong_scope = call_authenticated_tool(
            router,
            &identity,
            41,
            "certificateRequests.get",
            json!({ "projectId": other_project_id, "requestId": request_id }),
        )
        .await;
        assert_eq!(wrong_scope["result"]["isError"], true);
        assert!(
            wrong_scope["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("not found in the supplied Certificate Manager project")
        );
    }

    #[tokio::test]
    async fn authenticated_certificate_request_cancellation_is_preflighted_and_non_replayed() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let request_id = "22222222-2222-4222-8222-222222222222";
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "request-cancel-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/api/v1/cert-manager/certificates/certificate-requests/search",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateRequests": [{
                    "id": request_id,
                    "status": "pending_validation",
                    "commonName": "api.example.test",
                    "altNames": null,
                    "profileId": "33333333-3333-4333-8333-333333333333",
                    "profileName": "api-profile",
                    "caId": null,
                    "certificateId": null,
                    "approvalRequestId": null,
                    "createdAt": "2026-07-21T12:00:00.000Z",
                    "updatedAt": "2026-07-21T12:00:01.000Z",
                    "certificate": null
                }],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/certificate-requests/{request_id}/cancel"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "failed",
                "cancelled": true,
                "errorMessage": "wire-cancel-canary"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let response = call_authenticated_tool(
            router,
            &identity,
            42,
            "certificateRequests.cancel",
            json!({
                "target": { "projectId": project_id, "requestId": request_id },
                "confirm": true
            }),
        )
        .await;
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(response["result"]["structuredContent"]["cancelled"], true);
        assert_eq!(response["result"]["structuredContent"]["status"], "failed");
        assert!(!response.to_string().contains("wire-cancel-canary"));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn authenticated_certificate_request_result_uses_the_reveal_transfer_plane() {
        let (router, key, upstream_server) = test_router_with_files().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let request_id = "22222222-2222-4222-8222-222222222222";
        let certificate_id = "33333333-3333-4333-8333-333333333333";
        let certificate = include_str!("../../infisical-api/test-fixtures/profile-cert.txt")
            .strip_suffix('\n')
            .unwrap();
        let private_key = include_str!("../../infisical-api/test-fixtures/profile-private-key.txt")
            .strip_suffix('\n')
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "request-result-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/api/v1/cert-manager/certificates/certificate-requests/search",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateRequests": [{
                    "id": request_id,
                    "status": "issued",
                    "commonName": "certificate-profile.example",
                    "altNames": null,
                    "profileId": "44444444-4444-4444-8444-444444444444",
                    "profileName": "api-profile",
                    "caId": null,
                    "certificateId": certificate_id,
                    "approvalRequestId": null,
                    "createdAt": "2026-07-21T12:00:00.000Z",
                    "updatedAt": "2026-07-21T12:00:01.000Z",
                    "certificate": {
                        "id": certificate_id,
                        "serialNumber": "A1B2",
                        "status": "active"
                    }
                }],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificates/certificate-requests/{request_id}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "issued",
                "certificate": certificate,
                "certificateId": certificate_id,
                "privateKey": private_key,
                "serialNumber": "A1B2",
                "commonName": "certificate-profile.example",
                "createdAt": "2026-07-21T12:00:00.000Z",
                "updatedAt": "2026-07-21T12:00:01.000Z"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let reveal = call_authenticated_tool(
            router.clone(),
            &identity,
            43,
            "certificateRequests.result.reveal",
            json!({
                "target": { "projectId": project_id, "requestId": request_id },
                "confirmReveal": true
            }),
        )
        .await;
        assert_eq!(reveal["result"]["isError"], false);
        assert!(!reveal.to_string().contains(private_key));
        let structured = &reveal["result"]["structuredContent"];
        assert_eq!(structured["certificate"], certificate);
        assert!(structured.get("privateKey").is_none());
        let uri = structured["secretFile"]["uri"].as_str().unwrap();

        let authorized = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 44,
                    "method": "files/authorizeDownload",
                    "params": { "uri": uri }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("files/authorizeDownload response");
        assert_eq!(authorized.status(), StatusCode::OK);
        let authorized = json_body(authorized).await;
        let download = &authorized["result"]["download"];
        let url = download["url"].as_str().unwrap();
        let route = url.strip_prefix("http://localhost:8000").unwrap();
        let credential = download["headers"]["Infisical-Transfer-Credential"]
            .as_str()
            .unwrap();
        let served = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(route)
                    .header(header::HOST, "localhost")
                    .header("Infisical-Transfer-Credential", credential)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("certificate-request result download");
        assert_eq!(served.status(), StatusCode::OK);
        let envelope = json_body(served).await;
        assert_eq!(envelope["operation"], "certificateRequests.result.reveal");
        assert_eq!(envelope["data"]["privateKey"], private_key);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn authenticated_policy_profile_and_issuance_form_a_usable_wire_path() {
        let (router, key, upstream_server) = test_router_with_files().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let policy_id = "22222222-2222-4222-8222-222222222222";
        let profile_id = "33333333-3333-4333-8333-333333333333";
        let config_id = "44444444-4444-4444-8444-444444444444";
        let ca_id = "55555555-5555-4555-8555-555555555555";
        let request_id = "66666666-6666-4666-8666-666666666666";
        let certificate_id = "77777777-7777-4777-8777-777777777777";
        let certificate = include_str!("../../infisical-api/test-fixtures/profile-cert.txt")
            .strip_suffix('\n')
            .unwrap();
        let issuer_certificate =
            include_str!("../../infisical-api/test-fixtures/profile-issuer-cert.txt")
                .strip_suffix('\n')
                .unwrap();
        let private_key = include_str!("../../infisical-api/test-fixtures/profile-private-key.txt")
            .strip_suffix('\n')
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "issuance-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-policies/{policy_id}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificatePolicy": {
                    "id": policy_id,
                    "projectId": project_id,
                    "name": "server-certificates",
                    "description": null,
                    "subject": null,
                    "sans": null,
                    "keyUsages": null,
                    "extendedKeyUsages": null,
                    "algorithms": null,
                    "validity": null,
                    "basicConstraints": null,
                    "createdAt": "2026-07-21T12:00:00.000Z",
                    "updatedAt": "2026-07-21T12:00:01.000Z"
                }
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/certificate-profiles/{profile_id}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateProfile": {
                    "id": profile_id,
                    "projectId": project_id,
                    "caId": ca_id,
                    "certificatePolicyId": policy_id,
                    "slug": "api-profile",
                    "description": null,
                    "enrollmentType": "api",
                    "issuerType": "ca",
                    "apiConfigId": config_id,
                    "estConfigId": null,
                    "acmeConfigId": null,
                    "scepConfigId": null,
                    "externalConfigs": null,
                    "defaults": null,
                    "apiConfig": {
                        "id": config_id,
                        "autoRenew": false,
                        "renewBeforeDays": null
                    },
                    "createdAt": "2026-07-21T12:00:00.000Z",
                    "updatedAt": "2026-07-21T12:00:01.000Z"
                }
            })))
            .expect(2)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cert-manager/certificates"))
            .and(body_json(json!({
                "profileId": profile_id,
                "attributes": { "commonName": "certificate-profile.example" },
                "removeRootsFromChain": false
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificate": {
                    "certificate": certificate,
                    "issuingCaCertificate": issuer_certificate,
                    "certificateChain": issuer_certificate,
                    "privateKey": private_key,
                    "serialNumber": "A1B2",
                    "certificateId": certificate_id
                },
                "certificateRequestId": request_id,
                "status": "issued"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);

        let policy = call_authenticated_tool(
            router.clone(),
            &identity,
            45,
            "certificatePolicies.get",
            json!({ "projectId": project_id, "policyId": policy_id }),
        )
        .await;
        assert_eq!(policy["result"]["structuredContent"]["id"], policy_id);
        let profile = call_authenticated_tool(
            router.clone(),
            &identity,
            46,
            "certificateProfiles.get",
            json!({ "projectId": project_id, "profileId": profile_id }),
        )
        .await;
        assert_eq!(profile["result"]["structuredContent"]["id"], profile_id);
        let issuance_result = call_authenticated_tool(
            router.clone(),
            &identity,
            47,
            "certificates.issue",
            json!({
                "projectId": project_id,
                "profileId": profile_id,
                "request": {
                    "type": "managed",
                    "attributes": { "commonName": "certificate-profile.example" }
                },
                "confirm": true
            }),
        )
        .await;
        assert_eq!(issuance_result["result"]["isError"], false);
        assert!(!issuance_result.to_string().contains(private_key));
        let structured = &issuance_result["result"]["structuredContent"];
        assert_eq!(structured["outcome"], "issued");
        assert_eq!(structured["requestId"], request_id);
        assert_eq!(structured["certificate"], certificate);
        assert!(structured.get("privateKey").is_none());
        let uri = structured["secretFile"]["uri"].as_str().unwrap();

        let authorized = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 48,
                    "method": "files/authorizeDownload",
                    "params": { "uri": uri }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("files/authorizeDownload response");
        let authorized = json_body(authorized).await;
        let download = &authorized["result"]["download"];
        let route = download["url"]
            .as_str()
            .unwrap()
            .strip_prefix("http://localhost:8000")
            .unwrap();
        let credential = download["headers"]["Infisical-Transfer-Credential"]
            .as_str()
            .unwrap();
        let served = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(route)
                    .header(header::HOST, "localhost")
                    .header("Infisical-Transfer-Credential", credential)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("certificate issuance download");
        assert_eq!(served.status(), StatusCode::OK);
        let envelope = json_body(served).await;
        assert_eq!(envelope["operation"], "certificates.issue");
        assert_eq!(envelope["data"]["privateKey"], private_key);
    }

    #[tokio::test]
    async fn authenticated_certificate_profile_list_preserves_the_streamable_http_contract() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let profile_id = "22222222-2222-4222-8222-222222222222";
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "profile-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/certificate-profiles"))
            .and(query_param("projectId", project_id))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateProfiles": [{
                    "id": profile_id,
                    "projectId": project_id,
                    "caId": "33333333-3333-4333-8333-333333333333",
                    "certificatePolicyId": "44444444-4444-4444-8444-444444444444",
                    "slug": "api-profile",
                    "description": null,
                    "enrollmentType": "api",
                    "estConfigId": null,
                    "apiConfigId": "55555555-5555-4555-8555-555555555555",
                    "acmeConfigId": null,
                    "scepConfigId": null,
                    "createdAt": "2026-07-21T12:00:00.000Z",
                    "updatedAt": "2026-07-21T12:00:01.000Z",
                    "issuerType": "ca",
                    "externalConfigs": null,
                    "defaults": null
                }],
                "totalCount": 1
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let response = call_authenticated_tool(
            router,
            &identity,
            37,
            "certificateProfiles.list",
            json!({ "projectId": project_id }),
        )
        .await;
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["structuredContent"]["items"][0]["id"],
            profile_id
        );
    }

    #[tokio::test]
    async fn authenticated_external_ssh_ca_create_consumes_private_key_without_echoing_it() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let ca_id = "22222222-2222-4222-8222-222222222222";
        let public_key =
            include_str!("../../infisical-api/test-fixtures/ssh-ed25519-public-key.txt").trim();
        let private_key =
            include_str!("../../infisical-api/test-fixtures/ssh-ed25519-private-key.txt").trim();
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "ssh-ca-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ssh/ca"))
            .and(wire_header("authorization", "Bearer ssh-ca-wire-token"))
            .and(body_json(json!({
                "projectId": project_id,
                "friendlyName": "external-ca",
                "publicKey": public_key,
                "privateKey": private_key,
                "keySource": "external"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ca": {
                    "id": ca_id,
                    "projectId": project_id,
                    "friendlyName": "external-ca",
                    "status": "active",
                    "keyAlgorithm": "ED25519",
                    "keySource": "external",
                    "publicKey": public_key
                }
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let response = call_authenticated_tool(
            router,
            &identity,
            40,
            "sshCertificateAuthorities.create",
            json!({
                "projectId": project_id,
                "friendlyName": "external-ca",
                "keyMaterial": {
                    "keySource": "external",
                    "publicKey": public_key,
                    "privateKey": private_key
                },
                "confirm": true
            }),
        )
        .await;

        assert_eq!(response["result"]["isError"], false);
        assert_eq!(response["result"]["structuredContent"]["id"], ca_id);
        assert_eq!(
            response["result"]["structuredContent"]["publicKey"],
            public_key
        );
        let compatibility: Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("JSON text compatibility result"),
        )
        .unwrap();
        assert_eq!(compatibility, response["result"]["structuredContent"]);
        assert!(!response.to_string().contains("b3BlbnNzaC1rZXktdjE"));
        assert!(!response.to_string().contains("privateKey"));
    }

    #[tokio::test]
    async fn authenticated_ssh_issuance_requires_reveal_confirmation_before_upstream_auth() {
        let (router, key, _upstream_server) = test_router().await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let response = call_authenticated_tool(
            router,
            &identity,
            41,
            "sshCertificates.issue",
            json!({
                "target": {
                    "target": {
                        "projectId": "11111111-1111-4111-8111-111111111111",
                        "sshCaId": "22222222-2222-4222-8222-222222222222"
                    },
                    "certificateTemplateId": "33333333-3333-4333-8333-333333333333"
                },
                "keyAlgorithm": "ED25519",
                "certificate": {
                    "certType": "user",
                    "principals": ["deploy"]
                },
                "confirmReveal": false
            }),
        )
        .await;
        assert_eq!(response["result"]["isError"], true);
        assert!(
            response["result"]["content"][0]["text"]
                .as_str()
                .is_some_and(
                    |message| message.contains("private-key reveal require explicit confirmation")
                )
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn authenticated_ssh_host_inventories_preserve_the_streamable_http_contract() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let host_id = "22222222-2222-4222-8222-222222222222";
        let group_id = "33333333-3333-4333-8333-333333333333";
        let user_ca_id = "44444444-4444-4444-8444-444444444444";
        let host_ca_id = "55555555-5555-4555-8555-555555555555";
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "ssh-host-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{project_id}/ssh-hosts")))
            .and(wire_header("authorization", "Bearer ssh-host-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hosts": [{
                    "id": host_id,
                    "projectId": project_id,
                    "hostname": "node.example.com",
                    "alias": null,
                    "userCertTtl": "8h",
                    "hostCertTtl": "1y",
                    "userSshCaId": user_ca_id,
                    "hostSshCaId": host_ca_id,
                    "loginMappings": [{
                        "loginUser": "deploy",
                        "allowedPrincipals": {"usernames": ["user@example.com"]},
                        "source": "host"
                    }]
                }]
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/projects/{project_id}/ssh-host-groups"
            )))
            .and(wire_header("authorization", "Bearer ssh-host-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "groups": [{
                    "id": group_id,
                    "projectId": project_id,
                    "name": "ops-team",
                    "loginMappings": [{
                        "loginUser": "ops",
                        "allowedPrincipals": {"groups": ["ops-team"]}
                    }],
                    "hostCount": 1
                }]
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);

        let hosts = call_authenticated_tool(
            router.clone(),
            &identity,
            42,
            "sshHosts.list",
            json!({ "projectId": project_id }),
        )
        .await;
        assert_eq!(hosts["result"]["isError"], false);
        assert_eq!(
            hosts["result"]["structuredContent"]["hosts"][0]["id"],
            host_id
        );
        assert_eq!(
            hosts["result"]["structuredContent"]["hosts"][0]["loginMappings"][0]["source"],
            "host"
        );
        let hosts_compatibility: Value = serde_json::from_str(
            hosts["result"]["content"][0]["text"]
                .as_str()
                .expect("JSON text compatibility result"),
        )
        .unwrap();
        assert_eq!(hosts_compatibility, hosts["result"]["structuredContent"]);

        let groups = call_authenticated_tool(
            router,
            &identity,
            43,
            "sshHostGroups.list",
            json!({ "projectId": project_id }),
        )
        .await;
        assert_eq!(groups["result"]["isError"], false);
        assert_eq!(
            groups["result"]["structuredContent"]["groups"][0]["id"],
            group_id
        );
        assert_eq!(
            groups["result"]["structuredContent"]["groups"][0]["hostCount"],
            1
        );
        let groups_compatibility: Value = serde_json::from_str(
            groups["result"]["content"][0]["text"]
                .as_str()
                .expect("JSON text compatibility result"),
        )
        .unwrap();
        assert_eq!(groups_compatibility, groups["result"]["structuredContent"]);
    }

    #[tokio::test]
    async fn authenticated_code_signer_sign_preserves_the_streamable_http_contract() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let signer_id = "22222222-2222-4222-8222-222222222222";
        let certificate_id = "33333333-3333-4333-8333-333333333333";
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "signer-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/cert-manager/signers/{signer_id}")))
            .and(wire_header("authorization", "Bearer signer-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": signer_id,
                "projectId": project_id,
                "name": "release-signer",
                "description": null,
                "status": "active",
                "certificateId": certificate_id,
                "approvalPolicyId": "44444444-4444-4444-8444-444444444444",
                "lastSignedAt": null,
                "createdAt": "2026-07-21T12:00:00.000Z",
                "updatedAt": "2026-07-21T12:00:01.000Z",
                "caId": null,
                "commonName": null,
                "certificateTtlDays": null,
                "certificateRenewBeforeDays": null,
                "certificateFailureReason": null,
                "keyAlgorithm": "RSA_2048",
                "certificateCommonName": "release.example.test",
                "certificateSerialNumber": "01ab",
                "certificateNotBefore": "2026-07-21T12:00:00.000Z",
                "certificateNotAfter": "2036-07-21T12:00:00.000Z",
                "certificateKeyAlgorithm": "RSA_2048",
                "certificateStatus": "active",
                "certificateCaId": null,
                "approvalPolicyName": "signer:release"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{signer_id}/sign"
            )))
            .and(wire_header("authorization", "Bearer signer-wire-token"))
            .and(body_json(json!({
                "data": "AQID",
                "signingAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
                "isDigest": false,
                "clientMetadata": { "tool": "signtool" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signature": "BAUG",
                "signingAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
                "signerId": signer_id
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let response = call_authenticated_tool(
            router,
            &identity,
            38,
            "codeSigners.sign",
            json!({
                "target": { "projectId": project_id, "signerId": signer_id },
                "data": "AQID",
                "signingAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
                "clientMetadata": { "tool": "signtool" },
                "confirm": true
            }),
        )
        .await;
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(response["result"]["structuredContent"]["signature"], "BAUG");
        let compatibility: Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("JSON text compatibility result"),
        )
        .unwrap();
        assert_eq!(compatibility, response["result"]["structuredContent"]);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn authenticated_code_signer_governance_mutation_preserves_the_streamable_http_contract()
    {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let signer_id = "22222222-2222-4222-8222-222222222222";
        let certificate_id = "33333333-3333-4333-8333-333333333333";
        let member_id = "44444444-4444-4444-8444-444444444444";
        let membership_id = "55555555-5555-4555-8555-555555555555";
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "governance-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/cert-manager/signers/{signer_id}")))
            .and(wire_header("authorization", "Bearer governance-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": signer_id,
                "projectId": project_id,
                "name": "release-signer",
                "description": null,
                "status": "active",
                "certificateId": certificate_id,
                "approvalPolicyId": "66666666-6666-4666-8666-666666666666",
                "lastSignedAt": null,
                "createdAt": "2026-07-21T12:00:00.000Z",
                "updatedAt": "2026-07-21T12:00:01.000Z",
                "caId": null,
                "commonName": null,
                "certificateTtlDays": null,
                "certificateRenewBeforeDays": null,
                "certificateFailureReason": null,
                "keyAlgorithm": "RSA_2048",
                "certificateCommonName": "release.example.test",
                "certificateSerialNumber": "01ab",
                "certificateNotBefore": "2026-07-21T12:00:00.000Z",
                "certificateNotAfter": "2036-07-21T12:00:00.000Z",
                "certificateKeyAlgorithm": "RSA_2048",
                "certificateStatus": "active",
                "certificateCaId": null,
                "approvalPolicyName": "signer:release"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/cert-manager/signers/{signer_id}/identities"
            )))
            .and(wire_header("authorization", "Bearer governance-wire-token"))
            .and(body_json(json!({
                "identityId": member_id,
                "role": "operator"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "membershipId": membership_id,
                "signerId": signer_id,
                "actorUserId": null,
                "actorIdentityId": member_id,
                "actorGroupId": null,
                "role": "operator",
                "customRoleId": null,
                "createdAt": "2026-07-21T12:00:00.000Z",
                "updatedAt": "2026-07-21T12:00:01.000Z",
                "details": {
                    "name": "release-identity",
                    "email": null,
                    "username": null,
                    "authMethod": "universal-auth",
                    "slug": null
                }
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let response = call_authenticated_tool(
            router,
            &identity,
            39,
            "codeSigners.members.add",
            json!({
                "target": { "projectId": project_id, "signerId": signer_id },
                "memberKind": "identity",
                "memberId": member_id,
                "role": "operator",
                "confirm": true
            }),
        )
        .await;
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["structuredContent"]["membershipId"],
            membership_id
        );
        let compatibility: Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("JSON text compatibility result"),
        )
        .unwrap();
        assert_eq!(compatibility, response["result"]["structuredContent"]);
    }

    #[tokio::test]
    async fn authenticated_kms_decrypt_preserves_the_streamable_http_reveal_contract() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let kms_key_id = "22222222-2222-4222-8222-222222222222";
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "kms-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/kms/keys/{kms_key_id}")))
            .and(wire_header("authorization", "Bearer kms-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "key": {
                    "id": kms_key_id,
                    "name": "application-key",
                    "description": "application key",
                    "isDisabled": false,
                    "orgId": "44444444-4444-4444-8444-444444444444",
                    "projectId": project_id,
                    "keyUsage": "encrypt-decrypt",
                    "encryptionAlgorithm": "aes-256-gcm",
                    "version": 1,
                    "createdAt": "2026-07-20T01:02:03.000Z",
                    "updatedAt": "2026-07-20T01:02:03.000Z"
                }
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/kms/keys/{kms_key_id}/decrypt")))
            .and(wire_header("authorization", "Bearer kms-wire-token"))
            .and(body_json(json!({ "ciphertext": "Y2lwaGVydGV4dA==" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "plaintext": "cGxhaW50ZXh0LWNhbmFyeQ=="
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;

        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let body = call_authenticated_tool(
            router,
            &identity,
            41,
            "kms.decrypt",
            json!({
                "target": { "projectId": project_id, "keyId": kms_key_id },
                "ciphertext": "Y2lwaGVydGV4dA==",
                "confirmReveal": true
            }),
        )
        .await;

        assert_eq!(body["result"]["isError"], false);
        assert_eq!(
            body["result"]["structuredContent"],
            json!({
                "keyId": kms_key_id,
                "plaintext": "cGxhaW50ZXh0LWNhbmFyeQ=="
            })
        );
        assert!(
            body["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("cGxhaW50ZXh0LWNhbmFyeQ==")
        );
        assert!(!body.to_string().contains("Y2lwaGVydGV4dA=="));
    }

    #[tokio::test]
    async fn authenticated_certificate_authority_inventory_drops_provider_configuration() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let ca_id = "22222222-2222-4222-8222-222222222222";
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "ca-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/cert-manager/ca"))
            .and(query_param("projectId", project_id))
            .and(wire_header("authorization", "Bearer ca-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificateAuthorities": [{
                    "id": ca_id,
                    "projectId": project_id,
                    "name": "external-ca",
                    "type": "digicert",
                    "status": "active",
                    "enableDirectIssuance": true,
                    "configuration": { "apiKey": "provider-secret-canary" }
                }]
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;

        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let body = call_authenticated_tool(
            router,
            &identity,
            42,
            "certificateAuthorities.list",
            json!({ "projectId": project_id }),
        )
        .await;

        assert_eq!(body["result"]["isError"], false);
        assert_eq!(
            body["result"]["structuredContent"]["certificateAuthorities"][0],
            json!({
                "id": ca_id,
                "projectId": project_id,
                "name": "external-ca",
                "type": "digicert",
                "status": "active",
                "enableDirectIssuance": true
            })
        );
        assert!(!body.to_string().contains("provider-secret-canary"));
        assert!(!body.to_string().contains("configuration"));
    }

    #[tokio::test]
    async fn authenticated_internal_ca_csr_read_preserves_scope_and_wire_contract() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "11111111-1111-4111-8111-111111111111";
        let ca_id = "22222222-2222-4222-8222-222222222222";
        let csr = include_str!("../../infisical-api/test-fixtures/ca-csr.txt")
            .strip_suffix('\n')
            .expect("CSR fixture must have one final line feed");
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "ca-certificate-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/cert-manager/ca/internal/{ca_id}")))
            .and(wire_header(
                "authorization",
                "Bearer ca-certificate-wire-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": ca_id,
                "projectId": project_id,
                "name": "root-ca",
                "type": "internal",
                "status": "active",
                "enableDirectIssuance": false,
                "configuration": {
                    "type": "root",
                    "commonName": "Root CA",
                    "keyAlgorithm": "RSA_2048",
                    "crlDistributionPointUrls": [],
                    "disableManagedCrlDistributionPointUrl": false,
                    "encryptedPrivateKey": "must-never-cross"
                }
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/cert-manager/ca/internal/{ca_id}/csr"
            )))
            .and(wire_header(
                "authorization",
                "Bearer ca-certificate-wire-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "csr": csr })))
            .expect(1)
            .mount(&upstream_server)
            .await;

        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let body = call_authenticated_tool(
            router,
            &identity,
            43,
            "certificateAuthorities.internal.csr.get",
            json!({ "projectId": project_id, "caId": ca_id }),
        )
        .await;

        assert_eq!(body["result"]["isError"], false);
        assert_eq!(body["result"]["structuredContent"], json!({ "csr": csr }));
        assert!(!body.to_string().contains("must-never-cross"));
    }

    async fn mount_admin_wire_fixtures(upstream_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "admin-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/projects"))
            .and(wire_header("authorization", "Bearer admin-wire-token"))
            .and(body_json(json!({
                "projectName": "Payments",
                "slug": "payments-prod",
                "type": "secret-manager",
                "shouldCreateDefaultEnvs": true,
                "hasDeleteProtection": true
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": {
                    "id": "project-1",
                    "name": "Payments",
                    "slug": "payments-prod",
                    "type": "secret-manager",
                    "orgId": "org-1",
                    "description": null,
                    "environments": []
                }
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/projects/project-1/environments/env-1"))
            .and(wire_header("authorization", "Bearer admin-wire-token"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "environment": {
                    "id": "env-1",
                    "name": "Production",
                    "slug": "prod"
                }
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    #[tokio::test]
    async fn authenticated_admin_tools_preserve_project_defaults_and_soft_environment_delete() {
        let (router, key, upstream_server) = test_router().await;
        mount_admin_wire_fixtures(&upstream_server).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);

        let create = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 30,
                    "method": "tools/call",
                    "params": {
                        "name": "projects.create",
                        "arguments": {
                            "name": "Payments",
                            "slug": "payments-prod"
                        }
                    }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("projects.create response");
        assert_eq!(create.status(), StatusCode::OK);
        let create = json_body(create).await;
        assert_eq!(
            create["result"]["structuredContent"]["slug"],
            "payments-prod"
        );

        let delete = router
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 31,
                    "method": "tools/call",
                    "params": {
                        "name": "environments.delete",
                        "arguments": {
                            "target": {
                                "projectId": "project-1",
                                "environmentId": "env-1"
                            },
                            "confirm": true
                        }
                    }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("environments.delete response");
        assert_eq!(delete.status(), StatusCode::OK);
        let delete = json_body(delete).await;
        assert_eq!(delete["result"]["structuredContent"]["id"], "env-1");

        let requests = upstream_server.received_requests().await.unwrap();
        let environment_delete = requests
            .iter()
            .find(|request| request.url.path() == "/api/v1/projects/project-1/environments/env-1")
            .expect("environment delete reached pinned route");
        assert!(environment_delete.url.query().is_none());
    }

    async fn mount_folder_tag_wire_fixtures(upstream_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "folder-tag-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        for (method_name, route, body, response) in [
            (
                "POST",
                "/api/v2/folders",
                json!({
                    "projectId": "project-1",
                    "environment": "prod",
                    "name": "api",
                    "path": "/payments",
                    "description": "API credentials"
                }),
                json!({
                    "folder": {
                        "id": "folder-1",
                        "name": "api",
                        "envId": "env-1",
                        "parentId": null,
                        "description": "API credentials",
                        "isReserved": false,
                        "relativePath": "/payments/api"
                    }
                }),
            ),
            (
                "DELETE",
                "/api/v2/folders/folder-1",
                json!({
                    "projectId": "project-1",
                    "environment": "prod",
                    "path": "/payments",
                    "forceDelete": false
                }),
                json!({
                    "folder": {
                        "id": "folder-1",
                        "name": "api",
                        "envId": "env-1",
                        "parentId": null,
                        "description": "API credentials",
                        "isReserved": false,
                        "relativePath": "/payments/api"
                    }
                }),
            ),
            (
                "POST",
                "/api/v1/projects/project-1/tags",
                json!({ "slug": "critical", "color": "" }),
                json!({
                    "tag": {
                        "id": "tag-1",
                        "slug": "critical",
                        "projectId": "project-1",
                        "color": ""
                    }
                }),
            ),
            (
                "DELETE",
                "/api/v1/projects/project-1/tags/tag-1",
                json!({}),
                json!({
                    "tag": {
                        "id": "tag-1",
                        "slug": "critical",
                        "projectId": "project-1",
                        "color": ""
                    }
                }),
            ),
        ] {
            Mock::given(method(method_name))
                .and(path(route))
                .and(wire_header("authorization", "Bearer folder-tag-wire-token"))
                .and(body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(upstream_server)
                .await;
        }
    }

    #[tokio::test]
    async fn authenticated_folder_and_tag_mutations_preserve_pinned_wire_contracts() {
        let (router, key, upstream_server) = test_router().await;
        mount_folder_tag_wire_fixtures(&upstream_server).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for (id, name, arguments, expected_id) in [
            (
                32,
                "folders.create",
                json!({
                    "parent": {
                        "projectId": "project-1",
                        "environment": "prod",
                        "path": "/payments"
                    },
                    "name": "api",
                    "description": "API credentials"
                }),
                "folder-1",
            ),
            (
                33,
                "folders.delete",
                json!({
                    "target": {
                        "parent": {
                            "projectId": "project-1",
                            "environment": "prod",
                            "path": "/payments"
                        },
                        "folderId": "folder-1"
                    },
                    "confirm": true
                }),
                "folder-1",
            ),
            (
                34,
                "tags.create",
                json!({ "projectId": "project-1", "slug": "critical" }),
                "tag-1",
            ),
            (
                35,
                "tags.delete",
                json!({
                    "target": { "projectId": "project-1", "tagId": "tag-1" },
                    "confirm": true
                }),
                "tag-1",
            ),
        ] {
            let response = router
                .clone()
                .oneshot(mcp_request(
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/call",
                        "params": { "name": name, "arguments": arguments }
                    }),
                    Some(CURRENT),
                    Some(&identity),
                ))
                .await
                .expect("folder/tag tool response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            assert_eq!(body["result"]["structuredContent"]["id"], expected_id);
            assert_eq!(body["result"]["isError"], false);
        }
    }

    fn identity_membership_wire_fixture() -> Value {
        json!({
            "id": "membership-1",
            "role": "no-access",
            "roleId": null,
            "orgId": "org-1",
            "identityId": "identity-1",
            "identity": {
                "id": "identity-1",
                "name": "agent-one",
                "hasDeleteProtection": true,
                "authMethods": ["universal-auth"]
            }
        })
    }

    fn direct_identity_wire_fixture(name: &str) -> Value {
        json!({
            "id": "identity-1",
            "name": name,
            "orgId": "org-1",
            "projectId": null,
            "hasDeleteProtection": true,
            "authMethods": ["universal-auth"]
        })
    }

    async fn mount_identity_wire_fixtures(upstream_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "identity-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/identities"))
            .and(query_param("orgId", "org-1"))
            .and(wire_header("authorization", "Bearer identity-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identities": [identity_membership_wire_fixture()],
                "totalCount": 1
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/identities/identity-1"))
            .and(wire_header("authorization", "Bearer identity-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identity": identity_membership_wire_fixture()
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        for (method_name, body, name) in [
            (
                "POST",
                json!({
                    "name": "agent-one",
                    "organizationId": "org-1",
                    "role": "no-access",
                    "hasDeleteProtection": true
                }),
                "agent-one",
            ),
            ("PATCH", json!({ "role": "member" }), "agent-one"),
            ("DELETE", json!({}), "agent-one"),
        ] {
            let route = if method_name == "POST" {
                "/api/v1/identities"
            } else {
                "/api/v1/identities/identity-1"
            };
            Mock::given(method(method_name))
                .and(path(route))
                .and(wire_header("authorization", "Bearer identity-wire-token"))
                .and(body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "identity": direct_identity_wire_fixture(name)
                })))
                .expect(1)
                .mount(upstream_server)
                .await;
        }
    }

    #[tokio::test]
    async fn authenticated_identity_tools_preserve_pinned_wire_contracts() {
        let (router, key, upstream_server) = test_router().await;
        mount_identity_wire_fixtures(&upstream_server).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for (id, name, arguments) in [
            (
                36,
                "identities.list",
                json!({ "organizationId": "org-1", "limit": 1 }),
            ),
            (37, "identities.get", json!({ "identityId": "identity-1" })),
            (
                38,
                "identities.create",
                json!({ "name": "agent-one", "organizationId": "org-1" }),
            ),
            (
                39,
                "identities.update",
                json!({
                    "identityId": "identity-1",
                    "change": { "kind": "role", "role": "member" }
                }),
            ),
            (
                40,
                "identities.delete",
                json!({ "identityId": "identity-1", "confirm": true }),
            ),
        ] {
            let response = router
                .clone()
                .oneshot(mcp_request(
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/call",
                        "params": { "name": name, "arguments": arguments }
                    }),
                    Some(CURRENT),
                    Some(&identity),
                ))
                .await
                .expect("identity tool response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            assert_eq!(body["result"]["isError"], false, "{name}");
            assert!(
                !body["result"]["structuredContent"]
                    .to_string()
                    .contains("clientSecret"),
                "{name} output must not contain credentials"
            );
        }
    }

    async fn mount_project_membership_wire_fixtures(upstream_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "membership-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1/memberships"))
            .and(wire_header("authorization", "Bearer membership-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "memberships": [{
                    "id": "membership-1",
                    "projectId": "project-1",
                    "userId": "user-1",
                    "createdAt": "2026-07-19T20:00:00.000Z",
                    "user": {
                        "id": "user-1",
                        "username": "operator",
                        "email": "operator@example.com"
                    },
                    "roles": [{
                        "id": "role-1",
                        "role": "member",
                        "isTemporary": false
                    }]
                }]
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/api/v1/projects/project-1/memberships/identities/identity-1",
            ))
            .and(wire_header("authorization", "Bearer membership-wire-token"))
            .and(body_json(json!({
                "roles": [{"role": "viewer", "isTemporary": false}]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityMembership": {
                    "id": "identity-membership-1",
                    "projectId": "project-1",
                    "identityId": "identity-1"
                }
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    #[tokio::test]
    async fn authenticated_project_membership_tools_preserve_pinned_wire_contracts() {
        let (router, key, upstream_server) = test_router().await;
        mount_project_membership_wire_fixtures(&upstream_server).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for (id, name, arguments) in [
            (
                41,
                "projectUserMemberships.list",
                json!({"projectId": "project-1", "limit": 1}),
            ),
            (
                42,
                "projectIdentityMemberships.create",
                json!({
                    "projectId": "project-1",
                    "identityId": "identity-1",
                    "roles": ["viewer"]
                }),
            ),
        ] {
            let response = router
                .clone()
                .oneshot(mcp_request(
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/call",
                        "params": {"name": name, "arguments": arguments}
                    }),
                    Some(CURRENT),
                    Some(&identity),
                ))
                .await
                .expect("project membership tool response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            assert_eq!(body["result"]["isError"], false, "{name}");
            assert!(body["result"]["structuredContent"].is_object());
        }
    }

    fn role_wire_fixture(
        id: &str,
        name: &str,
        slug: &str,
        scope_key: &str,
        scope_id: &str,
        include_permissions: bool,
    ) -> Value {
        let mut role = json!({
            "id": id,
            "name": name,
            "slug": slug,
            "description": null,
            "createdAt": "2026-07-19T20:00:00.000Z",
            "updatedAt": "2026-07-19T20:00:00.000Z"
        });
        role[scope_key] = json!(scope_id);
        if include_permissions {
            role["permissions"] = json!([{
                "subject": "secrets",
                "action": ["read"],
                "conditions": { "environment": "prod" }
            }]);
        }
        role
    }

    async fn mount_role_wire_fixtures(upstream_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "role-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1/roles"))
            .and(wire_header("authorization", "Bearer role-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "roles": [role_wire_fixture(
                    "synthetic-id",
                    "Admin",
                    "admin",
                    "projectId",
                    "project-1",
                    false
                )]
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1/roles/slug/deployer"))
            .and(wire_header("authorization", "Bearer role-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "role": role_wire_fixture(
                    "custom-id",
                    "Deployer",
                    "deployer",
                    "projectId",
                    "project-1",
                    true
                )
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organization/roles"))
            .and(wire_header("authorization", "Bearer role-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "roles": [role_wire_fixture(
                    "dummy-id",
                    "No Access",
                    "no-access",
                    "orgId",
                    "org-1",
                    false
                )]
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organization/roles/slug/auditor"))
            .and(wire_header("authorization", "Bearer role-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "role": role_wire_fixture(
                    "custom-org-id",
                    "Auditor",
                    "auditor",
                    "orgId",
                    "org-1",
                    true
                )
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    #[tokio::test]
    async fn authenticated_role_reads_preserve_pinned_streamable_http_contracts() {
        let (router, key, upstream_server) = test_router().await;
        mount_role_wire_fixtures(&upstream_server).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for (id, name, arguments) in [
            (
                43,
                "projectRoles.list",
                json!({"projectId": "project-1", "limit": 1}),
            ),
            (
                44,
                "projectRoles.get",
                json!({"projectId": "project-1", "roleSlug": "deployer"}),
            ),
            (45, "organizationRoles.list", json!({"limit": 1})),
            (46, "organizationRoles.get", json!({"roleSlug": "auditor"})),
        ] {
            let response = router
                .clone()
                .oneshot(mcp_request(
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/call",
                        "params": {"name": name, "arguments": arguments}
                    }),
                    Some(CURRENT),
                    Some(&identity),
                ))
                .await
                .expect("role tool response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            assert_eq!(body["result"]["isError"], false, "{name}");
            let output = body["result"]["structuredContent"].to_string();
            assert!(!output.contains("synthetic-id"), "{name}");
            assert!(!output.contains("dummy-id"), "{name}");
            assert!(!output.contains("createdAt"), "{name}");
        }
    }

    fn group_wire_fixture() -> Value {
        json!({
            "id": "group-1",
            "orgId": "org-1",
            "name": "Operators",
            "slug": "operators",
            "role": "custom",
            "roleId": "role-1",
            "customRoleSlug": "auditor",
            "createdAt": "2026-07-19T20:00:00.000Z",
            "updatedAt": "2026-07-19T20:01:00.000Z"
        })
    }

    fn project_group_membership_wire_fixture() -> Value {
        json!({
            "id": "membership-1",
            "groupId": "group-1",
            "projectId": "project-1",
            "group": {
                "id": "group-1",
                "name": "Operators",
                "slug": "operators",
                "orgId": "org-1"
            },
            "roles": [{
                "id": "assignment-1",
                "role": "viewer",
                "isTemporary": false
            }],
            "createdAt": "2026-07-19T20:00:00.000Z",
            "updatedAt": "2026-07-19T20:01:00.000Z"
        })
    }

    async fn mount_group_wire_fixtures(upstream_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "group-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/groups"))
            .and(wire_header("authorization", "Bearer group-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([group_wire_fixture()])))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/groups/group-1"))
            .and(wire_header("authorization", "Bearer group-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(group_wire_fixture()))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/groups/group-1/members"))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"))
            .and(query_param("memberTypeFilter", "users"))
            .and(wire_header("authorization", "Bearer group-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "members": [{
                    "id": "user-1",
                    "joinedGroupAt": "2026-07-19T20:00:00.000Z",
                    "type": "user",
                    "user": {
                        "id": "user-1",
                        "firstName": "Ada",
                        "lastName": "Lovelace",
                        "email": "ada@example.test",
                        "username": "ada@example.test"
                    }
                }],
                "totalCount": 1
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/groups/group-1/projects"))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"))
            .and(query_param("filter", "assignedProjects"))
            .and(query_param("orderBy", "name"))
            .and(query_param("orderDirection", "asc"))
            .and(wire_header("authorization", "Bearer group-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "projects": [{
                    "id": "project-1",
                    "name": "Payments",
                    "slug": "payments",
                    "description": null,
                    "type": "secret-manager",
                    "joinedGroupAt": "2026-07-19T20:00:00.000Z"
                }],
                "totalCount": 1
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1/memberships/groups"))
            .and(wire_header("authorization", "Bearer group-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "groupMemberships": [project_group_membership_wire_fixture()]
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/projects/project-1/memberships/groups/group-1",
            ))
            .and(wire_header("authorization", "Bearer group-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "groupMembership": project_group_membership_wire_fixture()
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    #[tokio::test]
    async fn authenticated_group_reads_preserve_pinned_streamable_http_contracts() {
        let (router, key, upstream_server) = test_router().await;
        mount_group_wire_fixtures(&upstream_server).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for (id, name, arguments) in [
            (47, "groups.list", json!({"limit": 1})),
            (48, "groups.get", json!({"groupId": "group-1"})),
            (
                49,
                "groups.members.list",
                json!({"groupId": "group-1", "memberType": "users", "limit": 1}),
            ),
            (
                50,
                "groups.projects.list",
                json!({"groupId": "group-1", "assignment": "assigned", "limit": 1}),
            ),
            (
                51,
                "projectGroupMemberships.list",
                json!({"projectId": "project-1", "limit": 1}),
            ),
            (
                52,
                "projectGroupMemberships.get",
                json!({"projectId": "project-1", "groupId": "group-1"}),
            ),
        ] {
            let response = router
                .clone()
                .oneshot(mcp_request(
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/call",
                        "params": {"name": name, "arguments": arguments}
                    }),
                    Some(CURRENT),
                    Some(&identity),
                ))
                .await
                .expect("group tool response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            assert_eq!(body["result"]["isError"], false, "{name}");
            let output = &body["result"]["structuredContent"];
            assert!(!output.to_string().contains("secretValue"), "{name}");
            match name {
                "groups.members.list" => assert_eq!(output["items"][0]["type"], "user"),
                "groups.projects.list" => {
                    assert_eq!(output["items"][0]["type"], "secret-manager");
                    assert!(output["items"][0]["joinedGroupAt"].is_string());
                }
                "projectGroupMemberships.get" => {
                    assert_eq!(output["projectId"], "project-1");
                    assert_eq!(output["groupId"], "group-1");
                }
                _ => {}
            }
        }
    }

    fn serialized_additional_privilege_wire_fixture() -> Value {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/infisical-v0.160.12/identity-project-additional-privilege.json"
        )))
        .unwrap()
    }

    fn additional_privilege_wire_summary(id: &str, slug: &str) -> Value {
        let mut privilege = serialized_additional_privilege_wire_fixture();
        privilege["id"] = json!(id);
        privilege["slug"] = json!(slug);
        privilege.as_object_mut().unwrap().remove("permissions");
        privilege
    }

    fn additional_privilege_wire_fixture(id: &str, slug: &str) -> Value {
        let mut privilege = serialized_additional_privilege_wire_fixture();
        privilege["id"] = json!(id);
        privilege["slug"] = json!(slug);
        privilege["permissions"] = json!([{
            "subject": "secrets",
            "action": ["read"],
            "inverted": false
        }]);
        privilege
    }

    fn additional_privilege_without_permissions_wire_fixture(id: &str, slug: &str) -> Value {
        let mut privilege = additional_privilege_wire_fixture(id, slug);
        privilege["permissions"] = json!([]);
        privilege
    }

    fn temporary_additional_privilege_wire_fixture(id: &str, slug: &str) -> Value {
        let mut privilege = additional_privilege_wire_fixture(id, slug);
        privilege["permissions"][0]["inverted"] = json!(true);
        privilege["isTemporary"] = json!(true);
        privilege["temporaryMode"] = json!("relative");
        privilege["temporaryRange"] = json!("3600s");
        privilege["temporaryAccessStartTime"] = json!("2026-07-20T12:00:00.000Z");
        privilege["temporaryAccessEndTime"] = json!("2026-07-20T13:00:00.000Z");
        privilege
    }

    async fn mount_additional_privilege_wire_fixtures(upstream_server: &MockServer) {
        mount_additional_privilege_wire_read_fixtures(upstream_server).await;
        mount_additional_privilege_wire_mutation_fixtures(upstream_server).await;
    }

    async fn mount_additional_privilege_wire_read_fixtures(upstream_server: &MockServer) {
        let collection = "/api/v2/identity-project-additional-privilege";
        let exact_route = "/api/v2/identity-project-additional-privilege/privilege-1";
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "additional-privilege-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(collection))
            .and(query_param("projectId", "project-1"))
            .and(query_param("identityId", "identity-1"))
            .and(wire_header(
                "authorization",
                "Bearer additional-privilege-wire-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privileges": [additional_privilege_wire_summary("privilege-1", "auditor")]
            })))
            .expect(5)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(exact_route))
            .and(wire_header(
                "authorization",
                "Bearer additional-privilege-wire-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privilege": additional_privilege_wire_fixture("privilege-1", "auditor")
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v2/identity-project-additional-privilege/slug/auditor",
            ))
            .and(query_param("projectSlug", "payments"))
            .and(query_param("identityId", "identity-1"))
            .and(wire_header(
                "authorization",
                "Bearer additional-privilege-wire-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privilege": additional_privilege_wire_fixture("privilege-1", "auditor")
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    async fn mount_additional_privilege_wire_mutation_fixtures(upstream_server: &MockServer) {
        let collection = "/api/v2/identity-project-additional-privilege";
        let exact_route = "/api/v2/identity-project-additional-privilege/privilege-1";
        Mock::given(method("POST"))
            .and(path(collection))
            .and(wire_header(
                "authorization",
                "Bearer additional-privilege-wire-token",
            ))
            .and(body_json(json!({
                "projectId": "project-1",
                "identityId": "identity-1",
                "slug": "temporary-auditor",
                "permissions": [{
                    "subject": "secrets",
                    "action": ["read"],
                    "inverted": true
                }],
                "type": {
                    "isTemporary": true,
                    "temporaryMode": "relative",
                    "temporaryRange": "3600s",
                    "temporaryAccessStartTime": "2026-07-20T12:00:00Z"
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privilege": temporary_additional_privilege_wire_fixture(
                    "privilege-2",
                    "temporary-auditor"
                )
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(exact_route))
            .and(wire_header(
                "authorization",
                "Bearer additional-privilege-wire-token",
            ))
            .and(body_json(json!({
                "slug": "operator",
                "permissions": [],
                "type": { "isTemporary": false }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privilege": additional_privilege_without_permissions_wire_fixture(
                    "privilege-1",
                    "operator"
                )
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(exact_route))
            .and(wire_header(
                "authorization",
                "Bearer additional-privilege-wire-token",
            ))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "privilege": additional_privilege_wire_fixture("privilege-1", "operator")
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    #[tokio::test]
    async fn authenticated_additional_privileges_preserve_the_complete_v2_lifecycle() {
        let (router, key, upstream_server) = test_router().await;
        mount_additional_privilege_wire_fixtures(&upstream_server).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for (id, name, arguments) in [
            (
                53,
                "identityProjectAdditionalPrivileges.list",
                json!({"projectId": "project-1", "identityId": "identity-1", "limit": 1}),
            ),
            (
                54,
                "identityProjectAdditionalPrivileges.get",
                json!({
                    "projectId": "project-1",
                    "identityId": "identity-1",
                    "privilegeId": "privilege-1"
                }),
            ),
            (
                55,
                "identityProjectAdditionalPrivileges.getBySlug",
                json!({
                    "projectId": "project-1",
                    "projectSlug": "payments",
                    "identityId": "identity-1",
                    "privilegeSlug": "auditor"
                }),
            ),
            (
                56,
                "identityProjectAdditionalPrivileges.create",
                json!({
                    "projectId": "project-1",
                    "identityId": "identity-1",
                    "slug": "temporary-auditor",
                    "permissions": [{"subject": "secrets", "action": ["read"], "inverted": true}],
                    "confirmDenyPermissions": true,
                    "lifetime": {
                        "kind": "temporary",
                        "durationSeconds": 3600,
                        "startTime": "2026-07-20T12:00:00Z"
                    }
                }),
            ),
            (
                57,
                "identityProjectAdditionalPrivileges.update",
                json!({
                    "projectId": "project-1",
                    "identityId": "identity-1",
                    "privilegeId": "privilege-1",
                    "slug": "operator",
                    "permissions": [],
                    "confirmReplacePermissions": true,
                    "lifetime": {"kind": "permanent"}
                }),
            ),
            (
                58,
                "identityProjectAdditionalPrivileges.delete",
                json!({
                    "projectId": "project-1",
                    "identityId": "identity-1",
                    "privilegeId": "privilege-1",
                    "confirmDelete": true
                }),
            ),
        ] {
            let response = router
                .clone()
                .oneshot(mcp_request(
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/call",
                        "params": {"name": name, "arguments": arguments}
                    }),
                    Some(CURRENT),
                    Some(&identity),
                ))
                .await
                .expect("additional privilege tool response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            assert_eq!(body["result"]["isError"], false, "{name}");
            let output = &body["result"]["structuredContent"];
            assert!(!output.to_string().contains("secretValue"), "{name}");
            if name == "identityProjectAdditionalPrivileges.update" {
                assert_eq!(output["permissions"], json!([]));
            }
            assert_eq!(
                if name == "identityProjectAdditionalPrivileges.list" {
                    &output["items"][0]["projectId"]
                } else {
                    &output["projectId"]
                },
                "project-1"
            );
        }
    }

    #[tokio::test]
    async fn authenticated_audit_log_listing_preserves_the_bounded_observable_wire_contract() {
        let (router, key, upstream_server) = test_router().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "audit-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organization/audit-logs"))
            .and(query_param("projectId", "project-1"))
            .and(query_param("actorType", "identity"))
            .and(query_param("eventType", "create-secret"))
            .and(query_param("startDate", "2026-07-01T00:00:00.000Z"))
            .and(query_param("endDate", "2026-07-20T00:00:00.000Z"))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"))
            .and(wire_header("authorization", "Bearer audit-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auditLogs": [{
                    "id": "e94e92dc-494f-4c06-bbd3-bf75c5011d62",
                    "actor": {
                        "type": "identity",
                        "metadata": {"identityId": "identity-1", "name": "automation"}
                    },
                    "event": {
                        "type": "create-secret",
                        "metadata": {"secretKey": "DATABASE_URL", "secretValue": "must-not-escape"}
                    },
                    "ipAddress": "192.0.2.10",
                    "userAgent": "Infisical CLI",
                    "userAgentType": "cli",
                    "expiresAt": null,
                    "createdAt": "2026-07-10T12:30:00.000Z",
                    "updatedAt": "2026-07-10T12:30:00.000Z",
                    "orgId": "d5d7469f-91c4-4da9-8587-b59325fd89f7",
                    "projectId": "project-1",
                    "projectName": "Payments"
                }]
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;

        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let response = router
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 59,
                    "method": "tools/call",
                    "params": {
                        "name": "auditLogs.list",
                        "arguments": {
                            "projectId": "project-1",
                            "actorType": "identity",
                            "eventTypes": ["create-secret"],
                            "timeRange": {
                                "start": "2026-07-01T00:00:00.000Z",
                                "end": "2026-07-20T00:00:00.000Z"
                            },
                            "limit": 1
                        }
                    }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("audit log tool response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["result"]["isError"], false);
        let output = &body["result"]["structuredContent"];
        let compatibility = &body["result"]["content"];
        assert_eq!(output["items"][0]["eventType"], "create-secret");
        assert_eq!(output["items"][0]["actorType"], "identity");
        assert!(!output.to_string().contains("metadata"));
        assert!(!output.to_string().contains("must-not-escape"));
        assert!(compatibility.is_array());
        assert!(!compatibility.to_string().contains("metadata"));
        assert!(!compatibility.to_string().contains("must-not-escape"));
    }

    async fn mount_app_automation_wire_login(upstream_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "automation-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    async fn mount_app_connection_wire_fixture(
        upstream_server: &MockServer,
        project_id: &str,
        connection_id: &str,
    ) {
        Mock::given(method("GET"))
            .and(path("/api/v1/app-connections"))
            .and(query_param("projectId", project_id))
            .and(wire_header("authorization", "Bearer automation-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnections": [{
                    "id": connection_id,
                    "name": "github-primary",
                    "description": null,
                    "app": "github",
                    "version": 1,
                    "orgId": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    "projectId": project_id,
                    "createdAt": "2026-07-20T12:00:00.000Z",
                    "updatedAt": "2026-07-20T12:00:00.000Z",
                    "isPlatformManagedCredentials": false,
                    "isAutoRotationEnabled": false,
                    "credentialsHash": "automation-wire-canary"
                }]
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    async fn mount_app_automation_project_wire_fixture(
        upstream_server: &MockServer,
        project_id: &str,
        environment_id: &str,
    ) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{project_id}")))
            .and(wire_header("authorization", "Bearer automation-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": {
                    "id": project_id,
                    "name": "Platform",
                    "slug": "platform",
                    "type": "secret-manager",
                    "orgId": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    "environments": [{
                        "id": environment_id,
                        "name": "Production",
                        "slug": "prod"
                    }]
                }
            })))
            .expect(2)
            .mount(upstream_server)
            .await;
    }

    async fn mount_secret_sync_wire_fixture(
        upstream_server: &MockServer,
        project_id: &str,
        connection_id: &str,
        folder_id: &str,
        environment_id: &str,
    ) {
        Mock::given(method("GET"))
            .and(path("/api/v1/secret-syncs"))
            .and(query_param("projectId", project_id))
            .and(wire_header("authorization", "Bearer automation-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretSyncs": [{
                    "id": "11111111-1111-4111-8111-111111111111",
                    "name": "github-actions",
                    "description": null,
                    "destination": "github",
                    "version": 1,
                    "projectId": project_id,
                    "folderId": folder_id,
                    "connectionId": connection_id,
                    "connection": { "id": connection_id, "name": "github-primary", "app": "github" },
                    "environment": { "id": environment_id, "name": "Production", "slug": "prod" },
                    "folder": { "id": folder_id, "path": "/apps" },
                    "isAutoSyncEnabled": true,
                    "syncStatus": "succeeded",
                    "lastSyncedAt": "2026-07-20T12:01:00.000Z",
                    "importStatus": null,
                    "lastImportedAt": null,
                    "removeStatus": null,
                    "lastRemovedAt": null,
                    "createdAt": "2026-07-20T12:00:00.000Z",
                    "updatedAt": "2026-07-20T12:01:00.000Z",
                    "destinationConfig": { "secret": "automation-wire-canary" },
                    "lastSyncMessage": "automation-wire-canary"
                }]
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    async fn mount_secret_rotation_wire_fixture(
        upstream_server: &MockServer,
        project_id: &str,
        connection_id: &str,
        folder_id: &str,
        environment_id: &str,
    ) {
        Mock::given(method("GET"))
            .and(path("/api/v2/secret-rotations"))
            .and(query_param("projectId", project_id))
            .and(wire_header("authorization", "Bearer automation-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretRotations": [{
                    "id": "22222222-2222-4222-8222-222222222222",
                    "name": "database-password",
                    "description": null,
                    "type": "postgres-credentials",
                    "projectId": project_id,
                    "folderId": folder_id,
                    "connectionId": connection_id,
                    "connection": { "id": connection_id, "name": "postgres-primary", "app": "postgres" },
                    "environment": { "id": environment_id, "name": "Production", "slug": "prod" },
                    "folder": { "id": folder_id, "path": "/apps" },
                    "isAutoRotationEnabled": true,
                    "activeIndex": 1,
                    "rotationInterval": 30,
                    "rotateAtUtc": { "hours": 3, "minutes": 15 },
                    "rotationStatus": "success",
                    "lastRotationAttemptedAt": "2026-07-20T12:01:00.000Z",
                    "lastRotatedAt": "2026-07-20T12:01:00.000Z",
                    "nextRotationAt": null,
                    "isLastRotationManual": true,
                    "createdAt": "2026-07-20T12:00:00.000Z",
                    "updatedAt": "2026-07-20T12:01:00.000Z",
                    "parameters": { "password": "automation-wire-canary" },
                    "lastRotationMessage": "automation-wire-canary"
                }]
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    #[tokio::test]
    async fn authenticated_app_automation_inventory_preserves_value_free_wire_contracts() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let connection_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let folder_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let environment_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        mount_app_automation_wire_login(&upstream_server).await;
        mount_app_automation_project_wire_fixture(&upstream_server, project_id, environment_id)
            .await;
        mount_app_connection_wire_fixture(&upstream_server, project_id, connection_id).await;
        mount_secret_sync_wire_fixture(
            &upstream_server,
            project_id,
            connection_id,
            folder_id,
            environment_id,
        )
        .await;
        mount_secret_rotation_wire_fixture(
            &upstream_server,
            project_id,
            connection_id,
            folder_id,
            environment_id,
        )
        .await;

        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for (id, name) in [
            (60, "appConnections.list"),
            (61, "secretSyncs.list"),
            (62, "secretRotations.list"),
        ] {
            let body = call_authenticated_tool(
                router.clone(),
                &identity,
                id,
                name,
                json!({ "projectId": project_id, "limit": 10 }),
            )
            .await;
            assert_eq!(body["result"]["isError"], false, "{name}");
            for representation in [
                &body["result"]["structuredContent"],
                &body["result"]["content"],
            ] {
                let wire = representation.to_string();
                assert!(!wire.contains("automation-wire-canary"), "{name}");
                for forbidden in [
                    "credentialsHash",
                    "destinationConfig",
                    "syncOptions",
                    "parameters",
                    "secretsMapping",
                    "lastSyncMessage",
                    "lastRotationMessage",
                ] {
                    assert!(!wire.contains(forbidden), "{name} exposed {forbidden}");
                }
            }
        }
    }

    #[tokio::test]
    // One authenticated wire fixture proves both provider creations preserve the same secret boundary.
    #[allow(clippy::too_many_lines)]
    async fn authenticated_typed_github_creations_preserve_secret_and_confirmation_boundaries() {
        let (router, key, upstream_server) = test_router().await;
        let project_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let connection_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let folder_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let environment_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        let sync_id = "11111111-1111-4111-8111-111111111111";
        let rotation_path =
            format!("/api/v1/app-connections/github/{connection_id}/rotate-credentials");
        mount_app_automation_wire_login(&upstream_server).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/app-connections/github"))
            .and(wire_header("authorization", "Bearer automation-wire-token"))
            .and(body_json(json!({
                "name": "github-primary",
                "description": null,
                "projectId": project_id,
                "method": "pat",
                "credentials": {
                    "personalAccessToken": "github-wire-input-canary",
                    "instanceType": "cloud"
                },
                "isPlatformManagedCredentials": false,
                "isAutoRotationEnabled": false,
                "gatewayId": null,
                "gatewayPoolId": null
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnection": {
                    "id": connection_id,
                    "name": "github-primary",
                    "description": null,
                    "app": "github",
                    "method": "pat",
                    "credentials": { "instanceType": "cloud" },
                    "version": 1,
                    "orgId": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    "projectId": project_id,
                    "createdAt": "2026-07-20T12:00:00.000Z",
                    "updatedAt": "2026-07-20T12:00:00.000Z",
                    "isPlatformManagedCredentials": false,
                    "isAutoRotationEnabled": false,
                    "gatewayId": null,
                    "gatewayPoolId": null,
                    "credentialsHash": "github-wire-response-canary"
                }
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(rotation_path.clone()))
            .and(wire_header("authorization", "Bearer automation-wire-token"))
            .and(body_bytes(Vec::<u8>::new()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "appConnection": {
                    "id": connection_id,
                    "name": "github-primary",
                    "description": null,
                    "app": "github",
                    "method": "pat",
                    "credentials": { "instanceType": "cloud" },
                    "version": 2,
                    "orgId": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    "projectId": project_id,
                    "createdAt": "2026-07-20T12:00:00.000Z",
                    "updatedAt": "2026-07-20T12:01:00.000Z",
                    "isPlatformManagedCredentials": false,
                    "isAutoRotationEnabled": false,
                    "gatewayId": null,
                    "gatewayPoolId": null,
                    "credentialsHash": "github-wire-response-canary"
                }
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/projects/{project_id}")))
            .and(wire_header("authorization", "Bearer automation-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": {
                    "id": project_id,
                    "name": "Platform",
                    "slug": "platform",
                    "type": "secret-manager",
                    "orgId": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    "environments": [{
                        "id": environment_id,
                        "name": "Production",
                        "slug": "prod"
                    }]
                }
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/secret-syncs/github"))
            .and(wire_header(
                "authorization",
                "Bearer automation-wire-token",
            ))
            .and(body_json(json!({
                "name": "github-actions",
                "description": null,
                "projectId": project_id,
                "connectionId": connection_id,
                "environment": "prod",
                "secretPath": "/apps",
                "isAutoSyncEnabled": true,
                "destinationConfig": {
                    "scope": "repository",
                    "owner": "platform",
                    "repo": "api"
                },
                "syncOptions": {
                    "initialSyncBehavior": "overwrite-destination",
                    "keySchema": "{{environment}}/{{secretKey}}",
                    "disableSecretDeletion": false
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretSync": {
                    "id": sync_id,
                    "name": "github-actions",
                    "description": null,
                    "destination": "github",
                    "version": 1,
                    "projectId": project_id,
                    "folderId": folder_id,
                    "connectionId": connection_id,
                    "connection": { "id": connection_id, "name": "github-primary", "app": "github" },
                    "environment": { "id": environment_id, "name": "Production", "slug": "prod" },
                    "folder": { "id": folder_id, "path": "/apps" },
                    "isAutoSyncEnabled": true,
                    "syncStatus": "succeeded",
                    "lastSyncedAt": "2026-07-20T12:01:00.000Z",
                    "importStatus": null,
                    "lastImportedAt": null,
                    "removeStatus": null,
                    "lastRemovedAt": null,
                    "createdAt": "2026-07-20T12:00:00.000Z",
                    "updatedAt": "2026-07-20T12:01:00.000Z",
                    "destinationConfig": {
                        "scope": "repository",
                        "owner": "platform",
                        "repo": "api"
                    },
                    "syncOptions": {
                        "initialSyncBehavior": "overwrite-destination",
                        "keySchema": "{{environment}}/{{secretKey}}",
                        "disableSecretDeletion": false
                    },
                    "lastSyncMessage": "github-wire-response-canary"
                }
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;

        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let connection = call_authenticated_tool(
            router.clone(),
            &identity,
            63,
            "appConnections.github.create",
            json!({
                "name": "github-primary",
                "description": null,
                "projectId": project_id,
                "provider": {
                    "credentials": {
                        "method": "personalAccessToken",
                        "personalAccessToken": "github-wire-input-canary",
                        "instance": { "kind": "cloud" }
                    },
                    "route": { "kind": "direct" }
                }
            }),
        )
        .await;
        let unconfirmed_rotation = call_authenticated_tool(
            router.clone(),
            &identity,
            64,
            "appConnections.github.rotateCredentials",
            json!({
                "connectionId": connection_id,
                "confirm": false
            }),
        )
        .await;
        assert_eq!(unconfirmed_rotation["error"]["code"], -32602);
        assert!(
            upstream_server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.url.path() != rotation_path)
        );
        let rotation = call_authenticated_tool(
            router.clone(),
            &identity,
            65,
            "appConnections.github.rotateCredentials",
            json!({
                "connectionId": connection_id,
                "confirm": true
            }),
        )
        .await;
        let unconfirmed_sync = call_authenticated_tool(
            router.clone(),
            &identity,
            66,
            "secretSyncs.github.create",
            json!({
                "projectId": project_id,
                "name": "github-actions",
                "connectionId": connection_id,
                "environment": "prod",
                "secretPath": "/apps",
                "config": {
                    "destination": { "scope": "repository", "owner": "platform", "repo": "api" },
                    "options": {}
                }
            }),
        )
        .await;
        assert_eq!(unconfirmed_sync["error"]["code"], -32602);
        assert!(
            upstream_server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.url.path() != "/api/v1/secret-syncs/github")
        );
        let sync = call_authenticated_tool(
            router,
            &identity,
            67,
            "secretSyncs.github.create",
            json!({
                "projectId": project_id,
                "name": "github-actions",
                "description": null,
                "connectionId": connection_id,
                "environment": "prod",
                "secretPath": "/apps",
                "config": {
                    "destination": { "scope": "repository", "owner": "platform", "repo": "api" },
                    "options": {
                        "keySchema": "{{environment}}/{{secretKey}}",
                        "disableSecretDeletion": false
                    }
                },
                "confirmInitialOverwrite": true
            }),
        )
        .await;
        for (name, body) in [
            ("appConnections.github.create", connection),
            ("appConnections.github.rotateCredentials", rotation),
            ("secretSyncs.github.create", sync),
        ] {
            assert_eq!(body["result"]["isError"], false, "{name}");
            for representation in [
                &body["result"]["structuredContent"],
                &body["result"]["content"],
            ] {
                let wire = representation.to_string();
                for forbidden in [
                    "github-wire-input-canary",
                    "github-wire-response-canary",
                    "credentialsHash",
                    "lastSyncMessage",
                ] {
                    assert!(!wire.contains(forbidden), "{name} exposed {forbidden}");
                }
            }
        }
    }

    fn dynamic_secret_wire_configuration(config_id: &str, folder_id: &str) -> Value {
        json!({
            "id": config_id,
            "name": "database-user",
            "version": 1,
            "type": "sql-database",
            "defaultTTL": "3600s",
            "maxTTL": "86400s",
            "folderId": folder_id,
            "status": null,
            "statusDetails": "dynamic-wire-canary",
            "createdAt": "2026-07-20T12:00:00.000Z",
            "updatedAt": "2026-07-20T12:05:00.000Z",
            "projectGatewayId": null,
            "gatewayId": null,
            "gatewayV2Id": null,
            "gatewayPoolId": null,
            "usernameTemplate": "svc-{{randomUsername}}",
            "inputs": { "password": "dynamic-wire-canary" },
            "metadata": { "secretValue": "dynamic-wire-canary" }
        })
    }

    fn dynamic_secret_wire_lease(config_id: &str, lease_id: &str) -> Value {
        json!({
            "id": lease_id,
            "version": 2,
            "externalEntityId": "svc-lease-user",
            "expireAt": "2026-07-20T14:00:00.000Z",
            "status": null,
            "statusDetails": "dynamic-wire-canary",
            "dynamicSecretId": config_id,
            "createdAt": "2026-07-20T12:00:00.000Z",
            "updatedAt": "2026-07-20T12:05:00.000Z",
            "config": { "password": "dynamic-wire-canary" }
        })
    }

    fn assert_value_free_dynamic_secret_result(body: &Value) {
        for representation in [
            &body["result"]["structuredContent"],
            &body["result"]["content"],
        ] {
            let wire = representation.to_string();
            assert!(!wire.contains("dynamic-wire-canary"));
            assert!(!wire.contains("inputs"));
            assert!(!wire.contains("metadata"));
        }
    }

    async fn mount_dynamic_secret_wire_login(upstream_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "dynamic-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    async fn mount_dynamic_secret_lifecycle_fixtures(
        upstream_server: &MockServer,
        config_id: &str,
        folder_id: &str,
        lease_id: &str,
    ) {
        mount_dynamic_secret_wire_login(upstream_server).await;
        Mock::given(method("GET"))
            .and(path("/api/v1/dynamic-secrets"))
            .and(query_param("projectSlug", "platform"))
            .and(query_param("environmentSlug", "prod"))
            .and(query_param("path", "/database"))
            .and(wire_header("authorization", "Bearer dynamic-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dynamicSecrets": [dynamic_secret_wire_configuration(config_id, folder_id)]
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/dynamic-secrets/leases/{lease_id}/renew"
            )))
            .and(wire_header("authorization", "Bearer dynamic-wire-token"))
            .and(body_json(json!({
                "projectSlug": "platform",
                "environmentSlug": "prod",
                "path": "/database",
                "ttl": "7200s"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease": dynamic_secret_wire_lease(config_id, lease_id)
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    async fn mount_dynamic_secret_admin_wire_fixtures(
        upstream_server: &MockServer,
        config_id: &str,
        folder_id: &str,
    ) {
        mount_dynamic_secret_wire_login(upstream_server).await;
        let mut lifetime_configuration = dynamic_secret_wire_configuration(config_id, folder_id);
        lifetime_configuration["defaultTTL"] = json!("7200s");
        lifetime_configuration["maxTTL"] = Value::Null;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/dynamic-secrets/database-user"))
            .and(wire_header("authorization", "Bearer dynamic-wire-token"))
            .and(body_json(json!({
                "projectSlug": "platform",
                "environmentSlug": "prod",
                "path": "/database",
                "data": {
                    "defaultTTL": "7200s",
                    "maxTTL": null
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dynamicSecret": lifetime_configuration
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/dynamic-secrets/database-user"))
            .and(wire_header("authorization", "Bearer dynamic-wire-token"))
            .and(body_json(json!({
                "projectSlug": "platform",
                "environmentSlug": "prod",
                "path": "/database",
                "isForced": false
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dynamicSecret": dynamic_secret_wire_configuration(config_id, folder_id)
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    #[tokio::test]
    async fn authenticated_dynamic_secret_lifecycle_is_value_free_and_exactly_once() {
        let (router, key, upstream_server) = test_router().await;
        let config_id = "0b30c3c2-6a13-485f-9775-9768d8d2708a";
        let folder_id = "573a2b87-7f44-4fb4-81ca-851679a7419f";
        let lease_id = "4d40b103-d45a-44ca-a95f-57d7361a4d2a";
        mount_dynamic_secret_lifecycle_fixtures(&upstream_server, config_id, folder_id, lease_id)
            .await;

        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let scope = json!({
            "projectSlug": "platform",
            "environmentSlug": "prod",
            "path": "/database"
        });
        let list_response = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 60,
                    "method": "tools/call",
                    "params": {
                        "name": "dynamicSecrets.list",
                        "arguments": { "scope": scope.clone(), "limit": 10 }
                    }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("dynamic-secret list response");
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = json_body(list_response).await;
        assert_eq!(list_body["result"]["isError"], false);
        assert_eq!(
            list_body["result"]["structuredContent"]["items"][0]["name"],
            "database-user"
        );
        for representation in [
            &list_body["result"]["structuredContent"],
            &list_body["result"]["content"],
        ] {
            let wire = representation.to_string();
            assert!(!wire.contains("dynamic-wire-canary"));
            assert!(!wire.contains("inputs"));
            assert!(!wire.contains("metadata"));
        }

        let renew_response = router
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 61,
                    "method": "tools/call",
                    "params": {
                        "name": "dynamicSecretLeases.renew",
                        "arguments": {
                            "scope": scope,
                            "leaseId": lease_id,
                            "ttlSeconds": 7200
                        }
                    }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("dynamic-secret lease renew response");
        assert_eq!(renew_response.status(), StatusCode::OK);
        let renew_body = json_body(renew_response).await;
        assert_eq!(renew_body["result"]["isError"], false);
        assert_eq!(renew_body["result"]["structuredContent"]["id"], lease_id);
        for representation in [
            &renew_body["result"]["structuredContent"],
            &renew_body["result"]["content"],
        ] {
            assert!(!representation.to_string().contains("dynamic-wire-canary"));
        }
    }

    #[tokio::test]
    async fn authenticated_dynamic_secret_admin_mutations_are_value_free_and_exactly_once() {
        let (router, key, upstream_server) = test_router().await;
        let config_id = "0b30c3c2-6a13-485f-9775-9768d8d2708a";
        let folder_id = "573a2b87-7f44-4fb4-81ca-851679a7419f";
        mount_dynamic_secret_admin_wire_fixtures(&upstream_server, config_id, folder_id).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let target = json!({
            "scope": {
                "projectSlug": "platform",
                "environmentSlug": "prod",
                "path": "/database"
            },
            "dynamicSecretName": "database-user"
        });

        let update_response = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 62,
                    "method": "tools/call",
                    "params": {
                        "name": "dynamicSecrets.update",
                        "arguments": {
                            "target": target.clone(),
                            "change": {
                                "kind": "lifetime",
                                "defaultTtlSeconds": 7200,
                                "maxTtlSeconds": null
                            }
                        }
                    }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("dynamic-secret update response");
        assert_eq!(update_response.status(), StatusCode::OK);
        let update_body = json_body(update_response).await;
        assert_eq!(update_body["result"]["isError"], false);
        assert_eq!(
            update_body["result"]["structuredContent"]["defaultTTL"],
            "7200s"
        );
        assert_value_free_dynamic_secret_result(&update_body);

        let delete_response = router
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 63,
                    "method": "tools/call",
                    "params": {
                        "name": "dynamicSecrets.delete",
                        "arguments": { "target": target, "confirm": true }
                    }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("dynamic-secret delete response");
        assert_eq!(delete_response.status(), StatusCode::OK);
        let delete_body = json_body(delete_response).await;
        assert_eq!(delete_body["result"]["isError"], false);
        assert_eq!(
            delete_body["result"]["structuredContent"]["name"],
            "database-user"
        );
        assert_value_free_dynamic_secret_result(&delete_body);
    }

    fn sql_dynamic_secret_wire_inputs(password: &str) -> Value {
        json!({
            "client": "postgres",
            "host": "db.internal",
            "port": 5432,
            "database": "app",
            "username": "root",
            "password": password,
            "passwordRequirements": {
                "length": 48,
                "required": {
                    "lowercase": 1,
                    "uppercase": 1,
                    "digits": 1,
                    "symbols": 0
                },
                "allowedSymbols": "-_.~!*"
            },
            "creationStatement": "CREATE USER {{username}} WITH PASSWORD '{{password}}'",
            "revocationStatement": "DROP USER {{username}}",
            "renewStatement": "ALTER USER {{username}} VALID UNTIL '{{expiration}}'",
            "ca": "",
            "sslEnabled": false,
            "sslRejectUnauthorized": true,
            "gatewayId": null,
            "gatewayPoolId": null
        })
    }

    fn sql_dynamic_secret_mcp_provider(password: &str) -> Value {
        json!({
            "type": "sqlDatabase",
            "inputs": {
                "client": "postgres",
                "host": "db.internal",
                "port": 5432,
                "database": "app",
                "username": "root",
                "password": password,
                "creationStatement": "CREATE USER {{username}} WITH PASSWORD '{{password}}'",
                "revocationStatement": "DROP USER {{username}}",
                "renewStatement": "ALTER USER {{username}} VALID UNTIL '{{expiration}}'",
                "sslEnabled": false,
                "sslRejectUnauthorized": true,
                "route": { "kind": "direct" }
            }
        })
    }

    async fn mount_sql_dynamic_secret_wire_fixtures(
        server: &MockServer,
        config_id: &str,
        folder_id: &str,
        lease_id: &str,
    ) {
        mount_dynamic_secret_wire_login(server).await;
        let configuration = dynamic_secret_wire_configuration(config_id, folder_id);
        Mock::given(method("POST"))
            .and(path("/api/v1/dynamic-secrets"))
            .and(wire_header("authorization", "Bearer dynamic-wire-token"))
            .and(body_json(json!({
                "projectSlug": "platform",
                "environmentSlug": "prod",
                "path": "/database",
                "name": "database-user",
                "defaultTTL": "3600s",
                "maxTTL": "86400s",
                "provider": {
                    "type": "sql-database",
                    "inputs": sql_dynamic_secret_wire_inputs("create-root-canary")
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dynamicSecret": configuration.clone()
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/dynamic-secrets/database-user"))
            .and(wire_header("authorization", "Bearer dynamic-wire-token"))
            .and(query_param("projectSlug", "platform"))
            .and(query_param("environmentSlug", "prod"))
            .and(query_param("path", "/database"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dynamicSecret": configuration.clone()
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/dynamic-secrets/leases"))
            .and(wire_header("authorization", "Bearer dynamic-wire-token"))
            .and(body_json(json!({
                "dynamicSecretName": "database-user",
                "projectSlug": "platform",
                "environmentSlug": "prod",
                "path": "/database",
                "ttl": "7200s"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease": dynamic_secret_wire_lease(config_id, lease_id),
                "dynamicSecret": configuration,
                "data": {
                    "DB_USERNAME": "svc-lease-user",
                    "DB_PASSWORD": "lease-password-canary"
                }
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn authenticated_sql_dynamic_secret_workflows_preserve_secret_boundaries() {
        let (router, key, upstream_server) = test_router().await;
        let config_id = "0b30c3c2-6a13-485f-9775-9768d8d2708a";
        let folder_id = "573a2b87-7f44-4fb4-81ca-851679a7419f";
        let lease_id = "4d40b103-d45a-44ca-a95f-57d7361a4d2a";
        mount_sql_dynamic_secret_wire_fixtures(&upstream_server, config_id, folder_id, lease_id)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let scope = json!({
            "projectSlug": "platform",
            "environmentSlug": "prod",
            "path": "/database"
        });
        let target = json!({
            "scope": scope.clone(),
            "dynamicSecretName": "database-user"
        });

        let created = call_authenticated_tool(
            router.clone(),
            &identity,
            64,
            "dynamicSecrets.create",
            json!({
                "scope": scope,
                "name": "database-user",
                "defaultTtlSeconds": 3600,
                "maxTtlSeconds": 86400,
                "provider": sql_dynamic_secret_mcp_provider("create-root-canary")
            }),
        )
        .await;
        let lease = call_authenticated_tool(
            router,
            &identity,
            65,
            "dynamicSecretLeases.create",
            json!({
                "target": target,
                "provider": { "type": "sqlDatabase" },
                "ttlSeconds": 7200
            }),
        )
        .await;

        assert_eq!(created["result"]["isError"], false);
        assert_value_free_dynamic_secret_result(&created);
        assert!(!created["result"].to_string().contains("create-root-canary"));
        assert_eq!(lease["result"]["isError"], false);
        assert_eq!(
            lease["result"]["structuredContent"]["lease"]["id"],
            lease_id
        );
        assert_eq!(
            lease["result"]["structuredContent"]["password"],
            "lease-password-canary"
        );
        for representation in [
            &lease["result"]["structuredContent"],
            &lease["result"]["content"],
        ] {
            let wire = representation.to_string();
            assert!(wire.contains("lease-password-canary"));
            assert!(!wire.contains("dynamic-wire-canary"));
        }
    }

    fn universal_auth_wire_fixture() -> Value {
        json!({
            "id": "universal-auth-1",
            "clientId": "public-client-id",
            "identityId": "identity-1",
            "accessTokenTTL": 2_592_000,
            "accessTokenMaxTTL": 2_592_000,
            "accessTokenNumUsesLimit": 0,
            "accessTokenPeriod": 0,
            "lockoutEnabled": true,
            "lockoutThreshold": 3,
            "lockoutDurationSeconds": 300,
            "lockoutCounterResetSeconds": 30,
            "clientSecretTrustedIps": [
                { "ipAddress": "0.0.0.0", "type": "ipv4", "prefix": 0 }
            ],
            "accessTokenTrustedIps": [
                { "ipAddress": "::", "type": "ipv6", "prefix": 0 }
            ]
        })
    }

    fn universal_auth_client_secret_wire_fixture(id: &str, revoked: bool) -> Value {
        json!({
            "id": id,
            "description": "gateway credential",
            "clientSecretPrefix": "ua.abc",
            "clientSecretNumUses": 1,
            "clientSecretNumUsesLimit": 10,
            "clientSecretTTL": 86400,
            "identityUAId": "universal-auth-1",
            "isClientSecretRevoked": revoked,
            "createdAt": "2026-07-19T12:00:00.000Z",
            "updatedAt": "2026-07-19T12:00:00.000Z"
        })
    }

    async fn mount_universal_auth_config_wire_fixtures(upstream_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "universal-auth-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        let route = "/api/v1/auth/universal-auth/identities/identity-1";
        Mock::given(method("GET"))
            .and(path(route))
            .and(wire_header(
                "authorization",
                "Bearer universal-auth-wire-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityUniversalAuth": universal_auth_wire_fixture()
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        for (method_name, body) in [
            (
                "POST",
                json!({
                    "accessTokenTTL": 2_592_000,
                    "accessTokenMaxTTL": 2_592_000,
                    "accessTokenNumUsesLimit": 0,
                    "accessTokenPeriod": 0,
                    "lockoutEnabled": true,
                    "lockoutThreshold": 3,
                    "lockoutDurationSeconds": 300,
                    "lockoutCounterResetSeconds": 30
                }),
            ),
            (
                "PATCH",
                json!({
                    "accessTokenTTL": 1800,
                    "accessTokenMaxTTL": 7200,
                    "accessTokenPeriod": 0
                }),
            ),
            ("DELETE", json!({})),
        ] {
            Mock::given(method(method_name))
                .and(path(route))
                .and(wire_header(
                    "authorization",
                    "Bearer universal-auth-wire-token",
                ))
                .and(body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "identityUniversalAuth": universal_auth_wire_fixture()
                })))
                .expect(1)
                .mount(upstream_server)
                .await;
        }

        Mock::given(method("POST"))
            .and(path(format!("{route}/clear-lockouts")))
            .and(wire_header(
                "authorization",
                "Bearer universal-auth-wire-token",
            ))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "deleted": 1 })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    async fn mount_universal_auth_client_secret_wire_fixtures(upstream_server: &MockServer) {
        let route = "/api/v1/auth/universal-auth/identities/identity-1";
        let collection = format!("{route}/client-secrets");
        Mock::given(method("GET"))
            .and(path(collection.as_str()))
            .and(wire_header(
                "authorization",
                "Bearer universal-auth-wire-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "clientSecretData": [
                    universal_auth_client_secret_wire_fixture("client-secret-1", false)
                ]
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{collection}/client-secret-1")))
            .and(wire_header(
                "authorization",
                "Bearer universal-auth-wire-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "clientSecretData": universal_auth_client_secret_wire_fixture(
                    "client-secret-1",
                    false
                )
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(collection.as_str()))
            .and(wire_header(
                "authorization",
                "Bearer universal-auth-wire-token",
            ))
            .and(body_json(json!({
                "description": "gateway credential",
                "numUsesLimit": 10,
                "ttl": 86400
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "clientSecret": "generated-client-secret-wire-canary",
                "clientSecretData": universal_auth_client_secret_wire_fixture(
                    "client-secret-2",
                    false
                )
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{collection}/client-secret-1/revoke")))
            .and(wire_header(
                "authorization",
                "Bearer universal-auth-wire-token",
            ))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "clientSecretData": universal_auth_client_secret_wire_fixture(
                    "client-secret-1",
                    true
                )
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    fn universal_auth_wire_calls() -> [(i32, &'static str, Value); 9] {
        [
            (
                41,
                "identityUniversalAuth.get",
                json!({ "identityId": "identity-1" }),
            ),
            (
                42,
                "identityUniversalAuth.attach",
                json!({ "identityId": "identity-1" }),
            ),
            (
                43,
                "identityUniversalAuth.update",
                json!({
                    "identityId": "identity-1",
                    "change": {
                        "kind": "tokenLifetime",
                        "accessTokenTTL": 1800,
                        "accessTokenMaxTTL": 7200,
                        "accessTokenPeriod": 0
                    }
                }),
            ),
            (
                44,
                "identityUniversalAuth.clientSecrets.list",
                json!({ "identityId": "identity-1" }),
            ),
            (
                45,
                "identityUniversalAuth.clientSecrets.get",
                json!({
                    "identityId": "identity-1",
                    "clientSecretId": "client-secret-1"
                }),
            ),
            (
                46,
                "identityUniversalAuth.clientSecrets.create",
                json!({
                    "identityId": "identity-1",
                    "description": "gateway credential",
                    "numUsesLimit": 10,
                    "ttl": 86400
                }),
            ),
            (
                47,
                "identityUniversalAuth.clientSecrets.revoke",
                json!({
                    "identityId": "identity-1",
                    "clientSecretId": "client-secret-1",
                    "confirm": true
                }),
            ),
            (
                48,
                "identityUniversalAuth.lockouts.clear",
                json!({ "identityId": "identity-1", "confirm": true }),
            ),
            (
                49,
                "identityUniversalAuth.remove",
                json!({ "identityId": "identity-1", "confirm": true }),
            ),
        ]
    }

    #[tokio::test]
    async fn authenticated_universal_auth_tools_preserve_pinned_wire_contracts() {
        let (router, key, upstream_server) = test_router().await;
        mount_universal_auth_config_wire_fixtures(&upstream_server).await;
        mount_universal_auth_client_secret_wire_fixtures(&upstream_server).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for (id, name, arguments) in universal_auth_wire_calls() {
            let response = router
                .clone()
                .oneshot(mcp_request(
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/call",
                        "params": { "name": name, "arguments": arguments }
                    }),
                    Some(CURRENT),
                    Some(&identity),
                ))
                .await
                .expect("Universal Auth tool response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            assert_eq!(body["result"]["isError"], false, "{name}");
            let structured = &body["result"]["structuredContent"];
            if name == "identityUniversalAuth.clientSecrets.create" {
                assert_eq!(
                    structured["clientSecret"],
                    "generated-client-secret-wire-canary"
                );
            } else {
                assert!(
                    !structured
                        .to_string()
                        .contains("generated-client-secret-wire-canary"),
                    "{name} must not expose generated credentials"
                );
            }
        }
    }

    fn token_auth_wire_fixture() -> Value {
        json!({
            "id": "token-auth-1",
            "identityId": "identity-1",
            "accessTokenTTL": 3600,
            "accessTokenMaxTTL": 86400,
            "accessTokenNumUsesLimit": 10,
            "accessTokenPeriod": 0,
            "accessTokenTrustedIps": [
                { "ipAddress": "0.0.0.0", "type": "ipv4", "prefix": 0 }
            ],
            "createdAt": "2026-07-19T12:00:00.000Z",
            "updatedAt": "2026-07-19T12:00:00.000Z"
        })
    }

    fn token_auth_token_wire_fixture(id: &str, name: &str) -> Value {
        json!({
            "id": id,
            "identityId": "identity-1",
            "name": name,
            "authMethod": "token-auth",
            "accessTokenTTL": 3600,
            "accessTokenMaxTTL": 86400,
            "accessTokenNumUses": 1,
            "accessTokenNumUsesLimit": 10,
            "accessTokenLastUsedAt": null,
            "accessTokenLastRenewedAt": null,
            "isAccessTokenRevoked": false,
            "accessTokenPeriod": 0,
            "subOrganizationId": null,
            "createdAt": "2026-07-19T12:00:00.000Z",
            "updatedAt": "2026-07-19T12:00:00.000Z"
        })
    }

    async fn mount_token_auth_config_wire_fixtures(upstream_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "token-auth-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        let config_route = "/api/v1/auth/token-auth/identities/identity-1";
        Mock::given(method("GET"))
            .and(path(config_route))
            .and(wire_header("authorization", "Bearer token-auth-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityTokenAuth": token_auth_wire_fixture()
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        for (method_name, body) in [
            (
                "POST",
                json!({
                    "accessTokenTTL": 3600,
                    "accessTokenMaxTTL": 86400,
                    "accessTokenNumUsesLimit": 10
                }),
            ),
            (
                "PATCH",
                json!({ "accessTokenTTL": 1800, "accessTokenMaxTTL": 7200 }),
            ),
            ("DELETE", json!({})),
        ] {
            Mock::given(method(method_name))
                .and(path(config_route))
                .and(wire_header("authorization", "Bearer token-auth-wire-token"))
                .and(body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "identityTokenAuth": token_auth_wire_fixture()
                })))
                .expect(1)
                .mount(upstream_server)
                .await;
        }
    }

    async fn mount_token_auth_token_wire_fixtures(upstream_server: &MockServer) {
        let collection = "/api/v1/auth/token-auth/identities/identity-1/tokens";
        Mock::given(method("GET"))
            .and(path(collection))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "50"))
            .and(wire_header("authorization", "Bearer token-auth-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tokens": [token_auth_token_wire_fixture("token-1", "gateway")]
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/token-auth/tokens/token-1"))
            .and(wire_header("authorization", "Bearer token-auth-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token": token_auth_token_wire_fixture("token-1", "gateway")
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(collection))
            .and(wire_header("authorization", "Bearer token-auth-wire-token"))
            .and(body_json(
                json!({ "name": "gateway", "organizationSlug": "child-org" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "generated-token-wire-canary",
                "expiresIn": 3600,
                "accessTokenMaxTTL": 86400,
                "tokenType": "Bearer",
                "tokenData": token_auth_token_wire_fixture("token-2", "gateway")
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/auth/token-auth/tokens/token-1"))
            .and(wire_header("authorization", "Bearer token-auth-wire-token"))
            .and(body_json(json!({ "name": "renamed" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token": token_auth_token_wire_fixture("token-1", "renamed")
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/token-auth/tokens/token-1/revoke"))
            .and(wire_header("authorization", "Bearer token-auth-wire-token"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "Successfully revoked access token"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    fn token_auth_wire_calls() -> [(i32, &'static str, Value); 9] {
        [
            (
                50,
                "identityTokenAuth.get",
                json!({ "identityId": "identity-1" }),
            ),
            (
                51,
                "identityTokenAuth.attach",
                json!({
                    "identityId": "identity-1",
                    "accessTokenTTL": 3600,
                    "accessTokenMaxTTL": 86400,
                    "accessTokenNumUsesLimit": 10
                }),
            ),
            (
                52,
                "identityTokenAuth.update",
                json!({
                    "identityId": "identity-1",
                    "change": {
                        "kind": "tokenLifetime",
                        "accessTokenTTL": 1800,
                        "accessTokenMaxTTL": 7200
                    }
                }),
            ),
            (
                53,
                "identityTokenAuth.tokens.list",
                json!({ "identityId": "identity-1" }),
            ),
            (
                54,
                "identityTokenAuth.tokens.get",
                json!({ "tokenId": "token-1" }),
            ),
            (
                55,
                "identityTokenAuth.tokens.create",
                json!({
                    "identityId": "identity-1",
                    "name": "gateway",
                    "organizationSlug": "child-org"
                }),
            ),
            (
                56,
                "identityTokenAuth.tokens.update",
                json!({
                    "tokenId": "token-1",
                    "name": "renamed"
                }),
            ),
            (
                57,
                "identityTokenAuth.tokens.revoke",
                json!({
                    "tokenId": "token-1",
                    "confirm": true
                }),
            ),
            (
                58,
                "identityTokenAuth.remove",
                json!({
                    "identityId": "identity-1",
                    "confirm": true
                }),
            ),
        ]
    }

    #[tokio::test]
    async fn authenticated_token_auth_tools_preserve_pinned_wire_contracts() {
        let (router, key, upstream_server) = test_router().await;
        mount_token_auth_config_wire_fixtures(&upstream_server).await;
        mount_token_auth_token_wire_fixtures(&upstream_server).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for (id, name, arguments) in token_auth_wire_calls() {
            let response = router
                .clone()
                .oneshot(mcp_request(
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/call",
                        "params": { "name": name, "arguments": arguments }
                    }),
                    Some(CURRENT),
                    Some(&identity),
                ))
                .await
                .expect("Token Auth tool response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            assert_eq!(body["result"]["isError"], false, "{name}: {body}");
            let structured = &body["result"]["structuredContent"];
            if name == "identityTokenAuth.tokens.create" {
                assert_eq!(structured["accessToken"], "generated-token-wire-canary");
            } else {
                assert!(
                    !structured
                        .to_string()
                        .contains("generated-token-wire-canary"),
                    "{name} must not expose generated credentials"
                );
            }
        }
    }

    fn kubernetes_auth_wire_fixture() -> Value {
        json!({
            "id": "kubernetes-auth-1",
            "identityId": "identity-1",
            "accessTokenTTL": 3600,
            "accessTokenMaxTTL": 86400,
            "accessTokenNumUsesLimit": 10,
            "accessTokenTrustedIps": [
                { "ipAddress": "0.0.0.0", "type": "ipv4", "prefix": 0 }
            ],
            "tokenReviewMode": "api",
            "kubernetesHost": "https://kubernetes.default.svc",
            "allowedNamespaces": "payments,platform-*",
            "allowedNames": "api,worker-*",
            "allowedAudience": "infisical",
            "caCert": "",
            "tokenReviewerJwt": "stored-reviewer-wire-canary",
            "verifyTlsCertificate": false,
            "gatewayId": null,
            "gatewayPoolId": null,
            "createdAt": "2026-07-19T12:00:00.000Z",
            "updatedAt": "2026-07-19T12:00:00.000Z"
        })
    }

    async fn mount_kubernetes_auth_wire_fixtures(upstream_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "kubernetes-auth-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        let route = "/api/v1/auth/kubernetes-auth/identities/identity-1";
        Mock::given(method("GET"))
            .and(path(route))
            .and(wire_header(
                "authorization",
                "Bearer kubernetes-auth-wire-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityKubernetesAuth": kubernetes_auth_wire_fixture()
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path(route))
            .and(wire_header(
                "authorization",
                "Bearer kubernetes-auth-wire-token",
            ))
            .and(body_json(json!({
                "kubernetesHost": "https://kubernetes.default.svc",
                "verifyTlsCertificate": false,
                "tokenReviewerJwt": "reviewer-wire-input",
                "tokenReviewMode": "api",
                "allowedNamespaces": "payments,platform-*",
                "allowedNames": "api,worker-*",
                "allowedAudience": "infisical",
                "accessTokenTTL": 3600,
                "accessTokenMaxTTL": 86400,
                "accessTokenNumUsesLimit": 10
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityKubernetesAuth": kubernetes_auth_wire_fixture()
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(route))
            .and(wire_header(
                "authorization",
                "Bearer kubernetes-auth-wire-token",
            ))
            .and(body_json(json!({
                "kubernetesHost": "https://api.cluster.internal",
                "caCert": null,
                "verifyTlsCertificate": false,
                "tokenReviewerJwt": "reviewer-wire-replacement",
                "tokenReviewMode": "api",
                "gatewayId": null,
                "gatewayPoolId": null
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityKubernetesAuth": kubernetes_auth_wire_fixture()
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(route))
            .and(wire_header(
                "authorization",
                "Bearer kubernetes-auth-wire-token",
            ))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "identityKubernetesAuth": kubernetes_auth_wire_fixture()
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    fn kubernetes_auth_wire_calls() -> [(i32, &'static str, Value); 4] {
        [
            (
                59,
                "identityKubernetesAuth.get",
                json!({ "identityId": "identity-1" }),
            ),
            (
                60,
                "identityKubernetesAuth.attach",
                json!({
                    "identityId": "identity-1",
                    "kubernetesHost": "https://kubernetes.default.svc",
                    "caCert": null,
                    "verifyTlsCertificate": false,
                    "tokenReviewerJwt": "reviewer-wire-input",
                    "allowedNamespaces": ["payments", "platform-*"],
                    "allowedNames": ["api", "worker-*"],
                    "allowedAudience": "infisical",
                    "accessTokenTTL": 3600,
                    "accessTokenMaxTTL": 86400,
                    "accessTokenNumUsesLimit": 10
                }),
            ),
            (
                61,
                "identityKubernetesAuth.update",
                json!({
                    "identityId": "identity-1",
                    "change": {
                        "kind": "directReviewer",
                        "kubernetesHost": "https://api.cluster.internal",
                        "caCert": null,
                        "verifyTlsCertificate": false,
                        "tokenReviewerJwt": {
                            "kind": "replace",
                            "value": "reviewer-wire-replacement"
                        }
                    }
                }),
            ),
            (
                62,
                "identityKubernetesAuth.remove",
                json!({ "identityId": "identity-1", "confirm": true }),
            ),
        ]
    }

    #[tokio::test]
    async fn authenticated_kubernetes_auth_tools_preserve_pinned_wire_contracts() {
        let (router, key, upstream_server) = test_router().await;
        mount_kubernetes_auth_wire_fixtures(&upstream_server).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for (id, name, arguments) in kubernetes_auth_wire_calls() {
            let response = router
                .clone()
                .oneshot(mcp_request(
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/call",
                        "params": { "name": name, "arguments": arguments }
                    }),
                    Some(CURRENT),
                    Some(&identity),
                ))
                .await
                .expect("Kubernetes Auth tool response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            assert_eq!(body["result"]["isError"], false, "{name}: {body}");
            let structured = &body["result"]["structuredContent"];
            assert_eq!(structured["tokenReviewerJwtConfigured"], true);
            let serialized = structured.to_string();
            assert!(!serialized.contains("stored-reviewer-wire-canary"));
            assert!(!serialized.contains("reviewer-wire-input"));
            assert!(!serialized.contains("reviewer-wire-replacement"));
            assert!(structured.get("tokenReviewerJwt").is_none());
        }
    }

    async fn mount_secret_wire_fixtures(upstream_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "secret-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v4/secrets/STRIPE_API_KEY"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secret": {
                    "id": "secret-1",
                    "environment": "prod",
                    "version": 3,
                    "type": "shared",
                    "secretKey": "STRIPE_API_KEY",
                    "secretValue": "wire-reveal-canary",
                    "secretPath": "/payments"
                }
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v4/secrets/STRIPE_API_KEY"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secret": {
                    "id": "secret-1",
                    "environment": "prod",
                    "version": 4,
                    "type": "shared",
                    "secretKey": "STRIPE_API_KEY",
                    "secretValue": "wire-update-response-canary",
                    "createdAt": "2026-07-19T12:00:00.000Z",
                    "updatedAt": "2026-07-19T12:05:00.000Z"
                }
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v4/secrets/batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secrets": [{
                    "id": "secret-1",
                    "environment": "prod",
                    "version": 1,
                    "type": "shared",
                    "secretKey": "STRIPE_API_KEY",
                    "secretValue": "wire-batch-response-canary",
                    "createdAt": "2026-07-19T12:00:00.000Z",
                    "updatedAt": "2026-07-19T12:05:00.000Z"
                }]
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v2/secret-imports"))
            .and(wire_header("authorization", "Bearer secret-wire-token"))
            .and(body_json(json!({
                "projectId": "project-1",
                "environment": "prod",
                "path": "/payments",
                "import": { "environment": "staging", "path": "/shared" },
                "isReplication": false
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretImport": {
                    "id": "import-1",
                    "version": 1,
                    "importPath": "/shared",
                    "importEnv": {
                        "id": "env-staging",
                        "name": "Staging",
                        "slug": "staging"
                    },
                    "position": 1,
                    "createdAt": "2026-07-19T12:00:00.000Z",
                    "updatedAt": "2026-07-19T12:05:00.000Z",
                    "folderId": "folder-1",
                    "isReplication": false,
                    "isReplicationSuccess": null,
                    "lastReplicated": null,
                    "isReserved": false
                }
            })))
            .expect(1)
            .mount(upstream_server)
            .await;
    }

    async fn assert_single_secret_wire_contract(router: &Router, identity: &str) {
        let target = json!({
            "projectId": "project-1",
            "environment": "prod",
            "path": "/payments",
            "name": "STRIPE_API_KEY"
        });

        let reveal = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "secrets.reveal",
                        "arguments": { "target": target.clone() }
                    }
                }),
                Some(CURRENT),
                Some(identity),
            ))
            .await
            .expect("secrets.reveal response");
        assert_eq!(reveal.status(), StatusCode::OK);
        let reveal = json_body(reveal).await;
        assert_eq!(
            reveal["result"]["structuredContent"]["secretValue"],
            "wire-reveal-canary"
        );
        assert!(
            reveal["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("wire-reveal-canary")
        );

        let update = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "secrets.update",
                        "arguments": {
                            "target": target,
                            "secretValue": "wire-update-input-canary"
                        }
                    }
                }),
                Some(CURRENT),
                Some(identity),
            ))
            .await
            .expect("secrets.update response");
        assert_eq!(update.status(), StatusCode::OK);
        let update = json_body(update).await;
        let serialized = update.to_string();
        assert_eq!(update["result"]["structuredContent"]["status"], "applied");
        for canary in [
            "wire-update-input-canary",
            "wire-update-response-canary",
            "secretValue",
        ] {
            assert!(!serialized.contains(canary), "wire result leaked {canary}");
        }
    }

    async fn assert_batch_secret_wire_contract(router: &Router, identity: &str) {
        let batch_create = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": "secrets.batch.create",
                        "arguments": {
                            "scope": {
                                "projectId": "project-1",
                                "environment": "prod",
                                "path": "/payments"
                            },
                            "secrets": [{
                                "name": "STRIPE_API_KEY",
                                "secretValue": "wire-batch-input-canary"
                            }]
                        }
                    }
                }),
                Some(CURRENT),
                Some(identity),
            ))
            .await
            .expect("secrets.batch.create response");
        assert_eq!(batch_create.status(), StatusCode::OK);
        let batch_create = json_body(batch_create).await;
        let serialized = batch_create.to_string();
        assert_eq!(
            batch_create["result"]["structuredContent"]["status"],
            "applied"
        );
        for canary in [
            "wire-batch-input-canary",
            "wire-batch-response-canary",
            "secretValue",
        ] {
            assert!(!serialized.contains(canary), "wire result leaked {canary}");
        }
    }

    async fn assert_secret_import_wire_contract(router: &Router, identity: &str) {
        let create = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/call",
                    "params": {
                        "name": "secretImports.create",
                        "arguments": {
                            "target": {
                                "projectId": "project-1",
                                "environment": "prod",
                                "path": "/payments"
                            },
                            "source": {
                                "environment": "staging",
                                "path": "/shared"
                            }
                        }
                    }
                }),
                Some(CURRENT),
                Some(identity),
            ))
            .await
            .expect("secretImports.create response");
        assert_eq!(create.status(), StatusCode::OK);
        let create = json_body(create).await;
        let structured = &create["result"]["structuredContent"];
        assert_eq!(structured["id"], "import-1");
        assert_eq!(structured["target"]["environment"], "prod");
        assert_eq!(structured["source"]["environment"]["slug"], "staging");
        assert_eq!(structured["isReplication"], false);
        assert!(!create.to_string().contains("secretValue"));
    }

    #[tokio::test]
    async fn authenticated_secret_workflows_preserve_reveal_and_no_echo_wire_contracts() {
        let (router, key, upstream_server) = test_router().await;
        mount_secret_wire_fixtures(&upstream_server).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);

        assert_single_secret_wire_contract(&router, &identity).await;
        assert_batch_secret_wire_contract(&router, &identity).await;
        assert_secret_import_wire_contract(&router, &identity).await;
    }

    #[tokio::test]
    async fn mismatched_project_metadata_is_rejected_over_the_mcp_transport() {
        let (router, key, upstream_server) = test_router().await;
        mount_app_automation_wire_login(&upstream_server).await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects/project-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": {
                    "id": "project-2", "name": "unexpected-project-canary",
                    "slug": "other", "type": "secret-manager", "orgId": "org-1",
                    "environments": [{"id": "env-1", "name": "Unexpected", "slug": "prod"}]
                }
            })))
            .expect(2)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for operation in ["projects.get", "environments.list"] {
            let result = call_authenticated_tool(
                router.clone(),
                &identity,
                2,
                operation,
                json!({"projectId": "project-1"}),
            )
            .await;
            assert_eq!(result["result"]["isError"], true, "{operation}: {result}");
            assert!(result["result"].get("structuredContent").is_none());
            assert!(!result.to_string().contains("unexpected-project-canary"));
            assert!(!result.to_string().contains("env-1"));
        }
    }

    #[tokio::test]
    async fn mismatched_secret_scope_is_rejected_for_inline_and_file_delivery() {
        let (router, key, upstream_server) = test_router_with_files().await;
        mount_app_automation_wire_login(&upstream_server).await;
        Mock::given(method("GET"))
            .and(path("/api/v4/secrets/STRIPE_API_KEY"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secret": {
                    "id": "secret-1", "environment": "staging", "version": 3,
                    "type": "shared", "secretKey": "STRIPE_API_KEY",
                    "secretValue": "wrong-scope-wire-canary", "secretPath": "/payments"
                }
            })))
            .expect(2)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        for delivery in ["inlineValue", "reference"] {
            let result = call_authenticated_tool(
                router.clone(),
                &identity,
                2,
                "secrets.reveal",
                json!({
                    "target": {
                        "projectId": "project-1", "environment": "prod",
                        "path": "/payments", "name": "STRIPE_API_KEY"
                    },
                    "delivery": delivery
                }),
            )
            .await;
            assert_eq!(result["result"]["isError"], true, "{delivery}: {result}");
            assert!(result["result"].get("structuredContent").is_none());
            assert!(!result.to_string().contains("wrong-scope-wire-canary"));
            assert!(!result.to_string().contains("mcp-file://"));
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn the_reveal_transfer_plane_serves_a_staged_secret_end_to_end() {
        let (router, key, upstream_server) = test_router_with_files().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "secret-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v4/secrets/STRIPE_API_KEY"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secret": {
                    "id": "secret-1",
                    "environment": "prod",
                    "version": 3,
                    "type": "shared",
                    "secretKey": "STRIPE_API_KEY",
                    "secretValue": "wire-plane-canary",
                    "secretPath": "/payments"
                }
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);

        // With the plane on, the default reveal result carries a reference and no part
        // of the MCP response carries the value.
        let reveal = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "secrets.reveal",
                        "arguments": { "target": {
                            "projectId": "project-1",
                            "environment": "prod",
                            "path": "/payments",
                            "name": "STRIPE_API_KEY"
                        } }
                    }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("secrets.reveal response");
        assert_eq!(reveal.status(), StatusCode::OK);
        let reveal = json_body(reveal).await;
        assert!(
            !reveal.to_string().contains("wire-plane-canary"),
            "the MCP response must not carry the secret value: {reveal}"
        );
        let structured = &reveal["result"]["structuredContent"];
        assert!(structured.get("secretValue").is_none());
        let uri = structured["secretFile"]["uri"]
            .as_str()
            .expect("reference delivery returns a staged uri");
        assert!(uri.starts_with("mcp-file://infisical/"));

        // The gateway resolves the reference over the same authenticated MCP channel.
        let authorized = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "files/authorizeDownload",
                    "params": { "uri": uri }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("files/authorizeDownload response");
        assert_eq!(authorized.status(), StatusCode::OK);
        let authorized = json_body(authorized).await;
        assert_eq!(
            authorized["result"]["sensitivity"], "secret",
            "every staged envelope declares the secret retention hint"
        );
        let download = &authorized["result"]["download"];
        assert_eq!(download["method"], "GET");
        assert_eq!(download["transport"], "http");
        let url = download["url"].as_str().expect("download url");
        let route = url
            .strip_prefix("http://localhost:8000")
            .expect("descriptor names the configured public origin");
        let credential = download["headers"]["Infisical-Transfer-Credential"]
            .as_str()
            .expect("descriptor carries the transfer credential");

        let download_request = |credential: &str| {
            Request::builder()
                .method("GET")
                .uri(route)
                .header(header::HOST, "localhost")
                .header("Infisical-Transfer-Credential", credential)
                .body(Body::empty())
                .expect("valid download request")
        };

        // A HEAD with the true credential must not consume the one-time envelope.
        let head = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri(route)
                    .header(header::HOST, "localhost")
                    .header("Infisical-Transfer-Credential", credential)
                    .body(Body::empty())
                    .expect("valid HEAD request"),
            )
            .await
            .expect("HEAD response");
        assert_eq!(head.status(), StatusCode::METHOD_NOT_ALLOWED);

        // A wrong credential is refused without burning the live authorization.
        let forbidden = router
            .clone()
            .oneshot(download_request("not-the-credential"))
            .await
            .expect("refused download response");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let served = router
            .clone()
            .oneshot(download_request(credential))
            .await
            .expect("download response");
        assert_eq!(served.status(), StatusCode::OK);
        assert_eq!(
            served.headers()[header::CONTENT_TYPE],
            "application/json",
            "the envelope media type matches the declared one"
        );
        assert_eq!(
            served.headers()[header::CACHE_CONTROL],
            "no-store",
            "a cache must never replay the envelope past its single use"
        );
        let envelope = json_body(served).await;
        assert_eq!(envelope["operation"], "secrets.reveal");
        assert_eq!(envelope["data"]["secretValue"], "wire-plane-canary");

        // Single use: a served envelope is gone, and the refusal is the bounded code.
        let replay = router
            .clone()
            .oneshot(download_request(credential))
            .await
            .expect("replayed download response");
        assert_eq!(replay.status(), StatusCode::FORBIDDEN);
        let replay = json_body(replay).await;
        assert_eq!(replay["error"], "infisical_file_unauthorized");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn the_upload_plane_accepts_a_value_and_a_write_references_it() {
        let (router, key, upstream_server) = test_router_with_files().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "secret-wire-token",
                "expiresIn": 60,
                "accessTokenMaxTTL": 120,
                "tokenType": "Bearer"
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v4/secrets/STRIPE_API_KEY"))
            .and(body_partial_json(json!({
                "secretValue": "wire-upload-canary"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secret": {
                    "id": "secret-1",
                    "environment": "prod",
                    "version": 1,
                    "type": "shared",
                    "secretKey": "STRIPE_API_KEY",
                    "secretValue": "wire-upload-canary",
                    "createdAt": "2026-07-19T12:00:00.000Z",
                    "updatedAt": "2026-07-19T12:05:00.000Z"
                }
            })))
            .expect(1)
            .mount(&upstream_server)
            .await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);

        // The gateway obtains an upload descriptor over the authenticated MCP channel.
        let authorized = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": "files/authorizeUpload",
                    "params": { "name": "STRIPE_API_KEY", "mimeType": "text/plain" }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("files/authorizeUpload response");
        assert_eq!(authorized.status(), StatusCode::OK);
        let authorized = json_body(authorized).await;
        let uri = authorized["result"]["file"]["uri"]
            .as_str()
            .expect("authorization names the staged reference");
        assert!(uri.starts_with("mcp-file://infisical/"));
        let upload = &authorized["result"]["upload"];
        assert_eq!(upload["method"], "PUT");
        let route = upload["url"]
            .as_str()
            .expect("upload url")
            .strip_prefix("http://localhost:8000")
            .expect("descriptor names the configured public origin");
        let credential = upload["headers"]["Infisical-Transfer-Credential"]
            .as_str()
            .expect("descriptor carries the transfer credential");

        let put = |credential: &str| {
            Request::builder()
                .method("PUT")
                .uri(route)
                .header(header::HOST, "localhost")
                .header("Infisical-Transfer-Credential", credential)
                .body(Body::from("wire-upload-canary"))
                .expect("valid upload request")
        };

        // A wrong credential is refused without burning the live authorization.
        let forbidden = router
            .clone()
            .oneshot(put("not-the-credential"))
            .await
            .expect("refused upload response");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let accepted = router
            .clone()
            .oneshot(put(credential))
            .await
            .expect("upload response");
        assert_eq!(accepted.status(), StatusCode::NO_CONTENT);

        // The write references the uploaded value; the MCP result never carries it.
        let create = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 12,
                    "method": "tools/call",
                    "params": {
                        "name": "secrets.create",
                        "arguments": {
                            "target": {
                                "projectId": "project-1",
                                "environment": "prod",
                                "path": "/payments",
                                "name": "STRIPE_API_KEY"
                            },
                            "secretValueFile": uri
                        }
                    }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("secrets.create response");
        assert_eq!(create.status(), StatusCode::OK);
        let create = json_body(create).await;
        assert_eq!(create["result"]["isError"], false, "{create}");
        assert!(
            !create.to_string().contains("wire-upload-canary"),
            "the MCP response must not carry the uploaded value: {create}"
        );
    }

    #[tokio::test]
    async fn an_oversized_authorized_upload_spends_its_ticket_with_a_bounded_refusal() {
        let (router, key, _upstream_server) = test_router_with_files().await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);

        let authorized = router
            .clone()
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 21,
                    "method": "files/authorizeUpload",
                    "params": {}
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("files/authorizeUpload response");
        let authorized = json_body(authorized).await;
        let route = authorized["result"]["upload"]["url"]
            .as_str()
            .expect("upload url")
            .strip_prefix("http://localhost:8000")
            .expect("descriptor names the configured public origin")
            .to_owned();
        let credential = authorized["result"]["upload"]["headers"]["Infisical-Transfer-Credential"]
            .as_str()
            .expect("descriptor carries the transfer credential")
            .to_owned();

        let put = |body: Vec<u8>, credential: String, route: String| {
            Request::builder()
                .method("PUT")
                .uri(route)
                .header(header::HOST, "localhost")
                .header("Infisical-Transfer-Credential", credential)
                .body(Body::from(body))
                .expect("valid upload request")
        };

        let oversized = router
            .clone()
            .oneshot(put(
                vec![b'x'; infisical_mcp::files::MAX_UPLOAD_BYTES + 5],
                credential.clone(),
                route.clone(),
            ))
            .await
            .expect("oversized upload response");
        assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
        let refusal = json_body(oversized).await;
        assert_eq!(refusal["error"], "infisical_file_size_mismatch");

        // The attempted transfer spent the ticket; the descriptor cannot be replayed.
        let replay = router
            .clone()
            .oneshot(put(b"small".to_vec(), credential, route))
            .await
            .expect("replayed upload response");
        assert_eq!(replay.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn the_authorize_download_method_is_absent_without_the_plane() {
        let (router, key, _upstream_server) = test_router().await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);

        let response = router
            .oneshot(mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "files/authorizeDownload",
                    "params": { "uri": "mcp-file://infisical/absent" }
                }),
                Some(CURRENT),
                Some(&identity),
            ))
            .await
            .expect("authorizeDownload response");
        let body = json_body(response).await;
        assert_eq!(
            body["error"]["code"], -32601,
            "a plane that is off answers method-not-found: {body}"
        );
    }

    #[tokio::test]
    async fn unknown_key_ids_reuse_the_fresh_jwks_cache() {
        let (router, key, jwks_server) = test_router().await;
        let now = unix_timestamp();
        let identity = sign_identity_with_key_id(&key, "unknown-key", AUDIENCE, now, now + 60);

        for _ in 0..2 {
            let response = router
                .clone()
                .oneshot(mcp_request(
                    &initialize_body(),
                    Some(CURRENT),
                    Some(&identity),
                ))
                .await
                .expect("unknown key response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        assert_eq!(jwks_server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn newly_published_identity_key_is_refreshed_once_for_concurrent_callers() {
        let (router, initial_key, jwks_server) = test_router().await;
        let now = unix_timestamp();
        let initial_identity = sign_identity(&initial_key, AUDIENCE, now, now + 60);
        let initial_response = router
            .clone()
            .oneshot(mcp_request(
                &initialize_body(),
                Some(CURRENT),
                Some(&initial_identity),
            ))
            .await
            .expect("initial identity response");
        assert_eq!(initial_response.status(), StatusCode::OK);

        jwks_server.reset().await;
        let rotated_key = test_key_with("gateway-rotated", 9);
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(50))
                    .set_body_json(JwkSet {
                        keys: vec![initial_key.jwk.clone(), rotated_key.jwk.clone()],
                    }),
            )
            .mount(&jwks_server)
            .await;
        let rotated_identity =
            sign_identity_with_key_id(&rotated_key, "gateway-rotated", AUDIENCE, now, now + 60);

        let request_one = router.clone().oneshot(mcp_request(
            &initialize_body(),
            Some(CURRENT),
            Some(&rotated_identity),
        ));
        let request_two = router.clone().oneshot(mcp_request(
            &initialize_body(),
            Some(CURRENT),
            Some(&rotated_identity),
        ));
        let (response_one, response_two) = tokio::join!(request_one, request_two);

        assert_eq!(
            response_one.expect("first rotated response").status(),
            StatusCode::OK
        );
        assert_eq!(
            response_two.expect("second rotated response").status(),
            StatusCode::OK
        );
        assert_eq!(jwks_server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn missing_malformed_stale_and_wrong_audience_credentials_never_dispatch() {
        let (router, key, _jwks_server) = test_router().await;
        let now = unix_timestamp();
        let valid = sign_identity(&key, AUDIENCE, now, now + 60);
        let expired = sign_identity(&key, AUDIENCE, now - 120, now - 60);
        let wrong_audience = sign_identity(&key, "another-server", now, now + 60);

        let cases = [
            (None, Some(valid.as_str())),
            (Some("not-the-bearer"), Some(valid.as_str())),
            (Some(CURRENT), None),
            (Some(CURRENT), Some("not-a-jwt")),
            (Some(CURRENT), Some(expired.as_str())),
            (Some(CURRENT), Some(wrong_audience.as_str())),
        ];
        for (bearer, identity) in cases {
            let response = router
                .clone()
                .oneshot(mcp_request(&initialize_body(), bearer, identity))
                .await
                .expect("authentication rejection response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
                "Bearer"
            );
            let body = json_body(response).await;
            assert!(body.get("error").is_some());
            assert!(body.get("jsonrpc").is_none());
        }
    }

    #[tokio::test]
    async fn host_and_origin_are_checked_before_dispatch() {
        let (router, key, _jwks_server) = test_router().await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);

        let wrong_host = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "attacker.test")
            .header(header::AUTHORIZATION, format!("Bearer {CURRENT}"))
            .header("x-mcp-identity", &identity)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(initialize_body().to_string()))
            .unwrap();
        let wrong_host_response = router.clone().oneshot(wrong_host).await.unwrap();
        assert_eq!(wrong_host_response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(wrong_host_response).await,
            json!({ "error": "host_not_allowed" })
        );

        let mut allowed_origin = mcp_request(&initialize_body(), Some(CURRENT), Some(&identity));
        allowed_origin
            .headers_mut()
            .insert(header::ORIGIN, "https://gateway.test".parse().unwrap());
        assert_eq!(
            router
                .clone()
                .oneshot(allowed_origin)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );

        let mut wrong_origin = mcp_request(&initialize_body(), Some(CURRENT), Some(&identity));
        wrong_origin
            .headers_mut()
            .insert(header::ORIGIN, "https://attacker.test".parse().unwrap());
        let wrong_origin_response = router.oneshot(wrong_origin).await.unwrap();
        assert_eq!(wrong_origin_response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(wrong_origin_response).await,
            json!({ "error": "origin_not_allowed" })
        );
    }

    #[tokio::test]
    async fn oversized_mcp_body_is_rejected_after_authentication() {
        let (router, key, _jwks_server) = test_router().await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let mut body = initialize_body().to_string();
        body.push_str(&" ".repeat(16 * 1024));
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .header(header::AUTHORIZATION, format!("Bearer {CURRENT}"))
            .header("x-mcp-identity", identity)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(Body::from(body))
            .expect("valid oversized test request");

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn request_deadline_includes_identity_key_resolution() {
        let (router, key, _jwks_server) =
            test_router_with_timing(Duration::from_millis(20), Duration::from_millis(200)).await;
        let now = unix_timestamp();
        let identity = sign_identity(&key, AUDIENCE, now, now + 60);
        let request = mcp_request(&initialize_body(), Some(CURRENT), Some(&identity));

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn health_endpoint_is_minimal_and_does_not_require_mcp_credentials() {
        let (router, _key, _jwks_server) = test_router().await;
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await,
            json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") })
        );
    }
}
