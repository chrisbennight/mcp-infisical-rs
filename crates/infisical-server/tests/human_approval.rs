//! Isolated HTTP proof of the complete human approval and explicit retry flow.

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use infisical_api::{ClientSettings, InfisicalClient, SecretValue};
use infisical_mcp::approval::ApprovalLimits;
use infisical_server::{
    auth::GatewayBearers, config::Settings, human_approval::ApprovalSettings, server::build_router,
};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const AGENT: &str = "isolated-agent-bearer-00000000000000000000";
const PROXY: &str = "isolated-human-proxy-bearer-00000000000000";

#[tokio::test]
async fn gateway_tokens_are_bound_to_verified_subject_and_calling_actor() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let mut f = Fixture::new().await;
    let key = SigningKey::from_bytes(&[31; 32]);
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys":[{
            "kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"approval-test",
            "x":URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
        }]})))
        .mount(&f.api)
        .await;
    f.settings.identity = Some(infisical_server::auth::IdentityVerifierSettings {
        jwks_url: Url::parse(&format!("{}/jwks", f.api.uri())).unwrap(),
        issuer: "https://gateway.example.test".into(),
        allow_private_http: false,
        request_timeout: Duration::from_secs(2),
        cache_ttl: Duration::from_secs(60),
    });
    f.router = build_router(&f.settings, &f.cancellation).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let identity = |subject: &str, actor: &str| {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("approval-test".into());
        encode(&header, &json!({"iss":"https://gateway.example.test","sub":subject,"aud":"infisical","iat":now,"exp":now+60,"groups":[],"act":{"sub":actor}}),
            &EncodingKey::from_ed_der(key.to_pkcs8_der().unwrap().as_bytes())).unwrap()
    };
    let owner = identity("client-a", "agent-a");
    let call = |token: Option<&str>| json!({"name":"infisical.read","arguments":{"operation_id":"projects.list","approvalToken":token}});
    let first = raw_rpc(&f.router, "tools/call", call(None), Some(&owner)).await;
    let (token, id) = offer(&first);
    f.decide(
        id,
        json!({"decision":"timed","durationSeconds":300,"scope":"global"}),
    )
    .await;
    for wrong in [
        identity("client-b", "agent-a"),
        identity("client-a", "agent-b"),
    ] {
        let response = raw_rpc(&f.router, "tools/call", call(Some(token)), Some(&wrong)).await;
        let guidance = &response["result"]["structuredContent"]["approval"];
        assert_eq!(guidance["reason"], "unknownSession");
        assert!(guidance.get("session").is_none());
        let close = raw_rpc(
            &f.router,
            "tools/call",
            json!({"name":"approval.session","arguments":{"approvalToken":token,"action":"close"}}),
            Some(&wrong),
        )
        .await;
        assert!(close.get("error").is_some());
    }
    assert!(
        f.api
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.url.path() == "/jwks")
    );
    let result = raw_rpc(&f.router, "tools/call", call(Some(token)), Some(&owner)).await;
    assert_ne!(result["result"]["isError"], true);
}

async fn transfer(
    router: &Router,
    descriptor: &Value,
    body: Option<&str>,
) -> axum::response::Response {
    let route = descriptor["url"]
        .as_str()
        .unwrap()
        .strip_prefix("http://localhost")
        .unwrap();
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(descriptor["method"].as_str().unwrap())
                .uri(route)
                .header("Host", "localhost")
                .header(
                    "Infisical-Transfer-Credential",
                    descriptor["headers"]["Infisical-Transfer-Credential"]
                        .as_str()
                        .unwrap(),
                )
                .body(body.map_or_else(Body::empty, |value| Body::from(value.to_owned())))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn approval_preserves_governed_uploads_and_result_files_and_revokes_downloads() {
    let mut f = Fixture::new().await;
    f.settings.files = Some(infisical_server::config::FileSettings {
        public_origin: "http://localhost".into(),
        ttl: Duration::from_secs(120),
        max_staged: 4,
        max_staged_bytes: 4 * infisical_mcp::files::MAX_ENVELOPE_BYTES,
    });
    f.router = build_router(&f.settings, &f.cancellation).unwrap();
    Mock::given(method("POST")).and(path("/api/v4/secrets/APP_KEY"))
        .and(wiremock::matchers::body_partial_json(json!({"secretValue":"approval-upload-canary"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"secret":{
            "id":"secret-1","environment":"prod","version":1,"type":"shared","secretKey":"APP_KEY",
            "secretValue":"approval-upload-canary","createdAt":"2026-11-16T12:00:00.000Z","updatedAt":"2026-11-16T12:00:00.000Z"
        }}))).expect(1).mount(&f.api).await;
    let upload = raw_rpc(
        &f.router,
        "files/authorizeUpload",
        json!({"name":"APP_KEY","mimeType":"text/plain"}),
        None,
    )
    .await;
    assert_eq!(
        transfer(
            &f.router,
            &upload["result"]["upload"],
            Some("approval-upload-canary")
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let arguments = json!({"target":{"projectId":"project-1","environment":"prod","path":"/","name":"APP_KEY"},"secretValueFile":upload["result"]["file"]["uri"]});
    let first = f
        .rpc(
            "infisical.write",
            json!({"operation_id":"secrets.create","arguments":arguments}),
        )
        .await;
    let (token, id) = offer(&first);
    assert_eq!(f.requests().await, 0);
    f.decide(id, json!({"decision":"once"})).await;
    let result = f
        .rpc(
            "infisical.write",
            json!({"operation_id":"secrets.create","arguments":arguments,"approvalToken":token}),
        )
        .await;
    assert_ne!(result["result"]["isError"], true);
    assert!(!result.to_string().contains("approval-upload-canary"));
    assert_eq!(f.requests().await, 2);

    let first = f
        .rpc(
            "infisical.read",
            json!({"operation_id":"projects.list","resultDelivery":"file"}),
        )
        .await;
    let (token, id) = offer(&first);
    f.decide(
        id,
        json!({"decision":"timed","durationSeconds":300,"scope":"global"}),
    )
    .await;
    let result = f
        .rpc(
            "infisical.read",
            json!({"operation_id":"projects.list","resultDelivery":"file","approvalToken":token}),
        )
        .await;
    assert_ne!(result["result"]["isError"], true);
    let uri = &result["result"]["structuredContent"]["resultFile"]["uri"];
    let authorized = raw_rpc(
        &f.router,
        "files/authorizeDownload",
        json!({"uri":uri}),
        None,
    )
    .await;
    assert_eq!(
        transfer(&f.router, &authorized["result"]["download"], None)
            .await
            .status(),
        StatusCode::OK
    );
    let another = f
        .rpc(
            "infisical.read",
            json!({"operation_id":"projects.list","resultDelivery":"file","approvalToken":token}),
        )
        .await;
    let authorized = raw_rpc(
        &f.router,
        "files/authorizeDownload",
        json!({"uri":another["result"]["structuredContent"]["resultFile"]["uri"]}),
        None,
    )
    .await;
    f.decide(id, json!({"decision":"revoke"})).await;
    assert_eq!(
        transfer(&f.router, &authorized["result"]["download"], None)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
}

struct Fixture {
    api: MockServer,
    settings: Settings,
    router: Router,
    cancellation: CancellationToken,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl Fixture {
    async fn new() -> Self {
        let api = MockServer::start().await;
        Mock::given(method("POST")).and(path("/api/v1/auth/universal-auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accessToken":"isolated-upstream-token", "expiresIn":3600,"accessTokenMaxTTL":3600,"tokenType":"Bearer"}))).mount(&api).await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"projects":[]})))
            .mount(&api)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v4/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"secrets":[]})))
            .mount(&api)
            .await;
        let settings = Settings {
            approval: Some(ApprovalSettings {
                public_origin: Url::parse("http://localhost").unwrap(),
                proxy_bearer: Arc::new(SecretValue::new(PROXY)),
                trusted_proxy_ips: vec!["127.0.0.1".parse().unwrap()],
                approver_users: vec!["alice".into()],
                approver_groups: vec![],
                denied_users: vec!["agent-account".into()],
                duration_presets: vec![300, 900, 3600, 86400],
                limits: ApprovalLimits {
                    pending_ttl: Duration::from_mins(15),
                    once_ttl: Duration::from_secs(300),
                    max_duration: Duration::from_hours(24),
                    max_sessions: 32,
                    max_pending_per_owner: 16,
                },
            }),
            operation_profile: infisical_mcp::policy::OperationProfile::Full,
            host: "127.0.0.1".into(),
            port: 8000,
            log_level: "info".into(),
            allowed_hosts: vec!["localhost".into()],
            allowed_origins: vec![],
            request_timeout: Duration::from_secs(10),
            max_concurrent_requests: 8,
            max_body_bytes: 128 * 1024,
            bearers: Arc::new(GatewayBearers::new(AGENT.into(), None).unwrap()),
            identity: None,
            infisical: InfisicalClient::new(ClientSettings::new(
                Url::parse(&api.uri()).unwrap(),
                "isolated-client".into(),
                SecretValue::new("isolated-client-secret"),
            ))
            .unwrap(),
            files: None,
        };
        let cancellation = CancellationToken::new();
        let router = build_router(&settings, &cancellation).unwrap();
        Self {
            api,
            settings,
            router,
            cancellation,
        }
    }

    async fn rpc(&self, name: &str, arguments: Value) -> Value {
        rpc(&self.router, name, arguments).await
    }
    async fn human(
        &self,
        route: &str,
        body: Option<Value>,
        csrf: Option<&str>,
    ) -> (StatusCode, Vec<u8>) {
        human(
            &self.router,
            route,
            body,
            csrf,
            PROXY,
            "alice",
            "127.0.0.1:32100",
        )
        .await
    }
    async fn context(&self) -> Value {
        let (status, body) = self.human("/approval/api", None, None).await;
        assert_eq!(status, StatusCode::OK);
        serde_json::from_slice(&body).unwrap()
    }
    async fn decide(&self, session: &str, decision: Value) {
        let context = self.context().await;
        let (status, _) = self
            .human(
                &format!("/approval/api/sessions/{session}"),
                Some(decision),
                context["csrf"].as_str(),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }
    async fn requests(&self) -> usize {
        self.api.received_requests().await.unwrap().len()
    }
}

async fn rpc(router: &Router, name: &str, arguments: Value) -> Value {
    raw_rpc(
        router,
        "tools/call",
        json!({"name":name,"arguments":arguments}),
        None,
    )
    .await
}

async fn raw_rpc(router: &Router, method: &str, params: Value, identity: Option<&str>) -> Value {
    let mut request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {AGENT}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2025-11-25");
    if let Some(identity) = identity {
        request = request.header("X-MCP-Identity", identity);
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(Body::from(
                    serde_json::to_vec(
                        &json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}),
                    )
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(
        &to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn human(
    router: &Router,
    route: &str,
    body: Option<Value>,
    csrf: Option<&str>,
    credential: &str,
    user: &str,
    peer: &str,
) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder()
        .method(if body.is_some() { "POST" } else { "GET" })
        .uri(route)
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {credential}"))
        .header("X-Authentik-Username", user)
        .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    if let Some(csrf) = csrf {
        request = request
            .header("Origin", "http://localhost")
            .header("X-CSRF-Token", csrf);
    }
    let request = if let Some(body) = body {
        request
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    } else {
        request.body(Body::empty()).unwrap()
    };
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    assert_eq!(response.headers()["cache-control"], "no-store");
    (
        status,
        to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
}

fn offer(response: &Value) -> (&str, &str) {
    assert_eq!(response["result"]["isError"], true);
    let guidance = &response["result"]["structuredContent"]["approval"];
    (
        guidance["approvalToken"].as_str().unwrap(),
        guidance["session"]["sessionId"].as_str().unwrap(),
    )
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn human_approval_http_rejects_approves_retries_and_manages_sessions() {
    let f = Fixture::new().await;
    let caps = f.rpc("server.capabilities", json!({})).await;
    assert_eq!(
        caps["result"]["structuredContent"]["runtime"]["humanApproval"],
        true
    );
    let first = f
        .rpc(
            "infisical.read",
            json!({"operation_id":"projects.list","arguments":{"limit":5}}),
        )
        .await;
    let (token, id) = offer(&first);
    let url = first["result"]["structuredContent"]["approval"]["approvalUrl"]
        .as_str()
        .unwrap();
    assert!(url.contains("/approval?request="));
    assert!(!url.contains(token));
    assert_eq!(f.requests().await, 0);
    let pending = f
        .rpc(
            "infisical.read",
            json!({"operation_id":"projects.list","arguments":{"limit":5},"approvalToken":token}),
        )
        .await;
    assert_eq!(offer(&pending).1, id);
    assert_eq!(f.requests().await, 0);
    let context = f.context().await;
    assert!(!serde_json::to_string(&context).unwrap().contains(token));
    let route = format!("/approval/api/sessions/{id}");
    assert_eq!(
        f.human(&route, Some(json!({"decision":"once"})), None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    f.decide(id, json!({"decision":"once"})).await;
    assert_eq!(f.requests().await, 0);
    let changed = f
        .rpc(
            "infisical.read",
            json!({"operation_id":"projects.list","arguments":{"limit":1},"approvalToken":token}),
        )
        .await;
    assert_eq!(
        changed["result"]["structuredContent"]["approval"]["reason"],
        "requestMismatch"
    );
    assert_eq!(f.requests().await, 0);
    let approved = f
        .rpc(
            "infisical.read",
            json!({"operation_id":"projects.list","arguments":{"limit":5},"approvalToken":token}),
        )
        .await;
    assert_ne!(
        approved["result"]["isError"], true,
        "{}",
        approved["result"]["structuredContent"]["error"]["correction"]
    );
    assert_eq!(f.requests().await, 2);
    let repeated = f
        .rpc(
            "infisical.read",
            json!({"operation_id":"projects.list","arguments":{"limit":5},"approvalToken":token}),
        )
        .await;
    assert_eq!(
        repeated["result"]["structuredContent"]["approval"]["reason"],
        "consumed"
    );
    assert_eq!(f.requests().await, 2);

    let timed = f
        .rpc("infisical.read", json!({"operation_id":"projects.list"}))
        .await;
    let (token, id) = offer(&timed);
    f.decide(
        id,
        json!({"decision":"timed","durationSeconds":900,"scope":"global"}),
    )
    .await;
    for limit in [1, 5] {
        let result = f.rpc("infisical.read", json!({"operation_id":"projects.list","arguments":{"limit":limit},"approvalToken":token})).await;
        assert_ne!(result["result"]["isError"], true);
    }
    assert_eq!(f.requests().await, 4);
    let status = f
        .rpc("approval.session", json!({"approvalToken":token}))
        .await;
    let session = &status["result"]["structuredContent"]["session"];
    assert_eq!(session["state"], "active");
    assert!(session["remainingSeconds"].as_u64().unwrap() > 0);
    let closed = f
        .rpc(
            "approval.session",
            json!({"action":"close","approvalToken":token}),
        )
        .await;
    assert_eq!(
        closed["result"]["structuredContent"]["session"]["state"],
        "closed"
    );
    let denied = f
        .rpc(
            "infisical.read",
            json!({"operation_id":"projects.list","approvalToken":token}),
        )
        .await;
    assert_eq!(
        denied["result"]["structuredContent"]["approval"]["reason"],
        "closed"
    );
    assert_eq!(f.requests().await, 4);
}

#[tokio::test]
async fn scoped_approval_is_exact_to_project_environment_and_can_be_revoked() {
    let f = Fixture::new().await;
    let arguments = json!({"projectId":"project-1","environment":"prod","path":"/"});
    let request = f
        .rpc(
            "infisical.read",
            json!({"operation_id":"secrets.metadata.list","arguments":arguments}),
        )
        .await;
    let (token, id) = offer(&request);
    f.decide(
        id,
        json!({"decision":"timed","durationSeconds":300,"scope":"projectEnvironment"}),
    )
    .await;
    for target in [
        json!({"projectId":"project-2","environment":"prod","path":"/"}),
        json!({"projectId":"project-1","environment":"dev","path":"/"}),
    ] {
        let result = f.rpc("infisical.read", json!({"operation_id":"secrets.metadata.list","arguments":target,"approvalToken":token})).await;
        assert_eq!(
            result["result"]["structuredContent"]["approval"]["reason"],
            "scopeMismatch"
        );
    }
    assert_eq!(f.requests().await, 0);
    let result = f.rpc("infisical.read", json!({"operation_id":"secrets.metadata.list","arguments":arguments,"approvalToken":token})).await;
    assert_ne!(
        result["result"]["isError"], true,
        "{}",
        result["result"]["structuredContent"]["error"]["correction"]
    );
    assert_eq!(f.requests().await, 2);
    f.decide(id, json!({"decision":"revoke"})).await;
    let result = f.rpc("infisical.read", json!({"operation_id":"secrets.metadata.list","arguments":arguments,"approvalToken":token})).await;
    assert_eq!(
        result["result"]["structuredContent"]["approval"]["reason"],
        "revoked"
    );
    assert_eq!(f.requests().await, 2);
}

#[tokio::test]
async fn proxy_credentials_peer_and_human_identity_are_separate_from_agent_access() {
    let f = Fixture::new().await;
    for (credential, user, peer) in [
        (AGENT, "alice", "127.0.0.1:32100"),
        (PROXY, "mallory", "127.0.0.1:32100"),
        (PROXY, "alice", "192.0.2.1:32100"),
        (PROXY, "agent-account", "127.0.0.1:32100"),
    ] {
        assert_eq!(
            human(
                &f.router,
                "/approval/api",
                None,
                None,
                credential,
                user,
                peer
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    let (status, page) = f.human("/approval", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(page).unwrap().contains("Human approval"));
    assert_eq!(
        f.human("/approval/app.js", None, None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        f.human("/approval/app.css", None, None).await.0,
        StatusCode::OK
    );
    assert_eq!(f.requests().await, 0);
}

#[tokio::test]
async fn human_group_access_and_same_origin_decisions_are_enforced_by_the_server() {
    let mut f = Fixture::new().await;
    let settings = f.settings.approval.as_mut().unwrap();
    settings.approver_users.clear();
    settings.approver_groups = vec!["human-approvers".into()];
    f.router = build_router(&f.settings, &f.cancellation).unwrap();
    let request = |user: &str, groups: &str, route: &str, origin: &str, csrf: &str, post: bool| {
        Request::builder()
            .uri(route)
            .method(if post { "POST" } else { "GET" })
            .header("Host", "localhost")
            .header("Authorization", format!("Bearer {PROXY}"))
            .header("X-Authentik-Username", user)
            .header("X-Authentik-Groups", groups)
            .header("Origin", origin)
            .header("X-CSRF-Token", csrf)
            .header("Content-Type", "application/json")
            .extension(ConnectInfo(
                "127.0.0.1:32100".parse::<SocketAddr>().unwrap(),
            ))
            .body(if post {
                Body::from(r#"{"decision":"once"}"#)
            } else {
                Body::empty()
            })
            .unwrap()
    };
    let allowed = f
        .router
        .clone()
        .oneshot(request(
            "alice",
            "other|human-approvers",
            "/approval/api",
            "http://localhost",
            "",
            false,
        ))
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    let context: Value =
        serde_json::from_slice(&to_bytes(allowed.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    let denied = f
        .router
        .clone()
        .oneshot(request(
            "agent-account",
            "human-approvers",
            "/approval/api",
            "http://localhost",
            "",
            false,
        ))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let first = f
        .rpc("infisical.read", json!({"operation_id":"projects.list"}))
        .await;
    let (_, id) = offer(&first);
    let route = format!("/approval/api/sessions/{id}");
    for (origin, csrf) in [
        (
            "https://unrelated.example",
            context["csrf"].as_str().unwrap(),
        ),
        ("http://localhost", "wrong-csrf"),
    ] {
        let result = f
            .router
            .clone()
            .oneshot(request(
                "alice",
                "human-approvers",
                &route,
                origin,
                csrf,
                true,
            ))
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
    }
    let result = f
        .router
        .clone()
        .oneshot(request(
            "alice",
            "human-approvers",
            &route,
            "http://localhost",
            context["csrf"].as_str().unwrap(),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::OK);
    assert_eq!(f.requests().await, 0);
}

#[tokio::test]
async fn every_executor_is_gated_and_human_views_omit_submitted_secrets() {
    let f = Fixture::new().await;
    let target = json!({"projectId":"project-1","environment":"prod","path":"/","name":"APP_KEY"});
    for (executor, operation, arguments) in [
        ("infisical.read", "projects.list", json!({})),
        ("infisical.readAudited", "auditLogs.list", json!({})),
        (
            "infisical.write",
            "secrets.create",
            json!({"target":target,"secretValue":"submitted-secret-must-stay-out-of-dashboard"}),
        ),
        (
            "infisical.destroy",
            "secrets.delete",
            json!({"target":target,"confirm":true}),
        ),
    ] {
        assert_eq!(
            infisical_mcp::executor_for_operation(operation),
            Some(executor),
            "executor for {operation}"
        );
        let result = f
            .rpc(
                executor,
                json!({"operation_id":operation,"arguments":arguments}),
            )
            .await;
        let (token, _) = offer(&result);
        let context = serde_json::to_string(&f.context().await).unwrap();
        assert!(!context.contains(token));
        assert!(!context.contains("submitted-secret-must-stay-out-of-dashboard"));
        if operation == "secrets.create" {
            assert!(context.contains("APP_KEY"));
        }
    }
    assert_eq!(f.requests().await, 0);
    let health = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
}

#[tokio::test]
async fn custom_duration_is_bounded_denial_and_restart_leave_no_permission() {
    let f = Fixture::new().await;
    let request = f
        .rpc("infisical.read", json!({"operation_id":"projects.list"}))
        .await;
    let (token, id) = offer(&request);
    let context = f.context().await;
    assert_eq!(context["durationPresets"], json!([300, 900, 3600, 86400]));
    let route = format!("/approval/api/sessions/{id}");
    let invalid = f
        .human(
            &route,
            Some(json!({"decision":"timed","durationSeconds":86401,"scope":"global"})),
            context["csrf"].as_str(),
        )
        .await;
    assert_eq!(invalid.0, StatusCode::BAD_REQUEST);
    f.decide(
        id,
        json!({"decision":"timed","durationSeconds":420,"scope":"global"}),
    )
    .await;
    let status = f
        .rpc("approval.session", json!({"approvalToken":token}))
        .await;
    assert_eq!(
        status["result"]["structuredContent"]["session"]["state"],
        "active"
    );
    let restarted = build_router(&f.settings, &f.cancellation).unwrap();
    let result = rpc(
        &restarted,
        "infisical.read",
        json!({"operation_id":"projects.list","approvalToken":token}),
    )
    .await;
    assert_eq!(
        result["result"]["structuredContent"]["approval"]["reason"],
        "unknownSession"
    );
    assert_eq!(f.requests().await, 0);
    let denied = f
        .rpc("infisical.read", json!({"operation_id":"projects.list"}))
        .await;
    let (token, id) = offer(&denied);
    f.decide(id, json!({"decision":"deny"})).await;
    let result = f
        .rpc(
            "infisical.read",
            json!({"operation_id":"projects.list","approvalToken":token}),
        )
        .await;
    assert_eq!(
        result["result"]["structuredContent"]["approval"]["reason"],
        "denied"
    );
    assert_eq!(f.requests().await, 0);
}

#[tokio::test]
async fn expired_approval_blocks_new_work_and_disabled_mode_remains_compatible() {
    let mut f = Fixture::new().await;
    let settings = f.settings.approval.as_mut().unwrap();
    settings.duration_presets = vec![1];
    settings.limits.max_duration = Duration::from_secs(1);
    f.router = build_router(&f.settings, &f.cancellation).unwrap();
    let request = f
        .rpc("infisical.read", json!({"operation_id":"projects.list"}))
        .await;
    let (token, id) = offer(&request);
    f.decide(
        id,
        json!({"decision":"timed","durationSeconds":1,"scope":"global"}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let result = f
        .rpc(
            "infisical.read",
            json!({"operation_id":"projects.list","approvalToken":token}),
        )
        .await;
    assert_eq!(
        result["result"]["structuredContent"]["approval"]["reason"],
        "expired"
    );
    assert_eq!(f.requests().await, 0);
    f.settings.approval = None;
    f.router = build_router(&f.settings, &f.cancellation).unwrap();
    let result = f
        .rpc("infisical.read", json!({"operation_id":"projects.list"}))
        .await;
    assert_ne!(result["result"]["isError"], true);
    assert_eq!(f.requests().await, 2);
    let status = f.rpc("approval.session", json!({})).await;
    assert_eq!(status["result"]["structuredContent"]["enabled"], false);
}

#[tokio::test]
async fn startup_refuses_reusing_the_agent_credential_for_human_decisions() {
    let mut f = Fixture::new().await;
    f.settings.approval.as_mut().unwrap().proxy_bearer = Arc::new(SecretValue::new(AGENT));
    assert!(build_router(&f.settings, &f.cancellation).is_err());
}
