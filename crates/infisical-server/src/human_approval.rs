//! Embedded human dashboard behind an independently authenticated Authentik proxy.

use aws_lc_rs::hmac;
use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use infisical_api::SecretValue;
use infisical_mcp::approval::{
    ApprovalDecision, ApprovalError, ApprovalEvent, ApprovalEventKind, ApprovalLimits,
    ApprovalOwner, ApprovalRecordError, ApprovalRecorder, ApprovalService, ApprovalSession,
    ApprovalStore, HumanApprover, TimedScope,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;
use zeroize::Zeroizing;

/// Operator-owned human authentication and bounded approval settings.
#[derive(Clone)]
pub struct ApprovalSettings {
    pub public_origin: Url,
    pub proxy_bearer: Arc<SecretValue>,
    pub trusted_proxy_ips: Vec<IpAddr>,
    pub approver_users: Vec<String>,
    pub approver_groups: Vec<String>,
    pub denied_users: Vec<String>,
    pub duration_presets: Vec<u64>,
    pub limits: ApprovalLimits,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordedEvent {
    at: u64,
    event: ApprovalEvent,
}

struct History {
    entries: Mutex<VecDeque<RecordedEvent>>,
    capacity: usize,
}

impl ApprovalRecorder for History {
    fn record(&self, event: &ApprovalEvent) -> Result<(), ApprovalRecordError> {
        let mut entries = self.entries.lock().map_err(|_| ApprovalRecordError)?;
        if entries.len() == self.capacity {
            entries.pop_front();
        }
        entries.push_back(RecordedEvent {
            at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ApprovalRecordError)?
                .as_secs(),
            event: event.clone(),
        });
        tracing::info!(event = "human_approval", kind = ?event.kind, session_id = %event.session.session_id, operation = event.session.operation, state = ?event.session.state, "human approval event accepted");
        Ok(())
    }
}

pub(crate) struct HumanApproval {
    pub service: Arc<ApprovalService>,
    settings: ApprovalSettings,
    allowed_hosts: Vec<String>,
    csrf_key: hmac::Key,
    history: Arc<History>,
}

#[derive(Clone)]
struct HumanIdentity(String);

impl HumanApproval {
    pub(crate) fn new(
        settings: ApprovalSettings,
        bearers: &crate::auth::GatewayBearers,
        allowed_hosts: Vec<String>,
    ) -> Result<Arc<Self>, ApprovalError> {
        let secret = settings.proxy_bearer.expose_secret();
        if secret.len() < 32
            || secret.len() > 4096
            || secret.bytes().any(|byte| !byte.is_ascii_graphic())
            || bearers.accepts(secret.as_bytes())
            || settings.trusted_proxy_ips.is_empty()
            || settings.approver_users.is_empty() && settings.approver_groups.is_empty()
            || settings.duration_presets.is_empty()
            || settings.duration_presets.len() > 16
            || settings
                .duration_presets
                .iter()
                .any(|seconds| *seconds == 0 || *seconds > settings.limits.max_duration.as_secs())
            || settings
                .approver_users
                .iter()
                .chain(&settings.approver_groups)
                .chain(&settings.denied_users)
                .any(|name| {
                    name.trim().is_empty() || name.len() > 512 || name.chars().any(char::is_control)
                })
        {
            return Err(ApprovalError::InvalidConfiguration);
        }
        let history = Arc::new(History {
            entries: Mutex::new(VecDeque::new()),
            capacity: 1024,
        });
        let store = Arc::new(ApprovalStore::new(
            settings.limits.clone(),
            history.clone(),
        )?);
        let service = Arc::new(ApprovalService::new(store, &settings.public_origin)?);
        let mut key = Zeroizing::new([0; 32]);
        aws_lc_rs::rand::fill(key.as_mut()).expect("platform CSPRNG");
        Ok(Arc::new(Self {
            service,
            settings,
            allowed_hosts,
            csrf_key: hmac::Key::new(hmac::HMAC_SHA256, key.as_ref()),
            history,
        }))
    }

    pub(crate) fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/approval", get(page))
            .route("/approval/app.js", get(script))
            .route("/approval/app.css", get(styles))
            .route("/approval/api", get(snapshot))
            .route("/approval/api/sessions/{id}", post(decide))
            .layer(DefaultBodyLimit::max(4096))
            .layer(middleware::from_fn_with_state(
                Arc::clone(self),
                authenticate,
            ))
            .with_state(Arc::clone(self))
    }

    fn csrf(&self, user: &str) -> String {
        URL_SAFE_NO_PAD.encode(hmac::sign(&self.csrf_key, user.as_bytes()).as_ref())
    }
    fn valid_csrf(&self, headers: &HeaderMap, user: &str) -> bool {
        if crate::auth::single_header(headers, header::ORIGIN.as_str())
            != Some(
                self.settings
                    .public_origin
                    .origin()
                    .ascii_serialization()
                    .as_str(),
            )
        {
            return false;
        }
        let Some(value) =
            crate::auth::single_header(headers, "x-csrf-token").filter(|value| value.len() == 43)
        else {
            return false;
        };
        let Ok(value) = URL_SAFE_NO_PAD.decode(value) else {
            return false;
        };
        hmac::verify(&self.csrf_key, user.as_bytes(), &value).is_ok()
    }
}

async fn authenticate(
    State(app): State<Arc<HumanApproval>>,
    mut request: Request,
    next: Next,
) -> Response {
    let allowed = (|| {
        let peer = request.extensions().get::<ConnectInfo<SocketAddr>>()?;
        if !app.settings.trusted_proxy_ips.contains(&peer.0.ip())
            || !crate::auth::allowed_host(request.headers(), &app.allowed_hosts)
            || request.headers().contains_key(crate::auth::IDENTITY_HEADER)
        {
            return None;
        }
        let token = crate::auth::bearer_token(request.headers())?;
        if aws_lc_rs::constant_time::verify_slices_are_equal(
            token.as_bytes(),
            app.settings.proxy_bearer.expose_secret().as_bytes(),
        )
        .is_err()
        {
            return None;
        }
        let user = crate::auth::single_header(request.headers(), "x-authentik-username")?;
        HumanApprover::new(user.to_owned()).ok()?;
        if app
            .settings
            .denied_users
            .iter()
            .any(|denied| denied == user)
        {
            return None;
        }
        let groups =
            crate::auth::single_header(request.headers(), "x-authentik-groups").unwrap_or("");
        if groups.len() > 4096 {
            return None;
        }
        if !app
            .settings
            .approver_users
            .iter()
            .any(|allowed| allowed == user)
            && !groups.split('|').any(|group| {
                app.settings
                    .approver_groups
                    .iter()
                    .any(|allowed| allowed == group)
            })
        {
            return None;
        }
        Some(HumanIdentity(user.to_owned()))
    })();
    let mut response = if let Some(human) = allowed {
        request.extensions_mut().insert(human);
        next.run(request).await
    } else {
        refusal(
            StatusCode::FORBIDDEN,
            "Human approval requires the configured Authentik proxy and an authorized human account",
        )
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, header::HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    response
}

async fn page() -> Response {
    asset(
        "text/html; charset=utf-8",
        include_str!("approval_assets/index.html"),
    )
}
async fn script() -> Response {
    asset(
        "text/javascript; charset=utf-8",
        include_str!("approval_assets/app.js"),
    )
}
async fn styles() -> Response {
    asset(
        "text/css; charset=utf-8",
        include_str!("approval_assets/app.css"),
    )
}
fn asset(content_type: &'static str, value: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], Body::from(value)).into_response()
}
fn refusal(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({"error": message}))).into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    approver: String,
    csrf: String,
    duration_presets: Vec<u64>,
    max_duration_seconds: u64,
    sessions: Vec<HumanSession>,
    history: Vec<RecordedEvent>,
}

#[derive(Serialize)]
struct HumanSession {
    owner: ApprovalOwner,
    session: ApprovalSession,
}

async fn snapshot(
    State(app): State<Arc<HumanApproval>>,
    Extension(human): Extension<HumanIdentity>,
) -> Response {
    let mut sessions: Vec<_> = app
        .service
        .store()
        .sessions()
        .into_iter()
        .map(|(owner, session)| HumanSession { owner, session })
        .collect();
    sessions.sort_by_key(|item| item.session.age_seconds);
    let Ok(history) = app.history.entries.lock() else {
        return refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "Approval history is unavailable",
        );
    };
    let history = history
        .iter()
        .rev()
        .filter(|entry| {
            matches!(
                entry.event.kind,
                ApprovalEventKind::Decided | ApprovalEventKind::Closed | ApprovalEventKind::Revoked
            )
        })
        .cloned()
        .collect();
    Json(Snapshot {
        csrf: app.csrf(&human.0),
        approver: human.0,
        duration_presets: app.settings.duration_presets.clone(),
        max_duration_seconds: app.settings.limits.max_duration.as_secs(),
        sessions,
        history,
    })
    .into_response()
}

#[derive(Deserialize)]
#[serde(
    tag = "decision",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Decision {
    Once,
    Deny,
    Timed { duration_seconds: u64, scope: Scope },
    Revoke,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Scope {
    Global,
    ProjectEnvironment,
}

async fn decide(
    State(app): State<Arc<HumanApproval>>,
    Extension(human): Extension<HumanIdentity>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(decision): Json<Decision>,
) -> Response {
    if !app.valid_csrf(&headers, &human.0) {
        return refusal(
            StatusCode::FORBIDDEN,
            "Refresh the approval page before deciding",
        );
    }
    let human = HumanApprover::new(human.0).expect("identity was validated at ingress");
    let store = app.service.store();
    let result = match decision {
        Decision::Revoke => store.revoke(&id, &human),
        Decision::Once => store.decide(&id, &human, ApprovalDecision::ApproveOnce),
        Decision::Deny => store.decide(&id, &human, ApprovalDecision::Deny),
        Decision::Timed {
            duration_seconds,
            scope,
        } => store.decide(
            &id,
            &human,
            ApprovalDecision::ApproveFor {
                duration: Duration::from_secs(duration_seconds),
                scope: match scope {
                    Scope::Global => TimedScope::Global,
                    Scope::ProjectEnvironment => TimedScope::ProjectEnvironment,
                },
            },
        ),
    };
    match result {
        Ok(session) => Json(session).into_response(),
        Err(error) => refusal(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}
