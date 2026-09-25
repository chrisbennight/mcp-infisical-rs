use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};

use crate::{ClientSettings, InfisicalClient, KmsKeyId, ProjectId, ResourceError, SecretValue};

const PROJECT: &str = "11111111-1111-4111-8111-111111111111";

struct StateData {
    active: AtomicUsize,
    peak: AtomicUsize,
    reads: AtomicUsize,
    bulk_requests: AtomicUsize,
    latency: Duration,
    invalid_key: Option<String>,
}

struct ActiveRequest(Arc<StateData>);

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Fixture {
    state: Arc<StateData>,
    client: InfisicalClient,
    server: JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn key_id(index: usize) -> KmsKeyId {
    KmsKeyId::new(format!("22222222-2222-4222-8222-{index:012}")).unwrap()
}

async fn login() -> Json<Value> {
    Json(
        json!({"accessToken": "local-kms-test-token", "expiresIn": 300,
                "accessTokenMaxTTL": 600, "tokenType": "Bearer"}),
    )
}

async fn read_key(State(state): State<Arc<StateData>>, Path(id): Path<String>) -> Json<Value> {
    state.reads.fetch_add(1, Ordering::SeqCst);
    let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
    state.peak.fetch_max(active, Ordering::SeqCst);
    let _active = ActiveRequest(Arc::clone(&state));
    tokio::time::sleep(state.latency).await;
    Json(json!({"key": {
        "id": id, "name": "application-key", "description": "test key",
        "isDisabled": state.invalid_key.as_ref() == Some(&id),
        "orgId": "44444444-4444-4444-8444-444444444444", "projectId": PROJECT,
        "keyUsage": "encrypt-decrypt", "encryptionAlgorithm": "aes-256-gcm", "version": 1,
        "createdAt": "2026-07-20T01:02:03.000Z", "updatedAt": "2026-07-20T01:02:03.000Z"
    }}))
}

async fn bulk_reveal(State(state): State<Arc<StateData>>, Json(body): Json<Value>) -> Json<Value> {
    state.bulk_requests.fetch_add(1, Ordering::SeqCst);
    let keys = body["keyIds"].as_array().unwrap().iter().rev().map(|id| json!({
        "keyId": id, "name": "application-key", "keyUsage": "encrypt-decrypt",
        "algorithm": "aes-256-gcm", "privateKey": "cHJpdmF0ZS1rZXk=", "publicKey": "cHVibGljLWtleQ=="
    })).collect::<Vec<_>>();
    Json(json!({"keys": keys}))
}

async fn fixture(
    concurrency: usize,
    timeout: Duration,
    latency: Duration,
    invalid_key: Option<String>,
) -> Fixture {
    let state = Arc::new(StateData {
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        bulk_requests: AtomicUsize::new(0),
        latency,
        invalid_key,
    });
    let router = Router::new()
        .route("/api/v1/auth/universal-auth/login", post(login))
        .route("/api/v1/kms/keys/{id}", get(read_key))
        .route(
            "/api/v1/kms/keys/bulk-export-private-keys",
            post(bulk_reveal),
        )
        .with_state(Arc::clone(&state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let mut settings = ClientSettings::new(
        format!("http://{address}").parse().unwrap(),
        "local-kms-client".into(),
        SecretValue::new("local-kms-secret"),
    );
    settings.max_concurrent_requests = concurrency;
    settings.request_timeout = timeout;
    Fixture {
        state,
        client: InfisicalClient::new(settings).unwrap(),
        server,
    }
}

#[tokio::test]
async fn parallel_preflights_reduce_controlled_latency_and_preserve_requested_order() {
    let fixture = fixture(
        32,
        Duration::from_secs(10),
        Duration::from_millis(100),
        None,
    )
    .await;
    let project = ProjectId::new(PROJECT).unwrap();
    let ids = (0..8).map(key_id).collect::<Vec<_>>();
    let sequential_started = Instant::now();
    for id in &ids {
        fixture.client.get_kms_key(&project, id).await.unwrap();
    }
    let sequential_elapsed = sequential_started.elapsed();
    let parallel_started = Instant::now();
    let keys = fixture
        .client
        .bulk_reveal_kms_private_keys(&project, ids.clone(), true)
        .await
        .unwrap();
    let parallel_elapsed = parallel_started.elapsed();
    assert!(
        parallel_elapsed < sequential_elapsed,
        "parallel={parallel_elapsed:?}, sequential={sequential_elapsed:?}"
    );
    assert_eq!(fixture.state.peak.load(Ordering::SeqCst), 8);
    assert_eq!(fixture.state.bulk_requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        keys.iter()
            .map(|key| key.key_id.as_str())
            .collect::<Vec<_>>(),
        ids.iter().map(KmsKeyId::as_str).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn separate_bulk_calls_and_client_clones_share_one_http_budget() {
    let fixture = fixture(3, Duration::from_secs(10), Duration::from_millis(50), None).await;
    let other = fixture.client.clone();
    let project = ProjectId::new(PROJECT).unwrap();
    let first =
        fixture
            .client
            .bulk_reveal_kms_private_keys(&project, (0..8).map(key_id).collect(), true);
    let second = other.bulk_reveal_kms_private_keys(&project, (8..16).map(key_id).collect(), true);
    let (first, second) = tokio::join!(first, second);
    assert_eq!(first.unwrap().len(), 8);
    assert_eq!(second.unwrap().len(), 8);
    assert_eq!(fixture.state.peak.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.state.bulk_requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn failed_validation_never_sends_the_bulk_request() {
    let fixture = fixture(
        3,
        Duration::from_secs(10),
        Duration::from_millis(20),
        Some(key_id(1).as_str().to_owned()),
    )
    .await;
    let error = fixture
        .client
        .bulk_reveal_kms_private_keys(
            &ProjectId::new(PROJECT).unwrap(),
            (0..8).map(key_id).collect(),
            true,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ResourceError::KmsBulkPreflightFailed { requested: 8, .. }
    ));
    assert!(error.to_string().contains("access events"));
    assert!(error.to_string().contains("was not sent"));
    assert_eq!(fixture.state.bulk_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn total_preflight_deadline_stops_a_batch_that_individual_timeouts_would_allow() {
    let fixture = fixture(
        2,
        Duration::from_millis(300),
        Duration::from_millis(50),
        None,
    )
    .await;
    let error = tokio::time::timeout(
        Duration::from_secs(2),
        fixture.client.bulk_reveal_kms_private_keys(
            &ProjectId::new(PROJECT).unwrap(),
            (0..100).map(key_id).collect(),
            true,
        ),
    )
    .await
    .expect("total deadline must end the batch")
    .unwrap_err();
    match error {
        ResourceError::KmsBulkPreflightTimeout {
            validated,
            requested,
        } => {
            assert!(validated < 100);
            assert_eq!(requested, 100);
        }
        other => panic!("unexpected preflight error: {other}"),
    }
    assert_eq!(fixture.state.bulk_requests.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.peak.load(Ordering::SeqCst), 2);
    assert!(fixture.state.reads.load(Ordering::SeqCst) < 100);
}

#[tokio::test]
async fn invalid_local_input_has_no_upstream_effect() {
    let fixture = fixture(3, Duration::from_secs(10), Duration::ZERO, None).await;
    for (ids, confirm) in [
        (vec![key_id(0)], false),
        (vec![key_id(0), key_id(0)], true),
        (vec![], true),
    ] {
        assert!(
            fixture
                .client
                .bulk_reveal_kms_private_keys(&ProjectId::new(PROJECT).unwrap(), ids, confirm)
                .await
                .is_err()
        );
    }
    assert_eq!(fixture.state.reads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.bulk_requests.load(Ordering::SeqCst), 0);
}
