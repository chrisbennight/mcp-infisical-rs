use std::sync::{
    Barrier,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use serde_json::json;

use super::*;

struct ManualClock {
    origin: Instant,
    seconds: AtomicU64,
}
impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.origin + Duration::from_secs(self.seconds.load(Ordering::SeqCst))
    }
}

#[derive(Default)]
struct Recorder {
    fail: AtomicBool,
    events: Mutex<Vec<String>>,
}
impl ApprovalRecorder for Recorder {
    fn record(&self, event: &ApprovalEvent) -> Result<(), ApprovalRecordError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ApprovalRecordError);
        }
        self.events
            .lock()
            .unwrap()
            .push(serde_json::to_string(event).unwrap());
        Ok(())
    }
}

fn setup(limits: ApprovalLimits) -> (Arc<ApprovalStore>, Arc<Recorder>, Arc<ManualClock>) {
    let recorder = Arc::new(Recorder::default());
    let clock = Arc::new(ManualClock {
        origin: Instant::now(),
        seconds: AtomicU64::new(0),
    });
    let mut store = ApprovalStore::new(limits, recorder.clone()).unwrap();
    store.clock = clock.clone();
    (Arc::new(store), recorder, clock)
}

fn owner() -> ApprovalOwner {
    ApprovalOwner::new(
        "fixture-issuer".into(),
        "fixture-client".into(),
        "fixture-actor".into(),
    )
    .unwrap()
}

fn human() -> HumanApprover {
    HumanApprover::new("fixture-human".into()).unwrap()
}

fn scope(environment: &str) -> ProjectEnvironment {
    ProjectEnvironment::new("fixture-project".into(), environment.into()).unwrap()
}

fn operation(store: &ApprovalStore, arguments: &Value) -> PreparedApproval {
    store
        .prepare(
            "secrets.create",
            arguments,
            Some(scope("fixture-environment")),
        )
        .unwrap()
}

fn timed(store: &ApprovalStore, id: &str, scope: TimedScope, seconds: u64) -> ApprovalSession {
    store
        .decide(
            id,
            &human(),
            ApprovalDecision::ApproveFor {
                duration: Duration::from_secs(seconds),
                scope,
            },
        )
        .unwrap()
}

#[test]
fn a_pending_token_activates_without_replacement_and_single_use_cannot_replay() {
    let (store, _, _) = setup(ApprovalLimits::default());
    let request = operation(&store, &json!({"value": "fixture-value"}));
    let challenge = store.request(owner(), request.clone()).unwrap();
    assert_eq!(challenge.session.state, ApprovalState::Pending);
    assert_eq!(
        store
            .admit(&owner(), &challenge.token, request.clone())
            .err(),
        Some(ApprovalError::Pending)
    );
    let approved = store
        .decide(
            &challenge.session.session_id,
            &human(),
            ApprovalDecision::ApproveOnce,
        )
        .unwrap();
    assert_eq!(approved.remaining_uses, Some(1));
    let permit = store
        .admit(&owner(), &challenge.token, request.clone())
        .unwrap();
    assert!(store.check(&permit).is_ok());
    assert_eq!(
        store.admit(&owner(), &challenge.token, request).err(),
        Some(ApprovalError::Consumed)
    );
    assert_eq!(
        store
            .status(&owner(), &challenge.token)
            .unwrap()
            .remaining_uses,
        Some(0)
    );
}

#[test]
fn exact_approval_binds_arguments_operation_delivery_and_authoritative_scope() {
    let (store, _, _) = setup(ApprovalLimits::default());
    let args = json!({"value": "fixture-secret", "batch": ["a", "b"], "resultDelivery": "file"});
    let request = operation(&store, &args);
    let challenge = store.request(owner(), request.clone()).unwrap();
    store
        .decide(
            &challenge.session.session_id,
            &human(),
            ApprovalDecision::ApproveOnce,
        )
        .unwrap();
    let variants = [
        operation(
            &store,
            &json!({"value":"changed-secret", "batch":["a","b"], "resultDelivery":"file"}),
        ),
        operation(
            &store,
            &json!({"value":"fixture-secret", "batch":["b","a"], "resultDelivery":"file"}),
        ),
        operation(
            &store,
            &json!({"value":"fixture-secret", "batch":["a","b"], "resultDelivery":"inline"}),
        ),
        store
            .prepare("secrets.update", &args, Some(scope("fixture-environment")))
            .unwrap(),
        store
            .prepare("secrets.create", &args, Some(scope("other-environment")))
            .unwrap(),
    ];
    for variant in variants {
        assert_eq!(
            store.admit(&owner(), &challenge.token, variant).err(),
            Some(ApprovalError::RequestMismatch)
        );
    }
    assert!(store.admit(&owner(), &challenge.token, request).is_ok());
}

#[test]
fn object_order_is_canonical_but_secret_values_remain_bound() {
    let (store, _, _) = setup(ApprovalLimits::default());
    let a: Value = serde_json::from_str(r#"{"z": [{"b":2,"a":1}], "a":"fixture-secret"}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"a":"fixture-secret", "z": [{"a":1,"b":2}]}"#).unwrap();
    assert_eq!(
        operation(&store, &a).fingerprint,
        operation(&store, &b).fingerprint
    );
    let (other_store, _, _) = setup(ApprovalLimits::default());
    assert_ne!(
        operation(&store, &a).fingerprint,
        operation(&other_store, &a).fingerprint
    );
}

#[test]
fn streamed_serialization_matches_the_keyed_fingerprint_of_large_escaped_inputs() {
    let (store, _, _) = setup(ApprovalLimits::default());
    let args =
        json!({"secretValue": "synthetic\\\"\nvalue".repeat(2048), "nested": {"z": 2, "a": 1}});
    let target = Some(scope("fixture-environment"));
    let expected_bytes =
        serde_json::to_vec(&("secrets.create", CanonicalValue(&args), &target)).unwrap();
    let expected = hmac::sign(&store.fingerprint_key, &expected_bytes);
    let prepared = store.prepare("secrets.create", &args, target).unwrap();
    assert_eq!(prepared.fingerprint.as_slice(), expected.as_ref());
}

#[test]
fn global_timed_approval_covers_other_operations_only_for_its_owner() {
    let (store, _, _) = setup(ApprovalLimits::default());
    let challenge = store
        .request(owner(), operation(&store, &json!({})))
        .unwrap();
    timed(
        &store,
        &challenge.session.session_id,
        TimedScope::Global,
        300,
    );
    let other_operation = store
        .prepare("projects.list", &json!({"limit": 10}), None)
        .unwrap();
    assert!(
        store
            .admit(&owner(), &challenge.token, other_operation.clone())
            .is_ok()
    );
    for identity in [
        ApprovalOwner::new(
            "another-issuer".into(),
            "fixture-client".into(),
            "fixture-actor".into(),
        )
        .unwrap(),
        ApprovalOwner::new(
            "fixture-issuer".into(),
            "other-client".into(),
            "fixture-actor".into(),
        )
        .unwrap(),
        ApprovalOwner::new(
            "fixture-issuer".into(),
            "fixture-client".into(),
            "other-actor".into(),
        )
        .unwrap(),
    ] {
        assert_eq!(
            store
                .admit(&identity, &challenge.token, other_operation.clone())
                .err(),
            Some(ApprovalError::UnknownSession)
        );
        assert_eq!(
            store.status(&identity, &challenge.token).err(),
            Some(ApprovalError::UnknownSession)
        );
        assert_eq!(
            store.close(&identity, &challenge.token).err(),
            Some(ApprovalError::UnknownSession)
        );
    }
}

#[test]
fn scoped_timed_approval_accepts_only_proven_matching_environment_effects() {
    let (store, _, _) = setup(ApprovalLimits::default());
    let challenge = store
        .request(owner(), operation(&store, &json!({})))
        .unwrap();
    timed(
        &store,
        &challenge.session.session_id,
        TimedScope::ProjectEnvironment,
        900,
    );
    let same = store
        .prepare(
            "secrets.reveal",
            &json!({}),
            Some(scope("fixture-environment")),
        )
        .unwrap();
    assert!(store.admit(&owner(), &challenge.token, same).is_ok());
    for target in [
        None,
        Some(scope("other-environment")),
        Some(
            ProjectEnvironment::new("other-project".into(), "fixture-environment".into()).unwrap(),
        ),
    ] {
        let other = store.prepare("secrets.reveal", &json!({}), target).unwrap();
        assert_eq!(
            store.admit(&owner(), &challenge.token, other).err(),
            Some(ApprovalError::ScopeMismatch)
        );
    }
    let unscoped = store
        .request(
            owner(),
            store.prepare("projects.list", &json!({}), None).unwrap(),
        )
        .unwrap();
    let refused = store.decide(
        &unscoped.session.session_id,
        &human(),
        ApprovalDecision::ApproveFor {
            duration: Duration::from_secs(300),
            scope: TimedScope::ProjectEnvironment,
        },
    );
    assert_eq!(refused.err(), Some(ApprovalError::ScopeMismatch));
    assert_eq!(
        store.status(&owner(), &unscoped.token).unwrap().state,
        ApprovalState::Pending
    );
}

#[test]
fn elapsed_time_starts_at_decision_and_status_never_extends_approval() {
    let (store, _, clock) = setup(ApprovalLimits::default());
    let challenge = store
        .request(owner(), operation(&store, &json!({})))
        .unwrap();
    clock.seconds.store(100, Ordering::SeqCst);
    assert_eq!(
        timed(
            &store,
            &challenge.session.session_id,
            TimedScope::Global,
            300
        )
        .remaining_seconds,
        300
    );
    clock.seconds.store(399, Ordering::SeqCst);
    assert_eq!(
        store
            .status(&owner(), &challenge.token)
            .unwrap()
            .remaining_seconds,
        1
    );
    clock.seconds.store(400, Ordering::SeqCst);
    assert_eq!(
        store.status(&owner(), &challenge.token).unwrap().state,
        ApprovalState::Expired
    );
    assert_eq!(
        store
            .admit(&owner(), &challenge.token, operation(&store, &json!({})))
            .err(),
        Some(ApprovalError::Expired)
    );
}

#[test]
fn pending_expiry_and_close_prevent_late_approval() {
    let (store, _, clock) = setup(ApprovalLimits::default());
    let expired = store
        .request(owner(), operation(&store, &json!({})))
        .unwrap();
    clock.seconds.store(900, Ordering::SeqCst);
    assert_eq!(
        store
            .decide(
                &expired.session.session_id,
                &human(),
                ApprovalDecision::ApproveOnce
            )
            .err(),
        Some(ApprovalError::AlreadyDecided)
    );
    let closed = store
        .request(owner(), operation(&store, &json!({})))
        .unwrap();
    assert_eq!(
        store.close(&owner(), &closed.token).unwrap().state,
        ApprovalState::Closed
    );
    assert_eq!(
        store.close(&owner(), &closed.token).unwrap().state,
        ApprovalState::Closed
    );
    assert_eq!(
        store
            .decide(
                &closed.session.session_id,
                &human(),
                ApprovalDecision::ApproveOnce
            )
            .err(),
        Some(ApprovalError::AlreadyDecided)
    );
}

#[test]
fn deny_remains_denied_on_retry_and_cannot_be_approved_afterward() {
    let (store, _, _) = setup(ApprovalLimits::default());
    let request = operation(&store, &json!({}));
    let challenge = store.request(owner(), request.clone()).unwrap();
    store
        .decide(
            &challenge.session.session_id,
            &human(),
            ApprovalDecision::Deny,
        )
        .unwrap();
    assert_eq!(
        store.admit(&owner(), &challenge.token, request).err(),
        Some(ApprovalError::Denied)
    );
    assert_eq!(
        store
            .decide(
                &challenge.session.session_id,
                &human(),
                ApprovalDecision::ApproveOnce
            )
            .err(),
        Some(ApprovalError::AlreadyDecided)
    );
}

#[test]
fn permits_are_invalid_after_revocation_closure_or_expiry() {
    for mode in [ApprovalMode::Once, ApprovalMode::Global] {
        for end in [
            ApprovalState::Revoked,
            ApprovalState::Closed,
            ApprovalState::Expired,
        ] {
            let (store, _, clock) = setup(ApprovalLimits::default());
            let request = operation(&store, &json!({}));
            let challenge = store.request(owner(), request.clone()).unwrap();
            if mode == ApprovalMode::Once {
                store
                    .decide(
                        &challenge.session.session_id,
                        &human(),
                        ApprovalDecision::ApproveOnce,
                    )
                    .unwrap();
            } else {
                timed(
                    &store,
                    &challenge.session.session_id,
                    TimedScope::Global,
                    300,
                );
            }
            let permit = store.admit(&owner(), &challenge.token, request).unwrap();
            match end {
                ApprovalState::Revoked => {
                    store
                        .revoke(&challenge.session.session_id, &human())
                        .unwrap();
                }
                ApprovalState::Closed => {
                    store.close(&owner(), &challenge.token).unwrap();
                }
                ApprovalState::Expired => clock.seconds.store(300, Ordering::SeqCst),
                _ => unreachable!(),
            }
            assert!(store.check(&permit).is_err());
        }
    }
}

#[test]
fn simultaneous_retries_admit_only_one_single_use_attempt() {
    let (store, _, _) = setup(ApprovalLimits::default());
    let request = operation(&store, &json!({}));
    let challenge = store.request(owner(), request.clone()).unwrap();
    store
        .decide(
            &challenge.session.session_id,
            &human(),
            ApprovalDecision::ApproveOnce,
        )
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let store = store.clone();
            let request = request.clone();
            let barrier = barrier.clone();
            let token = ApprovalToken::parse(challenge.token.expose_secret().to_owned()).unwrap();
            std::thread::spawn(move || {
                barrier.wait();
                store.admit(&owner(), &token, request).is_ok()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        1
    );
}

#[test]
fn required_recording_failure_cannot_activate_or_consume_permission() {
    let (store, recorder, _) = setup(ApprovalLimits::default());
    let request = operation(&store, &json!({}));
    let challenge = store.request(owner(), request.clone()).unwrap();
    recorder.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        store
            .decide(
                &challenge.session.session_id,
                &human(),
                ApprovalDecision::ApproveOnce
            )
            .err(),
        Some(ApprovalError::RecordingFailed)
    );
    assert_eq!(
        store.status(&owner(), &challenge.token).unwrap().state,
        ApprovalState::Pending
    );
    recorder.fail.store(false, Ordering::SeqCst);
    store
        .decide(
            &challenge.session.session_id,
            &human(),
            ApprovalDecision::ApproveOnce,
        )
        .unwrap();
    recorder.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        store
            .admit(&owner(), &challenge.token, request.clone())
            .err(),
        Some(ApprovalError::RecordingFailed)
    );
    assert_eq!(
        store
            .status(&owner(), &challenge.token)
            .unwrap()
            .remaining_uses,
        Some(1)
    );
    recorder.fail.store(false, Ordering::SeqCst);
    let permit = store.admit(&owner(), &challenge.token, request).unwrap();
    recorder.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        store.revoke(&challenge.session.session_id, &human()).err(),
        Some(ApprovalError::RecordingFailed)
    );
    assert_eq!(store.check(&permit), Err(ApprovalError::Revoked));
}

#[test]
fn per_owner_and_global_capacity_are_bounded_and_expiry_reclaims_capacity() {
    let limits = ApprovalLimits {
        max_sessions: 2,
        max_pending_per_owner: 1,
        ..ApprovalLimits::default()
    };
    let (store, _, clock) = setup(limits);
    let request = operation(&store, &json!({}));
    store.request(owner(), request.clone()).unwrap();
    assert_eq!(
        store.request(owner(), request.clone()).err(),
        Some(ApprovalError::Capacity)
    );
    let other = ApprovalOwner::new(
        "fixture-issuer".into(),
        "second-client".into(),
        "fixture-actor".into(),
    )
    .unwrap();
    store.request(other, request.clone()).unwrap();
    assert_eq!(
        store.request(owner(), request.clone()).err(),
        Some(ApprovalError::Capacity)
    );
    clock.seconds.store(900, Ordering::SeqCst);
    assert!(store.request(owner(), request).is_ok());
}

#[test]
fn ordinary_new_requests_do_not_discard_a_consumed_but_running_once_permit() {
    let (store, _, _) = setup(ApprovalLimits::default());
    let request = operation(&store, &json!({}));
    let challenge = store.request(owner(), request.clone()).unwrap();
    store
        .decide(
            &challenge.session.session_id,
            &human(),
            ApprovalDecision::ApproveOnce,
        )
        .unwrap();
    let permit = store
        .admit(&owner(), &challenge.token, request.clone())
        .unwrap();
    store.request(owner(), request).unwrap();
    assert!(store.check(&permit).is_ok());
}

#[test]
fn tokens_and_submitted_values_are_absent_from_metadata_events_and_formatting() {
    let (store, recorder, _) = setup(ApprovalLimits::default());
    let secret = "submitted-secret-canary";
    let request = operation(&store, &json!({"secretValue": secret}));
    let challenge = store.request(owner(), request.clone()).unwrap();
    timed(
        &store,
        &challenge.session.session_id,
        TimedScope::Global,
        300,
    );
    store.admit(&owner(), &challenge.token, request).unwrap();
    let view = serde_json::to_string(&store.status(&owner(), &challenge.token).unwrap()).unwrap();
    let metadata = format!(
        "{}{}{}{:?}",
        view,
        recorder.events.lock().unwrap().join(""),
        challenge.token,
        challenge.token
    );
    assert!(!metadata.contains(secret));
    assert!(!metadata.contains(challenge.token.expose_secret()));
    assert!(metadata.contains("redacted"));
    assert!(!metadata.contains("fingerprint"));
    assert!(ApprovalToken::parse("malformed-sensitive-input".into()).is_err());
}

#[test]
fn a_new_store_cannot_reuse_tokens_after_restart() {
    let (store, _, _) = setup(ApprovalLimits::default());
    let challenge = store
        .request(owner(), operation(&store, &json!({})))
        .unwrap();
    timed(
        &store,
        &challenge.session.session_id,
        TimedScope::Global,
        300,
    );
    let (restarted, _, _) = setup(ApprovalLimits::default());
    assert_eq!(
        restarted.status(&owner(), &challenge.token).err(),
        Some(ApprovalError::UnknownSession)
    );
}

#[test]
fn invalid_limits_and_duration_do_not_create_authority() {
    let limits = ApprovalLimits {
        max_sessions: 0,
        ..ApprovalLimits::default()
    };
    assert_eq!(
        ApprovalStore::new(limits, Arc::new(Recorder::default())).err(),
        Some(ApprovalError::InvalidConfiguration)
    );
    let (store, _, _) = setup(ApprovalLimits::default());
    let challenge = store
        .request(owner(), operation(&store, &json!({})))
        .unwrap();
    for duration in [Duration::ZERO, Duration::from_secs(86_401)] {
        assert_eq!(
            store
                .decide(
                    &challenge.session.session_id,
                    &human(),
                    ApprovalDecision::ApproveFor {
                        duration,
                        scope: TimedScope::Global
                    }
                )
                .err(),
            Some(ApprovalError::InvalidDuration)
        );
    }
    assert_eq!(
        store.status(&owner(), &challenge.token).unwrap().state,
        ApprovalState::Pending
    );
}
