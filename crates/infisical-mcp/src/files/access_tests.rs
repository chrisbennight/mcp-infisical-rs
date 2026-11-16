use super::*;
use crate::approval::ApprovalOwner;
use std::sync::atomic::{AtomicBool, Ordering};

fn owner(subject: &str) -> ApprovalOwner {
    ApprovalOwner::new(
        "isolated-issuer".into(),
        subject.into(),
        "isolated-actor".into(),
    )
    .unwrap()
}

fn plane() -> Arc<SecretFilePlane> {
    SecretFilePlane::new_with_upload_ttl(
        FileConfig {
            public_origin: "http://localhost".into(),
            ttl: Duration::from_secs(1),
            max_staged: 4,
            max_staged_bytes: MAX_ENVELOPE_BYTES * 4,
        },
        Duration::from_secs(60),
    )
}

#[tokio::test]
async fn result_reference_is_owner_bound_and_withdrawal_blocks_its_download() {
    let plane = plane();
    let active = Arc::new(AtomicBool::new(true));
    let guard: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new({
        let active = Arc::clone(&active);
        move || active.load(Ordering::SeqCst)
    });
    let reference = with_access(Some(owner("alice")), Some(guard), async {
        let slot = plane.reserve().unwrap();
        slot.stage(
            "secrets.reveal",
            secret_envelope(
                "secrets.reveal",
                serde_json::json!({"value":"isolated-value"}),
            )
            .unwrap(),
        )
    })
    .await;
    assert!(
        with_access(Some(owner("bob")), None, async {
            plane.authorize_download(&reference.uri)
        })
        .await
        .is_err()
    );
    let descriptor = with_access(Some(owner("alice")), None, async {
        plane.authorize_download(&reference.uri)
    })
    .await
    .unwrap();
    let id = descriptor.download.url.rsplit('/').next().unwrap();
    let credential = &descriptor.download.headers[TRANSFER_CREDENTIAL_HEADER];
    active.store(false, Ordering::SeqCst);
    assert!(plane.serve(id, credential).is_err());
}

#[tokio::test]
async fn uploads_survive_approval_waits_without_extending_result_lifetimes() {
    let plane = plane();
    let authorization = with_access(Some(owner("alice")), None, async {
        plane.authorize_upload(AuthorizeUploadParams {
            size: Some(6),
            ..Default::default()
        })
    })
    .await
    .unwrap();
    let upload_id = authorization.upload.url.rsplit('/').next().unwrap();
    plane
        .claim_upload(
            upload_id,
            &authorization.upload.headers[TRANSFER_CREDENTIAL_HEADER],
        )
        .unwrap()
        .complete(Zeroizing::new(b"canary".to_vec()))
        .unwrap();
    {
        let id = authorization
            .file
            .uri
            .strip_prefix(STAGED_URI_PREFIX)
            .unwrap();
        plane
            .state
            .lock()
            .unwrap()
            .received
            .get_mut(id)
            .unwrap()
            .staged_at = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
    }
    plane.sweep();
    assert!(
        with_access(Some(owner("bob")), None, async {
            plane.take_received(&authorization.file.uri)
        })
        .await
        .is_none()
    );
    let bytes = with_access(Some(owner("alice")), None, async {
        plane.take_received(&authorization.file.uri)
    })
    .await
    .unwrap();
    assert_eq!(bytes.as_slice(), b"canary");
    let reference = with_access(Some(owner("alice")), None, async {
        plane.reserve().unwrap().stage(
            "projects.list",
            secret_envelope("projects.list", serde_json::json!({"items":[]})).unwrap(),
        )
    })
    .await;
    {
        let id = reference.uri.strip_prefix(STAGED_URI_PREFIX).unwrap();
        plane
            .state
            .lock()
            .unwrap()
            .staged
            .get_mut(id)
            .unwrap()
            .staged_at = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
    }
    plane.sweep();
    assert!(
        with_access(Some(owner("alice")), None, async {
            plane.authorize_download(&reference.uri)
        })
        .await
        .is_err()
    );
}
