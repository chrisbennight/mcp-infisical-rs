use super::*;

fn unconfirmed_kms_requests(project_id: &str, key_id: &str) -> [(&'static str, Value); 10] {
    let target = json!({ "projectId": project_id, "keyId": key_id });
    [
        (
            "kms.keys.create",
            json!({
                "projectId": project_id,
                "name": "application-key",
                "keyUsage": "encrypt-decrypt",
                "algorithm": "aes-256-gcm",
                "confirm": false
            }),
        ),
        (
            "kms.keys.update",
            json!({ "target": target, "disabled": true, "confirm": false }),
        ),
        (
            "kms.keys.delete",
            json!({ "target": target, "confirm": false }),
        ),
        (
            "kms.encrypt",
            json!({ "target": target, "data": "cGxhaW50ZXh0", "confirm": false }),
        ),
        (
            "kms.decrypt",
            json!({
                "target": target,
                "ciphertext": "Y2lwaGVydGV4dA==",
                "confirmReveal": false
            }),
        ),
        (
            "kms.keys.privateKey.reveal",
            json!({ "target": target, "confirmReveal": false }),
        ),
        (
            "kms.keys.bulkImport",
            json!({
                "projectId": project_id,
                "keys": [{
                    "name": "imported-key",
                    "keyUsage": "encrypt-decrypt",
                    "algorithm": "aes-256-gcm",
                    "keyMaterial": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                }],
                "confirm": false
            }),
        ),
        (
            "kms.keys.privateKeys.bulkReveal",
            json!({
                "projectId": project_id,
                "keyIds": [key_id],
                "confirmReveal": false
            }),
        ),
        (
            "kms.sign",
            json!({
                "target": target,
                "data": "cGxhaW50ZXh0",
                "signingAlgorithm": "RSASSA_PSS_SHA_256",
                "confirm": false
            }),
        ),
        (
            "kms.verify",
            json!({
                "target": target,
                "data": "cGxhaW50ZXh0",
                "signature": "c2lnbmF0dXJl",
                "signingAlgorithm": "RSASSA_PSS_SHA_256",
                "confirm": false
            }),
        ),
    ]
}

#[tokio::test]
async fn kms_inputs_are_closed_and_confirmations_fail_before_authentication() {
    let server = MockServer::start().await;
    let client = InfisicalClient::new(ClientSettings::new(
        server.uri().parse().unwrap(),
        "handler-client".into(),
        SecretValue::new("handler-client-secret"),
    ))
    .unwrap();
    let project_id = "11111111-1111-4111-8111-111111111111";
    let key_id = "22222222-2222-4222-8222-222222222222";

    assert_unknown_field_rejected::<KmsKeysListInput>(
        "kms.keys.list",
        &json!({ "projectId": project_id, "limt": 10 }),
    );
    assert_unknown_field_rejected::<KmsEncryptInput>(
        "kms.encrypt",
        &json!({
            "target": { "projectId": project_id, "keyId": key_id },
            "data": "cGxhaW50ZXh0",
            "confirm": true,
            "encoding": "base64"
        }),
    );
    assert_unknown_field_rejected::<KmsBulkImportInput>(
        "kms.keys.bulkImport",
        &json!({
            "projectId": project_id,
            "keys": [],
            "confirm": true,
            "continueOnError": true
        }),
    );

    for (name, arguments) in unconfirmed_kms_requests(project_id, key_id) {
        let result = dispatch_tool(&client, None, request(name, &arguments))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true), "{name}");
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn kms_bulk_input_cardinality_is_exact_at_the_mcp_boundary() {
    let project_id = "11111111-1111-4111-8111-111111111111";
    let import_keys = |count: usize| {
        (0..count)
            .map(|index| {
                json!({
                    "name": format!("key-{index}"),
                    "keyUsage": "encrypt-decrypt",
                    "algorithm": "aes-256-gcm",
                    "keyMaterial": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                })
            })
            .collect::<Vec<_>>()
    };
    for (count, valid) in [(0, false), (1, true), (100, true), (101, false)] {
        let input = parse_arguments::<KmsBulkImportInput>(
            &mut request(
                "kms.keys.bulkImport",
                &json!({
                    "projectId": project_id,
                    "keys": import_keys(count),
                    "confirm": true
                }),
            ),
            "KMS bulk import input must parse before semantic validation",
        )
        .unwrap();
        assert_eq!(input.into_parts().is_ok(), valid, "import count {count}");
    }

    let key_ids = |count: usize| {
        (0..count)
            .map(|index| format!("00000000-0000-4000-8000-{index:012}"))
            .collect::<Vec<_>>()
    };
    for (count, valid) in [(0, false), (1, true), (100, true), (101, false)] {
        let input = parse_arguments::<KmsBulkPrivateKeyRevealInput>(
            &mut request(
                "kms.keys.privateKeys.bulkReveal",
                &json!({
                    "projectId": project_id,
                    "keyIds": key_ids(count),
                    "confirmReveal": true
                }),
            ),
            "KMS bulk private-key input must parse before semantic validation",
        )
        .unwrap();
        assert_eq!(input.into_parts().is_ok(), valid, "reveal count {count}");
    }
}

#[tokio::test]
async fn kms_read_handlers_dispatch_each_pinned_route() {
    let server = MockServer::start().await;
    let project_id = "11111111-1111-4111-8111-111111111111";
    let key_id = "33333333-3333-4333-8333-333333333333";
    let key = json!({
        "id": key_id,
        "name": "signing-key",
        "description": "application signing key",
        "isDisabled": false,
        "orgId": "44444444-4444-4444-8444-444444444444",
        "projectId": project_id,
        "keyUsage": "sign-verify",
        "encryptionAlgorithm": "RSA_4096",
        "version": 1,
        "createdAt": "2026-07-20T01:02:03.000Z",
        "updatedAt": "2026-07-20T01:02:03.000Z"
    });
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/kms/keys/{key_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "key": key.clone()
        })))
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/kms/keys/key-name/signing-key"))
        .and(query_param("projectId", project_id))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "key": key
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/kms/keys/{key_id}/public-key")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "publicKey": "cHVibGljLWtleQ=="
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/v1/kms/keys/{key_id}/signing-algorithms"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "signingAlgorithms": RSA_SIGNING_ALGORITHMS
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server).await;
    let target = json!({ "projectId": project_id, "keyId": key_id });
    let exact = dispatch_tool(&client, None, request("kms.keys.get", &target))
        .await
        .unwrap()
        .structured_content
        .unwrap();
    assert_eq!(exact["id"], key_id);

    let by_name = dispatch_tool(
        &client,
        None,
        request(
            "kms.keys.getByName",
            &json!({ "projectId": project_id, "keyName": "signing-key" }),
        ),
    )
    .await
    .unwrap()
    .structured_content
    .unwrap();
    assert_eq!(by_name["name"], "signing-key");

    let public_key = dispatch_tool(&client, None, request("kms.keys.publicKey.get", &target))
        .await
        .unwrap()
        .structured_content
        .unwrap();
    assert_eq!(public_key["publicKey"], "cHVibGljLWtleQ==");

    let algorithms = dispatch_tool(
        &client,
        None,
        request("kms.keys.signingAlgorithms.list", &target),
    )
    .await
    .unwrap()
    .structured_content
    .unwrap();
    assert_eq!(
        algorithms["signingAlgorithms"],
        json!(RSA_SIGNING_ALGORITHMS)
    );
}

#[tokio::test]
async fn kms_handlers_dispatch_audited_metadata_and_explicit_plaintext_reveal() {
    let server = MockServer::start().await;
    let project_id = "11111111-1111-4111-8111-111111111111";
    let key_id = "22222222-2222-4222-8222-222222222222";
    let key = json!({
        "id": key_id,
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
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/kms/keys"))
        .and(query_param("projectId", project_id))
        .and(query_param("offset", "0"))
        .and(query_param("limit", "1"))
        .and(query_param("orderBy", "name"))
        .and(query_param("orderDirection", "asc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [key.clone()],
            "totalCount": 1
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/kms/keys/{key_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "key": key })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/kms/keys/{key_id}/decrypt")))
        .and(body_json(json!({ "ciphertext": "Y2lwaGVydGV4dA==" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "plaintext": "cGxhaW50ZXh0LWNhbmFyeQ=="
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server).await;
    let listed = dispatch_tool(
        &client,
        None,
        request(
            "kms.keys.list",
            &json!({ "projectId": project_id, "limit": 1 }),
        ),
    )
    .await
    .unwrap()
    .structured_content
    .unwrap();
    assert_eq!(listed["items"][0]["id"], key_id);
    assert!(
        serde_json::to_string(&listed)
            .unwrap()
            .contains("application-key")
    );
    assert!(
        !serde_json::to_string(&listed)
            .unwrap()
            .contains("plaintext")
    );

    let decrypted = dispatch_tool(
        &client,
        None,
        request(
            "kms.decrypt",
            &json!({
                "target": { "projectId": project_id, "keyId": key_id },
                "ciphertext": "Y2lwaGVydGV4dA==",
                "confirmReveal": true
            }),
        ),
    )
    .await
    .unwrap()
    .structured_content
    .unwrap();
    assert_eq!(decrypted["keyId"], key_id);
    assert_eq!(decrypted["plaintext"], "cGxhaW50ZXh0LWNhbmFyeQ==");
}
