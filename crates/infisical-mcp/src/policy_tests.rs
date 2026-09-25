use super::*;
use serde_json::json;

fn request(name: &'static str, arguments: Value) -> CallToolRequestParams {
    let Value::Object(arguments) = arguments else {
        panic!("object arguments")
    };
    CallToolRequestParams::new(name).with_arguments(arguments)
}

#[test]
fn policy_export_matches_registry_and_keeps_sensitive_reads_separate() {
    let manifest = operation_policy_payload();
    let entries = manifest["operations"].as_array().unwrap();
    assert_eq!(entries.len(), described_operations().len());
    for entry in entries {
        let operation = operation_definition(entry["operation"].as_str().unwrap()).unwrap();
        assert!(operation.policy.reviewed, "{}", operation.name);
        assert_eq!(entry["executor"], operation.tier.executor());
        assert_eq!(
            entry["inputSchema"],
            Value::Object(operation.input_schema().as_ref().clone())
        );
        assert_eq!(
            entry["outputSchema"],
            Value::Object(operation.output_schema().as_ref().clone())
        );
        if operation.policy.metadata {
            assert!(!operation.policy.credential_disclosure);
            assert!(matches!(
                operation.tier,
                ToolTier::Read | ToolTier::ReadAudited
            ));
        }
        if operation.input_schema()["properties"]
            .get("delivery")
            .is_some()
        {
            assert!(operation.policy.credential_disclosure, "{}", operation.name);
        }
    }
    let reveal = entries
        .iter()
        .find(|entry| entry["operation"] == "secrets.reveal")
        .unwrap();
    assert_eq!(reveal["effects"]["mutation"], false);
    assert_eq!(reveal["credentialDisclosure"], true);
    assert!(!OperationProfile::Metadata.allows(operation_policy::facts("future.metadata.read")));
    assert!(!OperationProfile::Secrets.allows(operation_policy::facts("secrets.future.create")));
    assert!(!OperationProfile::PkiSsh.allows(operation_policy::facts("certificates.future.issue")));
    assert!(OperationProfile::Full.allows(operation_policy::facts("future.operation")));
}

#[test]
fn restricted_discovery_is_complete_without_disabled_names() {
    for profile in [
        OperationProfile::Metadata,
        OperationProfile::Secrets,
        OperationProfile::PkiSsh,
    ] {
        let mut offset = 0;
        let mut names = std::collections::BTreeSet::new();
        loop {
            let result = dispatch_operations_list_for_profile(
                &mut request(OPERATIONS_LIST_TOOL, json!({"offset":offset,"limit":7})),
                profile,
            )
            .unwrap();
            let data = result.structured_content.unwrap();
            for entry in data["operations"].as_array().unwrap() {
                assert!(names.insert(entry["name"].as_str().unwrap().to_owned()));
            }
            let Some(next) = data["nextOffset"].as_u64() else {
                break;
            };
            offset = next;
        }
        let expected: std::collections::BTreeSet<_> = described_operations()
            .iter()
            .filter(|operation| profile.allows(operation.policy))
            .map(|operation| operation.name.to_owned())
            .collect();
        assert_eq!(names, expected);
    }
    assert!(
        dispatch_operations_describe_for_profile(
            &mut request(
                OPERATIONS_DESCRIBE_TOOL,
                json!({"operation":"secrets.reveal"})
            ),
            false,
            OperationProfile::Metadata
        )
        .is_err()
    );
}

// An isolated host-side policy fixture. This is not a server-side user-role engine.
fn metadata_gateway_accepts(
    manifest: &Value,
    executor: &str,
    envelope: &Value,
    project: &str,
) -> bool {
    let Some(envelope) = envelope.as_object() else {
        return false;
    };
    if envelope.len() != 2 {
        return false;
    }
    let Some(operation) = envelope.get("operation").and_then(Value::as_str) else {
        return false;
    };
    let Some(arguments) = envelope.get("arguments") else {
        return false;
    };
    let Some(entry) = manifest["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["operation"] == operation && entry["executor"] == executor)
    else {
        return false;
    };
    if !entry["profiles"]
        .as_array()
        .unwrap()
        .contains(&json!("metadata"))
        || entry["credentialDisclosure"] != false
        || entry["effects"]["mutation"] != false
    {
        return false;
    }
    if !entry["scopeSelectors"]
        .as_array()
        .unwrap()
        .contains(&json!("/projectId"))
    {
        return false;
    }
    jsonschema::validator_for(&entry["inputSchema"])
        .unwrap()
        .is_valid(arguments)
        && arguments.get("projectId") == Some(&json!(project))
}

#[tokio::test]
async fn metadata_gateway_denies_reveal_and_wrong_scope_without_forwarding() {
    let upstream = wiremock::MockServer::start().await;
    let client = InfisicalClient::new(infisical_api::ClientSettings::new(
        upstream.uri().parse().unwrap(),
        "policy-fixture-client".into(),
        SecretValue::new("policy-fixture-secret"),
    ))
    .unwrap();
    let manifest = operation_policy_payload();
    let valid = json!({"operation":"secrets.metadata.list", "arguments":{
        "projectId":"project-1", "environment":"prod", "path":"/"
    }});
    assert!(metadata_gateway_accepts(
        &manifest,
        "infisical.read",
        &valid,
        "project-1"
    ));
    assert!(!metadata_gateway_accepts(
        &manifest,
        "infisical.read",
        &valid,
        "project-2"
    ));
    for executor in [
        "infisical.read",
        "infisical.readAudited",
        "infisical.write",
        "infisical.destroy",
        "secrets.reveal",
    ] {
        let envelope = json!({"operation":"secrets.reveal","arguments":{
            "projectId":"project-1", "environment":"prod", "secretPath":"/", "secretName":"policy-canary", "confirm":true
        }});
        assert!(!metadata_gateway_accepts(
            &manifest,
            executor,
            &envelope,
            "project-1"
        ));
        let result = dispatch_with_profile(
            &client,
            None,
            &RuntimeSettings::default(),
            OperationProfile::Metadata,
            request(executor, envelope),
        )
        .await;
        assert!(result.is_err());
        assert!(!result.unwrap_err().message.contains("policy-canary"));
    }
    for envelope in [
        json!({}),
        json!({"operation":"secrets.reveal","arguments":[],"risk":"low"}),
        json!({"operation":"unknown","arguments":{}}),
    ] {
        assert!(!metadata_gateway_accepts(
            &manifest,
            "infisical.read",
            &envelope,
            "project-1"
        ));
    }
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[test]
fn credential_outputs_have_reviewed_envelope_bounds() {
    let reviewed = [
        "identityUniversalAuth.clientSecrets.create",
        "identityTokenAuth.tokens.create",
        "secrets.reveal",
        "secretRotations.sql.generatedCredentials.get",
        "certificates.issue",
        "certificates.renew",
        "certificates.bundle.reveal",
        "certificates.privateKey.reveal",
        "certificateRequests.result.reveal",
        "certificateProfiles.latestActiveBundle.reveal",
        "certificateProfiles.acmeEabSecret.reveal",
        "sshCertificates.issue",
        "kms.decrypt",
        "kms.keys.privateKey.reveal",
        "kms.keys.privateKeys.bulkReveal",
        "dynamicSecretLeases.create",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    let actual = described_operations()
        .iter()
        .filter(|op| op.policy.credential_disclosure)
        .map(|op| op.name)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        actual, reviewed,
        "review response size bounds before adding credential delivery"
    );
}
