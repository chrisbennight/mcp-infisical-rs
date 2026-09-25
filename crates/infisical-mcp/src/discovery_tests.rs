use super::*;
use serde_json::json;

fn request(name: &'static str, arguments: Value) -> CallToolRequestParams {
    let Value::Object(arguments) = arguments else {
        panic!("object arguments");
    };
    CallToolRequestParams::new(name).with_arguments(arguments)
}

fn list(arguments: Value) -> CallToolResult {
    dispatch_operations_list(&mut request(OPERATIONS_LIST_TOOL, arguments)).unwrap()
}

#[test]
fn discovery_pages_are_disjoint_complete_and_deterministic() {
    for (tier, prefix) in [
        (None, None),
        (Some("read"), None),
        (Some("write"), Some("secrets.")),
        (Some("readAudited"), Some("kms.")),
        (Some("destroy"), Some("certificates.")),
    ] {
        let mut offset = 0;
        let mut seen = Vec::new();
        loop {
            let arguments = json!({
                "tier": tier, "namePrefix": prefix, "offset": offset, "limit": 3
            });
            let result = list(arguments.clone());
            assert_eq!(
                serde_json::to_value(&result).unwrap(),
                serde_json::to_value(list(arguments)).unwrap()
            );
            let value = result.structured_content.unwrap();
            let page = value["operations"].as_array().unwrap();
            assert!(page.len() <= 3);
            seen.extend(
                page.iter()
                    .map(|entry| entry["name"].as_str().unwrap().to_owned()),
            );
            let Some(next) = value["nextOffset"].as_u64() else {
                assert_eq!(
                    u64::try_from(seen.len()).unwrap(),
                    value["matched"].as_u64().unwrap()
                );
                break;
            };
            assert!(next > offset);
            offset = next;
        }
        let expected: std::collections::BTreeSet<_> = operations()
            .into_iter()
            .filter(|entry| tier.is_none_or(|tier| tier == entry.tier.slug()))
            .filter(|entry| prefix.is_none_or(|prefix| entry.tool.name.starts_with(prefix)))
            .map(|entry| entry.tool.name.to_string())
            .collect();
        let unique: std::collections::BTreeSet<_> = seen.iter().cloned().collect();
        assert_eq!(unique.len(), seen.len());
        assert_eq!(unique, expected);
    }
}

#[test]
fn intent_search_finds_reviewed_workflows_and_keeps_exact_executors() {
    for (query, expected) in [
        ("rotate database password", "secretRotations.sql.rotate"),
        (
            "create temporary database credentials",
            "dynamicSecretLeases.create",
        ),
        ("reveal secret value", "secrets.reveal"),
        ("sign ssh certificate", "sshCertificates.sign"),
        ("encrypt data", "kms.encrypt"),
    ] {
        let value = list(json!({"query": query, "limit": 1}))
            .structured_content
            .unwrap();
        assert_eq!(value["operations"][0]["name"], expected);
        assert_eq!(
            value["operations"][0]["executor"],
            tool_tier(expected).unwrap().executor()
        );
    }
    for (name, _) in crate::discovery::REVIEWED_ALIASES {
        assert!(
            tool_tier(name).is_some(),
            "an alias must name a served operation"
        );
    }
}

#[test]
fn discovery_rejects_advertised_bounds_without_reflecting_values() {
    for arguments in [
        json!({"namePrefix": "discovery-input-canary".repeat(4)}),
        json!({"query": "discovery-input-canary".repeat(7)}),
        json!({"query": " ?! "}),
        json!({"limit": 0}),
        json!({"limit": 51}),
        json!({"offset": 10_001}),
    ] {
        let error =
            dispatch_operations_list(&mut request(OPERATIONS_LIST_TOOL, arguments)).unwrap_err();
        assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(!error.message.contains("discovery-input-canary"));
    }
    assert!(
        dispatch_operations_list(&mut request(
            OPERATIONS_LIST_TOOL,
            json!({"namePrefix": "é".repeat(64)})
        ))
        .is_ok()
    );
    for name in ["ab".to_owned(), "discovery-input-canary".repeat(7)] {
        let error = dispatch_operations_describe(
            &mut request(OPERATIONS_DESCRIBE_TOOL, json!({"operation": name})),
            false,
        )
        .unwrap_err();
        assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(!error.message.contains("discovery-input-canary"));
    }
}

#[test]
fn input_only_schema_and_brief_pages_reduce_serialized_results() {
    let brief = list(json!({}));
    let full_catalog = structured(json!({
        "operations": described_operations().iter().map(|operation| json!({
            "name": operation.name, "executor": operation.executor,
            "tier": operation.tier, "description": operation.description
        })).collect::<Vec<_>>(),
        "total": described_operations().len()
    }))
    .unwrap();
    let brief_bytes = serde_json::to_vec(&brief).unwrap().len();
    let catalog_bytes = serde_json::to_vec(&full_catalog).unwrap().len();
    assert!(
        brief_bytes * 5 < catalog_bytes,
        "a default page must materially reduce context"
    );

    let describe = |include_output| {
        dispatch_operations_describe(
            &mut request(
                OPERATIONS_DESCRIBE_TOOL,
                json!({
                    "operation": "projects.list", "includeOutputSchema": include_output
                }),
            ),
            false,
        )
        .unwrap()
    };
    let full = describe(true);
    let input_only = describe(false);
    assert!(
        input_only
            .structured_content
            .as_ref()
            .unwrap()
            .get("outputSchema")
            .is_none()
    );
    assert_eq!(
        input_only.structured_content.as_ref().unwrap()["inputSchema"],
        full.structured_content.as_ref().unwrap()["inputSchema"]
    );
    assert!(
        serde_json::to_vec(&input_only).unwrap().len() < serde_json::to_vec(&full).unwrap().len()
    );
    for result in [brief, input_only] {
        let serialized = serde_json::to_value(result).unwrap();
        let compatibility: Value =
            serde_json::from_str(serialized["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(compatibility, serialized["structuredContent"]);
    }
}
