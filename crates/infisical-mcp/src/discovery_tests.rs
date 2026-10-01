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
            "name": operation.name, "executor": operation.tier.executor(),
            "tier": operation.tier.slug(), "description": operation.description
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

#[test]
fn explicit_discovery_limits_are_honored_without_a_request_ceiling() {
    let output = list(json!({"limit": 100})).structured_content.unwrap();
    assert_eq!(output["operations"].as_array().unwrap().len(), 100);
    let all = list(json!({"limit": usize::MAX}))
        .structured_content
        .unwrap();
    assert_eq!(
        all["operations"].as_array().unwrap().len(),
        described_operations().len()
    );
    assert!(all.get("nextOffset").is_none());
    let schema = schema_value::<OperationsListInput>();
    assert!(schema["properties"]["limit"].get("maximum").is_none());
    assert_eq!(schema["properties"]["limit"]["minimum"], 1);
}

#[test]
fn describe_identifier_aliases_are_hidden_and_conflicts_are_rejected() {
    for name in ["operation_id", "name", "operation", "tool"] {
        let result = dispatch_operations_describe(
            &mut request(OPERATIONS_DESCRIBE_TOOL, json!({name: "secrets.create"})),
            true,
        )
        .unwrap();
        assert_eq!(result.structured_content.unwrap()["name"], "secrets.create");
    }
    assert!(
        dispatch_operations_describe(
            &mut request(
                OPERATIONS_DESCRIBE_TOOL,
                json!({"operation_id":"secrets.create", "name":"secrets.reveal"})
            ),
            true,
        )
        .is_err()
    );
    for schema in [
        schema_value::<OperationsDescribeInput>(),
        schema_value::<ExecuteInput>(),
    ] {
        let properties = schema["properties"].as_object().unwrap();
        assert!(properties.contains_key("operation_id"));
        for name in ["name", "operation", "tool", "args"] {
            assert!(!properties.contains_key(name), "{name}");
        }
    }
    let envelope: ExecuteInput = serde_json::from_value(
        json!({"name":"secrets.create", "args":{"projectId":"test-project"}}),
    )
    .unwrap();
    assert_eq!(envelope.operation, "secrets.create");
    assert_eq!(envelope.arguments["projectId"], "test-project");
}

#[test]
fn intent_search_can_supply_the_exact_contract_without_another_describe_call() {
    let expanded = list(json!({
        "namePrefix":"secrets.metadata.list", "limit":1, "includeInputSchema":true,
    }))
    .structured_content
    .unwrap();
    let row = &expanded["operations"][0];
    assert_eq!(row["name"], "secrets.metadata.list");
    assert_eq!(row["executor"], "infisical.read");
    let described = dispatch_operations_describe(
        &mut request(
            OPERATIONS_DESCRIBE_TOOL,
            json!({"operation_id":"secrets.metadata.list", "includeOutputSchema":false}),
        ),
        true,
    )
    .unwrap()
    .structured_content
    .unwrap();
    assert_eq!(row["inputSchema"], described["inputSchema"]);
    let arguments = json!({"projectId":"test-project","environment":"prod","path":"/"});
    assert!(
        jsonschema::validator_for(&row["inputSchema"])
            .unwrap()
            .is_valid(&arguments)
    );
    let ordinary = list(json!({"namePrefix":"secrets.metadata.list","limit":1}))
        .structured_content
        .unwrap();
    assert!(ordinary["operations"][0].get("inputSchema").is_none());
}

#[test]
fn metadata_read_and_secret_write_preparation_use_one_smaller_discovery_reply() {
    for (name, executor, arguments) in [
        (
            "secrets.metadata.list",
            "infisical.read",
            json!({"projectId":"test-project","environment":"prod","path":"/"}),
        ),
        (
            "secrets.create",
            "infisical.write",
            json!({
                "target":{"projectId":"test-project","environment":"prod","path":"/","name":"EXAMPLE"},
                "secretValueFile":"mcp-file://infisical/example-upload",
            }),
        ),
    ] {
        let expanded = list(json!({"namePrefix":name,"limit":1,"includeInputSchema":true}));
        let row = &expanded.structured_content.as_ref().unwrap()["operations"][0];
        assert_eq!(row["name"], name);
        assert_eq!(row["executor"], executor);
        assert!(
            jsonschema::validator_for(&row["inputSchema"])
                .unwrap()
                .is_valid(&arguments)
        );
        let brief = list(json!({"namePrefix":name,"limit":1}));
        let full = dispatch_operations_describe(
            &mut request(OPERATIONS_DESCRIBE_TOOL, json!({"operation_id":name})),
            true,
        )
        .unwrap();
        assert_eq!(
            row["inputSchema"],
            full.structured_content.as_ref().unwrap()["inputSchema"]
        );
        let compact_bytes = serde_json::to_vec(&expanded).unwrap().len();
        let separate_bytes =
            serde_json::to_vec(&brief).unwrap().len() + serde_json::to_vec(&full).unwrap().len();
        assert!(
            compact_bytes < separate_bytes,
            "{name}: {compact_bytes} >= {separate_bytes}"
        );
        let serialized = serde_json::to_value(&expanded).unwrap();
        let text: Value =
            serde_json::from_str(serialized["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, serialized["structuredContent"]);
        assert!(!serialized.to_string().contains("example-upload"));
    }
}

#[test]
fn secret_read_pointer_names_explain_the_governed_operation() {
    for name in ["secrets.get", "secrets.list"] {
        let error = dispatch_operations_describe(
            &mut request(OPERATIONS_DESCRIBE_TOOL, json!({"operation_id":name})),
            true,
        )
        .unwrap_err();
        assert!(error.message.contains("secrets.reveal"));
        assert!(error.message.contains("audited credential read"));
        assert!(error.message.contains("secrets.metadata.list"));
        assert!(operation_definition(name).is_none());
    }
}

#[test]
fn upstream_collection_bounds_do_not_suggest_a_smaller_local_page() {
    let result = collection_result::<Value>(
        Err(infisical_api::ResourceError::Client(
            infisical_api::ClientError::ResponseTooLarge { limit: 128 },
        )),
        "Select an exact path with recursive false; local paging does not reduce this fetch.",
    )
    .unwrap();
    assert_eq!(result.is_error, Some(true));
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(serialized.contains("upstream collection"));
    assert!(serialized.contains("exact path"));
    assert!(!serialized.contains("smaller limit"));
}
