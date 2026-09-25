use super::*;
use serde_json::json;

#[test]
fn metadata_lookup_and_search_do_not_construct_schemas() {
    let registry = OperationRegistry::new();
    assert!(registry.get("not.a.served.operation").is_none());
    assert_eq!(registry.get("projects.list").unwrap().tier, ToolTier::Read);
    let terms = crate::discovery::query_terms("rotate database password").unwrap();
    assert!(registry.operations.iter().any(|operation| {
        crate::discovery::score(&terms, operation.name, operation.description).is_some()
    }));
    assert!(registry.operations.iter().all(|operation| {
        operation.input_schema.get().is_none() && operation.output_schema.get().is_none()
    }));

    let selected = registry.get("projects.list").unwrap();
    let input = selected.input_schema();
    assert!(input.contains_key("properties"));
    assert!(selected.output_schema.get().is_none());
    assert!(Arc::ptr_eq(input, selected.input_schema()));
    assert!(registry.operations.iter().all(|operation| {
        operation.name == selected.name
            || (operation.input_schema.get().is_none() && operation.output_schema.get().is_none())
    }));
    let tool = selected.materialize();
    assert!(Arc::ptr_eq(&tool.input_schema, input));
    assert!(Arc::ptr_eq(
        tool.output_schema.as_ref().unwrap(),
        selected.output_schema()
    ));
}

#[test]
fn counting_results_matches_wire_serialization_for_unicode_and_escapes() {
    for text in ["ordinary", "é🔒\n\"\\\u{0000}", ""] {
        let result = CallToolResult::structured(json!({"value": text}));
        assert_eq!(
            tool_result_bytes(&result).unwrap(),
            serde_json::to_vec(&result).unwrap().len()
        );
    }
    let result = CallToolResult::structured(json!({
        "value": "é\"\\".repeat(MAX_TOOL_RESULT_BYTES)
    }));
    assert_eq!(
        tool_result_bytes(&result).unwrap(),
        serde_json::to_vec(&result).unwrap().len()
    );
    let refused = enforce_result_budget("identityTokenAuth.tokens.create", None, result);
    let text = serde_json::to_string(&refused).unwrap();
    assert_eq!(refused.is_error, Some(true));
    assert!(text.contains("must not be repeated"));
    assert!(!text.contains("Retry with a smaller limit"));
}
