//! Corrections derived from declared schemas, without reflecting request values.

use rmcp::ErrorData;
use serde_json::{Map, Value, json};
use serde_path_to_error::{Error, Segment};

pub(crate) fn correction(
    error: &Error<serde_json::Error>,
    schema: &Value,
    fallback: &'static str,
) -> ErrorData {
    let mut path = String::from("/arguments");
    let mut current = schema;
    let mut complete = error.path().iter().len() <= 32;
    for segment in error.path().iter().take(32) {
        let next = match segment {
            Segment::Map { key } => property(current, schema, key, 0)
                .map(|child| (child, key.replace('~', "~0").replace('/', "~1"))),
            Segment::Seq { index } => resolve(current, schema, 0)
                .and_then(|parent| parent.get("items"))
                .map(|child| (child, index.to_string())),
            Segment::Enum { .. } | Segment::Unknown => None,
        };
        let Some((child, name)) = next else {
            complete = false;
            break;
        };
        if path.len() + name.len() + 1 > 512 {
            complete = false;
            break;
        }
        path.push('/');
        path.push_str(&name);
        current = child;
    }

    // Serde's message is inspected only for a missing declared field. Its text,
    // including rejected values or unknown property names, is never returned.
    let message = error.inner().to_string();
    let missing = message
        .strip_prefix("missing field `")
        .and_then(|name| name.strip_suffix('`'))
        .filter(|name| complete && property(current, schema, name, 0).is_some());
    let correction = if let Some(name) = missing {
        let escaped = name.replace('~', "~0").replace('/', "~1");
        if path.len() + escaped.len() < 512 {
            path.push('/');
            path.push_str(&escaped);
        }
        format!("Missing required property {}.", json!(name))
    } else {
        let constraints = constraints(current, schema);
        format!("{fallback}. Correct {path}; declared constraints: {constraints}")
    };
    ErrorData::invalid_params(correction, Some(json!({"argumentFieldPath": path})))
}

fn resolve<'a>(schema: &'a Value, root: &'a Value, depth: usize) -> Option<&'a Value> {
    if depth >= 32 {
        return None;
    }
    match schema.get("$ref").and_then(Value::as_str) {
        Some(reference) => root
            .pointer(reference.strip_prefix('#')?)
            .and_then(|target| resolve(target, root, depth + 1)),
        None => Some(schema),
    }
}

fn property<'a>(schema: &'a Value, root: &'a Value, name: &str, depth: usize) -> Option<&'a Value> {
    if depth >= 32 {
        return None;
    }
    let schema = resolve(schema, root, depth)?;
    if let Some(child) = schema
        .get("properties")
        .and_then(|properties| properties.get(name))
    {
        return Some(child);
    }
    ["allOf", "anyOf", "oneOf"].into_iter().find_map(|keyword| {
        schema
            .get(keyword)
            .and_then(Value::as_array)
            .and_then(|branches| {
                branches
                    .iter()
                    .find_map(|branch| property(branch, root, name, depth + 1))
            })
    })
}

fn constraints(schema: &Value, root: &Value) -> String {
    let mut remaining = 16;
    let mut truncated = false;
    let selected = constraint_projection(schema, root, 0, &mut remaining, &mut truncated);
    if selected.as_object().is_none_or(Map::is_empty) {
        return "see the operation's inputSchema".into();
    }
    let text = selected.to_string();
    if text.chars().count() > 1024 {
        format!(
            "{}… (truncated; see inputSchema)",
            text.chars().take(1024).collect::<String>()
        )
    } else if truncated {
        format!("{text} (truncated; see inputSchema)")
    } else {
        text
    }
}

fn constraint_projection(
    schema: &Value,
    root: &Value,
    depth: usize,
    remaining: &mut usize,
    truncated: &mut bool,
) -> Value {
    if depth >= 4 || *remaining == 0 {
        *truncated = true;
        return json!({});
    }
    *remaining -= 1;
    let Some(schema) = resolve(schema, root, 0) else {
        *truncated = true;
        return json!({});
    };
    let mut selected = Map::new();
    for key in [
        "type",
        "enum",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "pattern",
        "required",
    ] {
        if let Some(value) = schema.get(key) {
            selected.insert(key.into(), value.clone());
        }
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        selected.insert(
            "acceptedProperties".into(),
            json!(properties.keys().take(12).collect::<Vec<_>>()),
        );
        if properties.len() > 12 {
            selected.insert("propertiesTruncated".into(), true.into());
            *truncated = true;
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            if branches.len() > 8 {
                *truncated = true;
            }
            selected.insert(
                keyword.into(),
                Value::Array(
                    branches
                        .iter()
                        .take(8)
                        .map(|branch| {
                            constraint_projection(branch, root, depth + 1, remaining, truncated)
                        })
                        .collect(),
                ),
            );
        }
    }
    Value::Object(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::{JsonSchema, schema_for};
    use serde::Deserialize;

    #[derive(Deserialize, JsonSchema)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Input {
        #[allow(dead_code)]
        project_id: String,
        #[allow(dead_code)]
        #[schemars(range(min = 1))]
        limit: usize,
    }

    fn error(arguments: Value) -> ErrorData {
        let error = serde_path_to_error::deserialize::<_, Input>(arguments)
            .err()
            .unwrap();
        correction(
            &error,
            &serde_json::to_value(schema_for!(Input)).unwrap(),
            "Invalid arguments",
        )
    }

    #[test]
    fn missing_field_names_the_declared_correction() {
        let error = error(json!({"limit": 1}));
        assert_eq!(error.message, "Missing required property \"projectId\".");
        assert_eq!(
            error.data.unwrap()["argumentFieldPath"],
            "/arguments/projectId"
        );
    }

    #[test]
    fn invalid_values_and_unknown_property_names_never_escape() {
        for input in [
            json!({"projectId":"fixture", "limit":"sensitive-value-canary"}),
            json!({"projectId":"fixture", "limit":1, "sensitive-key-canary":"sensitive-value-canary"}),
        ] {
            let error = error(input);
            let wire = serde_json::to_string(&error).unwrap();
            assert!(!wire.contains("sensitive-value-canary"));
            assert!(!wire.contains("sensitive-key-canary"));
            assert!(wire.contains("projectId") || wire.contains("integer"));
        }
        let error = error(json!({"projectId":"fixture", "limit":"sensitive-value-canary"}));
        assert_eq!(error.data.unwrap()["argumentFieldPath"], "/arguments/limit");
        assert!(error.message.contains("integer"));
        assert!(error.message.contains("minimum"));
    }

    #[test]
    fn nested_references_and_array_indices_identify_declared_fields() {
        #[derive(Deserialize, JsonSchema)]
        struct Batch {
            #[allow(dead_code)]
            entries: Vec<Input>,
        }
        let arguments =
            json!({"entries":[{"projectId":"fixture", "limit":"sensitive-value-canary"}]});
        let error = serde_path_to_error::deserialize::<_, Batch>(arguments)
            .err()
            .unwrap();
        let error = correction(
            &error,
            &serde_json::to_value(schema_for!(Batch)).unwrap(),
            "Invalid batch",
        );
        assert_eq!(
            error.data.unwrap()["argumentFieldPath"],
            "/arguments/entries/0/limit"
        );
        assert!(!error.message.contains("sensitive-value-canary"));
    }

    #[test]
    fn dynamic_map_keys_stop_at_the_declared_parent() {
        #[derive(Deserialize, JsonSchema)]
        struct Dynamic {
            #[allow(dead_code)]
            entries: std::collections::BTreeMap<String, usize>,
        }
        let arguments = json!({"entries":{"sensitive-key-canary":"sensitive-value-canary"}});
        let error = serde_path_to_error::deserialize::<_, Dynamic>(arguments)
            .err()
            .unwrap();
        let error = correction(
            &error,
            &serde_json::to_value(schema_for!(Dynamic)).unwrap(),
            "Invalid map",
        );
        assert_eq!(
            error.data.unwrap()["argumentFieldPath"],
            "/arguments/entries"
        );
        assert!(!error.message.contains("sensitive-key-canary"));
        assert!(!error.message.contains("sensitive-value-canary"));
    }

    #[test]
    fn alternatives_explain_nullable_types_and_enum_choices() {
        let schema = json!({"anyOf":[
            {"allOf":[{"type":"string"},{"enum":["shared","personal"]}]},
            {"type":"null"}
        ]});
        let hint = constraints(&schema, &schema);
        for expected in ["string", "null", "shared", "personal"] {
            assert!(hint.contains(expected), "missing {expected}: {hint}");
        }
        assert!(!hint.contains("truncated"));
    }

    #[test]
    fn bounded_alternatives_point_to_the_full_schema() {
        let schema = json!({"oneOf":vec![json!({"type":"integer","minimum":1}); 20]});
        let hint = constraints(&schema, &schema);
        assert!(hint.contains("integer"));
        assert!(hint.contains("truncated; see inputSchema"));
        assert_eq!(hint.matches("minimum").count(), 8);

        let schema = json!({"enum":["a".repeat(2048)]});
        let hint = constraints(&schema, &schema);
        assert!(hint.contains("truncated; see inputSchema"));
        assert!(hint.len() < 1100);
    }
}
