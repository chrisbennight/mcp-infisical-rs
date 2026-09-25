//! Value-free identifiers retained outside a whole-result file for reconciliation.

use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) enum ResourceKind {
    ClientSecret,
    Token,
    DynamicLease,
    Certificate,
    CertificateRequest,
    SshCertificate,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ReconciliationReference {
    /// Resource to inspect before revoking, replacing, or repeating issuance.
    kind: ResourceKind,
    /// Non-secret resource identifier; retain the original request scope as well.
    #[schemars(length(min = 1, max = 128))]
    id: String,
}

pub(super) fn references(operation: &str, payload: &Value) -> Vec<ReconciliationReference> {
    let selectors: &[(&str, ResourceKind)] = match operation {
        "identityUniversalAuth.clientSecrets.create" => {
            &[("/metadata/id", ResourceKind::ClientSecret)]
        }
        "identityTokenAuth.tokens.create" => &[("/metadata/id", ResourceKind::Token)],
        "dynamicSecretLeases.create" => &[("/lease/id", ResourceKind::DynamicLease)],
        "certificates.issue" | "certificates.renew" | "certificateRequests.result.reveal" => &[
            ("/certificateId", ResourceKind::Certificate),
            ("/requestId", ResourceKind::CertificateRequest),
        ],
        "sshCertificates.issue" => &[("/serialNumber", ResourceKind::SshCertificate)],
        _ => &[],
    };
    selectors
        .iter()
        .filter_map(|(path, kind)| {
            let value = payload.pointer(path)?;
            let id = match value {
                Value::String(id) => id.clone(),
                Value::Number(number) if number.is_u64() => number.to_string(),
                _ => return None,
            };
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
            {
                return None;
            }
            Some(ReconciliationReference { kind: *kind, id })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn receipt_selects_only_bounded_resource_ids_for_the_exact_operation() {
        let payload = json!({"metadata":{"id":"token-1","name":"label-canary"},"accessToken":"secret-canary"});
        assert_eq!(
            serde_json::to_value(references("identityTokenAuth.tokens.create", &payload)).unwrap(),
            json!([{"kind":"token","id":"token-1"}])
        );
        assert!(references("future.operation", &payload).is_empty());
        for id in [String::new(), "x".repeat(129), "bad\nidentifier".to_owned()] {
            assert!(
                references(
                    "identityTokenAuth.tokens.create",
                    &json!({"metadata":{"id":id}})
                )
                .is_empty()
            );
        }
    }
}
