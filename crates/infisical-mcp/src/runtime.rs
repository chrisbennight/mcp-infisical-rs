//! Deployment facts supplied by the transport host, without credentials or live probes.

use std::time::Duration;

use infisical_api::InfisicalClient;
use schemars::JsonSchema;
use serde::Serialize;

use crate::files::SecretFilePlane;

/// Revision of the discovery schemas; clients must include it in cache keys.
pub const SCHEMA_REVISION: &str = "2026-09-25.6";

/// gateway: bearer plus identity JWT; standalone: bearer only.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum HttpProfile {
    Gateway,
    Standalone,
}

/// Immutable settings supplied by the owner of the transport.
#[derive(Debug, Clone, Default)]
pub enum RuntimeSettings {
    /// A library host has not declared its transport or ingress limits.
    #[default]
    Embedded,
    /// Local newline-delimited MCP, with no HTTP listener.
    Stdio { max_message_bytes: usize },
    /// Authenticated MCP Streamable HTTP.
    Http {
        profile: HttpProfile,
        max_request_bytes: usize,
        max_concurrent_requests: usize,
        request_timeout: Duration,
    },
}

/// stdio or streamable-http; embedded means the host has not declared its transport.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
pub enum Transport {
    #[serde(rename = "embedded")]
    Embedded,
    #[serde(rename = "stdio")]
    Stdio,
    #[serde(rename = "streamable-http")]
    StreamableHttp,
}

/// Effective limits and delivery support, independent of upstream permissions.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeCapabilities {
    /// Static operation capabilities enabled in this instance.
    pub operation_profile: crate::policy::OperationProfile,
    /// Transport currently serving this handler.
    pub transport: Transport,
    /// HTTP authentication profile; absent for stdio or an undeclared library host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_profile: Option<HttpProfile>,
    /// Request, response, concurrency, and time bounds enforced by this instance.
    limits: RuntimeLimits,
    /// Secret and whole-result delivery methods supported by this instance.
    delivery: DeliveryCapabilities,
    /// Permissions and license entitlement have not been tested by discovery.
    #[schemars(extend("const" = "notProbed"))]
    upstream_access: &'static str,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct RuntimeLimits {
    /// HTTP request body or stdio message ceiling; absent when the host has not declared it.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_request_bytes: Option<usize>,
    /// HTTP concurrency ceiling; absent when no HTTP middleware applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_concurrent_requests: Option<usize>,
    /// HTTP request deadline in seconds; absent when no HTTP middleware applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    request_timeout_seconds: Option<f64>,
    /// Upstream response body ceiling before local projection or pagination.
    upstream_response_bytes: usize,
    /// Shared upstream HTTP concurrency ceiling, including login.
    upstream_max_concurrent_requests: usize,
    /// Per-request seconds, including capacity wait; login has its own budget.
    upstream_request_timeout_seconds: f64,
    /// Serialized MCP tool result ceiling, including compatibility text.
    tool_result_bytes: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct DeliveryCapabilities {
    /// Default delivery for operations that return secret values.
    default_secret_delivery: &'static str,
    /// Accepted secret delivery modes; reference requires a file-aware host.
    secret_modes: Vec<&'static str>,
    /// Accepted whole-result delivery modes on executors.
    result_modes: Vec<&'static str>,
    /// Whether typed upload references can be resolved by this instance.
    upload_references: bool,
    /// Effective in-memory file settings; absent when the extension is disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    file_transfer: Option<crate::files::FileCapabilities>,
}

impl RuntimeSettings {
    pub(crate) fn capabilities(
        &self,
        client: &InfisicalClient,
        files: Option<&SecretFilePlane>,
    ) -> RuntimeCapabilities {
        let (transport, http_profile, max_request_bytes, max_concurrent_requests, timeout) =
            match *self {
                Self::Embedded => (Transport::Embedded, None, None, None, None),
                Self::Stdio { max_message_bytes } => {
                    (Transport::Stdio, None, Some(max_message_bytes), None, None)
                }
                Self::Http {
                    profile,
                    max_request_bytes,
                    max_concurrent_requests,
                    request_timeout,
                } => (
                    Transport::StreamableHttp,
                    Some(profile),
                    Some(max_request_bytes),
                    Some(max_concurrent_requests),
                    Some(request_timeout.as_secs_f64()),
                ),
            };
        RuntimeCapabilities {
            operation_profile: crate::policy::OperationProfile::Full,
            transport,
            http_profile,
            limits: RuntimeLimits {
                max_request_bytes,
                max_concurrent_requests,
                request_timeout_seconds: timeout,
                upstream_response_bytes: client.max_response_bytes(),
                upstream_max_concurrent_requests: client.max_concurrent_requests(),
                upstream_request_timeout_seconds: client.request_timeout().as_secs_f64(),
                tool_result_bytes: crate::tools::MAX_TOOL_RESULT_BYTES,
            },
            delivery: DeliveryCapabilities {
                default_secret_delivery: if files.is_some() {
                    "reference"
                } else {
                    "inlineValue"
                },
                secret_modes: if files.is_some() {
                    vec!["inlineValue", "reference"]
                } else {
                    vec!["inlineValue"]
                },
                result_modes: if files.is_some() {
                    vec!["inline", "file"]
                } else {
                    vec!["inline"]
                },
                upload_references: files.is_some(),
                file_transfer: files.map(SecretFilePlane::capabilities),
            },
            upstream_access: "notProbed",
        }
    }
}
