//! Deployment facts supplied by the transport host, without credentials or live probes.

use std::time::Duration;

use infisical_api::InfisicalClient;
use schemars::JsonSchema;
use serde::Serialize;

use crate::files::SecretFilePlane;

/// Revision of the discovery schemas; clients must include it in cache keys.
pub const SCHEMA_REVISION: &str = "2026-11-16.1";

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

/// Effective limits and delivery; upstream authority is separate.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeCapabilities {
    /// Approval required; use approvalToken and approval.session.
    pub human_approval: bool,
    /// Enabled operation profile.
    pub operation_profile: crate::policy::OperationProfile,
    /// Active transport.
    pub transport: Transport,
    /// HTTP authentication profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_profile: Option<HttpProfile>,
    /// Enforced limits.
    limits: RuntimeLimits,
    /// Secret and result delivery.
    delivery: DeliveryCapabilities,
    /// Upstream access is not probed.
    #[schemars(extend("const" = "notProbed"))]
    upstream_access: &'static str,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct RuntimeLimits {
    /// HTTP body or stdio message bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_request_bytes: Option<usize>,
    /// Concurrent HTTP requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_concurrent_requests: Option<usize>,
    /// HTTP deadline, seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    request_timeout_seconds: Option<f64>,
    /// Upstream bytes before filtering.
    upstream_response_bytes: usize,
    /// Upstream concurrency, including login.
    upstream_max_concurrent_requests: usize,
    /// Upstream deadline including queueing, seconds.
    upstream_request_timeout_seconds: f64,
    /// MCP bytes including compatibility text.
    tool_result_bytes: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct DeliveryCapabilities {
    /// Default secret delivery.
    default_secret_delivery: &'static str,
    /// Secret delivery modes.
    secret_modes: Vec<&'static str>,
    /// Whole-result delivery modes.
    result_modes: Vec<&'static str>,
    /// Typed upload support.
    upload_references: bool,
    /// In-memory transfer limits.
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
            human_approval: false,
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
