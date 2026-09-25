//! Bounded newline-delimited MCP messages on local standard input and output.

use futures_util::{SinkExt, StreamExt};
use infisical_mcp::InfisicalMcp;
use rmcp::{
    ServiceExt,
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::async_rw::JsonRpcMessageCodec,
};
use tokio_util::{
    codec::{FramedRead, FramedWrite},
    sync::CancellationToken,
};

use crate::config::StdioSettings;

/// Serve a local client using the same typed handler as HTTP, without a listener.
///
/// # Errors
/// Returns a bounded diagnostic if initialization or the service task fails.
pub async fn serve(settings: StdioSettings, cancellation: CancellationToken) -> anyhow::Result<()> {
    let (input, output) = rmcp::transport::stdio();
    let reader = FramedRead::new(
        input,
        JsonRpcMessageCodec::<ClientJsonRpcMessage>::new_with_max_length(settings.max_body_bytes),
    )
    .scan((), |(), result| {
        // A framing error ends this connection. Do not log parser errors: their
        // messages may quote secret-bearing input.
        let message = if let Ok(message) = result {
            Some(message)
        } else {
            tracing::warn!("stdio connection closed: invalid or oversized MCP message");
            None
        };
        std::future::ready(message)
    });
    let writer = FramedWrite::new(
        output,
        JsonRpcMessageCodec::<ServerJsonRpcMessage>::default(),
    )
    .sink_map_err(|_| std::io::Error::other("MCP stdio output failed"));
    let service = InfisicalMcp::new(settings.infisical)
        .with_runtime(infisical_mcp::runtime::RuntimeSettings::Stdio {
            max_message_bytes: settings.max_body_bytes,
        })
        .serve_with_ct((writer, reader), cancellation)
        .await
        .map_err(|_| anyhow::anyhow!("MCP stdio initialization failed"))?;
    service
        .waiting()
        .await
        .map_err(|_| anyhow::anyhow!("MCP stdio service task failed"))?;
    Ok(())
}
