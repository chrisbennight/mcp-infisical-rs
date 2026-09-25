fn main() -> Result<(), serde_json::Error> {
    serde_json::to_writer_pretty(
        std::io::stdout().lock(),
        &infisical_mcp::operation_policy_payload(),
    )
}
