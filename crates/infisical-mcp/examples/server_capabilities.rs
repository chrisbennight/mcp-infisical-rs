fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payload = infisical_mcp::server_capabilities_payload()?;
    println!("{}", serde_json::to_string(&payload)?);
    Ok(())
}
