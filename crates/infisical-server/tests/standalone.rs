mod support;

use support::server_binary;

use std::{process::Stdio, time::Duration};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
    time::timeout,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const BEARER: &str = "standalone-test-bearer-value-00001";
const DEADLINE: Duration = Duration::from_secs(10);

fn command(api_url: &str) -> Command {
    let mut command = Command::new(server_binary());
    command
        .env_clear()
        .env("INFISICAL_API_URL", api_url)
        .env(
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID",
            "standalone-test-client",
        )
        .env(
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET",
            "standalone-test-client-secret",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

fn initialize() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},
        "clientInfo":{"name":"standalone-wire-test","version":"1"}
    }})
}

fn projects() -> Value {
    json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
        "name":"infisical.read","arguments":{"operation":"projects.list","arguments":{"offset":0,"limit":10}}
    }})
}

async fn upstream() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/api/v1/auth/universal-auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessToken":"standalone-test-access-token","expiresIn":60,"accessTokenMaxTTL":120,"tokenType":"Bearer"
        }))).expect(1).mount(&server).await;
    Mock::given(method("GET")).and(path("/api/v1/projects"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"projects":[{
            "id":"project-1","name":"Example","slug":"example","type":"secret-manager","orgId":"org-1","environments":[]
        }]}))).expect(1).mount(&server).await;
    server
}

async fn read_message(reader: &mut BufReader<tokio::process::ChildStdout>) -> Value {
    let mut line = String::new();
    assert!(
        timeout(DEADLINE, reader.read_line(&mut line))
            .await
            .unwrap()
            .unwrap()
            > 0
    );
    serde_json::from_str(&line).expect("stdout contains only JSON-RPC messages")
}

async fn send_message(child: &mut Child, message: &Value) {
    let line = format!("{message}\n");
    timeout(
        DEADLINE,
        child.stdin.as_mut().unwrap().write_all(line.as_bytes()),
    )
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test]
async fn stdio_initializes_discovers_and_reads_without_gateway_configuration() {
    let server = upstream().await;
    let mut child = command(&server.uri())
        .args(["--transport", "stdio"])
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    send_message(&mut child, &initialize()).await;
    let response = read_message(&mut reader).await;
    assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
    send_message(
        &mut child,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    send_message(
        &mut child,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    let catalog = read_message(&mut reader).await;
    assert!(
        catalog["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "infisical.read")
    );
    send_message(&mut child, &projects()).await;
    let result = read_message(&mut reader).await;
    assert_eq!(result["result"]["isError"], false);
    assert_eq!(
        result["result"]["structuredContent"]["items"][0]["id"],
        "project-1"
    );
    drop(child.stdin.take());
    assert!(
        timeout(DEADLINE, child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    let mut diagnostics = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut diagnostics)
        .await
        .unwrap();
    assert!(diagnostics.contains("MCP stdio transport ready"));
    assert!(!diagnostics.contains("standalone-test-client-secret"));
    assert!(!diagnostics.contains("standalone-test-access-token"));
}

#[tokio::test]
async fn stdio_reports_delivery_requirements_without_probing_upstream_access() {
    let upstream = MockServer::start().await;
    let mut child = command(&upstream.uri())
        .args(["--transport", "stdio"])
        .env("INFISICAL_MCP_MAX_BODY_BYTES", "4096")
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    send_message(&mut child, &initialize()).await;
    assert!(read_message(&mut reader).await.get("result").is_some());
    send_message(
        &mut child,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    for (name, arguments) in [
        ("server.info", json!({})),
        ("server.capabilities", json!({})),
        (
            "operations.describe",
            json!({"operation":"certificates.import"}),
        ),
    ] {
        send_message(
            &mut child,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
                "name":name,"arguments":arguments
            }}),
        )
        .await;
        let response = read_message(&mut reader).await;
        assert_eq!(response["result"]["isError"], false);
        let output = &response["result"]["structuredContent"];
        match name {
            "server.info" => {
                assert_eq!(output["transport"], "stdio");
                assert!(output.get("httpProfile").is_none());
                assert!(!output["schemaRevision"].as_str().unwrap().is_empty());
            }
            "server.capabilities" => {
                let runtime = &output["runtime"];
                assert_eq!(runtime["transport"], "stdio");
                assert_eq!(runtime["limits"]["maxRequestBytes"], 4096);
                assert!(runtime["limits"].get("requestTimeoutSeconds").is_none());
                assert_eq!(runtime["delivery"]["secretModes"], json!(["inlineValue"]));
                assert_eq!(runtime["delivery"]["resultModes"], json!(["inline"]));
                assert_eq!(runtime["delivery"]["uploadReferences"], false);
                assert_eq!(runtime["upstreamAccess"], "notProbed");
            }
            _ => {
                assert_eq!(output["availability"]["implemented"], true);
                assert_eq!(output["availability"]["enabledHere"], false);
                assert_eq!(output["availability"]["requiresFileTransfer"], true);
            }
        }
        assert!(
            !response
                .to_string()
                .contains("standalone-test-client-secret")
        );
    }
    assert!(upstream.received_requests().await.unwrap().is_empty());
    drop(child.stdin.take());
    assert!(
        timeout(DEADLINE, child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn stdio_rejects_oversized_and_malformed_messages_without_logging_payloads() {
    for input in [
        format!("{}\n", "x".repeat(2048)),
        "{\"jsonrpc\":\"2.0\",\"method\":123,\"secret\":\"fixture-must-not-be-logged\"}\n".into(),
    ] {
        let mut child = command("http://127.0.0.1:9")
            .args(["--transport", "stdio"])
            .env("INFISICAL_MCP_MAX_BODY_BYTES", "1024")
            .env(
                "INFISICAL_MCP_LOG_LEVEL",
                "trace,rmcp::transport::async_rw=trace",
            )
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .await
            .unwrap();
        drop(child.stdin.take());
        let output = timeout(DEADLINE, child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let diagnostics = String::from_utf8(output.stderr).unwrap();
        assert!(!diagnostics.contains("fixture-must-not-be-logged"));
        assert!(!diagnostics.contains(&"x".repeat(128)));
        assert!(diagnostics.contains("invalid or oversized MCP message"));
    }
}

#[tokio::test]
async fn stdio_refuses_http_file_delivery_and_http_cli_options() {
    for (args, file_url) in [
        (vec!["--transport", "stdio"], Some("https://files.example")),
        (
            vec!["--transport", "stdio", "--http-profile", "standalone"],
            None,
        ),
        (vec!["--transport", "stdio", "--healthcheck"], None),
    ] {
        let mut command = command("http://127.0.0.1:9");
        command.args(args);
        if let Some(url) = file_url {
            command.env("INFISICAL_MCP_FILE_PUBLIC_URL", url);
        }
        let output = timeout(DEADLINE, command.output()).await.unwrap().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn stdio_sigterm_exits_even_when_the_client_keeps_stdin_open() {
    let mut child = command("http://127.0.0.1:9")
        .args(["--transport", "stdio"])
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    send_message(&mut child, &initialize()).await;
    assert!(read_message(&mut reader).await.get("result").is_some());
    let signal = Command::new("kill")
        .args(["-TERM", &child.id().unwrap().to_string()])
        .status()
        .await
        .unwrap();
    assert!(signal.success());
    assert!(
        timeout(DEADLINE, child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn standalone_http_requires_a_configured_connection_bearer() {
    let output = timeout(
        DEADLINE,
        command("http://127.0.0.1:9")
            .args(["--http-profile", "standalone"])
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("missing required environment variable INFISICAL_MCP_BEARER_CURRENT")
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn standalone_http_authenticates_every_request_and_has_no_session_state() {
    let server = upstream().await;
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let mut child = command(&server.uri())
        .args(["--http-profile", "standalone", "--port", &port.to_string()])
        .env("INFISICAL_MCP_BEARER_CURRENT", BEARER)
        .spawn()
        .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let root = format!("http://127.0.0.1:{port}");
    timeout(DEADLINE, async {
        loop {
            if client
                .get(format!("{root}/healthz"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "HTTP process exited before readiness"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let request = |body: Value| {
        client
            .post(format!("{root}/mcp"))
            .header("Accept", "application/json, text/event-stream")
            .json(&body)
    };
    assert!(server.received_requests().await.unwrap().is_empty());
    assert_eq!(request(initialize()).send().await.unwrap().status(), 401);
    assert_eq!(
        request(initialize())
            .bearer_auth("wrong")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        request(initialize())
            .bearer_auth(BEARER)
            .header("Origin", "https://attacker.example")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        request(initialize())
            .bearer_auth(BEARER)
            .header("Host", "attacker.example")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    let response = request(initialize())
        .bearer_auth(BEARER)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers().get("mcp-session-id").is_none());
    assert_eq!(
        response.json::<Value>().await.unwrap()["result"]["protocolVersion"],
        "2025-11-25"
    );
    let capabilities = request(
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"server.capabilities","arguments":{}
        }}),
    )
    .bearer_auth(BEARER)
    .send()
    .await
    .unwrap()
    .json::<Value>()
    .await
    .unwrap();
    assert_eq!(
        capabilities["result"]["structuredContent"]["runtime"]["httpProfile"],
        "standalone"
    );
    assert_eq!(
        capabilities["result"]["structuredContent"]["runtime"]["transport"],
        "streamable-http"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    let response = request(projects())
        .bearer_auth(BEARER)
        .header("MCP-Protocol-Version", "2025-11-25")
        .header("X-MCP-Identity", "not-a-gateway-jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers().get("mcp-session-id").is_none());
    assert_eq!(
        response.json::<Value>().await.unwrap()["result"]["structuredContent"]["items"][0]["id"],
        "project-1"
    );
    assert_eq!(
        request(projects())
            .header("mcp-session-id", "invented-session")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let calls = server.received_requests().await.unwrap();
    assert_eq!(calls.len(), 2);
    assert!(
        calls
            .iter()
            .all(|r| !r.headers.contains_key("x-mcp-identity"))
    );
    child.kill().await.unwrap();
}

#[tokio::test]
async fn stdio_returns_safe_structured_argument_errors_without_upstream_requests() {
    let server = MockServer::start().await;
    let mut child = command(&server.uri())
        .args(["--transport", "stdio"])
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    send_message(&mut child, &initialize()).await;
    assert!(read_message(&mut reader).await.get("result").is_some());
    send_message(
        &mut child,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    send_message(
        &mut child,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"infisical.read", "arguments":{"operation":"projects.list",
                "arguments":{"offset":"stdio-sensitive-input-canary"}}
        }}),
    )
    .await;
    let result = read_message(&mut reader).await;
    assert_eq!(result["result"]["isError"], true);
    let error = &result["result"]["structuredContent"]["error"];
    assert_eq!(error["operation"], "projects.list");
    assert_eq!(error["effect"], "notStarted");
    assert_eq!(error["recovery"], "correctRequest");
    assert!(!result.to_string().contains("stdio-sensitive-input-canary"));
    drop(child.stdin.take());
    assert!(
        timeout(DEADLINE, child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    let mut diagnostics = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut diagnostics)
        .await
        .unwrap();
    assert!(!diagnostics.contains("stdio-sensitive-input-canary"));
    assert!(server.received_requests().await.unwrap().is_empty());
}
