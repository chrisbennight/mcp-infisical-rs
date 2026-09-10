use std::{
    net::TcpListener,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn configured_server_command(api_url: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-infisical-rs"));
    command
        .env(
            "INFISICAL_MCP_BEARER_CURRENT",
            "current-gateway-bearer-value-0001",
        )
        .env_remove("INFISICAL_MCP_BEARER_PREVIOUS")
        .env("INFISICAL_MCP_IDENTITY_JWKS_URL", "http://127.0.0.1:9/jwks")
        .env("INFISICAL_MCP_IDENTITY_ISSUER", "https://gateway.test")
        .env_remove("INFISICAL_MCP_IDENTITY_ALLOW_PRIVATE_HTTP")
        .env("INFISICAL_API_URL", api_url)
        .env_remove("INFISICAL_API_ALLOW_PRIVATE_HTTP")
        .env("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "cli-test-client")
        .env(
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET",
            "cli-test-client-secret",
        )
        .env_remove("INFISICAL_UNIVERSAL_AUTH_ORGANIZATION_SLUG");
    command
}

#[test]
fn version_reports_the_workspace_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-infisical-rs"))
        .arg("--version")
        .output()
        .expect("version command must start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("version output must be UTF-8"),
        format!("mcp-infisical-rs {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn server_fails_closed_when_gateway_credentials_are_missing() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-infisical-rs"))
        .env_remove("INFISICAL_MCP_BEARER_CURRENT")
        .env_remove("INFISICAL_MCP_BEARER_PREVIOUS")
        .env_remove("INFISICAL_MCP_IDENTITY_ISSUER")
        .env_remove("INFISICAL_MCP_IDENTITY_JWKS_URL")
        .env_remove("INFISICAL_MCP_IDENTITY_ALLOW_PRIVATE_HTTP")
        .env_remove("INFISICAL_API_ALLOW_PRIVATE_HTTP")
        .output()
        .expect("server command must start");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("bootstrap error must be UTF-8"),
        "configuration error: missing required environment variable INFISICAL_MCP_BEARER_CURRENT\n"
    );
}

#[test]
fn server_fails_closed_when_infisical_credentials_are_missing() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-infisical-rs"))
        .env(
            "INFISICAL_MCP_BEARER_CURRENT",
            "current-gateway-bearer-value-0001",
        )
        .env("INFISICAL_MCP_IDENTITY_JWKS_URL", "http://127.0.0.1:9/jwks")
        .env("INFISICAL_MCP_IDENTITY_ISSUER", "https://gateway.test")
        .env_remove("INFISICAL_MCP_IDENTITY_ALLOW_PRIVATE_HTTP")
        .env_remove("INFISICAL_API_URL")
        .env_remove("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID")
        .env_remove("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET")
        .env_remove("INFISICAL_UNIVERSAL_AUTH_ORGANIZATION_SLUG")
        .env_remove("INFISICAL_API_ALLOW_PRIVATE_HTTP")
        .output()
        .expect("server command must start");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("bootstrap error must be UTF-8"),
        "configuration error: missing required environment variable INFISICAL_API_URL\n"
    );
}

#[test]
fn server_rejects_a_malformed_identity_private_http_opt_in() {
    for invalid in ["", " ", " true ", "false ", "TRUE", "yes"] {
        let output = configured_server_command("http://127.0.0.1:9")
            .env("INFISICAL_MCP_IDENTITY_ALLOW_PRIVATE_HTTP", invalid)
            .output()
            .expect("server command must start");

        assert_eq!(output.status.code(), Some(2), "{invalid:?}");
        assert!(output.stdout.is_empty(), "{invalid:?}");
        assert_eq!(
            String::from_utf8(output.stderr).expect("bootstrap error must be UTF-8"),
            "configuration error: invalid value for INFISICAL_MCP_IDENTITY_ALLOW_PRIVATE_HTTP: expected true or false\n",
            "{invalid:?}"
        );
    }
}

#[test]
fn server_rejects_a_malformed_private_http_opt_in() {
    for invalid in ["", " ", " true ", "false ", "TRUE", "yes"] {
        let output = configured_server_command("http://server:8080")
            .env("INFISICAL_API_ALLOW_PRIVATE_HTTP", invalid)
            .output()
            .expect("server command must start");

        assert_eq!(output.status.code(), Some(2), "{invalid:?}");
        assert!(output.stdout.is_empty(), "{invalid:?}");
        assert_eq!(
            String::from_utf8(output.stderr).expect("bootstrap error must be UTF-8"),
            "configuration error: invalid value for INFISICAL_API_ALLOW_PRIVATE_HTTP: expected true or false\n",
            "{invalid:?}"
        );
    }
}

#[test]
fn private_service_url_requires_the_explicit_true_opt_in() {
    for value in [None, Some("false")] {
        let mut command = configured_server_command("http://server:8080");
        if let Some(value) = value {
            command.env("INFISICAL_API_ALLOW_PRIVATE_HTTP", value);
        }
        let output = command.output().expect("server command must start");

        assert_eq!(output.status.code(), Some(2), "{value:?}");
        assert!(output.stdout.is_empty(), "{value:?}");
        assert_eq!(
            String::from_utf8(output.stderr).expect("bootstrap error must be UTF-8"),
            "configuration error: Infisical API URL must be HTTPS, loopback HTTP, or explicitly allowed private HTTP without userinfo, query, fragment, or path\n",
            "{value:?}"
        );
    }
}

#[tokio::test]
async fn native_healthcheck_needs_only_the_listener_coordinates() {
    let health_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/healthz"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&health_server)
        .await;
    let proxy_server = MockServer::start().await;
    let port = health_server.address().port();
    let proxy_url = proxy_server.uri();

    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_mcp-infisical-rs"))
            .args([
                "--healthcheck",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .env("HTTP_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env_remove("INFISICAL_MCP_BEARER_CURRENT")
            .env_remove("INFISICAL_MCP_BEARER_PREVIOUS")
            .env_remove("INFISICAL_MCP_IDENTITY_ISSUER")
            .env_remove("INFISICAL_MCP_IDENTITY_JWKS_URL")
            .env_remove("INFISICAL_MCP_IDENTITY_ALLOW_PRIVATE_HTTP")
            .env_remove("INFISICAL_API_ALLOW_PRIVATE_HTTP")
            .output()
            .expect("healthcheck command must start")
    })
    .await
    .expect("healthcheck task must finish");

    assert_eq!(
        health_server.received_requests().await.unwrap().len(),
        1,
        "healthcheck must make exactly one request to the local listener"
    );
    assert!(
        proxy_server.received_requests().await.unwrap().is_empty(),
        "healthcheck must ignore environment proxies"
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn sigterm_uses_the_graceful_shutdown_path() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve isolated server port");
    let port = listener.local_addr().expect("reserved address").port();
    drop(listener);

    let mut child = configured_server_command("http://server:8080")
        .args(["--host", "127.0.0.1", "--port", &port.to_string()])
        .env("INFISICAL_API_ALLOW_PRIVATE_HTTP", "true")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("server command must start");

    let ready_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            child.try_wait().expect("inspect child status").is_none(),
            "server exited before becoming healthy"
        );
        assert!(
            Instant::now() < ready_deadline,
            "server did not start in time"
        );
        let healthcheck = Command::new(env!("CARGO_BIN_EXE_mcp-infisical-rs"))
            .args([
                "--healthcheck",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("healthcheck command must start");
        if healthcheck.success() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let signal_status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(signal_status.success());

    let exit_deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("inspect shutdown status") {
            break status;
        }
        if Instant::now() >= exit_deadline {
            child.kill().expect("terminate stuck test child");
            panic!("server did not shut down after SIGTERM");
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "SIGTERM must produce a clean exit");
}
