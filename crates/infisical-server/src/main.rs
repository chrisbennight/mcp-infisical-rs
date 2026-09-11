use std::{
    net::{IpAddr, SocketAddr},
    process::ExitCode,
};

use anyhow::Context;
use clap::{Parser, ValueEnum};
use infisical_server::{
    config::{HttpProfile, Settings, StdioSettings},
    server::build_router,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(Debug, Parser)]
#[command(
    name = "mcp-infisical-rs",
    version,
    about = "Authenticated MCP server for self-hosted Infisical"
)]
struct Cli {
    /// Bind host, overriding `INFISICAL_MCP_HOST`.
    #[arg(long)]
    host: Option<String>,

    /// Bind port, overriding `INFISICAL_MCP_PORT`.
    #[arg(long)]
    port: Option<u16>,

    /// MCP transport. Stdio requires only Infisical configuration.
    #[arg(long, default_value = "streamable-http")]
    transport: Transport,

    /// HTTP authentication profile (default: gateway). Not used with stdio.
    #[arg(long, value_enum)]
    http_profile: Option<HttpProfile>,

    /// Probe the local health endpoint and exit.
    #[arg(long, hide = true)]
    healthcheck: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Transport {
    StreamableHttp,
    Stdio,
}

enum Mode {
    Stdio(StdioSettings),
    Healthcheck {
        host: String,
        port: u16,
    },
    Serve {
        settings: Box<Settings>,
        host: String,
        port: u16,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.transport == Transport::Stdio
        && (cli.http_profile.is_some()
            || cli.host.is_some()
            || cli.port.is_some()
            || cli.healthcheck)
    {
        eprintln!("stdio does not accept HTTP profile, listener, or healthcheck options");
        return ExitCode::from(2);
    }
    let mode = if cli.healthcheck {
        let listener = match Settings::listener_from_env() {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("configuration error: {error}");
                return ExitCode::from(2);
            }
        };
        Mode::Healthcheck {
            host: cli.host.unwrap_or(listener.host),
            port: cli.port.unwrap_or(listener.port),
        }
    } else if cli.transport == Transport::Stdio {
        let settings = match StdioSettings::from_env() {
            Ok(settings) => settings,
            Err(error) => {
                eprintln!("configuration error: {error}");
                return ExitCode::from(2);
            }
        };
        init_tracing(&settings.log_level);
        Mode::Stdio(settings)
    } else {
        let settings = match Settings::from_env_with_profile(
            cli.http_profile.unwrap_or(HttpProfile::Gateway),
            cli.host.as_deref(),
            cli.port,
        ) {
            Ok(settings) => settings,
            Err(error) => {
                eprintln!("configuration error: {error}");
                return ExitCode::from(2);
            }
        };
        init_tracing(&settings.log_level);
        Mode::Serve {
            host: cli.host.unwrap_or_else(|| settings.host.clone()),
            port: cli.port.unwrap_or(settings.port),
            settings: Box::new(settings),
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to construct async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async move {
        match mode {
            Mode::Stdio(settings) => run_stdio(settings).await,
            Mode::Healthcheck { host, port } => run_healthcheck(&host, port).await,
            Mode::Serve {
                settings,
                host,
                port,
            } => run_server(*settings, &host, port).await,
        }
    });
    // Tokio's blocking stdin reader cannot be interrupted while a client keeps
    // the pipe open. Bound runtime shutdown so SIGTERM still terminates stdio.
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));

    match result {
        Ok(exit_code) => exit_code,
        Err(error) => {
            tracing::error!(error = %error, "server terminated");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .json()
                .with_target(true)
                .with_writer(std::io::stderr)
                // The SDK logs raw protocol messages, including malformed inputs.
                // Keep our bounded operational diagnostics instead of payload logs.
                .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
                    !metadata.target().starts_with("rmcp")
                })),
        )
        .try_init();
}

async fn run_stdio(settings: StdioSettings) -> anyhow::Result<ExitCode> {
    let cancellation = CancellationToken::new();
    tracing::info!("MCP stdio transport ready");
    tokio::select! {
        result = infisical_server::stdio::serve(settings, cancellation.child_token()) => result?,
        () = wait_for_shutdown_signal() => cancellation.cancel(),
    }
    Ok(ExitCode::SUCCESS)
}

async fn run_server(settings: Settings, host: &str, port: u16) -> anyhow::Result<ExitCode> {
    let cancellation = CancellationToken::new();
    let app = build_router(&settings, &cancellation).context("build application router")?;
    let bind_ip: IpAddr = host
        .parse()
        .with_context(|| format!("invalid bind IP address {host}"))?;
    let address = SocketAddr::new(bind_ip, port);
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("bind {address}"))?;
    tracing::info!(%address, "mcp-infisical-rs listening");

    let shutdown = async move {
        wait_for_shutdown_signal().await;
        cancellation.cancel();
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("serve MCP HTTP endpoint")?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => Some(signal),
        Err(error) => {
            tracing::error!(%error, "failed to install SIGTERM handler");
            None
        }
    };
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::error!(%error, "failed to install SIGINT handler");
            }
        }
        () = async {
            match terminate.as_mut() {
                Some(signal) => {
                    signal.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        } => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to install shutdown signal handler");
    }
}

async fn run_healthcheck(host: &str, port: u16) -> anyhow::Result<ExitCode> {
    let target = healthcheck_url(host, port)?;
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .context("build healthcheck client")?
        .get(target)
        .send()
        .await
        .context("request health endpoint")?;
    Ok(if response.status().is_success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn healthcheck_url(host: &str, port: u16) -> anyhow::Result<reqwest::Url> {
    let configured: IpAddr = host
        .parse()
        .with_context(|| format!("invalid healthcheck IP address {host}"))?;
    let target = match configured {
        IpAddr::V4(address) if address.is_unspecified() => {
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        }
        IpAddr::V6(address) if address.is_unspecified() => {
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        }
        address => address,
    };
    let address = SocketAddr::new(target, port);
    reqwest::Url::parse(&format!("http://{address}/healthz")).context("build healthcheck URL")
}

#[cfg(test)]
mod tests {
    use super::healthcheck_url;

    #[test]
    fn healthcheck_urls_support_wildcard_and_explicit_ip_listeners() {
        assert_eq!(
            healthcheck_url("0.0.0.0", 8000).unwrap().as_str(),
            "http://127.0.0.1:8000/healthz"
        );
        assert_eq!(
            healthcheck_url("192.0.2.1", 8000).unwrap().as_str(),
            "http://192.0.2.1:8000/healthz"
        );
        assert_eq!(
            healthcheck_url("::", 8000).unwrap().as_str(),
            "http://[::1]:8000/healthz"
        );
        assert_eq!(
            healthcheck_url("2001:db8::1", 8000).unwrap().as_str(),
            "http://[2001:db8::1]:8000/healthz"
        );
        assert!(healthcheck_url("server.example", 8000).is_err());
    }
}
