use std::{env, sync::Arc, time::Duration};

use axum::http::uri::Authority;
use infisical_api::{ClientConfigError, ClientSettings, InfisicalClient, SecretValue};
use thiserror::Error;
use url::Url;

use crate::auth::{BearerConfigError, GatewayBearers, IdentityVerifierSettings};

const DEFAULT_HOST: &str = "0.0.0.0";
const DEFAULT_PORT: u16 = 8000;
const DEFAULT_ALLOWED_HOSTS: &str = "localhost,127.0.0.1";
const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 32;
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const IDENTITY_REQUEST_TIMEOUT_SECONDS: u64 = 3;
const IDENTITY_CACHE_SECONDS: u64 = 300;
const DEFAULT_FILE_TTL_SECONDS: u64 = 120;
const DEFAULT_FILE_MAX_STAGED: usize = 16;

pub struct Settings {
    pub operation_profile: infisical_mcp::policy::OperationProfile,
    pub host: String,
    pub port: u16,
    pub log_level: String,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub request_timeout: Duration,
    pub max_concurrent_requests: usize,
    pub max_body_bytes: usize,
    pub bearers: Arc<GatewayBearers>,
    pub identity: Option<IdentityVerifierSettings>,
    pub infisical: InfisicalClient,
    pub files: Option<FileSettings>,
}

/// The reveal transfer plane, enabled by configuring the origin the gateway dials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSettings {
    /// Scheme and authority only, normalized; descriptors are built from it verbatim.
    pub public_origin: String,
    pub ttl: Duration,
    pub max_staged: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerSettings {
    pub host: String,
    pub port: u16,
}

/// HTTP authentication profile; Infisical enforces upstream permissions in both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HttpProfile {
    Gateway,
    Standalone,
}

/// Configuration for a local process with no HTTP listener or file-transfer routes.
pub struct StdioSettings {
    pub operation_profile: infisical_mcp::policy::OperationProfile,
    pub infisical: InfisicalClient,
    pub log_level: String,
    pub max_body_bytes: usize,
}

impl StdioSettings {
    /// Read upstream credentials and local transport bounds without gateway settings.
    ///
    /// # Errors
    /// Returns an error for invalid upstream settings or unsupported file delivery.
    pub fn from_env() -> Result<Self, SettingsError> {
        if optional("INFISICAL_MCP_FILE_PUBLIC_URL").is_some() {
            return Err(SettingsError::Invalid {
                variable: "INFISICAL_MCP_FILE_PUBLIC_URL",
                message: "file transfers require HTTP transport; unset this variable for stdio"
                    .into(),
            });
        }
        Ok(Self {
            infisical: infisical_from_env()?,
            operation_profile: operation_profile_from_env()?,
            log_level: value_or("INFISICAL_MCP_LOG_LEVEL", "info"),
            max_body_bytes: parse_number(
                "INFISICAL_MCP_MAX_BODY_BYTES",
                DEFAULT_MAX_BODY_BYTES,
                1024,
                16 * 1024 * 1024,
            )?,
        })
    }
}

#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid value for {variable}: {message}")]
    Invalid {
        variable: &'static str,
        message: String,
    },
    #[error(transparent)]
    Bearer(#[from] BearerConfigError),
    #[error(transparent)]
    Infisical(#[from] ClientConfigError),
}

impl Settings {
    /// Read and validate the complete ingress security configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when a required value is absent, malformed, weak, or
    /// outside a supported operational bound.
    pub fn from_env() -> Result<Self, SettingsError> {
        Self::from_env_with_profile(HttpProfile::Gateway, None, None)
    }

    /// Read settings for the selected HTTP authentication profile.
    ///
    /// # Errors
    /// Returns an error for missing credentials or invalid operational bounds.
    pub fn from_env_with_profile(
        profile: HttpProfile,
        host: Option<&str>,
        port: Option<u16>,
    ) -> Result<Self, SettingsError> {
        let mut listener = Self::listener_from_env()?;
        if profile == HttpProfile::Standalone {
            listener.host = value_or("INFISICAL_MCP_HOST", "127.0.0.1");
        }
        if let Some(host) = host {
            host.clone_into(&mut listener.host);
        }
        if let Some(port) = port {
            listener.port = port;
        }
        let default_allowed_hosts = if profile == HttpProfile::Standalone {
            format!(
                "localhost,127.0.0.1,[::1],localhost:{},127.0.0.1:{},[::1]:{}",
                listener.port, listener.port, listener.port
            )
        } else {
            DEFAULT_ALLOWED_HOSTS.to_owned()
        };
        let current = required_secret("INFISICAL_MCP_BEARER_CURRENT")?;
        let previous = optional_secret("INFISICAL_MCP_BEARER_PREVIOUS");
        let bearers = Arc::new(GatewayBearers::new(current, previous)?);
        let identity = if profile == HttpProfile::Gateway {
            let jwks_url = parse_url(
                "INFISICAL_MCP_IDENTITY_JWKS_URL",
                &required("INFISICAL_MCP_IDENTITY_JWKS_URL")?,
            )?;
            let issuer = required("INFISICAL_MCP_IDENTITY_ISSUER")?;
            let identity_allow_private_http =
                optional_exact("INFISICAL_MCP_IDENTITY_ALLOW_PRIVATE_HTTP")?;
            Some(IdentityVerifierSettings {
                jwks_url,
                issuer,
                allow_private_http: parse_boolean(
                    "INFISICAL_MCP_IDENTITY_ALLOW_PRIVATE_HTTP",
                    identity_allow_private_http.as_deref(),
                    false,
                )?,
                request_timeout: Duration::from_secs(IDENTITY_REQUEST_TIMEOUT_SECONDS),
                cache_ttl: Duration::from_secs(IDENTITY_CACHE_SECONDS),
            })
        } else {
            None
        };
        let infisical = infisical_from_env()?;

        Ok(Self {
            host: listener.host,
            operation_profile: operation_profile_from_env()?,
            port: listener.port,
            log_level: value_or("INFISICAL_MCP_LOG_LEVEL", "info"),
            allowed_hosts: parse_allowed_hosts(&value_or(
                "INFISICAL_MCP_ALLOWED_HOSTS",
                &default_allowed_hosts,
            ))?,
            allowed_origins: parse_allowed_origins(
                &env::var("INFISICAL_MCP_ALLOWED_ORIGINS").unwrap_or_default(),
            )?,
            request_timeout: Duration::from_secs(parse_number(
                "INFISICAL_MCP_REQUEST_TIMEOUT_SECONDS",
                DEFAULT_REQUEST_TIMEOUT_SECONDS,
                1,
                120,
            )?),
            max_concurrent_requests: parse_number(
                "INFISICAL_MCP_MAX_CONCURRENT_REQUESTS",
                DEFAULT_MAX_CONCURRENT_REQUESTS,
                1,
                1024,
            )?,
            max_body_bytes: parse_number(
                "INFISICAL_MCP_MAX_BODY_BYTES",
                DEFAULT_MAX_BODY_BYTES,
                1024,
                16 * 1024 * 1024,
            )?,
            bearers,
            identity,
            infisical,
            files: file_settings_from_env()?,
        })
    }

    /// Read only the listener coordinates needed by the native healthcheck.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured port is malformed or out of range.
    pub fn listener_from_env() -> Result<ListenerSettings, SettingsError> {
        Ok(ListenerSettings {
            host: value_or("INFISICAL_MCP_HOST", DEFAULT_HOST),
            port: parse_number("INFISICAL_MCP_PORT", DEFAULT_PORT, 1, u16::MAX)?,
        })
    }
}

fn operation_profile_from_env() -> Result<infisical_mcp::policy::OperationProfile, SettingsError> {
    const VARIABLE: &str = "INFISICAL_MCP_OPERATION_PROFILE";
    infisical_mcp::policy::OperationProfile::parse(&value_or(VARIABLE, "full")).map_err(|message| {
        SettingsError::Invalid {
            variable: VARIABLE,
            message: message.into(),
        }
    })
}

fn infisical_from_env() -> Result<InfisicalClient, SettingsError> {
    let mut settings = ClientSettings::new(
        parse_url("INFISICAL_API_URL", &required("INFISICAL_API_URL")?)?,
        required("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID")?,
        SecretValue::new(required_secret("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET")?),
    );
    let allow_private_http = optional_exact("INFISICAL_API_ALLOW_PRIVATE_HTTP")?;
    settings.allow_private_http = parse_boolean(
        "INFISICAL_API_ALLOW_PRIVATE_HTTP",
        allow_private_http.as_deref(),
        false,
    )?;
    settings.organization_slug = optional("INFISICAL_UNIVERSAL_AUTH_ORGANIZATION_SLUG");
    settings.max_concurrent_requests = parse_number(
        "INFISICAL_API_MAX_CONCURRENT_REQUESTS",
        settings.max_concurrent_requests,
        1,
        256,
    )?;
    Ok(InfisicalClient::new(settings)?)
}

fn required(variable: &'static str) -> Result<String, SettingsError> {
    optional(variable).ok_or(SettingsError::Missing(variable))
}

fn optional(variable: &'static str) -> Option<String> {
    env::var(variable)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn optional_exact(variable: &'static str) -> Result<Option<String>, SettingsError> {
    match env::var(variable) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(SettingsError::Invalid {
            variable,
            message: "expected true or false".to_owned(),
        }),
    }
}

fn required_secret(variable: &'static str) -> Result<String, SettingsError> {
    optional_secret(variable).ok_or(SettingsError::Missing(variable))
}

fn optional_secret(variable: &'static str) -> Option<String> {
    env::var(variable).ok().filter(|value| !value.is_empty())
}

fn value_or(variable: &'static str, default: &str) -> String {
    optional(variable).unwrap_or_else(|| default.to_owned())
}

fn parse_boolean(
    variable: &'static str,
    value: Option<&str>,
    default: bool,
) -> Result<bool, SettingsError> {
    match value {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => Err(SettingsError::Invalid {
            variable,
            message: "expected true or false".to_owned(),
        }),
    }
}

fn parse_number<T>(
    variable: &'static str,
    default: T,
    minimum: T,
    maximum: T,
) -> Result<T, SettingsError>
where
    T: Copy + PartialOrd + std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = match optional(variable) {
        Some(raw) => raw.parse::<T>().map_err(|error| SettingsError::Invalid {
            variable,
            message: error.to_string(),
        })?,
        None => default,
    };
    if value < minimum || value > maximum {
        return Err(SettingsError::Invalid {
            variable,
            message: "value is outside the supported range".to_owned(),
        });
    }
    Ok(value)
}

fn file_settings_from_env() -> Result<Option<FileSettings>, SettingsError> {
    let Some(raw) = optional("INFISICAL_MCP_FILE_PUBLIC_URL") else {
        return Ok(None);
    };
    Ok(Some(FileSettings {
        public_origin: parse_file_public_origin(&raw)?,
        ttl: Duration::from_secs(parse_number(
            "INFISICAL_MCP_FILE_TTL_SECONDS",
            DEFAULT_FILE_TTL_SECONDS,
            10,
            3600,
        )?),
        // Envelopes can be as large as the upstream response ceiling, so the entry
        // ceiling is kept small enough that a legal configuration cannot commit
        // gigabytes of process memory to staged secrets. The floor is 2 because
        // one call may legitimately stage two entries: a whole-result envelope
        // plus the secret reference it wraps. A cap of 1 would make that
        // combination impossible by construction rather than merely contended.
        max_staged: parse_number(
            "INFISICAL_MCP_FILE_MAX_STAGED",
            DEFAULT_FILE_MAX_STAGED,
            2,
            64,
        )?,
    }))
}

/// The origin a file-transfer descriptor names, so the gateway can dial it.
///
/// Parsed rather than pattern-matched, and rebuilt from the parse so descriptors are
/// built from a normalized value. A path, query, fragment, or userinfo here would be
/// refused by the gateway on every transfer, so failing at startup is strictly better.
/// Plain `http` is accepted because the gateway admits a cleartext transfer only on the
/// pinned private segment it already reaches this server's `/mcp` endpoint over.
fn parse_file_public_origin(value: &str) -> Result<String, SettingsError> {
    const VARIABLE: &str = "INFISICAL_MCP_FILE_PUBLIC_URL";
    let invalid = |message: &str| SettingsError::Invalid {
        variable: VARIABLE,
        message: message.to_owned(),
    };
    let parsed = parse_url(VARIABLE, value)?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(invalid("scheme must be http or https"));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(invalid("a host is required"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid("userinfo is not allowed"));
    }
    if !matches!(parsed.path(), "" | "/") || parsed.query().is_some() || parsed.fragment().is_some()
    {
        return Err(invalid(
            "only a scheme and authority are allowed, with no path, query, or fragment",
        ));
    }
    // The origin serialization, not a manual rebuild: it preserves IPv6 brackets and
    // normalizes default ports.
    Ok(parsed.origin().ascii_serialization())
}

fn parse_url(variable: &'static str, value: &str) -> Result<Url, SettingsError> {
    Url::parse(value).map_err(|error| SettingsError::Invalid {
        variable,
        message: error.to_string(),
    })
}

fn parse_allowed_hosts(value: &str) -> Result<Vec<String>, SettingsError> {
    let hosts = parse_csv(value)
        .map(|host| {
            host.parse::<Authority>()
                .map(|authority| authority.as_str().to_ascii_lowercase())
                .map_err(|error| SettingsError::Invalid {
                    variable: "INFISICAL_MCP_ALLOWED_HOSTS",
                    message: error.to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if hosts.is_empty() {
        return Err(SettingsError::Invalid {
            variable: "INFISICAL_MCP_ALLOWED_HOSTS",
            message: "at least one exact host authority is required".to_owned(),
        });
    }
    Ok(hosts)
}

fn parse_allowed_origins(value: &str) -> Result<Vec<String>, SettingsError> {
    parse_csv(value)
        .map(|origin| {
            let parsed = Url::parse(origin).map_err(|error| SettingsError::Invalid {
                variable: "INFISICAL_MCP_ALLOWED_ORIGINS",
                message: error.to_string(),
            })?;
            if !matches!(parsed.scheme(), "http" | "https")
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || parsed.path() != "/"
            {
                return Err(SettingsError::Invalid {
                    variable: "INFISICAL_MCP_ALLOWED_ORIGINS",
                    message: "origins must contain only an http(s) scheme and authority".to_owned(),
                });
            }
            Ok(parsed.origin().ascii_serialization())
        })
        .collect()
}

fn parse_csv(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{
        parse_allowed_hosts, parse_allowed_origins, parse_boolean, parse_file_public_origin,
    };

    #[test]
    fn file_public_origins_are_normalized_including_ipv6_brackets() {
        assert_eq!(
            parse_file_public_origin("http://infisical-mcp:8000").unwrap(),
            "http://infisical-mcp:8000"
        );
        assert_eq!(
            parse_file_public_origin("http://[::1]:8000/").unwrap(),
            "http://[::1]:8000"
        );
        assert!(parse_file_public_origin("http://user:pw@infisical-mcp:8000").is_err());
        assert!(parse_file_public_origin("http://infisical-mcp:8000/files").is_err());
        assert!(parse_file_public_origin("ftp://infisical-mcp").is_err());
    }

    #[test]
    fn allowed_hosts_are_exact_normalized_authorities() {
        assert_eq!(
            parse_allowed_hosts("Infisical-MCP:8000, localhost").unwrap(),
            ["infisical-mcp:8000", "localhost"]
        );
        assert!(parse_allowed_hosts("").is_err());
        assert!(parse_allowed_hosts("https://infisical-mcp").is_err());
    }

    #[test]
    fn allowed_origins_are_normalized_and_paths_are_rejected() {
        assert_eq!(
            parse_allowed_origins("HTTPS://MCP.EXAMPLE:443, http://localhost:3000").unwrap(),
            ["https://mcp.example", "http://localhost:3000"]
        );
        assert!(parse_allowed_origins("").unwrap().is_empty());
        assert!(parse_allowed_origins("https://mcp.example/path").is_err());
    }

    #[test]
    fn private_http_opt_in_is_strict_and_defaults_false() {
        assert!(!parse_boolean("TEST_BOOLEAN", None, false).unwrap());
        assert!(parse_boolean("TEST_BOOLEAN", Some("true"), false).unwrap());
        assert!(!parse_boolean("TEST_BOOLEAN", Some("false"), true).unwrap());
        for invalid in ["", " ", " true ", "false ", "1", "yes", "TRUE"] {
            assert!(
                parse_boolean("TEST_BOOLEAN", Some(invalid), false).is_err(),
                "{invalid}"
            );
        }
    }
}
