use std::{
    error::Error as StdError,
    net::{IpAddr, SocketAddr},
};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use thiserror::Error;
use url::{Host, Url};

const IPV6_INSTANCE_METADATA: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// DNS policy required by a validated outbound HTTP URL.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionPolicy {
    System,
    PrivateOnly,
}

/// System DNS adapter used when a private hostname must be validated before use.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(boxed_resolver_error)?
                .collect::<Vec<_>>();
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

/// Resolver that accepts an answer only when every address is private.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct PrivateHttpResolver<R> {
    inner: R,
}

impl<R> PrivateHttpResolver<R> {
    #[must_use]
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R> Resolve for PrivateHttpResolver<R>
where
    R: Resolve,
{
    fn resolve(&self, name: Name) -> Resolving {
        let resolved = self.inner.resolve(name);
        Box::pin(async move {
            let addresses = resolved.await?.collect::<Vec<_>>();
            let addresses = validate_private_resolution(addresses).map_err(boxed_resolver_error)?;
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

#[derive(Debug, Error)]
#[error("private HTTP hostname did not resolve exclusively to private addresses")]
struct UnsafePrivateResolution;

fn boxed_resolver_error(
    error: impl StdError + Send + Sync + 'static,
) -> Box<dyn StdError + Send + Sync> {
    Box::new(error)
}

/// Classify a credential-free URL authority for redirect-free HTTP use.
///
/// HTTPS and explicit loopback HTTP use the system resolver. Private HTTP
/// service names require a validating resolver so DNS rebinding cannot redirect
/// credentials. Callers remain responsible for validating the URL path.
#[doc(hidden)]
#[must_use]
pub fn url_resolution_policy(url: &Url, allow_private_http: bool) -> Option<ResolutionPolicy> {
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    if url.scheme() == "https" {
        return Some(ResolutionPolicy::System);
    }
    if url.scheme() != "http" {
        return None;
    }
    match url.host() {
        Some(Host::Domain(host)) if host.eq_ignore_ascii_case("localhost") => {
            Some(ResolutionPolicy::System)
        }
        Some(Host::Domain(host)) if allow_private_http && is_private_service_name(host) => {
            Some(ResolutionPolicy::PrivateOnly)
        }
        Some(Host::Ipv4(address))
            if address.is_loopback() || (allow_private_http && address.is_private()) =>
        {
            Some(ResolutionPolicy::System)
        }
        Some(Host::Ipv6(address))
            if address.is_loopback()
                || (allow_private_http && ipv6_is_private_destination(address)) =>
        {
            Some(ResolutionPolicy::System)
        }
        _ => None,
    }
}

#[doc(hidden)]
pub fn validate_private_resolution(
    addresses: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, impl StdError + Send + Sync + 'static> {
    if addresses.is_empty() || addresses.iter().any(|address| !ip_is_private(address.ip())) {
        return Err(UnsafePrivateResolution);
    }
    Ok(addresses)
}

fn ip_is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => ipv6_is_private_destination(address),
    }
}

fn ipv6_is_unique_local(address: std::net::Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

fn ipv6_is_private_destination(address: std::net::Ipv6Addr) -> bool {
    ipv6_is_unique_local(address) && address != IPV6_INSTANCE_METADATA
}

fn is_private_service_name(host: &str) -> bool {
    host.len() <= 63
        && !host.contains('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && host
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && host
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}
