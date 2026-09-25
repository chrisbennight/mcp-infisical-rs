# HTTP configuration reference

For the standalone Quickstart, see [Standalone connections](standalone.md).
The signed-identity requirements below apply only to the gateway profile.

In the gateway profile, all `/mcp` requests require both `Authorization: Bearer …` and
`X-MCP-Identity: …`. The bearer must contain at least 32 bytes and the identity
JWT must use EdDSA with a known `kid`, the configured issuer, audience
`infisical` (fixed by the server), and valid temporal claims. A fresh unknown
`kid` triggers a single-flight JWKS refresh limited to once every five seconds.
Failed fetches apply the same five-second cooldown even with an empty or expired
key cache. A cancelled fetch retains a retry window bounded by the JWKS request
timeout plus five seconds. A still-fresh cached key remains usable; expired keys
are never accepted as a fallback. Requests refused during a refresh cooldown
stay unauthorized and carry a bounded `Retry-After` header.
JWKS redirects and ambient proxies are disabled. Remote cleartext URLs are
rejected unless `INFISICAL_MCP_IDENTITY_ALLOW_PRIVATE_HTTP=true` explicitly
enables the same DNS-pinned private-authority policy used by the Infisical API
client. A present browser `Origin` is rejected unless it is explicitly
configured; `Host` is always matched against exact authorities.

See [.env.example](../.env.example) for an HTTP configuration example. In particular,
operators must set the Host allowlist to the advertised service
authority and set a cryptographically random 256-bit bearer. The
optional previous bearer is only for a bounded rotation overlap.

The upstream client accepts HTTPS API roots and loopback HTTP fixtures by
default. `INFISICAL_API_ALLOW_PRIVATE_HTTP=true` additionally permits only
single-label container service names, RFC 1918 IPv4 addresses, and IPv6
unique-local addresses. A permitted service name is resolved for each new
connection; the complete answer must contain only RFC 1918 or IPv6 unique-local
addresses, and the checked addresses are passed directly to the connector.
Public, link-local, metadata-service, credential-bearing, path-bearing,
query-bearing, and fragment-bearing cleartext URLs remain rejected. Resolved
service names also reject loopback answers, while explicit localhost and
loopback IP URLs retain their fixture behavior. The client ignores ambient
proxy settings, disables redirects, and bounds both request time and response
bytes. Universal Auth access tokens are zeroized on drop, cached only until a
pre-expiry deadline, and refreshed through one shared single-flight path. An
authentication failure retries a declared idempotent read once; observable
reads and mutations invalidate the rejected token for the next call but are
never replayed.

Failed logins pause new login attempts for five seconds; rejected credentials
pause them for thirty seconds. Upstream `Retry-After` guidance can extend the
pause up to five minutes. Callers receive a safe remaining-wait hint and the
original failure category, and the next eligible request can recover without
restarting the process. Both numeric and HTTP-date retry headers are supported,
with malformed or duplicate headers ignored. A retry hint controls pacing; it
does not make an observable read or mutation safe to replay.

Serving mode requires `INFISICAL_API_URL`,
`INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`, and
`INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET`; an optional
`INFISICAL_UNIVERSAL_AUTH_ORGANIZATION_SLUG` scopes the login when the deployed
identity requires it. The private-HTTP opt-in is intended only for an isolated
container network where Infisical does not expose TLS on its internal port.
Startup validates these settings and fails before binding when the upstream
client cannot be constructed. Healthcheck mode deliberately reads none of them.

The container health probe should invoke `mcp-infisical-rs --healthcheck`.
Healthcheck mode reads only the listener host and port, maps wildcard binds to
loopback, requests `/healthz` with a two-second deadline, and does not require
gateway or Infisical credentials.

## Reveal transfer plane

Setting `INFISICAL_MCP_FILE_PUBLIC_URL` to the origin the file-aware client dials — the
same scheme and authority as the `/mcp` endpoint, for example
`http://infisical-mcp:8000` — enables reference delivery for the reveal-class
operations. Staged envelopes live only in zeroizing memory, expire after
`INFISICAL_MCP_FILE_TTL_SECONDS` (default 120), are capped at
`INFISICAL_MCP_FILE_MAX_STAGED` (default 16) outstanding entries, and each
serves exactly one download. The download route authenticates with the
per-download `Infisical-Transfer-Credential` header minted by
`files/authorizeDownload` rather than the gateway bearer, because the gateway
fetches file transfers with descriptor headers alone. Every envelope is padded
to a fixed-size bucket with a random pad: the size a staging intermediary
publishes is a coarse bucket count — constant within a bucket and across
repeated reveals of one value, though values on opposite sides of a bucket
boundary still publish different counts — and the digest is salted.
The plane also carries the reverse direction: `secrets.create` and
`secrets.update` accept a `secretValueFile` reference in place of an inline
`secretValue`, while `certificates.import` accepts `certificateFile` and
optional `privateKeyFile` and `certificateChainFile` references. Each resolves
single-use from a value the gateway uploaded through `files/authorizeUpload`
and the credentialed `PUT /files/upload/{id}` route, so locally held material
need not enter model context. Inline `secretValue` remains supported unchanged.
Every executor additionally accepts `resultDelivery: "file"`, which stages any
operation's whole structured result on the plane and returns a fixed
operation-plus-`resultFile` wrapper, letting a host read large results
selectively out of context; the oversized-result refusal names this retry path
when the plane is configured and the call is classified as safely repeatable —
a refusal whose effect already applied never points at a retry.
Staged state is instance-local: a reference resolves only on the instance that
minted it, so run a single replica or pin download routing to the staging instance. Enable the plane only for a client or gateway
that implements this extension; ordinary MCP clients cannot resolve these
references.
