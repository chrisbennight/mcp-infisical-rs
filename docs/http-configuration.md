# HTTP configuration reference

For the standalone Quickstart, see [Standalone connections](standalone.md).
The signed-identity requirements below apply only to the gateway profile.

`INFISICAL_MCP_OPERATION_PROFILE` independently selects `metadata`, `secrets`,
`pkiSsh`, or `full` capabilities in every transport. See [Operation policy](operation-policy.md).

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

`INFISICAL_API_MAX_CONCURRENT_REQUESTS` bounds simultaneous upstream HTTP
requests across every client clone, including authentication, reads, and writes.
It defaults to 32 and accepts 1 through 256 in both HTTP and stdio modes. Waiting
for capacity consumes the same per-request timeout as network work. An exhausted
budget rejects that HTTP request before sending it. This is separate from
`INFISICAL_MCP_MAX_CONCURRENT_REQUESTS`, which bounds incoming HTTP requests.
Bulk KMS private-key preflights also have a total deadline and at most eight
concurrent reads per batch; they share the upstream budget with other work.

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
permits at most one download attempt. The download route authenticates with the
per-download `Infisical-Transfer-Credential` header minted by
`files/authorizeDownload` rather than the gateway bearer, because the gateway
fetches file transfers with descriptor headers alone. Every envelope is padded
to a fixed-size bucket with a random pad: the size a staging intermediary
publishes is a coarse bucket count — constant within a bucket and across
repeated reveals of one value, though values on opposite sides of a bucket
boundary still publish different counts — and the digest is salted.

`INFISICAL_MCP_FILE_MAX_STAGED_BYTES` bounds aggregate promised and retained
transfer bytes (default 512 MiB, configurable from 256 MiB through 1 GiB).
An output reserves its full 128 MiB envelope ceiling before upstream work,
then releases the unused portion after serialization. Requests that need both
a secret reference and a whole-result file reserve two envelopes. A staged
value keeps its charge after redemption until the HTTP response body is dropped.
An upload reserves its declared length, or the full 64 KiB upload ceiling when
no length is supplied; failed or cancelled transfers release their reservation.
A completed upload retains a charge for its allocated buffer, including spare
capacity after a short upload.
Expired staged entries release their bytes when swept. Uploaded values leave
this accounting when an operation consumes them. This limit covers transfer
buffers and reservations, not total process memory or upstream decoding buffers.

The output reservation accommodates the client’s maximum 16 MiB upstream body,
even allowing six JSON bytes per decoded byte and another 2 MiB for fixed
wrappers and bounded identifiers. Credential creation selects its token or
client-secret value and metadata from one response; dynamic SQL credentials
have explicit username/password limits. Certificate issuance and renewal cap
combined normalized material at 96 KiB, and SSH issuance bounds its key material.
KMS bulk reveal selects at most 100 keys from one bounded final response; its
preflight responses are not concatenated into the result. Changing these
contracts requires reviewing the envelope reservation as well as the API limits.

Runtime capabilities report both aggregate and per-envelope limits. Large
whole-result responses exceeding the envelope ceiling fail without an inline
fallback; reconcile any completed mutation before retrying.

The plane also carries the reverse direction: `secrets.create` and
`secrets.update` accept a `secretValueFile` reference in place of an inline
`secretValue`, while `certificates.import` accepts `certificateFile` and
optional `privateKeyFile` and `certificateChainFile` references. Each resolves
single-use from a value the gateway uploaded through `files/authorizeUpload`
and the credentialed `PUT /files/upload/{id}` route, so locally held material
need not enter model context. Inline `secretValue` remains supported unchanged.
Every executor additionally accepts `resultDelivery: "file"`, which stages any
operation's whole structured result on the plane and returns a fixed
operation-plus-`resultFile` wrapper with a bounded, value-free reconciliation
receipt, letting a host read large results
selectively out of context; the oversized-result refusal names this retry path
when the plane is configured and the call is classified as safely repeatable —
a refusal whose effect already applied never points at a retry.
Staged state is instance-local: a reference resolves only on the instance that
minted it, so run a single replica or pin download routing to the staging instance. Enable the plane only for a client or gateway
that implements this extension; ordinary MCP clients cannot resolve these
references.

### Transfer lifetime and uncertain receipt

Before an operation that can issue a credential once, inspect
the `runtime.delivery.fileTransfer` field from `server.capabilities` and the
operation's delivery schema.
The capability reports this server's extension identifier and version, effective
expiry, instance locality, and restart loss. It does not assert that the client
has a compatible transfer adapter. Establish that adapter before issuance;
an explicit reference request never falls back to putting values inline.

An authenticated GET consumes the staged download before the recipient can
acknowledge receipt. A connection failure after redemption can therefore lose
delivery. A wrong credential or HEAD request does not consume the value.
Reauthorizing an unconsumed reference invalidates the previous download
credential; it does not restore an already consumed or expired value. Restart
loses staged values and authorizations. Expiry and restart do not revoke a
credential that Infisical has already created.

The whole-result wrapper retains a `reconciliation` list for credential issuance,
containing only typed resource kinds and bounded resource identifiers. It never
contains credential values or resource labels. An empty list means no supported
identifier was available; retain the request scope and use scoped inventory.

Keep the original operation, input scope, and returned non-secret resource
identifiers in the authorized host. If delivery is uncertain, inspect that exact
resource before deciding whether to revoke, replace, or issue another credential.
For client secrets and tokens, retain their metadata identifiers; for dynamic
leases, retain the lease identifier and original project/environment/path; for
certificates, retain the certificate or request identifier and owning project.
Do not use a matching display name alone to select a resource for revocation.
Do not replay issuance because a file download failed. If the complete tool
response was also lost, reconcile through the scoped inventory or upstream audit
records; this process cannot promise recovery of the original credential value.

For replicas, the operator's deployment configuration must route authorization,
upload, and download requests to the process that owns the reference. An MCP
session does not itself provide that routing. This server does not persist
staged credentials in a shared database. Stdio hosts can compose typed calls
and filter inline results through the host-client package; the stdio transport
has no file listener and exposes no local path access.
