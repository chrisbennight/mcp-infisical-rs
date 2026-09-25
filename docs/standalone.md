# Standalone connections

Use stdio when an MCP client launches the server as a local child process. Use
stateless Streamable HTTP when a trusted client connects to a running service.
Both modes use the same typed operation catalog and the permissions of one
configured Infisical machine identity. This server does not assign local user
roles or implement an OAuth authorization service.

## Build and upstream configuration

Install the toolchain specified by `rust-toolchain.toml`, then build:

```sh
cargo build --release --locked -p infisical-server
```

The binary is `target/release/mcp-infisical-rs`. Supply these environment
variables to its process through your credential manager or client configuration:

| Variable | Meaning |
| --- | --- |
| `INFISICAL_API_URL` | Infisical API origin, normally HTTPS |
| `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` | Dedicated machine identity client ID |
| `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` | Machine identity client secret |
| `INFISICAL_UNIVERSAL_AUTH_ORGANIZATION_SLUG` | Optional organization scope |

The API coverage target is Infisical `v0.160.12`. Wire tests use isolated API
fakes; they do not certify every edition or a named desktop client. Operations
that require upstream licensing remain subject to that license and deployment.

The process does not load `.env` files automatically. Do not place credentials in
command arguments or commit them to configuration. Limit the machine identity's
upstream permissions to the operations and projects these callers need. An
Infisical denial remains a denial; the server does not grant additional rights.

## Local stdio

Configure your MCP client's process transport with the built binary and these
arguments, forwarding the upstream environment variables above:

```json
{
  "command": "/absolute/path/to/mcp-infisical-rs",
  "args": ["--transport", "stdio"]
}
```

The surrounding client configuration format varies. This is the process
configuration, not a claim that every client uses the same configuration file.
The server reads newline-delimited JSON-RPC on stdin and writes protocol messages
only to stdout. Diagnostics go to stderr. No HTTP listener, health endpoint,
connection bearer, gateway issuer, or JWKS URL is needed.

Have the client initialize using MCP `2025-11-25`, list tools, then call
`infisical.read` with:

```json
{
  "operation": "projects.list",
  "arguments": { "offset": 0, "limit": 10 }
}
```

The result contains `structuredContent.items`, with project metadata permitted
by the configured identity, plus a JSON text compatibility result. An empty
list can be valid. To discover other operations, call `operations.list` and
`operations.describe`; operation names are dispatched through their tier's
executor rather than appearing individually in `tools/list`.

Closing stdin ends the connection. Process termination is supported even while
stdin is open. Invalid or oversized protocol messages close the connection with
a bounded diagnostic. `INFISICAL_MCP_MAX_BODY_BYTES` bounds an incoming stdio message
(default 1 MiB). HTTP concurrency and request-timeout settings do not configure
stdio; the upstream client retains its own timeouts and response bounds.

## Stateless HTTP

In addition to the upstream configuration, supply
`INFISICAL_MCP_BEARER_CURRENT` as a cryptographically random connection credential
containing at least 32 bytes without whitespace. Keep it separate from the
Infisical credential. Start:

```sh
target/release/mcp-infisical-rs --transport streamable-http --http-profile standalone
```

The standalone default is `127.0.0.1:8000`, with exact loopback Host authorities
for the selected port. `--host` and `--port` override the listener environment
settings. For a different advertised authority, set `INFISICAL_MCP_ALLOWED_HOSTS`
explicitly, including its port when present. Browser Origins are refused unless
listed in `INFISICAL_MCP_ALLOWED_ORIGINS`.

Configure a Streamable HTTP client for `http://127.0.0.1:8000/mcp` and supply
`Authorization: Bearer …` on every request through its credential configuration.
The server returns JSON responses and does not issue MCP session IDs. Subsequent
requests include `MCP-Protocol-Version: 2025-11-25`. No `X-MCP-Identity` header is
required or interpreted in this profile. A session ID never replaces the bearer.
Clients that require automatic OAuth discovery need an upstream gateway.

`GET /healthz` is independent of both upstream availability and MCP
authentication. It proves process liveness, not successful Infisical access.
The native probe is `mcp-infisical-rs --healthcheck`. For remote access, explicitly
configure the listener and allowed authority and terminate TLS at a trusted
reverse proxy. The server itself does not serve TLS. A shared connection bearer
authenticates trusted callers; it does not identify individual users or grant
different permissions to them.

To rotate the connection credential, configure the new current value and retain
the old one temporarily as `INFISICAL_MCP_BEARER_PREVIOUS`. Restart the server,
switch clients, then remove the previous value and restart again. Each request
is authenticated independently. Stop the process with SIGINT or SIGTERM.

## Secret delivery and optional gateway integration

Stdio and HTTP without a file-transfer configuration return explicit reveal
results inline. These results can enter client logs, conversation history, or
model context. Confirmation fields express intent; they are not authorization.
Ordinary metadata reads do not reveal credential values.

The optional HTTP file-transfer extension uses short-lived, single-use,
instance-local references. It requires a client or gateway that understands
`files/authorizeDownload`, `files/authorizeUpload`, and the transfer descriptors;
ordinary MCP clients are not assumed to support it. Stdio rejects
`INFISICAL_MCP_FILE_PUBLIC_URL` instead of silently falling back from configured
file delivery to inline secrets. Use HTTP when you need this extension.

`certificates.import` accepts file references only, so it requires this HTTP
extension and is unavailable over stdio. The shared catalog still lists it;
`operations.describe` reports `availability.requiresFileTransfer: true` and
`availability.enabledHere: false` before execution on an instance without files.
Secret create/update operations also accept ordinary inline inputs and work
without the extension. Stateless HTTP means no MCP sessions; an enabled file
extension still keeps temporary, instance-local transfer state.

Use `server.info` to identify the active transport, HTTP profile where applicable,
build version, and discovery schema revision. `server.capabilities.runtime`
reports effective ingress and upstream limits, supported secret and whole-result
delivery modes, and the configured file expiry and staging ceiling. It omits
credentials, routing addresses, and limits that the transport does not enforce.
Discovery makes no upstream permission or license probe: `upstreamAccess` is
`notProbed`, and the compiled capability list is not a live entitlement check.

For the existing signed-identity integration, use
`--http-profile gateway` (also the default HTTP profile) and configure its bearer,
issuer, and JWKS URL. That profile still verifies both credentials on every
request. It may be placed behind a gateway providing user policy and attribution.
The upstream service sees the configured machine identity in every profile.

## Troubleshooting

- A configuration error names a missing variable or invalid setting. Gateway
  identity settings are required only for the gateway HTTP profile.
- HTTP 401 means the request did not provide an accepted connection bearer.
  HTTP 403 can indicate an unlisted Host or Origin; check exact authorities.
- A successful healthcheck with a failed resource call means the process is
  alive but upstream credentials, permissions, or connectivity need checking.
- A tool error after a mutation does not imply nothing happened. Reconcile
  upstream state before deciding whether to repeat it; mutations are not replayed.
- SDK payload logging is disabled, including when the log level requests SDK
  debug or trace events. Application diagnostics remain on stderr.
