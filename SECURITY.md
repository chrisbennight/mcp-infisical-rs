# Security

This server gives connected callers access through one configured Infisical
machine identity. Restrict that identity to the projects and operations needed.
Infisical is the authority for its permissions; this server does not implement
local user roles, tenant isolation, or an OAuth authorization service.

## Connection boundaries

| Mode | Connection authentication | Operator responsibility |
| --- | --- | --- |
| Stdio | Local process and pipe access | Trust the client and protect its environment, configuration, and history |
| Standalone HTTP | Connection bearer on every MCP request | Trust every bearer holder; restrict network access and terminate remote TLS |
| Gateway HTTP | Connection bearer and signed identity JWT on every MCP request | Configure the gateway's user policy and protect its signing keys |

HTTP checks exact Host authorities and configured browser Origins. It does not
serve TLS. Health checks are unauthenticated and report process liveness only.
MCP sessions are disabled. These properties do not supply per-user permissions.
The gateway profile verifies identity, but this server does not promise a
complete per-user operation audit trail. Infisical sees the machine identity.

## Secret handling

Credential values, secret identifiers, existence flags, and ordinary metadata
are different data classes. Metadata can still be sensitive. Explicit reveal
results are inline by default and may enter model context, client logs, or
conversation history. Confirmations express caller intent, not authority.

The optional HTTP file-transfer extension moves values through short-lived,
single-use references for compatible clients. It is not a universal MCP client
feature and does not add per-user authorization. Stdio cannot use it. See
[connection and delivery guidance](docs/standalone.md).

Secret-bearing Rust values redact their formatting; SDK payload logs are
suppressed and diagnostics go to stderr. This cannot control how a client,
reverse proxy, debugger, or crash collector records secrets. Protect those
systems too. Never automatically repeat a mutation after an uncertain outcome.

## Reporting

There is no supported public release yet. Security fixes target the current
development branch; there is no promised backport window or response deadline.

Do not put exploit details, credentials, or private deployment information in a
public issue. Use GitHub's **Report a vulnerability** option on the repository's
Security tab if it is available. If it is unavailable, open a minimal issue
titled “Private security contact requested” and tag `@chrisbennight`, without
technical details. The maintainer must arrange a private channel before you
send the report. Private vulnerability reporting must be verified before the
first public release.

Once a private channel is established, include the affected commit or version,
transport profile, impact, and a reproduction using synthetic data. Rotate any
real credential exposed during investigation through its owning system.
