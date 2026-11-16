# Human approval

Human approval is an optional global setting for standalone and gateway HTTP.
An authenticated client requests an ordinary operation and receives a rejection,
an approval link, and an inactive approval token. A person signs in through
Authentik, reviews the request, and chooses permission. The client then retries
explicitly with the same token. A human decision never starts Infisical work.

The embedded dashboard is served by the existing binary at `/approval`.
There is no separate frontend build or approval service. Enabling approval with
stdio refuses startup; stdio does not support this capability.

## Configure the server and Authentik proxy

Keep the existing [HTTP authentication](http-configuration.md) and Infisical
machine identity configuration. Supply these additional environment settings
through the operator's deployment system:

| Variable | Default | Purpose |
| --- | --- | --- |
| `INFISICAL_MCP_HUMAN_APPROVAL_ENABLED` | `false` | Require approval for every Infisical operation over HTTP |
| `INFISICAL_MCP_APPROVAL_PUBLIC_URL` | required when enabled | Public HTTPS origin, such as `https://approval.example.com`, without a path, query, or credentials; loopback HTTP is accepted for local testing |
| `INFISICAL_MCP_APPROVAL_PROXY_BEARER` | required when enabled | Independently generated proxy credential, at least 32 bytes, distinct from both MCP ingress bearers |
| `INFISICAL_MCP_APPROVAL_TRUSTED_PROXY_IPS` | `127.0.0.1,::1` | Comma-separated exact socket peer IP addresses permitted to assert human identity |
| `INFISICAL_MCP_APPROVAL_APPROVER_USERS` | empty | Comma-separated Authentik usernames permitted to decide |
| `INFISICAL_MCP_APPROVAL_APPROVER_GROUPS` | empty | Comma-separated Authentik groups permitted to decide; at least one user or group is required |
| `INFISICAL_MCP_APPROVAL_DENIED_USERS` | empty | Comma-separated service or other accounts excluded even if they match an allowed group |
| `INFISICAL_MCP_APPROVAL_DURATION_PRESETS_SECONDS` | `300,900,3600,86400` | Between one and sixteen positive presets within the maximum duration |
| `INFISICAL_MCP_APPROVAL_MAX_DURATION_SECONDS` | `86400` | Maximum custom or preset duration; configurable up to one year |
| `INFISICAL_MCP_APPROVAL_PENDING_TTL_SECONDS` | `900` | Time to decide a pending request; configurable from one second to one day |
| `INFISICAL_MCP_APPROVAL_ONCE_TTL_SECONDS` | `300` | Time to redeem an approved single attempt; configurable up to one hour |
| `INFISICAL_MCP_APPROVAL_MAX_SESSIONS` | `256` | Total bounded session capacity, including in-flight attempts; at most 1024 |
| `INFISICAL_MCP_APPROVAL_MAX_PENDING_PER_CLIENT` | `8` | Pending requests per verified owner, no greater than total capacity |

Use an Authentik proxy provider/outpost and an authenticating reverse proxy for
the public approval origin. Provisioning the identity provider and ingress
belongs in the operator's deployment repository. The server expects this
integration contract:

1. Protect `/approval` and every `/approval/*` route with human SSO, including
   assets and API routes. Restrict the Authentik application to human approvers;
   exclude machine accounts from its access policy and the server allowlists.
2. Strip client-supplied `Authorization`, `X-Authentik-Username`,
   `X-Authentik-Groups`, and `X-MCP-Identity` on the approval upstream path.
   After successful SSO, inject the separate proxy bearer and the verified
   `X-Authentik-Username`. Forward verified groups as `X-Authentik-Groups`,
   separated by `|`. Never let a browser choose these headers.
3. Configure exact proxy socket addresses in `TRUSTED_PROXY_IPS`. Forwarded IP
   headers do not establish trust. Restrict direct access to the listener and
   protect the proxy-to-server network against credential interception.
4. Preserve the external authority in `Host` and add it to
   `INFISICAL_MCP_ALLOWED_HOSTS`. Preserve the browser's `Origin` on decisions;
   it must equal `APPROVAL_PUBLIC_URL`. The dashboard and its API share one
   origin. Do not enable cross-origin decision access.
5. Route `/mcp` through its existing authentication path. The human proxy bearer
   is never an MCP credential. File transfers keep their descriptor credentials.

The server checks proxy credentials, actual socket peer, human allowlists,
same-origin decisions, and a per-human CSRF token. Pages and API responses are
not cacheable. A restrictive content security policy permits only embedded
same-origin assets. No browser-side dependency downloads are needed.

## Human decisions and their scope

The dashboard shows the operation, authenticated client and calling actor,
available project/environment scope, a bounded coordinate/identifier preview,
and remaining time. The preview uses selected metadata fields from validated
inputs; it omits secret values, provider configuration, file credentials, and
complete arguments. It does not establish authority. Compare the intended work
with the client before approving when the preview is insufficient.

**Approve once** binds the exact operation, submitted arguments, file references,
and whole-result delivery choice to one admitted attempt. The attempt consumes
permission even if validation later fails or its response is lost. Changing an
argument requires a fresh request. **Approve for duration** starts the clock
when the human decides and offers two choices:

- **Client global:** all operations otherwise available to that authenticated
  client carrying this token. Infisical permissions, operation profiles,
  confirmations, and gateway policy still apply.
- **Project/environment:** only supported operations in the exact project ID
  and environment slug consumed by the typed API handler. This grants access
  to a namespace for the approved period, including resources created there
  later; it does not pin an immutable environment object or a particular path.

Project/environment restriction is available for secret metadata listing,
exact secret reveal/create/update/delete, secret batches, and folder
list/create/update/delete. Imports, mixed-environment folder batches,
ID-only lookups, project-wide work, and APIs addressed by project slug do not
claim this scope. The page explains when restriction is unavailable; once and
global approval remain available. Scope is selected by reviewed operation
adapters, never inferred from arbitrary argument names.

Default buttons offer five minutes, fifteen minutes, one hour, and twenty-four
hours. A person can enter a custom duration in seconds, minutes, hours, or days
within the configured limit, deny a pending request, or revoke active approval.
Current approvals and retained decision history show permission and approver.

## Client contract and explicit retry

`server.capabilities.runtime.humanApproval` reports the enabled setting.
All four executors accept optional `approvalToken` alongside `operation_id`,
`arguments`, and `resultDelivery`. Discovery and `approval.session` do not need
human permission. A refusal is a tool result with `isError: true`, matching
structured content and JSON text, and this shape:

```json
{
  "error": {
    "category": "approvalRequired",
    "effect": "notStarted",
    "recovery": "obtainApproval",
    "correction": "Present the approval link to the human, then explicitly retry with approvalToken.",
    "operation": "projects.list"
  },
  "approval": {
    "reason": "required",
    "approvalUrl": "https://approval.example.com/approval?request=public-request-id",
    "approvalToken": "<opaque credential retained by the authorized host>",
    "session": { "state": "pending", "remainingSeconds": 900 }
  }
}
```

This is a shortened illustration; derive exact schemas from the offline policy
export or the [typed host client](../host-client/README.md). Keep the token in
the authorized host and present only the link and safe guidance to the human.
Approval URLs contain a public request ID, never the token. A pending retry with
the token refers to the existing request and does no Infisical work. After
approval, retry explicitly with the original operation and token. Timed
permission permits subsequent covered calls to reuse it.

Call `approval.session` with `{"approvalToken":"…"}` to inspect state, mode,
remaining seconds, and remaining uses. Add `"action":"close"` to withdraw the
client's permission. Reads never extend its lifetime. Pending, denied, expired,
revoked, closed, consumed, and unknown-session refusals have structured reasons.
An unknown token is not replaced automatically: submit a fresh request without
it when new human approval is wanted. Ordinary ingress credentials are required
on every call, even with an active approval token.

Gateway sessions bind the verified JWT issuer, subject, and calling actor.
Standalone HTTP has one connection identity shared by holders of its bearer;
approval tokens distinguish sessions but do not create individual user identities.
Use the gateway profile when separately authenticated client ownership is needed.
Gateways must preserve the envelope and structured result without substituting
their own identity or replaying mutations; see [Gateway integration](gateway-rollout.md).

## Lifetime, files, and operational boundaries

Approval is bounded and process-local. Run one instance, or consistently route
MCP requests, human decisions, and transfers to the instance that created the
session. Restart invalidates all pending and active tokens. There is no database
or cross-instance replication. Capacity limits fail closed; clients should
reuse their token rather than repeatedly creating pending requests.

The store records events without credential values before granting or admitting
permission. The host retains a bounded in-memory history of recent events and
emits structured event metadata through the existing logger. History is lost on
restart and is not a durable compliance ledger; operators own log retention.
Recording failures block grants and admission. Close/revoke still withdraw
permission if recording fails, so inspect status after such an error.

Revocation, expiry, and closure block later upstream submissions, including
work waiting for the shared HTTP budget, and block later staged downloads.
They cannot cancel an action already submitted to Infisical or erase bytes
already delivered. Multi-step work may have partial effects; reconcile its
outcome before any retry. Approval never makes mutation replay safe.

Secret upload and output references remain governed by the
[file transfer plane](http-configuration.md#reveal-transfer-plane). Inputs are
bound to the authenticated owner and remain usable while approval is pending:
their TTL is at least the pending plus single-use redemption windows. Discovery
reports this separately as `uploadTtlSeconds`. Output TTL stays unchanged;
result references and download authorization are bound to the owner and the
admitted permission. Closing or revoking it can therefore prevent an outstanding
result download. Complete required transfers before closing the session.

To roll out, configure and verify the Authentik proxy path, supply the server
settings, enable the flag, then exercise rejection, human decision, explicit
retry, status, and closure with the intended client. `/healthz` remains independent
of approval and Infisical. Disabling the setting restores ordinary HTTP behavior;
do that only as an intentional operator policy change. Upgrading or rolling back
restarts the process and requires fresh approvals.
