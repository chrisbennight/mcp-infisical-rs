# Human approval

Human approval is being developed as an optional HTTP capability. The approval
core is available to the server implementation, but this release does not yet
provide an enable setting, approval webpage, or MCP approval-session tool. Do
not rely on the library core alone to gate a deployed MCP server.

The intended experience lets an authenticated client request ordinary work and
receive an approval link and inactive token. A person signs in through an
independently authenticated webpage and approves the exact request once or
grants timed permission. Timed approval can cover the client's available
operations globally or a proven project and environment. Approval activates
permission; the client's explicit retry starts the operation.

## Approval core contract

The `infisical_mcp::approval` module owns bounded, process-local sessions. Its
host must supply authenticated client ownership, independently authenticated
human decisions, registry-owned operation names, validated effective arguments,
and authoritative resource scope. A string identifying a human is not itself
proof of authentication. The host remains responsible for its ingress and
human authorization boundaries.

Tokens never replace ingress credentials. Sessions bind issuer, subject, and
calling actor. The core retains only token digests and keyed fingerprints of
effective operation arguments, including the supplied scope. It does not retain
submitted secret values. Public session metadata and recording events omit
tokens and fingerprints. Token formatting is redacted; exposing a token is an
explicit action for an authorized transport boundary.

The core supports exact single-use approval, timed global approval, and timed
project/environment approval. Scoped permission is unavailable if the operation
adapter cannot establish a stable environment identity and the complete scope
of the operation's effects. Global approval applies only to its client session;
it cannot grant additional upstream permissions or override operation profiles.

The core serializes human decisions, admission, closure, and revocation. It
consumes single-use permission when an attempt is admitted, independently of
whether the eventual result is received. A permit belongs to that attempt and
allows the host to recheck expiry or withdrawal after waits. The host must
integrate those checks with operation dispatch and upstream submission; a check
alone cannot cancel an upstream action already sent or make mutation replay
safe.

Before a request, approval decision, or admission takes effect, a required
host-owned recorder must accept its value-free event. A recording failure
prevents granting permission. Closure and revocation take effect even if their
recording fails, and return an error directing the host to inspect current
state. Recorder acceptance and durability are distinct: the host must define
the durability of its selected sink. Recorder implementations are synchronous,
bounded, and must not call back into the store.

Expiry uses monotonic time and client status reads never extend permission.
Pending requests and single-use redemption have independent time limits; timed
approval starts when the person approves. Capacity is bounded globally and per
owner. A new store has no knowledge of previous tokens: restarting invalidates
pending requests and active approval. Clients must obtain fresh human approval.
There is no shared database or cross-instance session routing.

## Integration boundaries

The HTTP server will own settings, the human webpage, authentication, and
lifecycle. The MCP layer will own discoverable approval contracts and enforcement
on resolved typed operations. The API crate remains the only Infisical network
client. Host clients and gateways will carry approval outcomes and tokens
without automatic mutation retries.

Approval is HTTP-only. No stdio approval service is planned. Secret uploads and
file-result delivery must retain their governed paths when approval is wired
into execution; the approval core does not yet bind or extend file lifetimes.
The full capability, acceptance criteria, and linked delivery work are tracked
in the [human approval epic](https://github.com/chrisbennight/mcp-infisical-rs/issues/55).
