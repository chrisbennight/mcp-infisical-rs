# Choose an operation and delivery method

Start with `server.capabilities` on the instance you will use. It reports the
transport, active operation profile, limits, and file-transfer availability.
Compiled support does not prove that the configured Infisical machine identity
has permission or that the upstream edition enables a feature. Infisical makes
those decisions; a gateway may impose additional caller policy.

Use `operations.list` to search by intent, then `operations.describe` for the
selected operation's executor and exact argument schema. Keep the search filters
when following `nextOffset`. Set `includeOutputSchema: false` when only the
arguments are needed. A disabled startup-profile operation cannot be enabled by
choosing another executor or supplying a confirmation field.

## Choose a connection

| Mode | Connection authority | Secret and complete-result delivery |
| --- | --- | --- |
| Stdio | The local process boundary and its configured machine identity | Inline; no HTTP listener or file plane |
| Standalone HTTP | Bearer on every request, then the configured machine identity upstream | Inline, or file references when the instance enables its file plane |
| Gateway HTTP | Bearer and identity JWT on every request, gateway policy, then the configured machine identity upstream | Inline, or file references when both the instance and intermediary support transfer |

See [standalone setup](standalone.md), [HTTP configuration](http-configuration.md),
and [operation policy](operation-policy.md). Sessions and network membership do
not replace credentials. A confirmation records intent; it grants no authority.

For reveal operations, `delivery: "reference"` keeps credential values outside
the tool result. With file transfer enabled, reference delivery is the default
for supported reveals. Explicit inline delivery can put the value in model
context, client history, and client logs. A deployment without file transfer
cannot accept an explicit reference request.

For any executor, `resultDelivery: "file"` returns a reference to the complete
structured result so a host can filter it locally. This is separate from a
reveal's secret-only delivery option. Errors remain inline. Resolve file
references through a file-aware host; do not paste downloaded credentials back
into the conversation. References expire, are instance-local, and are lost on
restart. A consumed download is one transfer attempt, not proof of receipt.

## Inventory projects and secret names

1. Find and describe `projects.list`. Retain each project's `id`, `slug`, and
   organization identity. Use `includeDetails` only when descriptions or embedded
   environments are useful.
2. Use `environments.list` for the chosen project, then
   `secrets.metadata.list` for one environment and an exact folder path. Leave
   recursion disabled unless descendants are part of the task. Supported tag
   filters reduce upstream secret retrieval.
3. Follow the returned page continuation until absent. Check the operation's
   pagination metadata: local pages refetch a mutable collection, so separate
   pages are not a stable snapshot. A smaller local limit reduces MCP output,
   not upstream response bytes.
4. Return only the fields needed for the inventory. Secret metadata values and
   full tag details are opt-in because they may contain sensitive configuration.
   Keep complete data in the authorized host context when using file delivery.

If upstream retrieval exceeds its response bound, narrow the folder, recursion,
or supported tag filters. For projects, use a known exact identifier when the
full collection cannot be retrieved. Do not keep reducing a local page limit
and expect it to reduce the upstream collection.

## Read or change one secret

Select exact project, environment, folder, and name coordinates from metadata;
then describe `secrets.reveal`, `secrets.create`, or `secrets.update`. Reveal only
the selected value. Choose reference delivery before execution when it is
required by the host's information boundary.

Create and update accept either an inline value or an uploaded `secretValueFile`,
according to their schema. Upload through the file plane before invoking the
operation, and keep the resulting reference in the authorized host. The server
consumes uploads once and does not echo mutation values. Read the returned
receipt: a request awaiting upstream approval is not an applied change. Deletion
requires its explicit confirmation and the same exact scope.

A transport error after a mutation can leave its outcome uncertain. Inspect the
resource's current state before deciding what to do next; never replay a
mutation merely because a response was lost. Follow the returned recovery
guidance, including any retained file references for one-time credentials.

## Issue or import a certificate

Search for the certificate task and inspect its operation schema. Select the
Certificate Manager project and the relevant profile, authority, policy, or
existing certificate identifiers from their typed discovery operations. Treat
these identifiers as belonging to that scope; a matching display name alone is
insufficient.

Issuance can return a private key only once. Establish reference delivery and
host transfer support before issuing. For `certificates.import`, upload the
certificate and any required private-key or chain files first; that operation
requires the file plane and has no inline material fields. Keep the machine
identity's permission and the upstream feature entitlement separate from local
support reported by discovery.

Use the [operation reference](tool-surface.md) for the supported certificate
lifecycle. Preserve identifiers from issuance receipts for later renewal,
revocation, or deletion. Do not infer lifecycle completeness from catalog counts.

## Use KMS or manage authentication resources

KMS cryptographic, disclosure, and key-management actions require the full
startup profile; reviewed KMS metadata reads also appear in the metadata profile.
Describe the selected action, validate its project and key identifiers, and
supply the confirmations required by that action. Bulk operations validate their bounded set before the final
request. A failed preflight can still have produced upstream audit records.
Reconcile uncertain final outcomes instead of replaying cryptographic or
mutation-class requests automatically.

The server's Universal Auth login credentials are deployment configuration.
Identity, Universal Auth, Token Auth, and Kubernetes Auth management operations
act on explicitly selected managed identities; they do not reconfigure this
server's own login. Credential-creation operations can return a value once, so
prepare the required delivery path before invoking them.

## Interpret the catalog

The [generated catalog summary](generated-catalog.md) counts exact served
operations separately from the compiled capability ledger. An unavailable ledger
entry explains a compiled omission; an implemented entry still needs deployment,
permission, and edition checks. The [API coverage matrix](api-coverage.md)
records the broader pinned API, including deferred and edition-gated routes.

Audited reads, mutation classes, destructive actions, credential disclosure, and
confirmation fields are separate policy facts. Executor names alone are not an
authorization policy. The offline [operation policy export](operation-policy.md)
provides those facts with the exact schemas for an independently governed host.
Catalog measurements expressed as JSON bytes are not token or billing estimates.
