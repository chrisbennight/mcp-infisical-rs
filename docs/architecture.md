# Architecture

## Trust boundaries

```text
authenticated MCP user
          |
          v
  tool-search gateway
  - user authentication
  - infisical-admin authorization
  - tool risk policy
          |
          | private network A
          | Authorization: Bearer <service secret>
          | X-MCP-Identity: <gateway-signed JWT>
          v
  mcp-infisical-rs
  - authenticates every MCP request
  - validates and bounds typed operations
  - redacts secret-bearing data
          |
          | private network B or verified HTTPS
          | dedicated Universal Auth access token
          v
  Infisical REST API
```

There are three distinct authorities:

1. The user credential terminates at the gateway.
2. The opaque service bearer authenticates the gateway to this server.
3. The Universal Auth credential authenticates this server to Infisical.

Token passthrough is not used. MCP session identifiers are routing state and
never count as authentication. The initial transport is stateless, returning
JSON responses permitted by Streamable HTTP, so no session identifier is
issued or accepted as a credential.

## Crate boundaries

`infisical-api` owns HTTP, Universal Auth, endpoint versions, pagination, API
errors, and secret-bearing data types. `infisical-mcp` owns the catalog, JSON
schemas, validation, dispatch, result types, and gateway classification export.
`infisical-server` composes those crates with configuration, Streamable HTTP,
bearer and JWT middleware, rate limits, tracing, health, and shutdown.

This direction prevents HTTP details from leaking into tool schemas and keeps
the API client usable in isolated contract tests.

## Authentication details

The ingress bearer is a randomly generated 256-bit opaque value stored in
Infisical, not a user token. Comparison uses a vetted constant-time primitive.
The server accepts `CURRENT` and optionally `PREVIOUS`; rotation adds the new
server value, switches the gateway, and then removes the old value.

The signed identity is verified using the gateway JWKS. The verifier pins the
configured issuer and fixed `infisical` audience, rejects expired tokens and
unsupported algorithms, and refreshes keys only through bounded,
redirect-free requests that ignore ambient proxies. HTTPS is the default;
loopback HTTP supports isolated tests, and an explicit private-HTTP opt-in
permits only DNS-pinned container service names or private IP literals while
still rejecting the IPv6 instance-metadata endpoint. A fresh unknown key
identifier triggers one single-flight refresh, globally limited to once every
five seconds. Its claims are used for audit context, not to invent local
authorization rules.

The MCP path also enforces an exact host-authority allowlist, an explicit
browser-origin allowlist, a one MiB default body bound, a 32-request default
concurrency bound, and a 30-second default deadline. These limits do not wrap
`/healthz`, so a saturated MCP workload does not make the container appear
dead.

The upstream access token is cached until a conservative pre-expiry deadline.
Concurrent callers share one refresh. A failed authenticated idempotent read
may refresh and retry once. An observable read or mutation invalidates the
rejected token for the next call but is never replayed automatically because
the first attempt may already have produced a side effect. The typed client
disables redirects and ambient proxies, bounds request time and response bytes,
discards untrusted error bodies, and exposes only a validated request ID with a
fixed error category. Resource modules use sealed operation declarations, so
callers cannot supply an arbitrary method or path.

The pinned `v0.160.12` core routes span API versions: current project and
environment administration uses v1, folders use v2, tags use the v1 project
path, machine identities, groups, and project memberships use v1, secret
metadata and mutation use v4, and identity project additional privileges plus
secret-import mapping management use v2. Dynamic-secret configuration and
lease lifecycle uses v1. API
path versions are per-family
namespaces inside the pinned product release, not a global preference for the
highest number; the v2 project router in this release is deprecated. Dynamic
URL segments are appended through the URL library rather than interpolated into
a path. Project, organization, identity, group, membership, environment, and import
IDs plus bounded lowercase user handles, project-role slugs, environment slugs,
secret-tree paths, and positions are validated before requests. Upstream collection routes without pagination
remain bounded by the response-size limit, and the resource layer exposes a
validated local page of at most 100 items.

App-connection, secret-sync, and secret-rotation inventory is another
observable-read boundary. The pinned generic routes accept Machine Identity
tokens and write audit events, so each GET is attempted once and never retried.
The API layer projects the large provider unions onto common value-free records
and validates provider tags plus joined project, connection, environment, and
folder ownership. Sync and rotation results are followed by one ordinary exact
project read, and each joined environment must exactly match that project's
embedded environment catalog. It drops credential hashes, provider
configuration, sync options, secret mappings, generated credentials, job IDs,
and provider status messages before MCP serialization.

GitHub is the first provider-specific app-automation boundary. Connection
administration accepts only the pinned GitHub App, OAuth, or personal-access
token credential variants and validated GitHub Cloud, optional Enterprise
Cloud host, or Enterprise Server routing.
Credential updates require explicit acknowledgement before authentication or
the audited exact-connection read, then require the new secret to preserve the
stored authentication method; the pinned PATCH route cannot change that
method. GitHub secret-sync administration accepts only
organization, repository, or repository-environment destinations and the
pinned options contract. Creation explicitly acknowledges that initial sync
overwrites destination values. Update, deletion, independent remote removal,
manual sync, and manual remote-secret removal each have their own confirmation.
Sync ID operations perform the audited exact-provider read and validate its
project and environment before the one non-replayed mutation. Results remain
value-free, including provider tokens, installation IDs, job identifiers, and
status messages. GitHub import is unavailable in the pinned provider contract.
Credential rotation requires explicit confirmation before authentication and
sends the pinned bodyless action exactly once without replay; the result is the
same value-free connection projection. Other providers remain unavailable
without a generic JSON escape hatch.

KMS is a separate high-risk boundary. The API layer owns the exact v1 routes,
closed key-usage, key-algorithm, and signing-algorithm enums, bounded base64
decoding, project/key ownership checks, disabled-key checks, and response
reflection validation. All KMS GETs create upstream audit events and use the
non-replaying observable-read path; all other operations use the single-attempt
mutation path. Key creation validates its project first, and key-targeted
operations perform an exact audited preflight before a write or reveal.
Key projections require the upstream disabled-state field instead of assuming
that an incomplete response describes an active key. Validated import material
retains its algorithm so later request construction cannot reinterpret it.
Plaintext and private key material remain redacted until the MCP layer's three
declared, confirmed reveal serializers. The 512-KiB decoded data limit leaves
room for base64 and JSON beneath the default one-MiB authenticated ingress
limit; bulk imports apply the same limit to aggregate decoded material and
replace arbitrary upstream per-key diagnostics with a fixed local rejection.
Signing-algorithm discovery requires the exact set for the preflighted key. Sign
and verify validate digest mode before the preflight, then bind the requested
signing algorithm to the immutable key family observed by that preflight before
the cryptographic mutation. ML-DSA variants remain exact typed options while
Infisical enforces its `kmsPqc` plan entitlement.

Certificate authorities form another high-risk audited boundary. General
inventory deserializes only identity, project, name, closed provider type,
status, and direct-issuance state, dropping complete provider configuration.
Internal projections deserialize bounded subject, hierarchy, algorithm,
validity, certificate identity, serial, and CRL metadata while omitting the
encrypted private key. All CA GETs use non-replaying observable reads.

Internal creation validates the complete hierarchy, subject, algorithm,
validity, path-length, and distribution-point contract before project preflight
and a single confirmed mutation. `notBefore` requires `notAfter` because the
pinned service otherwise ignores it. Update and delete perform an exact audited
ownership read first; update compares the complete returned CA against that
snapshot with only the requested fields changed, and delete requires the exact
snapshot in response. CSR, certificate-history, active-certificate,
certificate-version, and CRL reads preflight the same exact ownership boundary.
Certificate generation also proves the optional parent belongs to that project.
Generation and import require a pending target without an active certificate;
renewal and signing require an active certificate. The signing boundary verifies
the CSR proof-of-possession signature with the pinned classical and ML-DSA
families, and each imported certificate must carry CA Basic Constraints plus
`keyCertSign`. All four mutations validate bounded PEM and certificate
constraints, require confirmation before authentication, and send one request.
External-provider credentials and configuration have no generic JSON or URL
escape hatch.

Certificate policies use a shared typed contract for public discovery,
confirmed lifecycle changes, and certificate-profile ownership preflight. Subject, SAN,
usage, algorithm, validity, and basic-constraint rules are validated before an
upstream call. Exact reads bind both policy ID and Certificate Manager project;
list reads validate project scope, pagination, and optional search reflection.
Creation confirms the project kind before its non-replayed mutation and accepts
Infisical's returned canonical policy name while requiring the other requested
rules to match. Update and delete prove exact ownership before one confirmed
mutation; update also preserves the difference between omitted and cleared basic constraints
and validates the returned durable state. This boundary follows the
[pinned policy service](https://github.com/Infisical/infisical/tree/v0.160.12/backend/src/services/certificate-policy).

Certificate profiles are a separate high-risk audited boundary layered on the
Certificate Manager project, certificate-policy, and optional CA scopes.
Creation accepts closed API, EST, ACME, or SCEP configuration and preflights all
three scopes before one confirmed mutation. Azure AD CS templates are bound to
Azure AD CS-backed CAs, and EST bootstrap chains accept only certificates with
CA Basic Constraints and `keyCertSign`. Exact reads sanitize enrollment metadata;
an EST passphrase returned by list is consumed into a zeroizing value and
discarded. Same-family updates are re-read so observable configuration must
reflect the request. The pinned PATCH service cannot create another enrollment
family’s missing configuration row, so family switching is rejected instead of
claiming a transition that Infisical cannot complete coherently. Latest bundle
and ACME EAB retrieval are explicit confirmed reveal boundaries with custom
serializers; no ordinary profile output includes those secrets. Latest-bundle
validation also proves that the leaf, private key, reported serial, and ordered
CA chain form one usable cryptographic bundle and that every certificate is
currently valid before serialization.
SCEP updates additionally preserve the preflighted static or dynamic challenge
mode because PATCH cannot prove coherent removal or creation of its stored
password while switching modes.

Certificate issuance is layered on the exact profile ownership read rather than
maintaining a second policy or issuer model. Only an API-enrolled profile reaches
the pinned canonical profile issuance route. Managed-key and signed-CSR inputs
use a closed typed contract; the one-shot response is converted into either a
validated immediate certificate or a pending request reference. Immediate
private keys cross only the existing reveal transfer boundary, while an
indeterminate mutation outcome must be reconciled through request inventory
before another issuance attempt.

Certificate requests add a project-bound observation and reveal boundary over
the same profile issuance flow. Inventory is sanitized before it reaches MCP:
upstream status messages, certificate bodies, and private keys are discarded.
Exact status, result retrieval, and cancellation locate the request by
traversing that project inventory because the exact upstream route does not
return project ownership. Result reveal then binds the issued certificate ID,
serial, common name, SAN values, and timestamps and verifies any returned
private key against the parsed leaf. The pinned search route flattens stored
typed SANs to values, and the exact result omits SANs, so this check does not
infer an original GeneralName type that the upstream contract erased.
Cancellation requires pending state before its single bodyless mutation;
concurrent settlement is reported without replay. A reveal-transfer reservation
is obtained before upstream reads so a returned one-time private key can be
staged without a later capacity failure.

SSH Access certificate authorities and templates form a distinct trust boundary
from Certificate Manager. The API layer owns UUID-only SSH project, CA, and
template identifiers; closed key algorithms and lifecycle states; canonical
OpenSSH public keys with exact RSA-size or NIST-curve validation; structurally
parsed, unencrypted, bounded zeroizing imported private keys with matching key
families; and complete template policies. CA creation sends the project ID in
its single non-replayed mutation and rebinds the response instead of adding a
redundant project read.
External key material is serialized only into that request and cannot enter a
public response. Exact reads, replacements, and deletions rebind the returned
project and resource IDs; the dedicated public-key route must equal the key on
the authenticated CA record.

Project-wide template inventory uses its project-scoped route without a second
project read. Template creation proves an active same-project CA because its
mutation is keyed only by CA ID. Replacement sends one complete policy instead
of depending on stale partial state. Durations use a
canonical positive `ms`, `s`, `m`, `h`, `d`, or `w` form bounded to ten years;
user and host allowlists are bounded and unique. All SSH administration reads
are observable and non-replayed, all writes require confirmation before
authentication, and no method, URL, key, or arbitrary policy escape hatch is
exposed. Signing and issuance preflight the exact project, CA, template, and
policy before one non-replayed mutation, then cryptographically bind the
returned certificate to the requested subject, principals, identity, lifetime,
and CA. The verifier permits only ssh-keygen's bounded past backdating while
requiring expiry no later than one requested TTL after receipt. It rejects every
critical option and requires exactly the five OpenSSH default user extensions
or an empty host-extension set. Issuance reveals its generated private key only
after proving the bounded unencrypted key pair matches.

Hosts extend that trust boundary with explicit user and host CA IDs, canonical
FQDNs and lifetimes, and bounded direct or inherited login mappings whose
provenance survives serialization. Project inventories are bounded and
canonical; exact reads and mutation results are rebound to the requested
project and resource. Host and host-group PATCH routes are exposed only as
complete replacement contracts. Membership mutations preflight the exact group
and host in parallel, perform one bodyless write, and validate the returned
host/project/hostname receipt without a second read. Host-certificate issuance
derives its principal, key ID, TTL, and signer from the preflighted host, mutates
once, and reuses the common cryptographic verifier. The capability ledger marks
the JWT-only `sshHosts.globalInventory.read` and
`sshHosts.userCertificate.issue` routes explicitly unavailable.

Code signers layer a signing authority over the same Certificate Manager
project and certificate scopes. Lifecycle and public-material reads are audited
and never replayed. Creation first proves the project and either a currently
valid, non-CA, same-project code-signing certificate whose private key
Infisical holds, or an active same-project internal CA;
external-CA issuance remains outside the enabled provider set. Mutations require
confirmation before authentication and bind every response to the exact signer
and project. Non-delete mutations additionally validate the certificate, CA,
state, and key-family invariants they were asked to preserve or change.

Signing data enters a zeroizing redacted value, must be canonical base64, and is
bounded to 128 decoded bytes; both its decoded bytes and re-encoded canonicality
check buffer also zeroize on drop. Digest length and RSA/ECDSA algorithm
compatibility are checked before the exact signer preflight and single signing
mutation. Signing also requires an active attached certificate within its
validity interval whose key algorithm exactly matches the signer. No signer
output contains submitted data or private key material.
Certificate export parses one non-CA PEM leaf, while public-key export validates
bounded base64 DER, exact RSA modulus size or EC curve, and byte-for-byte
equality with the attached leaf certificate key. Its public output reports the
validated signer key algorithm rather than Infisical's coarse RSA family label.
Signer governance is a separate typed module so its PII and transactional rules
remain explicit. Direct and effective memberships are normalized by principal
family, policy replacement validates every approver against current non-auditor
memberships, and approval requests must carry a finite count or time window.
Pre-approval additionally proves the grantee's effective non-auditor access.
Every mutation confirms before authentication and reuses exact signer ownership
preflights; every response is rebound to the requested signer, member, policy,
request, or grant. Packed effective-permission rules expose typed
actions/subjects and only a Boolean marker for arbitrary conditions. Sanitized
operation history discards data hashes, client metadata, and upstream error
text before serialization.

Dynamic-secret configuration and lease discovery is a separate observable-read
boundary. Infisical writes an audit event for each corresponding GET, so these
operations use the same non-replaying client path as first-page audit-log
discovery rather than the retryable read path. Typed outputs discard provider
inputs, arbitrary metadata, lease configuration maps, and status details before
MCP serialization. Configuration TTL metadata is parsed with the pinned
duration grammar and must form a bounded, coherent default/maximum pair.
Renewal accepts only a bounded whole-second lifetime;
revocation validates the exact scope and lease UUID and requires explicit
confirmation before authentication or mutation. SQL-database configuration
creation uses an opaque typed model; every connection, password-policy,
template, TLS, and route field is validated before authentication. Statement
templates admit only the pinned provider's
plain placeholders, while the root password is held in the same zeroizing,
redacting secret type used elsewhere. SQL lease creation returns the generated
username and password through its declared one-time sensitive output only. It
first performs the audited exact-configuration GET to prove the provider and
binds the result to that configuration ID. It revokes an invalid returned lease
only after proving ownership by that configuration or by a coherent direct
response for the same named SQL replacement configuration. Unrelated leases are
never touched and cleanup errors fail loudly. Provider-input replacement is
unavailable because the pinned name-addressed route has no configuration-ID,
version, or conditional precondition. Other provider families remain
capability-marked unavailable until their tagged contracts can be exposed
without a generic JSON escape hatch.

Project and environment updates serialize exactly one typed field, preventing
ambiguous mixed-setting changes. Project deletion requires confirmation and
uses upstream soft deletion before scheduled cleanup. Environment deletion
also requires confirmation, never sends the `hardDelete` query parameter, and
has a separate restore operation. Every mutation is attempted once and is not
replayed after an authentication failure.

Folder creation and update require exact project, environment, and normalized
parent-path coordinates. Single and batch updates send complete mutable state,
avoiding a read-await-write race; a batch is bounded to fifty unique folder
IDs. Folder deletion requires confirmation, defaults recursive deletion off,
and exposes it only through a separate explicit boolean. Tag updates likewise
send the complete slug and color state, and tag deletion requires exact IDs and
confirmation. These folder and tag mutations are also attempted only once.

Machine-identity list and get reads return a deliberately narrow projection:
identity and organization-membership identifiers, display name, deletion
protection, authentication method names, and existing role slugs. Metadata
values, login history, and credentials are dropped. Creation assigns only a
built-in organization role and defaults to `no-access` plus deletion
protection. Updates serialize one typed field, and confirmed deletion is sent
once. The pinned organization routes require a user JWT, so the server records
that family as unavailable rather than weakening the dedicated Universal Auth
boundary.

Project membership administration uses the pinned v1 project route families.
Human-user reads are locally paginated and return sanitized profile metadata,
membership IDs, and role assignments; machine-identity reads use the upstream
bounded page. Existing temporary-role scheduling metadata remains visible on
reads even though this server does not mutate it.
User invitation accepts at most fifty unique lowercase emails or usernames.
Create and update mutations send a complete, non-empty set of at most ten
permanent built-in or custom role slugs, avoiding a read-await-write window.
Updates require explicit confirmation that the complete replacement removes
every omitted assignment, including temporary roles, and are classified as
destructive.
Human removals address the opaque membership ID, while machine-identity
operations address the identity ID; both validate the exact project and require
confirmation before deletion. Temporary-role creation and scheduling are
capability-marked unavailable; confirmed complete replacement can remove an
omitted temporary assignment.
Every membership mutation is attempted once. Human profiles are PII but never
contain password hashes, public keys, devices, MFA state, or credentials.

Role discovery uses exact project or authenticated-organization scope and
selects roles by validated stable slug. Locally bounded list results omit
permissions; exact reads include normalized permission rules. Infisical's
built-in project role IDs and timestamps are generated per response, while its
built-in organization IDs are dummy values, so neither crosses the MCP
boundary. Outputs instead derive a `builtIn` marker from the pinned built-in
slug sets and retain the owning scope ID. Custom-role creation and update are
RBAC-plan gated, and the community deployment capability-gates the complete
administration lifecycle rather than exposing deletion alone.

Group discovery uses the authenticated organization for list and exact group
reads, and validates explicit group and project IDs before project-assignment or
project group-membership requests. Human group members expose sanitized PII;
machine members expose only identity ID and display name. Project-assignment
pages retain an explicit nullable join timestamp so assigned and unassigned
projects cannot be confused. Returned project group memberships must echo their
requested project and group scope. Group and project group-membership mutations
remain capability-gated because group administration requires the Groups plan
feature and temporary project-role scheduling is not yet typed.

Identity project additional privileges use the pinned v2 identity-token-compatible
router for their complete lifecycle. The public model separates locally bounded
list summaries from exact resources with normalized permission rules. Every
public result contains the stated project and identity scope. The pinned
serializer omits those fields from the upstream wire response, so list binds
them from its scoped query; exact reads, update, and delete first prove the
resource ID or slug in that scoped collection; and create binds the coordinates
sent in its body. Optional upstream scope echoes are validated when present.
Temporary responses must contain a bounded parseable relative duration and UTC
timestamps whose end equals start plus duration. Create and update responses
must also match the requested temporary start, duration, and any complete
permission set. Create validates all coordinates,
permission bounds, and the permanent-or-temporary lifetime, and requires
explicit acknowledgement before creating any inverted deny rule. Update and
delete perform a scoped-list preflight before their one
mutation so a caller cannot use an opaque ID to affect another project or
identity. Inverted creation, permission replacement, and deletion require
explicit acknowledgement; mutations are never replayed after authentication
failure. A successful mutation with an undecodable response reports an unknown
outcome and tells the caller to reconcile state before retrying. User-specific
additional privileges are capability-gated because their pinned route requires
a user JWT.

Universal Auth administration is a separate typed boundary. Configuration
reads expose public and policy metadata, while enterprise-only trusted-IP writes
are capability-gated. Attach supplies complete community settings; updates
replace one coherent lifetime, use-limit, or lockout group and therefore need no
racy read-before-write. Client-secret reads expose sanitized metadata only.
Creation temporarily owns the one-time secret in a zeroizing, non-cloneable,
redacted type and serializes it only in that tool's declared sensitive output.
Removal, credential revocation, and lockout clearing require explicit
confirmation after target validation and each mutation is attempted once.

Token Auth administration follows the same typed boundary on its pinned v1
routes. Configuration reads expose policy metadata, while enterprise trusted-IP
writes remain capability-gated. Attach requires complete explicit lifetime and
use-limit settings, and updates replace one coherent lifetime pair or use limit.
Token list and get are value-free. Creation temporarily owns the generated
bearer in the zeroizing secret type and serializes it only through its declared
one-time output. Token names are bounded non-secret metadata. Authentication
method removal and exact-token revocation require confirmation and are never
replayed.

Kubernetes Auth administration uses the pinned v1 identity route family and
exposes only direct Kubernetes API TokenReview configuration on the community
deployment. Attach requires HTTPS, explicit namespace/service-account policies,
an exact audience, and complete token limits. Updates replace one coherent
lifetime, use-limit, workload-policy, or direct-reviewer group. A direct-reviewer
change explicitly preserves, replaces, or clears the redacting reviewer JWT and
atomically clears any existing paid gateway selection. Configuration reads
consume Infisical's decrypted reviewer JWT into a non-serializable zeroizing
type, reduce it to a presence boolean, and discard it; the CA bundle is likewise
reported only as configured or absent. Paid trusted-IP, gateway, and gateway-pool
writes are capability-gated. Confirmed removal is attempted once.

All other machine-identity provider and federated authentication families are
closed at the MCP boundary and capability-marked unavailable: AWS IAM, GCP,
Azure, OIDC, JWT, LDAP, OCI, Alibaba Cloud, TLS Certificate, and SPIFFE. Their
upstream routes are not reachable through a generic method, URL, or JSON-body
tool.

Secret metadata reads always send `viewSecretValue=false` and also disable
reference expansion, personal overrides, and imports. The response field that
Infisical retains in its schema is deserialized into a zeroizing,
non-serializable type and dropped before the public result is built; the raw
response buffer is also zeroized on drop.

Serving mode validates and constructs the Universal Auth client before the
listener binds. Each stateless MCP service instance receives a clone of the
same bounded client, so access-token caching and refresh single-flight state are
shared across requests. Local discovery tools do not contact Infisical; resource
tools return upstream failures as MCP tool errors rather than protocol errors,
while malformed tool arguments remain protocol-level invalid-parameter errors.

## Reveal transfer plane

When `INFISICAL_MCP_FILE_PUBLIC_URL` is configured, reveal-class operations
default to staging their sensitive fields as an in-memory JSON envelope and
returning an opaque `mcp-file://infisical/…` reference in the tool result. A
file-aware gateway resolves the reference by calling `files/authorizeDownload`
over the authenticated `/mcp` channel, receives a descriptor naming this
server's `/files/download/{id}` route (the result also declares
`"sensitivity": "secret"` so a retention-aware gateway shortens its own copy's
lifetime), and streams the envelope with the per-download
`Infisical-Transfer-Credential` header. That credential is a
fourth authority, distinct from the three above: it is minted per
authorization, stored only as a hash, compared in constant time, and it alone
authenticates the download route, because the gateway fetches file transfers
with descriptor headers rather than its MCP bearer. Envelopes are held only in
zeroizing memory, expire on a short TTL, serve exactly one download, and are
padded to a fixed-size bucket with a random pad so the size a staging
intermediary publishes to model context is a coarse bucket count — constant
within a bucket and across repeated reveals — and the digest is salted. Reference delivery reserves its staging slot before the upstream call
runs, so a capacity refusal costs a retry rather than the only copy of a
one-time credential. Staged state is instance-local by design: a reference
resolves only on the instance that minted it, because externalizing
seconds-lived secret envelopes into shared storage would trade a routing
constraint for durable secret state. Without the configured origin the method
answers method-not-found and every reveal keeps its inline behavior.

The same plane carries values inward. `files/authorizeUpload` mints a
single-use ticket naming the credentialed `PUT /files/upload/{id}` route; the
uploaded bytes are verified against their declared size and digest, held in
zeroizing memory under the same ceiling and TTL, and consumed exactly once when
`secrets.create` or `secrets.update` names one through `secretValueFile`, or
`certificates.import` names certificate, optional private-key, and optional
chain uploads. Uploaded values must be UTF-8 and move directly into redacting
types. Certificate import validates the leaf, key, and issuer relationship
before its upstream mutation and checks confirmation before consuming any
upload reference.

## Network topology

The eventual Infisical compose change should attach only the application
service to a new external `infisical_api_private` network. Postgres and Redis
remain solely on the existing backend network. The MCP stack joins
`infisical_api_private` and owns `infisical_mcp_private`; the gateway joins only
`infisical_mcp_private`.

If the Infisical application cannot safely accept internal cleartext traffic,
the MCP service should use the existing verified HTTPS endpoint instead of
weakening TLS. In either case, it receives no database or Redis reachability.

## Observability

The typed audit-log client uses Infisical's current organization audit route
with bounded server-side pagination and filters. Metadata-backed environment,
secret-path, and secret-key filters require the project and secret-event scope
where the pinned implementation applies them. The client reads only those
metadata coordinates needed to prove returned records match the request, then
drops the route's arbitrary actor and event metadata while preserving bounded
event, actor, project, network-source, client, and timestamp fields. Offset zero
has an upstream write side effect because Infisical records the audit-log view,
so the MCP catalog marks that operation observable and non-idempotent rather
than calling it read-only. Its sealed observable-read execution path sends the
GET only once, including after an authentication rejection.

Request logs contain request IDs, authenticated gateway principal, tool name,
risk class, upstream status class, latency, and affected resource identifiers
when safe. Recording the operation an executor ran belongs in that set and is
not yet implemented; without it a log entry names only the executor, which no
longer identifies what was served.

They exclude authorization headers, MCP arguments and results, secret values,
private keys, certificates, and request/response bodies.

The community Infisical edition does not provide all enterprise audit and RBAC
features. Gateway and server logs therefore improve caller attribution, but the
upstream service will still see the shared Machine Identity rather than the
human caller. This is an explicit operational tradeoff, not equivalent to
native per-user Infisical audit history.
