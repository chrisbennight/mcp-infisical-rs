# Research notes

Research used Kagi search plus temporary shallow clones of the relevant public
repositories. The implementation plan is grounded in the following primary
sources.

## Existing Infisical MCP implementations

The [official Infisical MCP server](https://github.com/Infisical/infisical-mcp-server)
is a small TypeScript stdio server. At the inspected revision it provided ten
tools around secrets, projects, environments, folders, and project membership.
It is a useful naming and SDK reference, but it lacks Streamable HTTP, output
schemas, tool annotations, broad administrative coverage, and the gateway
security boundary required here.

The community [InfisicalMCP project](https://github.com/plgonzalezrx8/InfisicalMCP)
demonstrates a much broader FastMCP surface, including administrative resources.
It is useful as an endpoint inventory, not as a security template: its optional
HTTP mode, bulk export conveniences, TLS-disable path, and authentication cache
do not meet this deployment’s constraints.

Infisical’s [official Rust SDK](https://github.com/Infisical/rust-sdk) currently
covers secrets and KMS rather than the full management API. The server will
therefore own a typed REST client while re-evaluating the SDK as it matures.

## Infisical API inventory

The compatibility snapshot is the official Infisical `v0.160.12` source and its
[API reference](https://infisical.com/docs/api-reference/overview/introduction).
The inspected documentation tree contained 1,459 endpoint documents across 59
top-level resource categories, including 71 marked deprecated. App connections,
secret syncs, and secret rotations accounted for 901 documents because provider
variants repeat similar operations. This is the main evidence for tagged generic
resource families and on-demand schema discovery rather than route-to-tool code
generation.

The [generated coverage matrix](api-coverage.md) pins that inventory to source
commit `0a9dd1005f9d088c88b639760da3544fafd11388` and maps each endpoint document
to an implemented, edition-gated, intentionally omitted, superseded, or
deprecated disposition backed by a `server.capabilities` identifier. Coverage
decisions enumerate the exact document, method, and route; refresh also requires
the tagged upstream checkout to have a clean working tree. Normal CI reconstructs
the documentation subtree from a minimal checked-in Git repository, verifies
that its version tag resolves to the pinned upstream commit, and obtains
capability states by executing the same serialized registry returned by the
`server.capabilities` MCP tool.

The pinned generic `GET /api/v1/app-connections`,
`GET /api/v1/secret-syncs`, and `GET /api/v2/secret-rotations` routes accept
Universal Auth identity access tokens and each records an audit event. Their
responses join provider-specific records with connection, project,
environment, and folder metadata while retaining provider configuration,
credential hashes, sync options, secret mappings, generated-credential state,
and encrypted or decrypted status-message surfaces. The inventory foundation
therefore uses the non-replaying observable-read path, validates the closed
provider unions and ownership joins, and emits only common value-free metadata.
Because the generic records do not echo the environment's owning project, sync
and rotation inventory follows the audited list with one ordinary exact-project
read and accepts joined environment metadata only when it exactly matches that
project's embedded environment catalog.
The first provider-specific implementation follows the pinned
[GitHub connection router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/app-connection-routers/github-connection-router.ts)
and [GitHub secret-sync router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/secret-sync-routers/github-sync-router.ts).
The connection routes accept GitHub App, OAuth, and personal-access-token
credentials plus GitHub Cloud, optional Enterprise Cloud host, or Enterprise
Server routing. Their safe response
surface exposes only instance type and host; repository, organization, and
environment discovery routes require a user JWT and are not exposed. The sync
routes support organization, repository, and repository-environment
destinations, complete options replacement, manual sync, manual removal, and a
delete-time `removeSecrets` query flag. The provider fixes initial behavior to
destination overwrite and declares import unsupported. The MCP contract makes
each destructive or externally mutating choice explicit, validates scope before
the mutation, redacts all credentials, and returns no provider job or status
payload. The pinned connection endpoint also supports Machine
Identity-authenticated credential rotation. Its typed lifecycle requires
explicit confirmation, sends the bodyless mutation exactly once, and returns
only value-free connection metadata.

The same pinned source defines one reusable v2 lifecycle for PostgreSQL, MySQL,
Microsoft SQL Server, and Oracle Database credential rotations. Each provider
supports exact ID and scoped-name reads, create, update, delete, generated
credential reveal, move, manual rotate, and active-credential check. Creation
immediately creates an external database principal and mapped Infisical
secrets; mapping updates rename secrets; move can overwrite destination
secrets; delete can independently remove mapped secrets and revoke generated
principals. The MCP tools therefore validate the closed SQL parameter and
mapping schemas and require separate confirmations for each destructive effect.
Other provider-specific rotation contracts, including AWS IAM, remain
unavailable rather than accepting arbitrary parameter maps.

The pinned [KMS router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/cmek-router.ts)
defines fifteen `/api/v1/kms` operations, and every one accepts identity access
tokens. Key list, exact ID/name reads, public/private material reads, and
signing-algorithm discovery also create KMS audit events, so they cannot use the
retryable ordinary-read path. The remaining create, update, delete, encrypt,
decrypt, bulk import/export, sign, and verify requests are mutations and are
also attempted once. The route accepts up to one MiB of decoded operation data
inside a two-MiB HTTP envelope; this server narrows message, digest, and
plaintext inputs to 512 KiB so MCP JSON plus base64 remains within the
authenticated one-MiB ingress default. Bulk import and private-key export are
locally capped at one hundred unique targets; bulk import also caps aggregate
decoded key material at 512 KiB because the pinned route retains Fastify's
one-MiB default body limit. The pinned signing implementation binds RSA keys to
RSASSA algorithms, ECC keys to ECDSA algorithms, and each ML-DSA key to its
matching algorithm. Digest mode is unavailable for RSA-PSS and ML-DSA, while
RSA PKCS#1 v1.5 and ECDSA require the exact selected SHA digest length.
The MCP projection therefore requires an explicit `isDisabled` value, retains
the validated algorithm with imported key material, and accepts signing
algorithm discovery only when the complete response set exactly matches the
preflighted key family. Bulk-import rejection text is an upstream diagnostic
surface that may reflect submitted material, so it is consumed as a redacting
value and replaced with a fixed local message.

The pinned [KMS service](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/services/cmek/cmek-service.ts)
enforces the `kmsPqc` plan for ML-DSA key creation, import, and use. The MCP
contract keeps ML-DSA-44/65/87 in its closed key and signing enums so entitled
deployments can use the exact upstream capability, but reports entitlement
detection unavailable because no Machine-Identity-compatible plan probe exists.
Plaintext and private-key responses are redacting types and cross MCP only
through the three explicit confirmed reveal tools.

The pinned [general CA router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/certificate-authority-routers/general-certificate-authority-router.ts)
and provider router registration accept Machine Identity access tokens for the
current `/api/v1/cert-manager/ca` inventory plus provider-specific list, get,
create, update, and delete routes. The general response contains complete
provider configurations, so the MCP inventory deliberately projects only the
closed provider tag and value-free lifecycle metadata. The pinned
[internal CA router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/certificate-authority-routers/internal-certificate-authority-router.ts)
adds CSR, certificate, renewal, signing, import, CRL, signing-configuration, and
auto-renewal operations. The MCP surface implements the bounded CSR,
certificate, renewal, intermediate-signing, import, and CRL subset. It keeps
external signing configuration and auto-renewal configuration unavailable.
The pinned intermediate-signing service parses the supplied CSR and consumes its
public key without explicitly verifying the PKCS #10 self-signature. The MCP
boundary therefore verifies proof of possession locally for the classical and
ML-DSA algorithms accepted by the pinned CA model before permitting issuance.

The pinned [internal CA service](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/services/certificate-authority/internal/internal-certificate-authority-service.ts)
rejects SLH-DSA creation, plan-gates post-quantum algorithms, and ignores
`notBefore` unless `notAfter` is supplied. The MCP creation contract therefore
keeps every returned key algorithm typed, rejects SLH-DSA inputs and incomplete
validity locally, and requires full response reflection after the confirmed
mutation. The public DER route has no Machine Identity authentication and the
older `/api/v1/pki` surface is deprecated, so neither is exposed.

The pinned SSH Access
[CA router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/routes/v1/ssh-certificate-authority-router.ts)
and [template router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/routes/v1/ssh-certificate-template-router.ts)
accept identity access tokens for project inventory and exact CA/template
lifecycle operations. CA creation supports Infisical-generated RSA, NIST EC,
or Ed25519 keys and imported OpenSSH key pairs. The MCP boundary retains those
closed algorithms, structurally parses public and unencrypted private key
material, proves the exact RSA size or NIST curve and matching key families,
consumes imported private material in a zeroizing type, and relies on Infisical
to cryptographically match the pair before persistence. The dedicated
public-key result is independently bound to the exact CA record.

The template service stores complete issuance policy: canonical name, TTL and
maximum TTL, user and host certificate controls, optional custom key IDs, and
bounded user/host patterns. The MCP replacement contract sends that policy as a
whole so an omitted field cannot silently retain stale authority. The pinned
[certificate router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/routes/v1/ssh-certificate-router.ts)
accepts identity access tokens for signing and issuance. The MCP exposes those
as closed, non-replayed workflows that preflight template policy and verify the
returned certificate, plus the generated key pair for issuance, before output.
The pinned
[host router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/routes/v1/ssh-host-router.ts)
and
[host-group router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/routes/v1/ssh-host-group-router.ts)
also accept identity access tokens for project-scoped inventory, exact host and
group lifecycle, linked CA public keys, host-certificate issuance, and
membership administration. The MCP requires explicit active CA IDs for host
creation, models host/group PATCH as complete replacement, preserves direct
versus inherited login-mapping provenance, bounds unpaginated results, and
returns route-bound membership receipts without a race-prone follow-up read.
The global host inventory and user-certificate issuance routes remain
unavailable because the pinned router restricts them to JWT authentication.

The official [code-signing overview](https://infisical.com/docs/documentation/platform/pki/code-signing/overview)
describes a signer as a certificate-backed signing authority with members,
optional approvals, and audited use. The pinned
[signer router](https://github.com/Infisical/infisical/tree/v0.160.12/backend/src/server/routes/v1/signer-routers)
confirms that lifecycle, status, certificate reissue/export, public-key export,
and signing all accept Universal Auth identity access tokens. Signer reads are
audited. Creation can attach an existing code-signing certificate or issue from
Internal CA, AWS Private CA, or Azure AD CS; the current enabled-provider set
narrows issuance and reissue to Internal CA while retaining existing-certificate
attachment. The operational MCP slice omits optional inline memberships and
approval policy from creation because the same pinned source exposes those as a
separate, complete governance API. That API supplies direct user, identity, and
group membership routes; effective user and identity expansion; packed CASL
permissions; complete approval-policy replacement; approval request creation,
administrator pre-approval, revocation; and paginated signing-operation
history. The service creates an approval-policy record even for a signer with
no steps, so the MCP models an empty policy as an explicit record rather than
absence.

The pinned CASL serializer emits rules as an action, subject, optional
condition, inversion flag, optional fields, and optional reason tuple. Actions,
subjects, inversion, fields, and reason can be bounded and typed, but arbitrary
condition objects are intentionally withheld behind a `conditional` Boolean.
Policy mutation is exposed only as complete replacement after validating every
approver against current non-auditor memberships. Request and pre-approval
limits must remain finite and within the observed policy, and pre-approval must
target an effective non-auditor user or machine identity. Operation history is
sanitized to discard the submitted-data hash, client metadata, and upstream
error text.

The pinned signing route accepts at most 172 base64 characters representing no
more than 128 bytes and requires an explicit RSA, ECDSA, or ML-DSA algorithm.
The service-created signer key set is classical RSA/ECDSA, and its public-key
route rejects post-quantum certificate keys, so the useful closed MCP signing
enum contains only the nine compatible RSA/ECDSA algorithms. The client checks
canonical base64, exact digest length, active signer and certificate state,
project ownership, and algorithm/key compatibility before the non-replayed
mutation. The public-key read additionally exports the attached leaf and
requires the returned DER `SubjectPublicKeyInfo` to match its key and the signer
metadata to match its exact RSA modulus size or EC curve. The public result
reports that exact signer key algorithm rather than the upstream RSA family
label. The official
[Sign endpoint](https://infisical.com/docs/api-reference/endpoints/code-signing/signers/sign)
documents the same request and reflected signature response. Public
certificate and DER key outputs contain no private key. All signer operations
remain high risk because they disclose or exercise code-signing authority and
emit audit events.

The pinned source also establishes the Machine Identity boundary for the
remaining secret workflows. Secret-import list, get, create, update, and delete
accept Universal Auth identity tokens. Replication resync, secret-version reads,
and supported point-in-time recovery require user JWTs. The older snapshot
rollback route accepts an identity token but is deprecated and unconditionally
directs callers to point-in-time recovery. The server therefore implements only
the five supported mapping-management routes, forces new imports to be
non-replicating, and intentionally omits the bulk imported-values response.

The pinned v1 identity router establishes a separate administrative boundary.
Its core list, get, create, update, and delete routes accept Universal Auth
identity tokens. List and get return organization-membership wrappers, while
mutation responses return the direct identity. Creation defaults upstream to
`no-access` but leaves delete protection disabled, so this server selects the
safer explicit default of enabled protection. Updates permit mixed partial
changes upstream; the MCP surface narrows each call to exactly one typed field.
Custom roles exist in returned memberships. The separate project and
organization role routers accept Universal Auth identity tokens for list and
exact-slug reads, while creation and update explicitly require the RBAC plan
feature. Role discovery is therefore implemented, but custom-role
administration is capability-accounted as unavailable on the community
deployment. The core organization resource routes still require a user JWT, so
general organization read and administration remain unavailable.

The pinned v1 project-membership routers also accept Universal Auth identity
tokens. Human membership list and get use opaque membership IDs; invite accepts
lowercase emails or usernames plus permanent role slugs; update replaces the
complete role set; and delete removes one exact membership. Machine-identity
membership routes instead key create, get, update, and delete by identity ID and
offer an upstream offset/limit list. Read responses preserve existing
temporary-role scheduling metadata. Mutation responses are deliberately
narrower than read responses, so the MCP surface returns explicit receipts
instead of inventing missing profile or role state. Custom project-role slugs
can be assigned when already known, while temporary-role creation and scheduling
are reported unavailable rather than accepting unvalidated relative-duration
and timestamp strings. Permanent-only updates require explicit confirmation
that complete replacement removes every omitted assignment, including an
existing temporary role. The implementation follows the exact
[human membership route](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/project-membership-router.ts)
and [identity membership route](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/identity-project-membership-router.ts).

The pinned role service returns built-in and custom role definitions without a
license check on list or exact reads. Project built-ins receive a new UUID and
current timestamps for every response; organization built-ins use fixed dummy
UUIDs. Neither is a durable identifier, so the MCP surface selects roles by
validated stable slug and omits IDs and timestamps. Exact reads retain the
normalized action, subject, condition, and inversion fields needed to inspect
effective role intent. The implementation follows the pinned
[project role router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/routes/v1/project-role-router.ts),
[organization role router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/routes/v1/org-role-router.ts),
and [role service](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/services/role/role-service.ts).

The pinned enterprise group router accepts Universal Auth identity tokens for
organization group, member, project-assignment, and project group-membership
reads. Group list is unpaginated; member and project-assignment reads accept
bounded offset and limit values. Project-assignment results deliberately include
both assigned and unassigned projects unless filtered, with `joinedGroupAt` as
the assignment marker. Group create, update, and delete check the Groups plan
feature. The server therefore implements the six typed read workflows and
capability-accounts group and project group-membership administration as
unavailable instead of publishing an incomplete mutation subset. This mapping
follows the pinned
[group router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/routes/v1/group-router.ts),
[group service](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/services/group/group-service.ts),
and [project group-membership router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/project-group-memberships-router.ts).

The pinned v2 identity project additional-privilege router accepts both JWT and
identity access tokens for list, exact-ID read, exact-slug read, permanent or
temporary creation, update, and deletion. Unlike group and custom-role
administration, this route and its project additional-privilege service path do
not perform a plan-feature check. Temporary mode is `relative`; the route
requires a positive duration string and an ISO timestamp. The MCP surface uses
bounded seconds plus a canonical UTC timestamp instead of forwarding those
strings unchecked. The pinned service persists the range, parses it through its
duration library, and derives the end timestamp as start plus duration; response
validation enforces the same relationship and mutation-response equality. Update
addresses only the privilege ID upstream. The route handler attaches project and
identity IDs, but the pinned sanitized response schema omits both fields, so
Fastify's response serializer removes them from list, exact-read, and mutation
responses. The client therefore binds public scope from the list request and
uses that scoped collection to prove an opaque ID or slug belongs to the target
before exact reads, update, or deletion. Create binds the same coordinates sent
in its body. If a future response includes either scope field, it must match
before the response is accepted. User-specific additional-privilege routes
remain unavailable because their pinned router accepts JWT only. Response tests
share a fixture captured from this serialized contract rather than recreating
the route handler's pre-serialization object. This mapping follows the pinned
[v2 identity additional-privilege router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/routes/v2/identity-project-additional-privilege-router.ts)
and [project additional-privilege service](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/services/additional-privilege/project/project-additional-privilege-factory.ts).

The pinned Universal Auth router accepts Universal Auth identity tokens for
configuration get, attach, update, and removal; client-secret list, get, create,
and revoke; and lockout clearing. Creation returns the generated client secret
once, while later credential reads return only sanitized metadata. Removing the
authentication method or revoking a client secret invalidates associated
credentials and derived access tokens. Infisical's documentation identifies
trusted-IP restrictions as a paid feature, so the community MCP surface exposes
existing ranges read-only and capability-gates mutation. The implementation is
grounded in the exact
[v0.160.12 route source](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/identity-universal-auth-router.ts)
as well as the official Universal Auth guidance.

The pinned Token Auth router likewise accepts Universal Auth identity tokens
for configuration get, attach, update, and removal plus access-token list, get,
create, rename, and revoke. The older identity-scoped token-get route is hidden
and deprecated, so the MCP client uses the canonical token-ID route. Creation
returns the bearer once; every later operation returns metadata or an
acknowledgement only. The pinned list route narrows offsets to 100, and trusted
IP mutation is the same paid feature described by Infisical. The implementation
is grounded in the exact
[v0.160.12 route source](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/identity-token-auth-router.ts)
and the official [Token Auth guidance](https://infisical.com/docs/documentation/platform/identities/token-auth).

The pinned Kubernetes Auth router accepts Universal Auth identity tokens for
configuration get, attach, update, and removal. Direct API review is the
community-compatible path. Custom access-token IP ranges require IP allowlisting,
gateway routing requires the gateway plan feature, and gateway pools require an
Enterprise plan. The route returns the decrypted CA bundle and token-reviewer
JWT on reads, so the MCP boundary deliberately emits only configured booleans
for those fields. The server additionally narrows the permissive upstream
strings to HTTPS endpoints, bounded PEM/JWT inputs, explicit workload patterns,
and one exact audience. The implementation is grounded in the exact
[v0.160.12 route source](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/identity-kubernetes-auth-router.ts)
and the official [Kubernetes Auth guidance](https://infisical.com/docs/documentation/platform/identities/kubernetes-auth).

The remaining pinned provider and federated identity routers—AWS IAM, GCP,
Azure, OIDC, JWT, LDAP, OCI, Alibaba Cloud, TLS Certificate, and SPIFFE—are
deliberately not implemented. `server.capabilities` records each family as
unavailable so callers do not infer support from Infisical's upstream API or
attempt to reach it through an untyped escape hatch.

The pinned organization audit-log route accepts both user JWTs and Machine
Identity access tokens and authorizes either organization-wide or project-wide
audit access from the authenticated organization context. Its response embeds
unconstrained actor and event metadata, so the MCP model deliberately omits
those maps and retains only bounded typed summary fields. The pinned storage
query applies environment, secret-path, and secret-key predicates only when a
project is present and the event selection includes a filterable secret event;
the MCP input enforces that precondition and consumes only the matching metadata
coordinates to validate returned scope. The route also writes a
`view-audit-logs` event for offset zero; the MCP annotation, non-replaying client
path, and gateway risk model account for that observable side effect. The
implementation is grounded in the exact
[v0.160.12 route source](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/organization-router.ts).

The pinned dynamic-secret configuration and lease routers accept Machine
Identity access tokens for configuration list/get/update/delete and lease
list/get, renew, and revoke. Each of the four GET handlers creates an audit event, so none is a
retryable read even though it does not change the requested resource. The
configuration payload contains encrypted or provider-specific input objects
and arbitrary metadata, while lease payloads can contain a provider
configuration map and free-form status details. The MCP projection deliberately
drops those fields and validates the remaining identifiers, provider enum,
pinned duration syntax, default/maximum lifetime ordering, ownership
relationship, and timestamps. Unpaginated lists are
locally bounded. The provider-neutral update surface narrows each call to a
rename or complete lifetime policy and rejects incoherent lifetimes before the
first call. The pinned service still validates the stored provider connection
during either update, so the operation is never replayed. Confirmed deletion
keeps ordinary lease cleanup distinct from forced removal of Infisical tracking.
This mapping follows the pinned
[dynamic-secret router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/routes/v1/dynamic-secret-router.ts)
and [dynamic-secret lease router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/routes/v1/dynamic-secret-lease-router.ts).

The first provider-specific cohort implements the pinned `sql-database`
contract. Its upstream schema selects PostgreSQL, MySQL, Oracle, Microsoft SQL
Server, SAP ASE, or Vertica and requires connection credentials, password
requirements, lifecycle SQL statements, TLS settings, and optional gateway or
gateway-pool routing. Infisical's update service merges provider inputs, but its
pinned route is name-addressed and accepts no configuration ID, version, or
conditional precondition. The MCP server therefore marks provider-input
replacement unavailable: a preflight read cannot prevent a concurrent delete
and recreation from redirecting root credentials and privileged statements.
The provider validates plain lifecycle-template placeholders
and returns lease credentials as `DB_USERNAME` and `DB_PASSWORD`; the MCP layer
narrows the same placeholder vocabulary before the upstream call and exposes
those credentials only through the lease-creation output. Oracle's pinned
provider default uses a 30-character generated password; explicit MCP policies
enforce that same conservative bound. Because the provider-generic lease
route has no atomic provider discriminator, the MCP client performs the audited
exact-configuration GET before creation and binds the result to the observed
configuration ID. An invalid returned lease is compensatingly revoked only
when it belongs to that configuration or the direct response coherently names
the same SQL replacement configuration as its owner; an unrelated returned
lease is never touched. The
exact contract is
grounded in the pinned [provider models](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/services/dynamic-secret/providers/models.ts)
and [SQL provider implementation](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/ee/services/dynamic-secret/providers/sql-database.ts).
All provider-input replacement and other provider-specific creation and
credential-lease contracts remain capability-marked unavailable rather than
accepting free-form JSON.

Infisical documents Machine Identities and Universal Auth in its
[API authentication guide](https://infisical.com/docs/api-reference/overview/authentication).
The server uses that flow with a dedicated identity. Infisical’s separate
[documentation MCP server](https://infisical.com/docs/ai/model-context-protocol)
serves public documentation and is not a management-server precedent.

## MCP protocol guidance

The plan targets MCP `2025-11-25`. The official [tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
requires useful descriptions, typed schemas, input validation, safe errors, and
care around sensitive operations. The local gateway adds the stricter contract
of structured results with a JSON text compatibility form and complete gateway
classifications.

The [Streamable HTTP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
defines the single MCP endpoint, protocol-version behavior, Origin validation,
and session handling. The [authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
and [security guidance](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)
reinforce per-request authentication, token audience validation, least
privilege, and the prohibition on treating sessions as authorization or passing
tokens through to an upstream service.

## Local precedents

The homelab’s Rust MCP servers use `rmcp` Streamable HTTP, `/mcp` plus
`/healthz`, allowed-host enforcement, typed `schemars` models, handler-level
tests, and exact wire tests. The Wazuh deployment provides the two-network
sidecar pattern; the MCP gateway repository defines bearer injection,
gateway-signed `X-MCP-Identity`, generated risk classifications, and Cedar
confinement. The new repository adopts those contracts while accounting for its
write and secret-reveal surface.
