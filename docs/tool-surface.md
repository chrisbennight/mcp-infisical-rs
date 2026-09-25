# Tool surface

## Catalog rules

Tool names use `resource.action`. Each tool has a narrow typed input, typed
output, title, field-level descriptions, corrective errors, and annotations.
There is no tool that accepts an arbitrary HTTP method, URL, or JSON body.

Collections are paginated and bounded. Writes use the upstream API's exact
resource identity plus human-readable scope fields where ambiguity is possible.
Delete, revoke, rollback, rotate, and other irreversible operations require
explicit confirmation, and every input is validated before the first upstream
call.

## Planned families

The catalog will cover these resource workflows:

- server information, feature capabilities, and on-demand type descriptions
- organizations, projects, environments, folders, tags, roles, groups,
  memberships, users, identities, and authentication methods
- secret metadata, explicit reveal, versions, create, update, delete, batch,
  import, and rollback
- dynamic-secret configurations and lease lifecycle
- app connections, secret syncs, and secret rotations
- KMS keys and cryptographic operations exposed by Infisical
- PKI certificates, certificate authorities, code signing, and SSH resources
- secret scanning, integrations, webhooks, and audit events

Provider-specific app connection, sync, and rotation mutation models are
represented as tagged Rust variants. `types.describe` returns each implemented
variant's exact configuration schema and constraints on demand, and CRUD tools
reject unknown or mixed fields. Inventory returns a closed provider tag plus
common value-free metadata. The implemented `githubAppConnectionInput`,
`githubSecretSyncConfig`, and `dynamicSecretProviderInput` descriptions expose
the GitHub connection, GitHub secret-sync, and SQL-database contracts.
The implemented `sqlSecretRotationConfig` description exposes the shared SQL
credential-rotation parameter and secret-mapping contract.

## Published catalog

A client sees nine tools. Five are local and contact nothing: `server.info`,
`server.capabilities`, `operations.list`, `operations.describe`, and
`types.describe`. The other four are executors, one per operation tier:
`infisical.read`, `infisical.readAudited`, `infisical.write`, and
`infisical.destroy`.

Publishing every operation separately is what the executors replace. Each
operation carries a typed input and output schema, and the whole set is charged
against a caller's context before its first message even though any one turn
uses one or two of them.

An executor takes an `operation` name and that operation's own `arguments`.
`operations.list` gives names, executors, and purposes; `operations.describe`
returns one operation's input and output schema on demand. Names are discovered
there rather than repeated in every connection's initial catalog. Dispatch
rejects unknown names and wrong-tier calls before contacting Infisical.

Discovery defaults to ten brief results. `operations.list` accepts a `query`
such as `rotate database password`, an exact `namePrefix`, and a `tier`.
Search is local and deterministic: every query word must match the operation
name, description, or a reviewed alias. Results rank name matches ahead of alias
and description matches, with exact names breaking ties. This helps locate a
workflow; execution still requires its exact operation name.

Use `limit` (1–50) and the returned `nextOffset` to continue, retaining the
same filters. `matched` is the filtered count and `total` is the catalog count.
An absent `nextOffset` means the final page. Set `fullDescriptions: true`
for complete descriptions. Prefixes are limited to 64 characters and intent
queries to 128 characters; handlers enforce these bounds. Use
`operations.describe` with `includeOutputSchema: false` for an input-only
schema. These defaults replace the former unbounded discovery response.

### Collection cost and projections

`operations.describe.pagination` identifies each resource list's upstream cost:

| Value | What a page does | Effect of a smaller `limit` |
| --- | --- | --- |
| `nativeUpstream` | Sends page coordinates to Infisical | Reduces requested records upstream and in MCP output |
| `localSlice` | Fetches the complete scoped collection, then selects a local page | Reduces MCP output only |
| `boundedUnpaged` | Returns a validated collection without page coordinates | No page limit is available |

Offset pages are separate reads of mutable collections, not a stable snapshot.
Use each returned continuation until it is absent or null, and allow for records
moving between pages if the upstream collection changes. The effective upstream
response-byte ceiling is reported by `server.capabilities.runtime.limits` and
applies before local slicing or projection. No cross-caller inventory cache is
introduced.

Project lists return identity, name, slug, type, and organization by default.
Set `includeDetails: true` for descriptions and embedded environments; exact
`projects.get` still returns full details. Secret metadata lists retain secret
identity, name, environment, path, version, type, and hidden-value state. Set
`includeMetadata: true` to include operator metadata values, which may contain
sensitive configuration, and `includeTags: true` for full embedded tag details.
These projections reduce MCP output, not upstream bytes or audit events.

For secret and folder inventory, choose an exact path and leave `recursive`
false unless descendants are needed. Secret metadata also accepts `tagSlugs`,
with up to sixteen distinct validated tag slugs, each at most 64 characters.
The [pinned secret router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v4/secret-router.ts)
applies this comma-separated filter upstream; the client encodes it through
its typed query serializer and rejects returned secrets with no matching tag.
These filters reduce the upstream collection. A smaller MCP `limit` cannot fix
an oversized unpaged upstream body.
For project inventory that exceeds that bound, use `projects.get` with a known
project identifier. Native collection filters and page parameters remain bound
to the pinned API; the server does not send invented pagination parameters.

### Runtime capabilities

`server.info` reports the active transport, HTTP authentication profile, build
version, and schema revision. `server.capabilities` keeps the compiled capability
catalog separate from `runtime`, which reports this instance's limits and delivery
support. `operations.describe.availability` identifies mandatory file-transfer
requirements and whether this deployment satisfies them. None of these local
tools probes upstream permissions or license entitlements. Cache schemas by build
version and schema revision; do not cache deployment readiness across instances.

`runtime.limits.upstreamMaxConcurrentRequests` reports the shared upstream HTTP
request limit, including authentication. It is separate from the HTTP ingress
limit and also applies to stdio. Each upstream request's timeout includes its
wait for capacity; a separate login request has its own timeout budget.

The service-owned `io.cacahuate.infisical.file-transfer` extension is version 1.
An enabled instance advertises upload limits, staging capacity, expiry, and
instance-local storage. A transfer permits at most one redemption attempt and
does not confirm receipt; restart loses staged values. These are delivery facts,
not a claim that every MCP client supports the extension.

Nothing accepts an arbitrary HTTP method, URL, or body. An operation name this
build does not serve is rejected before any upstream call, as is an operation
addressed to the wrong tier's executor. Only a published tool is reachable, so
an operation cannot be invoked by name to bypass the annotations its executor
carries.

Because the gateway authorizes on the tool name and can no longer see the
operation, each executor is classified for the most sensitive thing it can
reach. Every one is high risk and marked for personal data.

## Operations

The operations below are served through the executors above.

`projects.list`, `projects.get`, `projects.create`, `projects.update`,
`projects.delete`, `environments.list`, `environments.get`,
`environments.create`, `environments.update`, `environments.delete`,
`environments.restore`, `folders.list`, `folders.get`, `folders.create`,
`folders.update`, `folders.batch.update`, `folders.delete`, `tags.list`,
`tags.get`, `tags.create`, `tags.update`, `tags.delete`, `identities.list`,
`identities.get`, `identities.create`, `identities.update`,
`identities.delete`, `projectUserMemberships.list`,
`projectUserMemberships.get`, `projectUserMemberships.invite`,
`projectUserMemberships.update`, `projectUserMemberships.delete`,
`projectIdentityMemberships.list`, `projectIdentityMemberships.get`,
`projectIdentityMemberships.create`, `projectIdentityMemberships.update`,
`projectIdentityMemberships.delete`, `projectRoles.list`,
`projectRoles.get`, `organizationRoles.list`, `organizationRoles.get`,
`groups.list`, `groups.get`, `groups.members.list`, `groups.projects.list`,
`projectGroupMemberships.list`, `projectGroupMemberships.get`,
`identityProjectAdditionalPrivileges.list`,
`identityProjectAdditionalPrivileges.get`,
`identityProjectAdditionalPrivileges.getBySlug`,
`identityProjectAdditionalPrivileges.create`,
`identityProjectAdditionalPrivileges.update`,
`identityProjectAdditionalPrivileges.delete`, `identityUniversalAuth.get`,
`identityUniversalAuth.attach`, `identityUniversalAuth.update`,
`identityUniversalAuth.remove`, `identityUniversalAuth.clientSecrets.list`,
`identityUniversalAuth.clientSecrets.get`,
`identityUniversalAuth.clientSecrets.create`,
`identityUniversalAuth.clientSecrets.revoke`,
`identityUniversalAuth.lockouts.clear`, `identityTokenAuth.get`,
`identityTokenAuth.attach`, `identityTokenAuth.update`,
`identityTokenAuth.remove`, `identityTokenAuth.tokens.list`,
`identityTokenAuth.tokens.get`, `identityTokenAuth.tokens.create`,
`identityTokenAuth.tokens.update`, `identityTokenAuth.tokens.revoke`,
`identityKubernetesAuth.get`, `identityKubernetesAuth.attach`,
`identityKubernetesAuth.update`, `identityKubernetesAuth.remove`,
`secrets.metadata.list`, `secrets.reveal`, `secrets.create`,
`secrets.update`, `secrets.delete`, `secrets.batch.create`,
`secrets.batch.update`, `secrets.batch.delete`, `secretImports.list`,
`secretImports.get`, `secretImports.create`, `secretImports.update`,
`secretImports.delete`, `auditLogs.list`, `appConnections.list`,
`secretSyncs.list`, `secretRotations.list`, `secretRotations.sql.get`,
`secretRotations.sql.getByName`, `secretRotations.sql.create`,
`secretRotations.sql.update`, `secretRotations.sql.delete`,
`secretRotations.sql.generatedCredentials.get`, `secretRotations.sql.move`,
`secretRotations.sql.rotate`, `secretRotations.sql.checkCredentials`,
`certificateAuthorities.list`, `certificateAuthorities.internal.list`,
`certificateAuthorities.internal.get`,
`certificateAuthorities.internal.create`,
`certificateAuthorities.internal.update`,
`certificateAuthorities.internal.delete`,
`certificateAuthorities.internal.csr.get`,
`certificateAuthorities.internal.certificates.list`,
`certificateAuthorities.internal.certificate.get`,
`certificateAuthorities.internal.certificateVersion.get`,
`certificateAuthorities.internal.certificate.generate`,
`certificateAuthorities.internal.certificate.renew`,
`certificateAuthorities.internal.intermediate.sign`,
`certificateAuthorities.internal.certificate.import`,
`certificateAuthorities.internal.crls.list`, `certificates.list`,
`certificates.get`, `certificates.issue`, `certificates.renew`, `certificates.revoke`,
`certificates.renewalConfiguration.update`, `certificates.delete`,
`certificates.import`, `certificates.certificate.get`,
`certificates.bundle.reveal`, `certificates.privateKey.reveal`,
`certificateRequests.list`, `certificateRequests.get`,
`certificateRequests.result.reveal`, `certificateRequests.cancel`,
`certificatePolicies.list`, `certificatePolicies.get`,
`certificatePolicies.create`, `certificatePolicies.update`,
`certificatePolicies.delete`, `certificateProfiles.list`,
`certificateProfiles.get`, `certificateProfiles.getBySlug`,
`certificateProfiles.create`, `certificateProfiles.update`,
`certificateProfiles.delete`, `certificateProfiles.certificates.list`,
`certificateProfiles.latestActiveBundle.reveal`,
`certificateProfiles.acmeEabSecret.reveal`,
`sshCertificateAuthorities.list`, `sshCertificateAuthorities.get`,
`sshCertificateAuthorities.publicKey.get`,
`sshCertificateAuthorities.create`, `sshCertificateAuthorities.replace`,
`sshCertificateAuthorities.delete`, `sshCertificateTemplates.list`,
`sshCertificateAuthorities.templates.list`, `sshCertificateTemplates.get`,
`sshCertificateTemplates.create`, `sshCertificateTemplates.replace`,
`sshCertificateTemplates.delete`, `sshCertificates.sign`,
`sshCertificates.issue`, `sshHosts.list`, `sshHosts.get`,
`sshHosts.create`, `sshHosts.replace`, `sshHosts.delete`,
`sshHosts.userCaPublicKey.get`, `sshHosts.hostCaPublicKey.get`,
`sshHosts.hostCertificate.issue`, `sshHostGroups.list`,
`sshHostGroups.get`, `sshHostGroups.create`, `sshHostGroups.replace`,
`sshHostGroups.delete`, `sshHostGroups.hosts.list`,
`sshHostGroups.hosts.add`, `sshHostGroups.hosts.remove`,
`codeSigners.list`, `codeSigners.get`, `codeSigners.create`,
`codeSigners.update`, `codeSigners.delete`, `codeSigners.status.update`,
`codeSigners.certificate.reissue`, `codeSigners.certificate.export`,
`codeSigners.publicKey.get`, `codeSigners.sign`,
`codeSigners.members.list`, `codeSigners.members.add`,
`codeSigners.members.role.update`, `codeSigners.members.remove`,
`codeSigners.effectiveMembers.list`, `codeSigners.permissions.get`,
`codeSigners.approvalPolicy.get`, `codeSigners.approvalPolicy.replace`,
`codeSigners.approvalRequests.list`, `codeSigners.approvalRequests.create`,
`codeSigners.approvalRequests.preApprove`,
`codeSigners.approvalRequests.revoke`, `codeSigners.operations.list`,
`kms.keys.list`, `kms.keys.get`, `kms.keys.getByName`, `kms.keys.create`,
`kms.keys.update`, `kms.keys.delete`, `kms.encrypt`, `kms.decrypt`,
`kms.keys.publicKey.get`, `kms.keys.privateKey.reveal`,
`kms.keys.bulkImport`, `kms.keys.privateKeys.bulkReveal`,
`kms.keys.signingAlgorithms.list`, `kms.sign`, `kms.verify`,
`dynamicSecrets.list`, `dynamicSecrets.get`, `dynamicSecrets.create`,
`dynamicSecrets.update`, `dynamicSecrets.delete`,
`dynamicSecretLeases.list`, `dynamicSecretLeases.get`,
`dynamicSecretLeases.create`, `dynamicSecretLeases.renew`,
`dynamicSecretLeases.revoke`, `appConnections.github.get`,
`appConnections.github.create`, `appConnections.github.update`,
`appConnections.github.rotateCredentials`, `appConnections.github.delete`,
`secretSyncs.github.get`, `secretSyncs.github.create`,
`secretSyncs.github.update`, `secretSyncs.github.delete`,
`secretSyncs.github.run`, `secretSyncs.github.removeSecrets`.

Ordinary read operations are annotated read-only, non-destructive, and
idempotent. Audited reads and writes are non-idempotent and sent exactly once.
Destructive operations additionally carry the destructive annotation and take
their own explicit confirmation field. Every operation has Rust-derived input
and output schemas plus structured JSON and compatibility text results.

## App-automation inventory and GitHub administration

`appConnections.list`, `secretSyncs.list`, and `secretRotations.list` use the
pinned generic inventory routes rather than provider-specific credential
routes. All three accept bounded local pagination. App connections optionally
filter by exact project ID; syncs and rotations require one exact project ID.
The upstream collections are unpaginated, remain bounded by the client response
limit, and are locally paged to at most one hundred records.

Infisical writes an audit event for each inventory GET, so these tools are
observable, non-idempotent, and sent exactly once. Their output validates the
closed v0.160.12 provider/destination/rotation enums, scope, timestamps, and
joined connection, environment, and folder ownership. Sync and rotation listing
performs one ordinary exact-project read after the audited inventory call and
requires every joined environment ID, name, and slug to match the requested
project's embedded environment catalog. Credential hashes,
provider configuration, sync options, secret mappings, generated credentials,
job IDs, and provider status messages are consumed or ignored without entering
the typed MCP result.
These three inventory operations are audited reads reached through
`infisical.readAudited`, which the manifest classifies high risk and
PII-bearing. Each invocation creates an Infisical audit event and exposes
privileged automation topology, even though the projected records are
value-free.

The five `appConnections.github.*` tools implement exact get, create, update,
confirmed credential rotation, and confirmed delete for the pinned GitHub
provider. Creation accepts closed GitHub App, OAuth, and personal-access-token
credentials plus GitHub Cloud, an optional Enterprise Cloud host, or a
validated GitHub Enterprise Server host. Secret values deserialize directly
into redacting types and never appear in results. Exact gets are audited
observable reads. Credential update performs that exact read first and requires
`confirmCredentialReplacement: true`; only then does it authenticate, perform
the read, and require the replacement to preserve the stored authentication
method because the pinned update route cannot change methods. The update tool
is classified destructive because its optional credential path can overwrite
the stored authorization credential. Credential rotation requires
`confirm: true` before authentication, then sends the pinned bodyless action
exactly once without automatic replay and returns only value-free metadata.
Delete requires `confirmDelete: true`.

The six `secretSyncs.github.*` tools implement exact get, create, update,
confirmed delete, manual sync, and manual remote-secret removal. The closed
configuration supports organization, repository, and repository-environment
destinations; organization visibility is restricted to all, private, or a
unique set of positive repository IDs. The key schema must contain exactly one
`{{secretKey}}` placeholder and may contain zero or more `{{environment}}`
placeholders.
Creation fixes the initial behavior to destination overwrite and requires an
explicit acknowledgement. Update, deletion, optional remote removal, manual
sync, and manual remote-secret removal each require an operation-specific
confirmation. ID-only operations first perform the audited exact GitHub sync
read and prove project and environment ownership before one non-replayed
mutation. Delete transmits the independent remote-removal choice as the pinned
`removeSecrets` query parameter rather than an undocumented body.

The nine `secretRotations.sql.*` tools implement the shared credential-rotation
lifecycle for PostgreSQL, MySQL, Microsoft SQL Server, and Oracle Database.
Exact ID and name reads validate the selected provider, project, app connection,
environment, and folder. Creation accepts two distinct alternating usernames,
an optional rotation statement restricted to the `username`, `password`, and
`database` templates, a coherent password policy, and two distinct mapped
secret names. It requires confirmation because Infisical immediately creates a
database principal and both mapped secrets.

ID-only update, delete, generated-credential reveal, move, rotate, and check
perform the audited exact provider read before the action and prove project and
provider ownership. Updates require confirmation because mapped-secret changes
rename live secrets and scheduling changes can queue an imminent rotation.
Deletion represents mapped-secret cleanup and generated-principal cleanup as
independent tagged choices; selecting either destructive action requires its
own confirmation before authentication. Move requires confirmation and a
separate acknowledgement before overwriting destination secrets. Manual rotate
and external credential check both require confirmation and are sent exactly
once. Generated credential reveal requires `confirmReveal: true`, returns one
or two typed username/password pairs with a validated active index, and is the
only SQL rotation result that contains credential values.

`server.capabilities` reports GitHub connection administration, GitHub sync
administration, GitHub credential rotation, and GitHub manual sync available.
GitHub import is unavailable because the pinned provider declares
`canImportSecrets: false`. The pinned
connection route's typed credential-rotation lifecycle is available. Other
app-connection providers and other sync destinations/manual jobs remain
unavailable. SQL secret-rotation administration, generated-credential reads,
manual rotation, and checks are available for the four named providers; every
other pinned rotation provider, including AWS IAM, remains explicitly
unavailable. No generic URL, request body, provider configuration map, or
credential escape hatch is exposed.

## KMS lifecycle and cryptographic operations

The fifteen `kms.*` tools cover every pinned `/api/v1/kms` route that accepts
Universal Auth identity access tokens: bounded key list, exact ID and name
reads, create, update, delete, encrypt, decrypt, public- and private-key reads,
bulk import, bulk private-key reveal, signing-algorithm discovery, sign, and
verify. There is no method, URL, algorithm, or JSON escape hatch.

Key targets always include the owning project and canonical key UUID. Exact
operations perform an audited key read and reject a project or usage mismatch
before the action. Encryption/decryption require an active symmetric key;
public-key, signing-algorithm, sign, and verify operations require an active
asymmetric key. The upstream disabled-state field is mandatory and is never
defaulted to active. Private-key reveals and bulk export reject disabled keys.
Update and delete deliberately still accept a disabled key so operators can
re-enable or remove it. Create validates the project before sending its single
confirmed mutation.

Key usage and algorithm are closed enums. AES-128-GCM and AES-256-GCM are
accepted only for encryption/decryption; RSA-4096, NIST P-256/P-384/P-521, and
ML-DSA-44/65/87 are accepted only for signing/verification. Signing algorithms
are separately closed to the exact RSA-PSS, RSA-PKCS#1 v1.5, ECDSA, and ML-DSA
variants returned by the pinned API. Infisical plan-gates the post-quantum
variants with `kmsPqc`; the server preserves them as typed choices but reports
entitlement detection unavailable because there is no identity-token probe.
Signing-algorithm discovery requires the upstream set to match the observed key
family exactly; missing, extra, duplicate, or cross-family values are rejected.

All binary inputs and outputs use canonical padded base64 and bounded response
validation. Although Infisical accepts one MiB of decoded operation data, the
MCP contract limits plaintext, message, or digest input to 512 KiB so base64
and JSON overhead remain inside the authenticated one-MiB ingress envelope.
Bulk requests contain at most one hundred unique key names or IDs, and bulk
import caps aggregate decoded key material at 512 KiB so every valid request
fits the same ingress envelope. AES imports must decode to exactly 16 or 32
bytes as selected. Validated import material retains its algorithm and cannot be
rebound to another algorithm when constructing a bulk entry. Per-key upstream
rejection messages are consumed as redacting values and replaced with a fixed
local rejection message. Sign and verify require an algorithm from the observed
key family. Digest mode accepts exact 32-, 48-, or 64-byte SHA-256, SHA-384, or
SHA-512 input for RSA PKCS#1 v1.5 and ECDSA; RSA-PSS and ML-DSA reject digest
mode.

Every KMS GET is an audited observable read and is never replayed. Every POST,
PATCH, and DELETE is likewise sent once. Creation, metadata or availability
changes, deletion, bulk import, encrypt, sign, and verify require explicit
confirmation. Decrypt and private-key results require `confirmReveal: true`;
plaintext or private material is held in redacting types and serialized only by
`kms.decrypt`, `kms.keys.privateKey.reveal`, or
`kms.keys.privateKeys.bulkReveal`. Every KMS operation is reached through an executor the
manifest classifies high risk, and each is a recorded or mutating call because
audited GETs create an upstream audit event and
all other KMS routes are mutations.

Bulk private-key reveal checks at most eight keys concurrently and shares the
client's upstream HTTP budget across requests and client clones. All preflights
must finish within one upstream timeout (10 seconds with the standard settings),
including authentication and capacity waits. Every key must pass scope and
availability checks before the single bulk export request. Returned keys follow
the requested order even if Infisical returns a different order.

A preflight failure or deadline reports the number of validated keys and states
that the bulk export request was not sent. Other reads may already have reached
Infisical and created access events, including reads cancelled after another
failure. The validated count is not a count of upstream audit events. Parallel
preflight failures can therefore record more accesses than sequential fail-fast
execution. Writes and the final bulk export are never automatically replayed.

## Certificate-authority inventory and internal lifecycle

`certificateAuthorities.list` uses the pinned general
`GET /api/v1/cert-manager/ca` route to return bounded value-free metadata across
the closed internal, ACME, Azure AD CS, AWS PCA, DigiCert, AWS ACM Public CA,
Venafi TPP, and GoDaddy provider families. The complete provider configuration
is discarded before the public type is built, so credentials and arbitrary
provider fields cannot enter an MCP result.

The fourteen `certificateAuthorities.internal.*` tools cover internal-provider
list, exact get, create, update, delete, CSR, certificate history, active and
historical certificate retrieval, generation, renewal, intermediate signing,
certificate import, and CRL routes. Reads validate
the explicit Certificate Manager project on every returned CA and use the
non-replaying observable-read path because Infisical records audit events.
Outputs include bounded subject, hierarchy, key-algorithm, validity,
path-length, certificate-ID, serial-number, and CRL-distribution metadata but
never the encrypted private key returned internally by Infisical.

Creation requires an existing Certificate Manager project and explicit
confirmation before one non-replayed mutation. Root and intermediate inputs use
closed hierarchy and key-algorithm enums plus a bounded subject. A root can be
created pending without validity or active with `notAfter` and an optional
`notBefore`; `notBefore` without `notAfter` is rejected because the pinned
service ignores it. Intermediate creation rejects root validity and path-length
fields. SLH-DSA algorithms remain output-compatible but are rejected for
creation exactly as the pinned service requires; Infisical enforces plan
entitlement for ML-DSA algorithms.

Update accepts only a non-empty complete desired name, lifecycle state, CRL
distribution-point set, or managed-distribution-point flag. It performs an
audited exact read before the mutation and requires the complete response to
equal that snapshot with only the requested fields changed. Delete likewise
preflights ownership, requires confirmation, and accepts only the exact deleted
snapshot in response.

Every certificate read first proves that the supplied Certificate Manager
project owns the internal CA, then uses one audited non-replayed GET. PEM
certificates, issuer chains, PKCS #10 CSRs, and CRLs have explicit size and
structure bounds; certificate identifiers, serials, versions, timestamps, and
path lengths are validated before serialization. Generation additionally
preflights an optional parent CA in the same project. Initial generation and
import require the target to be `pending-certificate` with no active certificate;
renewal and signing require an active certificate. Intermediate signing verifies
the PKCS #10 proof-of-possession signature, including the pinned ML-DSA families,
before contacting Infisical. Imported certificates must assert CA Basic
Constraints and `keyCertSign`; import has no private-key field. Every mutation
requires confirmation before authentication and sends exactly one request.

External-provider administration and installation, signing-configuration and
auto-renewal configuration, the unauthenticated public DER route, and deprecated
`/api/v1/pki` routes remain explicit unavailable capabilities. All fifteen CA operations are reached through executors the
manifest classifies high risk: reads disclose privileged PKI topology and create
audit events, while mutations create, change, or permanently remove trust
material.

## Certificate-policy lifecycle

`certificatePolicies.list`, `certificatePolicies.get`, and
`certificatePolicies.create`, `certificatePolicies.update`, and
`certificatePolicies.delete` use the project-scoped policy routes in the
[pinned certificate-policy router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/certificate-policy-router.ts).
List accepts bounded offset, limit, and optional search inputs. Exact reads bind
the returned policy to both the requested policy ID and Certificate Manager
project.

The typed result includes the policy's subject and SAN rules, key and extended
key usages, allowed algorithms, maximum validity, basic constraints, name,
description, and timestamps. Creation and update accept those rule families through
closed enums and bounded collections. They validate duplicate or contradictory
rules before an upstream call. Update distinguishes omitted basic constraints
from their explicit clearing, rejects empty changes, and proves exact project ownership before its
single confirmed mutation. Delete also requires confirmation and an exact
ownership preflight before its single request.
When the pinned service rejects deletion because a policy is still referenced,
the tool returns corrective guidance without forwarding dependent profile names;
the behavior is defined by the pinned
[policy service](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/services/certificate-policy/certificate-policy-service.ts).
The validation contract follows the pinned
[policy schemas](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/services/certificate-policy/certificate-policy-schemas.ts).

Policy reads are audited and therefore use the audited-read executor. Creation
and update use the write executor; delete uses the destructive executor. The
mutation contracts follow the
published [update](https://infisical.com/docs/api-reference/endpoints/certificate-policies/update)
and [delete](https://infisical.com/docs/api-reference/endpoints/certificate-policies/delete)
routes as pinned to the repository's supported Infisical version.
Certificate-profile creation reuses the same exact policy read and ownership
validation instead of maintaining a separate reduced response contract.

## Certificate inventory

`certificates.list` and `certificates.get` use the project-scoped search route
in the pinned
[project router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/project-router.ts).
The list operation accepts bounded pagination plus optional search, lifecycle,
profile, authority, application, key-algorithm, and ordering filters. Exact
retrieval searches for the certificate UUID and accepts only an exact ID and
project match.

Results contain certificate identity, ownership, names, serial and validity
metadata, revocation state, key and signature algorithms, key usages, CA status,
related profile, authority, and application identifiers when present, and
Infisical's `hasPrivateKey` result. Certificate PEM, issuer-chain PEM, and
private keys are not represented in either output schema. The response contract
follows the pinned
[certificate schema](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/db/schemas/certificates.ts)
and the search route's `hasPrivateKey` extension.

Because the upstream search is an audited POST, it uses the audited-read MCP
executor and is sent once without authentication replay.

## Certificate material transfer

`certificates.import` consumes the leaf certificate, optional private key, and
optional issuer chain from governed upload references. Confirmation is checked
before an upload is consumed. The leaf, chain, and key must agree before the
single import mutation; the response and project inventory are then reconciled
by certificate serial. This follows Infisical's
[import contract](https://infisical.com/docs/api-reference/endpoints/certificates/import-certificate).
The explicit project UUID is supplied to the request pre-validation hook rather
than relying on its cookie or organization fallback, matching the pinned
[Certificate Manager project resolver](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/plugins/inject-cert-manager-project-id.ts).

`certificates.certificate.get` returns the public leaf and issuer chain through
Infisical's
[certificate-body route](https://infisical.com/docs/api-reference/endpoints/certificates/cert-body)
after binding the material to the selected project inventory record.
`certificates.bundle.reveal` and `certificates.privateKey.reveal` require explicit
confirmation. Their private-key value uses governed reference delivery by
default when the transfer plane is configured; inline delivery remains an
explicit caller choice. The private key is checked against the selected leaf.
These operations follow the published
[bundle](https://infisical.com/docs/api-reference/endpoints/certificates/bundle)
and
[private-key](https://infisical.com/docs/api-reference/endpoints/certificates/private-key)
routes.

## Certificate issuance

`certificates.issue` uses Infisical's canonical profile issuance route and
accepts either typed managed-key attributes or one validated signed PKCS #10
CSR. It proves that the selected profile belongs to the supplied project and
uses API enrollment before sending the confirmed mutation. Subject fields,
typed SANs, usages, algorithms, validity, CA constraints, application scope,
and non-secret metadata are bounded before that preflight. This contract follows
the pinned
[certificate router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/certificate-router.ts)
and
[resource-metadata schema](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/services/resource-metadata/resource-metadata-schema.ts).

An immediate managed result is accepted only when its leaf, reported serial,
requested subject and SANs, and generated private key agree. A CSR result must
preserve the CSR subject and public key and cannot return a private key. An
approval or validation workflow instead returns a typed pending request
reference without certificate material or upstream message text. Immediate
private keys are inline unless the HTTP file-transfer extension is configured. The mutation is sent
once; an indeterminate transport or response outcome tells the caller to
reconcile through certificate-request inventory before deciding whether to
issue again.

The older issue and sign route variants remain superseded by this profile-based
route rather than becoming parallel issuance contracts.

## Certificate lifecycle

`certificates.renew`, `certificates.revoke`,
`certificates.renewalConfiguration.update`, and `certificates.delete` expose the
four distinct lifecycle mutations in the pinned
[certificate router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/certificate-router.ts).
Each operation first finds the exact end-entity certificate through
project-scoped inventory. Renewal and renewal-configuration changes additionally
require an active API-enrolled certificate whose managed private key and profile
are present. Revocation accepts the reason codes defined by
[RFC 5280 section 5.3.1](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1)
and requires an active certificate. Revocation and deletion require explicit
confirmation because they invalidate trust or remove the inventory record.

The pinned renewal route preserves the certificate attributes and accepts only
`removeRootsFromChain`; newer optional renewal controls are not inferred for
the v0.160.12 contract. A renewal response is accepted only when it identifies
a new certificate and request, reports a different matching serial, preserves
the source subject names and available key-algorithm and usage metadata, returns
a currently valid linked issuer chain, and supplies a private key matching the
renewed leaf. The returned certificate ID is then reconciled through project
inventory and must retain the source profile and certificate authority before
the result is reported.
That private key is inline unless the HTTP file-transfer extension is configured. Configuration
changes are closed to setting the documented lead-time range or disabling
automatic renewal, and their response must reflect the requested setting.
Revocation checks the returned serial and timestamp; deletion checks the
returned certificate identity, serial, and lifecycle state.
The published endpoint references are [renew](https://infisical.com/docs/api-reference/endpoints/certificates/renew),
[revoke](https://infisical.com/docs/api-reference/endpoints/certificates/revoke),
[update configuration](https://infisical.com/docs/api-reference/endpoints/certificates/update-config),
and [delete](https://infisical.com/docs/api-reference/endpoints/certificates/delete).

Each mutation is sent once. An indeterminate transport or response failure
returns operation-specific reconciliation guidance instead of replaying the
mutation.

## Certificate-request observation

`certificateRequests.list` returns a bounded project-scoped status page from
the pinned canonical request-search route. `certificateRequests.get` scans the
same project inventory for one exact request ID. Both discard upstream error
and pending messages and omit certificate bodies and private keys. Filters are
limited to fields the response can verify: common-name or SAN search, status,
creation window, profile IDs, and the route's closed sort fields.

`certificateRequests.result.reveal` first finds the exact request in that
project and requires its issued certificate ID and serial before calling the
exact result route. The result must preserve those identifiers, common name,
SAN values, and timestamps; the returned PEM leaf is parsed and its serial is
checked. The pinned search route
[serializes stored typed SANs as comma-joined values](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/certificate-router.ts#L684-L765),
while the
[exact result contract omits SANs](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/certificate-router.ts#L411-L471),
so this check does not infer a GeneralName type that Infisical did not return.
A returned PKCS#8 private key must match the leaf public key. The key uses the
same governed reveal delivery behavior as other secret-bearing operations and
defaults to an out-of-context reference when the transfer plane is configured.
CSR-based results without a returned private key do not create an empty secret
file.

`certificateRequests.cancel` requires confirmation before authentication,
finds the request in project inventory, accepts only pending or
pending-validation state, and sends the bodyless cancellation once. A race that
settles the request first is returned as a definitive non-cancellation rather
than retried. The contracts follow the pinned
[certificate router](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/server/routes/v1/certificate-router.ts)
and
[certificate-request service](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/services/certificate-request/certificate-request-service.ts).

## Certificate-profile lifecycle

The nine `certificateProfiles.*` tools cover every public profile route in the
pinned v0.160.12 Certificate Manager router:

- `POST /api/v1/cert-manager/certificate-profiles`
- `GET /api/v1/cert-manager/certificate-profiles`
- `GET /api/v1/cert-manager/certificate-profiles/:id`
- `GET /api/v1/cert-manager/certificate-profiles/slug/:slug`
- `PATCH /api/v1/cert-manager/certificate-profiles/:id`
- `DELETE /api/v1/cert-manager/certificate-profiles/:id`
- `GET /api/v1/cert-manager/certificate-profiles/:id/certificates`
- `GET /api/v1/cert-manager/certificate-profiles/:id/certificates/latest-active-bundle`
- `GET /api/v1/cert-manager/certificate-profiles/:id/acme/eab-secret/reveal`

Creation supports closed API, EST, ACME, and SCEP enrollment variants. It
validates the Certificate Manager project, policy ownership, optional CA
ownership, issuer/enrollment compatibility, defaults, and provider-specific
configuration before one confirmed mutation. Self-signed issuance is restricted
to API enrollment. An Azure AD CS template requires an Azure AD CS-backed CA,
and every certificate in an EST bootstrap chain must assert CA Basic Constraints
and `keyCertSign`. EST passphrases and SCEP challenge passwords deserialize
directly into zeroizing redacted values.

The pinned PATCH route cannot safely switch enrollment families: its service
only updates a configuration row that already exists and does not create the
new family’s row. The update tool therefore supports non-empty metadata,
defaults, public external configuration, and same-family enrollment changes.
A partial defaults object sends only supplied fields; for example,
`{"ttlDays": 365}` does not send null subject names or algorithms.
`clearDefaults: true` still sends an explicit null for the whole defaults object.
Basic constraints use `isCa` in tool inputs and Infisical's `isCA` spelling in
upstream requests and returned metadata.
It preflights exact profile ownership and re-reads configuration after a
same-family change so the public fields must reflect the request. Update and
delete require confirmation; delete accepts only the preflighted core profile
snapshot in response.
SCEP challenge-mode transitions are rejected because the PATCH contract cannot
coherently prove creation or removal of the mode-specific stored password;
same-mode SCEP policy changes remain supported.

List and exact reads expose bounded profile, policy, CA, metrics, defaults, and
enrollment metadata. The upstream list response may contain an EST passphrase;
the client consumes it into a zeroizing value and discards it before building
the MCP result. Returned list rows must match every requested enrollment,
issuer, CA, and application filter. Application membership is independently
verified through the pinned application-profile relationship route; nested CA
references use closed state and provider enums and remain bound to the
profile's scoped CA ID. PEM inputs and responses accept one terminal LF or CRLF
and cross the MCP boundary without that line ending. Issued-certificate listing
validates IDs, serials,
timestamps, requested state, and pagination. The latest bundle and ACME EAB
routes require `confirmReveal: true`; only those two tool serializers can expose
the bounded private key or EAB secret. Before a latest bundle crosses that
boundary, the client verifies the leaf certificate against its PKCS#8 private
key and serial and cryptographically links every supplied CA certificate in
issuer order; the leaf and every issuer must also be within their validity
periods. All nine operations are reached through executors the manifest
classifies high risk and PII-bearing, because every GET is audited. The six
profile-returning operations, issued-certificate listing, and latest-bundle
reveal carry personal data because subject fields and certificate contents can
identify people. The ACME EAB secret reveal returns no such content, but it is
reached through the same executor and therefore shares that executor's
classification.

## SSH Access administration

The thirty SSH tools cover pinned project inventory, exact authority, template,
host, and host-group lifecycles, plus certificate signing and issuance routes:

- `GET /api/v1/projects/:projectId/ssh-cas`
- `GET|POST /api/v1/ssh/ca[/:sshCaId]`
- `PATCH|DELETE /api/v1/ssh/ca/:sshCaId`
- `GET /api/v1/ssh/ca/:sshCaId/public-key`
- `GET /api/v1/projects/:projectId/ssh-certificate-templates`
- `GET /api/v1/ssh/ca/:sshCaId/certificate-templates`
- `GET|POST /api/v1/ssh/certificate-templates[/:certificateTemplateId]`
- `PATCH|DELETE /api/v1/ssh/certificate-templates/:certificateTemplateId`
- `POST /api/v1/ssh/certificates/sign`
- `POST /api/v1/ssh/certificates/issue`
- `GET /api/v1/projects/:projectId/ssh-hosts`
- `GET|POST /api/v1/ssh/hosts[/:sshHostId]`
- `PATCH|DELETE /api/v1/ssh/hosts/:sshHostId`
- `GET /api/v1/ssh/hosts/:sshHostId/{user-ca-public-key,host-ca-public-key}`
- `POST /api/v1/ssh/hosts/:sshHostId/issue-host-cert`
- `GET /api/v1/projects/:projectId/ssh-host-groups`
- `GET|POST /api/v1/ssh/host-groups[/:sshHostGroupId]`
- `PATCH|DELETE /api/v1/ssh/host-groups/:sshHostGroupId`
- `GET|POST /api/v1/ssh/host-groups/:sshHostGroupId/hosts[/:sshHostId]`
- `DELETE /api/v1/ssh/host-groups/:sshHostGroupId/hosts/:sshHostId`

CA creation sends the project ID in its one confirmed mutation and rebinds the
response, avoiding a redundant project read. Internal creation accepts the
closed RSA-2048, RSA-4096, NIST P-256/P-384, and Ed25519 algorithm set. External
creation accepts a bounded matching public and unencrypted private key pair.
The OpenSSH public key is structurally parsed to prove its exact RSA size, NIST
curve, or Ed25519 family. OpenSSH, PKCS#1 RSA, SEC1 EC, and PKCS#8 private keys
are structurally parsed and must match that family. The private key
deserializes directly into a zeroizing, redacted value, is sent once to
Infisical, and cannot enter structured or text output; Infisical remains
responsible for proving the two halves are the same key. CA replacement is a
complete name/status replacement. Delete and every write require confirmation
before authentication. Exact reads and writes bind the response to the
requested project and CA; the public-key route must equal the key on the
authenticated CA record.

Template creation and full replacement use one closed issuance policy: canonical
name, positive canonical TTL and maximum TTL, bounded unique user and host
patterns, separate user/host certificate flags, and an explicit custom-key-ID
flag. Project-wide inventory uses the project-scoped route directly. Creation
requires an active same-project CA because its route is keyed only by CA ID.
Replacement sends every mutable field in one request so omitted state cannot
survive accidentally. Lists are bounded and reject duplicate IDs; every exact
result is rebound to its project, CA, and template target.

Signing accepts one structurally parsed OpenSSH public key; issuance generates
one selected supported key pair and reveals the private half only through
`confirmReveal: true`. Both operations validate bounded unique principals,
template certificate-type and allowlist policy, optional TTL, and optional
custom key ID before one non-replayed mutation. Their two preflight reads prove
the supplied project, CA, and template relationship without redundant upstream
lookups. The returned OpenSSH certificate must be currently valid, signed by
the preflighted CA, and reflect the exact subject key, serial, certificate type,
principals, key ID, and requested usable lifetime. Issuance additionally parses
the unencrypted private key, proves its public half and algorithm match the
returned public key, and only then exposes the zeroizing private value. Bounded
past-only backdating from ssh-keygen is accepted, but expiry cannot exceed one
requested TTL after the response is received. Critical options are always
rejected. User certificates must contain exactly OpenSSH's default
`permit-X11-forwarding`,
`permit-agent-forwarding`, `permit-port-forwarding`, `permit-pty`, and
`permit-user-rc` extensions with empty values; host certificates must contain
no extensions. Infisical remains the persistence, permission, and upstream-error
authority; the MCP neither retries these mutations nor translates Infisical
failures into synthetic success.

The pinned signing and issuance routes expose no template version or conditional
precondition. The MCP therefore sends the preflighted effective TTL explicitly,
but cannot make every template-policy check atomic with the mutation. A
concurrent policy change remains subject to Infisical's current enforcement; if
Infisical persists a certificate whose response no longer matches the requested
semantics, the MCP returns a validation error after that single mutation and
does not retry it. Callers must reconcile that indeterminate result before
requesting another certificate.

Host creation requires explicit active user and host CA IDs instead of accepting
Infisical's implicit defaults. Host mutation responses must reflect the complete
hostname, alias, user and host TTL, immutable CA bindings, and direct login
policy. Effective login mappings retain direct or inherited provenance and are
canonicalized by source, login user, usernames, and groups. Host replacement is
a complete mutable-policy replacement; inherited group policy remains visible
but is not falsely treated as host-controlled state. The linked-CA key tools
bind the public route to both the exact host and authenticated CA record.

Host-certificate issuance preflights the exact host and active linked host CA,
then verifies the single mutation's returned certificate as a host certificate
for exactly the host's hostname, key ID `host-<host UUID>`, subject key, signer,
serial, configured TTL, empty critical options, and empty extensions. A
concurrent host-policy change can still make the persisted result
indeterminate; a failed post-mutation verification is returned as an error and
is never retried.

Host-group inventory carries bounded reflected host counts. Create and replace
send one complete group name and login policy. Membership listing is bounded,
rejects duplicate IDs, requires the returned count and membership filter to
agree, and binds the group through an exact project preflight. Add and remove
preflight both the group and host in parallel, perform one bodyless mutation,
and return a route-bound ID/project/hostname receipt; they avoid a follow-up read
that could race another membership change.

All thirty operations are reached through executors the manifest classifies
high risk and PII-bearing; Infisical audits their GETs and their mutations
change SSH trust or issuance policy. They carry CA names and public-key
comments, plus template user and host
allowlists, requested principals, hostnames, login mappings, group names, and
certificate key IDs can identify people or systems. The capability ledger marks
the JWT-only `sshHosts.globalInventory.read` and
`sshHosts.userCertificate.issue` capabilities unavailable; there is no generic
method, URL, key, or policy escape hatch.

## Code-signer operations

The twenty-three `codeSigners.*` tools implement the operational and governance signer surface from the
pinned v0.160.12 Certificate Manager router:

- `GET /api/v1/cert-manager/signers`
- `GET /api/v1/cert-manager/signers/:signerId`
- `POST /api/v1/cert-manager/signers`
- `PATCH /api/v1/cert-manager/signers/:signerId`
- `DELETE /api/v1/cert-manager/signers/:signerId`
- `PATCH /api/v1/cert-manager/signers/:signerId/status`
- `POST /api/v1/cert-manager/signers/:signerId/certificate/reissue`
- `GET /api/v1/cert-manager/signers/:signerId/certificate`
- `GET /api/v1/cert-manager/signers/:signerId/public-key`
- `POST /api/v1/cert-manager/signers/:signerId/sign`
- `GET|POST /api/v1/cert-manager/signers/:signerId/{users,identities,groups}`
- `PATCH|DELETE /api/v1/cert-manager/signers/:signerId/{users,identities,groups}/:memberId`
- `GET /api/v1/cert-manager/signers/:signerId/{effective-users,effective-identities}`
- `GET /api/v1/cert-manager/signers/:signerId/permissions`
- `GET|PUT /api/v1/cert-manager/signers/:signerId/approval-policy`
- `GET|POST /api/v1/cert-manager/signers/:signerId/requests`
- `POST /api/v1/cert-manager/signers/:signerId/requests/pre-approve`
- `POST /api/v1/cert-manager/signers/:signerId/requests/:requestId/revoke`
- `GET /api/v1/cert-manager/signers/:signerId/operations`

List responses must reconcile page length, offset, limit, and `totalCount`; an
empty or short page is accepted only when the reported collection is exhausted.

Creation accepts either a currently valid, non-CA, same-project certificate
with code-signing extended key usage and an Infisical-held private key, or a
fresh certificate from an active same-project internal CA. The existing path
reuses the typed project inventory lookup before mutation, matching the pinned
[signer service precondition](https://github.com/Infisical/infisical/blob/v0.160.12/backend/src/services/signer/signer-service.ts).
Internal issuance validates CA ownership, lifecycle state, RSA/ECDSA algorithm,
common name, validity, and renew-before ordering.
External-CA issuance and reissue remain explicit unavailable capabilities with
the other skipped provider families.

Direct member administration accepts only user, machine-identity, or group UUIDs
and built-in signer roles. Role replacement and removal first prove the exact
direct membership; effective membership expands only users and identities and
reports group provenance without exposing arbitrary upstream objects. Effective
permissions normalize the packed CASL rules into bounded actions and subjects;
arbitrary conditions are deliberately reduced to a `conditional` marker rather
than crossing the MCP boundary.

Approval-policy replacement is complete rather than patch-like: ordered steps,
eligible user/group approvers, signing count, and time-window constraints are
validated against active non-auditor signer memberships before one confirmed
PUT. Approval requests must ask for a finite signing count, a finite time
window, or both, and cannot exceed the observed policy. Administrator
pre-approval additionally proves an effective non-auditor grantee and binds the
returned request and grant to that principal. Revocation binds the returned
receipt to the exact request. Operation history omits data hashes, client
metadata, and upstream error text while retaining bounded attribution and
approval-grant identifiers.

Every metadata, status, deletion, certificate-reissue, and signing mutation
requires `confirm: true` before authentication. Update is non-empty and cannot
confuse omission with clearing. Omitted name, description, renewal window, and
status must remain equal to the preflight snapshot. Status changes must be real
transitions; enabling is accepted only from disabled state with an attached
certificate.
Reissue is restricted to internal CAs. Active signers retain their subject and
validity, while pending or failed signers may set missing values. The returned
resource must belong to the requested project and match the exact signer ID.
Non-delete mutations additionally reflect the requested or preserved
certificate, CA, state, and key-family invariants.

Signing accepts canonical padded base64 containing at most 128 decoded bytes;
the redacting domain value plus its decoded and re-encoded validation buffers
zeroize on drop.
RSA and ECDSA algorithm families must match the signer key. Digest mode accepts
only exact SHA-256, SHA-384, or SHA-512 lengths for RSA PKCS #1 v1.5 or ECDSA;
RSA-PSS requires message mode. The attached certificate must be active, within
its validity interval, and report the exact signer key algorithm. Submitted
data is zeroizing and redacted, is never emitted by MCP, and the mutation is
attempted once. Signature, algorithm, and signer ID must exactly reflect the
request. Certificate export validates a
single non-CA PEM leaf, and public-key export accepts only bounded canonical
base64 DER whose RSA modulus size or EC curve matches the signer and whose bytes
exactly match the attached leaf certificate `SubjectPublicKeyInfo`. The output
reports the validated exact signer key algorithm.

The operational and governance tools together form the complete signer surface
described above. All twenty-three operations are reached through executors the manifest
classifies high risk and PII-bearing: reads create audit events, mutations alter
or use signing authority, and signer subjects, certificate contents, client
metadata, or submitted data may identify people.

## Audit-log discovery

`auditLogs.list` uses the pinned `GET /api/v1/organization/audit-logs` route,
which accepts the dedicated Machine Identity's access token. It forwards a
bounded offset and limit and optionally filters by exact project, environment,
principal family, client family, normalized secret path, bounded secret key,
up to thirty-two canonical event types, and one complete canonical UTC range
of at most ninety days. The narrower local range stays within Infisical's
three-calendar-month maximum. Environment, secret-path, and secret-key filters
require an exact project and either no event filter or at least one of the
pinned secret-event types for which Infisical applies those metadata filters.

Results include the event and actor types, project coordinates, source IP,
bounded user agent and classification, and timestamps. Arbitrary actor and
event metadata are consumed without entering the typed output, preventing
secret-adjacent event payloads and unconstrained actor records from crossing
the MCP boundary. The environment, secret path, and top-level or batch secret
key are retained only long enough to validate the requested filters. Returned
records are rejected if any project, metadata, actor, client, event, or time
coordinate contradicts the request.

Infisical creates a `view-audit-logs` event whenever offset zero is requested.
The tool therefore advertises `readOnlyHint: false`, `idempotentHint: false`,
and `destructiveHint: false`; the behavior is documented rather than hidden
behind an inaccurate read-only annotation. `server.capabilities` reports
`auditLogs.read` available. This PII-bearing, externally observable operation is
reached through `infisical.readAudited`, which the manifest classifies high
risk. Its upstream GET is attempted
only once and is never automatically replayed after authentication rejection.

## Dynamic-secret configuration and lease lifecycle

The lifecycle foundation uses the pinned v1 dynamic-secret routes.
`dynamicSecrets.list` and `dynamicSecrets.get` address one exact project slug,
environment slug, and normalized absolute secret-tree path. Lease list adds one
canonical dynamic-secret name; lease get, renew, and revoke use one canonical
lease UUID. Infisical's configuration and lease GET handlers each record an
audit event. All four discovery tools therefore advertise `readOnlyHint:
false`, `idempotentHint: false`, and `destructiveHint: false`, send the upstream
GET once, and never replay it after authentication rejection.

Configuration outputs retain typed provider family, TTL expressions, gateway
coordinates, status, and timestamps. TTL expressions must match Infisical's
pinned duration grammar, remain between one minute and ten years, and keep an
optional maximum greater than or equal to the default. Lease outputs retain identity,
expiration, owner, status, and timestamps. Provider input objects, arbitrary
metadata, lease configuration maps, and free-form status details are consumed
without crossing the MCP boundary. The two unpaginated upstream collection
routes are exposed as locally bounded pages of at most 100 validated records.
These operations are reached through executors the manifest classifies high
risk; lease external-entity identifiers are PII-bearing.

`dynamicSecretLeases.renew` requires an explicit whole-second TTL from 60
through 315360000 and sends the mutation once. `dynamicSecretLeases.revoke`
requires `confirm: true`; its independent `force` flag defaults to false and is
reserved for provider cleanup failure. It is destructive and also sent once.

`dynamicSecrets.update` applies exactly one provider-neutral change: a canonical
rename or complete default/optional-maximum lifetime replacement. Lifetime
ordering is validated before the first upstream call. The pinned service probes
the stored provider connection on every update, even when provider inputs are
unchanged, so the tool is non-idempotent and never replayed. It does not accept
metadata, username templates, gateway selection, or provider input maps.

`dynamicSecrets.delete` requires `confirm: true`. Ordinary deletion revokes
existing provider leases before removing the configuration; `force: true`
instead removes Infisical tracking without requiring provider cleanup. The
force flag is independent and defaults to false. Both paths are destructive and
sent once.

`dynamicSecrets.create` accepts the `sqlDatabase` provider tag with a complete,
closed input object for PostgreSQL, MySQL, Oracle, Microsoft SQL Server, SAP
ASE, or Vertica. Connection identifiers, password requirements, TLS settings,
and direct/gateway/gateway-pool routing are bounded before the first upstream
call. Explicit Oracle password policies retain the pinned 30-character maximum;
the other SQL clients accept the provider's 250-character maximum. Creation,
renewal, and revocation SQL templates accept only the pinned
plain placeholders appropriate to each operation; nested or unknown template
expressions are rejected locally. These templates are privileged SQL executed
by Infisical against the configured database. Both configuration mutations and
credential lease creation are reached through executors the manifest classifies
high risk.

`dynamicSecrets.updateProviderInputs` is intentionally unavailable. Infisical
v0.160.12 exposes only a name-addressed replacement route with no configuration
ID, version, or conditional precondition. A concurrent delete and recreation
could therefore apply root credentials and privileged statements to a different
configuration after any preflight read. The server fails closed instead of
advertising that racy mutation.

`dynamicSecretLeases.create` optionally accepts a bounded
TTL and returns exactly one generated database username and password; the
password exists only in this declared sensitive output and is not retained or
logged by the server. Before the irreversible lease POST, the server performs
the pinned observable configuration GET and proves that the exact target is a
SQL configuration. It also binds the response to that configuration ID. If the
target is replaced between those calls or the returned credential contract is
invalid, a returned lease is revoked only when it belongs to the preflighted
configuration or the direct response coherently identifies the same named SQL
replacement configuration as its owner. An unrelated returned lease is never
touched; owned-resource cleanup failure is returned rather than hidden. Because
lease creation executes the configured privileged SQL, it advertises
`destructiveHint: true`.

`server.capabilities` reports configuration/lease reads, provider-neutral
settings updates, SQL-database creation, configuration deletion, SQL lease
creation, lease renewal, and lease revocation available. Provider-input
replacement is unavailable for every provider family; creation and credential
leases for non-SQL providers are also explicitly unavailable. No generic JSON
passthrough is exposed.

Machine-identity authentication is intentionally limited to Universal Auth,
Token Auth, and Kubernetes Auth. The capability catalog explicitly reports AWS
IAM, GCP, Azure, OIDC, JWT, LDAP, OCI, Alibaba Cloud, TLS Certificate, and
SPIFFE authentication administration as unavailable and not implemented. No
generic provider-auth passthrough is exposed.

Collection inputs default to offset 0 and limit 50, accept at most 100 records,
and return the next validated offset when another page exists. Resource reads
require exact validated project IDs, environment slugs, and absolute normalized
secret-tree paths where applicable. Upstream failures become tool-level errors
with a fixed safe category; API failures also include their status and any
validated request ID. Response bodies are never forwarded.

### Structured execution errors

A known operation called through its correct executor reports execution and
argument failures with `isError: true`. Both `structuredContent.error` and the
matching JSON text carry `category`, `operation`, `effect`, `recovery`, and
`correction`. A safe `fieldPath`, validated `requestId`, and bounded
`retryAfterSeconds` appear when available. Inspect the error before interpreting
the operation's success schema. `types.describe` accepts `executionError` for
the error object's schema.

`recovery` distinguishes correcting arguments, waiting, inspecting configuration,
and reconciling an uncertain result. Pacing guidance never authorizes automatic
mutation replay. A generic upstream 404 is `notFound`; it does not establish that
an API route is unavailable. Compiled omissions remain capability-discovery facts.

`effect: "notStarted"` means the final action was not initiated, as with a failed
capacity reservation or KMS bulk preflight. `preflightObservationsPossible` is true
when earlier preflight reads may have created audit events, false when refusal is
known to precede them, and omitted when that phase is unknown. `effect: "unknown"`
requires reconciliation; transport failure, invalid responses, and post-execution
delivery failures cannot prove that nothing happened. Queue and authentication
failures do not erase possible earlier operation steps. Successful receipts retain
their existing `applied` or `approvalRequired` outcomes where those receipts apply.

Malformed executor envelopes, unknown operations, and wrong executor routing stay
protocol errors. Invalid sensitive values are never repeated in correction text.
Errors stay inline even when successful results request file delivery; retained
delivery references in oversized-result errors remain usable until expiration.

## Project and environment administration

The product release pin and the route namespace are independent. For Infisical
`v0.160.12`, the current Machine-Identity-compatible project and environment
administration routes are under `/api/v1/projects`; the v2 project router in
that release is a deprecated compatibility surface. Other families use their
own current namespaces, including v2 secret imports and folders and v4 secrets.
Callers never select a route version; each typed operation fixes its canonical
method and path for the pinned release.

`projects.create` accepts every project kind exposed by the pinned API and
defaults both default-environment creation and deletion protection to true.
`projects.update` applies exactly one typed change per request: name,
description, slug, deletion protection, automatic capitalization, encrypted
secret-metadata enforcement, secret sharing, or point-in-time version limit.
It does not expose the secret-detection ignore-value array or deprecated
snapshot presentation setting. `projects.delete` requires `confirm: true`,
uses the upstream soft-delete route, and remains marked destructive because
Infisical schedules later cleanup. Upstream deletion protection is honored.

Environment tools use exact validated project and environment IDs. Create has
a bounded optional one-based position, and update changes exactly one of name,
slug, or position. Delete requires `confirm: true` and deliberately omits the
upstream `hardDelete` query parameter, so it can only soft-delete. Restore is a
separate typed mutation for a previously soft-deleted environment.

## Folder and tag administration

Folder tools use the pinned v2 route family. Get addresses one opaque folder
ID. Create requires an exact project, environment slug, parent path, and name;
Infisical may create missing parent segments as part of that request. Update
replaces the complete desired name and a required nullable description without
a racy read-before-write. Batch update accepts between one and fifty unique
folder IDs under one project and requires complete environment, path, name, and
nullable description state for every entry. Delete requires `confirm: true`;
recursive resource removal is separately controlled by `forceDelete`, which
defaults to false.

Tag tools use the pinned v1 project route family. Get selects exactly one tag
by opaque ID or stable slug. Create requires a lowercase slug and defaults the
opaque upstream color string to empty. Update replaces the complete slug and
color without first reading mutable state. Delete uses the exact project and
tag IDs and requires `confirm: true`.

## Machine-identity and organization administration

Machine-identity tools use the pinned v1 identity route family, whose core
list, get, create, update, and delete operations accept Universal Auth identity
tokens. List requires one exact organization ID and applies bounded local
pagination because the upstream route returns the complete collection. Read
results contain only identity and organization-membership metadata: they omit
metadata key/value records, login history, credentials, and authentication
configuration. Existing custom-role slugs remain readable.

Create defaults to the built-in `no-access` role and enables delete protection.
Only the built-in `admin`, `member`, and `no-access` roles are assignable; custom
RBAC is not emulated on the community deployment. Update applies exactly one
name, built-in role, or delete-protection change, avoiding a racy
read-before-write. Delete requires `confirm: true`, honors upstream delete
protection, and is marked destructive because Infisical also revokes the
identity's authentication tokens.

The pinned core organization read and administration routes accept user JWTs,
not Universal Auth identity tokens. `server.capabilities` reports
`organizations.read` and `organizations.admin` unavailable instead of routing
around the dedicated Machine Identity boundary.

## Project membership administration

The ten membership tools use the pinned v1 project routes and accept Universal
Auth identity tokens. Human-user list and get results expose sanitized PII:
user ID, username, optional email and names, email-verification state,
authentication-method names, membership ID, and roles. Password hashes, public
keys, devices, MFA details, login history, and credentials are never returned.
The unpaginated upstream human list is response-size bounded and locally
paginated. Machine-identity membership listing forwards the validated offset
and limit; reads return concise identity metadata and role assignments,
including the mode, range, start, and end metadata for existing temporary
roles.

`projectUserMemberships.invite` accepts one to fifty unique lowercase emails or
usernames and a complete set of one to ten permanent built-in or existing custom
role slugs. Updates replace the complete role set with permanent assignments
without first reading mutable state. They require
`confirmReplaceAllRoles: true`, explicitly acknowledging that every omitted
assignment—including a temporary role—is removed, and are classified as
destructive. Human-user get, update, and delete address the opaque
membership ID. Machine-identity create, get, update, and delete address the
identity ID. Both families require an exact project ID; both delete tools
require `confirm: true`; all writes are sent exactly once. Mutation responses
use narrow membership receipts when the pinned route does not return profile or
role state.

Temporary membership roles cannot be created or scheduled through a generic
string boundary. Confirmed complete role replacement can remove an omitted
temporary assignment.
`server.capabilities` reports `projectMemberships.temporaryRoles.update`
unavailable until relative durations and start timestamps have a bounded,
validated representation. Permanent custom-role assignment is supported by
slug, and the role discovery tools provide the stable slugs needed for that
workflow.

## Role discovery

The four role tools use the pinned v1 project and organization role routes,
which accept Universal Auth identity tokens for list and exact-slug reads.
`projectRoles.list` and `organizationRoles.list` apply bounded local pagination
to the upstream complete collections. Exact reads include normalized
permission rules and optional condition expressions.

Infisical generates fresh IDs and timestamps for built-in project roles on
each request and uses documented dummy IDs for built-in organization roles.
Those synthetic fields are not stable resource identities, so the MCP outputs
omit all role IDs and timestamps and expose the stable slug, owning scope,
description, and a derived `builtIn` marker instead. Custom role definitions
remain discoverable without exposing a generic permission or route passthrough.

Custom project- and organization-role creation and update require Infisical's
RBAC plan feature. `server.capabilities` reports `projectRoles.admin` and
`organizationRoles.admin` unavailable. The server does not offer deletion as
an isolated partial administration path when it cannot safely provide the
complete role lifecycle.

## Group and project group-membership discovery

The six group tools use the pinned v1 group and project-membership routes,
which accept Universal Auth identity tokens for reads. `groups.list` applies
bounded local pagination to the complete organization collection, while
`groups.members.list` and `groups.projects.list` forward bounded offset and
limit values to Infisical. Exact reads use validated group, project, and group
membership coordinates. Project-membership responses are rejected if the
returned project or group does not match those coordinates.

Group outputs include stable group identity, organization-role assignment, and
timestamps. Member results distinguish human users from machine identities.
Human results contain sanitized PII—username, optional email and names, user ID,
and join time—while machine-identity results contain only ID, display name, and
join time. Group project listing supports all, assigned, and unassigned views;
the nullable `joinedGroupAt` timestamp preserves the assignment state rather
than presenting every organization project as a membership.

Group creation, update, and deletion require Infisical's Groups plan feature.
`server.capabilities` therefore reports `groups.admin` unavailable. Project
group-membership administration is also unavailable because a useful complete
lifecycle depends on that plan-gated group administration, and this build does
not implement temporary role scheduling. The read capabilities remain explicit
as `groups.read` and `projectGroupMemberships.read`; no partial mutation or
generic route passthrough is exposed.

## Identity project additional privileges

The six `identityProjectAdditionalPrivileges` tools use the pinned v2 route
family, which accepts Universal Auth identity tokens for list, get by ID, get by
slug, create, update, and delete. Each call states the owning project and target
machine identity. The pinned response serializer omits project and identity
fields even though the route handler attaches them. List results therefore bind
those coordinates from the scoped query. Exact-ID and slug reads first prove the
resource in that collection, then require the exact response to preserve its ID
or slug. Slug reads also require the stable project slug used by the upstream
route. Optional scope fields are validated if a future response includes them.

Permission inputs require a bounded subject, one to sixty-four bounded actions,
at most 256 rules, and at most 64 KiB of serialized conditions per rule.
Infisical v2 remains authoritative for the subject-specific action and condition
union, so new pinned permission subjects remain representable without an
arbitrary HTTP or request-body escape hatch. Outputs expose normalized permission
rules and scheduling metadata but no credential or secret values. Temporary
responses require a bounded duration and parseable UTC start/end timestamps with
an exact start-plus-duration relationship. Create and update additionally reject
a response whose start, duration, or supplied complete permission set differs
from the request.

Creation supports permanent grants and temporary relative grants with a
positive duration of at most ten years and a validated UTC activation timestamp
in `YYYY-MM-DDTHH:MM:SSZ` form. Because an inverted rule denies its actions,
creation requires `confirmDenyPermissions: true` whenever any permission has
`inverted: true`. Update replaces the slug and complete lifetime;
permissions are preserved when omitted and completely replaced only when
`confirmReplacePermissions` is true. Supplying an empty confirmed set removes
all rules. Update and delete first read and validate the immutable project and
identity scope through the scoped collection before sending their single
mutation. Delete additionally
requires `confirmDelete: true`. Capabilities report read, create, update, and
delete as available; user-specific additional privileges remain outside this
Machine-Identity boundary because their pinned route is JWT-only. The capability
catalog reports `userProjectAdditionalPrivileges.read` and
`userProjectAdditionalPrivileges.admin` unavailable rather than implying that
the absent tools can be reached through another surface.

## Universal Auth administration

The Universal Auth family uses the pinned v1 routes under
`/api/v1/auth/universal-auth/identities/{identityId}`. Get returns non-secret
configuration, including the public client ID and current trusted-IP metadata.
Attach sends a complete community-compatible token and lockout configuration.
Update changes exactly one coherent group: the mutually constrained token
lifetime fields together, the use limit, or the complete lockout policy. This
avoids reading mutable configuration and then writing stale mixed state.

Trusted-IP ranges remain readable but are not writable through this deployment
because Infisical gates that mutation behind an enterprise feature. The
unavailable `identityUniversalAuth.trustedIps.update` capability makes that
constraint discoverable. Removing Universal Auth requires `confirm: true` and
is destructive because it revokes the method's credentials and derived tokens.
Clearing lockouts also requires confirmation because it changes an authentication
security control.

Client-secret list and get are locally bounded and return metadata only: ID,
safe prefix, description, lifetime, usage counts, revocation state, and
timestamps. Create is the sole credential-bearing operation in this family and
returns the generated client secret exactly once in an explicitly sensitive
field. The value is held in the same zeroizing, redacted type as other secrets
until that narrow serialization boundary. Creation requires the caller to state
both TTL and use-limit settings explicitly, including when intentionally selecting
zero for no limit. Revoke requires exact identity and
credential IDs plus `confirm: true`; it never returns the secret value.

## Token Auth administration

The Token Auth family uses the pinned v1 routes under
`/api/v1/auth/token-auth`. Configuration get, attach, update, and removal use
one exact machine-identity ID. Attach requires callers to state TTL, maximum
TTL, and use-limit settings explicitly, including intentional zero values.
Update changes either both lifetime fields together or the complete use limit,
so it does not create a read-before-write race. A zero maximum TTL represents
the upstream unlimited bound. Current trusted-IP ranges remain readable;
mutation is enterprise-gated and advertised unavailable as
`identityTokenAuth.trustedIps.update`.

Token list and get expose only non-secret identifiers, labels, usage and
lifetime counters, revocation state, scope, and timestamps. The pinned list
route accepts offsets only through 100, so its schema narrows that bound and
rejects a full terminal page rather than emitting an unusable continuation.
Create is the sole credential-bearing Token Auth operation and returns the
generated bearer exactly once from the same zeroizing, redacted secret type.
Later reads never return it. Update replaces one bounded non-secret token name.
Token revocation and authentication-method removal both require explicit
confirmation and are sent exactly once.

## Kubernetes Auth administration

The Kubernetes Auth family uses the pinned v1 routes under
`/api/v1/auth/kubernetes-auth/identities/{identityId}`. Get consumes the
upstream response into a value-free model: it returns workload policy, token
settings, TLS and credential-presence booleans, and current gateway/trusted-IP
metadata, but never the stored token-reviewer JWT or CA bundle. The reviewer
JWT is held in the zeroizing redacted secret type until it is discarded.

Attach configures the community-compatible direct Kubernetes API TokenReview
path. It requires an HTTPS API endpoint, explicit namespace and service-account
name or glob policies, an exact token audience, and complete token lifetime and
use-limit settings. Callers must state `*` deliberately to allow every
namespace or service-account name. TLS verification requires a bounded PEM CA
bundle; an optional bounded token-reviewer JWT is sent only to Infisical.

Update applies exactly one coherent group: both lifetime fields, the use limit,
the complete workload/audience policy, or the complete direct-reviewer
configuration. Reviewer credential handling is explicit—preserve, replace, or
clear—and switching to direct review clears existing paid gateway routing in
the same request. No update reads mutable configuration before writing. Custom
trusted IPs, gateway routing, and gateway pools are paid features advertised as
unavailable capabilities while their existing non-secret identifiers remain
readable. Removal requires `confirm: true`, revokes derived tokens, and is sent
exactly once.

## Secret response policy

`secrets.metadata.list` never returns values. The high-risk `secrets.reveal`
operation requires a precise project, environment, path, and secret identity
and returns one current shared-secret value to the authorized MCP caller.
Imports and reference expansion are always disabled. That reveal tool exists
specifically to transmit a secret: with inline delivery its structured JSON and
compatibility text necessarily contain the value, and with reference delivery
the value moves out-of-band instead. Neither representation is logged or
persisted by this server.

The other credential-bearing results are the explicitly documented one-time
outputs of `identityUniversalAuth.clientSecrets.create`,
`identityTokenAuth.tokens.create`, `dynamicSecretLeases.create`, and
`sshCertificates.issue`, the managed-key result of `certificates.issue`, the
managed-key result of `certificates.renew`, plus the confirmed
`secretRotations.sql.generatedCredentials.get`, `kms.decrypt`,
`kms.keys.privateKey.reveal`, `kms.keys.privateKeys.bulkReveal`,
`certificates.bundle.reveal`, `certificates.privateKey.reveal`,
`certificateProfiles.latestActiveBundle.reveal`, and
`certificateProfiles.acmeEabSecret.reveal` operations. No result outside these
named operations and `secrets.reveal` contains a generated credential, private
key, decrypted plaintext, or current shared-secret value.

Each of these operations takes an optional `delivery` argument. When the server
is deployed with its reveal transfer plane, delivery defaults to `reference`:
the result replaces its sensitive fields with a `secretFile` reference whose
envelope — the sensitive fields exactly as they would have appeared inline —
is fetched out-of-band through `files/authorizeDownload` and consumed by a
single download. `delivery: "inlineValue"` restores the inline result, and is
the only way to receive a value in-band on such a deployment. Without the
plane, delivery defaults to `inlineValue` and `reference` is refused before any
upstream call.

The write direction mirrors this. `secrets.create` and `secrets.update` take
exactly one of `secretValue` (inline, unchanged) and `secretValueFile`.
`certificates.import` takes `certificateFile` plus optional `privateKeyFile` and
`certificateChainFile`; it has no inline material fields. Each file field is an
opaque reference uploaded out-of-band through `files/authorizeUpload`, resolved
single-use and never echoed. On a deployment without the plane, these fields
are refused before an upstream call. Other secret-bearing write inputs remain
inline-only.

Every executor also takes an optional `resultDelivery` argument. `file` stages
the operation's whole structured result as an out-of-context envelope and
returns one fixed wrapper shape — the operation name plus a `resultFile`
reference — so the response type stays a function of the request rather than of
the payload; a host reads the staged result selectively instead of receiving it
in context. `inline` (the default) is unchanged and remains subject to the
result budget, whose oversized-result error names `resultDelivery` as a retry
path when the plane is configured and the refusal already classifies the call
as safely repeatable; an error whose effect was already applied never points
at a retry. Without the plane, `resultDelivery: "file"` is refused before any
upstream call. Tool errors are always returned inline.

The pinned `v0.160.12` secret-version listing route accepts user JWTs but not
Universal Auth identity tokens. `server.capabilities` therefore reports version
history as unavailable for this deployment instead of routing around the
Machine Identity boundary. Version mutations remain out of scope until
Infisical exposes a compatible authenticated contract.

Create and update inputs contain a redacting secret value, but their results
never echo it—even though Infisical's v4 response does. Results contain only
safe identity, version, timestamp, or approval-request metadata. Delete
requires `confirm: true`. All four workflows require exact project,
environment, normalized path, and secret name coordinates and currently act
only on shared secrets. Error messages refer to field names and upstream
request IDs, never field values.

Batch create, update, and delete accept between one and fifty unique names under
one exact project, environment, and normalized path. They reject empty,
oversized, or duplicate-name batches before authenticating upstream. Batch
update always selects Infisical's `failOnNotFound` mode so a missing target
cannot silently become a create. Batch delete requires `confirm: true`. Batch
receipts discard every submitted and upstream-echoed value.

Secret-import tools manage mappings, never imported values. List is locally
paginated because the pinned upstream route returns the complete exact-scope
collection; the response-byte limit still bounds that fetch. Get uses one
validated opaque import ID. Create requires complete destination and source
coordinates in the same project and forces replication off. Update replaces the
complete source coordinate or moves the mapping to a one-based position between
1 and 100,000; partial source updates are rejected so direct-cycle validation
does not require a racy read before the write. Delete requires `confirm: true`.
Every result contains value-free mapping metadata only.

The bulk imported-values route is intentionally omitted; callers must use
`secrets.reveal` for one exact shared secret. Replication resync and supported
point-in-time recovery routes accept user JWTs, not Universal Auth identity
tokens, so capabilities report them unavailable. The older snapshot rollback
route accepts an identity token but is deprecated and always rejects requests;
the server does not advertise a nonfunctional rollback tool.

Infisical v0.160.12 does not expose an atomic version precondition on the v4
update, delete, or batch routes. The server therefore does not perform a racy
read-then-write check or claim compare-and-swap protection. Each mutation is
sent exactly once against the validated target or scope; callers must account
for the possibility of a concurrent change.

## Gateway classifications

The checked-in manifest enumerates the published catalog in its canonical order:
the five local discovery tools and the four executors. Repository tests fail if
an entry is missing, duplicated, reordered, assigned the reserved `medium`
class, or given side-effect, risk, or PII metadata that contradicts the reviewed
rules below.

- local discovery — `server.info`, `server.capabilities`, `operations.list`,
  `operations.describe`, `types.describe`: `risk: low`, `side_effects: false`,
  `pii: false`. They contact nothing and return build metadata, capability
  descriptions, or schemas.
- the four executors — `infisical.read`, `infisical.readAudited`,
  `infisical.write`, `infisical.destroy`: `risk: high`, `pii: true`.
  `side_effects` follows the read-only annotation, so it is false only for
  `infisical.read`.

The executors are classified this way because the gateway authorizes on the tool
name and cannot see which operation a request carries. An executor is therefore
classified for the most sensitive thing it can reach: `infisical.read` serves
both `projects.list` and `secrets.reveal`, so it takes the classification of the
reveal.

That is coarser than the per-operation classification this catalog carried
before the operations moved behind executors. Nothing is under-classified, but a
principal permitted to read is permitted to reveal, and the confinement rule
restricting every Infisical tool to one group is what holds that line rather
than the risk class. Restoring per-operation authorization requires the gateway
to classify on the operation argument, which is tracked in the gateway
repository.

A repository test asserts that no operation is reachable through an executor
classified below it, so an operation added at any tier cannot acquire a weaker
class than the executor serving it.

No tool is classified `medium`, which the gateway reserves against use. Tool
annotations remain descriptive hints; the gateway's Cedar policy is the actual
authorization control.

## Coverage accounting

The checked-in [API coverage matrix](api-coverage.md) maps every documentation
page in the pinned Infisical API snapshot to its owning MCP family and exact
capability. Every non-deprecated endpoint is classified as implemented,
edition-gated, intentionally omitted with a reason, or superseded by a newer
semantic workflow. The generated CSV retains the HTTP method and route for
endpoint-level audit.

CI rejects snapshot count drift; document, method, or route signature drift;
unmapped or multiply mapped active endpoints; non-GET operations assigned to a
read-only capability; unknown capability IDs; disposition/capability-state
mismatches; dirty tagged source checkouts; and hand-edited generated output.
The normal gate reconstructs the documentation subtree from a minimal Git
repository, verifies its version tag resolves to the pinned upstream commit, and
executes the registry serialized by `server.capabilities`. Refreshing the
snapshot therefore cannot silently add or change an upstream endpoint,
capability, or provider family outside the MCP product contract.
