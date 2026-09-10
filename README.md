# mcp-infisical-rs

A fully featured, self-hosted Infisical MCP server written in Rust. It is
designed to run behind the homelab MCP tool-search gateway and to expose typed,
policy-classified operations rather than an arbitrary REST proxy.

The current implementation establishes the executable transport and ingress
security boundary. It serves stateless MCP Streamable HTTP at `/mcp`, exposes a
minimal `/healthz`, accepts current/previous gateway bearers for rotation, and
verifies the gateway's Ed25519 caller identity through a bounded JWKS client.
The `infisical-api` crate now provides the bounded Universal Auth REST client
and typed administration for projects, embedded environments, folders, tags,
machine identities, project user and identity memberships, Universal Auth,
Token Auth, Kubernetes Auth, project and organization role discovery, group and
project group-membership discovery, identity project additional privileges,
bounded audit-log listing, secret metadata, secret-import mappings, and
value-free app-connection, secret-sync, secret-rotation, dynamic-secret
configuration, lease discovery, KMS key and cryptographic operations,
certificate-authority inventory and internal lifecycle administration, and SSH
Access certificate-authority, certificate-template, host, and host-group
administration.
App-automation inventory validates the
pinned provider unions and linked project, connection, environment, and folder
coordinates, including exact environment metadata from the requested project's
catalog, while dropping credential hashes, provider configuration, secret
mappings, generated credentials, and status messages. Typed GitHub
app-connection administration supports GitHub App, OAuth, and personal-access
token credentials for GitHub Cloud, Enterprise Cloud, and Enterprise Server
without echoing them. Replacing a stored connection credential requires
explicit acknowledgement and preserves the existing authentication method.
Rotating the stored credential is a separate confirmed, bodyless action that is
sent exactly once and returns only value-free connection metadata.
Typed GitHub secret-sync administration supports organization, repository, and
repository-environment destinations, confirmed destination overwrite,
lifecycle changes, manual sync, and remote secret removal. GitHub import
remains unavailable under the pinned provider contract. Dynamic-secret rename,
complete lifetime-policy replacement, confirmed configuration deletion, lease
renewal, and confirmed lease revocation are also typed mutations. The
SQL-database provider additionally supports typed configuration creation and
one-time credential lease creation. Provider-input replacement remains
unavailable because the pinned API cannot bind the name-addressed mutation to
an observed configuration ID or version. It also provides exact-scope
shared-secret reveal, create, update, confirmed delete, and bounded batch
create/update/delete workflows.
The tool and capability catalog includes confirmed project and
environment soft deletion, folder create/update/batch-update/delete, tag
create/update/delete, built-in-role machine-identity administration, Universal
Auth and Token Auth configuration and credential lifecycles, direct Kubernetes
API authentication administration, sanitized project-membership reads,
invitation and identity assignment, confirmed complete role replacement,
confirmed access removal, stable slug-based role and permission reads, typed
group member and project assignment reads, and value-free secret-import mapping
administration. It also provides the complete v2 identity project
additional-privilege lifecycle, including bounded permanent and scheduled
temporary grants, scope-validated reads, confirmed inverted deny creation,
confirmed permission replacement, and confirmed deletion.
The shared SQL credential-rotation lifecycle is typed for PostgreSQL, MySQL,
Microsoft SQL Server, and Oracle Database, including exact reads, confirmed
create/update/delete/move/rotate/check actions, and explicit generated-credential
reveal. Other rotation providers, including AWS IAM, remain unavailable.
The KMS surface implements all fifteen pinned Machine-Identity-compatible key
lifecycle, encryption, signing, verification, and private-material routes.
Every operation uses closed algorithm and signing enums, exact project/key
ownership checks, bounded canonical base64, explicit confirmation for writes or
reveals, and the non-replaying path used for audited reads and mutations. Sign
and verify enforce the observed key family plus exact digest-mode rules before
dispatch, while bulk import caps aggregate decoded material at 512 KiB.
Imported material remains bound to the algorithm used for validation, and
per-key upstream rejection text is discarded in favor of a fixed local error.
Key reads require an explicit upstream disabled-state field, while signing
algorithm discovery must return exactly the algorithms valid for the observed
key family.
Post-quantum key variants remain typed, while Infisical enforces its `kmsPqc`
plan entitlement.
The certificate-authority surface lists value-free metadata for every pinned
provider family and provides exact internal-CA list, get, confirmed create,
update, delete, CSR, certificate history and retrieval, generation, renewal,
intermediate signing, certificate import, and CRL operations. General inventory discards complete provider
configuration, while internal projections omit encrypted private keys. Root and
intermediate creation use closed subject, hierarchy, key-algorithm, validity,
path-length, and CRL-distribution contracts; SLH-DSA creation is unavailable
because the pinned service rejects it. Certificate operations validate bounded
PEM, identifiers, serials, timestamps, and hierarchy before audited reads or
confirmed one-shot mutations. External-provider administration, signing
configuration, auto-renewal configuration, and the public DER route remain
explicit unavailable capabilities.
Certificate-policy discovery returns typed subject, SAN, usage, algorithm,
validity, and basic-constraint rules. Confirmed creation, update, and deletion
validate their inputs before mutation; update and deletion also prove exact
Certificate Manager project ownership first.
Certificate profiles cover the pinned API, EST, ACME, and SCEP lifecycle,
including bounded list/get, confirmed create/update/delete, issued-certificate
listing, and confirmed latest-bundle and ACME EAB reveals. Profile and policy
ownership are validated explicitly; ordinary outputs discard EST passphrases,
while private keys and EAB secrets cross only their named reveal boundaries.
Azure AD CS templates are accepted only for profiles backed by an Azure AD CS
CA, and every EST bootstrap-chain certificate must be a CA with `keyCertSign`.
Latest-bundle reveals additionally require a matching leaf key, serial, and
cryptographically linked issuer chain whose certificates are currently valid.
Enrollment-family switching is intentionally rejected because the pinned PATCH
service cannot create the newly selected family’s configuration row.
Certificate issuance accepts either typed managed-key attributes or a signed
PKCS #10 request through an API-enrolled profile. The confirmed mutation is sent
once after exact profile ownership preflight and returns either a pending
request reference or validated immediate certificate material. An immediately
generated private key uses the same governed out-of-context delivery boundary
as other reveal-class outputs.
Certificate lifecycle operations renew an eligible managed-key end-entity
certificate, revoke an active end-entity certificate with an RFC 5280 reason,
set or disable automatic renewal, and delete one exact end-entity certificate
record. Each operation proves project ownership and relevant state before its
one-shot mutation. Renewed private keys use the governed delivery boundary;
renewal results are checked for current X.509 validity and reconciled to the
source profile and certificate authority. Revocation and deletion require
explicit confirmation.
Certificate material transfer imports a validated leaf plus optional matching
private key and issuer chain from governed uploads, and reconciles the created
inventory record after the single mutation. Public certificate retrieval stays
inline. Confirmed bundle and private-key retrieval use governed reference
delivery by default and cryptographically bind returned keys to the selected
leaf.
SSH Access administration adds bounded CA inventory, exact CA and public-key
reads, confirmed internal or external-key creation, complete lifecycle
replacement, and confirmed deletion. Imported private keys enter a zeroizing
redacted value after structural parsing and public/private algorithm agreement;
exact RSA sizes and NIST curves are enforced locally. Private key material is
sent only to the pinned create route and never appears in MCP output.
Certificate-template list/get/create/replace/delete operations use a closed
policy with canonical durations, bounded unique user and host patterns, and
explicit user-, host-, and custom-key-ID controls. Every response is rebound to
the requested SSH project and CA. Certificate signing accepts one existing
bounded OpenSSH public key; issuance generates one supported key pair and
reveals its private half only after explicit confirmation. Both workflows
preflight the exact template policy, mutate once without replay, and verify the
returned certificate trust and requested semantics. Issuance also proves the
private/public key pair before reveal. Certificate verification rejects all
critical options, requires the exact OpenSSH default user-extension set or no
host extensions, and prevents past-only ssh-keygen backdating from extending
the requested usable lifetime after receipt. SSH host and host-group
administration adds bounded canonical inventory, exact reads, complete
confirmed create/replace/delete policy, verified linked-CA public keys, bounded
direct and inherited login mappings, reflected membership changes, and
non-replayed host-certificate issuance. Host creation requires explicit active
user and host CAs; JWT-only global inventory and user-certificate issuance
remain explicitly unavailable.
Code-signer operations add bounded list/get, confirmed create/update/delete and
status transitions, internal-CA certificate reissue, validated certificate and
certificate-bound public-key export, and non-replayed RSA/ECDSA signing.
Creation preflights the Certificate Manager project plus the existing
certificate or internal CA. Signing data is canonical base64, capped at 128
decoded bytes, and wrapped in a redacting value that zeroizes on drop. Decoded
bytes and the re-encoded canonicality-check buffer also zeroize, and the data
is never returned. Signer governance adds typed direct and effective membership,
effective-permission, complete approval-policy replacement, finite approval
request, administrator pre-approval/revocation, and sanitized operation-history
workflows. Every governance mutation confirms before authentication, validates
the current signer and relevant membership or policy state, and binds the
response to the requested project and signer. External-CA signer issuance
remains an explicit follow-on capability rather than accepting arbitrary
provider payloads.
It also lists organization-wide or project-scoped audit events through bounded
server-side filters while omitting arbitrary actor and event metadata. Because
Infisical records first-page audit-log views, that read is explicitly advertised
as observable and non-idempotent.
Dynamic-secret configuration and lease GETs are likewise observable audit
events and are never retried. Their outputs omit provider inputs, arbitrary
metadata, lease configuration, and status details. Provider-neutral updates
replace one coherent name or lifetime policy, while confirmed deletion makes
ordinary provider cleanup distinct from forced Infisical-only removal.
SQL-database writes accept a closed tagged contract, restrict statement
templates to the pinned provider placeholders, and create configurations and
leases through typed mutations. Provider-input replacement and other provider
families remain explicitly unavailable; no free-form JSON passthrough exists.
Schema-derived outputs keep ordinary metadata and mutation results value-free.
Secret values cross the MCP boundary only through explicit `secrets.reveal`;
the one-time results of `identityUniversalAuth.clientSecrets.create`,
`identityTokenAuth.tokens.create`, `dynamicSecretLeases.create`, and
`sshCertificates.issue`; the managed-key results of `certificates.issue` and
`certificates.renew`; and the confirmed
`secretRotations.sql.generatedCredentials.get`, `kms.decrypt`,
`kms.keys.privateKey.reveal`, `kms.keys.privateKeys.bulkReveal`,
`certificates.bundle.reveal`, `certificates.privateKey.reveal`,
`certificateProfiles.latestActiveBundle.reveal`, and
`certificateProfiles.acmeEabSecret.reveal` operations.
When the reveal transfer plane is configured, those same operations default to
returning an opaque `mcp-file://infisical/…` reference instead of the value: the
gateway resolves the reference through `files/authorizeDownload` and streams a
short-lived, single-use JSON envelope from this server's download route, so the
value reaches the caller's host without entering model context. Every
`files/authorizeDownload` result carries `"sensitivity": "secret"`, an
extension member a retention-aware gateway uses to keep its own copy of the
envelope on a short window; an intermediary that does not understand it
ignores an unknown member. An inline value
then requires the operation's explicit `delivery: "inlineValue"` argument, and
deployments without the plane keep the inline behavior unchanged.
Implementation sequencing and acceptance criteria are in [PLAN.md](PLAN.md).

## Design at a glance

```text
MCP client
    |
    v
tool-search gateway -- shared bearer + signed caller identity --> mcp-infisical-rs
                                                                  |
                                                       Universal Auth identity
                                                                  |
                                                                  v
                                                         Infisical REST API
```

The server publishes nine tools: five local discovery tools and one executor per
operation tier. The typed operations are reached through the executor serving
their tier rather than listed individually, because publishing all of them came
to roughly 934 KB of schema against a caller's context. `operations.list` returns
the operation names and `operations.describe` returns one operation's schemas on
demand.

The gateway is the authorization boundary. Every Infisical tool is confined to
the local `infisical-admin` group. That confinement is load-bearing rather than a
backstop: the gateway authorizes on the tool name and an executor carries every
operation of its tier, so it cannot distinguish a project listing from a secret
reveal. The server independently authenticates the
gateway on every `/mcp` request and verifies the gateway-minted caller identity.
Infisical receives a dedicated, least-privilege Machine Identity; its credential
is distinct from the gateway bearer.

See [the architecture](docs/architecture.md), [tool surface](docs/tool-surface.md),
[API coverage matrix](docs/api-coverage.md),
[gateway rollout](docs/gateway-rollout.md), and [research notes](docs/research.md)
for the decisions behind the plan.

## Workspace

- `infisical-api`: typed REST client, Universal Auth upstream login, safe
  idempotent-read retry, single-attempt observable reads and mutations,
  validated resource coordinates, bounded collection pages and responses,
  authentication-method administration, and redaction
- `infisical-mcp`: MCP schemas, catalog, handlers, and classifications
- `infisical-server`: Streamable HTTP process and security middleware

The pinned Rust toolchain and Nexus cargo proxy follow the homelab repository
conventions. CI runs formatting, Clippy, tests, documentation, the local-link
gate, and deterministic validation of the pinned endpoint coverage matrix.

## Container image

Merges to `main` publish
`gitea.cacahuate.org/bennight/mcp-infisical-rs:sha-<commit>` and the rolling
`:latest` deployment tag only after the complete repository gate passes. The
multi-stage image uses digest-pinned builder and distroless runtime bases,
runs as the distroless non-root user, and includes the binary's native
`--healthcheck`. Pull requests build and start the image with a read-only root
filesystem, no Linux capabilities, and `no-new-privileges` inside the required
test job. After the immutable push succeeds, the publication workflow sends
the full source commit and registry-reported digest to docker-home's allowlisted
image-update workflow. Docker-home then advances its immutable locks through a
normal CI- and review-gated pull request before its existing deployment
workflow touches the live stack.

## Ingress configuration

All `/mcp` requests require both `Authorization: Bearer …` and
`X-MCP-Identity: …`. The bearer must contain at least 32 bytes and the identity
JWT must use EdDSA with a known `kid`, the configured issuer, audience
`infisical` (fixed by the server), and valid temporal claims. A fresh unknown
`kid` triggers a single-flight JWKS refresh limited to once every five seconds.
JWKS redirects and ambient proxies are disabled. Remote cleartext URLs are
rejected unless `INFISICAL_MCP_IDENTITY_ALLOW_PRIVATE_HTTP=true` explicitly
enables the same DNS-pinned private-authority policy used by the Infisical API
client. A present browser `Origin` is rejected unless it is explicitly
configured; `Host` is always matched against exact authorities.

See [.env.example](.env.example) for the complete settings. In particular,
production must replace the development host allowlist with the private Docker
service authority and set a cryptographically random 256-bit bearer. The
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

### Reveal transfer plane

Setting `INFISICAL_MCP_FILE_PUBLIC_URL` to the origin the gateway dials — the
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
minted it, so run a single replica (the deployed topology) or pin download
routing to the staging instance. Enable the plane only behind a gateway whose
file storage is enabled; otherwise callers receive references nothing can
resolve.

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --no-deps --locked
python3 scripts/check_docs.py
python3 scripts/check_api_coverage.py
python3 scripts/check_release.py
python3 -m unittest discover -s scripts/tests
```
