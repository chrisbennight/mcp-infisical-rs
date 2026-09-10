# Implementation plan

## Outcome

Build a production-grade Rust MCP server covering the non-deprecated management
surface of the self-hosted Infisical version used by the homelab. The interface
must be useful to an agent, safe for writes, discoverable without flooding tool
search, and deployable only behind the existing MCP gateway.

“Fully featured” means every supported Infisical resource family has a typed MCP
workflow. It does not mean mechanically publishing one tool per REST route. The
target Infisical snapshot contains more than a thousand endpoint documents,
most of them repeated provider-specific variants. Those variants will share
typed generic operations and an on-demand schema-description tool.

## Delivery slices

### 0. Repository automation enrollment

- Create the private Gitea repository and establish `main` without placing
  implementation work directly on it.
- Verify the internal AERB webhook targets
  `http://gitea-pr-review-bot:8080/webhooks/gitea` with pull-request and issue
  comment events and mandatory HMAC validation.
- Add the `AERB` user as a Write collaborator. On a private repository the bot
  otherwise receives `404 Not Found` and cannot publish a verdict.
- Add the `renovate` user as a Write collaborator before relying on the
  checked-in Renovate configuration.
- Protect `main` against direct and force pushes, block outdated branches, and
  require `test / test (pull_request)` plus `pr-review/gate` on the current
  head.
- Open the bootstrap pull request only after verifying the webhook,
  collaborators, and branch-protection rule through the Gitea API.

Acceptance: a bootstrap PR receives both required contexts, and Gitea refuses
merge while either context is missing, pending, or failed.

### 1. Executable transport and security boundary

- Add pinned, registry-verified dependencies for `rmcp`, `axum`, `tokio`,
  `reqwest`, `serde`, `schemars`, tracing, JWT/JWKS validation, secret memory
  wrappers, and constant-time bearer comparison.
- Serve MCP Streamable HTTP at `/mcp` and a minimal `/healthz` endpoint.
- Require the current or previous gateway bearer on every `/mcp` request.
- Verify the gateway-minted `X-MCP-Identity` JWT, including signature, issuer,
  audience `infisical`, expiry, and key rotation through the gateway JWKS.
- Reject invalid present `Origin` headers and unexpected `Host` values. Add
  request size, concurrency, and deadline bounds.
- Implement graceful shutdown and a native `--healthcheck` command.
- Prove the exact wire contract with an in-process Streamable HTTP integration
  test; prove missing, malformed, stale, and wrong-audience credentials fail.

Acceptance: an authenticated gateway identity can initialize and list a small
bootstrap catalog; every other request is rejected before MCP dispatch.

### 2. Typed Infisical client and Universal Auth

- Build the REST client in `infisical-api`; do not base full coverage on the
  current official Rust SDK because it covers only secrets and KMS.
- Implement a dedicated Machine Identity using Universal Auth. Cache access
  tokens until shortly before expiry and coalesce concurrent refreshes.
- On an authentication failure, invalidate the token and retry an idempotent
  read once. Never automatically replay a mutation.
- Centralize API-version selection, pagination, error translation, capability
  detection, timeouts, and response-size limits.
- Use redacting types for all secret values, credentials, private keys, tokens,
  and certificate material. HTTP tracing must omit bodies and authorization
  headers.
- Use an in-process fake Infisical HTTP server for token-expiry, concurrent
  refresh, pagination, error, timeout, and no-mutation-replay tests.

Acceptance: no test or log representation contains credential material, and a
token-refresh race produces one upstream login.

### 3. Read and discovery foundation

- Implement `server.info`, `server.capabilities`, and `types.describe`.
- Add typed read workflows for projects, environments, folders, tags, secret
  metadata and version availability, organizations, memberships, groups,
  identities, roles, audit events, integrations, and feature availability.
- Add bounded pagination to every collection. Default responses are concise;
  callers opt into additional metadata rather than receiving unbounded blobs.
- Generate output schemas from the same Rust types returned by handlers and
  return structured content plus the JSON text compatibility form.

Acceptance: every read tool is deterministic against canned API fixtures,
paginated, classified, documented, and searchable by intent.

### 4. Secret workflows

- Add create, update, delete, batch, and supported import workflows. Report
  version and rollback unavailable while their supported routes require a user
  JWT rather than the dedicated Machine Identity.
- Keep list and metadata tools value-free. Put value retrieval behind the
  explicit high-risk `secrets.reveal` tool; it reveals one precisely identified
  secret per call.
- Never echo a submitted secret from create or update operations. A success
  result contains identifiers, version metadata, and timestamps only.
- Require exact project, environment, path, and secret identity on writes.
  Destructive operations require an explicit confirmation field and use an
  upstream conditional/version precondition wherever Infisical supports one.
- Do not add bulk `.env`, shell-export, or “fetch every secret” conveniences.
  Runtime injection remains the Infisical CLI’s job.

Acceptance: reverting redaction, value-free listing, confirmation, or exact
scope validation makes a contract test fail.

### 5. Administrative and advanced resource families

- Add typed CRUD for projects, environments, folders, tags, memberships,
  groups, roles, identities, authentication methods, and access controls.
- Add dynamic-secret configuration and lease create, renew, and revoke flows.
- Add closed tagged families for app connections, secret syncs, and secret
  rotations. Provider-specific tools share reusable lifecycle shapes while
  `types.describe` exposes each implemented configuration schema on demand;
  unsupported providers remain explicit capabilities rather than accepting
  arbitrary JSON.
- Extend the implemented KMS and certificate-authority lifecycle with typed
  certificate issuance, code-signing, and SSH workflows; keep skipped scanning,
  webhook, integration, and automation families explicitly unavailable.
- Detect unavailable edition features and return an actionable unsupported
  response. Never emulate or bypass a licensed capability.
- For irreversible operations, validate all inputs before the first upstream
  mutation and return the exact affected identifiers.

Acceptance: the generated capability matrix maps every non-deprecated endpoint
family in the pinned API snapshot to a typed tool, a documented omission, or an
edition-gated unsupported result.

### 6. Gateway policy and deployment

- Expand the checked-in reviewed high-risk gateway manifest to the full tool
  catalog, keeping machine checks over names, risk, side-effect, and PII
  classifications so policy cannot drift.
- Add an `infisical-admin` local group to the gateway and assign it explicitly
  to each authorized API key or provision the equivalent membership for
  interactive identities.
- Add both an allow rule for that group and a server-wide confinement rule. The
  confinement rule is required because the gateway baseline otherwise permits
  low-risk read-only tools to every authenticated principal.
- Add an application-only Infisical API network and a separate gateway-facing
  MCP network. The gateway must never join a network containing Infisical’s
  database or Redis.
- Store the Machine Identity credential and gateway bearer in Infisical. Use a
  current/previous bearer overlap for rotation.
- Build a multi-stage, digest-pinned image with a distroless non-root runtime,
  read-only root filesystem, no capabilities, no-new-privileges, bounded
  resources, and no host port or Traefik route.
- Register the stack with Komodo before enabling deployment automation, then
  use the generated stack identifier in the deploy workflow.

Acceptance: compose and policy tests prove the network boundary, secret
references, group confinement, healthcheck, and hardened runtime settings.

### 7. Release gate and operations

- Add handler, wire, policy, compose, and documentation contract tests.
- Run mutation testing for touched security and dispatch modules; surviving
  mutants block release or receive an explicit equivalent/unreachable review.
- Add redaction canaries to test logs and MCP errors. Scan the built image and
  dependency graph through established homelab gates.
- Document bearer rotation, Machine Identity rotation, incident revocation,
  capability drift after an Infisical upgrade, and rollback.
- Load-test bounded pagination and concurrency against a local fake only.

Acceptance: CI is green, the server remains unreachable outside its private
network, and a canary secret is absent from logs, errors, and non-reveal tools.

## Order and review boundaries

Each delivery slice should be a reviewable pull request. The first three slices
establish the security boundary and read path before any mutation exists. Secret
writes land before the broader administrative surface so their no-echo and
no-replay contracts become reusable invariants. `docker-home` changes are held
until the application image and gateway manifest exist.
