# Operation policy and startup profiles

`INFISICAL_MCP_OPERATION_PROFILE` restricts the operations one server instance
can execute. It applies to stdio, standalone HTTP, and gateway HTTP independently
of the HTTP authentication profile. The default `full` preserves administration
capabilities. Invalid values stop startup without reflecting their contents.

| Profile | Enabled operations |
|---|---|
| `metadata` | Reviewed ordinary and audited reads that do not disclose credential values |
| `secrets` | Reviewed secret, folder, tag, import, dynamic-secret, sync, and rotation operations, plus project and environment discovery |
| `pkiSsh` | Reviewed certificate, certificate-authority, policy, profile, request, code-signing, and SSH operations, plus project and environment discovery |
| `full` | All implemented operations, including identity administration and KMS |

Membership is an explicit registry fact. A new operation is full-administration
only until reviewed; adding a name to an existing family does not grant it to a
restricted profile. `operations.list` and its search and pagination expose only
enabled operations. Describe and execution reject disabled operations before
upstream authentication, including wrong-executor and legacy direct-name calls.
The executor tool catalog remains stable across profiles. `server.capabilities`
reports the active operation profile alongside the compiled capability ledger;
compiled support does not imply enablement in this instance.

A profile restricts service capabilities, not a caller's role. Infisical still
enforces the configured machine identity's permissions. Use separate instances
and upstream machine identities when different users need different authority.
Confirmations and MCP annotations remain intent safeguards and hints, never
authorization. Audited reads and credential disclosure are separate facts: a
read may disclose a credential without being a mutation, while an audited
metadata read still records access upstream.

## Offline gateway contract

Export the exact build's operation policy without credentials or network calls:

```sh
cargo run --locked -p infisical-mcp --example operation_policy > operation-policy.json
```

The export contains its schema revision, closed operation names and executors,
effect flags, possible credential disclosure, confirmation field names, supported
top-level JSON-pointer scope selectors, profile membership, file-transfer
requirements, and exact Rust-derived input and output schemas. The schemas and
operation descriptions explain when confirmations are required; the field list
alone does not turn every conditional confirmation into a mandatory true value.
All executor gateway risk classifications remain conservative.

`executionErrorSchema` describes the shared structured execution-error object.
Hosts inspect `isError` before validating a successful result against an
operation's output schema; a failure carries recovery and effect facts instead.

Effect flags describe the server's conservative execution classes: audited reads
are non-replayed observations, and mutation-class requests are never replayed.
They do not claim that every mutation-class action changes a resource's durable
configuration; cryptographic actions and bulk disclosure also use that class.
Mutation preflights can themselves create audit events. Use explicit profile
membership and credential-disclosure facts as well as effects when constructing
a metadata-only policy; a low-risk label supplied by a caller grants nothing.

A gateway integrating this contract must:

1. Bind the manifest to the deployed build and invalidate cached policy and
   schemas when its revision changes.
2. Validate the closed executor and operation pair, then validate arguments
   against that operation's input schema. Reject unknown fields and names.
3. Resolve the authenticated caller's operation and scope policy using server-owned
   facts. Read only the supported scope selectors; never trust a caller-supplied
   risk label, confirmation, role, or project name as authority.
4. Deny when required scope cannot be proven from supported selectors. Opaque
   resource identifiers or implicit organization scope require an independently
   authorized resolution or a separate appropriately scoped machine identity.
5. Forward only after authorization. Keep file references and complete sensitive
   results inside the governed host runtime and return bounded summaries to the
   model.

The repository's isolated fixtures exercise this contract; they do not install
or change a gateway policy. Deployment policy and rollout belong in the operator's
repository. This server does not add local user roles or execute caller code.

Upstream names, descriptions, comments, and other free text are untrusted data,
even when their JSON is valid. Keep them separate from instructions, bounded,
and projected in host integrations. Do not derive authorization from their text.
Removing instruction-like words is not a prompt-injection defense.
