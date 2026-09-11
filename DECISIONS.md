# Decision record

## Typed REST client instead of CLI execution

The server will call Infisical’s REST API with typed request and response models.
Spawning the CLI would add shell and environment exposure, complicate
cancellation and error typing, and make secret redaction harder to prove. The
CLI remains the preferred mechanism for injecting runtime secrets into existing
repositories.

## Curated resource tools instead of endpoint generation

The Infisical API is broad, with hundreds of provider-specific connection,
sync, and rotation variants. Publishing every route as a tool would overwhelm
search and expose low-level transport details. Stable resource operations plus
`types.describe` provide full coverage while keeping the catalog intelligible.
No arbitrary HTTP proxy or path/body escape hatch will be provided.

## Layered executors instead of one tool per operation

Publishing every typed operation as its own tool produced a catalog of roughly
934 KB. That is charged against a caller's context before its first message and
exceeds the window most clients have, while any single turn uses one or two
operations. Curating which endpoints to implement had already happened; what had
not was deciding what shape the published tools take.

The published surface is now local discovery plus one executor per operation
tier. An executor names an operation and carries that operation's arguments.

This is not an arbitrary request tool. The operation comes from a closed set,
each executor accepts only its own tier's names, and an operation this build does
not serve is rejected before the server authenticates to Infisical, so it
reaches no upstream route. The typed inputs, ownership
preflights, confirmation gates, non-replay guarantees, and redaction boundaries
are the same code they were, reached by name instead of by tool listing. An
operation cannot be called by name directly, because it would then carry none of
the annotations its executor exists to attach.

The cost is borne at the gateway, which authorizes on the tool name and can no
longer see the operation. Each executor is therefore classified for the most
sensitive thing it can reach, which never under-classifies a request but does
mean a principal permitted to read is permitted to reveal. Restoring the finer
line requires the gateway to authorize on an argument.

## Gateway authorization plus server authentication

This boundary applies to the optional gateway HTTP profile. Standalone HTTP
requires a shared connection bearer without the gateway JWT; stdio uses the local
process boundary. Neither standalone mode implements user-policy enforcement.

The tool-search gateway owns user and group authorization. The Infisical server
still requires a separate opaque bearer on every MCP request and verifies the
gateway-signed caller identity. The bearer proves the caller is the gateway;
the signed identity supplies verified request context. It does not by itself
produce a per-user operation audit trail. Neither token is forwarded to Infisical.

## Stateless Streamable HTTP

The server uses the JSON response form of stateless MCP Streamable HTTP. The
gateway must authenticate every request, so an MCP session identifier would be
routing state rather than an authentication mechanism. Stateless operation
avoids retaining caller state in the server, scales across replicas without a
shared session store, and keeps bearer rotation effective on the next request.

## Dedicated upstream Machine Identity

The server receives its own Infisical Universal Auth identity. It does not reuse
the host credential file or another stack’s identity. This creates a revocable,
auditable boundary and permits least-privilege access as the deployed edition
allows.

## Explicit secret reveal

Normal secret reads return metadata only. One high-risk tool reveals one value
at an exact scope. Secret values submitted to mutations are never echoed. This
keeps common agent workflows useful without turning search or broad listings
into bulk exfiltration paths.

## Secret values leave by reference when a transfer plane is configured

A tool result is model context: every inline reveal places the value in the
calling model's conversation permanently. When the operator configures
`INFISICAL_MCP_FILE_PUBLIC_URL`, reveal-class operations default to staging a
short-lived, single-use, in-memory envelope and returning an opaque
`mcp-file://infisical/…` reference that a file-aware gateway resolves
out-of-band. Inline delivery stays available behind the operation's explicit
`delivery: "inlineValue"` argument rather than being removed, because direct
clients without file support still need the governed path. Envelopes are padded
to a fixed-size bucket with a random pad: the bucket makes the size an
intermediary publishes into model context a coarse deterministic figure that
repeated reveals cannot refine, and the pad salts the content digest — an
unsalted SHA-256 of a low-entropy password would be an offline-crackable
oracle. A staging slot is reserved before the upstream operation runs, so a
capacity refusal can never discard a one-time credential the operation already
created. Staged state stays instance-local rather than shared, because
seconds-lived secret envelopes in shared storage would be durable secret state,
a larger exposure than the single-instance routing constraint it would remove.
Without the configured origin, nothing is advertised and nothing changes:
`files/authorizeDownload` answers method-not-found, which a file-aware
intermediary reads as the absence of native file transfer.

The upload direction is deliberately narrow: only `secrets.create` and
`secrets.update` accept a `secretValueFile` reference, because generating a
value locally and writing it is the rotation flow the capability exists for.
The reference is a separate optional field rather than an overload of
`secretValue`, so no legal inline value — including one that happens to look
like a URI — can ever be reinterpreted as a file reference.

## Two private network segments

The gateway-facing segment terminates at the MCP server. A separate
application-only segment reaches the Infisical API. The server must not join the
current Infisical backend network because that network also contains Postgres
and Redis. There is no public route for the MCP server.

## Versioned support target

The initial compatibility target is Infisical `0.160.12`, matching the current
homelab deployment. API coverage is tracked from that tagged documentation
snapshot. Future Infisical upgrades update the capability matrix before the
declared target changes.

The product release pin is separate from API path versions. Resource families
evolve independently inside one Infisical release, so the typed client selects
the canonical Machine-Identity-compatible path per operation rather than
preferring the largest `/api/vN` number. In `0.160.12`, project and environment
administration is current under v1 while the v2 project router is deprecated;
folders and secret imports use v2 and secrets use v4.
