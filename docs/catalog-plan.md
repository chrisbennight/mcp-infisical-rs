# Published catalog plan

This document records the historical catalog redesign and its measurements.
For current operation and capability counts, use the
[generated catalog summary](generated-catalog.md). The sizes below are serialized
JSON bytes; token usage requires the actual client's presentation and tokenizer.

## Problem

The server published one tool per implemented endpoint: 217 tools covering 223
upstream operations, serializing to roughly 934 KB. Loading that entire payload
made unrelated schemas part of discovery before the caller selected a task.

Composition of that payload:

| Component | Share |
| --- | --- |
| Output schemas | ~525 KB, about half of it repeated across tools in the same family |
| Input schemas | ~275 KB |
| Descriptions | ~25 KB |

The per-tool engineering was not the problem. Every tool carried a typed input,
a typed output, field-level constraints, and complete annotations. The problem
was that the catalog was assembled bottom-up from endpoints, so an agent
resolving `secrets.reveal` still carried every code-signing, SSH
certificate-authority, and KMS schema in context.

[DECISIONS.md](../DECISIONS.md) already recorded the intent to avoid this:
curation was applied when selecting which endpoints to implement, not when
deciding what shape the published tools take. The capability registry returned
by `server.capabilities` was evidence of the intended granularity — it describes
the historical surface with roughly 155 capabilities using consolidated `.read` verbs, one
layer above the tools that shattered those capabilities back into endpoints.

The redesign produced nine tools serializing to roughly 23 KB, against a
checked ceiling of 24,000 bytes. The phases below record that design and its
proposed follow-on work; they are not a current delivery-status ledger.

## Direction

A layered surface: discovery tools plus a small set of executors keyed on a
closed set of operation names, with per-operation schemas fetched on demand. The
typed layer is not removed. It stopped being published as 217 tool schemas and
became reachable through names dispatch already keys on.

This preserves every property the current design exists to provide. There is no
arbitrary HTTP method, URL, or body; an operation outside the served registry is
rejected before the server authenticates to Infisical; and every ownership
preflight, confirmation
gate, non-replay guarantee, and redaction boundary executes unchanged.

## Invariants

These hold at the end of every phase, not only the last.

- Secret values cross the MCP boundary only through `secrets.reveal`, the
  enumerated one-time creation outputs, and the enumerated confirmed reveals.
- Every published tool carries exactly one reviewed gateway classification, in
  catalog order, with `side_effects` bound to the read-only annotation. Because
  the gateway sees the executor rather than the operation, each executor is
  classified for the most sensitive thing it can reach.
- The operation identifier is drawn from a closed set. No arbitrary HTTP request
  reaches the upstream client, and an operation this build does not serve is
  rejected before the server authenticates to Infisical.
- Irreversible operations validate every input before the first upstream call
  and are never replayed.
- The catalog is static per session. Publishing a changing tool list, or
  injecting live data into server instructions, invalidates client prompt-prefix
  caches and is not done.

## Phases

Each phase is one reviewable pull request.

### 0. Measurement gates

Add executable checks over the real `tools/list` payload: a serialized ceiling
that ratchets down as the surface shrinks, and a gate binding the documented
catalog in [the tool surface](tool-surface.md) to the published catalog. That
tool list was previously hand-maintained with nothing validating it, and every
later phase renames tools.

### 1. Response-size guards

Bound what tool *results* cost, not only what schemas cost. A breach returns an
error naming the parameter that narrows the request, rather than a truncated
listing that reads as complete. Destructive operations return an affected-identifier
receipt instead of a full resource projection.

### 2. Operation tiers

An audited read and an ordinary write publish identical annotations, because an
audited read records the access upstream and so is no more replayable than a
write. The MCP hints cannot separate them, so the distinction is declared where
each tool is defined — read, audited read, write, destroy — and the published
annotations are derived from that declaration.

The tier is what later phases act on. Once operations are reached through
executors rather than by name, intent can no longer be recovered from a tool's
name, which is how it is currently inferred.

Reveal is deliberately not a tier. Secret egress cuts across the read and write
axis — one reveal is an idempotent read, another is a recorded mutation — so it
stays a risk classification in the gateway manifest rather than an annotation
tier that would have to span both.

This phase is classification-neutral: the published catalog is byte-identical.

### 3. Layered surface — done

Nine tools are published: the five local discovery tools and one executor per
operation tier. An executor takes an operation name and that operation's
arguments, checks both that the operation is served and that it belongs to the
executor's tier, and routes into the existing dispatch tree. Operation names
and purposes are now discovered through `operations.list`; detailed schemas
come from `operations.describe`. This leaves room for typed deployment
capabilities within the unchanged catalog budget. Unknown and cross-tier calls
are rejected by dispatch before upstream access.
Only a published tool is reachable, so an operation cannot be called by
name to bypass the annotations its executor carries.

The serialized catalog falls from roughly 934 KB to about 19 KB, before the
descriptions in phase 6 bring it to roughly 23 KB.

Secret-revealing operations are reached through the executor matching their own
tier. They keep their existing high-risk gateway classification, which is what
confines them, rather than being grouped into an executor of their own.

Because the envelope adds a deserialization step, the ownership transfer that
keeps secret deserializers from leaving plaintext duplicates in the request map
must be preserved and proven by redaction canaries through the executor path.

### 4. Hot-path promotion

Restore first-class published tools, with client-validated schemas and
single-turn latency, for the operations that measurably carry traffic. A
promoted tool and its executor path route into one handler so they cannot
diverge. Selection is driven by recorded usage; promoting the wrong set is worse
than promoting none.

### 5. Workflow tools

The layered surface reduces initial schema bytes and selection difficulty but not
chaining. Workflows that today require an operator to sequence several calls get
a single tool that orchestrates them server-side, bypassing no preflight and
occupying one risk tier. Where a workflow performs several upstream mutations,
its partial-failure semantics are stated in the description and returned in the
result.

### 6. Descriptions, errors, and documentation

With a small published surface, description quality has room to matter. Repo
vocabulary moves into the server instructions once instead of being restated per
tool. Corrective errors name what to do instead — the executor that serves an
operation, or the discovery call that lists the names — without reproducing the
caller's arguments, which can carry a secret value. Every documentation surface
is swept for the rename.

## Sequencing

Phases 0, 1, and 2 are independent of each other and of the layered surface.
Phase 3 depends on 0 and 2. Phase 4 depends on 3 and on usage recorded from
running it. Phase 6 depends on 3. Phase 5 depends only on identifying the
workflows that are actually run.

Phases 1 and 2 are worth shipping whether or not the layered surface is adopted.

## Withdrawn

A selection-and-completion baseline was planned: a corpus of operator requests
paired with the operation that answers each, and a runner scoring which one a
model picks. It was withdrawn.

The measurement it offered did not justify what it cost this repository. A
corpus of natural-language prompts is instruction-shaped content committed
beside a secrets server, read by an automated reviewer on every pass, and
needing maintenance on every rename — for an artifact that shipped no capability
and never contacted Infisical. Judging the surface change is better done against
recorded gateway usage, which is real traffic rather than requests written by
the same author as the code.

## Related

Splitting the surface into independently mountable per-domain servers is tracked
separately; it addresses operator separation rather than catalog size, and the
two are complementary.
