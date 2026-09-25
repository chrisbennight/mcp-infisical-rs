# Typed host client

This private source package lets an authenticated Node.js host compose Infisical
MCP operations without placing complete results in model context. It does not add
an interpreter, credentials, network transport, or authorization policy to the
server. Nothing in this package is published to npm.

Build from this repository with Node.js 22 or later, Python 3, and the repository's
Rust toolchain. Run `npm ci --ignore-scripts` and `npm test` in this directory.
The build generates its types and manifest from the offline Rust export before
compiling TypeScript. Generated files are ignored by Git; run `npm run build`
before using editor type information. The locked TypeScript compiler is a
development dependency; the compiled client has no runtime package dependencies.

Pass `HostClient.connect` an already-authenticated MCP SDK connection implementing
`Transport` and a JSON Schema 2020-12 validation callback. The callback must check
the supplied schema against the supplied value, returning true only on success.
It must not log values or include them in diagnostics. The host chooses its
validator; this package does not implement a partial schema validator.

Connection checks the live schema revision and deployment profile. These checks
are compatibility guidance, not authorization or an upstream permission probe.
Infisical and the configured gateway still enforce their own authority. A server
restart or configuration change can invalidate a previously observed capability.

```typescript
const client = await HostClient.connect(authenticatedTransport, validateSchema);
const result = await client.invoke('projects.list', { limit: 20 });
if (result.kind === 'success') {
  // Explicit host access: select only fields appropriate for the intended recipient.
  const names = result.value.read().items.map(project => project.name);
}
```

`HostValue` keeps its payload in a private field and redacts JSON serialization,
string conversion, and Node inspection. Calling `read()` deliberately exposes the
complete value inside the host. This is an accidental-disclosure safeguard, not a
sandbox or a claim that JavaScript memory can be securely erased. Do not log the
returned value or pass it wholesale to a model.

Inputs are checked before transport; successful outputs are checked before typed
access. Tool execution errors are validated separately and returned as
`{ kind: 'error', error: HostValue<ExecutionError> }`. Transport and malformed
response failures throw fixed messages without reflecting payloads. The client
preserves transport cancellation as an `AbortError` with safe reconciliation
guidance. It never retries. In particular, a lost response does not prove that a
mutation did not happen; reconcile its outcome before deciding whether another
call is safe.

`invoke` requests an inline whole result. Operation-level secret delivery still
follows the operation's `delivery` argument and server configuration; requesting
inline whole-result delivery does not implicitly reveal a secret value.
`invokeFile` returns a wrapped file reference with a different TypeScript result
type. Resolve that reference through the host's governed file-transfer adapter;
this client never fetches an arbitrary URL or silently falls back to inline data.
File references remain instance-local and short-lived. A consumed download is an
attempt, not an acknowledgement of receipt.

The [inventory example](src/inventory.ts) pages in the host, bounds the number of
calls, filters projects, joins selected environment pages, and returns only
identifiers, names, and environment slugs. It explicitly marks an incomplete result.
Pagination over mutable upstream data is not a stable snapshot.

Every package build regenerates after Rust contract changes. To generate or
check the local generated files separately:

```sh
python3 scripts/generate_host_client.py
python3 scripts/generate_host_client.py --check
```

Run these commands from the repository root. They execute the offline Rust policy
export; they do not contact Infisical. Generated argument/result types and the
manifest come from the same Rust schemas consumed by handlers. TypeScript types
cannot enforce numeric bounds, string patterns, exclusive unions, or JavaScript
number precision; the host validator remains mandatory. Unsupported schema
constructs fail generation instead of silently becoming `any`.
