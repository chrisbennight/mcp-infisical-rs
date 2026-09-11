# Repository instructions

This repository owns the Rust implementation and container image for the
Infisical MCP server. Deployment configuration belongs in `docker-home`.

## Architecture boundaries

- `infisical-api` is the only crate that talks to the Infisical REST API.
- `infisical-mcp` owns MCP schemas, tool dispatch, and tool metadata.
- `infisical-server` owns configuration, authentication middleware, HTTP
  transport, health checks, and process lifecycle.
- Do not expose an arbitrary HTTP request tool. Every operation must have a
  typed input, typed output, explicit validation, and a gateway risk class.
- Secret-bearing values must use a type whose `Debug` and `Display`
  implementations redact the value. Never log request or response bodies.
- Mutations must validate all preconditions before their first upstream call.
  Never automatically replay a mutation after an authentication or transport
  failure.

## MCP contract

- Implement MCP Streamable HTTP at `/mcp` with protocol version `2025-11-25`.
- Derive JSON schemas from the Rust types that handlers actually consume and
  return. Return `structuredContent` plus the JSON text compatibility form.
- Give every field a useful description and constraint. Errors must explain
  how the caller can correct the request without disclosing secret material.
- Treat tool annotations as hints, not authorization. Authorization is enforced
  by the gateway and the server authenticates the gateway on every MCP request.
- The gateway bearer and `X-MCP-Identity` JWT are both required on every MCP
  HTTP request. Sessions, source addresses, and network membership never
  replace either credential.
- Keep `/healthz` independent of MCP authentication, concurrency, and upstream
  Infisical availability. Its response must not disclose configuration.
- Add a wire-level test through the Streamable HTTP transport for every tool
  family, in addition to handler tests.

## Required checks

Before a commit or push, run each command and verify its explicit zero exit
status:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --no-deps --locked
python3 scripts/check_docs.py
python3 scripts/check_api_coverage.py
python3 -m unittest discover -s scripts/tests
```

Use isolated in-process HTTP fakes in tests. Tests must never contact the real
Infisical service, gateway, registry, or any shared infrastructure.

## Automated pull-request review

Every pull request is reviewed by the Automated Engineering Review Board
(`AERB`). A merge requires the repository test context and `pr-review/gate` to
be successful on the current head. A missing AERB status is a repository
enrollment failure, never a reason to waive the review.

AERB's repository-managed review and security policy lives under
`.github/pr-review/`. `RECOMMEND REVIEW` remains blocking; only a current-head
`RECOMMEND MERGE` satisfies the review gate.

Request an AERB GitHub review after each pushed PR head. When addressing a
finding, post the reasoning comment before pushing the fix so the next review
sees both.
The pull-request description is immutable after creation; corrections belong in
comments.
