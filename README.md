# mcp-infisical-rs

An MCP server for Infisical, written in Rust. It lets MCP clients discover and
call typed operations for secrets, projects, machine identities, certificates,
and other supported Infisical resources. It is an independent project, not an
official Infisical product.

Run it as a local child process over **stdio**, or as a service over **stateless
Streamable HTTP**. A gateway is optional. Every connection uses the authority of
one configured Infisical machine identity; the server has no local user roles
or OAuth authorization service.

## Get started

You need an Infisical instance, a dedicated machine identity with Universal Auth,
and an MCP client that supports process transport or Streamable HTTP with a
configured bearer credential. Install the pinned [Rust toolchain](rust-toolchain.toml)
and a C compiler, then build from this checkout:

```sh
cargo build --release --locked -p infisical-server
```

Supply `INFISICAL_API_URL`, `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`, and
`INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` through your credential manager or
client's process environment. The program does not automatically load `.env`.

For a client that launches a process:

```json
{
  "command": "/absolute/path/to/target/release/mcp-infisical-rs",
  "args": ["--transport", "stdio"]
}
```

For HTTP, also supply a random `INFISICAL_MCP_BEARER_CURRENT` of at least 32 bytes:

```sh
target/release/mcp-infisical-rs --http-profile standalone
```

This listens at `http://127.0.0.1:8000/mcp`. Configure the client's bearer header
for every request. Read [Standalone connections](docs/standalone.md) for a first
metadata call, transport settings, rotation, and troubleshooting.

## What to expect

- Discovery tools describe the operation catalog. Calls go through typed
  executors such as `infisical.read`; operation names are not separate MCP tools.
- Infisical enforces the machine identity's permissions. A shared bearer does
  not distinguish users. Put per-user authorization in an upstream gateway.
- Explicit reveal operations return secret values inline unless the optional
  HTTP file-transfer extension is enabled. Inline results can enter model context
  and client history. Confirmation fields are intent checks, not authorization.
- Mutations are not automatically replayed. After an uncertain result, check
  upstream state before retrying.
- The protocol target is MCP `2025-11-25`. API coverage is audited against
  Infisical `v0.160.12`; this is not a compatibility claim for every API version,
  edition, or license. See the [coverage matrix](docs/api-coverage.md).
- CI exercises Linux x86-64 source builds and a hardened Linux/amd64 container.
  Other platforms and named desktop clients have not been qualified. No public
  binary or image release is advertised yet.

`certificates.import` currently requires the optional HTTP file-transfer
extension and cannot run over stdio. The shared catalog still lists it.

## Documentation

- [Standalone connections and Quickstart](docs/standalone.md)
- [HTTP configuration and file transfer](docs/http-configuration.md)
- [Operation reference](docs/tool-surface.md)
- [Architecture and trust boundaries](docs/architecture.md)
- [Optional gateway integration](docs/gateway-rollout.md)
- [Security and vulnerability reporting](SECURITY.md)
- [Contributing and validation](CONTRIBUTING.md)

## Support and license

Use [GitHub issues](https://github.com/chrisbennight/mcp-infisical-rs/issues)
for reproducible bugs and scoped feature requests. Include versions, transport,
and a synthetic reproduction; never include credentials or reveal results.
This is maintained on a best-effort basis, without a support or response-time
commitment. Follow the [conduct guidance](CODE_OF_CONDUCT.md).

The server is [MIT licensed](LICENSE). Bundled upstream API documentation retains
its own [copyright and license notice](THIRD_PARTY_NOTICES.md).
