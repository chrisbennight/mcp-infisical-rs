# mcp-infisical-rs

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="docs/branding/assets/wordmark-dark.svg">
  <source media="(max-width: 600px)" srcset="docs/branding/assets/wordmark-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="docs/branding/assets/header-dark.svg">
  <img src="docs/branding/assets/header-light.svg" width="960" alt="mcp-infisical-rs">
</picture>

**Manage Infisical resources from an MCP client.**

List projects, read secret metadata, update secrets, and work with supported
machine identity and certificate operations. This is an independent Rust
implementation, not an official Infisical product. MCP (Model Context Protocol)
lets a client discover and call these operations as tools.

Run it as a local child process over **stdio**, or as a service over **stateless
Streamable HTTP**. A gateway is optional. Every connection uses the authority of
one configured Infisical machine identity; the server has no local user roles
or OAuth authorization service.

**[Get started](#get-started)** · **[Documentation](docs/README.md)** ·
**[Contribute](CONTRIBUTING.md)** ·
**[Get help](https://github.com/chrisbennight/mcp-infisical-rs/issues)**

## What you can do

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/branding/assets/resources-dark.svg">
  <img src="docs/branding/assets/resources-light.svg" width="24" height="24" alt="">
</picture>

**Inspect projects and secrets.** Start with project metadata, then discover the
secret operations available to your client. Reading metadata and revealing a
secret value are separate operations. The [operation reference](docs/tool-surface.md)
describes their inputs and results.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/branding/assets/connections-dark.svg">
  <img src="docs/branding/assets/connections-light.svg" width="24" height="24" alt="">
</picture>

**Connect a local client or a service.** Launch a child process over stdio or
connect over stateless Streamable HTTP. Neither requires a gateway.
[Choose a connection method](docs/standalone.md).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/branding/assets/certificates-dark.svg">
  <img src="docs/branding/assets/certificates-light.svg" width="24" height="24" alt="">
</picture>

**Work with certificates and machine identities.** Check the
[coverage matrix](docs/api-coverage.md) before choosing an operation: support
depends on the API family, Infisical version, and upstream license.

## Get started

You need an Infisical instance, a dedicated machine identity with Universal Auth,
and an MCP client that supports process transport or Streamable HTTP with a
configured bearer credential. Install Git, the pinned [Rust toolchain](rust-toolchain.toml),
and a C compiler, then clone and build:

```sh
git clone https://github.com/chrisbennight/mcp-infisical-rs.git
cd mcp-infisical-rs
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

### Make a first call

After the client initializes the MCP connection and lists tools, call
`infisical.read` with these arguments:

```json
{
  "operation": "projects.list",
  "arguments": { "offset": 0, "limit": 10 }
}
```

Expect `structuredContent.items` containing project metadata visible to the
configured machine identity. An empty list can be valid. This call does not
reveal secret values. Use `operations.list` and `operations.describe` to find
other operations and their required arguments. See
[troubleshooting](docs/standalone.md#troubleshooting) if the call fails.

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

The [documentation guide](docs/README.md) links to client setup, operation
coverage, HTTP configuration, architecture, and optional gateway integration.
Read [Security](SECURITY.md) before connecting real data, and
[Contributing](CONTRIBUTING.md) to build or change the server.

## Support and license

Use [GitHub issues](https://github.com/chrisbennight/mcp-infisical-rs/issues)
for reproducible bugs and scoped feature requests. Include versions, transport,
and a synthetic reproduction; never include credentials or reveal results.
This is maintained on a best-effort basis, without a support or response-time
commitment. Follow the [conduct guidance](CODE_OF_CONDUCT.md).

The server is [MIT licensed](LICENSE). Bundled upstream API documentation retains
its own [copyright and license notice](THIRD_PARTY_NOTICES.md).
