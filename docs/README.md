# Documentation

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="branding/assets/wordmark-dark.svg">
  <img src="branding/assets/wordmark-light.svg" width="560" alt="mcp-infisical-rs">
</picture>

Start with [Standalone connections](standalone.md) to build the server, connect
a client over stdio or HTTP, and make a first project metadata call.

| Task | Guide |
| --- | --- |
| Configure a client and troubleshoot its connection | [Standalone connections](standalone.md) |
| Find an operation and understand its inputs | [Operation reference](tool-surface.md) |
| Check implemented and unavailable API families | [API coverage](api-coverage.md) |
| Configure HTTP authentication, limits, and file transfer | [HTTP configuration](http-configuration.md) |
| Understand credentials and trust boundaries | [Architecture](architecture.md) |
| Add an upstream gateway | [Optional gateway integration](gateway-rollout.md) |
| Restrict startup capabilities and enforce operation policy | [Operation policy](operation-policy.md) |
| Report a vulnerability | [Security](../SECURITY.md) |
| Review dependency and image scan evidence | [Security evidence](security-evidence.md) |
| Change the code or documentation | [Contributing](../CONTRIBUTING.md) |
| Prepare and verify a release | [Releases](releases.md) |
| Use or update the project artwork | [Visual identity](branding/README.md) |

The server uses one configured Infisical machine identity. Infisical enforces
its permissions; an upstream gateway can supply per-user policy. Secret reveal
results can enter model context and client history. Read the
[secret delivery guidance](standalone.md#secret-delivery-and-optional-gateway-integration)
before using those operations.

[Research](research.md) and the [catalog plan](catalog-plan.md) preserve design
background. Use the setup and operation guides above for current behavior.

[Back to the project](../README.md) ·
[Get help](https://github.com/chrisbennight/mcp-infisical-rs/issues)
