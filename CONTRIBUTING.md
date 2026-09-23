# Contributing

Start with a reproducible bug or a small, concrete use case in
[GitHub issues](https://github.com/chrisbennight/mcp-infisical-rs/issues).
For a large design change, agree on its scope in an issue before implementing it.
The repository owner, [chrisbennight](https://github.com/chrisbennight), maintains
the project. Support and review are best effort.

## Development

Install the toolchain in `rust-toolchain.toml`, a C compiler, and Python 3.
Run these commands from the repository root:

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

Tests use isolated HTTP fakes and synthetic credentials. They must not contact
your Infisical instance or gateway. Docker is needed for the additional image
build and hardened-container smoke test in GitHub CI, not for the Rust tests.
Cargo uses crates.io by default; no private registry or gateway is required.

`infisical-api` owns REST requests and redaction; `infisical-mcp` owns schemas,
operation dispatch, and classifications; `infisical-server` owns transports,
configuration, authentication, and lifecycle. Read the
[architecture](docs/architecture.md) and [repository rules](AGENTS.md).

For documentation artwork, follow the [visual identity guide](docs/branding/README.md).
Keep editable sources, generated exports, and font notices together. Branding
tools are only needed when changing those assets.

## Pull requests

Describe the problem, resulting behavior, relevant risks, and actual validation.
Keep the change focused and use ordinary English. Add regression evidence for
changed contracts, including wire-level coverage for a new tool family. Update
the operation reference and API coverage matrix when the public catalog changes.

Never paste secret values into an issue, PR, test log, or screenshot. Synthetic
fixtures should be clearly artificial and must not originate from production.
Check [SECURITY.md](SECURITY.md) before reporting a vulnerability.

CI's `test` check and the maintainer's automated review, `pr-review/gate`, must
both succeed on the current PR head. A missing automated review requires
maintainer attention; it is not a successful review. The current review service
reads `.gitea/pr-review/` even on GitHub, so that directory is retained for
compatibility. Its policy is read from the PR's base commit.

Maintainers record a disposition for each review finding. Correct an existing
PR description through comments so the original intent remains available.
Contributions are submitted under the repository's MIT license.
