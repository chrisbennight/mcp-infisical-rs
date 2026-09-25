# Releases

The release workflow prepares a Linux/amd64 OCI image for
`ghcr.io/chrisbennight/mcp-infisical-rs` and a checksummed, attested Linux x86_64
native archive in the release metadata artifact. It does not deploy a service
or update a rolling `latest` tag. Other platforms have not been qualified.

## Compiler and client qualification

The digest-pinned Rust 1.96.1 builder supplies the bootstrap toolchain and Debian
12 libraries. After copying the source, rustup deliberately installs the compiler
selected by `rust-toolchain.toml` (currently 1.98.1). The build asserts that exact
effective version and records `rustc --version --verbose` in the runtime image.
The workspace's Rust 1.96 declaration is a minimum-version declaration, not a
claim that this workflow tests that older compiler. Dependency changes still
require validation with the selected compiler.

CI and publication extract the exact executable from their built image and run
the repository's isolated stdio and Streamable HTTP client fixtures against it.
These exercise initialization, discovery, argument schemas, malformed calls,
metadata reads, delivery capability reporting, and refusal of unavailable file
delivery. They use local fakes, never a real Infisical service. The resulting
record includes the immutable image ID, compiler, runner kernel and libc, and
test exit status. No named desktop application is qualified by these fixtures.

| Artifact or client | Qualification boundary |
|---|---|
| Linux/amd64 OCI image | Debian 12 runtime, hardened container smoke test, exact executable protocol tests |
| Linux x86_64 native archive | Same dynamically linked executable, tested on the recorded Linux runner; requires compatible glibc and runtime libraries |
| Repository stdio JSON-RPC and reqwest HTTP fixtures | MCP 2025-11-25, isolated initialization, discovery, schemas, reads, and delivery checks |
| macOS, Windows, ARM64, named desktop clients | Not qualified or advertised as supported |

Download the completed release's `release-metadata-*` Actions artifact to obtain
the native archive, checksums, compiler record, and qualification evidence. Verify
the checksums and GitHub attestation before extracting the archive:

```sh
gh attestation verify mcp-infisical-rs-linux-x86_64.tar.gz \
  --repo chrisbennight/mcp-infisical-rs
```

Native archives share the metadata artifact's 90-day retention. Archive them
with release notes for longer distribution. Source builds remain available.

## Before the first public release

The [forge evidence snapshot](release-controls.json) records the observed
settings on 25 September 2026: public repository, strict current-head `test` and
`pr-review/gate` checks with administrator enforcement, protected version tags
without bypass actors, enabled private vulnerability reporting, and publication
opt-in. This dated observation is not continuous verification. Package visibility
was not verified: the connected service lacks the user credential required by
the Packages API. Check package visibility before announcing a release; the
repository's public visibility does not prove the package is public.

The maintainer must verify repository and version-tag protection, private
vulnerability reporting, and the reviewed publication candidate. Main must
require the current-head `test` and `pr-review/gate` checks. Protect version tags
against deletion and replacement. Repository visibility and package visibility
are separate settings; verify both deliberately.

Publication is disabled unless the repository is public and its Actions variable
`ENABLE_RELEASE_PUBLICATION` is exactly `true`. Keeping that variable absent
allows the preparation work to be merged without publishing an image. No release
has been qualified merely by adding this workflow.

## Publish a version

1. Update the workspace version and lockfile through a reviewed PR. Run the
   [contributor checks](../CONTRIBUTING.md), including the container smoke test
   in CI, and merge after both required checks succeed.
2. Create a new `vMAJOR.MINOR.PATCH` tag on that reviewed main commit. The tag
   must match the workspace version. Pre-release suffixes are not supported by
   this workflow. Never move an existing release tag.
3. The release workflow reruns the full validation workflow. Publication then
   verifies the tag, event commit, main ancestry, and declared dependency
   licenses before obtaining the registry credential.
4. It rebuilds the validated Dockerfile for Linux/amd64 under a unique candidate
   tag with build provenance. It scans that candidate by digest and produces a
   runtime SBOM. It then qualifies the exact executable and prepares the native
   archive. After both gates pass, it assigns version and full-commit
   tags to that same digest without rebuilding, verifies both tags, and attaches
   a GitHub-signed image attestation. The registry digest identifies the immutable
   artifact; tags are convenient references, not an immutability guarantee.
5. Review the completed run, its image attestation, and the `release-metadata-*`
   artifact before announcing availability. Archive that metadata with the
   release notes before its 90-day Actions retention expires.

The publication job has repository-read, package-write, OIDC, and attestation
permissions. It uses GitHub's job token, with no external secret provider or
deployment webhook. Actions are pinned to full commits. The Dockerfile retains
locked Cargo builds and digest-pinned non-root runtime bases. The validation
job smoke-tests a build of that recipe; the publication job rebuilds it, tests
that candidate's exact executable, and promotes the qualified digest. It does
not claim byte-for-byte reproducibility with the earlier smoke image.

## Integrity and dependencies

Release metadata records the source commit, version, platform, image digest,
declared dependency licenses, runtime SBOM, image vulnerability scan and
dispositions, scanner version, and the project and upstream-documentation
notices. On successful publication, `SHA256SUMS` covers those metadata files.
See [Security evidence](security-evidence.md) for policy and expiring exceptions.
Verify the checksums after extraction:

```sh
sha256sum --check SHA256SUMS
```

Verify the signed image attestation with GitHub's CLI, substituting the exact
digest from `image-digest.txt`:

```sh
gh attestation verify oci://ghcr.io/chrisbennight/mcp-infisical-rs@sha256:YOUR_DIGEST \
  --repo chrisbennight/mcp-infisical-rs
```

See GitHub's [attestation verification documentation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds).
Attestations establish origin; they do not certify that software is free of
vulnerabilities.

The license check compares Cargo's declared expressions with an explicitly
reviewed list. Missing or new expressions stop publication for review. The
license inventory includes locked development and platform-specific dependencies;
the runtime SBOM and vulnerability report are separate artifacts. None proves
that every dependency's source notice has been audited. Preserve applicable dependency notices when
redistributing binaries. Do not regenerate the expression list blindly to make
a failing check pass. The bundled endpoint documentation's pinned upstream
notice is in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Recovery

If a push succeeds but attestation or metadata upload fails, the image may
already exist. Inspect the run and registry state before retrying; a failed run
does not prove publication was rolled back. Do not announce an unverified
artifact. Roll deployments back by selecting a previously verified digest in
your own deployment configuration. This repository does not operate deployments.
