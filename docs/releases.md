# Releases

The release workflow prepares a Linux/amd64 OCI image for
`ghcr.io/chrisbennight/mcp-infisical-rs`. It does not publish native binaries,
deploy a service, or update a rolling `latest` tag. Build from source for local
stdio use. Other platforms have not been qualified.

## Before the first public release

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
4. It rebuilds the validated Dockerfile for Linux/amd64, publishes version and
   full-commit tags, and attaches build provenance and a GitHub-signed image
   attestation. The registry digest identifies the immutable artifact; tags are
   convenient references, not an immutability guarantee.
5. Review the completed run, its image attestation, and the `release-metadata-*`
   artifact before announcing availability. Archive that metadata with the
   release notes before its 90-day Actions retention expires.

The publication job has repository-read, package-write, OIDC, and attestation
permissions. It uses GitHub's job token, with no external secret provider or
deployment webhook. Actions are pinned to full commits. The Dockerfile retains
locked Cargo builds and digest-pinned non-root runtime bases. The validation
job smoke-tests a build of that recipe; the publication job rebuilds it and
does not claim byte-for-byte reproducibility with the smoke image.

## Integrity and dependencies

Release metadata records the source commit, version, platform, image digest,
declared dependency licenses, and the project and upstream-documentation
notices. `SHA256SUMS` covers those metadata files. Verify it after extraction:

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
inventory includes locked development and platform-specific dependencies; it
is not a runtime SBOM, a vulnerability scan, or proof that every dependency's
source notice has been audited. Preserve applicable dependency notices when
redistributing binaries. Do not regenerate the expression list blindly to make
a failing check pass. The bundled endpoint documentation's pinned upstream
notice is in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Recovery

If a push succeeds but attestation or metadata upload fails, the image may
already exist. Inspect the run and registry state before retrying; a failed run
does not prove publication was rolled back. Do not announce an unverified
artifact. Roll deployments back by selecting a previously verified digest in
your own deployment configuration. This repository does not operate deployments.
