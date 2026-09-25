# Dependency and image security evidence

CI checks the complete lockfile against a freshly fetched RustSec database. It
retains the unfiltered report, the database commit and update time, scanner
version, and a disposition for each vulnerability. A missing database revision,
database older than 14 days, scanner error, filtered report, or unexcepted
vulnerability fails the gate. The check covers all advisory severities and
platforms, including development dependencies. Informational warnings remain in
the report for review. Registry yanking is a separate signal and is not checked
by this gate.

The container build uses checksum-pinned `cargo-auditable` to embed its Rust
dependency inventory. Trivy scans both that inventory and runtime OS packages;
the evidence validator fails if either inventory is absent. CI converts the
same complete scan into a CycloneDX runtime SBOM. This does not rely on scanning
the source lockfile as a substitute for inspecting the executable.

The image report must be at most 24 hours old. The gate also requires database
metadata from the same explicit scanner cache: its update must be within 48
hours, precede the scan, and not have reached its next scheduled update. Missing,
future, stale, or inconsistent timestamps fail validation. Both report and metadata
must identify the pinned scanner version. Evidence preserves the actual scan time
separately from validation time and retains the database timestamps; revalidating
an old report cannot make it a fresh scan.

Image findings with high, critical, or unknown severity block unless an exact
exception applies. Low and medium findings remain in the retained evidence with
an explicit review disposition. The separate RustSec gate still blocks Rust
vulnerability advisories of every severity unless excepted. Unfixed findings are
included. This policy does not claim that a passing scan proves the absence of
vulnerabilities.

## Artifact identity and retention

The pull-request scan must match the smoke image's immutable local image ID.
Release publication first builds a uniquely tagged candidate with build
provenance, then scans its registry digest. Version and commit tags are assigned
to that same digest only after the image gate passes, without rebuilding. The
workflow verifies the promoted tags' digests before signing the image
attestation. Candidate images can exist after a failed qualification; they are
not release tags.

The `security-evidence-*` Actions artifact contains the lockfile scan, advisory
dispositions, image scan, image dispositions, scanner versions, and runtime SBOM.
The `release-metadata-*` artifact contains the release image evidence alongside
source, license, digest, and checksum records. Both are retained for 90 days,
including available evidence on failure. Archive successful release evidence
with release notes before Actions retention expires. See [Releases](releases.md).

The validation job's smoke image and the publication job's candidate remain
separate builds. The candidate's security evidence identifies the actual
published digest; it does not claim that the two builds are byte-for-byte equal.

## Exception policy

[advisory-exceptions.json](../security/advisory-exceptions.json) identifies one
advisory, package, and exact version per exception. Aliases identify the same
advisory in image scans. Each exception records an owner, review date, expiry,
and rationale; it may last at most 90 days. The expiry day fails closed.
Exceptions cannot use package or version wildcards, cannot apply to a different
registry in the lockfile, and cannot exempt an OS package through a Rust package
exception. Changes require the repository's normal pull-request review gate.

Do not renew an exception just to make CI pass. Recheck the upstream advisory,
available patches, enabled features, reachable operations, and the consequences
of changing them. Preserve the old reports. A package upgrade requires a new
disposition if its version remains affected.

## Baseline assessment: 25 September 2026

`cargo-audit 0.22.2` scanned the original 351-package lockfile using database
commit `593df8c1b5ed0bcde9dddadfeeead776fa514ff8`, updated 24 September 2026.
No advisory, platform, or severity filters were applied. The targeted dependency
updates were rescanned against that database.

| Advisory | Original dependency | Disposition |
| --- | --- | --- |
| [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html) | `h2 0.4.15` | Update to patched `0.4.16`. |
| [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html) | `rustls 0.23.42` | Update to patched `0.23.45`, with its compatible AWS-LC and WebPKI dependencies. |
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) | `rsa 0.9.10` | Temporary exception through 23 November 2026; expiry is 24 November. No patched release was available. |

The updated lockfile scan retains only the RSA vulnerability. That is a
lockfile result, not a claim about a future image scan or future database.

## RSA reachability and feature assessment

The resolved feature graph retains RustCrypto `rsa` through both
`jsonwebtoken/rust_crypto` and `ssh-key/rsa`. The latter supplies required RSA
SSH certificate signature verification. Removing that feature would reject a
supported certificate family and would weaken the service's validation contract.
Changing the JWT backend alone would not remove the SSH dependency.

The inspected production paths have these constraints:

- `IdentityVerifier::verify` rejects algorithms other than EdDSA before JWT
  verification, and `validate_jwk` requires an Ed25519 public key.
- `validate_signed_certificate` in the SSH certificate module checks the
  expected authority and uses `ssh-key` public signature verification.
- `validate_private_key` in the SSH certificate-authority module parses
  unencrypted OpenSSH keys and examines their public algorithm. DER and PKCS#8
  RSA imports use AWS-LC key parsing. The imported value remains available to
  the authorized upstream operation.
- `InfisicalClient::kms_decrypt` and `kms_sign` perform typed upstream Infisical
  operations. They do not invoke local RustCrypto RSA private operations.

The dependency itself also provides private signing and decryption code. Its
presence is not evidence that the service exposes those paths. The inspected
service call sites did not establish a local RustCrypto RSA private-decryption
timing oracle. This is a bounded source and feature assessment, not a formal
proof that the advisory is unreachable under every future change. Reassess the
exception when JWT algorithms, SSH validation, local crypto calls, or dependency
features change. The existing SSH/PKI and authentication tests remain required.

## Tools and reproduction

The workflow pins the cargo-audit release archive by SHA-256, the Trivy action
by its full commit with an explicit scanner version, and the cargo-auditable
archive by Docker's checksum enforcement. The official tools and formats are
documented by [RustSec](https://github.com/rustsec/rustsec),
[cargo-auditable](https://github.com/rust-secure-code/cargo-auditable), and
[Trivy's Rust coverage](https://trivy.dev/docs/latest/guide/coverage/language/rust/).

With the workflow's verified scanner installed, retain the raw JSON before
applying policy. A cargo-audit exit of 1 reports findings; other nonzero exits
are scanner failures. The policy checker must still validate the JSON and pass:

```sh
mkdir -p .security
cargo audit --json --no-yanked > .security/cargo-audit.json
python3 scripts/check_advisories.py .security/cargo-audit.json \
  --output .security/advisory-dispositions.json
```

Do not use `--ignore`, platform/severity filters, or `--no-fetch` for gate
evidence. The pinned scanner omits database commit metadata on its no-fetch
path, which the validator correctly rejects.
