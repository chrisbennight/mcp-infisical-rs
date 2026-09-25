#!/usr/bin/env python3
"""Validate the container and image-publication contract."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO_ROOT / "Dockerfile"
BUILD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"
TEST_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "test.yml"
GITHUB_TEST_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "test.yml"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _dockerfile_instructions(text: str) -> tuple[list[str], bool]:
    """Join active Dockerfile continuations and report a dangling continuation."""
    instructions: list[str] = []
    continued: list[str] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        has_continuation = stripped.endswith("\\")
        content = stripped[:-1].rstrip() if has_continuation else stripped
        continued.append(content)
        if not has_continuation:
            instructions.append(" ".join(continued))
            continued = []
    return instructions, bool(continued)


def _mapping_block(text: str, key: str, indent: int) -> str | None:
    """Return one exact YAML mapping block at the requested indentation."""
    lines = text.splitlines()
    prefix = " " * indent
    matches = [
        index
        for index, line in enumerate(lines)
        if line == f"{prefix}{key}:"
    ]
    if len(matches) != 1:
        return None
    start = matches[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if _indent(line) <= indent:
            end = index
            break
    return "\n".join(lines[start:end])


def _named_step_block(job: str, name: str) -> str | None:
    """Return one named step, excluding identically worded comments or scripts."""
    lines = job.splitlines()
    matches = [
        index
        for index, line in enumerate(lines)
        if line == f"      - name: {name}"
    ]
    if len(matches) != 1:
        return None
    start = matches[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if _indent(line) <= 6:
            end = index
            break
    return "\n".join(lines[start:end])


def _has_yaml_line(block: str | None, line: str) -> bool:
    return block is not None and line in block.splitlines()


def _has_command(block: str | None, command: str) -> bool:
    if block is None:
        return False
    return any(
        line.strip() == command
        for line in block.splitlines()
        if not line.lstrip().startswith("#")
    )


def _require_step(
    errors: list[str],
    job: str,
    name: str,
    commands: tuple[str, ...] = (),
    *,
    always: bool = False,
) -> str | None:
    step = _named_step_block(job, name)
    if step is None:
        errors.append(f"workflow is missing unique {name!r} step")
        return None
    if always and not _has_yaml_line(step, "        if: always()"):
        errors.append(f"{name!r} step must run with if: always()")
    for command in commands:
        if not _has_command(step, command):
            errors.append(f"{name!r} step is missing command: {command}")
    return step


def validate_dockerfile(text: str) -> list[str]:
    errors: list[str] = []
    instructions, dangling_continuation = _dockerfile_instructions(text)
    if dangling_continuation:
        errors.append("Dockerfile ends with a dangling line continuation")
    stages = [
        instruction
        for instruction in instructions
        if instruction.upper().startswith("FROM ")
    ]
    if len(stages) != 2:
        errors.append("Dockerfile must contain exactly one builder and one runtime stage")
    for stage in stages:
        if not re.search(r"@sha256:[0-9a-f]{64}(?:\s|$)", stage):
            errors.append(f"container base is not digest-pinned: {stage}")
    required = {
        "locked release build": lambda instruction: instruction.startswith("RUN ")
        and "cargo auditable build --release --locked --bin mcp-infisical-rs" in instruction,
        "distroless non-root runtime": lambda instruction: instruction.startswith("FROM ")
        and "gcr.io/distroless/cc-debian12:nonroot@sha256:" in instruction,
        "license notices": lambda instruction: instruction
        == "COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/mcp-infisical-rs/",
        "explicit non-root user": lambda instruction: instruction
        == "USER nonroot:nonroot",
        "native healthcheck": lambda instruction: instruction.startswith("HEALTHCHECK ")
        and 'CMD ["/mcp-infisical-rs", "--healthcheck"]' in instruction,
        "binary entrypoint": lambda instruction: instruction
        == 'ENTRYPOINT ["/mcp-infisical-rs"]',
        "recorded effective compiler": lambda instruction: instruction
        == "COPY --from=builder /usr/local/share/mcp-rustc.txt /usr/share/mcp-rustc.txt",
        "verified effective compiler": lambda instruction: instruction.startswith("RUN ")
        and '''test "$(rustc --version | cut -d ' ' -f 2)" = "$expected"''' in instruction
        and "rustc --version --verbose > /usr/local/share/mcp-rustc.txt" in instruction,
    }
    for label, predicate in required.items():
        if not any(predicate(instruction) for instruction in instructions):
            errors.append(f"Dockerfile is missing {label}")
    return errors


def validate_build_workflow(text: str) -> list[str]:
    """Require validation, explicit public enablement, and scoped publication."""
    errors: list[str] = []
    on = _mapping_block(text, "on", 0)
    push = _mapping_block(on or "", "push", 2)
    if not _has_yaml_line(push, "    tags: ['v*']"):
        errors.append("release workflow must trigger on version tags")
    concurrency = _mapping_block(text, "concurrency", 0)
    if not _has_yaml_line(concurrency, "  group: mcp-infisical-rs-release-publication") or not _has_yaml_line(concurrency, "  cancel-in-progress: false"):
        errors.append("release publication must be serialized without cancellation")
    if (_mapping_block(text, "permissions", 0) or "").strip() != "permissions:\n  contents: read":
        errors.append("release workflow default permissions must be contents: read")
    jobs = _mapping_block(text, "jobs", 0)
    verify = _mapping_block(jobs or "", "verify", 2)
    if not _has_yaml_line(verify, "    uses: ./.github/workflows/test.yml"):
        errors.append("release verification must reuse repository validation")
    publish = _mapping_block(jobs or "", "publish", 2)
    for line in (
        "    needs: verify",
        "    if: github.event.repository.private == false && vars.ENABLE_RELEASE_PUBLICATION == 'true'",
        "    runs-on: ubuntu-latest",
        "    timeout-minutes: 45",
    ):
        if not _has_yaml_line(publish, line):
            errors.append(f"publication job is missing: {line.strip()}")
    permissions = _mapping_block(publish or "", "permissions", 4)
    if (permissions or "").strip() != ("permissions:\n      contents: read\n      packages: write\n      id-token: write\n      attestations: write"):
        errors.append("release publication permissions must be explicitly scoped")
    for name, lines in (
        ("Validate release source and dependency licenses", ("        run: python3 scripts/prepare_release.py",)),
        ("Build release candidate", (
            "          platforms: linux/amd64", "          push: true", "          provenance: mode=max",
            "            ${{ env.IMAGE }}:candidate-${{ github.run_id }}-${{ github.run_attempt }}",
        )),
        ("Scan exact release candidate", (
            "          image-ref: ${{ env.IMAGE }}@${{ steps.image.outputs.digest }}",
            "          cache-dir: .cache/trivy",
            "          list-all-pkgs: 'true'", "          ignore-unfixed: 'false'",
        )),
        ("Attest published image", ("          subject-digest: ${{ steps.image.outputs.digest }}", "          push-to-registry: true")),
        ("Record immutable image digest", ("        run: python3 scripts/prepare_release.py --record-digest",)),
    ):
        step = _require_step(errors, publish or "", name)
        for line in lines:
            if not _has_yaml_line(step, line):
                errors.append(f"{name!r} step is missing: {line.strip()}")
    for line in text.splitlines():
        if "uses:" in line and "uses: ./" not in line and not line.lstrip().startswith("#"):
            if not re.search(r"@[0-9a-f]{40}(?: |$)", line):
                errors.append("release actions must be pinned to full commits")
    _require_step(errors, publish or "", "Qualify release image and produce runtime SBOM", (
        'trivy --cache-dir .cache/trivy version --format json > .release/trivy-metadata.json',
        '--scanner-metadata .release/trivy-metadata.json \\',
        'trivy convert --format cyclonedx --output .release/runtime.cdx.json .release/image-scan.json',
        '--digest "$IMAGE_DIGEST" --output .release/image-dispositions.json',
    ))
    _require_step(errors, publish or "", "Promote qualified image without rebuilding", (
        '--tag "$IMAGE:$GITHUB_REF_NAME" --tag "$IMAGE:sha-$GITHUB_SHA" "$IMAGE@$IMAGE_DIGEST"',
        'test "$published_digest" = "$IMAGE_DIGEST"',
    ))
    _require_step(errors, publish or "", "Retain release metadata", always=True)
    _require_step(errors, publish or "", "Qualify exact release executable and prepare native archive", (
        'python3 scripts/qualify_image.py --image "$IMAGE@$IMAGE_DIGEST" --output .release',
    ))
    native_attestation = _require_step(errors, publish or "", "Attest qualified native archive")
    if not _has_yaml_line(native_attestation, "          subject-path: .release/mcp-infisical-rs-linux-x86_64.tar.gz"):
        errors.append("native attestation must cover the qualified archive")
    required_order = ["Build release candidate", "Scan exact release candidate",
                      "Qualify release image and produce runtime SBOM",
                      "Qualify exact release executable and prepare native archive",
                      "Promote qualified image without rebuilding", "Attest published image"]
    positions = [text.find(f"      - name: {name}\n") for name in required_order]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        errors.append("release image must be scanned and qualified before promotion and attestation")
    return errors


def validate_test_workflow(text: str) -> list[str]:
    errors: list[str] = []
    jobs = _mapping_block(text, "jobs", 0)
    test = _mapping_block(jobs or "", "test", 2)
    if test is None:
        return ["test workflow must contain one test job"]
    _require_step(
        errors,
        test,
        "Build hardened runtime image",
        (
            # The command gained the crate index argument. What the contract
            # was about - the smoke image is the production Dockerfile built
            # for linux/amd64 under the run's own tag - is unchanged; what it
            # now also requires is that the address be handed to the daemon,
            # since a build argument is the only way it reaches the image.
            'index_build_args=(--build-arg "CRATES_INDEX_URL=${CRATES_INDEX_URL}")',
            'sudo docker build "${index_build_args[@]}" --platform linux/amd64'
            ' --tag "$SMOKE_IMAGE" .',
        ),
    )
    _require_step(
        errors,
        test,
        "Inspect runtime image metadata",
        (
            'test "$configured_user" = "nonroot:nonroot"',
            "test \"$healthcheck_test\" = "
            '\'["CMD","/mcp-infisical-rs","--healthcheck"]\'',
        ),
    )
    _require_step(
        errors,
        test,
        "Smoke hardened runtime container",
        ("--read-only \\", "--cap-drop ALL \\", "--security-opt no-new-privileges \\"),
    )
    _require_step(
        errors,
        test,
        "Cleanup smoke artifacts",
        (
            'sudo docker rm -f -v "$SMOKE_CONTAINER" || failed=1',
            'sudo docker image rm "$SMOKE_IMAGE" || failed=1',
            'exit "$failed"',
        ),
        always=True,
    )
    if "trap " in text:
        errors.append("test workflow cleanup must not rely on EXIT traps")
    return errors


def validate_github_test_workflow(text: str) -> list[str]:
    """Check the public workflow's validation and container contract."""
    errors = validate_test_workflow(text)
    permissions = _mapping_block(text, "permissions", 0)
    if (permissions or "").strip() != "permissions:\n  contents: read":
        errors.append("GitHub checks must use only contents: read permissions")
    jobs = _mapping_block(text, "jobs", 0)
    test = _mapping_block(jobs or "", "test", 2)
    if not _has_yaml_line(test, "    runs-on: ubuntu-latest"):
        errors.append("GitHub checks must use the hosted Ubuntu runner")
    if not _has_yaml_line(test, "    timeout-minutes: 45"):
        errors.append("GitHub checks must have a bounded job timeout")
    for name, command in (
        ("Format", "cargo fmt --all -- --check"),
        ("Clippy", "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings"),
        ("Tests", "cargo test --workspace --all-features --locked"),
        ("Rust documentation", "cargo doc --workspace --no-deps --locked"),
        ("Documentation contract", "python3 scripts/check_docs.py"),
        ("API coverage contract", "python3 scripts/check_api_coverage.py"),
        ("Documentation validator tests", "python3 -m unittest discover -s scripts/tests"),
        ("Release contract", "python3 scripts/check_release.py"),
    ):
        step = _require_step(errors, test or "", name)
        if not _has_yaml_line(step, f"        run: {command}"):
            errors.append(f"GitHub checks must run {command}")
    _require_step(errors, test or "", "Dependency advisory gate", (
        '--output .security/advisory-dispositions.json',
    ))
    scan = _require_step(errors, test or "", "Scan runtime image")
    for line in ("          scanners: vuln", "          list-all-pkgs: 'true'",
                 "          cache-dir: .cache/trivy",
                 "          ignore-unfixed: 'false'", "          image-ref: ${{ env.SMOKE_IMAGE }}"):
        if not _has_yaml_line(scan, line):
            errors.append(f"runtime image scan is missing: {line.strip()}")
    _require_step(errors, test or "", "Validate image evidence and produce runtime SBOM", (
        'trivy --cache-dir .cache/trivy version --format json > .security/trivy-metadata.json',
        '--scanner-metadata .security/trivy-metadata.json \\',
        'trivy convert --format cyclonedx --output .security/runtime.cdx.json .security/image-scan.json',
        '--image-id "$image_id" --output .security/image-dispositions.json',
    ))
    _require_step(errors, test or "", "Retain security evidence", always=True)
    qualification = _require_step(errors, test or "", "Qualify image executable")
    if not _has_yaml_line(qualification, '        run: python3 scripts/qualify_image.py --sudo --image "$SMOKE_IMAGE" --output .security/qualification'):
        errors.append("CI must qualify the built executable with isolated clients")
    return errors


def main() -> int:
    errors = validate_dockerfile(DOCKERFILE.read_text(encoding="utf-8"))
    errors.extend(validate_build_workflow(BUILD_WORKFLOW.read_text(encoding="utf-8")))
    errors.extend(validate_github_test_workflow(GITHUB_TEST_WORKFLOW.read_text(encoding="utf-8")))
    if errors:
        for error in errors:
            print(f"release contract: {error}", file=sys.stderr)
        return 1
    print("release contract: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
