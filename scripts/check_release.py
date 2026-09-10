#!/usr/bin/env python3
"""Validate the container and image-publication contract."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO_ROOT / "Dockerfile"
BUILD_WORKFLOW = REPO_ROOT / ".gitea" / "workflows" / "build.yml"
TEST_WORKFLOW = REPO_ROOT / ".gitea" / "workflows" / "test.yml"


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


def _has_active_text(block: str | None, text: str) -> bool:
    if block is None:
        return False
    return any(
        text in line
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
        and "cargo build --release --locked --bin mcp-infisical-rs" in instruction,
        "distroless non-root runtime": lambda instruction: instruction.startswith("FROM ")
        and "gcr.io/distroless/cc-debian12:nonroot@sha256:" in instruction,
        "explicit non-root user": lambda instruction: instruction
        == "USER nonroot:nonroot",
        "native healthcheck": lambda instruction: instruction.startswith("HEALTHCHECK ")
        and 'CMD ["/mcp-infisical-rs", "--healthcheck"]' in instruction,
        "binary entrypoint": lambda instruction: instruction
        == 'ENTRYPOINT ["/mcp-infisical-rs"]',
    }
    for label, predicate in required.items():
        if not any(predicate(instruction) for instruction in instructions):
            errors.append(f"Dockerfile is missing {label}")
    return errors


def validate_build_workflow(text: str) -> list[str]:
    errors: list[str] = []
    on = _mapping_block(text, "on", 0)
    push = _mapping_block(on or "", "push", 2)
    if not _has_yaml_line(push, "    branches: [main]"):
        errors.append("build workflow automatic publication must target main only")

    concurrency = _mapping_block(text, "concurrency", 0)
    if not _has_yaml_line(
        concurrency, "  group: mcp-infisical-rs-build-publication"
    ) or not _has_yaml_line(concurrency, "  cancel-in-progress: false"):
        errors.append("build workflow must globally serialize shared-tag publication")

    env = _mapping_block(text, "env", 0)
    if not _has_yaml_line(
        env,
        "  IMAGE_IMMUTABLE: "
        "gitea.cacahuate.org/bennight/mcp-infisical-rs:sha-${{ github.sha }}",
    ):
        errors.append("immutable image tag must derive once from the full commit SHA")

    jobs = _mapping_block(text, "jobs", 0)
    verify = _mapping_block(jobs or "", "verify", 2)
    publish = _mapping_block(jobs or "", "publish", 2)
    if verify is None or publish is None:
        errors.append("build workflow must contain unique verify and publish jobs")
        return errors
    if not _has_yaml_line(publish, "    needs: verify"):
        errors.append("publish job must depend on verify")
    if not _has_yaml_line(publish, "    if: github.ref == 'refs/heads/main'"):
        errors.append("publish job must reject non-main workflow dispatches")

    fetch = _require_step(errors, publish, "Fetch registry credential")
    if not _has_yaml_line(fetch, "          secret-path: /bennight/mcp-infisical-rs"):
        errors.append("registry credential must use the per-repository Infisical path")

    _require_step(
        errors,
        publish,
        "Build image",
        (
            # The build forwards the crate index argument ahead of these flags,
            # so the asserted line carries it too. Platform and both tags are
            # what this contract is about; the argument rides in front of them.
            'docker build "${index_build_args[@]}" --platform linux/amd64 '
            '--tag "$IMAGE_IMMUTABLE" --tag "${IMAGE}:latest" .',
        ),
    )
    _require_step(
        errors,
        publish,
        "Inspect runtime image metadata",
        (
            'test "$configured_user" = "nonroot:nonroot"',
            "test \"$healthcheck_test\" = "
            '\'["CMD","/mcp-infisical-rs","--healthcheck"]\'',
        ),
    )
    _require_step(
        errors,
        publish,
        "Smoke hardened runtime container",
        ("--read-only \\", "--cap-drop ALL \\", "--security-opt no-new-privileges \\"),
    )
    _require_step(
        errors,
        publish,
        "Cleanup smoke container",
        ('docker rm -f -v "$SMOKE_CONTAINER"',),
        always=True,
    )
    publish_image = _require_step(
        errors,
        publish,
        "Publish image",
        (
            "printf '%s' \"$GITEATOKEN\" | docker login "
            "gitea.cacahuate.org --username bennight --password-stdin",
            'if ! immutable_push="$(docker push "$IMAGE_IMMUTABLE" 2>&1)"; then',
            'docker push "${IMAGE}:latest"',
        ),
    )
    if not _has_yaml_line(publish_image, "        id: publish"):
        errors.append("image publication must expose the immutable registry digest")
    if not _has_command(
        publish_image, 'echo "digest=$digest" >> "$GITHUB_OUTPUT"'
    ):
        errors.append("image publication must emit its immutable registry digest")

    deploy = _require_step(
        errors,
        publish,
        "Request docker-home image update",
    )
    required_dispatch_markers = (
        "          SOURCE_SHA: ${{ github.sha }}",
        "          IMAGE_DIGEST: ${{ steps.publish.outputs.digest }}",
        '"image": "gitea.cacahuate.org/bennight/mcp-infisical-rs"',
        '"source_sha": os.environ["SOURCE_SHA"]',
        '"digest": os.environ["IMAGE_DIGEST"]',
        "class RejectRedirect(urllib.request.HTTPRedirectHandler):",
        'raise RuntimeError("docker-home workflow redirects are forbidden")',
        '"https://gitea.cacahuate.org/api/v1/repos/bennight/docker-home/"',
        '"actions/workflows/update-first-party-image.yml/dispatches"',
        "opener = urllib.request.build_opener(RejectRedirect())",
    )
    for marker in required_dispatch_markers:
        if not _has_active_text(deploy, marker):
            errors.append(
                f"docker-home image update step is missing contract marker: {marker}"
            )
    if _has_active_text(deploy, "urllib.request.urlopen("):
        errors.append("docker-home image update must not use the redirecting opener")
    _require_step(
        errors,
        publish,
        "Remove registry authentication",
        ('rm -rf -- "$DOCKER_CONFIG"', 'test ! -e "$DOCKER_CONFIG"'),
        always=True,
    )
    _require_step(
        errors,
        publish,
        "Remove local image tags",
        ('docker image rm "$image_ref" || failed=1', 'exit "$failed"'),
        always=True,
    )
    if "trap " in text:
        errors.append("build workflow cleanup must not rely on EXIT traps")
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


def main() -> int:
    errors = validate_dockerfile(DOCKERFILE.read_text(encoding="utf-8"))
    errors.extend(validate_build_workflow(BUILD_WORKFLOW.read_text(encoding="utf-8")))
    errors.extend(validate_test_workflow(TEST_WORKFLOW.read_text(encoding="utf-8")))
    if errors:
        for error in errors:
            print(f"release contract: {error}", file=sys.stderr)
        return 1
    print("release contract: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
