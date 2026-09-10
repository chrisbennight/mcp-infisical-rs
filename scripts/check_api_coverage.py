#!/usr/bin/env python3
"""Validate the pinned Infisical endpoint snapshot and generated coverage matrix."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COVERAGE_ROOT = ROOT / "api-coverage"
SNAPSHOT_PATH = COVERAGE_ROOT / "infisical-v0.160.12.json"
RULES_PATH = COVERAGE_ROOT / "rules.json"
MATRIX_PATH = COVERAGE_ROOT / "matrix.csv"
SUMMARY_PATH = ROOT / "docs" / "api-coverage.md"
SOURCE_REPOSITORY = "https://github.com/Infisical/infisical"
SOURCE_DOCS_ROOT = Path("docs/api-reference/endpoints")
PINNED_SOURCE_COMMIT = "0a9dd1005f9d088c88b639760da3544fafd11388"
PINNED_SOURCE_GIT = COVERAGE_ROOT / "infisical-v0.160.12-0a9dd1005f9d.git"
CAPABILITY_COMMAND = (
    "cargo",
    "run",
    "--quiet",
    "--locked",
    "-p",
    "infisical-mcp",
    "--example",
    "server_capabilities",
)
ACTIVE_STATUSES = frozenset(
    {
        "deferred",
        "edition_gated",
        "implemented",
        "intentionally_omitted",
        "superseded",
    }
)
SUMMARY_STATUSES = (
    "implemented",
    "edition_gated",
    "deferred",
    "intentionally_omitted",
    "superseded",
    "deprecated",
)
HTTP_METHODS = frozenset({"DELETE", "GET", "PATCH", "POST", "PUT"})
OPENAPI = re.compile(r'^openapi:\s*["\'](?P<operation>[^"\']+)["\']\s*$', re.MULTILINE)
TITLE = re.compile(r'^title:\s*["\'](?P<title>[^"\']+)["\']\s*$', re.MULTILINE)
class CoverageError(ValueError):
    """A deterministic coverage invariant failed."""


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CoverageError(f"cannot read {path.relative_to(ROOT)}: {error}") from error
    if not isinstance(value, dict):
        raise CoverageError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def canonical_json(value: object) -> str:
    return json.dumps(value, indent=1, sort_keys=True) + "\n"


def git_output(source: Path, *arguments: str) -> str:
    environment = os.environ.copy()
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    process = subprocess.run(
        ["git", "-C", str(source), *arguments],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise CoverageError(f"git {' '.join(arguments)} failed: {detail}")
    return process.stdout.strip()


def parse_endpoint_text(text: str, relative: str) -> dict[str, object]:
    openapi = OPENAPI.search(text)
    title = TITLE.search(text)
    if openapi is None or title is None:
        raise CoverageError(f"{relative} must declare title and openapi frontmatter")

    operation = openapi.group("operation").split(maxsplit=1)
    if len(operation) != 2:
        raise CoverageError(f"{relative} has malformed openapi operation")
    method, route = operation[0].upper(), operation[1]
    if method not in HTTP_METHODS or not route.startswith("/"):
        raise CoverageError(f"{relative} has unsupported openapi operation {operation!r}")

    return {
        "deprecated": relative.startswith("deprecated/"),
        "document": relative,
        "method": method,
        "path": route,
        "title": title.group("title"),
    }


def parse_endpoint(document: Path, endpoints_root: Path) -> dict[str, object]:
    return parse_endpoint_text(
        document.read_text(encoding="utf-8"),
        document.relative_to(endpoints_root).as_posix(),
    )


def build_snapshot(
    endpoints: list[dict[str, object]],
    expected_version: str,
    commit: str,
) -> dict[str, object]:
    endpoints.sort(key=lambda endpoint: str(endpoint["document"]))
    documents = [str(endpoint["document"]) for endpoint in endpoints]
    if len(documents) != len(set(documents)):
        raise CoverageError("source snapshot contains duplicate document paths")

    active = sum(not bool(endpoint["deprecated"]) for endpoint in endpoints)
    deprecated = len(endpoints) - active
    categories = len(
        {
            str(endpoint["document"]).split("/", maxsplit=1)[0]
            for endpoint in endpoints
        }
    )
    return {
        "counts": {
            "active": active,
            "deprecated": deprecated,
            "topLevelCategories": categories,
            "total": len(endpoints),
        },
        "endpoints": endpoints,
        "schemaVersion": 1,
        "source": {
            "commit": commit,
            "docsRoot": SOURCE_DOCS_ROOT.as_posix(),
            "repository": SOURCE_REPOSITORY,
            "tag": f"v{expected_version}",
        },
        "targetInfisicalVersion": expected_version,
    }


def snapshot_from_source(source: Path, expected_version: str) -> dict[str, object]:
    source = source.resolve()
    endpoints_root = source / SOURCE_DOCS_ROOT
    if not endpoints_root.is_dir():
        raise CoverageError(f"{source} does not contain {SOURCE_DOCS_ROOT}")

    if git_output(source, "status", "--porcelain=v1", "--untracked-files=all"):
        raise CoverageError(
            "source checkout must be clean before recording tag and commit provenance"
        )
    tag = git_output(source, "describe", "--tags", "--exact-match")
    expected_tag = f"v{expected_version}"
    if tag != expected_tag:
        raise CoverageError(f"source tag is {tag!r}, expected {expected_tag!r}")
    commit = git_output(source, "rev-parse", "HEAD")

    endpoints = [
        parse_endpoint(path, endpoints_root)
        for path in endpoints_root.rglob("*.mdx")
    ]
    return build_snapshot(endpoints, expected_version, commit)


def isolated_git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment.pop("GIT_ALTERNATE_OBJECT_DIRECTORIES", None)
    return environment


def git_bytes_from_pinned_repository(
    repository: Path,
    *arguments: str,
) -> bytes:
    process = subprocess.run(
        ["git", f"--git-dir={repository.resolve()}", *arguments],
        check=False,
        capture_output=True,
        env=isolated_git_environment(),
    )
    if process.returncode != 0:
        detail = process.stderr.decode(errors="replace").strip()
        raise CoverageError(f"pinned git {' '.join(arguments)} failed: {detail}")
    return process.stdout


def snapshot_from_pinned_repository(
    repository: Path,
    expected_version: str,
    expected_commit: str,
) -> dict[str, object]:
    pack_directory = repository / "objects" / "pack"
    indexes = sorted(pack_directory.glob("pack-*.idx"))
    packs = sorted(pack_directory.glob("pack-*.pack"))
    if (
        len(indexes) != 1
        or len(packs) != 1
        or indexes[0].stem != packs[0].stem
    ):
        raise CoverageError("pinned Git object store must contain one matching pack and index")
    verification = subprocess.run(
        ["git", "verify-pack", "-v", str(indexes[0])],
        check=False,
        capture_output=True,
        env=isolated_git_environment(),
        text=True,
    )
    if verification.returncode != 0:
        detail = verification.stderr.strip() or verification.stdout.strip()
        raise CoverageError(f"pinned Git object pack verification failed: {detail}")

    tag = f"refs/tags/v{expected_version}"
    try:
        tag_commit = git_bytes_from_pinned_repository(
            repository,
            "rev-parse",
            f"{tag}^{{commit}}",
        ).decode("ascii").strip()
    except CoverageError as error:
        raise CoverageError(
            f"pinned tag v{expected_version} does not resolve to a commit"
        ) from error
    if tag_commit != expected_commit:
        raise CoverageError(
            f"pinned tag v{expected_version} resolves to {tag_commit}, "
            f"expected {expected_commit}"
        )

    git_bytes_from_pinned_repository(
        repository,
        "cat-file",
        "-e",
        f"{expected_commit}^{{commit}}",
    )
    endpoint_tree = git_bytes_from_pinned_repository(
        repository,
        "rev-parse",
        f"{expected_commit}:{SOURCE_DOCS_ROOT.as_posix()}",
    ).decode("ascii").strip()
    if re.fullmatch(r"[0-9a-f]{40}", endpoint_tree) is None:
        raise CoverageError("pinned endpoint tree resolved to an invalid object ID")
    archive = git_bytes_from_pinned_repository(
        repository,
        "archive",
        "--format=tar",
        endpoint_tree,
    )
    endpoints: list[dict[str, object]] = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source_archive:
        for member in source_archive.getmembers():
            path = Path(member.name)
            if not member.isfile() or path.suffix != ".mdx":
                continue
            if path.is_absolute() or ".." in path.parts:
                raise CoverageError(
                    f"pinned archive escaped {SOURCE_DOCS_ROOT}: {member.name!r}"
                )
            relative = path.as_posix()
            extracted = source_archive.extractfile(member)
            if extracted is None:
                raise CoverageError(f"cannot read pinned endpoint {member.name!r}")
            try:
                text = extracted.read().decode("utf-8")
            except UnicodeDecodeError as error:
                raise CoverageError(
                    f"pinned endpoint {member.name!r} is not UTF-8"
                ) from error
            endpoints.append(parse_endpoint_text(text, relative))
    if not endpoints:
        raise CoverageError("pinned Git object store contains no endpoint documents")
    return build_snapshot(endpoints, expected_version, expected_commit)


def pinned_object_ids(source: Path, commit: str) -> list[str]:
    identifiers = {commit, git_output(source, "rev-parse", f"{commit}^{{tree}}")}
    path_parts: list[str] = []
    for part in SOURCE_DOCS_ROOT.parts:
        path_parts.append(part)
        identifiers.add(
            git_output(source, "rev-parse", f"{commit}:{'/'.join(path_parts)}")
        )
    tree_listing = git_output(
        source,
        "ls-tree",
        "-r",
        "-t",
        f"{commit}:{SOURCE_DOCS_ROOT.as_posix()}",
    )
    for line in tree_listing.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) < 3:
            raise CoverageError(f"malformed git ls-tree output: {line!r}")
        identifiers.add(fields[2])
    if any(re.fullmatch(r"[0-9a-f]{40}", identifier) is None for identifier in identifiers):
        raise CoverageError("pinned source object closure contains an invalid object ID")
    return sorted(identifiers)


def initialize_pinned_repository(
    repository: Path,
    expected_version: str,
    expected_commit: str,
) -> None:
    (repository / "objects" / "pack").mkdir(parents=True)
    tag_reference = repository / "refs" / "tags" / f"v{expected_version}"
    tag_reference.parent.mkdir(parents=True)
    tag_reference.write_text(f"{expected_commit}\n", encoding="ascii")
    (repository / "HEAD").write_text(
        "ref: refs/heads/unborn\n",
        encoding="ascii",
    )
    (repository / "config").write_text(
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = true\n",
        encoding="ascii",
    )


def write_pinned_repository(
    source: Path,
    destination: Path,
    expected_version: str,
    expected_commit: str,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".api-coverage-objects-",
        dir=destination.parent,
    ) as temporary_directory:
        temporary_root = Path(temporary_directory)
        temporary_repository = temporary_root / "repository"
        initialize_pinned_repository(
            temporary_repository,
            expected_version,
            expected_commit,
        )
        pack_directory = temporary_repository / "objects" / "pack"
        object_input = "\n".join(pinned_object_ids(source, expected_commit)) + "\n"
        pack_process = subprocess.run(
            [
                "git",
                "-C",
                str(source),
                "pack-objects",
                "--stdout",
                "--compression=9",
            ],
            check=False,
            capture_output=True,
            env={
                **os.environ,
                "GIT_NO_REPLACE_OBJECTS": "1",
            },
            input=object_input.encode(),
        )
        if pack_process.returncode != 0:
            detail = pack_process.stderr.decode(errors="replace").strip()
            raise CoverageError(f"git pack-objects failed: {detail}")
        index_process = subprocess.run(
            [
                "git",
                f"--git-dir={temporary_repository}",
                "index-pack",
                "--stdin",
                "--no-rev-index",
            ],
            check=False,
            capture_output=True,
            env=isolated_git_environment(),
            input=pack_process.stdout,
        )
        if index_process.returncode != 0:
            detail = index_process.stderr.decode(errors="replace").strip()
            raise CoverageError(f"git index-pack failed: {detail}")
        index_output = index_process.stdout.decode("ascii").split()
        pack_hash = (
            index_output[-1]
            if len(index_output) in {1, 2}
            and (len(index_output) == 1 or index_output[0] == "pack")
            else ""
        )
        if re.fullmatch(r"[0-9a-f]{40}", pack_hash) is None:
            raise CoverageError(f"git pack-objects returned invalid hash {pack_hash!r}")
        generated = (
            pack_directory / f"pack-{pack_hash}.idx",
            pack_directory / f"pack-{pack_hash}.pack",
        )
        if any(not path.is_file() for path in generated):
            raise CoverageError("git pack-objects did not produce an index and pack")

        packed_snapshot = snapshot_from_pinned_repository(
            temporary_repository,
            expected_version,
            expected_commit,
        )
        source_snapshot = snapshot_from_source(source, expected_version)
        if packed_snapshot != source_snapshot:
            raise CoverageError("pinned Git object pack does not reproduce the source checkout")

        previous_repository = temporary_root / "previous"
        if destination.exists():
            os.replace(destination, previous_repository)
        try:
            os.replace(temporary_repository, destination)
        except OSError as error:
            try:
                if previous_repository.exists():
                    os.replace(previous_repository, destination)
            except OSError as restore_error:
                raise CoverageError(
                    "replace pinned Git repository failed and restoring the "
                    f"previous repository also failed: {restore_error}"
                ) from error
            raise CoverageError(f"replace pinned Git repository failed: {error}") from error


def parse_capability_states(
    payload: object,
    expected_version: str,
) -> dict[str, bool]:
    if not isinstance(payload, dict):
        raise CoverageError("server.capabilities payload must be an object")
    if payload.get("targetInfisicalVersion") != expected_version:
        raise CoverageError(
            "server.capabilities targetInfisicalVersion does not match the coverage rules"
        )
    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        raise CoverageError("server.capabilities must contain a non-empty capability array")
    states: dict[str, bool] = {}
    for capability in capabilities:
        if not isinstance(capability, dict):
            raise CoverageError("server.capabilities contains a malformed capability")
        name = capability.get("name")
        available = capability.get("available")
        reason = capability.get("reason")
        if not isinstance(name, str) or not name or not isinstance(available, bool):
            raise CoverageError("server.capabilities contains a malformed capability")
        if name in states:
            raise CoverageError(f"server.capabilities contains duplicate {name!r}")
        if available and reason is not None:
            raise CoverageError(f"available capability {name!r} must not include a reason")
        if not available and (not isinstance(reason, str) or not reason):
            raise CoverageError(f"unavailable capability {name!r} requires a reason")
        states[name] = available
    return states


def capability_states(expected_version: str) -> dict[str, bool]:
    process = subprocess.run(
        CAPABILITY_COMMAND,
        check=False,
        capture_output=True,
        cwd=ROOT,
        text=True,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise CoverageError(f"execute server.capabilities registry failed: {detail}")
    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise CoverageError("server.capabilities registry returned invalid JSON") from error
    return parse_capability_states(payload, expected_version)


def validate_snapshot(
    snapshot: dict[str, Any],
    expected_version: str,
    expected_commit: str = PINNED_SOURCE_COMMIT,
) -> list[dict[str, Any]]:
    if snapshot.get("schemaVersion") != 1:
        raise CoverageError("snapshot schemaVersion must be 1")
    if snapshot.get("targetInfisicalVersion") != expected_version:
        raise CoverageError("snapshot and rules target different Infisical versions")
    endpoints = snapshot.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        raise CoverageError("snapshot endpoints must be a non-empty array")

    documents: list[str] = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            raise CoverageError("every snapshot endpoint must be an object")
        document = endpoint.get("document")
        method = endpoint.get("method")
        route = endpoint.get("path")
        deprecated = endpoint.get("deprecated")
        title = endpoint.get("title")
        if (
            not isinstance(document, str)
            or not document.endswith(".mdx")
            or method not in HTTP_METHODS
            or not isinstance(route, str)
            or not route.startswith("/")
            or not isinstance(deprecated, bool)
            or not isinstance(title, str)
            or not title
        ):
            raise CoverageError(f"malformed endpoint record: {endpoint!r}")
        documents.append(document)

    if documents != sorted(documents) or len(documents) != len(set(documents)):
        raise CoverageError("snapshot endpoints must be uniquely sorted by document")

    counts = snapshot.get("counts")
    active = sum(not endpoint["deprecated"] for endpoint in endpoints)
    deprecated = len(endpoints) - active
    categories = len(
        {
            endpoint["document"].split("/", maxsplit=1)[0]
            for endpoint in endpoints
        }
    )
    expected_counts = {
        "active": active,
        "deprecated": deprecated,
        "topLevelCategories": categories,
        "total": len(endpoints),
    }
    if counts != expected_counts:
        raise CoverageError(f"snapshot counts drifted: expected {expected_counts}, got {counts}")

    source = snapshot.get("source")
    expected_source = {
        "commit": expected_commit,
        "docsRoot": SOURCE_DOCS_ROOT.as_posix(),
        "repository": SOURCE_REPOSITORY,
        "tag": f"v{expected_version}",
    }
    if not isinstance(source, dict) or any(
        source.get(field) != value for field, value in expected_source.items()
    ):
        raise CoverageError(f"snapshot source must retain {expected_source}")
    return endpoints


def validate_pinned_snapshot(
    snapshot: dict[str, Any],
    expected_version: str,
    repository: Path = PINNED_SOURCE_GIT,
    expected_commit: str = PINNED_SOURCE_COMMIT,
) -> list[dict[str, Any]]:
    endpoints = validate_snapshot(snapshot, expected_version, expected_commit)
    pinned_snapshot = snapshot_from_pinned_repository(
        repository,
        expected_version,
        expected_commit,
    )
    if snapshot != pinned_snapshot:
        raise CoverageError(
            "checked-in endpoint snapshot does not match the pinned upstream Git tree"
        )
    return endpoints


def validate_rules(
    rules_document: dict[str, Any], capabilities: dict[str, bool]
) -> list[dict[str, Any]]:
    if rules_document.get("schemaVersion") != 3:
        raise CoverageError("rules schemaVersion must be 3")
    rules = rules_document.get("rules")
    if not isinstance(rules, list) or not rules:
        raise CoverageError("rules must be a non-empty array")

    normalized: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    matchers: set[tuple[str, str, str]] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise CoverageError("every rule must be an object")
        required = ("id", "status", "mcpFamily", "capability", "reason")
        if any(not isinstance(rule.get(field), str) or not rule[field] for field in required):
            raise CoverageError(f"rule is missing a non-empty string field: {rule!r}")
        if rule["id"] in identifiers:
            raise CoverageError(f"duplicate rule id {rule['id']!r}")
        if rule["status"] not in ACTIVE_STATUSES:
            raise CoverageError(f"rule {rule['id']!r} has invalid status")
        if rule["capability"] not in capabilities:
            raise CoverageError(
                f"rule {rule['id']!r} cites unknown capability {rule['capability']!r}"
            )
        if rule["status"] == "implemented" and not capabilities[rule["capability"]]:
            raise CoverageError(
                f"implemented rule {rule['id']!r} cites an unavailable capability"
            )
        if (
            rule["status"]
            in {"deferred", "edition_gated", "intentionally_omitted"}
            and capabilities[rule["capability"]]
        ):
            raise CoverageError(
                f"{rule['status']} rule {rule['id']!r} cites an available capability"
            )

        endpoints = rule.get("endpoints")
        if not isinstance(endpoints, dict) or not endpoints:
            raise CoverageError(
                f"rule {rule['id']!r} endpoints must be a non-empty object"
            )
        normalized_endpoints: list[dict[str, str]] = []
        endpoint_order: list[tuple[str, str, str]] = []
        for document, operation in endpoints.items():
            if (
                not isinstance(document, str)
                or not document.endswith(".mdx")
                or not isinstance(operation, str)
            ):
                raise CoverageError(
                    f"rule {rule['id']!r} has a malformed exact endpoint matcher"
                )
            parsed_operation = operation.split(maxsplit=1)
            if len(parsed_operation) != 2:
                raise CoverageError(
                    f"rule {rule['id']!r} has a malformed exact endpoint matcher"
                )
            method, route = parsed_operation
            if (
                method not in HTTP_METHODS
                or not isinstance(route, str)
                or not route.startswith("/")
            ):
                raise CoverageError(
                    f"rule {rule['id']!r} has a malformed exact endpoint matcher"
                )
            if (
                rule["status"] == "implemented"
                and method != "GET"
                and rule["capability"].endswith((".read", ".list"))
            ):
                raise CoverageError(
                    f"implemented non-GET endpoint {document!r} cites read-only "
                    f"capability {rule['capability']!r}"
                )
            matcher = (document, method, route)
            if matcher in matchers:
                raise CoverageError(f"duplicate exact endpoint matcher {matcher!r}")
            matchers.add(matcher)
            endpoint_order.append(matcher)
            normalized_endpoints.append(
                {"document": document, "method": method, "path": route}
            )
        if endpoint_order != sorted(endpoint_order):
            raise CoverageError(
                f"rule {rule['id']!r} exact endpoint matchers must be sorted"
            )

        identifiers.add(rule["id"])
        normalized_rule = {field: rule[field] for field in required}
        normalized_rule["endpoints"] = normalized_endpoints
        normalized.append(normalized_rule)
    return normalized


def validate_workflow_dependencies(
    rules_document: dict[str, Any], rules: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    dependencies = rules_document.get("workflowDependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise CoverageError("workflowDependencies must be a non-empty array")

    rules_by_id = {rule["id"]: rule for rule in rules}
    identifiers: set[str] = set()
    consumer_identifiers: set[tuple[str, str, str]] = set()
    normalized: list[dict[str, Any]] = []
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != {
            "consumerRule",
            "id",
            "identifier",
            "scope",
            "sources",
        }:
            raise CoverageError("every workflow dependency must be a closed object")
        required = ("id", "consumerRule", "identifier", "scope")
        if any(
            not isinstance(dependency.get(field), str) or not dependency[field]
            for field in required
        ):
            raise CoverageError(
                "workflow dependency is missing a non-empty string field"
            )
        dependency_id = dependency["id"]
        if dependency_id in identifiers:
            raise CoverageError(f"duplicate workflow dependency id {dependency_id!r}")
        identifiers.add(dependency_id)

        consumer_id = dependency["consumerRule"]
        consumer = rules_by_id.get(consumer_id)
        if consumer is None:
            raise CoverageError(
                f"workflow dependency {dependency_id!r} cites unknown consumer rule "
                f"{consumer_id!r}"
            )
        if consumer["status"] != "implemented":
            raise CoverageError(
                f"workflow dependency {dependency_id!r} consumer must be implemented"
            )
        consumer_key = (consumer_id, dependency["identifier"], dependency["scope"])
        if consumer_key in consumer_identifiers:
            raise CoverageError(
                f"duplicate workflow identifier requirement {consumer_key!r}"
            )
        consumer_identifiers.add(consumer_key)

        sources = dependency.get("sources")
        if not isinstance(sources, list) or not sources:
            raise CoverageError(
                f"workflow dependency {dependency_id!r} requires at least one source"
            )
        normalized_sources: list[dict[str, str]] = []
        source_order: list[tuple[str, str]] = []
        source_rules: set[str] = set()
        for source in sources:
            if not isinstance(source, dict) or set(source) != {"kind", "rule", "scope"}:
                raise CoverageError(
                    f"workflow dependency {dependency_id!r} has a malformed source"
                )
            if source.get("kind") not in {"discovery", "producer"}:
                raise CoverageError(
                    f"workflow dependency {dependency_id!r} has an invalid source kind"
                )
            source_id = source.get("rule")
            source_scope = source.get("scope")
            if not isinstance(source_id, str) or not source_id:
                raise CoverageError(
                    f"workflow dependency {dependency_id!r} has an invalid source rule"
                )
            if source_scope != dependency["scope"]:
                raise CoverageError(
                    f"workflow dependency {dependency_id!r} source scope does not match "
                    "the consumer scope"
                )
            if source_id in source_rules:
                raise CoverageError(
                    f"workflow dependency {dependency_id!r} repeats source {source_id!r}"
                )
            source_rules.add(source_id)
            source_rule = rules_by_id.get(source_id)
            if source_rule is None:
                raise CoverageError(
                    f"workflow dependency {dependency_id!r} cites unknown source rule "
                    f"{source_id!r}"
                )
            if source_rule["status"] != "implemented":
                raise CoverageError(
                    f"workflow dependency {dependency_id!r} source {source_id!r} "
                    "must be implemented"
                )
            source_order.append((source_id, source["kind"]))
            normalized_sources.append(
                {"kind": source["kind"], "rule": source_id, "scope": source_scope}
            )
        if source_order != sorted(source_order):
            raise CoverageError(
                f"workflow dependency {dependency_id!r} sources must be sorted by rule"
            )
        normalized.append(
            {
                "consumerRule": consumer_id,
                "id": dependency_id,
                "identifier": dependency["identifier"],
                "scope": dependency["scope"],
                "sources": normalized_sources,
            }
        )
    if [dependency["id"] for dependency in normalized] != sorted(identifiers):
        raise CoverageError("workflow dependencies must be sorted by id")
    return normalized


def classify_endpoint(
    endpoint: dict[str, Any], rules: list[dict[str, Any]]
) -> dict[str, str]:
    if endpoint["deprecated"]:
        return {
            "capability": "",
            "mcpFamily": "deprecated",
            "reason": "Deprecated in the pinned Infisical documentation snapshot.",
            "rule": "pinned-deprecated-document",
            "status": "deprecated",
        }

    matcher = (endpoint["document"], endpoint["method"], endpoint["path"])
    matches = [
        rule
        for rule in rules
        if any(
            matcher
            == (candidate["document"], candidate["method"], candidate["path"])
            for candidate in rule["endpoints"]
        )
    ]
    if not matches:
        raise CoverageError(f"active endpoint signature {matcher!r} has no coverage rule")
    if len(matches) != 1:
        raise CoverageError(
            f"active endpoint signature {matcher!r} has ambiguous coverage rules"
        )
    return matches[0]


def coverage_rows(
    endpoints: list[dict[str, Any]], rules: list[dict[str, Any]]
) -> list[dict[str, str]]:
    active_signatures = {
        (endpoint["document"], endpoint["method"], endpoint["path"])
        for endpoint in endpoints
        if not endpoint["deprecated"]
    }
    rule_signatures = {
        (endpoint["document"], endpoint["method"], endpoint["path"])
        for rule in rules
        for endpoint in rule["endpoints"]
    }
    missing = sorted(active_signatures - rule_signatures)
    if missing:
        raise CoverageError(
            f"active endpoint signature {missing[0]!r} has no coverage rule"
        )
    extra = sorted(rule_signatures - active_signatures)
    if extra:
        raise CoverageError(
            f"coverage rule cites an endpoint outside the active snapshot: {extra[0]!r}"
        )

    rows: list[dict[str, str]] = []
    used_rules: Counter[str] = Counter()
    for endpoint in endpoints:
        classification = classify_endpoint(endpoint, rules)
        used_rules[classification["rule" if endpoint["deprecated"] else "id"]] += 1
        rows.append(
            {
                "capability": classification["capability"],
                "document": endpoint["document"],
                "mcp_family": classification["mcpFamily"],
                "method": endpoint["method"],
                "path": endpoint["path"],
                "reason": classification["reason"],
                "rule": classification["rule" if endpoint["deprecated"] else "id"],
                "status": classification["status"],
            }
        )

    unused = sorted(rule["id"] for rule in rules if used_rules[rule["id"]] == 0)
    if unused:
        raise CoverageError(f"coverage rules match no active endpoint: {', '.join(unused)}")
    return rows


def render_csv(rows: list[dict[str, str]]) -> str:
    output = io.StringIO(newline="")
    fields = (
        "document",
        "method",
        "path",
        "status",
        "mcp_family",
        "capability",
        "rule",
    )
    writer = csv.DictWriter(
        output,
        fieldnames=fields,
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def render_summary(
    snapshot: dict[str, Any],
    rows: list[dict[str, str]],
    rules: list[dict[str, Any]],
    workflow_dependencies: list[dict[str, Any]],
) -> str:
    by_category: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        category = row["document"].split("/", maxsplit=1)[0]
        if category == "deprecated":
            category = "deprecated endpoint documents"
        by_category[category][row["status"]] += 1

    lines = [
        "# Infisical API coverage",
        "",
        "<!-- Generated by scripts/check_api_coverage.py; do not hand edit. -->",
        "",
        f"Target: Infisical `{snapshot['targetInfisicalVersion']}` at "
        f"`{snapshot['source']['commit']}`.",
        "",
        "The compact table summarizes the checked-in endpoint matrix. "
        "The [CSV matrix](../api-coverage/matrix.csv) records every pinned "
        "documentation page, HTTP operation, owning MCP family, capability, "
        "disposition, and exact decision-rule identifier. The rules ledger owns "
        "the corresponding rationale. Deprecated pages remain in the snapshot "
        "for drift accounting but do not require an active coverage rule. "
        "Declared identifier links below are checked workflow evidence, not a "
        "claim that every possible multi-step workflow is complete.",
        "",
        "| Category | Implemented | Edition-gated | Deferred | "
        "Intentionally omitted | Superseded | Deprecated | Total |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    totals: Counter[str] = Counter()
    for category in sorted(by_category):
        counts = by_category[category]
        totals.update(counts)
        values = [counts[status] for status in SUMMARY_STATUSES]
        lines.append(
            f"| `{category}` | {values[0]} | {values[1]} | {values[2]} | "
            f"{values[3]} | {values[4]} | {values[5]} | {sum(values)} |"
        )
    total_values = [totals[status] for status in SUMMARY_STATUSES]
    lines.extend(
        [
            f"| **Total** | **{total_values[0]}** | **{total_values[1]}** | "
            f"**{total_values[2]}** | **{total_values[3]}** | "
            f"**{total_values[4]}** | **{total_values[5]}** | "
            f"**{sum(total_values)}** |",
            "",
            "## Declared workflow identifier dependencies",
            "",
            "Each row validates that the named implemented consumer is linked "
            "to at least one implemented producer or discovery rule in the same "
            "declared scope. The checker fails when a source is absent, deferred, "
            "intentionally omitted, edition-gated, superseded, or scope-mismatched.",
            "",
            "| Consumer rule | Identifier | Scope | Sources |",
            "| --- | --- | --- | --- |",
        ]
    )
    for dependency in workflow_dependencies:
        sources = ", ".join(
            f"{source['kind']} `{source['rule']}`" for source in dependency["sources"]
        )
        lines.append(
            f"| `{dependency['consumerRule']}` | `{dependency['identifier']}` | "
            f"`{dependency['scope']}` | {sources} |"
        )

    deferred = sorted(
        (rule for rule in rules if rule["status"] == "deferred"),
        key=lambda rule: rule["id"],
    )
    lines.extend(
        [
            "",
            "## Deferred operator-facing work",
            "",
            "These unavailable capabilities are recorded as unfinished work, not "
            "as enduring product exclusions. The entries describe only their "
            "named endpoint families.",
            "",
            "| Rule | MCP family | Capability | Reason |",
            "| --- | --- | --- | --- |",
        ]
    )
    for rule in deferred:
        lines.append(
            f"| `{rule['id']}` | `{rule['mcpFamily']}` | `{rule['capability']}` | "
            f"{rule['reason']} |"
        )
    lines.extend(
        [
            "",
            "## Maintenance",
            "",
            "The default command is read-only. It reconstructs the endpoint tree "
            "from a checked-in minimal Git repository whose version tag resolves "
            "to the pinned commit, and executes the same serialized registry used "
            "by `server.capabilities`. It fails on tag or source mismatch, an "
            "invalid snapshot, an unmapped or multiply mapped exact endpoint "
            "signature, an unknown capability ID, a disposition/capability-state "
            "mismatch, an invalid declared workflow identifier link, or "
            "generated-file drift:",
            "",
            "```sh",
            "python3 scripts/check_api_coverage.py",
            "```",
            "",
            "After intentionally changing `api-coverage/rules.json`, regenerate "
            "the checked-in artifacts:",
            "",
            "```sh",
            "python3 scripts/check_api_coverage.py --write",
            "```",
            "",
            "To refresh for a new pinned Infisical checkout, first update the "
            "target version and snapshot filename in the checker and rules. The "
            "checkout must be at the exact tag with no tracked or untracked "
            "working-tree changes; the checker rejects provenance capture from "
            "a dirty source. Refresh atomically replaces the minimal offline Git "
            "repository as well as regenerating the snapshot and derived "
            "artifacts. Then run:",
            "",
            "```sh",
            "python3 scripts/check_api_coverage.py --refresh-snapshot "
            "/path/to/infisical",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def generated_files(
    snapshot: dict[str, Any], rules_document: dict[str, Any]
) -> tuple[str, str]:
    version = rules_document.get("targetInfisicalVersion")
    if not isinstance(version, str) or not version:
        raise CoverageError("rules targetInfisicalVersion must be a non-empty string")
    endpoints = validate_pinned_snapshot(snapshot, version)
    rules = validate_rules(rules_document, capability_states(version))
    workflow_dependencies = validate_workflow_dependencies(rules_document, rules)
    rows = coverage_rows(endpoints, rules)
    return render_csv(rows), render_summary(
        snapshot, rows, rules, workflow_dependencies
    )


def write_generated(snapshot: dict[str, Any], rules_document: dict[str, Any]) -> None:
    matrix, summary = generated_files(snapshot, rules_document)
    MATRIX_PATH.write_text(matrix, encoding="utf-8")
    SUMMARY_PATH.write_text(summary, encoding="utf-8")


def check_generated(snapshot: dict[str, Any], rules_document: dict[str, Any]) -> None:
    matrix, summary = generated_files(snapshot, rules_document)
    expected = ((MATRIX_PATH, matrix), (SUMMARY_PATH, summary))
    drifted = [
        path.relative_to(ROOT).as_posix()
        for path, content in expected
        if not path.is_file() or path.read_text(encoding="utf-8") != content
    ]
    if drifted:
        raise CoverageError(
            "generated coverage artifacts drifted; run "
            f"`python3 scripts/check_api_coverage.py --write`: {', '.join(drifted)}"
        )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--write",
        action="store_true",
        help="regenerate the matrix and summary from the checked-in snapshot and rules",
    )
    action.add_argument(
        "--refresh-snapshot",
        type=Path,
        metavar="INFISICAL_CHECKOUT",
        help="replace the snapshot from an exact pinned Infisical tag and regenerate",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        rules_document = read_json(RULES_PATH)
        if arguments.refresh_snapshot is not None:
            version = rules_document.get("targetInfisicalVersion")
            if not isinstance(version, str) or not version:
                raise CoverageError(
                    "rules targetInfisicalVersion must be a non-empty string"
                )
            snapshot = snapshot_from_source(arguments.refresh_snapshot, version)
            if snapshot["source"]["commit"] != PINNED_SOURCE_COMMIT:
                raise CoverageError(
                    "source tag commit differs from PINNED_SOURCE_COMMIT; "
                    "update the reviewed pin before refreshing"
                )
            write_pinned_repository(
                arguments.refresh_snapshot.resolve(),
                PINNED_SOURCE_GIT,
                version,
                PINNED_SOURCE_COMMIT,
            )
            matrix, summary = generated_files(snapshot, rules_document)
            SNAPSHOT_PATH.write_text(canonical_json(snapshot), encoding="utf-8")
            MATRIX_PATH.write_text(matrix, encoding="utf-8")
            SUMMARY_PATH.write_text(summary, encoding="utf-8")
            print(
                f"refreshed {snapshot['counts']['total']} endpoint documents "
                f"from {snapshot['source']['tag']}"
            )
            return 0

        snapshot = read_json(SNAPSHOT_PATH)
        if arguments.write:
            write_generated(snapshot, rules_document)
            print("regenerated API coverage matrix")
            return 0

        check_generated(snapshot, rules_document)
        counts = snapshot["counts"]
        print(
            "validated API coverage: "
            f"{counts['active']} active, {counts['deprecated']} deprecated"
        )
        return 0
    except CoverageError as error:
        print(f"api coverage: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
