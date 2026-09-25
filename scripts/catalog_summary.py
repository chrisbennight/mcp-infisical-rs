#!/usr/bin/env python3
"""Generate documentation from executable operation and capability exports."""

from __future__ import annotations

import argparse
from collections import Counter
import html
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "docs" / "generated-catalog.md"
IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]+\Z")
PROFILES = ("metadata", "secrets", "pkiSsh", "full")
EXECUTORS = ("infisical.read", "infisical.readAudited", "infisical.write", "infisical.destroy")


def identifier(value: object) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("export contains an invalid identifier")
    return value


def cell(value: str) -> str:
    return html.escape(" ".join(value.split())).replace("|", "&#124;")


def schema_field(root: dict, path: list[str]) -> dict:
    node = root
    for component in [*path, None]:
        seen: set[str] = set()
        while "$ref" in node or "anyOf" in node:
            if "anyOf" in node:
                branches = node["anyOf"]
                values = [branch for branch in branches if branch != {"type": "null"}]
                if len(branches) != 2 or len(values) != 1:
                    raise ValueError("workflow field has an ambiguous schema union")
                node = values[0]
                continue
            reference = node["$ref"]
            if not isinstance(reference, str) or not reference.startswith("#/") or reference in seen:
                raise ValueError("workflow field has an unsupported or cyclic schema reference")
            seen.add(reference)
            node = root
            for key in reference[2:].split("/"):
                node = node[key.replace("~1", "/").replace("~0", "~")]
        if component is None:
            return node
        node = node["items"] if component == "[]" else node["properties"][component]
    raise ValueError("workflow field path could not be resolved")


def workflow_rows(operations: list[dict], workflows: list[dict]) -> list[str]:
    by_name = {item["operation"]: item for item in operations}
    rows = []
    seen: set[str] = set()
    for workflow in workflows:
        if set(workflow) != {"name", "source", "outputPath", "consumer", "inputPath", "scope"}:
            raise ValueError("workflow must be a closed identifier-handoff object")
        if workflow["name"] in seen:
            raise ValueError("duplicate workflow name")
        seen.add(workflow["name"])
        source = by_name[identifier(workflow["source"])]
        consumer = by_name[identifier(workflow["consumer"])]
        for name in ("outputPath", "inputPath"):
            path = workflow[name]
            if not isinstance(path, list) or not path or any(not isinstance(part, str) for part in path):
                raise ValueError("workflow field paths must be nonempty string arrays")
        output = schema_field(source["outputSchema"], workflow["outputPath"])
        argument = schema_field(consumer["inputSchema"], workflow["inputPath"])
        if output.get("type") != "string" or argument.get("type") != "string":
            raise ValueError("workflow handoff must join string identifier fields")
        output_path = cell(".".join(workflow["outputPath"]))
        input_path = cell(".".join(workflow["inputPath"]))
        rows.append(f"| {cell(workflow['name'])} | `{source['operation']}`: `{output_path}` | `{consumer['operation']}`: `{input_path}` | {cell(workflow['scope'])} |")
    return rows


def render(policy: dict, capabilities: dict, workflows: list[dict] | None = None) -> str:
    revision = identifier(policy["schemaRevision"])
    if revision != capabilities["schemaRevision"]:
        raise ValueError("operation and capability schema revisions differ")
    operations = policy["operations"]
    ledger = capabilities["capabilities"]
    names = [identifier(item["operation"]) for item in operations]
    ledger_names = [identifier(item["name"]) for item in ledger]
    if len(set(names)) != len(names) or len(set(ledger_names)) != len(ledger_names):
        raise ValueError("export contains duplicate operation or capability identifiers")
    domains: dict[str, Counter] = {}
    executors: Counter = Counter()
    profiles: Counter = Counter()
    for operation in operations:
        name = identifier(operation["operation"])
        if operation["executor"] not in EXECUTORS:
            raise ValueError("export contains an unknown executor")
        if not isinstance(operation["profiles"], list) or any(
            profile not in PROFILES for profile in operation["profiles"]
        ) or len(set(operation["profiles"])) != len(operation["profiles"]):
            raise ValueError("export contains invalid profile membership")
        for field in ("credentialDisclosure", "requiresFileTransfer"):
            if type(operation[field]) is not bool:
                raise ValueError("export contains an invalid policy flag")
        properties = operation["inputSchema"].get("properties", {})
        if not isinstance(properties, dict):
            raise ValueError("export contains invalid schema properties")
        counts = domains.setdefault(name.split(".")[0], Counter())
        counts["operations"] += 1
        counts["disclosure"] += operation["credentialDisclosure"]
        counts["delivery"] += "delivery" in properties
        counts["requires_files"] += operation["requiresFileTransfer"]
        executors[operation["executor"]] += 1
        profiles.update(operation["profiles"])
    for item in ledger:
        if type(item["available"]) is not bool:
            raise ValueError("export contains an invalid availability flag")
        if not item["available"] and not isinstance(item.get("reason"), str):
            raise ValueError("unavailable capability lacks its reason")
        counts = domains.setdefault(item["name"].split(".")[0], Counter())
        counts["available" if item["available"] else "unavailable"] += 1

    lines = [
        "# Generated catalog summary", "",
        "Generated from the executable `operation_policy` and `server_capabilities` exports.",
        "Run `python3 scripts/catalog_summary.py --write` to regenerate; ordinary",
        "documentation validation checks this file for drift.", "",
        f"Schema revision: `{revision}`. Pinned upstream: `{identifier(capabilities['targetInfisicalVersion'])}`.", "",
        f"This build serves **{len(operations)} operations**. The separate capability ledger has",
        f"**{sum(item['available'] for item in ledger)} implemented** and",
        f"**{sum(not item['available'] for item in ledger)} unavailable** entries. Ledger entries",
        "describe capabilities and are not a count of callable operations.", "",
        "These are build facts. Check the instance's `server.capabilities` and",
        "`operations.describe` for its profile and delivery prerequisites. Upstream",
        "permissions and edition entitlement are not probed by these exports. See",
        "[task guides](tasks.md), [operation policy](operation-policy.md), and",
        "[API coverage](api-coverage.md) for those separate decisions.", "",
        "## Executor classes", "", "| Executor | Operations |", "| --- | ---: |",
    ]
    lines.extend(f"| `{name}` | {executors[name]} |" for name in EXECUTORS)
    lines += ["", "Audited reads, mutation classes, destructive effects, credential disclosure,",
              "and confirmation fields are separate policy facts. A class is not caller",
              "authorization and does not prove every action changes durable configuration.",
              "", "## Startup profile membership", "", "| Profile | Enabled operations |", "| --- | ---: |"]
    lines.extend(f"| `{name}` | {profiles[name]} |" for name in PROFILES)
    lines += ["", "## Domain and delivery facts", "",
              "The domain is the first component of the exported name. Secret delivery counts",
              "identify operations with a `delivery` argument; actual reference availability",
              "depends on the instance. Every executor also supports whole-result file delivery",
              "when the file plane is enabled. Inline errors remain inline.", "",
              "| Domain | Operations | May disclose credentials | Secret delivery argument | Requires file plane | Implemented ledger entries | Unavailable ledger entries |",
              "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for domain, counts in sorted(domains.items()):
        values = [counts[key] for key in ("operations", "disclosure", "delivery", "requires_files", "available", "unavailable")]
        lines.append(f"| `{domain}` | " + " | ".join(map(str, values)) + " |")
    lines += ["", "## Unavailable compiled capabilities", "",
              "This list preserves each exported reason. Edition-gated and deferred API routes",
              "are classified separately in the coverage matrix; availability here does not",
              "establish licensing, caller permission, or deployment readiness.", "",
              "| Capability | Reason |", "| --- | --- |"]
    for item in sorted(ledger, key=lambda item: item["name"]):
        if not item["available"]:
            lines.append(f"| `{item['name']}` | {cell(item['reason'])} |")
    lines += ["", "## Checked identifier handoffs", "",
              "These declared links are checked against the exported operation names and",
              "input/output schema fields. They prove field presence and string types, not",
              "caller authority, complete lifecycle coverage, or permission to change scope.", "",
              "| Task | Source field | Consumer field | Scope to preserve |",
              "| --- | --- | --- | --- |"]
    lines.extend(workflow_rows(operations, workflows or []))
    return "\n".join(lines) + "\n"


def export(example: str) -> dict:
    result = subprocess.run(
        ["cargo", "run", "--quiet", "--locked", "-p", "infisical-mcp", "--example", example],
        cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True,
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("offline export must be an object")
    return value


def generated() -> str:
    workflows = json.loads((ROOT / "docs" / "workflows.json").read_text(encoding="utf-8"))
    if not isinstance(workflows, list):
        raise ValueError("workflow declarations must be an array")
    return render(export("operation_policy"), export("server_capabilities"), workflows)


def check() -> list[str]:
    expected = generated()
    if not DESTINATION.exists() or DESTINATION.read_text(encoding="utf-8") != expected:
        return ["docs/generated-catalog.md is stale; run python3 scripts/catalog_summary.py --write"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        if args.write:
            DESTINATION.write_text(generated(), encoding="utf-8")
        else:
            errors = check()
            if errors:
                print("\n".join(errors), file=sys.stderr)
                return 1
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"catalog generation failed ({type(error).__name__}); inspect the offline export contracts", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
