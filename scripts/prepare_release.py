#!/usr/bin/env python3
"""Validate a version-tagged source and write bounded release metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def validate_tag(ref: str, version: str) -> str:
    if not re.fullmatch(r"refs/tags/v[0-9]+\.[0-9]+\.[0-9]+", ref):
        raise ValueError("release requires a stable vMAJOR.MINOR.PATCH tag")
    tag = ref.removeprefix("refs/tags/")
    if tag != f"v{version}":
        raise ValueError("release tag must match the workspace version")
    return tag


def dependency_inventory(metadata: dict, allowed: set[str]) -> list[dict]:
    packages = []
    for package in metadata["packages"]:
        license_expression = package.get("license")
        if license_expression not in allowed:
            raise ValueError(
                f"review the declared license for {package['name']} {package['version']}"
            )
        packages.append({
            "name": package["name"],
            "version": package["version"],
            "license": license_expression,
        })
    return sorted(packages, key=lambda package: (package["name"], package["version"]))


def write_checksums(output: Path) -> None:
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in sorted(output.iterdir())
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    (output / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record-digest", action="store_true")
    args = parser.parse_args()
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    tag = validate_tag(os.environ.get("GITHUB_REF", ""), version)
    commit = git("rev-parse", "HEAD")
    if commit != os.environ.get("GITHUB_SHA"):
        raise ValueError("checkout must match the release event commit")
    if git("rev-parse", f"{tag}^{{commit}}") != commit:
        raise ValueError("local release tag must resolve to the checkout")
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, "origin/main"],
        cwd=ROOT, check=True,
    )
    output = ROOT / ".release"
    output.mkdir(exist_ok=True)
    if args.record_digest:
        digest = os.environ.get("IMAGE_DIGEST", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("registry returned an invalid image digest")
        (output / "image-digest.txt").write_text(
            f"ghcr.io/chrisbennight/mcp-infisical-rs@{digest}\n", encoding="utf-8"
        )
    else:
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            cwd=ROOT, text=True,
        ))
        allowed = set(json.loads((ROOT / "scripts/release-license-expressions.json").read_text()))
        inventory = dependency_inventory(metadata, allowed)
        (output / "dependencies.json").write_text(json.dumps(inventory, indent=2) + "\n")
        (output / "source.json").write_text(json.dumps({
            "repository": "https://github.com/chrisbennight/mcp-infisical-rs",
            "commit": commit,
            "tag": tag,
            "platform": "linux/amd64",
        }, indent=2) + "\n")
        for filename in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            (output / filename).write_bytes((ROOT / filename).read_bytes())
    write_checksums(output)


if __name__ == "__main__":
    main()
