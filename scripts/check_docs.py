#!/usr/bin/env python3
"""Validate local Markdown links and reject fragile line-number anchors."""

from __future__ import annotations

import re
import sys
import subprocess

import catalog_summary
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"!?\[[^\]]*\]\((?P<target>[^)]+)\)")
LINE_ANCHOR = re.compile(r":\d+(?:#.*)?$")
REMOTE_SCHEMES = ("http://", "https://", "mailto:")
IGNORED_DIRECTORIES = frozenset({".git", "target", "node_modules", "dist"})


def markdown_files(root: Path = ROOT) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.md")
        if IGNORED_DIRECTORIES.isdisjoint(path.relative_to(root).parts)
    )


def validate(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")

    for match in LINK.finditer(text):
        raw_target = match.group("target").strip()
        target = raw_target[1:-1] if raw_target.startswith("<") and raw_target.endswith(">") else raw_target
        target = unquote(target)

        if target.startswith(REMOTE_SCHEMES) or target.startswith("#"):
            continue
        if LINE_ANCHOR.search(target):
            errors.append(f"{path.relative_to(ROOT)}: fragile line-number link: {raw_target}")
            continue

        file_part = target.split("#", maxsplit=1)[0]
        if not file_part:
            continue
        resolved = (path.parent / file_part).resolve()
        try:
            resolved.relative_to(ROOT)
        except ValueError:
            errors.append(f"{path.relative_to(ROOT)}: link escapes repository: {raw_target}")
            continue
        if not resolved.exists():
            errors.append(f"{path.relative_to(ROOT)}: missing local link target: {raw_target}")

    return errors


def main() -> int:
    files = markdown_files()
    errors = [error for path in files for error in validate(path)]
    try:
        errors.extend(catalog_summary.check())
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        errors.append(f"catalog export validation failed ({type(error).__name__})")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"validated {len(files)} Markdown files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
