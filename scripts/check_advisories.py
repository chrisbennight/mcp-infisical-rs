#!/usr/bin/env python3
"""Apply expiring, package-specific dispositions to an unfiltered RustSec report."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
MAX_DATABASE_AGE = dt.timedelta(days=14)
MAX_EXCEPTION_AGE = dt.timedelta(days=90)


def validate_exceptions(policy: dict, today: dt.date) -> dict[tuple[str, str, str], dict]:
    """Reject broad, expired, ambiguous, or undocumented exceptions."""
    if policy.get("version") != 1 or not isinstance(policy.get("exceptions"), list):
        raise ValueError("exception policy must have version 1 and an exceptions array")
    indexed = {}
    required = {"advisory", "aliases", "package", "version", "owner", "reviewed", "expires", "rationale"}
    for entry in policy["exceptions"]:
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError("exception fields must match the documented policy")
        if any(not isinstance(entry[key], str) or not entry[key].strip() for key in required - {"aliases"}):
            raise ValueError("every exception field must be nonempty text")
        aliases = entry["aliases"]
        if not isinstance(aliases, list) or any(
            not isinstance(alias, str) or not re.fullmatch(r"(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", alias)
            for alias in aliases
        ):
            raise ValueError("exception aliases must be exact CVE or GHSA identifiers")
        if not re.fullmatch(r"RUSTSEC-\d{4}-\d{4}", entry["advisory"]):
            raise ValueError("exception must name one RustSec advisory")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", entry["package"]):
            raise ValueError("exception must name one package")
        if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", entry["version"]):
            raise ValueError("exception must name one exact package version")
        reviewed = dt.date.fromisoformat(entry["reviewed"])
        expires = dt.date.fromisoformat(entry["expires"])
        if not reviewed <= today < expires or expires - reviewed > MAX_EXCEPTION_AGE:
            raise ValueError("exception is expired, future-dated, or exceeds 90 days")
        for advisory in [entry["advisory"], *aliases]:
            key = (advisory, entry["package"], entry["version"])
            if key in indexed:
                raise ValueError("duplicate exception or alias")
            indexed[key] = entry
    return indexed


def assess(report: dict, policy: dict, now: dt.datetime) -> dict:
    """Fail closed on incomplete reports or scanner-side advisory filtering."""
    exceptions = validate_exceptions(policy, now.date())
    database = report["database"]
    revision = database["last-commit"]
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("report must record the advisory database commit")
    updated = dt.datetime.fromisoformat(database["last-updated"])
    if updated.tzinfo is None or not -dt.timedelta(days=1) <= now - updated <= MAX_DATABASE_AGE:
        raise ValueError("advisory database must be current within 14 days")
    if not isinstance(database["advisory-count"], int) or database["advisory-count"] <= 0:
        raise ValueError("advisory database must not be empty")
    settings = report["settings"]
    if any(settings[key] != [] for key in ("ignore", "target_arch", "target_os")):
        raise ValueError("scanner must not ignore advisories or filter platforms")
    if settings["severity"] is not None:
        raise ValueError("scanner must report all advisory severities")
    if set(settings["informational_warnings"]) != {"notice", "unmaintained", "unsound"}:
        raise ValueError("scanner must retain informational warnings")
    vulnerabilities = report["vulnerabilities"]
    findings = vulnerabilities["list"]
    if not isinstance(findings, list) or vulnerabilities["count"] != len(findings):
        raise ValueError("incomplete vulnerability report")
    if vulnerabilities["found"] is not bool(findings):
        raise ValueError("inconsistent vulnerability report")
    dispositions = []
    for finding in findings:
        advisory = finding["advisory"]["id"]
        package = finding["package"]
        key = (advisory, package["name"], package["version"])
        exception = exceptions.get(key) if package["source"] == REGISTRY else None
        dispositions.append({
            "advisory": advisory,
            "package": package["name"],
            "version": package["version"],
            "disposition": "temporary exception" if exception else "blocked",
            "exception": exception,
        })
    warnings = report["warnings"]
    if not isinstance(warnings, dict) or any(not isinstance(v, list) for v in warnings.values()):
        raise ValueError("incomplete informational warning report")
    return {
        "database": database,
        "scannedAt": now.isoformat(),
        "passed": all(item["exception"] is not None for item in dispositions),
        "dispositions": dispositions,
        "informationalWarnings": warnings,
        "warningPolicy": "Retained for review; vulnerability advisories block unless excepted.",
        "yankedPackageCheck": "Not included; this gate checks RustSec advisories.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--policy", type=Path, default=ROOT / "security" / "advisory-exceptions.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = assess(
            json.loads(args.report.read_text()),
            json.loads(args.policy.read_text()),
            dt.datetime.now(dt.timezone.utc),
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"advisory gate: invalid evidence: {error}", file=sys.stderr)
        return 2
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    for finding in result["dispositions"]:
        print(f"{finding['advisory']} {finding['package']} {finding['version']}: {finding['disposition']}")
    print(f"advisory database: {result['database']['last-commit']}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
