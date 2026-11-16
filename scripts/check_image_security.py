#!/usr/bin/env python3
"""Require image identity and Rust/OS inventory before applying image scan policy."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

from check_advisories import MAX_EXCEPTION_AGE, ROOT, validate_exceptions

MAX_SCAN_AGE = dt.timedelta(hours=24)
MAX_DATABASE_AGE = dt.timedelta(hours=48)
CLOCK_SKEW = dt.timedelta(minutes=5)


def validate_image_exceptions(policy: dict, today: dt.date) -> dict[tuple[str, str, str, str], dict]:
    """Keep OS acceptance separate from Rust advisories and exact to the package."""
    entries = policy.get("imageExceptions", [])
    if not isinstance(entries, list):
        raise ValueError("imageExceptions must be an array")
    required = {"advisory", "distribution", "package", "version", "owner", "reviewed", "expires", "rationale"}
    indexed = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError("image exception fields must match the documented policy")
        if any(not isinstance(value, str) or not value.strip() for value in entry.values()):
            raise ValueError("every image exception field must be nonempty text")
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", entry["advisory"]):
            raise ValueError("image exception must name one exact CVE")
        if entry["distribution"] != "debian":
            raise ValueError("image exception must name the supported Debian distribution")
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", entry["package"]):
            raise ValueError("image exception must name one exact Debian package")
        if not re.fullmatch(r"[0-9][0-9A-Za-z.+:~_-]*", entry["version"]):
            raise ValueError("image exception must name one exact Debian package version")
        reviewed = dt.date.fromisoformat(entry["reviewed"])
        expires = dt.date.fromisoformat(entry["expires"])
        if not reviewed <= today < expires or expires - reviewed > MAX_EXCEPTION_AGE:
            raise ValueError("image exception is expired, future-dated, or exceeds 90 days")
        key = (entry["distribution"], entry["advisory"], entry["package"], entry["version"])
        if key in indexed:
            raise ValueError("duplicate image exception")
        indexed[key] = entry
    return indexed


def timestamp(value: object) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError("scan timestamps must be timezone-aware strings")
    parsed = dt.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("scan timestamps must include a timezone")
    return parsed


def assess(report: dict, policy: dict, now: dt.datetime, image_id: str | None, digest: str | None,
           scanner: dict) -> dict:
    exceptions = validate_exceptions(policy, now.date())
    image_exceptions = validate_image_exceptions(policy, now.date())
    identity = image_id or digest
    if bool(image_id) == bool(digest) or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity or ""):
        raise ValueError("one exact image ID or published digest is required")
    if report["SchemaVersion"] != 2 or report["ArtifactType"] != "container_image":
        raise ValueError("expected a Trivy container image report")
    scanned = timestamp(report["CreatedAt"])
    if not -CLOCK_SKEW <= now - scanned <= MAX_SCAN_AGE:
        raise ValueError("image scan must be current within 24 hours")
    if scanner["Version"] != "0.70.0" or report["Trivy"]["Version"] != scanner["Version"]:
        raise ValueError("report and database metadata must use the pinned Trivy version")
    database = scanner["VulnerabilityDB"]
    if database["Version"] != 2:
        raise ValueError("unsupported vulnerability database schema")
    updated = timestamp(database["UpdatedAt"])
    downloaded = timestamp(database["DownloadedAt"])
    next_update = timestamp(database["NextUpdate"])
    if not -CLOCK_SKEW <= now - updated <= MAX_DATABASE_AGE:
        raise ValueError("image vulnerability database must be current within 48 hours")
    if updated > downloaded + CLOCK_SKEW or downloaded > scanned + CLOCK_SKEW:
        raise ValueError("database metadata must precede the recorded scan")
    if next_update <= updated or next_update < max(now, scanned):
        raise ValueError("vulnerability database update is due; scan again with a current database")
    metadata = report["Metadata"]
    if image_id and metadata["ImageID"] != image_id:
        raise ValueError("scan does not match the built image ID")
    if digest and not any(value.endswith("@" + digest) for value in metadata["RepoDigests"]):
        raise ValueError("scan does not match the published image digest")
    results = report["Results"]
    if not isinstance(results, list) or not any(item["Class"] == "os-pkgs" and item.get("Packages") for item in results):
        raise ValueError("scan must retain the runtime OS package inventory")
    rust_results = [item for item in results if item["Type"] == "rustbinary"]
    rust_packages = {package["Name"] for item in rust_results for package in item.get("Packages", [])}
    if not {"infisical-server", "infisical-api", "infisical-mcp"} <= rust_packages:
        raise ValueError("scan must include the auditable service binary and its Rust dependencies")
    dispositions = []
    for item in results:
        for finding in item.get("Vulnerabilities") or []:
            severity = finding["Severity"]
            if severity not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ValueError("unrecognized vulnerability severity")
            key = (finding["VulnerabilityID"], finding["PkgName"], finding["InstalledVersion"])
            exception = None
            if item["Type"] == "rustbinary":
                exception = exceptions.get(key)
            elif item["Class"] == "os-pkgs":
                exception = image_exceptions.get((item["Type"], *key))
            disposition = "temporary exception" if exception else (
                "blocked" if severity in {"UNKNOWN", "HIGH", "CRITICAL"} else "retained for review"
            )
            dispositions.append({
                "advisory": key[0], "package": key[1], "version": key[2],
                "severity": severity, "target": item["Target"],
                "disposition": disposition, "exception": exception,
            })
    return {
        "passed": all(item["disposition"] != "blocked" for item in dispositions),
        "imageId": metadata["ImageID"], "publishedDigest": digest,
        "scannedAt": scanned.isoformat(), "validatedAt": now.isoformat(),
        "scannerVersion": scanner["Version"],
        "database": {key: database[key] for key in ("Version", "UpdatedAt", "DownloadedAt", "NextUpdate")},
        "dispositions": dispositions,
        "policy": "High, critical, and unclassified image findings block unless explicitly excepted; lower severities remain in evidence. The separate RustSec gate covers all Rust advisory severities.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--policy", type=Path, default=ROOT / "security" / "advisory-exceptions.json")
    parser.add_argument("--scanner-metadata", type=Path, required=True)
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--image-id")
    identity.add_argument("--digest")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = assess(json.loads(args.report.read_text()), json.loads(args.policy.read_text()),
                        dt.datetime.now(dt.timezone.utc), args.image_id, args.digest,
                        json.loads(args.scanner_metadata.read_text()))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"image gate: invalid evidence: {error}", file=sys.stderr)
        return 2
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    for finding in result["dispositions"]:
        print(f"{finding['advisory']} {finding['package']} {finding['version']}: {finding['disposition']}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
