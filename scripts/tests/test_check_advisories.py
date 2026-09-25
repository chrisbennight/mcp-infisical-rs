"""Regression evidence for advisory gating and narrow exceptions."""

import copy
import datetime as dt
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("check_advisories", Path(__file__).resolve().parents[1] / "check_advisories.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
NOW = dt.datetime(2026, 9, 25, tzinfo=dt.timezone.utc)


def report():
    return {
        "database": {"last-commit": "a" * 40, "last-updated": NOW.isoformat(), "advisory-count": 1},
        "settings": {"ignore": [], "target_arch": [], "target_os": [], "severity": None,
                     "informational_warnings": ["unmaintained", "unsound", "notice"]},
        "vulnerabilities": {"found": True, "count": 1, "list": [{
            "advisory": {"id": "RUSTSEC-2023-0071"},
            "package": {"name": "rsa", "version": "0.9.10", "source": MODULE.REGISTRY},
        }]},
        "warnings": {},
    }


def policy():
    return {"version": 1, "exceptions": [{
        "advisory": "RUSTSEC-2023-0071", "aliases": ["CVE-2023-49092"], "package": "rsa", "version": "0.9.10",
        "owner": "Maintainers", "reviewed": "2026-09-25", "expires": "2026-11-24",
        "rationale": "Only public verification is called in this fixture.",
    }]}


class AdvisoryGateTests(unittest.TestCase):
    def test_exact_exception_is_recorded_and_other_findings_block(self):
        self.assertTrue(MODULE.assess(report(), policy(), NOW)["passed"])
        for field, value in (("name", "other"), ("version", "0.9.11"), ("source", "git+https://example.test/repo")):
            changed = report()
            changed["vulnerabilities"]["list"][0]["package"][field] = value
            self.assertFalse(MODULE.assess(changed, policy(), NOW)["passed"])
        changed = report()
        changed["vulnerabilities"]["list"][0]["advisory"]["id"] = "RUSTSEC-2026-0001"
        self.assertFalse(MODULE.assess(changed, policy(), NOW)["passed"])

    def test_expired_future_wildcard_and_long_exceptions_fail(self):
        for field, value in (("expires", "2026-09-25"), ("reviewed", "2026-09-26"),
                             ("expires", "2027-01-01"), ("version", "*"), ("owner", "")):
            with self.subTest(field=field, value=value):
                changed = policy()
                changed["exceptions"][0][field] = value
                with self.assertRaises(ValueError):
                    MODULE.assess(report(), changed, NOW)

    def test_duplicate_exceptions_fail(self):
        changed = policy()
        changed["exceptions"].append(copy.deepcopy(changed["exceptions"][0]))
        with self.assertRaises(ValueError):
            MODULE.assess(report(), changed, NOW)

    def test_stale_unidentified_empty_and_future_database_fail(self):
        for field, value in (("last-commit", None), ("last-commit", "abc"), ("advisory-count", 0),
                             ("last-updated", "2026-09-01T00:00:00Z"),
                             ("last-updated", "2026-09-28T00:00:00Z"),
                             ("last-updated", "2026-09-25T00:00:00")):
            changed = report()
            changed["database"][field] = value
            with self.assertRaises(ValueError):
                MODULE.assess(changed, policy(), NOW)

    def test_scanner_filters_and_inconsistent_report_fail(self):
        for field, value in (("ignore", ["RUSTSEC-2023-0071"]), ("target_os", ["linux"]),
                             ("target_arch", ["x86_64"]), ("severity", "high"),
                             ("informational_warnings", [])):
            changed = report()
            changed["settings"][field] = value
            with self.assertRaises(ValueError):
                MODULE.assess(changed, policy(), NOW)
        for field, value in (("count", 0), ("found", False)):
            changed = report()
            changed["vulnerabilities"][field] = value
            with self.assertRaises(ValueError):
                MODULE.assess(changed, policy(), NOW)

    def test_clean_report_passes_and_informational_warnings_are_retained(self):
        changed = report()
        changed["vulnerabilities"] = {"found": False, "count": 0, "list": []}
        changed["warnings"] = {"unmaintained": [{"package": {"name": "example"}}]}
        result = MODULE.assess(changed, policy(), NOW)
        self.assertTrue(result["passed"])
        self.assertEqual(result["informationalWarnings"], changed["warnings"])


if __name__ == "__main__":
    unittest.main()
