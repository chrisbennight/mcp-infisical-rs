"""Image evidence must identify the artifact and include its runtime packages."""

import datetime as dt
import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("check_image_security", SCRIPTS / "check_image_security.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
NOW = dt.datetime(2026, 9, 25, tzinfo=dt.timezone.utc)
IMAGE_ID = "sha256:" + "a" * 64
DIGEST = "sha256:" + "b" * 64
POLICY = {"version": 1, "exceptions": []}


def scanner():
    return {"Version": "0.70.0", "VulnerabilityDB": {
        "Version": 2,
        "UpdatedAt": (NOW - dt.timedelta(hours=2)).isoformat(),
        "DownloadedAt": (NOW - dt.timedelta(hours=1)).isoformat(),
        "NextUpdate": (NOW + dt.timedelta(hours=4)).isoformat(),
    }}


def report():
    return {
        "SchemaVersion": 2, "ArtifactType": "container_image",
        "CreatedAt": (NOW - dt.timedelta(minutes=10)).isoformat(), "Trivy": {"Version": "0.70.0"},
        "Metadata": {"ImageID": IMAGE_ID, "RepoDigests": ["registry.test/image@" + DIGEST]},
        "Results": [
            {"Class": "os-pkgs", "Type": "debian", "Target": "image (debian 12)",
             "Packages": [{"Name": "libc6"}]},
            {"Class": "lang-pkgs", "Type": "rustbinary", "Target": "mcp-infisical-rs",
             "Packages": [{"Name": name} for name in ("infisical-api", "infisical-mcp", "infisical-server")],
             "Vulnerabilities": []},
        ],
    }


def image_exception():
    return {
        "advisory": "CVE-2026-12345", "distribution": "debian", "package": "libc6",
        "version": "2.41-12+deb13u4", "owner": "Maintainers", "reviewed": "2026-09-25",
        "expires": "2026-10-25", "rationale": "Explicit, temporary acceptance for this fixture",
    }


def os_finding():
    return {"VulnerabilityID": "CVE-2026-12345", "PkgName": "libc6",
            "InstalledVersion": "2.41-12+deb13u4", "Severity": "HIGH"}


class ImageGateTests(unittest.TestCase):
    def test_validation_preserves_scan_time_and_database_evidence(self):
        original = report()
        metadata = scanner()
        result = MODULE.assess(original, POLICY, NOW, IMAGE_ID, None, metadata)
        self.assertEqual(result["scannedAt"], original["CreatedAt"])
        self.assertEqual(result["validatedAt"], NOW.isoformat())
        self.assertNotEqual(result["scannedAt"], result["validatedAt"])
        self.assertEqual(result["database"], metadata["VulnerabilityDB"])

    def test_old_future_missing_and_unqualified_scan_times_fail(self):
        for value in ((NOW - dt.timedelta(days=2)).isoformat(),
                      (NOW + dt.timedelta(hours=1)).isoformat(),
                      "2026-09-25T00:00:00", "not-a-time", None):
            with self.subTest(value=value):
                changed = report()
                changed["CreatedAt"] = value
                with self.assertRaises(ValueError):
                    MODULE.assess(changed, POLICY, NOW, IMAGE_ID, None, scanner())
        changed = report()
        del changed["CreatedAt"]
        with self.assertRaises(KeyError):
            MODULE.assess(changed, POLICY, NOW, IMAGE_ID, None, scanner())

    def test_stale_due_or_post_scan_database_is_rejected(self):
        cases = [
            ("UpdatedAt", NOW - dt.timedelta(days=3)),
            ("UpdatedAt", NOW + dt.timedelta(hours=1)),
            ("DownloadedAt", NOW + dt.timedelta(hours=1)),
            ("DownloadedAt", NOW - dt.timedelta(days=1)),
            ("NextUpdate", NOW - dt.timedelta(minutes=1)),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                metadata = scanner()
                metadata["VulnerabilityDB"][field] = value.isoformat()
                with self.assertRaises(ValueError):
                    MODULE.assess(report(), POLICY, NOW, IMAGE_ID, None, metadata)
        for field in ("UpdatedAt", "DownloadedAt", "NextUpdate", "Version"):
            metadata = scanner()
            del metadata["VulnerabilityDB"][field]
            with self.assertRaises(KeyError):
                MODULE.assess(report(), POLICY, NOW, IMAGE_ID, None, metadata)
        with self.assertRaises(KeyError):
            MODULE.assess(report(), POLICY, NOW, IMAGE_ID, None, {"Version": "0.70.0"})

    def test_report_and_database_scanner_versions_must_match_the_pin(self):
        for report_version, metadata_version in (("0.69.0", "0.70.0"),
                                                 ("0.70.0", "0.69.0")):
            changed, metadata = report(), scanner()
            changed["Trivy"]["Version"] = report_version
            metadata["Version"] = metadata_version
            with self.assertRaises(ValueError):
                MODULE.assess(changed, POLICY, NOW, IMAGE_ID, None, metadata)

    def test_requires_exact_built_or_published_identity(self):
        self.assertTrue(MODULE.assess(report(), POLICY, NOW, IMAGE_ID, None, scanner())["passed"])
        self.assertTrue(MODULE.assess(report(), POLICY, NOW, None, DIGEST, scanner())["passed"])
        for image_id, digest in ((DIGEST, None), (None, IMAGE_ID), (IMAGE_ID, DIGEST), (None, None), ("tag", None)):
            with self.assertRaises(ValueError):
                MODULE.assess(report(), POLICY, NOW, image_id, digest, scanner())

    def test_missing_runtime_inventory_fails_even_without_vulnerabilities(self):
        for index in (0, 1):
            changed = report()
            changed["Results"].pop(index)
            with self.assertRaises(ValueError):
                MODULE.assess(changed, POLICY, NOW, IMAGE_ID, None, scanner())
        changed = report()
        changed["Results"][1]["Packages"].pop()
        with self.assertRaises(ValueError):
            MODULE.assess(changed, POLICY, NOW, IMAGE_ID, None, scanner())

    def test_all_severities_are_retained_and_gate_policy_is_explicit(self):
        for severity, passed in (("LOW", True), ("MEDIUM", True), ("HIGH", False),
                                 ("CRITICAL", False), ("UNKNOWN", False)):
            changed = report()
            changed["Results"][1]["Vulnerabilities"] = [{
                "VulnerabilityID": "CVE-2026-12345", "PkgName": "example",
                "InstalledVersion": "1.0.0", "Severity": severity,
            }]
            result = MODULE.assess(changed, POLICY, NOW, IMAGE_ID, None, scanner())
            self.assertEqual(result["passed"], passed)
            self.assertEqual(result["dispositions"][0]["severity"], severity)

    def test_rust_exception_does_not_apply_to_same_named_os_package(self):
        policy = {"version": 1, "exceptions": [{
            "advisory": "RUSTSEC-2023-0071", "aliases": ["CVE-2023-49092"],
            "package": "rsa", "version": "0.9.10", "owner": "Maintainers",
            "reviewed": "2026-09-25", "expires": "2026-11-24", "rationale": "Fixture rationale",
        }]}
        changed = report()
        finding = {"VulnerabilityID": "CVE-2023-49092", "PkgName": "rsa",
                   "InstalledVersion": "0.9.10", "Severity": "HIGH"}
        changed["Results"][1]["Vulnerabilities"] = [finding]
        self.assertTrue(MODULE.assess(changed, policy, NOW, IMAGE_ID, None, scanner())["passed"])
        changed["Results"][0]["Vulnerabilities"] = [finding]
        self.assertFalse(MODULE.assess(changed, policy, NOW, IMAGE_ID, None, scanner())["passed"])

    def test_exact_os_acceptance_retains_severity_and_other_findings_still_block(self):
        entry = image_exception()
        policy = {**POLICY, "imageExceptions": [entry]}
        changed = report()
        changed["Results"][0]["Vulnerabilities"] = [os_finding()]
        result = MODULE.assess(changed, policy, NOW, IMAGE_ID, None, scanner())
        self.assertTrue(result["passed"])
        accepted = result["dispositions"][0]
        self.assertEqual(accepted["severity"], "HIGH")
        self.assertEqual(accepted["disposition"], "temporary exception")
        self.assertEqual(accepted["exception"], entry)
        for severity in ("HIGH", "CRITICAL", "UNKNOWN"):
            with self.subTest(severity=severity):
                changed["Results"][0]["Vulnerabilities"] = [
                    os_finding(), {**os_finding(), "VulnerabilityID": "CVE-2026-54321", "Severity": severity},
                ]
                result = MODULE.assess(changed, policy, NOW, IMAGE_ID, None, scanner())
                self.assertFalse(result["passed"])
                self.assertEqual(result["dispositions"][1]["disposition"], "blocked")

    def test_os_acceptance_is_bound_to_exact_finding_distribution_and_class(self):
        policy = {**POLICY, "imageExceptions": [image_exception()]}
        for field, value in (("VulnerabilityID", "CVE-2026-54321"), ("PkgName", "libgcc-s1"),
                             ("InstalledVersion", "2.41-12+deb13u5")):
            with self.subTest(field=field):
                changed = report()
                changed["Results"][0]["Vulnerabilities"] = [{**os_finding(), field: value}]
                self.assertFalse(MODULE.assess(changed, policy, NOW, IMAGE_ID, None, scanner())["passed"])
        for package_type, package_class in (("ubuntu", "os-pkgs"), ("debian", "lang-pkgs"),
                                            ("rustbinary", "lang-pkgs")):
            with self.subTest(package_type=package_type, package_class=package_class):
                changed = report()
                changed["Results"].append({
                    "Type": package_type, "Class": package_class, "Target": "other target",
                    "Vulnerabilities": [os_finding()],
                })
                self.assertFalse(MODULE.assess(changed, policy, NOW, IMAGE_ID, None, scanner())["passed"])

    def test_image_acceptance_policy_rejects_unbounded_or_invalid_entries(self):
        invalid_entries = [
            {**image_exception(), field: value} for field, value in (
                ("advisory", "CVE-*"), ("package", "lib*"), ("version", "*"),
                ("distribution", "*"), ("owner", ""), ("rationale", ""),
                ("expires", "2026-09-25"), ("expires", "2027-01-01"),
                ("reviewed", "2026-09-26"), ("reviewed", "invalid-date"),
            )
        ]
        missing_owner = image_exception()
        del missing_owner["owner"]
        invalid_entries.append(missing_owner)
        for entry in invalid_entries:
            with self.subTest(entry=entry):
                with self.assertRaises(ValueError):
                    MODULE.assess(report(), {**POLICY, "imageExceptions": [entry]},
                                  NOW, IMAGE_ID, None, scanner())
        for entries in ({}, [image_exception(), image_exception()]):
            with self.assertRaises(ValueError):
                MODULE.assess(report(), {**POLICY, "imageExceptions": entries},
                              NOW, IMAGE_ID, None, scanner())


if __name__ == "__main__":
    unittest.main()
