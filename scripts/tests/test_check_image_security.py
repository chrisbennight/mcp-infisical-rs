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


def report():
    return {
        "SchemaVersion": 2, "ArtifactType": "container_image",
        "Metadata": {"ImageID": IMAGE_ID, "RepoDigests": ["registry.test/image@" + DIGEST]},
        "Results": [
            {"Class": "os-pkgs", "Type": "debian", "Target": "image (debian 12)",
             "Packages": [{"Name": "libc6"}]},
            {"Class": "lang-pkgs", "Type": "rustbinary", "Target": "mcp-infisical-rs",
             "Packages": [{"Name": name} for name in ("infisical-api", "infisical-mcp", "infisical-server")],
             "Vulnerabilities": []},
        ],
    }


class ImageGateTests(unittest.TestCase):
    def test_requires_exact_built_or_published_identity(self):
        self.assertTrue(MODULE.assess(report(), POLICY, NOW, IMAGE_ID, None)["passed"])
        self.assertTrue(MODULE.assess(report(), POLICY, NOW, None, DIGEST)["passed"])
        for image_id, digest in ((DIGEST, None), (None, IMAGE_ID), (IMAGE_ID, DIGEST), (None, None), ("tag", None)):
            with self.assertRaises(ValueError):
                MODULE.assess(report(), POLICY, NOW, image_id, digest)

    def test_missing_runtime_inventory_fails_even_without_vulnerabilities(self):
        for index in (0, 1):
            changed = report()
            changed["Results"].pop(index)
            with self.assertRaises(ValueError):
                MODULE.assess(changed, POLICY, NOW, IMAGE_ID, None)
        changed = report()
        changed["Results"][1]["Packages"].pop()
        with self.assertRaises(ValueError):
            MODULE.assess(changed, POLICY, NOW, IMAGE_ID, None)

    def test_all_severities_are_retained_and_gate_policy_is_explicit(self):
        for severity, passed in (("LOW", True), ("MEDIUM", True), ("HIGH", False),
                                 ("CRITICAL", False), ("UNKNOWN", False)):
            changed = report()
            changed["Results"][1]["Vulnerabilities"] = [{
                "VulnerabilityID": "CVE-2026-12345", "PkgName": "example",
                "InstalledVersion": "1.0.0", "Severity": severity,
            }]
            result = MODULE.assess(changed, POLICY, NOW, IMAGE_ID, None)
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
        self.assertTrue(MODULE.assess(changed, policy, NOW, IMAGE_ID, None)["passed"])
        changed["Results"][0]["Vulnerabilities"] = [finding]
        self.assertFalse(MODULE.assess(changed, policy, NOW, IMAGE_ID, None)["passed"])


if __name__ == "__main__":
    unittest.main()
