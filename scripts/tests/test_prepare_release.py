from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "prepare_release", Path(__file__).resolve().parents[1] / "prepare_release.py"
)
assert SPEC is not None and SPEC.loader is not None
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


class ReleasePreparationTests(unittest.TestCase):
    def test_only_matching_stable_version_tags_are_accepted(self) -> None:
        self.assertEqual(PREPARE.validate_tag("refs/tags/v0.1.0", "0.1.0"), "v0.1.0")
        for ref in ("refs/heads/main", "refs/tags/v0.2.0", "refs/tags/v0.1.0-rc1", "refs/tags/v0.1.0\n", "refs/tags/--help"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                PREPARE.validate_tag(ref, "0.1.0")

    def test_unknown_or_missing_declared_licenses_block_preparation(self) -> None:
        for license_expression in (None, "LicenseRef-unreviewed"):
            with self.subTest(license=license_expression), self.assertRaises(ValueError):
                PREPARE.dependency_inventory({"packages": [{
                    "name": "example", "version": "1.0.0", "license": license_expression,
                }]}, {"MIT"})

    def test_inventory_excludes_local_paths_and_unrelated_metadata(self) -> None:
        result = PREPARE.dependency_inventory({"packages": [{
            "name": "example", "version": "1.0.0", "license": "MIT",
            "manifest_path": "/private/build/Cargo.toml", "metadata": {"private": "fixture"},
        }]}, {"MIT"})
        self.assertEqual(result, [{"name": "example", "version": "1.0.0", "license": "MIT"}])

    def test_checksums_cover_the_metadata_without_hashing_themselves(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "source.json").write_bytes(b"{}")
            (root / "SHA256SUMS").write_text("stale")
            PREPARE.write_checksums(root)
            self.assertEqual((root / "SHA256SUMS").read_text(),
                             f"{hashlib.sha256(b'{}').hexdigest()}  source.json\n")


if __name__ == "__main__":
    unittest.main()
