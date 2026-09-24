"""Keep reviewed Rustup versions paired with upstream installer digests."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]

# Independently verified against the downloaded Linux x86_64 installer and:
# https://static.rust-lang.org/rustup/archive/1.29.1/x86_64-unknown-linux-gnu/rustup-init.sha256
# New releases require the same artifact verification, not a copied workflow hash.
REVIEWED_INSTALLERS = {
    "1.29.1": "dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71",
}


class RustupChecksumTests(unittest.TestCase):
    def test_workflow_installer_pins_match_reviewed_release(self) -> None:
        declarations = 0
        for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            versions = re.findall(r'^\s*RUSTUP_INIT_VERSION:', text, re.MULTILINE)
            pairs = re.findall(
                r'^\s*RUSTUP_INIT_VERSION: "([^"]+)"\s*\n'
                r'\s*RUSTUP_INIT_SHA256: "([0-9a-f]{64})"$',
                text,
                re.MULTILINE,
            )
            self.assertEqual(len(pairs), len(versions), workflow.name)
            declarations += len(pairs)
            for version, checksum in pairs:
                with self.subTest(workflow=workflow.name, version=version):
                    self.assertIn(version, REVIEWED_INSTALLERS)
                    self.assertEqual(checksum, REVIEWED_INSTALLERS[version])
        self.assertGreater(declarations, 0, "No Rustup installer pins were checked")


if __name__ == "__main__":
    unittest.main()
