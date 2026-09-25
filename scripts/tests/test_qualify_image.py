from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "qualify_image", Path(__file__).resolve().parents[1] / "qualify_image.py"
)
assert SPEC and SPEC.loader
QUALIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFY)


class TestImageQualification(unittest.TestCase):
    def exercise(self, *, compiler="1.98.1", fail_tests=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.98.1"\n')
        for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            (root / name).write_text("fixture notice")
        output = root / "evidence"
        commands = []

        def run(argv, **kwargs):
            commands.append(argv)
            stdout = ""
            if argv[:2] == ["docker", "create"]:
                stdout = "a" * 64
            elif argv[:2] == ["docker", "cp"]:
                Path(argv[3]).write_text(
                    f"rustc {compiler} (fixture)\n" if argv[3].endswith("rustc.txt") else "fixture binary"
                )
            elif argv[:3] == ["docker", "container", "inspect"]:
                stdout = "sha256:" + "b" * 64
            elif argv[0] == "cargo":
                binary = Path(kwargs["env"]["INFISICAL_QUALIFICATION_BINARY"])
                self.assertEqual(binary.read_text(), "fixture binary")
                if fail_tests:
                    raise subprocess.CalledProcessError(1, argv)
            return subprocess.CompletedProcess(argv, 0, stdout=stdout)

        with patch.object(QUALIFY, "ROOT", root), patch.object(QUALIFY, "run", side_effect=run), \
                patch.object(QUALIFY.platform, "system", return_value="Linux"), \
                patch.object(QUALIFY.platform, "machine", return_value="x86_64"), \
                patch("sys.argv", ["qualify_image.py", "--image", "fixture@sha256:" + "b" * 64,
                                   "--output", str(output)]):
            if compiler != "1.98.1":
                with self.assertRaisesRegex(ValueError, "compiler differs"):
                    QUALIFY.main()
            elif fail_tests:
                with self.assertRaises(subprocess.CalledProcessError):
                    QUALIFY.main()
            else:
                QUALIFY.main()
        self.assertIn(["docker", "rm", "-v", "a" * 64], commands)
        return output, commands

    def test_failed_protocol_tests_cannot_produce_a_qualified_archive(self):
        output, _ = self.exercise(fail_tests=True)
        self.assertFalse((output / "client-qualification.json").exists())
        self.assertFalse((output / "mcp-infisical-rs-linux-x86_64.tar.gz").exists())

    def test_unexpected_compiler_stops_before_client_execution(self):
        output, commands = self.exercise(compiler="1.96.1")
        self.assertFalse(any(command[0] == "cargo" for command in commands))
        self.assertFalse((output / "client-qualification.json").exists())

    def test_qualified_archive_records_the_tested_image(self):
        output, _ = self.exercise()
        evidence = json.loads((output / "client-qualification.json").read_text())
        self.assertEqual(evidence["imageId"], "sha256:" + "b" * 64)
        self.assertEqual(evidence["exit"], 0)
        self.assertTrue((output / evidence["nativeArchive"]).is_file())
