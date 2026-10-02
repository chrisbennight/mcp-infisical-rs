from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check_docs  # noqa: E402


class MarkdownFileDiscoveryTests(unittest.TestCase):
    def test_ignores_git_and_cargo_build_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            kept = root / "docs" / "kept.md"
            ignored = [
                root / ".git" / "review.md",
                root / ".worktrees" / "other" / "README.md",
                root / "target" / "doc" / "generated.md",
            ]

            for path in [kept, *ignored]:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# Document\n", encoding="utf-8")

            self.assertEqual(check_docs.markdown_files(root), [kept])

    def test_documentation_validation_does_not_compile_the_server(self) -> None:
        with patch("subprocess.run", side_effect=AssertionError("documentation must not run Cargo")):
            self.assertEqual(check_docs.main(), 0)


if __name__ == "__main__":
    unittest.main()
