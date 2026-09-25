from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "check_release.py"
SPEC = importlib.util.spec_from_file_location("check_release", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECK_RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK_RELEASE)


class TestReleaseContract(unittest.TestCase):
    def test_image_freshness_evidence_uses_the_scan_cache(self) -> None:
        for path, validate, directory in (
            (CHECK_RELEASE.GITHUB_TEST_WORKFLOW, CHECK_RELEASE.validate_github_test_workflow, ".security"),
            (CHECK_RELEASE.BUILD_WORKFLOW, CHECK_RELEASE.validate_build_workflow, ".release"),
        ):
            workflow = path.read_text(encoding="utf-8")
            for marker in (
                "          cache-dir: .cache/trivy",
                f"          trivy --cache-dir .cache/trivy version --format json > {directory}/trivy-metadata.json",
                f"            --scanner-metadata {directory}/trivy-metadata.json",
            ):
                with self.subTest(path=path, marker=marker):
                    self.assertIn(marker, workflow)
                    self.assertTrue(validate(workflow.replace(marker, "")))

    def test_github_checks_preserve_validation_and_runtime_hardening(self) -> None:
        workflow = CHECK_RELEASE.GITHUB_TEST_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(CHECK_RELEASE.validate_github_test_workflow(workflow), [])
        for before, after, expected in (
            ("contents: read", "contents: write", "contents: read permissions"),
            ("run: cargo test --workspace --all-features --locked", "run: true", "must run cargo test"),
            ("--cap-drop ALL", "--cap-drop NET_RAW", "Smoke hardened runtime container"),
            ("runs-on: ubuntu-latest", "runs-on: self-hosted", "hosted Ubuntu runner"),
        ):
            with self.subTest(change=before):
                self.assertIn(before, workflow)
                errors = CHECK_RELEASE.validate_github_test_workflow(
                    workflow.replace(before, after)
                )
                self.assertTrue(any(expected in error for error in errors), errors)

    def test_publication_guards_cannot_be_removed(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        for marker in (
            "    needs: verify",
            "    if: github.event.repository.private == false && vars.ENABLE_RELEASE_PUBLICATION == 'true'",
            "          provenance: mode=max",
            "        run: python3 scripts/prepare_release.py",
            "          subject-digest: ${{ steps.image.outputs.digest }}",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, workflow)
                broken = workflow.replace(marker, "# " + marker)
                self.assertTrue(CHECK_RELEASE.validate_build_workflow(broken))
        self.assertTrue(CHECK_RELEASE.validate_build_workflow(
            workflow.replace("      packages: write", "      contents: write")
        ))

    def test_guard_text_in_another_job_does_not_authorize_publication(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        broken = workflow.replace("    needs: verify\n", "").replace(
            "  verify:\n", "  verify:\n    needs: verify\n"
        )
        self.assertTrue(CHECK_RELEASE.validate_build_workflow(broken))

    def test_repository_release_contract_is_valid(self) -> None:
        self.assertEqual(
            CHECK_RELEASE.validate_dockerfile(
                CHECK_RELEASE.DOCKERFILE.read_text(encoding="utf-8")
            ),
            [],
        )
        self.assertEqual(
            CHECK_RELEASE.validate_build_workflow(
                CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
            ),
            [],
        )
        self.assertEqual(
            CHECK_RELEASE.validate_test_workflow(
                CHECK_RELEASE.TEST_WORKFLOW.read_text(encoding="utf-8")
            ),
            [],
        )

    def test_image_qualification_must_precede_release_tag_promotion(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        qualify = CHECK_RELEASE._named_step_block(workflow, "Qualify release image and produce runtime SBOM")
        self.assertIsNotNone(qualify)
        broken = workflow.replace(qualify + "\n", "")
        marker = "      - name: Attest published image\n"
        broken = broken.replace(marker, qualify + "\n" + marker)
        self.assertIn("release image must be scanned and qualified before promotion and attestation",
                      CHECK_RELEASE.validate_build_workflow(broken))

    def test_security_evidence_and_scanner_coverage_are_required(self) -> None:
        workflow = CHECK_RELEASE.GITHUB_TEST_WORKFLOW.read_text(encoding="utf-8")
        for marker in ("          list-all-pkgs: 'true'", "          ignore-unfixed: 'false'",
                       "            --output .security/advisory-dispositions.json",
                       "            --image-id \"$image_id\" --output .security/image-dispositions.json"):
            self.assertIn(marker, workflow)
            self.assertTrue(CHECK_RELEASE.validate_github_test_workflow(workflow.replace(marker, "# " + marker)))

    def test_undigested_builder_is_rejected(self) -> None:
        dockerfile = CHECK_RELEASE.DOCKERFILE.read_text(encoding="utf-8")
        broken = dockerfile.replace(
            "rust:${RUST_VERSION}-slim-bookworm@sha256:"
            "e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3",
            "rust:${RUST_VERSION}-slim-bookworm",
        )
        self.assertTrue(
            any(
                "not digest-pinned" in error
                for error in CHECK_RELEASE.validate_dockerfile(broken)
            )
        )

    def test_commented_non_root_user_is_rejected(self) -> None:
        dockerfile = CHECK_RELEASE.DOCKERFILE.read_text(encoding="utf-8")
        broken = dockerfile.replace(
            "USER nonroot:nonroot\n",
            "# USER nonroot:nonroot\n",
        )
        self.assertIn(
            "Dockerfile is missing explicit non-root user",
            CHECK_RELEASE.validate_dockerfile(broken),
        )

    def test_commented_healthcheck_is_rejected(self) -> None:
        dockerfile = CHECK_RELEASE.DOCKERFILE.read_text(encoding="utf-8")
        broken = dockerfile.replace(
            "HEALTHCHECK --interval=30s --timeout=3s --retries=3 \\\n",
            "# HEALTHCHECK --interval=30s --timeout=3s --retries=3 \\\n",
        )
        self.assertIn(
            "Dockerfile is missing native healthcheck",
            CHECK_RELEASE.validate_dockerfile(broken),
        )


    def test_hardening_marker_outside_smoke_step_is_rejected(self) -> None:
        workflow = CHECK_RELEASE.TEST_WORKFLOW.read_text(encoding="utf-8")
        broken = workflow.replace(
            "            --read-only \\\n",
            "            # --read-only \\\n",
        )
        self.assertIn(
            "'Smoke hardened runtime container' step is missing command: --read-only \\",
            CHECK_RELEASE.validate_test_workflow(broken),
        )

    def test_runtime_metadata_inspection_cannot_be_removed(self) -> None:
        workflow = CHECK_RELEASE.TEST_WORKFLOW.read_text(encoding="utf-8")
        broken = workflow.replace(
            '          test "$configured_user" = "nonroot:nonroot"\n',
            '          # test "$configured_user" = "nonroot:nonroot"\n',
        )
        self.assertIn(
            "'Inspect runtime image metadata' step is missing command: "
            'test "$configured_user" = "nonroot:nonroot"',
            CHECK_RELEASE.validate_test_workflow(broken),
        )


if __name__ == "__main__":
    unittest.main()
