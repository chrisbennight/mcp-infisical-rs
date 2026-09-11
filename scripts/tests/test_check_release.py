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

    def test_publication_without_verification_dependency_is_rejected(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        broken = workflow.replace(
            "    needs: verify\n",
            "    # needs: verify\n",
        )
        self.assertIn(
            "publish job must depend on verify",
            CHECK_RELEASE.validate_build_workflow(broken),
        )

    def test_manual_publication_from_non_main_is_rejected(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        broken = workflow.replace(
            "    if: github.ref == 'refs/heads/main'\n",
            "    if: github.event_name == 'workflow_dispatch'\n",
        )
        self.assertIn(
            "publish job must reject non-main workflow dispatches",
            CHECK_RELEASE.validate_build_workflow(broken),
        )

    def test_rolling_tag_marker_in_unrelated_step_is_rejected(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        broken = workflow.replace(
            '          docker push "${IMAGE}:latest"\n',
            '          # docker push "${IMAGE}:latest"\n',
        )
        self.assertIn(
            "'Publish image' step is missing command: docker push \"${IMAGE}:latest\"",
            CHECK_RELEASE.validate_build_workflow(broken),
        )

    def test_publication_must_emit_the_immutable_digest(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        broken = workflow.replace(
            '          echo "digest=$digest" >> "$GITHUB_OUTPUT"\n',
            '          # echo "digest=$digest" >> "$GITHUB_OUTPUT"\n',
        )
        self.assertIn(
            "image publication must emit its immutable registry digest",
            CHECK_RELEASE.validate_build_workflow(broken),
        )

    def test_publication_must_dispatch_the_gated_docker_home_update(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        for marker in (
            '"image": "gitea.cacahuate.org/bennight/mcp-infisical-rs",',
            '"source_sha": os.environ["SOURCE_SHA"],',
            '"digest": os.environ["IMAGE_DIGEST"],',
            "class RejectRedirect(urllib.request.HTTPRedirectHandler):",
            'raise RuntimeError("docker-home workflow redirects are forbidden")',
            '"https://gitea.cacahuate.org/api/v1/repos/bennight/docker-home/"',
            '"actions/workflows/update-first-party-image.yml/dispatches",',
            "opener = urllib.request.build_opener(RejectRedirect())",
        ):
            with self.subTest(marker=marker):
                active_line = next(
                    line
                    for line in workflow.splitlines()
                    if line.strip() == marker
                )
                indentation = active_line[: -len(active_line.lstrip())]
                broken = workflow.replace(
                    f"{active_line}\n",
                    f"{indentation}# {marker}\n",
                    1,
                )
                self.assertTrue(
                    any(
                        "docker-home image update step is missing contract marker"
                        in error
                        for error in CHECK_RELEASE.validate_build_workflow(
                            broken
                        )
                    )
                )

    def test_docker_home_dispatch_must_not_use_the_default_opener(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        broken = workflow.replace(
            "with opener.open(request, timeout=30) as response:",
            "with urllib.request.urlopen(request, timeout=30) as response:",
        )
        self.assertIn(
            "docker-home image update must not use the redirecting opener",
            CHECK_RELEASE.validate_build_workflow(broken),
        )

    def test_docker_home_dispatch_script_is_valid_python(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        jobs = CHECK_RELEASE._mapping_block(workflow, "jobs", 0)
        publish = CHECK_RELEASE._mapping_block(jobs or "", "publish", 2)
        dispatch = CHECK_RELEASE._named_step_block(
            publish or "", "Request docker-home image update"
        )
        self.assertIsNotNone(dispatch)
        python_source = (
            dispatch.split("python3 - <<'PY'\n", 1)[1]
            .rsplit("\n          PY", 1)[0]
        )
        python_source = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in python_source.splitlines()
        )
        compile(python_source, str(CHECK_RELEASE.BUILD_WORKFLOW), "exec")

    def test_publication_runs_are_serialized_without_cancellation(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        broken = workflow.replace(
            "  group: mcp-infisical-rs-build-publication\n",
            "  group: mcp-infisical-rs-build-${{ github.ref }}\n",
        )
        self.assertIn(
            "build workflow must globally serialize shared-tag publication",
            CHECK_RELEASE.validate_build_workflow(broken),
        )

    def test_immutable_tag_uses_the_full_commit_sha(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        broken = workflow.replace(
            "sha-${{ github.sha }}",
            "sha-${GITHUB_SHA::12}",
        )
        self.assertIn(
            "immutable image tag must derive once from the full commit SHA",
            CHECK_RELEASE.validate_build_workflow(broken),
        )

    def test_cleanup_requires_an_explicit_always_step(self) -> None:
        workflow = CHECK_RELEASE.BUILD_WORKFLOW.read_text(encoding="utf-8")
        broken = workflow.replace(
            "      - name: Remove registry authentication\n"
            "        if: always()\n",
            "      - name: Remove registry authentication\n"
            "        # if: always()\n",
        )
        self.assertIn(
            "'Remove registry authentication' step must run with if: always()",
            CHECK_RELEASE.validate_build_workflow(broken),
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
