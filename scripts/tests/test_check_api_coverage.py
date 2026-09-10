from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check_api_coverage  # noqa: E402


def initialize_source_checkout(root: Path) -> Path:
    document = (
        root
        / "docs"
        / "api-reference"
        / "endpoints"
        / "kms"
        / "read.mdx"
    )
    document.parent.mkdir(parents=True)
    document.write_text(
        '---\ntitle: "Read key"\nopenapi: "GET /api/v1/kms/keys/{keyId}"\n---\n',
        encoding="utf-8",
    )
    for arguments in (
        ("init",),
        ("config", "user.email", "coverage@example.invalid"),
        ("config", "user.name", "Coverage Test"),
        ("add", "."),
        ("commit", "-m", "fixture"),
        ("tag", "v0.160.12"),
    ):
        subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
    return document


class EndpointSnapshotTests(unittest.TestCase):
    def test_parses_and_normalizes_openapi_frontmatter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            document = root / "kms" / "keys" / "read.mdx"
            document.parent.mkdir(parents=True)
            document.write_text(
                '---\ntitle: "Read key"\nopenapi: "Get /api/v1/kms/keys/{keyId}"\n---\n',
                encoding="utf-8",
            )

            self.assertEqual(
                check_api_coverage.parse_endpoint(document, root),
                {
                    "deprecated": False,
                    "document": "kms/keys/read.mdx",
                    "method": "GET",
                    "path": "/api/v1/kms/keys/{keyId}",
                    "title": "Read key",
                },
            )

    def test_snapshot_refresh_rejects_dirty_tracked_and_untracked_sources(self) -> None:
        for dirty_kind in ("tracked", "untracked"):
            with self.subTest(dirty_kind=dirty_kind), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                document = initialize_source_checkout(root)

                clean_snapshot = check_api_coverage.snapshot_from_source(
                    root, "0.160.12"
                )
                self.assertEqual(clean_snapshot["counts"]["total"], 1)
                self.assertEqual(clean_snapshot["source"]["tag"], "v0.160.12")

                if dirty_kind == "tracked":
                    document.write_text(
                        document.read_text(encoding="utf-8") + "\nDirty\n",
                        encoding="utf-8",
                    )
                else:
                    (document.parent / "untracked.mdx").write_text(
                        '---\ntitle: "Untracked"\nopenapi: "GET /api/v1/untracked"\n---\n',
                        encoding="utf-8",
                    )

                with self.assertRaisesRegex(
                    check_api_coverage.CoverageError,
                    "source checkout must be clean",
                ):
                    check_api_coverage.snapshot_from_source(root, "0.160.12")

    def test_pinned_git_repository_binds_tag_and_replaces_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source"
            source.mkdir()
            document = initialize_source_checkout(source)
            snapshot = check_api_coverage.snapshot_from_source(source, "0.160.12")
            commit = snapshot["source"]["commit"]
            self.assertIsInstance(commit, str)
            repository = root / "pinned.git"
            check_api_coverage.write_pinned_repository(
                source,
                repository,
                "0.160.12",
                commit,
            )

            self.assertEqual(
                check_api_coverage.snapshot_from_pinned_repository(
                    repository,
                    "0.160.12",
                    commit,
                ),
                snapshot,
            )
            check_api_coverage.validate_pinned_snapshot(
                snapshot,
                "0.160.12",
                repository,
                commit,
            )

            tag_reference = repository / "refs" / "tags" / "v0.160.12"
            tag_reference.write_text(f"{'0' * 40}\n", encoding="ascii")
            with self.assertRaisesRegex(
                check_api_coverage.CoverageError,
                "pinned tag v0.160.12 does not resolve",
            ):
                check_api_coverage.validate_pinned_snapshot(
                    snapshot,
                    "0.160.12",
                    repository,
                    commit,
                )
            tag_reference.write_text(f"{commit}\n", encoding="ascii")

            tampered = json.loads(json.dumps(snapshot))
            tampered["endpoints"][0]["path"] = "/api/v2/kms/keys/{keyId}"
            with self.assertRaisesRegex(
                check_api_coverage.CoverageError,
                "does not match the pinned upstream Git tree",
            ):
                check_api_coverage.validate_pinned_snapshot(
                    tampered,
                    "0.160.12",
                    repository,
                    commit,
                )

            document.write_text(
                '---\ntitle: "Read key"\nopenapi: "GET /api/v2/kms/keys/{keyId}"\n---\n',
                encoding="utf-8",
            )
            for arguments in (
                ("add", "."),
                ("commit", "-m", "update endpoint"),
                ("tag", "-f", "v0.160.12"),
            ):
                subprocess.run(
                    ["git", "-C", str(source), *arguments],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            updated_snapshot = check_api_coverage.snapshot_from_source(
                source,
                "0.160.12",
            )
            updated_commit = updated_snapshot["source"]["commit"]
            self.assertIsInstance(updated_commit, str)
            self.assertNotEqual(updated_commit, commit)
            check_api_coverage.write_pinned_repository(
                source,
                repository,
                "0.160.12",
                updated_commit,
            )

            self.assertEqual(
                len(list((repository / "objects" / "pack").glob("pack-*.pack"))),
                1,
            )
            self.assertEqual(
                len(list((repository / "objects" / "pack").glob("pack-*.idx"))),
                1,
            )
            self.assertEqual(
                check_api_coverage.snapshot_from_pinned_repository(
                    repository,
                    "0.160.12",
                    updated_commit,
                ),
                updated_snapshot,
            )


class CapabilityRegistryTests(unittest.TestCase):
    def test_parses_serialized_registry_contract(self) -> None:
        self.assertEqual(
            check_api_coverage.parse_capability_states(
                {
                    "targetInfisicalVersion": "0.160.12",
                    "capabilities": [
                        {"name": "projects.read", "available": True},
                        {
                            "name": "admin.bootstrap",
                            "available": False,
                            "reason": "out of band",
                        },
                    ],
                },
                "0.160.12",
            ),
            {"projects.read": True, "admin.bootstrap": False},
        )

    def test_executes_the_runtime_server_capabilities_registry(self) -> None:
        states = check_api_coverage.capability_states("0.160.12")
        self.assertTrue(states["projects.read"])
        self.assertFalse(states["admin.bootstrap"])


class CoverageRuleTests(unittest.TestCase):
    def test_exact_signature_owns_each_active_endpoint(self) -> None:
        endpoint = {
            "deprecated": False,
            "document": "ssh/hosts/issue-user-cert.mdx",
            "method": "POST",
            "path": "/api/v1/ssh/hosts/{id}/issue-user-cert",
            "title": "Issue",
        }
        rules = [
            {
                "capability": "sshHosts.userCertificate.issue",
                "endpoints": {
                    "ssh/hosts/issue-user-cert.mdx": (
                        "POST /api/v1/ssh/hosts/{id}/issue-user-cert"
                    )
                },
                "id": "jwt-only-user-issuance",
                "mcpFamily": "sshHosts.userCertificate",
                "reason": "requires JWT",
                "status": "intentionally_omitted",
            },
        ]

        normalized = check_api_coverage.validate_rules(
            {"schemaVersion": 3, "rules": rules},
            {"sshHosts.userCertificate.issue": False},
        )
        self.assertEqual(
            check_api_coverage.classify_endpoint(endpoint, normalized)["id"],
            "jwt-only-user-issuance",
        )

    def test_document_match_does_not_hide_method_or_path_drift(self) -> None:
        rule = {
            "capability": "kms.keys.read",
            "endpoints": {"kms/keys/read.mdx": "GET /api/v1/kms/keys/{keyId}"},
            "id": "kms-read",
            "mcpFamily": "kms.keys",
            "reason": "exact read",
            "status": "implemented",
        }
        base = {
            "deprecated": False,
            "document": "kms/keys/read.mdx",
            "method": "GET",
            "path": "/api/v1/kms/keys/{keyId}",
            "title": "Read",
        }
        normalized = check_api_coverage.validate_rules(
            {"schemaVersion": 3, "rules": [rule]},
            {"kms.keys.read": True},
        )
        for field, value in (
            ("method", "POST"),
            ("path", "/api/v2/kms/keys/{keyId}"),
        ):
            with self.subTest(field=field):
                endpoint = {**base, field: value}
                with self.assertRaisesRegex(
                    check_api_coverage.CoverageError, "has no coverage rule"
                ):
                    check_api_coverage.classify_endpoint(endpoint, normalized)

    def test_rejects_unmapped_active_endpoint(self) -> None:
        endpoint = {
            "deprecated": False,
            "document": "new-family/read.mdx",
            "method": "GET",
            "path": "/api/v1/new-family",
            "title": "Read",
        }

        with self.assertRaisesRegex(
            check_api_coverage.CoverageError, "has no coverage rule"
        ):
            check_api_coverage.classify_endpoint(endpoint, [])

    def test_rejects_unknown_capability_evidence(self) -> None:
        rules = {
            "schemaVersion": 3,
            "rules": [
                {
                    "capability": "missing.capability",
                    "endpoints": {
                        "missing/read.mdx": "GET /api/v1/missing"
                    },
                    "id": "missing",
                    "mcpFamily": "missing",
                    "reason": "missing",
                    "status": "intentionally_omitted",
                }
            ],
        }

        with self.assertRaisesRegex(
            check_api_coverage.CoverageError, "unknown capability"
        ):
            check_api_coverage.validate_rules(rules, {})

    def test_rejects_implemented_rule_backed_by_unavailable_capability(self) -> None:
        rules = {
            "schemaVersion": 3,
            "rules": [
                {
                    "capability": "feature.read",
                    "endpoints": {
                        "feature/read.mdx": "GET /api/v1/feature"
                    },
                    "id": "incorrectly-implemented",
                    "mcpFamily": "feature",
                    "reason": "incorrect",
                    "status": "implemented",
                }
            ],
        }

        with self.assertRaisesRegex(
            check_api_coverage.CoverageError, "cites an unavailable capability"
        ):
            check_api_coverage.validate_rules(rules, {"feature.read": False})

    def test_rejects_non_get_endpoint_backed_by_read_capability(self) -> None:
        rules = {
            "schemaVersion": 3,
            "rules": [
                {
                    "capability": "feature.read",
                    "endpoints": {
                        "feature/create.mdx": "POST /api/v1/feature"
                    },
                    "id": "incorrect-mutation",
                    "mcpFamily": "feature",
                    "reason": "incorrect",
                    "status": "implemented",
                }
            ],
        }

        with self.assertRaisesRegex(
            check_api_coverage.CoverageError,
            "non-GET endpoint.*read-only capability",
        ):
            check_api_coverage.validate_rules(rules, {"feature.read": True})

    def test_profile_policy_identifier_requires_an_implemented_scoped_source(self) -> None:
        consumer = {
            "capability": "certificateProfiles.create",
            "endpoints": {
                "certificate-profiles/create.mdx": (
                    "POST /api/v1/cert-manager/certificate-profiles"
                )
            },
            "id": "profile-create",
            "mcpFamily": "certificateProfiles",
            "reason": "typed profile creation",
            "status": "implemented",
        }
        policy_read = {
            "capability": "certificatePolicies.read",
            "endpoints": {
                "certificate-policies/list.mdx": (
                    "GET /api/v1/cert-manager/certificate-policies"
                )
            },
            "id": "policy-read",
            "mcpFamily": "certificatePolicies",
            "reason": "policy discovery is unfinished",
            "status": "intentionally_omitted",
        }
        dependency = {
            "consumerRule": "profile-create",
            "id": "certificate-profile-policy",
            "identifier": "certificatePolicyId",
            "scope": "certificateManagerProject",
            "sources": [
                {
                    "kind": "discovery",
                    "rule": "policy-read",
                    "scope": "certificateManagerProject",
                }
            ],
        }
        document = {
            "schemaVersion": 3,
            "rules": [consumer, policy_read],
            "workflowDependencies": [dependency],
        }
        normalized = check_api_coverage.validate_rules(
            document,
            {"certificatePolicies.read": False, "certificateProfiles.create": True},
        )
        with self.assertRaisesRegex(
            check_api_coverage.CoverageError, "source 'policy-read' must be implemented"
        ):
            check_api_coverage.validate_workflow_dependencies(document, normalized)

        policy_read["reason"] = "typed project-scoped policy discovery"
        policy_read["status"] = "implemented"
        normalized = check_api_coverage.validate_rules(
            document,
            {"certificatePolicies.read": True, "certificateProfiles.create": True},
        )
        dependencies = check_api_coverage.validate_workflow_dependencies(
            document, normalized
        )
        self.assertEqual(dependencies[0]["identifier"], "certificatePolicyId")

    def test_workflow_identifier_source_scope_must_match_consumer_scope(self) -> None:
        rules = [
            {
                "capability": "policies.read",
                "endpoints": {"policies/list.mdx": "GET /api/v1/policies"},
                "id": "policy-read",
                "mcpFamily": "policies",
                "reason": "scoped discovery",
                "status": "implemented",
            },
            {
                "capability": "profiles.create",
                "endpoints": {"profiles/create.mdx": "POST /api/v1/profiles"},
                "id": "profile-create",
                "mcpFamily": "profiles",
                "reason": "scoped creation",
                "status": "implemented",
            },
        ]
        document = {
            "schemaVersion": 3,
            "rules": rules,
            "workflowDependencies": [
                {
                    "consumerRule": "profile-create",
                    "id": "profile-policy",
                    "identifier": "policyId",
                    "scope": "project",
                    "sources": [
                        {
                            "kind": "discovery",
                            "rule": "policy-read",
                            "scope": "organization",
                        }
                    ],
                }
            ],
        }
        normalized = check_api_coverage.validate_rules(
            document, {"policies.read": True, "profiles.create": True}
        )
        with self.assertRaisesRegex(
            check_api_coverage.CoverageError, "source scope does not match"
        ):
            check_api_coverage.validate_workflow_dependencies(document, normalized)

    def test_deferred_is_distinct_from_an_available_or_intentional_boundary(self) -> None:
        rule = {
            "capability": "unfinished.admin",
            "endpoints": {"unfinished/list.mdx": "GET /api/v1/unfinished"},
            "id": "unfinished",
            "mcpFamily": "unfinished",
            "reason": "typed administration remains unfinished",
            "status": "deferred",
        }
        document = {"schemaVersion": 3, "rules": [rule]}
        self.assertEqual(
            check_api_coverage.validate_rules(
                document, {"unfinished.admin": False}
            )[0]["status"],
            "deferred",
        )
        with self.assertRaisesRegex(
            check_api_coverage.CoverageError, "deferred rule.*available capability"
        ):
            check_api_coverage.validate_rules(document, {"unfinished.admin": True})

    def test_canonical_rule_can_supersede_legacy_variants(self) -> None:
        endpoints = [
            {
                "deprecated": False,
                "document": "certificates/create.mdx",
                "method": "POST",
                "path": "/api/v1/certificates",
                "title": "Create certificate",
            },
            {
                "deprecated": False,
                "document": "certificates/issue-legacy.mdx",
                "method": "POST",
                "path": "/api/v1/certificates/issue",
                "title": "Issue certificate",
            },
        ]
        rules = [
            {
                "capability": "certificates.issue",
                "endpoints": {
                    "certificates/create.mdx": "POST /api/v1/certificates"
                },
                "id": "certificate-create",
                "mcpFamily": "certificates",
                "reason": "canonical typed issuance",
                "status": "implemented",
            },
            {
                "capability": "certificates.issue",
                "endpoints": {
                    "certificates/issue-legacy.mdx": (
                        "POST /api/v1/certificates/issue"
                    )
                },
                "id": "certificate-issue-legacy",
                "mcpFamily": "certificates",
                "reason": "canonical issuance supersedes this variant",
                "status": "superseded",
            },
        ]
        normalized = check_api_coverage.validate_rules(
            {"schemaVersion": 3, "rules": rules}, {"certificates.issue": True}
        )
        rows = check_api_coverage.coverage_rows(endpoints, normalized)
        self.assertEqual(
            [row["status"] for row in rows], ["implemented", "superseded"]
        )


if __name__ == "__main__":
    unittest.main()
