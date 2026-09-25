from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import catalog_summary


class CatalogSummaryTests(unittest.TestCase):
    def test_nullable_container_preserves_path_and_rejects_ambiguous_union(self):
        schema = {"properties": {"environments": {"anyOf": [
            {"$ref": "#/$defs/Page"}, {"type": "null"}
        ]}}, "$defs": {"Page": {"properties": {
            "items": {"items": {"properties": {"slug": {"type": "string"}}}}
        }}}}
        path = ["environments", "items", "[]", "slug"]
        self.assertEqual(catalog_summary.schema_field(schema, path), {"type": "string"})
        schema["properties"]["environments"]["anyOf"].append({"type": "string"})
        with self.assertRaises(ValueError):
            catalog_summary.schema_field(schema, path)

    def exports(self):
        policy = {
            "schemaRevision": "2026-09-25.4",
            "operations": [{
                "operation": "secrets.reveal", "executor": "infisical.read",
                "profiles": ["secrets", "full"], "credentialDisclosure": True,
                "requiresFileTransfer": False,
                "inputSchema": {"properties": {"delivery": {"type": "string"}}},
            }],
        }
        capabilities = {
            "schemaRevision": policy["schemaRevision"], "targetInfisicalVersion": "v0.160.12",
            "capabilities": [
                {"name": "secrets.read", "available": True},
                {"name": "secrets.history", "available": False, "reason": "Requires JWT | upstream\npermission"},
                {"name": "secrets.restore", "available": False, "reason": "Deferred"},
            ],
        }
        return policy, capabilities

    def test_operation_totals_are_not_capability_totals(self):
        text = catalog_summary.render(*self.exports())
        self.assertIn("**1 operations**", text)
        self.assertIn("**1 implemented**", text)
        self.assertIn("**2 unavailable**", text)
        self.assertIn("| `secrets` | 1 | 1 | 1 | 0 | 1 | 2 |", text)
        self.assertIn("Requires JWT &#124; upstream permission", text)
        self.assertIn("| `metadata` | 0 |", text)

    def test_rejects_inconsistent_or_duplicate_export_contracts(self):
        for change in ("revision", "duplicate_operation", "duplicate_capability", "flag", "executor", "reason"):
            with self.subTest(change=change):
                policy, capabilities = self.exports()
                if change == "revision": capabilities["schemaRevision"] = "different"
                if change == "duplicate_operation": policy["operations"] *= 2
                if change == "duplicate_capability": capabilities["capabilities"] *= 2
                if change == "flag": policy["operations"][0]["credentialDisclosure"] = "false"
                if change == "executor": policy["operations"][0]["executor"] = "custom"
                if change == "reason": del capabilities["capabilities"][1]["reason"]
                with self.assertRaises(ValueError): catalog_summary.render(policy, capabilities)

    def test_new_registry_operation_makes_documentation_stale(self):
        policy, capabilities = self.exports()
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "catalog.md"
            destination.write_text(catalog_summary.render(policy, capabilities), encoding="utf-8")
            with patch.object(catalog_summary, "DESTINATION", destination), patch.object(
                catalog_summary, "generated", side_effect=lambda: catalog_summary.render(policy, capabilities)
            ):
                self.assertEqual(catalog_summary.check(), [])
                added = copy.deepcopy(policy["operations"][0])
                added["operation"] = "secrets.metadata.list"
                added["credentialDisclosure"] = False
                added["inputSchema"] = {"properties": {}}
                added["profiles"].append("metadata")
                policy["operations"].append(added)
                self.assertEqual(len(catalog_summary.check()), 1)

    def test_identifier_handoff_resolves_refs_and_rejects_missing_or_wrong_types(self):
        source = {"operation": "projects.list", "outputSchema": {
            "properties": {"items": {"items": {"$ref": "#/$defs/Project"}}},
            "$defs": {"Project": {"properties": {"id": {"type": "string"}}}},
        }}
        consumer = {"operation": "environments.list", "inputSchema": {
            "properties": {"projectId": {"type": "string"}}
        }}
        workflow = {"name": "Project inventory", "source": "projects.list",
                    "outputPath": ["items", "[]", "id"], "consumer": "environments.list",
                    "inputPath": ["projectId"], "scope": "Same project"}
        self.assertEqual(len(catalog_summary.workflow_rows([source, consumer], [workflow])), 1)
        consumer["inputSchema"]["properties"]["projectId"]["type"] = "integer"
        with self.assertRaises(ValueError):
            catalog_summary.workflow_rows([source, consumer], [workflow])
        del consumer["inputSchema"]["properties"]["projectId"]
        with self.assertRaises(KeyError):
            catalog_summary.workflow_rows([source, consumer], [workflow])
