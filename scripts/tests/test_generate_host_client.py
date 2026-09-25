from __future__ import annotations
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('generate_host_client', Path(__file__).resolve().parents[1] / 'generate_host_client.py')
assert SPEC is not None and SPEC.loader is not None
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)

class HostTypeGenerationTests(unittest.TestCase):
    def render(self, schema):
        return GENERATOR.Types(schema, 'Example').render(schema)

    def test_nullable_arrays_preserve_sibling_items(self):
        self.assertEqual(self.render({'anyOf': [{'type': 'array'}, {'type': 'null'}],
                                     'items': {'type': 'string'}}), '(Array<string> | null)')

    def test_closed_required_optional_fields_and_escaped_names(self):
        self.assertEqual(self.render({'type': 'object', 'additionalProperties': False,
                                     'properties': {'name': {'type': 'string'}, 'x"y': {'type': 'boolean'}},
                                     'required': ['name']}), '{ "name": string; "x\\"y"?: boolean; }')

    def test_local_references_and_recursive_definitions_have_stable_names(self):
        root = {'$defs': {'Node': {'type': 'object', 'properties': {'next': {'$ref': '#/$defs/Node'}}}},
                '$ref': '#/$defs/Node'}
        types = GENERATOR.Types(root, 'Tree')
        self.assertEqual(types.render(root), 'TreeDef0')
        self.assertIn('"next"?: TreeDef0;', types.declarations()[0])

    def test_remote_references_and_unknown_constraints_fail_closed(self):
        for schema in [{'$ref': 'https://example.invalid/schema'}, {'not': {'type': 'string'}},
                       {'type': 'invented'}, {'type': 'object', 'required': ['missing']}]:
            with self.subTest(schema=schema), self.assertRaises((ValueError, KeyError)):
                self.render(schema)

    def test_duplicate_operations_are_rejected(self):
        operation = {'operation': 'sample.get', 'inputSchema': {}, 'outputSchema': {}}
        with self.assertRaisesRegex(ValueError, 'duplicate operation'):
            GENERATOR.generate({'operations': [operation, operation]})

    def test_discriminated_union_keeps_branch_literals(self):
        result = self.render({'type': 'object', 'oneOf': [
            {'type': 'object', 'properties': {'status': {'const': status}}, 'required': ['status'],
             'additionalProperties': False} for status in ['applied', 'approvalRequired']]})
        self.assertEqual(result, '({ "status": "applied"; } | { "status": "approvalRequired"; })')
