#!/usr/bin/env python3
"""Generate host types and a data-only manifest from the Rust schema export."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ANNOTATIONS = {'$schema', '$defs', 'title', 'description', 'default', 'format',
               'maximum', 'minimum', 'pattern', 'maxLength', 'minLength',
               'maxItems', 'minItems', 'uniqueItems', 'x-mcp-file'}
STRUCTURAL = {'type', 'properties', 'required', 'additionalProperties', 'items',
              '$ref', 'anyOf', 'oneOf', 'allOf', 'const', 'enum'}

def literal(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'))

class Types:
    def __init__(self, root, prefix):
        self.root = root
        self.prefix = prefix
        self.defs = {key: f'{prefix}Def{index}' for index, key in enumerate(root.get('$defs', {}))}

    def render(self, node):
        if node is True:
            return 'unknown'
        if node is False:
            return 'never'
        if not isinstance(node, dict) or set(node) - ANNOTATIONS - STRUCTURAL:
            raise ValueError('unsupported schema construct')
        for union in ('anyOf', 'oneOf', 'allOf'):
            if union in node:
                siblings = {key: value for key, value in node.items() if key != union}
                # Apply sibling constraints to each branch. In particular, nullable
                # arrays have their items schema beside anyOf in the Rust export.
                branches = []
                for branch in node[union]:
                    if not isinstance(branch, dict) or any(
                        siblings[key] != branch[key]
                        for key in set(siblings).intersection(branch) - ANNOTATIONS
                    ):
                        raise ValueError('ambiguous schema union siblings')
                    branches.append(self.render({**siblings, **branch}))
                if not branches:
                    raise ValueError('empty schema union')
                return '(' + (' & ' if union == 'allOf' else ' | ').join(branches) + ')'
        if '$ref' in node:
            if set(node) - ANNOTATIONS - {'$ref'}:
                raise ValueError('reference siblings require explicit support')
            ref = node['$ref']
            if not isinstance(ref, str) or not ref.startswith('#/$defs/'):
                raise ValueError('only local definition references are supported')
            key = ref[len('#/$defs/'):].replace('~1', '/').replace('~0', '~')
            return self.defs[key]
        if 'const' in node:
            if isinstance(node['const'], (dict, list)):
                raise ValueError('non-scalar constants require explicit support')
            return literal(node['const'])
        if 'enum' in node:
            if any(isinstance(value, (dict, list)) for value in node['enum']):
                raise ValueError('non-scalar enum requires explicit support')
            return '(' + ' | '.join(literal(value) for value in node['enum']) + ')'
        kind = node.get('type')
        if isinstance(kind, list):
            return '(' + ' | '.join(self.render({**node, 'type': value}) for value in kind) + ')'
        if kind == 'object' or 'properties' in node:
            properties = node.get('properties', {})
            required = set(node.get('required', []))
            if required - properties.keys():
                raise ValueError('required property lacks a schema')
            fields = [f'{literal(key)}{"" if key in required else "?"}: {self.render(value)};'
                      for key, value in properties.items()]
            extra = node.get('additionalProperties', True)
            if extra is not False:
                value = self.render(extra)
                fields.append(f'[key: string]: {value};')
            return '{ ' + ' '.join(fields) + ' }'
        if kind == 'array':
            return f'Array<{self.render(node.get("items", True))}>'
        if kind in ('integer', 'number'):
            return 'number'
        if kind in ('string', 'boolean', 'null'):
            return kind
        if kind is not None:
            raise ValueError('unsupported schema type')
        if set(node) - ANNOTATIONS:
            raise ValueError('untyped constraints require explicit support')
        return 'unknown'

    def declarations(self):
        return [f'type {self.defs[key]} = {self.render(value)};'
                for key, value in self.root.get('$defs', {}).items()]

def generate(policy):
    declarations = ['// Generated from Rust schemas. Run scripts/generate_host_client.py.']
    inputs, outputs = [], []
    seen = set()
    for index, operation in enumerate(policy['operations']):
        name = operation['operation']
        if name in seen:
            raise ValueError('duplicate operation')
        seen.add(name)
        for field, target in [('inputSchema', inputs), ('outputSchema', outputs)]:
            prefix = f'Operation{index}{"Input" if field == "inputSchema" else "Output"}'
            types = Types(operation[field], prefix)
            declarations.extend(types.declarations())
            declarations.append(f'type {prefix} = {types.render(operation[field])};')
            target.append(f'  {literal(name)}: {prefix};')
    errors = Types(policy['executionErrorSchema'], 'ExecutionError')
    declarations.extend(errors.declarations())
    declarations.append(f'export type ExecutionError = {errors.render(policy["executionErrorSchema"])};')
    declarations += ['export interface InputByOperation {', *inputs, '}',
                     'export interface OutputByOperation {', *outputs, '}',
                     'export type Operation = keyof InputByOperation;',
                     f'export const schemaRevision = {literal(policy["schemaRevision"])} as const;']
    manifest = {**policy, 'operations': {op['operation']: op for op in policy['operations']}}
    return '\n'.join(declarations) + '\n', json.dumps(manifest, indent=2, ensure_ascii=True) + '\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--export', type=Path, help='Existing offline Rust export')
    args = parser.parse_args()
    if args.export:
        policy = json.loads(args.export.read_text())
    else:
        result = subprocess.run(['cargo', 'run', '--quiet', '--locked', '--offline', '-p',
                                 'infisical-mcp', '--example', 'operation_policy'],
                                cwd=ROOT, check=True, capture_output=True, text=True)
        policy = json.loads(result.stdout)
    definitions, manifest = generate(policy)
    for name, value in [('generated.ts', definitions), ('manifest.json', manifest)]:
        path = ROOT / 'host-client' / 'src' / name
        if args.check:
            if not path.exists() or path.read_text() != value:
                raise SystemExit(f'{path.relative_to(ROOT)} is stale; regenerate the host client')
        else:
            path.write_text(value)
    print('host client schemas match Rust export' if args.check else 'host client schemas generated')

if __name__ == '__main__':
    main()
