import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import test from 'node:test';
import { ApprovalRequiredError, HostClient, HostValue } from '../dist/client.js';
import { summarizeProjects } from '../dist/inventory.js';
import manifest from '../dist/manifest.json' with { type: 'json' };
const capabilities = (overrides = {}) => ({ structuredContent: {
  schemaRevision: manifest.schemaRevision,
  runtime: { operationProfile: 'full', delivery: { resultModes: ['inline', 'file'] } },
  ...overrides,
} });
function fake(response, validator = () => true, caps = capabilities()) {
  const calls = [];
  const transport = { async callTool(request) {
    calls.push(request);
    if (request.name === 'server.capabilities') return caps;
    return typeof response === 'function' ? response(request) : response;
  } };
  return { calls, connect: () => HostClient.connect(transport, validator) };
}
test('host values redact strings, JSON, and Node inspection until explicitly read', () => {
  const value = new HostValue({ secret: 'host-secret-canary' });
  for (const rendered of [String(value), JSON.stringify(value), inspect(value), inspect({ value })]) {
    assert.ok(!rendered.includes('host-secret-canary'));
  }
  assert.equal(value.read().secret, 'host-secret-canary');
});

test('approval guidance stays redacted and a bound client explicitly reuses and closes its token', async () => {
  const token = 'A'.repeat(43);
  const session = { sessionId: 'B'.repeat(43), operation: 'projects.list', state: 'pending', mode: null,
    requestedScope: null, approvedBy: null, ageSeconds: 0, remainingSeconds: 900, remainingUses: null };
  const f = fake(request => {
    if (request.name === 'approval.session') return { structuredContent: { enabled: true,
      session: { ...session, state: request.arguments.action === 'close' ? 'closed' : 'active' } } };
    if (request.arguments.approvalToken) return { structuredContent: { items: [], next: null } };
    return { isError: true, structuredContent: {
      error: { operation: 'projects.list', category: 'approvalRequired', effect: 'notStarted', recovery: 'obtainApproval', correction: 'Present the approval link' },
      approval: { reason: 'required', approvalUrl: 'https://approval.example/approval?request=request-id', approvalToken: token, session },
    } };
  }, () => true, capabilities({ runtime: { operationProfile: 'full', humanApproval: true, delivery: { resultModes: ['inline', 'file'] } } }));
  const client = await f.connect();
  assert.equal(client.requiresApproval, true);
  const result = await client.invoke('projects.list', {});
  assert.equal(result.kind, 'approvalRequired');
  assert.equal(f.calls.length, 2);
  assert.equal(result.approval.url, 'https://approval.example/approval?request=request-id');
  for (const rendered of [JSON.stringify(result), inspect(result)]) assert.ok(!rendered.includes(token));
  const approved = client.withApproval(result.approval.token);
  assert.equal(f.calls.length, 2);
  assert.equal((await approved.approvalStatus()).read().session.state, 'active');
  assert.equal((await approved.invoke('projects.list', {})).kind, 'success');
  assert.equal((await approved.invoke('projects.list', { limit: 5 })).kind, 'success');
  assert.equal((await approved.closeApproval()).read().session.state, 'closed');
  assert.equal(f.calls.length, 6);
  for (const request of f.calls.slice(2)) assert.equal(request.arguments.approvalToken, token);
});

test('composition stops on approval and preserves safe guidance without background retry', async () => {
  const token = 'A'.repeat(43);
  const f = fake({ isError: true, structuredContent: {
    error: { operation: 'projects.list', category: 'approvalRequired', effect: 'notStarted', recovery: 'obtainApproval', correction: 'Present the approval link' },
    approval: { reason: 'required', approvalUrl: 'https://approval.example/approval?request=request-id', approvalToken: token },
  } }, () => true, capabilities({ runtime: { operationProfile: 'full', humanApproval: true, delivery: { resultModes: ['inline'] } } }));
  await assert.rejects(summarizeProjects(await f.connect()), error => {
    assert.ok(error instanceof ApprovalRequiredError);
    assert.ok(!inspect(error).includes(token));
    assert.equal(error.approval.url, 'https://approval.example/approval?request=request-id');
    return true;
  });
  assert.equal(f.calls.length, 2);
});
test('invalid arguments are rejected locally using the exact generated input schema', async () => {
  const seen = [];
  const f = fake({}, (schema, value) => { seen.push([schema, value]); return false; });
  const client = await f.connect();
  await assert.rejects(client.invoke('projects.list', { limit: 'secret-input-canary' }), /Arguments do not satisfy/);
  assert.equal(f.calls.length, 1);
  assert.deepEqual(seen[0][0], manifest.operations['projects.list'].inputSchema);
});
test('successful outputs must pass the exact output schema before exposure', async () => {
  // JSON module instances are shared, but compare schema shape to make the contract explicit.
  const invalid = fake({ structuredContent: { items: 'invalid' } }, (schema, value) =>
    schema.title !== manifest.operations['projects.list'].outputSchema.title || Array.isArray(value.items));
  await assert.rejects((await invalid.connect()).invoke('projects.list', {}), /output does not satisfy/);
  assert.equal(invalid.calls.length, 2);
});
test('tool errors use the error schema before any success-output validation', async () => {
  const error = { operation: 'projects.list', category: 'rateLimited', effect: 'unknown',
    recovery: 'wait', correction: 'Wait before a new attempt', preflightObservationsPossible: false };
  const seen = [];
  const f = fake({ isError: true, structuredContent: { error } }, (schema, value) => {
    seen.push(schema); return value === error || !Object.hasOwn(value, 'error');
  });
  const result = await (await f.connect()).invoke('projects.list', {});
  assert.equal(result.kind, 'error');
  assert.deepEqual(result.error.read(), error);
  assert.deepEqual(seen[1], manifest.executionErrorSchema);
  assert.equal(seen.length, 2);
});
test('revision and profile mismatches stop operations before transport', async () => {
  const stale = fake({}, () => true, capabilities({ schemaRevision: 'stale' }));
  await assert.rejects(stale.connect(), /capability contract differs/);
  const f = fake({}, () => true, capabilities({ runtime: {
    operationProfile: 'metadata', delivery: { resultModes: ['inline'] },
  } }));
  const client = await f.connect();
  await assert.rejects(client.invoke('secrets.reveal', {}), /unavailable/);
  await assert.rejects(client.invokeFile('projects.list', {}), /does not support/);
  assert.equal(f.calls.length, 1);
});
test('transport failures never replay mutations or reflect transport diagnostics', async () => {
  const f = fake(() => { throw new Error('transport-secret-canary'); });
  await assert.rejects((await f.connect()).invoke('secrets.create', {}), error =>
    !String(error).includes('transport-secret-canary') && /Reconcile/.test(String(error)));
  assert.equal(f.calls.length, 2);
  assert.equal(f.calls[1].name, manifest.operations['secrets.create'].executor);
});
test('whole-result file results remain opaque and are never fetched automatically', async () => {
  const f = fake({ structuredContent: { operation: 'projects.list', reconciliation: [], resultFile: {
    uri: 'mcp-file://infisical/opaque-test-reference', name: 'projects.list.json', mimeType: 'application/json',
  } } });
  const result = await (await f.connect()).invokeFile('projects.list', {});
  assert.equal(result.kind, 'success');
  assert.equal(result.value.read().operation, 'projects.list');
  assert.ok(!JSON.stringify(result).includes('opaque-test-reference'));
  assert.equal(f.calls[1].arguments.resultDelivery, 'file');
  assert.equal(f.calls.length, 2);
});
test('transport cancellation preserves AbortError without exposing its message or retrying', async () => {
  const f = fake(() => { throw new DOMException('cancel-secret-canary', 'AbortError'); });
  await assert.rejects((await f.connect()).invoke('secrets.create', {}), error =>
    error.name === 'AbortError' && !String(error).includes('cancel-secret-canary') &&
    /reconcile/.test(error.message));
  assert.equal(f.calls.length, 2);
});
test('inventory retains full pages in the host and returns only selected summaries', async () => {
  const f = fake(request => ({ structuredContent: {
    items: [{ id: `id-${request.arguments.arguments.offset}`, name: 'project', description: 'omitted-canary' }],
    next: request.arguments.arguments.offset === 0 ? { offset: 100, limit: 100 } : null,
  } }));
  const client = await f.connect();
  const result = await summarizeProjects(client);
  assert.equal(result.complete, true);
  assert.equal(result.projects.length, 2);
  assert.ok(!JSON.stringify(result).includes('omitted-canary'));
  assert.equal((await summarizeProjects(client, 1)).complete, false);
});

test('host composition filters and joins scoped results with explicit incompleteness', async () => {
  const { summarizeProjectEnvironments } = await import('../dist/inventory.js');
  const f = fake(request => {
    if (request.arguments.operation === 'projects.list') return { structuredContent: {
      items: [{ id: 'selected', name: 'app-one' }, { id: 'omitted', name: 'other' }], next: null,
    } };
    assert.equal(request.arguments.arguments.projectId, 'selected');
    return { structuredContent: { projectId: 'selected', environments: {
      items: [{ id: 'host-only-id', name: 'host-only-name', slug: 'prod' }], next: { offset: 100, limit: 100 },
    } } };
  });
  const result = await summarizeProjectEnvironments(await f.connect(), 'app-');
  assert.deepEqual(result, { projects: [{ id: 'selected', name: 'app-one', environments: ['prod'], complete: false }], complete: false });
  assert.equal(f.calls.length, 3);
});

test('file receipts use the exported Rust schema before host exposure', async () => {
  const seen = [];
  const f = fake({ structuredContent: { operation: 'identityTokenAuth.tokens.create',
    resultFile: { uri: 'mcp-file://infisical/opaque', name: 'token.json', mimeType: 'application/json' },
    reconciliation: [{ kind: 'token', id: 'token-1' }],
  } }, (schema, value) => { seen.push(schema); return true; });
  const result = await (await f.connect()).invokeFile('identityTokenAuth.tokens.create', { identityId: 'identity-1' });
  assert.deepEqual(seen[1], manifest.fileResultSchema);
  assert.deepEqual(result.value.read().reconciliation, [{ kind: 'token', id: 'token-1' }]);
  assert.equal(f.calls.length, 2);
});
