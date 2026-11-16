import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { setImmediate } from 'node:timers/promises';
import { test } from 'node:test';
import vm from 'node:vm';

// A small DOM adapter exercises the shipped script's decisions without an
// identity provider, browser installation, or external network access.
class Element {
  constructor(tagName) { this.tagName = tagName.toUpperCase(); this.children = []; this.listeners = {}; this.attributes = {}; this.value = ''; this.textContent = ''; }
  append(...children) {
    this.children.push(...children);
    if (this.tagName === 'SELECT' && !this.value) this.value = this.children[0]?.value || '';
  }
  replaceChildren(...children) { this.children = []; this.append(...children); }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(name, handler) { this.listeners[name] = handler; }
  querySelectorAll(tagName) { return this.descendants().filter(item => item.tagName === tagName.toUpperCase()); }
  descendants() { return this.children.flatMap(child => [child, ...child.descendants()]); }
  async click() { await this.listeners.click(); await setImmediate(); }
}

async function dashboard(scope = { projectId: 'project-1', environment: 'prod' }, state = 'pending') {
  const elements = Object.fromEntries(['requests', 'history', 'notice', 'identity', 'refresh'].map(id => [`#${id}`, new Element('div')]));
  const calls = [];
  const session = { sessionId: 'public-id', operation: '<script>never execute</script>', state, mode: state === 'consumed' ? 'once' : null, requestedScope: scope, target: { 'target.name': 'APP_KEY' }, remainingSeconds: 900 };
  const snapshot = { approver: 'alice', csrf: 'isolated-csrf-token', durationPresets: [300,900,3600,86400], maxDurationSeconds: 86400, sessions: [{session, owner: {subject: 'client-a',actor:'agent-a',issuer:'gateway'}}], history: [] };
  const source = await readFile(new URL('../../crates/infisical-server/src/approval_assets/app.js', import.meta.url), 'utf8');
  const context = vm.createContext({
    document: { querySelector: selector => elements[selector], createElement: tag => new Element(tag), activeElement: null },
    URL, location: {href:'https://approval.example.test/approval?request=public-id'}, setInterval: () => {},
    fetch: async (url, options = {}) => { calls.push({ url, ...options }); return {ok:true,json:async()=>snapshot}; },
  });
  vm.runInContext(source, context, {filename: 'approval-dashboard.js'});
  await setImmediate();
  const controls = () => elements['#requests'].descendants();
  const button = label => controls().find(item => item.tagName === 'BUTTON' && item.textContent === label);
  const control = label => controls().find(item => item.attributes['aria-label'] === label);
  return {elements,calls,button,control};
}

test('dashboard renders request metadata as text and sends only an explicit scoped decision', async () => {
  const d = await dashboard();
  assert.equal(d.calls.length,1);
  assert.equal(d.calls[0].url,'/approval/api');
  const headings = d.elements['#requests'].querySelectorAll('h3');
  assert.equal(headings[0].textContent,'<script>never execute</script>');
  assert.ok(d.elements['#requests'].querySelectorAll('dd').some(item => item.textContent === 'APP_KEY'));
  for (const preset of ['5 minutes','15 minutes','1 hour','1 day']) assert.ok(d.button(preset));
  d.control('Custom duration').value = '7';
  d.control('Duration unit').value = '60';
  assert.equal(d.control('Timed approval scope').value,'projectEnvironment');
  await d.button('Approve for duration').click();
  const posts = d.calls.filter(call => call.method === 'POST');
  assert.equal(posts.length,1);
  assert.equal(posts[0].url,'/approval/api/sessions/public-id');
  assert.deepEqual(JSON.parse(posts[0].body),{decision:'timed',durationSeconds:420,scope:'projectEnvironment'});
  assert.equal(posts[0].headers['x-csrf-token'],'isolated-csrf-token');
  assert.match(d.elements['#notice'].textContent,/explicitly retry/);
  assert.ok(d.calls.every(call => call.url.startsWith('/approval/')));
});

test('dashboard bounds custom durations and offers global approval when scope is unavailable', async () => {
  const d = await dashboard(null);
  assert.equal(d.control('Timed approval scope').value,'global');
  d.control('Custom duration').value = '86401';
  await d.button('Approve for duration').click();
  assert.equal(d.calls.filter(call => call.method === 'POST').length,0);
  assert.equal(d.elements['#notice'].className,'error');
  await d.button('15 minutes').click();
  assert.equal(d.control('Custom duration').value,'900');
  await d.button('Approve once').click();
  assert.deepEqual(JSON.parse(d.calls.find(call => call.method === 'POST').body),{decision:'once'});
});

test('a consumed single-use permit remains visible and revocable without another admission', async () => {
  const d = await dashboard(null, 'consumed');
  assert.equal(d.button('Approve once'), undefined);
  assert.ok(d.elements['#requests'].querySelectorAll('p').some(item => item.textContent.includes('queued steps or outstanding downloads')));
  await d.button('Revoke approval').click();
  assert.deepEqual(JSON.parse(d.calls.find(call => call.method === 'POST').body), {decision:'revoke'});
});
