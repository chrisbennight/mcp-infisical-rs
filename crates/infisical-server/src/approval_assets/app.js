'use strict';
const requests = document.querySelector('#requests');
const history = document.querySelector('#history');
const notice = document.querySelector('#notice');
let context;
let busy = false;
const selected = new URL(location.href).searchParams.get('request');
function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}
function message(text, error = false) { notice.textContent = text; notice.className = error ? 'error' : ''; }
function duration(seconds) {
  for (const [unit, size] of [['day', 86400], ['hour', 3600], ['minute', 60]]) {
    if (seconds > 0 && seconds % size === 0) return `${seconds / size} ${unit}${seconds / size === 1 ? '' : 's'}`;
  }
  return `${seconds} seconds`;
}
function detail(list, label, value) { list.append(node('dt', label), node('dd', value)); }
function scopeDescription(session) {
  return session.mode === 'projectEnvironment' ? `Project ${session.requestedScope.projectId} / ${session.requestedScope.environment}` : session.mode === 'global' ? 'Client global' : session.mode === 'once' ? 'Exact request once' : 'Undecided';
}
function button(text, action, className) {
  const result = node('button', text, className); result.type = 'button'; result.addEventListener('click', action); return result;
}
async function decide(id, decision, controls) {
  if (busy) return;
  busy = true; controls.querySelectorAll('button').forEach(item => { item.disabled = true; });
  try {
    const response = await fetch(`/approval/api/sessions/${encodeURIComponent(id)}`, {
      method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json', 'x-csrf-token': context.csrf }, body: JSON.stringify(decision),
    });
    if (!response.ok) { message('The decision could not be recorded. Refresh to check the current state and your sign-in.', true); return; }
    message(decision.decision === 'deny' ? 'Request denied.' : decision.decision === 'revoke' ? 'Approval revoked. New work is blocked.' : 'Approval recorded. Return to the client and explicitly retry. No operation was started by this decision.');
    await load();
  } catch { message('The approval service could not be reached. Refresh to check the current state.', true); }
  finally { busy = false; controls.querySelectorAll('button').forEach(item => { item.disabled = false; }); }
}
function render(item) {
  const { session, owner } = item;
  const card = node('article', undefined, `request${session.sessionId === selected ? ' selected' : ''}`);
  card.append(node('span', session.state, 'badge'), node('h3', session.operation));
  const details = node('dl');
  detail(details, 'Client', owner.subject); detail(details, 'Calling actor', owner.actor); detail(details, 'Issuer', owner.issuer);
  for (const [field, value] of Object.entries(session.target || {})) detail(details, field, value);
  detail(details, 'Project / environment', session.requestedScope ? `${session.requestedScope.projectId} / ${session.requestedScope.environment}` : 'No supported project/environment restriction for this operation');
  detail(details, 'Permission', session.mode === 'global' ? 'All operations otherwise available to this client' : session.mode === 'projectEnvironment' ? 'Only this project and environment' : session.mode === 'once' ? 'Exact operation and submitted arguments, one attempt' : 'Awaiting your decision');
  detail(details, 'Time remaining', duration(session.remainingSeconds));
  if (session.approvedBy) detail(details, 'Decided by', session.approvedBy);
  card.append(details);
  if (session.state === 'pending') {
    card.append(node('p', 'Submitted secret values are omitted. Approve once binds this exact request; a timed approval allows further covered work.', 'muted'));
    const controls = node('div', undefined, 'approval-controls');
    const presets = node('div', undefined, 'presets');
    const amount = node('input'); amount.type = 'number'; amount.min = '0.01'; amount.step = 'any'; amount.value = String(context.durationPresets[0]); amount.setAttribute('aria-label', 'Custom duration');
    const unit = node('select'); unit.setAttribute('aria-label', 'Duration unit');
    for (const [label, value] of [['seconds', 1], ['minutes', 60], ['hours', 3600], ['days', 86400]]) { const option = node('option', label); option.value = String(value); unit.append(option); }
    unit.value = '1';
    for (const seconds of context.durationPresets) presets.append(button(duration(seconds), () => { amount.value = String(seconds); unit.value = '1'; }));
    const custom = node('div', undefined, 'duration'); custom.append(node('label', 'Duration'), amount, unit);
    const scope = node('select', undefined, 'scope'); scope.setAttribute('aria-label', 'Timed approval scope');
    if (session.requestedScope) { const option = node('option', 'Only this project and environment'); option.value = 'projectEnvironment'; scope.append(option); }
    const global = node('option', 'All operations otherwise available to this client'); global.value = 'global'; scope.append(global);
    const actions = node('div', undefined, 'actions');
    actions.append(button('Approve once', () => decide(session.sessionId, { decision: 'once' }, controls), 'primary'));
    actions.append(button('Approve for duration', () => {
      const seconds = Number(amount.value) * Number(unit.value);
      if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > context.maxDurationSeconds) { message(`Choose a duration between 1 second and ${duration(context.maxDurationSeconds)}.`, true); return; }
      decide(session.sessionId, { decision: 'timed', durationSeconds: seconds, scope: scope.value }, controls);
    }, 'primary'));
    actions.append(button('Deny', () => decide(session.sessionId, { decision: 'deny' }, controls), 'danger'));
    controls.append(presets, custom, scope, actions); card.append(controls);
  } else if (['active', 'consumed'].includes(session.state)) {
    if (session.state === 'consumed') card.append(node('p', 'The single attempt has been admitted. You can still revoke permission for queued steps or outstanding downloads.', 'muted'));
    const controls = node('div', undefined, 'actions'); controls.append(button('Revoke approval', () => decide(session.sessionId, { decision: 'revoke' }, controls), 'danger')); card.append(controls);
  }
  return card;
}
async function load() {
  const response = await fetch('/approval/api', { credentials: 'same-origin', cache: 'no-store' });
  if (!response.ok) throw new Error('Approval context unavailable');
  context = await response.json();
  document.querySelector('#identity').textContent = `Signed in as ${context.approver}`;
  const current = context.sessions.filter(item => ['pending', 'active', 'consumed'].includes(item.session.state));
  requests.replaceChildren(...(current.length ? current.map(render) : [node('p', 'No pending requests or active approvals.', 'muted')]));
  history.replaceChildren(...(context.history.length ? context.history.map(item => node('div', `${new Date(item.at * 1000).toLocaleString()} · ${item.event.session.operation} · ${item.event.session.state} · ${scopeDescription(item.event.session)} · ${duration(item.event.session.remainingSeconds)} remaining at event · ${item.event.human || item.event.session.approvedBy || 'client'}`, 'history-item')) : [node('p', 'No decisions recorded in this process.', 'muted')]));
}
function refresh() { return load().catch(() => message('Unable to load approvals. Check your sign-in and refresh.', true)); }
document.querySelector('#refresh').addEventListener('click', refresh);
refresh();
setInterval(() => { if (!busy && !['INPUT', 'SELECT'].includes(document.activeElement?.tagName)) refresh(); }, 10000);
