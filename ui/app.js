// VANTAGE dashboard. Vanilla ESM. Routes: #/ and #/e/<id>/<tab>?severity=&status=&q=
// Findings and evidence are target-influenced data: every string goes through esc().

const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['open', 'fixed', 'accepted', 'false_positive', 'not_observed'];
const TABS = [['findings', 'Findings'], ['assets', 'Assets'], ['runs', 'Runs'], ['activity', 'Activity']];
const $ = (sel, root = document) => root.querySelector(sel);
const view = $('#view');
const drawer = $('#drawer');
const esc = (v) => String(v ?? '').replace(/[&<>"'`]/g, (c) => `&#${c.charCodeAt(0)};`);
const human = (s) => String(s ?? '').replace(/_/g, ' ');
const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const when = (iso) => (iso ? dateFmt.format(new Date(iso)) : 'not set');
const num = new Intl.NumberFormat();
const enc = encodeURIComponent;

let token = '';
try { token = sessionStorage.getItem('vantage-token') ?? ''; } catch { /* storage blocked */ }
let current = null; // { id, tab, findings }

async function api(path, init = {}) {
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: { 'content-type': 'application/json', ...(token ? { 'x-vantage-token': token } : {}) }
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error ?? `The server answered ${res.status}.`);
  return body;
}

function toast(message, kind = '') {
  const el = document.createElement('div');
  el.className = `toast${kind ? ` toast--${kind}` : ''}`;
  el.textContent = message;
  $('#toasts').append(el);
  setTimeout(() => el.remove(), 4000);
}

const chip = (value, kind = value) => `<span class="chip chip--${esc(kind)}">${esc(human(value))}</span>`;
const stat = (value, label) => `<div class="stat"><div class="stat-value">${esc(value)}</div><div class="stat-label">${esc(label)}</div></div>`;
const cmd = (text) => `<div class="cmd"><code>${esc(text)}</code><button type="button" class="btn btn--sm" data-copy="${esc(text)}">Copy</button></div>`;
const empty = (title, detail, command = '') => `<div class="empty"><h2>${esc(title)}</h2><p>${esc(detail)}</p>${command ? cmd(command) : ''}</div>`;

// ---------- URL state ----------

function parseHash() {
  const [path, query = ''] = location.hash.slice(1).split('?');
  const [, kind, id, tab] = path.split('/');
  return { kind, id: id ? decodeURIComponent(id) : null, tab: TABS.some(([k]) => k === tab) ? tab : 'findings', params: new URLSearchParams(query) };
}

function setParams(changes) {
  const { id, tab, params } = parseHash();
  for (const [k, v] of Object.entries(changes)) (v ? params.set(k, v) : params.delete(k));
  const q = params.toString();
  history.replaceState(null, '', `#/e/${enc(id)}/${tab}${q ? `?${q}` : ''}`);
  return renderFindings();
}

// ---------- engagement list ----------

async function renderList() {
  current = null;
  document.title = 'Engagements, VANTAGE';
  const list = await api('/engagements');
  const head = '<div class="head"><div><h1 class="page-title">Engagements</h1><p class="page-sub">Assessments stored on this machine.</p></div></div>';
  if (!list.length) {
    view.innerHTML = head + empty('No engagements yet', 'Try the built-in lab first, or create an engagement for a system you are authorized to test.', 'node bin/vantage.js demo --serve');
    return;
  }
  view.innerHTML = head + `<div class="grid">${list.map((g) => {
    const counts = SEVS.filter((s) => g.counts.bySeverity?.[s]).map((s) => chip(`${g.counts.bySeverity[s]} ${s}`, s)).join('');
    return `<a class="eng" href="#/e/${enc(g.id)}/findings">
      <div><div class="eng-name">${esc(g.name)}</div><div class="sub">${esc(g.client || 'No client recorded')}</div></div>
      <div class="eng-meta">${counts || '<span class="sub">No findings yet</span>'}</div>
      <div class="eng-foot"><span>${num.format(g.counts.runs)} ${g.counts.runs === 1 ? 'run' : 'runs'}</span><span>${g.lastRunAt ? `Last run ${esc(when(g.lastRunAt))}` : 'Never run'}</span></div>
    </a>`;
  }).join('')}</div>`;
}

// ---------- one engagement ----------

function permit(g, scope) {
  const start = Date.parse(g.startsAt);
  const end = Date.parse(g.endsAt);
  const now = Date.now();
  let windowHtml = `${esc(when(g.startsAt))} until ${g.endsAt ? esc(when(g.endsAt)) : 'no end date'}`;
  if (Number.isFinite(start) && Number.isFinite(end) && end > start) {
    const pct = Math.min(100, Math.max(0, ((now - start) / (end - start)) * 100));
    const expired = now > end;
    const left = Math.ceil((end - now) / 864e5);
    windowHtml = `<div class="window"><span>${esc(when(g.startsAt))} until ${esc(when(g.endsAt))}. ${expired ? '<b>Expired: the guard refuses all network actions.</b>' : `${num.format(left)} ${left === 1 ? 'day' : 'days'} left.`}</span>
      <span class="window-bar" role="img" aria-label="${Math.round(pct)}% of the authorization window used"><span class="window-fill" data-state="${expired ? 'expired' : 'ok'}" style="width:${pct}%"></span></span></div>`;
  }
  return `<section class="permit" aria-label="Authorization">
    <div class="permit-row"><span class="permit-key">Authorization</span><span><span class="permit-ref">${esc(g.authorizationRef || 'No reference recorded')}</span>${g.authorizedBy ? `<span class="sub">Approved by ${esc(g.authorizedBy)}</span>` : ''}</span></div>
    <div class="permit-row"><span class="permit-key">Window</span>${windowHtml}</div>
    <div class="permit-row"><span class="permit-key">In scope</span><span class="targets">${scope.targets.map((t) => `<span class="target">${esc(t.describe ?? t.raw ?? t)}</span>`).join('') || 'Nothing'}</span></div>
    <div class="permit-row"><span class="permit-key">Mode</span><span>${esc(human(scope.mode))}${scope.mode === 'passive' ? ', DNS and headers only' : scope.mode === 'full' ? ', includes longer content discovery' : ', all non-destructive checks'}</span></div>
  </section>`;
}

async function renderEngagement(id, tab) {
  const d = await api(`/engagements/${enc(id)}`);
  const g = d.engagement;
  const c = d.counts;
  current = { id, tab };
  document.title = `${g.name}, VANTAGE`;
  const max = Math.max(1, ...SEVS.map((s) => c.bySeverity[s] ?? 0));
  const counts = { findings: c.findings, assets: c.assets, runs: c.runs, activity: d.activity.length };
  view.innerHTML = `
    <a class="back" href="#/">Back to engagements</a>
    <div class="head"><div><h1 class="page-title">${esc(g.name)}</h1><p class="page-sub">${esc(g.client || 'No client recorded')}</p></div></div>
    ${permit(g, d.scope)}
    <div class="stats">
      ${stat(num.format(c.open), `open of ${num.format(c.findings)} findings`)}
      ${stat(c.highest ? human(c.highest) : 'None', 'highest severity')}
      ${stat(`${num.format(c.tested)} of ${num.format(c.assets)}`, 'assets tested')}
      ${stat(num.format(c.requests), `requests, ${num.format(c.denials)} refused by scope`)}
    </div>
    <div class="overview">
      <section class="card" aria-labelledby="sev-title"><h2 id="sev-title">Findings by severity</h2><div class="sev-list" id="sev-list">
        ${SEVS.map((s) => `<button type="button" class="sev-row" data-sev="${s}" aria-pressed="false"><span class="sev-name">${s}</span><span class="sev-track"><span class="sev-fill" style="width:${((c.bySeverity[s] ?? 0) / max) * 100}%;background:var(--${s})"></span></span><span class="sev-count">${c.bySeverity[s] ?? 0}</span></button>`).join('')}
      </div></section>
      <section class="card" aria-labelledby="rep-title"><h2 id="rep-title">Report</h2><div class="btn-row">
        <a class="btn btn--primary" target="_blank" rel="noopener" href="/api/engagements/${enc(id)}/report?format=html">Open HTML report</a>
        <a class="btn" download href="/api/engagements/${enc(id)}/report?format=md">Markdown</a>
        <a class="btn" download href="/api/engagements/${enc(id)}/report?format=json">JSON</a>
      </div><p class="report-note">Built from the latest data each time you open it.</p></section>
    </div>
    <nav class="tabs" aria-label="Engagement sections">${TABS.map(([k, label]) => `<a class="tab" ${k === tab ? 'aria-current="page"' : ''} href="#/e/${enc(id)}/${k}">${label}<span class="tab-count">${counts[k]}</span></a>`).join('')}</nav>
    <div id="tab-body"></div>`;

  view.querySelectorAll('.sev-row').forEach((b) => b.addEventListener('click', () => {
    const next = parseHash().params.get('severity') === b.dataset.sev ? '' : b.dataset.sev;
    if (tab !== 'findings') location.hash = `#/e/${enc(id)}/findings${next ? `?severity=${next}` : ''}`;
    else setParams({ severity: next });
  }));

  if (tab === 'findings') return renderFindings();
  if (tab === 'assets') return renderAssets();
  if (tab === 'runs') return renderRuns();
  return renderActivity(d.activity);
}

async function renderFindings() {
  const { params } = parseHash();
  const filters = { severity: params.get('severity') ?? '', status: params.get('status') ?? '', search: params.get('q') ?? '' };
  view.querySelectorAll('.sev-row').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.sev === filters.severity)));
  const q = new URLSearchParams(Object.entries(filters).filter(([, v]) => v));
  const { findings, total } = await api(`/engagements/${enc(current.id)}/findings?${q}`);
  current.findings = findings;
  const body = $('#tab-body');
  const focused = body.contains(document.activeElement) ? document.activeElement.name : null;
  const select = (name, label, values) => `<label class="field">${label}<select name="${name}"><option value="">Any</option>${values.map((v) => `<option value="${v}" ${filters[name] === v ? 'selected' : ''}>${esc(human(v))}</option>`).join('')}</select></label>`;
  body.innerHTML = `
    <form class="toolbar" role="search" onsubmit="return false">
      ${select('severity', 'Severity', SEVS)}${select('status', 'Status', STATUSES)}
      <label class="field grow">Search<input id="f-search" name="q" type="search" autocomplete="off" value="${esc(filters.search)}" placeholder="Title, target or check…"></label>
      <span class="result-count" aria-live="polite">${findings.length} of ${total}</span>
    </form>
    ${findings.length ? `<div class="table-wrap"><table class="stack"><thead><tr><th>Severity</th><th>Finding</th><th>Status</th><th>Last seen</th></tr></thead><tbody>
      ${findings.map((f, i) => `<tr><td>${chip(f.severity)}</td>
        <td><button type="button" class="row-link" data-i="${i}">${esc(f.title)}</button><span class="sub">${esc(f.target)}</span></td>
        <td>${chip(f.status)}</td><td class="when">${esc(when(f.lastSeen))}</td></tr>`).join('')}
    </tbody></table></div>`
    : total ? empty('No findings match these filters', 'Clear a filter or change the search to see more.')
      : empty('No findings yet', 'Run the engagement to start collecting findings.', `node bin/vantage.js run ${current.id} --serve`)}`;

  let t;
  body.querySelectorAll('select').forEach((el) => el.addEventListener('change', () => setParams({ [el.name]: el.value })));
  const search = $('#f-search');
  search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => setParams({ q: search.value.trim() }), 200); });
  const refocus = focused && body.querySelector(`[name="${focused}"]`);
  if (refocus) { refocus.focus(); if (refocus === search) search.setSelectionRange(search.value.length, search.value.length); }
  body.querySelectorAll('.row-link').forEach((b) => b.addEventListener('click', () => openFinding(current.findings[b.dataset.i])));
}

async function renderAssets() {
  const { assets, coverage } = await api(`/engagements/${enc(current.id)}/assets`);
  $('#tab-body').innerHTML = assets.length ? `<p class="hint" style="margin-bottom:12px">${coverage.tested} of ${coverage.total} assets tested (${coverage.percentTested}%).</p>
    <div class="table-wrap"><table class="stack"><thead><tr><th>Type</th><th>Asset</th><th>State</th><th>Details</th></tr></thead><tbody>
    ${assets.map((a) => `<tr><td>${esc(human(a.type))}</td><td class="mono">${esc(a.value)}</td><td>${chip(a.state)}</td><td class="sub">${esc(Object.entries(a.attributes ?? {}).map(([k, v]) => `${k} ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(', ')) || 'None'}</td></tr>`).join('')}
    </tbody></table></div>` : empty('No assets yet', 'Hosts, services and endpoints appear here as checks discover them.');
}

async function renderRuns() {
  const runs = await api(`/engagements/${enc(current.id)}/runs`);
  $('#tab-body').innerHTML = runs.length ? `<div class="table-wrap"><table class="stack"><thead><tr><th>Started</th><th>Result</th><th>New findings</th><th>Requests</th><th>Refused by scope</th></tr></thead><tbody>
    ${runs.map((r) => `<tr><td class="when">${esc(when(r.startedAt))}<span class="sub mono">${esc(r.id)}</span></td><td>${chip(r.status, r.status === 'completed' ? 'completed' : 'open')}</td><td class="num">${r.stats.findings ?? 0}</td><td class="num">${r.stats.requests ?? 0}</td><td class="num">${r.stats.denials ?? 0}</td></tr>`).join('')}
    </tbody></table></div>` : empty('No runs yet', 'Start a run from the terminal. This page updates live while it works.', `node bin/vantage.js run ${current.id} --serve`);
}

function renderActivity(activity) {
  $('#tab-body').innerHTML = activity.length
    ? `<ol class="activity" reversed>${[...activity].reverse().map((a) => `<li><span class="when">${esc(when(a.ts))}</span><span>${esc(a.message)}</span></li>`).join('')}</ol>`
    : empty('No activity yet', 'Progress messages appear here during a run.');
}

// ---------- finding drawer (native modal dialog: focus trap and Esc for free) ----------

async function openFinding(f) {
  const block = (title, html) => (html ? `<section><h3>${title}</h3>${html}</section>` : '');
  const refs = [...(f.cwe ?? []), ...(f.owasp ?? [])].map((r) => `<span class="chip chip--plain">${esc(r)}</span>`).join(' ');
  const links = (f.references ?? []).filter((u) => /^https?:\/\//.test(u)).map((u) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a>`).join('<br>');
  drawer.innerHTML = `
    <div class="drawer-head"><div><div class="btn-row">${chip(f.severity)}${chip(f.status)}<span class="chip chip--plain">${esc(f.confidence)}</span></div>
      <h2 id="drawer-title">${esc(f.title)}</h2><span class="sub mono">${esc(f.target)}</span></div>
      <button type="button" class="btn btn--sm" data-close aria-label="Close finding">Close</button></div>
    <div class="drawer-body">
      ${block('What we saw', f.description && `<p>${esc(f.description)}</p>`)}
      ${block('Why it matters', f.impact && `<p>${esc(f.impact)}</p>`)}
      ${block('Observed values', f.observed?.length && `<table class="kv">${f.observed.map((o) => `<tr><th>${esc(o.key)}</th><td>${esc(o.value)}</td></tr>`).join('')}</table>`)}
      ${block('How to fix it', f.remediation && `<p>${esc(f.remediation)}</p>`)}
      ${block('References', (refs || links) && `<div class="btn-row" style="margin-bottom:8px">${refs}</div>${links}`)}
      <section><h3>Status</h3><form class="status-form" id="status-form">
        <div class="btn-row"><label class="field">Status<select id="d-status">${STATUSES.map((s) => `<option value="${s}" ${s === f.status ? 'selected' : ''}>${esc(human(s))}</option>`).join('')}</select></label></div>
        <label class="field">Note for the audit trail<textarea id="d-note" rows="2" maxlength="2000" placeholder="Why the status changed…"></textarea></label>
        <div class="btn-row"><button type="submit" class="btn btn--primary">Save status</button>${token ? '' : '<span class="hint">Needs the operator token. <button type="button" class="row-link" data-token style="display:inline;font-weight:500;color:var(--accent)">Set token</button></span>'}</div>
        <p class="hint" id="d-error" role="alert"></p>
      </form></section>
      ${block('History', f.history?.length && `<ul class="history">${f.history.map((h) => `<li><b>${esc(human(h.event))}</b>${h.to ? ` to ${esc(human(h.to))}` : ''} by ${esc(h.actor ?? 'unknown')}, ${esc(when(h.ts))}${h.note ? `<br>${esc(h.note)}` : ''}</li>`).join('')}</ul>`)}
      <section><h3>Evidence</h3><div id="d-evidence">${f.evidence?.length ? '<p class="loading">Loading evidence…</p>' : '<p class="hint">No evidence recorded.</p>'}</div></section>
    </div>`;
  drawer.showModal();

  $('[data-token]', drawer)?.addEventListener('click', () => $('#token-dialog').showModal());
  $('#status-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = e.submitter;
    btn.disabled = true;
    btn.textContent = 'Saving…';
    try {
      const { finding } = await api(`/engagements/${enc(current.id)}/findings/${enc(f.id)}`, {
        method: 'PATCH', body: JSON.stringify({ status: $('#d-status').value, note: $('#d-note').value })
      });
      toast(`Status saved: ${human(finding.status)}`);
      drawer.close();
      await route();
    } catch (error) {
      $('#d-error').textContent = /token/i.test(error.message) ? 'The token is missing or wrong. Set the token from the top bar, then save again.' : error.message;
      btn.disabled = false;
      btn.textContent = 'Save status';
    }
  });

  const items = await Promise.all((f.evidence ?? []).slice(0, 5).map((ev) => api(`/engagements/${enc(current.id)}/evidence/${enc(ev)}`).catch(() => null)));
  const box = $('#d-evidence');
  if (!box || !f.evidence?.length) return;
  box.innerHTML = items.map((ev, i) => (ev ? `<div class="evidence"><div class="evidence-head"><span class="mono">${esc(ev.request?.method)} ${esc(ev.request?.url)}</span><span>Status ${esc(ev.response?.status)}</span></div>
    <pre>${esc(Object.entries(ev.response?.headers ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n'))}${ev.response?.bodyPreview ? `\n\n${esc(ev.response.bodyPreview)}` : ''}</pre></div>`
    : `<p class="hint">Evidence ${esc(f.evidence[i])} could not be loaded.</p>`)).join('');
}

drawer.addEventListener('click', (e) => { if (e.target === drawer) drawer.close(); }); // backdrop click

// ---------- token, copy, live stream ----------

function paintToken() { $('#token-button').textContent = token ? 'Token set' : 'Set token'; }
function setToken(value) {
  token = value;
  try { value ? sessionStorage.setItem('vantage-token', value) : sessionStorage.removeItem('vantage-token'); } catch { /* storage blocked */ }
  paintToken();
  toast(value ? 'Token saved for this tab' : 'Token cleared');
}
$('#token-button').addEventListener('click', () => { $('#token-input').value = token; $('#token-dialog').showModal(); });
$('#token-form').addEventListener('submit', () => setToken($('#token-input').value.trim()));
$('#token-clear').addEventListener('click', () => { setToken(''); $('#token-dialog').close(); });

document.addEventListener('click', async (e) => {
  const close = e.target.closest('[data-close]');
  if (close) close.closest('dialog')?.close();
  const copy = e.target.closest('[data-copy]');
  if (!copy) return;
  try {
    await navigator.clipboard.writeText(copy.dataset.copy);
    copy.textContent = 'Copied';
    setTimeout(() => { copy.textContent = 'Copy'; }, 1500);
  } catch {
    toast('Copy failed. Select the command and copy it by hand.', 'error');
  }
});

function live() {
  const pill = $('#live');
  const set = (state, label) => { pill.dataset.state = state; pill.textContent = label; };
  set('connecting', 'Connecting…');
  const es = new EventSource('/api/events');
  let pending;
  es.addEventListener('open', () => set('live', 'Live'));
  es.addEventListener('error', () => set(es.readyState === EventSource.CLOSED ? 'offline' : 'connecting', es.readyState === EventSource.CLOSED ? 'Offline' : 'Reconnecting…'));
  for (const type of ['run:start', 'module:done', 'finding', 'run:done', 'finding:updated']) {
    es.addEventListener(type, (e) => {
      const data = JSON.parse(e.data);
      if (type === 'run:start') toast('Run started');
      if (type === 'run:done') toast(`Run ${data.run?.status ?? 'finished'}: ${data.run?.stats?.findings ?? 0} new findings`);
      if (current && data.engagementId && data.engagementId !== current.id) return;
      clearTimeout(pending);
      pending = setTimeout(() => { if (!drawer.open) route(); }, 400); // coalesce bursts; never yank an open drawer
    });
  }
}

// ---------- router ----------

async function route() {
  const { kind, id, tab } = parseHash();
  try {
    if (kind === 'e' && id) await renderEngagement(id, tab);
    else await renderList();
  } catch (error) {
    view.innerHTML = `<div class="error"><h2>This page could not load</h2><p>${esc(error.message)} Check that the VANTAGE server is still running, then reload.</p></div>`;
  }
}

let lastPath = '';
window.addEventListener('hashchange', () => {
  const path = location.hash.split('?')[0];
  if (path !== lastPath) $('#main').focus({ preventScroll: true });
  lastPath = path;
  route();
});
paintToken();
live();
route();
