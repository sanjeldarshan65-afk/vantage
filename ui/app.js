// VANTAGE dashboard. Vanilla ESM, hash routes: #/ (engagements) and #/e/<id>[/<tab>].
// Everything shown comes from target-influenced data, so all text goes through esc().

const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['open', 'fixed', 'accepted', 'false_positive', 'not_observed'];
const $ = (sel, root = document) => root.querySelector(sel);
const view = $('#view');
const esc = (v) => String(v ?? '').replace(/[&<>"'`]/g, (c) => `&#${c.charCodeAt(0)};`);
const when = (iso) => (iso ? new Date(iso).toLocaleString() : '—');

let token = '';
try { token = sessionStorage.getItem('vantage-token') ?? ''; } catch { /* storage blocked */ }
let current = null; // { id, tab, findings, filters }

async function api(path, init = {}) {
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: { 'content-type': 'application/json', ...(token ? { 'x-vantage-token': token } : {}), ...(init.headers ?? {}) }
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
  return body;
}

function toast(message, kind = '') {
  const el = document.createElement('div');
  el.className = `toast ${kind ? `toast--${kind}` : ''}`;
  el.textContent = message;
  $('#toast-root').append(el);
  setTimeout(() => el.remove(), 4000);
}

const chip = (value, kind = value) => `<span class="chip chip--${esc(kind)}">${esc(String(value).replace('_', ' '))}</span>`;
const stat = (label, value, cls = '', hint = '') =>
  `<div class="stat ${cls}"><div class="stat-label">${esc(label)}</div><div class="stat-value">${esc(value)}</div>${hint ? `<div class="stat-hint">${esc(hint)}</div>` : ''}</div>`;
const empty = (title, detail, code = '') =>
  `<div class="empty"><div class="empty-title">${esc(title)}</div><div class="empty-detail">${esc(detail)}</div>${code ? `<pre class="empty-code">${esc(code)}</pre>` : ''}</div>`;

// ---------- engagement list ----------

async function renderList() {
  current = null;
  const list = await api('/engagements');
  if (!list.length) {
    view.innerHTML = `<div class="page-head"><h1 class="page-title">Engagements</h1></div>` +
      empty('No engagements yet', 'Create one for a target you are authorized to test, or run the local demo.',
        'node bin/vantage.js demo --serve\nnode bin/vantage.js init acme --target https://app.acme.example --auth-ref "SOW-123"');
    return;
  }
  view.innerHTML = `<div class="page-head"><h1 class="page-title">Engagements</h1><p class="page-subtitle">${list.length} on this machine</p></div>
    <div class="engagement-grid">${list.map((g) => `
      <a class="engagement-card" href="#/e/${encodeURIComponent(g.id)}">
        <div class="engagement-card-top"><div><div class="engagement-name">${esc(g.name)}</div><div class="engagement-client">${esc(g.client)}</div></div>${chip(g.mode, 'mode')}</div>
        <div class="auth-ref">${esc(g.authorizationRef)}</div>
        <div class="chip-row">${SEVS.filter((s) => g.counts.bySeverity?.[s]).map((s) => chip(`${g.counts.bySeverity[s]} ${s}`, s)).join('') || '<span class="muted">no findings</span>'}</div>
        <div class="card-foot"><span>${g.counts.runs} run(s)</span><span>last ${esc(when(g.lastRunAt))}</span></div>
      </a>`).join('')}</div>`;
}

// ---------- one engagement ----------

async function renderEngagement(id, tab = 'findings') {
  const d = await api(`/engagements/${encodeURIComponent(id)}`);
  const g = d.engagement;
  const c = d.counts;
  current = { id, tab, filters: current?.id === id ? current.filters : { severity: '', status: '', search: '' } };
  const max = Math.max(1, ...SEVS.map((s) => c.bySeverity[s] ?? 0));
  const tabs = [['findings', 'Findings', c.findings], ['assets', 'Assets', c.assets], ['runs', 'Runs', c.runs], ['activity', 'Activity', d.activity.length]];
  view.innerHTML = `
    <p><a href="#/">← Engagements</a></p>
    <div class="engagement-banner">
      <h1 class="page-title">${esc(g.name)}</h1>
      <div class="banner-meta"><span>${esc(g.client)}</span><span>mode ${esc(d.scope.mode)}</span><span>window ${esc(when(g.startsAt))} → ${esc(g.endsAt ? when(g.endsAt) : 'open')}</span></div>
      <div class="auth-ref">Authorization: ${esc(g.authorizationRef)}${g.authorizedBy ? ` — ${esc(g.authorizedBy)}` : ''}</div>
      <div class="banner-meta">Scope: ${d.scope.targets.map((t) => `<span class="mono">${esc(t.describe ?? t.raw ?? t)}</span>`).join(' ')}</div>
    </div>
    <div class="stat-grid">
      ${stat('Open findings', c.open, 'stat--accent', `${c.findings} total`)}
      ${stat('Highest', c.highest ?? 'none', c.highest ? `stat--${c.highest}` : '')}
      ${stat('Assets tested', `${c.coveragePercent}%`, '', `${c.tested} of ${c.assets}`)}
      ${stat('Requests', c.requests, '', `${c.denials} refused by scope`)}
      ${stat('Evidence', c.evidence)}
    </div>
    <div class="overview-grid">
      <div class="card"><div class="card-head"><div class="card-title">Severity</div></div><div class="card-body sev-chart">
        ${SEVS.map((s) => `<button type="button" class="sev-row" data-sev="${s}"><span class="sev-name">${s}</span><span class="sev-track"><span class="sev-fill sev-fill--${s}" style="width:${((c.bySeverity[s] ?? 0) / max) * 100}%"></span></span><span class="sev-count">${c.bySeverity[s] ?? 0}</span></button>`).join('')}
      </div></div>
      <div class="card"><div class="card-head"><div class="card-title">Report</div></div><div class="card-body btn-row">
        ${['html', 'md', 'json'].map((f) => `<a class="btn btn--ghost" target="_blank" rel="noopener" href="/api/engagements/${encodeURIComponent(id)}/report?format=${f}">${f.toUpperCase()}</a>`).join('')}
      </div></div>
    </div>
    <nav class="tabs" role="tablist">${tabs.map(([k, label, n]) => `<a role="tab" class="tab ${k === tab ? 'tab--active' : ''}" aria-selected="${k === tab}" href="#/e/${encodeURIComponent(id)}/${k}">${label} <span class="tab-count">${n}</span></a>`).join('')}</nav>
    <div id="tab-body"></div>`;

  view.querySelectorAll('.sev-row').forEach((b) => b.addEventListener('click', () => {
    current.filters.severity = current.filters.severity === b.dataset.sev ? '' : b.dataset.sev;
    if (tab !== 'findings') location.hash = `#/e/${encodeURIComponent(id)}/findings`;
    else renderFindings();
  }));

  if (tab === 'findings') return renderFindings();
  if (tab === 'assets') return renderAssets();
  if (tab === 'runs') return renderRuns();
  return renderActivity(d.activity);
}

async function renderFindings() {
  const { id, filters } = current;
  const q = new URLSearchParams(Object.entries(filters).filter(([, v]) => v));
  const { findings, total } = await api(`/engagements/${encodeURIComponent(id)}/findings?${q}`);
  current.findings = findings;
  const select = (name, values) => `<div class="field"><label for="f-${name}">${name}</label><select id="f-${name}" data-filter="${name}"><option value="">any</option>${values.map((v) => `<option ${filters[name] === v ? 'selected' : ''} value="${v}">${v.replace('_', ' ')}</option>`).join('')}</select></div>`;
  $('#tab-body').innerHTML = `
    <div class="toolbar">${select('severity', SEVS)}${select('status', STATUSES)}
      <div class="field"><label for="f-search">search</label><input id="f-search" type="search" data-filter="search" value="${esc(filters.search)}" placeholder="title, target, check"></div>
      <span class="result-count">${findings.length} of ${total}</span></div>
    ${findings.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Severity</th><th>Finding</th><th>Status</th><th>Last seen</th></tr></thead><tbody>
      ${findings.map((f, i) => `<tr class="row--interactive"><td>${chip(f.severity)}</td>
        <td><button type="button" class="row-link" data-i="${i}"><span class="cell-title">${esc(f.title)}</span></button><div class="cell-sub mono">${esc(f.check)} · ${esc(f.target)}</div></td>
        <td>${chip(f.status)}</td><td class="nowrap muted">${esc(when(f.lastSeen))}</td></tr>`).join('')}
    </tbody></table></div>` : empty('No findings match', total ? 'Clear a filter to see more.' : 'Run the engagement to collect findings.')}`;

  let t;
  $('#tab-body').querySelectorAll('[data-filter]').forEach((el) => el.addEventListener(el.tagName === 'SELECT' ? 'change' : 'input', () => {
    clearTimeout(t);
    t = setTimeout(async () => {
      filters[el.dataset.filter] = el.value.trim();
      await renderFindings();
      if (el.type === 'search') { const s = $('#f-search'); s.focus(); s.setSelectionRange(s.value.length, s.value.length); }
    }, el.type === 'search' ? 200 : 0);
  }));
  $('#tab-body').querySelectorAll('.row-link').forEach((b) => b.addEventListener('click', () => openFinding(current.findings[b.dataset.i])));
}

async function renderAssets() {
  const { assets, coverage } = await api(`/engagements/${encodeURIComponent(current.id)}/assets`);
  $('#tab-body').innerHTML = assets.length ? `<p class="list-summary">${coverage.tested} of ${coverage.total} tested (${coverage.percentTested}%)</p>
    <div class="table-wrap"><table class="data"><thead><tr><th>Type</th><th>Value</th><th>State</th><th>Attributes</th></tr></thead><tbody>
    ${assets.map((a) => `<tr><td>${esc(a.type)}</td><td class="cell-mono">${esc(a.value)}</td><td>${chip(a.state)}</td><td class="cell-sub mono">${esc(Object.entries(a.attributes ?? {}).map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' '))}</td></tr>`).join('')}
    </tbody></table></div>` : empty('No assets yet', 'Assets appear as modules discover hosts, services and endpoints.');
}

async function renderRuns() {
  const runs = await api(`/engagements/${encodeURIComponent(current.id)}/runs`);
  $('#tab-body').innerHTML = runs.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Run</th><th>Status</th><th>Started</th><th>Findings</th><th>Requests</th><th>Refused</th></tr></thead><tbody>
    ${runs.map((r) => `<tr><td class="cell-mono">${esc(r.id)}</td><td>${chip(r.status, r.status === 'completed' ? 'fixed' : 'open')}</td><td class="nowrap">${esc(when(r.startedAt))}</td><td>${r.stats.findings ?? 0}</td><td>${r.stats.requests ?? 0}</td><td>${r.stats.denials ?? 0}</td></tr>`).join('')}
    </tbody></table></div>` : empty('No runs yet', 'Start one from the CLI.', `node bin/vantage.js run ${current.id} --serve`);
}

function renderActivity(activity) {
  $('#tab-body').innerHTML = activity.length ? `<ul class="history-list">${[...activity].reverse().map((a) => `<li class="history-item"><span class="muted nowrap">${esc(when(a.ts))}</span> ${esc(a.message)}</li>`).join('')}</ul>` : empty('No activity yet', '');
}

// ---------- finding drawer ----------

async function openFinding(f) {
  const close = () => { $('#drawer-root').innerHTML = ''; document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  const section = (title, body) => (body ? `<section class="drawer-section"><h3>${title}</h3>${body}</section>` : '');
  $('#drawer-root').innerHTML = `<div class="drawer-backdrop"></div>
    <aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
      <div class="drawer-head"><div class="drawer-head-main"><div class="chip-row">${chip(f.severity)}${chip(f.status)}${chip(f.confidence, 'mode')}</div>
        <h2 id="drawer-title" class="drawer-title">${esc(f.title)}</h2><div class="drawer-sub mono">${esc(f.check)} · ${esc(f.target)}</div></div>
        <button type="button" class="btn btn--ghost btn--sm drawer-close" aria-label="Close">✕</button></div>
      <div class="drawer-body">
        ${section('Description', f.description && `<p>${esc(f.description)}</p>`)}
        ${section('Impact', f.impact && `<p>${esc(f.impact)}</p>`)}
        ${section('Observed', f.observed?.length && `<table class="kv-table">${f.observed.map((o) => `<tr><th>${esc(o.key)}</th><td class="mono">${esc(o.value)}</td></tr>`).join('')}</table>`)}
        ${section('Remediation', f.remediation && `<p>${esc(f.remediation)}</p>`)}
        ${section('References', [...(f.cwe ?? []), ...(f.owasp ?? [])].map(esc).join(' · ') + (f.references ?? []).filter((u) => /^https?:\/\//.test(u)).map((u) => `<br><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a>`).join(''))}
        ${section('Status', `<div class="status-controls"><select id="d-status">${STATUSES.map((s) => `<option ${s === f.status ? 'selected' : ''} value="${s}">${s.replace('_', ' ')}</option>`).join('')}</select>
          <button type="button" id="d-save" class="btn btn--primary btn--sm">Save</button></div>
          <label class="note-label" for="d-note">Note</label><textarea id="d-note" rows="2" maxlength="2000"></textarea>
          ${token ? '' : '<p class="drawer-token-hint">Set the operator token (top right) to change status.</p>'}`)}
        ${section('History', f.history?.length && `<ul class="history-list">${f.history.map((h) => `<li class="history-item"><strong>${esc(h.event)}</strong> ${esc(h.from ?? '')}${h.to ? ` → ${esc(h.to)}` : ''} <span class="muted">${esc(when(h.ts))} ${esc(h.actor ?? '')}</span>${h.note ? `<div>${esc(h.note)}</div>` : ''}</li>`).join('')}</ul>`)}
        <section class="drawer-section"><h3>Evidence</h3><div id="d-evidence" class="evidence-list">${f.evidence?.length ? '<div class="loading">loading…</div>' : '<p class="muted">No evidence recorded.</p>'}</div></section>
      </div></aside>`;
  $('.drawer-backdrop').addEventListener('click', close);
  $('.drawer-close').addEventListener('click', close);
  $('.drawer-close').focus();
  $('#d-save').addEventListener('click', async () => {
    try {
      const { finding } = await api(`/engagements/${encodeURIComponent(current.id)}/findings/${encodeURIComponent(f.id)}`, {
        method: 'PATCH', body: JSON.stringify({ status: $('#d-status').value, note: $('#d-note').value })
      });
      toast('Finding updated');
      close();
      await route();
      openFinding(finding);
    } catch (error) {
      toast(error.message, 'error');
    }
  });

  const items = await Promise.all((f.evidence ?? []).slice(0, 5).map((ev) => api(`/engagements/${encodeURIComponent(current.id)}/evidence/${encodeURIComponent(ev)}`).catch(() => null)));
  const box = $('#d-evidence');
  if (box && f.evidence?.length) {
    box.innerHTML = items.map((ev, i) => (ev ? `<div class="evidence-item"><div class="evidence-item-head"><span class="mono">${esc(ev.id)}</span><span class="muted">${esc(ev.request?.method)} ${esc(ev.request?.url)} → ${esc(ev.response?.status)}</span></div>
      <pre class="pre-block">${esc(Object.entries(ev.response?.headers ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n'))}${ev.response?.bodyPreview ? `\n\n${esc(ev.response.bodyPreview)}` : ''}</pre></div>`
      : `<div class="evidence-item muted">${esc(f.evidence[i])} unavailable</div>`)).join('');
  }
}

// ---------- token + live stream ----------

function paintToken() {
  $('#token-state').className = `token-state ${token ? 'token-state--set' : ''}`;
}
$('#token-button').addEventListener('click', () => { $('#token-input').value = token; $('#token-dialog').showModal(); });
$('#token-cancel').addEventListener('click', () => $('#token-dialog').close());
$('#token-clear').addEventListener('click', () => { setToken(''); $('#token-dialog').close(); });
$('#token-form').addEventListener('submit', (e) => { e.preventDefault(); setToken($('#token-input').value.trim()); $('#token-dialog').close(); });
function setToken(value) {
  token = value;
  try { value ? sessionStorage.setItem('vantage-token', value) : sessionStorage.removeItem('vantage-token'); } catch { /* storage blocked */ }
  paintToken();
}

function live() {
  const pill = $('#live-pill');
  const set = (state) => { pill.className = `pill pill--${state}`; $('#live-label').textContent = state; };
  set('connecting');
  const es = new EventSource('/api/events');
  let pending;
  es.addEventListener('open', () => set('live'));
  es.addEventListener('error', () => set(es.readyState === EventSource.CLOSED ? 'offline' : 'connecting'));
  for (const type of ['run:start', 'module:done', 'finding', 'run:done', 'finding:updated']) {
    es.addEventListener(type, (e) => {
      const data = JSON.parse(e.data);
      if (type === 'run:start') toast('Assessment run started');
      if (type === 'run:done') toast(`Run ${data.run?.status ?? 'finished'}: ${data.run?.stats?.findings ?? 0} new findings`);
      if (current && data.engagementId && data.engagementId !== current.id) return;
      clearTimeout(pending);
      pending = setTimeout(() => { if (!$('.drawer')) route(); }, 400); // coalesce bursts
    });
  }
}

// ---------- router ----------

async function route() {
  const [, kind, id, tab] = location.hash.split('/');
  try {
    if (kind === 'e' && id) await renderEngagement(decodeURIComponent(id), tab || 'findings');
    else await renderList();
  } catch (error) {
    view.innerHTML = `<div class="error-box"><h3>Could not load</h3><p>${esc(error.message)}</p></div>`;
  }
}

window.addEventListener('hashchange', route);
paintToken();
live();
route();
