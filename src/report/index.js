/**
 * Report entry point: JSON (machine), Markdown (review/diff) and HTML (deliverable).
 * All three render from buildJsonReport so counts and wording never drift between formats.
 */
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { buildJsonReport } from './json.js';
import { buildMarkdownReport } from './markdown.js';
import { REPORT_DISCLAIMER, SEVERITY_META, escapeHtml as e, formatDate, formatStamp } from './shared.js';
import { SEVERITY_ORDER, ensureDir } from '../core/util.js';
import { FILES, engagementDir } from '../core/paths.js';

/**
 * Build every report format.
 * @param {object} storeOrSnapshot a live EngagementStore or a plain snapshot object
 * @returns {Promise<{json: string, markdown: string, html: string}>}
 */
export async function buildReport(storeOrSnapshot) {
  const snapshot = typeof storeOrSnapshot?.snapshot === 'function' ? await storeOrSnapshot.snapshot() : storeOrSnapshot;
  const report = buildJsonReport(snapshot);
  return {
    json: JSON.stringify(report, null, 2),
    markdown: buildMarkdownReport(snapshot),
    html: renderHtml(report)
  };
}

/**
 * Write report.json / report.md / report.html into reports/<stamp>/ of the engagement.
 * @param {import('../core/store.js').EngagementStore} store
 * @param {{outDir?: string}} [options]
 */
export async function writeReports(store, { outDir } = {}) {
  const built = await buildReport(store);
  const dir = outDir ?? path.join(store.dir ?? engagementDir(store.id), FILES.reports, formatStamp());
  await ensureDir(dir);
  const jsonPath = path.join(dir, 'report.json');
  const markdownPath = path.join(dir, 'report.md');
  const htmlPath = path.join(dir, 'report.html');
  await Promise.all([
    fs.writeFile(jsonPath, built.json),
    fs.writeFile(markdownPath, built.markdown),
    fs.writeFile(htmlPath, built.html)
  ]);
  return { dir, jsonPath, markdownPath, htmlPath };
}

const sevLabel = (s) => SEVERITY_META[s]?.label ?? s;
const list = (items) => (items.length ? `<ul>${items.map((x) => `<li>${e(x)}</li>`).join('')}</ul>` : '');

/** Render the HTML deliverable. Every target-derived string goes through escapeHtml. */
export function renderHtml(r) {
  const g = r.engagement;
  const sevRows = SEVERITY_ORDER.map((s) => `<tr><td><span class="sev sev-${s}">${e(sevLabel(s))}</span></td><td>${r.summary.bySeverity[s] ?? 0}</td><td>${r.summary.active.bySeverity[s] ?? 0}</td></tr>`).join('');
  const findings = r.findings.map((f, i) => `
    <article class="finding" id="f-${i + 1}">
      <h3><span class="sev sev-${f.severity}">${e(sevLabel(f.severity))}</span> ${i + 1}. ${e(f.title)}</h3>
      <p class="meta"><code>${e(f.check)}</code> · ${e(f.target)} · confidence ${e(f.confidence)} · status ${e(f.status)} · seen ${f.occurrences}×</p>
      ${f.description ? `<p>${e(f.description)}</p>` : ''}
      ${f.impact ? `<p><b>Impact.</b> ${e(f.impact)}</p>` : ''}
      ${f.observed.length ? `<table class="obs">${f.observed.map((o) => `<tr><th>${e(o.key)}</th><td><code>${e(o.value)}</code></td></tr>`).join('')}</table>` : ''}
      ${f.remediation ? `<p><b>Remediation.</b> ${e(f.remediation)}</p>` : ''}
      <p class="meta">${[...f.cwe, ...f.owasp].map(e).join(' · ')}${f.evidence.length ? ` · evidence ${f.evidence.map((id) => `<code>${e(id)}</code>`).join(' ')}` : ''}</p>
      ${f.references.length ? `<p class="meta">${f.references.map((u) => `<a href="${e(u)}" rel="noreferrer">${e(u)}</a>`).join('<br>')}</p>` : ''}
    </article>`).join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${e(g.name)} — VANTAGE assessment report</title>
<style>
:root{--bg:#fff;--fg:#14171c;--muted:#5b6472;--line:#dde1e7;--critical:#b0172b;--high:#d4471b;--medium:#b07d00;--low:#2a6fb0;--info:#5b6472}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:900px;margin:0 auto;padding:32px 16px}
h1{margin:0 0 4px}h2{border-bottom:1px solid var(--line);padding-bottom:4px;margin-top:36px}
.meta{color:var(--muted);font-size:13px}code{font:12px ui-monospace,Consolas,monospace;word-break:break-all}
table{border-collapse:collapse;width:100%}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;color:#fff;font-size:12px;font-weight:600}
${SEVERITY_ORDER.map((s) => `.sev-${s}{background:var(--${s})}`).join('')}
.finding{border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:16px 0}.finding h3{margin:0 0 4px}
.auth{background:#f4f6f9;border:1px solid var(--line);border-radius:8px;padding:12px 16px}
@media print{.finding{break-inside:avoid}}
</style></head><body><main>
<h1>${e(g.name)}</h1>
<p class="meta">Security assessment report · ${e(g.client || 'client not recorded')} · generated ${e(formatDate(r.generatedAt))} · ${e(r.tool.name)} ${e(r.tool.version)}</p>
<div class="auth"><b>Authorization.</b> ${e(g.authorizationRef || 'not recorded')}${g.authorizedBy ? ` — authorized by ${e(g.authorizedBy)}` : ''}<br>
<span class="meta">Window ${e(formatDate(g.startsAt))} → ${e(g.endsAt ? formatDate(g.endsAt) : 'open')} · mode ${e(r.scope.mode)}</span></div>

<h2>Executive summary</h2>
<p><b>Overall risk: ${e(r.summary.riskLabel)}.</b> ${e(r.summary.riskRationale)}</p>
<p>${r.summary.total} finding(s), ${r.summary.active.total} still active. ${r.coverage.tested} of ${r.coverage.total} discovered assets tested (${r.coverage.percentTested}%).</p>
<table><tr><th>Severity</th><th>Total</th><th>Active</th></tr>${sevRows}</table>

<h2>Scope</h2>
<p>In scope: ${r.scope.targets.map((t) => `<code>${e(t)}</code>`).join(', ') || 'none'}${r.scope.exclude.length ? `<br>Excluded: ${r.scope.exclude.map((t) => `<code>${e(t)}</code>`).join(', ')}` : ''}</p>

<h2>Findings</h2>
${findings || '<p>No findings were recorded within this scope and check set.</p>'}

<h2>Methodology</h2>
<p>${e(r.methodology.capability)}</p>
${r.methodology.steps.map((s) => `<p><b>${e(s.name)}.</b> ${e(s.detail)}</p>`).join('')}

<h2>Limitations</h2>
${list(r.limitations)}

<h2>Disclaimer</h2>
<p class="meta">${e(REPORT_DISCLAIMER)}</p>
</main></body></html>
`;
}
