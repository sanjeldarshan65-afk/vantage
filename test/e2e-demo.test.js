import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { startLab } from '../examples/lab-target.js';
import { EngagementStore } from '../src/core/store.js';
import { ScopeGuard } from '../src/core/guard.js';
import { Engine } from '../src/core/engine.js';
import { loadModules } from '../src/core/registry.js';
import { createEngagementTemplate } from '../src/core/scope.js';
import { silentLogger } from '../src/core/log.js';
import { buildReport, renderHtml, writeReports } from '../src/report/index.js';
import { buildJsonReport } from '../src/report/json.js';

test('demo: lab target -> engine -> findings -> reports', async () => {
  const lab = await startLab();
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vantage-e2e-'));
  const logger = silentLogger();
  const doc = createEngagementTemplate({ id: 'e2e', targets: [lab.url], authorizationRef: 'TEST' });
  const store = await EngagementStore.create(doc, { engagementsRoot: root, logger });
  try {
    const guard = new ScopeGuard({ engagement: store.engagement, scope: store.scope, logger, audit: store.audit, evidence: store.evidence });
    const { run } = await new Engine({ store, guard, logger, registry: await loadModules() }).run();
    assert.equal(run.status, 'completed');
    const checks = store.listFindings().map((f) => f.check);
    for (const expected of ['web.cors', 'web.cookies', 'web.headers']) {
      assert.ok(checks.some((c) => c.startsWith(expected)), `expected a ${expected} finding, got ${checks}`);
    }
    assert.ok(store.listFindings().every((f) => f.evidence.length > 0), 'every finding links evidence');
    await store.flush();
    const [summary] = await EngagementStore.list({ engagementsRoot: root });
    assert.equal(summary.lastRunAt, run.startedAt, 'lastRunAt is the run start time, not a run id');

    const built = await buildReport(store);
    assert.match(built.html, /CORS reflects an arbitrary origin/);
    assert.equal(JSON.parse(built.json).summary.total, checks.length);
    const paths = await writeReports(store);
    assert.ok((await fs.stat(paths.htmlPath)).size > 1000);
  } finally {
    await store.close();
    await lab.close();
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('html report escapes target-controlled text', () => {
  const report = buildJsonReport({
    engagement: { id: 'x', name: '<img src=x onerror=alert(1)>' },
    findings: [{ id: 'f', check: 'c', title: '<script>alert(1)</script>', severity: 'high', references: ['javascript:alert(1)'] }]
  });
  const html = renderHtml(report);
  assert.ok(!html.includes('<script>alert'), 'script tag escaped');
  assert.ok(!html.includes('<img src=x'), 'img tag escaped');
  assert.ok(!html.includes('javascript:'), 'non-http references dropped');
});
